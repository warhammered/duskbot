// Webhooks for a sleeping home, one Durable Object per label (binding HOOK_QUEUE, class HookQueue). The Worker accepts the
// hook at once (202), so a sender that waits only a few seconds (GitHub waits 10 and never retries) still sees it taken;
// this object keeps it sealed in its storage and delivers it, byte for byte with its headers, once the home answers.
//
// Sealing: AES-256-GCM under a key derived per label from HOOK_SEAL_KEY, a secret only the Worker holds. The account
// service never sees a queued hook, sealed or not, and the object's storage holds only ciphertext and a hash id.
//
// Delivery: an alarm, so it outlives the isolate that took the hook. While the home is not up the alarm asks for the
// wake again (free while one is under way) and backs off from 1 s to 30 s; a hook still undelivered after DROP_AFTER_MS
// is dropped with an `edge_hook_dropped` log line. A delivered id is remembered for SEEN_MS, so a sender's retry of a
// hook this object already delivered is answered without a second delivery.
import { DOWN, LABEL, askWake, lookupRoute, upstreamRequest } from "./route.js";

export const QUEUE_LIMITS = { maxEntries: 50, maxBytes: 16 * 1024 * 1024, maxEnvelope: 2 * 1024 * 1024 + 64 * 1024, chunk: 96 * 1024,
  firstRetryMs: 1_000, maxRetryMs: 30_000, dropAfterMs: 30 * 60_000, seenMs: 24 * 3_600_000 };
const ID = /^[0-9a-f]{64}$/;
// cloudflare's own and per-hop headers: the delivery sets its own
const UNSENT = /^(?:host|content-length|connection|transfer-encoding|keep-alive|upgrade|cdn-loop|x-forwarded-host|cf-.*)$/i;

const encoder = new TextEncoder(), decoder = new TextDecoder();

/** the plaintext the queue seals: the request line and headers as JSON, then the body's exact bytes */
export function envelope({ method, path, headers, body }) {
  const kept = [];
  for (const [name, value] of new Headers(headers)) if (!UNSENT.test(name)) kept.push([name, value]);
  const head = encoder.encode(JSON.stringify({ method, path, headers: kept }));
  const bytes = body ? new Uint8Array(body) : new Uint8Array(0);
  const out = new Uint8Array(4 + head.length + bytes.length);
  new DataView(out.buffer).setUint32(0, head.length);
  out.set(head, 4); out.set(bytes, 4 + head.length);
  return out;
}

export function openEnvelope(bytes) {
  const length = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(0);
  const head = JSON.parse(decoder.decode(bytes.subarray(4, 4 + length)));
  const body = bytes.subarray(4 + length);
  return { ...head, body: ["GET", "HEAD"].includes(head.method) || body.length === 0 ? undefined : body.slice() };
}

async function sealKey(env, label) {
  const material = await crypto.subtle.importKey("raw", encoder.encode(env.HOOK_SEAL_KEY), "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: encoder.encode(`dusk-edge-hook-v1:${label}`) },
    material, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

/** true when the Worker can queue hooks: the binding and the sealing secret are both there */
export function queueReady(env) {
  return Boolean(env.HOOK_QUEUE && typeof env.HOOK_SEAL_KEY === "string" && env.HOOK_SEAL_KEY.length >= 32);
}

function audit(event, fields) {
  console.log(JSON.stringify({ at: new Date().toISOString(), event, ...fields }));
}


export class HookQueue {
  constructor(state, env) {
    this.storage = state.storage;
    this.env = env;
    this.now = () => Date.now();
    this._sealKey = null;
    this._sealLabel = null;
  }

  async _sealKeyFor(label) {
    if (this._sealKey && this._sealLabel === label) return this._sealKey;
    const key = await sealKey(this.env, label);
    this._sealKey = key;
    this._sealLabel = label;
    return key;
  }

  /** internal only, from the Worker through the binding: POST /accept (the envelope, 202 queued or 200 duplicate) and /forget */
  async fetch(request) {
    const url = new URL(request.url), id = request.headers.get("x-hook-id") ?? "";
    if (!ID.test(id)) return new Response("bad id", { status: 400 });
    if (url.pathname === "/forget") {
      await this.remove(id);
      return new Response(null, { status: 204 });
    }
    if (url.pathname !== "/accept" || request.method !== "POST") return new Response("not found", { status: 404 });
    const label = request.headers.get("x-hook-label") ?? "", host = request.headers.get("x-hook-host") ?? "";
    if (!LABEL.test(label) || !host.startsWith(`${label}.`)) return new Response("bad label", { status: 400 });
    const plain = new Uint8Array(await request.arrayBuffer());
    if (plain.byteLength > QUEUE_LIMITS.maxEnvelope) return new Response("too large", { status: 413 });
    const now = this.now();
    if (await this.storage.get(`e:${id}`)) return Response.json({ duplicate: true, state: "queued" });
    if ((await this.storage.get(`s:${id}`) ?? 0) > now) return Response.json({ duplicate: true, state: "delivered" });
    const entries = await this.entries();
    if (entries.length >= QUEUE_LIMITS.maxEntries || entries.reduce((n, e) => n + e.bytes, 0) + plain.byteLength > QUEUE_LIMITS.maxBytes) return new Response("queue full", { status: 507 });
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: encoder.encode(id) }, await this._sealKeyFor(label), plain));
    const writes = { "meta": { ...(await this.storage.get("meta")), label, host }, [`e:${id}`]: { id, at: now, bytes: sealed.byteLength, chunks: 0, iv: [...iv] } };
    let chunks = 0;
    for (let at = 0; at < sealed.byteLength; at += QUEUE_LIMITS.chunk) writes[`c:${id}:${chunks++}`] = sealed.slice(at, at + QUEUE_LIMITS.chunk);
    writes[`e:${id}`].chunks = chunks;
    await this.storage.put(writes);
    // the Worker asks for the wake itself right after this; the first look at the home comes a second later
    const alarm = await this.storage.getAlarm();
    if (alarm === null || alarm > now + QUEUE_LIMITS.firstRetryMs) await this.storage.setAlarm(now + QUEUE_LIMITS.firstRetryMs);
    return Response.json({ queued: true }, { status: 202 });
  }

  async alarm() {
    const now = this.now(), meta = await this.storage.get("meta") ?? {};
    for (const [key, until] of await this.storage.list({ prefix: "s:" })) if (until <= now) await this.storage.delete(key);
    const attempts = (meta.attempts ?? 0) + 1;
    const drop = async (e, reason) => { await this._removeEntry(e); audit("edge_hook_dropped", { label: meta.label, id: e.id, reason, attempts, ageMs: now - e.at }); };
    let entries = [];
    for (const e of await this.entries()) if (now - e.at >= QUEUE_LIMITS.dropAfterMs) await drop(e, "expired"); else entries.push(e);
    let left = entries.length;
    if (entries.length) {
      let route;
      try { route = await lookupRoute(meta.label, this.env); } catch { route = undefined; }
      if (route === null || route?.wakeable === false && !route.awake) {
        for (const e of entries) await drop(e, route === null ? "no_home" : "not_wakeable");
        left = 0;
      } else if (route?.awake) {
        let delivered = 0;
        for (const e of entries) {
          if (await this.deliver(e, meta, route.upstream, now, attempts, drop)) delivered++;
          else break;
        }
        left = entries.length - delivered;
      } else if (route) {
        await askWake(meta.label, "webhook", this.env);
        // left remains entries.length
      }
    }
    await this.storage.put("meta", { ...meta, attempts: left ? attempts : 0 });
    if (left) {
      const next = now + Math.min(QUEUE_LIMITS.firstRetryMs * 2 ** (attempts - 1), QUEUE_LIMITS.maxRetryMs);
      const alarm = await this.storage.getAlarm();
      if (alarm === null || alarm > next) await this.storage.setAlarm(next);
    }
  }

  /** true when the hook left the queue (delivered, or unsealable), false when the home is not answering yet */
  async deliver(e, meta, upstream, now, attempts, drop) {
    let hook;
    try {
      const parts = await this.storage.get(Array.from({ length: e.chunks }, (_, n) => `c:${e.id}:${n}`));
      const sealed = new Uint8Array(e.bytes);
      let offset = 0;
      for (let n = 0; n < e.chunks; n++) { const part = parts.get(`c:${e.id}:${n}`); sealed.set(part, offset); offset += part.byteLength; }
      hook = openEnvelope(new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: new Uint8Array(e.iv), additionalData: encoder.encode(e.id) }, await this._sealKeyFor(meta.label), sealed)));
    } catch {
      await drop(e, "unsealable");
      return true;
    }
    const response = await fetch(upstreamRequest(upstream, meta.host, hook)).catch(() => null);
    await response?.body?.cancel().catch(() => {});
    if (!response || DOWN.includes(response.status)) return false;
    await this._removeEntry(e);
    await this.storage.put(`s:${e.id}`, now + QUEUE_LIMITS.seenMs);
    audit("edge_hook_delivered", { label: meta.label, id: e.id, status: response.status, attempts, ageMs: now - e.at });
    return true;
  }

  async entries() {
    return [...(await this.storage.list({ prefix: "e:" })).values()].sort((a, b) => a.at - b.at);
  }

  async _removeEntry(e) {
    await this.storage.delete([`e:${e.id}`, ...Array.from({ length: e.chunks }, (_, n) => `c:${e.id}:${n}`)]);
  }

  async remove(id) {
    const e = await this.storage.get(`e:${id}`);
    if (e) await this._removeEntry(e);
  }
}
