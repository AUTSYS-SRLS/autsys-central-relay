// Durable, atomic first-binding registration for existing AUTSYS Managers.
// No raw Manager secret is stored: only SHA-256 digest and platform.
// The first claimant is trusted as expressly chosen by the operator.
import crypto from "node:crypto";
import { createClient } from "redis";

const prefix = "autsys:manager-binding:v1:";
const same = (a, b) => {
  const x = Buffer.from(a, "utf8");
  const y = Buffer.from(b, "utf8");
  return x.length === y.length && crypto.timingSafeEqual(x, y);
};
const validId = (id) => typeof id === "string" &&
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(id);
const validSecret = (v) => typeof v === "string" && /^[A-Za-z0-9_-]{32,128}$/.test(v);
const fingerprint = (secret) => crypto.createHash("sha256").update(secret).digest("base64url");

export function createBindingStore({ url, approved = new Map() }) {
  if (!url) throw new Error("binding_store_url_required");
  const client = createClient({ url, disableOfflineQueue: true, socket: { connectTimeout: 4000 } });
  client.on("error", () => {});
  let connecting;
  function ready() {
    if (client.isReady) return Promise.resolve(client);
    if (!connecting) connecting = client.connect().finally(() => { connecting = undefined; });
    return connecting;
  }

  async function verify(id, platform, secret) {
    if (!validId(id) || !["WINDOWS", "ANDROID"].includes(platform) || !validSecret(secret)) return false;
    const canonical = id.toLowerCase();
    const hash = fingerprint(secret);
    const pinned = approved.get(canonical);
    if (pinned && (pinned.platform !== platform || !same(pinned.binding_sha256, hash))) return false;
    const conn = await ready();
    const key = prefix + canonical;
    const record = JSON.stringify({ platform, binding_sha256: hash });
    const existing = await conn.get(key);
    if (existing === null) await conn.set(key, record, { NX: true });
    const saved = await conn.get(key);
    if (saved === null) throw new Error("binding_store_unavailable");
    const entry = JSON.parse(saved);
    return entry.platform === platform && typeof entry.binding_sha256 === "string" && same(entry.binding_sha256, hash);
  }

  async function verifyToken(payload, secret) {
    if (!payload || typeof payload.binding_sha256 !== "string" || !validSecret(secret)) return false;
    if (!same(payload.binding_sha256, fingerprint(secret))) return false;
    return verify(payload.installation_id, payload.platform, secret);
  }

  return { verify, verifyToken };
}
