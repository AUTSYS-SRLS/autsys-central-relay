// AUTSYS Central Relay
// Transport-only relay between AUTSYS Manager installations and AUTSYS Centrale.
// No licensing logic. No authoritative database. No private licensing keys.
//
// v0.3.0 adds an EPHEMERAL package transport cache. AUTSYS Centrale remains
// authoritative for releases. The relay only transports a verified copy long
// enough for a Manager to download it through an opaque, expiring ticket.

import crypto from "crypto";
import fs from "fs";
import os from "os";
import path from "path";
import express from "express";

const app = express();
const port = Number(process.env.PORT || 10010);
const VERSION = "0.3.0";
const PROTOCOL = 2; // backward-compatible with Manager Android 1.0.0.17

const CENTRAL_KEY = String(process.env.AUTSYS_CENTRAL_RELAY_KEY || "");
const MANAGER_TOKEN_KEY = String(process.env.AUTSYS_MANAGER_TOKEN_KEY || "");

const MAX_EVENTS = 5000;
const MAX_COMMANDS_PER_INSTALLATION = 500;
const MAX_BODY = "256kb";
const MAX_BATCH = 100;
const DEFAULT_EVENT_TTL_SEC = 24 * 60 * 60;
const DEFAULT_COMMAND_TTL_SEC = 24 * 60 * 60;
const MANAGER_TOKEN_TTL_SEC = 7 * 24 * 60 * 60;
const DEFAULT_PACKAGE_TTL_SEC = 24 * 60 * 60;
const MAX_PACKAGE_TTL_SEC = 7 * 24 * 60 * 60;
const MAX_PACKAGE_BYTES = Math.max(1, Number(process.env.AUTSYS_RELAY_MAX_PACKAGE_BYTES || 2147483648));
const PACKAGE_ROOT = path.resolve(String(process.env.AUTSYS_RELAY_PACKAGE_ROOT || path.join(os.tmpdir(), "autsys-relay-packages")));

app.set("trust proxy", 1);
app.disable("x-powered-by");
app.use(express.json({ limit: MAX_BODY }));

app.use((req, res, next) => {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("X-AUTSYS-Relay-Version", VERSION);
  res.setHeader("X-AUTSYS-Protocol", String(PROTOCOL));
  next();
});

const nowSec = () => Math.floor(Date.now() / 1000);
const isSafeId = (v) => typeof v === "string" && /^[A-Za-z0-9._:-]{1,128}$/.test(v);
const isUuid = (v) => typeof v === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(v);
const isBindingSecret = (v) => typeof v === "string" && /^[A-Za-z0-9_-]{32,128}$/.test(v);
const isSha256 = (v) => typeof v === "string" && /^[0-9a-f]{64}$/i.test(v);
const asObject = (v) => (v && typeof v === "object" && !Array.isArray(v) ? v : null);

function safeEqualText(a, b) {
  const ab = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

function b64urlDecodeText(v) {
  return Buffer.from(v, "base64url").toString("utf8");
}

function sha256Text(v) {
  return crypto.createHash("sha256").update(String(v)).digest("base64url");
}

function signManagerToken(payload) {
  if (!MANAGER_TOKEN_KEY) return "";
  const payload64 = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
  const signature64 = crypto.createHmac("sha256", MANAGER_TOKEN_KEY).update(payload64).digest("base64url");
  return `${payload64}.${signature64}`;
}

function verifyManagerToken(token) {
  if (!MANAGER_TOKEN_KEY || typeof token !== "string") return null;
  const parts = token.split(".");
  if (parts.length !== 2) return null;
  const [payload64, signature64] = parts;
  if (!payload64 || !signature64) return null;
  const expected = crypto.createHmac("sha256", MANAGER_TOKEN_KEY).update(payload64).digest("base64url");
  if (!safeEqualText(expected, signature64)) return null;
  try {
    const payload = JSON.parse(b64urlDecodeText(payload64));
    if (!payload || payload.purpose !== "manager-relay") return null;
    if (!isSafeId(payload.installation_id)) return null;
    if (!Number.isInteger(payload.exp) || payload.exp <= nowSec()) return null;
    return payload;
  } catch {
    return null;
  }
}

function bearer(req) {
  const h = String(req.get("authorization") || "");
  return h.startsWith("Bearer ") ? h.slice(7).trim() : "";
}

function requireCentral(req, res, next) {
  if (!CENTRAL_KEY) return res.status(503).json({ ok: false, error: "relay_not_configured" });
  const token = bearer(req);
  if (!token || !safeEqualText(token, CENTRAL_KEY)) return res.status(401).json({ ok: false, error: "unauthorized" });
  next();
}

function requireManager(req, res, next) {
  const payload = verifyManagerToken(bearer(req));
  if (!payload) return res.status(401).json({ ok: false, error: "unauthorized" });
  if (payload.binding_sha256) {
    const binding = String(req.get("x-autsys-binding") || "").trim();
    if (!isBindingSecret(binding) || !safeEqualText(sha256Text(binding), payload.binding_sha256)) {
      return res.status(401).json({ ok: false, error: "invalid_binding" });
    }
  }
  req.autsysManager = payload;
  next();
}

const rateBuckets = new Map();
app.use((req, res, next) => {
  const ip = String(req.ip || req.socket.remoteAddress || "unknown");
  const now = Date.now();
  let b = rateBuckets.get(ip);
  if (!b || now - b.startedAt >= 60_000) {
    b = { startedAt: now, count: 0 };
    rateBuckets.set(ip, b);
  }
  b.count += 1;
  if (b.count > 240) return res.status(429).json({ ok: false, error: "rate_limited" });
  next();
});

const bootstrapBuckets = new Map();
function allowBootstrap(req) {
  const ip = String(req.ip || req.socket.remoteAddress || "unknown");
  const now = Date.now();
  let b = bootstrapBuckets.get(ip);
  if (!b || now - b.startedAt >= 10 * 60_000) {
    b = { startedAt: now, count: 0 };
    bootstrapBuckets.set(ip, b);
  }
  b.count += 1;
  return b.count <= 20;
}

const events = [];
const eventIds = new Set();
const commandsByInstallation = new Map();
const commandIds = new Set();
const packagesByRelease = new Map();
const packageTickets = new Map();

function safeFilename(v) {
  const raw = String(v || "package.zip").trim();
  const base = path.basename(raw).replace(/[^A-Za-z0-9._-]/g, "_");
  return base || "package.zip";
}

function publicBase(req) {
  return `${req.protocol}://${req.get("host")}`.replace(/\/$/, "");
}

function packagePath(releaseId) {
  return path.join(PACKAGE_ROOT, `${releaseId}.zip`);
}

function purgeExpired() {
  const now = nowSec();
  for (let i = events.length - 1; i >= 0; i -= 1) {
    if (events[i].expires_at <= now) {
      eventIds.delete(events[i].event_id);
      events.splice(i, 1);
    }
  }
  for (const [installationId, list] of commandsByInstallation.entries()) {
    const kept = list.filter((x) => x.expires_at > now);
    for (const x of list) if (x.expires_at <= now) commandIds.delete(x.command_id);
    if (kept.length === 0) commandsByInstallation.delete(installationId);
    else commandsByInstallation.set(installationId, kept);
  }
  for (const [ticket, item] of packageTickets.entries()) {
    if (item.expires_at <= now) packageTickets.delete(ticket);
  }
  for (const [releaseId, item] of packagesByRelease.entries()) {
    if (item.expires_at <= now) {
      packagesByRelease.delete(releaseId);
      try { fs.unlinkSync(item.path); } catch {}
    }
  }
}

setInterval(purgeExpired, 60_000).unref();
try { fs.mkdirSync(PACKAGE_ROOT, { recursive: true }); } catch {}

app.get("/", (req, res) => {
  res.json({ ok: true, service: "autsys-central-relay", version: VERSION, protocol: PROTOCOL });
});

app.get("/health", (req, res) => {
  res.json({ ok: true, service: "autsys-central-relay", version: VERSION, protocol: PROTOCOL, ts: nowSec() });
});

app.post("/v1/manager/bootstrap", (req, res) => {
  if (!MANAGER_TOKEN_KEY) return res.status(503).json({ ok: false, error: "relay_not_configured" });
  if (!allowBootstrap(req)) return res.status(429).json({ ok: false, error: "bootstrap_rate_limited" });
  const body = asObject(req.body);
  if (!body) return res.status(400).json({ ok: false, error: "invalid_body" });
  const installationId = String(body.installation_id || "").trim();
  const productCode = String(body.product_code || "").trim().toUpperCase();
  const managerVersion = String(body.manager_version || "").trim();
  const platform = String(body.platform || "").trim().toUpperCase();
  const bindingSecret = String(body.binding_secret || "").trim();
  if (!isUuid(installationId)) return res.status(400).json({ ok: false, error: "invalid_installation_id" });
  if (productCode !== "AUTSYS_MANAGER") return res.status(400).json({ ok: false, error: "invalid_product" });
  if (platform !== "ANDROID") return res.status(400).json({ ok: false, error: "invalid_platform" });
  if (!/^[0-9A-Za-z._-]{1,64}$/.test(managerVersion)) return res.status(400).json({ ok: false, error: "invalid_manager_version" });
  if (!isBindingSecret(bindingSecret)) return res.status(400).json({ ok: false, error: "invalid_binding" });
  const issuedAt = nowSec();
  const expiresAt = issuedAt + MANAGER_TOKEN_TTL_SEC;
  const payload = {
    installation_id: installationId,
    purpose: "manager-relay",
    platform: "ANDROID",
    token_version: 2,
    binding_sha256: sha256Text(bindingSecret),
    iat: issuedAt,
    exp: expiresAt
  };
  const relayToken = signManagerToken(payload);
  if (!relayToken) return res.status(503).json({ ok: false, error: "relay_not_configured" });
  return res.status(201).json({
    ok: true,
    installation_id: installationId,
    relay_token: relayToken,
    expires_at: expiresAt,
    relay_version: VERSION,
    protocol: PROTOCOL
  });
});

app.post("/v1/manager/events", requireManager, (req, res) => {
  purgeExpired();
  const installationId = req.autsysManager.installation_id;
  const body = asObject(req.body);
  if (!body) return res.status(400).json({ ok: false, error: "invalid_body" });
  const eventId = String(body.event_id || "").trim();
  const kind = String(body.kind || "").trim();
  const payload = asObject(body.payload);
  const signature = typeof body.signature === "string" ? body.signature : "";
  const ts = Number.isInteger(body.ts) ? body.ts : nowSec();
  if (!isSafeId(eventId) || !isSafeId(kind) || !payload) return res.status(400).json({ ok: false, error: "invalid_event" });
  if (eventIds.has(eventId)) return res.status(200).json({ ok: true, duplicate: true, event_id: eventId });
  if (events.length >= MAX_EVENTS) return res.status(503).json({ ok: false, error: "queue_full" });
  const ttl = Number.isInteger(body.ttl_sec) ? Math.max(60, Math.min(body.ttl_sec, DEFAULT_EVENT_TTL_SEC)) : DEFAULT_EVENT_TTL_SEC;
  const item = { event_id: eventId, installation_id: installationId, kind, ts, received_at: nowSec(), expires_at: nowSec() + ttl, payload, signature };
  events.push(item);
  eventIds.add(eventId);
  return res.status(202).json({ ok: true, event_id: eventId });
});

app.get("/v1/central/events", requireCentral, (req, res) => {
  purgeExpired();
  const requested = Number.parseInt(String(req.query.limit || "50"), 10);
  const limit = Number.isFinite(requested) ? Math.max(1, Math.min(requested, MAX_BATCH)) : 50;
  return res.json({ ok: true, count: Math.min(events.length, limit), items: events.slice(0, limit) });
});

app.post("/v1/central/events/ack", requireCentral, (req, res) => {
  const ids = Array.isArray(req.body?.event_ids) ? req.body.event_ids.filter(isSafeId).slice(0, MAX_BATCH) : [];
  if (ids.length === 0) return res.status(400).json({ ok: false, error: "invalid_event_ids" });
  const wanted = new Set(ids);
  let removed = 0;
  for (let i = events.length - 1; i >= 0; i -= 1) {
    if (wanted.has(events[i].event_id)) {
      eventIds.delete(events[i].event_id);
      events.splice(i, 1);
      removed += 1;
    }
  }
  return res.json({ ok: true, removed });
});

app.get("/v1/central/packages/:releaseId", requireCentral, (req, res) => {
  purgeExpired();
  const releaseId = String(req.params.releaseId || "").trim();
  if (!isUuid(releaseId)) return res.status(400).json({ ok: false, error: "invalid_release_id" });
  const item = packagesByRelease.get(releaseId);
  if (!item || !fs.existsSync(item.path)) return res.status(404).json({ ok: false, error: "package_not_cached" });
  return res.json({ ok: true, release_id: releaseId, sha256: item.sha256, size_bytes: item.size_bytes, filename: item.filename, expires_at: item.expires_at });
});

app.put("/v1/central/packages/:releaseId", requireCentral, (req, res) => {
  purgeExpired();
  const releaseId = String(req.params.releaseId || "").trim();
  if (!isUuid(releaseId)) return res.status(400).json({ ok: false, error: "invalid_release_id" });
  const expectedSha = String(req.get("x-autsys-sha256") || "").trim().toLowerCase();
  const expectedSize = Number.parseInt(String(req.get("x-autsys-size") || "0"), 10);
  const filename = safeFilename(req.get("x-autsys-filename") || "package.zip");
  const requestedTtl = Number.parseInt(String(req.get("x-autsys-ttl-sec") || DEFAULT_PACKAGE_TTL_SEC), 10);
  const ttl = Number.isFinite(requestedTtl) ? Math.max(60, Math.min(requestedTtl, MAX_PACKAGE_TTL_SEC)) : DEFAULT_PACKAGE_TTL_SEC;
  if (!isSha256(expectedSha) || !Number.isSafeInteger(expectedSize) || expectedSize <= 0 || expectedSize > MAX_PACKAGE_BYTES) {
    return res.status(400).json({ ok: false, error: "invalid_package_metadata" });
  }
  const existing = packagesByRelease.get(releaseId);
  if (existing && existing.sha256 === expectedSha && existing.size_bytes === expectedSize && fs.existsSync(existing.path)) {
    existing.expires_at = nowSec() + ttl;
    return res.status(200).json({ ok: true, duplicate: true, release_id: releaseId, sha256: expectedSha, size_bytes: expectedSize, expires_at: existing.expires_at });
  }
  try { fs.mkdirSync(PACKAGE_ROOT, { recursive: true }); } catch {
    return res.status(503).json({ ok: false, error: "package_cache_unavailable" });
  }
  const finalPath = packagePath(releaseId);
  const tempPath = `${finalPath}.uploading.${crypto.randomBytes(8).toString("hex")}`;
  const hash = crypto.createHash("sha256");
  const out = fs.createWriteStream(tempPath, { flags: "wx" });
  let received = 0;
  let finished = false;
  const fail = (status, error) => {
    if (finished) return;
    finished = true;
    try { req.unpipe(out); } catch {}
    try { out.destroy(); } catch {}
    try { fs.unlinkSync(tempPath); } catch {}
    if (!res.headersSent) res.status(status).json({ ok: false, error });
  };
  req.on("data", (chunk) => {
    received += chunk.length;
    if (received > expectedSize || received > MAX_PACKAGE_BYTES) {
      fail(413, "package_too_large");
      try { req.destroy(); } catch {}
      return;
    }
    hash.update(chunk);
  });
  req.on("aborted", () => fail(400, "upload_aborted"));
  req.on("error", () => fail(400, "upload_failed"));
  out.on("error", () => fail(503, "package_cache_write_failed"));
  out.on("finish", () => {
    if (finished) return;
    const actualSha = hash.digest("hex");
    if (received !== expectedSize) return fail(400, "package_size_mismatch");
    if (!safeEqualText(actualSha, expectedSha)) return fail(400, "package_sha256_mismatch");
    finished = true;
    try { fs.renameSync(tempPath, finalPath); }
    catch {
      try { fs.unlinkSync(finalPath); } catch {}
      try { fs.renameSync(tempPath, finalPath); }
      catch {
        try { fs.unlinkSync(tempPath); } catch {}
        return res.status(503).json({ ok: false, error: "package_cache_commit_failed" });
      }
    }
    const item = { release_id: releaseId, sha256: actualSha, size_bytes: received, filename, path: finalPath, expires_at: nowSec() + ttl };
    packagesByRelease.set(releaseId, item);
    return res.status(201).json({ ok: true, release_id: releaseId, sha256: actualSha, size_bytes: received, filename, expires_at: item.expires_at });
  });
  req.pipe(out);
});

app.post("/v1/central/package-tickets", requireCentral, (req, res) => {
  purgeExpired();
  const body = asObject(req.body);
  if (!body) return res.status(400).json({ ok: false, error: "invalid_body" });
  const releaseId = String(body.release_id || "").trim();
  const installationId = String(body.installation_id || "").trim();
  if (!isUuid(releaseId) || !isSafeId(installationId)) return res.status(400).json({ ok: false, error: "invalid_ticket_request" });
  const pkg = packagesByRelease.get(releaseId);
  if (!pkg || !fs.existsSync(pkg.path)) return res.status(404).json({ ok: false, error: "package_not_cached" });
  const requested = Number.isInteger(body.ttl_sec) ? body.ttl_sec : DEFAULT_COMMAND_TTL_SEC;
  const ttl = Math.max(60, Math.min(requested, MAX_PACKAGE_TTL_SEC));
  const ticket = crypto.randomBytes(32).toString("base64url");
  const expiresAt = nowSec() + ttl;
  packageTickets.set(ticket, { release_id: releaseId, installation_id: installationId, expires_at: expiresAt });
  pkg.expires_at = Math.max(pkg.expires_at, expiresAt);
  return res.status(201).json({ ok: true, release_id: releaseId, installation_id: installationId, expires_at: expiresAt, download_url: `${publicBase(req)}/v1/download/${ticket}` });
});

app.get("/v1/download/:ticket", (req, res) => {
  purgeExpired();
  const ticket = String(req.params.ticket || "").trim();
  if (!/^[A-Za-z0-9_-]{40,128}$/.test(ticket)) return res.status(404).end();
  const access = packageTickets.get(ticket);
  if (!access || access.expires_at <= nowSec()) return res.status(404).end();
  const pkg = packagesByRelease.get(access.release_id);
  if (!pkg || !fs.existsSync(pkg.path)) return res.status(404).end();
  res.setHeader("Content-Type", "application/zip");
  res.setHeader("Content-Length", String(pkg.size_bytes));
  res.setHeader("Content-Disposition", `attachment; filename="${safeFilename(pkg.filename)}"`);
  res.setHeader("X-AUTSYS-Package-SHA256", pkg.sha256);
  const stream = fs.createReadStream(pkg.path);
  stream.on("error", () => { if (!res.headersSent) res.status(503).end(); else res.destroy(); });
  stream.pipe(res);
});

app.post("/v1/central/commands", requireCentral, (req, res) => {
  purgeExpired();
  const body = asObject(req.body);
  if (!body) return res.status(400).json({ ok: false, error: "invalid_body" });
  const commandId = String(body.command_id || "").trim();
  const installationId = String(body.installation_id || "").trim();
  const kind = String(body.kind || "").trim();
  const payload = asObject(body.payload);
  const signature = typeof body.signature === "string" ? body.signature : "";
  if (!isSafeId(commandId) || !isSafeId(installationId) || !isSafeId(kind) || !payload || !signature) {
    return res.status(400).json({ ok: false, error: "invalid_command" });
  }
  if (commandIds.has(commandId)) return res.status(200).json({ ok: true, duplicate: true, command_id: commandId });
  const list = commandsByInstallation.get(installationId) || [];
  if (list.length >= MAX_COMMANDS_PER_INSTALLATION) return res.status(503).json({ ok: false, error: "queue_full" });
  const ttl = Number.isInteger(body.ttl_sec) ? Math.max(60, Math.min(body.ttl_sec, DEFAULT_COMMAND_TTL_SEC)) : DEFAULT_COMMAND_TTL_SEC;
  const item = { command_id: commandId, installation_id: installationId, kind, created_at: nowSec(), expires_at: nowSec() + ttl, payload, signature };
  list.push(item);
  commandsByInstallation.set(installationId, list);
  commandIds.add(commandId);
  return res.status(202).json({ ok: true, command_id: commandId });
});

app.get("/v1/manager/commands", requireManager, (req, res) => {
  purgeExpired();
  const installationId = req.autsysManager.installation_id;
  const list = commandsByInstallation.get(installationId) || [];
  return res.json({ ok: true, count: list.length, items: list });
});

app.post("/v1/central/commands/ack", requireCentral, (req, res) => {
  const ids = Array.isArray(req.body?.command_ids) ? req.body.command_ids.filter(isSafeId).slice(0, MAX_BATCH) : [];
  if (ids.length === 0) return res.status(400).json({ ok: false, error: "invalid_command_ids" });
  const wanted = new Set(ids);
  let removed = 0;
  for (const [installationId, list] of commandsByInstallation.entries()) {
    const kept = [];
    for (const item of list) {
      if (wanted.has(item.command_id)) {
        commandIds.delete(item.command_id);
        removed += 1;
      } else kept.push(item);
    }
    if (kept.length === 0) commandsByInstallation.delete(installationId);
    else commandsByInstallation.set(installationId, kept);
  }
  return res.json({ ok: true, removed });
});

app.get("/diag", requireCentral, (req, res) => {
  purgeExpired();
  let commandCount = 0;
  for (const list of commandsByInstallation.values()) commandCount += list.length;
  let cachedBytes = 0;
  for (const item of packagesByRelease.values()) cachedBytes += item.size_bytes;
  return res.json({
    ok: true,
    service: "autsys-central-relay",
    version: VERSION,
    protocol: PROTOCOL,
    ts: nowSec(),
    manager_events_queued: events.length,
    manager_installations_with_commands: commandsByInstallation.size,
    commands_queued: commandCount,
    package_cache_items: packagesByRelease.size,
    package_cache_bytes: cachedBytes,
    package_tickets: packageTickets.size,
    persistence: "memory+ephemeral_package_files",
    authoritative: false
  });
});

app.use((req, res) => res.status(404).json({ ok: false, error: "not_found" }));
app.use((err, req, res, next) => {
  if (err?.type === "entity.too.large") return res.status(413).json({ ok: false, error: "payload_too_large" });
  if (err instanceof SyntaxError) return res.status(400).json({ ok: false, error: "invalid_json" });
  return res.status(500).json({ ok: false, error: "internal_error" });
});

app.listen(port, () => {
  console.log(`AUTSYS Central Relay ${VERSION} listening on port ${port}`);
});
