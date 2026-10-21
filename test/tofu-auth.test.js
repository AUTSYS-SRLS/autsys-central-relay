import assert from "node:assert/strict";
import crypto from "node:crypto";
import { spawn } from "node:child_process";
import { createServer } from "node:net";
import { once } from "node:events";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { createClient } from "redis";
import { createBindingStore } from "../manager-binding-store.js";

const url = process.env.AUTSYS_TEST_REDIS_URL;
const prefix = "autsys:manager-binding:v1:";
const IDs = [
  "11111111-1111-4111-8111-111111111111",
  "22222222-2222-4222-8222-222222222222",
  "33333333-3333-4333-8333-333333333333",
  "44444444-4444-4444-8444-444444444444"
];
const A = "A".repeat(43);
const B = "B".repeat(43);
const C = "C".repeat(43);
const CENTRAL = "central-test-credential";
const TOKEN = "manager-test-credential";
const repo = path.dirname(fileURLToPath(new URL("../server.js", import.meta.url)));

if (!url) {
  test("TOFU integration requires AUTSYS_TEST_REDIS_URL", { skip: "Redis integration service is not configured" }, () => {});
} else {
  let redis;
  const stores = [];
  let processHandle;
  let base;

  before(async () => {
    redis = createClient({url});
    redis.on("error", () => {});
    await redis.connect();
    await redis.del(IDs.map(id => prefix + id));
  });
  after(async () => {
    if (processHandle) await stop();
    for (const store of stores) await store.close();
    if (redis?.isReady) {
      await redis.del(IDs.map(id => prefix + id));
      await redis.quit();
    }
  });

  async function port() {
    const server = createServer();
    await new Promise(done => server.listen(0, "127.0.0.1", done));
    const result = server.address().port;
    await new Promise(done => server.close(done));
    return result;
  }
  async function http(route, method = "GET", body = null, headers = {}) {
    const init = {method, headers: {...headers}};
    if (body !== null) {
      init.headers["content-type"] = "application/json";
      init.body = JSON.stringify(body);
    }
    const response = await fetch(base + route, init);
    return {status: response.status, data: await response.json()};
  }
  async function start() {
    base = "http://127.0.0.1:" + (await port());
    const {port: p} = new URL(base);
    processHandle = spawn(process.execPath, ["server.js"], {
      cwd: repo,
      stdio: "ignore",
      env: {
        ...process.env,
      AUTSYS_RELAY_MESSAGES_REDIS_URL: process.env.AUTSYS_TEST_REDIS_URL,
      AUTSYS_RELAY_MESSAGES_PREFIX: "test:relay:tofu-auth.test",
        PORT: p,
        AUTSYS_CENTRAL_RELAY_KEY: CENTRAL,
        AUTSYS_MANAGER_TOKEN_KEY: TOKEN,
        AUTSYS_MANAGER_BINDINGS_JSON: "",
        AUTSYS_MANAGER_BINDING_MODE: "TOFU",
        AUTSYS_MANAGER_BINDINGS_REDIS_URL: url
      }
    });
    for (let i = 0; i < 120; i++) {
      if (processHandle.exitCode !== null) throw Error("Relay terminated on startup");
      try {
        if ((await http("/health")).status === 200) return;
      } catch { /* transient startup */ }
      await new Promise(done => setTimeout(done, 50));
    }
    throw Error("Relay startup timed out");
  }
  async function stop() {
    if (!processHandle) return;
    const p = processHandle;
    processHandle = null;
    if (p.exitCode !== null) return;
    p.kill();
    await once(p, "exit");
  }
  function boot(id, secret, platform="WINDOWS") {
    return http("/v1/manager/bootstrap", "POST", {
      installation_id: id,
      binding_secret: secret,
      platform,
      product_code: "AUTSYS_MANAGER",
      manager_version: platform === "WINDOWS" ? "1.0.0.20" : "1.0.0.35"
    });
  }
  function signedToken(id, secret, platform="WINDOWS") {
    const payload = {
      installation_id: id,
      purpose: "manager-relay",
      platform,
      token_version: 2,
      binding_sha256: crypto.createHash("sha256").update(secret).digest("base64url"),
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 300
    };
    const p = Buffer.from(JSON.stringify(payload)).toString("base64url");
    const sig = crypto.createHmac("sha256", TOKEN).update(p).digest("base64url");
    return p + "." + sig;
  }
  function auth(id, secret, platform="WINDOWS") {
    return {authorization: "Bearer " + signedToken(id, secret, platform), "x-autsys-binding": secret};
  }

  test("atomic first key wins and changing it or its platform is rejected", async () => {
    const store1 = createBindingStore({url});
    const store2 = createBindingStore({url});
    stores.push(store1,store2);
    assert.equal(await store1.verify(IDs[0], "WINDOWS", A), true);
    assert.equal(await store2.verify(IDs[0], "WINDOWS", A), true);
    assert.equal(await store1.verify(IDs[0], "WINDOWS", B), false);
    assert.equal(await store1.verify(IDs[0], "ANDROID", A), false);
    const result = await Promise.all([
      store1.verify(IDs[1], "ANDROID", B),
      store2.verify(IDs[1], "ANDROID", C)
    ]);
    assert.equal(result.filter(Boolean).length, 1);
    const saved = JSON.parse(await redis.get(prefix + IDs[0]));
    assert.equal(saved.platform, "WINDOWS");
    assert.equal(saved.binding_sha256, crypto.createHash("sha256").update(A).digest("base64url"));
    assert.equal((await redis.ttl(prefix + IDs[0])), -1);
  });

  test("existing Manager bootstrap and authenticated requests pin only the first key", async () => {
    await start();
    const first = await boot(IDs[2], A);
    assert.equal(first.status, 201);
    assert.ok(first.data.relay_token);
    assert.equal((await boot(IDs[2], A)).status, 201);
    assert.equal((await boot(IDs[2], B)).status, 401);
    assert.equal((await boot(IDs[2], A, "ANDROID")).status, 401);

    const good = await http("/v1/manager/commands", "GET", null, auth(IDs[2], A));
    assert.equal(good.status, 200);
    assert.equal((await http("/v1/manager/commands", "GET", null, auth(IDs[2], B))).status, 401);

    const cmd = await http("/v1/central/commands", "POST", {
      command_id:"test-pinned-1",installation_id:IDs[2],kind:"test",payload:{},signature:"signed"
    }, {authorization: "Bearer " + CENTRAL});
    assert.equal(cmd.status, 202);
    assert.equal((await http("/v1/manager/commands", "GET", null, auth(IDs[2], A))).data.count, 1);

    // Existing token can pin the first key without re-bootstrap.
    assert.equal((await http("/v1/manager/commands", "GET", null, auth(IDs[3], C, "ANDROID"))).status, 200);
    assert.equal((await boot(IDs[3], C, "ANDROID")).status, 201);
    assert.equal((await boot(IDs[3], B, "ANDROID")).status, 401);
  });

  test("registry and Manager credentials survive Relay process restart", async () => {
    await stop();
    await start();
    assert.equal((await boot(IDs[2], A)).status, 201);
    assert.equal((await boot(IDs[2], B)).status, 401);
    assert.equal((await http("/v1/manager/commands", "GET", null, auth(IDs[3], C, "ANDROID"))).status, 200);
  });
}

