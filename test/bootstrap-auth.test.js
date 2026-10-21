import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { spawn } from 'node:child_process';
import { createServer } from 'node:net';
import { after, before, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { loadApprovedManagerBindings, isApprovedManagerBinding, isApprovedManagerSession } from '../manager-bindings.js';

const MESSAGE_PREFIX = `test:relay:bootstrap-auth.test:${process.pid}:${Date.now()}`;
const repo = path.dirname(fileURLToPath(new URL('../server.js', import.meta.url)));
const ANDROID_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const WINDOWS_ID = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const UNKNOWN_ID = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const ANDROID_SECRET = 'A'.repeat(43);
const WINDOWS_SECRET = 'W'.repeat(43);
const ATTACKER_SECRET = 'X'.repeat(43);
const CENTRAL_KEY = 'central-test-secret-not-for-production';
const MANAGER_KEY = 'manager-test-secret-not-for-production';
const hashed = (s) => crypto.createHash('sha256').update(s).digest('base64url');
const approvals = {
  [ANDROID_ID]: { platform: 'ANDROID', binding_sha256: hashed(ANDROID_SECRET) },
  [WINDOWS_ID]: { platform: 'WINDOWS', binding_sha256: hashed(WINDOWS_SECRET) }
};
let serverProcess;
let address;

async function freePort() {
  const server = createServer();
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return port;
}
async function call(route, method = 'GET', body = null, headers = {}) {
  const opts = { method, headers: { ...headers } };
  if (body !== null) {
    opts.headers['content-type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  const response = await fetch(address + route, opts);
  return { status: response.status, json: await response.json() };
}
async function startRelay() {
  const port = await freePort();
  address = `http://127.0.0.1:${port}`;
  serverProcess = spawn(process.execPath, ['server.js'], {
    cwd: repo,
    env: {
      ...process.env,
      AUTSYS_RELAY_MESSAGES_REDIS_URL: process.env.AUTSYS_TEST_REDIS_URL,
      AUTSYS_RELAY_MESSAGES_PREFIX: MESSAGE_PREFIX,
      PORT: String(port),
      AUTSYS_MANAGER_TOKEN_KEY: MANAGER_KEY,
      AUTSYS_CENTRAL_RELAY_KEY: CENTRAL_KEY,
      AUTSYS_MANAGER_BINDINGS_JSON: JSON.stringify(approvals)
    },
    stdio: 'ignore'
  });
  for (let i = 0; i < 120; i += 1) {
    if (serverProcess.exitCode !== null) throw new Error(`Relay exited: ${serverProcess.exitCode}`);
    try {
      const result = await call('/health');
      if (result.status === 200) return;
    } catch { /* wait for server */ }
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  throw new Error('Relay startup timed out');
}
function bootstrap(installationId, platform, bindingSecret, managerVersion) {
  return call('/v1/manager/bootstrap', 'POST', {
    installation_id: installationId,
    product_code: 'AUTSYS_MANAGER',
    manager_version: managerVersion,
    platform,
    binding_secret: bindingSecret
  });
}
function signedToken(installationId, platform, bindingSecret, includeBinding = true) {
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    installation_id: installationId,
    purpose: 'manager-relay',
    platform,
    token_version: 2,
    ...(includeBinding ? { binding_sha256: hashed(bindingSecret) } : {}),
    iat: now,
    exp: now + 300
  };
  const p64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const s64 = crypto.createHmac('sha256', MANAGER_KEY).update(p64).digest('base64url');
  return p64 + '.' + s64;
}
function authorization(token, binding) {
  return { authorization: 'Bearer ' + token, 'x-autsys-binding': binding };
}

before(startRelay);
after(() => { if (serverProcess) serverProcess.kill(); });

test('registry validates hashes and defaults to no trust', () => {
  assert.equal(loadApprovedManagerBindings('').size, 0);
  assert.throws(() => loadApprovedManagerBindings('{invalid'), /invalid_AUTSYS_MANAGER_BINDINGS_JSON/);
  assert.throws(() => loadApprovedManagerBindings(JSON.stringify({
    [ANDROID_ID]: { platform: 'ANDROID', binding_sha256: 'fake' }
  })), /invalid_manager_binding_record/);
  const r = loadApprovedManagerBindings(JSON.stringify(approvals));
  assert.equal(isApprovedManagerBinding(r, ANDROID_ID, 'ANDROID', ANDROID_SECRET), true);
  assert.equal(isApprovedManagerBinding(r, ANDROID_ID, 'ANDROID', ATTACKER_SECRET), false);
  assert.equal(isApprovedManagerBinding(r, UNKNOWN_ID, 'ANDROID', ANDROID_SECRET), false);
  assert.equal(isApprovedManagerSession(r, {
    installation_id: ANDROID_ID, platform: 'ANDROID', binding_sha256: hashed(ANDROID_SECRET)
  }, ANDROID_SECRET), true);
  assert.equal(isApprovedManagerSession(r, { installation_id: ANDROID_ID, platform: 'ANDROID' }, ANDROID_SECRET), false);
});

test('existing Android and Windows Manager bootstrap protocols remain unchanged', async () => {
  const android = await bootstrap(ANDROID_ID, 'ANDROID', ANDROID_SECRET, '1.0.0.22');
  const windows = await bootstrap(WINDOWS_ID, 'WINDOWS', WINDOWS_SECRET, '1.0.0.20');
  assert.equal(android.status, 201);
  assert.equal(windows.status, 201);
  assert.ok(android.json.relay_token && windows.json.relay_token);
  const response = await call('/v1/manager/commands', 'GET', null, authorization(android.json.relay_token, ANDROID_SECRET));
  assert.equal(response.status, 200);
  assert.equal(response.json.count, 0);
});

test('known installation ID with attacker-selected secret cannot bootstrap', async () => {
  const r = await bootstrap(ANDROID_ID, 'ANDROID', ATTACKER_SECRET, '1.0.0.35');
  assert.equal(r.status, 401);
});

test('unknown ID or wrong platform cannot bootstrap', async () => {
  assert.equal((await bootstrap(UNKNOWN_ID, 'ANDROID', ATTACKER_SECRET, '1.0.0.35')).status, 401);
  assert.equal((await bootstrap(WINDOWS_ID, 'ANDROID', WINDOWS_SECRET, '1.0.0.20')).status, 401);
});

test('existing tokens remain usable only when their binding is approved', async () => {
  const okay = await call('/v1/manager/commands', 'GET', null, authorization(
    signedToken(WINDOWS_ID, 'WINDOWS', WINDOWS_SECRET), WINDOWS_SECRET
  ));
  assert.equal(okay.status, 200);
  const forged = await call('/v1/manager/commands', 'GET', null, authorization(
    signedToken(WINDOWS_ID, 'WINDOWS', ATTACKER_SECRET), ATTACKER_SECRET
  ));
  assert.equal(forged.status, 401);
  const unbound = await call('/v1/manager/commands', 'GET', null, {
    authorization: 'Bearer ' + signedToken(WINDOWS_ID, 'WINDOWS', WINDOWS_SECRET, false)
  });
  assert.equal(unbound.status, 401);
});

test('only the approved device can retrieve queued commands', async () => {
  const posted = await call('/v1/central/commands', 'POST', {
    command_id: 'security-test-command',
    installation_id: ANDROID_ID,
    kind: 'test_command',
    payload: { action: 'noop' },
    signature: 'test-signature'
  }, { authorization: 'Bearer ' + CENTRAL_KEY });
  assert.equal(posted.status, 202);
  const legit = await bootstrap(ANDROID_ID, 'ANDROID', ANDROID_SECRET, '1.0.0.35');
  assert.equal(legit.status, 201);
  const inbox = await call('/v1/manager/commands', 'GET', null, authorization(legit.json.relay_token, ANDROID_SECRET));
  assert.equal(inbox.status, 200);
  assert.equal(inbox.json.count, 1);
  const forged = await call('/v1/manager/commands', 'GET', null, authorization(
    signedToken(ANDROID_ID, 'ANDROID', ATTACKER_SECRET), ATTACKER_SECRET
  ));
  assert.equal(forged.status, 401);
  const win = await bootstrap(WINDOWS_ID, 'WINDOWS', WINDOWS_SECRET, '1.0.0.20');
  const winInbox = await call('/v1/manager/commands', 'GET', null, authorization(win.json.relay_token, WINDOWS_SECRET));
  assert.equal(winInbox.status, 200);
  assert.equal(winInbox.json.count, 0);
});

test('event injection using an impersonated token is rejected', async () => {
  const forged = await call('/v1/manager/events', 'POST', {
    event_id: 'forged-event-test', kind: 'manager_heartbeat',
    payload: { installation_id: ANDROID_ID }
  }, authorization(signedToken(ANDROID_ID, 'ANDROID', ATTACKER_SECRET), ATTACKER_SECRET));
  assert.equal(forged.status, 401);
});

