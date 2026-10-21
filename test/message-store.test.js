import assert from "node:assert/strict";
import crypto from "node:crypto";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { createServer, createConnection } from "node:net";
import { after, before, test } from "node:test";
import { createClient } from "redis";
import { createMessageStore } from "../message-store.js";

const url = process.env.AUTSYS_TEST_REDIS_URL;
const root = new URL("../", import.meta.url);
const WINDOWS = "66666666-6666-4666-8666-666666666666";
const ANDROID = "77777777-7777-4777-8777-777777777777";
const secret = "M".repeat(43);
const key = "queue-test-manager-key";
const central = { authorization: "Bearer queue-test-central" };
const prefix = `test:relay:messages:${crypto.randomUUID()}`;
const connections = [], children = [];
let redis, a, b, server, origin;

async function freePort() {
  const net = createServer();
  await new Promise(done => net.listen(0, "127.0.0.1", done));
  const port = net.address().port;
  await new Promise(done => net.close(done));
  return port;
}
async function stop(child, signal = "SIGKILL") {
  if (child && child.exitCode === null && child.signalCode === null) {
    const exited = once(child, "exit"); child.kill(signal); await exited;
  }
}
async function connect() {
  const c = createClient({url, socket: {reconnectStrategy: false}, disableOfflineQueue: true});
  c.on("error", () => {}); await c.connect(); connections.push(c); return c;
}
async function call(route, method = "GET", body, headers = central, base = origin) {
  const r = await fetch(base + route, { method,
    headers: { ...headers, ...(body === undefined ? {} : {"content-type": "application/json"}) },
    body: body === undefined ? undefined : JSON.stringify(body) });
  return {status: r.status, data: await r.json()};
}
function manager(id, platform) {
  const payload = Buffer.from(JSON.stringify({purpose: "manager-relay", token_version: 2,
    installation_id: id, platform, binding_sha256: crypto.createHash("sha256").update(secret).digest("base64url"),
    exp: Math.floor(Date.now()/1000) + 600})).toString("base64url");
  return { authorization: `Bearer ${payload}.${crypto.createHmac("sha256", key).update(payload).digest("base64url")}`,
    "x-autsys-binding": secret };
}
const win = manager(WINDOWS, "WINDOWS"), android = manager(ANDROID, "ANDROID");
async function start(extra = {}) {
  const port = await freePort(); const base = `http://127.0.0.1:${port}`;
  const hash = crypto.createHash("sha256").update(secret).digest("base64url");
  const child = spawn(process.execPath, ["server.js"], { cwd: root, stdio: "ignore",
    env: {...process.env, PORT: String(port), AUTSYS_MANAGER_BINDING_MODE: "PREAPPROVED",
      AUTSYS_RELAY_LICENSE_ENFORCEMENT: "OFF", AUTSYS_RELAY_MESSAGES_REDIS_URL: url,
      AUTSYS_RELAY_MESSAGES_PREFIX: prefix, AUTSYS_MANAGER_TOKEN_KEY: key,
      AUTSYS_CENTRAL_RELAY_KEY: "queue-test-central", AUTSYS_MANAGER_BINDINGS_JSON: JSON.stringify({
        [WINDOWS]: {platform:"WINDOWS", binding_sha256:hash},
        [ANDROID]: {platform:"ANDROID", binding_sha256:hash}}), ...extra } });
  children.push(child);
  for (let i=0; i<100; i++) {
    if (child.exitCode !== null) throw new Error("relay_startup_failed");
    try { if ((await call("/health", "GET", undefined, {}, base)).status === 200) return {child, base}; } catch {}
    await new Promise(done => setTimeout(done, 30));
  }
  throw new Error("relay_startup_timeout");
}
function event(id, owner = WINDOWS) {
  return {event_id: id, installation_id: owner, kind:"update_result", ts: 123,
    received_at: Math.floor(Date.now()/1000), expires_at: Math.floor(Date.now()/1000)+60,
    payload:{ empty: {}, array: [], nested: [1, {x:"è"}] }, signature:""};
}
function command(id, owner = WINDOWS) {
  return {command_id:id, installation_id:owner, kind:"admin_device_command",
    created_at: Math.floor(Date.now()/1000), expires_at: Math.floor(Date.now()/1000)+60,
    payload:{action:"SYNC_STATE"}, signature:"opaque-signed-by-centrale"};
}

if (!url) {
  test("durable queue integration requires AUTSYS_TEST_REDIS_URL", {skip:true}, () => {});
} else {
  before(async () => {
    redis = await connect();
    const other = await connect();
    a = createMessageStore({connection:{ready:async()=>redis}, prefix});
    b = createMessageStore({connection:{ready:async()=>other}, prefix});
  });
  after(async () => {
    for (const child of children) await stop(child);
    const keys = [];
    for await (const batch of redis.scanIterator({MATCH:prefix+":*", COUNT:100})) keys.push(...batch);
    if (keys.length) await redis.del(keys);
    for (const c of connections) if (c.isOpen) await c.quit();
  });

  test("HTTP 202 survives SIGKILL; GET redelivers unchanged until durable ACK, for Windows and Android", async () => {
    ({child:server,base:origin} = await start());
    for (const [owner, auth] of [[WINDOWS,win],[ANDROID,android]]) {
      const e = event("http-event-"+owner,owner);
      assert.equal((await call("/v1/manager/events","POST",e,auth)).status,202);
      assert.equal((await call("/v1/central/commands","POST",command("http-command-"+owner,owner))).status,202);
    }
    const original = (await call("/v1/central/events")).data.items;
    assert.equal(original.length,2);
    const originalCommands = (await call("/v1/manager/commands","GET",undefined,win)).data.items;
    await stop(server);
    ({child:server,base:origin} = await start());
    assert.deepEqual((await call("/v1/central/events")).data.items,original);
    assert.deepEqual((await call("/v1/manager/commands","GET",undefined,win)).data.items,originalCommands);
    assert.deepEqual((await call("/v1/central/events")).data.items,original,"GET must not consume messages");
    assert.equal((await call("/v1/central/events?limit=1")).data.count,1);
    assert.equal((await call("/v1/manager/commands","GET",undefined,android)).data.items[0].installation_id,ANDROID);
    assert.equal((await call("/v1/central/commands","POST",command("http-command-"+WINDOWS))).data.duplicate,true);
    assert.equal((await call("/v1/manager/events","POST",event("http-event-"+WINDOWS),win)).data.duplicate,true);
    for (const type of ["events","commands"]) {
      const ids = type === "events" ? original.map(x=>x.event_id) : ["http-command-"+WINDOWS,"http-command-"+ANDROID];
      const body = {[type === "events" ? "event_ids" : "command_ids"]:ids};
      assert.equal((await call(`/v1/central/${type}/ack`,"POST",body)).data.removed,2);
      assert.equal((await call(`/v1/central/${type}/ack`,"POST",body)).data.removed,0);
    }
    await stop(server);
    ({child:server,base:origin} = await start());
    assert.equal((await call("/v1/central/events")).data.count,0);
    assert.equal((await call("/v1/manager/commands","GET",undefined,win)).data.count,0);
    // Centrale retries FAILED updates with the same logical command ID after ACK.
    assert.equal((await call("/v1/central/commands","POST",command("http-command-"+WINDOWS))).status,202);
    await a.ack("commands",["http-command-"+WINDOWS]);
  });

  test("lost HTTP response can be retried after restart without duplicate delivery", async () => {
    const endpoint = new URL(origin);
    const socket = createConnection({host:"127.0.0.1",port:Number(endpoint.port)});
    socket.on("error",()=>{});
    await once(socket,"connect");
    const body=JSON.stringify(command("response-never-read"));
    // Do not read the response: the sender cannot know the acceptance result.
    socket.pause();
    socket.write(`POST /v1/central/commands HTTP/1.1\r\nHost: localhost\r\nAuthorization: ${central.authorization}\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`);
    try {
      let accepted=false;
      for(let i=0;i<100;i++) {
        if((await a.read("commands",WINDOWS)).some(x=>x.command_id==="response-never-read")){accepted=true;break;}
        await new Promise(done=>setTimeout(done,20));
      }
      assert.equal(accepted,true);
      await stop(server); socket.destroy();
      ({child:server,base:origin}=await start());
      const retry=await call("/v1/central/commands","POST",command("response-never-read"));
      assert.equal(retry.status,200);assert.equal(retry.data.duplicate,true);
      assert.equal((await a.read("commands",WINDOWS)).length,1);
      await a.ack("commands",["response-never-read"]);
    } finally {socket.destroy();}
  });

  test("two independent Relay instances atomically deduplicate concurrent submissions", async () => {
    const second = await start();
    const commands = await Promise.all(Array.from({length:20},(_,i)=>call("/v1/central/commands","POST",
      command("parallel-http"),central,i%2 ? origin : second.base)));
    assert.equal(commands.filter(x=>x.status===202).length,1);
    assert.equal(commands.filter(x=>x.status===200 && x.data.duplicate).length,19);
    const events = await Promise.all(Array.from({length:20},(_,i)=>call("/v1/manager/events","POST",
      event("parallel-event"),win,i%2 ? origin : second.base)));
    assert.equal(events.filter(x=>x.status===202).length,1);
    assert.equal((await a.read("events")).length,1);
    await a.ack("events",["parallel-event"]); await a.ack("commands",["parallel-http"]);
    await stop(second.child);
  });

  test("concurrent capacity checks never evict an accepted event or command", async () => {
    const es = await Promise.all(Array.from({length:30},(_,i)=>(i%2?a:b).enqueue("events",event("capacity-e-"+i),60,7)));
    assert.equal(es.filter(x=>x==="accepted").length,7);
    assert.equal(es.filter(x=>x==="full").length,23);
    const kept = await a.read("events");
    assert.equal(await a.enqueue("events",kept[0],60,7),"duplicate","duplicate succeeds even when full");
    assert.deepEqual((await b.read("events")).map(x=>x.event_id),kept.map(x=>x.event_id));
    assert.deepEqual(kept[0].payload,event("x").payload,"JSON arrays and empty objects stay unchanged");
    await a.ack("events",kept.map(x=>x.event_id));
    for (const owner of [WINDOWS,ANDROID]) {
      const cs = await Promise.all(Array.from({length:20},(_,i)=>(i%2?a:b).enqueue("commands",command(`capacity-c-${owner}-${i}`,owner),60,3)));
      assert.equal(cs.filter(x=>x==="accepted").length,3);
    }
    assert.deepEqual(await a.stats(),{events:0,commands:6,installations:2,tickets:0});
    for (const owner of [WINDOWS,ANDROID]) await a.ack("commands",(await a.read("commands",owner)).map(x=>x.command_id));
  });

  test("ACK races cannot erase a different newly submitted message; repeated ACK is idempotent", async () => {
    await a.enqueue("events",event("old"),60,100);
    const result = await Promise.all([a.ack("events",["old","old"]),b.ack("events",["old"]),
      b.enqueue("events",event("new"),60,100)]);
    assert.equal(result[0]+result[1],1);
    assert.deepEqual((await a.read("events")).map(x=>x.event_id),["new"]);
    await a.ack("events",["new"]);
  });

  test("expiration is persistent and duplicate retries do not extend TTL", async () => {
    for (const type of ["events","commands"]) {
      const item = type === "events" ? event("ttl") : command("ttl");
      await a.enqueue(type,item,60,100);
      const expiry = await redis.zScore(`${prefix}:${type}:expiry`,"ttl");
      assert.equal(await b.enqueue(type,item,86400,100),"duplicate");
      assert.equal(await redis.zScore(`${prefix}:${type}:expiry`,"ttl"),expiry);
      // Move only the expiry score to the past: reproducible without a 60s wait.
      await redis.zAdd(`${prefix}:${type}:expiry`,{score:1,value:"ttl"});
      assert.deepEqual(await b.read(type,type === "commands" ? WINDOWS : ""),[]);
      assert.equal(await a.ack(type,["ttl"]),0);
      assert.equal(await a.enqueue(type,item,60,100),"accepted");
      await a.ack(type,["ttl"]);
    }
    const posted = await call("/v1/manager/events","POST",{...event("clamp"),ttl_sec:0},win);
    assert.equal(posted.status,202);
    const item = (await a.read("events"))[0];
    assert.ok(item.expires_at-Math.floor(Date.now()/1000)>=59);
    await a.ack("events",["clamp"]);
  });

  test("persisted download tickets remain valid when Centrale reuploads a lost package cache", async () => {
    const release = "88888888-8888-4888-8888-888888888888";
    const bytes = Buffer.from("test-zip-bytes");
    async function upload() {
      const r = await fetch(origin+"/v1/central/packages/"+release,{method:"PUT",headers:{...central,
        "content-type":"application/octet-stream", "x-autsys-sha256":crypto.createHash("sha256").update(bytes).digest("hex"),
        "x-autsys-size":String(bytes.length)},body:bytes});
      assert.ok([200,201].includes(r.status),await r.text());
    }
    await upload();
    const ticket = await call("/v1/central/package-tickets","POST",{release_id:release,installation_id:WINDOWS});
    assert.equal(ticket.status,201);
    const route = new URL(ticket.data.download_url).pathname;
    await stop(server); ({child:server,base:origin} = await start());
    await upload(); // same automatic recovery used by Centrale's heartbeat path
    const downloaded = await fetch(origin+route);
    assert.equal(downloaded.status,200);
    assert.deepEqual(Buffer.from(await downloaded.arrayBuffer()),bytes);
  });

  test("Redis failure yields 503 for queue operations and never volatile 202", async () => {
    const username = "queue-test-"+crypto.randomUUID();
    const password = crypto.randomBytes(16).toString("hex");
    await redis.sendCommand(["ACL","SETUSER",username,"on",">"+password,"~"+prefix+":*","+@all"]);
    const restrictedUrl = new URL(url); restrictedUrl.username=username; restrictedUrl.password=password;
    const broken = await start({AUTSYS_RELAY_MESSAGES_REDIS_URL:restrictedUrl.href});
    try {
      assert.equal((await call("/v1/central/commands","POST",command("stored-before-failure"),central,broken.base)).status,202);
      await redis.sendCommand(["ACL","SETUSER",username,"-eval"]);
      for (const [route,method,body,auth] of [
        ["/v1/central/commands","POST",command("never-accepted"),central],
        ["/v1/manager/events","POST",event("never-accepted"),win],
        ["/v1/central/events","GET",undefined,central],
        ["/v1/manager/commands","GET",undefined,win],
        ["/v1/central/commands/ack","POST",{command_ids:["stored-before-failure"]},central],
        ["/v1/central/events/ack","POST",{event_ids:["never-accepted"]},central]
      ]) {
        const response = await call(route,method,body,auth,broken.base);
        assert.equal(response.status,503);
        assert.equal(response.data.error,"message_store_unavailable");
      }
      assert.deepEqual((await a.read("commands",WINDOWS)).map(x=>x.command_id),["stored-before-failure"]);
      assert.deepEqual(await a.read("events"),[]);
      await redis.sendCommand(["ACL","SETUSER",username,"+eval"]);
      assert.equal((await call("/v1/manager/commands","GET",undefined,win,broken.base)).data.count,1);
      await a.ack("commands",["stored-before-failure"]);
    } finally {
      await stop(broken.child);
      await redis.sendCommand(["ACL","DELUSER",username]);
    }
  });
}
