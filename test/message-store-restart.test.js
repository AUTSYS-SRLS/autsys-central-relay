import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createServer } from "node:net";
import { test } from "node:test";
import { createClient } from "redis";
import { createMessageStore } from "../message-store.js";

test("Redis AOF retains pending messages, ACKs and TTLs through SIGKILL and restart", async () => {
  const binary = process.env.AUTSYS_TEST_REDIS_SERVER || "redis-server";
  const dir = await mkdtemp(path.join(os.tmpdir(), "relay-aof-test-"));
  const net = createServer();
  await new Promise(done=>net.listen(0,"127.0.0.1",done));
  const port = net.address().port;
  await new Promise(done=>net.close(done));
  let child, connection;
  async function start() {
    child = spawn(binary,["--bind","127.0.0.1","--port",String(port),"--dir",dir,
      "--save","","--appendonly","yes","--appendfsync","always"],{stdio:["ignore","pipe","pipe"]});
    await new Promise((resolve,reject)=>{
      let logs="";
      const timer=setTimeout(()=>reject(new Error("Redis startup timeout: "+logs)),10000);
      child.once("error",err=>{clearTimeout(timer);reject(err);});
      child.once("exit",()=>{clearTimeout(timer);reject(new Error("Redis exited: "+logs));});
      child.stderr.on("data",chunk=>{logs+=chunk;});
      child.stdout.on("data",chunk=>{
        logs+=chunk;
        if(logs.includes("Ready to accept connections")){clearTimeout(timer);resolve();}
      });
    });
    connection=createClient({url:`redis://127.0.0.1:${port}`,socket:{reconnectStrategy:false}});
    connection.on("error",()=>{}); await connection.connect();
    return createMessageStore({connection:{ready:async()=>connection},prefix:"aof-queue-test"});
  }
  async function kill() {
    if (connection?.isOpen) connection.destroy();
    if (child?.exitCode===null && child?.signalCode===null) {
      const exited=once(child,"exit");child.kill("SIGKILL");await exited;
    }
  }
  try {
    let store=await start();
    const pending={event_id:"pending",installation_id:"device",kind:"support_request",payload:{text:"keep me"},expires_at:0};
    const retired={...pending,event_id:"retired"};
    const command={command_id:"admin",installation_id:"device",kind:"admin_device_command",payload:{action:"SYNC_STATE"},signature:"signed",expires_at:0};
    await store.enqueue("events",pending,60,10);
    await store.enqueue("events",retired,60,10);
    await store.enqueue("commands",command,60,10);
    assert.equal(await store.ack("events",["retired"]),1);
    const events=await store.read("events");
    const commands=await store.read("commands","device");
    await kill();
    store=await start();
    assert.deepEqual(await store.read("events"),events);
    assert.deepEqual(await store.read("commands","device"),commands);
    assert.equal(await store.enqueue("events",pending,86400,10),"duplicate");
    assert.deepEqual(await store.read("events"),events,"restart/retry must not refresh expiry");
    assert.equal(await store.ack("events",["retired"]),0);
  } finally {
    await kill(); await rm(dir,{recursive:true,force:true});
  }
});
