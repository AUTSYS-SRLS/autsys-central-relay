import test from "node:test";
import assert from "node:assert/strict";
import { createClient } from "redis";
import { createMessageStore } from "../message-store.js";

const URL = process.env.AUTSYS_TEST_REDIS_URL;
const item = (id, installation_id="device-1", kind="example") => ({
  event_id:id,command_id:id,installation_id,kind,payload:{message:id},
  signature:"signature",created_at:Math.floor(Date.now()/1000),
  expires_at:Math.floor(Date.now()/1000)+3600
});

async function withStore(t,fn) {
  if (!URL) { t.skip("Set AUTSYS_TEST_REDIS_URL to run real Redis integration tests"); return; }
  const client=createClient({url:URL,disableOfflineQueue:true});
  client.on("error",()=>{});
  await client.connect();
  const prefix="autsys:relay-mailbox:test:"+process.pid+":"+Math.random().toString(36).slice(2)+":";
  try { await fn(client,prefix); }
  finally {
    const keys=await client.keys(prefix+"*");
    if(keys.length)await client.del(keys);
    await client.quit();
  }
}

test("202 is durable across store recreation and ACK removes only the confirmed message",async t=>{
 await withStore(t,async(client,prefix)=>{
  const first=createMessageStore(client,{prefix});
  const a=item("evt-a"),b=item("evt-b");
  assert.equal(await first.enqueue("events",a,{id:"evt-a"}),"accepted");
  assert.equal(await first.enqueue("events",b,{id:"evt-b"}),"accepted");
  // Simulates a Relay restart: all in-process state is discarded.
  const restarted=createMessageStore(client,{prefix});
  assert.deepEqual((await restarted.list("events")).map(x=>x.event_id).sort(),["evt-a","evt-b"]);
  assert.equal(await restarted.ack("events",["evt-a"]),1);
  assert.deepEqual((await first.list("events")).map(x=>x.event_id),["evt-b"]);
  assert.equal(await restarted.ack("events",["evt-a"]),0);
  // Deduplication survives ACK, so retries cannot resurrect an already processed message.
  assert.equal(await restarted.enqueue("events",a,{id:"evt-a"}),"duplicate");
 });
});

test("parallel duplicate submissions write exactly once",async t=>{
 await withStore(t,async(client,prefix)=>{
  const store=createMessageStore(client,{prefix}),x=item("command-one");
  const results=await Promise.all(Array.from({length:24},()=>store.enqueue("commands",x,{id:"command-one",scope:"device-1",maxPerScope:500})));
  assert.equal(results.filter(x=>x==="accepted").length,1);
  assert.equal(results.filter(x=>x==="duplicate").length,23);
  assert.equal((await store.list("commands",{scope:"device-1"})).length,1);
 });
});

test("commands are isolated per installation and scope capacity is enforced",async t=>{
 await withStore(t,async(client,prefix)=>{
  const store=createMessageStore(client,{prefix});
  assert.equal(await store.enqueue("commands",item("a","device-a"),{id:"a",scope:"device-a",maxPerScope:1}),"accepted");
  assert.equal(await store.enqueue("commands",item("b","device-a"),{id:"b",scope:"device-a",maxPerScope:1}),"full");
  assert.equal(await store.enqueue("commands",item("c","device-b"),{id:"c",scope:"device-b",maxPerScope:1}),"accepted");
  assert.deepEqual((await store.list("commands",{scope:"device-a"})).map(x=>x.command_id),["a"]);
  assert.deepEqual((await store.list("commands",{scope:"device-b"})).map(x=>x.command_id),["c"]);
  assert.equal(await store.ack("commands",["a"]),1);
  assert.equal(await store.enqueue("commands",item("b","device-a"),{id:"b",scope:"device-a",maxPerScope:1}),"accepted");
 });
});

test("expired messages disappear, and original IDs become reusable only after expiry",async t=>{
 await withStore(t,async(client,prefix)=>{
  const store=createMessageStore(client,{prefix}),x=item("expires");
  x.expires_at=Math.floor(Date.now()/1000)+2;
  assert.equal(await store.enqueue("events",x,{id:"expires"}),"accepted");
  assert.equal(await store.enqueue("events",x,{id:"expires"}),"duplicate");
  await new Promise(resolve=>setTimeout(resolve,2500));
  assert.equal((await store.list("events")).length,0);
  assert.equal(await store.enqueue("events",item("expires"),{id:"expires"}),"accepted");
 });
});

test("Redis failure refuses acceptance instead of returning a false 202",async t=>{
 await withStore(t,async(client,prefix)=>{
  const failingStore=createMessageStore({eval:async()=>{throw new Error("redis_unavailable");}},{prefix});
  await assert.rejects(()=>failingStore.enqueue("events",item("event-outage"),{id:"event-outage"}),/redis_unavailable/);
 });
});
