import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:net";
import { createClient } from "redis";

const centralToken="local-test-central-redis-inspection";
const installation="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const bindingKey="autsys:manager-binding:v1:"+installation;
const licenseKey="autsys:central-relay:license-inventory:v1";
const pendingEventsKey="autsys:relay-mailbox:v1:events:pending";
async function getPort(){
  const s=createServer();
  await new Promise(resolve=>s.listen(0,"127.0.0.1",resolve));
  const p=s.address().port;
  await new Promise(resolve=>s.close(resolve));
  return p;
}
function testDatabaseUrl(url){
  const u=new URL(url||"redis://127.0.0.1:6379");
  u.pathname="/13";
  return u.toString();
}
async function stop(child) {
  if(!child || child.exitCode!==null)return;
  child.kill("SIGTERM");
  await Promise.race([
    new Promise(resolve=>child.once("exit",resolve)),
    new Promise(resolve=>setTimeout(resolve,2500))
  ]);
  if(child.exitCode===null)child.kill("SIGKILL");
}
test("Redis admin inspection uses only read calls and hides values and raw keys",async()=>{
  const redisUrl=testDatabaseUrl(process.env.AUTSYS_TEST_REDIS_URL);
  const client=createClient({url:redisUrl});
  client.on("error",()=>{});
  await client.connect();
  const port=await getPort();
  let child=null;
  const markers=[bindingKey,licenseKey,pendingEventsKey];
  try{
    await client.del(markers);
    const bindingValue=JSON.stringify({platform:"ANDROID",binding_sha256:"TEST_HASH_ONLY"});
    const licenseValue=JSON.stringify({
      schema:1,generated_at_ms:123,
      installations:{[installation]:{platform:"ANDROID",licenses:[]}}
    });
    await client.set(bindingKey,bindingValue);
    await client.set(licenseKey,licenseValue);
    await client.zAdd(pendingEventsKey,[{score:Math.floor(Date.now()/1000)+400,value:"synthetic-event"}]);
    const before={
      binding:await client.get(bindingKey),license:await client.get(licenseKey),
      queued:await client.zCard(pendingEventsKey),licenseTtl:await client.pTTL(licenseKey)
    };
    child=spawn(process.execPath,["server.js"],{
      cwd:process.cwd(),
      env:{...process.env,PORT:String(port),
        AUTSYS_CENTRAL_RELAY_KEY:centralToken,
        AUTSYS_MANAGER_TOKEN_KEY:"local-test-manager-key",
        AUTSYS_MANAGER_BINDING_MODE:"TOFU",
        AUTSYS_MANAGER_BINDINGS_REDIS_URL:redisUrl,
        AUTSYS_RELAY_MESSAGES_REDIS_URL:redisUrl,
        AUTSYS_RELAY_LICENSE_ENFORCEMENT:"OFF"},
      stdio:"ignore"
    });
    const base="http://127.0.0.1:"+port;
    let online=false;
    for(let i=0;i<100;i++){
      if(child.exitCode!==null)throw new Error("relay_child_exited");
      try{
        const res=await fetch(base+"/diag",{headers:{authorization:"Bearer "+centralToken}});
        if(res.ok){online=true;break;}
      }catch{}
      await new Promise(resolve=>setTimeout(resolve,50));
    }
    assert.equal(online,true);
    const unauthorized=await fetch(base+"/v1/central/redis/inspect");
    assert.equal(unauthorized.status,401);
    const authorized=await fetch(base+"/v1/central/redis/inspect",{
      headers:{authorization:"Bearer "+centralToken}
    });
    assert.equal(authorized.status,200);
    const report=await authorized.json();
    assert.equal(report.ok,true);
    assert.equal(report.read_only,true);
    assert.equal(report.ack_sent,false);
    assert.equal(report.purge_called,false);
    assert.equal(report.payloads_included,false);
    assert.equal(report.credentials_exposed,false);
    assert.equal(report.raw_keys_returned,false);
    assert.equal(report.redis.manager_binding_keys.count,1);
    assert.equal(report.redis.license_inventory.present,true);
    assert.equal(report.redis.license_inventory.bytes,Buffer.byteLength(licenseValue));
    assert.equal(report.redis.durable_events.present,true);
    assert.equal(report.redis.durable_events.pending,1);
    assert.equal(report.redis.durable_commands.present,false);
    assert.equal(report.redis.durable_commands.pending,null);
    assert.equal(report.current_transport.events,1);
    assert.equal(report.current_transport.commands,0);
    const serialized=JSON.stringify(report);
    assert.equal(serialized.includes(installation),false,"must not expose raw device IDs");
    assert.equal(serialized.includes("TEST_HASH_ONLY"),false,"must not expose value data");
    const after={
      binding:await client.get(bindingKey),license:await client.get(licenseKey),
      queued:await client.zCard(pendingEventsKey),licenseTtl:await client.pTTL(licenseKey)
    };
    assert.equal(after.binding,before.binding);
    assert.equal(after.license,before.license);
    assert.equal(after.queued,before.queued);
    assert.equal(after.licenseTtl,before.licenseTtl);
  } finally {
    await stop(child);
    await client.del(markers);
    await client.quit();
  }
});
