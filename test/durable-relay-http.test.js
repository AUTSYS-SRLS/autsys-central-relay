import assert from "node:assert/strict";
import crypto from "node:crypto";
import { spawn } from "node:child_process";
import { createServer } from "node:net";
import { test } from "node:test";
import { createClient } from "redis";

const REDIS_URL=process.env.AUTSYS_TEST_REDIS_URL;
const ID="dddddddd-dddd-4ddd-8ddd-dddddddddddd";
const SECRET="S".repeat(43);
const CENTRAL="integration-central-secret";
const TOKEN="integration-token-secret";
const hash=(s)=>crypto.createHash("sha256").update(s).digest("base64url");
const approvals=JSON.stringify({[ID]:{platform:"ANDROID",binding_sha256:hash(SECRET)}});
async function freePort(){
 const srv=createServer();
 await new Promise(resolve=>srv.listen(0,"127.0.0.1",resolve));
 const port=srv.address().port;
 await new Promise(resolve=>srv.close(resolve));
 return port;
}
function bearerToken(){
 const now=Math.floor(Date.now()/1000);
 const payload={installation_id:ID,purpose:"manager-relay",platform:"ANDROID",
   binding_sha256:hash(SECRET),iat:now,exp:now+600};
 const encoded=Buffer.from(JSON.stringify(payload)).toString("base64url");
 return encoded+"."+crypto.createHmac("sha256",TOKEN).update(encoded).digest("base64url");
}
test("HTTP acceptance, durable restart, ACK and redelivery remain protocol 2 compatible",async t=>{
 if(!REDIS_URL){t.skip("AUTSYS_TEST_REDIS_URL not set");return;}
 const prefix="autsys:relay-mailbox:http-test:"+process.pid+":"+crypto.randomUUID()+":";
 const port=await freePort(),url="http://127.0.0.1:"+port;
 let child=null;
 const redis=createClient({url:REDIS_URL,disableOfflineQueue:true});
 redis.on("error",()=>{});
 await redis.connect();
 const cleanup=async()=>{
  if(child){
   const old=child;child=null;
   if(old.exitCode===null){
    old.kill();
    await Promise.race([new Promise(resolve=>old.once("exit",resolve)),
      new Promise(resolve=>setTimeout(resolve,3000))]);
   }
  }
 };
 const req=async(method,uri,body,headers={})=>{
  const res=await fetch(url+uri,{method,headers:{"content-type":"application/json",...headers},body:body===undefined?undefined:JSON.stringify(body)});
  return {status:res.status,data:await res.json()};
 };
 const central={"authorization":"Bearer "+CENTRAL};
 const manager={"authorization":"Bearer "+bearerToken(),"x-autsys-binding":SECRET};
 const start=async()=>{
  child=spawn(process.execPath,["server.js"],{
   cwd:process.cwd(),
   env:{...process.env,PORT:String(port),AUTSYS_CENTRAL_RELAY_KEY:CENTRAL,
      AUTSYS_MANAGER_TOKEN_KEY:TOKEN,AUTSYS_MANAGER_BINDINGS_JSON:approvals,
      AUTSYS_MANAGER_BINDING_MODE:"PREAPPROVED",AUTSYS_RELAY_MESSAGES_REDIS_URL:REDIS_URL,
      AUTSYS_RELAY_MESSAGES_PREFIX:prefix},
   stdio:"ignore"
  });
  for(let i=0;i<100;i++){
   if(child.exitCode!==null)throw new Error("relay_exited_"+child.exitCode);
   try{const r=await req("GET","/health");if(r.status===200)return;}catch{}
   await new Promise(resolve=>setTimeout(resolve,50));
  }
  throw new Error("relay_start_timeout");
 };
 try{
  await start();
  const e={event_id:"http-event-1",kind:"manager_heartbeat",payload:{sample:true}};
  const c={command_id:"update:integration-1",installation_id:ID,kind:"update_available",payload:{sample:true},signature:"test-signature"};
  assert.equal((await req("POST","/v1/manager/events",e,manager)).status,202);
  assert.equal((await req("POST","/v1/central/commands",c,central)).status,202);
  await cleanup();
  await start();
  const gotEvents=await req("GET","/v1/central/events",undefined,central);
  assert.equal(gotEvents.status,200);
  assert.equal(gotEvents.data.items.length,1);
  assert.equal(gotEvents.data.items[0].event_id,e.event_id);
  const gotCommands=await req("GET","/v1/manager/commands",undefined,manager);
  assert.equal(gotCommands.status,200);
  assert.equal(gotCommands.data.items[0].command_id,c.command_id);
  assert.equal((await req("POST","/v1/manager/events",e,manager)).status,200);
  assert.equal((await req("POST","/v1/central/events/ack",{event_ids:[e.event_id]},central)).data.removed,1);
  assert.equal((await req("POST","/v1/central/events/ack",{event_ids:[e.event_id]},central)).data.removed,0);
  assert.equal((await req("POST","/v1/manager/events",e,manager)).status,200);
  assert.equal((await req("POST","/v1/central/commands/ack",{command_ids:[c.command_id]},central)).data.removed,1);
  // An update assignment can be rebuilt by Centrale and must be accepted after ACK.
  assert.equal((await req("POST","/v1/central/commands",c,central)).status,202);
  assert.equal((await req("GET","/v1/manager/commands",undefined,manager)).data.items.length,1);
 }finally{
  await cleanup();
  const keys=await redis.keys(prefix+"*");
  if(keys.length)await redis.del(keys);
  await redis.quit();
 }
});
