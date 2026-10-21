import assert from "node:assert/strict";
import crypto from "node:crypto";
import { spawn } from "node:child_process";
import { createServer } from "node:net";
import { test } from "node:test";

const INSTALLATION = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
const OTHER_INSTALLATION = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
const CENTRAL = "local-test-central-secret-only";
const MANAGER_TOKEN_KEY = "local-test-manager-secret-only";
const BINDING = "B".repeat(43);
const hash = text => crypto.createHash("sha256").update(text).digest("base64url");
const APPROVED = JSON.stringify({
  [INSTALLATION]: {platform:"ANDROID",binding_sha256:hash(BINDING)}
});
async function freePort() {
  const server=createServer();
  await new Promise(resolve=>server.listen(0,"127.0.0.1",resolve));
  const port=server.address().port;
  await new Promise(resolve=>server.close(resolve));
  return port;
}
function managerBearer() {
  const now=Math.floor(Date.now()/1000);
  const data={installation_id:INSTALLATION,purpose:"manager-relay",platform:"ANDROID",
    binding_sha256:hash(BINDING),iat:now,exp:now+600};
  const body=Buffer.from(JSON.stringify(data)).toString("base64url");
  return body+"."+crypto.createHmac("sha256",MANAGER_TOKEN_KEY).update(body).digest("base64url");
}
test("Centrale metadata-only inspection is authenticated, paginated and never ACKs or exposes payloads", async () => {
  const port=await freePort();
  const base="http://127.0.0.1:"+port;
  let child=null;
  const request=async(method,path,body,headers={})=>{
    const r=await fetch(base+path,{
      method,headers:{"content-type":"application/json",...headers},
      body:body===undefined?undefined:JSON.stringify(body)
    });
    return {status:r.status,data:await r.json()};
  };
  const central={"authorization":"Bearer "+CENTRAL};
  const manager={"authorization":"Bearer "+managerBearer(),"x-autsys-binding":BINDING};
  try {
    const redisUrl=new URL(process.env.AUTSYS_TEST_REDIS_URL || "redis://127.0.0.1:6379");
    redisUrl.pathname="/14";
    child=spawn(process.execPath,["server.js"],{
      cwd:process.cwd(),
      env:{...process.env,PORT:String(port),
        AUTSYS_CENTRAL_RELAY_KEY:CENTRAL,
        AUTSYS_MANAGER_TOKEN_KEY:MANAGER_TOKEN_KEY,
        AUTSYS_MANAGER_BINDINGS_JSON:APPROVED,
        AUTSYS_MANAGER_BINDING_MODE:"PREAPPROVED",
        AUTSYS_RELAY_MESSAGES_REDIS_URL:redisUrl.toString(),
        AUTSYS_RELAY_LICENSE_ENFORCEMENT:"OFF"},
      stdio:"ignore"
    });
    let listening=false;
    for(let i=0;i<100;i++){
      if(child.exitCode!==null)throw new Error("relay_child_exited");
      try{if((await request("GET","/health")).status===200){listening=true;break;}}catch{}
      await new Promise(resolve=>setTimeout(resolve,50));
    }
    assert.equal(listening,true,"local test Relay must start");
    assert.equal((await request("GET","/v1/central/commands/inspect")).status,401);
    assert.equal((await request("GET","/v1/central/events/inspect")).status,401);
    const sensitive="SENSITIVE_PAYLOAD_MUST_NOT_LEAK";
    for(const [id,installation,kind] of [
      ["c-a",INSTALLATION,"update_available"],
      ["c-b",INSTALLATION,"license_result"],
      ["c-c",OTHER_INSTALLATION,"update_available"]
    ]){
      const response=await request("POST","/v1/central/commands",{
        command_id:id,installation_id:installation,kind,
        payload:{sensitive},signature:"signature-only-for-local-test"
      },central);
      assert.equal(response.status,202);
    }
    const first=await request("GET","/v1/central/commands/inspect?limit=2",undefined,central);
    assert.equal(first.status,200);
    assert.equal(first.data.total,3);
    assert.equal(first.data.items.length,2);
    assert.equal(first.data.next_offset,2);
    assert.equal(first.data.read_only,true);
    assert.equal(first.data.ttl_purge_called,false);
    assert.equal(first.data.ack_sent,false);
    assert.equal(first.data.payloads_included,false);
    assert.equal(JSON.stringify(first.data).includes(sensitive),false);
    assert.equal(JSON.stringify(first.data).includes("signature-only-for-local-test"),false);
    const second=await request("GET","/v1/central/commands/inspect?limit=2&offset=2",undefined,central);
    assert.equal(second.status,200);
    assert.equal(second.data.items.length,1);
    assert.equal(second.data.next_offset,null);
    const filtered=await request("GET",
      "/v1/central/commands/inspect?installation_id="+INSTALLATION+"&kind=license_result",
      undefined,central);
    assert.equal(filtered.status,200);
    assert.equal(filtered.data.total,1);
    assert.equal(filtered.data.items[0].command_id,"c-b");
    assert.equal((await request("GET","/v1/central/commands/inspect?offset=bad",undefined,central)).status,400);
    assert.equal((await request("GET","/v1/central/commands/inspect?limit=1000",undefined,central)).status,400);
    const ev=await request("POST","/v1/manager/events",
      {event_id:"event-one",kind:"manager_heartbeat",payload:{sensitive}},manager);
    assert.equal(ev.status,202);
    const events=await request("GET","/v1/central/events/inspect?limit=5",undefined,central);
    assert.equal(events.status,200);
    assert.equal(events.data.total,1);
    assert.equal(events.data.items[0].event_id,"event-one");
    assert.equal(JSON.stringify(events.data).includes(sensitive),false);
    assert.equal(events.data.ttl_purge_called,false);
    const still=await request("GET","/v1/manager/commands",undefined,manager);
    assert.equal(still.status,200);
    assert.equal(still.data.count,2,"read-only inspection must not remove Manager commands");
    const original=await request("GET","/v1/central/events?limit=5",undefined,central);
    assert.equal(original.status,200);
    assert.equal(original.data.count,1,"read-only inspection must not remove Manager events");
  } finally {
    if(child&&child.exitCode===null){
      child.kill();
      await Promise.race([
        new Promise(resolve=>child.once("exit",resolve)),
        new Promise(resolve=>setTimeout(resolve,3000))
      ]);
    }
  }
});
