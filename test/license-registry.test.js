import assert from "node:assert/strict";
import { createServer } from "node:net";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { createClient } from "redis";
import { createLicenseRegistry, validateLicenseInventory, managerLicenseState } from "../license-registry.js";

const MESSAGE_PREFIX = `test:relay:license-registry.test:${process.pid}:${Date.now()}`;
const UUID = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
const OTHER = "ffffffff-ffff-4fff-8fff-ffffffffffff";
const LEGIT = "L".repeat(43);
const CENTRAL = "central-test";
const MANAGER = "manager-test";
const redisUrl = process.env.AUTSYS_TEST_REDIS_URL;
const repoRoot = path.dirname(fileURLToPath(new URL("../server.js", import.meta.url)));
const redisKeys = ["autsys:central-relay:license-inventory:v1","autsys:manager-binding:v1:" + UUID];

function inventory(productStatus = "ACTIVE", until = null) {
  return {
    schema: 1,
    generated_at_ms: Date.now(),
    installations: [{
      id: UUID, platform: "WINDOWS", licenses: [
        { license_number: "AUTSYS-LIC-TEST-MANAGER", product_code: "AUTSYS_MANAGER", status: "ACTIVE", valid_until: null },
        { license_number: "AUTSYS-LIC-TEST-PRODUCT", product_code: "CESTINO_DI_RETE", status: productStatus, valid_until: until }
      ]
    }]
  };
}

test("an active product and Manager license must share the same installation", () => {
  const active = validateLicenseInventory(inventory());
  assert.equal(managerLicenseState(active, UUID, "WINDOWS").authorized, true);
  assert.equal(managerLicenseState(active, OTHER, "WINDOWS").authorized, false);
  assert.equal(managerLicenseState(active, UUID, "ANDROID").authorized, false);
  assert.equal(managerLicenseState(validateLicenseInventory(inventory("REVOKED")), UUID, "WINDOWS").authorized, false);
  assert.equal(managerLicenseState(validateLicenseInventory(inventory("ACTIVE", "2020-01-01T00:00:00Z")), UUID, "WINDOWS").authorized, false);
  const managerOnly = inventory();
  managerOnly.installations[0].licenses.pop();
  assert.equal(managerLicenseState(validateLicenseInventory(managerOnly), UUID, "WINDOWS").authorized, false);
  assert.throws(() => validateLicenseInventory({schema:1,generated_at_ms:Date.now(), installations:[{id: UUID, platform:"WINDOWS", licenses:[{license_number:"BAD",product_code:"PORTIERI",status:"FAKE",valid_until:null}]}]}), /invalid_license_inventory/);
});

if (!redisUrl) {
  test("live license registry requires Redis for integration", {skip: true}, () => {});
} else {
  let redis;
  let proc;
  let origin;
  before(async () => {
    redis = createClient({url: redisUrl});
    redis.on("error", () => {});
    await redis.connect();
    await redis.del(redisKeys);
  });
  after(async () => {
    if(proc && proc.exitCode === null) {
      proc.kill();
      await once(proc, "exit");
    }
    if(redis?.isReady) {
      await redis.del(redisKeys);
      await redis.quit();
    }
  });
  async function request(route, method="GET", body, headers={}) {
    const config={ method, headers:{...headers} };
    if(body !== undefined) {
      config.headers["content-type"]="application/json";
      config.body=JSON.stringify(body);
    }
    const result=await fetch(origin+route,config);
    return {status:result.status,data:await result.json()};
  }
  test("the Relay uses Centrale's durable license inventory without device polling", async () => {
    const server=createServer();
    await new Promise(resolve=>server.listen(0,"127.0.0.1",resolve));
    const port=server.address().port;
    await new Promise(resolve=>server.close(resolve));
    origin="http://127.0.0.1:"+port;
    proc=spawn(process.execPath,["server.js"],{
      cwd:repoRoot,
      stdio:"ignore",
      env:{...process.env,
      AUTSYS_RELAY_MESSAGES_REDIS_URL: process.env.AUTSYS_TEST_REDIS_URL,
      AUTSYS_RELAY_MESSAGES_PREFIX: MESSAGE_PREFIX,PORT:String(port),
        AUTSYS_CENTRAL_RELAY_KEY:CENTRAL,
        AUTSYS_MANAGER_TOKEN_KEY:MANAGER,
        AUTSYS_MANAGER_BINDING_MODE:"TOFU",
        AUTSYS_RELAY_LICENSE_ENFORCEMENT:"ON",
        AUTSYS_MANAGER_BINDINGS_JSON:"",
        AUTSYS_MANAGER_BINDINGS_REDIS_URL:redisUrl}
    });
    let ready=false;
    for(let i=0;i<100;i++) {
      if(proc.exitCode!==null)throw Error("server exited early");
      try { if((await request("/health")).status===200){ready=true;break;} }catch{}
      await new Promise(resolve=>setTimeout(resolve,50));
    }
    assert.equal(ready,true,"server did not become ready");
    const centralAuth={authorization:"Bearer "+CENTRAL};
    const boot=await request("/v1/manager/bootstrap","POST",{
      installation_id:UUID,product_code:"AUTSYS_MANAGER",
      manager_version:"1.0.0.20",platform:"WINDOWS",binding_secret:LEGIT
    });
    assert.equal(boot.status,201);
    const managerAuth={authorization:"Bearer "+boot.data.relay_token,"x-autsys-binding":LEGIT};
    const restricted=await request("/v1/manager/events","POST",{
      event_id:"unlicensed-admin-event",kind:"super_manager_api_request",payload:{installation_id:UUID}
    },managerAuth);
    assert.equal(restricted.status,403);
    const allowed=await request("/v1/manager/events","POST",{
      event_id:"unlicensed-initial-heartbeat",kind:"manager_startup_sync",payload:{installation_id:UUID}
    },managerAuth);
    assert.equal(allowed.status,202);

    const unauthorizedPush=await request("/v1/central/license-inventory","POST",inventory());
    assert.equal(unauthorizedPush.status,401);
    const push=await request("/v1/central/license-inventory","POST",inventory(),centralAuth);
    assert.equal(push.status,200);
    assert.equal(push.data.devices,1);
    assert.equal(push.data.licenses,2);
    const allowedAfter=await request("/v1/manager/events","POST",{
      event_id:"licensed-admin-event",kind:"super_manager_api_request",payload:{installation_id:UUID}
    },managerAuth);
    assert.equal(allowedAfter.status,202);
    assert.equal((await request("/v1/central/license-inventory/status","GET",undefined,centralAuth)).data.ready,true);

    const revoked=await request("/v1/central/license-inventory","POST",inventory("REVOKED"),centralAuth);
    assert.equal(revoked.status,200);
    const restrictedAgain=await request("/v1/manager/events","POST",{
      event_id:"revoked-admin-event",kind:"super_manager_api_request",payload:{installation_id:UUID}
    },managerAuth);
    assert.equal(restrictedAgain.status,403);
    assert.equal((await redis.ttl(redisKeys[0])),-1);
  });
  test("late older inventory cannot restore revoked product licenses", async () => {
    const auth={authorization:"Bearer "+CENTRAL};
    const t=Date.now()+2000;
    const active=inventory("ACTIVE");
    active.generated_at_ms=t;
    const revoked=inventory("REVOKED");
    revoked.generated_at_ms=t+200;
    const lateOld=inventory("ACTIVE");
    lateOld.generated_at_ms=t+100;

    assert.equal((await request("/v1/central/license-inventory","POST",active,auth)).status,200);
    const published=await request("/v1/central/license-inventory","POST",revoked,auth);
    assert.equal(published.status,200);
    assert.equal(published.data.action,"updated");
    const saved=await redis.get(redisKeys[0]);

    const rejected=await request("/v1/central/license-inventory","POST",lateOld,auth);
    assert.equal(rejected.status,409);
    assert.equal(rejected.data.error,"stale_license_inventory");
    assert.equal(await redis.get(redisKeys[0]),saved,"stale inventory overwrote a revocation");
    assert.equal(managerLicenseState(JSON.parse(saved),UUID,"WINDOWS").authorized,false);
  });

  test("repeated identical sync is idempotent; conflicting same timestamp is blocked", async () => {
    const auth={authorization:"Bearer "+CENTRAL};
    const state=inventory("REVOKED");
    state.generated_at_ms=Date.now()+6000;
    const first=await request("/v1/central/license-inventory","POST",state,auth);
    assert.equal(first.status,200);
    assert.equal(first.data.action,"updated");
    const original=await redis.get(redisKeys[0]);
    for(let i=0;i<3;i++) {
      const repeated=await request("/v1/central/license-inventory","POST",structuredClone(state),auth);
      assert.equal(repeated.status,200);
      assert.equal(repeated.data.action,"duplicate");
      assert.equal(await redis.get(redisKeys[0]),original,"duplicate unexpectedly rewrote metadata");
    }
    const conflicting=structuredClone(state);
    conflicting.installations[0].licenses[1].status="ACTIVE";
    const conflict=await request("/v1/central/license-inventory","POST",conflicting,auth);
    assert.equal(conflict.status,409);
    assert.equal(conflict.data.error,"conflicting_license_inventory_timestamp");
    assert.equal(await redis.get(redisKeys[0]),original,"same-version conflict restored a license");

    const staleRepeat=structuredClone(state);
    staleRepeat.generated_at_ms-=1;
    const stale=await request("/v1/central/license-inventory","POST",staleRepeat,auth);
    assert.equal(stale.status,409);
    assert.equal(await redis.get(redisKeys[0]),original);
  });

  test("concurrent writers from separate Redis connections preserve newest revocation", async () => {
    await redis.del(redisKeys[0]);
    const conn1=createClient({url:redisUrl});
    const conn2=createClient({url:redisUrl});
    conn1.on("error",()=>{});
    conn2.on("error",()=>{});
    await Promise.all([conn1.connect(),conn2.connect()]);
    try {
      const registry1=createLicenseRegistry({ready:async()=>conn1});
      const registry2=createLicenseRegistry({ready:async()=>conn2});
      const t=Date.now()+10000;
      const batches=[];
      for(let i=0;i<12;i++){
        const s=inventory(i===11?"REVOKED":"ACTIVE");
        s.generated_at_ms=t+i;
        batches.push((i%2===0?registry1:registry2).replace(s));
      }
      const results=await Promise.allSettled(batches.reverse());
      assert.ok(results.some(r=>r.status==="fulfilled"));
      assert.ok(results.every(r=>r.status==="fulfilled" ||
        (r.status==="rejected" && r.reason?.message==="stale_license_inventory")));
      const stored=JSON.parse(await redis.get(redisKeys[0]));
      assert.equal(stored.generated_at_ms,t+11);
      assert.equal(managerLicenseState(stored,UUID,"WINDOWS").authorized,false);
      assert.equal(stored.installations[UUID].licenses[1].status,"REVOKED");

      // All same-generation writes with identical content return one
      // creation/update at most, without changing the persisted snapshot.
      const saved=await redis.get(redisKeys[0]);
      const identical=inventory("REVOKED");
      identical.generated_at_ms=t+11;
      const duplicateResults=await Promise.all([
        registry1.replace(structuredClone(identical)),
        registry2.replace(structuredClone(identical))
      ]);
      assert.deepEqual(duplicateResults.map(r=>r.action),["duplicate","duplicate"]);
      assert.equal(await redis.get(redisKeys[0]),saved);
    } finally {
      await Promise.all([conn1.quit(),conn2.quit()]);
    }
  });

}

