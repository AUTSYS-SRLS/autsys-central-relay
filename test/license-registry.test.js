import assert from "node:assert/strict";
import { createServer } from "node:net";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { createClient } from "redis";
import { validateLicenseInventory, managerLicenseState } from "../license-registry.js";

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
      env:{...process.env,PORT:String(port),
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
}
