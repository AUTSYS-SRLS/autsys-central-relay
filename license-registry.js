// The authoritative license inventory is pushed by AUTSYS Centrale only.
// A Manager's self-asserted identifier is never accepted as proof of licensing.
// Redis retains the complete inventory across Relay restart/deploy.
const KEY = "autsys:central-relay:license-inventory:v1";
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SAFE = /^[A-Z0-9_.:-]{1,128}$/;
const STATUSES = new Set(["ACTIVE", "DELIVERED", "ISSUED", "SUSPENDED", "REVOKED", "INVISIBLE", "EXPIRED"]);
const PLATFORMS = new Set(["ANDROID", "WINDOWS"]);
const MAX_DEVICES = 5000;
const MAX_LICENSES = 15000;

// Redis runs this script atomically: inspection and conditional write cannot
// interleave with a competing Centrale sync from another Relay instance.
// Legacy stored snapshots (without additional metadata) remain compatible.
const ATOMIC_REPLACE_IF_NEWER = \`
local old_json = redis.call('GET', KEYS[1])

local function equal_content(a, b)
  if type(a) ~= type(b) then return false end
  if type(a) ~= 'table' then return a == b end
  for key, value in pairs(a) do
    if not equal_content(value, b[key]) then return false end
  end
  for key in pairs(b) do
    if a[key] == nil then return false end
  end
  return true
end

if old_json then
  local ok, old = pcall(cjson.decode, old_json)
  if not ok or type(old) ~= 'table' or old.schema ~= 1
      or type(old.generated_at_ms) ~= 'number'
      or old.generated_at_ms <= 0 or type(old.installations) ~= 'table' then
    return redis.error_reply('stored_license_registry_corrupt')
  end

  local incoming = cjson.decode(ARGV[1])
  if incoming.generated_at_ms < old.generated_at_ms then
    return 'stale'
  end
  if incoming.generated_at_ms == old.generated_at_ms then
    if equal_content(incoming.installations, old.installations) then
      return 'duplicate'
    end
    return 'conflict'
  end
end

redis.call('SET', KEYS[1], ARGV[1])
return old_json and 'updated' or 'created'
\`;


export function validateLicenseInventory(input) {
  if (!input || typeof input !== "object" || Array.isArray(input) ||
      input.schema !== 1 || !Number.isSafeInteger(input.generated_at_ms) ||
      input.generated_at_ms <= 0 || !Array.isArray(input.installations) ||
      input.installations.length > MAX_DEVICES) throw new Error("invalid_license_inventory");
  const ids = new Set();
  let count = 0;
  const installations = {};
  for (const row of input.installations) {
    if (!row || typeof row !== "object" || !UUID.test(row.id) ||
        !PLATFORMS.has(row.platform) || !Array.isArray(row.licenses)) {
      throw new Error("invalid_license_inventory");
    }
    const id = row.id.toLowerCase();
    if (ids.has(id)) throw new Error("duplicate_installation_id");
    ids.add(id);
    count += row.licenses.length;
    if (count > MAX_LICENSES) throw new Error("license_inventory_too_large");
    const seenNumbers = new Set();
    const licenses = [];
    for (const license of row.licenses) {
      if (!license || typeof license !== "object" ||
          typeof license.license_number !== "string" ||
          !SAFE.test(license.license_number) ||
          typeof license.product_code !== "string" ||
          !SAFE.test(license.product_code) ||
          !STATUSES.has(license.status) ||
          !(license.valid_until === null ||
            (typeof license.valid_until === "string" &&
              Number.isFinite(Date.parse(license.valid_until))))) {
        throw new Error("invalid_license_inventory");
      }
      if (seenNumbers.has(license.license_number)) throw new Error("duplicate_license_number");
      seenNumbers.add(license.license_number);
      licenses.push({
        license_number: license.license_number,
        product_code: license.product_code,
        status: license.status,
        valid_until: license.valid_until
      });
    }
    installations[id] = { platform: row.platform, licenses };
  }
  return { schema: 1, generated_at_ms: input.generated_at_ms,
    synced_at_ms: Date.now(), installations };
}

function licenseIsActive(row, at) {
  return row.status === "ACTIVE" &&
    (row.valid_until === null || Date.parse(row.valid_until) > at);
}

export function managerLicenseState(inventory, installationId, platform, at = Date.now()) {
  const empty = { authorized: false, known: false, products: [], reason: "license_registry_not_synced" };
  if (!inventory || typeof inventory !== "object" || !inventory.installations) return empty;
  const id = typeof installationId === "string" ? installationId.toLowerCase() : "";
  const device = inventory.installations[id];
  if (!device) return { ...empty, reason: "installation_unknown" };
  if (device.platform !== platform) return { ...empty, known: true, reason: "platform_mismatch" };
  const licenses = device.licenses;
  const manager = licenses.some(l => l.product_code === "AUTSYS_MANAGER" && licenseIsActive(l, at));
  const products = licenses.filter(l => l.product_code !== "AUTSYS_MANAGER" && licenseIsActive(l, at))
    .map(l => l.product_code);
  const authorized = manager && products.length > 0;
  return { authorized, known: true, products, reason: authorized ? "licensed" :
    manager ? "product_license_missing_or_inactive" : "manager_license_missing_or_inactive" };
}

export function createLicenseRegistry(bindingStore) {
  if (!bindingStore || typeof bindingStore.ready !== "function") throw new Error("binding_store_required");
  async function get() {
    const conn = await bindingStore.ready();
    const raw = await conn.get(KEY);
    if (!raw) return null;
    let data;
    try { data = JSON.parse(raw); }
    catch { throw new Error("stored_license_registry_corrupt"); }
    if (!data || data.schema !== 1 || !data.installations) throw new Error("stored_license_registry_corrupt");
    return data;
  }
  async function replace(snapshot) {
    const data = validateLicenseInventory(snapshot);
    const conn = await bindingStore.ready();
    // GET + comparison + SET are one indivisible operation on Redis.
    // An identical retry at the same timestamp must not refresh synced_at_ms.
    const action = await conn.eval(ATOMIC_REPLACE_IF_NEWER, {
      keys: [KEY],
      arguments: [JSON.stringify(data)]
    });
    if (action === "stale" || action === "conflict") {
      const err = new Error(action === "stale"
        ? "stale_license_inventory" : "conflicting_license_inventory_timestamp");
      err.status = 409;
      throw err;
    }
    if (!["created", "updated", "duplicate"].includes(action)) {
      throw new Error("invalid_license_registry_write_result");
    }
    return { devices: Object.keys(data.installations).length,
      licenses: Object.values(data.installations).reduce((n, d) => n + d.licenses.length, 0),
      generated_at_ms: data.generated_at_ms, action };
  }
  async function verify(installationId, platform) {
    return managerLicenseState(await get(), installationId, platform);
  }
  async function status() {
    const i = await get();
    if (!i) return { ready: false, devices: 0, licenses: 0 };
    return { ready: true, generated_at_ms: i.generated_at_ms,
      synced_at_ms: i.synced_at_ms,
      devices: Object.keys(i.installations).length,
      licenses: Object.values(i.installations).reduce((n, d) => n + d.licenses.length, 0) };
  }
  return { replace, verify, status };
}
