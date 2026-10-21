// Durable transport only. Centrale remains authoritative for business state.
import { createClient } from "redis";

// All queue mutations, including capacity checks, deduplication, expiry and ACK,
// execute on Redis as one operation shared by every Relay process.
const QUEUE = `
local op, id, raw, ttl, capacity, installation, limit = unpack(ARGV)
local now = tonumber(redis.call('TIME')[1])
local function order(owner)
  return KEYS[3] .. ':' .. owner
end
local function remove_pending(mid, item)
  local owner = item.installation_id
  local key = order(owner)
  local removed = redis.call('ZREM', key, mid)
  if redis.call('ZCARD', key) == 0 then redis.call('SREM', KEYS[5], owner) end
  redis.call('ZREM', KEYS[3], mid)
  return removed
end
for _, mid in ipairs(redis.call('ZRANGEBYSCORE', KEYS[2], '-inf', now)) do
  local saved = redis.call('HGET', KEYS[1], mid)
  if saved then remove_pending(mid, cjson.decode(saved)) end
  redis.call('HDEL', KEYS[1], mid)
  redis.call('ZREM', KEYS[2], mid)
end
if op == 'enqueue' then
  if redis.call('HEXISTS', KEYS[1], id) == 1 then return 'duplicate' end
  local key = installation == '' and KEYS[3] or order(installation)
  if redis.call('ZCARD', key) >= tonumber(capacity) then return 'full' end
  local item = cjson.decode(raw)
  local expires = now + tonumber(ttl)
  -- JS prepares received/created timestamps; Redis owns the accepted TTL.
  -- Store the original JSON to preserve payload arrays/objects exactly.
  local sequence = redis.call('INCR', KEYS[4])
  redis.call('HSET', KEYS[1], id, raw)
  redis.call('ZADD', KEYS[2], expires, id)
  redis.call('ZADD', KEYS[3], sequence, id)
  redis.call('ZADD', order(item.installation_id), sequence, id)
  redis.call('SADD', KEYS[5], item.installation_id)
  return 'accepted'
end
if op == 'read' then
  local key = installation == '' and KEYS[3] or order(installation)
  local result = {}
  for _, mid in ipairs(redis.call('ZRANGE', key, 0, tonumber(limit)-1)) do
    table.insert(result, {redis.call('HGET', KEYS[1], mid), redis.call('ZSCORE', KEYS[2], mid)})
  end
  return result
end
if op == 'ack' then
  local removed = 0
  for _, mid in ipairs(cjson.decode(raw)) do
    local saved = redis.call('HGET', KEYS[1], mid)
    if saved then
      remove_pending(mid, cjson.decode(saved))
      -- ACK retires the ID as in protocol v2. Centrale intentionally reuses
      -- update:<assignment> after FAILED to request a new delivery attempt.
      redis.call('HDEL', KEYS[1], mid)
      redis.call('ZREM', KEYS[2], mid)
      removed = removed + 1
    end
  end
  return removed
end
if op == 'stats' then
  return {redis.call('ZCARD', KEYS[3]), redis.call('SCARD', KEYS[5])}
end
return redis.error_reply('invalid_queue_operation')
`;

// Tickets are small transport metadata. Package ZIPs remain a recoverable cache:
// Centrale reuploads their authoritative copy; existing URLs must still work.
const TICKETS = `
local now = tonumber(redis.call('TIME')[1])
for _, ticket in ipairs(redis.call('ZRANGEBYSCORE', KEYS[2], '-inf', now)) do
  redis.call('HDEL', KEYS[1], ticket)
  redis.call('ZREM', KEYS[2], ticket)
end
if ARGV[1] == 'put' then
  redis.call('HSET', KEYS[1], ARGV[2], ARGV[3])
  redis.call('ZADD', KEYS[2], ARGV[4], ARGV[2])
  return 'OK'
end
if ARGV[1] == 'get' then return redis.call('HGET', KEYS[1], ARGV[2]) end
return redis.call('HLEN', KEYS[1])
`;

export function createMessageStore({ url, connection, prefix = "autsys:central-relay:messages:v1" } = {}) {
  if (!connection && !url) throw new Error("message_store_url_required");
  const client = connection ? null : createClient({ url, disableOfflineQueue: true,
    socket: { connectTimeout: 4000, reconnectStrategy: false } });
  client?.on("error", () => {});
  let connecting;
  async function ready() {
    if (connection) return connection.ready();
    if (client.isReady) return client;
    if (!connecting) connecting = client.connect().finally(() => { connecting = undefined; });
    return connecting;
  }
  async function run(type, op, { id = "", item = null, ids = [], ttl = 0,
    capacity = 0, installation = "", limit = 100 } = {}) {
    if (!["events", "commands"].includes(type)) throw new Error("invalid_queue_type");
    const base = `${prefix}:${type}`;
    const conn = await ready();
    return conn.eval(QUEUE, {
      keys: ["records", "expiry", "pending", "sequence", "installations"].map(k => `${base}:${k}`),
      arguments: [op, id, JSON.stringify(item ?? ids), String(ttl), String(capacity), installation, String(limit)]
    });
  }
  async function tickets(op, ticket = "", item = null) {
    const conn = await ready();
    return conn.eval(TICKETS, { keys: [`${prefix}:tickets`, `${prefix}:ticket-expiry`],
      arguments: [op, ticket, JSON.stringify(item), String(item?.expires_at || 0)] });
  }
  return {
    ready,
    enqueue: async (type, item, ttl, capacity) => {
      const result = await run(type, "enqueue", {
        id: item.event_id ?? item.command_id, item, ttl, capacity,
        installation: type === "commands" ? item.installation_id : ""
      });
      if (!["accepted", "duplicate", "full"].includes(result)) throw new Error("invalid_message_store_result");
      return result;
    },
    read: async (type, installation = "", limit = 100) =>
      (await run(type, "read", { installation, limit })).map(([raw, expires]) =>
        ({ ...JSON.parse(raw), expires_at: Number(expires) })),
    ack: (type, ids) => run(type, "ack", { ids }),
    stats: async () => {
      const [events, commands, count] = await Promise.all([run("events", "stats"), run("commands", "stats"), tickets("count")]);
      return { events: events[0], commands: commands[0], installations: commands[1], tickets: count };
    },
    putTicket: (ticket, item) => tickets("put", ticket, item),
    getTicket: async ticket => {
      const raw = await tickets("get", ticket);
      return raw ? JSON.parse(raw) : null;
    },
    close: async () => { if (client?.isOpen) await client.quit(); }
  };
}
