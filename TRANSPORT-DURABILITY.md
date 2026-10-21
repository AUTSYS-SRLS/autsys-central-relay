# Durable relay queues (protocol 2)

## Failure and recovery assessment

The previous relay returned HTTP 202 after appending to Node's `events` array
or `commandsByInstallation` map. A crash, deploy, process replacement or restart
discarded pending messages and their deduplication IDs. Neither successful POST
nor polling GET is an application ACK. No production loss has been established.

Source review on 21 October 2026 included `server.js` at base commit
`eff993459b9bd048ef7b80a3b1857a37cf7695a4` and the current local client sources
(read only): `AUTSYS.Service.cs`, Android `RelayClient.java`, and Centrale's
`autsys_centrale.py`. These client sources live outside this GitHub repository;
the automated checks exercise their existing HTTP contract, not their binaries.

| Message family | Sender recovery observed | Persistence requirement |
| --- | --- | --- |
| `manager_heartbeat`, `manager_startup_sync` | Managers send fresh snapshots; Windows `SendRelayManagerState` and Android `sendState` create a new event ID. This recovers current state, not the original snapshot/history. | Persist every accepted snapshot through ACK/TTL. |
| `product_installed`, `product_uninstalled` | Later state sync can reconcile current products (Windows explicitly logs this). It does not reproduce the original ordered transition. | Persist accepted transitions. |
| `update_result`, requests and other one-shot events | Windows `ReportUpdateResult` and Android `sendUpdateResult`/`sendEvent` POST without a durable per-event outbox in these methods. A successful POST is not followed by polling for event acceptance by Centrale. Interactive retries are not guaranteed replay. | Persist all accepted events; do not infer recoverability from a later heartbeat. |
| `license_result_received` | Can be generated again while Managers poll a still-pending license result. | Persist the ACK event too; it causes Centrale to ACK the command. |
| `update_available` | Centrale `_send_relay_updates_for_installation` reconstructs active assignments from its DB, uploads packages and issues tickets on heartbeat/startup recovery. It uses `update:<assignment_id>`. | Persist pending command and ticket; keep ZIPs as recoverable cache. |
| `license_result`, `license_status_result`, `bootstrap_plan_result` | May be reconstructed if the request event is redelivered before Centrale ACKs it. There is no general replay after that event ACK. | Persist the accepted result independently of the request event. |
| `admin_device_command`, remote responses, other commands | `_send_admin_device_command` generates a UUID and POSTs directly. No general durable command replay is provided by the inspected path. | Persist all accepted commands, irrespective of kind. |

## Implementation and compatibility

`message-store.js` uses Redis hashes for original JSON, sorted indexes for FIFO
delivery and expiry, and per-installation command indexes. A Lua operation
serializes enqueue, capacity, deduplication, reads, ACK and expiry across Relay
instances. The original payload JSON, signatures and empty array/object shapes
are preserved. Redis time determines the accepted expiry; duplicate POSTs do not
change the queued record, order or expiry.

HTTP 202 follows a successful Redis write only. A duplicate pending ID still
returns HTTP 200 with `duplicate: true`; a full queue returns 503 `queue_full`.
Redis failures return 503 `message_store_unavailable`, including reads and ACKs.
There is no fallback to volatile memory. A missing URL or inaccessible Redis
prevents startup. Reads never remove messages, so interruption before ACK causes
redelivery. Application handlers must remain idempotent: protocol 2 provides
at-least-once delivery within TTL, not exactly-once execution.

ACK still removes the message **and retires its deduplication ID**, atomically.
Repeated ACK returns `removed: 0`. The same ID can be accepted again after ACK
or expiry. This is deliberate compatibility: Centrale ACKs `update:<assignment>`
on `FAILED` and can then reissue the same ID from its pending assignments.
A tombstone blocking this retry until TTL would change existing behavior.
The existing protocol cannot distinguish an intentional new attempt from a late
POST retry after ACK; this limitation is preserved rather than inventing a new
wire protocol. Deduplication applies while the message is pending.

Endpoint paths, authentication, installation isolation, provisional license
filters, signatures, POST/GET/ACK JSON shapes, protocol number, TTL clamping
(60–86400 seconds), batch limit (100), event capacity (5000), and command capacity
(500 per installation) stay unchanged. No Manager or Centrale release is needed
for this HTTP contract change. `/diag` keeps queue counters and reports durable
queues; package ZIPs are still explicitly ephemeral.

Ticket metadata is also in Redis. A pending command can therefore retain its
original download URL after process replacement. If ZIPs are lost, Centrale's
existing recovery reuploads the authoritative package, after which the original
ticket works until its original expiry. There can still be a temporary package
404 before recovery; the relay does not claim to preserve package bytes or to
execute an expired command. Multi-instance queues work across instances, while
ZIP caches still require deployment routing/shared storage appropriate to the
existing package transport. This PR does not enable horizontal scaling.

## Deployment and rollback review (not performed by this PR)

Set `AUTSYS_RELAY_MESSAGES_REDIS_URL`, or reuse the already configured
`AUTSYS_MANAGER_BINDINGS_REDIS_URL`. This also applies to PREAPPROVED mode.
`AUTSYS_RELAY_MESSAGES_PREFIX` optionally separates staging/test environments;
all production Relay instances must use the same stable prefix. Do not switch
URLs/prefixes during an upgrade without migrating/draining pending messages.
The default namespace is `autsys:central-relay:messages:v1`; binding/license
keys are untouched. This implementation targets standalone Redis/Render Key
Value; dynamic per-installation Lua keys are not Redis Cluster compatible.

Before production rollout, verify the managed Redis service's persistence,
backup/recovery and eviction policy. Use a durable instance with `noeviction`.
A Redis command success survives Node restarts; Redis host/storage loss is only
as durable as the configured Redis persistence/replication. The isolated AOF
crash test uses `appendonly yes` and `appendfsync always`; it does not assert that
production already has those settings. A cache-only Redis or eviction policy
can invalidate the delivery guarantee and must not be used for these queues.

For the **first** upgrade, drain/ACK the legacy in-memory queues while the old
process still runs, or arrange a quiesced export/replay before replacing it.
The new code cannot recover messages already lost by the previous process or
import memory from another running process. Do not assume a new heartbeat can
recover one-shot events/admin commands. Subsequent deploys use the same Redis
namespace. Rolling back to the old memory-only binary also requires draining
Redis queues first; otherwise it cannot see accepted durable messages.

## Reproducible checks

Install Node 22 and a local `redis-server` (Redis 7+). Start an isolated test
Redis, then run:

```sh
npm install --ignore-scripts
AUTSYS_TEST_REDIS_URL=redis://127.0.0.1:6379 npm test
```

`AUTSYS_TEST_REDIS_SERVER` can name a nonstandard Redis executable. The AOF test
starts and kills its own Redis on a free port in a temporary directory. Other
integration tests require the supplied test URL, never a production service:
they create test bindings/inventory, queue prefixes and a temporary Redis ACL
user for failure injection. The existing CI workflow supplies an isolated Redis
and installs the executable. The URL must allow test ACL operations.

Tests cover Windows/Android protocol authentication and license restrictions;
HTTP 202 followed by SIGKILL/restart; lost HTTP responses and duplicate retry;
GET redelivery; persistent/idempotent ACK; reuse after ACK for update retries;
two concurrent Relay processes; capacity races on independent connections;
ACK/enqueue races; TTL and duplicate expiry stability; ticket recovery after ZIP
reupload; Redis failures without volatile acceptance; and Redis AOF crash/restart.

No production endpoints, configuration, services, credentials or client sources
are changed by this PR or these tests.
