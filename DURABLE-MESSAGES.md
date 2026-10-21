# Durable Relay messages (pre-deployment checklist)

The Relay retains its existing REST endpoints, protocol 2, Manager auth, event and command JSON, HTTP 202 acceptance, duplicate HTTP 200, and explicit ACK requests. Redis is the transport authority; no in-memory fallback is permitted.

## Configuration
- Set `AUTSYS_RELAY_MESSAGES_REDIS_URL` to a persistent Redis/Render Key Value instance. For existing installations, `AUTSYS_MANAGER_BINDINGS_REDIS_URL` is a fallback.
- Configure Redis persistence and backup appropriate for desired message durability. Redis memory-only persistence settings can still lose data after Redis process restarts.
- Confirm staging Redis access from the deployment and that its credentials are not exposed to Android/Windows Managers.
- Do not deploy a version with a missing Redis URL: startup intentionally fails rather than accepting lossy messages.

## Delivery semantics
- POST commits payload + pending index + dedup index atomically before responding 202. Redis outages yield 503; sender should retry the same ID.
- GET does not consume. Central or Manager can fetch repeatedly; ACK removes pending records atomically.
- ACK dedup history persists until the message's declared expiry, protecting against late sender retries.
- Messages expire after the protocol's existing capped TTL; expiry can remove an undelivered message by design. Guarantee beyond TTL requires raising the protocol limit or changing the retention policy in a separate change.
- Expired-message cleanup is invoked during enqueue. Acknowledge confirmation is not the same as consumer business-level application.

## Validation
- GitHub Actions uses Redis 7 and runs integration tests for process-independent access, duplicate retries, expiry, capacity, concurrent enqueues, and Redis outage.
- Before production rollout, verify Windows and Android Manager retries after 503 and after timeouts, and verify AUTSYS Centrale event ingestion / command ACK ordering against staging.
- Run a staged rolling upgrade during a verified empty queue. In-memory messages accepted by the *old* Relay **cannot be migrated retroactively** by this patch. Drain existing queues with Centrale before replacing old instances.
- After upgrading confirm `/diag`, event ingestion, Central ACK, command delivery to both Manager platforms, and Central command ACK.
- This PR must **not** be merged/deployed until integration CI passes and staging compatibility is confirmed.

## Known limits
- Redis durability depends on Redis persistence configuration; this is not a guarantee of disk-fsynced writes.
- The Relay remains a transport component, not the authoritative source of licenses or releases.
- Sender recovery capabilities are not proven by this repository alone; inspect the two Manager applications and AUTSYS Centrale implementations before claiming automatic recovery.
