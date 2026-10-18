# AUTSYS Manager Relay authentication: activation runbook

## Current vulnerability
Until this patch is deployed, `POST /v1/manager/bootstrap` can mint an authenticated token using an arbitrary self-asserted client `binding_secret` and an installation ID. Rate limiting and the token's HMAC do not prove that the requester owns an approved installation.

## Approved bindings: authoritative inventory, never self-enroll
The new Relay accepts only pre-approved pairs of installation ID and **existing** device binding. The binding is a random value kept locally by AUTSYS Manager. The Relay holds only its SHA-256 digest, encoded using base64url without padding.

Render environment variable (example **not** real data):

```json
{
  "11111111-1111-4111-8111-111111111111": {
    "platform": "WINDOWS",
    "binding_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  },
  "22222222-2222-4222-8222-222222222222": {
    "platform": "ANDROID",
    "binding_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  }
}
```

Variable: `AUTSYS_MANAGER_BINDINGS_JSON`. The JSON should contain a record for **each** active installation before release.

- Approval must originate from a trusted device-administration path and be cross-checked with the AUTSYS Centrale installation registry.
- On Windows, a read-only local administrative script can calculate the binding SHA-256 from `%ProgramData%\\AUTSYS\\MANAGER\\CONFIG\\manager.json`. It must print **only the digest**, platform and UUID; never the `relay_binding` itself.
- On Android, the binding is in the app's private SharedPreferences. Extract or approve it only by a trusted authorized device-management path. A visible app prompt or a trust-on-first-use (TOFU) remote bootstrap is **not** an acceptable replacement.
- Do not use historical unverified tokens, source IP, user-controlled product/version headers, or a forged heartbeat as evidence of ownership.
- Never check real device IDs, binding digests, or raw secrets into GitHub.

## Activation with zero end-user interaction
1. Inventory all active Manager installations from AUTSYS Centrale.
2. Obtain a trusted fingerprint of each existing Manager device binding through authorized administration, silently if devices are managed.
3. Confirm UUID, platform, 43-character digest and uniqueness. Investigate any missing or conflicting binding.
4. Configure `AUTSYS_MANAGER_BINDINGS_JSON` on **autsys-central-relay** in Render. Do **not** merge while records are incomplete.
5. Run `npm test` and confirm GitHub Actions success. Validate existing client versions in a controlled environment and keep a rollback plan.
6. Merge the security PR to `main`. Render auto-deploys from `main`; monitor the deploy to `live`.
7. Confirm valid bootstrap/event/command paths for each platform; verify fake-secret bootstrap returns 401; check Central heartbeat continuity. If unexpected communication loss occurs, roll back the deploy to the previous revision and remediate the registry.

## Security behavior
- Missing or empty approved registry: all Manager authentication is rejected (fail-closed).
- Malformed JSON or records: startup fails (avoid silently weakening security).
- Bootstrap with unknown UUID, wrong platform or wrong binding: 401.
- Previously issued token with a non-approved binding: 401, even before expiry.
- Existing approved Android/Windows clients use the **unchanged** request and response protocol.
- Removing an approval revokes access after the configuration is deployed, independent of token expiry.
