# mesh-lighthouse

Native Rust MetaMesh participant. Match is the first consumer. A single service identity stores signed state for multiple Match workspaces and synchronizes each scope over Iroh. Each scope and peer has its own retry loop, so an unreachable peer does not delay other boards.

Build the pinned Git dependencies:

```sh
cargo build --release --locked
```

Provision with an owner-issued Match invitation:

```sh
mesh-lighthouse join INVITE_URL STATE_DIR
mesh-lighthouse STATE_DIR/config.json
```

In Match, open **Sync → Add someone**, select the starting boards, and generate an invitation. When Lighthouse requests access, the owner selects Visitor or Editor and can explicitly enable **Connect all my boards, including future boards**. Lighthouse uses its own identity; it never receives the owner's private keys. Without that option, access stays limited to the invited boards.

Owner connection pins the approving owner. Additional boards require an owner-signed grant, signed route, and verified Match document before becoming active. New scopes are saved in the same durable registry and survive restart. Revocation or departure on a board prevents the browser from reissuing access through this policy. The future-board preference is currently local to the approving browser, which must be online to issue new grants. Synchronizing integration settings between enrolled devices remains a separate, unimplemented part of the integration spec.

Set `LIGHTHOUSE_TRACE_SYNC=1` to log frame types and service-lock timings when diagnosing slow replication. The trace omits frame payloads and invitation secrets.

`config.json`, scope state files, and `route-sequence` contain private identity or board state. Keep `STATE_DIR` private and durable. Existing single-scope configuration remains readable. HTTP intake continues to target the primary invited board; adding replicated boards does not change its destination.

The HTTP intake runs independently before a mesh identity is paired:

```sh
mesh-lighthouse serve-http STATE_DIR 127.0.0.1:8080
curl -X POST -H 'Content-Type: application/json' \
  -d '{"message":"Hello","contact":"me@example.com"}' http://127.0.0.1:8080/ingest
```

`GET /challenge` issues a short-lived signed human check. `POST /ingest` verifies it, durably stores a bounded JSON message under `STATE_DIR/inbox`, and returns `202` with `status: pending`. A background worker classifies opportunity relevance, role type, and seniority with Jev, retaining every probability distribution. Once paired, every intake is posted to workspace chat; relevant opportunities also become idempotent Match lead cards. `GET /health` supports the deploy proxy. When the native mesh process is paired, `LIGHTHOUSE_HTTP_BIND=0.0.0.0:8080 mesh-lighthouse STATE_DIR/config.json` serves and processes the same inbox alongside replication.

For Match hostname discovery, set LIGHTHOUSE_PUBLIC_ORIGIN to the external HTTPS origin and LIGHTHOUSE_CORS_ORIGINS to a comma-separated allowlist of exact Match web origins. HTTP origins are allowed only on loopback for development. No browser origins are allowed unless configured. GET /.well-known/mesh-lighthouse exposes the configured service identity and supported capabilities. Pairing requires the controller's signed approval and an authenticated operator decision bound to one transcript. After both approvals, Match sends an ordinary ten-minute visitor invitation in a signed request. Lighthouse joins with its existing identity, verifies each selected board, stages all scopes, and activates them in one durable registry write. Match reports active only after Lighthouse signs its committed per-board result. Discovery alone proves no prior service ownership and grants no board access. Active policy updates, disconnection, and deletion controls remain unimplemented.

For an initialized service, set `LIGHTHOUSE_ADMIN_TOKEN` to the operator secret, then open **Sync → Add keeper** in Match. Enter the public hostname and discover the service. Match selects all currently owned boards and **Also replicate my future boards** by default. The operator signs in at `/admin/`, compares the code and identities, and approves the displayed boards and future-board policy. The owner independently confirms the same code in Match. Until both approve, no board access is granted.

The operator page keeps the Lighthouse service identity, its replicated boards, and the JEV intake trigger together under **Keepers**. Pairing requests stay under **Approvals**. The JEV row reports whether `JEV_API_KEY` is configured, pending intake count, and saved outcomes; intake continues to target the primary invited board. Replication state reflects the native replication worker and active peers, not HTTP readiness. The authenticated `GET /admin/api/overview` endpoint supplies this summary; it returns `403` without the operator session.

Activation stores scopes under `STATE_DIR/scopes/<workspace hash>/state.json` before committing `config.json`. The completion receipt binds the exact offered snapshot, board list, and future-board policy. A lost HTTP response can be recovered through signed status or an exact retry after restart; a different snapshot cannot reuse the earlier commit. Failed activation remains pending and does not produce a durable ACK. New boards still require an online approving browser to issue signed grants.

For deployment, retain the existing durable volume and stop the old native process before starting its replacement: two processes must not write the same registry or use the same device identity concurrently. Build and deliver the new image before stopping the old process. Back up the complete stopped `STATE_DIR`, including `config.json`, `scopes`, the primary state, pairing records, and inbox. A health check confirms HTTP readiness; inspect discovery for pairing/provisioning capabilities separately. Restart with the same volume to recover committed scopes. If startup fails, stop the replacement and restart the previous image; retain the backup for recovery. Never restore only `config.json` without its referenced scope files.

The container starts in HTTP-only mode. An owner-issued invitation can initialize the existing `/data` volume without deleting its inbox. Restart the container after `join` succeeds; it then runs the native mesh peer and HTTP intake together. A failed join removes only its incomplete mesh state, leaving queued messages intact. Invite secrets must not be logged or committed.

`Cargo.toml` and `Cargo.lock` pin Match authority and MetaMesh Git revisions so the node uses shared authority rules and Rust types. Match's `e2e/lighthouse-keeper-provisioning.spec.ts` runs against this standalone binary and checks real discovery, operator login failure, pending and mutual approval, three current boards, a future board, stable state files, lost HTTP response, restart, and exact retry. Its older `lighthouse-join` scenario still exercises the in-tree adapter. Proof paging bounds transfer size but does not prune Automerge history; capacity and production connection stability need separate measurements.
