# mesh-lighthouse

Native Rust MetaMesh participant. Match is the first consumer. A single service identity stores signed state for multiple Match workspaces and synchronizes each scope over Iroh. Each scope and peer has its own retry loop, so an unreachable peer does not delay other boards.

Initialize dependencies and build:

```sh
git submodule update --init --recursive
cargo build --release
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

The container starts in HTTP-only mode. An owner-issued invitation can initialize the existing `/data` volume without deleting its inbox. Restart the container after `join` succeeds; it then runs the native mesh peer and HTTP intake together. A failed join removes only its incomplete mesh state, leaving queued messages intact. Invite secrets must not be logged or committed.

This repository pins Match and MetaMesh as submodules so the node uses the exact same Match authority rules and MetaMesh Rust types. Match's `e2e/lighthouse-owner.spec.ts` runs against this standalone binary and checks current boards, future boards, chat, restart recovery, and declined access. Its older `lighthouse-join` scenario still exercises the in-tree adapter.
