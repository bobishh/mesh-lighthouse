# mesh-lighthouse

Native Rust MetaMesh participant. Match is first consumer. The node joins one Match workspace as an editor, stores signed workspace state, and synchronizes it over Iroh. A local integration scenario in Match verifies cards in both directions across a node restart.

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

`config.json`, `state.json`, and `route-sequence` contain private identity or board state. Keep `STATE_DIR` private and durable. `create-lead CONFIG.json COMPANY ROLE` signs a Match lead while the service is stopped.

The HTTP intake runs independently before a mesh identity is paired:

```sh
mesh-lighthouse serve-http STATE_DIR 127.0.0.1:8080
curl -X POST -H 'Content-Type: application/json' \
  -d '{"message":"Hello","contact":"me@example.com"}' http://127.0.0.1:8080/ingest
```

`POST /ingest` durably stores a bounded JSON message under `STATE_DIR/inbox` and returns `202` with `status: pending`. Exact duplicate payloads return the same receipt. The HTTP process does **not** classify, answer through Jev, create a Match card, or sync the inbox yet. `GET /health` supports the deploy proxy. When the native mesh process is paired, `LIGHTHOUSE_HTTP_BIND=0.0.0.0:8080 mesh-lighthouse STATE_DIR/config.json` serves the same inbox alongside replication.

This repository pins Match and MetaMesh as submodules so the node uses the exact same Match authority rules and MetaMesh Rust types. Match's existing `crates/match-lighthouse` remains the source for its integration test until that test runs against this standalone binary.
