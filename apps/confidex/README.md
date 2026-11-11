# Confidex app

The desktop and browser clients use one egui interface and the shared
`confidex-app` engine. Native hosts use SQLite and OS device credentials;
browser hosts use IndexedDB, dedicated workers and optional passkey unlock.

```sh
cargo run --locked --release -p confidex
```

Create a vault, save its secret key separately, then add records. Synchronization
is optional. Imports support encrypted Confidex backups and third-party exports;
review the import before applying it. Multiple revision branches remain visible
for explicit conflict resolution.

```sh
make web
node apps/confidex/web/serve.mjs dist/wasm
```

Install the pinned WASM tools first. See [build instructions](../../docs/BUILD.md).
The browser assets and workers are in `web/`; Rust platform adapters are in
`src/`. Images always use WebP in records; arbitrary file fields retain bytes.
