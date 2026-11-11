# confidexsyncd

An optional synchronization server for signed encrypted vaults. It verifies a
lock before accepting its records, pins the verification key and keeps every
valid revision branch. It never receives vault passwords or secret keys.

The native binary uses SQLite or PostgreSQL for its index and mirrors objects
to any number of S3, POSIX filesystem or local Git destinations. Reads try the
available copies. The Cloudflare Worker uses D1 and one or more S3 destinations.
Index commits serialize acceptance and publish only after mirror writes succeed.

```sh
cargo run --locked --release -p confidexsyncd -- apps/confidexsyncd/example.toml
```

The example listens on `127.0.0.1:8080`. Open `/v1` for local OpenAPI documentation.
See [configuration and deployment](docs/CONFIGURATION.md), [the API](docs/SYNC-API.md)
and [sync architecture](docs/SYNC.md). The service has no account system:
clients authenticate writes with signatures. Place HTTPS at the deployment proxy.

```sh
cargo test --locked -p confidexsyncd
cargo check --locked -p confidexsyncd --lib --target wasm32-unknown-unknown
```

Licensed under [AGPLv3](LICENSE).
