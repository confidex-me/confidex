# confidex-storage

Storage contracts for opaque encrypted vault objects, revision heads, sync
checkpoints and backups. The optional `sqlite` feature provides the native store.

Implement `Store` for another backend, or use `SqliteStore::open(path)` with
`features = ["sqlite"]`. Callers must authenticate received wire objects.

```sh
cargo test --locked -p confidex-storage
```

See [build instructions](../../docs/BUILD.md) for target prerequisites.
