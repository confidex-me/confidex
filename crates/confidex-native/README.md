# confidex-native

Native database paths, device credentials and optional HTTP sync transport
shared by the desktop app and CLI.

Call `database_path()` and `open_store(path)` for the shared local SQLite store.
Use `Credentials` through the application device-key contract. Enable `sync`
for `sync_transport`; the default library build has no HTTP transport.

```sh
cargo test --locked -p confidex-native
```

See [build instructions](../../docs/BUILD.md) for target prerequisites.
