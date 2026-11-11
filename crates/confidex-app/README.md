# confidex-app

Shared vault operations for the desktop app, browser workers and CLI.
It owns sessions, editing, search, import/export, backups and synchronization.

Create an `Engine` and execute `Command` values with a `Store` and `DeviceKeys`.
Use `execute_with_transport` for HTTP synchronization. Hosts provide I/O and
background execution; this crate has no UI.

```sh
cargo test --locked -p confidex-app
```

See [build instructions](../../docs/BUILD.md) for target prerequisites.
