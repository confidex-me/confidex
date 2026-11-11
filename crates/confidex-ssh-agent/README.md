# confidex-ssh-agent

A bounded SSH-agent protocol implementation with Unix sockets and Windows
named pipes. It does not store vaults or decide when to unlock them.

Implement `KeySource`, bind a `Listener` in a private location and serve each
`Connection` with an explicit authorization callback. Keep the listener inside
the host's unlocked-session lifetime; locking must close access.

```sh
cargo test --locked -p confidex-ssh-agent
```

See [build instructions](../../docs/BUILD.md) for target prerequisites.
