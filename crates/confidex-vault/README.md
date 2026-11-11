# confidex-vault

Portable encrypted-vault format, key derivation, signatures and revision graph.
It has no UI or persistent storage.

Use `lock` to open a vault, `record` for content, `envelope` for signed encrypted
objects and `revisions` to validate their graph. See [the format](docs/FORMAT.md).

```sh
cargo test --locked -p confidex-vault
```

See [build instructions](../../docs/BUILD.md) for target prerequisites.
