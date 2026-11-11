# cfdex

The native command-line client. It uses the desktop app's local database and
device key, with its own unlocked session. It runs on macOS, Linux and Windows.

```sh
cargo build --locked --release -p cfdex
cargo run --locked --release -p cfdex -- --help
```

After installation:

```sh
cfdex init
cfdex unlock
cfdex list
cfdex fields 'Example account'
cfdex get 'Example account' --field Password
cfdex lock
```

Use `--database PATH` for a separate database. No data is sent to a server by
local read commands. `cfdex sync` explicitly runs configured synchronization.
See [command usage](docs/USAGE.md) and [build instructions](../../docs/BUILD.md).
