# Confidex

A local-first password and secrets manager for macOS, Windows, Linux and the
browser. Vaults use a secret key and a password. Encryption and signatures run
on the client; the optional sync service stores signed, encrypted objects.

[Web app](https://app.confidex.me) · [Website](https://confidex.me) ·
[Downloads](https://github.com/confidex-me/confidex/releases)

This is early software. Keep a separate backup of important data and your
secret key. The cryptographic design has not had an independent security audit.

## Build

Install [Rust](https://rustup.rs), Git LFS and your platform's development tools.
The repository pins Rust in `rust-toolchain.toml` and dependencies in `Cargo.lock`.

- macOS: Xcode Command Line Tools (`xcode-select --install`).
- Windows: Visual Studio Build Tools with the C++ desktop workload and Windows SDK.
- Ubuntu 24.04: `sudo apt-get install build-essential pkg-config libtss2-dev libxkbcommon-dev libwayland-dev libx11-dev libxi-dev libxcursor-dev libxrandr-dev libgl1-mesa-dev`.

```sh
git lfs install
git lfs pull
cargo build --locked --release -p confidex -p cfdex -p confidexsyncd
cargo run --locked --release -p confidex
```

Binaries are in `target/release/`. On Windows they have the `.exe` suffix.
For a desktop client without HTTP synchronization, build `confidex` or `cfdex`
with `--no-default-features`. Folder synchronization remains available.

For the browser build, install Python 3.12+, Node.js 24 (see `.node-version`)
and the pinned tools:

```sh
python3 tools/install-wasm-tools.py
export PATH="$PWD/.tools/bin:$PATH"
make web
node apps/confidex/web/serve.mjs dist/wasm
```

`dist/web/` contains the self-hosted web application, including fonts and
security headers. See [build and release instructions](docs/BUILD.md) for
platform dependencies, verification, packaging and Cloudflare deployment.

## Components

| Component | Purpose |
| --- | --- |
| [confidex](apps/confidex) | Desktop and browser app, with platform adapters. |
| [cfdex](apps/cfdex) | Command-line client for local vaults. |
| [confidexsyncd](apps/confidexsyncd) | Optional native or Cloudflare sync server. |
| [confidex-vault](crates/confidex-vault) | Portable format, cryptography and signed revision graph. |
| [confidex-storage](crates/confidex-storage) | Storage contract, SQLite and encrypted backups. |
| [confidex-app](crates/confidex-app) | Vault operations, search, import, export and sync. |
| [confidex-ui](crates/confidex-ui) | Shared egui screens, components and translations. |
| [confidex-native](crates/confidex-native) | Native database, device credentials and HTTP transport. |
| [confidex-device-secrets](crates/confidex-device-secrets) | OS key stores, TPM, Secure Enclave and WebAuthn PRF. |
| [confidex-ssh-agent](crates/confidex-ssh-agent) | Local SSH-agent protocol and transport. |
| [confidex-image-codec](crates/confidex-image-codec) | Isolated browser WebP compression worker. |

The [website](https://github.com/confidex-me/website) has its own repository.
The [format](crates/confidex-vault/docs/FORMAT.md) and [sync API](apps/confidexsyncd/docs/SYNC-API.md) document interoperability.
The [security and leakage model](crates/confidex-vault/docs/spec/LEAKAGE.md) describes visible data
and the limits of local protection. Tags are not encrypted.

## Contribute

Run `make check` before opening a pull request. Add a regression test when a
change affects the format, persistence or secret handling. Use English for code
and documentation; keep translations in their locale files. Keep secrets, real
vaults and local cloud configuration out of commits.

## License

The client and shared crates use GPLv3; see [LICENSE](LICENSE).
The synchronization server uses AGPLv3; see
[its license](apps/confidexsyncd/LICENSE). Vendored code, fonts, word lists,
themes and Swagger UI retain their own licenses and attribution files.
