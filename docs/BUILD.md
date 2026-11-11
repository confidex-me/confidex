# Build and release

Run commands from the repository root unless stated otherwise. The Rust version
is pinned in `rust-toolchain.toml`. Always use `--locked`; do not regenerate the
lockfile during a release. Tool versions and package locks are committed.
These inputs reproduce the build procedure; output bytes can differ with the
OS SDK, linker and native toolchain.

## Native

Install the platform dependencies listed in the root README. Linux builds need
TPM2-TSS headers even when the build host has no TPM. Running the Linux client
with remembered secrets needs a user D-Bus session, an unlocked Secret Service
collection and access to a TPM 2.0 resource manager. Windows uses Credential
Manager and the Microsoft Platform Crypto Provider. macOS uses Keychain and
Secure Enclave. Hardware-dependent checks need a suitable machine and session.

```sh
cargo build --locked --release -p confidex -p cfdex -p confidexsyncd
cargo test --locked --workspace
cargo fmt --all --check
cargo check --locked -p confidex --no-default-features
cargo check --locked -p cfdex --no-default-features
```

Git LFS supplies the large image regression fixture. `git lfs pull` must run
before tests. Test data is synthetic, except for the supplied public image
fixture. Tests that contact PostgreSQL, S3 or a Worker are opt-in and require
disposable services; see the daemon configuration guide.

For a machine with little disk space, set `CARGO_BUILD_JOBS=2`,
`CARGO_INCREMENTAL=0` and `CARGO_PROFILE_TEST_DEBUG=0`. Build directories are
ignored. Changing a target directory affects where packaging looks for binaries.

## Browser

Install Node.js at the version in `.node-version`, Python 3.12+ and the pinned
WASM tools. The installer verifies SHA-256 digests of official release archives
before extracting the required executables into ignored `.tools/bin/`.

```sh
python3 tools/install-wasm-tools.py
export PATH="$PWD/.tools/bin:$PATH"
make web
node apps/confidex/web/serve.mjs dist/wasm
```

The main module has a 256 MiB memory ceiling; the isolated image encoder has a
2 GiB ceiling. `wasm-release` uses size optimization, LTO, one codegen unit and
abort-on-panic. `wasm-opt -Oz` runs after wasm-bindgen. Additional fonts remain
separate files. `tools/check-web.mjs` rejects a complete package of 25 MB or more.
The output includes a build manifest with the source commit and asset hashes.

Run browser checks with a Chromium executable and the generated bundle:

```sh
node apps/confidex/web/check.mjs /path/to/chromium dist/wasm
node apps/confidex/web/storage-check.mjs /path/to/chromium dist/wasm
node apps/confidex/web/device-unlock-check.mjs /path/to/chromium dist/wasm
```

These headless checks do not replace real Safari input and passkey checks.
Keep `dist/web/` on one HTTPS origin. Apply its `_headers` file or equivalent
server headers. Changing origins changes browser storage and passkey scope.
For Cloudflare, authenticate with Wrangler and configure your account and routes
in an ignored `apps/confidex/wrangler.production.toml` copied from the template:

```sh
npm ci
npx wrangler deploy --dry-run --config apps/confidex/wrangler.toml
npx wrangler deploy --config apps/confidex/wrangler.production.toml
```

## Sync Worker

The sync Worker shares the Rust daemon's implementation but uses D1 and S3.
Install the pinned builder and prepare a local configuration:

```sh
cargo install --locked worker-build --version 0.8.7
npm ci
cd apps/confidexsyncd
worker-build --release
```

See [configuration](../apps/confidexsyncd/docs/CONFIGURATION.md) for D1 setup, S3
secrets and native storage mirrors. Account IDs, database IDs and credentials
belong in local configuration or repository secrets, not source control.

## Releases

CI checks native targets on Linux, macOS and Windows, and builds the browser
application and sync Worker. A `v*` tag runs the release workflow. It packages
the desktop app, CLI and daemon separately, includes their licenses, records the
source commit and writes SHA-256 checksums. macOS packages contain an `.app`;
Windows packages are ZIP archives; Linux packages are tar archives.

The workflow creates a **draft** GitHub release. Review the assets and release
notes before publishing it. No deployment runs on a pull request. Cloudflare
credentials are not needed to build or create release artifacts.

Release binaries are unsigned unless signing is added separately. Windows and
macOS can show OS security prompts for these packages. The workflow does not
claim notarization, Authenticode signing or a security audit.
