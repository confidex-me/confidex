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

The test profile optimizes dependencies outside the workspace, including the
vendored KeePass reader. Real KDF fixtures keep their original parameters;
workspace test code keeps its normal debug checks. CI limits each workspace test
step to 60 minutes, including compilation.

Windows ARM CI tests use `-C target-cpu=native` to enable the runner's crypto
instructions. RustCrypto's ARM feature detection does not support Windows.
This flag applies only to that test step; release packages use portable targets.

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
node apps/confidex/web/check.mjs /path/to/chromium dist/web
node apps/confidex/web/input-check.mjs /path/to/chromium dist/wasm
node apps/confidex/web/storage-check.mjs /path/to/chromium
node apps/confidex/web/device-unlock-check.mjs /path/to/chromium dist/wasm DISPOSABLE_SYNC_SERVER_URL
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
Build the compiled Worker, then prepare a local configuration:

```sh
npm ci
python3 builders/syncd/build.py
npx wrangler deploy --dry-run --config apps/confidexsyncd/wrangler.toml
```

See [configuration](../apps/confidexsyncd/docs/CONFIGURATION.md) for D1 setup, S3
secrets and native storage mirrors. Account IDs, database IDs and credentials
belong in local configuration or repository secrets, not source control.

## Releases

CI checks native targets on Linux, macOS and Windows, and builds the browser
application and sync Worker. Create and publish a GitHub Release to start
`.github/workflows/release.yml`, as with the release process in the repository's
GitHub interface. The workflow builds the release tag, derives the version as `tag+gSHA6`
without changing Cargo manifests, packages the outputs and uploads them to the existing
release. Tests and feature checks run on main pushes and pull requests; release
builds do not repeat them. A tag push alone does not create or publish a release.

macOS app packages are two DMG images, for Apple Silicon and Intel. Each contains
`Confidex.app` and a link to `/Applications`. The copied website icon and its
raster sizes are in `apps/confidex/assets/icons/`. Windows packages are MSI installers; Linux packages are tar archives for glibc
and musl. Desktop packages include the GUI and CLI; daemon archives are separate.
See the [artifact contract](../builders/docs/ARTIFACTS.md) for stable names.
All packages include licenses and source provenance. `SHA256SUMS` covers the
release assets. CI and release builds require no Cloudflare credentials.

Release binaries are unsigned unless signing is added separately. Windows and
macOS can show OS security prompts for these packages. The workflow does not
claim notarization, Authenticode signing or a security audit.

The release can also deploy the app and sync Worker. Add the
`CLOUDFLARE_API_TOKEN` secret and `CLOUDFLARE_ACCOUNT_ID` Actions variable or secret in the
application repository. Without the token this step is skipped. Existing D1
data and Worker variables/secrets are preserved; see the
[deployment helper](../builders/cloudflare/README.md).

Releases also publish `ghcr.io/confidex-me/confidexsyncd` and
`ghcr.io/confidex-me/confidex-web` for amd64 and arm64, with the original release
tag and `latest`. Use a tag without `+` metadata. For local image builds and the
one-time GHCR Public visibility setting, see the
[container builder](../builders/containers/README.md).

`confidex-selfhost-{version}.zip` combines the web and Worker packages,
Linux servers for both architectures/libcs, Compose, native and Cloudflare
configuration, D1 schema and pinned Wrangler tooling. It needs no Rust compiler
for installation. See the [bundle builder](../builders/selfhost/README.md).
