# Confidex for Chromium

This branch is the first implementation stage. The toolbar action opens an
egui session tab. The tab can connect an existing synchronized vault, display
login titles and usernames, and unlock the local encrypted cache offline. The
preview recognizes both the composite login field and the separate fields
created by the Login template. It skips ambiguous combinations and conflicted
records. Each page contains up to 128 logins. When a record spans pages, the
next page resumes at the next login in that revision.

The worker uses the existing Confidex Engine, sync protocol and IndexedDB
schema. The extension has its own storage origin and requires the master
password and secret key on each unlock. There is no device unlock or
remembered key. The preview never sends a vault password to the UI. Closing the
session tab destroys its Dedicated Worker. A duplicated tab returns to the
original tab, and the worker holds an exclusive lock for its lifetime. The full session hardening,
permission onboarding, website integration, and pilot packaging are later
implementation stages.

## Build and load

Use the Rust, Node.js and WASM tool versions pinned by the main web build.

```sh
make extension
```

Load `dist/extension` as an unpacked extension in a test profile. Click the
Confidex toolbar action to open the session tab. The server field defaults to
`https://sync.confidex.me/` and accepts a custom HTTPS sync-server origin.

The builder compiles into a temporary directory and validates the packaged
modules before replacing `dist/extension`. A failed build preserves the previous
package. After rebuilding, refresh the session tab. Startup failures display
an error and a reload button.

## Browser checks

Check visible startup errors for missing JavaScript and WASM assets with
`node apps/confidex-extension/startup-check.mjs "/path/to/chrome" dist/extension`.

```sh
make web
cargo build --locked -p confidexsyncd
node apps/confidex-extension/browser-check.mjs \
  "/path/to/chrome" dist/extension dist/web target/debug/confidexsyncd
```

The test creates a local HTTPS fixture and uses the packaged web client to
generate and sync a synthetic vault. It installs the unpacked extension in a
temporary Chromium profile, opens the session through the toolbar action,
connects to the fixture and previews a login. It verifies rejection of an
incorrect password, exclusive session ownership after tab duplication,
manual locking, lock on tab close, offline unlock, and absence of the
fixture credentials in the extension's IndexedDB and local storage. Browser
profiles, server databases, test certificates and keys are temporary. The test
does not write traces or screenshots.

The default command also exercises the packaged content bootstrap in Chrome's
isolated world. Use `--vault-only` to run the independent vault check. See
[Content WASM under a strict site CSP](../../docs/chromium-extension-content-csp.md)
for the observed platform blocker.
