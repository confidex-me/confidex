# Confidex for Chromium

The toolbar action opens the Confidex egui session tab. The tab can connect
an existing synchronized vault and unlock the local encrypted cache offline.
It recognizes composite logins and separate Login template fields. Each page
contains up to 128 previews with titles and usernames.

## Build and load

Use the Rust, Node.js and WASM tool versions pinned by the main web build.

```sh
make extension
```

Load `dist/extension` as an unpacked extension. Click the Confidex toolbar
action to open or focus the session. The server defaults to
`https://sync.confidex.me/` and accepts a custom Confidex HTTPS sync origin.

The builder validates the package before replacing `dist/extension`. Reload
the extension and reopen the session after rebuilding. Startup failures display
an error and a reload button.

## Session and site access

The session tab and its Dedicated Worker hold exclusive Web Locks. A duplicate
tab returns to the owner. The Dedicated Worker is the only Engine owner and
uses the shared encrypted IndexedDB store on the extension origin. Each unlock
requires the master password and secret key.

The worker checks its 15-minute idle deadline before processing vault requests
and returning results. Trusted pointer, keyboard and scroll events in the
session tab can renew the deadline. Background traffic and sync leave the
deadline untouched. Closing or reloading the tab, locking manually, expiry, or
loss of the worker clears the previews and requires another unlock. The
session tab checks the worker's ownership lock while a command is pending.
Users can cancel a pending connection or unlock from the session tab. The
background service worker asks the existing session for live authorization
on each route, so background restarts preserve routing without storing keys
or granting any session authority to the background.

## Logins and synchronization

Use **New login** to create a record from the standard Login template. The
record stores the HTTPS origin of the supplied URL. Use **Edit** to update the
username and password of one listed login. Each edit checks the revision
selected when the form was opened and preserves the other record fields,
including the original website, sections, and notes. Ambiguous separate
fields and records with conflicting revisions require the main Confidex app.

A saved login is committed to the encrypted IndexedDB vault before
synchronization. Pending writes survive locking and browser restarts.
The worker synchronizes after unlock, after a local write, and every minute
while unlocked. **Sync now** requests an immediate run. Automatic retries
wait 5, 15, and then 60 seconds after failures. Sync uses the same durable
checkpoint as the main app. It preserves concurrent versions, which can be
reviewed and resolved from the main app's synchronization screen.

## Site access

Use **Allow access to HTTPS sites** in the session tab to grant optional
site access. Use the same control to withdraw access. Chromium registers the
isolated-world channel for main HTTPS documents after grant, including new
navigations and reloaded pages. Revocation removes the registration. The
router also checks current permissions and the active document on each request,
including replies from isolated worlds already present when access was revoked.

At this stage the website channel accepts only a versioned boolean form report
and replies with a boolean acknowledgement. Chromium supplies the tab, frame,
document and origin independently of the payload. The Engine exchange is private
to the extension session page. Form analysis, autofill and capture are later stages.
See [Content WASM under a strict site CSP](../../docs/chromium-extension-content-csp.md)
for the isolated-world WASM experiment.

## Browser checks

Check visible startup errors for missing JavaScript and WASM assets with
`node apps/confidex-extension/startup-check.mjs "/path/to/chrome" dist/extension`.

```sh
make web
cargo build --locked -p confidexsyncd
node apps/confidex-extension/browser-check.mjs \
  "/path/to/chrome" dist/extension dist/web target/debug/confidexsyncd --vault-only
```

The check creates a local HTTPS server and uses the packaged web client to create
and sync a synthetic vault. It installs the unpacked extension in a temporary
Chromium profile and checks permission grant and revocation, sender validation,
the isolated messaging channel under strict CSP, routing after a background
restart, worker loss, idle expiry, duplicate ownership, and closing the session.
The revocation check sends a report from the original isolated world without
reloading the page. The slow-unlock check blocks the worker across the previous
probe timeout and verifies that unlock completes. A separate check closes the
worker without a reply during unlock and verifies recovery in the same tab.
The suite also checks incorrect credentials, offline creation and update,
duplicate requests, stale revisions, and absence of fixture credentials in
persistent extension data. It restarts Chromium with the same temporary
profile, unlocks offline again, and checks both directions of synchronization
and conflict resolution with the main web runtime. It removes the temporary
browser profile and server data and writes no traces or screenshots.

Headless runs record prior consent in Chromium's test profile and then use the
permission button to request actual access. To exercise the first-use native
permission prompt, add `--interactive-permission` and accept the prompt in the
temporary browser window. Omit `--vault-only` to also run the standalone WASM
probe, which reproduces the separate strict-CSP issue.
