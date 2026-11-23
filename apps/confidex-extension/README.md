# Confidex for Chromium

The toolbar action shows the Confidex autofill popup. **Open session** opens or
focuses the Confidex egui session tab. The tab can connect
an existing synchronized vault and unlock the local encrypted cache offline.
It recognizes composite logins and separate Login template fields. Each page
contains up to 128 previews with titles and usernames.

## Build and load

Use the Rust, Node.js and WASM tool versions pinned by the main web build.

```sh
make extension
```

Load `dist/extension` as an unpacked extension. Click the Confidex toolbar
action and select **Open session**. The server defaults to
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

**New login** and **Edit** share the Login template's title, username,
password, website, notes and tag controls. The editor loads the current
saved values and accepts a new password in the empty password field.
Saving a new or changed website stores its HTTPS origin. Edits check the
selected revision and preserve sections and unrelated record fields.
An ordinary note can be edited when it can be identified unambiguously.
Use the main Confidex app for protected or ambiguous fields and for
records with conflicting revisions.

When a save detects a newer revision, the session keeps the draft in memory.
Use **Compare versions** to inspect the current values, then **Reapply my edits**
to carry the draft changes onto that revision. Use **Save** to submit the edit
with a fresh revision check.

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

## Autofill

Open the toolbar popup on an HTTPS page. Confidex shows saved logins for the
exact HTTPS origin, including the port, even on signed-in pages without a form.
When the current top-level document contains a supported form, choose an
account and, when listed, a specific form, then select **Fill login**.
**Refresh** rescans the page.
Confidex fills visible, editable fields in ordinary forms, dynamically
rendered forms, and open Shadow DOM. The site still controls submission.

For a two-step sign-in, choose the login to fill the username and proceed
on the site. Reopen the popup on the password step. For up to two minutes,
Confidex can preselect the same account in the same tab and origin.
**Fill login** is required for both steps. Form or document changes can
invalidate the selection and require a fresh scan. Registration, password
changes, insecure or cross-origin form destinations, iframes and closed
Shadow DOM are outside the supported fill flow. Password fill excludes
masked fields with explicit non-login autocomplete roles and forms that
can submit credentials using HTTP GET.

The popup receives account previews and form choices. Each selection is bound to the live
session, tab, document and form. The worker rejects replay, conflicting
or stale revisions and changed form metadata. The content adapter
checks the current form and address again immediately before insertion.
See [Content WASM under a strict site CSP](../../docs/chromium-extension-content-csp.md)
for the architecture decision and isolated-world WASM experiment.

## Save submitted logins

With HTTPS site access granted and the vault unlocked, submit a sign-in
form and look for the Confidex toolbar badge. The toolbar popup shows the
offer for the current tab. The session tab shows pending offers from all
tabs. Review the origin and account, then choose **Save** or select an
existing login and choose **Update password**. Confidex detects the
submission, so verify that the credentials worked before saving.

A matching origin, username and password produces no offer. Registration
forms with a confirmation field require both password values to match.
Password changes update the selected saved login and preserve its other
fields. If that revision changes before confirmation, review the new
selection and try again. A confirmed change is stored locally first, and
the UI shows synchronization status separately.

Confidex keeps offers in the unlocked worker for two minutes, up to one per
tab and ten per session. An offer survives navigation in its source tab.
Closing the tab, dismissing the offer, or locking the vault clears it.
The worker also keeps a short-lived username for two-step sign-ins in the
same tab and origin.

Use **Never offer to save on this site** to retain autofill while suppressing
save offers. **Disable Confidex on this site** turns off both. Re-enable
either from the toolbar popup while visiting the site. The extension
stores these exceptions locally as HTTPS origins, including domain and
port. Captured credentials are held in memory until dismissed, expired,
or confirmed into the encrypted vault.

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
keyboard activation of the session from the toolbar popup, autofill under
strict CSP and dynamic open Shadow DOM, two-step sign-ins, account and
form selection, input and change events without submission, blocked form
and document replacement, stale revisions, replay rejection, routing after a background
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

Autosave coverage includes native submission and navigation under strict
CSP, an offline save followed by autofill and web sync, duplicate
suppression, registration confirmation, a password change in an open
Shadow DOM SPA, stale revision rejection, two-step sign-in, and separate
saving and site-access exceptions.

Headless runs record prior consent in Chromium's test profile and then use the
permission button to request actual access. To exercise the first-use native
permission prompt, add `--interactive-permission` and accept the prompt in the
temporary browser window. Omit `--vault-only` to also run the standalone WASM
probe, which reproduces the separate strict-CSP issue.
