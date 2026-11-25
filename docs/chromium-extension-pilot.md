# Chromium extension pilot verification

## Package

`make extension` builds `dist/extension` and `dist/confidex-chromium.zip`.
The ZIP has `manifest.json` at its root and is suitable for **Load unpacked**
after extraction. The [extension README](../apps/confidex-extension/README.md)
contains installation, update and test commands.

Two builds on the same host with Rust 1.98.0, wasm-bindgen 0.2.130 and
Binaryen 133 produced byte-identical archives. Archive integrity and all
files in the extracted directory were checked. The pilot build used
manifest version `0.1.0` and produced an 8,309,563-byte ZIP with SHA-256
`ee98e5ffad22a3a4a8ce64b430aa1ab936a60ac75c6d5e7f9cfbfe0ba0b83c43`.

The `Build` workflow creates `chromium-extension` after running the Chrome
startup, popup and vault checks on the extracted ZIP. GitHub Actions
execution for these steps is pending. The workflow uses Ubuntu and the
local results below are from macOS.

## Browser acceptance

Local checks used macOS 15.7.7 (24G720) on Apple Silicon and Node.js
24.22.1 on 2026-11-25. The headless browser tests loaded the extracted ZIP
directory through Chromium DevTools in temporary profiles with a synthetic
vault, a locally built web client and a locally built `confidexsyncd`. The
harness records consent in the temporary profile before exercising the
extension's HTTPS access button.

| Browser | Installed version | Startup errors | Toolbar and themes | Vault E2E |
| --- | --- | --- | --- | --- |
| Chrome | 158.0.8127.36 | Pass | Pass | Pass |
| Edge | 158.0.4370.33 | Pass | Pass | Pass |
| Brave | 158.1.100.59 (Chromium 158.0.8127.92) | Pass | Pass | Pass |

- The toolbar check covered keyboard connection and unlock, closing and
  reopening the popup, and manual lock. The session also locked after a
  simulated idle timeout, worker loss and a browser restart.
- The site checks covered ordinary and dynamic forms, native submit and
  open Shadow DOM, two-step sign-in, stale selections, strict site CSP,
  HTTPS origin matching, HTTP pages, closed Shadow DOM, iframes and revoked
  access. The [standalone WASM experiment](chromium-extension-content-csp.md)
  is a separate diagnostic.
- The autosave check covered registration, password change, dismissal after
  a rejected sign-in, deduplication and site exceptions. A confirmed offline
  save survived a browser restart and filled the form before reconnecting.
  The web client opened the same record after sync, edited its note and
  synchronized the new revision back to the extension.
- Persistent browser data was checked for fixture secrets. The harness
  deletes the temporary profiles and retains only scenario results.

## Visual review and remaining coverage

In Chrome, the connection form and saved logins were reviewed at 360 × 480
CSS pixels in the light and dark themes. The canvas and footer fit the
viewport without horizontal scrolling, and the connection form's first
keyboard focus was visible. The automated compact layout check runs the
popup page in an extension tab at the same size and checks the painted
palette. The keyboard flow also runs in the browser's toolbar popup.

This verification covers the macOS builds listed above. The native
permission prompt and native desktop client interaction remain manual
checks. Web client interoperability is covered by the end-to-end test.
