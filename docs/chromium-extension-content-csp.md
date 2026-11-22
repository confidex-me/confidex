# Chromium content WASM under a strict site CSP

The first implementation stage includes a separate Rust/WASM content module.
The packaged module detects a password input in a synthetic HTTPS document.
It handles no credentials and imports no vault or UI crates.

## Observed behavior

Chrome 157.0.8103.51, Edge 157.0.4341.46 and Brave 157.1.99.55 (Chromium
157.0.8103.39) in temporary headless profiles on macOS 15.7.7 loaded the
packaged JavaScript and 15 KiB WASM module on an ordinary HTTPS page. The same extension, content script, isolated world, HTML and HTTPS
origin failed when the page returned `default-src 'none'; script-src 'none'; object-src 'none'`. WASM
initialization rejected with `CompileError: WebAssembly.instantiateStreaming():`.
The WASM resource itself returned HTTP 200 with `Content-Type: application/wasm`.

A follow-up probe reproduced the error with both programmatic injection and
dynamic registration at `document_start`. Compiling the same module from an
`ArrayBuffer` also failed. Even a valid empty WASM module supplied directly to
`WebAssembly.compile()` in the isolated world was rejected. Chrome documents
`'wasm-unsafe-eval'` in the isolated-world policy, so this observation describes
the tested browser and launch mode. It does not establish the behavior of
other Chromium versions. [Chrome content-script CSP](https://developer.chrome.com/docs/extensions/develop/concepts/content-scripts#content-security-policy)

The session-routing stage reproduced the same WASM compile error in Chrome
158.0.8127.36 on macOS 15.7.7. The ordinary-page WASM control and isolated
messaging under strict CSP both passed.

## Decision for autofill

Run form classification in the session worker's Rust/WASM. The isolated
content adapter uses native DOM and Chrome APIs to collect bounded,
value-free snapshots and to apply an authorized fill. It visits only the top
document and open Shadow DOM. The adapter neither loads WASM on the website
nor reads field values. The isolated-world WASM probe remains reproducible
using a disposable test manifest with its own web-accessible resources.

A snapshot contains document-local IDs and form revisions, input types,
autocomplete tokens, bounded label/name/id hints, and the resolved origins
of the form and its submit overrides, along with whether any submit route
uses GET. Browser APIs supply the tab, document
and effective origin independently. The session returns only account
previews and form choices to the popup. It consumes the selected
operation once and checks the current record revision and HTTPS origin
before preparing credentials. A login password requires an eligible
password field and a form without a GET route. The background addresses the exact Chrome
document ID and checks live session ownership and permission before
delivery. The adapter checks the current address and form again before
assigning values and dispatching input and change events.

This route uses isolated-world messaging under strict CSP. The acceptance
check exercises a fill on the strict page. The optional standalone probe
continues to reproduce the original WASM compilation limitation.
