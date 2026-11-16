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

## Pending architecture decision

Strict-CSP integration is a gate for the content architecture. The unpacked
prototype keeps the packaged WASM probe and does not register content scripts
during normal use. The smoke test uses a disposable copy with access to the
local fixture host and fails if the strict page cannot initialize the module.

A candidate design is to keep DOM access and field mutation in a restricted
isolated-world adapter and move form classification to Rust/WASM in an
extension-owned context. Before adopting it, verify strict-CSP coverage and
define the metadata that can cross the browser-provided messaging boundary.
Only an approved one-time fill may carry a vault credential into the target
document. This branch retains the original runtime and the reproducible
browser check while that design is pending.
