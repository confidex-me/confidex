# Raw decoder in a browser Worker

`browser.mjs` builds `probe.rs` as a temporary WASM crate outside the checkout and
uses the existing headless Chrome harness. It opens eight real public synthetic
databases through the production raw API, consumes protected nodes in physical
order and compares binary bytes. No Store, server or application UI is involved.

The Worker also changes an Argon2 header to 64 MiB / three passes, repairs its
public SHA256 and leaves the HMAC invalid. The decoder must perform that admitted
KDF and reject the credentials. This exercises work-memory cleanup on failure
without adding a large fixture or weakening authentication. Wrong credentials
and cancellation are checked separately. The page heartbeat must continue while
the Worker runs; WASM linear memory must remain below 256 MiB.
After the failed derivation, the Worker scans its test instance and requires a
contiguous zeroed span of at least 63 MiB. Together with the 64 MiB exercised
allocation and the code's Zeroizing guard, this checks that work blocks did not
remain in the released heap. It is not a proof that every stack/register or
browser-internal copy is erased.

Use Rust with wasm32-unknown-unknown installed, wasm-bindgen CLI 0.2.130 and Chrome:

```sh
WASM_BINDGEN=/path/to/wasm-bindgen CARGO_TARGET_DIR=/path/to/build-cache node vendor/keepass/tests/browser/browser.mjs
```

`CARGO`, `RUSTC` and `CHROME` may select local executables. The isolated crate,
generated bindings and lockfile remain in the printed work directory for review.
`probe.lock` pins dependencies separately from the standalone library checks.
The fixture password values are public; no user data is read. This proves the raw
library boundary, not app preview/apply, worker message cancellation or a complete
import memory peak. Argon2 cannot be interrupted inside one library call.
AES callbacks also run synchronously in the Worker: an ordinary queued cancel
message cannot update a flag until Rust yields. The app must provide a real
cross-thread cancellation signal or an isolated parser Worker; this probe only
checks the supplied callback and that the page remains responsive.

## Bounded save bridge

`save.mjs` runs `save.rs` in a real browser Worker with the same tool variables.
It seals five public credential modes (password, raw keyfile, both, empty
password, empty password with keyfile), using KDBX4.1/AES256/Argon2id64MiB/three
passes/one lane/ChaCha20 inner/no compression. It reopens the bytes through Raw,
checks three sequential protected values and exact nonempty/empty binary entries,
including protection flags, and requires zero live library charges on return.
It also cancels before serialization and requires no output. A page heartbeat
must continue and WASM linear memory must stay below 256 MiB. The resulting public
files remain in the printed work directory for an independent reader. The probe
does not substitute for application mapping, UI save/lock or 10k calibration.

```sh
WASM_BINDGEN=/path/to/wasm-bindgen CARGO_TARGET_DIR=/path/to/build-cache node vendor/keepass/tests/browser/save.mjs
python3 vendor/keepass/tests/browser/save-reader.py /printed/work/directory /path/to/keepassxc-cli
```

The independent CLI check reads all five outputs, verifies CR/LF and Unicode in
the protected password, private and empty fields, and exports both attachments
for exact comparison. Wrong passwords, wrong keyfiles and a changed terminal
block MAC must fail. The report records the reader version and executable SHA256.
All data in this probe is public; these commands do not use the native GUI.
