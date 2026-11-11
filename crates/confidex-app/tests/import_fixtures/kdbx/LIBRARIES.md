# KDBX dependency review

This is a review of candidate APIs, not the importer's final support matrix.
No dependency has yet been added to the production workspace.

| Candidate | Evidence | Required changes or rejection reason |
| --- | --- | --- |
| `keepass` 0.17.0, MIT | Native opens all three real CLI fixtures; browser target compiles; default features avoid challenge-response/FFI | No output budget in gzip; high-level parser builds its own model; raw XML retains inner ciphertext and omits access to the inner-header binary pool |
| `kdbx-rs` 0.5.2, GPL-3.0+ | Reviewed published source; has stream readers internally | Decompression and immediate XML parsing are unbounded in public unlock API; streaming pipeline is private |
| `keepass-rs` 0.2.0, MIT OR MulanPSL-2.0 | Reviewed published source, public format/crypto modules | Reader omits the KDBX4 header SHA-256 field and decompresses after inner-header parsing; this differs from the official format; no runtime compatibility claim |

Sources:

- [KDBX specification](https://keepass.info/help/kb/kdbx.html).
- [keepass 0.17.0](https://docs.rs/keepass/0.17.0/keepass/).
- [kdbx-rs 0.5.2](https://docs.rs/kdbx-rs/0.5.2/kdbx_rs/).
- [keepass-rs 0.2.0](https://docs.rs/keepass-rs/0.2.0/keepass_rs/).

The strongest candidate is `keepass` 0.17.0. Its `Database::get_xml` is not a
ready bridge: internal protected values still need the stateful inner cipher,
and KDBX4 attachments are outside that XML. Merely imposing a small input size
does not bound its `GZipCompression::decompress` or the resulting XML tree.

It also derives Argon2 through `rust-argon2` 3.0.0. That dependency explicitly
[does not clear its work memory](https://docs.rs/rust-argon2/3.0.0/argon2/#limitations).
Our existing RustCrypto Argon2 backend with admitted, zeroizing memory must be
used for this boundary, or equivalent clearing must be proved. No implementation
of an encryption algorithm or KDF should be added to the application.

A usable library boundary must validate versions, complete headers and KDF
parameters before work; authenticate the encrypted payload; bound intermediate
buffers and decompression; clear plaintext and key buffers; and expose protected
XML plus the binary pool with cancellation checks. The existing KeePass semantic
mapper can then preserve unknown source data, field protection and history.

Native fixture opening and a WASM compile are positive dependency evidence only.
They do not prove bounded hostile-input behavior, browser runtime compatibility,
complete KDBX import or any production UI flow.
