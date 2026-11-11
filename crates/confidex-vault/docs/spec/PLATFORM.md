# Platform guarantees and limits v1

The core uses Rust cryptographic implementations on macOS, Linux, Windows, and
browser WASM. Platform system calls and Web Crypto supply entropy. Python/CFFI,
OpenSSL, libsodium, and native C cryptographic builds are not runtime/build/test
dependencies. WASI tests exercise a separate host API; they do not substitute
for testing a browser.

## Entropy contract

`getrandom` 0.4.3 supplies system entropy: macOS `getentropy`, Linux system RNG,
Windows 10+ `ProcessPrng`, WASI `random_get`, and browser `crypto.getRandomValues`.
Browser application builds explicitly enable the core's optional `browser`
feature, which selects `wasm_js` and wasm-bindgen glue. OS-less WASM without that
feature compiles without requiring JS and returns `Unavailable` for entropy.
WASI uses its system provider. See the
[getrandom target notes](https://docs.rs/getrandom/0.4.3/getrandom/).

`entropy::fill_random` returns an error on failure and wipes the entire output,
including partially written bytes. A request is at most 65,536 bytes; larger
requests fail before invoking the provider. Use fresh platform entropy for
vault material, IDs, HPKE encapsulation input, lock salts, and nonces. Never
substitute clocks, counters, `Math.random`, all-zero buffers, or a custom hedged
construction. Never retry with weaker cryptographic parameters.

Obtain entropy fallibly before an operation can change accepted state. In
particular, do not connect an infallible HPKE RNG interface to a fallible system
source through an adapter that panics on system failure. The integrated sender
must test this boundary explicitly. A pre-seeded standard CSPRNG can bridge an
infallible dependency API only when its seed was obtained successfully and its
state lifetime/cleanup is controlled. This profile does not invent a new RNG.

An embedding host can replace or corrupt its entropy provider. The library
cannot prove that a browser/OS supplied real randomness. The sample tests check
API reachability and failure behavior, not entropy quality or independence.

## Owned secrets and lifetime

Use non-debug, non-serializable key containers and borrowed inputs. Keep the
private material, derived seeds, secret_key, P, wrapping keys, Argon2 arena,
plaintext, and accessible scratch buffers in `Zeroizing` storage. Drop or clear
them at the end of the operation; locking a vault releases live key containers
and plaintext caches owned by the core. A retained external clone remains its
owner's responsibility. Do not put secrets in logs or error values.

Reserve bounded plaintext capacities before filling them, avoiding growth that
can leave old allocations behind. `zeroize` 1.9.1 clears initialized Vec elements
and spare capacity; it cannot erase prior reallocations. Dependency features
enable zeroization for Ed25519/X25519 keys, HPKE/ChaCha key state, and Argon2
buffers where exposed. The feature graph was checked with `cargo tree -e features`.
Use in-place authenticated operations on owned wiping buffers where practical;
review convenience APIs that copy plaintext before adding them to the core.

No claim is made to erase all compiler temporaries, registers, opaque HMAC/HKDF,
compressor or other dependency internals, allocator copies, swap, crash dumps,
browser snapshots, JS strings, or application-created clones. Cleanup on Drop
cannot be promised after process termination or an abort/trap. Native memory
locking is not part of this portable profile; browsers expose no comparable
general guarantee. A compromised OS, extension, JS host, debugger, or unlocked
application can read accessible secrets. These limits apply even with zeroize.
See [zeroize's guarantees and limitations](https://docs.rs/zeroize/1.9.1/zeroize/).

## Timing requirements

Use release builds for secret operations and the selected primitive APIs:

| Operation | Required behavior / limit |
| --- | --- |
| X25519 scalar multiplication, Ed25519 seed-to-key/signing | Use the selected dalek constant-time secret-key paths; do not substitute variable-time scalar routines |
| HKDF/HMAC-SHA256 key derivation | Fixed key-material lengths and standard primitive implementation; no secret-dependent application branches or comparisons |
| ChaCha20-Poly1305 / XChaCha20-Poly1305 | Use authenticated library APIs and verify tags before releasing plaintext; the portable backend requires constant-time multiplication on its CPU |
| Recovered secret_key correspondence | Compare the complete fixed 32 bytes with `subtle::ConstantTimeEq`, not early-exit equality |
| Ed25519 verification and public pin/schema/ID checks | Inputs are public; strict verification is required, but uniform timing of malformed public inputs is not promised |
| Argon2id | Preserve the selected algorithm; it deliberately includes data-dependent memory access and is not claimed to have secret-independent accesses |

The [AEAD backend notes](https://docs.rs/chacha20poly1305/latest/chacha20poly1305/)
exclude CPUs with variable-time multiplication. Supported desktop aarch64/x86_64
and browser builds use the chosen backends; this is not a timing proof for every
processor or JIT. `subtle` itself is a
[best-effort software guarantee](https://docs.rs/subtle/2.6.1/subtle/), with debug
assertions that can branch on secrets. No whole-operation constant-time claim
is made for compression, serialization, Base32 presentation, arbitrary content
validation, allocation, OS calls, JS glue, or garbage collection. Browser JIT
and host scheduling can change generated behavior and observed timing.

## Verification limits

Run `cargo test --locked -p confidex-vault` for entropy failure, secret lifetime
and bounded parsing checks. Use the browser build and host checks described in
[build instructions](../../../../docs/BUILD.md) for the application path.
These checks do not prove entropy quality, uniform timing on every processor,
or complete erasure of OS, browser and dependency copies.

Device-key persistence has a separate [platform contract](../../../confidex-device-secrets/docs/PLATFORMS.md).
