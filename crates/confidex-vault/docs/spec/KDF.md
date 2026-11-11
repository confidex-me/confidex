# Argon2id profile v1

Creation and reading accept exactly this tuple:

| Field | Value |
| --- | ---: |
| Algorithm (Argon2 identifier) | 2, Argon2id |
| Argon2 version | 19 (`0x13`) |
| Memory | 65,536 KiB (64 MiB) |
| Passes | 3 |
| Lanes | 4 |
| Raw output | 32 bytes |
| Salt | 16 fresh random bytes |
| Password input | 0–4,096 bytes |
| Required operation memory budget | 68 MiB |

This is the second recommended parameter set in
[RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html#section-4).
Four logical lanes do not require four threads. The selected RustCrypto build
runs without a thread pool, browser workers, or shared WASM memory.

The output is raw P for the two-input lock construction, not a PHC password
verifier. No optional Argon2 secret/associated data is used. Secret-key mixing
remains in the lock HKDF. Callers supply fresh salt from the platform CSPRNG;
this module does not generate it. The core does not normalize password bytes.
Text callers use unchanged UTF-8. Password-strength and empty-password UX policy
belong to the application; the KDF accepts empty byte strings.

## Admission and failure

Treat all received parameters as untrusted wide integers. Reject any tuple
other than the one above, including weaker candidates, version changes, zero,
overflow-sized fields, and output-length changes. Check input lengths and the
available operation budget before allocating or running Argon2. Do not truncate
integers, clamp parameters, tune them on unlock, retry a weaker profile, or use
library defaults. There are no released legacy profiles to support in v1.
Adding another readable profile requires an explicit version/profile decision.

`admit` performs these checks without allocating. `password_key` repeats them
before a fallible arena reservation and uses explicit Argon2 parameters. The
64 MiB arena and output use `Zeroizing`; the remaining 4 MiB is the allowance
for operation overhead. Allocation failure is distinct from an unsupported
profile or insufficient declared budget. Admission cannot guarantee that an
allocator or host will actually provide memory. Browser traps/OS termination
remain platform limitations; do not claim all process-wide failures are caught.

Only one KDF should run per available arena budget. The application must account
for other live operations under the shared resource profile and run browser
derivation outside the UI thread. Cancellation must not silently weaken the
result. A slower device still computes the same tuple or returns an error.

Use the [core lock API](../LOCK.md) for the complete parser, admission checks
and key derivation. Run `cargo test --locked -p confidex-vault` from the
repository root to check the selected profile and its failure cases.
