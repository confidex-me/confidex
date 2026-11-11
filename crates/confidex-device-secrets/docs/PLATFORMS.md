# Device secret backends

This crate protects local copies of a vault's `secret_key` and an optional
quick unlock capability. It does not open vaults, save master passwords, or
change the vault or sync formats. The Confidex native host uses the
`me.confidex.device-secrets` namespace.

```rust,no_run
use confidex_device_secrets::{
    AccessPolicy, Interaction, Purpose, SecretBytes, SecretId, platform,
};

async fn save(vault: [u8; 16], secret_key: Vec<u8>) -> confidex_device_secrets::Result<()> {
    let mut secrets = platform::system("me.confidex.client")?;
    let id = SecretId { vault, purpose: Purpose::SecretKey };
    let value = SecretBytes::new(secret_key)?;
    secrets.put(id, &value, AccessPolicy::DeviceBound, Interaction::Forbid).await
}
```

`platform::system(namespace)` selects the local store and key protector.
Keep the namespace stable and use lowercase ASCII. `SecretId` includes a vault ID and a purpose, so
the same vault can have separate `SecretKey` and `QuickUnlock` entries.

| Operation | Result |
| --- | --- |
| `capabilities()` | Protection and verification policies the key protector reports without a prompt. Store access can still fail. |
| `inspect(id)` | Missing or stored with a policy. Checks structure without opening the key or verifying the ciphertext. |
| `put(id, value, policy, interaction)` | Protect a new copy and replace the complete entry in one store operation. |
| `get(id, interaction)` | Verify the binding and return the secret in a zeroizing buffer. |
| `remove(id, interaction)` | Remove only the addressed entry. Removing a missing entry succeeds. |

Use `Interaction::Forbid` in background work. An operation that needs user
interaction returns `InteractionRequired` or `KeychainLocked`. Use `Allow`
when the user requests the operation. `UserVerified` requires verification
in the protector. `QuickUnlock` requires this policy and accepts an opaque
capability from the application. Saving `SecretKey` does not enable quick
unlock.

`ProtectedStore` reads, replaces and removes encrypted entries.
`KeyProtector` seals and unseals a 32 byte data key with a binding and a policy.
`DeviceSecrets::new` accepts implementations of these traits. Only use
trusted implementations: the facade relies on their capability reports.
The API is async. Native system calls can block the calling thread, so use a
native worker. Browser futures run on the browser thread and need no `Send`
bound. The crate has no UI or Tokio dependency.

| Target | Store | Key protection |
| --- | --- | --- |
| macOS | Keychain | Secure Enclave P-256 through CryptoKit. `UserVerified` requires enrolled Touch ID. |
| Windows | Credential Manager | TPM RSA through Microsoft Platform Crypto Provider. `DeviceBound` only. |
| Linux | Default Secret Service collection | TPM 2.0 sealed data through `/dev/tpmrm0`. `DeviceBound` only. |
| Browser WASM | IndexedDB for the current origin | WebAuthn PRF. Reports `Authenticator` and supports `AuthenticatorVerified`. |

The macOS adapter uses the Swift compiler from Xcode Command Line Tools.
CryptoKit supplies an opaque key blob that only the same Secure Enclave can
open. The blob is stored inside the encrypted Keychain entry. No persistent
private key item or additional Keychain access group is necessary.
The app can read the verification timestamp from Keychain to decide when to
show the password field. It checks the encrypted timestamp after Touch ID.

Windows needs a user logon session with access to Credential Manager. An
SSH network logon can return `KeychainLocked` while the TPM is available.

Linux needs a user D-Bus session, an unlocked default Secret Service
collection, TPM 2.0 ESAPI development libraries and access to `/dev/tpmrm0`.
The TPM uses a transient owner primary and encrypted command parameters.
It needs an owner hierarchy available with empty authorization. It does not
clear the TPM, allocate a persistent handle, or bind to PCR values.
The native protection status relies on the OS device boundary. It does not
attest the physical source of a TPM. A software TPM is suitable for tests.

WebAuthn needs a secure browser context and an authenticator with PRF support.
The browser does not prove that the credential is hardware protected or bound
to one device. `AuthenticatorVerified` requires user verification for the
passkey and permits protecting a vault key. `DeviceBound` and `UserVerified`
still require the native device boundary. Browser workers can use
`attach_passkey_host` to request credentials through their owning page.
Clearing the browser profile, removing the credential, or changing origin
can make the local data inaccessible.

New entries use a random data key. Each write uses a new nonce. XChaCha20-Poly1305 protects
the value and authenticates its header. The namespace, vault ID, purpose and
policy are bound to both the protected data key and the entry. The store
receives ciphertext only. Secret buffers have redacted `Debug` output and
are zeroized on drop. This protects stored copies. It does not protect
secrets in use from a compromised user session, and removal does not erase
copies from backups. Keep a recovery copy outside this local store.

Run the contract tests with `cargo test -p confidex-device-secrets`. Use a
unique `dev.confidex.test.*` namespace with the native `probe` example and
the `backend-check` feature. `--write` followed by `--read-cleanup` checks
persistence across processes. For the browser probe, build this crate with
`--target wasm32-unknown-unknown --features backend-check`, generate a
`wasm-bindgen --target web` bundle, and pass its directory and a Chrome
executable to `tools/browser-check.mjs`. The browser probe uses an isolated
profile and a virtual authenticator.
