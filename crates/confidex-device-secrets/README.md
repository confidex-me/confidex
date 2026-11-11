# confidex-device-secrets

A shared contract for local protected secrets. Native backends use Keychain +
Secure Enclave, Windows Credential Manager + TPM, or Linux Secret Service + TPM.
Browser WASM uses IndexedDB and WebAuthn PRF; it does not attest physical hardware.

Call `platform::system(namespace)` for the local backend, then use `put`, `get`
and `remove` with a `SecretId`, `AccessPolicy` and `Interaction`. Keep namespaces
stable. Use `Interaction::Forbid` for background work. Native calls can block;
run them outside the UI thread.

`ProtectedStore` and `KeyProtector` are the extension interfaces.
See [platform requirements and API examples](docs/PLATFORMS.md) and
[build instructions](../../docs/BUILD.md).

```sh
cargo test --locked -p confidex-device-secrets
```

Contract tests use test backends. Hardware checks require a suitable device,
user session and explicit interaction.
