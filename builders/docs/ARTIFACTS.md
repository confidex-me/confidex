# Release artifact contract

Schema 1 is in `builders/artifacts.json`. Its copy in the website repository is
`data/release-artifacts.json`. Both repositories test the same example fixtures.
Update both copies together when a new package type is added.

The build version is the release tag without an initial `v`, followed by `+g`
and the first **six** lowercase hexadecimal characters of the full source commit
SHA. Example: tag `v1.2.3`, commit `abcdef012345…` gives `1.2.3+gabcdef`.
A tag with SemVer build metadata appends `.gabcdef` to that metadata instead.
The original release tag remains the Docker image tag; `latest` is also published.

| Component | Filename |
| --- | --- |
| macOS application and CLI | `confidex-{version}-{arch}-macos.dmg` |
| Windows application and CLI | `confidex-{version}-{arch}-windows.msi` |
| Linux application and CLI | `confidex-{version}-{arch}-linux-{libc}.tar.gz` |
| macOS sync daemon | `confidexsyncd-{version}-{arch}-macos.tar.gz` |
| Windows sync daemon | `confidexsyncd-{version}-{arch}-windows.zip` |
| Linux sync daemon | `confidexsyncd-{version}-{arch}-linux-{libc}.tar.gz` |
| Browser application | `confidex-{version}-web.tar.gz` |
| Sync daemon Worker | `confidexsyncd-{version}-worker.tar.gz` |
| Self-host bundle | `confidex-selfhost-{version}.zip` |

`arch` is `amd64` or `arm64`. `libc` is `gnu` or `musl`. Names are case-sensitive.
`SHA256SUMS` contains checksums and is not a download package. The website offers
only desktop application packages as native client downloads.

`CONFIDEX_BUILD_VERSION` supplies the version to Rust during compilation.
`cfdex --version`, `confidexm --version`, `confidexsyncd --version`, the browser
handle's `version()` and web `BUILD.json` expose it. Native package `SOURCE.json`
also records the full source commit. Direct Cargo builds use the package version.
MSI ProductVersion and macOS numeric bundle versions contain only `major.minor.patch`;
macOS `CFBundleGetInfoString` retains the full build version. Build hashes are
never written back into Cargo manifests or cryptographic wire formats.
