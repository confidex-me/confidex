# Browser application builder

Build the browser client and its separate image-codec worker with Rust 1.98.0,
Node.js from `.node-version` and Python 3.12+ on macOS or Linux.

```sh
npm ci
python builders/wasm/build.py --version v1.2.3
```

The builder installs checksum-verified wasm-bindgen 0.2.130 and Binaryen 133 in
`.tools/`, checks cached versions and applies `wasm-opt -Oz`. The app memory cap
is 256 MiB; the separate image codec cap is 2 GiB. Fonts stay beside the WASM.
`dist/web/` contains the deployable app, offline shell, licenses and `BUILD.json`.
The complete package must remain below 25,000,000 bytes. A matching web tar archive
is written to `dist/releases/`; see the [artifact contract](../docs/ARTIFACTS.md).
