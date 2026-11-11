# confidex-image-codec

The browser image worker's WASM entry point for JPEG/PNG/WebP to WebP
compression. It uses the same bounded Rust codec as the native client.

Build through `make web`. The `image_compress(bytes, quality, keep_exif)` export
runs in a separate worker with a 2 GiB memory ceiling. The UI and browser
adapters remain in `confidex-ui` and `apps/confidex/web`.

```sh
cargo test --locked -p confidex-image-codec
```

See [build instructions](../../docs/BUILD.md) for target prerequisites.
