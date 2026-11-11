# confidex-ui

Shared egui vault screens, field controls, viewers, themes and translations.
The host supplies storage, background work, file dialogs and clipboard access.

Create `VaultApp::new(ctx, runtime)` with a `Runtime` implementation, install
the required host callbacks, then call `show(ui)`. `ui_kit` exposes reusable
components. `embedded-fonts` is enabled for native clients; browser builds load
additional fonts as separate assets.

```sh
cargo test --locked -p confidex-ui
```

See [build instructions](../../docs/BUILD.md) for target prerequisites.
