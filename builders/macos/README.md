# macOS builder

Builds a DMG with `Confidex.app` and a link to `/Applications`. The app includes
the GUI in `Contents/MacOS/confidexm` and the CLI in `Contents/MacOS/cfdex`.
A separate archive contains the native synchronization daemon.

Install Rust, Python 3.12+ and Xcode Command Line Tools, then run:

```sh
python3 builders/macos/build.py --arch arm64
python3 builders/macos/build.py --arch amd64
```

The other architecture can be compiled with the same Xcode SDK. Output is in
`dist/releases/`. The builder verifies the app signature and DMG checksum.
Signing is ad hoc; Developer ID signing and notarization require separate setup.

The website logo is copied into `apps/confidex/assets/icons/confidex.svg`.
PNG sizes, the macOS icon set, ICNS and Windows ICO are committed. To regenerate
them, run `npm ci`, `npx playwright install chromium`, then `node tools/icons.mjs`
on macOS. This does not contact a CDN at application runtime.
