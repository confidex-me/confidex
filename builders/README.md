# Release builders

Python entry points build and package one platform from a Git checkout. Use
Python 3.12 or later. Run `python builders/<platform>/build.py --help` for its
options. `--arch` accepts `amd64` or `arm64`; native builds use a matching runner. The macOS builder can also cross-compile
with the installed Xcode SDK.

`--version` or `RELEASE_VERSION` accepts a semantic release tag with an optional
`v` prefix. The builder adds `+g` and the first six characters of the source
commit SHA, for example `1.2.3+gabcdef`. Without a tag it uses the app's Cargo
version. Sources and lock files stay unchanged. Output is in `dist/releases/`.

`common.py` supplies Cargo invocation, source metadata, licenses and archives.
`version.py` derives the build version. Platform scripts own packaging steps.
See the [artifact contract](docs/ARTIFACTS.md) for stable names and versions,
and the root build guide for platform requirements.

```sh
python -m unittest discover -s builders -p 'test_common.py'
```
