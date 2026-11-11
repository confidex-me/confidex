# Release builders

Python entry points build and package one platform from a Git checkout. Use
Python 3.12 or later. Run `python builders/<platform>/build.py --help` for its
options. `--arch` accepts `amd64` or `arm64`; native builds use a matching runner.

`--version` or `RELEASE_VERSION` accepts a semantic version with an optional `v`
prefix. Without it, the builder uses the app's Cargo version. The build updates
workspace package versions when needed and keeps non-workspace dependencies
locked. Output archives are in `dist/releases/`.

`common.py` supplies Cargo invocation, source commit metadata, license files,
archive modes and SHA-256 checksums. `version.py` validates all package manifests
before changing versions. Platform scripts own their tool and packaging steps.
Detailed platform requirements are in the root build guide.

```sh
python -m unittest discover -s builders -p 'test_common.py'
```
