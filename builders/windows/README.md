# Windows MSI builder

Build the GUI, CLI and sync daemon on Windows with Rust 1.98.0, the Visual C++
build tools, Python 3.12+ and .NET SDK 10.0.404. Use a native amd64 or arm64 runner.
The builder installs WiX 5.0.2 into the repository-local `.tools` cache.

```powershell
python builders/windows/build.py --arch amd64 --version v1.2.3
```

`dist/releases/` receives an MSI with `confidexm.exe`, `cfdex.exe`, the shared
application icon, licenses and source metadata, plus a separate sync daemon ZIP.
The MSI adds a Start menu shortcut and the CLI directory to the system PATH.
It supports upgrades and removes installed files on uninstall. Vault and keychain
data are outside the installation directory and are never packaged or removed.
An administrator must approve installation. Packages are currently unsigned.

MSI ProductVersion uses the three numeric version components. The full version
is in the filename, `CONFIDEXBUILDVERSION`, `SOURCE.json` and `cfdex --version`.
Use a higher numeric version for an upgrade. See the [artifact contract](../docs/ARTIFACTS.md).
