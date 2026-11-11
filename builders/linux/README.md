# Linux archive builder

Build application and sync daemon tar archives in pinned Debian or Alpine Rust
containers. Use a Linux amd64 or arm64 host with Python 3.12+ and Docker. Builds
use the host architecture and preserve TPM support.

```sh
CONFIDEX_LIBC=gnu python builders/linux/build.py --arch amd64 --version v1.2.3
CONFIDEX_LIBC=musl python builders/linux/build.py --arch amd64 --version v1.2.3
```

Output is in `dist/releases/`. The client archive contains `bin/confidexm` and
`bin/cfdex`; the daemon archive contains `bin/confidexsyncd`. Extract the matching
archive and run a binary directly. Licenses and `SOURCE.json` travel with it.

The GNU build uses Debian 12 (glibc 2.36). The musl build uses Alpine 3.24.
These builds use system libraries, including libgcc. Native clients need TPM2-TSS libraries;
the GUI also needs X11 or Wayland, xkbcommon and an OpenGL or Vulkan driver.
The daemon needs the matching C runtime and CA certificates for HTTPS. Git object
storage additionally requires Git. See the image package lists for build dependencies.

`CARGO_BUILD_JOBS` defaults to 2 inside the container. Cargo registry data is
cached in `.tools/cargo-linux/`; build output uses `target/gnu/` or `target/musl/`.
See the [artifact contract](../docs/ARTIFACTS.md) for names and versions.
