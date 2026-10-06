# JVM on Linux via C-FFI

This document describes the recommended server-side integration path for JVM
applications on Linux using `rgb-lib` C-FFI artifacts.

## Why this path

The public Android Kotlin artifact is Android-oriented. For server-side JVM on
Linux, use native C-FFI outputs from this repository:

- `librgblibcffi.so` (shared native library)
- `rgblib.h` (C header)
- `rgblib.hpp` (C++ header, optional)

JVM code can load the native library via JNA/JNI and call C-FFI entry points.

## Build Linux artifacts locally

Build from repository root:

```sh
cd bindings/c-ffi
cargo build --release --target x86_64-unknown-linux-gnu
```

Outputs:

- `bindings/c-ffi/target/x86_64-unknown-linux-gnu/release/librgblibcffi.so`
- `bindings/c-ffi/rgblib.h`
- `bindings/c-ffi/rgblib.hpp`

For Linux ARM64:

```sh
cd bindings/c-ffi
cargo build --release --target aarch64-unknown-linux-gnu
```

## Build Linux artifacts in CI

Use workflow `C-FFI Linux Artifacts`:

- Trigger: `workflow_dispatch`
- Platforms: `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`
- Output: `rgb-lib-cffi-linux-<target>.tar.gz` containing `.so` and headers

## Packaging for JVM consumption

A common server packaging approach is:

1. Include `librgblibcffi.so` in your deployment image.
2. Load it from JVM startup (`java.library.path`, `System.load`, or JNA config).
3. Keep headers in your binding-generation/build pipeline (not required at runtime).

## Notes

- Treat this as a Linux server distribution path; it is separate from Android AAR.
- Keep native library and JVM wrapper versions in lockstep.
