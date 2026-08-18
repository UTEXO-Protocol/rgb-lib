# Language bindings for RGB Lib

Bindings for other languages are generated using either [uniffi] or [c-ffi].

See each project's documentation for more details.

## Official

These are the officially supported languages:

| Language | Tool   | Platform              | Location         |
| -------- | ------ | --------------------- | ---------------- |
| C        | c-ffi  | Linux, macOS, Windows | [c-ffi]          |
| C++      | c-ffi  | Linux, macOS, Windows | [c-ffi]          |
| Kotlin   | uniffi | android               | [rgb-lib-kotlin] |
| Node.js  | c-ffi  | Linux, macOS, Windows | [rgb-lib-nodejs] |
| Python   | uniffi | Linux, macOS, Windows | [rgb-lib-python] |
| Swift    | uniffi | iOS, macOS            | [rgb-lib-swift]  |

## Unofficial

These are the unofficially supported languages:

> **Note:** These bindings may or may not use an unmodified rgb-lib,
> we cannot guarantee their reliability and compatibility.

| Language | Tool   | Platform              | Location         |
| -------- | ------ | --------------------- | ---------------- |
| Go       | uniffi | Linux, macOS          | [rgb-lib-go]     |
| C#       | c-ffi  | Linux, macOS, Windows | [rgb-lib-c-sharp]|

[rgb-lib-go]: https://github.com/Utexo-protocol/rgb-lib-go
[rgb-lib-kotlin]: https://github.com/RGB-Tools/rgb-lib-kotlin
[rgb-lib-nodejs]: https://github.com/RGB-Tools/rgb-lib-nodejs
[rgb-lib-python]: https://github.com/RGB-Tools/rgb-lib-python
[rgb-lib-swift]: https://github.com/RGB-Tools/rgb-lib-swift
[rgb-lib-c-sharp]: https://github.com/UTEXO-Protocol/rgb-lib-c-sharp
[c-ffi]: c-ffi/
[uniffi]: uniffi/
