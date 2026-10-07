# RGB Lib Go Bindings

Go bindings for the RGB Lib, a Rust library for RGB protocol operations.

## Prerequisites

- Go 1.21 or higher
- Rust and Cargo
- C/C++ compiler (for CGO)
- `uniffi-bindgen-go` tool

## Installation

### Option 1: Use pre-built bindings (if available)

```bash
go get github.com/RGB-Tools/rgb-lib/bindings/uniffi/rgb_lib
```

### Option 2: Build from source

1. Install dependencies:
```bash
make install-deps
```

2. Build the library and generate bindings:
```bash
make build-go
```

Or manually:
```bash
cd bindings/uniffi
./build-go.sh
```

## Usage

```go
package main

import (
    "fmt"
    rgb_lib "github.com/RGB-Tools/rgb-lib/bindings/uniffi/rgb_lib/rgb_lib"
)

func main() {
    // Generate new keys for testnet
    keys := rgb_lib.GenerateKeys(rgb_lib.BitcoinNetworkTestnet)
    
    fmt.Printf("Mnemonic: %s\n", keys.Mnemonic)
    fmt.Printf("Xpub: %s\n", keys.Xpub)
    
    // Always destroy resources when done
    keys.Destroy()
}
```

## Cross-compilation

The library includes platform-specific shared libraries. You need to build for each target platform:

- macOS: `.dylib`
- Linux: `.so` 
- Windows: `.dll`

## Notes

- Always call `.Destroy()` on objects that have it to prevent memory leaks
- The shared library must be available at runtime
- CGO is required for compilation 