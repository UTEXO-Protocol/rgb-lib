#!/bin/bash

set -e

echo "Building RGB Lib Go bindings..."

# Check if uniffi-bindgen-go is installed
if ! command -v uniffi-bindgen-go &> /dev/null; then
    echo "ERROR: uniffi-bindgen-go is not installed"
    echo "Install with: go install github.com/NordSecurity/uniffi-bindgen-go/cmd/uniffi-bindgen-go@latest"
    exit 1
fi

# Build the Rust library
echo "Building Rust library..."
cargo build --release

# Generate Go bindings
echo "Generating Go bindings..."
uniffi-bindgen-go src/rgb-lib.udl --out-dir rgb_lib --config uniffi.toml

# Determine library extension
case "$(uname -s)" in
    Darwin*) LIB_EXT=".dylib" ;;
    Linux*)  LIB_EXT=".so" ;;
    CYGWIN*|MINGW32*|MSYS*|MINGW*) LIB_EXT=".dll" ;;
    *) echo "ERROR: Unsupported OS"; exit 1 ;;
esac

# Copy shared library
RUST_LIB="target/release/librgblibuniffi${LIB_EXT}"
GO_LIB_PATH="rgb_lib/rgb_lib/librgblibuniffi${LIB_EXT}"

if [ -f "$RUST_LIB" ]; then
    echo "Copying shared library..."
    cp "$RUST_LIB" "$GO_LIB_PATH"
else
    echo "ERROR: Library not found at $RUST_LIB"
    exit 1
fi

# Create CGO configuration
echo "Creating CGO configuration..."
cat > rgb_lib/rgb_lib/cgo_flags.go << 'EOF'
//go:build !windows

package rgb_lib

/*
#cgo LDFLAGS: -L${SRCDIR} -lrgblibuniffi
#cgo darwin LDFLAGS: -Wl,-rpath,${SRCDIR}
#cgo linux LDFLAGS: -Wl,-rpath,${SRCDIR}
*/
import "C"
EOF

cat > rgb_lib/rgb_lib/cgo_flags_windows.go << 'EOF'
//go:build windows

package rgb_lib

/*
#cgo LDFLAGS: -L${SRCDIR} -lrgblibuniffi
*/
import "C"
EOF

# Update Go module
echo "Updating Go module..."
cd rgb_lib && go mod tidy

echo "Build completed successfully"
echo "Go bindings available in: bindings/uniffi/rgb_lib/" 