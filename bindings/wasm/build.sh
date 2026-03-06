#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
wasm-pack build --target web --out-dir pkg
echo "Build complete. Serve with: python3 -m http.server 8000"
echo "Then open: http://localhost:8000/examples/simple-test.html"
