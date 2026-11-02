#!/usr/bin/env bash
# Builds the core as an XCFramework for macOS and iOS, with the Swift bindings
# beside it.
#
#   ./scripts/build-apple.sh [--release]
#
# Needs macOS with Xcode.
set -euo pipefail

cd "$(dirname "$0")/.."

PROFILE_DIR=debug
CARGO_FLAGS=()
if [[ "${1:-}" == "--release" ]]; then
  PROFILE_DIR=release
  CARGO_FLAGS+=(--release)
fi

OUT=build/apple
TARGETS=(
  aarch64-apple-darwin      # Apple silicon Macs
  x86_64-apple-darwin       # Intel Macs
  aarch64-apple-ios         # iPhone and iPad
  aarch64-apple-ios-sim     # Simulator on Apple silicon
  x86_64-apple-ios          # Simulator on an Intel Mac
)

echo "==> Adding targets"
for target in "${TARGETS[@]}"; do
  rustup target add "$target"
done

echo "==> Building the static library"
# qr-image goes into every slice, including iOS, which does not use it: one set
# of Swift bindings is compiled into both app targets, and those bindings call
# a checksum symbol for every exported function. A feature enabled on only one
# platform would leave that symbol missing and fail to link on the other.
for target in "${TARGETS[@]}"; do
  cargo build -p mfa-ffi --lib --features qr-image "${CARGO_FLAGS[@]}" --target "$target"
done

echo "==> Generating the Swift bindings"
rm -rf "$OUT"
mkdir -p "$OUT/Headers" "$OUT/Sources"
# Generated from the built library, so the bindings cannot drift from it.
cargo run -q -p mfa-ffi --bin uniffi-bindgen -- generate \
  --library "target/aarch64-apple-darwin/$PROFILE_DIR/libmfa_ffi.dylib" \
  --language swift --out-dir "$OUT/Sources"

# UniFFI emits the header and modulemap next to the Swift; the XCFramework
# wants them in a headers directory, and the modulemap has to be called
# `module.modulemap`.
mv "$OUT/Sources"/*.h "$OUT/Headers/"
mv "$OUT/Sources"/*.modulemap "$OUT/Headers/module.modulemap"

echo "==> Making the fat slices"
# Both slices carry Apple silicon and Intel. The simulator one has to: Xcode
# builds a simulator target for every architecture the Mac can run, so an
# arm64-only simulator library fails to link even on an Apple silicon Mac.
mkdir -p "$OUT/macos" "$OUT/iossim"
lipo -create \
  "target/aarch64-apple-darwin/$PROFILE_DIR/libmfa_ffi.a" \
  "target/x86_64-apple-darwin/$PROFILE_DIR/libmfa_ffi.a" \
  -output "$OUT/macos/libmfa_ffi.a"
lipo -create \
  "target/aarch64-apple-ios-sim/$PROFILE_DIR/libmfa_ffi.a" \
  "target/x86_64-apple-ios/$PROFILE_DIR/libmfa_ffi.a" \
  -output "$OUT/iossim/libmfa_ffi.a"

echo "==> Assembling the XCFramework"
xcodebuild -create-xcframework \
  -library "$OUT/macos/libmfa_ffi.a"                                  -headers "$OUT/Headers" \
  -library "target/aarch64-apple-ios/$PROFILE_DIR/libmfa_ffi.a"       -headers "$OUT/Headers" \
  -library "$OUT/iossim/libmfa_ffi.a"                                 -headers "$OUT/Headers" \
  -output "$OUT/MfaCoreFFI.xcframework"

echo
echo "Done:"
echo "  $OUT/MfaCoreFFI.xcframework   linked by apple/project.yml"
echo "  $OUT/Sources/MfaCore.swift    compiled into both app targets"
echo
echo "Then:  cd apple && xcodegen generate && open MFA.xcodeproj"
