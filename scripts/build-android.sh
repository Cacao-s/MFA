#!/usr/bin/env bash
# Builds the core as JNI libraries for Android, with the Kotlin bindings.
#
#   ./scripts/build-android.sh [--release]
#
# Needs the Android NDK and cargo-ndk (`cargo install cargo-ndk`). Written
# here so it is ready to run; it has not been executed, because this machine
# has no NDK.
set -euo pipefail

cd "$(dirname "$0")/.."

PROFILE_DIR=debug
CARGO_FLAGS=()
if [[ "${1:-}" == "--release" ]]; then
  PROFILE_DIR=release
  CARGO_FLAGS+=(--release)
fi

OUT=build/android
TARGETS=(
  aarch64-linux-android      # arm64-v8a: almost every current phone
  armv7-linux-androideabi    # armeabi-v7a: older 32-bit devices
  x86_64-linux-android       # emulator on a PC or Intel Mac
)

echo "==> Adding targets"
for target in "${TARGETS[@]}"; do
  rustup target add "$target"
done

rm -rf "$OUT"
mkdir -p "$OUT/jniLibs" "$OUT/kotlin"

echo "==> Building the shared libraries"
# cargo-ndk lays the output out the way Gradle expects under jniLibs/.
cargo ndk -o "$OUT/jniLibs" \
  $(printf -- '-t %s ' "${TARGETS[@]}") \
  build -p mfa-ffi "${CARGO_FLAGS[@]}"

echo "==> Generating the Kotlin bindings"
cargo build -p mfa-ffi --lib "${CARGO_FLAGS[@]}"
cargo run -q -p mfa-ffi --bin uniffi-bindgen -- generate \
  --library "target/$PROFILE_DIR/libmfa_ffi.so" \
  --language kotlin --out-dir "$OUT/kotlin"

echo
echo "Done:"
echo "  $OUT/jniLibs/   copy to app/src/main/jniLibs/"
echo "  $OUT/kotlin/    add to the module's source set"
echo
echo "The Kotlin bindings need net.java.dev.jna:jna with the 'aar' artifact:"
echo "  implementation(\"net.java.dev.jna:jna:5.14.0@aar\")"
