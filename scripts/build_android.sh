#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 OUTPUT_DIR" >&2
  exit 2
fi

: "${ANDROID_NDK_HOME:?ANDROID_NDK_HOME must point to an Android NDK}"

output_dir="$1"
toolchain="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin"
mkdir -p "$output_dir"

build_one() {
  local abi="$1"
  local goarch="$2"
  local cc="$3"
  local goarm="${4:-}"
  local output="$output_dir/libxray-$abi.so"

  echo "building $abi"
  if [[ -n "$goarm" ]]; then
    CGO_ENABLED=1 GOOS=android GOARCH="$goarch" GOARM="$goarm" \
      CC="$toolchain/$cc" \
      go build -buildmode=c-shared -trimpath -buildvcs=false \
        -ldflags="-s -w -buildid=" -o "$output" ./cmd/exitfy-xray
  else
    CGO_ENABLED=1 GOOS=android GOARCH="$goarch" \
      CC="$toolchain/$cc" \
      go build -buildmode=c-shared -trimpath -buildvcs=false \
        -ldflags="-s -w -buildid=" -o "$output" ./cmd/exitfy-xray
  fi
}

build_one arm64-v8a arm64 aarch64-linux-android26-clang
build_one armeabi-v7a arm armv7a-linux-androideabi26-clang 7
build_one x86 386 i686-linux-android26-clang
build_one x86_64 amd64 x86_64-linux-android26-clang

