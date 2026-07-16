#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: $0 CORE_SO [ADB_SERIAL]" >&2
  exit 2
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
# shellcheck source=ndk_env.sh
source "$script_dir/ndk_env.sh"

core="$1"
serial="${2:-${ANDROID_SERIAL:-}}"
adb_args=()
if [[ -n "$serial" ]]; then adb_args=(-s "$serial"); fi

case "$(basename "$core")" in
  libexitfy-sb-arm64-v8a.so) abi="arm64-v8a"; compiler="aarch64-linux-android26-clang" ;;
  libexitfy-sb-armeabi-v7a.so) abi="armeabi-v7a"; compiler="armv7a-linux-androideabi26-clang" ;;
  libexitfy-sb-x86.so) abi="x86"; compiler="i686-linux-android26-clang" ;;
  libexitfy-sb-x86_64.so) abi="x86_64"; compiler="x86_64-linux-android26-clang" ;;
  *) echo "unsupported SB core artifact name: $core" >&2; exit 2 ;;
esac

device_api="$(adb "${adb_args[@]}" shell getprop ro.build.version.sdk | tr -d '\r')"
device_abi="$(adb "${adb_args[@]}" shell getprop ro.product.cpu.abi | tr -d '\r')"
if [[ "$device_api" -lt 26 ]]; then
  echo "Android API 26+ is required, got $device_api" >&2
  exit 1
fi
if [[ "$device_abi" != "$abi" ]]; then
  echo "device ABI $device_abi does not match artifact ABI $abi" >&2
  exit 1
fi

ndk_home="$(exitfy_find_ndk)"
toolchain="$(exitfy_ndk_toolchain "$ndk_home")"
cc="$(exitfy_find_tool "$toolchain" "$compiler")"
temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"; adb "${adb_args[@]}" shell rm -rf /data/local/tmp/exitfy-sb-smoke >/dev/null 2>&1 || true' EXIT

"$cc" -std=c11 -Wall -Wextra -Werror -fPIE -pie \
  "$script_dir/android_smoke.c" -ldl -o "$temporary/exitfy-core-smoke"
adb "${adb_args[@]}" shell mkdir -p /data/local/tmp/exitfy-sb-smoke
adb "${adb_args[@]}" push "$temporary/exitfy-core-smoke" /data/local/tmp/exitfy-sb-smoke/runner
adb "${adb_args[@]}" push "$core" /data/local/tmp/exitfy-sb-smoke/core.so
adb "${adb_args[@]}" shell chmod 700 /data/local/tmp/exitfy-sb-smoke/runner

for config in "$repo_root"/singbox/testdata/*.json; do
  name="$(basename "$config")"
  adb "${adb_args[@]}" push "$config" "/data/local/tmp/exitfy-sb-smoke/$name"
  if [[ "$name" == unsupported-* ]]; then
    if adb "${adb_args[@]}" shell /data/local/tmp/exitfy-sb-smoke/runner \
      /data/local/tmp/exitfy-sb-smoke/core.so "/data/local/tmp/exitfy-sb-smoke/$name"; then
      echo "unsupported fixture was accepted: $name" >&2
      exit 1
    fi
  else
    adb "${adb_args[@]}" shell /data/local/tmp/exitfy-sb-smoke/runner \
      /data/local/tmp/exitfy-sb-smoke/core.so "/data/local/tmp/exitfy-sb-smoke/$name"
  fi
done
