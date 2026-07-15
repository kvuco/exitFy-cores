#!/usr/bin/env bash

# Shared Android NDK discovery for Linux and macOS hosts. Explicit variables
# win; otherwise the newest installed NDK under an Android SDK is selected.

exitfy_find_ndk() {
  local candidate=""
  for candidate in "${ANDROID_NDK_HOME:-}" "${ANDROID_NDK_ROOT:-}"; do
    if [[ -n "$candidate" && -d "$candidate/toolchains/llvm/prebuilt" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done

  local sdk=""
  for sdk in "${ANDROID_SDK_ROOT:-}" "${ANDROID_HOME:-}"; do
    [[ -n "$sdk" ]] || continue
    if [[ -n "${NDK_VERSION:-}" && -d "$sdk/ndk/$NDK_VERSION/toolchains/llvm/prebuilt" ]]; then
      printf '%s\n' "$sdk/ndk/$NDK_VERSION"
      return 0
    fi
    if [[ -d "$sdk/ndk" ]]; then
      candidate="$(find "$sdk/ndk" -mindepth 1 -maxdepth 1 -type d \
        -name '[0-9]*' -print | LC_ALL=C sort | tail -n 1)"
      if [[ -n "$candidate" && -d "$candidate/toolchains/llvm/prebuilt" ]]; then
        printf '%s\n' "$candidate"
        return 0
      fi
    fi
  done
  echo "Android NDK not found; set ANDROID_NDK_HOME or ANDROID_SDK_ROOT" >&2
  return 1
}

exitfy_ndk_toolchain() {
  local ndk_home="$1"
  local host_tag=""
  case "$(uname -s):$(uname -m)" in
    Linux:x86_64|Linux:amd64) host_tag="linux-x86_64" ;;
    Darwin:x86_64|Darwin:arm64) host_tag="darwin-x86_64" ;;
  esac
  if [[ -n "$host_tag" && -d "$ndk_home/toolchains/llvm/prebuilt/$host_tag/bin" ]]; then
    printf '%s\n' "$ndk_home/toolchains/llvm/prebuilt/$host_tag/bin"
    return 0
  fi

  local candidate=""
  for candidate in "$ndk_home"/toolchains/llvm/prebuilt/*/bin; do
    if [[ -d "$candidate" && ( -x "$candidate/clang" || -x "$candidate/clang.exe" ) ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  echo "No compatible LLVM toolchain found in NDK: $ndk_home" >&2
  return 1
}

exitfy_find_tool() {
  local directory="$1"
  local name="$2"
  local suffix=""
  for suffix in "" ".cmd" ".exe"; do
    if [[ -x "$directory/$name$suffix" ]]; then
      printf '%s\n' "$directory/$name$suffix"
      return 0
    fi
  done
  echo "NDK tool is missing: $name" >&2
  return 1
}
