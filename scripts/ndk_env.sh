#!/usr/bin/env bash

# Shared Android NDK discovery for Linux and macOS hosts. Explicit variables
# win; a configured pin is exact, while unpinned SDK discovery uses numeric
# revision ordering rather than lexical directory ordering.

exitfy_ndk_revision() {
  local ndk_home="$1"
  local properties="$ndk_home/source.properties"
  if [[ ! -f "$properties" ]]; then
    echo "NDK source.properties is missing: $ndk_home" >&2
    return 1
  fi
  local parsed=""
  parsed="$(awk '
    BEGIN { count = 0; value = "" }
    {
      line = $0
      sub(/\r$/, "", line)
      equals = index(line, "=")
      if (equals == 0) next
      key = substr(line, 1, equals - 1)
      candidate = substr(line, equals + 1)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", key)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", candidate)
      if (key == "Pkg.Revision") { count += 1; value = candidate }
    }
    END { printf "%d|%s", count, value }
  ' "$properties")" || return 1
  local count="${parsed%%|*}"
  local revision="${parsed#*|}"
  if [[ "$count" != 1 || ! "$revision" =~ ^[0-9]+(\.[0-9]+)*$ ]]; then
    echo "NDK source.properties has an invalid Pkg.Revision: $ndk_home" >&2
    return 1
  fi
  printf '%s\n' "$revision"
}

exitfy_validate_ndk() {
  local candidate="$1"
  local expected="${2:-}"
  if [[ ! -d "$candidate/toolchains/llvm/prebuilt" ]]; then
    echo "NDK LLVM toolchain is missing: $candidate" >&2
    return 1
  fi
  local actual=""
  actual="$(exitfy_ndk_revision "$candidate")" || return 1
  if [[ -n "$expected" && "$actual" != "$expected" ]]; then
    echo "NDK revision mismatch: expected $expected, got $actual" >&2
    return 1
  fi
}

exitfy_numeric_version_greater() {
  local LC_ALL=C
  local left="$1"
  local right="$2"
  local old_ifs="$IFS"
  local -a left_parts=()
  local -a right_parts=()
  IFS='.' read -r -a left_parts <<< "$left"
  IFS='.' read -r -a right_parts <<< "$right"
  IFS="$old_ifs"
  local count="${#left_parts[@]}"
  if (( ${#right_parts[@]} > count )); then count="${#right_parts[@]}"; fi
  local index=0
  local left_value=""
  local right_value=""
  for ((index = 0; index < count; index += 1)); do
    left_value="${left_parts[index]:-0}"
    right_value="${right_parts[index]:-0}"
    while [[ ${#left_value} -gt 1 && "$left_value" == 0* ]]; do
      left_value="${left_value#0}"
    done
    while [[ ${#right_value} -gt 1 && "$right_value" == 0* ]]; do
      right_value="${right_value#0}"
    done
    if (( ${#left_value} > ${#right_value} )); then return 0; fi
    if (( ${#left_value} < ${#right_value} )); then return 1; fi
    if [[ "$left_value" > "$right_value" ]]; then return 0; fi
    if [[ "$left_value" < "$right_value" ]]; then return 1; fi
  done
  return 1
}

exitfy_find_ndk() {
  local candidate=""
  if [[ -n "${NDK_VERSION:-}" && ! "$NDK_VERSION" =~ ^[0-9]+(\.[0-9]+)*$ ]]; then
    echo "Pinned Android NDK revision is invalid: $NDK_VERSION" >&2
    return 1
  fi
  for candidate in "${ANDROID_NDK_HOME:-}" "${ANDROID_NDK_ROOT:-}"; do
    [[ -n "$candidate" ]] || continue
    exitfy_validate_ndk "$candidate" "${NDK_VERSION:-}" || return 1
    printf '%s\n' "$candidate"
    return 0
  done

  local sdk=""
  local saw_sdk=false
  for sdk in "${ANDROID_SDK_ROOT:-}" "${ANDROID_HOME:-}"; do
    [[ -n "$sdk" ]] || continue
    saw_sdk=true
    if [[ -n "${NDK_VERSION:-}" ]]; then
      candidate="$sdk/ndk/$NDK_VERSION"
      if [[ -d "$candidate" ]]; then
        exitfy_validate_ndk "$candidate" "$NDK_VERSION" || return 1
        printf '%s\n' "$candidate"
        return 0
      fi
      continue
    fi
    if [[ -d "$sdk/ndk" ]]; then
      local best=""
      local best_revision=""
      local revision=""
      for candidate in "$sdk"/ndk/*; do
        [[ -d "$candidate" ]] || continue
        revision="$(basename "$candidate")"
        [[ "$revision" =~ ^[0-9]+(\.[0-9]+)*$ ]] || continue
        if [[ -z "$best" ]] || exitfy_numeric_version_greater "$revision" "$best_revision"; then
          best="$candidate"
          best_revision="$revision"
        fi
      done
      if [[ -n "$best" ]]; then
        exitfy_validate_ndk "$best" "$best_revision" || return 1
        printf '%s\n' "$best"
        return 0
      fi
    fi
  done
  if [[ -n "${NDK_VERSION:-}" && "$saw_sdk" == true ]]; then
    echo "Pinned Android NDK $NDK_VERSION is not installed" >&2
    return 1
  fi
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
