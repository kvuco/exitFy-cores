#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 OUTPUT_DIR" >&2
  exit 2
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
# shellcheck source=ndk_env.sh
source "$script_dir/ndk_env.sh"

output_dir="$1"
module_dir="$repo_root/singbox"
ndk_home="$(exitfy_find_ndk)"
toolchain="$(exitfy_ndk_toolchain "$ndk_home")"
mkdir -p "$output_dir"
# go build runs from the nested sing-box module. Resolve the caller-provided
# directory first so relative CI paths such as dist/ keep their intended root.
output_dir="$(cd "$output_dir" && pwd)"

build_tags="with_quic,with_utls,badlinkname,tfogo_checklinkname0"
upstream_version="$({ cd "$module_dir"; GOTOOLCHAIN=local go list -m -f '{{.Version}}' github.com/sagernet/sing-box; })"
if [[ ! "$upstream_version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "unexpected pinned upstream version: $upstream_version" >&2
  exit 1
fi

build_one() {
  local abi="$1"
  local goarch="$2"
  local cc="$3"
  local goarm="${4:-}"
  local output="$output_dir/libexitfy-sb-$abi.so"
  local compiler
  compiler="$(exitfy_find_tool "$toolchain" "$cc")"

  echo "building SB core $abi from $upstream_version"
  build_env=(
    GOTOOLCHAIN=local
    CGO_ENABLED=1
    GOOS=android
    GOARCH="$goarch"
    CC="$compiler"
  )
  if [[ -n "$goarm" ]]; then build_env+=(GOARM="$goarm"); fi
  (
    cd "$module_dir"
    env "${build_env[@]}" go build \
      -buildmode=c-shared -trimpath -buildvcs=false \
      -tags "$build_tags" \
      -ldflags="-X github.com/sagernet/sing-box/constant.Version=${upstream_version#v} -X internal/godebug.defaultGODEBUG=multipathtcp=0 -s -w -buildid= -checklinkname=0 -extldflags=-Wl,--version-script=$repo_root/scripts/core_exports.map,-z,max-page-size=16384" \
      -o "$output" ./cmd/exitfy-sb
  )
  rm -f "${output%.so}.h"
}

build_one arm64-v8a arm64 aarch64-linux-android26-clang
build_one armeabi-v7a arm armv7a-linux-androideabi26-clang 7
build_one x86 386 i686-linux-android26-clang
build_one x86_64 amd64 x86_64-linux-android26-clang
