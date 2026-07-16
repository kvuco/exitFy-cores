# exitFy cores

Reproducible Android core builds used by exitFy. The repository builds both
Xray and the exitFy SB core from pinned official upstream source. It does not
use the historical third-party `libvless.so` or its source.

The current release workflow follows the latest stable XTLS/libXray release,
builds the exact commit referenced by its tag, records both pins, runs adapter
lifecycle tests, builds four Android
ABIs at API 26, checks reproducibility, verifies ELF metadata and required
exports, requires 16 KiB-compatible `PT_LOAD` alignment, performs a real
start/stop on an Android API 26 x86_64 emulator, and
publishes:

- libxray-arm64-v8a.so
- libxray-armeabi-v7a.so
- libxray-x86.so
- libxray-x86_64.so
- manifest.json

`manifest.json` uses schema 2 with `coreApi: 2` and `configContract: 1`.
ABI 2 release names use wrapper revision `w2` or newer, for example
`xray-v26.7.11-w2`.

The independent SB workflow tracks only stable SagerNet upstream releases and
uses a separate Go module so its dependency graph cannot change the libXray
build. It enables only the features used by exitFy: QUIC-based outbounds and
uTLS/Reality. It publishes:

- `libexitfy-sb-arm64-v8a.so`
- `libexitfy-sb-armeabi-v7a.so`
- `libexitfy-sb-x86.so`
- `libexitfy-sb-x86_64.so`
- `manifest.json`
- a reproducible corresponding-source bundle

SB release names use `sb-v<upstream>-wN`. These builds are not affiliated
with or endorsed by SagerNet.

The exported ABI is deliberately small:

- StartCore(const char *configJson) returns NULL on success or a malloc-owned
  sanitized error string.
- StopCore() is synchronized and idempotent and returns NULL on success or a
  malloc-owned sanitized error string.

Only `StartCore` and `StopCore` are exported as defined dynamic functions.

Release integrity uses GitHub's asset digest plus the SHA-256 values in the
manifest. This detects corruption but does not add a trust root independent
from GitHub Releases. exitFy deliberately downloads through trust-all TLS;
under that accepted policy, the hashes do not prevent a targeted MITM from
replacing the `.so`, manifest, and advertised digest together.

Workflow build/test jobs are read-only. A separate serialized publisher has
the minimal `contents: write` permission, records exact module pins, creates a
draft, verifies the complete asset set and GitHub digests, and only then makes
the release public. Every external Action is pinned to a full commit SHA; the
API 26 emulator is launched by the repository's own shell runner.

## Local build

Go must match the version required by the pinned libXray tag. Set
`ANDROID_NDK_HOME`, `ANDROID_NDK_ROOT`, or an Android SDK root containing an
installed NDK, then run:

    ./scripts/audit_public_tree.py
    go test ./...
    ./scripts/build_android.sh dist
    ./scripts/verify_artifacts.py dist

For the separate SB module, use the Go version declared in `singbox/go.mod`:

    (cd singbox && go test -tags 'with_quic,with_utls,badlinkname,tfogo_checklinkname0' ./...)
    ./scripts/build_singbox_android.sh dist
    ./scripts/verify_singbox_artifacts.py dist
    ./scripts/build_singbox_source_bundle.py --upstream-version v1.13.14 \
      --output dist/exitfy-sb-v1.13.14-source.tar.gz

With a matching Android device or emulator connected, run:

    ./scripts/run_android_smoke.sh dist/libxray-x86_64.so

The public-tree audit examines tracked and untracked publishable files. It
rejects packaged client artifacts, client implementation namespaces, local
home paths, and unapproved binaries before repository pushes or releases.

## Upstream

Xray is built through the official XTLS/libXray module, which embeds the
compatible XTLS/Xray-core revision selected by that release. See
`THIRD_PARTY.md` for licensing. The combined SB shared libraries are
GPL-3.0-or-later; the complete license text is in `singbox/COPYING` and every
release includes corresponding source.
