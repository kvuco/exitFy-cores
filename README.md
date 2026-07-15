# exitFy cores

Reproducible Android core builds used by exitFy. This repository does not use
the historical libvless.so or its source.

The current release workflow follows the latest stable XTLS/libXray release,
pins both its tag and commit, runs adapter lifecycle tests, builds four Android
ABIs at API 26, checks reproducibility, verifies ELF metadata and required
exports, performs a real start/stop on an Android API 26 x86_64 emulator, and
publishes:

- libxray-arm64-v8a.so
- libxray-armeabi-v7a.so
- libxray-x86.so
- libxray-x86_64.so
- manifest.json

`manifest.json` uses schema 2 with `coreApi: 1` and `configContract: 1`.
Stable release names end in `-w1`, for example `xray-v26.7.11-w1`.

The exported ABI is deliberately small:

- StartCore(const char *configJson) returns NULL on success or a malloc-owned
  sanitized error string.
- StopCore() is synchronized and idempotent.

Release integrity uses GitHub's asset digest plus the SHA-256 values in the
manifest. This detects corruption but does not add a trust root independent
from GitHub Releases.

## Local build

Go must match the version required by the pinned libXray tag. Set
`ANDROID_NDK_HOME`, `ANDROID_NDK_ROOT`, or an Android SDK root containing an
installed NDK, then run:

    ./scripts/audit_public_tree.py
    go test ./...
    ./scripts/build_android.sh dist
    ./scripts/verify_artifacts.py dist

With a matching Android device or emulator connected, run:

    ./scripts/run_android_smoke.sh dist/libxray-x86_64.so

The public-tree audit examines tracked and untracked publishable files. It
rejects packaged client artifacts, client implementation namespaces, local
home paths, and unapproved binaries before repository pushes or releases.

## Upstream

Xray is built through the official XTLS/libXray module, which embeds the
compatible XTLS/Xray-core revision selected by that release. See
THIRD_PARTY.md for licensing.
