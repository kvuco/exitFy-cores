# exitFy cores

Reproducible Android core builds used by exitFy. This repository does not use
the historical libvless.so or its source.

The current release workflow follows the latest stable XTLS/libXray release,
pins both its tag and commit, runs adapter lifecycle tests, builds four Android
ABIs at API 26, checks reproducibility, verifies ELF metadata and required
exports, and publishes:

- libxray-arm64-v8a.so
- libxray-armeabi-v7a.so
- libxray-x86.so
- libxray-x86_64.so
- manifest.json

The exported ABI is deliberately small:

- StartCore(const char *configJson) returns NULL on success or a malloc-owned
  sanitized error string.
- StopCore() is synchronized and idempotent.

Release integrity uses GitHub's asset digest plus the SHA-256 values in the
manifest. This detects corruption but does not add a trust root independent
from GitHub Releases.

## Local build

Go must match the version required by the pinned libXray tag. Set
ANDROID_NDK_HOME to an Android NDK containing LLVM host tools, then run:

    go test ./...
    ./scripts/build_android.sh dist
    ./scripts/verify_artifacts.py dist

## Upstream

Xray is built through the official XTLS/libXray module, which embeds the
compatible XTLS/Xray-core revision selected by that release. See
THIRD_PARTY.md for licensing.

