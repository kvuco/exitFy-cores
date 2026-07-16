# Third-party software

The produced Xray libraries include code from:

- XTLS/libXray: https://github.com/XTLS/libXray
- XTLS/Xray-core: https://github.com/XTLS/Xray-core

Both upstream projects are licensed under the Mozilla Public License 2.0.
Each schema 2 release manifest records the exact libXray tag and commit plus
the wrapper commit. The pinned Go module graph records the compatible
Xray-core revision and other dependencies.

The produced exitFy SB libraries include code from:

- SagerNet/sing-box: https://github.com/SagerNet/sing-box
- the exact Go module graph recorded in `singbox/go.mod` and `singbox/go.sum`

The combined SB shared libraries are distributed under GPL-3.0-or-later.
The complete GPL text is stored in `singbox/COPYING`. Each SB manifest records
the exact upstream tag and commit, Go version, build tags, NDK version and
wrapper commit. Every SB release attaches a reproducible corresponding-source
bundle. The release naming and notes explicitly state that the build is not
affiliated with or endorsed by SagerNet.
