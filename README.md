# exitFy cores

Reproducible Android core builds used by exitFy. The repository builds both
Xray and the exitFy SB core from pinned official upstream source. It does not
use the historical third-party `libvless.so` or its source.

The current release workflow follows the latest stable XTLS/libXray release,
builds the exact commit referenced by its tag, records both pins, runs adapter
lifecycle tests, builds only Android `arm64-v8a` at API 29, checks
reproducibility, verifies ELF64/`EM_AARCH64` metadata and required exports,
requires 16 KiB-compatible `PT_LOAD` alignment, and publishes:

- libxray-arm64-v8a.so
- manifest.json

`manifest.json` uses schema 3 with `coreApi: 2`, `configContract: 1`, and
`minAndroidApi: 29`.
ABI 2 release names use wrapper revision `w2` or newer, for example
`xray-v26.7.11-w2`.

The independent SB workflow tracks only stable SagerNet upstream releases and
uses a separate Go module so its dependency graph cannot change the libXray
build. It enables only the features used by exitFy: QUIC-based outbounds and
uTLS/Reality. It publishes:

- `libexitfy-sb-arm64-v8a.so`
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
the release public. Publisher-only reruns empty and reuse their exact draft,
retarget it to the same verified wrapper commit, and check both the draft target
and final Git tag against that commit. A read-only build token cannot enumerate
draft releases, so every new workflow run also adds a monotonic run-specific
offset to the visible public wrapper maximum. That reservation scheme prevents
an invisible stale draft from capturing a later run's candidate tag; the epoch
is explicitly bumped if a workflow counter is ever reset. The publisher still
refuses to retarget any older draft's provenance. Every external Action is
pinned to a full commit SHA. Android emulator/device smoke is intentionally not
part of CI; it remains a downstream device-testing responsibility.

The hardened publishers live at unique v2 workflow paths. A job-level guard
rejects `workflow_dispatch` from anything except the default branch before a
runner or Action starts. Candidate artifact names are stable for the workflow
run, so both a full rerun and a failed-publisher-only rerun consume the same
verified candidate.

### One-time legacy workflow retirement

The former release workflow identities had rerunnable runs created before the
full-SHA Action policy. Removing their files from the default branch blocks
new manual dispatches, but completed runs can remain rerunnable for up to 30
days. Retirement therefore happens in two phases. Do not push the workflow-path
migration until the pre-migration phase below has succeeded.

While the default branch still contains the two legacy paths, generate a
read-only plan from this hardened worktree:

    ./scripts/retire_legacy_workflows.py

The plan discovers the legacy workflow IDs from their exact paths; IDs are
never assumed from documentation. Every `gh api` call is explicitly pinned to
`github.com`, regardless of `GH_HOST`; the host is shown in the plan and bound
into the token. The plan lists every run and prints a
snapshot-bound `applyToken`. If any run is not completed, cancel it and
generate a new plan. After explicit operator approval of the listed workflow
and run IDs, copy that exact token into:

    ./scripts/retire_legacy_workflows.py --apply-token 'RETIRE-LEGACY-EXITFY-WORKFLOWS:...'

Apply mode requires the old paths to remain on the default branch. It disables
only the two runtime-resolved workflow IDs, deletes only their approved
completed run IDs, verifies the live disabled/empty state, and atomically writes
`.github/legacy-workflow-retirement.json`. The tracked receipt contains only
the GitHub host, repository, default branch, exact paths and captured IDs,
schema, and the zero-run proof; it contains no token, actor, commit, or local path. A partial
failure is recoverable by generating a fresh plan and token; a fully completed
rerun is idempotent and rewrites the same proof.

Review the receipt, then include it in the same push that removes the legacy
paths and adds both hardened v2 paths. After GitHub registers the replacements,
run the post-migration proof:

    ./scripts/retire_legacy_workflows.py --verify

Post-migration verification requires both replacement workflows to be active,
the old paths to be absent, and the repository-wide run list to contain no run
for either captured ID or legacy path. If GitHub still exposes a captured
legacy identity it must also remain `disabled_manually` with zero runs; if the
deleted identity is no longer listed, the captured IDs and global run check
avoid depending on undocumented retention behavior. The tool never modifies a
tag or Release. Run deletion is intentionally irreversible and requires the
explicit approval above. Both hardened publishers run the same live proof
before building, before any pin commit/push, and immediately before Release
mutation.

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
    expected_head="$(git rev-parse HEAD)"
    pin_mod_sha="$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' singbox/go.mod)"
    pin_sum_sha="$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' singbox/go.sum)"
    ./scripts/build_singbox_source_bundle.py --repo-root "$PWD" \
      --expected-head "$expected_head" \
      --expected-pin-sha256 "singbox/go.mod=$pin_mod_sha" \
      --expected-pin-sha256 "singbox/go.sum=$pin_sum_sha" \
      --upstream-version v1.13.14 \
      --output dist/exitfy-sb-v1.13.14-source.tar.gz

The public-tree audit examines the exact `HEAD` blobs, staged/index blobs,
working and untracked files, and every commit in the unpushed range. It rejects
symlinks instead of following them, and rejects packaged client artifacts,
client implementation namespaces, local host paths, and unapproved binaries.
External `uses:` references are checked in workflows and nested local
`action.yml`/`action.yaml` metadata, including YAML flow-style mappings.
Run it locally immediately before every push. The read-only `audit-public`
workflow runs without path filters on every push and pull request, but a check
that starts after a direct push can only detect a leak after it reached GitHub;
preventing such pushes requires the local audit plus branch protection that
requires the workflow before changes reach the protected public branch.

## Upstream

Xray is built through the official XTLS/libXray module, which embeds the
compatible XTLS/Xray-core revision selected by that release. See
`THIRD_PARTY.md` for licensing. The combined SB shared libraries are
GPL-3.0-or-later; the complete license text is in `singbox/COPYING` and every
release includes corresponding source.
