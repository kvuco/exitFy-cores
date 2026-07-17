#!/usr/bin/env python3
"""Prove that an exact public Release is an already-completed candidate."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

import candidate_handoff
import release_draft_state
import verify_build_inputs
import verify_remote_release


MAX_RELEASE_BYTES = 16 * 1024 * 1024
MAX_REFERENCES_BYTES = 16 * 1024 * 1024


def _read_external(path: Path, maximum: int, label: str) -> bytes:
    return verify_build_inputs._read_regular_stable(path, maximum, label)


def _load_object(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{label} is not valid JSON") from error
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def _load_json(raw: bytes, label: str) -> Any:
    try:
        return json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{label} is not valid JSON") from error


def verify_published_candidate(
    *,
    family: str,
    candidate_directory: Path,
    release_path: Path,
    references_path: Path,
    remote_manifest_path: Path,
    handoff_sha256: str,
    event_commit: str,
    upstream_tag: str,
    upstream_commit: str,
    go_version: str,
    release_tag: str,
    snapshot_sha256: str,
    wrapper_commit: str,
) -> None:
    candidate_handoff.verify_handoff(
        candidate_directory,
        expected_sha256=handoff_sha256,
        family=family,
        event_commit=event_commit,
        upstream_tag=upstream_tag,
        upstream_commit=upstream_commit,
        go_version=go_version,
        release_tag=release_tag,
        snapshot_sha256=snapshot_sha256,
        allowed_extra_files=frozenset({"manifest.json"}),
    )
    if re.fullmatch(r"[0-9a-f]{40}", wrapper_commit) is None:
        raise ValueError("published wrapper commit is invalid")

    release = _load_object(
        _read_external(release_path, MAX_RELEASE_BYTES, "published release"),
        "published release",
    )
    if (
        release.get("tag_name") != release_tag
        or release.get("target_commitish") != wrapper_commit
        or release.get("draft") is not False
        or release.get("prerelease") is not False
        or type(release.get("id")) is not int
        or release["id"] <= 0
    ):
        raise ValueError("published release identity does not match the candidate")
    references = _load_json(
        _read_external(
            references_path, MAX_REFERENCES_BYTES, "release tag references"
        ),
        "release tag references",
    )
    release_draft_state.verify_tag_references(
        references, release_tag, wrapper_commit
    )

    root = candidate_handoff._open_directory(
        candidate_directory, "candidate directory"
    )
    try:
        local_manifest, local_manifest_digest = candidate_handoff._read_regular(
            root,
            "manifest.json",
            verify_remote_release.MAX_MANIFEST_BYTES,
            "local release manifest",
        )
        remote_manifest = _read_external(
            remote_manifest_path,
            verify_remote_release.MAX_MANIFEST_BYTES,
            "remote release manifest",
        )
        if remote_manifest != local_manifest:
            raise ValueError("remote manifest bytes differ from the local candidate")
        manifest = _load_object(local_manifest, "local release manifest")
        verify_remote_release.verify_remote_release(
            release,
            manifest,
            local_manifest,
            family,
            upstream_commit,
            wrapper_commit,
            allow_draft=False,
        )
        remote_assets = verify_remote_release._asset_map(release)
        artifact_names, _, _ = candidate_handoff._family_contract(
            family, upstream_tag
        )
        expected_release_names = set(artifact_names) | {"manifest.json"}
        if set(remote_assets) != expected_release_names:
            raise ValueError("published release asset set differs from the candidate")
        for name in sorted(artifact_names):
            size, digest = candidate_handoff._digest_regular(
                root,
                name,
                candidate_handoff._artifact_limit(name),
                f"local release asset {name}",
            )
            remote = remote_assets[name]
            if (
                remote.get("size") != size
                or remote.get("digest") != f"sha256:{digest}"
            ):
                raise ValueError(f"published asset differs from the candidate: {name}")
        remote_manifest_asset = remote_assets["manifest.json"]
        if (
            remote_manifest_asset.get("size") != len(local_manifest)
            or remote_manifest_asset.get("digest")
            != f"sha256:{local_manifest_digest}"
            or hashlib.sha256(remote_manifest).hexdigest() != local_manifest_digest
        ):
            raise ValueError("published manifest digest differs from the candidate")
    finally:
        os.close(root)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--family", choices=("xray", "sing_box"), required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--release", type=Path, required=True)
    parser.add_argument("--references", type=Path, required=True)
    parser.add_argument("--remote-manifest", type=Path, required=True)
    parser.add_argument("--handoff-sha256", required=True)
    parser.add_argument("--event-commit", required=True)
    parser.add_argument("--upstream-tag", required=True)
    parser.add_argument("--upstream-commit", required=True)
    parser.add_argument("--go-version", required=True)
    parser.add_argument("--release-tag", required=True)
    parser.add_argument("--snapshot-sha256", required=True)
    parser.add_argument("--wrapper-commit", required=True)
    args = parser.parse_args()
    verify_published_candidate(
        family=args.family,
        candidate_directory=args.candidate,
        release_path=args.release,
        references_path=args.references,
        remote_manifest_path=args.remote_manifest,
        handoff_sha256=args.handoff_sha256,
        event_commit=args.event_commit,
        upstream_tag=args.upstream_tag,
        upstream_commit=args.upstream_commit,
        go_version=args.go_version,
        release_tag=args.release_tag,
        snapshot_sha256=args.snapshot_sha256,
        wrapper_commit=args.wrapper_commit,
    )
    print("published release exactly matches the immutable candidate")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as error:
        raise SystemExit(f"published candidate verification failed: {error}") from error
