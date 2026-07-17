#!/usr/bin/env python3
"""Validate an already-published core Release without trusting asset names alone."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any


ABIS = {"arm64-v8a": (64, 183, "EM_AARCH64")}
EXPORTS = {"StartCore", "StopCore"}
TOP_LEVEL = {
    "schema", "coreApi", "configContract", "family", "releaseTag",
    "upstream", "wrapper", "minAndroidApi", "requiredExports", "assets",
}
SB_TAGS = ["badlinkname", "tfogo_checklinkname0", "with_quic", "with_utls"]
NDK_VERSION = "27.2.12479018"
MAX_MANIFEST_BYTES = 1024 * 1024
DIGEST = re.compile(r"sha256:([0-9a-f]{64})")
COMMIT = re.compile(r"[0-9a-f]{40}")
VERSION = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+")


def _read_bounded(path: Path, maximum: int, label: str) -> bytes:
    with path.open("rb") as stream:
        value = stream.read(maximum + 1)
    if len(value) > maximum:
        raise ValueError(f"{label} exceeds {maximum} bytes")
    return value


def _exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError(f"{label} fields do not match the contract")
    return value


def _asset_map(release: dict[str, Any]) -> dict[str, dict[str, Any]]:
    values = release.get("assets")
    if not isinstance(values, list):
        raise ValueError("release assets are missing")
    result: dict[str, dict[str, Any]] = {}
    for value in values:
        if not isinstance(value, dict):
            raise ValueError("release asset is malformed")
        name = value.get("name")
        if not isinstance(name, str) or not name or name in result:
            raise ValueError("release asset names are missing or duplicated")
        size = value.get("size")
        digest = value.get("digest")
        asset_id = value.get("id")
        if type(asset_id) is not int or asset_id <= 0:
            raise ValueError(f"release asset id is invalid: {name}")
        if type(size) is not int or size <= 0:
            raise ValueError(f"release asset size is invalid: {name}")
        if not isinstance(digest, str) or DIGEST.fullmatch(digest) is None:
            raise ValueError(f"release asset digest is invalid: {name}")
        result[name] = value
    return result


def verify_remote_release(
    release: dict[str, Any],
    manifest: dict[str, Any],
    manifest_bytes: bytes,
    family: str,
    upstream_commit: str,
    wrapper_commit: str,
    allow_draft: bool = False,
) -> None:
    if len(manifest_bytes) > MAX_MANIFEST_BYTES:
        raise ValueError(f"manifest exceeds {MAX_MANIFEST_BYTES} bytes")
    if family not in {"xray", "sing_box"}:
        raise ValueError("unsupported core family")
    draft = release.get("draft")
    if (draft is not False and not (allow_draft and draft is True)) or release.get(
        "prerelease"
    ) is not False:
        raise ValueError("release is not stable")
    if COMMIT.fullmatch(upstream_commit) is None or COMMIT.fullmatch(wrapper_commit) is None:
        raise ValueError("expected commits are invalid")
    if release.get("target_commitish") != wrapper_commit:
        raise ValueError("release target commit is stale")

    manifest = _exact_keys(manifest, TOP_LEVEL, "manifest")
    if (
        manifest.get("schema") != 3
        or manifest.get("coreApi") != 2
        or manifest.get("configContract") != 1
        or manifest.get("family") != family
        or manifest.get("minAndroidApi") != 29
        or set(manifest.get("requiredExports") or []) != EXPORTS
        or len(manifest.get("requiredExports") or []) != len(EXPORTS)
    ):
        raise ValueError("manifest core contract is invalid")

    upstream = manifest.get("upstream")
    wrapper = manifest.get("wrapper")
    upstream_tag = upstream.get("tag") if isinstance(upstream, dict) else None
    if not isinstance(upstream_tag, str) or VERSION.fullmatch(upstream_tag) is None:
        raise ValueError("manifest upstream tag is invalid")
    prefix = "xray" if family == "xray" else "sb"
    release_tag = release.get("tag_name")
    if (
        not isinstance(release_tag, str)
        or re.fullmatch(rf"{prefix}-{re.escape(upstream_tag)}-w(?:[2-9]|[1-9][0-9]+)", release_tag)
        is None
        or manifest.get("releaseTag") != release_tag
    ):
        raise ValueError("release tag does not match the manifest")

    if family == "xray":
        upstream = _exact_keys(upstream, {"repository", "tag", "commit"}, "upstream")
        wrapper = _exact_keys(wrapper, {"repository", "commit"}, "wrapper")
        if upstream.get("repository") != "XTLS/libXray":
            raise ValueError("unexpected Xray upstream repository")
    else:
        upstream = _exact_keys(
            upstream, {"repository", "tag", "commit", "goVersion"}, "upstream"
        )
        wrapper = _exact_keys(
            wrapper,
            {"repository", "commit", "ndkVersion", "buildTags", "sourceBundle"},
            "wrapper",
        )
        if (
            upstream.get("repository") != "SagerNet/sing-box"
            or re.fullmatch(r"[0-9]+\.[0-9]+(?:\.[0-9]+)?", upstream.get("goVersion", ""))
            is None
            or wrapper.get("ndkVersion") != NDK_VERSION
            or wrapper.get("buildTags") != SB_TAGS
        ):
            raise ValueError("sing-box build contract is invalid")
    if (
        upstream.get("commit") != upstream_commit
        or wrapper.get("repository") != "kvuco/exitFy-cores"
        or wrapper.get("commit") != wrapper_commit
    ):
        raise ValueError("manifest commit pins are stale")

    remote_assets = _asset_map(release)
    manifest_asset = remote_assets.get("manifest.json")
    manifest_sha = hashlib.sha256(manifest_bytes).hexdigest()
    if (
        manifest_asset is None
        or manifest_asset.get("size") != len(manifest_bytes)
        or manifest_asset.get("digest") != f"sha256:{manifest_sha}"
    ):
        raise ValueError("remote manifest size/digest mismatch")

    entries = manifest.get("assets")
    if not isinstance(entries, dict) or set(entries) != set(ABIS):
        raise ValueError("manifest ABI set is incomplete")
    expected_names = {"manifest.json"}
    for abi, (elf_class, machine, machine_name) in ABIS.items():
        name = f"libxray-{abi}.so" if family == "xray" else f"libexitfy-sb-{abi}.so"
        expected_names.add(name)
        entry = _exact_keys(
            entries.get(abi),
            {"name", "size", "sha256", "elfClass", "elfMachine", "elfMachineName", "exports"},
            f"manifest asset {abi}",
        )
        remote = remote_assets.get(name)
        digest = entry.get("sha256")
        if (
            remote is None
            or entry.get("name") != name
            or type(entry.get("size")) is not int
            or not 1024 * 1024 <= entry["size"] <= 64 * 1024 * 1024
            or not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            or remote.get("size") != entry.get("size")
            or remote.get("digest") != f"sha256:{digest}"
            or entry.get("elfClass") != elf_class
            or entry.get("elfMachine") != machine
            or entry.get("elfMachineName") != machine_name
            or set(entry.get("exports") or []) != EXPORTS
            or len(entry.get("exports") or []) != len(EXPORTS)
        ):
            raise ValueError(f"remote core asset contract mismatch for {abi}")

    if family == "sing_box":
        source = _exact_keys(
            wrapper.get("sourceBundle"), {"name", "size", "sha256"}, "source bundle"
        )
        source_name = f"exitfy-sb-{upstream_tag}-source.tar.gz"
        expected_names.add(source_name)
        remote = remote_assets.get(source_name)
        if (
            source.get("name") != source_name
            or remote is None
            or type(source.get("size")) is not int
            or not 0 < source["size"] <= 512 * 1024 * 1024
            or re.fullmatch(r"[0-9a-f]{64}", source.get("sha256", "")) is None
            or remote.get("size") != source.get("size")
            or remote.get("digest") != f"sha256:{source.get('sha256')}"
        ):
            raise ValueError("remote source bundle contract mismatch")

    if set(remote_assets) != expected_names:
        raise ValueError("release asset set is incomplete or contains extras")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--family", choices=("xray", "sing_box"), required=True)
    parser.add_argument("--release", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--upstream-commit", required=True)
    parser.add_argument("--wrapper-commit", required=True)
    parser.add_argument(
        "--allow-draft",
        action="store_true",
        help="allow one pre-publication draft; prereleases remain forbidden",
    )
    args = parser.parse_args()

    # The manifest is a remote Release asset. Bound the read itself, not just
    # the subsequent JSON parse, so a hostile asset cannot exhaust CI memory.
    manifest_bytes = _read_bounded(args.manifest, MAX_MANIFEST_BYTES, "manifest")
    verify_remote_release(
        json.loads(args.release.read_text(encoding="utf-8")),
        json.loads(manifest_bytes),
        manifest_bytes,
        args.family,
        args.upstream_commit,
        args.wrapper_commit,
        args.allow_draft,
    )
    print(f"remote {args.family} release contract verified")


if __name__ == "__main__":
    main()
