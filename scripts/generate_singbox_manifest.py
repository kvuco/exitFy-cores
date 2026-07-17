#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

from verify_artifacts import ABI_LAYOUT, REQUIRED_EXPORTS, inspect_elf
from verify_singbox_artifacts import PREFIX, verify


BUILD_TAGS = ["badlinkname", "tfogo_checklinkname0", "with_quic", "with_utls"]
NDK_VERSION = "27.2.12479018"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--upstream-tag", required=True)
    parser.add_argument("--upstream-commit", required=True)
    parser.add_argument("--go-version", required=True)
    parser.add_argument("--wrapper-commit", required=True)
    parser.add_argument("--release-tag", required=True)
    parser.add_argument("--source-bundle", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", args.upstream_tag):
        raise ValueError("invalid upstream tag")
    release_match = re.fullmatch(
        rf"sb-{re.escape(args.upstream_tag)}-w([1-9][0-9]*)", args.release_tag
    )
    if release_match is None or int(release_match.group(1)) < 2:
        raise ValueError("ABI 2 release tag must use wrapper revision w2 or newer")
    if not re.fullmatch(r"[0-9]+\.[0-9]+(?:\.[0-9]+)?", args.go_version):
        raise ValueError("invalid upstream Go version")
    for label, value in (
        ("upstream", args.upstream_commit),
        ("wrapper", args.wrapper_commit),
    ):
        if not re.fullmatch(r"[0-9a-f]{40}", value):
            raise ValueError(f"invalid {label} commit")
    if not args.source_bundle.is_file() or args.source_bundle.stat().st_size <= 0:
        raise ValueError("source bundle is missing")

    verify(args.directory)
    assets: dict[str, object] = {}
    for abi in ABI_LAYOUT:
        path = args.directory / f"{PREFIX}-{abi}.so"
        info = inspect_elf(path)
        assets[abi] = {
            "name": path.name,
            "size": path.stat().st_size,
            "sha256": sha256(path),
            "elfClass": 64 if info.elf_class == 2 else 32,
            "elfMachine": info.machine,
            "elfMachineName": info.machine_name,
            "exports": sorted(REQUIRED_EXPORTS),
        }

    manifest = {
        "schema": 3,
        "coreApi": 2,
        "configContract": 1,
        "family": "sing_box",
        "releaseTag": args.release_tag,
        "upstream": {
            "repository": "SagerNet/sing-box",
            "tag": args.upstream_tag,
            "commit": args.upstream_commit,
            "goVersion": args.go_version,
        },
        "wrapper": {
            "repository": "kvuco/exitFy-cores",
            "commit": args.wrapper_commit,
            "ndkVersion": NDK_VERSION,
            "buildTags": BUILD_TAGS,
            "sourceBundle": {
                "name": args.source_bundle.name,
                "size": args.source_bundle.stat().st_size,
                "sha256": sha256(args.source_bundle),
            },
        },
        "minAndroidApi": 29,
        "requiredExports": sorted(REQUIRED_EXPORTS),
        "assets": assets,
    }
    args.output.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
