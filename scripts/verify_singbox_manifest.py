#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

from generate_singbox_manifest import BUILD_TAGS, NDK_VERSION
from verify_artifacts import ABI_LAYOUT, REQUIRED_EXPORTS, inspect_elf
from verify_singbox_artifacts import PREFIX, verify


TOP_LEVEL_KEYS = {
    "schema", "coreApi", "configContract", "family", "releaseTag",
    "upstream", "wrapper", "minAndroidApi", "requiredExports", "assets",
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("directory", type=Path)
    parser.add_argument("source_bundle", type=Path)
    args = parser.parse_args()

    verify(args.directory)
    value = json.loads(args.manifest.read_text(encoding="utf-8"))
    if set(value) != TOP_LEVEL_KEYS:
        raise ValueError("manifest top-level fields do not match schema 2")
    if (
        value.get("schema") != 2
        or value.get("coreApi") != 2
        or value.get("configContract") != 1
        or value.get("family") != "sing_box"
        or value.get("minAndroidApi") != 26
        or set(value.get("requiredExports", [])) != REQUIRED_EXPORTS
    ):
        raise ValueError("unsupported SB manifest contract")

    upstream = value.get("upstream") or {}
    wrapper = value.get("wrapper") or {}
    source = wrapper.get("sourceBundle") or {}
    release_tag = value.get("releaseTag", "")
    upstream_tag = upstream.get("tag", "")
    if (
        upstream.get("repository") != "SagerNet/sing-box"
        or not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", upstream_tag)
        or not re.fullmatch(
            rf"sb-{re.escape(upstream_tag)}-w(?:[2-9]|[1-9][0-9]+)", release_tag
        )
        or not re.fullmatch(r"[0-9a-f]{40}", upstream.get("commit", ""))
        or not re.fullmatch(r"[0-9]+\.[0-9]+(?:\.[0-9]+)?", upstream.get("goVersion", ""))
        or wrapper.get("repository") != "kvuco/exitFy-cores"
        or not re.fullmatch(r"[0-9a-f]{40}", wrapper.get("commit", ""))
        or wrapper.get("ndkVersion") != NDK_VERSION
        or wrapper.get("buildTags") != BUILD_TAGS
    ):
        raise ValueError("SB manifest pins are invalid")
    if (
        source.get("name") != args.source_bundle.name
        or source.get("size") != args.source_bundle.stat().st_size
        or source.get("sha256") != sha256(args.source_bundle)
    ):
        raise ValueError("source bundle metadata mismatch")

    assets = value.get("assets") or {}
    if set(assets) != set(ABI_LAYOUT):
        raise ValueError("manifest ABI set is incomplete")
    for abi, (elf_class, machine, machine_name) in ABI_LAYOUT.items():
        path = args.directory / f"{PREFIX}-{abi}.so"
        entry = assets[abi]
        info = inspect_elf(path)
        if (
            entry.get("name") != path.name
            or entry.get("size") != path.stat().st_size
            or entry.get("sha256") != sha256(path)
            or entry.get("elfClass") != (64 if elf_class == 2 else 32)
            or entry.get("elfMachine") != machine
            or entry.get("elfMachineName") != machine_name
            or set(entry.get("exports", [])) != REQUIRED_EXPORTS
            or info.machine != machine
        ):
            raise ValueError(f"manifest asset mismatch for {abi}")
    print(f"SB manifest schema 2 verified: {release_tag}")


if __name__ == "__main__":
    main()
