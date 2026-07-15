#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

from verify_artifacts import ABI_LAYOUT, REQUIRED_EXPORTS, inspect_elf, verify


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
    args = parser.parse_args()

    verify(args.directory)
    value = json.loads(args.manifest.read_text(encoding="utf-8"))
    if set(value) != TOP_LEVEL_KEYS:
        raise ValueError("manifest top-level fields do not match schema 2")
    if (
        value.get("schema") != 2
        or value.get("coreApi") != 1
        or value.get("configContract") != 1
        or value.get("family") != "xray"
        or value.get("minAndroidApi") != 26
        or set(value.get("requiredExports", [])) != REQUIRED_EXPORTS
    ):
        raise ValueError("unsupported manifest contract")
    upstream = value.get("upstream") or {}
    wrapper = value.get("wrapper") or {}
    release_tag = value.get("releaseTag", "")
    if (
        not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", upstream.get("tag", ""))
        or release_tag != f"xray-{upstream.get('tag')}-w1"
        or upstream.get("repository") != "XTLS/libXray"
        or wrapper.get("repository") != "kvuco/exitFy-cores"
        or not re.fullmatch(r"[0-9a-f]{40}", upstream.get("commit", ""))
        or not re.fullmatch(r"[0-9a-f]{40}", wrapper.get("commit", ""))
    ):
        raise ValueError("manifest pins are invalid")

    assets = value.get("assets") or {}
    if set(assets) != set(ABI_LAYOUT):
        raise ValueError("manifest ABI set is incomplete")
    for abi, (elf_class, machine, machine_name) in ABI_LAYOUT.items():
        path = args.directory / f"libxray-{abi}.so"
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
    print(f"manifest schema 2 verified: {release_tag}")


if __name__ == "__main__":
    main()
