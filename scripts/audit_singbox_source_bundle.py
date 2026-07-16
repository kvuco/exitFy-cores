#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import tarfile
from pathlib import Path, PurePosixPath


FORBIDDEN_SUFFIXES = {
    ".plugin", ".dex", ".jar", ".apk", ".aar", ".class", ".so",
    ".dylib", ".dll", ".exe",
}
FORBIDDEN_BYTES = (
    ("TMessages" + "Proj").encode(),
    ("com" + ".exteragram").encode(),
    ("org" + ".telegram").encode(),
)
HOME_PATHS = (
    re.compile(rb"(?<![A-Za-z0-9_])/(?:home)/[^/\s]+/"),
    re.compile(rb"(?<![A-Za-z0-9_])/" + b"Users" + rb"/[^/\s]+/"),
    re.compile(rb"(?i)(?<![A-Za-z0-9_])[A-Z]:\\" + b"Users" + rb"\\[^\\\s]+\\"),
)
MAX_BUNDLE_BYTES = 512 * 1024 * 1024
MAX_MEMBER_BYTES = 64 * 1024 * 1024
MAX_EXPANDED_BYTES = 512 * 1024 * 1024


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle", type=Path)
    args = parser.parse_args()

    if not args.bundle.is_file() or args.bundle.stat().st_size > MAX_BUNDLE_BYTES:
        raise SystemExit("source-bundle audit failed: invalid bundle size")

    failures: list[str] = []
    files = 0
    expanded = 0
    with tarfile.open(args.bundle, "r:gz") as archive:
        members = archive.getmembers()
        roots = {PurePosixPath(member.name).parts[0] for member in members if member.name}
        if len(roots) != 1:
            failures.append("source bundle must contain exactly one root directory")
        for member in members:
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts:
                failures.append(f"unsafe archive path: {member.name}")
                continue
            if member.issym() or member.islnk():
                failures.append(f"archive link is forbidden: {member.name}")
                continue
            if not member.isfile():
                continue
            files += 1
            expanded += member.size
            if member.size < 0 or member.size > MAX_MEMBER_BYTES:
                failures.append(f"oversized archive member: {member.name}")
                continue
            if expanded > MAX_EXPANDED_BYTES:
                failures.append("expanded source bundle exceeds limit")
                break
            if path.suffix.lower() in FORBIDDEN_SUFFIXES:
                failures.append(f"forbidden packaged artifact: {member.name}")
            source = archive.extractfile(member)
            if source is None:
                failures.append(f"cannot read archive member: {member.name}")
                continue
            data = source.read()
            lowered = data.lower()
            for forbidden in FORBIDDEN_BYTES:
                if forbidden.lower() in lowered:
                    failures.append(f"forbidden client reference: {member.name}")
                    break
            if any(pattern.search(data) for pattern in HOME_PATHS):
                failures.append(f"absolute local home path: {member.name}")

    if failures:
        raise SystemExit("source-bundle audit failed:\n" + "\n".join(sorted(set(failures))))
    if files == 0:
        raise SystemExit("source-bundle audit failed: bundle contains no files")
    print(f"source-bundle audit passed: {files} files")


if __name__ == "__main__":
    main()
