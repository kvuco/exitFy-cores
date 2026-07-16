#!/usr/bin/env python3
from __future__ import annotations

import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN_SUFFIXES = {
    ".plugin", ".dex", ".jar", ".apk", ".aar", ".class",
    ".so", ".dylib", ".dll", ".exe",
}
FORBIDDEN_TEXT = (
    "TMessages" + "Proj",
    "com" + ".exteragram",
    "org" + ".telegram",
    "/" + "Users" + "/",
    "C:" + "\\Users\\",
)
HOME_PATH = re.compile(r"(?<![A-Za-z0-9_])/(?:home)/[^/\s]+/")
ACTION_USE = re.compile(r"(?m)^\s*-?\s*uses:\s*([^@\s]+)@([^\s#]+)")
FULL_COMMIT = re.compile(r"[0-9a-f]{40}")


def public_files() -> list[Path]:
    output = subprocess.check_output(
        ["git", "-C", str(ROOT), "ls-files", "--cached", "--others",
         "--exclude-standard", "-z"],
    )
    return sorted({ROOT / value.decode("utf-8") for value in output.split(b"\0") if value})


def main() -> None:
    failures: list[str] = []
    files = public_files()
    for path in files:
        relative = path.relative_to(ROOT).as_posix()
        if path.suffix.lower() in FORBIDDEN_SUFFIXES:
            failures.append(f"forbidden artifact: {relative}")
            continue
        if ("TMessages" + "Proj") in path.parts:
            failures.append(f"forbidden source tree: {relative}")
            continue
        data = path.read_bytes()
        if b"\0" in data or data.startswith((b"\x7fELF", b"PK\x03\x04", b"dex\n")):
            failures.append(f"unapproved binary: {relative}")
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            failures.append(f"non-UTF-8 tracked file: {relative}")
            continue
        lowered = text.lower()
        for forbidden in FORBIDDEN_TEXT:
            if forbidden.lower() in lowered:
                failures.append(f"forbidden client reference in {relative}")
                break
        if HOME_PATH.search(text):
            failures.append(f"absolute local home path in {relative}")
        if relative.startswith(".github/workflows/"):
            for action, revision in ACTION_USE.findall(text):
                if action.startswith("./"):
                    continue
                if not FULL_COMMIT.fullmatch(revision):
                    failures.append(
                        f"unpinned GitHub Action in {relative}: {action}@{revision}"
                    )
            if ("reactive" + "circus/android-emulator-runner") in text:
                failures.append(f"third-party emulator action in {relative}")

    if failures:
        raise SystemExit("public-tree audit failed:\n" + "\n".join(sorted(set(failures))))
    print(f"public-tree audit passed: {len(files)} public text files")


if __name__ == "__main__":
    main()
