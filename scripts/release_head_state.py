#!/usr/bin/env python3
"""Derive current-release wrapper candidates from one immutable Git head."""

from __future__ import annotations

import argparse
import re
from pathlib import Path, PurePosixPath

import verify_build_inputs


FULL_COMMIT = re.compile(r"[0-9a-f]{40}\Z")


def _canonical_path(value: str) -> str:
    path = PurePosixPath(value)
    if (
        not value
        or path.is_absolute()
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ValueError("foreign pin path is not canonical")
    return value


def _parse_name_status(raw: bytes) -> list[tuple[str, str]]:
    parts = raw.split(b"\0")
    if parts and parts[-1] == b"":
        parts.pop()
    if len(parts) % 2 != 0:
        raise ValueError("Git returned malformed name-status output")
    result: list[tuple[str, str]] = []
    for index in range(0, len(parts), 2):
        try:
            status = parts[index].decode("ascii", "strict")
            path = parts[index + 1].decode("utf-8", "strict")
        except UnicodeDecodeError as error:
            raise ValueError("Git returned a non-UTF-8 change") from error
        result.append((status, _canonical_path(path)))
    return result


def current_wrapper_candidates(
    root: Path, head: str, foreign_pins: set[str]
) -> list[str]:
    if FULL_COMMIT.fullmatch(head) is None:
        raise ValueError("workflow head is invalid")
    canonical_pins = {_canonical_path(path) for path in foreign_pins}
    if not canonical_pins:
        raise ValueError("foreign pin set is empty")
    root = verify_build_inputs._canonical_root(root)
    verify_build_inputs._require_expected_head(root, head)
    parents = verify_build_inputs._git(
        root, "rev-list", "--parents", "-n", "1", head
    ).decode("ascii", "strict").strip().split()
    if not parents or parents[0] != head or any(
        FULL_COMMIT.fullmatch(value) is None for value in parents
    ):
        raise ValueError("Git returned malformed parentage")
    candidates = [head]
    if len(parents) == 2:
        parent = parents[1]
        changes = _parse_name_status(
            verify_build_inputs._git(
                root,
                "diff",
                "--no-ext-diff",
                "--no-renames",
                "--name-status",
                "-z",
                parent,
                head,
                "--",
            )
        )
        if changes and all(
            status == "M" and path in canonical_pins for status, path in changes
        ):
            candidates.append(parent)
    verify_build_inputs._require_expected_head(root, head)
    return candidates


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--foreign-pin", action="append", required=True)
    args = parser.parse_args()
    for candidate in current_wrapper_candidates(
        args.repo, args.head, set(args.foreign_pin)
    ):
        print(candidate)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as error:
        raise SystemExit(f"release head verification failed: {error}") from error
