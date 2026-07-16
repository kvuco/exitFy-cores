#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from verify_artifacts import (
    ABI_LAYOUT,
    MAX_SIZE,
    MIN_ANDROID_PAGE_ALIGNMENT,
    REQUIRED_EXPORTS,
    inspect_elf,
)


PREFIX = "libexitfy-sb"


def verify(directory: Path) -> None:
    expected_names = {f"{PREFIX}-{abi}.so" for abi in ABI_LAYOUT}
    actual_names = {path.name for path in directory.glob(f"{PREFIX}-*.so")}
    if actual_names != expected_names:
        raise ValueError(
            f"unexpected SB artifacts: expected {sorted(expected_names)}, "
            f"got {sorted(actual_names)}"
        )
    for abi, (expected_class, expected_machine, machine_name) in ABI_LAYOUT.items():
        path = directory / f"{PREFIX}-{abi}.so"
        size = path.stat().st_size
        if size < 1024 * 1024 or size > MAX_SIZE:
            raise ValueError(f"{path.name}: invalid size {size}")
        info = inspect_elf(path)
        if info.elf_class != expected_class or info.machine != expected_machine:
            raise ValueError(
                f"{path.name}: wrong ELF class/machine "
                f"{info.elf_class}/{info.machine}"
            )
        missing = REQUIRED_EXPORTS - info.exports
        if missing:
            raise ValueError(f"{path.name}: missing exports {sorted(missing)}")
        if min(info.load_alignments) < MIN_ANDROID_PAGE_ALIGNMENT:
            raise ValueError(
                f"{path.name}: PT_LOAD alignment is below "
                f"{MIN_ANDROID_PAGE_ALIGNMENT} bytes"
            )
        print(
            f"{path.name}: {size} bytes, {machine_name}, "
            f"exports={','.join(sorted(REQUIRED_EXPORTS))}, "
            f"min-load-alignment={min(info.load_alignments)}"
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    verify(args.directory)


if __name__ == "__main__":
    main()
