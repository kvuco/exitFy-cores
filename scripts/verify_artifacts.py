#!/usr/bin/env python3
from __future__ import annotations

import argparse
import struct
from dataclasses import dataclass
from pathlib import Path


MAX_SIZE = 64 * 1024 * 1024
REQUIRED_EXPORTS = {"StartCore", "StopCore"}
ABI_LAYOUT = {
    "arm64-v8a": (2, 183, "EM_AARCH64"),
    "armeabi-v7a": (1, 40, "EM_ARM"),
    "x86": (1, 3, "EM_386"),
    "x86_64": (2, 62, "EM_X86_64"),
}


@dataclass(frozen=True)
class ElfInfo:
    elf_class: int
    machine: int
    machine_name: str
    exports: frozenset[str]


def _unpack(fmt: str, data: bytes, offset: int):
    size = struct.calcsize(fmt)
    if offset < 0 or offset + size > len(data):
        raise ValueError("truncated ELF")
    return struct.unpack_from(fmt, data, offset)


def inspect_elf(path: Path) -> ElfInfo:
    data = path.read_bytes()
    if len(data) < 64 or data[:4] != b"\x7fELF":
        raise ValueError("not an ELF file")
    elf_class = data[4]
    if elf_class not in (1, 2):
        raise ValueError(f"unsupported ELF class {elf_class}")
    if data[5] != 1:
        raise ValueError("ELF must be little-endian")

    machine = _unpack("<H", data, 18)[0]
    if elf_class == 2:
        section_offset = _unpack("<Q", data, 40)[0]
        section_size, section_count = _unpack("<HH", data, 58)
        section_fmt = "<IIQQQQIIQQ"
        symbol_fmt = "<IBBHQQ"
    else:
        section_offset = _unpack("<I", data, 32)[0]
        section_size, section_count = _unpack("<HH", data, 46)
        section_fmt = "<IIIIIIIIII"
        symbol_fmt = "<IIIBBH"

    expected_section_size = struct.calcsize(section_fmt)
    if section_size < expected_section_size or section_count == 0:
        raise ValueError("invalid ELF section table")

    sections = []
    for index in range(section_count):
        values = _unpack(section_fmt, data, section_offset + index * section_size)
        sections.append(
            {
                "type": values[1],
                "offset": values[4],
                "size": values[5],
                "link": values[6],
                "entry_size": values[9],
            }
        )

    exports: set[str] = set()
    for section in sections:
        if section["type"] != 11:
            continue
        link = section["link"]
        if link >= len(sections):
            raise ValueError("invalid dynamic string table link")
        strings = sections[link]
        string_data = data[strings["offset"] : strings["offset"] + strings["size"]]
        symbol_size = section["entry_size"] or struct.calcsize(symbol_fmt)
        if symbol_size < struct.calcsize(symbol_fmt):
            raise ValueError("invalid dynamic symbol size")
        for offset in range(
            section["offset"],
            section["offset"] + section["size"],
            symbol_size,
        ):
            values = _unpack(symbol_fmt, data, offset)
            name_offset = values[0]
            if name_offset == 0 or name_offset >= len(string_data):
                continue
            end = string_data.find(b"\0", name_offset)
            if end < 0:
                continue
            exports.add(string_data[name_offset:end].decode("utf-8", "replace"))

    machine_name = next(
        (name for _, expected, name in ABI_LAYOUT.values() if expected == machine),
        f"EM_{machine}",
    )
    return ElfInfo(elf_class, machine, machine_name, frozenset(exports))


def verify(directory: Path) -> None:
    expected_names = {f"libxray-{abi}.so" for abi in ABI_LAYOUT}
    actual_names = {path.name for path in directory.glob("libxray-*.so")}
    if actual_names != expected_names:
        raise ValueError(
            f"unexpected artifacts: expected {sorted(expected_names)}, "
            f"got {sorted(actual_names)}"
        )

    for abi, (expected_class, expected_machine, _) in ABI_LAYOUT.items():
        path = directory / f"libxray-{abi}.so"
        size = path.stat().st_size
        if size <= 0 or size > MAX_SIZE:
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
        print(
            f"{path.name}: {size} bytes, {info.machine_name}, "
            f"exports={','.join(sorted(REQUIRED_EXPORTS))}"
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    verify(args.directory)


if __name__ == "__main__":
    main()

