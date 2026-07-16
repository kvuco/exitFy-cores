#!/usr/bin/env python3
from __future__ import annotations

import argparse
import struct
from dataclasses import dataclass
from pathlib import Path


MAX_SIZE = 64 * 1024 * 1024
MIN_ANDROID_PAGE_ALIGNMENT = 16 * 1024
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
    load_alignments: tuple[int, ...]


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
        program_offset = _unpack("<Q", data, 32)[0]
        program_size, program_count = _unpack("<HH", data, 54)
        program_fmt = "<IIQQQQQQ"
        section_offset = _unpack("<Q", data, 40)[0]
        section_size, section_count = _unpack("<HH", data, 58)
        section_fmt = "<IIQQQQIIQQ"
        symbol_fmt = "<IBBHQQ"
    else:
        program_offset = _unpack("<I", data, 28)[0]
        program_size, program_count = _unpack("<HH", data, 42)
        program_fmt = "<IIIIIIII"
        section_offset = _unpack("<I", data, 32)[0]
        section_size, section_count = _unpack("<HH", data, 46)
        section_fmt = "<IIIIIIIIII"
        symbol_fmt = "<IIIBBH"

    minimum_program_size = struct.calcsize(program_fmt)
    if program_size < minimum_program_size or program_count == 0:
        raise ValueError("invalid ELF program table")
    load_alignments: list[int] = []
    for index in range(program_count):
        values = _unpack(program_fmt, data, program_offset + index * program_size)
        if values[0] != 1:  # PT_LOAD
            continue
        file_offset = values[2] if elf_class == 2 else values[1]
        virtual_address = values[3] if elf_class == 2 else values[2]
        file_size = values[5] if elf_class == 2 else values[4]
        alignment = values[7]
        if file_offset > len(data) or file_size > len(data) - file_offset:
            raise ValueError("PT_LOAD segment escapes ELF")
        if alignment <= 0 or alignment & (alignment - 1):
            raise ValueError("invalid PT_LOAD alignment")
        if (virtual_address - file_offset) % alignment:
            raise ValueError("incongruent PT_LOAD segment")
        load_alignments.append(alignment)
    if not load_alignments:
        raise ValueError("ELF has no PT_LOAD segments")

    expected_section_size = struct.calcsize(section_fmt)
    if section_size < expected_section_size or section_count == 0:
        raise ValueError("invalid ELF section table")

    sections = []
    for index in range(section_count):
        values = _unpack(section_fmt, data, section_offset + index * section_size)
        payload_offset = values[4]
        payload_size = values[5]
        section_type = values[1]
        if section_type != 8 and (  # SHT_NOBITS has no file payload.
            payload_offset > len(data) or payload_size > len(data) - payload_offset
        ):
            raise ValueError("ELF section escapes file")
        sections.append(
            {
                "type": section_type,
                "offset": payload_offset,
                "size": payload_size,
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
        if strings["type"] != 3:  # SHT_STRTAB
            raise ValueError("dynamic symbols do not reference a string table")
        string_data = data[strings["offset"] : strings["offset"] + strings["size"]]
        symbol_size = section["entry_size"] or struct.calcsize(symbol_fmt)
        if symbol_size < struct.calcsize(symbol_fmt):
            raise ValueError("invalid dynamic symbol size")
        if section["size"] % symbol_size:
            raise ValueError("truncated dynamic symbol table")
        for offset in range(
            section["offset"],
            section["offset"] + section["size"],
            symbol_size,
        ):
            values = _unpack(symbol_fmt, data, offset)
            name_offset = values[0]
            if elf_class == 2:
                symbol_info = values[1]
                section_index = values[3]
            else:
                symbol_info = values[3]
                section_index = values[5]
            # An undefined import with the expected name is not an exported
            # implementation. Require a non-local, defined dynamic symbol.
            if (
                name_offset == 0
                or name_offset >= len(string_data)
                or symbol_info >> 4 == 0
                or section_index == 0
            ):
                continue
            end = string_data.find(b"\0", name_offset)
            if end < 0:
                continue
            exports.add(string_data[name_offset:end].decode("utf-8", "replace"))

    machine_name = next(
        (name for _, expected, name in ABI_LAYOUT.values() if expected == machine),
        f"EM_{machine}",
    )
    return ElfInfo(
        elf_class,
        machine,
        machine_name,
        frozenset(exports),
        tuple(load_alignments),
    )


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
        if min(info.load_alignments) < MIN_ANDROID_PAGE_ALIGNMENT:
            raise ValueError(
                f"{path.name}: PT_LOAD alignment is below "
                f"{MIN_ANDROID_PAGE_ALIGNMENT} bytes"
            )
        print(
            f"{path.name}: {size} bytes, {info.machine_name}, "
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
