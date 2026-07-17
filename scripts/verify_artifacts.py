#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any


MAX_SIZE = 64 * 1024 * 1024
MIN_ANDROID_PAGE_ALIGNMENT = 16 * 1024
MAX_PROGRAM_HEADERS = 1024
MAX_DYNAMIC_ENTRIES = 65_536
MAX_DYNAMIC_SYMBOLS = 100_000
MAX_HASH_BUCKETS = 100_000
MAX_SYMBOL_NAME_BYTES = 4096
READ_CHUNK = 64 * 1024
REQUIRED_EXPORTS = frozenset({"StartCore", "StopCore"})

ET_DYN = 3
PT_LOAD = 1
PT_DYNAMIC = 2
PF_X = 1
DT_NULL = 0
DT_HASH = 4
DT_STRTAB = 5
DT_SYMTAB = 6
DT_STRSZ = 10
DT_SYMENT = 11
DT_GNU_HASH = 0x6FFFFEF5
SHT_NULL = 0
SHT_PROGBITS = 1
SHT_STRTAB = 3
SHT_NOBITS = 8
SHT_DYNSYM = 11
SHF_ALLOC = 0x2
SHN_UNDEF = 0
SHN_LORESERVE = 0xFF00
STB_LOCAL = 0
STB_GLOBAL = 1
STT_FUNC = 2
STV_DEFAULT = 0
STV_PROTECTED = 3

ABI_LAYOUT = {
    "arm64-v8a": (2, 183, "EM_AARCH64"),
}
FAMILY_LAYOUT = {
    "xray": ("libxray", 1),
    "sing_box": ("libexitfy-sb", 1024 * 1024),
}


@dataclass(frozen=True)
class ElfInfo:
    elf_class: int
    machine: int
    machine_name: str
    exports: frozenset[str]
    load_alignments: tuple[int, ...]
    size: int
    sha256: str


@dataclass(frozen=True)
class _LoadSegment:
    offset: int
    virtual_address: int
    file_size: int
    memory_size: int
    flags: int
    alignment: int


@dataclass(frozen=True)
class _Section:
    section_type: int
    flags: int
    address: int
    offset: int
    size: int
    link: int
    entry_size: int


@dataclass(frozen=True)
class _SysvHashTable:
    buckets: tuple[int, ...]
    chains: tuple[int, ...]

    @property
    def symbol_count(self) -> int:
        return len(self.chains)


@dataclass(frozen=True)
class _GnuHashTable:
    symbol_count: int
    symbol_offset: int
    bloom_shift: int
    word_bits: int
    bloom: tuple[int, ...]
    buckets: tuple[int, ...]
    chains: tuple[int, ...]


def _identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        int(value.st_dev),
        int(value.st_ino),
        int(value.st_mode),
        int(value.st_nlink),
        int(value.st_size),
        int(value.st_mtime_ns),
        int(value.st_ctime_ns),
    )


def _directory_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        int(value.st_dev),
        int(value.st_ino),
        int(stat.S_IFMT(value.st_mode)),
    )


def _open_directory(path: Path, label: str) -> tuple[int, tuple[int, ...]]:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    if not nofollow or not directory:
        raise ValueError("artifact verification requires O_NOFOLLOW/O_DIRECTORY")
    try:
        before = os.lstat(path)
        descriptor = os.open(
            path,
            os.O_RDONLY | nofollow | directory | getattr(os, "O_CLOEXEC", 0),
        )
    except OSError as error:
        raise ValueError(f"{label} cannot be opened safely") from error
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(before.st_mode)
            or not stat.S_ISDIR(opened.st_mode)
            or _directory_identity(before) != _directory_identity(opened)
        ):
            raise ValueError(f"{label} changed while opening")
        return descriptor, _directory_identity(opened)
    except BaseException:
        os.close(descriptor)
        raise


def _verify_directory(path: Path, descriptor: int, expected: tuple[int, ...]) -> None:
    try:
        named = os.lstat(path)
        opened = os.fstat(descriptor)
    except OSError as error:
        raise ValueError("artifact directory changed during verification") from error
    if (
        _directory_identity(named) != expected
        or _directory_identity(opened) != expected
    ):
        raise ValueError("artifact directory changed during verification")


def _canonical_name(name: str) -> str:
    if (
        not name
        or name in {".", ".."}
        or "/" in name
        or "\0" in name
        or Path(name).name != name
    ):
        raise ValueError("artifact name is not canonical")
    return name


class _Reader:
    def __init__(self, descriptor: int, size: int) -> None:
        self.descriptor = descriptor
        self.size = size

    def read(self, offset: int, size: int, label: str = "ELF data") -> bytes:
        if offset < 0 or size < 0 or offset > self.size or size > self.size - offset:
            raise ValueError(f"{label} escapes ELF")
        chunks: list[bytes] = []
        remaining = size
        current = offset
        while remaining:
            try:
                chunk = os.pread(self.descriptor, min(remaining, READ_CHUNK), current)
            except (AttributeError, OSError) as error:
                raise ValueError(f"cannot read {label}") from error
            if not chunk:
                raise ValueError(f"truncated {label}")
            chunks.append(chunk)
            current += len(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def unpack(self, fmt: str, offset: int, label: str = "ELF data") -> tuple[Any, ...]:
        return struct.unpack(fmt, self.read(offset, struct.calcsize(fmt), label))


def _digest_descriptor(reader: _Reader) -> str:
    digest = hashlib.sha256()
    offset = 0
    while offset < reader.size:
        chunk = reader.read(offset, min(READ_CHUNK, reader.size - offset), "ELF digest")
        digest.update(chunk)
        offset += len(chunk)
    return digest.hexdigest()


def _checked_end(start: int, size: int, limit: int, label: str) -> int:
    if start < 0 or size < 0 or start > limit or size > limit - start:
        raise ValueError(f"{label} range is invalid")
    return start + size


def _mapped_offset(
    segments: list[_LoadSegment], address: int, size: int, label: str
) -> int:
    if address < 0 or size < 0:
        raise ValueError(f"{label} address is invalid")
    candidates: set[int] = set()
    for segment in segments:
        if (
            address >= segment.virtual_address
            and address - segment.virtual_address <= segment.file_size
            and size <= segment.file_size - (address - segment.virtual_address)
        ):
            candidates.add(segment.offset + address - segment.virtual_address)
    if len(candidates) != 1:
        raise ValueError(f"{label} is not uniquely file-backed by PT_LOAD")
    return next(iter(candidates))


def _mapped_available(segments: list[_LoadSegment], address: int, label: str) -> int:
    values = {
        segment.file_size - (address - segment.virtual_address)
        for segment in segments
        if segment.virtual_address <= address < segment.virtual_address + segment.file_size
    }
    if len(values) != 1:
        raise ValueError(f"{label} is not uniquely file-backed by PT_LOAD")
    return next(iter(values))


def _read_c_string(
    reader: _Reader, base_offset: int, table_size: int, name_offset: int
) -> str:
    if name_offset < 0 or name_offset >= table_size:
        raise ValueError("dynamic symbol name escapes DT_STRTAB")
    remaining = min(table_size - name_offset, MAX_SYMBOL_NAME_BYTES + 1)
    value = bytearray()
    cursor = base_offset + name_offset
    while remaining:
        chunk = reader.read(cursor, min(256, remaining), "dynamic symbol name")
        end = chunk.find(b"\0")
        if end >= 0:
            value.extend(chunk[:end])
            break
        value.extend(chunk)
        cursor += len(chunk)
        remaining -= len(chunk)
    else:
        raise ValueError("dynamic symbol name is unterminated or oversized")
    try:
        return bytes(value).decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise ValueError("dynamic symbol name is not valid UTF-8") from error


def _sysv_hash_symbol_count(
    reader: _Reader, segments: list[_LoadSegment], address: int
) -> _SysvHashTable:
    offset = _mapped_offset(segments, address, 8, "DT_HASH header")
    buckets, chains = reader.unpack("<II", offset, "DT_HASH header")
    if (
        buckets == 0
        or buckets > MAX_HASH_BUCKETS
        or chains == 0
        or chains > MAX_DYNAMIC_SYMBOLS
    ):
        raise ValueError("DT_HASH cardinality is invalid")
    table_size = 8 + 4 * (buckets + chains)
    offset = _mapped_offset(segments, address, table_size, "DT_HASH table")
    values: list[int] = []
    for index in range(buckets + chains):
        value = reader.unpack("<I", offset + 8 + index * 4, "DT_HASH entry")[0]
        if value >= chains and value != 0:
            raise ValueError("DT_HASH entry escapes the dynamic symbol table")
        values.append(value)
    return _SysvHashTable(
        buckets=tuple(values[:buckets]),
        chains=tuple(values[buckets:]),
    )


def _gnu_hash_symbol_count(
    reader: _Reader,
    segments: list[_LoadSegment],
    address: int,
    elf_class: int,
) -> _GnuHashTable:
    offset = _mapped_offset(segments, address, 16, "DT_GNU_HASH header")
    buckets, symbol_offset, bloom_size, _bloom_shift = reader.unpack(
        "<IIII", offset, "DT_GNU_HASH header"
    )
    if (
        buckets == 0
        or buckets > MAX_HASH_BUCKETS
        or bloom_size == 0
        or bloom_size & (bloom_size - 1)
        or symbol_offset > MAX_DYNAMIC_SYMBOLS
        or _bloom_shift >= 32
    ):
        raise ValueError("DT_GNU_HASH header is invalid")
    word_size = 8 if elf_class == 2 else 4
    word_bits = word_size * 8
    bloom_address = address + 16
    bloom_offset = _mapped_offset(
        segments, bloom_address, bloom_size * word_size, "DT_GNU_HASH bloom"
    )
    bloom_format = "<Q" if elf_class == 2 else "<I"
    bloom = tuple(
        reader.unpack(
            bloom_format,
            bloom_offset + index * word_size,
            "DT_GNU_HASH bloom",
        )[0]
        for index in range(bloom_size)
    )
    bucket_address = address + 16 + bloom_size * word_size
    bucket_size = buckets * 4
    bucket_offset = _mapped_offset(
        segments, bucket_address, bucket_size, "DT_GNU_HASH buckets"
    )
    chain_address = bucket_address + bucket_size
    available = _mapped_available(segments, chain_address, "DT_GNU_HASH chains")
    maximum_chains = min(available // 4, MAX_DYNAMIC_SYMBOLS)
    terminals: dict[int, int] = {}
    maximum_terminal = symbol_offset - 1

    def terminal(start: int) -> int:
        path: list[int] = []
        index = start
        while index not in terminals:
            relative = index - symbol_offset
            if relative < 0 or relative >= maximum_chains:
                raise ValueError("DT_GNU_HASH chain escapes PT_LOAD")
            chain_offset = _mapped_offset(
                segments,
                chain_address + relative * 4,
                4,
                "DT_GNU_HASH chain",
            )
            value = reader.unpack("<I", chain_offset, "DT_GNU_HASH chain")[0]
            path.append(index)
            if value & 1:
                result = index
                break
            index += 1
            if index > MAX_DYNAMIC_SYMBOLS:
                raise ValueError("DT_GNU_HASH chain exceeds symbol limit")
        else:
            result = terminals[index]
        for visited in path:
            terminals[visited] = result
        return result

    bucket_values: list[int] = []
    for index in range(buckets):
        value = reader.unpack(
            "<I", bucket_offset + index * 4, "DT_GNU_HASH bucket"
        )[0]
        bucket_values.append(value)
        if value == 0:
            continue
        if value < symbol_offset or value > MAX_DYNAMIC_SYMBOLS:
            raise ValueError("DT_GNU_HASH bucket is invalid")
        maximum_terminal = max(maximum_terminal, terminal(value))
    count = max(symbol_offset, maximum_terminal + 1)
    if count <= 0 or count > MAX_DYNAMIC_SYMBOLS:
        raise ValueError("DT_GNU_HASH cardinality is invalid")
    chain_values = tuple(
        reader.unpack(
            "<I",
            _mapped_offset(
                segments,
                chain_address + index * 4,
                4,
                "DT_GNU_HASH chain",
            ),
            "DT_GNU_HASH chain",
        )[0]
        for index in range(count - symbol_offset)
    )
    return _GnuHashTable(
        symbol_count=count,
        symbol_offset=symbol_offset,
        bloom_shift=_bloom_shift,
        word_bits=word_bits,
        bloom=bloom,
        buckets=tuple(bucket_values),
        chains=chain_values,
    )


def _sysv_hash(name: bytes) -> int:
    value = 0
    for byte in name:
        value = ((value << 4) + byte) & 0xFFFFFFFF
        high = value & 0xF0000000
        if high:
            value ^= high >> 24
            value &= ~high
    return value & 0xFFFFFFFF


def _gnu_hash(name: bytes) -> int:
    value = 5381
    for byte in name:
        value = (value * 33 + byte) & 0xFFFFFFFF
    return value


def _sysv_hash_reaches(
    table: _SysvHashTable, name: str, target_index: int
) -> bool:
    name_bytes = name.encode("utf-8")
    index = table.buckets[_sysv_hash(name_bytes) % len(table.buckets)]
    visited: set[int] = set()
    while index != 0:
        if index >= table.symbol_count or index in visited:
            raise ValueError("DT_HASH lookup chain is invalid")
        visited.add(index)
        if index == target_index:
            return True
        index = table.chains[index]
    return False


def _gnu_hash_reaches(
    table: _GnuHashTable, name: str, target_index: int
) -> bool:
    if target_index < table.symbol_offset:
        return False
    name_hash = _gnu_hash(name.encode("utf-8"))
    word = table.bloom[
        (name_hash // table.word_bits) % len(table.bloom)
    ]
    mask = (
        1 << (name_hash % table.word_bits)
        | 1 << ((name_hash >> table.bloom_shift) % table.word_bits)
    )
    if word & mask != mask:
        return False
    index = table.buckets[name_hash % len(table.buckets)]
    if index < table.symbol_offset:
        return False
    while index < table.symbol_count:
        chain_hash = table.chains[index - table.symbol_offset]
        if (chain_hash | 1) == (name_hash | 1) and index == target_index:
            return True
        if chain_hash & 1:
            return False
        index += 1
    raise ValueError("DT_GNU_HASH lookup chain escapes dynamic symbols")


def _parse_sections(
    reader: _Reader,
    elf_class: int,
    section_offset: int,
    section_size: int,
    section_count: int,
    section_name_index: int,
) -> list[_Section]:
    section_fmt = "<IIQQQQIIQQ" if elf_class == 2 else "<IIIIIIIIII"
    native_size = struct.calcsize(section_fmt)
    if section_offset == 0:
        if section_count != 0 or section_name_index != 0 or section_size not in {0, native_size}:
            raise ValueError("sectionless ELF header is inconsistent")
        return []
    if section_count == 0 or section_size != native_size:
        raise ValueError("invalid ELF section table")
    _checked_end(section_offset, section_size * section_count, reader.size, "section table")
    if section_name_index not in {0} and section_name_index >= section_count:
        raise ValueError("invalid section-name table index")
    sections: list[_Section] = []
    for index in range(section_count):
        values = reader.unpack(
            section_fmt, section_offset + index * section_size, "section header"
        )
        section = _Section(
            section_type=values[1],
            flags=values[2],
            address=values[3],
            offset=values[4],
            size=values[5],
            link=values[6],
            entry_size=values[9],
        )
        if section.section_type != SHT_NOBITS:
            _checked_end(section.offset, section.size, reader.size, "section")
        sections.append(section)
    if sections[0].section_type != SHT_NULL:
        raise ValueError("ELF section zero is not SHT_NULL")
    return sections


def _cross_check_dynamic_sections(
    sections: list[_Section],
    segments: list[_LoadSegment],
    symbol_address: int,
    symbol_offset: int,
    symbol_size: int,
    symbol_count: int,
    string_address: int,
    string_offset: int,
    string_size: int,
) -> None:
    dynamic_sections = [section for section in sections if section.section_type == SHT_DYNSYM]
    if not dynamic_sections:
        return
    if len(dynamic_sections) != 1:
        raise ValueError("ELF must not contain multiple SHT_DYNSYM sections")
    symbols = dynamic_sections[0]
    if (
        symbols.flags & SHF_ALLOC == 0
        or symbols.address != symbol_address
        or symbols.offset != symbol_offset
        or symbols.size != symbol_count * symbol_size
        or symbols.entry_size != symbol_size
        or symbols.link >= len(sections)
    ):
        raise ValueError("SHT_DYNSYM does not match PT_DYNAMIC")
    strings = sections[symbols.link]
    if (
        strings.section_type != SHT_STRTAB
        or strings.flags & SHF_ALLOC == 0
        or strings.address != string_address
        or strings.offset != string_offset
        or strings.size != string_size
    ):
        raise ValueError("SHT_DYNSYM string table does not match PT_DYNAMIC")
    if _mapped_offset(segments, symbols.address, symbols.size, "SHT_DYNSYM") != symbols.offset:
        raise ValueError("SHT_DYNSYM is not loader-mapped consistently")
    if _mapped_offset(segments, strings.address, strings.size, "SHT_STRTAB") != strings.offset:
        raise ValueError("SHT_STRTAB is not loader-mapped consistently")


def _inspect_reader(reader: _Reader, digest: str) -> ElfInfo:
    ident = reader.read(0, 16, "ELF identification")
    if ident[:4] != b"\x7fELF":
        raise ValueError("not an ELF file")
    elf_class = ident[4]
    if elf_class not in (1, 2):
        raise ValueError(f"unsupported ELF class {elf_class}")
    if ident[5] != 1 or ident[6] != 1 or ident[7] not in {0, 3} or ident[8] != 0:
        raise ValueError("ELF identification is not Android-compatible")
    if any(ident[9:]):
        raise ValueError("ELF identification padding is nonzero")

    if elf_class == 2:
        header_fmt = "<16sHHIQQQIHHHHHH"
        program_fmt = "<IIQQQQQQ"
        dynamic_fmt = "<qQ"
        symbol_fmt = "<IBBHQQ"
    else:
        header_fmt = "<16sHHIIIIIHHHHHH"
        program_fmt = "<IIIIIIII"
        dynamic_fmt = "<iI"
        symbol_fmt = "<IIIBBH"
    header_size = struct.calcsize(header_fmt)
    values = reader.unpack(header_fmt, 0, "ELF header")
    (
        _ident,
        elf_type,
        machine,
        version,
        _entry,
        program_offset,
        section_offset,
        _flags,
        declared_header_size,
        program_size,
        program_count,
        section_size,
        section_count,
        section_name_index,
    ) = values
    if elf_type != ET_DYN:
        raise ValueError("ELF must use ET_DYN")
    if version != 1 or declared_header_size != header_size:
        raise ValueError("invalid ELF header version or size")
    native_program_size = struct.calcsize(program_fmt)
    if (
        program_size != native_program_size
        or program_count == 0
        or program_count > MAX_PROGRAM_HEADERS
    ):
        raise ValueError("invalid ELF program table")
    _checked_end(program_offset, program_size * program_count, reader.size, "program table")

    load_segments: list[_LoadSegment] = []
    dynamic_segments: list[tuple[int, int, int]] = []
    for index in range(program_count):
        program = reader.unpack(
            program_fmt, program_offset + index * program_size, "program header"
        )
        if elf_class == 2:
            p_type, p_flags, p_offset, p_vaddr, _paddr, p_filesz, p_memsz, p_align = program
        else:
            p_type, p_offset, p_vaddr, _paddr, p_filesz, p_memsz, p_flags, p_align = program
        if p_filesz > p_memsz:
            raise ValueError("program segment file size exceeds memory size")
        _checked_end(p_offset, p_filesz, reader.size, "program segment")
        if p_type == PT_LOAD:
            if p_align <= 0 or p_align & (p_align - 1):
                raise ValueError("invalid PT_LOAD alignment")
            if p_offset % p_align != p_vaddr % p_align:
                raise ValueError("incongruent PT_LOAD segment")
            load_segments.append(
                _LoadSegment(p_offset, p_vaddr, p_filesz, p_memsz, p_flags, p_align)
            )
        elif p_type == PT_DYNAMIC:
            dynamic_segments.append((p_offset, p_vaddr, p_filesz))
    if not load_segments:
        raise ValueError("ELF has no PT_LOAD segments")
    if len(dynamic_segments) != 1:
        raise ValueError("ELF must contain exactly one PT_DYNAMIC segment")

    dynamic_offset, dynamic_address, dynamic_size = dynamic_segments[0]
    native_dynamic_size = struct.calcsize(dynamic_fmt)
    if (
        dynamic_size < native_dynamic_size
        or dynamic_size % native_dynamic_size
        or dynamic_size // native_dynamic_size > MAX_DYNAMIC_ENTRIES
    ):
        raise ValueError("PT_DYNAMIC has an invalid size")
    if (
        _mapped_offset(load_segments, dynamic_address, dynamic_size, "PT_DYNAMIC")
        != dynamic_offset
    ):
        raise ValueError("PT_DYNAMIC file and virtual mappings disagree")
    dynamic_values: dict[int, list[int]] = {}
    null_seen = False
    for offset in range(dynamic_offset, dynamic_offset + dynamic_size, native_dynamic_size):
        tag, value = reader.unpack(dynamic_fmt, offset, "PT_DYNAMIC entry")
        if null_seen:
            if tag != DT_NULL or value != 0:
                raise ValueError("nonzero PT_DYNAMIC entry follows DT_NULL")
            continue
        if tag == DT_NULL:
            null_seen = True
            continue
        dynamic_values.setdefault(tag, []).append(value)
    if not null_seen:
        raise ValueError("PT_DYNAMIC is not terminated")
    critical = (DT_SYMTAB, DT_STRTAB, DT_STRSZ, DT_SYMENT, DT_HASH, DT_GNU_HASH)
    for tag in critical:
        if len(dynamic_values.get(tag, [])) > 1:
            raise ValueError(f"duplicate critical dynamic tag: {tag}")
    for tag in (DT_SYMTAB, DT_STRTAB, DT_STRSZ, DT_SYMENT):
        if len(dynamic_values.get(tag, [])) != 1:
            raise ValueError(f"required dynamic tag is missing: {tag}")
    if DT_HASH not in dynamic_values and DT_GNU_HASH not in dynamic_values:
        raise ValueError("ELF has no loader hash table")

    native_symbol_size = struct.calcsize(symbol_fmt)
    symbol_address = dynamic_values[DT_SYMTAB][0]
    string_address = dynamic_values[DT_STRTAB][0]
    string_size = dynamic_values[DT_STRSZ][0]
    if dynamic_values[DT_SYMENT][0] != native_symbol_size:
        raise ValueError("DT_SYMENT does not match the ELF class")
    if string_size <= 0:
        raise ValueError("DT_STRSZ is invalid")
    string_offset = _mapped_offset(
        load_segments, string_address, string_size, "DT_STRTAB"
    )
    if reader.read(string_offset, 1, "DT_STRTAB") != b"\0":
        raise ValueError("DT_STRTAB does not start with NUL")

    sysv_hash: _SysvHashTable | None = None
    gnu_hash: _GnuHashTable | None = None
    counts: list[int] = []
    if DT_HASH in dynamic_values:
        sysv_hash = _sysv_hash_symbol_count(
            reader, load_segments, dynamic_values[DT_HASH][0]
        )
        counts.append(sysv_hash.symbol_count)
    if DT_GNU_HASH in dynamic_values:
        gnu_hash = _gnu_hash_symbol_count(
            reader, load_segments, dynamic_values[DT_GNU_HASH][0], elf_class
        )
        counts.append(gnu_hash.symbol_count)
    if len(set(counts)) != 1:
        raise ValueError("loader hash tables disagree on symbol cardinality")
    symbol_count = counts[0]
    if symbol_count <= 0 or symbol_count > MAX_DYNAMIC_SYMBOLS:
        raise ValueError("dynamic symbol cardinality is invalid")
    symbol_bytes = symbol_count * native_symbol_size
    symbol_offset = _mapped_offset(
        load_segments, symbol_address, symbol_bytes, "DT_SYMTAB"
    )

    sections = _parse_sections(
        reader,
        elf_class,
        section_offset,
        section_size,
        section_count,
        section_name_index,
    )
    _cross_check_dynamic_sections(
        sections,
        load_segments,
        symbol_address,
        symbol_offset,
        native_symbol_size,
        symbol_count,
        string_address,
        string_offset,
        string_size,
    )

    required: dict[str, list[tuple[int, int, int, int, int, int]]] = {
        name: [] for name in REQUIRED_EXPORTS
    }
    exports: set[str] = set()
    for index in range(symbol_count):
        symbol = reader.unpack(
            symbol_fmt,
            symbol_offset + index * native_symbol_size,
            "dynamic symbol",
        )
        if elf_class == 2:
            name_offset, info, other, section_index, value, symbol_size = symbol
        else:
            name_offset, value, symbol_size, info, other, section_index = symbol
        if index == 0:
            if any(symbol):
                raise ValueError("dynamic symbol table has no null entry")
            continue
        if other & ~0x03:
            raise ValueError("dynamic symbol st_other contains reserved bits")
        name = _read_c_string(reader, string_offset, string_size, name_offset)
        binding = info >> 4
        symbol_type = info & 0x0F
        visibility = other & 0x03
        if name in required:
            required[name].append(
                (index, binding, symbol_type, visibility, section_index, value)
            )
        externally_visible = (
            binding != STB_LOCAL
            and visibility in {STV_DEFAULT, STV_PROTECTED}
            and section_index != SHN_UNDEF
        )
        if externally_visible:
            if name not in REQUIRED_EXPORTS:
                raise ValueError(f"unexpected externally visible symbol: {name!r}")
            exports.add(name)

    for name, occurrences in required.items():
        if len(occurrences) != 1:
            raise ValueError(
                f"{name}: expected exactly one dynamic symbol, got {len(occurrences)}"
            )
        index, binding, symbol_type, visibility, section_index, value = occurrences[0]
        if binding != STB_GLOBAL:
            raise ValueError(f"{name}: dynamic symbol must use STB_GLOBAL")
        if visibility != STV_DEFAULT:
            raise ValueError(f"{name}: dynamic symbol must use raw STV_DEFAULT")
        if symbol_type != STT_FUNC:
            raise ValueError(f"{name}: dynamic symbol must use STT_FUNC")
        if section_index == SHN_UNDEF or section_index >= SHN_LORESERVE:
            raise ValueError(f"{name}: dynamic symbol is not regularly defined")
        executable = any(
            segment.flags & PF_X
            and segment.virtual_address
            <= value
            < segment.virtual_address + segment.file_size
            for segment in load_segments
        )
        if not executable:
            raise ValueError(
                f"{name}: dynamic function is not in file-backed executable PT_LOAD"
            )
        if sysv_hash is not None and not _sysv_hash_reaches(sysv_hash, name, index):
            raise ValueError(f"{name}: dynamic symbol is not reachable through DT_HASH")
        if gnu_hash is not None and not _gnu_hash_reaches(gnu_hash, name, index):
            raise ValueError(
                f"{name}: dynamic symbol is not reachable through DT_GNU_HASH"
            )

    if exports != set(REQUIRED_EXPORTS):
        raise ValueError("required dynamic export set is incomplete")
    machine_name = next(
        (name for _, expected, name in ABI_LAYOUT.values() if expected == machine),
        f"EM_{machine}",
    )
    return ElfInfo(
        elf_class=elf_class,
        machine=machine,
        machine_name=machine_name,
        exports=frozenset(exports),
        load_alignments=tuple(segment.alignment for segment in load_segments),
        size=reader.size,
        sha256=digest,
    )


def _inspect_at(directory: int, name: str, minimum_size: int) -> ElfInfo:
    name = _canonical_name(name)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow or os.stat not in getattr(os, "supports_dir_fd", set()):
        raise ValueError("artifact verification requires safe dir_fd support")
    try:
        before = os.stat(name, dir_fd=directory, follow_symlinks=False)
    except OSError as error:
        raise ValueError(f"{name}: artifact cannot be inspected") from error
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size < minimum_size
        or before.st_size > MAX_SIZE
    ):
        raise ValueError(f"{name}: artifact is not a bounded single-link regular file")
    flags = (
        os.O_RDONLY
        | nofollow
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor = os.open(name, flags, dir_fd=directory)
    try:
        opened = os.fstat(descriptor)
        expected = _identity(before)
        if _identity(opened) != expected:
            raise ValueError(f"{name}: artifact changed while opening")
        reader = _Reader(descriptor, before.st_size)
        digest = _digest_descriptor(reader)
        info = _inspect_reader(reader, digest)
        if _identity(os.fstat(descriptor)) != expected:
            raise ValueError(f"{name}: artifact changed while verifying")
    finally:
        os.close(descriptor)
    try:
        final = os.stat(name, dir_fd=directory, follow_symlinks=False)
        reopened = os.open(name, flags, dir_fd=directory)
    except OSError as error:
        raise ValueError(f"{name}: artifact changed after verification") from error
    try:
        if _identity(final) != expected or _identity(os.fstat(reopened)) != expected:
            raise ValueError(f"{name}: artifact changed after verification")
    finally:
        os.close(reopened)
    return info


def inspect_elf(path: Path) -> ElfInfo:
    path = Path(path)
    directory, identity = _open_directory(path.parent, "artifact parent")
    try:
        info = _inspect_at(directory, path.name, 1)
        _verify_directory(path.parent, directory, identity)
        return info
    finally:
        os.close(directory)


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def _write_attestation(path: Path, payload: bytes) -> None:
    parent, identity = _open_directory(path.parent, "attestation parent")
    name = _canonical_name(path.name)
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptor: int | None = None
    created = False
    try:
        descriptor = os.open(name, flags, 0o600, dir_fd=parent)
        created = True
        view = memoryview(payload)
        offset = 0
        while offset < len(view):
            written = os.write(descriptor, view[offset : offset + READ_CHUNK])
            if written <= 0:
                raise OSError("attestation write made no progress")
            offset += written
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size != len(payload)
        ):
            raise ValueError("attestation output is not a stable regular file")
        _verify_directory(path.parent, parent, identity)
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
            descriptor = None
        if created:
            try:
                os.unlink(name, dir_fd=parent)
            except OSError:
                pass
        raise
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent)


def verify_family(
    directory: Path,
    family: str,
    *,
    attestation: Path | None = None,
    emit: bool = True,
) -> dict[str, Any]:
    if family not in FAMILY_LAYOUT:
        raise ValueError("unknown core family")
    prefix, minimum_size = FAMILY_LAYOUT[family]
    expected_names = {f"{prefix}-{abi}.so" for abi in ABI_LAYOUT}
    root, root_identity = _open_directory(Path(directory), "artifact directory")
    try:
        names = set(os.listdir(root))
        actual_names = {
            name
            for name in names
            if name.startswith(prefix + "-") and name.endswith(".so")
        }
        if actual_names != expected_names:
            raise ValueError(
                f"unexpected artifacts: expected {sorted(expected_names)}, "
                f"got {sorted(actual_names)}"
            )
        records: list[dict[str, Any]] = []
        for abi, (expected_class, expected_machine, _) in ABI_LAYOUT.items():
            name = f"{prefix}-{abi}.so"
            info = _inspect_at(root, name, minimum_size)
            if info.elf_class != expected_class or info.machine != expected_machine:
                raise ValueError(
                    f"{name}: wrong ELF class/machine "
                    f"{info.elf_class}/{info.machine}"
                )
            if info.exports != REQUIRED_EXPORTS:
                raise ValueError(
                    f"{name}: dynamic exports must be exactly "
                    f"{sorted(REQUIRED_EXPORTS)}, got {sorted(info.exports)}"
                )
            if min(info.load_alignments) < MIN_ANDROID_PAGE_ALIGNMENT:
                raise ValueError(
                    f"{name}: PT_LOAD alignment is below "
                    f"{MIN_ANDROID_PAGE_ALIGNMENT} bytes"
                )
            records.append(
                {
                    "path": name,
                    "size": info.size,
                    "sha256": info.sha256,
                    "elfClass": info.elf_class,
                    "machine": info.machine,
                    "exports": sorted(info.exports),
                    "loadAlignments": list(info.load_alignments),
                }
            )
            if emit:
                print(
                    f"{name}: {info.size} bytes, {info.machine_name}, "
                    f"sha256={info.sha256}, "
                    f"exports={','.join(sorted(REQUIRED_EXPORTS))}, "
                    f"min-load-alignment={min(info.load_alignments)}"
                )
        if set(os.listdir(root)) != names:
            raise ValueError("artifact directory entries changed during verification")
        _verify_directory(Path(directory), root, root_identity)
    finally:
        os.close(root)
    result = {"schema": 1, "family": family, "files": sorted(records, key=lambda x: x["path"])}
    raw_attestation = _canonical_json(result)
    if attestation is not None:
        _write_attestation(Path(attestation), raw_attestation)
    return result


def verify(directory: Path, *, attestation: Path | None = None) -> dict[str, Any]:
    return verify_family(directory, "xray", attestation=attestation)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    parser.add_argument("--family", choices=tuple(FAMILY_LAYOUT), default="xray")
    parser.add_argument("--attestation", type=Path)
    parser.add_argument("--print-attestation-sha256", action="store_true")
    args = parser.parse_args()
    if args.print_attestation_sha256 and args.attestation is None:
        parser.error("--print-attestation-sha256 requires --attestation")
    result = verify_family(
        args.directory,
        args.family,
        attestation=args.attestation,
        emit=not args.print_attestation_sha256,
    )
    if args.print_attestation_sha256:
        print(hashlib.sha256(_canonical_json(result)).hexdigest())


if __name__ == "__main__":
    main()
