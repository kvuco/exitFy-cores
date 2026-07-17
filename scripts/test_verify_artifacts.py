from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import stat
import struct
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path
from unittest import mock

import verify_artifacts
import verify_singbox_artifacts


@dataclass(frozen=True)
class SymbolSpec:
    name: str
    binding: int = 1
    symbol_type: int = 2
    visibility: int = 0
    section_index: int = 1


def align(value: int, alignment: int) -> int:
    return (value + alignment - 1) & -alignment


def sysv_hash(name: bytes) -> int:
    value = 0
    for byte in name:
        value = ((value << 4) + byte) & 0xFFFFFFFF
        high = value & 0xF0000000
        if high:
            value ^= high >> 24
            value &= ~high
    return value & 0xFFFFFFFF


def gnu_hash(name: bytes) -> int:
    value = 5381
    for byte in name:
        value = (value * 33 + byte) & 0xFFFFFFFF
    return value


def synthetic_elf(
    elf_class: int,
    machine: int,
    *,
    symbols: tuple[SymbolSpec, ...] | None = None,
    text_flags: int = 5,
    elf_type: int = 3,
    include_dynamic: bool = True,
    include_sections: bool = True,
    use_gnu_hash: bool = False,
    use_both_hashes: bool = False,
    hash_count: int | None = None,
    dynsym_entry_size: int | None = None,
    dynsym_link: int = 2,
    malformed_null_symbol: bool = False,
    bss_export: str | None = None,
    gnu_bloom_shift: int = 5,
    pad_to: int = 0,
) -> bytes:
    if symbols is None:
        symbols = (SymbolSpec("StartCore"), SymbolSpec("StopCore"))
    if elf_class == 2:
        header_fmt = "<16sHHIQQQIHHHHHH"
        program_fmt = "<IIQQQQQQ"
        section_fmt = "<IIQQQQIIQQ"
        symbol_fmt = "<IBBHQQ"
        dynamic_fmt = "<qQ"
    elif elf_class == 1:
        header_fmt = "<16sHHIIIIIHHHHHH"
        program_fmt = "<IIIIIIII"
        section_fmt = "<IIIIIIIIII"
        symbol_fmt = "<IIIBBH"
        dynamic_fmt = "<iI"
    else:
        raise ValueError("synthetic ELF class must be 1 or 2")

    header_size = struct.calcsize(header_fmt)
    program_size = struct.calcsize(program_fmt)
    program_count = 2 if include_dynamic else 1
    section_size = struct.calcsize(section_fmt)
    symbol_size = struct.calcsize(symbol_fmt)
    text_offset = align(header_size + program_count * program_size, 16)
    text = b"\x90" * 64

    strings = bytearray(b"\0")
    name_offsets: dict[str, int] = {}
    for symbol in symbols:
        if symbol.name not in name_offsets:
            name_offsets[symbol.name] = len(strings)
            strings.extend(symbol.name.encode("utf-8") + b"\0")
    string_offset = text_offset + len(text)
    symbol_offset = align(string_offset + len(strings), 8 if elf_class == 2 else 4)
    symbol_count = len(symbols) + 1
    symbol_bytes = bytearray(symbol_count * symbol_size)
    if malformed_null_symbol:
        symbol_bytes[4 if elf_class == 2 else 12] = 0x12
    for index, symbol in enumerate(symbols, 1):
        info = symbol.binding << 4 | symbol.symbol_type
        value = text_offset + min(index * 4, len(text) - 4)
        if elf_class == 2:
            packed = (
                name_offsets[symbol.name],
                info,
                symbol.visibility,
                symbol.section_index,
                value,
                4,
            )
        else:
            packed = (
                name_offsets[symbol.name],
                value,
                4,
                info,
                symbol.visibility,
                symbol.section_index,
            )
        struct.pack_into(symbol_fmt, symbol_bytes, index * symbol_size, *packed)

    hash_offset = align(symbol_offset + len(symbol_bytes), 8)
    count = symbol_count if hash_count is None else hash_count
    sysv_chains = [0] * count
    for index in range(1, min(count, symbol_count) - 1):
        sysv_chains[index] = index + 1
    sysv = struct.pack("<II", 1, count) + struct.pack("<I", 1 if count > 1 else 0)
    sysv += b"".join(struct.pack("<I", value) for value in sysv_chains)
    word_size = 8 if elf_class == 2 else 4
    word_bits = word_size * 8
    bloom = 0
    for symbol in symbols:
        value = gnu_hash(symbol.name.encode("utf-8"))
        bloom |= 1 << (value % word_bits)
        bloom |= 1 << ((value >> gnu_bloom_shift) % word_bits)
    bloom_format = "<Q" if elf_class == 2 else "<I"
    gnu = struct.pack(
        "<IIII", 1, 1, 1, gnu_bloom_shift
    ) + struct.pack(bloom_format, bloom)
    gnu += struct.pack("<I", 1 if symbol_count > 1 else 0)
    if symbol_count > 1:
        gnu += b"".join(
            struct.pack(
                "<I",
                (gnu_hash(symbol.name.encode("utf-8")) & ~1)
                | (1 if index == symbol_count - 2 else 0),
            )
            for index, symbol in enumerate(symbols)
        )
    hash_payload = gnu if use_gnu_hash else sysv
    second_hash_offset: int | None = None
    if use_both_hashes:
        second_hash_offset = hash_offset + len(hash_payload)
        hash_payload += sysv if use_gnu_hash else gnu

    dynamic_offset = align(hash_offset + len(hash_payload), 8 if elf_class == 2 else 4)
    dynamic_entries: list[tuple[int, int]] = [
        (verify_artifacts.DT_STRTAB, string_offset),
        (verify_artifacts.DT_SYMTAB, symbol_offset),
        (verify_artifacts.DT_STRSZ, len(strings)),
        (verify_artifacts.DT_SYMENT, symbol_size),
    ]
    if use_gnu_hash:
        dynamic_entries.append((verify_artifacts.DT_GNU_HASH, hash_offset))
        if second_hash_offset is not None:
            dynamic_entries.append((verify_artifacts.DT_HASH, second_hash_offset))
    else:
        dynamic_entries.append((verify_artifacts.DT_HASH, hash_offset))
        if second_hash_offset is not None:
            dynamic_entries.append((verify_artifacts.DT_GNU_HASH, second_hash_offset))
    dynamic_entries.append((verify_artifacts.DT_NULL, 0))
    dynamic = b"".join(struct.pack(dynamic_fmt, *entry) for entry in dynamic_entries)

    after_dynamic = dynamic_offset + (len(dynamic) if include_dynamic else 0)
    section_offset = align(after_dynamic, 8 if elf_class == 2 else 4)
    section_count = 4 if include_sections else 0
    content_size = section_offset + section_count * section_size
    file_size = max(content_size, pad_to)
    load_memory_size = file_size
    if bss_export is not None:
        try:
            bss_index = next(
                index
                for index, symbol in enumerate(symbols, 1)
                if symbol.name == bss_export
            )
        except StopIteration as error:
            raise ValueError("bss_export must name a synthetic symbol") from error
        bss_value = file_size + 16
        value_offset = 8 if elf_class == 2 else 4
        value_format = "<Q" if elf_class == 2 else "<I"
        struct.pack_into(
            value_format,
            symbol_bytes,
            bss_index * symbol_size + value_offset,
            bss_value,
        )
        load_memory_size = bss_value + 16
    data = bytearray(file_size)
    ident = bytearray(16)
    ident[:7] = b"\x7fELF" + bytes((elf_class, 1, 1))
    header_values = (
        bytes(ident),
        elf_type,
        machine,
        1,
        0,
        header_size,
        section_offset if include_sections else 0,
        0,
        header_size,
        program_size,
        program_count,
        section_size,
        section_count,
        0,
    )
    struct.pack_into(header_fmt, data, 0, *header_values)
    if elf_class == 2:
        load = (
            1,
            text_flags,
            0,
            0,
            0,
            file_size,
            load_memory_size,
            0x4000,
        )
        dynamic_program = (
            2,
            6,
            dynamic_offset,
            dynamic_offset,
            dynamic_offset,
            len(dynamic),
            len(dynamic),
            8,
        )
    else:
        load = (
            1,
            0,
            0,
            0,
            file_size,
            load_memory_size,
            text_flags,
            0x4000,
        )
        dynamic_program = (
            2,
            dynamic_offset,
            dynamic_offset,
            dynamic_offset,
            len(dynamic),
            len(dynamic),
            6,
            4,
        )
    struct.pack_into(program_fmt, data, header_size, *load)
    if include_dynamic:
        struct.pack_into(program_fmt, data, header_size + program_size, *dynamic_program)
    data[text_offset : text_offset + len(text)] = text
    data[string_offset : string_offset + len(strings)] = strings
    data[symbol_offset : symbol_offset + len(symbol_bytes)] = symbol_bytes
    data[hash_offset : hash_offset + len(hash_payload)] = hash_payload
    if include_dynamic:
        data[dynamic_offset : dynamic_offset + len(dynamic)] = dynamic

    if include_sections:
        sections = (
            (0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
            (0, 1, 0x6, text_offset, text_offset, len(text), 0, 0, 16, 0),
            (0, 3, 0x2, string_offset, string_offset, len(strings), 0, 0, 1, 0),
            (
                0,
                11,
                0x2,
                symbol_offset,
                symbol_offset,
                len(symbol_bytes),
                dynsym_link,
                1,
                8 if elf_class == 2 else 4,
                symbol_size if dynsym_entry_size is None else dynsym_entry_size,
            ),
        )
        for index, section in enumerate(sections):
            struct.pack_into(
                section_fmt,
                data,
                section_offset + index * section_size,
                *section,
            )
    return bytes(data)


class ElfLoaderContractTest(unittest.TestCase):
    def inspect(self, payload: bytes) -> verify_artifacts.ElfInfo:
        directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        path = directory / "fixture.so"
        path.write_bytes(payload)
        return verify_artifacts.inspect_elf(path)

    def test_accepts_loader_backed_sysv_gnu_and_sectionless_elf(self) -> None:
        for elf_class, machine in ((1, 40), (2, 183)):
            for gnu, sections in ((False, True), (True, True), (False, False)):
                with self.subTest(elf_class=elf_class, gnu=gnu, sections=sections):
                    payload = synthetic_elf(
                        elf_class,
                        machine,
                        use_gnu_hash=gnu,
                        include_sections=sections,
                    )
                    info = self.inspect(payload)
                    self.assertEqual(verify_artifacts.REQUIRED_EXPORTS, info.exports)
                    self.assertEqual(hashlib.sha256(payload).hexdigest(), info.sha256)

    def test_rejects_et_exec_and_missing_loader_dynamic_view(self) -> None:
        for elf_class, machine in ((1, 40), (2, 183)):
            with self.subTest(elf_class=elf_class, case="type"):
                with self.assertRaisesRegex(ValueError, "ET_DYN"):
                    self.inspect(synthetic_elf(elf_class, machine, elf_type=2))
            with self.subTest(elf_class=elf_class, case="dynamic"):
                with self.assertRaisesRegex(ValueError, "PT_DYNAMIC"):
                    self.inspect(
                        synthetic_elf(elf_class, machine, include_dynamic=False)
                    )

    def test_rejects_fake_or_inconsistent_section_dynamic_view(self) -> None:
        payload = bytearray(synthetic_elf(2, 183))
        section_offset = struct.unpack_from("<Q", payload, 40)[0]
        section_size = struct.unpack_from("<H", payload, 58)[0]
        dynsym = section_offset + 3 * section_size
        struct.pack_into("<Q", payload, dynsym + 24, 8)  # sh_offset
        with self.assertRaisesRegex(ValueError, "SHT_DYNSYM"):
            self.inspect(bytes(payload))

    def test_rejects_hash_cardinality_disagreement_and_bad_hash(self) -> None:
        with self.assertRaisesRegex(ValueError, "disagree"):
            self.inspect(synthetic_elf(2, 183, use_both_hashes=True, hash_count=2))
        with self.assertRaisesRegex(ValueError, "cardinality|DT_HASH"):
            self.inspect(synthetic_elf(2, 183, hash_count=0))

    def test_rejects_required_exports_unreachable_through_loader_hashes(self) -> None:
        sysv_payload = bytearray(synthetic_elf(2, 183))
        sysv_header = sysv_payload.find(struct.pack("<II", 1, 3))
        self.assertGreaterEqual(sysv_header, 0)
        struct.pack_into("<I", sysv_payload, sysv_header + 16, 0)
        with self.assertRaisesRegex(ValueError, "not reachable through DT_HASH"):
            self.inspect(bytes(sysv_payload))

        gnu_payload = bytearray(synthetic_elf(2, 183, use_gnu_hash=True))
        gnu_header = gnu_payload.find(struct.pack("<IIII", 1, 1, 1, 5))
        self.assertGreaterEqual(gnu_header, 0)
        gnu_chain = gnu_header + 16 + 8 + 4
        original = struct.unpack_from("<I", gnu_payload, gnu_chain)[0]
        struct.pack_into("<I", gnu_payload, gnu_chain, original ^ 2)
        with self.assertRaisesRegex(ValueError, "not reachable through DT_GNU_HASH"):
            self.inspect(bytes(gnu_payload))

        pre_offset = bytearray(synthetic_elf(2, 183, use_gnu_hash=True))
        gnu_header = pre_offset.find(struct.pack("<IIII", 1, 1, 1, 5))
        struct.pack_into("<I", pre_offset, gnu_header + 4, 3)
        struct.pack_into("<I", pre_offset, gnu_header + 16 + 8, 0)
        with self.assertRaisesRegex(ValueError, "not reachable through DT_GNU_HASH"):
            self.inspect(bytes(pre_offset))

    def test_requires_reachability_in_every_present_hash_table(self) -> None:
        payload = bytearray(synthetic_elf(2, 183, use_both_hashes=True))
        sysv_header = payload.find(struct.pack("<II", 1, 3))
        self.assertGreaterEqual(sysv_header, 0)
        struct.pack_into("<I", payload, sysv_header + 16, 0)
        with self.assertRaisesRegex(ValueError, "not reachable through DT_HASH"):
            self.inspect(bytes(payload))

    def test_rejects_reserved_other_and_every_extra_visible_symbol_kind(self) -> None:
        with self.assertRaisesRegex(ValueError, "reserved"):
            self.inspect(
                synthetic_elf(
                    2,
                    183,
                    symbols=(
                        SymbolSpec("StartCore", visibility=0x80),
                        SymbolSpec("StopCore"),
                    ),
                )
            )
        for symbol_type in (0, 1, 10):
            with self.subTest(symbol_type=symbol_type):
                with self.assertRaisesRegex(ValueError, "unexpected externally visible"):
                    self.inspect(
                        synthetic_elf(
                            2,
                            183,
                            symbols=(
                                SymbolSpec("StartCore"),
                                SymbolSpec("StopCore"),
                                SymbolSpec("Unexpected", symbol_type=symbol_type),
                            ),
                        )
                    )

    def test_hidden_extra_and_undefined_import_are_not_exports(self) -> None:
        payload = synthetic_elf(
            2,
            183,
            symbols=(
                SymbolSpec("StartCore"),
                SymbolSpec("StopCore"),
                SymbolSpec("HiddenHelper", visibility=2, symbol_type=1),
                SymbolSpec("Imported", section_index=0, symbol_type=0),
            ),
        )
        self.assertEqual(verify_artifacts.REQUIRED_EXPORTS, self.inspect(payload).exports)

    def test_rejects_required_symbol_shape_duplicate_and_nonexec(self) -> None:
        cases = (
            (
                "exactly one",
                dict(
                    symbols=(
                        SymbolSpec("StartCore"),
                        SymbolSpec("StartCore"),
                        SymbolSpec("StopCore"),
                    )
                ),
            ),
            (
                "STB_GLOBAL",
                dict(
                    symbols=(
                        SymbolSpec("StartCore", binding=2),
                        SymbolSpec("StopCore"),
                    )
                ),
            ),
            (
                "STT_FUNC",
                dict(
                    symbols=(
                        SymbolSpec("StartCore", symbol_type=1),
                        SymbolSpec("StopCore"),
                    )
                ),
            ),
            ("executable", dict(text_flags=4)),
        )
        for expected, options in cases:
            with self.subTest(expected=expected):
                with self.assertRaisesRegex(ValueError, expected):
                    self.inspect(synthetic_elf(2, 183, **options))

        with self.assertRaisesRegex(ValueError, "file-backed executable"):
            self.inspect(synthetic_elf(2, 183, bss_export="StartCore"))

    def test_rejects_gnu_bloom_shift_outside_hash_width(self) -> None:
        for elf_class, machine in ((1, 40), (2, 183)):
            with self.subTest(elf_class=elf_class, shift=31):
                self.inspect(
                    synthetic_elf(
                        elf_class,
                        machine,
                        use_gnu_hash=True,
                        gnu_bloom_shift=31,
                    )
                )
            with self.subTest(elf_class=elf_class, shift=32):
                with self.assertRaisesRegex(ValueError, "DT_GNU_HASH header"):
                    self.inspect(
                        synthetic_elf(
                            elf_class,
                            machine,
                            use_gnu_hash=True,
                            gnu_bloom_shift=32,
                        )
                    )

    def test_rejects_malformed_section_symbol_metadata(self) -> None:
        with self.assertRaisesRegex(ValueError, "SHT_DYNSYM"):
            self.inspect(synthetic_elf(2, 183, dynsym_entry_size=1))
        with self.assertRaisesRegex(ValueError, "SHT_DYNSYM"):
            self.inspect(synthetic_elf(2, 183, dynsym_link=9))
        with self.assertRaisesRegex(ValueError, "null entry"):
            self.inspect(synthetic_elf(2, 183, malformed_null_symbol=True))


class ArtifactFileSafetyTest(unittest.TestCase):
    def test_rejects_symlink_hardlink_and_detects_name_swap(self) -> None:
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        payload = synthetic_elf(2, 183)
        original = root / "original.so"
        original.write_bytes(payload)
        symlink = root / "symlink.so"
        symlink.symlink_to(original.name)
        with self.assertRaises((OSError, ValueError)):
            verify_artifacts.inspect_elf(symlink)

        hardlink = root / "hardlink.so"
        os.link(original, hardlink)
        with self.assertRaisesRegex(ValueError, "single-link"):
            verify_artifacts.inspect_elf(hardlink)
        hardlink.unlink()

        raced = root / "raced.so"
        raced.write_bytes(payload)
        backup = root / "raced-original.so"
        real_digest = verify_artifacts._digest_descriptor

        def swap(reader):
            digest = real_digest(reader)
            raced.rename(backup)
            raced.write_bytes(payload)
            return digest

        with mock.patch.object(
            verify_artifacts, "_digest_descriptor", side_effect=swap
        ):
            with self.assertRaisesRegex(ValueError, "changed"):
                verify_artifacts.inspect_elf(raced)

    def test_fifo_substitution_cannot_block_artifact_open(self) -> None:
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        path = root / "raced.so"
        backup = root / "regular.so"
        path.write_bytes(synthetic_elf(2, 183))
        original_open = os.open
        swapped = False

        def substitute(name, flags, *args, dir_fd=None, **kwargs):
            nonlocal swapped
            if name == path.name and dir_fd is not None and not swapped:
                swapped = True
                self.assertTrue(flags & os.O_NONBLOCK)
                path.rename(backup)
                os.mkfifo(path)
            if dir_fd is None:
                return original_open(name, flags, *args, **kwargs)
            return original_open(name, flags, *args, dir_fd=dir_fd, **kwargs)

        with mock.patch.object(
            verify_artifacts.os, "open", side_effect=substitute
        ):
            with self.assertRaises(ValueError):
                verify_artifacts.inspect_elf(path)
        self.assertTrue(stat.S_ISFIFO(path.lstat().st_mode))

    def test_all_reads_are_bounded_pread_calls(self) -> None:
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        path = root / "fixture.so"
        path.write_bytes(synthetic_elf(2, 183, pad_to=2 * 1024 * 1024))
        real_pread = os.pread

        def bounded(descriptor: int, size: int, offset: int) -> bytes:
            self.assertLessEqual(size, verify_artifacts.READ_CHUNK)
            return real_pread(descriptor, size, offset)

        with mock.patch.object(verify_artifacts.os, "pread", side_effect=bounded):
            verify_artifacts.inspect_elf(path)


class ArtifactMatrixAndAttestationTest(unittest.TestCase):
    def populate(self, root: Path, family: str) -> None:
        prefix, minimum = verify_artifacts.FAMILY_LAYOUT[family]
        for abi, (elf_class, machine, _) in verify_artifacts.ABI_LAYOUT.items():
            (root / f"{prefix}-{abi}.so").write_bytes(
                synthetic_elf(elf_class, machine, pad_to=minimum)
            )

    def test_both_verifiers_accept_matrix_and_emit_canonical_attestation(self) -> None:
        for family in ("xray", "sing_box"):
            with self.subTest(family=family):
                root = Path(self.enterContext(tempfile.TemporaryDirectory()))
                self.populate(root, family)
                attestation_root = Path(
                    self.enterContext(tempfile.TemporaryDirectory())
                )
                attestation = attestation_root / f"{family}-attestation.json"
                with contextlib.redirect_stdout(io.StringIO()):
                    if family == "xray":
                        result = verify_artifacts.verify(
                            root, attestation=attestation
                        )
                    else:
                        result = verify_singbox_artifacts.verify(
                            root, attestation=attestation
                        )
                raw = attestation.read_bytes()
                self.assertEqual(
                    raw,
                    (json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n").encode(),
                )
                self.assertEqual(family, result["family"])
                self.assertEqual(4, len(result["files"]))
                for record in result["files"]:
                    self.assertEqual(
                        hashlib.sha256((root / record["path"]).read_bytes()).hexdigest(),
                        record["sha256"],
                    )

    def test_matrix_rejects_wrong_machine_and_extra_export(self) -> None:
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.populate(root, "xray")
        (root / "libxray-x86.so").write_bytes(synthetic_elf(1, 62))
        with self.assertRaisesRegex(ValueError, "wrong ELF class/machine"):
            verify_artifacts.verify(root)

        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.populate(root, "xray")
        (root / "libxray-arm64-v8a.so").write_bytes(
            synthetic_elf(
                2,
                183,
                symbols=(
                    SymbolSpec("StartCore"),
                    SymbolSpec("StopCore"),
                    SymbolSpec("Unexpected"),
                ),
            )
        )
        with self.assertRaisesRegex(ValueError, "unexpected externally visible"):
            verify_artifacts.verify(root)


if __name__ == "__main__":
    unittest.main()
