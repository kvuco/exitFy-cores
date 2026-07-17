#!/usr/bin/env python3
from __future__ import annotations

import argparse
import codecs
import gzip
import hashlib
import os
import re
import stat
import tarfile
import tempfile
import zlib
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Iterator


FORBIDDEN_SUFFIXES = {
    ".plugin", ".dex", ".jar", ".apk", ".aar", ".class", ".so",
    ".dylib", ".dll", ".exe", ".syso",
    # Packaged/compiled artifacts are not corresponding source, even when an
    # individual format happens to be ASCII (PDF and Intel HEX in particular).
    ".o", ".obj", ".a", ".lib", ".lo", ".la", ".wasm", ".node",
    ".pyc", ".pyo", ".whl", ".deb", ".rpm", ".msi", ".cab", ".pkg",
    ".zip", ".tar", ".tgz", ".gz", ".bz2", ".xz", ".zst", ".7z",
    ".rar", ".war", ".ear", ".ipa", ".pdf", ".bin", ".img", ".iso",
    ".dmg", ".hex", ".ihex", ".srec", ".s19", ".s28", ".s37", ".uf2",
}
FORBIDDEN_BYTES = (
    ("TMessages" + "Proj").encode(),
    ("com" + ".exteragram").encode(),
    ("org" + ".telegram").encode(),
    ("com" + "/exteragram").encode(),
    ("org" + "/telegram").encode(),
)
FORBIDDEN_PATH_PARTS = (("com", "exteragram"), ("org", "telegram"))
FORBIDDEN_DOTTED_PATH_PARTS = {
    "com" + ".exteragram",
    "org" + ".telegram",
}
FORBIDDEN_SOURCE_TREE_PARTS = {("TMessages" + "Proj").lower()}
HOME_PATHS = (
    re.compile(rb"(?<![A-Za-z0-9_])/(?:home|root)/"),
    re.compile(rb"(?<![A-Za-z0-9_])/" + b"Users" + rb"/"),
    re.compile(rb"(?i)(?<![A-Za-z0-9_])[A-Z]:\\" + b"Users" + rb"\\"),
    re.compile(
        rb"(?<![A-Za-z0-9_])/(?:" + b"private" + rb"/(?:tmp|var/folders)|"
        + b"opt" + rb"/homebrew)(?:/|\b)"
    ),
)
MAX_BUNDLE_BYTES = 512 * 1024 * 1024
MAX_MEMBER_BYTES = 64 * 1024 * 1024
MAX_EXPANDED_BYTES = 512 * 1024 * 1024
MAX_TAR_STREAM_BYTES = MAX_EXPANDED_BYTES + 128 * 1024 * 1024
MAX_ARCHIVE_FILES = 50_000
MAX_ARCHIVE_DIRECTORIES = 50_000
MAX_MEMBERS = MAX_ARCHIVE_FILES + MAX_ARCHIVE_DIRECTORIES
MAX_FAILURES = 100
MAX_FAILURE_BYTES = 1024
MAX_MEMBER_NAME_BYTES = 4096
MAX_RETAINED_NAME_BYTES = 16 * 1024 * 1024
MAX_PAX_BYTES = 8192
MAX_ALLOWED_BINARY_BYTES = 1024 * 1024
GZIP_INPUT_BYTES = 64 * 1024
GZIP_OUTPUT_BYTES = 64 * 1024
CONTENT_READ_BYTES = 64 * 1024
CONTENT_SCAN_OVERLAP_BYTES = 256
PDF_HEADER_WINDOW_BYTES = 1024
PDF_TRAILER_WINDOW_BYTES = 1024
PDF_HEADER_BYTES = len(b"%PDF-1.0")
MAGIC_PROBE_BYTES = max(263, PDF_HEADER_WINDOW_BYTES + PDF_HEADER_BYTES - 1)
MAX_INTEL_HEX_LINE_BYTES = 1024
CANONICAL_GZIP_HEADER = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff"
GIT_LFS_POINTER_HEADER = b"version https://git-lfs.github.com/spec/v1"
BINARY_MAGICS = (
    b"\x7fELF",
    b"MZ",
    b"\xfe\xed\xfa\xce",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca",
    b"\xca\xfe\xba\xbf",
    b"\xbf\xba\xfe\xca",
    b"!<arch>\n",
    b"\0asm",
    b"PK\x03\x04",
    b"PK\x05\x06",
    b"PK\x07\x08",
    b"\x1f\x8b",
    b"BZh",
    b"\xfd7zXZ\0",
    b"\x28\xb5\x2f\xfd",
    b"7z\xbc\xaf\x27\x1c",
    b"Rar!\x1a\x07\x00",
    b"Rar!\x1a\x07\x01\x00",
    b"dex\n",
)
PDF_HEADER = re.compile(rb"%PDF-[0-9]\.[0-9]")
PDF_EOF = re.compile(
    rb"(?:\A|[\r\n\f])[\x00\t\f ]*%%EOF[\x00\t\f ]*"
    rb"(?=\r\n|[\r\n\f]|\Z)"
)
PDF_WHITESPACE = b"\x00\t\n\f\r "
PDF_DELIMITERS = b"()<>[]{}/%"
UTF8_BOM = b"\xef\xbb\xbf"
INTEL_LINE_END = re.compile(rb"[\r\n]")


@dataclass(frozen=True)
class AllowedBinary:
    size: int
    sha256: str


# These are the only non-UTF-8 files in the pinned golang.org/x/net v0.50.0
# vendor tree. The reviewed module ZIP reproduces the exact go.sum checksum
# h1:ucWh9eiCGyDR3vtzso0WMQinm2Dnt8cFMuQa9K33J60=.
ALLOWED_BINARY_FILES = {
    PurePosixPath("singbox/vendor/golang.org/x/net/publicsuffix/data/children"):
        AllowedBinary(
            3484,
            "bda2852d2be3d2187bcb45acedf9973af4ceeead7cec45dfd22f17424f746b9d",
        ),
    PurePosixPath("singbox/vendor/golang.org/x/net/publicsuffix/data/nodes"):
        AllowedBinary(
            50500,
            "4291647663383213ccefb726abacf571c5d76904ee939e0e3feb41898bb43102",
        ),
}
SYSTEM_ROOT_ALIASES = {
    # Darwin exposes these root-owned compatibility links. Resolve only their
    # exact documented targets, then traverse the resulting chain with
    # O_NOFOLLOW like every other input path.
    "etc": ("private", "etc"),
    "tmp": ("private", "tmp"),
    "var": ("private", "var"),
}


@dataclass(frozen=True)
class GzipStreamInfo:
    expanded_size: int
    last_nonzero_offset: int


@dataclass(frozen=True)
class RawTarLayout:
    archive_end: int
    member_count: int
    file_count: int
    directory_count: int


@dataclass(frozen=True)
class OpenedBundle:
    stream: BinaryIO
    fingerprint: tuple[int, ...]
    absolute_path: Path
    leaf_name: str
    parent_descriptor: int
    directory_fingerprints: tuple[tuple[int, ...], ...]


@contextmanager
def managed_opened_bundle(opened: OpenedBundle) -> Iterator[BinaryIO]:
    try:
        yield opened.stream
    finally:
        try:
            opened.stream.close()
        finally:
            os.close(opened.parent_descriptor)


@dataclass(frozen=True)
class ContentAudit:
    bytes_read: int
    exact_size: bool
    forbidden_magic: bool
    sha256: str | None
    has_nul: bool
    valid_utf8: bool
    forbidden_reference: bool
    local_host_path: bool
    git_lfs_pointer: bool


class IntelHexScanner:
    """Recognize a complete Intel HEX stream without retaining the payload."""

    def __init__(self) -> None:
        self.possible = True
        self.line = bytearray()
        self.records = 0
        self.eof_seen = False
        self.preamble = bytearray()
        self.preamble_done = False

    def feed(self, data: bytes) -> None:
        if not self.possible:
            return
        offset = 0
        if not self.preamble_done:
            while offset < len(data) and not self.preamble_done:
                self.preamble.append(data[offset])
                offset += 1
                if not UTF8_BOM.startswith(self.preamble):
                    pending = bytes(self.preamble)
                    self.preamble.clear()
                    self.preamble_done = True
                    self._feed_body(pending)
                elif len(self.preamble) == len(UTF8_BOM):
                    # Intel HEX commonly permits one UTF-8 BOM, but only at
                    # absolute byte zero. A second BOM is ordinary payload and
                    # therefore makes the first substantive line invalid.
                    self.preamble.clear()
                    self.preamble_done = True
            if not self.preamble_done or not self.possible:
                return
        self._feed_body(data[offset:])

    def _feed_body(self, data: bytes) -> None:
        offset = 0
        while offset < len(data):
            terminator = INTEL_LINE_END.search(data, offset)
            end = len(data) if terminator is None else terminator.start()
            piece = data[offset:end]
            if len(self.line) + len(piece) > MAX_INTEL_HEX_LINE_BYTES:
                self.possible = False
                self.line.clear()
                return
            self.line.extend(piece)
            if terminator is None:
                return
            self._finish_line()
            if not self.possible:
                return
            offset = end + 1

    def finish(self) -> bool:
        if self.possible and not self.preamble_done:
            pending = bytes(self.preamble)
            self.preamble.clear()
            self.preamble_done = True
            self._feed_body(pending)
        if self.possible and self.line:
            self._finish_line()
        return self.possible and self.eof_seen and self.records >= 2

    def _finish_line(self) -> None:
        line = bytes(self.line)
        self.line.clear()
        stripped = line.strip(b" \t\f")
        if not stripped or stripped.startswith((b";", b"#")):
            return
        record_type = intel_hex_record_type(stripped)
        if record_type is None or self.eof_seen:
            self.possible = False
            return
        self.records += 1
        if record_type == 1:
            self.eof_seen = True


class PdfObjectScanner:
    """Recognize an indirect-object declaration with constant memory."""

    SEEK_FIRST = 0
    NUMBER = 1
    NUMBER_GAP = 2
    KEYWORD_O = 3
    KEYWORD_B = 4
    KEYWORD_J = 5
    COMMENT = 6

    def __init__(self) -> None:
        self.state = self.SEEK_FIRST
        self.digits = 0
        self.completed_numbers = 0
        self.boundary = True
        self.found = False

    @staticmethod
    def _is_whitespace(byte: int) -> bool:
        return byte in PDF_WHITESPACE

    @staticmethod
    def _is_boundary(byte: int) -> bool:
        return byte in PDF_WHITESPACE or byte in PDF_DELIMITERS

    def _reset(self, byte: int) -> None:
        self.state = self.SEEK_FIRST
        self.digits = 0
        self.completed_numbers = 0
        self.boundary = self._is_boundary(byte)

    def feed(self, data: bytes) -> None:
        if self.found:
            return
        for byte in data:
            if self.state == self.COMMENT:
                if byte in b"\r\n":
                    self.state = (
                        self.NUMBER_GAP
                        if self.completed_numbers
                        else self.SEEK_FIRST
                    )
                    self.boundary = True
            elif self.state == self.SEEK_FIRST:
                if self.boundary and 0x30 <= byte <= 0x39:
                    self.state = self.NUMBER
                    self.digits = 1
                    self.completed_numbers = 0
                    self.boundary = False
                elif byte == ord("%"):
                    self.state = self.COMMENT
                    self.completed_numbers = 0
                else:
                    self.boundary = self._is_boundary(byte)
            elif self.state == self.NUMBER:
                if 0x30 <= byte <= 0x39:
                    self.digits += 1
                    if self.digits > 10:
                        self._reset(byte)
                elif self._is_whitespace(byte):
                    self.completed_numbers = min(
                        2, self.completed_numbers + 1
                    )
                    self.state = self.NUMBER_GAP
                elif byte == ord("%"):
                    self.completed_numbers = min(
                        2, self.completed_numbers + 1
                    )
                    self.state = self.COMMENT
                else:
                    self._reset(byte)
            elif self.state == self.NUMBER_GAP:
                if self._is_whitespace(byte):
                    continue
                if 0x30 <= byte <= 0x39:
                    self.state = self.NUMBER
                    self.digits = 1
                elif self.completed_numbers >= 2 and byte == ord("o"):
                    self.state = self.KEYWORD_O
                elif byte == ord("%"):
                    self.state = self.COMMENT
                else:
                    self._reset(byte)
            elif self.state == self.KEYWORD_O:
                if byte == ord("b"):
                    self.state = self.KEYWORD_B
                elif byte == ord("%"):
                    self.completed_numbers = 0
                    self.state = self.COMMENT
                else:
                    self._reset(byte)
            elif self.state == self.KEYWORD_B:
                if byte == ord("j"):
                    self.state = self.KEYWORD_J
                elif byte == ord("%"):
                    self.completed_numbers = 0
                    self.state = self.COMMENT
                else:
                    self._reset(byte)
            elif self._is_boundary(byte):
                self.found = True
                return
            else:
                self._reset(byte)


class AuditFailures(list[str]):
    def append(self, message: str) -> None:
        if len(self) >= MAX_FAILURES:
            raise ValueError(
                f"source bundle exceeds the {MAX_FAILURES}-failure limit"
            )
        cleaned = (
            str(message)
            .replace("\0", "\\0")
            .replace("\r", "\\r")
            .replace("\n", "\\n")
        )
        encoded = cleaned.encode("utf-8", "replace")
        if len(encoded) > MAX_FAILURE_BYTES:
            cleaned = (
                encoded[:MAX_FAILURE_BYTES - 3]
                .decode("utf-8", "ignore")
                + "..."
            )
        super().append(cleaned)


def forbidden_namespace_path(path: PurePosixPath) -> bool:
    parts = tuple(part.lower() for part in path.parts)
    return (
        any(part in FORBIDDEN_DOTTED_PATH_PARTS for part in parts)
        or any(part in FORBIDDEN_SOURCE_TREE_PARTS for part in parts)
        or any(
            parts[index:index + len(forbidden)] == forbidden
            for forbidden in FORBIDDEN_PATH_PARTS
            for index in range(len(parts) - len(forbidden) + 1)
        )
    )


def contains_local_host_path(data: bytes) -> bool:
    return any(pattern.search(data) for pattern in HOME_PATHS)


def member_name_policy_failure(
    encoded_name: bytes,
    *,
    directory: bool = False,
) -> str | None:
    """Return the first fail-closed metadata policy violation."""
    candidate = encoded_name
    if directory and candidate.endswith(b"/"):
        candidate = candidate[:-1]
    if b"\\" in candidate:
        return "archive member name contains a backslash"
    if any(byte < 0x20 or byte == 0x7F for byte in candidate):
        return "archive member name contains a control character"
    if any(
        part.endswith((b".", b" "))
        for part in candidate.split(b"/")
        if part
    ):
        return "archive member path component has a trailing dot or space"
    lowered = candidate.lower()
    if any(forbidden.lower() in lowered for forbidden in FORBIDDEN_BYTES):
        return "forbidden archive namespace"
    if contains_local_host_path(candidate):
        return "absolute local host path in archive member name"
    return None


def contains_local_host_path_before(
    data: bytes,
    start_limit: int,
    minimum_start: int = 0,
) -> bool:
    if start_limit <= 0:
        return False
    for pattern in HOME_PATHS:
        position = 0
        while position < start_limit:
            match = pattern.search(data, position)
            if match is None or match.start() >= start_limit:
                break
            if match.start() >= minimum_start:
                return True
            position = match.start() + 1
    return False


def has_forbidden_binary_magic(data: bytes) -> bool:
    if data.startswith(BINARY_MAGICS):
        return True
    if len(data) >= 263 and data[257:263] in {b"ustar\0", b"ustar "}:
        return True
    return (
        len(data) >= 4
        and 0x50 <= data[0] <= 0x5F
        and data[1:4] == b"\x2a\x4d\x18"
    )


def intel_hex_record_type(line: bytes) -> int | None:
    encoded = line[1:] if line.startswith(b":") else b""
    if (
        len(encoded) < 10
        or len(encoded) % 2
        or any(
            byte not in b"0123456789abcdefABCDEF"
            for byte in encoded
        )
    ):
        return None
    try:
        record = bytes.fromhex(encoded.decode("ascii"))
    except (UnicodeDecodeError, ValueError):
        return None
    if (
        len(record) != record[0] + 5
        or record[3] > 5
        or sum(record) % 256 != 0
    ):
        return None
    record_type = record[3]
    if record_type == 0:
        return record_type
    expected_lengths = {1: 0, 2: 2, 3: 4, 4: 2, 5: 4}
    if record[0] != expected_lengths[record_type] or record[1:3] != b"\0\0":
        return None
    return record_type


def has_structured_pdf(
    prefix: bytes,
    has_object: bool,
    trailer: bytes,
) -> bool:
    header = PDF_HEADER.search(prefix)
    return (
        header is not None
        and header.start() < PDF_HEADER_WINDOW_BYTES
        and has_object
        and PDF_EOF.search(trailer) is not None
    )


def bundle_fingerprint(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_mode),
        int(metadata.st_nlink),
        int(metadata.st_size),
        int(metadata.st_mtime_ns),
        int(metadata.st_ctime_ns),
    )


def bundle_open_flags() -> int:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        raise ValueError("platform cannot safely open source bundles")
    return (
        os.O_RDONLY
        | nofollow
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )


def directory_open_flags() -> int:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    if (
        not nofollow
        or not directory
        or os.open not in getattr(os, "supports_dir_fd", set())
    ):
        raise ValueError("platform cannot safely traverse source bundle paths")
    return (
        os.O_RDONLY
        | nofollow
        | directory
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )


def validate_bundle_metadata(metadata: os.stat_result) -> tuple[int, ...]:
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ValueError("bundle is not a private regular file")
    return bundle_fingerprint(metadata)


def directory_fingerprint(metadata: os.stat_result) -> tuple[int, ...]:
    if not stat.S_ISDIR(metadata.st_mode):
        raise ValueError("bundle ancestor is not a directory")
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(stat.S_IFMT(metadata.st_mode)),
    )


def normalized_bundle_path(bundle: Path) -> Path:
    try:
        absolute = Path(os.path.abspath(os.fspath(bundle)))
    except (OSError, TypeError, ValueError) as error:
        raise ValueError("bundle path cannot be normalized") from error
    if (
        len(absolute.parts) < 2
        or absolute.parts[0] != os.sep
        or any(part in {"", ".", ".."} for part in absolute.parts[1:])
    ):
        raise ValueError("bundle path is not a safe absolute path")
    alias_target = SYSTEM_ROOT_ALIASES.get(absolute.parts[1])
    if alias_target is not None:
        alias_path = Path(os.sep, absolute.parts[1])
        try:
            metadata = os.lstat(alias_path)
            target = os.readlink(alias_path)
        except OSError:
            pass
        else:
            expected_target = "/".join(alias_target)
            if stat.S_ISLNK(metadata.st_mode) and target == expected_target:
                absolute = Path(os.sep).joinpath(
                    *alias_target,
                    *absolute.parts[2:],
                )
    return absolute


def open_directory_chain(
    absolute_path: Path,
) -> tuple[int, tuple[tuple[int, ...], ...], str]:
    flags = directory_open_flags()
    components = absolute_path.parts
    descriptor = os.open(os.sep, flags)
    fingerprints: list[tuple[int, ...]] = []
    try:
        fingerprints.append(directory_fingerprint(os.fstat(descriptor)))
        for component in components[1:-1]:
            next_descriptor = os.open(
                component,
                flags,
                dir_fd=descriptor,
            )
            try:
                fingerprint = directory_fingerprint(
                    os.fstat(next_descriptor)
                )
            except Exception:
                os.close(next_descriptor)
                raise
            os.close(descriptor)
            descriptor = next_descriptor
            fingerprints.append(fingerprint)
        return descriptor, tuple(fingerprints), components[-1]
    except Exception:
        os.close(descriptor)
        raise


def leaf_metadata(parent_descriptor: int, leaf_name: str) -> os.stat_result:
    if (
        os.stat not in getattr(os, "supports_dir_fd", set())
        or os.stat not in getattr(os, "supports_follow_symlinks", set())
    ):
        raise ValueError("platform cannot safely inspect source bundle paths")
    return os.stat(
        leaf_name,
        dir_fd=parent_descriptor,
        follow_symlinks=False,
    )


def verify_leaf_identity(
    parent_descriptor: int,
    leaf_name: str,
    expected_fingerprint: tuple[int, ...],
) -> None:
    if validate_bundle_metadata(
        leaf_metadata(parent_descriptor, leaf_name)
    ) != expected_fingerprint:
        raise ValueError("bundle path changed while it was audited")
    reopened = os.open(
        leaf_name,
        bundle_open_flags(),
        dir_fd=parent_descriptor,
    )
    try:
        if validate_bundle_metadata(
            os.fstat(reopened)
        ) != expected_fingerprint:
            raise ValueError("bundle path changed while it was audited")
    finally:
        os.close(reopened)


def open_regular_bundle(bundle: Path) -> OpenedBundle:
    absolute_path = normalized_bundle_path(bundle)
    try:
        parent_descriptor, directory_fingerprints, leaf_name = (
            open_directory_chain(absolute_path)
        )
    except (OSError, ValueError) as error:
        raise ValueError("bundle cannot be opened safely") from error
    try:
        before_fingerprint = validate_bundle_metadata(
            leaf_metadata(parent_descriptor, leaf_name)
        )
        descriptor = os.open(
            leaf_name,
            bundle_open_flags(),
            dir_fd=parent_descriptor,
        )
        try:
            after_fingerprint = validate_bundle_metadata(os.fstat(descriptor))
            if before_fingerprint != after_fingerprint:
                raise ValueError("bundle changed while it was opened")
            stream = os.fdopen(descriptor, "rb", closefd=True)
        except Exception:
            os.close(descriptor)
            raise
    except Exception:
        os.close(parent_descriptor)
        raise
    return OpenedBundle(
        stream,
        after_fingerprint,
        absolute_path,
        leaf_name,
        parent_descriptor,
        directory_fingerprints,
    )


def verify_opened_bundle(
    bundle: Path,
    opened: OpenedBundle,
) -> None:
    if bundle_fingerprint(os.fstat(opened.stream.fileno())) != opened.fingerprint:
        raise ValueError("bundle changed while it was audited")
    if normalized_bundle_path(bundle) != opened.absolute_path:
        raise ValueError("bundle path changed while it was audited")
    try:
        if directory_fingerprint(
            os.fstat(opened.parent_descriptor)
        ) != opened.directory_fingerprints[-1]:
            raise ValueError("bundle path changed while it was audited")
        verify_leaf_identity(
            opened.parent_descriptor,
            opened.leaf_name,
            opened.fingerprint,
        )
        parent_descriptor, directory_fingerprints, leaf_name = (
            open_directory_chain(opened.absolute_path)
        )
        try:
            if (
                directory_fingerprints != opened.directory_fingerprints
                or leaf_name != opened.leaf_name
            ):
                raise ValueError("bundle path changed while it was audited")
            verify_leaf_identity(
                parent_descriptor,
                leaf_name,
                opened.fingerprint,
            )
        finally:
            os.close(parent_descriptor)
    except (OSError, ValueError) as error:
        if str(error) == "bundle path changed while it was audited":
            raise
        raise ValueError("bundle path changed while it was audited") from error


def read_exact_at(stream: BinaryIO, size: int, offset: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        request_size = min(remaining, GZIP_OUTPUT_BYTES)
        try:
            chunk = os.pread(stream.fileno(), request_size, offset)
        except (AttributeError, OSError) as error:
            raise ValueError("cannot inspect decompressed tar stream") from error
        if not chunk:
            raise ValueError("truncated decompressed tar stream")
        chunks.append(chunk)
        offset += len(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def validate_zero_range(
    stream: BinaryIO,
    offset: int,
    size: int,
    error_message: str,
) -> None:
    remaining = size
    while remaining:
        chunk_size = min(remaining, GZIP_OUTPUT_BYTES)
        if read_exact_at(stream, chunk_size, offset).strip(b"\0"):
            raise ValueError(error_message)
        offset += chunk_size
        remaining -= chunk_size


def parse_canonical_tar_size(header: bytes) -> int:
    field = header[124:136]
    if (
        len(field) != 12
        or field[-1:] != b"\0"
        or any(byte < ord("0") or byte > ord("7") for byte in field[:-1])
    ):
        raise ValueError("noncanonical raw archive size field")
    return int(field[:-1], 8)


def validate_raw_tar_checksum(header: bytes) -> None:
    field = header[148:156]
    if (
        len(field) != 8
        or field[6:] != b"\0 "
        or any(byte < ord("0") or byte > ord("7") for byte in field[:6])
    ):
        raise ValueError("noncanonical raw archive checksum field")
    expected = sum(header[:148]) + 8 * ord(" ") + sum(header[156:])
    if int(field[:6], 8) != expected:
        raise ValueError("invalid raw archive header checksum")


def validate_raw_pax_payload(payload: bytes) -> None:
    separator = payload.find(b" ")
    if separator <= 0:
        raise ValueError("noncanonical archive PAX metadata")
    length_field = payload[:separator]
    if (
        not length_field.isdigit()
        or len(length_field) > 5
        or length_field.startswith(b"0")
        or int(length_field, 10) != len(payload)
        or payload.count(b"\n") != 1
        or not payload.endswith(b"\n")
    ):
        raise ValueError("noncanonical archive PAX metadata")
    record = payload[separator + 1:-1]
    if not record.startswith(b"path="):
        raise ValueError("noncanonical archive PAX metadata")
    path_bytes = record[len(b"path="):]
    if (
        not path_bytes
        or len(path_bytes) > MAX_MEMBER_NAME_BYTES + 1
        or b"\0" in path_bytes
        or b"\r" in path_bytes
    ):
        raise ValueError("noncanonical archive PAX path")
    try:
        path_bytes.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise ValueError("noncanonical archive PAX path") from error
    policy_failure = member_name_policy_failure(
        path_bytes,
        directory=path_bytes.endswith(b"/"),
    )
    if policy_failure is not None:
        raise ValueError(policy_failure)


def validate_raw_member_name(name_bytes: bytes, *, directory: bool) -> None:
    if not name_bytes:
        raise ValueError("empty archive member name")
    try:
        name_bytes.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise ValueError("raw archive member name is not valid UTF-8") from error
    policy_failure = member_name_policy_failure(
        name_bytes,
        directory=directory,
    )
    if policy_failure is not None:
        raise ValueError(policy_failure)


def scan_raw_tar_stream(
    tar_stream: BinaryIO,
    expanded_size: int,
) -> RawTarLayout:
    offset = 0
    member_count = 0
    file_count = 0
    directory_count = 0
    payload_total = 0
    pending_pax = False
    unsafe_extension_types = {
        tarfile.GNUTYPE_LONGLINK,
        tarfile.GNUTYPE_LONGNAME,
        tarfile.GNUTYPE_SPARSE,
        tarfile.SOLARIS_XHDTYPE,
        tarfile.XGLTYPE,
    }
    semantic_types = {
        tarfile.REGTYPE,
        tarfile.AREGTYPE,
        tarfile.CONTTYPE,
        tarfile.DIRTYPE,
        tarfile.SYMTYPE,
        tarfile.LNKTYPE,
    }

    while True:
        header = read_exact_at(tar_stream, tarfile.BLOCKSIZE, offset)
        if header == b"\0" * tarfile.BLOCKSIZE:
            if pending_pax:
                raise ValueError("orphaned archive PAX metadata")
            expected_size = canonical_tar_stream_size(offset)
            if expanded_size != expected_size:
                raise ValueError("noncanonical decompressed tar stream length")
            if expanded_size - offset < 2 * tarfile.BLOCKSIZE:
                raise ValueError("missing canonical tar end markers")
            validate_zero_range(
                tar_stream,
                offset,
                expanded_size - offset,
                "nonzero data follows the tar members",
            )
            return RawTarLayout(
                offset,
                member_count,
                file_count,
                directory_count,
            )

        validate_raw_tar_checksum(header)
        member_size = parse_canonical_tar_size(header)
        typeflag = header[156:157]
        padded_size = (
            (member_size + tarfile.BLOCKSIZE - 1)
            // tarfile.BLOCKSIZE
            * tarfile.BLOCKSIZE
        )
        next_offset = offset + tarfile.BLOCKSIZE + padded_size
        if next_offset > expanded_size:
            raise ValueError("truncated decompressed tar member")

        if typeflag == tarfile.XHDTYPE:
            if pending_pax:
                raise ValueError("stacked archive PAX metadata")
            if member_size <= 0 or member_size > MAX_PAX_BYTES:
                raise ValueError(
                    f"archive PAX metadata exceeds {MAX_PAX_BYTES} bytes"
                )
            payload_offset = offset + tarfile.BLOCKSIZE
            payload = read_exact_at(tar_stream, member_size, payload_offset)
            validate_raw_pax_payload(payload)
            padding = read_exact_at(
                tar_stream,
                padded_size - member_size,
                payload_offset + member_size,
            )
            if padding.strip(b"\0"):
                raise ValueError("nonzero archive PAX padding")
            pending_pax = True
            offset = next_offset
            continue

        if typeflag in unsafe_extension_types:
            raise ValueError(
                "noncanonical archive PAX metadata or extension type"
            )
        if typeflag not in semantic_types:
            raw_name = (
                header[:tarfile.LENGTH_NAME]
                .split(b"\0", 1)[0]
                .decode("utf-8", "replace")
                .replace("\r", "\\r")
                .replace("\n", "\\n")
            )
            raise ValueError(f"unsupported archive member type: {raw_name}")
        if not pending_pax:
            validate_raw_member_name(
                header[:tarfile.LENGTH_NAME].split(b"\0", 1)[0],
                directory=typeflag == tarfile.DIRTYPE,
            )
        if member_size > MAX_MEMBER_BYTES:
            raise ValueError(f"oversized raw archive member: {member_size} bytes")
        payload_total += member_size
        if payload_total > MAX_EXPANDED_BYTES:
            raise ValueError("expanded source bundle exceeds limit")
        member_count += 1
        if member_count > MAX_MEMBERS:
            raise ValueError(
                f"source bundle exceeds the {MAX_MEMBERS}-member limit"
            )
        if typeflag == tarfile.DIRTYPE:
            directory_count += 1
            if directory_count > MAX_ARCHIVE_DIRECTORIES:
                raise ValueError(
                    "source bundle exceeds the "
                    f"{MAX_ARCHIVE_DIRECTORIES}-directory limit"
                )
        elif typeflag in {
            tarfile.REGTYPE,
            tarfile.AREGTYPE,
            tarfile.CONTTYPE,
        }:
            file_count += 1
            if file_count > MAX_ARCHIVE_FILES:
                raise ValueError(
                    f"source bundle exceeds the {MAX_ARCHIVE_FILES}-file limit"
                )
        pending_pax = False
        offset = next_offset


def inspect_gzip_stream(
    source: BinaryIO,
    expanded_sink: BinaryIO | None = None,
) -> GzipStreamInfo:
    source.seek(0)
    if source.read(len(CANONICAL_GZIP_HEADER)) != CANONICAL_GZIP_HEADER:
        raise ValueError("noncanonical gzip header")
    source.seek(0)
    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    expanded = 0
    compressed_total = 0
    last_nonzero = -1

    def account(data: bytes) -> None:
        nonlocal expanded, last_nonzero
        if expanded + len(data) > MAX_TAR_STREAM_BYTES:
            raise ValueError("decompressed tar stream exceeds limit")
        if expanded_sink is not None and data:
            if expanded_sink.write(data) != len(data):
                raise ValueError("cannot materialize decompressed tar stream")
        without_trailing_zeroes = data.rstrip(b"\0")
        if without_trailing_zeroes:
            last_nonzero = expanded + len(without_trailing_zeroes) - 1
        expanded += len(data)

    try:
        while True:
            compressed = source.read(GZIP_INPUT_BYTES)
            if not compressed:
                break
            compressed_total += len(compressed)
            if compressed_total > MAX_BUNDLE_BYTES:
                raise ValueError("compressed source bundle exceeds limit")
            if decompressor.eof:
                raise ValueError("data follows the gzip member")
            pending = compressed
            while pending:
                before = len(pending)
                output = decompressor.decompress(pending, GZIP_OUTPUT_BYTES)
                pending = decompressor.unconsumed_tail
                if decompressor.unused_data:
                    raise ValueError("data follows the gzip member")
                account(output)
                if not output and len(pending) == before:
                    raise ValueError("gzip decompressor made no progress")
    except zlib.error as error:
        raise ValueError("invalid gzip stream") from error
    finally:
        source.seek(0)

    if not decompressor.eof:
        raise ValueError("truncated gzip stream")
    if decompressor.unused_data:
        raise ValueError("data follows the gzip member")
    return GzipStreamInfo(expanded, last_nonzero)


def verify_canonical_gzip_bytes(
    source: BinaryIO,
    tar_stream: BinaryIO,
) -> None:
    source.seek(0)
    tar_stream.flush()
    tar_stream.seek(0)
    try:
        with tempfile.TemporaryFile(mode="w+b") as canonical:
            with gzip.GzipFile(
                filename="",
                mode="wb",
                fileobj=canonical,
                mtime=0,
            ) as compressed:
                while True:
                    payload = tar_stream.read(GZIP_OUTPUT_BYTES)
                    if not payload:
                        break
                    compressed.write(payload)
            canonical.flush()
            if canonical.tell() > MAX_BUNDLE_BYTES:
                raise ValueError("canonical compressed source bundle exceeds limit")
            canonical.seek(0)
            while True:
                actual = source.read(GZIP_INPUT_BYTES)
                expected = canonical.read(GZIP_INPUT_BYTES)
                if actual != expected:
                    raise ValueError("noncanonical gzip payload")
                if not actual:
                    break
    finally:
        source.seek(0)
        tar_stream.seek(0)


def scan_member_payload(
    payload_stream: BinaryIO,
    member_size: int,
    binary_allowed: bool,
) -> ContentAudit:
    remaining = member_size
    bytes_read = 0
    prefix = bytearray()
    scan_tail = b""
    pdf_tail = b""
    pdf_object_scanner: PdfObjectScanner | None = None
    pdf_scanned_bytes = 0
    intel_hex = IntelHexScanner()
    content_digest = hashlib.sha256() if binary_allowed else None
    has_nul = False
    forbidden_reference = False
    local_host_path = False
    valid_utf8 = True
    decoder = None
    if not binary_allowed:
        decoder = codecs.getincrementaldecoder("utf-8")("strict")

    while remaining:
        chunk = payload_stream.read(min(CONTENT_READ_BYTES, remaining))
        if not chunk:
            break
        if len(chunk) > remaining:
            raise ValueError("archive payload reader exceeded member size")
        remaining -= len(chunk)
        bytes_read += len(chunk)
        if content_digest is not None:
            content_digest.update(chunk)
        if len(prefix) < MAGIC_PROBE_BYTES:
            prefix.extend(chunk[:MAGIC_PROBE_BYTES - len(prefix)])
            header = PDF_HEADER.search(prefix)
            if header is not None and header.start() < PDF_HEADER_WINDOW_BYTES:
                if pdf_object_scanner is None:
                    pdf_object_scanner = PdfObjectScanner()
                    pdf_object_scanner.feed(bytes(prefix[header.end():]))
                    pdf_scanned_bytes = len(prefix)
        pdf_tail = (pdf_tail + chunk)[-PDF_TRAILER_WINDOW_BYTES:]
        intel_hex.feed(chunk)

        window = scan_tail + chunk
        if pdf_object_scanner is not None and not pdf_object_scanner.found:
            chunk_offset = bytes_read - len(chunk)
            scan_offset = max(pdf_scanned_bytes, chunk_offset)
            if scan_offset < bytes_read:
                pdf_object_scanner.feed(chunk[scan_offset - chunk_offset:])
                pdf_scanned_bytes = bytes_read
        lowered = window.lower()
        if not forbidden_reference:
            forbidden_reference = any(
                forbidden.lower() in lowered for forbidden in FORBIDDEN_BYTES
            )
        if not local_host_path:
            safe_start_limit = max(
                0, len(window) - CONTENT_SCAN_OVERLAP_BYTES
            )
            local_host_path = contains_local_host_path_before(
                window,
                safe_start_limit,
                0 if bytes_read == len(window) else 1,
            )
        scan_tail = window[-(CONTENT_SCAN_OVERLAP_BYTES + 1):]

        if not binary_allowed:
            has_nul = has_nul or b"\0" in chunk
            if decoder is not None:
                try:
                    decoder.decode(chunk, final=False)
                except UnicodeDecodeError:
                    valid_utf8 = False
                    decoder = None

    extra = payload_stream.read(1)
    exact_size = remaining == 0 and not extra
    if not local_host_path:
        local_host_path = contains_local_host_path_before(
            scan_tail,
            len(scan_tail),
            0 if bytes_read == len(scan_tail) else 1,
        )
    if decoder is not None:
        try:
            decoder.decode(b"", final=True)
        except UnicodeDecodeError:
            valid_utf8 = False

    return ContentAudit(
        bytes_read=bytes_read,
        exact_size=exact_size,
        forbidden_magic=(
            has_forbidden_binary_magic(bytes(prefix))
            or has_structured_pdf(
                bytes(prefix),
                pdf_object_scanner is not None and pdf_object_scanner.found,
                pdf_tail,
            )
            or intel_hex.finish()
        ),
        sha256=(content_digest.hexdigest() if content_digest is not None else None),
        has_nul=has_nul,
        valid_utf8=valid_utf8,
        forbidden_reference=forbidden_reference,
        local_host_path=local_host_path,
        git_lfs_pointer=bytes(prefix).startswith(GIT_LFS_POINTER_HEADER),
    )


def validate_reproducible_metadata(
    member: tarfile.TarInfo,
    failures: list[str],
) -> None:
    if member.uid != 0 or member.gid != 0:
        failures.append(f"noncanonical archive ownership: {member.name}")
    if member.uname or member.gname:
        failures.append(f"noncanonical archive owner names: {member.name}")
    if member.mtime != 0:
        failures.append(f"noncanonical archive mtime: {member.name}")
    if member.linkname:
        failures.append(f"noncanonical archive link metadata: {member.name}")
    if member.mode & ~0o777:
        failures.append(f"archive mode contains special bits: {member.name}")
    if member.isdir():
        if member.type != tarfile.DIRTYPE or member.mode != 0o755 or member.size != 0:
            failures.append(f"noncanonical archive directory metadata: {member.name}")
    elif member.isfile():
        if member.type != tarfile.REGTYPE or member.mode not in {0o644, 0o755}:
            failures.append(f"noncanonical archive file metadata: {member.name}")

    try:
        member.name.encode("ascii", "strict")
        path_needs_pax = len(member.name) > tarfile.LENGTH_NAME
    except UnicodeEncodeError:
        path_needs_pax = True
    expected_keys = {"path"} if path_needs_pax else set()
    actual_keys = set(member.pax_headers)
    if actual_keys != expected_keys:
        failures.append(f"noncanonical archive PAX metadata: {member.name}")
    if "path" in member.pax_headers:
        expected_path = member.name + "/" if member.isdir() else member.name
        if member.pax_headers["path"] != expected_path:
            failures.append(f"noncanonical archive PAX path: {member.name}")


def allowed_binary_spec(path: PurePosixPath) -> AllowedBinary | None:
    if len(path.parts) < 2:
        return None
    return ALLOWED_BINARY_FILES.get(PurePosixPath(*path.parts[1:]))


def canonical_tar_stream_size(archive_end: int) -> int:
    terminator_end = archive_end + 2 * tarfile.BLOCKSIZE
    return (
        (terminator_end + tarfile.RECORDSIZE - 1)
        // tarfile.RECORDSIZE
        * tarfile.RECORDSIZE
    )


def validate_canonical_member_bytes(
    tar_stream: BinaryIO,
    member: tarfile.TarInfo,
    failures: list[str],
) -> None:
    """Reject bytes which tarfile parses away from a semantic TarInfo."""
    try:
        expected = member.tobuf(
            tarfile.PAX_FORMAT,
            tarfile.ENCODING,
            "surrogateescape",
        )
    except (OverflowError, UnicodeError, ValueError) as error:
        failures.append(
            f"cannot canonicalize archive member header: {member.name}: "
            f"{type(error).__name__}"
        )
        return

    header_size = int(member.offset_data) - int(member.offset)
    if header_size != len(expected):
        failures.append(f"noncanonical archive header span: {member.name}")
        return
    actual = read_exact_at(tar_stream, header_size, int(member.offset))
    if actual != expected:
        failures.append(f"noncanonical raw archive header: {member.name}")

    padding_size = (-int(member.size)) % tarfile.BLOCKSIZE
    if not padding_size:
        return
    padding_offset = int(member.offset_data) + int(member.size)
    padding = read_exact_at(tar_stream, padding_size, padding_offset)
    if padding.strip(b"\0"):
        failures.append(f"nonzero archive member padding: {member.name}")


def validate_builder_topology(
    member_sequence: list[PurePosixPath],
    member_kinds: dict[PurePosixPath, set[str]],
    failures: AuditFailures,
) -> None:
    if any(len(path.parts) == 1 for path in member_sequence):
        failures.append("explicit logical root archive member is forbidden")

    expected_order = sorted(member_sequence, key=lambda path: path.parts)
    if member_sequence != expected_order:
        failures.append("archive members are not in canonical builder order")

    for path in member_kinds:
        if len(path.parts) <= 2:
            continue
        parent = path.parent
        parent_kinds = member_kinds.get(parent)
        if parent_kinds is None or "directory" not in parent_kinds:
            failures.append(
                f"archive parent directory is missing: {parent.as_posix()}"
            )

    ordered_paths = sorted(member_kinds, key=lambda path: path.parts)
    active_directories: list[tuple[PurePosixPath, bool]] = []

    def close_directory() -> None:
        path, has_file = active_directories.pop()
        if not has_file:
            failures.append(
                f"empty archive directory is not emitted by builder: "
                f"{path.as_posix()}"
            )
        elif active_directories:
            parent, _ = active_directories[-1]
            active_directories[-1] = (parent, True)

    for path in ordered_paths:
        while active_directories:
            parent = active_directories[-1][0]
            if (
                len(path.parts) > len(parent.parts)
                and path.parts[:len(parent.parts)] == parent.parts
            ):
                break
            close_directory()
        kinds = member_kinds[path]
        if "directory" in kinds:
            active_directories.append((path, False))
        if "file" in kinds and active_directories:
            current = active_directories[-1][0]
            if current != path:
                active_directories[-1] = (current, True)
    while active_directories:
        close_directory()


def audit_bundle(bundle: Path) -> int:
    failures = AuditFailures()
    files = 0
    directories = 0
    expanded = 0
    member_count = 0
    retained_name_bytes = 0
    archive_end = 0
    try:
        opened = open_regular_bundle(bundle)
    except (OSError, ValueError) as error:
        raise ValueError("bundle cannot be opened") from error
    with managed_opened_bundle(opened) as raw:
        metadata = os.fstat(raw.fileno())
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size <= 0
            or metadata.st_size > MAX_BUNDLE_BYTES
        ):
            raise ValueError("invalid bundle size or type")
        with tempfile.TemporaryFile(mode="w+b") as tar_stream:
            gzip_info = inspect_gzip_stream(raw, tar_stream)
            tar_stream.flush()
            verify_canonical_gzip_bytes(raw, tar_stream)
            tar_stream.seek(0)
            raw_layout = scan_raw_tar_stream(
                tar_stream,
                gzip_info.expanded_size,
            )

            root_name: str | None = None
            multiple_roots = False
            member_kinds: dict[PurePosixPath, set[str]] = {}
            member_sequence: list[PurePosixPath] = []
            archive = tarfile.open(fileobj=tar_stream, mode="r|")
            while True:
                member = archive.next()
                archive.members.clear()
                if member is None:
                    break
                member_count += 1
                if member_count > MAX_MEMBERS:
                    raise ValueError(
                        f"source bundle exceeds the {MAX_MEMBERS}-member limit"
                    )

                member_size = int(member.size)
                archive_end = max(
                    archive_end,
                    int(member.offset_data)
                    + ((max(member_size, 0) + tarfile.BLOCKSIZE - 1)
                       // tarfile.BLOCKSIZE * tarfile.BLOCKSIZE),
                )
                path = PurePosixPath(member.name)
                member_sequence.append(path)
                try:
                    encoded_name = member.name.encode("utf-8", "strict")
                except UnicodeEncodeError:
                    encoded_name = b""
                    failures.append(
                        f"archive member name is not valid UTF-8: {member.name!r}"
                    )
                retained_name_bytes += len(
                    member.name.encode("utf-8", "replace")
                )
                if retained_name_bytes > MAX_RETAINED_NAME_BYTES:
                    raise ValueError(
                        "archive member names exceed the retained-byte limit"
                    )
                if len(encoded_name) > MAX_MEMBER_NAME_BYTES:
                    failures.append(
                        f"archive member name exceeds {MAX_MEMBER_NAME_BYTES} bytes: "
                        f"{member.name}"
                    )
                if len(path.parts) > 128:
                    failures.append(
                        f"archive member depth exceeds 128: {member.name}"
                    )
                if member.isdir():
                    kind = "directory"
                    directories += 1
                    if directories > MAX_ARCHIVE_DIRECTORIES:
                        raise ValueError(
                            "source bundle exceeds the "
                            f"{MAX_ARCHIVE_DIRECTORIES}-directory limit"
                        )
                elif member.isfile():
                    kind = "file"
                    files += 1
                    if files > MAX_ARCHIVE_FILES:
                        raise ValueError(
                            "source bundle exceeds the "
                            f"{MAX_ARCHIVE_FILES}-file limit"
                        )
                else:
                    kind = "other"

                if encoded_name:
                    policy_failure = member_name_policy_failure(
                        encoded_name,
                        directory=member.isdir(),
                    )
                    if policy_failure is not None:
                        failures.append(
                            f"{policy_failure}: {member.name}"
                        )

                if not member.name or not path.parts:
                    failures.append("empty archive member name")
                else:
                    current_root = path.parts[0]
                    if root_name is None:
                        root_name = current_root
                    elif current_root != root_name and not multiple_roots:
                        failures.append(
                            "source bundle must contain exactly one root directory"
                        )
                        multiple_roots = True
                if path.as_posix() != member.name:
                    failures.append(
                        f"noncanonical archive member name: {member.name}"
                    )
                if path in member_kinds:
                    failures.append(
                        f"duplicate normalized archive member: {path.as_posix()}"
                    )
                member_kinds.setdefault(path, set()).add(kind)
                validate_reproducible_metadata(member, failures)
                validate_canonical_member_bytes(tar_stream, member, failures)

                if path.is_absolute() or ".." in path.parts:
                    failures.append(f"unsafe archive path: {member.name}")
                    continue
                if forbidden_namespace_path(path):
                    failures.append(f"forbidden archive namespace: {member.name}")
                    continue
                if member.issym() or member.islnk():
                    failures.append(f"archive link is forbidden: {member.name}")
                    continue
                if member.isdir():
                    continue
                if not member.isfile():
                    failures.append(
                        f"unsupported archive member type: {member.name}"
                    )
                    continue
                if member_size < 0 or member_size > MAX_MEMBER_BYTES:
                    failures.append(f"oversized archive member: {member.name}")
                    continue
                expanded += member_size
                if expanded > MAX_EXPANDED_BYTES:
                    failures.append("expanded source bundle exceeds limit")
                    continue
                if path.suffix.lower() in FORBIDDEN_SUFFIXES:
                    failures.append(f"forbidden packaged artifact: {member.name}")
                payload_stream = archive.extractfile(member)
                if payload_stream is None:
                    failures.append(f"cannot read archive member: {member.name}")
                    continue
                binary_spec = allowed_binary_spec(path)
                with payload_stream:
                    content = scan_member_payload(
                        payload_stream,
                        member_size,
                        binary_spec is not None,
                    )
                if not content.exact_size or content.bytes_read != member_size:
                    failures.append(f"archive member size mismatch: {member.name}")
                    continue
                if content.forbidden_magic:
                    failures.append(
                        f"executable or archive magic is forbidden: {member.name}"
                    )
                if content.git_lfs_pointer:
                    failures.append(
                        f"Git LFS pointer is forbidden: {member.name}"
                    )
                if binary_spec is not None:
                    if member_size > MAX_ALLOWED_BINARY_BYTES:
                        failures.append(
                            f"allowed binary source exceeds "
                            f"{MAX_ALLOWED_BINARY_BYTES} bytes: {member.name}"
                        )
                    if (
                        member_size != binary_spec.size
                        or content.sha256 != binary_spec.sha256
                    ):
                        failures.append(
                            f"allowed binary source does not match the reviewed "
                            f"size and digest: {member.name}"
                        )
                else:
                    if content.has_nul:
                        failures.append(f"NUL byte in source text: {member.name}")
                    if not content.valid_utf8:
                        failures.append(f"non-UTF-8 source text: {member.name}")

                if content.forbidden_reference:
                    failures.append(
                        f"forbidden client reference: {member.name}"
                    )
                if content.local_host_path:
                    failures.append(f"absolute local host path: {member.name}")
            archive.close()

            if root_name is None:
                failures.append(
                    "source bundle must contain exactly one root directory"
                )
            validate_builder_topology(
                member_sequence,
                member_kinds,
                failures,
            )
            for path, kinds in member_kinds.items():
                if "file" in kinds and "directory" in kinds:
                    failures.append(
                        f"archive file/directory type collision: "
                        f"{path.as_posix()}"
                    )
                for index in range(1, len(path.parts)):
                    ancestor = PurePosixPath(*path.parts[:index])
                    if "file" in member_kinds.get(ancestor, set()):
                        failures.append(
                            f"archive file/directory type collision: "
                            f"{ancestor.as_posix()}"
                        )

            expected_stream_size = canonical_tar_stream_size(archive_end)
            if gzip_info.expanded_size != expected_stream_size:
                failures.append("noncanonical decompressed tar stream length")
            if gzip_info.last_nonzero_offset >= archive_end:
                failures.append("nonzero data follows the tar members")
            if (
                archive_end != raw_layout.archive_end
                or member_count != raw_layout.member_count
                or files != raw_layout.file_count
                or directories != raw_layout.directory_count
            ):
                failures.append("raw and parsed archive layouts differ")
        verify_opened_bundle(bundle, opened)

    if files == 0:
        failures.append("bundle contains no files")
    if failures:
        raise ValueError("\n".join(sorted(set(failures))))
    return files


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle", type=Path)
    args = parser.parse_args()
    try:
        files = audit_bundle(args.bundle)
    except (OSError, ValueError, tarfile.TarError) as error:
        raise SystemExit(f"source-bundle audit failed:\n{error}") from error
    print(f"source-bundle audit passed: {files} files")


if __name__ == "__main__":
    main()
