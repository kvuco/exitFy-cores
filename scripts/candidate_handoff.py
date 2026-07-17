#!/usr/bin/env python3
"""Create and verify the immutable build-to-publisher candidate handoff."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from pathlib import Path, PurePosixPath
from typing import Any


ABIS = ("arm64-v8a",)
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
GO_VERSION = re.compile(r"[0-9]+\.[0-9]+(?:\.[0-9]+)?\Z")
UPSTREAM_TAG = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+\Z")
MAX_CORE_BYTES = 64 * 1024 * 1024
MAX_SOURCE_BYTES = 512 * 1024 * 1024
MAX_PIN_BYTES = 16 * 1024 * 1024
MAX_HANDOFF_BYTES = 1024 * 1024
HANDOFF_NAME = "candidate-handoff.json"
CORE_ATTESTATION_NAME = "core-attestation.json"
SNAPSHOT_DIR = "pin-snapshot"
SNAPSHOT_FILES = ("go.mod", "go.sum", "snapshot.json")
ABI_LAYOUT = {
    "arm64-v8a": (2, 183),
}
REQUIRED_EXPORTS = ["StartCore", "StopCore"]
MIN_ANDROID_PAGE_ALIGNMENT = 16 * 1024


def _identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _canonical_component(value: str, label: str) -> str:
    path = PurePosixPath(value)
    if (
        not value
        or path.is_absolute()
        or len(path.parts) != 1
        or path.parts[0] in {".", ".."}
        or path.as_posix() != value
        or "\x00" in value
    ):
        raise ValueError(f"{label} is not a canonical filename")
    return value


def _open_directory(path: Path, label: str) -> int:
    before = os.lstat(path)
    if not stat.S_ISDIR(before.st_mode):
        raise ValueError(f"{label} is not a directory")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(path, flags)
    opened = os.fstat(descriptor)
    if not stat.S_ISDIR(opened.st_mode) or _identity(opened) != _identity(before):
        os.close(descriptor)
        raise ValueError(f"{label} changed while opening")
    return descriptor


def _open_child_directory(parent: int, name: str, label: str) -> int:
    _canonical_component(name, label)
    before = os.stat(name, dir_fd=parent, follow_symlinks=False)
    if not stat.S_ISDIR(before.st_mode):
        raise ValueError(f"{label} is not a directory")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(name, flags, dir_fd=parent)
    opened = os.fstat(descriptor)
    if not stat.S_ISDIR(opened.st_mode) or _identity(opened) != _identity(before):
        os.close(descriptor)
        raise ValueError(f"{label} changed while opening")
    return descriptor


def _directory_names(descriptor: int, label: str) -> set[str]:
    names = os.listdir(descriptor)
    if len(names) != len(set(names)):
        raise ValueError(f"{label} contains duplicate names")
    result: set[str] = set()
    for name in names:
        try:
            encoded = name.encode("utf-8", "strict")
        except UnicodeError as error:
            raise ValueError(f"{label} contains a non-UTF-8 name") from error
        if len(encoded) > 255:
            raise ValueError(f"{label} contains an oversized name")
        result.add(_canonical_component(name, label))
    return result


def _read_regular(
    directory: int, name: str, maximum: int, label: str
) -> tuple[bytes, str]:
    _canonical_component(name, label)
    before = os.stat(name, dir_fd=directory, follow_symlinks=False)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size <= 0
        or before.st_size > maximum
    ):
        raise ValueError(f"{label} is not a bounded single-link regular file")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor = os.open(name, flags, dir_fd=directory)
    try:
        opened = os.fstat(descriptor)
        if _identity(opened) != _identity(before):
            raise ValueError(f"{label} changed while opening")
        chunks: list[bytes] = []
        digest = hashlib.sha256()
        total = 0
        while total <= maximum:
            chunk = os.read(descriptor, min(64 * 1024, maximum + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            digest.update(chunk)
            chunks.append(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    final = os.stat(name, dir_fd=directory, follow_symlinks=False)
    if (
        total > maximum
        or total != before.st_size
        or _identity(after) != _identity(before)
        or _identity(final) != _identity(before)
    ):
        raise ValueError(f"{label} changed while reading")
    final_descriptor = os.open(name, flags, dir_fd=directory)
    try:
        if _identity(os.fstat(final_descriptor)) != _identity(before):
            raise ValueError(f"{label} changed before final verification")
    finally:
        os.close(final_descriptor)
    return b"".join(chunks), digest.hexdigest()


def _digest_regular(
    directory: int, name: str, maximum: int, label: str
) -> tuple[int, str]:
    _canonical_component(name, label)
    before = os.stat(name, dir_fd=directory, follow_symlinks=False)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size <= 0
        or before.st_size > maximum
    ):
        raise ValueError(f"{label} is not a bounded single-link regular file")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor = os.open(name, flags, dir_fd=directory)
    try:
        opened = os.fstat(descriptor)
        if _identity(opened) != _identity(before):
            raise ValueError(f"{label} changed while opening")
        digest = hashlib.sha256()
        total = 0
        while total <= maximum:
            chunk = os.read(descriptor, min(64 * 1024, maximum + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            digest.update(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    final = os.stat(name, dir_fd=directory, follow_symlinks=False)
    if (
        total > maximum
        or total != before.st_size
        or _identity(after) != _identity(before)
        or _identity(final) != _identity(before)
    ):
        raise ValueError(f"{label} changed while reading")
    final_descriptor = os.open(name, flags, dir_fd=directory)
    try:
        if _identity(os.fstat(final_descriptor)) != _identity(before):
            raise ValueError(f"{label} changed before final verification")
    finally:
        os.close(final_descriptor)
    return total, digest.hexdigest()


def _copy_regular(
    source_directory: int,
    source_name: str,
    destination_directory: int,
    destination_name: str,
    maximum: int,
    label: str,
) -> tuple[int, str]:
    _canonical_component(source_name, label)
    _canonical_component(destination_name, "candidate output")
    before = os.stat(source_name, dir_fd=source_directory, follow_symlinks=False)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size <= 0
        or before.st_size > maximum
    ):
        raise ValueError(f"{label} is not a bounded single-link regular file")
    read_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    write_flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    source = os.open(source_name, read_flags, dir_fd=source_directory)
    destination: int | None = None
    created = False
    try:
        opened = os.fstat(source)
        if _identity(opened) != _identity(before):
            raise ValueError(f"{label} changed while opening")
        destination = os.open(
            destination_name, write_flags, 0o600, dir_fd=destination_directory
        )
        created = True
        digest = hashlib.sha256()
        total = 0
        while total <= maximum:
            chunk = os.read(source, min(64 * 1024, maximum + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            digest.update(chunk)
            view = memoryview(chunk)
            offset = 0
            while offset < len(view):
                written = os.write(destination, view[offset:])
                if written <= 0:
                    raise OSError("short candidate write")
                offset += written
        source_after = os.fstat(source)
        os.fsync(destination)
        destination_after = os.fstat(destination)
        if (
            total > maximum
            or total != before.st_size
            or _identity(source_after) != _identity(before)
            or not stat.S_ISREG(destination_after.st_mode)
            or destination_after.st_nlink != 1
            or destination_after.st_size != total
        ):
            raise ValueError(f"{label} changed while copying")
    except BaseException:
        if destination is not None:
            os.close(destination)
            destination = None
        if created:
            try:
                os.unlink(destination_name, dir_fd=destination_directory)
            except OSError:
                pass
        raise
    finally:
        if destination is not None:
            os.close(destination)
        os.close(source)
    source_final = os.stat(
        source_name, dir_fd=source_directory, follow_symlinks=False
    )
    if _identity(source_final) != _identity(before):
        raise ValueError(f"{label} changed after copying")
    final_size, final_digest = _digest_regular(
        destination_directory,
        destination_name,
        maximum,
        f"copied {label}",
    )
    if final_size != total or final_digest != digest.hexdigest():
        raise ValueError(f"copied {label} differs from its source")
    return total, digest.hexdigest()


def _write_regular(directory: int, name: str, value: bytes) -> None:
    _canonical_component(name, "candidate output")
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(name, flags, 0o600, dir_fd=directory)
    try:
        view = memoryview(value)
        offset = 0
        while offset < len(view):
            written = os.write(descriptor, view[offset : offset + 64 * 1024])
            if written <= 0:
                raise OSError("short candidate write")
            offset += written
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size != len(value)
        ):
            raise ValueError("candidate output is not a stable regular file")
    finally:
        os.close(descriptor)


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def _load_object(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{label} is not valid JSON") from error
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def _family_contract(family: str, upstream_tag: str) -> tuple[list[str], str, str]:
    if UPSTREAM_TAG.fullmatch(upstream_tag) is None:
        raise ValueError("upstream tag is invalid")
    if family == "xray":
        cores = [f"libxray-{abi}.so" for abi in ABIS]
        return cores, "github.com/xtls/libxray", f"xray-{upstream_tag}-w"
    if family == "sing_box":
        cores = [f"libexitfy-sb-{abi}.so" for abi in ABIS]
        cores.append(f"exitfy-sb-{upstream_tag}-source.tar.gz")
        return cores, "github.com/sagernet/sing-box", f"sb-{upstream_tag}-w"
    raise ValueError("candidate family is invalid")


def _validate_provenance(
    family: str,
    event_commit: str,
    upstream_tag: str,
    upstream_commit: str,
    go_version: str,
    release_tag: str,
    snapshot_sha256: str,
) -> tuple[list[str], str]:
    artifacts, module_path, release_prefix = _family_contract(family, upstream_tag)
    if COMMIT.fullmatch(event_commit) is None or COMMIT.fullmatch(upstream_commit) is None:
        raise ValueError("candidate commit provenance is invalid")
    if GO_VERSION.fullmatch(go_version) is None:
        raise ValueError("candidate Go version is invalid")
    if (
        not release_tag.startswith(release_prefix)
        or re.fullmatch(re.escape(release_prefix) + r"(?:[2-9]|[1-9][0-9]+)", release_tag)
        is None
    ):
        raise ValueError("candidate release tag is invalid")
    if DIGEST.fullmatch(snapshot_sha256) is None:
        raise ValueError("candidate snapshot digest is invalid")
    return artifacts, module_path


def _validate_snapshot(
    raw: bytes,
    family: str,
    module_path: str,
    upstream_commit: str,
    snapshot_sha256: str,
) -> dict[str, Any]:
    if hashlib.sha256(raw).hexdigest() != snapshot_sha256:
        raise ValueError("snapshot metadata digest does not match provenance")
    value = _load_object(raw, "pin snapshot")
    if raw != _canonical_json(value):
        raise ValueError("pin snapshot is not canonical JSON")
    if set(value) != {"schema", "modulePath", "moduleVersion", "originCommit", "pins"}:
        raise ValueError("pin snapshot fields do not match the contract")
    expected_paths = (
        ["go.mod", "go.sum"]
        if family == "xray"
        else ["singbox/go.mod", "singbox/go.sum"]
    )
    pins = value.get("pins")
    if (
        value.get("schema") != 1
        or value.get("modulePath") != module_path
        or value.get("originCommit") != upstream_commit
        or not isinstance(value.get("moduleVersion"), str)
        or not value["moduleVersion"]
        or not isinstance(pins, list)
        or len(pins) != 2
    ):
        raise ValueError("pin snapshot provenance is invalid")
    for record, expected_path, expected_file in zip(
        pins, expected_paths, ("go.mod", "go.sum")
    ):
        if (
            not isinstance(record, dict)
            or set(record) != {"path", "file", "size", "sha256"}
            or record.get("path") != expected_path
            or record.get("file") != expected_file
            or type(record.get("size")) is not int
            or not 0 < record["size"] <= MAX_PIN_BYTES
            or not isinstance(record.get("sha256"), str)
            or DIGEST.fullmatch(record["sha256"]) is None
        ):
            raise ValueError("pin snapshot record is invalid")
    return value


def _read_snapshot(
    directory: int,
    family: str,
    module_path: str,
    upstream_commit: str,
    snapshot_sha256: str,
) -> tuple[dict[str, tuple[bytes, str]], dict[str, Any]]:
    if _directory_names(directory, "pin snapshot") != set(SNAPSHOT_FILES):
        raise ValueError("pin snapshot file set is not exact")
    values: dict[str, tuple[bytes, str]] = {}
    for name in SNAPSHOT_FILES:
        values[name] = _read_regular(
            directory, name, MAX_PIN_BYTES, f"pin snapshot {name}"
        )
    metadata = _validate_snapshot(
        values["snapshot.json"][0],
        family,
        module_path,
        upstream_commit,
        snapshot_sha256,
    )
    for record in metadata["pins"]:
        raw, digest = values[record["file"]]
        if len(raw) != record["size"] or digest != record["sha256"]:
            raise ValueError(f"snapshot pin bytes differ: {record['file']}")
    if _directory_names(directory, "pin snapshot") != set(SNAPSHOT_FILES):
        raise ValueError("pin snapshot changed while reading")
    return values, metadata


def _artifact_limit(name: str) -> int:
    if name.endswith(".so"):
        return MAX_CORE_BYTES
    if name.endswith("-source.tar.gz"):
        return MAX_SOURCE_BYTES
    raise ValueError("unexpected candidate artifact")


def _read_path_regular(path: Path, maximum: int, label: str) -> tuple[bytes, str]:
    parent = _open_directory(path.parent, f"{label} parent")
    try:
        return _read_regular(parent, path.name, maximum, label)
    finally:
        os.close(parent)


def _validate_core_attestation(
    raw: bytes,
    family: str,
    core_names: list[str],
) -> dict[str, tuple[int, str]]:
    value = _load_object(raw, "core attestation")
    if raw != _canonical_json(value):
        raise ValueError("core attestation is not canonical JSON")
    if set(value) != {"schema", "family", "files"}:
        raise ValueError("core attestation fields do not match the contract")
    files = value.get("files")
    if (
        value.get("schema") != 1
        or value.get("family") != family
        or not isinstance(files, list)
        or len(files) != len(core_names)
    ):
        raise ValueError("core attestation provenance is invalid")
    expected = sorted(core_names)
    if [record.get("path") if isinstance(record, dict) else None for record in files] != expected:
        raise ValueError("core attestation file set is not exact")
    result: dict[str, tuple[int, str]] = {}
    minimum_core_size = 1024 * 1024 if family == "sing_box" else 1
    for record, name in zip(files, expected):
        assert isinstance(record, dict)
        abi = next((value for value in ABIS if name.endswith(f"-{value}.so")), None)
        if abi is None:
            raise ValueError("core attestation ABI is invalid")
        expected_class, expected_machine = ABI_LAYOUT[abi]
        alignments = record.get("loadAlignments")
        size = record.get("size")
        digest = record.get("sha256")
        if (
            set(record)
            != {
                "path",
                "size",
                "sha256",
                "elfClass",
                "machine",
                "exports",
                "loadAlignments",
            }
            or record.get("path") != name
            or type(size) is not int
            or not minimum_core_size <= size <= MAX_CORE_BYTES
            or not isinstance(digest, str)
            or DIGEST.fullmatch(digest) is None
            or record.get("elfClass") != expected_class
            or record.get("machine") != expected_machine
            or record.get("exports") != REQUIRED_EXPORTS
            or not isinstance(alignments, list)
            or not alignments
            or any(
                type(alignment) is not int
                or alignment < MIN_ANDROID_PAGE_ALIGNMENT
                or alignment & (alignment - 1)
                for alignment in alignments
            )
        ):
            raise ValueError(f"core attestation record is invalid: {name}")
        result[name] = (size, digest)
    return result


def create_handoff(
    artifacts_directory: Path,
    snapshot_directory: Path,
    core_attestation: Path,
    output_directory: Path,
    *,
    family: str,
    event_commit: str,
    upstream_tag: str,
    upstream_commit: str,
    go_version: str,
    release_tag: str,
    snapshot_sha256: str,
    core_attestation_sha256: str,
) -> str:
    artifacts, module_path = _validate_provenance(
        family,
        event_commit,
        upstream_tag,
        upstream_commit,
        go_version,
        release_tag,
        snapshot_sha256,
    )
    artifacts_fd = _open_directory(artifacts_directory, "artifact directory")
    snapshot_fd = _open_directory(snapshot_directory, "snapshot directory")
    try:
        core_names = [name for name in artifacts if name.endswith(".so")]
        attestation_raw, attestation_digest = _read_path_regular(
            core_attestation,
            MAX_HANDOFF_BYTES,
            "core attestation",
        )
        if (
            DIGEST.fullmatch(core_attestation_sha256) is None
            or attestation_digest != core_attestation_sha256
        ):
            raise ValueError(
                "core attestation digest differs from the verifier output"
            )
        attested_cores = _validate_core_attestation(
            attestation_raw,
            family,
            core_names,
        )
        snapshot_values, snapshot_metadata = _read_snapshot(
            snapshot_fd,
            family,
            module_path,
            upstream_commit,
            snapshot_sha256,
        )
        parent = output_directory.parent.resolve(strict=True)
        output_name = _canonical_component(output_directory.name, "output directory")
        parent_fd = _open_directory(parent, "output parent")
        try:
            os.mkdir(output_name, 0o700, dir_fd=parent_fd)
            output_fd = _open_child_directory(parent_fd, output_name, "output directory")
            try:
                os.mkdir(SNAPSHOT_DIR, 0o700, dir_fd=output_fd)
                output_snapshot = _open_child_directory(
                    output_fd, SNAPSHOT_DIR, "output snapshot directory"
                )
                try:
                    records: list[dict[str, Any]] = []
                    for name in sorted(artifacts):
                        size, digest = _copy_regular(
                            artifacts_fd,
                            name,
                            output_fd,
                            name,
                            _artifact_limit(name),
                            f"artifact {name}",
                        )
                        if name.endswith(".so") and attested_cores.get(name) != (
                            size,
                            digest,
                        ):
                            raise ValueError(
                                f"artifact {name} differs from its ELF attestation"
                            )
                        records.append(
                            {
                                "path": name,
                                "role": "core" if name.endswith(".so") else "source",
                                "size": size,
                                "sha256": digest,
                            }
                        )
                    _write_regular(
                        output_fd,
                        CORE_ATTESTATION_NAME,
                        attestation_raw,
                    )
                    records.append(
                        {
                            "path": CORE_ATTESTATION_NAME,
                            "role": "verification",
                            "size": len(attestation_raw),
                            "sha256": attestation_digest,
                        }
                    )
                    for name in SNAPSHOT_FILES:
                        raw, digest = snapshot_values[name]
                        _write_regular(output_snapshot, name, raw)
                        records.append(
                            {
                                "path": f"{SNAPSHOT_DIR}/{name}",
                                "role": "snapshot" if name == "snapshot.json" else "pin",
                                "size": len(raw),
                                "sha256": digest,
                            }
                        )
                    records.sort(key=lambda item: item["path"])
                    handoff = {
                        "schema": 2,
                        "family": family,
                        "eventCommit": event_commit,
                        "releaseTag": release_tag,
                        "coreAttestationSha256": core_attestation_sha256,
                        "upstream": {
                            "tag": upstream_tag,
                            "commit": upstream_commit,
                            "goVersion": go_version,
                        },
                        "pinSnapshot": {
                            "metadataSha256": snapshot_sha256,
                            "modulePath": snapshot_metadata["modulePath"],
                            "moduleVersion": snapshot_metadata["moduleVersion"],
                            "originCommit": snapshot_metadata["originCommit"],
                        },
                        "files": records,
                    }
                    raw_handoff = _canonical_json(handoff)
                    if len(raw_handoff) > MAX_HANDOFF_BYTES:
                        raise ValueError("candidate handoff exceeds the safety limit")
                    _write_regular(output_fd, HANDOFF_NAME, raw_handoff)
                    os.fsync(output_snapshot)
                    os.fsync(output_fd)
                finally:
                    os.close(output_snapshot)
            finally:
                os.close(output_fd)
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    finally:
        os.close(snapshot_fd)
        os.close(artifacts_fd)

    digest = hashlib.sha256(raw_handoff).hexdigest()
    verify_handoff(
        output_directory,
        expected_sha256=digest,
        family=family,
        event_commit=event_commit,
        upstream_tag=upstream_tag,
        upstream_commit=upstream_commit,
        go_version=go_version,
        release_tag=release_tag,
        snapshot_sha256=snapshot_sha256,
    )
    return digest


def verify_handoff(
    directory: Path,
    *,
    expected_sha256: str,
    family: str,
    event_commit: str,
    upstream_tag: str,
    upstream_commit: str,
    go_version: str,
    release_tag: str,
    snapshot_sha256: str,
    allowed_extra_files: frozenset[str] = frozenset(),
) -> None:
    artifacts, module_path = _validate_provenance(
        family,
        event_commit,
        upstream_tag,
        upstream_commit,
        go_version,
        release_tag,
        snapshot_sha256,
    )
    if DIGEST.fullmatch(expected_sha256) is None:
        raise ValueError("candidate handoff digest is invalid")
    root = _open_directory(directory, "candidate directory")
    try:
        if any(
            _canonical_component(name, "allowed candidate file") != name
            for name in allowed_extra_files
        ):
            raise ValueError("allowed candidate file set is invalid")
        expected_root = (
            set(artifacts)
            | {HANDOFF_NAME, CORE_ATTESTATION_NAME, SNAPSHOT_DIR}
            | set(allowed_extra_files)
        )
        if _directory_names(root, "candidate directory") != expected_root:
            raise ValueError("candidate root file set is not exact")
        for name in sorted(allowed_extra_files):
            _digest_regular(
                root,
                name,
                MAX_HANDOFF_BYTES,
                f"allowed candidate file {name}",
            )
        raw_handoff, handoff_digest = _read_regular(
            root, HANDOFF_NAME, MAX_HANDOFF_BYTES, "candidate handoff"
        )
        if handoff_digest != expected_sha256:
            raise ValueError("candidate handoff digest does not match the build output")
        handoff = _load_object(raw_handoff, "candidate handoff")
        if raw_handoff != _canonical_json(handoff):
            raise ValueError("candidate handoff is not canonical JSON")
        if set(handoff) != {
            "schema",
            "family",
            "eventCommit",
            "releaseTag",
            "coreAttestationSha256",
            "upstream",
            "pinSnapshot",
            "files",
        }:
            raise ValueError("candidate handoff fields do not match the contract")
        if (
            handoff.get("schema") != 2
            or handoff.get("family") != family
            or handoff.get("eventCommit") != event_commit
            or handoff.get("releaseTag") != release_tag
            or handoff.get("upstream")
            != {"tag": upstream_tag, "commit": upstream_commit, "goVersion": go_version}
        ):
            raise ValueError("candidate handoff provenance differs")

        snapshot = _open_child_directory(root, SNAPSHOT_DIR, "pin snapshot")
        try:
            snapshot_values, snapshot_metadata = _read_snapshot(
                snapshot,
                family,
                module_path,
                upstream_commit,
                snapshot_sha256,
            )
        finally:
            os.close(snapshot)
        expected_snapshot = {
            "metadataSha256": snapshot_sha256,
            "modulePath": snapshot_metadata["modulePath"],
            "moduleVersion": snapshot_metadata["moduleVersion"],
            "originCommit": snapshot_metadata["originCommit"],
        }
        if handoff.get("pinSnapshot") != expected_snapshot:
            raise ValueError("candidate snapshot provenance differs")

        attestation_raw, attestation_digest = _read_regular(
            root,
            CORE_ATTESTATION_NAME,
            MAX_HANDOFF_BYTES,
            "core attestation",
        )
        if handoff.get("coreAttestationSha256") != attestation_digest:
            raise ValueError("candidate core attestation digest differs")
        attested_cores = _validate_core_attestation(
            attestation_raw,
            family,
            [name for name in artifacts if name.endswith(".so")],
        )

        actual_records: list[dict[str, Any]] = []
        for name in sorted(artifacts):
            size, digest = _digest_regular(
                root, name, _artifact_limit(name), f"candidate artifact {name}"
            )
            if name.endswith(".so") and attested_cores.get(name) != (size, digest):
                raise ValueError(
                    f"candidate artifact {name} differs from its ELF attestation"
                )
            actual_records.append(
                {
                    "path": name,
                    "role": "core" if name.endswith(".so") else "source",
                    "size": size,
                    "sha256": digest,
                }
            )
        actual_records.append(
            {
                "path": CORE_ATTESTATION_NAME,
                "role": "verification",
                "size": len(attestation_raw),
                "sha256": attestation_digest,
            }
        )
        for name in SNAPSHOT_FILES:
            raw, digest = snapshot_values[name]
            actual_records.append(
                {
                    "path": f"{SNAPSHOT_DIR}/{name}",
                    "role": "snapshot" if name == "snapshot.json" else "pin",
                    "size": len(raw),
                    "sha256": digest,
                }
            )
        actual_records.sort(key=lambda item: item["path"])
        if handoff.get("files") != actual_records:
            raise ValueError("candidate bytes differ from the handoff manifest")
        if _directory_names(root, "candidate directory") != expected_root:
            raise ValueError("candidate root changed while verifying")
    finally:
        os.close(root)


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="mode", required=True)
    for mode in ("create", "verify"):
        command = subparsers.add_parser(mode)
        command.add_argument("--family", choices=("xray", "sing_box"), required=True)
        command.add_argument("--event-commit", required=True)
        command.add_argument("--upstream-tag", required=True)
        command.add_argument("--upstream-commit", required=True)
        command.add_argument("--go-version", required=True)
        command.add_argument("--release-tag", required=True)
        command.add_argument("--snapshot-sha256", required=True)
    create = subparsers.choices["create"]
    create.add_argument("--artifacts", type=Path, required=True)
    create.add_argument("--snapshot", type=Path, required=True)
    create.add_argument("--core-attestation", type=Path, required=True)
    create.add_argument("--core-attestation-sha256", required=True)
    create.add_argument("--output", type=Path, required=True)
    verify = subparsers.choices["verify"]
    verify.add_argument("--directory", type=Path, required=True)
    verify.add_argument("--expected-sha256", required=True)
    verify.add_argument("--allow-final-manifest", action="store_true")
    args = parser.parse_args()
    common = {
        "family": args.family,
        "event_commit": args.event_commit,
        "upstream_tag": args.upstream_tag,
        "upstream_commit": args.upstream_commit,
        "go_version": args.go_version,
        "release_tag": args.release_tag,
        "snapshot_sha256": args.snapshot_sha256,
    }
    if args.mode == "create":
        print(
            create_handoff(
                args.artifacts,
                args.snapshot,
                args.core_attestation,
                args.output,
                core_attestation_sha256=args.core_attestation_sha256,
                **common,
            )
        )
    else:
        verify_handoff(
            args.directory,
            expected_sha256=args.expected_sha256,
            allowed_extra_files=(
                frozenset({"manifest.json"})
                if args.allow_final_manifest
                else frozenset()
            ),
            **common,
        )
        print("candidate handoff verified")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as error:
        raise SystemExit(f"candidate handoff failed: {error}") from error
