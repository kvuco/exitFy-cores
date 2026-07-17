from __future__ import annotations

import gzip
import hashlib
import io
import os
import tarfile
import tempfile
import unittest
from pathlib import Path, PurePosixPath
from unittest import mock

import audit_singbox_source_bundle as verifier


FORBIDDEN_DOTTED_ORG = "org" + ".telegram"
FORBIDDEN_DOTTED_COM = "com" + ".exteragram"
FORBIDDEN_SLASH_ORG = "org" + "/telegram"
FORBIDDEN_SLASH_COM = "com" + "/exteragram"
FORBIDDEN_CLIENT_TREE = "TMessages" + "Proj"


def regular_member(
    name: str,
    payload: bytes,
    *,
    mode: int = 0o644,
    uid: int = 0,
    gid: int = 0,
    uname: str = "",
    gname: str = "",
    mtime: int = 0,
    linkname: str = "",
    member_type: bytes = tarfile.REGTYPE,
    pax_headers: dict[str, str] | None = None,
) -> tuple[tarfile.TarInfo, bytes]:
    member = tarfile.TarInfo(name)
    member.type = member_type
    member.size = len(payload)
    member.mode = mode
    member.uid = uid
    member.gid = gid
    member.uname = uname
    member.gname = gname
    member.mtime = mtime
    member.linkname = linkname
    member.pax_headers = dict(pax_headers or {})
    return member, payload


def directory_member(
    name: str,
    *,
    mode: int = 0o755,
) -> tuple[tarfile.TarInfo, None]:
    member = tarfile.TarInfo(name)
    member.type = tarfile.DIRTYPE
    member.size = 0
    member.mode = mode
    member.uid = 0
    member.gid = 0
    member.uname = ""
    member.gname = ""
    member.mtime = 0
    member.pax_headers = {}
    return member, None


def canonical_file_entries(
    files: dict[str, bytes],
) -> list[tuple[tarfile.TarInfo, bytes | None]]:
    paths = {PurePosixPath(name): payload for name, payload in files.items()}
    directories = {
        PurePosixPath(*path.parts[:depth])
        for path in paths
        for depth in range(2, len(path.parts))
    }
    entries: list[tuple[tarfile.TarInfo, bytes | None]] = []
    for path in sorted(set(paths) | directories, key=lambda value: value.parts):
        if path in paths:
            entries.append(regular_member(path.as_posix(), paths[path]))
        else:
            entries.append(directory_member(path.as_posix()))
    return entries


def write_bundle(
    path: Path,
    entries: list[tuple[tarfile.TarInfo, bytes | None]],
    *,
    gzip_filename: str = "",
    gzip_mtime: int = 0,
    tar_format: int = tarfile.PAX_FORMAT,
) -> None:
    with path.open("wb") as raw:
        with gzip.GzipFile(
            filename=gzip_filename,
            mode="wb",
            fileobj=raw,
            mtime=gzip_mtime,
        ) as compressed:
            with tarfile.open(
                fileobj=compressed,
                mode="w",
                format=tar_format,
            ) as archive:
                for member, payload in entries:
                    archive.addfile(
                        member,
                        io.BytesIO(payload) if payload is not None else None,
                    )


def canonical_gzip(data: bytes, compresslevel: int = 9) -> bytes:
    output = io.BytesIO()
    with gzip.GzipFile(
        filename="",
        mode="wb",
        fileobj=output,
        mtime=0,
        compresslevel=compresslevel,
    ) as compressed:
        compressed.write(data)
    return output.getvalue()


def update_tar_header_checksum(stream: bytearray, offset: int) -> None:
    header = bytearray(stream[offset:offset + tarfile.BLOCKSIZE])
    if len(header) != tarfile.BLOCKSIZE:
        raise AssertionError("test fixture has a truncated TAR header")
    header[148:156] = b" " * 8
    header[148:156] = f"{sum(header):06o}\0 ".encode("ascii")
    stream[offset:offset + tarfile.BLOCKSIZE] = header


def update_tar_header_size(stream: bytearray, offset: int, size: int) -> None:
    stream[offset + 124:offset + 136] = f"{size:011o}\0".encode("ascii")
    update_tar_header_checksum(stream, offset)


class SourceBundleVerifierTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = Path(
            self.enterContext(tempfile.TemporaryDirectory())
        )

    def test_git_lfs_pointer_is_not_corresponding_source(self) -> None:
        bundle = self.directory / "lfs-pointer.tar.gz"
        pointer = (
            b"version https://git-lfs.github.com/spec/v1\n"
            b"oid sha256:" + b"b" * 64 + b"\n"
            b"size 73400320\n"
        )
        write_bundle(
            bundle,
            canonical_file_entries({"root/vendor/archive.dat": pointer}),
        )
        with self.assertRaisesRegex(ValueError, "Git LFS pointer is forbidden"):
            verifier.audit_bundle(bundle)

    def test_streams_members_with_a_hard_count_bound(self) -> None:
        long_name = "root/" + "a" * 101
        valid = self.directory / "valid.tar.gz"
        write_bundle(
            valid,
            canonical_file_entries(
                {
                    "root/safe.txt": b"safe\n",
                    long_name: b"long path\n",
                }
            ),
        )
        with mock.patch.object(
            tarfile.TarFile,
            "getmembers",
            side_effect=AssertionError("verifier must stream"),
        ):
            self.assertEqual(2, verifier.audit_bundle(valid))

        overflow = self.directory / "overflow.tar.gz"
        write_bundle(
            overflow,
            [
                regular_member("root/one", b"1"),
                regular_member("root/two", b"2"),
                regular_member("root/three", b"3"),
            ],
        )
        with mock.patch.object(verifier, "MAX_MEMBERS", 2):
            with self.assertRaisesRegex(ValueError, "2-member limit"):
                verifier.audit_bundle(overflow)

    def test_enforces_builder_file_and_directory_limits_in_both_passes(
        self,
    ) -> None:
        import build_singbox_source_bundle as builder

        self.assertEqual(
            builder.MAX_ARCHIVE_FILES,
            verifier.MAX_ARCHIVE_FILES,
        )
        self.assertEqual(
            builder.MAX_ARCHIVE_DIRECTORIES,
            verifier.MAX_ARCHIVE_DIRECTORIES,
        )
        files = self.directory / "too-many-files.tar.gz"
        write_bundle(
            files,
            [
                regular_member("root/one", b"1"),
                regular_member("root/three", b"3"),
                regular_member("root/two", b"2"),
            ],
        )
        with mock.patch.object(verifier, "MAX_ARCHIVE_FILES", 2):
            with self.assertRaisesRegex(ValueError, "2-file limit"):
                verifier.audit_bundle(files)

        real_scan = verifier.scan_raw_tar_stream

        def scan_with_relaxed_file_limit(*args, **kwargs):
            with mock.patch.object(verifier, "MAX_ARCHIVE_FILES", 100):
                return real_scan(*args, **kwargs)

        with (
            mock.patch.object(
                verifier,
                "scan_raw_tar_stream",
                side_effect=scan_with_relaxed_file_limit,
            ),
            mock.patch.object(verifier, "MAX_ARCHIVE_FILES", 2),
        ):
            with self.assertRaisesRegex(ValueError, "2-file limit"):
                verifier.audit_bundle(files)

        directories = self.directory / "too-many-directories.tar.gz"
        write_bundle(
            directories,
            canonical_file_entries(
                {"root/a/b/c/payload.txt": b"source\n"}
            ),
        )
        with mock.patch.object(verifier, "MAX_ARCHIVE_DIRECTORIES", 2):
            with self.assertRaisesRegex(ValueError, "2-directory limit"):
                verifier.audit_bundle(directories)

        def scan_with_relaxed_directory_limit(*args, **kwargs):
            with mock.patch.object(verifier, "MAX_ARCHIVE_DIRECTORIES", 100):
                return real_scan(*args, **kwargs)

        with (
            mock.patch.object(
                verifier,
                "scan_raw_tar_stream",
                side_effect=scan_with_relaxed_directory_limit,
            ),
            mock.patch.object(verifier, "MAX_ARCHIVE_DIRECTORIES", 2),
        ):
            with self.assertRaisesRegex(ValueError, "2-directory limit"):
                verifier.audit_bundle(directories)

    def test_bounds_failures_before_attacker_labels_accumulate(self) -> None:
        bundle = self.directory / "many-invalid-members.tar.gz"
        write_bundle(
            bundle,
            [
                regular_member(f"root/invalid-{index}", b"x", mode=0o600)
                for index in range(10)
            ],
        )
        with mock.patch.object(verifier, "MAX_FAILURES", 5):
            with self.assertRaisesRegex(ValueError, "5-failure limit"):
                verifier.audit_bundle(bundle)

    def test_bounds_names_retained_by_the_path_map(self) -> None:
        bundle = self.directory / "retained-names.tar.gz"
        write_bundle(
            bundle,
            [
                regular_member("root/first-name", b"1"),
                regular_member("root/second-name", b"2"),
            ],
        )
        with mock.patch.object(verifier, "MAX_RETAINED_NAME_BYTES", 16):
            with self.assertRaisesRegex(ValueError, "retained-byte limit"):
                verifier.audit_bundle(bundle)

    def test_bounds_total_payload_before_semantic_validation(self) -> None:
        bundle = self.directory / "payload-total.tar.gz"
        write_bundle(
            bundle,
            [
                regular_member("root/one", b"1"),
                regular_member("root/two", b"2"),
            ],
        )
        with mock.patch.object(verifier, "MAX_EXPANDED_BYTES", 1):
            with self.assertRaisesRegex(ValueError, "expanded source bundle"):
                verifier.audit_bundle(bundle)

    def test_rejects_oversized_pax_before_tarfile_parses_it(self) -> None:
        valid = self.directory / "pax-base.tar.gz"
        write_bundle(valid, [regular_member("root/safe.txt", b"safe\n")])
        raw_tar = bytearray(gzip.decompress(valid.read_bytes()))
        raw_tar[156:157] = tarfile.XHDTYPE
        update_tar_header_size(raw_tar, 0, verifier.MAX_PAX_BYTES + 1)
        oversized_pax = self.directory / "oversized-pax.tar.gz"
        oversized_pax.write_bytes(canonical_gzip(raw_tar))
        with mock.patch.object(
            tarfile,
            "open",
            side_effect=AssertionError("raw pre-scan must reject PAX first"),
        ):
            with self.assertRaisesRegex(ValueError, "PAX metadata exceeds"):
                verifier.audit_bundle(oversized_pax)

    def test_rejects_symlink_and_fifo_bundle_inputs(self) -> None:
        valid = self.directory / "regular.tar.gz"
        write_bundle(valid, [regular_member("root/safe.txt", b"safe\n")])

        symlink = self.directory / "symlink.tar.gz"
        symlink.symlink_to(valid)
        with self.assertRaisesRegex(ValueError, "bundle cannot be opened"):
            verifier.audit_bundle(symlink)

        fifo = self.directory / "bundle.fifo"
        os.mkfifo(fifo)
        with self.assertRaisesRegex(ValueError, "bundle cannot be opened"):
            verifier.audit_bundle(fifo)

        raced = self.directory / "raced.tar.gz"
        backup = self.directory / "raced.backup"
        write_bundle(raced, [regular_member("root/safe.txt", b"safe\n")])
        original_open = os.open

        swapped = False

        def replace_with_fifo(
            path: os.PathLike[str],
            flags: int,
            *,
            dir_fd: int | None = None,
        ) -> int:
            nonlocal swapped
            if path == raced.name and dir_fd is not None and not swapped:
                swapped = True
                self.assertTrue(flags & os.O_NONBLOCK)
                raced.rename(backup)
                os.mkfifo(raced)
            if dir_fd is None:
                return original_open(path, flags)
            return original_open(path, flags, dir_fd=dir_fd)

        with mock.patch.object(
            verifier.os,
            "open",
            side_effect=replace_with_fifo,
        ):
            with self.assertRaisesRegex(ValueError, "bundle cannot be opened"):
                verifier.audit_bundle(raced)

        hardlink_source = self.directory / "hardlink-source.tar.gz"
        write_bundle(
            hardlink_source,
            [regular_member("root/safe.txt", b"safe\n")],
        )
        hardlink = self.directory / "hardlink.tar.gz"
        os.link(hardlink_source, hardlink)
        with self.assertRaisesRegex(ValueError, "bundle cannot be opened"):
            verifier.audit_bundle(hardlink)

        real_parent = self.directory / "real-parent"
        real_parent.mkdir()
        via_symlink = self.directory / "parent-symlink"
        via_symlink.symlink_to(real_parent.name, target_is_directory=True)
        write_bundle(
            real_parent / "nested.tar.gz",
            [regular_member("root/safe.txt", b"safe\n")],
        )
        with self.assertRaisesRegex(ValueError, "bundle cannot be opened"):
            verifier.audit_bundle(via_symlink / "nested.tar.gz")

    def test_rechecks_bundle_path_and_fingerprint_before_success(self) -> None:
        bundle = self.directory / "bundle.tar.gz"
        replacement = self.directory / "replacement.tar.gz"
        original_path = self.directory / "original.tar.gz"
        write_bundle(bundle, [regular_member("root/safe.txt", b"safe\n")])
        write_bundle(
            replacement,
            [
                regular_member(
                    "root/unsafe.txt",
                    (FORBIDDEN_DOTTED_ORG + "\n").encode(),
                )
            ],
        )
        real_inspect = verifier.inspect_gzip_stream

        def replace_path(source, expanded_sink=None):
            result = real_inspect(source, expanded_sink)
            bundle.rename(original_path)
            replacement.rename(bundle)
            return result

        with mock.patch.object(
            verifier,
            "inspect_gzip_stream",
            side_effect=replace_path,
        ):
            with self.assertRaisesRegex(
                ValueError, "bundle (?:path )?changed"
            ):
                verifier.audit_bundle(bundle)
        self.assertIn(
            FORBIDDEN_DOTTED_ORG.encode(),
            gzip.decompress(bundle.read_bytes()),
        )

        restored = self.directory / "restored.tar.gz"
        write_bundle(restored, [regular_member("root/safe.txt", b"safe\n")])
        original = restored.read_bytes()

        def mutate_and_restore(source, expanded_sink=None):
            result = real_inspect(source, expanded_sink)
            with restored.open("r+b", buffering=0) as mutable:
                first = mutable.read(1)
                mutable.seek(0)
                mutable.write(bytes((first[0] ^ 0xFF,)))
                os.fsync(mutable.fileno())
                mutable.seek(0)
                mutable.write(first)
                os.fsync(mutable.fileno())
            return result

        with mock.patch.object(
            verifier,
            "inspect_gzip_stream",
            side_effect=mutate_and_restore,
        ):
            with self.assertRaisesRegex(ValueError, "bundle changed"):
                verifier.audit_bundle(restored)
        self.assertEqual(original, restored.read_bytes())

    def test_rechecks_each_ancestor_identity_before_success(self) -> None:
        parent = self.directory / "parent"
        parent.mkdir()
        original_parent = self.directory / "parent-original"
        bundle = parent / "bundle.tar.gz"
        write_bundle(bundle, [regular_member("root/safe.txt", b"safe\n")])
        real_inspect = verifier.inspect_gzip_stream

        def replace_parent_with_symlink(source, expanded_sink=None):
            result = real_inspect(source, expanded_sink)
            parent.rename(original_parent)
            parent.symlink_to(
                original_parent.name,
                target_is_directory=True,
            )
            return result

        with mock.patch.object(
            verifier,
            "inspect_gzip_stream",
            side_effect=replace_parent_with_symlink,
        ):
            with self.assertRaisesRegex(ValueError, "bundle path changed"):
                verifier.audit_bundle(bundle)
        self.assertTrue(parent.is_symlink())
        self.assertTrue(bundle.samefile(original_parent / bundle.name))

    def test_rejects_client_source_tree_and_dotted_namespace_paths(self) -> None:
        for path in (
            f"root/{FORBIDDEN_CLIENT_TREE}/Empty.java",
            f"root/{FORBIDDEN_DOTTED_ORG}/Empty.java",
            f"root/{FORBIDDEN_DOTTED_COM}/Empty.java",
            f"root/{FORBIDDEN_SLASH_ORG}/Empty.java",
            f"root/{FORBIDDEN_SLASH_COM}/Empty.java",
        ):
            with self.subTest(path=path):
                bundle = self.directory / (
                    path.replace("/", "-") + ".tar.gz"
                )
                write_bundle(
                    bundle,
                    canonical_file_entries({path: b"package safe;\n"}),
                )
                with self.assertRaisesRegex(
                    ValueError, "forbidden archive namespace"
                ):
                    verifier.audit_bundle(bundle)

    def test_rejects_unsafe_policy_metadata_in_short_and_pax_names(self) -> None:
        private_tmp = "/" + "/".join(("private", "tmp"))
        short_cases = (
            (
                "backslash",
                "root/" + "org" + "\\telegram\\Client.java",
                "backslash",
            ),
            ("line-feed", "root/name\nnext.txt", "control character"),
            ("carriage-return", "root/name\rnext.txt", "control character"),
            ("delete", "root/name\x7fnext.txt", "control character"),
            ("trailing-dot", "root/source.", "trailing dot or space"),
            ("trailing-space", "root/source ", "trailing dot or space"),
            (
                "embedded-namespace",
                f"root/prefix-{FORBIDDEN_DOTTED_ORG}-suffix.txt",
                "forbidden archive namespace",
            ),
            (
                "embedded-local-path",
                f"root/build-{private_tmp}/source.txt",
                "absolute local host path",
            ),
        )
        for label, name, expected in short_cases:
            with self.subTest(representation="short", case=label):
                self.assertLessEqual(len(name.encode("utf-8")), 100)
                bundle = self.directory / f"short-{label}.tar.gz"
                write_bundle(bundle, [regular_member(name, b"source\n")])
                with self.assertRaisesRegex(ValueError, expected):
                    verifier.audit_bundle(bundle)

        prefix = "root/" + "a" * 101
        pax_cases = (
            ("backslash", prefix + "\\source.txt", "backslash"),
            (
                "line-feed",
                prefix + "\nsource.txt",
                "PAX metadata|control character",
            ),
            (
                "carriage-return",
                prefix + "\rsource.txt",
                "PAX path|control character",
            ),
            ("delete", prefix + "\x7fsource.txt", "control character"),
            ("trailing-dot", prefix + ".", "trailing dot or space"),
            ("trailing-space", prefix + " ", "trailing dot or space"),
            (
                "embedded-namespace",
                prefix + f"-{FORBIDDEN_DOTTED_COM}.txt",
                "forbidden archive namespace",
            ),
            (
                "embedded-local-path",
                prefix + f"-{private_tmp}/source.txt",
                "absolute local host path",
            ),
        )
        for label, name, expected in pax_cases:
            with self.subTest(representation="PAX", case=label):
                self.assertGreater(len(name.encode("utf-8")), 100)
                bundle = self.directory / f"pax-{label}.tar.gz"
                write_bundle(bundle, [regular_member(name, b"source\n")])
                with self.assertRaisesRegex(ValueError, expected):
                    verifier.audit_bundle(bundle)

        parsed_short = self.directory / "parsed-short-policy.tar.gz"
        write_bundle(
            parsed_short,
            [regular_member("root/unsafe\\name.txt", b"source\n")],
        )
        parsed_pax = self.directory / "parsed-pax-policy.tar.gz"
        write_bundle(
            parsed_pax,
            [regular_member(prefix + "\\unsafe.txt", b"source\n")],
        )
        real_scan = verifier.scan_raw_tar_stream

        def scan_without_raw_name_policy(*args, **kwargs):
            with mock.patch.object(
                verifier,
                "member_name_policy_failure",
                return_value=None,
            ):
                return real_scan(*args, **kwargs)

        with mock.patch.object(
            verifier,
            "scan_raw_tar_stream",
            side_effect=scan_without_raw_name_policy,
        ):
            for representation, bundle in (
                ("short", parsed_short),
                ("PAX", parsed_pax),
            ):
                with self.subTest(parsed_pass=representation):
                    with self.assertRaisesRegex(ValueError, "backslash"):
                        verifier.audit_bundle(bundle)

    def test_requires_exact_builder_topology_and_order(self) -> None:
        valid = self.directory / "valid-topology.tar.gz"
        write_bundle(
            valid,
            canonical_file_entries(
                {
                    "root/a/one.txt": b"one\n",
                    "root/z.txt": b"z\n",
                }
            ),
        )
        self.assertEqual(2, verifier.audit_bundle(valid))

        cases = (
            (
                "explicit-root",
                [
                    directory_member("root"),
                    regular_member("root/safe.txt", b"safe\n"),
                ],
                "explicit logical root",
            ),
            (
                "missing-parent",
                [regular_member("root/sub/safe.txt", b"safe\n")],
                "parent directory is missing",
            ),
            (
                "parent-after-child",
                [
                    regular_member("root/sub/safe.txt", b"safe\n"),
                    directory_member("root/sub"),
                ],
                "canonical builder order",
            ),
            (
                "unsorted",
                [
                    regular_member("root/z.txt", b"z\n"),
                    regular_member("root/a.txt", b"a\n"),
                ],
                "canonical builder order",
            ),
            (
                "empty-directory",
                [
                    directory_member("root/empty"),
                    regular_member("root/safe.txt", b"safe\n"),
                ],
                "empty archive directory",
            ),
        )
        for name, entries, error in cases:
            with self.subTest(name=name):
                bundle = self.directory / f"{name}.tar.gz"
                write_bundle(bundle, entries)
                with self.assertRaisesRegex(ValueError, error):
                    verifier.audit_bundle(bundle)

    def test_rejects_noncanonical_deflate_with_a_canonical_header(self) -> None:
        valid = self.directory / "canonical-deflate.tar.gz"
        write_bundle(valid, [regular_member("root/safe.txt", b"safe\n")])
        tar_payload = gzip.decompress(valid.read_bytes())
        alternate = bytearray(canonical_gzip(tar_payload, compresslevel=1))
        self.assertEqual(4, alternate[8])
        alternate[8] = verifier.CANONICAL_GZIP_HEADER[8]
        noncanonical = self.directory / "noncanonical-deflate.tar.gz"
        noncanonical.write_bytes(alternate)
        self.assertNotEqual(valid.read_bytes(), noncanonical.read_bytes())
        with self.assertRaisesRegex(ValueError, "noncanonical gzip payload"):
            verifier.audit_bundle(noncanonical)

    def test_streams_member_policy_across_chunk_boundaries(self) -> None:
        unicode_bundle = self.directory / "unicode-boundary.tar.gz"
        unicode_payload = (
            b"a" * (verifier.CONTENT_READ_BYTES - 1)
            + "😀\n".encode("utf-8")
        )
        write_bundle(
            unicode_bundle,
            [regular_member("root/unicode.txt", unicode_payload)],
        )

        forbidden_bundle = self.directory / "forbidden-boundary.tar.gz"
        forbidden_payload = (
            b"a" * (verifier.CONTENT_READ_BYTES - 4)
            + (FORBIDDEN_DOTTED_ORG + "\n").encode()
        )
        write_bundle(
            forbidden_bundle,
            [regular_member("root/forbidden.txt", forbidden_payload)],
        )

        local_path_bundle = self.directory / "path-boundary.tar.gz"
        local_path_payload = (
            b"a" * (verifier.CONTENT_READ_BYTES - 4)
            + b" /"
            + b"Users"
            + b"/Build Agent/work\n"
        )
        write_bundle(
            local_path_bundle,
            [regular_member("root/path.txt", local_path_payload)],
        )

        boundary_false_positive = self.directory / "path-prefix.tar.gz"
        host_prefix = b" /opt/" + b"homebrew"
        benign_path_payload = (
            b"a" * (verifier.CONTENT_READ_BYTES - len(host_prefix))
            + host_prefix
            + b"x/bin\n"
        )
        write_bundle(
            boundary_false_positive,
            [regular_member("root/benign-path.txt", benign_path_payload)],
        )

        lookbehind_false_positive = self.directory / "path-lookbehind.tar.gz"
        lookbehind_payload = (
            b"a"
            * (
                verifier.CONTENT_READ_BYTES
                - verifier.CONTENT_SCAN_OVERLAP_BYTES
                - 1
            )
            + b"/"
            + b"Users"
            + b"/not-local"
            + b"b" * 1024
        )
        self.assertFalse(verifier.contains_local_host_path(lookbehind_payload))
        write_bundle(
            lookbehind_false_positive,
            [regular_member("root/lookbehind.txt", lookbehind_payload)],
        )

        real_read = tarfile.ExFileObject.read

        def bounded_read(stream, size=-1):
            self.assertGreaterEqual(size, 0)
            self.assertLessEqual(size, verifier.CONTENT_READ_BYTES)
            return real_read(stream, size)

        with mock.patch.object(
            tarfile.ExFileObject,
            "read",
            new=bounded_read,
        ):
            self.assertEqual(1, verifier.audit_bundle(unicode_bundle))
            with self.assertRaisesRegex(ValueError, "forbidden client reference"):
                verifier.audit_bundle(forbidden_bundle)
            with self.assertRaisesRegex(ValueError, "absolute local host path"):
                verifier.audit_bundle(local_path_bundle)
            self.assertEqual(
                1, verifier.audit_bundle(boundary_false_positive)
            )
            self.assertEqual(
                1, verifier.audit_bundle(lookbehind_false_positive)
            )

    def test_rejects_noncanonical_member_metadata_and_pax(self) -> None:
        cases: list[
            tuple[
                str,
                list[tuple[tarfile.TarInfo, bytes | None]],
                str,
                int,
            ]
        ] = [
            (
                "directory-mode",
                [directory_member("root", mode=0o700), regular_member("root/a", b"a")],
                "directory metadata",
                tarfile.PAX_FORMAT,
            ),
            (
                "file-mode",
                [regular_member("root/a", b"a", mode=0o600)],
                "file metadata",
                tarfile.PAX_FORMAT,
            ),
            (
                "special-mode",
                [regular_member("root/a", b"a", mode=0o4644)],
                "special bits",
                tarfile.PAX_FORMAT,
            ),
            (
                "ownership",
                [regular_member("root/a", b"a", uid=1, gid=2)],
                "archive ownership",
                tarfile.PAX_FORMAT,
            ),
            (
                "owner-names",
                [regular_member("root/a", b"a", uname="builder", gname="staff")],
                "owner names",
                tarfile.PAX_FORMAT,
            ),
            (
                "mtime",
                [regular_member("root/a", b"a", mtime=1)],
                "archive mtime",
                tarfile.PAX_FORMAT,
            ),
            (
                "link-metadata",
                [regular_member("root/a", b"a", linkname="unexpected")],
                "link metadata",
                tarfile.PAX_FORMAT,
            ),
            (
                "alternate-regular-type",
                [regular_member("root/a", b"a", member_type=tarfile.AREGTYPE)],
                "file metadata",
                tarfile.PAX_FORMAT,
            ),
            (
                "arbitrary-pax",
                [
                    regular_member(
                        "root/a",
                        b"a",
                        pax_headers={"comment": "local build"},
                    )
                ],
                "PAX metadata",
                tarfile.PAX_FORMAT,
            ),
            (
                "unnecessary-pax-path",
                [
                    regular_member(
                        "root/a",
                        b"a",
                        pax_headers={"path": "root/a"},
                    )
                ],
                "PAX metadata",
                tarfile.PAX_FORMAT,
            ),
            (
                "missing-required-pax-path",
                [regular_member("root/" + "b" * 101, b"a")],
                "PAX metadata",
                tarfile.GNU_FORMAT,
            ),
        ]
        for name, entries, expected, tar_format in cases:
            with self.subTest(name=name):
                bundle = self.directory / f"{name}.tar.gz"
                write_bundle(bundle, entries, tar_format=tar_format)
                with self.assertRaisesRegex(ValueError, expected):
                    verifier.audit_bundle(bundle)

    def test_rejects_gzip_trailers_headers_and_nonzero_tar_padding(self) -> None:
        valid = self.directory / "canonical.tar.gz"
        write_bundle(valid, [regular_member("root/safe.txt", b"safe\n")])
        self.assertEqual(1, verifier.audit_bundle(valid))
        canonical = valid.read_bytes()

        filename = self.directory / "filename.tar.gz"
        write_bundle(
            filename,
            [regular_member("root/safe.txt", b"safe\n")],
            gzip_filename="local-name.tar",
        )
        with self.assertRaisesRegex(ValueError, "noncanonical gzip header"):
            verifier.audit_bundle(filename)

        mtime = self.directory / "mtime.tar.gz"
        write_bundle(
            mtime,
            [regular_member("root/safe.txt", b"safe\n")],
            gzip_mtime=1,
        )
        with self.assertRaisesRegex(ValueError, "noncanonical gzip header"):
            verifier.audit_bundle(mtime)

        comment = bytearray(canonical)
        comment[3] |= 0x10
        comment[10:10] = b"local comment\0"
        comment_path = self.directory / "comment.tar.gz"
        comment_path.write_bytes(comment)
        with self.assertRaisesRegex(ValueError, "noncanonical gzip header"):
            verifier.audit_bundle(comment_path)

        raw_trailer = self.directory / "raw-trailer.tar.gz"
        raw_trailer.write_bytes(
            canonical + ("org" + ".telegram").encode("ascii")
        )
        with self.assertRaisesRegex(ValueError, "data follows the gzip member"):
            verifier.audit_bundle(raw_trailer)

        concatenated = self.directory / "concatenated.tar.gz"
        concatenated.write_bytes(canonical + canonical_gzip(b"second member"))
        with self.assertRaisesRegex(ValueError, "data follows the gzip member"):
            verifier.audit_bundle(concatenated)

        tar_payload = bytearray(gzip.decompress(canonical))
        self.assertEqual(0, tar_payload[-1])
        tar_payload[-1] = 1
        nonzero_padding = self.directory / "nonzero-padding.tar.gz"
        nonzero_padding.write_bytes(canonical_gzip(tar_payload))
        with self.assertRaisesRegex(ValueError, "nonzero data follows"):
            verifier.audit_bundle(nonzero_padding)

        extra_zero_record = self.directory / "extra-zero-record.tar.gz"
        extra_zero_record.write_bytes(
            canonical_gzip(gzip.decompress(canonical) + b"\0" * tarfile.RECORDSIZE)
        )
        with self.assertRaisesRegex(ValueError, "tar stream length"):
            verifier.audit_bundle(extra_zero_record)

        oversized_zero_tail = self.directory / "oversized-zero-tail.tar.gz"
        oversized_zero_tail.write_bytes(
            canonical_gzip(gzip.decompress(canonical) + b"\0" * 1024 * 1024)
        )
        original_pread = os.pread

        def bounded_pread(descriptor: int, size: int, offset: int) -> bytes:
            self.assertLessEqual(size, verifier.GZIP_OUTPUT_BYTES)
            return original_pread(descriptor, size, offset)

        with mock.patch.object(verifier.os, "pread", side_effect=bounded_pread):
            with self.assertRaisesRegex(ValueError, "tar stream length"):
                verifier.audit_bundle(oversized_zero_tail)

    def test_rejects_hidden_tar_header_and_member_padding_bytes(self) -> None:
        member_name = "root/safe.txt"
        payload = b"safe\n"
        valid = self.directory / "raw-canonical.tar.gz"
        write_bundle(valid, [regular_member(member_name, payload)])
        canonical_tar = bytearray(gzip.decompress(valid.read_bytes()))

        hidden_name_tail = bytearray(canonical_tar)
        hidden_name_tail[len(member_name) + 1] = ord("X")
        update_tar_header_checksum(hidden_name_tail, 0)
        hidden_name_path = self.directory / "hidden-name-tail.tar.gz"
        hidden_name_path.write_bytes(canonical_gzip(hidden_name_tail))
        with self.assertRaisesRegex(ValueError, "raw archive header"):
            verifier.audit_bundle(hidden_name_path)

        hidden_reserved = bytearray(canonical_tar)
        hidden_reserved[500] = ord("X")
        update_tar_header_checksum(hidden_reserved, 0)
        hidden_reserved_path = self.directory / "hidden-reserved.tar.gz"
        hidden_reserved_path.write_bytes(canonical_gzip(hidden_reserved))
        with self.assertRaisesRegex(ValueError, "raw archive header"):
            verifier.audit_bundle(hidden_reserved_path)

        hidden_padding = bytearray(canonical_tar)
        hidden_padding[tarfile.BLOCKSIZE + len(payload)] = ord("X")
        hidden_padding_path = self.directory / "hidden-member-padding.tar.gz"
        hidden_padding_path.write_bytes(canonical_gzip(hidden_padding))
        with self.assertRaisesRegex(ValueError, "member padding"):
            verifier.audit_bundle(hidden_padding_path)

    def test_enforces_text_policy_with_two_exact_binary_exceptions(self) -> None:
        children = (
            "root/singbox/vendor/golang.org/x/net/publicsuffix/data/children"
        )
        nodes = "root/singbox/vendor/golang.org/x/net/publicsuffix/data/nodes"
        unreviewed = self.directory / "unreviewed-binary.tar.gz"
        write_bundle(
            unreviewed,
            canonical_file_entries(
                {
                    children: b"\0\xffchildren",
                    nodes: b"\0\xfenodes",
                }
            ),
        )
        with self.assertRaisesRegex(ValueError, "reviewed size and digest"):
            verifier.audit_bundle(unreviewed)

        self.assertEqual(
            verifier.AllowedBinary(
                3484,
                "bda2852d2be3d2187bcb45acedf9973af4ceeead7cec45dfd22f17424f746b9d",
            ),
            verifier.ALLOWED_BINARY_FILES[
                PurePosixPath(
                    "singbox/vendor/golang.org/x/net/publicsuffix/data/children"
                )
            ],
        )
        self.assertEqual(
            verifier.AllowedBinary(
                50500,
                "4291647663383213ccefb726abacf571c5d76904ee939e0e3feb41898bb43102",
            ),
            verifier.ALLOWED_BINARY_FILES[
                PurePosixPath(
                    "singbox/vendor/golang.org/x/net/publicsuffix/data/nodes"
                )
            ],
        )

        magic_cases = (
            ("elf", b"\x7fELFpayload"),
            ("pe", b"MZpayload"),
            ("macho-thin", b"\xcf\xfa\xed\xfepayload"),
            ("macho-fat", b"\xca\xfe\xba\xbepayload"),
            ("ar", b"!<arch>\npayload"),
            ("wasm", b"\0asmpayload"),
            ("zip", b"PK\x03\x04payload"),
            ("gzip", b"\x1f\x8bpayload"),
            ("bzip2", b"BZhpayload"),
            ("xz", b"\xfd7zXZ\0payload"),
            ("zstd", b"\x28\xb5\x2f\xfdpayload"),
            ("zstd-skippable", b"\x5f\x2a\x4d\x18payload"),
            ("7z", b"7z\xbc\xaf\x27\x1cpayload"),
            ("rar", b"Rar!\x1a\x07\x01\0payload"),
            ("dex", b"dex\n035\0payload"),
            (
                "pdf",
                b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\n%%EOF\n",
            ),
            (
                "intel-hex",
                b":10010000214601360121470136007EFE09D2190140\n"
                b":00000001FF\n",
            ),
            ("tar", b"name" + b"\0" * 253 + b"ustar\0"),
        )
        for name, payload in magic_cases:
            with self.subTest(magic=name):
                bundle = self.directory / f"{name}.tar.gz"
                write_bundle(bundle, [regular_member("root/disguised.txt", payload)])
                with self.assertRaisesRegex(ValueError, "magic is forbidden"):
                    verifier.audit_bundle(bundle)

        nul = self.directory / "nul.tar.gz"
        write_bundle(nul, [regular_member("root/source.txt", b"text\0tail")])
        with self.assertRaisesRegex(ValueError, "NUL byte"):
            verifier.audit_bundle(nul)

        non_utf8 = self.directory / "non-utf8.tar.gz"
        write_bundle(non_utf8, [regular_member("root/source.txt", b"\xfftext")])
        with self.assertRaisesRegex(ValueError, "non-UTF-8"):
            verifier.audit_bundle(non_utf8)

        wrong_exception = self.directory / "wrong-exception.tar.gz"
        write_bundle(
            wrong_exception,
            canonical_file_entries(
                {children + ".backup": b"\0\xffbinary"}
            ),
        )
        with self.assertRaisesRegex(ValueError, "NUL byte|non-UTF-8"):
            verifier.audit_bundle(wrong_exception)

        for index, (name, payload) in enumerate(magic_cases):
            with self.subTest(allowed_magic=name):
                allowed_magic = self.directory / f"allowed-{name}.tar.gz"
                allowed_path = children if index % 2 == 0 else nodes
                write_bundle(
                    allowed_magic,
                    canonical_file_entries({allowed_path: payload}),
                )
                with self.assertRaisesRegex(ValueError, "magic is forbidden"):
                    verifier.audit_bundle(allowed_magic)

        syso = self.directory / "syso.tar.gz"
        write_bundle(syso, [regular_member("root/object.syso", b"plain text")])
        with self.assertRaisesRegex(ValueError, "forbidden packaged artifact"):
            verifier.audit_bundle(syso)

        packaged_text_cases = (
            ("pdf", "root/manual.pdf", b"plain text placeholder\n"),
            (
                "intel-hex",
                "root/firmware.hex",
                b":10010000214601360121470136007EFE09D2190140\n"
                b":00000001FF\n",
            ),
            ("object", "root/module.o", b"plain text placeholder\n"),
            ("archive", "root/sources.zip", b"plain text placeholder\n"),
            ("disk-image", "root/firmware.img", b"plain text placeholder\n"),
        )
        for label, name, payload in packaged_text_cases:
            with self.subTest(packaged_text=label):
                bundle = self.directory / f"packaged-{label}.tar.gz"
                write_bundle(bundle, [regular_member(name, payload)])
                with self.assertRaisesRegex(
                    ValueError, "forbidden packaged artifact"
                ):
                    verifier.audit_bundle(bundle)

        oversized = self.directory / "oversized-binary.tar.gz"
        write_bundle(
            oversized,
            canonical_file_entries({nodes: b"\0\xffabc"}),
        )
        with mock.patch.object(verifier, "MAX_ALLOWED_BINARY_BYTES", 4):
            with self.assertRaisesRegex(ValueError, "allowed binary source exceeds"):
                verifier.audit_bundle(oversized)

    def test_allowed_binary_exception_requires_exact_streamed_bytes(self) -> None:
        relative = PurePosixPath(
            "singbox/vendor/golang.org/x/net/publicsuffix/data/children"
        )
        archive_name = "root/" + relative.as_posix()
        reviewed = (
            b"\0\xffreviewed"
            + b"a" * (verifier.CONTENT_READ_BYTES + 17)
        )
        expected = verifier.AllowedBinary(
            len(reviewed), hashlib.sha256(reviewed).hexdigest()
        )
        valid = self.directory / "reviewed-binary.tar.gz"
        write_bundle(
            valid,
            canonical_file_entries({archive_name: reviewed}),
        )
        mutated = self.directory / "mutated-binary.tar.gz"
        mutated_payload = reviewed[:-1] + bytes((reviewed[-1] ^ 1,))
        write_bundle(
            mutated,
            canonical_file_entries({archive_name: mutated_payload}),
        )
        wrong_size = self.directory / "wrong-size-binary.tar.gz"
        write_bundle(
            wrong_size,
            canonical_file_entries({archive_name: reviewed + b"x"}),
        )

        with mock.patch.dict(
            verifier.ALLOWED_BINARY_FILES,
            {relative: expected},
            clear=True,
        ):
            self.assertEqual(1, verifier.audit_bundle(valid))
            with self.assertRaisesRegex(ValueError, "reviewed size and digest"):
                verifier.audit_bundle(mutated)
            with self.assertRaisesRegex(ValueError, "reviewed size and digest"):
                verifier.audit_bundle(wrong_size)

    def test_detects_structured_pdf_and_intel_hex_with_bounded_leading_data(
        self,
    ) -> None:
        pdf_body = b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\n%%EOF\n"
        pdf_cases = {
            "pdf-whitespace": b"\n \t" + pdf_body,
            "pdf-bom-junk": b"\xef\xbb\xbfreader-junk\n" + pdf_body,
            "pdf-window-edge": b"x" * 1023 + pdf_body,
            "pdf-trailing-reader-junk": pdf_body + b"ignored trailer\n",
            "pdf-long-indentation": (
                b"%PDF-1.7\n"
                + b" " * (verifier.CONTENT_READ_BYTES + 65)
                + b"1 0 obj\n<<>>\nendobj\n%%EOF\n"
            ),
            "pdf-form-feed-whitespace": (
                b"%PDF-1.7\f"
                + b" " * 4096
                + b"1\f0\fobj\f<<>>\fendobj\f%%EOF\f"
            ),
            "pdf-numeric-comment-overlap": (
                b"%PDF-1.7\n% generated by reader 99 1\n"
                b"1 0 obj\n<<>>\nendobj\n%%EOF\n"
            ),
            "pdf-multi-number-prefix": (
                b"%PDF-1.7\n1 2 3 4 5 0 obj\n"
                b"<<>>\nendobj\n%%EOF\n"
            ),
            "pdf-comments-as-whitespace": (
                b"%PDF-1.7\n1% object comment\r"
                b"0 % generation comment\nobj\n"
                b"<<>>\nendobj\n%%EOF\n"
            ),
        }
        intel_hex = (
            b"\n; generated image\r\n# build metadata\r\n"
            b":10010000214601360121470136007EFE09D2190140\r\n"
            b":00000001FF\r\n"
        )
        intel_record = b":10010000214601360121470136007EFE09D2190140\n"
        intel_boundary = (
            b"\n" * (verifier.CONTENT_READ_BYTES - len(intel_record) // 2)
            + intel_record
            + b":00000001FF\n"
        )
        intel_cr_boundary = (
            b"\n" * (verifier.CONTENT_READ_BYTES - len(intel_record) - 1)
            + intel_record
            + b"\r:00000001FF\r"
        )
        for label, payload in {
            **pdf_cases,
            "intel-hex-comments": intel_hex,
            "intel-hex-chunk-boundary": intel_boundary,
            "intel-hex-cr-only": intel_hex.replace(b"\r\n", b"\r"),
            "intel-hex-cr-chunk-boundary": intel_cr_boundary,
            "intel-hex-byte-zero-bom": verifier.UTF8_BOM + intel_hex,
        }.items():
            with self.subTest(rejected=label):
                bundle = self.directory / f"{label}.tar.gz"
                write_bundle(
                    bundle,
                    [regular_member("root/disguised.txt", payload)],
                )
                with self.assertRaisesRegex(ValueError, "magic is forbidden"):
                    verifier.audit_bundle(bundle)

        allowed_cases = {
            "pdf-after-window": b"x" * 1024 + pdf_body,
            "pdf-source-literal": (
                b'const header = "%PDF-1.7";\n'
                b'const object = "1 0 obj";\n'
                b'const eof = "%%EOF";\n'
            ),
            "pdf-no-object": b"%PDF-1.7\nplain source text\n%%EOF\n",
            "intel-after-source": (
                b"package main\n"
                b":10010000214601360121470136007EFE09D2190140\n"
                b":00000001FF\n"
            ),
            "intel-no-eof": (
                b":10010000214601360121470136007EFE09D2190140\n"
                b":020000040000FA\n"
            ),
            "intel-double-bom": verifier.UTF8_BOM * 2 + intel_hex,
            "intel-nonzero-bom": b"\n" + verifier.UTF8_BOM + intel_hex,
        }
        for label, payload in allowed_cases.items():
            with self.subTest(allowed=label):
                bundle = self.directory / f"{label}.tar.gz"
                write_bundle(
                    bundle,
                    [regular_member("root/source.txt", payload)],
                )
                self.assertEqual(1, verifier.audit_bundle(bundle))

        split_bom = verifier.IntelHexScanner()
        split_bom.feed(verifier.UTF8_BOM[:1])
        self.assertLessEqual(len(split_bom.preamble), len(verifier.UTF8_BOM))
        split_bom.feed(verifier.UTF8_BOM[1:2])
        self.assertLessEqual(len(split_bom.preamble), len(verifier.UTF8_BOM))
        split_bom.feed(
            verifier.UTF8_BOM[2:]
            + b":10010000214601360121470136007EFE09D2190140\n"
        )
        split_bom.feed(b":00000001FF\n")
        self.assertTrue(split_bom.finish())

        for payload in (
            verifier.UTF8_BOM * 2 + intel_hex,
            b"\n" + verifier.UTF8_BOM + intel_hex,
        ):
            with self.subTest(noncanonical_bom=payload[:8]):
                scanner = verifier.IntelHexScanner()
                scanner.feed(payload)
                self.assertFalse(scanner.finish())


if __name__ == "__main__":
    unittest.main()
