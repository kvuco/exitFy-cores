from __future__ import annotations

import contextlib
import gzip
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import unittest
from pathlib import Path, PurePosixPath
from unittest import mock

import audit_public_tree
import audit_singbox_source_bundle
import build_singbox_source_bundle


FORBIDDEN_CLIENT_SAMPLE = "org" + ".telegram"
GIT_LFS_POINTER = (
    b"version https://git-lfs.github.com/spec/v1\n"
    b"oid sha256:" + b"a" * 64 + b"\n"
    b"size 73400320\n"
)


def git(root: Path, *arguments: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(root), *arguments], text=True
    ).strip()


def initialize_repository(
    test: unittest.TestCase,
    directory: Path | None = None,
) -> Path:
    if directory is None:
        directory = Path(test.enterContext(tempfile.TemporaryDirectory()))
    else:
        directory.mkdir(parents=True)
    subprocess.run(["git", "init", "-q", str(directory)], check=True)
    subprocess.run(
        ["git", "-C", str(directory), "config", "user.name", "Audit Test"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(directory), "config", "user.email", "audit@example.invalid"],
        check=True,
    )
    (directory / "README.md").write_text("clean\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(directory), "add", "README.md"], check=True)
    subprocess.run(
        ["git", "-C", str(directory), "commit", "-q", "-m", "initial"],
        check=True,
    )
    return directory


def descriptor_count() -> int | None:
    for candidate in (Path("/proc/self/fd"), Path("/dev/fd")):
        if candidate.is_dir():
            return len(tuple(candidate.iterdir()))
    return None


def git_index_record(
    path: bytes,
    *,
    tag: bytes = b"H",
    mode: bytes = b"100644",
    object_id: bytes = b"a" * 40,
    stage: bytes = b"0",
    flags: bytes = b"0",
) -> bytes:
    return (
        tag
        + b" "
        + mode
        + b" "
        + object_id
        + b" "
        + stage
        + b"\t"
        + path
        + b"\0"
        + b"  ctime: 0:0\n"
        + b"  mtime: 0:0\n"
        + b"  dev: 0\tino: 0\n"
        + b"  uid: 0\tgid: 0\n"
        + b"  size: 0\tflags: "
        + flags
        + b"\n"
    )


class AuditBoundaryTest(unittest.TestCase):
    def test_frozen_builder_uses_explicit_repo_without_executing_worktree_python(self) -> None:
        root = initialize_repository(self)
        scripts = root / "scripts"
        scripts.mkdir()
        module = root / "singbox"
        module.mkdir()
        (module / "go.mod").write_text("module old.invalid\n", encoding="utf-8")
        (module / "go.sum").write_text("old\n", encoding="utf-8")
        marker = Path(self.enterContext(tempfile.TemporaryDirectory())) / "executed"
        (scripts / "audit_public_tree.py").write_text(
            "from pathlib import Path\n"
            f"Path({str(marker)!r}).write_text('executed')\n",
            encoding="utf-8",
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(root),
                "add",
                "scripts/audit_public_tree.py",
                "singbox/go.mod",
                "singbox/go.sum",
            ],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(root), "commit", "-q", "-m", "script"],
            check=True,
        )
        (module / "go.mod").write_text("module pinned.invalid\n", encoding="utf-8")
        (module / "go.sum").write_text("pinned\n", encoding="utf-8")
        head = git(root, "rev-parse", "HEAD")
        mod_digest = hashlib.sha256((module / "go.mod").read_bytes()).hexdigest()
        sum_digest = hashlib.sha256((module / "go.sum").read_bytes()).hexdigest()
        output = Path(self.enterContext(tempfile.TemporaryDirectory())) / "source.tar.gz"
        with (
            mock.patch.object(build_singbox_source_bundle, "ROOT", root),
            mock.patch.object(
                sys,
                "argv",
                [
                    "build_singbox_source_bundle.py",
                    "--repo-root",
                    str(root),
                    "--expected-head",
                    head,
                    "--expected-pin-sha256",
                    f"singbox/go.mod={mod_digest}",
                    "--expected-pin-sha256",
                    f"singbox/go.sum={sum_digest}",
                    "--upstream-version",
                    "v1.2.3",
                    "--output",
                    str(output),
                ],
            ),
            mock.patch.object(
                build_singbox_source_bundle,
                "build_minimal_vendor",
                return_value={},
            ),
            mock.patch.object(
                build_singbox_source_bundle, "validate_archive_manifest"
            ),
            mock.patch.object(
                build_singbox_source_bundle, "write_source_archive"
            ) as write_archive,
        ):
            build_singbox_source_bundle.main()
        self.assertFalse(marker.exists())
        write_archive.assert_called_once()

    def test_frozen_builder_requires_exact_head_index_and_pin_digests(self) -> None:
        root = initialize_repository(self)
        target_root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        clean_target = target_root / "clean"
        clean_target.mkdir()
        head = git(root, "rev-parse", "HEAD")
        with mock.patch.object(build_singbox_source_bundle, "ROOT", root):
            build_singbox_source_bundle.copy_public_tree(
                clean_target, expected_head=head
            )

        (root / "staged.txt").write_text("staged\n", encoding="utf-8")
        subprocess.run(
            ["git", "-C", str(root), "add", "staged.txt"], check=True
        )
        staged_target = target_root / "staged"
        staged_target.mkdir()
        with (
            mock.patch.object(build_singbox_source_bundle, "ROOT", root),
            self.assertRaisesRegex(ValueError, "index differs"),
        ):
            build_singbox_source_bundle.copy_public_tree(
                staged_target, expected_head=head
            )
        self.assertEqual([], list(staged_target.iterdir()))

        with self.assertRaisesRegex(ValueError, "incomplete"):
            build_singbox_source_bundle.parse_expected_pin_digests(
                ["singbox/go.mod=" + "a" * 64]
            )
        with self.assertRaisesRegex(ValueError, "invalid"):
            build_singbox_source_bundle.parse_expected_pin_digests(
                [
                    "singbox/go.mod=" + "a" * 64,
                    "singbox/go.sum=" + "g" * 64,
                ]
            )

    def test_source_bundle_uses_exact_tracked_index_files(self) -> None:
        root = initialize_repository(self)
        similarly_named = root / "legacy-workflow.yml.backup"
        tracked = root / "tracked.txt"
        similarly_named.write_text("must remain\n", encoding="utf-8")
        tracked.write_text("tracked\n", encoding="utf-8")
        subprocess.run(
            [
                "git", "-C", str(root), "add", similarly_named.name,
                tracked.name,
            ],
            check=True,
        )
        untracked = root / "nested" / "untracked.txt"
        untracked.parent.mkdir()
        untracked.write_text("untracked\n", encoding="utf-8")

        output_root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        first = output_root / "first"
        second = output_root / "second"
        first.mkdir()
        second.mkdir()
        with mock.patch.object(build_singbox_source_bundle, "ROOT", root):
            relative = [
                path.as_posix()
                for path in build_singbox_source_bundle.public_files()
            ]
            build_singbox_source_bundle.copy_public_tree(first)
            build_singbox_source_bundle.copy_public_tree(second)

        self.assertIn(similarly_named.name, relative)
        self.assertIn(tracked.name, relative)
        self.assertNotIn("nested/untracked.txt", relative)
        self.assertEqual(relative, sorted(relative))

        def snapshot_tree(directory: Path) -> list[tuple[str, bytes, int]]:
            return [
                (
                    path.relative_to(directory).as_posix(),
                    path.read_bytes(),
                    path.stat().st_mode & 0o777,
                )
                for path in sorted(
                    item for item in directory.rglob("*") if item.is_file()
                )
            ]

        self.assertEqual(snapshot_tree(first), snapshot_tree(second))

    def test_source_bundle_rejects_split_git_index(self) -> None:
        root = initialize_repository(self)
        (root / "second.txt").write_text("tracked\n", encoding="utf-8")
        subprocess.run(
            ["git", "-C", str(root), "add", "second.txt"], check=True
        )
        subprocess.run(
            ["git", "-C", str(root), "update-index", "--split-index"],
            check=True,
        )
        target = Path(self.enterContext(tempfile.TemporaryDirectory()))

        with mock.patch.object(build_singbox_source_bundle, "ROOT", root):
            with self.assertRaisesRegex(ValueError, "split Git index"):
                build_singbox_source_bundle.copy_public_tree(target)

        self.assertEqual([], list(target.iterdir()))

    def test_source_bundle_rejects_hidden_index_states(self) -> None:
        for state in ("assume-unchanged", "skip-worktree", "intent-to-add"):
            with self.subTest(state=state):
                root = initialize_repository(self)
                if state == "intent-to-add":
                    (root / "intent.txt").write_text("intent\n", encoding="utf-8")
                    subprocess.run(
                        ["git", "-C", str(root), "add", "-N", "intent.txt"],
                        check=True,
                    )
                else:
                    subprocess.run(
                        [
                            "git",
                            "-C",
                            str(root),
                            "update-index",
                            f"--{state}",
                            "README.md",
                        ],
                        check=True,
                    )
                target = Path(self.enterContext(tempfile.TemporaryDirectory()))
                with (
                    mock.patch.object(build_singbox_source_bundle, "ROOT", root),
                    self.assertRaisesRegex(
                        ValueError, "non-default entry flags"
                    ),
                ):
                    build_singbox_source_bundle.copy_public_tree(target)
                self.assertEqual([], list(target.iterdir()))

    def test_source_bundle_verifies_worktree_bytes_and_mode_against_index(self) -> None:
        root = initialize_repository(self)
        target_root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        (target_root / "content").mkdir()
        (root / "README.md").write_text("hidden worktree bytes\n", encoding="utf-8")
        with (
            mock.patch.object(build_singbox_source_bundle, "ROOT", root),
            self.assertRaisesRegex(ValueError, "content differs from Git index"),
        ):
            build_singbox_source_bundle.copy_public_tree(target_root / "content")

        second = initialize_repository(self)
        (target_root / "mode").mkdir()
        (second / "README.md").chmod(0o755)
        with (
            mock.patch.object(build_singbox_source_bundle, "ROOT", second),
            self.assertRaisesRegex(ValueError, "mode differs from Git index"),
        ):
            build_singbox_source_bundle.copy_public_tree(target_root / "mode")

    def test_source_bundle_allows_only_exact_validated_worktree_pins(self) -> None:
        root = initialize_repository(self)
        module = root / "singbox"
        module.mkdir()
        (module / "go.mod").write_text("old mod\n", encoding="utf-8")
        (module / "go.sum").write_text("old sum\n", encoding="utf-8")
        subprocess.run(
            ["git", "-C", str(root), "add", "singbox/go.mod", "singbox/go.sum"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(root), "commit", "-q", "-m", "pins"],
            check=True,
        )
        (module / "go.mod").write_text("validated mod\n", encoding="utf-8")
        (module / "go.sum").write_text("validated sum\n", encoding="utf-8")
        target = Path(self.enterContext(tempfile.TemporaryDirectory()))
        with mock.patch.object(build_singbox_source_bundle, "ROOT", root):
            build_singbox_source_bundle.copy_public_tree(target)
        self.assertEqual("validated mod\n", (target / "singbox/go.mod").read_text())
        self.assertEqual("validated sum\n", (target / "singbox/go.sum").read_text())

    def test_source_bundle_public_file_list_fails_closed(self) -> None:
        root = initialize_repository(self)
        cases = (
            (git_index_record(b"../outside.txt"), "unsafe public file path"),
            (git_index_record(b"missing.txt"), "changed or is unsafe"),
            (b"not-terminated", "malformed index metadata"),
        )
        for listed, message in cases:
            with self.subTest(message=message):
                with (
                    mock.patch.object(build_singbox_source_bundle, "ROOT", root),
                    mock.patch.object(
                        build_singbox_source_bundle,
                        "reject_split_index",
                    ),
                    mock.patch.object(
                        build_singbox_source_bundle,
                        "pinned_git_command_output",
                        return_value=listed,
                    ),
                ):
                    with self.assertRaisesRegex(ValueError, message):
                        build_singbox_source_bundle.public_files()

    def test_bounded_command_rejects_output_and_kills_timed_out_group(self) -> None:
        with self.assertRaisesRegex(ValueError, "output exceeds"):
            build_singbox_source_bundle.bounded_command_output(
                [sys.executable, "-c", "import os; os.write(1, b'x' * 4096)"],
                max_output_bytes=32,
                timeout_seconds=2,
            )

        started_at = time.monotonic()
        self.assertEqual(
            b"",
            build_singbox_source_bundle.bounded_command_output(
                [
                    sys.executable,
                    "-c",
                    (
                        "import subprocess,sys; "
                        "subprocess.Popen([sys.executable,'-c',"
                        "'import time; time.sleep(30)'])"
                    ),
                ],
                max_output_bytes=32,
                timeout_seconds=2,
            ),
        )
        self.assertLess(time.monotonic() - started_at, 1.5)

        real_popen = subprocess.Popen
        started: list[subprocess.Popen[bytes]] = []

        def capture_process(*arguments, **keywords):
            process = real_popen(*arguments, **keywords)
            started.append(process)
            return process

        with (
            mock.patch.object(
                build_singbox_source_bundle.subprocess,
                "Popen",
                side_effect=capture_process,
            ),
            self.assertRaisesRegex(ValueError, "timed out"),
        ):
            build_singbox_source_bundle.bounded_command_output(
                [
                    sys.executable,
                    "-c",
                    (
                        "import subprocess,sys,time; "
                        "subprocess.Popen([sys.executable,'-c',"
                        "'import time; time.sleep(30)']); time.sleep(30)"
                    ),
                ],
                max_output_bytes=32,
                timeout_seconds=0.2,
            )

        self.assertEqual(1, len(started))
        group = started[0].pid
        deadline = time.monotonic() + 2
        while True:
            try:
                os.killpg(group, 0)
            except ProcessLookupError:
                break
            if time.monotonic() >= deadline:
                self.fail("timed-out subprocess group remained alive")
            time.sleep(0.02)

    def test_builder_disables_repo_executables_and_relative_commands(self) -> None:
        with self.assertRaisesRegex(ValueError, "absolute executable"):
            build_singbox_source_bundle.bounded_command_output(
                ["python3", "-c", "pass"],
                max_output_bytes=32,
                timeout_seconds=1,
            )

        root = initialize_repository(self)
        marker = root / "fsmonitor-called"
        hook = root / "fsmonitor.sh"
        hook.write_text(
            "#!/bin/sh\nprintf called > \"$1\"\n",
            encoding="utf-8",
        )
        hook.chmod(0o755)
        subprocess.run(
            [
                "git",
                "-C",
                str(root),
                "config",
                "core.fsmonitor",
                f"{hook} {marker}",
            ],
            check=True,
        )
        fake_bin = root / "fake-bin"
        fake_bin.mkdir()
        fake_git = fake_bin / "git"
        fake_git.write_text(
            f"#!/bin/sh\nprintf called > {marker}\nexit 99\n",
            encoding="utf-8",
        )
        fake_git.chmod(0o755)
        with (
            mock.patch.object(build_singbox_source_bundle, "ROOT", root),
            mock.patch.dict(
                os.environ,
                {"PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}"},
            ),
        ):
            files = build_singbox_source_bundle.public_files()
        self.assertEqual([PurePosixPath("README.md")], files)
        self.assertFalse(marker.exists())

    def test_source_bundle_rejects_intermediate_symlink_escape(self) -> None:
        root = initialize_repository(self)
        outside = Path(self.enterContext(tempfile.TemporaryDirectory()))
        (outside / "payload.txt").write_text("outside\n", encoding="utf-8")
        (root / "linked").symlink_to(outside, target_is_directory=True)
        with (
            mock.patch.object(build_singbox_source_bundle, "ROOT", root),
            mock.patch.object(
                build_singbox_source_bundle,
                "reject_split_index",
            ),
            mock.patch.object(
                build_singbox_source_bundle,
                "pinned_git_command_output",
                return_value=git_index_record(b"linked/payload.txt"),
            ),
        ):
            with self.assertRaisesRegex(ValueError, "changed or is unsafe"):
                build_singbox_source_bundle.public_files()

    def test_source_bundle_copy_rejects_parent_and_leaf_symlink_swaps(self) -> None:
        for swap in ("parent", "leaf"):
            with self.subTest(swap=swap):
                root = initialize_repository(self)
                source = root / "safe" / "payload.txt"
                source.parent.mkdir()
                source.write_text("PUBLIC\n", encoding="utf-8")
                subprocess.run(
                    ["git", "-C", str(root), "add", "safe/payload.txt"],
                    check=True,
                )
                outside = Path(self.enterContext(tempfile.TemporaryDirectory()))
                (outside / "payload.txt").write_text(
                    "SECRET_OUTSIDE\n", encoding="utf-8"
                )
                target = Path(self.enterContext(tempfile.TemporaryDirectory()))

                with mock.patch.object(build_singbox_source_bundle, "ROOT", root):
                    relative = build_singbox_source_bundle.public_files()
                    if swap == "parent":
                        source.parent.rename(root / "safe-original")
                        source.parent.symlink_to(outside, target_is_directory=True)
                    else:
                        source.rename(source.with_name("payload-original.txt"))
                        source.symlink_to(outside / "payload.txt")
                    with mock.patch.object(
                        build_singbox_source_bundle,
                        "public_files",
                        return_value=relative,
                    ):
                        with self.assertRaisesRegex(
                            ValueError, "changed or is unsafe"
                        ):
                            build_singbox_source_bundle.copy_public_tree(target)

                copied = target / "safe" / "payload.txt"
                if copied.exists():
                    self.assertNotEqual("SECRET_OUTSIDE\n", copied.read_text())

    def test_source_bundle_secure_copy_is_fail_fast_and_leak_free(self) -> None:
        root = initialize_repository(self)
        source = root / "nested" / "source.txt"
        source.parent.mkdir()
        source.write_text("safe\n", encoding="utf-8")
        source.chmod(0o711)
        subprocess.run(
            ["git", "-C", str(root), "add", "nested/source.txt"],
            check=True,
        )
        output = Path(self.enterContext(tempfile.TemporaryDirectory()))

        with mock.patch.object(build_singbox_source_bundle, "ROOT", root):
            with mock.patch.object(
                build_singbox_source_bundle.os,
                "supports_dir_fd",
                frozenset(),
            ):
                with self.assertRaisesRegex(ValueError, "dir_fd"):
                    build_singbox_source_bundle.copy_public_tree(output / "unsupported")
            with mock.patch.object(
                build_singbox_source_bundle.os, "O_NOFOLLOW", 0
            ):
                with self.assertRaisesRegex(ValueError, "O_NOFOLLOW"):
                    build_singbox_source_bundle.copy_public_tree(output / "no-flag")

            before = descriptor_count()
            if before is None:
                self.skipTest("open descriptor directory is unavailable")
            for index in range(8):
                target = output / f"copy-{index}"
                target.mkdir()
                build_singbox_source_bundle.copy_public_tree(target)
                copied = target / "nested" / "source.txt"
                self.assertEqual(b"safe\n", copied.read_bytes())
                self.assertEqual(0o755, copied.stat().st_mode & 0o777)
            self.assertEqual(before, descriptor_count())

            existing_target = output / "existing"
            (existing_target / "nested").mkdir(parents=True)
            existing = existing_target / "nested" / "source.txt"
            existing.write_text("DO_NOT_OVERWRITE\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "destination"):
                build_singbox_source_bundle.copy_public_tree(existing_target)
            self.assertEqual("DO_NOT_OVERWRITE\n", existing.read_text())
            self.assertEqual(before, descriptor_count())

            if not hasattr(os, "mkfifo"):
                self.skipTest("mkfifo is unavailable")
            relative = build_singbox_source_bundle.public_files()
            source.unlink()
            os.mkfifo(source)
            special_target = output / "special"
            special_target.mkdir()
            started = time.monotonic()
            with mock.patch.object(
                build_singbox_source_bundle,
                "public_files",
                return_value=relative,
            ):
                with self.assertRaisesRegex(ValueError, "regular file"):
                    build_singbox_source_bundle.copy_public_tree(special_target)
            self.assertLess(time.monotonic() - started, 1.0)
            self.assertFalse((special_target / "nested" / "source.txt").exists())
            self.assertEqual(before, descriptor_count())

    def test_source_bundle_detects_content_and_file_set_mutation(self) -> None:
        root = initialize_repository(self)
        source = root / "nested" / "source.txt"
        source.parent.mkdir()
        source.write_text("stable\n", encoding="utf-8")
        subprocess.run(
            ["git", "-C", str(root), "add", "nested/source.txt"],
            check=True,
        )
        output = Path(self.enterContext(tempfile.TemporaryDirectory()))

        with mock.patch.object(build_singbox_source_bundle, "ROOT", root):
            real_copy = build_singbox_source_bundle.copy_descriptor_bytes
            source_inode = source.stat().st_ino

            def mutate_after_copy(
                source_fd: int,
                destination_fd: int,
                expected_size: int,
                digest=None,
            ) -> int:
                copied = real_copy(
                    source_fd, destination_fd, expected_size, digest
                )
                if os.fstat(source_fd).st_ino == source_inode:
                    source.write_text("tamper\n", encoding="utf-8")
                return copied

            content_target = output / "content"
            content_target.mkdir()
            with mock.patch.object(
                build_singbox_source_bundle,
                "copy_descriptor_bytes",
                side_effect=mutate_after_copy,
            ):
                with self.assertRaisesRegex(ValueError, "changed while"):
                    build_singbox_source_bundle.copy_public_tree(content_target)
            self.assertFalse(
                (content_target / "nested" / "source.txt").exists()
            )

        second_root = initialize_repository(self)
        (second_root / "tracked.txt").write_text("tracked\n", encoding="utf-8")
        subprocess.run(
            ["git", "-C", str(second_root), "add", "tracked.txt"],
            check=True,
        )
        set_target = output / "file-set"
        set_target.mkdir()
        with mock.patch.object(build_singbox_source_bundle, "ROOT", second_root):
            real_public_files = build_singbox_source_bundle.public_files
            calls = 0

            def mutate_after_enumeration(*_args):
                nonlocal calls
                current = real_public_files()
                calls += 1
                if calls == 1:
                    late = second_root / "late-tracked.txt"
                    late.write_text(
                        "late\n", encoding="utf-8"
                    )
                    subprocess.run(
                        ["git", "-C", str(second_root), "add", late.name],
                        check=True,
                    )
                return current

            with mock.patch.object(
                build_singbox_source_bundle,
                "public_files",
                side_effect=mutate_after_enumeration,
            ):
                with self.assertRaisesRegex(
                    ValueError, "index changed|file set changed"
                ):
                    build_singbox_source_bundle.copy_public_tree(set_target)
        self.assertFalse((set_target / "late-tracked.txt").exists())

    def test_source_bundle_bounds_file_tree_and_concurrent_growth(self) -> None:
        oversized_root = initialize_repository(self)
        oversized = oversized_root / "oversized.bin"
        oversized.touch()
        os.truncate(
            oversized,
            build_singbox_source_bundle.MAX_PUBLIC_FILE_BYTES + 1
        )
        subprocess.run(
            ["git", "-C", str(oversized_root), "add", oversized.name],
            check=True,
        )
        oversized_target = Path(
            self.enterContext(tempfile.TemporaryDirectory())
        )
        with mock.patch.object(
            build_singbox_source_bundle, "ROOT", oversized_root
        ):
            with self.assertRaisesRegex(ValueError, "per-file limit"):
                build_singbox_source_bundle.copy_public_tree(oversized_target)
        self.assertFalse((oversized_target / oversized.name).exists())

        tree_root = initialize_repository(self)
        (tree_root / "a.bin").write_bytes(b"aaaaaa")
        (tree_root / "b.bin").write_bytes(b"bbbbbb")
        subprocess.run(
            ["git", "-C", str(tree_root), "add", "a.bin", "b.bin"],
            check=True,
        )
        tree_target = Path(self.enterContext(tempfile.TemporaryDirectory()))
        with (
            mock.patch.object(build_singbox_source_bundle, "ROOT", tree_root),
            mock.patch.object(
                build_singbox_source_bundle, "MAX_PUBLIC_TREE_BYTES", 16
            ),
        ):
            with self.assertRaisesRegex(ValueError, "source tree exceeds"):
                build_singbox_source_bundle.copy_public_tree(tree_target)
        self.assertEqual(b"aaaaaa", (tree_target / "a.bin").read_bytes())
        self.assertFalse((tree_target / "b.bin").exists())

        for mutation in ("append", "truncate"):
            with self.subTest(mutation=mutation):
                root = initialize_repository(self)
                source = root / "nested" / "source.bin"
                source.parent.mkdir()
                source.write_bytes(b"initial")
                subprocess.run(
                    [
                        "git", "-C", str(root), "add",
                        "nested/source.bin",
                    ],
                    check=True,
                )
                target = Path(self.enterContext(tempfile.TemporaryDirectory()))
                source_inode = source.stat().st_ino
                real_copy = build_singbox_source_bundle.copy_descriptor_bytes
                observed: list[tuple[int, int]] = []

                def mutate_before_read(
                    source_fd: int,
                    destination_fd: int,
                    expected_size: int,
                    digest=None,
                ) -> int:
                    if os.fstat(source_fd).st_ino == source_inode:
                        if mutation == "append":
                            with source.open("ab") as payload:
                                payload.write(
                                    b"x"
                                    * (2 * build_singbox_source_bundle.COPY_BUFFER_BYTES)
                                )
                        else:
                            source.write_bytes(b"")
                    copied = real_copy(
                        source_fd, destination_fd, expected_size, digest
                    )
                    if os.fstat(source_fd).st_ino == source_inode:
                        observed.append((expected_size, copied))
                    return copied

                with (
                    mock.patch.object(build_singbox_source_bundle, "ROOT", root),
                    mock.patch.object(
                        build_singbox_source_bundle,
                        "copy_descriptor_bytes",
                        side_effect=mutate_before_read,
                    ),
                ):
                    started = time.monotonic()
                    with self.assertRaisesRegex(ValueError, "changed while"):
                        build_singbox_source_bundle.copy_public_tree(target)
                    self.assertLess(time.monotonic() - started, 1.0)

                self.assertEqual(1, len(observed))
                expected_size, copied = observed[0]
                if mutation == "append":
                    self.assertEqual(expected_size + 1, copied)
                else:
                    self.assertLess(copied, expected_size)
                self.assertFalse((target / "nested" / "source.bin").exists())

    def test_source_bundle_rechecks_path_after_opened_file_is_swapped(self) -> None:
        for swap in ("parent", "leaf"):
            with self.subTest(swap=swap):
                root = initialize_repository(self)
                parent = root / "safe"
                parent.mkdir()
                source = parent / "payload.txt"
                source.write_text("PUBLIC\n", encoding="utf-8")
                subprocess.run(
                    ["git", "-C", str(root), "add", "safe/payload.txt"],
                    check=True,
                )
                outside = Path(self.enterContext(tempfile.TemporaryDirectory()))
                (outside / "payload.txt").write_text(
                    "SECRET_OUTSIDE\n", encoding="utf-8"
                )
                target = Path(self.enterContext(tempfile.TemporaryDirectory()))
                source_inode = source.stat().st_ino
                real_copy = build_singbox_source_bundle.copy_descriptor_bytes
                swapped = False

                def swap_after_copy(
                    source_fd: int,
                    destination_fd: int,
                    expected_size: int,
                    digest=None,
                ) -> int:
                    nonlocal swapped
                    copied = real_copy(
                        source_fd, destination_fd, expected_size, digest
                    )
                    if not swapped and os.fstat(source_fd).st_ino == source_inode:
                        swapped = True
                        if swap == "parent":
                            parent.rename(root / "safe-original")
                            parent.symlink_to(outside, target_is_directory=True)
                        else:
                            source.rename(parent / "payload-original.txt")
                            source.symlink_to(outside / "payload.txt")
                    return copied

                with (
                    mock.patch.object(build_singbox_source_bundle, "ROOT", root),
                    mock.patch.object(
                        build_singbox_source_bundle,
                        "copy_descriptor_bytes",
                        side_effect=swap_after_copy,
                    ),
                ):
                    with self.assertRaisesRegex(
                        ValueError, "changed while|changed or is unsafe"
                    ):
                        build_singbox_source_bundle.copy_public_tree(target)

                self.assertTrue(swapped)
                self.assertFalse((target / "safe" / "payload.txt").exists())

    def test_source_bundle_pins_root_before_git_enumeration(self) -> None:
        container = Path(self.enterContext(tempfile.TemporaryDirectory()))
        root = initialize_repository(self, container / "repo")
        pinned_root = container / "repo-pinned"
        target = container / "target"
        target.mkdir()
        real_public_files = build_singbox_source_bundle.public_files
        swapped = False
        descriptors_before = descriptor_count()

        def swap_root_after_enumeration(*_args) -> list[PurePosixPath]:
            nonlocal swapped
            current = real_public_files()
            if not swapped:
                swapped = True
                root.rename(pinned_root)
                root.mkdir()
                (root / "README.md").write_text(
                    "SECRET_REPLACEMENT\n", encoding="utf-8"
                )
            return current

        try:
            with (
                mock.patch.object(build_singbox_source_bundle, "ROOT", root),
                mock.patch.object(
                    build_singbox_source_bundle,
                    "public_files",
                    side_effect=swap_root_after_enumeration,
                ),
            ):
                with self.assertRaisesRegex(
                    ValueError, "root or \\.git changed|root changed"
                ):
                    build_singbox_source_bundle.copy_public_tree(target)
            self.assertTrue(swapped)
            self.assertFalse((target / "README.md").exists())
            if descriptors_before is not None:
                self.assertEqual(descriptors_before, descriptor_count())
        finally:
            if pinned_root.exists():
                replacement = root / "README.md"
                if replacement.exists():
                    replacement.unlink()
                if root.exists():
                    root.rmdir()
                pinned_root.rename(root)

    def test_git_snapshot_uses_pinned_root_during_swap_and_restore(self) -> None:
        container = Path(self.enterContext(tempfile.TemporaryDirectory()))
        root = initialize_repository(self, container / "repo")
        pinned_root = container / "repo-pinned"
        target = container / "target"
        target.mkdir()
        real_git_file_set = build_singbox_source_bundle.git_file_set
        swapped = False

        def git_during_swap(
            repository: build_singbox_source_bundle.PinnedGitRepository,
            *arguments: str,
        ) -> set[bytes]:
            nonlocal swapped
            if swapped:
                return real_git_file_set(repository, *arguments)
            swapped = True
            root.rename(pinned_root)
            root.mkdir()
            replacement = root / "README.md"
            replacement.write_text("SECRET_REPLACEMENT\n", encoding="utf-8")
            try:
                with mock.patch.dict(
                    os.environ,
                    {
                        "GIT_DIR": str(root / ".git"),
                        "GIT_WORK_TREE": str(root),
                        "GIT_INDEX_FILE": str(root / "hostile-index"),
                    },
                ):
                    return real_git_file_set(repository, *arguments)
            finally:
                replacement.unlink()
                root.rmdir()
                pinned_root.rename(root)

        with (
            mock.patch.object(build_singbox_source_bundle, "ROOT", root),
            mock.patch.object(
                build_singbox_source_bundle,
                "git_file_set",
                side_effect=git_during_swap,
            ),
        ):
            with self.assertRaisesRegex(ValueError, "root or .git changed"):
                build_singbox_source_bundle.copy_public_tree(target)

        self.assertTrue(swapped)
        self.assertFalse((target / "README.md").exists())

    def test_git_snapshot_rejects_in_place_index_mutation_and_restore(self) -> None:
        container = Path(self.enterContext(tempfile.TemporaryDirectory()))
        root = initialize_repository(self, container / "repo")
        target = container / "target"
        target.mkdir()
        index = root / ".git" / "index"
        original = index.read_bytes()
        real_git_file_set = build_singbox_source_bundle.git_file_set
        mutated = False

        def mutate_index_after_scan(
            repository: build_singbox_source_bundle.PinnedGitRepository,
            *arguments: str,
        ) -> set[bytes]:
            nonlocal mutated
            result = real_git_file_set(repository, *arguments)
            if not mutated:
                mutated = True
                with index.open("r+b", buffering=0) as descriptor:
                    descriptor.seek(0)
                    descriptor.write(b"DIRC" if original[:4] != b"DIRC" else b"XXXX")
                    os.fsync(descriptor.fileno())
                    descriptor.seek(0)
                    descriptor.write(original[:4])
                    os.fsync(descriptor.fileno())
            return result

        with (
            mock.patch.object(build_singbox_source_bundle, "ROOT", root),
            mock.patch.object(
                build_singbox_source_bundle,
                "git_file_set",
                side_effect=mutate_index_after_scan,
            ),
        ):
            with self.assertRaisesRegex(ValueError, "index changed"):
                build_singbox_source_bundle.copy_public_tree(target)

        self.assertTrue(mutated)
        self.assertEqual(original, index.read_bytes())
        self.assertEqual([], list(target.iterdir()))

    def test_source_bundle_fails_when_tracked_file_is_missing(self) -> None:
        root = initialize_repository(self)
        missing = root / "tracked-missing.txt"
        missing.write_text("tracked\n", encoding="utf-8")
        subprocess.run(
            ["git", "-C", str(root), "add", missing.name], check=True
        )
        missing.unlink()
        target = Path(self.enterContext(tempfile.TemporaryDirectory()))

        with mock.patch.object(build_singbox_source_bundle, "ROOT", root):
            with self.assertRaisesRegex(ValueError, "changed or is unsafe"):
                build_singbox_source_bundle.copy_public_tree(target)

        self.assertFalse((target / missing.name).exists())

    def test_source_bundle_rejects_gitfile_symlink_and_gitdir_swap(self) -> None:
        for kind in ("gitfile", "symlink"):
            with self.subTest(kind=kind):
                container = Path(
                    self.enterContext(tempfile.TemporaryDirectory())
                )
                root = initialize_repository(self, container / "repo")
                real_git = root / ".git-real"
                (root / ".git").rename(real_git)
                if kind == "gitfile":
                    (root / ".git").write_text(
                        "gitdir: .git-real\n", encoding="utf-8"
                    )
                else:
                    (root / ".git").symlink_to(real_git, target_is_directory=True)
                target = container / "target"
                target.mkdir()
                with mock.patch.object(
                    build_singbox_source_bundle, "ROOT", root
                ):
                    with self.assertRaisesRegex(ValueError, "direct non-symlink"):
                        build_singbox_source_bundle.copy_public_tree(target)
                self.assertEqual([], list(target.iterdir()))

        for kind in ("index-symlink", "index-hardlink"):
            with self.subTest(kind=kind):
                container = Path(
                    self.enterContext(tempfile.TemporaryDirectory())
                )
                root = initialize_repository(self, container / "repo")
                index = root / ".git" / "index"
                real_index = root / ".git" / "index-real"
                index.rename(real_index)
                if kind == "index-symlink":
                    index.symlink_to(real_index.name)
                else:
                    os.link(real_index, index)
                target = container / "target"
                target.mkdir()
                with mock.patch.object(
                    build_singbox_source_bundle, "ROOT", root
                ):
                    with self.assertRaisesRegex(
                        ValueError, "direct regular .git/index"
                    ):
                        build_singbox_source_bundle.copy_public_tree(target)
                self.assertEqual([], list(target.iterdir()))

        container = Path(self.enterContext(tempfile.TemporaryDirectory()))
        root = initialize_repository(self, container / "repo")
        target = container / "target"
        target.mkdir()
        real_git_file_set = build_singbox_source_bundle.git_file_set
        swapped = False

        def swap_gitdir(
            repository: build_singbox_source_bundle.PinnedGitRepository,
            *arguments: str,
        ) -> set[bytes]:
            nonlocal swapped
            if swapped:
                return real_git_file_set(repository, *arguments)
            swapped = True
            original = root / ".git-original"
            gitdir = root / ".git"
            gitdir.rename(original)
            gitdir.mkdir()
            try:
                return real_git_file_set(repository, *arguments)
            finally:
                gitdir.rmdir()
                original.rename(gitdir)

        with (
            mock.patch.object(build_singbox_source_bundle, "ROOT", root),
            mock.patch.object(
                build_singbox_source_bundle,
                "git_file_set",
                side_effect=swap_gitdir,
            ),
        ):
            with self.assertRaisesRegex(ValueError, "root or .git changed"):
                build_singbox_source_bundle.copy_public_tree(target)
        self.assertTrue(swapped)
        self.assertEqual([], list(target.iterdir()))

    def test_archive_rejects_parent_leaf_swaps_and_injection(self) -> None:
        for swap in ("parent", "leaf"):
            with self.subTest(swap=swap):
                container = Path(
                    self.enterContext(tempfile.TemporaryDirectory())
                )
                root = initialize_repository(self, container / "repo")
                source = root / "safe" / "payload.txt"
                source.parent.mkdir()
                source.write_text("PUBLIC\n", encoding="utf-8")
                subprocess.run(
                    ["git", "-C", str(root), "add", "safe/payload.txt"],
                    check=True,
                )
                tree = container / "tree"
                tree.mkdir()
                with mock.patch.object(
                    build_singbox_source_bundle, "ROOT", root
                ):
                    manifest = build_singbox_source_bundle.copy_public_tree(tree)

                archived_source = tree / "safe" / "payload.txt"
                source_inode = archived_source.stat().st_ino
                outside = container / "outside"
                outside.mkdir()
                (outside / "payload.txt").write_text(
                    "SECRET_OUTSIDE\n", encoding="utf-8"
                )
                real_read = build_singbox_source_bundle.DescriptorReader.read
                swapped = False

                def swap_before_archive_read(reader, size: int = -1) -> bytes:
                    nonlocal swapped
                    if (
                        not swapped
                        and os.fstat(reader.descriptor).st_ino == source_inode
                    ):
                        swapped = True
                        parent = tree / "safe"
                        if swap == "parent":
                            parent.rename(tree / "safe-original")
                            parent.symlink_to(outside, target_is_directory=True)
                        else:
                            archived_source.rename(
                                parent / "payload-original.txt"
                            )
                            archived_source.symlink_to(outside / "payload.txt")
                    return real_read(reader, size)

                output = io.BytesIO()
                with (
                    mock.patch.object(
                        build_singbox_source_bundle.DescriptorReader,
                        "read",
                        new=swap_before_archive_read,
                    ),
                    self.assertRaises(ValueError),
                ):
                    with tarfile.open(
                        fileobj=output,
                        mode="w",
                        format=tarfile.PAX_FORMAT,
                    ) as archive:
                        build_singbox_source_bundle.add_tree(
                            archive, tree, "root", manifest
                        )
                self.assertTrue(swapped)
                self.assertNotIn(b"SECRET_OUTSIDE", output.getvalue())

        container = Path(self.enterContext(tempfile.TemporaryDirectory()))
        tree = container / "tree"
        tree.mkdir()
        payload = b"ORIGINAL\n"
        source = tree / "payload.txt"
        source.write_bytes(payload)
        manifest = {
            PurePosixPath("payload.txt"):
            build_singbox_source_bundle.PublicArchiveEntry(
                hashlib.sha256(payload).hexdigest(), len(payload), 0o644
            )
        }
        output = container / "bundle.tar.gz"
        output.write_bytes(b"KEEP_OLD_OUTPUT")

        source.write_bytes(b"INJECTED\n")
        with self.assertRaisesRegex(ValueError, "differs at archive time"):
            build_singbox_source_bundle.write_source_archive(
                output, tree, "root", manifest
            )
        self.assertEqual(b"KEEP_OLD_OUTPUT", output.read_bytes())

        source.write_bytes(payload)
        injected = tree / "injected.txt"
        injected.write_bytes(b"INJECTED_SECRET")
        with self.assertRaisesRegex(ValueError, "unexpected file"):
            build_singbox_source_bundle.write_source_archive(
                output, tree, "root", manifest
            )
        self.assertEqual(b"KEEP_OLD_OUTPUT", output.read_bytes())

        injected.unlink()
        real_addfile = tarfile.TarFile.addfile
        injected_during_archive = False

        def inject_after_first_member(
            archive: tarfile.TarFile,
            member: tarfile.TarInfo,
            fileobj=None,
        ) -> None:
            nonlocal injected_during_archive
            real_addfile(archive, member, fileobj)
            if not injected_during_archive:
                injected_during_archive = True
                injected.write_bytes(b"LATE_INJECTED_SECRET")

        with (
            mock.patch.object(
                tarfile.TarFile,
                "addfile",
                new=inject_after_first_member,
            ),
            self.assertRaisesRegex(ValueError, "directory changed"),
        ):
            build_singbox_source_bundle.write_source_archive(
                output, tree, "root", manifest
            )
        self.assertTrue(injected_during_archive)
        self.assertEqual(b"KEEP_OLD_OUTPUT", output.read_bytes())

    def test_archive_requires_exact_vendor_manifest(self) -> None:
        container = Path(self.enterContext(tempfile.TemporaryDirectory()))
        tree = container / "tree"
        vendor = tree / "singbox" / "vendor"
        vendor.mkdir(parents=True)
        public = tree / "singbox" / "go.mod"
        public.write_bytes(b"module example.invalid/test\n")
        modules = vendor / "modules.txt"
        modules_entry = build_singbox_source_bundle.write_atomic_file(
            modules, b"# exact vendor\n"
        )

        def entry(path: Path) -> build_singbox_source_bundle.PublicArchiveEntry:
            payload = path.read_bytes()
            mode = 0o755 if path.stat().st_mode & 0o100 else 0o644
            return build_singbox_source_bundle.PublicArchiveEntry(
                hashlib.sha256(payload).hexdigest(), len(payload), mode
            )

        manifest = {
            PurePosixPath("singbox/go.mod"): entry(public),
            PurePosixPath("singbox/vendor/modules.txt"): modules_entry,
        }
        first = container / "first.tar.gz"
        second = container / "second.tar.gz"
        build_singbox_source_bundle.write_source_archive(
            first, tree, "root", manifest
        )
        build_singbox_source_bundle.write_source_archive(
            second, tree, "root", manifest
        )
        self.assertEqual(first.read_bytes(), second.read_bytes())

        extra = vendor / "injected.go"
        extra.write_bytes(b"package injected\n")
        with self.assertRaisesRegex(ValueError, "unexpected file"):
            build_singbox_source_bundle.write_source_archive(
                second, tree, "root", manifest
            )
        extra.unlink()

        empty = vendor / "empty"
        empty.mkdir()
        with self.assertRaisesRegex(ValueError, "unexpected directory"):
            build_singbox_source_bundle.write_source_archive(
                second, tree, "root", manifest
            )
        empty.rmdir()

        modules.write_bytes(b"# other vendor\n")
        with self.assertRaisesRegex(ValueError, "source differs"):
            build_singbox_source_bundle.write_source_archive(
                second, tree, "root", manifest
            )

    def test_minimal_vendor_returns_exact_reproducible_manifest(self) -> None:
        container = Path(self.enterContext(tempfile.TemporaryDirectory()))
        module = container / "singbox"
        module.mkdir()
        dependency = container / "dependency"
        package = dependency / "pkg"
        package.mkdir(parents=True)
        (package / "source.go").write_bytes(b"package dependency\n")
        (dependency / "LICENSE").write_bytes(b"license\n")
        package_document = {
            "ImportPath": "example.com/dependency/pkg",
            "Dir": str(package),
            "GoFiles": ["source.go"],
            "Module": {
                "Path": "example.com/dependency",
                "Dir": str(dependency),
            },
        }
        module_document = {
            "Path": "example.com/dependency",
            "Version": "v1.2.3",
            "GoVersion": "1.24",
        }

        command_environments: list[dict[str, str]] = []

        def command_output(command, **kwargs) -> bytes:
            command_environments.append(dict(kwargs.get("env") or {}))
            arguments = command[1:]
            if arguments[:2] == ["mod", "verify"]:
                return b"all modules verified\n"
            if arguments[:2] == ["list", "-mod=mod"]:
                return build_singbox_source_bundle.json.dumps(
                    package_document
                ).encode()
            if arguments[:2] == ["mod", "edit"]:
                return build_singbox_source_bundle.json.dumps(
                    {
                        "Require": [
                            {
                                "Path": "example.com/dependency",
                                "Version": "v1.2.3",
                            }
                        ]
                    }
                ).encode()
            if arguments[:3] == ["list", "-m", "-json"]:
                return build_singbox_source_bundle.json.dumps(
                    module_document
                ).encode()
            if arguments[:2] == ["list", "-mod=vendor"]:
                return b""
            self.fail(f"unexpected command: {command}")

        with (
            mock.patch.object(
                build_singbox_source_bundle,
                "bounded_command_output",
                side_effect=command_output,
            ),
            mock.patch.object(
                build_singbox_source_bundle,
                "trusted_tool_path",
                side_effect=lambda name, _environment: f"/trusted/{name}",
            ),
        ):
            hostile_environment = {
                "GOENV": "/tmp/hostile-goenv",
                "GOFLAGS": "-overlay=/tmp/hostile-overlay.json",
                "GOWORK": "/tmp/hostile-go.work",
            }
            first = build_singbox_source_bundle.build_minimal_vendor(
                module, hostile_environment
            )
            second = build_singbox_source_bundle.build_minimal_vendor(
                module, hostile_environment
            )
            with self.assertRaisesRegex(ValueError, "remaining aggregate"):
                build_singbox_source_bundle.build_minimal_vendor(
                    module,
                    hostile_environment,
                    max_tree_bytes=1,
                )

        self.assertTrue(command_environments)
        for environment in command_environments:
            self.assertEqual("off", environment.get("GOENV"))
            self.assertEqual("", environment.get("GOFLAGS"))
            self.assertEqual("off", environment.get("GOWORK"))
            self.assertEqual("local", environment.get("GOTOOLCHAIN"))
            self.assertEqual("3", environment.get("GIT_CONFIG_COUNT"))
            self.assertEqual(
                "core.fsmonitor", environment.get("GIT_CONFIG_KEY_0")
            )

        self.assertEqual(first, second)
        actual_files = {
            PurePosixPath("singbox/vendor")
            / path.relative_to(module / "vendor").as_posix()
            for path in (module / "vendor").rglob("*")
            if path.is_file()
        }
        self.assertEqual(set(first), actual_files)
        for relative, expected in first.items():
            path = container.joinpath(*relative.parts)
            payload = path.read_bytes()
            self.assertEqual(expected.size, len(payload))
            self.assertEqual(expected.sha256, hashlib.sha256(payload).hexdigest())
            self.assertEqual(expected.mode, path.stat().st_mode & 0o777)

    def test_minimal_vendor_reverifies_module_cache_after_copy(self) -> None:
        container = Path(self.enterContext(tempfile.TemporaryDirectory()))
        module = container / "singbox"
        module.mkdir()
        dependency = container / "dependency"
        package = dependency / "pkg"
        package.mkdir(parents=True)
        source = package / "source.go"
        source.write_bytes(b"package dependency\n")
        (dependency / "LICENSE").write_bytes(b"license\n")
        package_document = {
            "ImportPath": "example.com/dependency/pkg",
            "Dir": str(package),
            "GoFiles": ["source.go"],
            "Module": {
                "Path": "example.com/dependency",
                "Dir": str(dependency),
            },
        }
        module_document = {
            "Path": "example.com/dependency",
            "Version": "v1.2.3",
            "GoVersion": "1.24",
        }
        verify_calls = 0
        mutated = False

        def command_output(command, **_kwargs) -> bytes:
            nonlocal mutated, verify_calls
            arguments = command[1:]
            if arguments[:2] == ["mod", "verify"]:
                verify_calls += 1
                if source.read_bytes() != b"package dependency\n":
                    raise ValueError("module cache mutation detected")
                return b"all modules verified\n"
            if arguments[:2] == ["list", "-mod=mod"]:
                return json.dumps(package_document).encode()
            if arguments[:2] == ["mod", "edit"]:
                return json.dumps(
                    {
                        "Require": [
                            {
                                "Path": "example.com/dependency",
                                "Version": "v1.2.3",
                            }
                        ]
                    }
                ).encode()
            if arguments[:3] == ["list", "-m", "-json"]:
                return json.dumps(module_document).encode()
            if arguments[:2] == ["list", "-mod=vendor"]:
                if not mutated:
                    mutated = True
                    source.write_bytes(b"package tampered\n")
                return b""
            self.fail(f"unexpected command: {command}")

        with (
            mock.patch.object(
                build_singbox_source_bundle,
                "bounded_command_output",
                side_effect=command_output,
            ),
            mock.patch.object(
                build_singbox_source_bundle,
                "trusted_tool_path",
                side_effect=lambda name, _environment: f"/trusted/{name}",
            ),
            self.assertRaisesRegex(ValueError, "module cache mutation"),
        ):
            build_singbox_source_bundle.build_minimal_vendor(module, {})

        self.assertTrue(mutated)
        self.assertEqual(2, verify_calls)

    def test_stage_name_swaps_are_detected_without_unlinking_replacement(self) -> None:
        container = Path(self.enterContext(tempfile.TemporaryDirectory()))
        tree = container / "tree"
        tree.mkdir()
        payload = b"SAFE\n"
        (tree / "payload.txt").write_bytes(payload)
        manifest = {
            PurePosixPath("payload.txt"):
            build_singbox_source_bundle.PublicArchiveEntry(
                hashlib.sha256(payload).hexdigest(), len(payload), 0o644
            )
        }
        victim = container / "victim.txt"
        victim.write_bytes(b"VICTIM_UNCHANGED")
        output = container / "bundle.tar.gz"
        output.write_bytes(b"OLD_OUTPUT")
        real_verify_staged = build_singbox_source_bundle.verify_staged_name
        replacement: Path | None = None

        def swap_staged_name(
            parent_descriptor: int,
            name: str,
            descriptor: int,
        ) -> None:
            nonlocal replacement
            staged = container / name
            staged.rename(container / f"{name}.held")
            staged.symlink_to(victim)
            replacement = staged
            real_verify_staged(parent_descriptor, name, descriptor)

        with (
            mock.patch.object(
                build_singbox_source_bundle,
                "verify_staged_name",
                side_effect=swap_staged_name,
            ),
            self.assertRaisesRegex(ValueError, "staging name changed"),
        ):
            build_singbox_source_bundle.write_source_archive(
                output, tree, "root", manifest
            )
        self.assertEqual(b"OLD_OUTPUT", output.read_bytes())
        self.assertEqual(b"VICTIM_UNCHANGED", victim.read_bytes())
        self.assertIsNotNone(replacement)
        self.assertTrue(replacement.is_symlink())

        second = Path(self.enterContext(tempfile.TemporaryDirectory()))
        second_tree = second / "tree"
        second_tree.mkdir()
        (second_tree / "payload.txt").write_bytes(payload)
        second_victim = second / "victim.txt"
        second_victim.write_bytes(b"SECOND_VICTIM")
        second_output = second / "bundle.tar.gz"
        second_output.write_bytes(b"SECOND_OLD")
        real_verify_published = build_singbox_source_bundle.verify_published_name

        def swap_published_name(
            parent_descriptor: int,
            name: str,
            descriptor: int,
        ) -> None:
            published = second / name
            published.rename(second / f"{name}.held")
            published.symlink_to(second_victim)
            real_verify_published(parent_descriptor, name, descriptor)

        with (
            mock.patch.object(
                build_singbox_source_bundle,
                "verify_published_name",
                side_effect=swap_published_name,
            ),
            self.assertRaisesRegex(ValueError, "does not match staged"),
        ):
            build_singbox_source_bundle.write_source_archive(
                second_output, second_tree, "root", manifest
            )
        self.assertTrue(second_output.is_symlink())
        self.assertEqual(b"SECOND_VICTIM", second_victim.read_bytes())

        vendor_root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        source_root = vendor_root / "source"
        source_root.mkdir()
        (source_root / "source.go").write_bytes(b"package safe\n")
        destination = vendor_root / "vendor" / "source.go"
        vendor_victim = vendor_root / "victim.txt"
        vendor_victim.write_bytes(b"VENDOR_VICTIM")
        vendor_replacement: Path | None = None

        def swap_vendor_stage(
            parent_descriptor: int,
            name: str,
            descriptor: int,
        ) -> None:
            nonlocal vendor_replacement
            staged = destination.parent / name
            staged.rename(destination.parent / f"{name}.held")
            staged.symlink_to(vendor_victim)
            vendor_replacement = staged
            real_verify_staged(parent_descriptor, name, descriptor)

        with (
            mock.patch.object(
                build_singbox_source_bundle,
                "verify_staged_name",
                side_effect=swap_vendor_stage,
            ),
            self.assertRaisesRegex(ValueError, "staging name changed"),
        ):
            build_singbox_source_bundle.copy_file(
                source_root, Path("source.go"), destination
            )
        self.assertFalse(destination.exists())
        self.assertIsNotNone(vendor_replacement)
        self.assertTrue(vendor_replacement.is_symlink())
        self.assertEqual(b"VENDOR_VICTIM", vendor_victim.read_bytes())

    def test_output_parent_rename_is_detected_before_publish(self) -> None:
        container = Path(self.enterContext(tempfile.TemporaryDirectory()))
        tree = container / "tree"
        tree.mkdir()
        payload = b"SAFE\n"
        (tree / "payload.txt").write_bytes(payload)
        manifest = {
            PurePosixPath("payload.txt"):
            build_singbox_source_bundle.PublicArchiveEntry(
                hashlib.sha256(payload).hexdigest(), len(payload), 0o644
            )
        }
        output_parent = container / "output"
        output_parent.mkdir()
        renamed_parent = container / "output-renamed"
        output = output_parent / "bundle.tar.gz"
        real_verify_staged = build_singbox_source_bundle.verify_staged_name
        swapped = False

        def rename_parent(
            parent_descriptor: int,
            name: str,
            descriptor: int,
        ) -> None:
            nonlocal swapped
            real_verify_staged(parent_descriptor, name, descriptor)
            if not swapped:
                swapped = True
                output_parent.rename(renamed_parent)
                output_parent.mkdir()

        with (
            mock.patch.object(
                build_singbox_source_bundle,
                "verify_staged_name",
                side_effect=rename_parent,
            ),
            self.assertRaisesRegex(ValueError, "output directory changed"),
        ):
            build_singbox_source_bundle.write_source_archive(
                output, tree, "root", manifest
            )

        self.assertTrue(swapped)
        self.assertFalse(output.exists())
        self.assertFalse((renamed_parent / output.name).exists())
        self.assertEqual(
            [],
            [
                path
                for path in renamed_parent.iterdir()
                if path.name.endswith(".tmp")
            ],
        )

        second = Path(self.enterContext(tempfile.TemporaryDirectory()))
        second_tree = second / "tree"
        second_tree.mkdir()
        (second_tree / "payload.txt").write_bytes(payload)
        second_parent = second / "output"
        second_parent.mkdir()
        second_renamed = second / "output-renamed"
        second_output = second_parent / "bundle.tar.gz"
        real_fsync = os.fsync
        swapped_after_fsync = False

        def rename_after_parent_fsync(descriptor: int) -> None:
            nonlocal swapped_after_fsync
            real_fsync(descriptor)
            if (
                not swapped_after_fsync
                and stat.S_ISDIR(os.fstat(descriptor).st_mode)
            ):
                swapped_after_fsync = True
                second_parent.rename(second_renamed)
                second_parent.mkdir()

        with (
            mock.patch.object(
                build_singbox_source_bundle.os,
                "fsync",
                side_effect=rename_after_parent_fsync,
            ),
            self.assertRaisesRegex(ValueError, "output directory changed"),
        ):
            build_singbox_source_bundle.write_source_archive(
                second_output, second_tree, "root", manifest
            )

        self.assertTrue(swapped_after_fsync)
        self.assertFalse(second_output.exists())
        self.assertTrue((second_renamed / second_output.name).exists())
        self.assertEqual(
            1,
            audit_singbox_source_bundle.audit_bundle(
                second_renamed / second_output.name
            ),
        )

    def test_output_parent_walk_rejects_intermediate_symlink(self) -> None:
        container = Path(self.enterContext(tempfile.TemporaryDirectory()))
        tree = container / "tree"
        tree.mkdir()
        payload = b"SAFE\n"
        (tree / "payload.txt").write_bytes(payload)
        manifest = {
            PurePosixPath("payload.txt"):
            build_singbox_source_bundle.PublicArchiveEntry(
                hashlib.sha256(payload).hexdigest(), len(payload), 0o644
            )
        }
        safe = container / "safe"
        outside = container / "outside"
        safe.mkdir()
        (outside / "sub").mkdir(parents=True)
        (safe / "link").symlink_to(outside, target_is_directory=True)
        escaped = outside / "sub" / "bundle.tar.gz"
        with self.assertRaisesRegex(ValueError, "opened securely"):
            build_singbox_source_bundle.write_source_archive(
                safe / "link" / "sub" / "bundle.tar.gz",
                tree,
                "root",
                manifest,
            )
        self.assertFalse(escaped.exists())

    def test_directory_fsync_failure_restores_existing_output(self) -> None:
        container = Path(self.enterContext(tempfile.TemporaryDirectory()))
        tree = container / "tree"
        tree.mkdir()
        payload = b"NEW\n"
        (tree / "payload.txt").write_bytes(payload)
        manifest = {
            PurePosixPath("payload.txt"):
            build_singbox_source_bundle.PublicArchiveEntry(
                hashlib.sha256(payload).hexdigest(), len(payload), 0o644
            )
        }
        output = container / "bundle.tar.gz"
        output.write_bytes(b"OLD")
        real_fsync = os.fsync
        directory_fsyncs = 0

        def fail_published_directory_fsync(descriptor: int) -> None:
            nonlocal directory_fsyncs
            if stat.S_ISDIR(os.fstat(descriptor).st_mode):
                directory_fsyncs += 1
                if directory_fsyncs == 2:
                    raise OSError("simulated directory fsync failure")
            real_fsync(descriptor)

        with (
            mock.patch.object(
                build_singbox_source_bundle.os,
                "fsync",
                side_effect=fail_published_directory_fsync,
            ),
            self.assertRaisesRegex(OSError, "simulated directory fsync failure"),
        ):
            build_singbox_source_bundle.write_source_archive(
                output, tree, "root", manifest
            )

        self.assertGreaterEqual(directory_fsyncs, 3)
        self.assertEqual(b"OLD", output.read_bytes())
        self.assertEqual(
            [],
            [
                path.name
                for path in container.iterdir()
                if path.name.endswith((".old", ".tmp"))
            ],
        )

    def test_manifest_and_writer_limits_fail_before_growth(self) -> None:
        entry = build_singbox_source_bundle.PublicArchiveEntry(
            hashlib.sha256(b"").hexdigest(), 0, 0o644
        )
        with (
            mock.patch.object(
                build_singbox_source_bundle, "MAX_ARCHIVE_FILES", 1
            ),
            self.assertRaisesRegex(ValueError, "manifest exceeds 1 files"),
        ):
            build_singbox_source_bundle.validate_archive_manifest(
                {
                    PurePosixPath("one"): entry,
                    PurePosixPath("two"): entry,
                },
                "root",
            )

        descriptor, path = tempfile.mkstemp()
        self.addCleanup(lambda: os.path.exists(path) and os.unlink(path))
        try:
            writer = build_singbox_source_bundle.DescriptorWriter(
                descriptor, 1
            )
            with self.assertRaisesRegex(ValueError, "compressed source archive"):
                writer.write(b"ab")
            self.assertEqual(0, os.fstat(descriptor).st_size)
        finally:
            os.close(descriptor)

    def test_compressed_archive_limit_matches_audit(self) -> None:
        self.assertEqual(
            build_singbox_source_bundle.MAX_SOURCE_ARCHIVE_BYTES,
            audit_singbox_source_bundle.MAX_BUNDLE_BYTES,
        )
        container = Path(self.enterContext(tempfile.TemporaryDirectory()))
        tree = container / "tree"
        tree.mkdir()
        payload = b"payload\n"
        (tree / "payload.txt").write_bytes(payload)
        manifest = {
            PurePosixPath("payload.txt"):
            build_singbox_source_bundle.PublicArchiveEntry(
                hashlib.sha256(payload).hexdigest(), len(payload), 0o644
            )
        }
        output = container / "bundle.tar.gz"
        output.write_bytes(b"KEEP")
        with (
            mock.patch.object(
                build_singbox_source_bundle,
                "MAX_SOURCE_ARCHIVE_BYTES",
                1,
            ),
            self.assertRaisesRegex(ValueError, "compressed source archive"),
        ):
            build_singbox_source_bundle.write_source_archive(
                output, tree, "root", manifest
            )
        self.assertEqual(b"KEEP", output.read_bytes())

    def test_output_staging_resists_symlinks_and_concurrent_builds(self) -> None:
        container = Path(self.enterContext(tempfile.TemporaryDirectory()))
        tree = container / "tree"
        tree.mkdir()
        payload = b"SAFE_ARCHIVE_CONTENT\n"
        (tree / "payload.txt").write_bytes(payload)
        manifest = {
            PurePosixPath("payload.txt"):
            build_singbox_source_bundle.PublicArchiveEntry(
                hashlib.sha256(payload).hexdigest(), len(payload), 0o644
            )
        }
        victim = container / "victim.txt"
        victim.write_bytes(b"DO_NOT_TOUCH")
        output = container / "bundle.tar.gz"
        output.symlink_to(victim)
        predictable_stage = container / f".{output.name}.tmp"
        predictable_stage.symlink_to(victim)

        build_singbox_source_bundle.write_source_archive(
            output, tree, "root", manifest
        )
        self.assertEqual(1, audit_singbox_source_bundle.audit_bundle(output))
        self.assertEqual(b"DO_NOT_TOUCH", victim.read_bytes())
        self.assertTrue(predictable_stage.is_symlink())
        self.assertFalse(output.is_symlink())
        with tarfile.open(output, "r:gz") as archive:
            member = archive.extractfile("root/payload.txt")
            self.assertIsNotNone(member)
            self.assertEqual(payload, member.read())
        reproducible_output = container / "reproducible.tar.gz"
        build_singbox_source_bundle.write_source_archive(
            reproducible_output, tree, "root", manifest
        )
        self.assertEqual(output.read_bytes(), reproducible_output.read_bytes())
        random_stages = [
            path
            for path in container.iterdir()
            if path.name.startswith(f".{output.name}.")
            and path.name.endswith(".tmp")
            and path != predictable_stage
        ]
        self.assertEqual([], random_stages)

        locked_output = container / "locked.tar.gz"
        lock_path = container / f".{locked_output.name}.lock"
        lock_path.symlink_to(victim)
        with self.assertRaisesRegex(ValueError, "lock is unsafe"):
            build_singbox_source_bundle.write_source_archive(
                locked_output, tree, "root", manifest
            )
        self.assertEqual(b"DO_NOT_TOUCH", victim.read_bytes())
        self.assertFalse(locked_output.exists())

        concurrent_output = container / "concurrent.tar.gz"
        entered = threading.Event()
        release = threading.Event()
        worker_errors: list[BaseException] = []
        real_add_tree = build_singbox_source_bundle.add_tree
        worker: threading.Thread

        def blocking_add_tree(*arguments, **keywords) -> None:
            if threading.current_thread() is worker:
                entered.set()
                if not release.wait(5):
                    raise TimeoutError("test did not release archive build")
            real_add_tree(*arguments, **keywords)

        def run_worker() -> None:
            try:
                build_singbox_source_bundle.write_source_archive(
                    concurrent_output, tree, "root", manifest
                )
            except BaseException as error:
                worker_errors.append(error)

        with mock.patch.object(
            build_singbox_source_bundle,
            "add_tree",
            side_effect=blocking_add_tree,
        ):
            worker = threading.Thread(target=run_worker)
            worker.start()
            self.assertTrue(entered.wait(5))
            try:
                with self.assertRaisesRegex(ValueError, "already running"):
                    build_singbox_source_bundle.write_source_archive(
                        concurrent_output, tree, "root", manifest
                    )
            finally:
                release.set()
                worker.join(5)
        self.assertFalse(worker.is_alive())
        self.assertEqual([], worker_errors)
        self.assertTrue(concurrent_output.is_file())

    def test_minimal_vendor_copy_uses_pinned_regular_source(self) -> None:
        container = Path(self.enterContext(tempfile.TemporaryDirectory()))
        source_root = container / "source"
        source = source_root / "nested" / "source.go"
        source.parent.mkdir(parents=True)
        source.write_bytes(b"package safe\n")
        source.chmod(0o711)
        destination = container / "vendor" / "source.go"
        copied_entry = build_singbox_source_bundle.copy_file(
            source_root, Path("nested/source.go"), destination
        )
        self.assertEqual(b"package safe\n", destination.read_bytes())
        self.assertEqual(0o755, destination.stat().st_mode & 0o777)
        self.assertEqual(len(b"package safe\n"), copied_entry.size)
        self.assertEqual(
            hashlib.sha256(b"package safe\n").hexdigest(),
            copied_entry.sha256,
        )
        self.assertEqual(0o755, copied_entry.mode)

        outside = container / "outside"
        outside.mkdir()
        (outside / "source.go").write_bytes(b"SECRET_OUTSIDE")
        source.parent.rename(source_root / "nested-original")
        source.parent.symlink_to(outside, target_is_directory=True)
        escaped_destination = container / "vendor" / "escaped.go"
        with self.assertRaisesRegex(ValueError, "changed or is unsafe"):
            build_singbox_source_bundle.copy_file(
                source_root, Path("nested/source.go"), escaped_destination
            )
        self.assertFalse(escaped_destination.exists())

        second_root = container / "second-source"
        second_source = second_root / "source.go"
        second_root.mkdir()
        second_source.write_bytes(b"PINNED_SAFE")
        second_inode = second_source.stat().st_ino
        second_destination = container / "vendor" / "second.go"
        real_copy = build_singbox_source_bundle.copy_descriptor_bytes
        swapped = False

        def swap_vendor_leaf(
            source_fd: int,
            destination_fd: int,
            expected_size: int,
            digest=None,
        ) -> int:
            nonlocal swapped
            copied = real_copy(
                source_fd, destination_fd, expected_size, digest
            )
            if not swapped and os.fstat(source_fd).st_ino == second_inode:
                swapped = True
                second_source.rename(second_root / "source-original.go")
                second_source.symlink_to(outside / "source.go")
            return copied

        with mock.patch.object(
            build_singbox_source_bundle,
            "copy_descriptor_bytes",
            side_effect=swap_vendor_leaf,
        ):
            with self.assertRaisesRegex(
                ValueError, "changed while|changed or is unsafe"
            ):
                build_singbox_source_bundle.copy_file(
                    second_root,
                    Path("source.go"),
                    second_destination,
                )
        self.assertTrue(swapped)
        self.assertFalse(second_destination.exists())

    def test_slash_namespaces_are_forbidden_in_paths_and_text(self) -> None:
        for namespace in (("org", "telegram"), ("com", "exteragram")):
            relative = "/".join(("vendor", *namespace, "Client.java"))
            text = "/".join(namespace)
            with self.subTest(relative=relative):
                self.assertTrue(audit_public_tree.forbidden_namespace_path(relative))
                self.assertTrue(any(value in text for value in audit_public_tree.FORBIDDEN_TEXT))
                self.assertTrue(audit_singbox_source_bundle.forbidden_namespace_path(
                    PurePosixPath(relative)
                ))
                self.assertTrue(any(
                    value in text.encode()
                    for value in audit_singbox_source_bundle.FORBIDDEN_BYTES
                ))

    def test_local_macos_paths_are_forbidden_but_android_tmp_is_allowed(self) -> None:
        forbidden = (
            "/" + "/".join(("private", "tmp", "exitfy")),
            "/" + "/".join(("private", "var", "folders", "cache")),
            "/" + "/".join(("opt", "homebrew", "bin", "go")),
            "/" + "/".join(("root", "exitfy", "build")),
        )
        for value in forbidden:
            with self.subTest(value=value):
                self.assertTrue(audit_public_tree.contains_local_host_path(value))
                self.assertTrue(audit_singbox_source_bundle.contains_local_host_path(
                    value.encode()
                ))
        android = "/" + "/".join(("data", "local", "tmp", "exitfy"))
        self.assertFalse(audit_public_tree.contains_local_host_path(android))
        self.assertFalse(audit_singbox_source_bundle.contains_local_host_path(
            android.encode()
        ))

    def test_existing_home_boundaries_remain_forbidden(self) -> None:
        unix_home = "/" + "/".join(("home", "builder", "work")) + "/"
        mac_home = "/" + "/".join(("Users", "builder", "work")) + "/"
        spaced_mac_home = "/" + "/".join(("Users", "Build Agent", "work")) + "/"
        self.assertTrue(audit_public_tree.contains_local_host_path(unix_home))
        self.assertTrue(any(value in mac_home for value in audit_public_tree.FORBIDDEN_TEXT))
        self.assertTrue(audit_singbox_source_bundle.contains_local_host_path(
            unix_home.encode()
        ))
        self.assertTrue(audit_singbox_source_bundle.contains_local_host_path(
            mac_home.encode()
        ))
        self.assertTrue(any(
            value in spaced_mac_home for value in audit_public_tree.FORBIDDEN_TEXT
        ))
        self.assertTrue(audit_singbox_source_bundle.contains_local_host_path(
            spaced_mac_home.encode()
        ))

    def test_source_bundle_local_path_boundaries_are_exact(self) -> None:
        slash = b"/"
        for value in (
            slash + b"home",
            slash + b"root:",
            slash + slash + b" " + slash + b"home",
            b"root:x:0:0:" + slash + b"root:",
        ):
            with self.subTest(allowed=value):
                self.assertFalse(
                    audit_singbox_source_bundle.contains_local_host_path(value)
                )

        for value in (
            slash + slash.join((b"home", b"runner", b"work")),
            slash + slash.join((b"root", b"go", b"pkg")),
            slash + slash.join((b"Users", b"builder", b"work")),
            slash + slash.join((b"Users", b"Build Agent", b"work")),
            slash + slash.join((b"private", b"tmp", b"exitfy")),
            slash + slash.join((b"private", b"var", b"folders", b"cache")),
            slash + slash.join((b"opt", b"homebrew", b"bin", b"go")),
        ):
            with self.subTest(forbidden=value):
                self.assertTrue(
                    audit_singbox_source_bundle.contains_local_host_path(value)
                )

    def test_source_bundle_audit_rejects_special_member_types(self) -> None:
        def write_bundle(path: Path, member_type: bytes | None) -> None:
            with path.open("wb") as raw:
                with gzip.GzipFile(
                    filename="", mode="wb", fileobj=raw, mtime=0
                ) as compressed:
                    with tarfile.open(
                        fileobj=compressed,
                        mode="w",
                        format=tarfile.PAX_FORMAT,
                    ) as archive:
                        payload = b"safe\n"
                        regular = tarfile.TarInfo("root/safe.txt")
                        regular.size = len(payload)
                        archive.addfile(regular, io.BytesIO(payload))

                        if member_type is not None:
                            special = tarfile.TarInfo("root/special")
                            special.type = member_type
                            special.devmajor = 1
                            special.devminor = 3
                            archive.addfile(special)

        directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        regular_bundle = directory / "regular.tar.gz"
        write_bundle(regular_bundle, None)
        with (
            mock.patch.object(
                sys, "argv", ["audit_singbox_source_bundle.py", str(regular_bundle)]
            ),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            audit_singbox_source_bundle.main()

        member_types = (
            ("fifo", tarfile.FIFOTYPE),
            ("character-device", tarfile.CHRTYPE),
            ("block-device", tarfile.BLKTYPE),
            ("socket", b"s"),
            ("unknown", b"Z"),
        )
        for name, member_type in member_types:
            with self.subTest(name=name):
                bundle = directory / f"{name}.tar.gz"
                write_bundle(bundle, member_type)
                with mock.patch.object(
                    sys, "argv", ["audit_singbox_source_bundle.py", str(bundle)]
                ):
                    with self.assertRaisesRegex(
                        SystemExit, "unsupported archive member type: root/special"
                    ):
                        audit_singbox_source_bundle.main()

    def test_source_bundle_audit_enforces_one_canonical_root_tree(self) -> None:
        def write_bundle(
            path: Path,
            entries: tuple[tuple[str, bytes, bytes], ...],
        ) -> None:
            with path.open("wb") as raw:
                with gzip.GzipFile(
                    filename="", mode="wb", fileobj=raw, mtime=0
                ) as compressed:
                    with tarfile.open(
                        fileobj=compressed,
                        mode="w",
                        format=tarfile.PAX_FORMAT,
                    ) as archive:
                        for name, member_type, payload in entries:
                            member = tarfile.TarInfo(name)
                            member.type = member_type
                            member.size = len(payload)
                            member.mode = 0o755 if member.isdir() else 0o644
                            archive.addfile(
                                member,
                                io.BytesIO(payload) if member.isfile() else None,
                            )

        def run_audit(path: Path) -> None:
            with (
                mock.patch.object(
                    sys, "argv", ["audit_singbox_source_bundle.py", str(path)]
                ),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                audit_singbox_source_bundle.main()

        directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        valid_cases = (
            (
                "builder-shaped",
                (("root/safe.txt", tarfile.REGTYPE, b"safe\n"),),
            ),
        )
        for name, entries in valid_cases:
            with self.subTest(valid=name):
                bundle = directory / f"{name}.tar.gz"
                write_bundle(bundle, entries)
                run_audit(bundle)

        invalid_cases = (
            (
                "empty-name",
                (("", tarfile.REGTYPE, b"safe\n"),),
                "empty archive member name",
            ),
            (
                "top-level-file",
                (("root", tarfile.REGTYPE, b"safe\n"),),
                "explicit logical root archive member is forbidden",
            ),
            (
                "explicit-root-directory",
                (
                    ("root", tarfile.DIRTYPE, b""),
                    ("root/safe.txt", tarfile.REGTYPE, b"safe\n"),
                ),
                "explicit logical root archive member is forbidden",
            ),
            (
                "duplicate",
                (
                    ("root/safe.txt", tarfile.REGTYPE, b"one\n"),
                    ("root/safe.txt", tarfile.REGTYPE, b"two\n"),
                ),
                "duplicate normalized archive member",
            ),
            (
                "alias",
                (
                    ("root/safe.txt", tarfile.REGTYPE, b"one\n"),
                    ("root//safe.txt", tarfile.REGTYPE, b"two\n"),
                ),
                "noncanonical archive member name",
            ),
            (
                "same-path-type-collision",
                (
                    ("root/node", tarfile.DIRTYPE, b""),
                    ("root/node", tarfile.REGTYPE, b"safe\n"),
                ),
                "archive file/directory type collision",
            ),
            (
                "parent-type-collision",
                (
                    ("root/node", tarfile.REGTYPE, b"safe\n"),
                    ("root/node/child", tarfile.REGTYPE, b"safe\n"),
                ),
                "archive file/directory type collision",
            ),
        )
        for name, entries, expected in invalid_cases:
            with self.subTest(invalid=name):
                bundle = directory / f"{name}.tar.gz"
                write_bundle(bundle, entries)
                with self.assertRaisesRegex(SystemExit, expected):
                    run_audit(bundle)

    def test_staged_forbidden_blob_cannot_be_hidden_by_benign_worktree(self) -> None:
        root = initialize_repository(self)
        base = git(root, "rev-parse", "HEAD")
        leak = root / "safe.txt"
        leak.write_text(FORBIDDEN_CLIENT_SAMPLE + "\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(root), "add", "safe.txt"], check=True)
        leak.write_text("benign working copy\n", encoding="utf-8")

        failures, _ = audit_public_tree.audit_repository(root, history_base=base)
        self.assertTrue(any(
            "forbidden client reference: index:safe.txt" in failure
            for failure in failures
        ), failures)
        self.assertFalse(any(
            "working:safe.txt" in failure for failure in failures
        ), failures)

    def test_forbidden_head_blob_cannot_be_hidden_by_benign_worktree(self) -> None:
        root = initialize_repository(self)
        leak = root / "safe.txt"
        leak.write_text(FORBIDDEN_CLIENT_SAMPLE + "\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(root), "add", "safe.txt"], check=True)
        subprocess.run(
            ["git", "-C", str(root), "commit", "-q", "-m", "unsafe commit"],
            check=True,
        )
        leak.write_text("benign working copy\n", encoding="utf-8")

        failures, _ = audit_public_tree.audit_repository(root)
        self.assertTrue(any(
            "forbidden client reference: HEAD:safe.txt" in failure
            for failure in failures
        ), failures)

    def test_deleted_later_file_is_still_found_in_unpushed_history(self) -> None:
        root = initialize_repository(self)
        base = git(root, "rev-parse", "HEAD")
        leak = root / "temporary.txt"
        leak.write_text(FORBIDDEN_CLIENT_SAMPLE + "\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(root), "add", "temporary.txt"], check=True)
        subprocess.run(
            ["git", "-C", str(root), "commit", "-q", "-m", "unsafe history"],
            check=True,
        )
        leak.unlink()
        subprocess.run(["git", "-C", str(root), "add", "-u"], check=True)
        subprocess.run(
            ["git", "-C", str(root), "commit", "-q", "-m", "hide file"],
            check=True,
        )

        failures, _ = audit_public_tree.audit_repository(root, history_base=base)
        self.assertTrue(any(
            failure.startswith("forbidden client reference: commit-")
            and failure.endswith(":temporary.txt")
            for failure in failures
        ), failures)

    def test_git_lfs_pointer_is_rejected_in_every_repository_view(self) -> None:
        root = initialize_repository(self)
        base = git(root, "rev-parse", "HEAD")
        pointer = root / "payload.txt"

        pointer.write_bytes(GIT_LFS_POINTER)
        failures, _ = audit_public_tree.audit_repository(root)
        self.assertIn(
            "Git LFS pointer is forbidden: working:payload.txt", failures
        )

        subprocess.run(["git", "-C", str(root), "add", "payload.txt"], check=True)
        pointer.write_text("benign working copy\n", encoding="utf-8")
        failures, _ = audit_public_tree.audit_repository(root)
        self.assertIn(
            "Git LFS pointer is forbidden: index:payload.txt", failures
        )

        pointer.write_bytes(GIT_LFS_POINTER)
        subprocess.run(["git", "-C", str(root), "add", "payload.txt"], check=True)
        subprocess.run(
            ["git", "-C", str(root), "commit", "-q", "-m", "lfs pointer"],
            check=True,
        )
        pointer.write_text("benign working copy\n", encoding="utf-8")
        failures, _ = audit_public_tree.audit_repository(root)
        self.assertIn("Git LFS pointer is forbidden: HEAD:payload.txt", failures)

        pointer.unlink()
        subprocess.run(["git", "-C", str(root), "add", "-u"], check=True)
        subprocess.run(
            ["git", "-C", str(root), "commit", "-q", "-m", "hide pointer"],
            check=True,
        )
        failures, _ = audit_public_tree.audit_repository(root, history_base=base)
        self.assertTrue(any(
            failure.startswith("Git LFS pointer is forbidden: commit-")
            and failure.endswith(":payload.txt")
            for failure in failures
        ), failures)

    def test_working_and_index_symlinks_are_rejected_without_following(self) -> None:
        root = initialize_repository(self)
        target = root / "target.txt"
        target.write_text("clean target\n", encoding="utf-8")
        link = root / "link.txt"
        link.symlink_to(target.name)

        failures, _ = audit_public_tree.audit_repository(root)
        self.assertIn("symlink is forbidden: working:link.txt", failures)

        subprocess.run(["git", "-C", str(root), "add", "link.txt"], check=True)
        failures, _ = audit_public_tree.audit_repository(root)
        self.assertIn("symlink is forbidden: index:link.txt", failures)
        self.assertIn("symlink is forbidden: working:link.txt", failures)

    def test_zero_before_sha_uses_default_branch_merge_base(self) -> None:
        root = initialize_repository(self)
        base = git(root, "rev-parse", "HEAD")
        subprocess.run(
            ["git", "-C", str(root), "update-ref", "refs/remotes/origin/main", base],
            check=True,
        )
        (root / "branch.txt").write_text("clean branch\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(root), "add", "branch.txt"], check=True)
        subprocess.run(
            ["git", "-C", str(root), "commit", "-q", "-m", "branch"],
            check=True,
        )
        with mock.patch.dict(
            os.environ,
            {
                "EXITFY_AUDIT_BASE": audit_public_tree.ZERO_COMMIT,
                "EXITFY_AUDIT_DEFAULT_BRANCH": "main",
            },
            clear=False,
        ):
            history_base, scan_all = audit_public_tree.resolve_history_base(root)
        self.assertEqual(history_base, base)
        self.assertFalse(scan_all)

    def test_always_on_audit_workflow_has_no_path_filter_or_write_token(self) -> None:
        workflow = (
            audit_public_tree.ROOT / ".github/workflows/audit-public.yml"
        ).read_text(encoding="utf-8")
        trigger = workflow.split("permissions:", 1)[0]
        self.assertRegex(trigger, r"(?m)^  push:\s*$")
        self.assertRegex(trigger, r"(?m)^  pull_request:\s*$")
        self.assertNotIn("paths:", trigger)
        self.assertIn("contents: read", workflow)
        self.assertNotIn("contents: write", workflow)
        self.assertIn("cancel-in-progress: false", workflow)
        self.assertIn("fetch-depth: 0", workflow)
        self.assertIn("EXITFY_AUDIT_BASE", workflow)
        self.assertIn("EXITFY_AUDIT_DEFAULT_BRANCH", workflow)
        self.assertIn("EXITFY_AUDIT_PR_BASE", workflow)
        self.assertIn("github.event.pull_request.base.sha", workflow)
        self.assertIn('git show "$audit_ref:scripts/audit_public_tree.py"', workflow)
        self.assertIn('python3 "$audit_dir/audit_public_tree.py"', workflow)
        self.assertIn('--repo-root "$GITHUB_WORKSPACE"', workflow)
        self.assertIn('mktemp -d "$RUNNER_TEMP/', workflow)
        self.assertNotIn("./scripts/audit_public_tree.py", workflow)
        self.assertIn("unittest discover -s scripts", workflow)
        self.assertLess(
            workflow.index('python3 "$audit_dir/audit_public_tree.py"'),
            workflow.index("unittest discover -s scripts"),
        )
        checkouts = re.findall(
            r"(?m)^\s*- uses: (actions/checkout)@([^\s#]+)", workflow
        )
        self.assertEqual(len(checkouts), 1)
        self.assertIsNotNone(audit_public_tree.FULL_COMMIT.fullmatch(checkouts[0][1]))

    def test_pull_request_cannot_replace_the_frozen_public_auditor(self) -> None:
        root = initialize_repository(self)
        scripts = root / "scripts"
        scripts.mkdir()
        frozen_source = Path(audit_public_tree.__file__).read_bytes()
        (scripts / "audit_public_tree.py").write_bytes(frozen_source)
        subprocess.run(
            ["git", "-C", str(root), "add", "scripts/audit_public_tree.py"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(root), "commit", "-q", "-m", "base auditor"],
            check=True,
        )
        base = git(root, "rev-parse", "HEAD")

        (scripts / "audit_public_tree.py").write_text(
            "raise SystemExit(0)\n", encoding="utf-8"
        )
        (root / "leak.txt").write_text(
            FORBIDDEN_CLIENT_SAMPLE + "\n", encoding="utf-8"
        )
        subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
        subprocess.run(
            ["git", "-C", str(root), "commit", "-q", "-m", "bypass"],
            check=True,
        )

        frozen = Path(self.enterContext(tempfile.TemporaryDirectory())) / "audit.py"
        frozen.write_bytes(subprocess.check_output(
            [
                "git", "-C", str(root), "show",
                f"{base}:scripts/audit_public_tree.py",
            ]
        ))
        environment = os.environ.copy()
        environment.update({
            "EXITFY_AUDIT_BASE": base,
            "EXITFY_AUDIT_DEFAULT_BRANCH": "main",
            "GITHUB_ACTIONS": "true",
        })
        result = subprocess.run(
            [sys.executable, str(frozen), "--repo-root", str(root)],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=environment,
        )
        self.assertNotEqual(0, result.returncode)
        self.assertIn("forbidden client reference", result.stderr)

    def test_release_workflows_reconcile_paginated_drafts_and_exact_tags(self) -> None:
        self.assertTrue(os.access(
            audit_public_tree.ROOT / "scripts/release_draft_state.py", os.X_OK
        ))
        self.assertFalse(
            (audit_public_tree.ROOT / ".github/workflows/release-xray.yml").exists()
        )
        self.assertFalse(
            (audit_public_tree.ROOT / ".github/workflows/release-singbox.yml").exists()
        )
        for name in ("publish-xray-core-v2.yml", "publish-singbox-core-v2.yml"):
            with self.subTest(name=name):
                workflow = (
                    audit_public_tree.ROOT / ".github/workflows" / name
                ).read_text(encoding="utf-8")
                self.assertNotIn('releases?per_page=100"', workflow)
                self.assertGreaterEqual(
                    workflow.count("fetch_github_release_pages.sh"), 3
                )
                self.assertIn("release_draft_state.py prepare", workflow)
                self.assertIn("release_draft_state.py verify", workflow)
                self.assertIn("release_draft_state.py guard-upstream", workflow)
                self.assertGreaterEqual(
                    workflow.count("release_draft_state.py verify-tag"), 3
                )
                self.assertIn("gh api --method DELETE", workflow)
                self.assertNotIn('-f target_commitish="$wrapper_commit"', workflow)
                self.assertIn('--target "$wrapper_commit"', workflow)
                self.assertGreaterEqual(workflow.count('--commit "$wrapper_commit"'), 4)
                self.assertIn("--paginate --slurp", workflow)
                self.assertGreaterEqual(
                    workflow.count("retire_legacy_workflows.py --verify"), 3
                )
                self.assertNotIn("github.run_attempt", workflow)
                self.assertIn("overwrite: true", workflow)
                self.assertIn("actions: read", workflow)
                self.assertNotRegex(workflow, r"(?m)^\s+\[\[")
                build = workflow.split("  build:\n", 1)[1].split("  publish:\n", 1)[0]
                self.assertLess(build.index("    if: >-"), build.index("    steps:"))
                self.assertIn("github.event_name != 'workflow_dispatch'", build)
                self.assertIn("github.event.repository.default_branch", build)
                build_header = build.split("    steps:\n", 1)[0]
                self.assertNotIn("GH_TOKEN:", build_header)
                self.assertEqual(build.count("GH_TOKEN:"), 2)
                self.assertIn("GOPROXY: https://proxy.golang.org", build_header)
                self.assertIn("GOSUMDB: sum.golang.org", build_header)
                self.assertIn("Isolate verified Go module downloads", build)
                self.assertIn(
                    'GOMODCACHE=$RUNNER_TEMP/exitfy-go-mod-cache', build
                )
                self.assertIn("cache: false", build)
                self.assertIn("Freeze clean wrapper build inputs", build)
                self.assertIn("verify_build_inputs.py preflight", build)
                self.assertIn("verify_build_inputs.py capture", build)
                self.assertGreaterEqual(
                    build.count('--snapshot-sha256 "${{ steps.pins.outputs.snapshot_sha }}"'),
                    2,
                )
                self.assertGreaterEqual(
                    build.count('show "$GITHUB_SHA:scripts/verify_build_inputs.py"'),
                    2,
                )
                self.assertGreaterEqual(build.count('--expected-head "$GITHUB_SHA"'), 4)
                pin_step = build.split(
                    "- name: Pin exact", 1
                )[1].split("\n      - name:", 1)[0]
                self.assertNotIn("GH_TOKEN", pin_step)
                publish = workflow.split("  publish:\n", 1)[1]
                self.assertLess(publish.index("    if: >-"), publish.index("    steps:"))
                self.assertIn("github.event_name != 'workflow_dispatch'", publish)
                self.assertIn("github.event.repository.default_branch", publish)
                self.assertIn("ref: ${{ github.sha }}", publish)
                self.assertLess(
                    publish.index("Download verified candidate"),
                    publish.index("Validate frozen publish head before local code"),
                )
                self.assertLess(
                    publish.index("Validate frozen publish head before local code"),
                    publish.index("Require retired legacy release workflows"),
                )
                before_guard = publish.split(
                    "- name: Validate frozen publish head before local code", 1
                )[0]
                self.assertNotIn("./scripts/", before_guard)
                self.assertIn("git rev-list --count", publish)
                self.assertIn("git checkout --detach", publish)
                self.assertIn("Confirm main still equals the wrapper commit", publish)
                self.assertLess(
                    publish.rindex("retire_legacy_workflows.py --verify"),
                    publish.index("Create verified draft and publish atomically"),
                )
                self.assertGreater(
                    publish.rindex("retire_legacy_workflows.py --verify"),
                    publish.index("Generate and verify final manifest"),
                )

    def test_workflow_action_audit_rejects_unpinned_and_docker_references(self) -> None:
        failures: list[str] = []
        audit_public_tree._audit_bytes(
            "test",
            ".github/workflows/example.yml",
            (
                "steps:\n"
                "  - uses: actions/checkout@v4\n"
                "  - uses: docker://alpine:latest\n"
                "  - uses: ./local-action\n"
                "  - uses: actions/setup-python@" + "a" * 40 + "\n"
            ).encode(),
            failures,
        )
        self.assertEqual(len(failures), 2, failures)
        self.assertTrue(all("unpinned GitHub Action" in value for value in failures))

    def test_nested_composite_and_flow_style_action_uses_are_audited(self) -> None:
        for name in ("tools/example/action.yml", "tools/example/action.yaml"):
            failures: list[str] = []
            audit_public_tree._audit_bytes(
                "test",
                name,
                (
                    "name: nested\nruns:\n  using: composite\n  steps:\n"
                    "    - { 'uses': actions/setup-python@v5 }\n"
                ).encode(),
                failures,
            )
            self.assertEqual(1, len(failures), failures)
            self.assertIn("unpinned GitHub Action", failures[0])

        failures = []
        audit_public_tree._audit_bytes(
            "test",
            ".github/workflows/flow.yml",
            b"jobs: { audit: { steps: [ { uses: actions/checkout@v4 } ] } }\n",
            failures,
        )
        self.assertEqual(1, len(failures), failures)
        self.assertIn("unpinned GitHub Action", failures[0])


if __name__ == "__main__":
    unittest.main()
