from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import verify_build_inputs


MODULE = "example.invalid/upstream"
COMMIT = "a" * 40


def git(root: Path, *arguments: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(root), *arguments], text=True
    ).strip()


def repository(test: unittest.TestCase) -> Path:
    root = Path(test.enterContext(tempfile.TemporaryDirectory()))
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    subprocess.run(["git", "-C", str(root), "config", "user.name", "test"], check=True)
    subprocess.run(
        ["git", "-C", str(root), "config", "user.email", "test@example.invalid"],
        check=True,
    )
    (root / ".gitignore").write_text("dist/\ndist-repro/\n*.h\n__pycache__/\n", encoding="utf-8")
    (root / "go.mod").write_text("module test.invalid/wrapper\n", encoding="utf-8")
    (root / "go.sum").write_text("initial\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(root), "add", "."], check=True)
    subprocess.run(["git", "-C", str(root), "commit", "-q", "-m", "base"], check=True)
    return root


def origin_runner(
    *,
    replace: bool = False,
    origin_hash: str = COMMIT,
    path: str = MODULE,
    download_error: bool = False,
):
    def run(arguments, _cwd: Path) -> bytes:
        if tuple(arguments[:3]) == ("go", "list", "-m"):
            value = {"Path": path, "Version": "v1.2.3"}
            if replace:
                value["Replace"] = {"Path": "../local"}
        else:
            value = {
                "Path": path,
                "Version": "v1.2.3",
                "Origin": {"VCS": "git", "Hash": origin_hash},
            }
            if download_error:
                value["Error"] = "download failed"
        return json.dumps(value).encode()

    return run


class BuildInputVerificationTest(unittest.TestCase):
    def test_bounded_command_caps_output_and_kills_owned_group(self) -> None:
        with (
            mock.patch.object(verify_build_inputs, "MAX_COMMAND_OUTPUT", 1024),
            self.assertRaisesRegex(ValueError, "output is too large"),
        ):
            verify_build_inputs._run_bounded(
                [sys.executable, "-c", "import os; os.write(1, b'x' * 65536)"],
                Path.cwd(),
            )

        real_popen = subprocess.Popen
        started: list[subprocess.Popen[bytes]] = []

        def capture_process(*arguments, **keywords):
            process = real_popen(*arguments, **keywords)
            started.append(process)
            return process

        with (
            mock.patch.object(
                verify_build_inputs.subprocess,
                "Popen",
                side_effect=capture_process,
            ),
            mock.patch.object(
                verify_build_inputs, "COMMAND_TIMEOUT_SECONDS", 0.2
            ),
            self.assertRaisesRegex(ValueError, "timed out"),
        ):
            verify_build_inputs._run_bounded(
                [
                    sys.executable,
                    "-c",
                    (
                        "import subprocess,sys,time; "
                        "subprocess.Popen([sys.executable,'-c',"
                        "'import time; time.sleep(30)']); time.sleep(30)"
                    ),
                ],
                Path.cwd(),
            )
        self.assertEqual(1, len(started))
        deadline = time.monotonic() + 2
        while True:
            try:
                os.killpg(started[0].pid, 0)
            except ProcessLookupError:
                break
            if time.monotonic() >= deadline:
                self.fail("timed-out verification command group remained alive")
            time.sleep(0.02)

    def test_bounded_command_detects_executable_replacement(self) -> None:
        directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        script = directory / "tool"
        original = directory / "tool-original"
        script.write_text("#!/bin/sh\n/bin/sleep 30\n", encoding="utf-8")
        script.chmod(0o755)
        real_popen = subprocess.Popen

        def replace_after_spawn(*arguments, **keywords):
            process = real_popen(*arguments, **keywords)
            script.rename(original)
            script.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            script.chmod(0o755)
            return process

        with (
            mock.patch.object(
                verify_build_inputs.subprocess,
                "Popen",
                side_effect=replace_after_spawn,
            ),
            self.assertRaisesRegex(ValueError, "executable changed"),
        ):
            verify_build_inputs._run_bounded([str(script)], Path.cwd())

    def test_descriptor_reads_reject_symlinked_ancestors(self) -> None:
        root = repository(self)
        outside = Path(self.enterContext(tempfile.TemporaryDirectory()))
        (outside / "go.mod").write_text("outside\n", encoding="utf-8")
        (root / "linked").symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlinked path"):
            verify_build_inputs._read_pin(root, "linked/go.mod")

        root_directory = verify_build_inputs._pin_directory(root)
        try:
            with self.assertRaisesRegex(ValueError, "symlinked ancestor"):
                verify_build_inputs._pin_relative_directory(
                    root_directory, "linked", "module directory"
                )
        finally:
            verify_build_inputs._close_pinned_directory(root_directory)

    def test_descriptor_read_detects_parent_replacement(self) -> None:
        directory = Path(self.enterContext(tempfile.TemporaryDirectory())) / "snapshot"
        directory.mkdir()
        (directory / "value").write_text("safe\n", encoding="utf-8")
        pinned = verify_build_inputs._pin_directory(directory)
        moved = directory.with_name("snapshot-moved")
        directory.rename(moved)
        directory.mkdir()
        (directory / "value").write_text("hostile\n", encoding="utf-8")
        try:
            with self.assertRaisesRegex(ValueError, "directory changed"):
                verify_build_inputs._read_regular_at(
                    pinned, "value", 1024, "snapshot file"
                )
        finally:
            verify_build_inputs._close_pinned_directory(pinned)

    def test_snapshot_directory_cleanup_never_removes_replacement(self) -> None:
        parent = Path(self.enterContext(tempfile.TemporaryDirectory()))
        target = parent / "snapshot"
        moved = parent / "snapshot-original"
        real_verify = verify_build_inputs._verify_pinned_directory
        swapped = False

        def swap_before_success(directory):
            nonlocal swapped
            if directory.requested_path == target and not swapped:
                swapped = True
                target.rename(moved)
                target.mkdir()
                raise ValueError("forced directory replacement")
            return real_verify(directory)

        with (
            mock.patch.object(
                verify_build_inputs,
                "_verify_pinned_directory",
                side_effect=swap_before_success,
            ),
            self.assertRaisesRegex(ValueError, "forced directory replacement"),
        ):
            verify_build_inputs._create_pinned_directory(target, "snapshot")
        self.assertTrue(swapped)
        self.assertTrue(target.is_dir())
        self.assertTrue(moved.is_dir())

    def test_exact_origin_accepts_path_version_and_commit(self) -> None:
        self.assertEqual(
            verify_build_inputs.verify_module_origin(
                Path("."), MODULE, COMMIT, "v1.2.3", run_command=origin_runner()
            ),
            "v1.2.3",
        )

    def test_replace_wrong_path_or_wrong_origin_fail_closed(self) -> None:
        cases = (
            (origin_runner(replace=True), "replacement"),
            (origin_runner(path="example.invalid/other"), "path"),
            (origin_runner(origin_hash="b" * 40), "origin"),
            (origin_runner(download_error=True), "resolution error"),
        )
        for runner, reason in cases:
            with self.subTest(reason=reason):
                with self.assertRaises(ValueError):
                    verify_build_inputs.verify_module_origin(
                        Path("."), MODULE, COMMIT, run_command=runner
                    )

    def test_tree_gate_rejects_tracked_untracked_and_build_relevant_ignored(self) -> None:
        root = repository(self)
        head = git(root, "rev-parse", "HEAD")
        (root / "go.mod").write_text("changed\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "tracked"):
            verify_build_inputs.assert_repository_state(root, head, set())
        verify_build_inputs.assert_repository_state(root, head, {"go.mod"})

        (root / "note.txt").write_text("untracked\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "untracked"):
            verify_build_inputs.assert_repository_state(root, head, {"go.mod"})
        (root / "note.txt").unlink()

        (root / "generated.h").write_text("ignored input\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "ignored"):
            verify_build_inputs.assert_repository_state(root, head, {"go.mod"})

    def test_tree_gate_rejects_hidden_index_flags_even_for_allowed_pins(self) -> None:
        for state in ("assume-unchanged", "skip-worktree", "intent-to-add"):
            with self.subTest(state=state):
                root = repository(self)
                head = git(root, "rev-parse", "HEAD")
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
                            "go.mod",
                        ],
                        check=True,
                    )
                with self.assertRaisesRegex(ValueError, "non-default entry"):
                    verify_build_inputs.assert_repository_state(
                        root, head, {"go.mod", "intent.txt"}
                    )

    def test_tree_gate_accepts_equivalent_index_refresh_during_settlement(self) -> None:
        root = repository(self)
        head = git(root, "rev-parse", "HEAD")
        index = root / ".git" / "index"
        real_assert = verify_build_inputs._assert_default_index_entries
        calls = 0

        def refresh_after_first_read(directory):
            nonlocal calls
            logical = real_assert(directory)
            calls += 1
            if calls == 1:
                replacement = index.with_name("index.refresh")
                replacement.write_bytes(index.read_bytes())
                os.replace(replacement, index)
            return logical

        with mock.patch.object(
            verify_build_inputs,
            "_assert_default_index_entries",
            side_effect=refresh_after_first_read,
        ):
            verify_build_inputs.assert_repository_state(root, head, set())

        self.assertEqual(4, calls)

    def test_tree_gate_rejects_equivalent_index_replacement_after_pin(self) -> None:
        root = repository(self)
        head = git(root, "rev-parse", "HEAD")
        index = root / ".git" / "index"
        real_assert = verify_build_inputs._assert_default_index_entries
        calls = 0

        def replace_during_protected_scan(directory):
            nonlocal calls
            logical = real_assert(directory)
            calls += 1
            if calls == 3:
                replacement = index.with_name("index.raced")
                replacement.write_bytes(index.read_bytes())
                os.replace(replacement, index)
            return logical

        with (
            mock.patch.object(
                verify_build_inputs,
                "_assert_default_index_entries",
                side_effect=replace_during_protected_scan,
            ),
            self.assertRaisesRegex(ValueError, "Git index changed"),
        ):
            verify_build_inputs.assert_repository_state(root, head, set())

        self.assertEqual(4, calls)

    def test_tree_gate_rejects_split_index(self) -> None:
        root = repository(self)
        head = git(root, "rev-parse", "HEAD")
        subprocess.run(
            ["git", "-C", str(root), "update-index", "--split-index"],
            check=True,
        )
        with self.assertRaisesRegex(ValueError, "split Git index"):
            verify_build_inputs.assert_repository_state(root, head, set())

    def test_tree_gate_disables_repository_fsmonitor(self) -> None:
        root = repository(self)
        head = git(root, "rev-parse", "HEAD")
        external = Path(self.enterContext(tempfile.TemporaryDirectory()))
        marker = external / "fsmonitor-called"
        hook = external / "fsmonitor.sh"
        hook.write_text(
            f"#!/bin/sh\nprintf called > {marker}\nexit 1\n",
            encoding="utf-8",
        )
        hook.chmod(0o755)
        subprocess.run(
            ["git", "-C", str(root), "config", "core.fsmonitor", str(hook)],
            check=True,
        )
        verify_build_inputs.assert_repository_state(root, head, set())
        self.assertFalse(marker.exists())
        subprocess.run(
            ["git", "-C", str(root), "config", "core.fileMode", "false"],
            check=True,
        )
        (root / "go.mod").chmod(0o755)
        with self.assertRaisesRegex(ValueError, "tracked"):
            verify_build_inputs.assert_repository_state(root, head, set())

    def test_default_module_origin_uses_exact_sanitized_go_environment(self) -> None:
        directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        calls: list[tuple[tuple[str, ...], dict[str, str]]] = []

        def run_tool(executable, arguments, _directory, environment):
            calls.append(((executable, *arguments), dict(environment)))
            if tuple(arguments[:3]) == ("list", "-m", "-json"):
                return json.dumps(
                    {"Path": MODULE, "Version": "v1.2.3"}
                ).encode()
            return json.dumps(
                {
                    "Path": MODULE,
                    "Version": "v1.2.3",
                    "Origin": {"VCS": "git", "Hash": COMMIT},
                }
            ).encode()

        with (
            mock.patch.object(
                verify_build_inputs,
                "_run_tool_in_directory",
                side_effect=run_tool,
            ),
            mock.patch.object(
                verify_build_inputs,
                "_trusted_tool",
                side_effect=lambda name, _environment: f"/trusted/{name}",
            ),
            mock.patch.dict(
                os.environ,
                {
                    "GOENV": "/tmp/hostile-goenv",
                    "GOFLAGS": "-overlay=/tmp/hostile.json",
                    "GOTOOLCHAIN": "auto",
                    "GOWORK": "/tmp/hostile.work",
                    "GIT_CONFIG_GLOBAL": "/tmp/hostile.gitconfig",
                },
            ),
        ):
            version = verify_build_inputs.verify_module_origin(
                directory, MODULE, COMMIT, "v1.2.3"
            )

        self.assertEqual("v1.2.3", version)
        self.assertEqual(2, len(calls))
        for arguments, environment in calls:
            self.assertEqual("/trusted/go", arguments[0])
            self.assertEqual("off", environment["GOENV"])
            self.assertEqual("", environment["GOFLAGS"])
            self.assertEqual("local", environment["GOTOOLCHAIN"])
            self.assertEqual("off", environment["GOWORK"])
            self.assertEqual(os.devnull, environment["GIT_CONFIG_GLOBAL"])
            self.assertEqual("3", environment["GIT_CONFIG_COUNT"])
            self.assertEqual("core.fsmonitor", environment["GIT_CONFIG_KEY_0"])
            self.assertEqual("false", environment["GIT_CONFIG_VALUE_0"])

    def test_generated_outputs_are_allowed_only_when_explicit(self) -> None:
        root = repository(self)
        head = git(root, "rev-parse", "HEAD")
        output = root / "dist" / "artifact.bin"
        output.parent.mkdir()
        output.write_bytes(b"output")
        with self.assertRaisesRegex(ValueError, "ignored"):
            verify_build_inputs.assert_repository_state(root, head, set())
        verify_build_inputs.assert_repository_state(
            root, head, set(), allow_generated=True
        )

    def test_tree_gate_rejects_moved_head_even_when_new_tree_is_clean(self) -> None:
        root = repository(self)
        expected = git(root, "rev-parse", "HEAD")
        (root / "go.mod").write_text("module test.invalid/replaced\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(root), "add", "go.mod"], check=True)
        subprocess.run(
            ["git", "-C", str(root), "commit", "-q", "-m", "move head"],
            check=True,
        )
        with self.assertRaisesRegex(ValueError, "HEAD moved"):
            verify_build_inputs.assert_repository_state(root, expected, set())

    def test_snapshot_is_byte_exact_and_outside_repository(self) -> None:
        root = repository(self)
        (root / "go.sum").write_text("updated\n", encoding="utf-8")
        snapshot = Path(self.enterContext(tempfile.TemporaryDirectory())) / "pins"
        digest = verify_build_inputs.capture_snapshot(
            root, snapshot, ["go.mod", "go.sum"], MODULE, "v1.2.3", COMMIT
        )
        verify_build_inputs.verify_snapshot(
            root, snapshot, ["go.mod", "go.sum"], digest
        )
        self.assertEqual((snapshot / "go.sum").read_text(), "updated\n")

        (root / "go.sum").write_text("late mutation\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "changed"):
            verify_build_inputs.verify_snapshot(
                root, snapshot, ["go.mod", "go.sum"], digest
            )

    def test_snapshot_rejects_pin_set_or_in_repository_destination(self) -> None:
        root = repository(self)
        with self.assertRaisesRegex(ValueError, "outside"):
            verify_build_inputs.capture_snapshot(
                root,
                root / "snapshot",
                ["go.mod", "go.sum"],
                MODULE,
                "v1.2.3",
                COMMIT,
            )
        snapshot = Path(self.enterContext(tempfile.TemporaryDirectory())) / "pins"
        digest = verify_build_inputs.capture_snapshot(
            root, snapshot, ["go.mod", "go.sum"], MODULE, "v1.2.3", COMMIT
        )
        with self.assertRaisesRegex(ValueError, "pin set"):
            verify_build_inputs.verify_snapshot(root, snapshot, ["go.mod"], digest)

    def test_snapshot_rechecks_outside_boundary_after_directory_creation(self) -> None:
        root = repository(self)
        outside = Path(self.enterContext(tempfile.TemporaryDirectory()))
        requested = outside / "pins"
        escaped = root / "escaped-snapshot"
        real_create = verify_build_inputs._create_pinned_directory

        def create_inside(_path: Path, label: str):
            return real_create(escaped, label)

        with (
            mock.patch.object(
                verify_build_inputs,
                "_create_pinned_directory",
                side_effect=create_inside,
            ),
            self.assertRaisesRegex(ValueError, "parent changed|remain outside"),
        ):
            verify_build_inputs.capture_snapshot(
                root,
                requested,
                ["go.mod", "go.sum"],
                MODULE,
                "v1.2.3",
                COMMIT,
            )

    def test_pin_reader_rejects_symlink_and_in_place_mutation(self) -> None:
        root = repository(self)
        pin = root / "go.mod"
        backup = root / "real.mod"
        pin.rename(backup)
        pin.symlink_to(backup.name)
        with self.assertRaises((OSError, ValueError)):
            verify_build_inputs._read_pin(root, "go.mod")

        pin.unlink()
        backup.rename(pin)
        original_read = verify_build_inputs.os.read
        mutated = False

        def racing_read(descriptor: int, size: int) -> bytes:
            nonlocal mutated
            value = original_read(descriptor, size)
            if not mutated:
                mutated = True
                pin.write_bytes(b"x" * pin.stat().st_size)
            return value

        with mock.patch.object(verify_build_inputs.os, "read", side_effect=racing_read):
            with self.assertRaisesRegex(ValueError, "changed"):
                verify_build_inputs._read_pin(root, "go.mod")

    def test_snapshot_reader_rejects_symlink_substitution(self) -> None:
        root = repository(self)
        snapshot = Path(self.enterContext(tempfile.TemporaryDirectory())) / "pins"
        digest = verify_build_inputs.capture_snapshot(
            root, snapshot, ["go.mod", "go.sum"], MODULE, "v1.2.3", COMMIT
        )
        (snapshot / "go.mod").unlink()
        (snapshot / "go.mod").symlink_to(root / "go.mod")
        with self.assertRaises((OSError, ValueError)):
            verify_build_inputs.verify_snapshot(
                root, snapshot, ["go.mod", "go.sum"], digest
            )

    def test_snapshot_metadata_digest_is_anchored_before_tests(self) -> None:
        root = repository(self)
        snapshot = Path(self.enterContext(tempfile.TemporaryDirectory())) / "pins"
        digest = verify_build_inputs.capture_snapshot(
            root, snapshot, ["go.mod", "go.sum"], MODULE, "v1.2.3", COMMIT
        )
        metadata = json.loads((snapshot / "snapshot.json").read_text())
        metadata["originCommit"] = "b" * 40
        (snapshot / "snapshot.json").write_text(
            json.dumps(metadata, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "pre-test"):
            verify_build_inputs.verify_snapshot(
                root, snapshot, ["go.mod", "go.sum"], digest
            )

    def test_snapshot_pin_digest_comes_only_from_anchored_metadata(self) -> None:
        root = repository(self)
        snapshot = Path(self.enterContext(tempfile.TemporaryDirectory())) / "pins"
        digest = verify_build_inputs.capture_snapshot(
            root, snapshot, ["go.mod", "go.sum"], MODULE, "v1.2.3", COMMIT
        )
        self.assertEqual(
            hashlib.sha256((root / "go.mod").read_bytes()).hexdigest(),
            verify_build_inputs.snapshot_pin_digest(
                snapshot, digest, "go.mod"
            ),
        )
        (snapshot / "go.mod").write_text("late file mutation\n", encoding="utf-8")
        self.assertEqual(
            hashlib.sha256((root / "go.mod").read_bytes()).hexdigest(),
            verify_build_inputs.snapshot_pin_digest(
                snapshot, digest, "go.mod"
            ),
        )
        with self.assertRaisesRegex(ValueError, "captured value"):
            verify_build_inputs.snapshot_pin_digest(
                snapshot, "0" * 64, "go.mod"
            )

    def test_module_cache_verification_runs_exact_command_between_tree_gates(self) -> None:
        root = repository(self)
        head = git(root, "rev-parse", "HEAD")
        calls: list[tuple[tuple[str, ...], Path]] = []

        def runner(arguments, cwd: Path) -> bytes:
            calls.append((tuple(arguments), cwd))
            return b"all modules verified\n"

        verify_build_inputs.verify_module_cache(
            root,
            Path("."),
            head,
            ["go.mod", "go.sum"],
            run_command=runner,
        )
        self.assertEqual(calls, [(('go', 'mod', 'verify'), root.resolve())])

        def mutating_runner(arguments, cwd: Path) -> bytes:
            (root / "go.mod").write_text("late mutation\n", encoding="utf-8")
            return b"all modules verified\n"

        with self.assertRaisesRegex(ValueError, "tracked"):
            verify_build_inputs.verify_module_cache(
                root,
                Path("."),
                head,
                [],
                run_command=mutating_runner,
            )


if __name__ == "__main__":
    unittest.main()
