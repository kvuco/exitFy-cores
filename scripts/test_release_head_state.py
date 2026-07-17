from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

import release_head_state


def git(root: Path, *arguments: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(root), *arguments], text=True
    ).strip()


class ReleaseHeadStateTest(unittest.TestCase):
    def repository(self) -> tuple[Path, str]:
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        subprocess.run(["git", "init", "-q", "-b", "main", str(root)], check=True)
        git(root, "config", "user.name", "test")
        git(root, "config", "user.email", "test@example.invalid")
        (root / "singbox").mkdir()
        for name in ("go.mod", "go.sum"):
            (root / name).write_text(f"xray {name}\n", encoding="utf-8")
            (root / "singbox" / name).write_text(f"sb {name}\n", encoding="utf-8")
        (root / "other").write_text("base\n", encoding="utf-8")
        git(root, "add", ".")
        git(root, "commit", "-q", "-m", "base")
        return root, git(root, "rev-parse", "HEAD")

    def commit(self, root: Path, path: str, value: str) -> str:
        (root / path).write_text(value, encoding="utf-8")
        git(root, "add", path)
        git(root, "commit", "-q", "-m", path)
        return git(root, "rev-parse", "HEAD")

    def test_exact_head_and_one_foreign_pin_child_are_candidates(self) -> None:
        root, parent = self.repository()
        head = self.commit(root, "singbox/go.mod", "foreign\n")
        self.assertEqual(
            release_head_state.current_wrapper_candidates(
                root, head, {"singbox/go.mod", "singbox/go.sum"}
            ),
            [head, parent],
        )

    def test_own_mixed_added_deleted_and_merge_changes_do_not_admit_parent(self) -> None:
        root, _ = self.repository()
        head = self.commit(root, "go.mod", "own\n")
        self.assertEqual(
            release_head_state.current_wrapper_candidates(
                root, head, {"singbox/go.mod", "singbox/go.sum"}
            ),
            [head],
        )

        root, _ = self.repository()
        (root / "singbox" / "go.mod").write_text("foreign\n", encoding="utf-8")
        (root / "other").write_text("mixed\n", encoding="utf-8")
        git(root, "add", ".")
        git(root, "commit", "-q", "-m", "mixed")
        head = git(root, "rev-parse", "HEAD")
        self.assertEqual(
            release_head_state.current_wrapper_candidates(
                root, head, {"singbox/go.mod", "singbox/go.sum"}
            ),
            [head],
        )

        root, _ = self.repository()
        git(root, "rm", "-q", "singbox/go.mod")
        git(root, "commit", "-q", "-m", "delete")
        head = git(root, "rev-parse", "HEAD")
        self.assertEqual(
            release_head_state.current_wrapper_candidates(
                root, head, {"singbox/go.mod", "singbox/go.sum"}
            ),
            [head],
        )

    def test_moved_head_and_noncanonical_paths_fail_closed(self) -> None:
        root, head = self.repository()
        self.commit(root, "other", "moved\n")
        with self.assertRaisesRegex(ValueError, "HEAD moved"):
            release_head_state.current_wrapper_candidates(
                root, head, {"singbox/go.mod"}
            )
        with self.assertRaisesRegex(ValueError, "canonical"):
            release_head_state.current_wrapper_candidates(
                root, git(root, "rev-parse", "HEAD"), {"../go.mod"}
            )


if __name__ == "__main__":
    unittest.main()
