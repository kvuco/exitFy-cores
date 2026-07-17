#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import re
import stat
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN_SUFFIXES = {
    ".plugin", ".dex", ".jar", ".apk", ".aar", ".class",
    ".so", ".dylib", ".dll", ".exe",
}
FORBIDDEN_TEXT = (
    "TMessages" + "Proj",
    "com" + ".exteragram",
    "org" + ".telegram",
    "com" + "/exteragram",
    "org" + "/telegram",
    "/" + "Users" + "/",
    "C:" + "\\Users\\",
)
FORBIDDEN_PATH_PARTS = (("com", "exteragram"), ("org", "telegram"))
LOCAL_HOST_PATHS = (
    re.compile(r"(?<![A-Za-z0-9_])/(?:home|root)(?:/|\b)"),
    re.compile(
        r"(?<![A-Za-z0-9_])/(?:" + "private" + r"/(?:tmp|var/folders)|"
        + "opt" + r"/homebrew)(?:/|\b)"
    ),
)
ACTION_USE = re.compile(
    r"(?im)(?:^|[,{\[])\s*-?\s*(?:uses|\"uses\"|'uses')\s*:\s*"
    r"[\"']?([^\"'\s#,}\]]+)"
)
ACTION_METADATA_NAMES = {"action.yml", "action.yaml"}
FULL_COMMIT = re.compile(r"[0-9a-f]{40}")
REGULAR_GIT_MODES = {"100644", "100755"}
ZERO_COMMIT = "0" * 40
MAX_PUBLIC_FILE_BYTES = 64 * 1024 * 1024
GIT_LFS_POINTER_HEADER = b"version https://git-lfs.github.com/spec/v1"


def _git(root: Path, *arguments: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(root), *arguments])


def _decode_path(value: bytes) -> str:
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("Git path is not valid UTF-8") from error


def public_files(root: Path = ROOT) -> list[Path]:
    """Return publishable working-tree paths without reading through them."""
    output = _git(
        root, "ls-files", "--cached", "--others", "--exclude-standard", "-z"
    )
    return sorted(
        {root / _decode_path(value) for value in output.split(b"\0") if value}
    )


def forbidden_namespace_path(relative: str) -> bool:
    parts = tuple(part.lower() for part in Path(relative).parts)
    return any(
        parts[index:index + len(forbidden)] == forbidden
        for forbidden in FORBIDDEN_PATH_PARTS
        for index in range(len(parts) - len(forbidden) + 1)
    )


def contains_local_host_path(text: str) -> bool:
    return any(pattern.search(text) for pattern in LOCAL_HOST_PATHS)


def _audit_bytes(label: str, relative: str, data: bytes, failures: list[str]) -> None:
    display = f"{label}:{relative}"
    if data.startswith(GIT_LFS_POINTER_HEADER):
        failures.append(f"Git LFS pointer is forbidden: {display}")
    suffix = Path(relative).suffix.lower()
    if suffix in FORBIDDEN_SUFFIXES:
        failures.append(f"forbidden artifact: {display}")
        return
    parts = tuple(part.lower() for part in Path(relative).parts)
    if ("tmessages" + "proj") in parts or forbidden_namespace_path(relative):
        failures.append(f"forbidden source tree or namespace: {display}")
        return
    if b"\0" in data or data.startswith((b"\x7fELF", b"PK\x03\x04", b"dex\n")):
        failures.append(f"unapproved binary: {display}")
        return
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        failures.append(f"non-UTF-8 public file: {display}")
        return
    lowered = text.lower()
    for forbidden in FORBIDDEN_TEXT:
        if forbidden.lower() in lowered:
            failures.append(f"forbidden client reference: {display}")
            break
    if contains_local_host_path(text):
        failures.append(f"absolute local host path: {display}")
    if (
        relative.startswith(".github/workflows/")
        or Path(relative).name.lower() in ACTION_METADATA_NAMES
    ):
        for reference in ACTION_USE.findall(text):
            if reference.startswith("./"):
                continue
            if "@" not in reference:
                failures.append(
                    f"unpinned GitHub Action in {display}: {reference}"
                )
                continue
            action, revision = reference.rsplit("@", 1)
            if not action or not FULL_COMMIT.fullmatch(revision):
                failures.append(
                    f"unpinned GitHub Action in {display}: {reference}"
                )
        if ("reactive" + "circus/android-emulator-runner") in text:
            failures.append(f"third-party emulator action: {display}")


def _audit_git_entry(
    root: Path,
    label: str,
    relative: str,
    mode: str,
    object_type: str,
    object_id: str,
    failures: list[str],
) -> None:
    display = f"{label}:{relative}"
    if mode == "120000":
        failures.append(f"symlink is forbidden: {display}")
        return
    if mode not in REGULAR_GIT_MODES or object_type != "blob":
        failures.append(
            f"unsupported Git entry {mode}/{object_type}: {display}"
        )
        return
    try:
        size = int(_git(root, "cat-file", "-s", object_id).decode("ascii").strip())
    except ValueError:
        failures.append(f"invalid Git blob size: {display}")
        return
    if size < 0 or size > MAX_PUBLIC_FILE_BYTES:
        failures.append(f"oversized public file: {display}")
        return
    _audit_bytes(label, relative, _git(root, "cat-file", "blob", object_id), failures)


def _audit_tree(
    root: Path, treeish: str, label: str, failures: list[str]
) -> int:
    output = _git(root, "ls-tree", "-r", "-z", "--full-tree", treeish)
    count = 0
    for record in output.split(b"\0"):
        if not record:
            continue
        count += 1
        try:
            metadata, raw_path = record.split(b"\t", 1)
            mode, object_type, object_id = metadata.decode("ascii").split()
            relative = _decode_path(raw_path)
        except (ValueError, UnicodeDecodeError):
            failures.append(f"malformed Git tree entry in {label}")
            continue
        _audit_git_entry(
            root, label, relative, mode, object_type, object_id, failures
        )
    return count


def _head_commit(root: Path) -> str | None:
    result = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--verify", "--quiet", "HEAD^{commit}"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    return result.stdout.strip() if result.returncode == 0 else None


def _audit_index(root: Path, failures: list[str]) -> int:
    output = _git(root, "ls-files", "--stage", "-z")
    count = 0
    for record in output.split(b"\0"):
        if not record:
            continue
        count += 1
        try:
            metadata, raw_path = record.split(b"\t", 1)
            mode, object_id, stage = metadata.decode("ascii").split()
            relative = _decode_path(raw_path)
        except (ValueError, UnicodeDecodeError):
            failures.append("malformed Git index entry")
            continue
        label = "index" if stage == "0" else f"index-stage-{stage}"
        if stage != "0":
            failures.append(f"unmerged Git index entry: {label}:{relative}")
        _audit_git_entry(root, label, relative, mode, "blob", object_id, failures)
    return count


def _read_regular_worktree_file(path: Path) -> bytes:
    before = path.lstat()
    if stat.S_ISLNK(before.st_mode):
        raise OSError("symlink")
    if not stat.S_ISREG(before.st_mode):
        raise OSError("not a regular file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        after = os.fstat(descriptor)
        if (
            not stat.S_ISREG(after.st_mode)
            or before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
        ):
            raise OSError("working-tree file changed during audit")
        if after.st_size < 0 or after.st_size > MAX_PUBLIC_FILE_BYTES:
            raise OSError("working-tree file exceeds the public size limit")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            data = stream.read(MAX_PUBLIC_FILE_BYTES + 1)
        if len(data) > MAX_PUBLIC_FILE_BYTES:
            raise OSError("working-tree file grew beyond the public size limit")
        return data
    finally:
        os.close(descriptor)


def _audit_worktree(root: Path, failures: list[str]) -> int:
    count = 0
    for path in public_files(root):
        relative = path.relative_to(root).as_posix()
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            # A tracked deletion has already been covered by HEAD/index/history.
            continue
        count += 1
        if stat.S_ISLNK(metadata.st_mode):
            failures.append(f"symlink is forbidden: working:{relative}")
            continue
        try:
            data = _read_regular_worktree_file(path)
        except OSError as error:
            failures.append(f"unreadable or non-regular file: working:{relative}: {error}")
            continue
        _audit_bytes("working", relative, data, failures)
    return count


def _validate_base(root: Path, value: str) -> str:
    if FULL_COMMIT.fullmatch(value) is None:
        raise ValueError("history base must be a full commit SHA")
    result = subprocess.run(
        ["git", "-C", str(root), "cat-file", "-e", f"{value}^{{commit}}"],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if result.returncode != 0:
        raise ValueError(f"history base is not available: {value}")
    return value


def _default_branch_merge_base(root: Path) -> str | None:
    candidates: list[str] = []
    configured = os.environ.get("EXITFY_AUDIT_DEFAULT_BRANCH", "")
    if configured and re.fullmatch(r"[A-Za-z0-9._/-]+", configured):
        candidates.extend((f"refs/remotes/origin/{configured}", configured))
    symbolic = subprocess.run(
        [
            "git", "-C", str(root), "symbolic-ref", "--quiet", "--short",
            "refs/remotes/origin/HEAD",
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    if symbolic.returncode == 0 and symbolic.stdout.strip():
        candidates.append(symbolic.stdout.strip())
    for candidate in dict.fromkeys(candidates):
        result = subprocess.run(
            ["git", "-C", str(root), "merge-base", "HEAD", candidate],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        value = result.stdout.strip()
        if result.returncode == 0 and FULL_COMMIT.fullmatch(value):
            return _validate_base(root, value)
    return None


def resolve_history_base(root: Path = ROOT) -> tuple[str | None, bool]:
    explicit = os.environ.get("EXITFY_AUDIT_BASE")
    if explicit:
        if explicit == ZERO_COMMIT:
            default_base = _default_branch_merge_base(root)
            return (default_base, False) if default_base is not None else (None, True)
        return _validate_base(root, explicit), False

    result = subprocess.run(
        [
            "git", "-C", str(root), "rev-parse", "--verify", "--quiet",
            "@{upstream}^{commit}",
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    if result.returncode == 0 and result.stdout.strip():
        return _validate_base(root, result.stdout.strip()), False
    default_base = _default_branch_merge_base(root)
    if default_base is not None:
        return default_base, False
    # A local branch with no upstream is commonly an initial push. Audit every
    # commit then; detached CI jobs without an explicit event base audit HEAD.
    return None, os.environ.get("GITHUB_ACTIONS") != "true"


def audit_repository(
    root: Path,
    history_base: str | None = None,
    scan_all_history: bool = False,
) -> tuple[list[str], int]:
    failures: list[str] = []
    count = 0
    head = _head_commit(root)
    if head is not None:
        count += _audit_tree(root, head, "HEAD", failures)
    count += _audit_index(root, failures)
    count += _audit_worktree(root, failures)

    commits: list[str] = []
    if head is not None and history_base is not None:
        _validate_base(root, history_base)
        commits = _git(root, "rev-list", "--reverse", f"{history_base}..{head}").decode(
            "ascii"
        ).split()
    elif head is not None and scan_all_history:
        commits = _git(root, "rev-list", "--reverse", head).decode("ascii").split()
    for commit in commits:
        if commit == head:
            continue
        count += _audit_tree(root, commit, f"commit-{commit[:12]}", failures)
    return sorted(set(failures)), count


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=ROOT)
    args = parser.parse_args()
    try:
        root = args.repo_root.resolve(strict=True)
        if not stat.S_ISDIR(root.lstat().st_mode):
            raise ValueError("public repository root is not a directory")
        history_base, scan_all_history = resolve_history_base(root)
        failures, count = audit_repository(root, history_base, scan_all_history)
    except (OSError, subprocess.CalledProcessError, ValueError) as error:
        raise SystemExit(f"public-tree audit failed:\n{error}") from error
    if failures:
        raise SystemExit("public-tree audit failed:\n" + "\n".join(failures))
    print(f"public-tree audit passed: {count} exact Git/working entries")


if __name__ == "__main__":
    main()
