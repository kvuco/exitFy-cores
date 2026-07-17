#!/usr/bin/env python3
from __future__ import annotations

import argparse
import contextlib
import errno
import fcntl
import gzip
import hashlib
import json
import os
import re
import selectors
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parents[1]
BUILD_TAGS = "with_quic,with_utls,badlinkname,tfogo_checklinkname0"
SOURCE_FIELDS = (
    "GoFiles", "CgoFiles", "CFiles", "CXXFiles", "MFiles", "HFiles",
    "FFiles", "SFiles", "SwigFiles", "SwigCXXFiles", "SysoFiles",
    "EmbedFiles",
)
REQUIRED_SECURE_OPEN_FLAGS = (
    "O_DIRECTORY",
    "O_NOFOLLOW",
    "O_CLOEXEC",
    "O_NONBLOCK",
    "O_CREAT",
    "O_EXCL",
    "O_RDWR",
    "O_WRONLY",
)
COPY_BUFFER_BYTES = 1024 * 1024
MAX_PUBLIC_FILE_BYTES = 64 * 1024 * 1024
MAX_SOURCE_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_PUBLIC_TREE_BYTES = MAX_SOURCE_ARCHIVE_BYTES
MAX_ARCHIVE_FILES = 50_000
MAX_ARCHIVE_DIRECTORIES = 50_000
MAX_ARCHIVE_PATH_BYTES = 4 * 1024
MAX_RETAINED_PATH_BYTES = 16 * 1024 * 1024
MAX_DIRECTORY_ENTRIES = MAX_ARCHIVE_FILES + MAX_ARCHIVE_DIRECTORIES
MAX_GO_JSON_DOCUMENTS = 100_000
MAX_GIT_OUTPUT_BYTES = 64 * 1024 * 1024
MAX_GO_OUTPUT_BYTES = 64 * 1024 * 1024
MAX_COMMAND_DIAGNOSTIC_BYTES = 4 * 1024
COMMAND_READ_CHUNK_BYTES = 64 * 1024
COMMAND_POLL_SECONDS = 0.05
COMMAND_DRAIN_SECONDS = 2.0
COMMAND_REAP_TIMEOUT_SECONDS = 5.0
GIT_COMMAND_TIMEOUT_SECONDS = 60.0
GO_COMMAND_TIMEOUT_SECONDS = 300.0
SOURCE_FINGERPRINT_FIELDS = (
    "st_dev",
    "st_ino",
    "st_mode",
    "st_nlink",
    "st_size",
    "st_mtime_ns",
    "st_ctime_ns",
)
VALIDATED_WORKTREE_PIN_PATHS = frozenset(
    {
        PurePosixPath("singbox/go.mod"),
        PurePosixPath("singbox/go.sum"),
    }
)
INDEX_DEBUG_METADATA = re.compile(
    rb"  ctime: [0-9]+:[0-9]+\n"
    rb"  mtime: [0-9]+:[0-9]+\n"
    rb"  dev: [0-9]+\tino: [0-9]+\n"
    rb"  uid: [0-9]+\tgid: [0-9]+\n"
    rb"  size: [0-9]+\tflags: ([0-9a-fA-F]+)\n"
)
FULL_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
SHA256_HEX = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True)
class PublicArchiveEntry:
    sha256: str
    size: int
    mode: int


@dataclass(frozen=True)
class GitIndexEntry:
    object_id: str
    mode: int
    hash_name: str


@dataclass(frozen=True)
class PinnedGitRepository:
    root_descriptor: int
    git_descriptor: int
    index_descriptor: int
    directory_flags: int
    leaf_flags: int
    root_fingerprint: tuple[int, ...]
    git_fingerprint: tuple[int, ...]
    index_fingerprint: tuple[int, ...]


GIT_FCHDIR_HELPER = (
    "import os,sys; "
    "descriptor=int(sys.argv[1]); "
    "os.fchdir(descriptor); "
    "os.close(descriptor); "
    "os.execv(sys.argv[2],sys.argv[2:])"
)


def sanitized_search_path(environment: dict[str, str]) -> str:
    values: list[str] = []
    seen: set[str] = set()
    root = ROOT.resolve(strict=False)
    for raw in environment.get("PATH", "").split(os.pathsep):
        candidate = Path(raw)
        if not raw or not candidate.is_absolute():
            continue
        try:
            resolved = candidate.resolve(strict=True)
        except OSError:
            continue
        if not resolved.is_dir():
            continue
        try:
            resolved.relative_to(root)
        except ValueError:
            pass
        else:
            continue
        value = str(resolved)
        if value not in seen:
            seen.add(value)
            values.append(value)
    if not values:
        raise ValueError("trusted executable search path is empty")
    return os.pathsep.join(values)


def trusted_tool_path(name: str, environment: dict[str, str]) -> str:
    if name not in {"git", "go"}:
        raise ValueError("unsupported trusted tool")
    candidate = shutil.which(name, path=environment.get("PATH"))
    if candidate is None:
        raise ValueError(f"trusted {name} executable is unavailable")
    try:
        resolved = Path(candidate).resolve(strict=True)
        metadata = os.stat(resolved, follow_symlinks=False)
    except OSError as error:
        raise ValueError(f"trusted {name} executable cannot be resolved") from error
    if (
        not resolved.is_absolute()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_mode & 0o111 == 0
        or not os.access(resolved, os.X_OK)
    ):
        raise ValueError(f"trusted {name} executable is unsafe")
    return str(resolved)


def sanitized_base_environment(
    source: dict[str, str],
) -> dict[str, str]:
    forbidden = {
        "BASH_ENV",
        "CDPATH",
        "ENV",
        "LD_AUDIT",
        "LD_LIBRARY_PATH",
        "LD_PRELOAD",
        "PYTHONHOME",
        "PYTHONPATH",
    }
    environment = {
        key: value
        for key, value in source.items()
        if key not in forbidden and not key.startswith("DYLD_")
    }
    environment["PATH"] = sanitized_search_path(environment)
    return environment


def sanitized_git_environment() -> dict[str, str]:
    base = sanitized_base_environment(dict(os.environ))
    environment = {
        key: value
        for key, value in base.items()
        if not key.startswith("GIT_")
    }
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": "/dev/null",
            "GIT_CONFIG_COUNT": "3",
            "GIT_CONFIG_KEY_0": "core.fsmonitor",
            "GIT_CONFIG_VALUE_0": "false",
            "GIT_CONFIG_KEY_1": "core.hooksPath",
            "GIT_CONFIG_VALUE_1": "/dev/null",
            "GIT_CONFIG_KEY_2": "core.fileMode",
            "GIT_CONFIG_VALUE_2": "true",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "LC_ALL": "C",
        }
    )
    return environment


def sanitized_go_environment(
    environment: dict[str, str],
) -> dict[str, str]:
    source = dict(environment)
    source.setdefault("PATH", os.environ.get("PATH", ""))
    sanitized = sanitized_base_environment(source)
    for key in tuple(sanitized):
        if (
            key in {
                "AR",
                "CC",
                "CXX",
                "FC",
                "GCCGO",
                "GOROOT",
                "PKG_CONFIG",
            }
            or key.startswith("CGO_")
            or key.startswith("GIT_")
        ):
            sanitized.pop(key, None)
    sanitized.update(
        {
            "GO111MODULE": "on",
            "GOENV": "off",
            "GOFLAGS": "",
            "GOTOOLCHAIN": "local",
            "GOWORK": "off",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": "/dev/null",
            "GIT_CONFIG_COUNT": "3",
            "GIT_CONFIG_KEY_0": "core.fsmonitor",
            "GIT_CONFIG_VALUE_0": "false",
            "GIT_CONFIG_KEY_1": "core.hooksPath",
            "GIT_CONFIG_VALUE_1": "/dev/null",
            "GIT_CONFIG_KEY_2": "core.fileMode",
            "GIT_CONFIG_VALUE_2": "true",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    return sanitized


def command_error_detail(payload: bytes) -> str:
    decoded = payload[:MAX_COMMAND_DIAGNOSTIC_BYTES].decode(
        "utf-8", "replace"
    )
    cleaned = " ".join(
        "".join(
            character if character.isprintable() else " "
            for character in decoded
        ).split()
    )
    return cleaned or "no diagnostic output"


class ProcessOwnershipLost(ValueError):
    pass


@dataclass(frozen=True)
class PinnedExecutable:
    path: str
    descriptor: int
    fingerprint: tuple[int, ...]


def executable_fingerprint(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_mode),
        int(metadata.st_size),
        int(metadata.st_mtime_ns),
        int(metadata.st_ctime_ns),
    )


def pin_exact_executable(value: str) -> PinnedExecutable:
    # A POSIX process group cannot contain a descendant which deliberately
    # calls setsid(). The release boundary is therefore the fixed executable
    # identity and sanitized arguments/environment, not an impossible claim
    # that arbitrary child code can always be reclaimed.
    candidate = Path(value)
    if not candidate.is_absolute():
        raise ValueError("bounded subprocess requires an absolute executable")
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as error:
        raise ValueError("bounded subprocess executable cannot be resolved") from error
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if nofollow == 0:
        raise ValueError("bounded subprocess requires POSIX O_NOFOLLOW")
    try:
        descriptor = os.open(resolved, flags | nofollow)
    except OSError as error:
        raise ValueError("bounded subprocess executable cannot be pinned") from error
    try:
        metadata = os.fstat(descriptor)
        path_metadata = os.stat(resolved, follow_symlinks=False)
        fingerprint = executable_fingerprint(metadata)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_mode & 0o111 == 0
            or executable_fingerprint(path_metadata) != fingerprint
        ):
            raise ValueError("bounded subprocess executable is unsafe")
        return PinnedExecutable(str(resolved), descriptor, fingerprint)
    except BaseException:
        os.close(descriptor)
        raise


def verify_pinned_executable(executable: PinnedExecutable) -> None:
    try:
        descriptor_metadata = os.fstat(executable.descriptor)
        path_metadata = os.stat(executable.path, follow_symlinks=False)
    except OSError as error:
        raise ValueError("bounded subprocess executable changed") from error
    if (
        executable_fingerprint(descriptor_metadata) != executable.fingerprint
        or executable_fingerprint(path_metadata) != executable.fingerprint
    ):
        raise ValueError("bounded subprocess executable changed")


def command_leader_exited(process: subprocess.Popen[bytes]) -> bool:
    try:
        status = os.waitid(
            os.P_PID,
            process.pid,
            os.WEXITED | os.WNOHANG | os.WNOWAIT,
        )
    except ChildProcessError as error:
        raise ProcessOwnershipLost(
            "subprocess leader ownership was lost"
        ) from error
    return status is not None


def command_group_exists(group: int) -> bool:
    try:
        os.killpg(group, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def terminate_command_group(
    process: subprocess.Popen[bytes],
    *,
    leader_exited: bool = False,
) -> OSError | None:
    group = process.pid
    if not leader_exited:
        try:
            current_group = os.getpgid(process.pid)
        except ProcessLookupError:
            if not command_leader_exited(process):
                raise ProcessOwnershipLost(
                    "subprocess group ownership was lost"
                )
            leader_exited = True
            current_group = group
        except OSError as error:
            raise ValueError(
                "subprocess group identity could not be verified"
            ) from error
        if current_group != group:
            raise ValueError("subprocess escaped its owned process group")
    try:
        os.killpg(group, signal.SIGKILL)
    except ProcessLookupError:
        return
    except OSError as error:
        if leader_exited and error.errno in {errno.ESRCH, errno.EPERM}:
            return error
        raise ValueError("subprocess group could not be terminated") from error
    return None


def finalize_command_group(
    process: subprocess.Popen[bytes],
    *,
    leader_exited: bool,
) -> int:
    kill_error = terminate_command_group(
        process, leader_exited=leader_exited
    )
    try:
        return_code = process.wait(timeout=COMMAND_REAP_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired as error:
        raise ValueError("subprocess leader could not be reaped") from error
    if kill_error is not None and command_group_exists(process.pid):
        raise ValueError("subprocess group could not be killed") from kill_error
    return return_code


def bounded_command_output(
    command: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    pass_fds: tuple[int, ...] = (),
    max_output_bytes: int,
    timeout_seconds: float,
) -> bytes:
    if (
        os.name != "posix"
        or not hasattr(os, "waitid")
        or not hasattr(os, "killpg")
        or not hasattr(os, "P_PID")
        or not hasattr(os, "WEXITED")
        or not hasattr(os, "WNOHANG")
        or not hasattr(os, "WNOWAIT")
        or signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL
    ):
        raise ValueError(
            "bounded subprocess execution requires POSIX process groups and waitid"
        )
    if (
        not command
        or max_output_bytes < 0
        or timeout_seconds <= 0
        or any(type(value) is not str or not value for value in command)
    ):
        raise ValueError("invalid bounded subprocess request")

    executable = pin_exact_executable(command[0])
    command = [executable.path, *command[1:]]

    try:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            close_fds=True,
            pass_fds=pass_fds,
        )
    except OSError as error:
        os.close(executable.descriptor)
        raise ValueError(f"subprocess could not start: {command[0]}") from error
    except BaseException:
        os.close(executable.descriptor)
        raise
    try:
        verify_pinned_executable(executable)
    except BaseException:
        try:
            process.kill()
            process.wait(timeout=COMMAND_REAP_TIMEOUT_SECONDS)
        finally:
            os.close(executable.descriptor)
        raise

    if process.stdout is None or process.stderr is None:
        failure = ValueError("subprocess pipes could not be created")
        try:
            leader_exited = command_leader_exited(process)
            finalize_command_group(
                process, leader_exited=leader_exited
            )
        except BaseException as cleanup_error:
            if hasattr(failure, "add_note"):
                failure.add_note(
                    f"subprocess cleanup also failed: {cleanup_error}"
                )
        finally:
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()
            os.close(executable.descriptor)
        raise failure

    selector = selectors.DefaultSelector()
    stdout = bytearray()
    stderr = bytearray()
    total = 0
    failure: str | None = None
    leader_exited = False
    ownership_lost = False
    deadline = time.monotonic() + timeout_seconds
    streams = {
        process.stdout.fileno(): (process.stdout, stdout),
        process.stderr.fileno(): (process.stderr, stderr),
    }
    try:
        for descriptor, (stream, _target) in streams.items():
            os.set_blocking(descriptor, False)
            selector.register(stream, selectors.EVENT_READ)

        while not leader_exited and failure is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                failure = "subprocess timed out"
                break
            for key, _mask in selector.select(
                min(COMMAND_POLL_SECONDS, remaining)
            ):
                descriptor = key.fileobj.fileno()
                try:
                    chunk = os.read(descriptor, COMMAND_READ_CHUNK_BYTES)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                total += len(chunk)
                if total > max_output_bytes:
                    failure = "subprocess output exceeds bounded limit"
                    break
                streams[descriptor][1].extend(chunk)

            try:
                leader_exited = command_leader_exited(process)
            except ProcessOwnershipLost:
                ownership_lost = True
                raise
            if time.monotonic() >= deadline:
                failure = "subprocess timed out"

        if not leader_exited:
            try:
                leader_exited = command_leader_exited(process)
            except ProcessOwnershipLost:
                ownership_lost = True
                raise
        return_code = finalize_command_group(
            process, leader_exited=leader_exited
        )
        verify_pinned_executable(executable)

        drain_deadline = time.monotonic() + COMMAND_DRAIN_SECONDS
        while selector.get_map() and time.monotonic() < drain_deadline:
            for key, _mask in selector.select(COMMAND_POLL_SECONDS):
                descriptor = key.fileobj.fileno()
                try:
                    chunk = os.read(descriptor, COMMAND_READ_CHUNK_BYTES)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                total += len(chunk)
                if failure is None and total > max_output_bytes:
                    failure = "subprocess output exceeds bounded limit"
                if total <= max_output_bytes:
                    streams[descriptor][1].extend(chunk)
        if selector.get_map() and failure is None:
            failure = "subprocess descendants retained output pipes"

        if failure is not None:
            raise ValueError(failure)
        if return_code != 0:
            raise ValueError(
                f"subprocess failed ({return_code}): "
                f"{command_error_detail(bytes(stderr))}"
            )
        return bytes(stdout)
    except BaseException as primary_error:
        if process.returncode is None and not ownership_lost:
            try:
                if not leader_exited:
                    leader_exited = command_leader_exited(process)
                finalize_command_group(
                    process, leader_exited=leader_exited
                )
            except ProcessOwnershipLost as cleanup_error:
                ownership_lost = True
                if hasattr(primary_error, "add_note"):
                    primary_error.add_note(str(cleanup_error))
            except BaseException as cleanup_error:
                if hasattr(primary_error, "add_note"):
                    primary_error.add_note(
                        f"subprocess cleanup also failed: {cleanup_error}"
                    )
        raise
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()
        os.close(executable.descriptor)


def verify_pinned_git(repository: PinnedGitRepository) -> None:
    if (
        source_fingerprint(os.fstat(repository.root_descriptor))
        != repository.root_fingerprint
        or source_fingerprint(os.fstat(repository.git_descriptor))
        != repository.git_fingerprint
        or source_fingerprint(os.fstat(repository.index_descriptor))
        != repository.index_fingerprint
    ):
        raise ValueError(
            "source bundle root or .git changed, or index changed during Git scan"
        )
    try:
        reopened = os.open(
            ".git",
            repository.directory_flags,
            dir_fd=repository.root_descriptor,
        )
    except OSError as error:
        raise ValueError("source bundle requires a direct .git directory") from error
    try:
        if source_fingerprint(os.fstat(reopened)) != repository.git_fingerprint:
            raise ValueError("source bundle .git path changed during Git scan")
    finally:
        os.close(reopened)
    try:
        reopened_index = os.open(
            "index",
            repository.leaf_flags,
            dir_fd=repository.git_descriptor,
        )
    except OSError as error:
        raise ValueError(
            "source bundle requires a direct regular .git/index"
        ) from error
    try:
        metadata = os.fstat(reopened_index)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or source_fingerprint(metadata) != repository.index_fingerprint
        ):
            raise ValueError(
                "source bundle .git/index path changed during Git scan"
            )
    finally:
        os.close(reopened_index)


def pinned_git_repository(
    root_descriptor: int,
    directory_flags: int,
    leaf_flags: int,
) -> PinnedGitRepository:
    try:
        git_descriptor = os.open(
            ".git", directory_flags, dir_fd=root_descriptor
        )
    except OSError as error:
        raise ValueError(
            "source bundle requires a direct non-symlink .git directory"
        ) from error
    try:
        index_descriptor = os.open(
            "index", leaf_flags, dir_fd=git_descriptor
        )
    except OSError as error:
        os.close(git_descriptor)
        raise ValueError(
            "source bundle requires a direct regular .git/index"
        ) from error
    try:
        index_metadata = os.fstat(index_descriptor)
        if (
            not stat.S_ISREG(index_metadata.st_mode)
            or index_metadata.st_nlink != 1
        ):
            raise ValueError(
                "source bundle requires a direct regular .git/index"
            )
        repository = PinnedGitRepository(
            root_descriptor=root_descriptor,
            git_descriptor=git_descriptor,
            index_descriptor=index_descriptor,
            directory_flags=directory_flags,
            leaf_flags=leaf_flags,
            root_fingerprint=source_fingerprint(os.fstat(root_descriptor)),
            git_fingerprint=source_fingerprint(os.fstat(git_descriptor)),
            index_fingerprint=source_fingerprint(index_metadata),
        )
        verify_pinned_git(repository)
        return repository
    except BaseException:
        try:
            os.close(index_descriptor)
        finally:
            os.close(git_descriptor)
        raise


def close_pinned_git(repository: PinnedGitRepository) -> None:
    try:
        os.close(repository.index_descriptor)
    finally:
        os.close(repository.git_descriptor)


def verify_expected_git_state(
    repository: PinnedGitRepository, expected_head: str
) -> None:
    if FULL_COMMIT.fullmatch(expected_head) is None:
        raise ValueError("source bundle expected HEAD is invalid")
    head = pinned_git_command_output(
        repository,
        "rev-parse",
        "--verify",
        "HEAD^{commit}",
        max_output_bytes=128,
    )
    try:
        actual_head = head.decode("ascii", "strict").strip()
    except UnicodeDecodeError as error:
        raise ValueError("source bundle Git HEAD is malformed") from error
    if actual_head != expected_head:
        raise ValueError("source bundle Git HEAD moved away from the expected commit")
    staged = pinned_git_command_output(
        repository,
        "diff",
        "--no-ext-diff",
        "--cached",
        "--name-only",
        "-z",
        expected_head,
        "--",
    )
    if staged:
        raise ValueError("source bundle Git index differs from the expected commit")


def pinned_git_command_output(
    repository: PinnedGitRepository,
    *arguments: str,
    max_output_bytes: int = MAX_GIT_OUTPUT_BYTES,
) -> bytes:
    verify_pinned_git(repository)
    environment = sanitized_git_environment()
    git_executable = trusted_tool_path("git", environment)
    output = bounded_command_output(
        [
            sys.executable,
            "-I",
            "-c",
            GIT_FCHDIR_HELPER,
            str(repository.root_descriptor),
            git_executable,
            "--no-pager",
            "--git-dir=.git",
            "--work-tree=.",
            "-c",
            "core.excludesFile=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fileMode=true",
            "-c",
            "core.untrackedCache=false",
            *arguments,
        ],
        pass_fds=(repository.root_descriptor,),
        env=environment,
        max_output_bytes=max_output_bytes,
        timeout_seconds=GIT_COMMAND_TIMEOUT_SECONDS,
    )
    verify_pinned_git(repository)
    return output


def reject_split_index(repository: PinnedGitRepository) -> None:
    output = pinned_git_command_output(
        repository,
        "rev-parse",
        "--shared-index-path",
        max_output_bytes=MAX_ARCHIVE_PATH_BYTES,
    )
    try:
        shared_index_path = output.decode("utf-8", "strict").strip()
    except UnicodeDecodeError as error:
        raise ValueError("Git shared-index path is not valid UTF-8") from error
    if "\0" in shared_index_path or "\n" in shared_index_path:
        raise ValueError("Git returned a malformed shared-index path")
    if shared_index_path:
        raise ValueError(
            "split Git index is not supported for reproducible source bundles"
        )


def git_index_entries(
    repository: PinnedGitRepository,
) -> dict[PurePosixPath, GitIndexEntry]:
    reject_split_index(repository)
    output = pinned_git_command_output(
        repository,
        "ls-files",
        "-v",
        "--stage",
        "--debug",
        "-z",
        "--",
    )
    reject_split_index(repository)
    values: dict[PurePosixPath, GitIndexEntry] = {}
    offset = 0
    retained_bytes = 0
    records = 0
    while offset < len(output):
        end = output.find(b"\0", offset)
        if end < 0:
            raise ValueError("git returned malformed index metadata")
        header = output[offset:end]
        debug = INDEX_DEBUG_METADATA.match(output, end + 1)
        if debug is None:
            raise ValueError("git returned malformed index debug metadata")
        offset = debug.end()
        try:
            metadata, raw_path = header.split(b"\t", 1)
            tag, raw_mode, raw_object_id, raw_stage = metadata.split(b" ")
        except ValueError as error:
            raise ValueError("git returned malformed index entry") from error
        if tag != b"H":
            raise ValueError("Git index contains non-default entry flags")
        try:
            flags = int(debug.group(1), 16)
        except ValueError as error:
            raise ValueError("git returned malformed index flags") from error
        if flags != 0:
            raise ValueError("Git index contains non-default entry flags")
        if raw_stage != b"0":
            raise ValueError("Git index contains an unmerged entry")
        if raw_mode not in {b"100644", b"100755"}:
            raise ValueError("Git index contains a non-regular public entry")
        if re.fullmatch(rb"[0-9a-f]{40}|[0-9a-f]{64}", raw_object_id) is None:
            raise ValueError("Git index contains an invalid object id")
        relative = public_relative_path(raw_path)
        records += 1
        retained_bytes += len(raw_path)
        if records > MAX_ARCHIVE_FILES:
            raise ValueError(
                f"public Git file set exceeds {MAX_ARCHIVE_FILES} files"
            )
        if retained_bytes > MAX_RETAINED_PATH_BYTES:
            raise ValueError("public Git file paths exceed the retained-name limit")
        if relative in values:
            raise ValueError("Git index contains a duplicate public entry")
        object_id = raw_object_id.decode("ascii")
        values[relative] = GitIndexEntry(
            object_id=object_id,
            mode=int(raw_mode, 8),
            hash_name="sha1" if len(object_id) == 40 else "sha256",
        )
    return values


def git_file_set(
    repository: PinnedGitRepository,
    *arguments: str,
) -> set[bytes]:
    if arguments != ("--cached",):
        raise ValueError("unsupported Git public file query")
    return {
        relative.as_posix().encode("utf-8", "strict")
        for relative in git_index_entries(repository)
    }


def public_relative_path(raw: bytes) -> PurePosixPath:
    if len(raw) > MAX_ARCHIVE_PATH_BYTES:
        raise ValueError(
            f"public file path exceeds {MAX_ARCHIVE_PATH_BYTES} bytes"
        )
    try:
        value = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("public file path is not valid UTF-8") from error
    parts = value.split("/")
    if (
        not value
        or value.startswith("/")
        or any(part in {"", ".", ".."} for part in parts)
        or parts[0] == ".git"
        or len(parts) > 128
    ):
        raise ValueError(f"unsafe public file path: {value!r}")
    return PurePosixPath(value)


def public_files(
    repository: PinnedGitRepository | None = None,
    leaf_flags: int | None = None,
) -> list[PurePosixPath]:
    if repository is None:
        directory_flags, default_leaf_flags, _ = secure_open_flags()
        if leaf_flags is None:
            leaf_flags = default_leaf_flags
        try:
            owned_root = os.open(ROOT, directory_flags)
        except OSError as error:
            raise ValueError(
                "source bundle root cannot be opened securely"
            ) from error
        owned_repository: PinnedGitRepository | None = None
        try:
            owned_repository = pinned_git_repository(
                owned_root, directory_flags, leaf_flags
            )
            identity = source_root_identity(os.fstat(owned_root))
            verify_source_root_path(identity)
            files = public_files_from_descriptor(
                owned_repository, leaf_flags
            )
            verify_pinned_git(owned_repository)
            verify_source_root_path(identity)
            return files
        finally:
            if owned_repository is not None:
                close_pinned_git(owned_repository)
            os.close(owned_root)

    if leaf_flags is None:
        directory_flags, leaf_flags, _ = secure_open_flags()
        if directory_flags != repository.directory_flags:
            raise ValueError("pinned Git directory flags changed")
    return public_files_from_descriptor(
        repository, leaf_flags
    )


def public_files_from_descriptor(
    repository: PinnedGitRepository,
    leaf_flags: int,
) -> list[PurePosixPath]:

    listed = git_file_set(repository, "--cached")
    if len(listed) > MAX_ARCHIVE_FILES:
        raise ValueError(
            f"public Git file set exceeds {MAX_ARCHIVE_FILES} files"
        )
    if sum(len(raw) for raw in listed) > MAX_RETAINED_PATH_BYTES:
        raise ValueError("public Git file paths exceed the retained-name limit")
    files: list[PurePosixPath] = []
    directories: set[PurePosixPath] = set()
    retained_path_bytes = sum(len(raw) for raw in listed)
    for raw in listed:
        relative = public_relative_path(raw)
        for index in range(1, len(relative.parts)):
            directory = PurePosixPath(*relative.parts[:index])
            if directory in directories:
                continue
            directories.add(directory)
            retained_path_bytes += len(
                directory.as_posix().encode("utf-8", "strict")
            )
            if len(directories) > MAX_ARCHIVE_DIRECTORIES:
                raise ValueError(
                    "public Git file set exceeds the directory limit"
                )
            if retained_path_bytes > MAX_RETAINED_PATH_BYTES:
                raise ValueError(
                    "public Git file paths exceed the retained-name limit"
                )
        descriptor, _ = open_public_file(
            repository.root_descriptor,
            relative,
            repository.directory_flags,
            leaf_flags,
        )
        os.close(descriptor)
        files.append(relative)
    return sorted(files, key=PurePosixPath.as_posix)


def secure_open_flags() -> tuple[int, int, int]:
    dir_fd_functions = (os.open, os.mkdir, os.stat, os.unlink, os.link)
    supported = getattr(os, "supports_dir_fd", ())
    if (
        os.name != "posix"
        or any(function not in supported for function in dir_fd_functions)
        or os.scandir not in getattr(os, "supports_fd", ())
        or os.stat not in getattr(os, "supports_follow_symlinks", ())
        or os.link not in getattr(os, "supports_follow_symlinks", ())
        or not hasattr(os, "fchmod")
    ):
        raise ValueError(
            "source bundle requires POSIX dir_fd/scandir descriptor support"
        )
    values: dict[str, int] = {}
    for name in REQUIRED_SECURE_OPEN_FLAGS:
        value = getattr(os, name, None)
        if type(value) is not int or value == 0:
            raise ValueError(f"source bundle requires POSIX {name}")
        values[name] = value
    directory_flags = (
        os.O_RDONLY
        | values["O_DIRECTORY"]
        | values["O_NOFOLLOW"]
        | values["O_CLOEXEC"]
    )
    leaf_flags = (
        os.O_RDONLY
        | values["O_NOFOLLOW"]
        | values["O_CLOEXEC"]
        | values["O_NONBLOCK"]
    )
    destination_flags = (
        values["O_WRONLY"]
        | values["O_CREAT"]
        | values["O_EXCL"]
        | values["O_NOFOLLOW"]
        | values["O_CLOEXEC"]
    )
    return directory_flags, leaf_flags, destination_flags


def open_public_file(
    root_descriptor: int,
    relative: PurePosixPath,
    directory_flags: int,
    leaf_flags: int,
) -> tuple[int, os.stat_result]:
    descriptor: int | None = None
    try:
        with contextlib.ExitStack() as parents:
            parent_descriptor = root_descriptor
            for part in relative.parts[:-1]:
                parent_descriptor = os.open(
                    part, directory_flags, dir_fd=parent_descriptor
                )
                parents.callback(os.close, parent_descriptor)
            descriptor = os.open(
                relative.name, leaf_flags, dir_fd=parent_descriptor
            )
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError(
                    f"source bundle requires a regular file: {relative}"
                )
    except OSError as error:
        if descriptor is not None:
            os.close(descriptor)
        raise ValueError(
            f"listed public file changed or is unsafe: {relative}"
        ) from error
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
        raise
    return descriptor, metadata


def source_fingerprint(metadata: os.stat_result) -> tuple[int, ...]:
    try:
        return tuple(
            int(getattr(metadata, field)) for field in SOURCE_FINGERPRINT_FIELDS
        )
    except (AttributeError, TypeError, ValueError) as error:
        raise ValueError("source filesystem lacks stable file metadata") from error


def source_root_identity(metadata: os.stat_result) -> tuple[int, int]:
    if not stat.S_ISDIR(metadata.st_mode):
        raise ValueError("source bundle root is not a directory")
    try:
        return int(metadata.st_dev), int(metadata.st_ino)
    except (AttributeError, TypeError, ValueError) as error:
        raise ValueError(
            "source filesystem lacks stable root identity"
        ) from error


def verify_source_root_path(expected: tuple[int, int]) -> None:
    try:
        metadata = ROOT.lstat()
    except OSError as error:
        raise ValueError("source bundle root changed during source copy") from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or source_root_identity(metadata) != expected
    ):
        raise ValueError("source bundle root changed during source copy")


def copy_descriptor_bytes(
    source: int,
    destination: int,
    expected_size: int,
    digest=None,
) -> int:
    total = 0
    while total <= expected_size:
        remaining_limit = expected_size + 1 - total
        chunk = os.read(source, min(COPY_BUFFER_BYTES, remaining_limit))
        if not chunk:
            return total
        total += len(chunk)
        if digest is not None:
            digest.update(chunk)
        remaining = memoryview(chunk)
        while remaining:
            written = os.write(destination, remaining)
            if written <= 0:
                raise OSError("destination write made no progress")
            remaining = remaining[written:]
    return total


class DigestFanout:
    def __init__(self, *digests) -> None:
        self.digests = digests

    def update(self, payload: bytes) -> None:
        for digest in self.digests:
            digest.update(payload)


def verify_worktree_index_mode(
    relative: PurePosixPath,
    metadata: os.stat_result,
    expected: GitIndexEntry,
) -> None:
    actual = 0o100755 if metadata.st_mode & stat.S_IXUSR else 0o100644
    if actual != expected.mode:
        raise ValueError(f"public worktree mode differs from Git index: {relative}")


def verify_source_metadata(
    relative: PurePosixPath,
    expected: tuple[int, ...],
    metadata: os.stat_result,
    bytes_read: int | None = None,
) -> None:
    if source_fingerprint(metadata) != expected or (
        bytes_read is not None
        and bytes_read != expected[SOURCE_FINGERPRINT_FIELDS.index("st_size")]
    ):
        raise ValueError(f"public source changed while it was copied: {relative}")


def copy_public_entry(
    source_root: int,
    target_root: int,
    relative: PurePosixPath,
    directory_flags: int,
    leaf_flags: int,
    destination_flags: int,
    remaining_tree_bytes: int,
    expected_index: GitIndexEntry,
) -> tuple[tuple[int, ...], int, PublicArchiveEntry]:
    source_descriptor, source_metadata = open_public_file(
        source_root, relative, directory_flags, leaf_flags
    )
    try:
        expected = source_fingerprint(source_metadata)
        verify_worktree_index_mode(relative, source_metadata, expected_index)
        expected_size = expected[SOURCE_FINGERPRINT_FIELDS.index("st_size")]
        if expected_size < 0 or expected_size > MAX_PUBLIC_FILE_BYTES:
            raise ValueError(
                f"public source exceeds the {MAX_PUBLIC_FILE_BYTES}-byte "
                f"per-file limit: {relative}"
            )
        if expected_size > remaining_tree_bytes:
            raise ValueError(
                f"public source tree exceeds the {MAX_PUBLIC_TREE_BYTES}-byte "
                f"limit at: {relative}"
            )
        with contextlib.ExitStack() as destination_parents:
            destination_parent = target_root
            for part in relative.parts[:-1]:
                try:
                    os.mkdir(part, 0o755, dir_fd=destination_parent)
                except FileExistsError:
                    pass
                destination_parent = os.open(
                    part, directory_flags, dir_fd=destination_parent
                )
                destination_parents.callback(os.close, destination_parent)
                os.fchmod(destination_parent, 0o755)

            destination_descriptor: int | None = None
            created = False
            try:
                destination_descriptor = os.open(
                    relative.name,
                    destination_flags,
                    0o600,
                    dir_fd=destination_parent,
                )
                created = True
                digest = hashlib.sha256()
                index_digest = hashlib.new(expected_index.hash_name)
                index_digest.update(f"blob {expected_size}\0".encode("ascii"))
                bytes_read = copy_descriptor_bytes(
                    source_descriptor,
                    destination_descriptor,
                    expected_size,
                    DigestFanout(digest, index_digest),
                )
                verify_source_metadata(
                    relative,
                    expected,
                    os.fstat(source_descriptor),
                    bytes_read,
                )
                if (
                    relative not in VALIDATED_WORKTREE_PIN_PATHS
                    and index_digest.hexdigest() != expected_index.object_id
                ):
                    raise ValueError(
                        f"public worktree content differs from Git index: {relative}"
                    )

                reopened, reopened_metadata = open_public_file(
                    source_root, relative, directory_flags, leaf_flags
                )
                try:
                    verify_source_metadata(relative, expected, reopened_metadata)
                    verify_worktree_index_mode(
                        relative, reopened_metadata, expected_index
                    )
                finally:
                    os.close(reopened)

                normalized_mode = (
                    0o755 if expected_index.mode == 0o100755 else 0o644
                )
                os.fchmod(destination_descriptor, normalized_mode)
                completed_descriptor = destination_descriptor
                destination_descriptor = None
                os.close(completed_descriptor)
            except BaseException:
                failed_descriptor = destination_descriptor
                destination_descriptor = None
                try:
                    if failed_descriptor is not None:
                        os.close(failed_descriptor)
                finally:
                    if created:
                        os.unlink(relative.name, dir_fd=destination_parent)
                raise
    except OSError as error:
        raise ValueError(
            f"source bundle destination changed or is unsafe: {relative}"
        ) from error
    finally:
        os.close(source_descriptor)
    return expected, bytes_read, PublicArchiveEntry(
        sha256=digest.hexdigest(),
        size=bytes_read,
        mode=normalized_mode,
    )


def copy_public_tree(
    target: Path, *, expected_head: str | None = None
) -> dict[PurePosixPath, PublicArchiveEntry]:
    directory_flags, leaf_flags, destination_flags = secure_open_flags()
    try:
        source_root = os.open(ROOT, directory_flags)
    except OSError as error:
        raise ValueError("source bundle root cannot be opened securely") from error
    repository: PinnedGitRepository | None = None
    try:
        repository = pinned_git_repository(
            source_root, directory_flags, leaf_flags
        )
        if expected_head is not None:
            verify_expected_git_state(repository, expected_head)
        root_identity = source_root_identity(os.fstat(source_root))
        verify_source_root_path(root_identity)
        relative_files = tuple(
            public_files(repository, leaf_flags)
        )
        index_entries = git_index_entries(repository)
        if tuple(sorted(index_entries, key=PurePosixPath.as_posix)) != relative_files:
            raise ValueError("public Git file set changed during index scan")
        verify_pinned_git(repository)
        verify_source_root_path(root_identity)
        try:
            target_root = os.open(target, directory_flags)
        except OSError as error:
            raise ValueError(
                "source bundle target cannot be opened securely"
            ) from error
        try:
            fingerprints: dict[PurePosixPath, tuple[int, ...]] = {}
            archive_manifest: dict[PurePosixPath, PublicArchiveEntry] = {}
            copied_bytes = 0
            for relative in relative_files:
                fingerprint, entry_bytes, archive_entry = copy_public_entry(
                    source_root,
                    target_root,
                    relative,
                    directory_flags,
                    leaf_flags,
                    destination_flags,
                    MAX_PUBLIC_TREE_BYTES - copied_bytes,
                    index_entries[relative],
                )
                fingerprints[relative] = fingerprint
                archive_manifest[relative] = archive_entry
                copied_bytes += entry_bytes
            verify_source_root_path(root_identity)
            final_relative_files = tuple(
                public_files(repository, leaf_flags)
            )
            final_index_entries = git_index_entries(repository)
            verify_pinned_git(repository)
            verify_source_root_path(root_identity)
            if (
                final_relative_files != relative_files
                or final_index_entries != index_entries
            ):
                raise ValueError("public Git file set changed during source copy")
            for relative, expected in fingerprints.items():
                descriptor, metadata = open_public_file(
                    source_root, relative, directory_flags, leaf_flags
                )
                try:
                    verify_source_metadata(relative, expected, metadata)
                finally:
                    os.close(descriptor)
            verify_source_root_path(root_identity)
            verify_pinned_git(repository)
            if expected_head is not None:
                verify_expected_git_state(repository, expected_head)
        finally:
            os.close(target_root)
    finally:
        if repository is not None:
            close_pinned_git(repository)
        os.close(source_root)
    return archive_manifest


class DescriptorReader:
    def __init__(self, descriptor: int, expected_size: int) -> None:
        self.descriptor = descriptor
        self.expected_size = expected_size
        self.bytes_read = 0
        self.digest = hashlib.sha256()

    def read(self, size: int = -1) -> bytes:
        remaining = self.expected_size - self.bytes_read
        if remaining <= 0:
            return b""
        requested = remaining if size < 0 else min(size, remaining)
        chunk = os.read(self.descriptor, requested)
        self.bytes_read += len(chunk)
        self.digest.update(chunk)
        return chunk


class DescriptorWriter:
    def __init__(self, descriptor: int, max_bytes: int) -> None:
        if max_bytes < 0:
            raise ValueError("compressed source archive limit is invalid")
        self.descriptor = descriptor
        self.max_bytes = max_bytes
        self.bytes_written = 0
        self.digest = hashlib.sha256()

    def write(self, payload: bytes) -> int:
        view = memoryview(payload)
        total = len(view)
        if total > self.max_bytes - self.bytes_written:
            raise ValueError(
                f"compressed source archive exceeds {self.max_bytes} bytes"
            )
        while view:
            written = os.write(self.descriptor, view)
            if written <= 0:
                raise OSError("source archive write made no progress")
            self.digest.update(view[:written])
            self.bytes_written += written
            view = view[written:]
        return total

    def flush(self) -> None:
        return None

    def tell(self) -> int:
        return self.bytes_written


def archive_info(
    name: str,
    metadata: os.stat_result,
    is_directory: bool,
) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.type = tarfile.DIRTYPE if is_directory else tarfile.REGTYPE
    info.size = 0 if is_directory else int(metadata.st_size)
    info.mode = (
        0o755
        if is_directory or metadata.st_mode & stat.S_IXUSR
        else 0o644
    )
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = 0
    info.pax_headers = {}
    return info


def archive_directory_names(
    descriptor: int,
    relative: PurePosixPath,
) -> tuple[str, ...]:
    values: list[str] = []
    retained_bytes = 0
    try:
        with os.scandir(descriptor) as entries:
            for entry in entries:
                if len(values) >= MAX_DIRECTORY_ENTRIES:
                    raise ValueError(
                        "source archive directory exceeds the entry limit"
                    )
                value = entry.name
                try:
                    encoded = value.encode("utf-8", "strict")
                except UnicodeEncodeError as error:
                    raise ValueError(
                        "source archive name is not valid UTF-8 under: "
                        f"{relative}"
                    ) from error
                retained_bytes += len(encoded)
                if retained_bytes > MAX_RETAINED_PATH_BYTES:
                    raise ValueError(
                        "source archive directory names exceed the retained-name "
                        "limit"
                    )
                if value in {"", ".", ".."} or "/" in value:
                    raise ValueError(
                        f"source archive contains an unsafe name: {value!r}"
                    )
                values.append(value)
    except OSError as error:
        raise ValueError(
            f"source archive directory is unreadable: {relative}"
        ) from error
    return tuple(sorted(values))


def validate_archive_manifest(
    manifest: dict[PurePosixPath, PublicArchiveEntry],
    prefix: str,
) -> set[PurePosixPath]:
    if len(manifest) > MAX_ARCHIVE_FILES:
        raise ValueError(
            f"source archive manifest exceeds {MAX_ARCHIVE_FILES} files"
        )
    retained_path_bytes = 0
    payload_bytes = 0
    expected_directories: set[PurePosixPath] = set()
    for relative, entry in manifest.items():
        if not isinstance(relative, PurePosixPath):
            raise ValueError("source archive manifest path has an invalid type")
        value = relative.as_posix()
        path_bytes = value.encode("utf-8", "strict")
        archive_path_bytes = f"{prefix}/{value}".encode("utf-8", "strict")
        if (
            not relative.parts
            or relative.is_absolute()
            or len(relative.parts) > 128
            or any(part in {"", ".", ".."} for part in relative.parts)
            or len(path_bytes) > MAX_ARCHIVE_PATH_BYTES
            or len(archive_path_bytes) > MAX_ARCHIVE_PATH_BYTES
        ):
            raise ValueError(f"source archive manifest path is unsafe: {value!r}")
        if not isinstance(entry, PublicArchiveEntry):
            raise ValueError(f"source archive manifest entry is invalid: {value}")
        if (
            type(entry.size) is not int
            or entry.size < 0
            or entry.size > MAX_PUBLIC_FILE_BYTES
            or entry.mode not in {0o644, 0o755}
            or len(entry.sha256) != 64
            or any(character not in "0123456789abcdef" for character in entry.sha256)
        ):
            raise ValueError(f"source archive manifest entry is invalid: {value}")
        payload_bytes += entry.size
        if payload_bytes > MAX_PUBLIC_TREE_BYTES:
            raise ValueError(
                f"source archive manifest exceeds {MAX_PUBLIC_TREE_BYTES} bytes"
            )
        retained_path_bytes += len(path_bytes)
        if retained_path_bytes > MAX_RETAINED_PATH_BYTES:
            raise ValueError(
                "source archive manifest paths exceed the retained-name limit"
            )
        for index in range(1, len(relative.parts)):
            directory = PurePosixPath(*relative.parts[:index])
            if directory in expected_directories:
                continue
            expected_directories.add(directory)
            retained_path_bytes += len(
                directory.as_posix().encode("utf-8", "strict")
            )
            if len(expected_directories) > MAX_ARCHIVE_DIRECTORIES:
                raise ValueError(
                    "source archive manifest exceeds the directory limit"
                )
            if retained_path_bytes > MAX_RETAINED_PATH_BYTES:
                raise ValueError(
                    "source archive manifest paths exceed the retained-name limit"
                )
    return expected_directories


def archive_directory(
    archive: tarfile.TarFile,
    descriptor: int,
    relative: PurePosixPath,
    prefix: str,
    directory_flags: int,
    leaf_flags: int,
    expected_manifest: dict[PurePosixPath, PublicArchiveEntry],
    expected_directories: set[PurePosixPath],
    seen_entries: set[PurePosixPath],
    copied_bytes: list[int],
    depth: int,
) -> None:
    if depth > 128:
        raise ValueError("source archive directory depth exceeds 128")
    initial_metadata = os.fstat(descriptor)
    if not stat.S_ISDIR(initial_metadata.st_mode):
        raise ValueError(f"source archive entry is not a directory: {relative}")
    initial_fingerprint = source_fingerprint(initial_metadata)
    initial_names = archive_directory_names(descriptor, relative)

    for name in initial_names:
        child_relative = relative / name if relative.parts else PurePosixPath(name)
        if (
            len(child_relative.parts) > 128
            or len(child_relative.as_posix().encode("utf-8", "strict"))
            > MAX_ARCHIVE_PATH_BYTES
            or len(
                f"{prefix}/{child_relative.as_posix()}".encode(
                    "utf-8", "strict"
                )
            )
            > MAX_ARCHIVE_PATH_BYTES
        ):
            raise ValueError(
                f"source archive path exceeds safe limits: {child_relative}"
            )
        archive_name = f"{prefix}/{child_relative.as_posix()}"
        child_descriptor: int | None = None
        try:
            try:
                child_descriptor = os.open(
                    name, directory_flags, dir_fd=descriptor
                )
            except OSError:
                child_descriptor = os.open(name, leaf_flags, dir_fd=descriptor)
                metadata = os.fstat(child_descriptor)
                if not stat.S_ISREG(metadata.st_mode):
                    raise ValueError(
                        f"source archive requires a regular file: {child_relative}"
                    )
                expected_size = int(metadata.st_size)
                if expected_size < 0 or expected_size > MAX_PUBLIC_FILE_BYTES:
                    raise ValueError(
                        f"source archive file exceeds {MAX_PUBLIC_FILE_BYTES} "
                        f"bytes: {child_relative}"
                    )
                if copied_bytes[0] + expected_size > MAX_PUBLIC_TREE_BYTES:
                    raise ValueError(
                        f"source archive exceeds {MAX_PUBLIC_TREE_BYTES} bytes"
                    )
                expected_entry = expected_manifest.get(child_relative)
                if expected_entry is None:
                    raise ValueError(
                        f"unexpected file added before source archive: "
                        f"{child_relative}"
                    )
                expected_fingerprint = source_fingerprint(metadata)
                reader = DescriptorReader(child_descriptor, expected_size)
                info = archive_info(archive_name, metadata, False)
                archive.addfile(info, reader)
                if reader.bytes_read != expected_size or os.read(
                    child_descriptor, 1
                ):
                    raise ValueError(
                        f"source archive file changed while read: {child_relative}"
                    )
                verify_source_metadata(
                    child_relative,
                    expected_fingerprint,
                    os.fstat(child_descriptor),
                    reader.bytes_read,
                )
                normalized_mode = info.mode
                actual = PublicArchiveEntry(
                    sha256=reader.digest.hexdigest(),
                    size=reader.bytes_read,
                    mode=normalized_mode,
                )
                if actual != expected_entry:
                    raise ValueError(
                        f"source differs at archive time: {child_relative}"
                    )
                seen_entries.add(child_relative)
                copied_bytes[0] += expected_size
                continue

            metadata = os.fstat(child_descriptor)
            if not stat.S_ISDIR(metadata.st_mode):
                raise ValueError(
                    f"source archive entry changed type: {child_relative}"
                )
            if (
                child_relative not in expected_directories
            ):
                raise ValueError(
                    f"unexpected directory added before source archive: "
                    f"{child_relative}"
                )
            archive.addfile(archive_info(archive_name, metadata, True))
            archive_directory(
                archive,
                child_descriptor,
                child_relative,
                prefix,
                directory_flags,
                leaf_flags,
                expected_manifest,
                expected_directories,
                seen_entries,
                copied_bytes,
                depth + 1,
            )
        except OSError as error:
            raise ValueError(
                f"source archive entry changed or is unsafe: {child_relative}"
            ) from error
        finally:
            if child_descriptor is not None:
                os.close(child_descriptor)

    if archive_directory_names(descriptor, relative) != initial_names:
        raise ValueError(f"source archive directory changed: {relative}")
    if source_fingerprint(os.fstat(descriptor)) != initial_fingerprint:
        raise ValueError(f"source archive directory changed: {relative}")


def add_tree(
    archive: tarfile.TarFile,
    source: Path,
    prefix: str,
    expected_manifest: dict[PurePosixPath, PublicArchiveEntry] | None = None,
) -> None:
    prefix_path = PurePosixPath(prefix)
    if (
        not prefix
        or prefix.startswith("/")
        or any(part in {"", ".", ".."} for part in prefix.split("/"))
    ):
        raise ValueError("source archive prefix is unsafe")
    if prefix_path.as_posix() != prefix:
        raise ValueError("source archive prefix is not normalized")
    if len(prefix.encode("utf-8", "strict")) > MAX_ARCHIVE_PATH_BYTES:
        raise ValueError("source archive prefix exceeds the path limit")
    manifest = dict(expected_manifest or {})
    expected_directories = validate_archive_manifest(manifest, prefix)
    directory_flags, leaf_flags, _ = secure_open_flags()
    try:
        root_descriptor = os.open(source, directory_flags)
    except OSError as error:
        raise ValueError("source archive root cannot be opened securely") from error
    try:
        root_identity = source_root_identity(os.fstat(root_descriptor))
        seen_entries: set[PurePosixPath] = set()
        archive_directory(
            archive,
            root_descriptor,
            PurePosixPath(),
            prefix,
            directory_flags,
            leaf_flags,
            manifest,
            expected_directories,
            seen_entries,
            [0],
            0,
        )
        if seen_entries != set(manifest):
            missing = sorted(
                set(manifest) - seen_entries,
                key=PurePosixPath.as_posix,
            )
            raise ValueError(f"public source missing at archive time: {missing[0]}")
        try:
            current_root = source.lstat()
        except OSError as error:
            raise ValueError("source archive root changed") from error
        if source_root_identity(current_root) != root_identity:
            raise ValueError("source archive root changed")
    finally:
        os.close(root_descriptor)


def open_output_lock(
    parent_descriptor: int,
    output_name: str,
) -> int:
    lock_name = f".{output_name}.lock"
    flags = (
        os.O_RDWR
        | os.O_CREAT
        | os.O_NOFOLLOW
        | os.O_CLOEXEC
        | os.O_NONBLOCK
    )
    try:
        descriptor = os.open(
            lock_name,
            flags,
            0o600,
            dir_fd=parent_descriptor,
        )
    except OSError as error:
        raise ValueError("source archive lock is unsafe") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError("source archive lock is not a private regular file")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (BlockingIOError, OSError) as error:
            raise ValueError(
                f"source archive build is already running for: {output_name}"
            ) from error
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def verify_output_lock(
    parent_descriptor: int,
    output_name: str,
    lock_descriptor: int,
    leaf_flags: int,
    expected_fingerprint: tuple[int, ...],
) -> None:
    expected = os.fstat(lock_descriptor)
    if (
        not stat.S_ISREG(expected.st_mode)
        or expected.st_nlink != 1
        or source_fingerprint(expected) != expected_fingerprint
    ):
        raise ValueError("source archive lock changed while held")
    lock_name = f".{output_name}.lock"
    try:
        reopened = os.open(lock_name, leaf_flags, dir_fd=parent_descriptor)
    except OSError as error:
        raise ValueError("source archive lock path changed while held") from error
    try:
        current = os.fstat(reopened)
        if (
            not stat.S_ISREG(current.st_mode)
            or current.st_nlink != 1
            or source_fingerprint(current) != expected_fingerprint
        ):
            raise ValueError("source archive lock path changed while held")
    finally:
        os.close(reopened)


def descriptor_matches_name(
    parent_descriptor: int,
    name: str,
    descriptor: int,
) -> bool:
    try:
        descriptor_metadata = os.fstat(descriptor)
        name_metadata = os.stat(
            name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
    except OSError:
        return False
    return (
        stat.S_ISREG(descriptor_metadata.st_mode)
        and stat.S_ISREG(name_metadata.st_mode)
        and descriptor_metadata.st_nlink == 1
        and name_metadata.st_nlink == 1
        and (descriptor_metadata.st_dev, descriptor_metadata.st_ino)
        == (name_metadata.st_dev, name_metadata.st_ino)
    )


def verify_staged_name(
    parent_descriptor: int,
    name: str,
    descriptor: int,
) -> None:
    if not descriptor_matches_name(parent_descriptor, name, descriptor):
        raise ValueError("source archive staging name changed before publish")


def verify_published_name(
    parent_descriptor: int,
    name: str,
    descriptor: int,
) -> None:
    if not descriptor_matches_name(parent_descriptor, name, descriptor):
        raise ValueError("published source archive does not match staged file")


def unlink_staged_if_owned(
    parent_descriptor: int,
    name: str,
    descriptor: int,
) -> None:
    if descriptor_matches_name(parent_descriptor, name, descriptor):
        os.unlink(name, dir_fd=parent_descriptor)


def verify_compressed_archive_size(descriptor: int) -> None:
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size < 0
        or metadata.st_size > MAX_SOURCE_ARCHIVE_BYTES
    ):
        raise ValueError(
            f"compressed source archive exceeds {MAX_SOURCE_ARCHIVE_BYTES} bytes"
        )


def verify_descriptor_payload(
    descriptor: int,
    expected_size: int,
    expected_sha256: str,
) -> None:
    if expected_size < 0 or expected_size > MAX_SOURCE_ARCHIVE_BYTES:
        raise ValueError("published source archive has an invalid size")
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    total = 0
    while total <= expected_size:
        chunk = os.read(
            descriptor,
            min(COPY_BUFFER_BYTES, expected_size + 1 - total),
        )
        if not chunk:
            break
        digest.update(chunk)
        total += len(chunk)
    if total != expected_size or digest.hexdigest() != expected_sha256:
        raise ValueError("published source archive payload changed")


def output_directory_anchor(path: Path) -> tuple[Path, tuple[str, ...]]:
    if any(part in {"..", ""} for part in path.parts):
        raise ValueError("source archive output directory is noncanonical")
    if not path.is_absolute():
        parts = tuple(part for part in path.parts if part != ".")
        return Path.cwd().resolve(strict=True), parts

    lexical = Path(os.path.abspath(path))
    candidates = (ROOT, Path.cwd(), Path(tempfile.gettempdir()))
    for candidate in candidates:
        candidate = Path(os.path.abspath(candidate))
        try:
            relative = lexical.relative_to(candidate)
        except ValueError:
            continue
        return candidate.resolve(strict=True), relative.parts
    anchor = Path(lexical.anchor).resolve(strict=True)
    return anchor, lexical.relative_to(Path(lexical.anchor)).parts


def open_output_directory(
    path: Path,
    directory_flags: int,
    *,
    create: bool,
) -> int:
    try:
        anchor, parts = output_directory_anchor(path)
        descriptor = os.open(anchor, directory_flags)
    except OSError as error:
        raise ValueError("source archive output anchor is unsafe") from error
    try:
        for part in parts:
            if part in {"", ".", ".."}:
                raise ValueError("source archive output directory is noncanonical")
            if create:
                try:
                    os.mkdir(part, 0o755, dir_fd=descriptor)
                except FileExistsError:
                    pass
            child = os.open(part, directory_flags, dir_fd=descriptor)
            previous = descriptor
            descriptor = child
            os.close(previous)
        return descriptor
    except OSError as error:
        os.close(descriptor)
        raise ValueError(
            "source archive output ancestor is missing, changed, or is a symlink"
        ) from error
    except BaseException:
        os.close(descriptor)
        raise


def verify_directory_path(
    path: Path,
    expected_identity: tuple[int, int],
    directory_flags: int,
) -> None:
    try:
        descriptor = open_output_directory(
            path, directory_flags, create=False
        )
    except (OSError, ValueError) as error:
        raise ValueError("source archive output directory changed") from error
    try:
        if source_root_identity(os.fstat(descriptor)) != expected_identity:
            raise ValueError("source archive output directory changed")
    finally:
        os.close(descriptor)


def open_unique_staged_output(
    parent_descriptor: int,
    output_name: str,
) -> tuple[str, int]:
    flags = (
        os.O_RDWR
        | os.O_CREAT
        | os.O_EXCL
        | os.O_NOFOLLOW
        | os.O_CLOEXEC
    )
    for _ in range(128):
        name = f".{output_name}.{secrets.token_hex(16)}.tmp"
        try:
            descriptor = os.open(
                name,
                flags,
                0o600,
                dir_fd=parent_descriptor,
            )
        except FileExistsError:
            continue
        except OSError as error:
            raise ValueError("source archive staging path is unsafe") from error
        try:
            metadata = os.fstat(descriptor)
            if stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1:
                return name, descriptor
            raise ValueError("source archive staging file is not regular")
        except BaseException:
            try:
                unlink_staged_if_owned(parent_descriptor, name, descriptor)
            finally:
                os.close(descriptor)
            raise
    raise ValueError("source archive could not allocate a unique staging file")


def descriptor_name_identity_matches(
    parent_descriptor: int,
    name: str,
    descriptor: int,
) -> bool:
    try:
        opened = os.fstat(descriptor)
        named = os.stat(
            name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
    except OSError:
        return False
    return (
        stat.S_ISREG(opened.st_mode)
        and stat.S_ISREG(named.st_mode)
        and (opened.st_dev, opened.st_ino) == (named.st_dev, named.st_ino)
    )


def create_existing_output_backup(
    parent_descriptor: int,
    output_name: str,
    leaf_flags: int,
) -> tuple[str, int] | None:
    try:
        output_metadata = os.stat(
            output_name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return None
    except OSError as error:
        raise ValueError("existing source archive cannot be inspected") from error
    if not stat.S_ISREG(output_metadata.st_mode):
        return None

    for _ in range(128):
        backup_name = f".{output_name}.{secrets.token_hex(16)}.old"
        try:
            os.link(
                output_name,
                backup_name,
                src_dir_fd=parent_descriptor,
                dst_dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except FileExistsError:
            continue
        except OSError as error:
            raise ValueError("existing source archive cannot be preserved") from error
        backup_descriptor: int | None = None
        try:
            backup_descriptor = os.open(
                backup_name, leaf_flags, dir_fd=parent_descriptor
            )
            if (
                not descriptor_name_identity_matches(
                    parent_descriptor, output_name, backup_descriptor
                )
                or not descriptor_name_identity_matches(
                    parent_descriptor, backup_name, backup_descriptor
                )
            ):
                raise ValueError("existing source archive changed before publish")
            return backup_name, backup_descriptor
        except BaseException:
            if backup_descriptor is not None:
                if descriptor_name_identity_matches(
                    parent_descriptor, backup_name, backup_descriptor
                ):
                    os.unlink(backup_name, dir_fd=parent_descriptor)
                os.close(backup_descriptor)
            else:
                try:
                    os.unlink(backup_name, dir_fd=parent_descriptor)
                except OSError:
                    pass
            raise
    raise ValueError("source archive could not allocate a rollback name")


def unlink_backup_if_owned(
    parent_descriptor: int,
    backup_name: str,
    backup_descriptor: int,
) -> None:
    if descriptor_name_identity_matches(
        parent_descriptor, backup_name, backup_descriptor
    ):
        os.unlink(backup_name, dir_fd=parent_descriptor)


def write_source_archive(
    output: Path,
    tree: Path,
    prefix: str,
    expected_manifest: dict[PurePosixPath, PublicArchiveEntry],
) -> None:
    output_name = output.name
    if output_name in {"", ".", ".."} or "/" in output_name:
        raise ValueError("source archive output name is unsafe")
    directory_flags, leaf_flags, _ = secure_open_flags()
    try:
        parent_descriptor = open_output_directory(
            output.parent, directory_flags, create=True
        )
    except (OSError, ValueError) as error:
        raise ValueError(
            "source archive output directory cannot be opened securely"
        ) from error
    lock_descriptor: int | None = None
    staged_descriptor: int | None = None
    staged_name: str | None = None
    backup_descriptor: int | None = None
    backup_name: str | None = None
    replaced = False
    published = False
    try:
        parent_identity = source_root_identity(os.fstat(parent_descriptor))
        verify_directory_path(
            output.parent, parent_identity, directory_flags
        )
        lock_descriptor = open_output_lock(parent_descriptor, output_name)
        lock_fingerprint = source_fingerprint(os.fstat(lock_descriptor))
        staged_name, staged_descriptor = open_unique_staged_output(
            parent_descriptor, output_name
        )
        raw = DescriptorWriter(
            staged_descriptor, MAX_SOURCE_ARCHIVE_BYTES
        )
        with gzip.GzipFile(
            filename="", mode="wb", fileobj=raw, mtime=0
        ) as compressed:
            with tarfile.open(
                fileobj=compressed,
                mode="w",
                format=tarfile.PAX_FORMAT,
            ) as archive:
                add_tree(
                    archive,
                    tree,
                    prefix,
                    expected_manifest,
                )
        raw.flush()
        verify_compressed_archive_size(staged_descriptor)
        if os.fstat(staged_descriptor).st_size != raw.bytes_written:
            raise ValueError("compressed source archive size changed while written")
        os.fchmod(staged_descriptor, 0o644)
        os.fsync(staged_descriptor)
        verify_output_lock(
            parent_descriptor,
            output_name,
            lock_descriptor,
            leaf_flags,
            lock_fingerprint,
        )
        verify_staged_name(
            parent_descriptor,
            staged_name,
            staged_descriptor,
        )
        verify_compressed_archive_size(staged_descriptor)
        verify_directory_path(
            output.parent, parent_identity, directory_flags
        )
        backup = create_existing_output_backup(
            parent_descriptor, output_name, leaf_flags
        )
        if backup is not None:
            backup_name, backup_descriptor = backup
            os.fsync(parent_descriptor)
            if not descriptor_name_identity_matches(
                parent_descriptor, output_name, backup_descriptor
            ):
                raise ValueError("existing source archive changed before publish")
        os.replace(
            staged_name,
            output_name,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
        )
        replaced = True
        verify_published_name(
            parent_descriptor,
            output_name,
            staged_descriptor,
        )
        verify_compressed_archive_size(staged_descriptor)
        verify_descriptor_payload(
            staged_descriptor,
            raw.bytes_written,
            raw.digest.hexdigest(),
        )
        os.fsync(parent_descriptor)
        verify_directory_path(
            output.parent, parent_identity, directory_flags
        )
        published = True
        if backup_name is not None and backup_descriptor is not None:
            unlink_backup_if_owned(
                parent_descriptor, backup_name, backup_descriptor
            )
            backup_name = None
            try:
                os.fsync(parent_descriptor)
            except OSError:
                # The published name was already durably fsynced. A failure to
                # persist deletion of the rollback link must not destroy it.
                pass
    except BaseException as primary_error:
        if (
            replaced
            and not published
            and backup_name is not None
            and backup_descriptor is not None
            and staged_descriptor is not None
            and descriptor_matches_name(
                parent_descriptor, output_name, staged_descriptor
            )
        ):
            try:
                os.replace(
                    backup_name,
                    output_name,
                    src_dir_fd=parent_descriptor,
                    dst_dir_fd=parent_descriptor,
                )
                backup_name = None
                if not descriptor_name_identity_matches(
                    parent_descriptor, output_name, backup_descriptor
                ):
                    raise ValueError("source archive rollback identity changed")
                try:
                    os.fsync(parent_descriptor)
                except OSError as rollback_fsync_error:
                    if hasattr(primary_error, "add_note"):
                        primary_error.add_note(
                            f"rollback directory fsync also failed: "
                            f"{rollback_fsync_error}"
                        )
            except BaseException as rollback_error:
                if hasattr(primary_error, "add_note"):
                    primary_error.add_note(
                        f"source archive rollback also failed: {rollback_error}"
                    )
        raise
    finally:
        try:
            try:
                if (
                    staged_descriptor is not None
                    and staged_name is not None
                    and not published
                ):
                    if not replaced:
                        unlink_staged_if_owned(
                            parent_descriptor,
                            staged_name,
                            staged_descriptor,
                        )
            finally:
                if staged_descriptor is not None:
                    os.close(staged_descriptor)
        finally:
            try:
                try:
                    if (
                        backup_name is not None
                        and backup_descriptor is not None
                        and (published or not replaced)
                    ):
                        unlink_backup_if_owned(
                            parent_descriptor,
                            backup_name,
                            backup_descriptor,
                        )
                finally:
                    if backup_descriptor is not None:
                        os.close(backup_descriptor)
            finally:
                try:
                    if lock_descriptor is not None:
                        try:
                            fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
                        finally:
                            os.close(lock_descriptor)
                finally:
                    os.close(parent_descriptor)


def json_stream(value: str):
    decoder = json.JSONDecoder()
    offset = 0
    while offset < len(value):
        while offset < len(value) and value[offset].isspace():
            offset += 1
        if offset >= len(value):
            return
        item, offset = decoder.raw_decode(value, offset)
        yield item


def command_json_documents(
    command: list[str], directory: Path, environment: dict[str, str]
) -> list[dict[str, object]]:
    payload = bounded_command_output(
        command,
        cwd=directory,
        env=environment,
        max_output_bytes=MAX_GO_OUTPUT_BYTES,
        timeout_seconds=GO_COMMAND_TIMEOUT_SECONDS,
    )
    try:
        output = payload.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise ValueError("Go command returned non-UTF-8 JSON") from error
    documents: list[dict[str, object]] = []
    for item in json_stream(output):
        if not isinstance(item, dict):
            raise ValueError("Go command returned a non-object JSON document")
        if len(documents) >= MAX_GO_JSON_DOCUMENTS:
            raise ValueError("Go command returned too many JSON documents")
        documents.append(item)
    return documents


def write_atomic_file(
    destination: Path,
    payload: bytes,
    mode: int = 0o644,
) -> PublicArchiveEntry:
    if len(payload) > MAX_PUBLIC_FILE_BYTES or mode not in {0o644, 0o755}:
        raise ValueError("generated vendor file exceeds safe limits")
    destination.parent.mkdir(parents=True, exist_ok=True)
    directory_flags, _, _ = secure_open_flags()
    try:
        parent_descriptor = os.open(destination.parent, directory_flags)
    except OSError as error:
        raise ValueError("generated vendor destination is unsafe") from error
    staged_name: str | None = None
    staged_descriptor: int | None = None
    published = False
    try:
        staged_name, staged_descriptor = open_unique_staged_output(
            parent_descriptor, destination.name
        )
        remaining = memoryview(payload)
        while remaining:
            written = os.write(staged_descriptor, remaining)
            if written <= 0:
                raise OSError("generated vendor write made no progress")
            remaining = remaining[written:]
        os.fchmod(staged_descriptor, mode)
        os.fsync(staged_descriptor)
        verify_staged_name(
            parent_descriptor,
            staged_name,
            staged_descriptor,
        )
        os.replace(
            staged_name,
            destination.name,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
        )
        verify_published_name(
            parent_descriptor,
            destination.name,
            staged_descriptor,
        )
        published = True
        return PublicArchiveEntry(
            sha256=hashlib.sha256(payload).hexdigest(),
            size=len(payload),
            mode=mode,
        )
    finally:
        try:
            if (
                staged_descriptor is not None
                and staged_name is not None
                and not published
            ):
                unlink_staged_if_owned(
                    parent_descriptor,
                    staged_name,
                    staged_descriptor,
                )
        finally:
            try:
                if staged_descriptor is not None:
                    os.close(staged_descriptor)
            finally:
                os.close(parent_descriptor)


def copy_file(
    source_root: Path,
    source_relative: Path,
    destination: Path,
    max_bytes: int = MAX_PUBLIC_FILE_BYTES,
) -> PublicArchiveEntry:
    if (
        source_relative.is_absolute()
        or not source_relative.parts
        or any(part in {"", ".", ".."} for part in source_relative.parts)
    ):
        raise ValueError(f"unsafe minimal vendor source: {source_relative}")
    relative = PurePosixPath(source_relative.as_posix())
    directory_flags, leaf_flags, _ = secure_open_flags()
    try:
        source_root_descriptor = os.open(source_root, directory_flags)
    except OSError as error:
        raise ValueError(
            f"minimal vendor source root is unsafe: {source_root}"
        ) from error
    source_descriptor: int | None = None
    destination_parent: int | None = None
    staged_descriptor: int | None = None
    staged_name: str | None = None
    published = False
    try:
        root_identity = source_root_identity(os.fstat(source_root_descriptor))
        source_descriptor, metadata = open_public_file(
            source_root_descriptor,
            relative,
            directory_flags,
            leaf_flags,
        )
        expected = source_fingerprint(metadata)
        expected_size = int(metadata.st_size)
        if (
            max_bytes < 0
            or expected_size < 0
            or expected_size > MAX_PUBLIC_FILE_BYTES
            or expected_size > max_bytes
        ):
            raise ValueError(
                "minimal vendor source exceeds the remaining aggregate or "
                f"{MAX_PUBLIC_FILE_BYTES}-byte per-file limit: "
                f"{relative}"
            )

        destination.parent.mkdir(parents=True, exist_ok=True)
        destination_parent = os.open(destination.parent, directory_flags)
        staged_name, staged_descriptor = open_unique_staged_output(
            destination_parent, destination.name
        )
        digest = hashlib.sha256()
        bytes_read = copy_descriptor_bytes(
            source_descriptor,
            staged_descriptor,
            expected_size,
            digest,
        )
        verify_source_metadata(
            relative,
            expected,
            os.fstat(source_descriptor),
            bytes_read,
        )
        reopened, reopened_metadata = open_public_file(
            source_root_descriptor,
            relative,
            directory_flags,
            leaf_flags,
        )
        try:
            verify_source_metadata(relative, expected, reopened_metadata)
        finally:
            os.close(reopened)
        try:
            root_metadata = source_root.lstat()
        except OSError as error:
            raise ValueError("minimal vendor source root changed") from error
        if source_root_identity(root_metadata) != root_identity:
            raise ValueError("minimal vendor source root changed")
        mode = 0o755 if metadata.st_mode & stat.S_IXUSR else 0o644
        os.fchmod(staged_descriptor, mode)
        os.fsync(staged_descriptor)
        verify_staged_name(
            destination_parent,
            staged_name,
            staged_descriptor,
        )
        os.replace(
            staged_name,
            destination.name,
            src_dir_fd=destination_parent,
            dst_dir_fd=destination_parent,
        )
        verify_published_name(
            destination_parent,
            destination.name,
            staged_descriptor,
        )
        published = True
        return PublicArchiveEntry(
            sha256=digest.hexdigest(),
            size=bytes_read,
            mode=mode,
        )
    finally:
        try:
            try:
                if (
                    staged_descriptor is not None
                    and staged_name is not None
                    and destination_parent is not None
                    and not published
                ):
                    unlink_staged_if_owned(
                        destination_parent,
                        staged_name,
                        staged_descriptor,
                    )
            finally:
                if staged_descriptor is not None:
                    os.close(staged_descriptor)
        finally:
            try:
                if destination_parent is not None:
                    os.close(destination_parent)
            finally:
                try:
                    if source_descriptor is not None:
                        os.close(source_descriptor)
                finally:
                    os.close(source_root_descriptor)


def safe_vendor_relative(value: str) -> PurePosixPath:
    parts = value.split("/")
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeEncodeError as error:
        raise ValueError("generated vendor path is not valid UTF-8") from error
    if (
        not value
        or value.startswith("/")
        or any(part in {"", ".", ".."} for part in parts)
        or len(parts) > 128
        or len(encoded) > MAX_ARCHIVE_PATH_BYTES
    ):
        raise ValueError(f"unsafe generated vendor path: {value!r}")
    return PurePosixPath(value)


def build_minimal_vendor(
    module: Path,
    environment: dict[str, str],
    *,
    max_tree_bytes: int = MAX_PUBLIC_TREE_BYTES,
    max_files: int = MAX_ARCHIVE_FILES,
    max_directories: int = MAX_ARCHIVE_DIRECTORIES,
    max_retained_path_bytes: int = MAX_RETAINED_PATH_BYTES,
) -> dict[PurePosixPath, PublicArchiveEntry]:
    if (
        max_tree_bytes < 0
        or max_files < 0
        or max_directories < 0
        or max_retained_path_bytes < 0
    ):
        raise ValueError("generated vendor aggregate limit is invalid")
    environment = sanitized_go_environment(environment)
    go_executable = trusted_tool_path("go", environment)
    git_executable = trusted_tool_path("git", environment)
    trusted_directories = [
        str(Path(go_executable).parent),
        str(Path(git_executable).parent),
    ]
    environment["PATH"] = os.pathsep.join(
        dict.fromkeys(
            [
                *trusted_directories,
                *environment["PATH"].split(os.pathsep),
            ]
        )
    )
    bounded_command_output(
        [go_executable, "mod", "verify"],
        cwd=module,
        env=environment,
        max_output_bytes=MAX_GO_OUTPUT_BYTES,
        timeout_seconds=GO_COMMAND_TIMEOUT_SECONDS,
    )
    vendor_manifest: dict[PurePosixPath, PublicArchiveEntry] = {}
    manifest_prefix = PurePosixPath(module.name, "vendor")
    vendor_bytes = 0
    retained_path_bytes = 0
    vendor_directories: set[PurePosixPath] = set()

    def checked_key(
        relative: PurePosixPath,
    ) -> tuple[PurePosixPath, set[PurePosixPath], int]:
        key = manifest_prefix / relative
        if key in vendor_manifest:
            return key, set(), 0
        encoded = key.as_posix().encode("utf-8", "strict")
        directories = {
            PurePosixPath(*key.parts[:index])
            for index in range(1, len(key.parts))
        }
        new_directories = directories - vendor_directories
        added_path_bytes = len(encoded) + sum(
            len(directory.as_posix().encode("utf-8", "strict"))
            for directory in new_directories
        )
        if len(encoded) > MAX_ARCHIVE_PATH_BYTES:
            raise ValueError(f"generated vendor path exceeds safe limits: {key}")
        if len(vendor_manifest) >= max_files:
            raise ValueError("generated vendor exceeds the aggregate file limit")
        if len(vendor_directories) + len(new_directories) > max_directories:
            raise ValueError(
                "generated vendor exceeds the aggregate directory limit"
            )
        if retained_path_bytes + added_path_bytes > max_retained_path_bytes:
            raise ValueError(
                "generated vendor paths exceed the retained-name limit"
            )
        return key, new_directories, added_path_bytes

    def record(
        relative: PurePosixPath,
        entry: PublicArchiveEntry,
    ) -> None:
        nonlocal retained_path_bytes, vendor_bytes
        key, new_directories, added_path_bytes = checked_key(relative)
        previous = vendor_manifest.get(key)
        if previous is not None and previous != entry:
            raise ValueError(f"conflicting generated vendor file: {key}")
        if previous is None:
            if entry.size > max_tree_bytes - vendor_bytes:
                raise ValueError(
                    "generated vendor exceeds the aggregate byte limit"
                )
            retained_path_bytes += added_path_bytes
            vendor_bytes += entry.size
            vendor_directories.update(new_directories)
        vendor_manifest[key] = entry

    def copy_and_record(
        source_root: Path,
        source_relative: Path,
        destination: Path,
        archive_relative: PurePosixPath,
    ) -> None:
        key, _new_directories, _added_path_bytes = checked_key(
            archive_relative
        )
        previous = vendor_manifest.get(key)
        remaining = (
            MAX_PUBLIC_FILE_BYTES
            if previous is not None
            else max_tree_bytes - vendor_bytes
        )
        entry = copy_file(
            source_root,
            source_relative,
            destination,
            max_bytes=remaining,
        )
        record(archive_relative, entry)

    packages: list[dict[str, object]] = []
    for goarch, goarm in (("arm64", ""),):
        list_environment = environment.copy()
        list_environment.update(
            {"GOOS": "android", "GOARCH": goarch, "CGO_ENABLED": "1"}
        )
        if goarm:
            list_environment["GOARM"] = goarm
        packages.extend(command_json_documents(
            [go_executable, "list", "-mod=mod", "-deps", "-json", "-tags", BUILD_TAGS,
             "./cmd/exitfy-sb"],
            module,
            list_environment,
        ))
        if len(packages) > MAX_GO_JSON_DOCUMENTS:
            raise ValueError("Go package graph exceeds the document limit")

    # `go mod vendor` treats almost every build tag as enabled and downloads
    # multi-gigabyte optional Cronet/TUN/Tailscale modules that exitFy does not
    # compile. Build the canonical minimal modules.txt from the explicit module
    # graph and the exact arm64-v8a package list instead.
    edit_payload = bounded_command_output(
        [go_executable, "mod", "edit", "-json"],
        cwd=module,
        env=environment,
        max_output_bytes=MAX_GO_OUTPUT_BYTES,
        timeout_seconds=GO_COMMAND_TIMEOUT_SECONDS,
    )
    try:
        edit = json.loads(edit_payload.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("go mod edit returned invalid JSON") from error
    if not isinstance(edit, dict):
        raise ValueError("go mod edit returned a non-object JSON document")
    if edit.get("Replace"):
        raise ValueError("minimal vendor does not allow module replacements")
    explicit = {
        item["Path"]: item["Version"] for item in edit.get("Require", [])
    }
    module_metadata = {
        item["Path"]: item
        for item in command_json_documents(
            [go_executable, "list", "-m", "-json", "all"], module, environment
        )
        if not item.get("Main")
    }
    minimal_vendor = module / ".vendor-minimal"
    if minimal_vendor.exists():
        shutil.rmtree(minimal_vendor)
    minimal_vendor.mkdir()

    module_roots: dict[str, Path] = {}
    module_packages: dict[str, set[str]] = {}
    for package in packages:
        module_info = package.get("Module") or {}
        if not module_info or module_info.get("Main"):
            continue
        import_path = package.get("ImportPath", "")
        package_dir = Path(package.get("Dir", ""))
        module_path = module_info.get("Path", "")
        module_dir = Path(module_info.get("Dir", ""))
        if not import_path or not package_dir.is_dir() or not module_path or not module_dir.is_dir():
            raise ValueError(f"incomplete Go package metadata for {import_path!r}")
        import_relative = safe_vendor_relative(str(import_path))
        destination = minimal_vendor.joinpath(*import_relative.parts)
        for field in SOURCE_FIELDS:
            for relative_name in package.get(field, []) or []:
                relative = Path(relative_name)
                if relative.is_absolute() or ".." in relative.parts:
                    raise ValueError(f"unsafe Go source path: {relative_name}")
                source = package_dir / relative
                if not source.is_file():
                    raise ValueError(f"listed Go source is missing: {source}")
                copy_and_record(
                    package_dir,
                    relative,
                    destination / relative,
                    import_relative / PurePosixPath(relative.as_posix()),
                )
        module_roots[module_path] = module_dir
        module_packages.setdefault(module_path, set()).add(import_path)

    for module_path, module_dir in module_roots.items():
        module_relative = safe_vendor_relative(module_path)
        destination = minimal_vendor.joinpath(*module_relative.parts)
        license_sources: dict[str, Path] = {}
        candidate_path_bytes = 0
        for pattern in ("LICENSE*", "COPYING*", "NOTICE*", "AUTHORS*"):
            for source in module_dir.glob(pattern):
                if source.is_file():
                    if source.name in license_sources:
                        continue
                    archive_relative = module_relative / source.name
                    key = manifest_prefix / archive_relative
                    encoded = key.as_posix().encode("utf-8", "strict")
                    if (
                        len(encoded) > MAX_ARCHIVE_PATH_BYTES
                        or len(license_sources)
                        >= max_files - len(vendor_manifest)
                        or retained_path_bytes + candidate_path_bytes + len(encoded)
                        > max_retained_path_bytes
                    ):
                        raise ValueError(
                            "generated vendor license set exceeds safe limits"
                        )
                    candidate_path_bytes += len(encoded)
                    license_sources[source.name] = source
        for source_name in sorted(license_sources):
            copy_and_record(
                module_dir,
                Path(source_name),
                destination / source_name,
                module_relative / source_name,
            )

    modules_lines: list[str] = []
    modules_payload_bytes = 0
    modules_payload_limit = min(
        MAX_PUBLIC_FILE_BYTES, max_tree_bytes - vendor_bytes
    )

    def append_modules_line(value: str) -> None:
        nonlocal modules_payload_bytes
        encoded_size = len(value.encode("utf-8", "strict")) + 1
        if encoded_size > modules_payload_limit - modules_payload_bytes:
            raise ValueError("generated modules.txt exceeds safe limits")
        modules_lines.append(value)
        modules_payload_bytes += encoded_size

    for module_path in sorted(set(explicit) | set(module_packages)):
        metadata = module_metadata.get(module_path) or {}
        version = explicit.get(module_path) or metadata.get("Version", "")
        if not version:
            raise ValueError(f"missing module version for {module_path}")
        append_modules_line(f"# {module_path} {version}")
        annotations: list[str] = []
        if module_path in explicit:
            annotations.append("explicit")
        go_version = metadata.get("GoVersion", "")
        if go_version:
            annotations.append(f"go {go_version}")
        if annotations:
            append_modules_line("## " + "; ".join(annotations))
        for package_path in sorted(module_packages.get(module_path, set())):
            append_modules_line(package_path)
    modules_payload = ("\n".join(modules_lines) + "\n").encode("utf-8")
    modules_relative = PurePosixPath("modules.txt")
    checked_key(modules_relative)
    if len(modules_payload) > max_tree_bytes - vendor_bytes:
        raise ValueError("generated vendor exceeds the aggregate byte limit")
    record(
        modules_relative,
        write_atomic_file(
            minimal_vendor / "modules.txt",
            modules_payload,
        ),
    )

    full_vendor = module / "vendor"
    if full_vendor.exists():
        shutil.rmtree(full_vendor)
    minimal_vendor.rename(full_vendor)
    for goarch, goarm in (("arm64", ""),):
        list_environment = environment.copy()
        list_environment.update(
            {"GOOS": "android", "GOARCH": goarch, "CGO_ENABLED": "1"}
        )
        if goarm:
            list_environment["GOARM"] = goarm
        bounded_command_output(
            [go_executable, "list", "-mod=vendor", "-tags", BUILD_TAGS, "./cmd/exitfy-sb"],
            cwd=module,
            env=list_environment,
            max_output_bytes=MAX_GO_OUTPUT_BYTES,
            timeout_seconds=GO_COMMAND_TIMEOUT_SECONDS,
        )
    bounded_command_output(
        [go_executable, "mod", "verify"],
        cwd=module,
        env=environment,
        max_output_bytes=MAX_GO_OUTPUT_BYTES,
        timeout_seconds=GO_COMMAND_TIMEOUT_SECONDS,
    )
    return vendor_manifest


def parse_expected_pin_digests(values: list[str]) -> dict[PurePosixPath, str]:
    digests: dict[PurePosixPath, str] = {}
    for value in values:
        raw_path, separator, digest = value.partition("=")
        try:
            path = PurePosixPath(raw_path)
        except (TypeError, ValueError) as error:
            raise ValueError("expected pin digest path is invalid") from error
        if (
            separator != "="
            or path.as_posix() != raw_path
            or path not in VALIDATED_WORKTREE_PIN_PATHS
            or SHA256_HEX.fullmatch(digest) is None
            or path in digests
        ):
            raise ValueError("expected pin digest set is invalid")
        digests[path] = digest
    if set(digests) != set(VALIDATED_WORKTREE_PIN_PATHS):
        raise ValueError("expected pin digest set is incomplete")
    return digests


def main() -> None:
    global ROOT
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--expected-pin-sha256", action="append", required=True)
    parser.add_argument("--upstream-version", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    try:
        repository_root = args.repo_root.resolve(strict=True)
        repository_metadata = repository_root.lstat()
    except OSError as error:
        raise ValueError("source repository root cannot be resolved") from error
    if not stat.S_ISDIR(repository_metadata.st_mode):
        raise ValueError("source repository root is not a directory")
    ROOT = repository_root
    if FULL_COMMIT.fullmatch(args.expected_head) is None:
        raise ValueError("source repository expected HEAD is invalid")
    expected_pin_digests = parse_expected_pin_digests(
        args.expected_pin_sha256
    )

    version = args.upstream_version.removeprefix("v")
    if not version or any(part == "" or not part.isdigit() for part in version.split(".")):
        raise ValueError("invalid upstream version")

    with tempfile.TemporaryDirectory(prefix="exitfy-sb-source-") as temporary:
        tree = Path(temporary) / f"exitfy-sb-source-{version}"
        tree.mkdir()
        public_manifest = copy_public_tree(
            tree, expected_head=args.expected_head
        )
        for path, expected_digest in expected_pin_digests.items():
            entry = public_manifest.get(path)
            if entry is None or entry.sha256 != expected_digest:
                raise ValueError(
                    f"validated worktree pin differs from its frozen digest: {path}"
                )
        module = tree / "singbox"
        public_bytes = sum(entry.size for entry in public_manifest.values())
        public_directories = {
            PurePosixPath(*relative.parts[:index])
            for relative in public_manifest
            for index in range(1, len(relative.parts))
        }
        public_path_bytes = sum(
            len(relative.as_posix().encode("utf-8", "strict"))
            for relative in public_manifest
        ) + sum(
            len(directory.as_posix().encode("utf-8", "strict"))
            for directory in public_directories
        )
        vendor_manifest = build_minimal_vendor(
            module,
            sanitized_go_environment(dict(os.environ)),
            max_tree_bytes=MAX_PUBLIC_TREE_BYTES - public_bytes,
            max_files=MAX_ARCHIVE_FILES - len(public_manifest),
            max_directories=(
                MAX_ARCHIVE_DIRECTORIES - len(public_directories)
            ),
            max_retained_path_bytes=(
                MAX_RETAINED_PATH_BYTES - public_path_bytes
            ),
        )
        overlap = set(public_manifest) & set(vendor_manifest)
        if overlap:
            first = min(overlap, key=PurePosixPath.as_posix)
            raise ValueError(f"generated vendor replaces public source: {first}")
        archive_manifest = {**public_manifest, **vendor_manifest}
        validate_archive_manifest(archive_manifest, tree.name)

        write_source_archive(
            args.output,
            tree,
            tree.name,
            archive_manifest,
        )
    print(f"wrote reproducible source bundle: {args.output}")


if __name__ == "__main__":
    main()
