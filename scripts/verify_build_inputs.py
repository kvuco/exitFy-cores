#!/usr/bin/env python3
"""Fail-closed provenance and worktree checks for release build inputs."""

from __future__ import annotations

import argparse
import contextlib
import errno
import hashlib
import json
import os
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Sequence


MAX_COMMAND_OUTPUT = 1024 * 1024
MAX_PIN_BYTES = 16 * 1024 * 1024
COMMAND_READ_CHUNK = 64 * 1024
COMMAND_POLL_SECONDS = 0.05
COMMAND_DRAIN_SECONDS = 2.0
COMMAND_REAP_SECONDS = 5.0
COMMAND_TIMEOUT_SECONDS = 90.0
FULL_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
INDEX_DEBUG_METADATA = re.compile(
    rb"  ctime: [0-9]+:[0-9]+\n"
    rb"  mtime: [0-9]+:[0-9]+\n"
    rb"  dev: [0-9]+\tino: [0-9]+\n"
    rb"  uid: [0-9]+\tgid: [0-9]+\n"
    rb"  size: [0-9]+\tflags: ([0-9a-fA-F]+)\n"
)
RunCommand = Callable[[Sequence[str], Path], bytes]


class ProcessOwnershipLost(ValueError):
    pass


@dataclass(frozen=True)
class PinnedExecutable:
    path: str
    descriptor: int
    fingerprint: tuple[int, ...]


@dataclass(frozen=True)
class PinnedDirectory:
    requested_path: Path
    canonical_path: Path
    descriptor: int
    identity: tuple[int, int, int]


FCHDIR_EXEC_HELPER = (
    "import os,sys; "
    "descriptor=int(sys.argv[1]); "
    "os.fchdir(descriptor); "
    "os.close(descriptor); "
    "os.execv(sys.argv[2],sys.argv[2:])"
)


def _decode_paths(raw: bytes, label: str) -> set[str]:
    values: set[str] = set()
    for item in raw.split(b"\0"):
        if not item:
            continue
        try:
            value = item.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError(f"{label} contains a non-UTF-8 path") from error
        if value.startswith("/") or value in {"", "."} or ".." in Path(value).parts:
            raise ValueError(f"{label} contains a noncanonical path")
        values.add(value)
    return values


def _executable_fingerprint(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_mode),
        int(metadata.st_size),
        int(metadata.st_mtime_ns),
        int(metadata.st_ctime_ns),
    )


def _pin_exact_executable(value: str) -> PinnedExecutable:
    candidate = Path(value)
    if not candidate.is_absolute():
        raise ValueError("command executable must be an exact absolute path")
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as error:
        raise ValueError("command executable cannot be resolved") from error
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if nofollow == 0:
        raise ValueError("command execution requires POSIX O_NOFOLLOW")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | nofollow
    try:
        descriptor = os.open(resolved, flags)
    except OSError as error:
        raise ValueError("command executable cannot be pinned") from error
    try:
        opened = os.fstat(descriptor)
        named = os.stat(resolved, follow_symlinks=False)
        fingerprint = _executable_fingerprint(opened)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_mode & 0o111 == 0
            or _executable_fingerprint(named) != fingerprint
        ):
            raise ValueError("command executable is unsafe")
        return PinnedExecutable(str(resolved), descriptor, fingerprint)
    except BaseException:
        os.close(descriptor)
        raise


def _verify_pinned_executable(executable: PinnedExecutable) -> None:
    try:
        opened = os.fstat(executable.descriptor)
        named = os.stat(executable.path, follow_symlinks=False)
    except OSError as error:
        raise ValueError("command executable changed") from error
    if (
        _executable_fingerprint(opened) != executable.fingerprint
        or _executable_fingerprint(named) != executable.fingerprint
    ):
        raise ValueError("command executable changed")


def _command_leader_exited(process: subprocess.Popen[bytes]) -> bool:
    try:
        status = os.waitid(
            os.P_PID,
            process.pid,
            os.WEXITED | os.WNOHANG | os.WNOWAIT,
        )
    except ChildProcessError as error:
        raise ProcessOwnershipLost("command leader ownership was lost") from error
    return status is not None


def _command_group_exists(group: int) -> bool:
    try:
        os.killpg(group, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _terminate_command_group(
    process: subprocess.Popen[bytes], *, leader_exited: bool
) -> OSError | None:
    group = process.pid
    if not leader_exited:
        try:
            current_group = os.getpgid(process.pid)
        except ProcessLookupError:
            if not _command_leader_exited(process):
                raise ProcessOwnershipLost("command group ownership was lost")
            leader_exited = True
            current_group = group
        except OSError as error:
            raise ValueError("command group identity cannot be verified") from error
        if current_group != group:
            raise ValueError("command escaped its owned process group")
    try:
        os.killpg(group, signal.SIGKILL)
    except ProcessLookupError:
        return None
    except OSError as error:
        if leader_exited and error.errno in {errno.ESRCH, errno.EPERM}:
            return error
        raise ValueError("command process group cannot be terminated") from error
    return None


def _finalize_command_group(
    process: subprocess.Popen[bytes], *, leader_exited: bool
) -> int:
    kill_error = _terminate_command_group(process, leader_exited=leader_exited)
    try:
        return_code = process.wait(timeout=COMMAND_REAP_SECONDS)
    except subprocess.TimeoutExpired as error:
        raise ValueError("command leader cannot be reaped") from error
    if kill_error is not None and _command_group_exists(process.pid):
        raise ValueError("command process group could not be killed") from kill_error
    return return_code


def _clean_command_detail(payload: bytes) -> str:
    value = payload[:4096].decode("utf-8", "replace")
    cleaned = " ".join(
        "".join(character if character.isprintable() else " " for character in value).split()
    )
    return cleaned or "no diagnostic output"


def _run_bounded(
    arguments: Sequence[str],
    cwd: Path | None,
    *,
    environment: dict[str, str] | None = None,
    pass_fds: tuple[int, ...] = (),
) -> bytes:
    if (
        os.name != "posix"
        or not hasattr(os, "waitid")
        or not hasattr(os, "killpg")
        or not hasattr(os, "WNOWAIT")
        or signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL
    ):
        raise ValueError("bounded commands require POSIX process groups and waitid")
    if not arguments or any(type(value) is not str or not value for value in arguments):
        raise ValueError("command arguments are invalid")

    executable = _pin_exact_executable(arguments[0])
    command = [executable.path, *arguments[1:]]
    try:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            close_fds=True,
            pass_fds=pass_fds,
        )
    except OSError as error:
        os.close(executable.descriptor)
        raise ValueError(f"command could not start: {command[0]}") from error
    except BaseException:
        os.close(executable.descriptor)
        raise

    selector = selectors.DefaultSelector()
    leader_exited = False
    ownership_lost = False
    failure: str | None = None
    stdout = bytearray()
    stderr = bytearray()
    total = 0
    deadline = time.monotonic() + COMMAND_TIMEOUT_SECONDS
    try:
        _verify_pinned_executable(executable)
        if process.stdout is None or process.stderr is None:
            raise ValueError("command output pipes were not created")
        streams = {
            process.stdout.fileno(): (process.stdout, stdout),
            process.stderr.fileno(): (process.stderr, stderr),
        }
        for descriptor, (stream, _target) in streams.items():
            os.set_blocking(descriptor, False)
            selector.register(stream, selectors.EVENT_READ)

        while not leader_exited and failure is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                failure = "command timed out"
                break
            for key, _mask in selector.select(min(COMMAND_POLL_SECONDS, remaining)):
                descriptor = key.fileobj.fileno()
                try:
                    chunk = os.read(descriptor, COMMAND_READ_CHUNK)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                total += len(chunk)
                if total > MAX_COMMAND_OUTPUT:
                    failure = "command output is too large"
                    break
                streams[descriptor][1].extend(chunk)
            try:
                leader_exited = _command_leader_exited(process)
            except ProcessOwnershipLost:
                ownership_lost = True
                raise

        if not leader_exited:
            try:
                leader_exited = _command_leader_exited(process)
            except ProcessOwnershipLost:
                ownership_lost = True
                raise
        return_code = _finalize_command_group(process, leader_exited=leader_exited)
        _verify_pinned_executable(executable)

        drain_deadline = time.monotonic() + COMMAND_DRAIN_SECONDS
        while selector.get_map() and time.monotonic() < drain_deadline:
            for key, _mask in selector.select(COMMAND_POLL_SECONDS):
                descriptor = key.fileobj.fileno()
                try:
                    chunk = os.read(descriptor, COMMAND_READ_CHUNK)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                total += len(chunk)
                if failure is None and total > MAX_COMMAND_OUTPUT:
                    failure = "command output is too large"
                if total <= MAX_COMMAND_OUTPUT:
                    streams[descriptor][1].extend(chunk)
        if selector.get_map() and failure is None:
            failure = "command descendants retained output pipes"
        if failure is not None:
            raise ValueError(failure)
        if return_code != 0:
            raise ValueError(
                f"command failed: {command[0]}: {_clean_command_detail(bytes(stderr))}"
            )
        return bytes(stdout)
    except BaseException as primary_error:
        if process.returncode is None and not ownership_lost:
            try:
                if not leader_exited:
                    leader_exited = _command_leader_exited(process)
                _finalize_command_group(process, leader_exited=leader_exited)
            except BaseException as cleanup_error:
                if hasattr(primary_error, "add_note"):
                    primary_error.add_note(f"command cleanup also failed: {cleanup_error}")
        raise
    finally:
        selector.close()
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()
        os.close(executable.descriptor)


def _directory_flags() -> int:
    required = ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC")
    values = {name: getattr(os, name, 0) for name in required}
    if (
        os.name != "posix"
        or os.open not in getattr(os, "supports_dir_fd", ())
        or any(type(value) is not int or value == 0 for value in values.values())
    ):
        raise ValueError("secure input paths require POSIX dir_fd and O_NOFOLLOW")
    return os.O_RDONLY | values["O_DIRECTORY"] | values["O_NOFOLLOW"] | values["O_CLOEXEC"]


def _directory_identity(metadata: os.stat_result) -> tuple[int, int, int]:
    if not stat.S_ISDIR(metadata.st_mode):
        raise ValueError("pinned input path is not a directory")
    return int(metadata.st_dev), int(metadata.st_ino), int(metadata.st_mode)


def _absolute_path(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _open_canonical_directory(path: Path) -> int:
    if not path.is_absolute():
        raise ValueError("canonical input directory is not absolute")
    flags = _directory_flags()
    anchor = Path(path.anchor)
    try:
        descriptor = os.open(anchor, flags)
    except OSError as error:
        raise ValueError("input directory anchor cannot be opened") from error
    try:
        for part in path.relative_to(anchor).parts:
            child = os.open(part, flags, dir_fd=descriptor)
            previous = descriptor
            descriptor = child
            os.close(previous)
        return descriptor
    except OSError as error:
        os.close(descriptor)
        raise ValueError("input directory has a changed or symlinked ancestor") from error
    except BaseException:
        os.close(descriptor)
        raise


def _verify_pinned_directory(directory: PinnedDirectory) -> None:
    try:
        opened = _directory_identity(os.fstat(directory.descriptor))
        canonical = _directory_identity(os.stat(directory.canonical_path))
        requested = _directory_identity(os.stat(directory.requested_path))
    except OSError as error:
        raise ValueError("pinned input directory changed") from error
    if opened != directory.identity or canonical != directory.identity or requested != directory.identity:
        raise ValueError("pinned input directory changed")


def _pin_directory(path: Path, label: str = "input directory") -> PinnedDirectory:
    requested = _absolute_path(path)
    try:
        canonical = requested.resolve(strict=True)
    except OSError as error:
        raise ValueError(f"{label} cannot be resolved") from error
    descriptor = _open_canonical_directory(canonical)
    try:
        directory = PinnedDirectory(
            requested_path=requested,
            canonical_path=canonical,
            descriptor=descriptor,
            identity=_directory_identity(os.fstat(descriptor)),
        )
        _verify_pinned_directory(directory)
        return directory
    except BaseException:
        os.close(descriptor)
        raise


def _close_pinned_directory(directory: PinnedDirectory) -> None:
    os.close(directory.descriptor)


def _relative_parts(value: str | Path, label: str, *, allow_dot: bool = False) -> tuple[str, ...]:
    raw = os.fspath(value)
    if not isinstance(raw, str) or not raw or "\\" in raw or "\0" in raw:
        raise ValueError(f"{label} is invalid")
    path = PurePosixPath(raw)
    if path.is_absolute() or any(part in {"", ".."} for part in path.parts):
        raise ValueError(f"{label} is invalid")
    canonical = path.as_posix()
    if canonical == ".":
        if allow_dot and raw == ".":
            return ()
        raise ValueError(f"{label} is invalid")
    if canonical != raw or any(part == "." for part in path.parts):
        raise ValueError(f"{label} is not canonical")
    return path.parts


def _pin_relative_directory(
    root: PinnedDirectory, relative: str | Path, label: str
) -> PinnedDirectory:
    parts = _relative_parts(relative, label, allow_dot=True)
    flags = _directory_flags()
    _verify_pinned_directory(root)
    descriptor = os.dup(root.descriptor)
    os.set_inheritable(descriptor, False)
    try:
        for part in parts:
            child = os.open(part, flags, dir_fd=descriptor)
            previous = descriptor
            descriptor = child
            os.close(previous)
        suffix = Path(*parts) if parts else Path(".")
        directory = PinnedDirectory(
            requested_path=root.requested_path / suffix,
            canonical_path=root.canonical_path / suffix,
            descriptor=descriptor,
            identity=_directory_identity(os.fstat(descriptor)),
        )
        _verify_pinned_directory(root)
        _verify_pinned_directory(directory)
        return directory
    except OSError as error:
        os.close(descriptor)
        raise ValueError(f"{label} has a changed or symlinked ancestor") from error
    except BaseException:
        os.close(descriptor)
        raise


def _file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_mode),
        int(metadata.st_nlink),
        int(metadata.st_size),
        int(metadata.st_mtime_ns),
        int(metadata.st_ctime_ns),
    )


def _open_relative_regular(
    directory: PinnedDirectory, relative: str | Path, label: str
) -> tuple[int, os.stat_result]:
    parts = _relative_parts(relative, label)
    dir_flags = _directory_flags()
    leaf_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    _verify_pinned_directory(directory)
    descriptor: int | None = None
    try:
        with contextlib.ExitStack() as parents:
            parent = directory.descriptor
            for part in parts[:-1]:
                parent = os.open(part, dir_flags, dir_fd=parent)
                parents.callback(os.close, parent)
            descriptor = os.open(parts[-1], leaf_flags, dir_fd=parent)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError(f"{label} is not a single-link regular file")
        return descriptor, metadata
    except OSError as error:
        if descriptor is not None:
            os.close(descriptor)
        raise ValueError(f"{label} has a changed or symlinked path") from error
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
        raise


def _read_regular_at(
    directory: PinnedDirectory,
    relative: str | Path,
    maximum: int,
    label: str,
) -> bytes:
    descriptor, opened = _open_relative_regular(directory, relative, label)
    identity = _file_identity(opened)
    if opened.st_size < 0 or opened.st_size > maximum:
        os.close(descriptor)
        raise ValueError(f"{label} exceeds the safety limit")
    try:
        chunks: list[bytes] = []
        total = 0
        while total <= maximum:
            chunk = os.read(descriptor, min(64 * 1024, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        value = b"".join(chunks)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if len(value) > maximum:
        raise ValueError(f"{label} exceeds the safety limit")
    reopened, reopened_metadata = _open_relative_regular(directory, relative, label)
    os.close(reopened)
    if _file_identity(after) != identity or _file_identity(reopened_metadata) != identity:
        raise ValueError(f"{label} changed while reading")
    _verify_pinned_directory(directory)
    return value


def _write_new_regular_at(
    directory: PinnedDirectory, name: str, payload: bytes, mode: int = 0o600
) -> None:
    parts = _relative_parts(name, "snapshot filename")
    if len(parts) != 1:
        raise ValueError("snapshot filename must be a basename")
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    _verify_pinned_directory(directory)
    try:
        descriptor = os.open(parts[0], flags, mode, dir_fd=directory.descriptor)
    except OSError as error:
        raise ValueError("snapshot destination is unsafe") from error
    try:
        remaining = memoryview(payload)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OSError("snapshot write made no progress")
            remaining = remaining[written:]
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
        identity = _file_identity(os.fstat(descriptor))
    finally:
        os.close(descriptor)
    reopened, metadata = _open_relative_regular(directory, parts[0], "snapshot file")
    os.close(reopened)
    if metadata.st_size != len(payload) or _file_identity(metadata) != identity:
        raise ValueError("snapshot file changed while publishing")
    os.fsync(directory.descriptor)
    _verify_pinned_directory(directory)


def _create_pinned_directory(path: Path, label: str) -> PinnedDirectory:
    requested = _absolute_path(path)
    if requested.name in {"", ".", ".."}:
        raise ValueError(f"{label} path is invalid")
    parent = _pin_directory(requested.parent, f"{label} parent")
    descriptor: int | None = None
    try:
        os.mkdir(requested.name, 0o700, dir_fd=parent.descriptor)
        descriptor = os.open(requested.name, _directory_flags(), dir_fd=parent.descriptor)
        os.fchmod(descriptor, 0o700)
        os.fsync(parent.descriptor)
        directory = PinnedDirectory(
            requested_path=requested,
            canonical_path=parent.canonical_path / requested.name,
            descriptor=descriptor,
            identity=_directory_identity(os.fstat(descriptor)),
        )
        _verify_pinned_directory(parent)
        _verify_pinned_directory(directory)
        descriptor = None
        return directory
    except OSError as error:
        if descriptor is not None:
            os.close(descriptor)
        raise ValueError(f"{label} cannot be created securely") from error
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
        raise
    finally:
        _close_pinned_directory(parent)


def _sanitized_search_path(
    environment: dict[str, str], forbidden_root: Path
) -> str:
    values: list[str] = []
    seen: set[str] = set()
    forbidden_root = forbidden_root.resolve(strict=True)
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
            resolved.relative_to(forbidden_root)
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


def _trusted_tool(name: str, environment: dict[str, str]) -> str:
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


def _base_environment(source: dict[str, str], forbidden_root: Path) -> dict[str, str]:
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
    environment["PATH"] = _sanitized_search_path(environment, forbidden_root)
    return environment


def _run_tool_in_directory(
    executable: str,
    arguments: Sequence[str],
    directory: PinnedDirectory,
    environment: dict[str, str],
) -> bytes:
    tool = _pin_exact_executable(executable)
    try:
        _verify_pinned_directory(directory)
        output = _run_bounded(
            (
                sys.executable,
                "-I",
                "-c",
                FCHDIR_EXEC_HELPER,
                str(directory.descriptor),
                tool.path,
                *arguments,
            ),
            None,
            environment=environment,
            pass_fds=(directory.descriptor,),
        )
        _verify_pinned_executable(tool)
        _verify_pinned_directory(directory)
        return output
    finally:
        os.close(tool.descriptor)


def _git(root: Path | PinnedDirectory, *arguments: str) -> bytes:
    owned = not isinstance(root, PinnedDirectory)
    directory = _pin_directory(root, "repository root") if owned else root
    base = _base_environment(dict(os.environ), directory.canonical_path)
    environment = {
        key: value for key, value in base.items() if not key.startswith("GIT_")
    }
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_CONFIG_COUNT": "3",
            "GIT_CONFIG_KEY_0": "core.fsmonitor",
            "GIT_CONFIG_VALUE_0": "false",
            "GIT_CONFIG_KEY_1": "core.hooksPath",
            "GIT_CONFIG_VALUE_1": os.devnull,
            "GIT_CONFIG_KEY_2": "core.fileMode",
            "GIT_CONFIG_VALUE_2": "true",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "LC_ALL": "C",
        }
    )
    git_executable = _trusted_tool("git", environment)
    try:
        return _run_tool_in_directory(
            git_executable,
            (
                "--no-pager",
                "-c",
                "core.fsmonitor=false",
                "-c",
                f"core.hooksPath={os.devnull}",
                "-c",
                "core.fileMode=true",
                *arguments,
            ),
            directory,
            environment,
        )
    finally:
        if owned:
            _close_pinned_directory(directory)


def _run_go_in_directory(
    arguments: Sequence[str], directory: PinnedDirectory
) -> bytes:
    if not arguments or arguments[0] != "go":
        raise ValueError("unexpected Go command")
    environment = _base_environment(dict(os.environ), directory.canonical_path)
    for key in tuple(environment):
        if (
            key in {"AR", "CC", "CXX", "FC", "GCCGO", "GOROOT", "PKG_CONFIG"}
            or key.startswith("CGO_")
            or key.startswith("GIT_")
        ):
            environment.pop(key, None)
    environment.update(
        {
            "GO111MODULE": "on",
            "GOENV": "off",
            "GOFLAGS": "",
            "GOTOOLCHAIN": "local",
            "GOWORK": "off",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_CONFIG_COUNT": "3",
            "GIT_CONFIG_KEY_0": "core.fsmonitor",
            "GIT_CONFIG_VALUE_0": "false",
            "GIT_CONFIG_KEY_1": "core.hooksPath",
            "GIT_CONFIG_VALUE_1": os.devnull,
            "GIT_CONFIG_KEY_2": "core.fileMode",
            "GIT_CONFIG_VALUE_2": "true",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "LC_ALL": "C",
        }
    )
    go_executable = _trusted_tool("go", environment)
    git_executable = _trusted_tool("git", environment)
    environment["PATH"] = os.pathsep.join(
        dict.fromkeys(
            [
                str(Path(go_executable).parent),
                str(Path(git_executable).parent),
                *environment["PATH"].split(os.pathsep),
            ]
        )
    )
    return _run_tool_in_directory(
        go_executable,
        arguments[1:],
        directory,
        environment,
    )


def _run_go_bounded(arguments: Sequence[str], cwd: Path) -> bytes:
    directory = _pin_directory(cwd, "Go module directory")
    try:
        return _run_go_in_directory(arguments, directory)
    finally:
        _close_pinned_directory(directory)


def _canonical_root(root: Path) -> Path:
    directory = _pin_directory(root, "repository root")
    try:
        top = _git(directory, "rev-parse", "--show-toplevel").decode(
            "utf-8", "strict"
        ).strip()
        try:
            top_path = Path(top).resolve(strict=True)
            top_identity = _directory_identity(os.stat(top_path))
        except OSError as error:
            raise ValueError("Git worktree root changed") from error
        _verify_pinned_directory(directory)
        if top_path != directory.canonical_path or top_identity != directory.identity:
            raise ValueError("repository path is not the Git worktree root")
        return directory.canonical_path
    finally:
        _close_pinned_directory(directory)


def _relative_pin(value: str) -> str:
    return PurePosixPath(*_relative_parts(value, "pin path")).as_posix()


def _require_expected_head(root: Path | PinnedDirectory, expected_head: str) -> None:
    if FULL_COMMIT.fullmatch(expected_head) is None:
        raise ValueError("expected build commit is invalid")
    actual = _git(root, "rev-parse", "--verify", "HEAD^{commit}").decode(
        "ascii", "strict"
    ).strip()
    if actual != expected_head:
        raise ValueError("repository HEAD moved away from the expected build commit")


def _is_non_build_ignored(path: str) -> bool:
    parts = Path(path).parts
    return Path(path).name == ".DS_Store" or "__pycache__" in parts


def _is_generated_output(path: str) -> bool:
    return path.startswith("dist/") or path.startswith("dist-repro/")


def _assert_default_index_entries(
    root: Path | PinnedDirectory,
) -> tuple[tuple[str, str, str, int], ...]:
    output = _git(
        root,
        "ls-files",
        "-v",
        "--stage",
        "--debug",
        "-z",
        "--",
    )
    offset = 0
    paths: set[str] = set()
    entries: list[tuple[str, str, str, int]] = []
    while offset < len(output):
        end = output.find(b"\0", offset)
        if end < 0:
            raise ValueError("Git returned malformed index metadata")
        header = output[offset:end]
        debug = INDEX_DEBUG_METADATA.match(output, end + 1)
        if debug is None:
            raise ValueError("Git returned malformed index debug metadata")
        offset = debug.end()
        try:
            metadata, raw_path = header.split(b"\t", 1)
            tag, mode, object_id, stage = metadata.split(b" ")
            path = raw_path.decode("utf-8", "strict")
            flags = int(debug.group(1), 16)
        except (UnicodeDecodeError, ValueError) as error:
            raise ValueError("Git returned malformed index entry") from error
        if (
            tag != b"H"
            or flags != 0
            or stage != b"0"
            or mode not in {b"100644", b"100755"}
            or re.fullmatch(rb"[0-9a-f]{40}|[0-9a-f]{64}", object_id) is None
        ):
            raise ValueError("Git index contains non-default entry flags or state")
        canonical = _decode_paths(raw_path + b"\0", "Git index")
        if canonical != {path} or path in paths:
            raise ValueError("Git index contains a duplicate or noncanonical path")
        paths.add(path)
        entries.append(
            (
                path,
                mode.decode("ascii", "strict"),
                object_id.decode("ascii", "strict"),
                int(stage),
            )
        )
    return tuple(sorted(entries))


@dataclass(frozen=True)
class _RepositoryStateSnapshot:
    index_entries: tuple[tuple[str, str, str, int], ...]
    staged: frozenset[str]
    unstaged: frozenset[str]
    untracked: frozenset[str]
    ignored: frozenset[str]


def _scan_repository_state(
    directory: PinnedDirectory,
    expected_head: str,
    allowed: set[str],
    *,
    allow_generated: bool,
) -> _RepositoryStateSnapshot:
    if _git(directory, "rev-parse", "--shared-index-path").strip():
        raise ValueError("split Git index is forbidden for release inputs")
    _require_expected_head(directory, expected_head)
    index_before = _assert_default_index_entries(directory)
    staged = _decode_paths(
        _git(
            directory,
            "diff",
            "--no-ext-diff",
            "--cached",
            "--name-only",
            "-z",
            "HEAD",
            "--",
        ),
        "staged changes",
    )
    unstaged = _decode_paths(
        _git(
            directory,
            "diff",
            "--no-ext-diff",
            "--name-only",
            "-z",
            "--",
        ),
        "unstaged changes",
    )
    if staged:
        raise ValueError(
            "unexpected staged build input: " + ", ".join(sorted(staged))
        )
    unexpected_tracked = unstaged - allowed
    if unexpected_tracked:
        raise ValueError(
            "unexpected tracked build input: "
            + ", ".join(sorted(unexpected_tracked))
        )

    untracked = _decode_paths(
        _git(directory, "ls-files", "--others", "--exclude-standard", "-z"),
        "untracked files",
    )
    if untracked:
        raise ValueError(
            "unexpected untracked build input: " + ", ".join(sorted(untracked))
        )

    ignored = _decode_paths(
        _git(
            directory,
            "ls-files",
            "--others",
            "--ignored",
            "--exclude-standard",
            "-z",
        ),
        "ignored files",
    )
    unexpected_ignored = {
        value
        for value in ignored
        if not _is_non_build_ignored(value)
        and not (allow_generated and _is_generated_output(value))
    }
    if unexpected_ignored:
        raise ValueError(
            "unexpected ignored build input: "
            + ", ".join(sorted(unexpected_ignored))
        )
    index_after = _assert_default_index_entries(directory)
    if index_after != index_before:
        raise ValueError("Git index logical state changed during repository scan")
    if _git(directory, "rev-parse", "--shared-index-path").strip():
        raise ValueError("split Git index is forbidden for release inputs")
    _require_expected_head(directory, expected_head)
    return _RepositoryStateSnapshot(
        index_entries=index_after,
        staged=frozenset(staged),
        unstaged=frozenset(unstaged),
        untracked=frozenset(untracked),
        ignored=frozenset(ignored),
    )


def assert_repository_state(
    root: Path,
    expected_head: str,
    allowed_tracked: set[str],
    *,
    allow_generated: bool = False,
) -> None:
    root = _canonical_root(root)
    allowed = {_relative_pin(value) for value in allowed_tracked}
    directory = _pin_directory(root, "repository root")
    git_directory: PinnedDirectory | None = None
    index_descriptor: int | None = None
    try:
        git_directory = _pin_relative_directory(
            directory, ".git", "Git metadata directory"
        )
        # Git may atomically rewrite an otherwise equivalent index merely to
        # refresh its stat cache. Let one complete logical scan settle that
        # implementation detail before pinning the physical index. The second
        # scan must match the first and runs while both the chosen index inode
        # and its path are pinned, retaining concurrent-mutation detection.
        settled_state = _scan_repository_state(
            directory,
            expected_head,
            allowed,
            allow_generated=allow_generated,
        )
        index_descriptor, index_metadata = _open_relative_regular(
            git_directory, "index", "Git index"
        )
        index_identity = _file_identity(index_metadata)
        protected_state = _scan_repository_state(
            directory,
            expected_head,
            allowed,
            allow_generated=allow_generated,
        )
        if protected_state != settled_state:
            raise ValueError(
                "repository logical state changed after Git index settlement"
            )
        if _file_identity(os.fstat(index_descriptor)) != index_identity:
            raise ValueError("Git index changed during release input verification")
        reopened_index, reopened_metadata = _open_relative_regular(
            git_directory, "index", "Git index"
        )
        os.close(reopened_index)
        if _file_identity(reopened_metadata) != index_identity:
            raise ValueError("Git index changed during release input verification")
        _verify_pinned_directory(git_directory)
        _verify_pinned_directory(directory)
    finally:
        if index_descriptor is not None:
            os.close(index_descriptor)
        if git_directory is not None:
            _close_pinned_directory(git_directory)
        _close_pinned_directory(directory)


def _parse_json_object(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{label} is not valid JSON") from error
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def verify_module_origin(
    module_dir: Path | PinnedDirectory,
    module_path: str,
    expected_commit: str,
    expected_version: str | None = None,
    *,
    run_command: RunCommand | None = None,
) -> str:
    if not module_path or any(character.isspace() for character in module_path):
        raise ValueError("module path is invalid")
    if FULL_COMMIT.fullmatch(expected_commit) is None:
        raise ValueError("upstream commit is invalid")
    with contextlib.ExitStack() as resources:
        if run_command is None:
            if isinstance(module_dir, PinnedDirectory):
                directory = module_dir
            else:
                directory = _pin_directory(module_dir, "Go module directory")
                resources.callback(_close_pinned_directory, directory)
            run_command = lambda arguments, _cwd: _run_go_in_directory(
                arguments, directory
            )
            command_directory = directory.canonical_path
        else:
            command_directory = (
                module_dir.canonical_path
                if isinstance(module_dir, PinnedDirectory)
                else module_dir
            )

        selected = _parse_json_object(
            run_command(("go", "list", "-m", "-json", module_path), command_directory),
            "selected module",
        )
        if selected.get("Path") != module_path:
            raise ValueError("selected module path does not match")
        if "Error" in selected:
            raise ValueError("selected module reports a resolution error")
        if "Replace" in selected:
            raise ValueError("module replacement is forbidden")
        version = selected.get("Version")
        if not isinstance(version, str) or not version:
            raise ValueError("selected module version is missing")
        if expected_version is not None and version != expected_version:
            raise ValueError("selected module version does not match")

        downloaded = _parse_json_object(
            run_command(
                ("go", "mod", "download", "-json", f"{module_path}@{version}"),
                command_directory,
            ),
            "downloaded module",
        )
        if downloaded.get("Path") != module_path or downloaded.get("Version") != version:
            raise ValueError("downloaded module identity does not match")
        if "Error" in downloaded:
            raise ValueError("downloaded module reports a resolution error")
        if "Replace" in downloaded:
            raise ValueError("downloaded module replacement is forbidden")
        origin = downloaded.get("Origin")
        if not isinstance(origin, dict):
            raise ValueError("downloaded module origin is missing")
        if origin.get("VCS") != "git" or origin.get("Hash") != expected_commit:
            raise ValueError("downloaded module origin does not match the pinned commit")
        if run_command is not None and isinstance(module_dir, PinnedDirectory):
            _verify_pinned_directory(module_dir)
        return version


def _read_pin(root: Path | PinnedDirectory, relative: str) -> bytes:
    canonical = _relative_pin(relative)
    owned = not isinstance(root, PinnedDirectory)
    directory = _pin_directory(root, "repository root") if owned else root
    try:
        return _read_regular_at(directory, canonical, MAX_PIN_BYTES, f"pin {canonical}")
    finally:
        if owned:
            _close_pinned_directory(directory)


def _read_regular_stable(path: Path, maximum: int, label: str) -> bytes:
    requested = _absolute_path(path)
    directory = _pin_directory(requested.parent, f"{label} parent")
    try:
        return _read_regular_at(directory, requested.name, maximum, label)
    finally:
        _close_pinned_directory(directory)


def capture_snapshot(
    root: Path,
    snapshot: Path,
    pins: list[str],
    module_path: str,
    module_version: str,
    expected_commit: str,
) -> str:
    root = _canonical_root(root)
    snapshot = _absolute_path(snapshot)
    try:
        snapshot_parent = snapshot.parent.resolve(strict=True)
    except OSError as error:
        raise ValueError("snapshot parent does not exist") from error
    snapshot_canonical = snapshot_parent / snapshot.name
    try:
        snapshot_canonical.relative_to(root)
    except ValueError:
        pass
    else:
        raise ValueError("snapshot must be outside the repository")
    canonical_pins = [_relative_pin(value) for value in pins]
    basenames = [Path(value).name for value in canonical_pins]
    if len(canonical_pins) != len(set(canonical_pins)) or len(basenames) != len(set(basenames)):
        raise ValueError("pin paths must be unique")
    root_directory = _pin_directory(root, "repository root")
    snapshot_directory: PinnedDirectory | None = None
    try:
        snapshot_directory = _create_pinned_directory(snapshot, "snapshot")
        if snapshot_directory.canonical_path != snapshot_canonical:
            raise ValueError("snapshot parent changed during creation")
        try:
            snapshot_directory.canonical_path.relative_to(root)
        except ValueError:
            pass
        else:
            raise ValueError("snapshot must remain outside the repository")
        records: list[dict[str, Any]] = []
        for relative, basename in zip(canonical_pins, basenames):
            value = _read_pin(root_directory, relative)
            _write_new_regular_at(snapshot_directory, basename, value)
            records.append(
                {
                    "path": relative,
                    "file": basename,
                    "size": len(value),
                    "sha256": hashlib.sha256(value).hexdigest(),
                }
            )
        metadata = {
            "schema": 1,
            "modulePath": module_path,
            "moduleVersion": module_version,
            "originCommit": expected_commit,
            "pins": records,
        }
        metadata_raw = (
            json.dumps(metadata, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        _write_new_regular_at(snapshot_directory, "snapshot.json", metadata_raw)
        _verify_pinned_directory(root_directory)
        _verify_pinned_directory(snapshot_directory)
        return hashlib.sha256(metadata_raw).hexdigest()
    finally:
        if snapshot_directory is not None:
            _close_pinned_directory(snapshot_directory)
        _close_pinned_directory(root_directory)


def verify_snapshot(
    root: Path, snapshot: Path, pins: list[str], expected_metadata_sha256: str
) -> None:
    root = _canonical_root(root)
    root_directory = _pin_directory(root, "repository root")
    snapshot_directory = _pin_directory(snapshot, "snapshot directory")
    try:
        try:
            snapshot_directory.canonical_path.relative_to(root)
        except ValueError:
            pass
        else:
            raise ValueError("snapshot must be outside the repository")
        metadata_raw = _read_regular_at(
            snapshot_directory, "snapshot.json", MAX_PIN_BYTES, "snapshot metadata"
        )
        if (
            re.fullmatch(r"[0-9a-f]{64}", expected_metadata_sha256) is None
            or hashlib.sha256(metadata_raw).hexdigest() != expected_metadata_sha256
        ):
            raise ValueError("snapshot metadata digest does not match the pre-test value")
        metadata = _parse_json_object(metadata_raw, "snapshot metadata")
        records = metadata.get("pins")
        canonical_pins = [_relative_pin(value) for value in pins]
        if metadata.get("schema") != 1 or not isinstance(records, list):
            raise ValueError("snapshot metadata is invalid")
        if [record.get("path") if isinstance(record, dict) else None for record in records] != canonical_pins:
            raise ValueError("snapshot pin set does not match")
        for record in records:
            assert isinstance(record, dict)
            relative = record["path"]
            basename = record.get("file")
            if not isinstance(basename, str) or basename != Path(relative).name:
                raise ValueError("snapshot pin filename is invalid")
            snapshot_value = _read_regular_at(
                snapshot_directory,
                basename,
                MAX_PIN_BYTES,
                f"snapshot file {basename}",
            )
            current_value = _read_pin(root_directory, relative)
            expected_size = record.get("size")
            expected_digest = record.get("sha256")
            if (
                type(expected_size) is not int
                or expected_size != len(snapshot_value)
                or not isinstance(expected_digest, str)
                or hashlib.sha256(snapshot_value).hexdigest() != expected_digest
                or current_value != snapshot_value
            ):
                raise ValueError(f"pin changed after provenance capture: {relative}")
        _verify_pinned_directory(root_directory)
        _verify_pinned_directory(snapshot_directory)
    finally:
        _close_pinned_directory(snapshot_directory)
        _close_pinned_directory(root_directory)


def verify_module_cache(
    root: Path,
    module_dir: Path,
    expected_head: str,
    pins: list[str],
    *,
    allow_generated: bool = False,
    run_command: RunCommand | None = None,
) -> None:
    root = _canonical_root(root)
    canonical_pins = [_relative_pin(value) for value in pins]
    assert_repository_state(
        root,
        expected_head,
        set(canonical_pins),
        allow_generated=allow_generated,
    )
    root_directory = _pin_directory(root, "repository root")
    module_directory: PinnedDirectory | None = None
    try:
        module_directory = _pin_relative_directory(
            root_directory, module_dir, "module directory"
        )
        if run_command is None:
            _run_go_in_directory(("go", "mod", "verify"), module_directory)
        else:
            run_command(("go", "mod", "verify"), module_directory.canonical_path)
        _verify_pinned_directory(module_directory)
        _verify_pinned_directory(root_directory)
    finally:
        if module_directory is not None:
            _close_pinned_directory(module_directory)
        _close_pinned_directory(root_directory)
    assert_repository_state(
        root,
        expected_head,
        set(canonical_pins),
        allow_generated=allow_generated,
    )


def _read_external_regular(path: Path, maximum: int) -> bytes:
    return _read_regular_stable(path, maximum, f"snapshot file {path.name}")


def snapshot_pin_digest(
    snapshot: Path, expected_metadata_sha256: str, pin: str
) -> str:
    relative = _relative_pin(pin)
    directory = _pin_directory(snapshot, "snapshot directory")
    try:
        metadata_raw = _read_regular_at(
            directory, "snapshot.json", MAX_PIN_BYTES, "snapshot metadata"
        )
        if (
            re.fullmatch(r"[0-9a-f]{64}", expected_metadata_sha256) is None
            or hashlib.sha256(metadata_raw).hexdigest() != expected_metadata_sha256
        ):
            raise ValueError("snapshot metadata digest does not match the captured value")
        metadata = _parse_json_object(metadata_raw, "snapshot metadata")
        records = metadata.get("pins")
        if metadata.get("schema") != 1 or not isinstance(records, list):
            raise ValueError("snapshot metadata is invalid")
        matches = [
            record
            for record in records
            if isinstance(record, dict) and record.get("path") == relative
        ]
        if len(matches) != 1:
            raise ValueError("snapshot pin is missing or duplicated")
        record = matches[0]
        basename = record.get("file")
        size = record.get("size")
        digest = record.get("sha256")
        if (
            basename != Path(relative).name
            or type(size) is not int
            or size < 0
            or size > MAX_PIN_BYTES
            or not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        ):
            raise ValueError("snapshot pin record is invalid")
        _verify_pinned_directory(directory)
        return digest
    finally:
        _close_pinned_directory(directory)


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="mode", required=True)

    preflight = subparsers.add_parser("preflight")
    preflight.add_argument("--repo", type=Path, required=True)
    preflight.add_argument("--expected-head", required=True)

    capture = subparsers.add_parser("capture")
    capture.add_argument("--repo", type=Path, required=True)
    capture.add_argument("--module-dir", type=Path, required=True)
    capture.add_argument("--module-path", required=True)
    capture.add_argument("--commit", required=True)
    capture.add_argument("--expected-head", required=True)
    capture.add_argument("--version")
    capture.add_argument("--snapshot", type=Path, required=True)
    capture.add_argument("--pin", action="append", required=True)

    verify = subparsers.add_parser("verify")
    verify.add_argument("--repo", type=Path, required=True)
    verify.add_argument("--snapshot", type=Path, required=True)
    verify.add_argument("--snapshot-sha256", required=True)
    verify.add_argument("--expected-head", required=True)
    verify.add_argument("--pin", action="append", required=True)
    verify.add_argument("--allow-generated", action="store_true")

    module_cache = subparsers.add_parser("verify-module-cache")
    module_cache.add_argument("--repo", type=Path, required=True)
    module_cache.add_argument("--module-dir", type=Path, required=True)
    module_cache.add_argument("--expected-head", required=True)
    module_cache.add_argument("--pin", action="append", required=True)
    module_cache.add_argument("--allow-generated", action="store_true")

    pin_digest = subparsers.add_parser("snapshot-pin-digest")
    pin_digest.add_argument("--snapshot", type=Path, required=True)
    pin_digest.add_argument("--snapshot-sha256", required=True)
    pin_digest.add_argument("--pin", required=True)
    args = parser.parse_args()

    if args.mode == "preflight":
        assert_repository_state(args.repo, args.expected_head, set())
        assert_repository_state(args.repo, args.expected_head, set())
        print("release build inputs are clean")
        return
    if args.mode == "capture":
        root = _canonical_root(args.repo)
        pins = [_relative_pin(value) for value in args.pin]
        assert_repository_state(root, args.expected_head, set(pins))
        root_directory = _pin_directory(root, "repository root")
        module_directory: PinnedDirectory | None = None
        try:
            module_directory = _pin_relative_directory(
                root_directory, args.module_dir, "module directory"
            )
            version = verify_module_origin(
                module_directory,
                args.module_path,
                args.commit,
                args.version,
            )
            _verify_pinned_directory(module_directory)
            _verify_pinned_directory(root_directory)
        finally:
            if module_directory is not None:
                _close_pinned_directory(module_directory)
            _close_pinned_directory(root_directory)
        assert_repository_state(root, args.expected_head, set(pins))
        digest = capture_snapshot(
            root,
            args.snapshot,
            pins,
            args.module_path,
            version,
            args.commit,
        )
        assert_repository_state(root, args.expected_head, set(pins))
        print(digest)
        return

    if args.mode == "verify-module-cache":
        verify_module_cache(
            args.repo,
            args.module_dir,
            args.expected_head,
            args.pin,
            allow_generated=args.allow_generated,
        )
        print("Go module cache matches all downloaded module checksums")
        return

    if args.mode == "snapshot-pin-digest":
        print(
            snapshot_pin_digest(
                args.snapshot, args.snapshot_sha256, args.pin
            )
        )
        return

    root = _canonical_root(args.repo)
    pins = [_relative_pin(value) for value in args.pin]
    assert_repository_state(
        root,
        args.expected_head,
        set(pins),
        allow_generated=args.allow_generated,
    )
    verify_snapshot(root, args.snapshot, pins, args.snapshot_sha256)
    assert_repository_state(
        root,
        args.expected_head,
        set(pins),
        allow_generated=args.allow_generated,
    )
    print("release build inputs still match the verified snapshot")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        raise SystemExit(f"build input verification failed: {error}") from error
