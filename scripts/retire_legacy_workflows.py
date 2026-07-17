#!/usr/bin/env python3
"""Retire only the two legacy publisher identities with a two-phase proof.

Run the read-only plan and explicit-token apply before publishing the workflow
path migration.  The apply step disables both runtime-discovered identities,
deletes only the approved completed runs, verifies the live state, and writes a
small public receipt.  After the migration is pushed, ``--verify`` checks that
receipt against the live workflow catalog and the repository-wide run list.
No release or tag is modified.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import selectors
import signal
import subprocess
import tempfile
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any


REPOSITORY = "kvuco/exitFy-cores"
GITHUB_HOST = "github.com"
LEGACY_PATHS = (
    ".github/workflows/release-singbox.yml",
    ".github/workflows/release-xray.yml",
)
REPLACEMENT_PATHS = (
    ".github/workflows/publish-singbox-core-v2.yml",
    ".github/workflows/publish-xray-core-v2.yml",
)
RECEIPT_SCHEMA = 1
RECEIPT_PATH = (
    Path(__file__).resolve().parent.parent
    / ".github"
    / "legacy-workflow-retirement.json"
)
MAX_API_BYTES = 64 * 1024 * 1024
MAX_API_DIAGNOSTIC_BYTES = 8 * 1024
API_READ_CHUNK_BYTES = 64 * 1024
PROCESS_POLL_SECONDS = 0.05
PROCESS_TIMEOUT_SECONDS = 90.0
PROCESS_TERMINATE_GRACE_SECONDS = 1.0
PROCESS_POST_EXIT_DRAIN_SECONDS = 1.0
PROCESS_REAP_GRACE_SECONDS = 1.0
MAX_RECEIPT_BYTES = 16 * 1024
FULL_SHA = re.compile(r"[0-9a-f]{40}")


class RetirementError(RuntimeError):
    pass


class GitHubApiUnavailable(RetirementError):
    """The gh transport is unavailable, so a narrow fallback may be tried."""


class _ProcessOwnershipLost(RetirementError):
    """The child was reaped externally, so its numeric PGID is no longer safe."""


@dataclass
class _ProcessCleanupState:
    # Once this flips, no exception path may signal the numeric PGID again:
    # Popen.wait() may already have reaped the leader and released that ID.
    hard_kill_resolved: bool = False
    hard_kill_error: OSError | None = None


class GitHubApi:
    @staticmethod
    def _require_posix_process_groups() -> None:
        required = ("killpg", "waitid", "P_PID", "WEXITED", "WNOHANG", "WNOWAIT")
        if os.name != "posix" or any(not hasattr(os, name) for name in required):
            raise RetirementError(
                "GitHub API capture requires POSIX process groups and waitid WNOWAIT"
            )
        if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
            raise RetirementError(
                "GitHub API capture requires the default SIGCHLD disposition"
            )

    def _start_process(self, arguments: list[str]) -> subprocess.Popen[bytes]:
        return subprocess.Popen(
            ["gh", "api", "--hostname", GITHUB_HOST, *arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
            close_fds=True,
            start_new_session=True,
        )

    @staticmethod
    def _signal_process_group(pgid: int, *, kill: bool) -> bool:
        try:
            os.killpg(pgid, signal.SIGKILL if kill else signal.SIGTERM)
            return True
        except ProcessLookupError:
            return False

    @staticmethod
    def _leader_exited(process: subprocess.Popen[bytes]) -> bool:
        while True:
            try:
                result = os.waitid(
                    os.P_PID,
                    process.pid,
                    os.WEXITED | os.WNOHANG | os.WNOWAIT,
                )
                return result is not None
            except InterruptedError:
                continue
            except ChildProcessError as error:
                raise _ProcessOwnershipLost(
                    "GitHub API process ownership was lost"
                ) from error

    @staticmethod
    def _process_group_exists(pgid: int) -> bool:
        try:
            os.killpg(pgid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True

    @classmethod
    def _kill_group_and_reap(
        cls,
        process: subprocess.Popen[bytes],
        pgid: int,
        cleanup: _ProcessCleanupState,
    ) -> int:
        if not cleanup.hard_kill_resolved:
            kill_error: OSError | None = None
            try:
                cls._signal_process_group(pgid, kill=True)
            except OSError as error:
                kill_error = error
            # This assignment happens before any reap. If an async exception
            # lands before it, the still-unreaped leader keeps PGID retry safe;
            # after it, cleanup only performs a bounded reap and never signals
            # the numeric group identity again.
            cleanup.hard_kill_error = kill_error
            cleanup.hard_kill_resolved = True
        try:
            returncode = process.wait(timeout=PROCESS_REAP_GRACE_SECONDS)
        except subprocess.TimeoutExpired as error:
            raise RetirementError("GitHub API process group did not stop") from error

        # Darwin reports EPERM when a group contains only the unreaped zombie
        # leader. Reaping the leader makes that group disappear. Accept that
        # exact case, but fail closed if any group identity remains afterward.
        if (
            cleanup.hard_kill_error is not None
            and cls._process_group_exists(pgid)
        ):
            raise RetirementError(
                "GitHub API process group could not be killed"
            ) from cleanup.hard_kill_error
        return returncode

    @classmethod
    def _stop_process(
        cls,
        process: subprocess.Popen[bytes],
        pgid: int,
        cleanup: _ProcessCleanupState,
    ) -> int:
        if cleanup.hard_kill_resolved:
            return cls._kill_group_and_reap(process, pgid, cleanup)
        # Every first signal is preceded by an ownership probe. ECHILD means
        # the zombie anchor was reaped elsewhere and this numeric PGID may have
        # been reused; in that state no signal is safe.
        cls._leader_exited(process)
        # start_new_session=True makes pid == pgid == sid. Keep the leader
        # unreaped through this fixed grace period so that the kernel cannot
        # reuse the immutable group identity before the unconditional KILL.
        try:
            cls._signal_process_group(pgid, kill=False)
        except OSError:
            # The unconditional hard kill below remains authoritative.
            pass
        deadline = time.monotonic() + PROCESS_TERMINATE_GRACE_SECONDS
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(PROCESS_POLL_SECONDS, remaining))
        return cls._kill_group_and_reap(process, pgid, cleanup)

    @staticmethod
    def _close_stream(
        selector: selectors.BaseSelector | None, stream: Any
    ) -> None:
        if selector is not None:
            try:
                selector.unregister(stream)
            except (KeyError, ValueError, OSError):
                pass
        try:
            stream.close()
        except (OSError, ValueError):
            pass

    def _capture_process(
        self, process: subprocess.Popen[bytes]
    ) -> tuple[int, bytearray, bytearray, bool, bool]:
        pgid = process.pid
        available_streams = tuple(
            stream
            for stream in (process.stdout, process.stderr)
            if stream is not None
        )
        output = {"stdout": bytearray(), "stderr": bytearray()}
        captured_bytes = 0
        overflow = False
        timed_out = False
        post_exit_deadline: float | None = None
        command_deadline = time.monotonic() + PROCESS_TIMEOUT_SECONDS
        selector: selectors.BaseSelector | None = None
        streams = available_streams
        cleanup = _ProcessCleanupState()
        group_finalized = False
        returncode: int | None = None

        try:
            if process.stdout is None or process.stderr is None:
                self._stop_process(process, pgid, cleanup)
                group_finalized = True
                raise RetirementError("GitHub API process pipes are unavailable")

            selector = selectors.DefaultSelector()
            for name, stream in zip(("stdout", "stderr"), streams):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, name)

            while True:
                now = time.monotonic()
                # The command deadline is absolute. Once it has elapsed, do
                # not retroactively accept a process first observed as exited
                # after the boundary.
                if returncode is None and now >= command_deadline:
                    timed_out = True
                    returncode = self._stop_process(process, pgid, cleanup)
                    group_finalized = True
                    break

                if returncode is None:
                    leader_exited = self._leader_exited(process)
                    now = time.monotonic()
                    # waitid is nonblocking, but the Python thread can still be
                    # descheduled around it. Arbitrate again at the instant the
                    # exit result is first observed, not using a stale clock.
                    if now >= command_deadline:
                        timed_out = True
                        returncode = self._stop_process(process, pgid, cleanup)
                        group_finalized = True
                        break
                    if leader_exited:
                        # The WNOWAIT zombie pins pid/pgid until this KILL has
                        # removed every same-session descendant. A child that
                        # deliberately calls setsid() is outside this fixed gh
                        # command's cleanup contract.
                        returncode = self._kill_group_and_reap(
                            process, pgid, cleanup
                        )
                        group_finalized = True
                        post_exit_deadline = (
                            now + PROCESS_POST_EXIT_DRAIN_SECONDS
                        )

                if returncode is not None and not selector.get_map():
                    break

                select_timeout = PROCESS_POLL_SECONDS
                if returncode is None:
                    select_timeout = min(
                        select_timeout, max(0.0, command_deadline - now)
                    )
                elif post_exit_deadline is not None:
                    select_timeout = min(
                        select_timeout, max(0.0, post_exit_deadline - now)
                    )
                events = selector.select(select_timeout)
                for key, _ in events:
                    stream = key.fileobj
                    try:
                        chunk = os.read(stream.fileno(), API_READ_CHUNK_BYTES)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        self._close_stream(selector, stream)
                        continue

                    remaining = max(0, MAX_API_BYTES - captured_bytes)
                    if remaining:
                        accepted = chunk[:remaining]
                        output[key.data].extend(accepted)
                        captured_bytes += len(accepted)
                    if len(chunk) > remaining:
                        overflow = True

                if overflow and returncode is None:
                    returncode = self._stop_process(process, pgid, cleanup)
                    group_finalized = True
                    break

                now = time.monotonic()
                if (
                    returncode is not None
                    and post_exit_deadline is not None
                    and now >= post_exit_deadline
                    and selector.get_map()
                ):
                    for key in tuple(selector.get_map().values()):
                        self._close_stream(selector, key.fileobj)

            if returncode is None:
                raise RetirementError("GitHub API process result is unavailable")
            return returncode, output["stdout"], output["stderr"], overflow, timed_out
        except BaseException as error:
            # ECHILD means another handler/thread reaped the session leader.
            # Its numeric PID/PGID is no longer anchored and may already have
            # been reused, so sending either TERM or KILL would be unsafe.
            if isinstance(error, _ProcessOwnershipLost):
                group_finalized = True
            if not group_finalized:
                try:
                    self._stop_process(process, pgid, cleanup)
                except _ProcessOwnershipLost as ownership_error:
                    if hasattr(ownership_error, "add_note"):
                        ownership_error.add_note(
                            f"original capture error: {error}"
                        )
                    raise ownership_error from error
                except BaseException as cleanup_error:
                    failure = RetirementError("GitHub API process cleanup failed")
                    if hasattr(failure, "add_note"):
                        failure.add_note(f"original capture error: {error}")
                    raise failure from cleanup_error
            if isinstance(error, (KeyboardInterrupt, SystemExit, RetirementError)):
                raise
            raise RetirementError("GitHub API capture failed") from error
        finally:
            for stream in streams:
                self._close_stream(selector, stream)
            if selector is not None:
                try:
                    selector.close()
                except OSError:
                    pass

    @staticmethod
    def _error_detail(stderr: bytearray, returncode: int) -> str:
        raw = bytes(stderr[:MAX_API_DIAGNOSTIC_BYTES])
        detail = raw.decode("utf-8", "replace").strip()
        if len(stderr) > MAX_API_DIAGNOSTIC_BYTES:
            detail = f"{detail} …[truncated]".strip()
        return detail or str(returncode)

    def _run(self, arguments: list[str], expect_json: bool) -> Any:
        # Fail before spawning anything on platforms where pipe selection and
        # descendant cleanup cannot satisfy this command's safety contract.
        self._require_posix_process_groups()
        try:
            process = self._start_process(arguments)
        except OSError as error:
            raise GitHubApiUnavailable("GitHub API process could not start") from error
        returncode, stdout, stderr, overflow, timed_out = self._capture_process(process)
        if overflow:
            raise RetirementError("GitHub API response exceeds the safety limit")
        if timed_out:
            raise GitHubApiUnavailable("GitHub API request timed out")
        if returncode != 0:
            raise GitHubApiUnavailable(
                f"GitHub API failed: {self._error_detail(stderr, returncode)}"
            )
        if not expect_json:
            return None
        try:
            return json.loads(stdout)
        except json.JSONDecodeError as error:
            raise RetirementError("GitHub API returned invalid JSON") from error

    def get(self, endpoint: str, *, paginate: bool = False) -> Any:
        arguments = ["--paginate", "--slurp", endpoint] if paginate else [endpoint]
        return self._run(arguments, True)

    def graphql_repository_identity(self) -> Any:
        """Read only the fixed repository identity and default branch.

        This is deliberately not a general GraphQL escape hatch: workflow
        paths, identities, and runs continue to use their existing REST
        endpoints and validation.
        """
        owner, name = REPOSITORY.split("/", 1)
        query = (
            "query($owner:String!,$name:String!){"
            "repository(owner:$owner,name:$name){"
            "nameWithOwner defaultBranchRef{name}}}"
        )
        return self._run(
            [
                "graphql",
                "-f",
                f"query={query}",
                "-f",
                f"owner={owner}",
                "-f",
                f"name={name}",
            ],
            True,
        )

    def mutate(self, method: str, endpoint: str) -> None:
        if method not in {"PUT", "DELETE"}:
            raise RetirementError("unsupported retirement mutation")
        self._run(["--method", method, endpoint], False)


@dataclass(frozen=True)
class Workflow:
    id: int
    path: str
    state: str


@dataclass(frozen=True)
class Run:
    id: int
    workflow_id: int
    path: str
    status: str
    event: str
    head_sha: str


@dataclass(frozen=True)
class Snapshot:
    default_branch: str
    legacy: tuple[tuple[Workflow, tuple[Run, ...]], ...]


@dataclass(frozen=True)
class Receipt:
    host: str
    default_branch: str
    legacy: tuple[Workflow, ...]


def _positive_integer(value: Any, label: str) -> int:
    if type(value) is not int or value <= 0:
        raise RetirementError(f"{label} is invalid")
    return value


def _flatten_pages(value: Any, key: str) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise RetirementError("paginated GitHub response is invalid")
    output: list[dict[str, Any]] = []
    for page in value:
        if not isinstance(page, dict) or not isinstance(page.get(key), list):
            raise RetirementError("paginated GitHub response is malformed")
        for item in page[key]:
            if not isinstance(item, dict):
                raise RetirementError("paginated GitHub item is malformed")
            output.append(item)
    return output


def _workflow_catalog(
    api: GitHubApi, captured_ids: frozenset[int] = frozenset()
) -> tuple[Workflow, ...]:
    values = _flatten_pages(
        api.get(f"repos/{REPOSITORY}/actions/workflows?per_page=100", paginate=True),
        "workflows",
    )
    relevant_paths = set(LEGACY_PATHS) | set(REPLACEMENT_PATHS)
    selected: list[Workflow] = []
    seen_ids: set[int] = set()
    seen_paths: set[str] = set()
    for value in values:
        path = value.get("path")
        raw_id = value.get("id")
        if path not in relevant_paths and raw_id not in captured_ids:
            continue
        workflow_id = _positive_integer(raw_id, f"workflow id for {path}")
        state = value.get("state")
        if not isinstance(path, str) or not isinstance(state, str) or not state:
            raise RetirementError("relevant workflow identity is malformed")
        if workflow_id in seen_ids or path in seen_paths:
            raise RetirementError(f"workflow identity is ambiguous: {path}")
        seen_ids.add(workflow_id)
        seen_paths.add(path)
        selected.append(Workflow(workflow_id, path, state))
    return tuple(selected)


def _by_path(workflows: tuple[Workflow, ...], paths: tuple[str, ...]) -> tuple[Workflow, ...]:
    output: list[Workflow] = []
    for path in paths:
        matches = [workflow for workflow in workflows if workflow.path == path]
        if len(matches) != 1:
            raise RetirementError(f"required workflow identity is missing: {path}")
        output.append(matches[0])
    return tuple(output)


def _run(value: dict[str, Any], label: str) -> Run:
    run_id = _positive_integer(value.get("id"), f"{label} id")
    workflow_id = _positive_integer(value.get("workflow_id"), f"{label} workflow id")
    path = value.get("path")
    status = value.get("status")
    event = value.get("event")
    head_sha = value.get("head_sha")
    if (
        not isinstance(path, str)
        or not isinstance(status, str)
        or not isinstance(event, str)
        or not isinstance(head_sha, str)
        or FULL_SHA.fullmatch(head_sha) is None
    ):
        raise RetirementError(f"{label} is malformed")
    return Run(run_id, workflow_id, path, status, event, head_sha)


def _runs(api: GitHubApi, workflow: Workflow) -> tuple[Run, ...]:
    values = _flatten_pages(
        api.get(
            f"repos/{REPOSITORY}/actions/workflows/{workflow.id}/runs?per_page=100",
            paginate=True,
        ),
        "workflow_runs",
    )
    output: list[Run] = []
    seen: set[int] = set()
    for value in values:
        run = _run(value, "workflow run")
        if (
            run.workflow_id != workflow.id
            or run.path != workflow.path
            or run.id in seen
        ):
            raise RetirementError(f"run does not belong exactly to {workflow.path}")
        seen.add(run.id)
        output.append(run)
    return tuple(sorted(output, key=lambda item: item.id))


def _relevant_repository_runs(
    api: GitHubApi, captured_ids: frozenset[int]
) -> tuple[Run, ...]:
    values = _flatten_pages(
        api.get(f"repos/{REPOSITORY}/actions/runs?per_page=100", paginate=True),
        "workflow_runs",
    )
    output: list[Run] = []
    seen: set[int] = set()
    for value in values:
        raw_id = value.get("workflow_id")
        path = value.get("path")
        if raw_id not in captured_ids and path not in LEGACY_PATHS:
            continue
        run = _run(value, "repository workflow run")
        if run.id in seen:
            raise RetirementError("repository workflow run is duplicated")
        seen.add(run.id)
        output.append(run)
    return tuple(sorted(output, key=lambda item: item.id))


def _valid_default_branch(value: Any) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[A-Za-z0-9._/-]+", value) is None:
        raise RetirementError("default branch is invalid")
    return value


def _repository_default_branch(api: GitHubApi) -> str:
    try:
        repository = api.get(f"repos/{REPOSITORY}")
    except GitHubApiUnavailable as rest_error:
        try:
            response = api.graphql_repository_identity()
        except GitHubApiUnavailable as graphql_error:
            raise GitHubApiUnavailable(
                "repository identity lookup failed through REST and GraphQL"
            ) from graphql_error
        if not isinstance(response, dict) or "errors" in response:
            raise RetirementError("GraphQL repository identity response is invalid")
        data = response.get("data")
        graphql_repository = data.get("repository") if isinstance(data, dict) else None
        if not isinstance(graphql_repository, dict):
            raise RetirementError("GraphQL repository identity response is invalid")
        if graphql_repository.get("nameWithOwner") != REPOSITORY:
            raise RetirementError("authenticated repository identity is invalid")
        branch_ref = graphql_repository.get("defaultBranchRef")
        if not isinstance(branch_ref, dict):
            raise RetirementError("default branch is invalid")
        return _valid_default_branch(branch_ref.get("name"))

    # A successful but contradictory REST response is not a reason to consult
    # another API surface. Fail closed instead of selecting the answer we like.
    if not isinstance(repository, dict) or repository.get("full_name") != REPOSITORY:
        raise RetirementError("authenticated repository identity is invalid")
    return _valid_default_branch(repository.get("default_branch"))


def _default_branch_paths(api: GitHubApi) -> tuple[str, set[str]]:
    branch = _repository_default_branch(api)
    endpoint = (
        f"repos/{REPOSITORY}/contents/.github/workflows?ref="
        + urllib.parse.quote(branch, safe="")
    )
    contents = api.get(endpoint)
    if not isinstance(contents, list):
        raise RetirementError("default-branch workflow directory is invalid")
    paths = {
        item.get("path")
        for item in contents
        if isinstance(item, dict) and isinstance(item.get("path"), str)
    }
    return branch, paths


def collect_pre_migration_snapshot(api: GitHubApi) -> Snapshot:
    branch, paths = _default_branch_paths(api)
    missing_legacy = set(LEGACY_PATHS) - paths
    premature_replacements = set(REPLACEMENT_PATHS) & paths
    if missing_legacy or premature_replacements:
        raise RetirementError(
            "pre-migration retirement requires only the legacy publisher paths on "
            f"the default branch: missing={sorted(missing_legacy)}, "
            f"replacement={sorted(premature_replacements)}"
        )
    legacy = _by_path(_workflow_catalog(api), LEGACY_PATHS)
    return Snapshot(
        branch,
        tuple((workflow, _runs(api, workflow)) for workflow in legacy),
    )


def apply_token(snapshot: Snapshot) -> str:
    value = {
        "host": GITHUB_HOST,
        "repository": REPOSITORY,
        "defaultBranch": snapshot.default_branch,
        "legacy": [
            {
                "id": workflow.id,
                "path": workflow.path,
                "runIds": [run.id for run in runs],
            }
            for workflow, runs in snapshot.legacy
        ],
    }
    digest = hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return f"RETIRE-LEGACY-EXITFY-WORKFLOWS:{digest}"


def _plan_json(snapshot: Snapshot) -> dict[str, Any]:
    return {
        "phase": "before-workflow-path-migration",
        "host": GITHUB_HOST,
        "repository": REPOSITORY,
        "defaultBranch": snapshot.default_branch,
        "legacy": [
            {
                "id": workflow.id,
                "path": workflow.path,
                "state": workflow.state,
                "runs": [
                    {
                        "id": run.id,
                        "status": run.status,
                        "event": run.event,
                        "headSha": run.head_sha,
                    }
                    for run in runs
                ],
            }
            for workflow, runs in snapshot.legacy
        ],
        "applyToken": apply_token(snapshot),
    }


def verify_pre_migration_retired(snapshot: Snapshot) -> None:
    failures: list[str] = []
    for workflow, runs in snapshot.legacy:
        if workflow.state != "disabled_manually":
            failures.append(f"legacy workflow is not disabled: {workflow.path}")
        if runs:
            failures.append(f"legacy workflow still has {len(runs)} runs: {workflow.path}")
    if failures:
        raise RetirementError("; ".join(failures))


def _receipt_value(snapshot: Snapshot) -> dict[str, Any]:
    return {
        "schema": RECEIPT_SCHEMA,
        "host": GITHUB_HOST,
        "repository": REPOSITORY,
        "defaultBranch": snapshot.default_branch,
        "legacy": [
            {"id": workflow.id, "path": workflow.path}
            for workflow, _ in snapshot.legacy
        ],
        "verifiedState": "disabled_manually",
        "verifiedRunCount": 0,
    }


def _write_receipt(snapshot: Snapshot, path: Path) -> None:
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True)
    payload = (
        json.dumps(_receipt_value(snapshot), indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", dir=parent, prefix=f".{path.name}.", delete=False
        ) as stream:
            temporary_name = stream.name
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, path)
        temporary_name = None
    finally:
        if temporary_name is not None:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass


def load_receipt(path: Path = RECEIPT_PATH) -> Receipt:
    try:
        with path.open("rb") as stream:
            raw = stream.read(MAX_RECEIPT_BYTES + 1)
    except OSError as error:
        raise RetirementError(f"retirement receipt cannot be read: {error}") from error
    if len(raw) > MAX_RECEIPT_BYTES:
        raise RetirementError("retirement receipt exceeds the safety limit")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RetirementError("retirement receipt is invalid JSON") from error
    expected_keys = {
        "schema",
        "host",
        "repository",
        "defaultBranch",
        "legacy",
        "verifiedState",
        "verifiedRunCount",
    }
    if not isinstance(value, dict) or set(value) != expected_keys:
        raise RetirementError("retirement receipt fields do not match the contract")
    if (
        type(value.get("schema")) is not int
        or value.get("schema") != RECEIPT_SCHEMA
        or value.get("host") != GITHUB_HOST
        or value.get("repository") != REPOSITORY
        or value.get("verifiedState") != "disabled_manually"
        or type(value.get("verifiedRunCount")) is not int
        or value.get("verifiedRunCount") != 0
    ):
        raise RetirementError("retirement receipt proof is invalid")
    branch = value.get("defaultBranch")
    entries = value.get("legacy")
    if (
        not isinstance(branch, str)
        or re.fullmatch(r"[A-Za-z0-9._/-]+", branch) is None
        or not isinstance(entries, list)
        or len(entries) != len(LEGACY_PATHS)
    ):
        raise RetirementError("retirement receipt identity is invalid")
    legacy: list[Workflow] = []
    for expected_path, entry in zip(LEGACY_PATHS, entries):
        if not isinstance(entry, dict) or set(entry) != {"id", "path"}:
            raise RetirementError("retirement receipt legacy entry is malformed")
        if entry.get("path") != expected_path:
            raise RetirementError("retirement receipt legacy path is invalid")
        legacy.append(
            Workflow(
                _positive_integer(entry.get("id"), "retirement receipt workflow id"),
                expected_path,
                "disabled_manually",
            )
        )
    if len({workflow.id for workflow in legacy}) != len(legacy):
        raise RetirementError("retirement receipt workflow ids are duplicated")
    return Receipt(GITHUB_HOST, branch, tuple(legacy))


def retire(
    api: GitHubApi,
    snapshot: Snapshot,
    confirmation: str,
    receipt_path: Path = RECEIPT_PATH,
) -> None:
    expected = apply_token(snapshot)
    if confirmation != expected:
        raise RetirementError("apply token does not match the current exact snapshot")
    active = [run for _, runs in snapshot.legacy for run in runs if run.status != "completed"]
    if active:
        raise RetirementError(
            "legacy workflows have active runs; cancel them and generate a new plan: "
            + ",".join(str(run.id) for run in active)
        )

    for workflow, _ in snapshot.legacy:
        api.mutate(
            "PUT", f"repos/{REPOSITORY}/actions/workflows/{workflow.id}/disable"
        )

    disabled = collect_pre_migration_snapshot(api)
    original_ids = tuple(workflow.id for workflow, _ in snapshot.legacy)
    if disabled.default_branch != snapshot.default_branch:
        raise RetirementError("default branch changed after workflow disable")
    if tuple(workflow.id for workflow, _ in disabled.legacy) != original_ids:
        raise RetirementError("legacy workflow identities changed after disable")
    original_runs = {run.id for _, runs in snapshot.legacy for run in runs}
    disabled_runs = {run.id for _, runs in disabled.legacy for run in runs}
    if any(workflow.state != "disabled_manually" for workflow, _ in disabled.legacy):
        raise RetirementError("legacy workflow disable did not become authoritative")
    if disabled_runs != original_runs:
        raise RetirementError("legacy run set changed after disable; generate a new plan")
    if any(run.status != "completed" for _, runs in disabled.legacy for run in runs):
        raise RetirementError("a legacy run is still active after disable")

    for run_id in sorted(original_runs):
        api.mutate("DELETE", f"repos/{REPOSITORY}/actions/runs/{run_id}")

    retired = collect_pre_migration_snapshot(api)
    if retired.default_branch != snapshot.default_branch:
        raise RetirementError("default branch changed during run deletion")
    if tuple(workflow.id for workflow, _ in retired.legacy) != original_ids:
        raise RetirementError("legacy workflow identities changed after run deletion")
    verify_pre_migration_retired(retired)
    _write_receipt(retired, receipt_path)


def verify_post_migration(
    api: GitHubApi, receipt_path: Path = RECEIPT_PATH
) -> None:
    receipt = load_receipt(receipt_path)
    branch, paths = _default_branch_paths(api)
    legacy_on_default = set(LEGACY_PATHS) & paths
    missing_replacements = set(REPLACEMENT_PATHS) - paths
    if branch != receipt.default_branch:
        raise RetirementError("default branch changed after legacy retirement")
    if legacy_on_default or missing_replacements:
        raise RetirementError(
            "default branch is not migrated to only the hardened workflow paths: "
            f"legacy={sorted(legacy_on_default)}, missing={sorted(missing_replacements)}"
        )

    captured_ids = frozenset(workflow.id for workflow in receipt.legacy)
    catalog = _workflow_catalog(api, captured_ids)
    replacements = _by_path(catalog, REPLACEMENT_PATHS)
    if any(workflow.state != "active" for workflow in replacements):
        raise RetirementError("replacement workflows must be active")
    if captured_ids & {workflow.id for workflow in replacements}:
        raise RetirementError("replacement workflow reuses a legacy identity")

    receipt_by_id = {workflow.id: workflow for workflow in receipt.legacy}
    for workflow in catalog:
        expected = receipt_by_id.get(workflow.id)
        if workflow.path in LEGACY_PATHS and expected is None:
            raise RetirementError("an unexpected legacy workflow identity still exists")
        if expected is None:
            continue
        if workflow.path != expected.path or workflow.state != "disabled_manually":
            raise RetirementError("captured legacy workflow identity is not retired")
        if _runs(api, workflow):
            raise RetirementError("captured legacy workflow still has runs")

    remaining_runs = _relevant_repository_runs(api, captured_ids)
    if remaining_runs:
        raise RetirementError(
            "repository still contains legacy workflow runs: "
            + ",".join(str(run.id) for run in remaining_runs)
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--verify", action="store_true")
    modes.add_argument("--apply-token")
    args = parser.parse_args()
    api = GitHubApi()
    try:
        if args.verify:
            verify_post_migration(api)
            print("legacy publishers retired; hardened workflows are active")
        else:
            snapshot = collect_pre_migration_snapshot(api)
            if args.apply_token is not None:
                retire(api, snapshot, args.apply_token)
                print(f"legacy publishers retired; receipt written to {RECEIPT_PATH}")
            else:
                print(json.dumps(_plan_json(snapshot), indent=2, sort_keys=True))
    except (OSError, RetirementError) as error:
        raise SystemExit(f"legacy workflow retirement failed: {error}") from error


if __name__ == "__main__":
    main()
