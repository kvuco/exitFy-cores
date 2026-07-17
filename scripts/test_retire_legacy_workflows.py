from __future__ import annotations

import json
import os
import selectors
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import retire_legacy_workflows as retirement
from retire_legacy_workflows import (
    GITHUB_HOST,
    GitHubApi,
    GitHubApiUnavailable,
    LEGACY_PATHS,
    RECEIPT_SCHEMA,
    REPLACEMENT_PATHS,
    REPOSITORY,
    RetirementError,
    Run,
    Snapshot,
    Workflow,
    apply_token,
    collect_pre_migration_snapshot,
    load_receipt,
    retire,
    verify_post_migration,
    verify_pre_migration_retired,
)


_DEFAULT_REST_FAILURE = object()


def snapshot(
    *, state: str = "active", statuses: tuple[str, ...] = ("completed",)
) -> Snapshot:
    legacy = []
    next_run = 100
    for index, path in enumerate(LEGACY_PATHS, 1):
        workflow = Workflow(index, path, state)
        runs = []
        for status in statuses:
            runs.append(Run(next_run, index, path, status, "push", "a" * 40))
            next_run += 1
        legacy.append((workflow, tuple(runs)))
    return Snapshot("main", tuple(legacy))


def receipt_value(value: Snapshot) -> dict[str, object]:
    return {
        "schema": RECEIPT_SCHEMA,
        "host": GITHUB_HOST,
        "repository": REPOSITORY,
        "defaultBranch": value.default_branch,
        "legacy": [
            {"id": workflow.id, "path": workflow.path}
            for workflow, _ in value.legacy
        ],
        "verifiedState": "disabled_manually",
        "verifiedRunCount": 0,
    }


class MutationFakeApi:
    def __init__(self, initial: Snapshot):
        self.current = initial
        self.mutations: list[tuple[str, str]] = []

    def mutate(self, method: str, endpoint: str) -> None:
        self.mutations.append((method, endpoint))
        if endpoint.endswith("/disable"):
            workflow_id = int(endpoint.split("/")[-2])
            self.current = Snapshot(
                self.current.default_branch,
                tuple(
                    (
                        Workflow(workflow.id, workflow.path, "disabled_manually")
                        if workflow.id == workflow_id
                        else workflow,
                        runs,
                    )
                    for workflow, runs in self.current.legacy
                ),
            )
        elif "/actions/runs/" in endpoint:
            run_id = int(endpoint.rsplit("/", 1)[1])
            self.current = Snapshot(
                self.current.default_branch,
                tuple(
                    (workflow, tuple(run for run in runs if run.id != run_id))
                    for workflow, runs in self.current.legacy
                ),
            )


class BranchChangingMutationFakeApi(MutationFakeApi):
    def __init__(self, initial: Snapshot, phase: str):
        super().__init__(initial)
        self.phase = phase

    def mutate(self, method: str, endpoint: str) -> None:
        super().mutate(method, endpoint)
        disabled = all(
            workflow.state == "disabled_manually"
            for workflow, _ in self.current.legacy
        )
        runs_gone = all(not runs for _, runs in self.current.legacy)
        if (
            (self.phase == "disable" and method == "PUT" and disabled)
            or (self.phase == "delete" and method == "DELETE" and runs_gone)
        ):
            self.current = Snapshot("release-maintenance", self.current.legacy)


class PostMigrationFakeApi:
    def __init__(
        self,
        value: Snapshot,
        *,
        include_legacy_identities: bool = False,
        legacy_state: str = "disabled_manually",
        repository_runs: tuple[Run, ...] = (),
    ):
        self.value = value
        self.include_legacy_identities = include_legacy_identities
        self.legacy_state = legacy_state
        self.repository_runs = repository_runs

    @staticmethod
    def _workflow_json(workflow: Workflow) -> dict[str, object]:
        return {"id": workflow.id, "path": workflow.path, "state": workflow.state}

    @staticmethod
    def _run_json(run: Run) -> dict[str, object]:
        return {
            "id": run.id,
            "workflow_id": run.workflow_id,
            "path": run.path,
            "status": run.status,
            "event": run.event,
            "head_sha": run.head_sha,
        }

    def get(self, endpoint: str, *, paginate: bool = False):
        if endpoint == f"repos/{REPOSITORY}":
            return {"full_name": REPOSITORY, "default_branch": self.value.default_branch}
        if endpoint.startswith(f"repos/{REPOSITORY}/contents/.github/workflows?"):
            return [{"path": path} for path in REPLACEMENT_PATHS]
        if endpoint == f"repos/{REPOSITORY}/actions/workflows?per_page=100":
            workflows = [
                Workflow(20 + index, path, "active")
                for index, path in enumerate(REPLACEMENT_PATHS, 1)
            ]
            if self.include_legacy_identities:
                workflows.extend(
                    Workflow(workflow.id, workflow.path, self.legacy_state)
                    for workflow, _ in self.value.legacy
                )
            return [{"workflows": [self._workflow_json(item) for item in workflows]}]
        if endpoint == f"repos/{REPOSITORY}/actions/runs?per_page=100":
            return [{"workflow_runs": [self._run_json(run) for run in self.repository_runs]}]
        for workflow, runs in self.value.legacy:
            if endpoint == (
                f"repos/{REPOSITORY}/actions/workflows/{workflow.id}/runs?per_page=100"
            ):
                return [{"workflow_runs": [self._run_json(run) for run in runs]}]
        raise AssertionError(f"unexpected endpoint: {endpoint}, paginate={paginate}")


class RepositoryFallbackFakeApi:
    def __init__(self, graphql_result, repository_result=_DEFAULT_REST_FAILURE):
        self.value = snapshot()
        self.graphql_result = graphql_result
        self.repository_result = repository_result
        self.calls: list[tuple[str, str, bool]] = []

    @staticmethod
    def _workflow_json(workflow: Workflow) -> dict[str, object]:
        return {"id": workflow.id, "path": workflow.path, "state": workflow.state}

    @staticmethod
    def _run_json(run: Run) -> dict[str, object]:
        return {
            "id": run.id,
            "workflow_id": run.workflow_id,
            "path": run.path,
            "status": run.status,
            "event": run.event,
            "head_sha": run.head_sha,
        }

    def get(self, endpoint: str, *, paginate: bool = False):
        self.calls.append(("rest", endpoint, paginate))
        if endpoint == f"repos/{REPOSITORY}":
            if self.repository_result is _DEFAULT_REST_FAILURE:
                raise GitHubApiUnavailable(
                    "REST repository lookup returned HTTP 503"
                )
            if isinstance(self.repository_result, BaseException):
                raise self.repository_result
            return self.repository_result
        if endpoint.startswith(f"repos/{REPOSITORY}/contents/.github/workflows?"):
            return [{"path": path} for path in LEGACY_PATHS]
        if endpoint == f"repos/{REPOSITORY}/actions/workflows?per_page=100":
            return [{
                "workflows": [
                    self._workflow_json(workflow)
                    for workflow, _ in self.value.legacy
                ]
            }]
        for workflow, runs in self.value.legacy:
            if endpoint == (
                f"repos/{REPOSITORY}/actions/workflows/{workflow.id}/runs?per_page=100"
            ):
                return [{"workflow_runs": [self._run_json(run) for run in runs]}]
        raise AssertionError(f"unexpected endpoint: {endpoint}, paginate={paginate}")

    def graphql_repository_identity(self):
        self.calls.append(("graphql", "repository identity", False))
        if isinstance(self.graphql_result, BaseException):
            raise self.graphql_result
        return self.graphql_result


class ProcessFixtureApi(GitHubApi):
    def __init__(self, script: str, ready_path: Path | None = None):
        self.script = script
        self.ready_path = ready_path
        self.arguments: list[list[str]] = []
        self.process: subprocess.Popen[bytes] | None = None

    def _start_process(self, arguments: list[str]) -> subprocess.Popen[bytes]:
        self.arguments.append(arguments)
        self.process = subprocess.Popen(
            [sys.executable, "-c", self.script],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
            close_fds=True,
            start_new_session=True,
        )
        if self.ready_path is not None:
            deadline = time.monotonic() + 5.0
            while not self.ready_path.exists():
                if self.process.poll() is not None:
                    raise AssertionError("fixture exited before readiness")
                if time.monotonic() >= deadline:
                    self.process.kill()
                    self.process.wait()
                    raise AssertionError("fixture readiness timed out")
                time.sleep(0.005)
        return self.process


class SpawnFailureApi(GitHubApi):
    def _start_process(self, arguments: list[str]) -> subprocess.Popen[bytes]:
        raise OSError("fixture spawn failure")


def graphql_repository_response(
    *, identity: str = REPOSITORY, branch: str | None = "main"
) -> dict[str, object]:
    return {
        "data": {
            "repository": {
                "nameWithOwner": identity,
                "defaultBranchRef": None if branch is None else {"name": branch},
            }
        }
    }


class RetirementTest(unittest.TestCase):
    def assert_pid_gone(self, pid: int, timeout: float = 2.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return
            time.sleep(0.01)
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            return
        self.fail(f"descendant process survived cleanup: {pid}")

    def _write_receipt(self, directory: str, value: Snapshot) -> Path:
        path = Path(directory) / "receipt.json"
        path.write_text(json.dumps(receipt_value(value)), encoding="utf-8")
        return path

    def test_api_capture_accepts_exact_limit_and_rejects_limit_plus_one(self) -> None:
        payload = b'{"ok":true}'
        exact = ProcessFixtureApi(f"import os; os.write(1, {payload!r})")
        with mock.patch.object(retirement, "MAX_API_BYTES", len(payload)):
            self.assertEqual({"ok": True}, exact.get("repos/example/exact"))

        oversized = ProcessFixtureApi(
            f"import os; os.write(1, {payload + b' '!r})"
        )
        with mock.patch.object(retirement, "MAX_API_BYTES", len(payload)):
            with self.assertRaisesRegex(RetirementError, "safety limit"):
                oversized.get("repos/example/oversized")

    def test_rest_stdout_overflow_terminates_sleeping_process(self) -> None:
        api = ProcessFixtureApi(
            "import os, time; os.write(1, b'x' * 129); time.sleep(60)"
        )
        started = time.monotonic()
        with (
            mock.patch.object(retirement, "MAX_API_BYTES", 128),
            mock.patch.object(retirement, "PROCESS_POLL_SECONDS", 0.005),
            mock.patch.object(retirement, "PROCESS_TERMINATE_GRACE_SECONDS", 0.05),
        ):
            with self.assertRaisesRegex(RetirementError, "safety limit"):
                api.get("repos/example/overflow")
        self.assertLess(time.monotonic() - started, 2.0)
        self.assertIsNotNone(api.process)
        self.assertIsNotNone(api.process.poll())

    def test_graphql_stderr_overflow_kills_term_ignoring_process(self) -> None:
        api = ProcessFixtureApi(
            "import os, signal, time; "
            "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
            "os.write(2, b'e' * 129); time.sleep(60)"
        )
        started = time.monotonic()
        with (
            mock.patch.object(retirement, "MAX_API_BYTES", 128),
            mock.patch.object(retirement, "PROCESS_POLL_SECONDS", 0.005),
            mock.patch.object(retirement, "PROCESS_TERMINATE_GRACE_SECONDS", 0.05),
        ):
            with self.assertRaisesRegex(RetirementError, "safety limit"):
                api.graphql_repository_identity()
        self.assertLess(time.monotonic() - started, 2.0)
        self.assertEqual("graphql", api.arguments[0][0])
        self.assertIsNotNone(api.process)
        self.assertIsNotNone(api.process.poll())

    def test_api_capture_combines_simultaneous_stdout_and_stderr(self) -> None:
        script = """
import os
import threading
import time

gate = threading.Barrier(3)
def write_stream(fd):
    gate.wait()
    os.write(fd, b'x' * 80)

threads = [threading.Thread(target=write_stream, args=(fd,)) for fd in (1, 2)]
for thread in threads:
    thread.start()
gate.wait()
for thread in threads:
    thread.join()
time.sleep(60)
"""
        api = ProcessFixtureApi(script)
        with (
            mock.patch.object(retirement, "MAX_API_BYTES", 128),
            mock.patch.object(retirement, "PROCESS_POLL_SECONDS", 0.005),
            mock.patch.object(retirement, "PROCESS_TERMINATE_GRACE_SECONDS", 0.05),
        ):
            with self.assertRaisesRegex(RetirementError, "safety limit"):
                api.get("repos/example/simultaneous")
        self.assertIsNotNone(api.process)
        self.assertIsNotNone(api.process.poll())

    def test_api_capture_times_out_silent_process(self) -> None:
        api = ProcessFixtureApi("import time; time.sleep(60)")
        started = time.monotonic()
        with (
            mock.patch.object(retirement, "PROCESS_TIMEOUT_SECONDS", 0.05),
            mock.patch.object(retirement, "PROCESS_POLL_SECONDS", 0.005),
            mock.patch.object(retirement, "PROCESS_TERMINATE_GRACE_SECONDS", 0.05),
        ):
            with self.assertRaisesRegex(RetirementError, "timed out"):
                api.get("repos/example/hang")
        self.assertLess(time.monotonic() - started, 2.0)
        self.assertIsNotNone(api.process)
        self.assertIsNotNone(api.process.poll())

    def test_exit_first_observed_after_deadline_is_not_accepted(self) -> None:
        api = ProcessFixtureApi(
            "import os,time; os.write(1,b'{}'); time.sleep(0.08)"
        )
        with (
            mock.patch.object(retirement, "PROCESS_TIMEOUT_SECONDS", 0.05),
            mock.patch.object(retirement, "PROCESS_POLL_SECONDS", 0.2),
            mock.patch.object(retirement, "PROCESS_TERMINATE_GRACE_SECONDS", 0.02),
        ):
            with self.assertRaisesRegex(GitHubApiUnavailable, "timed out"):
                api.get("repos/example/late-exit")
        self.assertIsNotNone(api.process)
        self.assertIsNotNone(api.process.poll())

    def test_delayed_exit_observation_cannot_bypass_deadline(self) -> None:
        class DelayedObservationApi(ProcessFixtureApi):
            @staticmethod
            def _leader_exited(process):
                time.sleep(0.2)
                return GitHubApi._leader_exited(process)

        api = DelayedObservationApi(
            "import os,time; os.write(1,b'{}'); time.sleep(0.08)"
        )
        with (
            mock.patch.object(retirement, "PROCESS_TIMEOUT_SECONDS", 0.05),
            mock.patch.object(retirement, "PROCESS_POLL_SECONDS", 0.005),
            mock.patch.object(retirement, "PROCESS_TERMINATE_GRACE_SECONDS", 0.02),
        ):
            with self.assertRaisesRegex(GitHubApiUnavailable, "timed out"):
                api.get("repos/example/delayed-observation")
        self.assertIsNotNone(api.process)
        self.assertIsNotNone(api.process.poll())

    def test_timeout_kills_term_ignoring_descendant_with_closed_stdio(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pid_path = Path(directory) / "child.pid"
            ready_path = Path(directory) / "child.ready"
            child = (
                "import pathlib,signal,time; "
                "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                f"pathlib.Path({str(ready_path)!r}).write_text('ready'); "
                "time.sleep(60)"
            )
            parent = (
                "import os,pathlib,subprocess,sys,time; "
                f"child=subprocess.Popen([sys.executable,'-c',{child!r}],"
                "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,"
                "stderr=subprocess.DEVNULL); "
                f"pathlib.Path({str(pid_path)!r}).write_text(str(child.pid)); "
                f"ready=pathlib.Path({str(ready_path)!r}); "
                "deadline=time.monotonic()+5; "
                "exec(\"while not ready.exists():\\n"
                " if time.monotonic() >= deadline: raise RuntimeError('not ready')\\n"
                " time.sleep(0.005)\"); "
                "time.sleep(60)"
            )
            api = ProcessFixtureApi(parent, ready_path)
            with (
                mock.patch.object(retirement, "PROCESS_TIMEOUT_SECONDS", 0.05),
                mock.patch.object(retirement, "PROCESS_POLL_SECONDS", 0.005),
                mock.patch.object(
                    retirement, "PROCESS_TERMINATE_GRACE_SECONDS", 0.05
                ),
            ):
                with self.assertRaisesRegex(GitHubApiUnavailable, "timed out"):
                    api.get("repos/example/descendant-timeout")
            child_pid = int(pid_path.read_text())
            self.assert_pid_gone(child_pid)

    def test_normal_exit_kills_silent_descendant_before_return(self) -> None:
        child = (
            "import signal,time; "
            "signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)"
        )
        with tempfile.TemporaryDirectory() as directory:
            pid_path = Path(directory) / "child.pid"
            parent = (
                "import os,pathlib,subprocess,sys; "
                f"child=subprocess.Popen([sys.executable,'-c',{child!r}],"
                "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,"
                "stderr=subprocess.DEVNULL); "
                f"pathlib.Path({str(pid_path)!r}).write_text(str(child.pid)); "
                "os.write(1,b'{}')"
            )
            api = ProcessFixtureApi(parent)
            self.assertEqual({}, api.get("repos/example/normal-descendant"))
            child_pid = int(pid_path.read_text())
            self.assert_pid_gone(child_pid)

    def test_interrupt_before_hard_kill_still_cleans_group(self) -> None:
        class InterruptOnceApi(ProcessFixtureApi):
            interrupted = False

            @classmethod
            def _kill_group_and_reap(cls, process, pgid, cleanup):
                if not cls.interrupted:
                    cls.interrupted = True
                    raise KeyboardInterrupt()
                return super()._kill_group_and_reap(process, pgid, cleanup)

        with tempfile.TemporaryDirectory() as directory:
            pid_path = Path(directory) / "child.pid"
            ready_path = Path(directory) / "child.ready"
            child = (
                "import pathlib,signal,time; "
                "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                f"pathlib.Path({str(ready_path)!r}).write_text('ready'); "
                "time.sleep(60)"
            )
            parent = (
                "import os,pathlib,subprocess,sys,time; "
                f"child=subprocess.Popen([sys.executable,'-c',{child!r}],"
                "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,"
                "stderr=subprocess.DEVNULL); "
                f"pathlib.Path({str(pid_path)!r}).write_text(str(child.pid)); "
                f"ready=pathlib.Path({str(ready_path)!r}); "
                "deadline=time.monotonic()+5; "
                "exec(\"while not ready.exists():\\n"
                " if time.monotonic() >= deadline: raise RuntimeError('not ready')\\n"
                " time.sleep(0.005)\"); "
                "os.write(1,b'{}')"
            )
            api = InterruptOnceApi(parent, ready_path)
            with (
                mock.patch.object(retirement, "PROCESS_POLL_SECONDS", 0.005),
                mock.patch.object(
                    retirement, "PROCESS_TERMINATE_GRACE_SECONDS", 0.05
                ),
            ):
                with self.assertRaises(KeyboardInterrupt):
                    api.get("repos/example/interrupted-cleanup")
            child_pid = int(pid_path.read_text())
            self.assert_pid_gone(child_pid)
            self.assertIsNotNone(api.process)
            self.assertIsNotNone(api.process.poll())

    def test_partial_selector_registration_closes_both_pipes_and_process(self) -> None:
        real_selector_factory = selectors.DefaultSelector

        class FailSecondRegistration:
            def __init__(self):
                self.delegate = real_selector_factory()
                self.registrations = 0

            def register(self, *args, **kwargs):
                self.registrations += 1
                if self.registrations == 2:
                    raise OSError("injected second-register failure")
                return self.delegate.register(*args, **kwargs)

            def unregister(self, *args, **kwargs):
                return self.delegate.unregister(*args, **kwargs)

            def get_map(self):
                return self.delegate.get_map()

            def select(self, *args, **kwargs):
                return self.delegate.select(*args, **kwargs)

            def close(self):
                return self.delegate.close()

        with tempfile.TemporaryDirectory() as directory:
            pid_path = Path(directory) / "child.pid"
            ready_path = Path(directory) / "child.ready"
            child = (
                "import pathlib,signal,time; "
                "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                f"pathlib.Path({str(ready_path)!r}).write_text('ready'); "
                "time.sleep(60)"
            )
            parent = (
                "import pathlib,subprocess,sys,time; "
                f"child=subprocess.Popen([sys.executable,'-c',{child!r}],"
                "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,"
                "stderr=subprocess.DEVNULL); "
                f"pathlib.Path({str(pid_path)!r}).write_text(str(child.pid)); "
                "time.sleep(60)"
            )
            api = ProcessFixtureApi(parent, ready_path)
            with (
                mock.patch.object(
                    retirement.selectors,
                    "DefaultSelector",
                    side_effect=FailSecondRegistration,
                ),
                mock.patch.object(retirement, "PROCESS_POLL_SECONDS", 0.005),
                mock.patch.object(
                    retirement, "PROCESS_TERMINATE_GRACE_SECONDS", 0.05
                ),
            ):
                with self.assertRaisesRegex(RetirementError, "capture failed"):
                    api.get("repos/example/selector-registration")
            child_pid = int(pid_path.read_text())
            self.assert_pid_gone(child_pid)
            self.assertIsNotNone(api.process)
            self.assertIsNotNone(api.process.poll())
            self.assertTrue(api.process.stdout.closed)
            self.assertTrue(api.process.stderr.closed)

    def test_missing_pipe_branch_closes_available_pipe_and_reaps(self) -> None:
        process = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=0,
            close_fds=True,
            start_new_session=True,
        )
        self.assertIsNotNone(process.stdout)
        self.assertIsNone(process.stderr)
        with (
            mock.patch.object(retirement, "PROCESS_POLL_SECONDS", 0.005),
            mock.patch.object(retirement, "PROCESS_TERMINATE_GRACE_SECONDS", 0.05),
        ):
            with self.assertRaisesRegex(RetirementError, "pipes are unavailable"):
                GitHubApi()._capture_process(process)
        self.assertIsNotNone(process.poll())
        self.assertTrue(process.stdout.closed)

    def test_non_posix_platform_fails_before_process_spawn(self) -> None:
        api = ProcessFixtureApi("raise SystemExit(0)")
        with mock.patch.object(retirement.os, "name", "nt"):
            with self.assertRaisesRegex(RetirementError, "requires POSIX"):
                api.get("repos/example/non-posix")
        self.assertEqual([], api.arguments)
        self.assertIsNone(api.process)

    def test_nondefault_sigchld_fails_before_process_spawn(self) -> None:
        api = ProcessFixtureApi("raise SystemExit(0)")
        with mock.patch.object(
            retirement.signal, "getsignal", return_value=signal.SIG_IGN
        ):
            with self.assertRaisesRegex(RetirementError, "default SIGCHLD"):
                api.get("repos/example/sigchld")
        self.assertEqual([], api.arguments)
        self.assertIsNone(api.process)

    def test_externally_reaped_leader_never_signals_stale_pgid(self) -> None:
        api = ProcessFixtureApi("import os; os.write(1,b'{}')")
        process = api._start_process(["repos/example/external-reap"])
        pid, status = os.waitpid(process.pid, 0)
        self.assertEqual(process.pid, pid)
        process.returncode = os.waitstatus_to_exitcode(status)

        with mock.patch.object(
            GitHubApi, "_signal_process_group", wraps=GitHubApi._signal_process_group
        ) as signal_group:
            with self.assertRaisesRegex(RetirementError, "ownership was lost"):
                api._capture_process(process)
        signal_group.assert_not_called()
        self.assertTrue(process.stdout.closed)
        self.assertTrue(process.stderr.closed)

    def test_externally_reaped_missing_pipe_never_signals_stale_pgid(self) -> None:
        process = subprocess.Popen(
            [sys.executable, "-c", "raise SystemExit(0)"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=0,
            close_fds=True,
            start_new_session=True,
        )
        pid, status = os.waitpid(process.pid, 0)
        self.assertEqual(process.pid, pid)
        process.returncode = os.waitstatus_to_exitcode(status)

        with mock.patch.object(
            GitHubApi, "_signal_process_group", wraps=GitHubApi._signal_process_group
        ) as signal_group:
            with self.assertRaisesRegex(RetirementError, "ownership was lost"):
                GitHubApi()._capture_process(process)
        signal_group.assert_not_called()
        self.assertTrue(process.stdout.closed)

    def test_externally_reaped_selector_failure_never_signals_stale_pgid(self) -> None:
        process = subprocess.Popen(
            [sys.executable, "-c", "raise SystemExit(0)"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
            close_fds=True,
            start_new_session=True,
        )
        pid, status = os.waitpid(process.pid, 0)
        self.assertEqual(process.pid, pid)
        process.returncode = os.waitstatus_to_exitcode(status)

        with (
            mock.patch.object(
                retirement.selectors,
                "DefaultSelector",
                side_effect=OSError("injected selector construction failure"),
            ),
            mock.patch.object(
                GitHubApi,
                "_signal_process_group",
                wraps=GitHubApi._signal_process_group,
            ) as signal_group,
        ):
            with self.assertRaisesRegex(RetirementError, "ownership was lost"):
                GitHubApi()._capture_process(process)
        signal_group.assert_not_called()
        self.assertTrue(process.stdout.closed)
        self.assertTrue(process.stderr.closed)

    def test_api_capture_uses_absolute_post_exit_pipe_deadline(self) -> None:
        descendant = """
import os
import time
while True:
    os.write(2, b'descendant-output')
    time.sleep(0.001)
"""
        parent = (
            "import os, subprocess, sys; "
            f"subprocess.Popen([sys.executable, '-c', {descendant!r}]); "
            "os.write(1, b'{}')"
        )
        api = ProcessFixtureApi(parent)
        started = time.monotonic()
        with (
            mock.patch.object(retirement, "MAX_API_BYTES", 1024 * 1024),
            mock.patch.object(retirement, "PROCESS_TIMEOUT_SECONDS", 2.0),
            mock.patch.object(retirement, "PROCESS_POLL_SECONDS", 0.005),
            mock.patch.object(retirement, "PROCESS_POST_EXIT_DRAIN_SECONDS", 0.05),
        ):
            self.assertEqual({}, api.get("repos/example/inherited-pipe"))
        self.assertLess(time.monotonic() - started, 1.0)

    def test_api_error_diagnostic_is_utf8_safe_and_bounded(self) -> None:
        stderr = b"prefix-" + "🙂".encode("utf-8") * 20 + b"\xffSECRET_AT_END"
        api = ProcessFixtureApi(
            f"import os; os.write(2, {stderr!r}); raise SystemExit(7)"
        )
        with (
            mock.patch.object(retirement, "MAX_API_BYTES", len(stderr) + 1),
            mock.patch.object(retirement, "MAX_API_DIAGNOSTIC_BYTES", 10),
        ):
            with self.assertRaises(RetirementError) as caught:
                api.get("repos/example/error")
        detail = str(caught.exception)
        self.assertIn("GitHub API failed: prefix-", detail)
        self.assertIn("\ufffd", detail)
        self.assertIn("…[truncated]", detail)
        self.assertNotIn("SECRET_AT_END", detail)
        self.assertLess(len(detail), 80)

    def test_api_spawn_failure_is_clean_and_fail_closed(self) -> None:
        with self.assertRaisesRegex(RetirementError, "could not start") as caught:
            SpawnFailureApi().get("repos/example/spawn-failure")
        self.assertIsInstance(caught.exception.__cause__, OSError)

    def test_gh_hostname_is_pinned_despite_environment(self) -> None:
        sentinel = object()
        with (
            mock.patch.dict(os.environ, {"GH_HOST": "enterprise.example"}),
            mock.patch.object(
                retirement.subprocess, "Popen", return_value=sentinel
            ) as popen,
        ):
            result = GitHubApi()._start_process(
                ["--method", "DELETE", "repos/example/actions/runs/1"]
            )
        self.assertIs(sentinel, result)
        command = popen.call_args.args[0]
        self.assertEqual(
            ["gh", "api", "--hostname", GITHUB_HOST], command[:4]
        )
        self.assertIn("--method", command)
        self.assertIn("DELETE", command)
        self.assertEqual(GITHUB_HOST, retirement._plan_json(snapshot())["host"])

    def test_rest_repository_503_uses_bounded_graphql_identity_only(self) -> None:
        api = RepositoryFallbackFakeApi(graphql_repository_response())
        value = collect_pre_migration_snapshot(api)

        self.assertEqual("main", value.default_branch)
        self.assertEqual(
            tuple(workflow.id for workflow, _ in api.value.legacy),
            tuple(workflow.id for workflow, _ in value.legacy),
        )
        self.assertEqual(1, sum(call[0] == "graphql" for call in api.calls))
        rest_endpoints = [call[1] for call in api.calls if call[0] == "rest"]
        self.assertIn(f"repos/{REPOSITORY}", rest_endpoints)
        self.assertIn(f"repos/{REPOSITORY}/actions/workflows?per_page=100", rest_endpoints)
        self.assertTrue(any("/contents/.github/workflows?" in item for item in rest_endpoints))
        self.assertEqual(
            2,
            sum("/actions/workflows/" in item and item.endswith("/runs?per_page=100")
                for item in rest_endpoints),
        )

    def test_graphql_repository_fallback_rejects_invalid_identity_and_branch(self) -> None:
        cases = (
            ("wrong identity", graphql_repository_response(identity="attacker/repository"),
             "identity"),
            ("null branch", graphql_repository_response(branch=None), "default branch"),
            ("invalid response", {"data": {"repository": []}}, "response"),
            ("GraphQL errors", {
                **graphql_repository_response(),
                "errors": [{"message": "partial failure"}],
            }, "response"),
        )
        for label, response, message in cases:
            with self.subTest(label=label):
                with self.assertRaisesRegex(RetirementError, message):
                    collect_pre_migration_snapshot(RepositoryFallbackFakeApi(response))

    def test_repository_identity_fails_closed_when_rest_and_graphql_fail(self) -> None:
        api = RepositoryFallbackFakeApi(
            GitHubApiUnavailable("GraphQL unavailable")
        )
        with self.assertRaisesRegex(RetirementError, "REST and GraphQL"):
            collect_pre_migration_snapshot(api)

    def test_rest_protocol_failures_never_use_graphql_fallback(self) -> None:
        failures = (
            RetirementError("GitHub API response exceeds the safety limit"),
            RetirementError("GitHub API returned invalid JSON"),
            RetirementError("GitHub API capture failed"),
        )
        for failure in failures:
            with self.subTest(failure=str(failure)):
                api = RepositoryFallbackFakeApi(
                    graphql_repository_response(), repository_result=failure
                )
                with self.assertRaisesRegex(RetirementError, str(failure)):
                    collect_pre_migration_snapshot(api)
                self.assertFalse(any(call[0] == "graphql" for call in api.calls))

    def test_successful_contradictory_rest_never_uses_graphql_fallback(self) -> None:
        cases = (
            (
                "wrong identity",
                {"full_name": "attacker/repository", "default_branch": "main"},
                "identity",
            ),
            (
                "missing branch",
                {"full_name": REPOSITORY},
                "default branch",
            ),
            (
                "invalid branch",
                {"full_name": REPOSITORY, "default_branch": "main?ref=attacker"},
                "default branch",
            ),
        )
        for label, rest_response, message in cases:
            with self.subTest(label=label):
                api = RepositoryFallbackFakeApi(
                    graphql_repository_response(), repository_result=rest_response
                )
                with self.assertRaisesRegex(RetirementError, message):
                    collect_pre_migration_snapshot(api)
                self.assertFalse(any(call[0] == "graphql" for call in api.calls))

    def test_token_binds_exact_workflow_and_run_ids(self) -> None:
        first = snapshot()
        second_legacy = list(first.legacy)
        workflow, runs = second_legacy[0]
        second_legacy[0] = (
            workflow,
            runs
            + (Run(999, workflow.id, workflow.path, "completed", "push", "b" * 40),),
        )
        second = Snapshot(first.default_branch, tuple(second_legacy))
        self.assertNotEqual(apply_token(first), apply_token(second))
        self.assertTrue(
            apply_token(first).startswith("RETIRE-LEGACY-EXITFY-WORKFLOWS:")
        )

    def test_apply_rejects_wrong_token_or_active_run_before_mutation(self) -> None:
        value = snapshot()
        api = MutationFakeApi(value)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(RetirementError, "token"):
                retire(api, value, "wrong", Path(directory) / "receipt.json")
        self.assertEqual([], api.mutations)

        active = snapshot(statuses=("in_progress",))
        api = MutationFakeApi(active)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(RetirementError, "active runs"):
                retire(
                    api,
                    active,
                    apply_token(active),
                    Path(directory) / "receipt.json",
                )
        self.assertEqual([], api.mutations)

    def test_apply_fails_closed_when_default_branch_changes(self) -> None:
        import retire_legacy_workflows

        original_collect = retire_legacy_workflows.collect_pre_migration_snapshot
        try:
            for phase in ("disable", "delete"):
                with self.subTest(phase=phase):
                    value = snapshot()
                    api = BranchChangingMutationFakeApi(value, phase)
                    retire_legacy_workflows.collect_pre_migration_snapshot = (
                        lambda _api, selected=api: selected.current
                    )
                    with tempfile.TemporaryDirectory() as directory:
                        receipt = Path(directory) / "receipt.json"
                        with self.assertRaisesRegex(
                            RetirementError, "default branch changed"
                        ):
                            retire(api, value, apply_token(value), receipt)
                        self.assertFalse(receipt.exists())
                    if phase == "disable":
                        self.assertTrue(api.mutations)
                        self.assertTrue(
                            all(method == "PUT" for method, _ in api.mutations)
                        )
                    else:
                        self.assertTrue(
                            any(method == "DELETE" for method, _ in api.mutations)
                        )
        finally:
            retire_legacy_workflows.collect_pre_migration_snapshot = original_collect

    def test_apply_disables_deletes_exact_runs_and_writes_public_receipt(self) -> None:
        value = snapshot()
        api = MutationFakeApi(value)

        import retire_legacy_workflows

        original = retire_legacy_workflows.collect_pre_migration_snapshot
        retire_legacy_workflows.collect_pre_migration_snapshot = lambda _api: api.current
        try:
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "receipt.json"
                retire(api, value, apply_token(value), path)
                receipt = load_receipt(path)
                self.assertEqual(
                    tuple(workflow.id for workflow, _ in value.legacy),
                    tuple(workflow.id for workflow in receipt.legacy),
                )
                raw = path.read_text(encoding="utf-8")
                self.assertIn(f'"host": "{GITHUB_HOST}"', raw)
                self.assertNotIn("applyToken", raw)
                self.assertNotIn("headSha", raw)
        finally:
            retire_legacy_workflows.collect_pre_migration_snapshot = original

        expected_disable = {
            ("PUT", f"repos/{REPOSITORY}/actions/workflows/{workflow.id}/disable")
            for workflow, _ in value.legacy
        }
        expected_delete = {
            ("DELETE", f"repos/{REPOSITORY}/actions/runs/{run.id}")
            for _, runs in value.legacy
            for run in runs
        }
        self.assertEqual(expected_disable | expected_delete, set(api.mutations))
        verify_pre_migration_retired(api.current)

    def test_apply_is_idempotently_recoverable_after_all_runs_are_gone(self) -> None:
        value = snapshot(state="disabled_manually", statuses=())
        api = MutationFakeApi(value)
        import retire_legacy_workflows

        original = retire_legacy_workflows.collect_pre_migration_snapshot
        retire_legacy_workflows.collect_pre_migration_snapshot = lambda _api: api.current
        try:
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "receipt.json"
                retire(api, value, apply_token(value), path)
                load_receipt(path)
        finally:
            retire_legacy_workflows.collect_pre_migration_snapshot = original
        self.assertEqual(2, len(api.mutations))
        self.assertTrue(all(method == "PUT" for method, _ in api.mutations))

    def test_post_verify_tolerates_absent_deleted_identities_but_checks_global_runs(self) -> None:
        value = snapshot(state="disabled_manually", statuses=())
        with tempfile.TemporaryDirectory() as directory:
            path = self._write_receipt(directory, value)
            verify_post_migration(PostMigrationFakeApi(value), path)

            remaining = Run(
                777,
                value.legacy[0][0].id,
                value.legacy[0][0].path,
                "completed",
                "workflow_dispatch",
                "c" * 40,
            )
            with self.assertRaisesRegex(RetirementError, "still contains"):
                verify_post_migration(
                    PostMigrationFakeApi(value, repository_runs=(remaining,)), path
                )

    def test_post_verify_checks_live_state_when_legacy_identity_still_exists(self) -> None:
        value = snapshot(state="disabled_manually", statuses=())
        with tempfile.TemporaryDirectory() as directory:
            path = self._write_receipt(directory, value)
            verify_post_migration(
                PostMigrationFakeApi(value, include_legacy_identities=True), path
            )
            with self.assertRaisesRegex(RetirementError, "not retired"):
                verify_post_migration(
                    PostMigrationFakeApi(
                        value,
                        include_legacy_identities=True,
                        legacy_state="active",
                    ),
                    path,
                )

    def test_receipt_contract_rejects_extra_fields_and_duplicate_ids(self) -> None:
        value = snapshot(state="disabled_manually", statuses=())
        with tempfile.TemporaryDirectory() as directory:
            path = self._write_receipt(directory, value)
            document = json.loads(path.read_text(encoding="utf-8"))
            document["unexpected"] = True
            path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(RetirementError, "fields"):
                load_receipt(path)

            document.pop("unexpected")
            for field, boolean_value, integer_value in (
                ("schema", True, RECEIPT_SCHEMA),
                ("verifiedRunCount", False, 0),
            ):
                document[field] = boolean_value
                path.write_text(json.dumps(document), encoding="utf-8")
                with self.assertRaisesRegex(RetirementError, "proof"):
                    load_receipt(path)
                document[field] = integer_value

            document["host"] = "enterprise.example"
            path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(RetirementError, "proof"):
                load_receipt(path)

            document["host"] = GITHUB_HOST
            document["legacy"][1]["id"] = document["legacy"][0]["id"]
            path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(RetirementError, "duplicated"):
                load_receipt(path)


if __name__ == "__main__":
    unittest.main()
