from __future__ import annotations

import os
import hashlib
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def run_git(root: Path, *arguments: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(root), *arguments], text=True
    ).strip()


def guard_script(workflow: Path) -> str:
    text = workflow.read_text(encoding="utf-8")
    section = text.split(
        "      - name: Validate frozen publish head before local code\n", 1
    )[1].split("\n      - name:", 1)[0]
    body = section.split("        run: |\n", 1)[1]
    script = textwrap.dedent(body)
    if "${{" in script or "./scripts/" in script:
        raise AssertionError("frozen-head guard must be standalone inline shell")
    return script


def initialize(test: unittest.TestCase) -> tuple[Path, Path, str]:
    directory = Path(test.enterContext(tempfile.TemporaryDirectory()))
    work = directory / "work"
    remote = directory / "remote.git"
    subprocess.run(["git", "init", "-q", "-b", "main", str(work)], check=True)
    subprocess.run(["git", "init", "-q", "--bare", str(remote)], check=True)
    run_git(work, "config", "user.name", "test")
    run_git(work, "config", "user.email", "test@example.invalid")
    (work / "singbox").mkdir()
    (work / "go.mod").write_text("xray base\n", encoding="utf-8")
    (work / "go.sum").write_text("xray sum base\n", encoding="utf-8")
    (work / "singbox" / "go.mod").write_text("sing-box base\n", encoding="utf-8")
    (work / "singbox" / "go.sum").write_text("sing-box sum base\n", encoding="utf-8")
    run_git(work, "add", ".")
    run_git(work, "commit", "-q", "-m", "base")
    event = run_git(work, "rev-parse", "HEAD")
    run_git(work, "remote", "add", "origin", str(remote))
    run_git(work, "push", "-q", "-u", "origin", "main")
    return directory, work, event


def set_candidate(directory: Path, work: Path, prefix: str) -> None:
    pins = directory / "candidate" / "pin-snapshot"
    pins.mkdir(parents=True)
    for name in ("go.mod", "go.sum"):
        (pins / name).write_bytes((work / prefix / name).read_bytes())
    (directory / "candidate" / "candidate-handoff.json").write_bytes(
        b'{"fixture":true}\n'
    )


def execute_guard(
    workflow: str,
    directory: Path,
    work: Path,
    event: str,
) -> subprocess.CompletedProcess[str]:
    output = directory / "github-output.txt"
    environment = os.environ.copy()
    environment.update(
        {
            "GITHUB_SHA": event,
            "GITHUB_OUTPUT": str(output),
            "RUNNER_TEMP": str(directory),
            "HANDOFF_SHA": hashlib.sha256(
                (directory / "candidate" / "candidate-handoff.json").read_bytes()
            ).hexdigest(),
        }
    )
    return subprocess.run(
        ["bash", "-c", workflow],
        cwd=work,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


class PublishHeadGuardTest(unittest.TestCase):
    def exercise_family(self, workflow_name: str, own_prefix: str, foreign: str) -> None:
        workflow = guard_script(ROOT / ".github" / "workflows" / workflow_name)

        directory, work, event = initialize(self)
        set_candidate(directory, work, own_prefix)
        exact = execute_guard(workflow, directory, work, event)
        self.assertEqual(exact.returncode, 0, exact.stderr)
        self.assertEqual(run_git(work, "rev-parse", "HEAD"), event)

        directory, work, event = initialize(self)
        own_pin = work / own_prefix / "go.mod"
        own_pin.write_text("updated own pin\n", encoding="utf-8")
        run_git(work, "add", own_prefix + "/go.mod" if own_prefix else "go.mod")
        run_git(work, "commit", "-q", "-m", "own pin")
        child = run_git(work, "rev-parse", "HEAD")
        run_git(work, "push", "-q", "origin", "main")
        set_candidate(directory, work, own_prefix)
        run_git(work, "checkout", "-q", "--detach", event)
        accepted = execute_guard(workflow, directory, work, event)
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        self.assertEqual(run_git(work, "rev-parse", "HEAD"), child)

        directory, work, event = initialize(self)
        own_pin = work / own_prefix / "go.mod"
        own_pin.write_text("remote own pin\n", encoding="utf-8")
        run_git(work, "add", own_prefix + "/go.mod" if own_prefix else "go.mod")
        run_git(work, "commit", "-q", "-m", "different own pin")
        run_git(work, "push", "-q", "origin", "main")
        run_git(work, "checkout", "-q", "--detach", event)
        set_candidate(directory, work, own_prefix)
        mismatch = execute_guard(workflow, directory, work, event)
        self.assertNotEqual(mismatch.returncode, 0)

        directory, work, event = initialize(self)
        foreign_pin = work / foreign
        foreign_pin.write_text("foreign family update\n", encoding="utf-8")
        run_git(work, "add", foreign)
        run_git(work, "commit", "-q", "-m", "foreign pin")
        foreign_child = run_git(work, "rev-parse", "HEAD")
        run_git(work, "push", "-q", "origin", "main")
        set_candidate(directory, work, own_prefix)
        run_git(work, "checkout", "-q", "--detach", event)
        cross_family = execute_guard(workflow, directory, work, event)
        self.assertEqual(cross_family.returncode, 0, cross_family.stderr)
        self.assertEqual(run_git(work, "rev-parse", "HEAD"), foreign_child)

        directory, work, event = initialize(self)
        run_git(work, "rm", "-q", foreign)
        run_git(work, "commit", "-q", "-m", "delete foreign pin")
        run_git(work, "push", "-q", "origin", "main")
        set_candidate(directory, work, own_prefix)
        run_git(work, "checkout", "-q", "--detach", event)
        deleted_foreign = execute_guard(workflow, directory, work, event)
        self.assertNotEqual(deleted_foreign.returncode, 0)

        directory, work, event = initialize(self)
        foreign_pin = work / foreign
        foreign_pin.write_text("foreign family update\n", encoding="utf-8")
        own_pin = work / own_prefix / "go.mod"
        own_pin.write_text("own family update\n", encoding="utf-8")
        run_git(work, "add", foreign,
                own_prefix + "/go.mod" if own_prefix else "go.mod")
        run_git(work, "commit", "-q", "-m", "mixed family pins")
        run_git(work, "push", "-q", "origin", "main")
        set_candidate(directory, work, own_prefix)
        run_git(work, "checkout", "-q", "--detach", event)
        mixed_family = execute_guard(workflow, directory, work, event)
        self.assertNotEqual(mixed_family.returncode, 0)

        directory, work, event = initialize(self)
        own_pin = work / own_prefix / "go.mod"
        own_pin.write_text("first update\n", encoding="utf-8")
        run_git(work, "add", own_prefix + "/go.mod" if own_prefix else "go.mod")
        run_git(work, "commit", "-q", "-m", "first child")
        own_pin.write_text("second update\n", encoding="utf-8")
        run_git(work, "add", own_prefix + "/go.mod" if own_prefix else "go.mod")
        run_git(work, "commit", "-q", "-m", "second child")
        run_git(work, "push", "-q", "origin", "main")
        set_candidate(directory, work, own_prefix)
        run_git(work, "checkout", "-q", "--detach", event)
        stale = execute_guard(workflow, directory, work, event)
        self.assertNotEqual(stale.returncode, 0)

    def test_xray_guard_accepts_exact_own_or_one_foreign_pin_child(self) -> None:
        self.exercise_family(
            "publish-xray-core-v2.yml", "", "singbox/go.mod"
        )

    def test_singbox_guard_accepts_exact_own_or_one_foreign_pin_child(self) -> None:
        self.exercise_family(
            "publish-singbox-core-v2.yml", "singbox", "go.mod"
        )


if __name__ == "__main__":
    unittest.main()
