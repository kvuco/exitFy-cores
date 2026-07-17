from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = {
    "xray": ROOT / ".github/workflows/publish-xray-core-v2.yml",
    "sing_box": ROOT / ".github/workflows/publish-singbox-core-v2.yml",
}


class ReleaseWorkflowHardeningTest(unittest.TestCase):
    def test_readme_source_bundle_command_supplies_frozen_inputs(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        local_build = readme.split("## Local build", 1)[1]
        self.assertEqual(
            local_build.count("./scripts/build_singbox_source_bundle.py"), 1
        )
        self.assertIn('expected_head="$(git rev-parse HEAD)"', local_build)
        self.assertIn("hashlib.sha256", local_build)
        self.assertIn('--repo-root "$PWD"', local_build)
        self.assertIn('--expected-head "$expected_head"', local_build)
        self.assertEqual(local_build.count("--expected-pin-sha256"), 2)
        self.assertIn('"singbox/go.mod=$pin_mod_sha"', local_build)
        self.assertIn('"singbox/go.sum=$pin_sum_sha"', local_build)

    def test_candidate_handoff_is_immutable_and_verified_before_pin_commit(self) -> None:
        for family, path in WORKFLOWS.items():
            with self.subTest(family=family):
                workflow = path.read_text(encoding="utf-8")
                build = workflow.split("  build:\n", 1)[1].split("  publish:\n", 1)[0]
                publish = workflow.split("  publish:\n", 1)[1]
                self.assertIn("handoff_sha: ${{ steps.handoff.outputs.handoff_sha }}", build)
                self.assertIn("snapshot_sha: ${{ steps.pins.outputs.snapshot_sha }}", build)
                self.assertIn("Create immutable candidate handoff", build)
                self.assertIn('show "$GITHUB_SHA:scripts/candidate_handoff.py"', build)
                self.assertIn("candidate-handoff.json", workflow)
                self.assertIn("core-attestation.json", workflow)
                self.assertIn("pin-snapshot", workflow)
                self.assertIn("path: ${{ runner.temp }}/candidate/", build)
                self.assertNotIn("dist/pins", workflow)
                self.assertIn("HANDOFF_SHA: ${{ needs.build.outputs.handoff_sha }}", publish)
                self.assertIn("SNAPSHOT_SHA: ${{ needs.build.outputs.snapshot_sha }}", publish)
                self.assertLess(
                    publish.index("Verify immutable candidate handoff"),
                    publish.index("Commit exact frozen"),
                )
                self.assertLess(
                    publish.index("Validate frozen publish head before local code"),
                    publish.index("Verify immutable candidate handoff"),
                )
                before_guard = publish.split(
                    "- name: Validate frozen publish head before local code", 1
                )[0]
                self.assertNotIn("./scripts/", before_guard)
                final_verification = build.split(
                    "- name: Verify final core bytes and freeze attestation", 1
                )[1].split("\n      - name:", 1)[0]
                self.assertIn(
                    'show "$GITHUB_SHA:scripts/verify_artifacts.py"',
                    final_verification,
                )
                self.assertIn("--attestation", final_verification)
                self.assertIn("--print-attestation-sha256", final_verification)
                self.assertIn('echo "sha256=$attestation_sha"', final_verification)
                self.assertIn("--core-attestation", build)
                self.assertIn("--core-attestation-sha256", build)
                self.assertIn(
                    "steps.core_attestation.outputs.sha256",
                    build,
                )
                self.assertLess(
                    build.index("Verify final core bytes and freeze attestation"),
                    build.index("Create immutable candidate handoff"),
                )

    def test_upstream_metadata_is_by_commit_and_foreign_pin_children_are_handled(self) -> None:
        xray = WORKFLOWS["xray"].read_text(encoding="utf-8")
        sing_box = WORKFLOWS["sing_box"].read_text(encoding="utf-8")
        self.assertIn("contents/go.mod?ref=$upstream_commit", xray)
        self.assertIn("contents/go.mod?ref=$upstream_commit", sing_box)
        self.assertNotIn("contents/go.mod?ref=$upstream_tag", xray)
        self.assertNotIn("contents/go.mod?ref=$upstream_tag", sing_box)
        self.assertIn('- "singbox/go.mod"', xray)
        self.assertIn('- "singbox/go.sum"', xray)
        self.assertRegex(sing_box, r'(?m)^      - "go\.mod"$')
        self.assertRegex(sing_box, r'(?m)^      - "go\.sum"$')
        self.assertIn("release_head_state.py", xray)
        self.assertIn("release_head_state.py", sing_box)
        self.assertIn("--foreign-pin singbox/go.mod", xray)
        self.assertIn("--foreign-pin go.mod", sing_box)

    def test_reproducibility_lanes_are_empty_private_and_independent(self) -> None:
        xray = WORKFLOWS["xray"].read_text(encoding="utf-8")
        sing_box = WORKFLOWS["sing_box"].read_text(encoding="utf-8")
        for workflow in (xray, sing_box):
            self.assertIn("mkdir -m 700", workflow)
            self.assertGreaterEqual(workflow.count("GOCACHE="), 2)
            self.assertEqual(workflow.count("GOCACHE="), workflow.count("GOTMPDIR="))
        self.assertIn("xray-repro-cache-a", xray)
        self.assertIn("xray-repro-cache-b", xray)
        self.assertIn("sb-source-cache-a", sing_box)
        self.assertIn("sb-source-cache-b", sing_box)
        self.assertIn("sb-repro-cache-a", sing_box)
        self.assertIn("sb-repro-cache-b", sing_box)

    def test_module_cache_and_source_builder_execute_frozen_code(self) -> None:
        for family, path in WORKFLOWS.items():
            with self.subTest(family=family):
                workflow = path.read_text(encoding="utf-8")
                build = workflow.split("  build:\n", 1)[1].split("  publish:\n", 1)[0]
                self.assertGreaterEqual(build.count("verify-module-cache"), 3)
                self.assertGreaterEqual(
                    build.count('show "$GITHUB_SHA:scripts/verify_build_inputs.py"'),
                    build.count("verify-module-cache"),
                )
                self.assertLess(build.index("go test"), build.index("verify-module-cache"))
                post_test_audit = build.split(
                    "- name: Re-audit before handoff to publisher", 1
                )[1].split("\n      - name:", 1)[0]
                self.assertIn(
                    'show "$GITHUB_SHA:scripts/audit_public_tree.py"',
                    post_test_audit,
                )
                self.assertIn('--repo-root "$GITHUB_WORKSPACE"', post_test_audit)
                self.assertNotIn("./scripts/audit_public_tree.py", post_test_audit)
        sing_box = WORKFLOWS["sing_box"].read_text(encoding="utf-8")
        self.assertEqual(
            sing_box.count(
                'show "$GITHUB_SHA:scripts/build_singbox_source_bundle.py"'
            ),
            2,
        )
        self.assertGreaterEqual(sing_box.count('--repo-root "$GITHUB_WORKSPACE"'), 3)
        self.assertGreaterEqual(sing_box.count('--expected-head "$GITHUB_SHA"'), 9)
        self.assertEqual(
            sing_box.count('--expected-pin-sha256 "singbox/go.mod=$pin_mod_sha"'),
            2,
        )
        self.assertEqual(
            sing_box.count('--expected-pin-sha256 "singbox/go.sum=$pin_sum_sha"'),
            2,
        )
        self.assertEqual(
            sing_box.count(
                'show "$GITHUB_SHA:scripts/audit_singbox_source_bundle.py"'
            ),
            3,
        )
        self.assertNotIn("./scripts/build_singbox_source_bundle.py", sing_box)

    def test_singbox_candidate_source_is_audited_after_handoff_and_download(self) -> None:
        workflow = WORKFLOWS["sing_box"].read_text(encoding="utf-8")
        build = workflow.split("  build:\n", 1)[1].split("  publish:\n", 1)[0]
        publish = workflow.split("  publish:\n", 1)[1]
        self.assertLess(
            build.index("Create immutable candidate handoff"),
            build.index("Audit immutable candidate source bundle"),
        )
        self.assertLess(
            build.index("Audit immutable candidate source bundle"),
            build.index("Upload verified candidate"),
        )
        self.assertLess(
            publish.index("Verify immutable candidate handoff"),
            publish.index("Audit downloaded candidate source bundle"),
        )
        for section in (build, publish):
            audit = section.split("candidate source bundle", 1)[1]
            self.assertIn(
                'show "$GITHUB_SHA:scripts/audit_singbox_source_bundle.py"',
                audit,
            )

    def test_exact_public_recovery_proves_remote_and_local_candidate(self) -> None:
        for family, path in WORKFLOWS.items():
            with self.subTest(family=family):
                workflow = path.read_text(encoding="utf-8")
                publish = workflow.split("  publish:\n", 1)[1]
                self.assertIn("public_count", publish)
                self.assertIn("exact_count", publish)
                self.assertIn("public-recovery-manifest.json", publish)
                self.assertIn("verify_published_candidate.py", publish)
                self.assertGreaterEqual(
                    publish.count("verify_published_candidate.py"), 2
                )
                self.assertIn("--handoff-sha256", publish)
                self.assertIn("--remote-manifest", publish)
                self.assertIn("published-live-manifest.json", publish)
                self.assertLess(
                    publish.index("if [[ \"$public_count\" == 1 ]]"),
                    publish.index("gh release upload"),
                )

    def test_new_draft_visibility_retry_is_bounded_and_fail_closed(self) -> None:
        expected_counts = {"xray": 5, "sing_box": 6}
        for family, path in WORKFLOWS.items():
            with self.subTest(family=family):
                workflow = path.read_text(encoding="utf-8")
                publish = workflow.split("  publish:\n", 1)[1]
                upload = publish.index("gh release upload")
                ready = publish.index("release_draft_state.py verify-ready")
                remote = publish.index("verify_remote_release.py", ready)
                retry = publish[upload:remote]

                self.assertLess(upload, ready)
                self.assertLess(ready, remote)
                self.assertIn("for attempt in 1 2 3 4 5 6", retry)
                self.assertIn('if [[ "$status" -ne 75 ]]', retry)
                self.assertIn('if [[ "$attempt" -lt 6 ]]', retry)
                self.assertIn("sleep_seconds=$((1 << (attempt - 1)))", retry)
                self.assertIn('if [[ "$draft_ready" != true ]]', retry)
                self.assertEqual(
                    retry.count("--expected-asset"), expected_counts[family]
                )

                # Readiness polling is additive: final exact-set, remote
                # manifest and local digest verification still gate publish.
                self.assertIn("draft asset set is incomplete or unexpected", publish)
                self.assertIn("GitHub asset digest differs", publish)
                self.assertLess(
                    publish.index("draft asset set is incomplete or unexpected"),
                    publish.index("gh api --method PATCH", remote),
                )

    def test_actions_are_full_sha_pinned_and_write_token_is_publish_only(self) -> None:
        for family, path in WORKFLOWS.items():
            with self.subTest(family=family):
                workflow = path.read_text(encoding="utf-8")
                actions = re.findall(r"(?m)^\s*- uses: ([^@\s]+)@([^\s#]+)", workflow)
                self.assertTrue(actions)
                for _name, revision in actions:
                    self.assertRegex(revision, r"^[0-9a-f]{40}$")
                build = workflow.split("  build:\n", 1)[1].split("  publish:\n", 1)[0]
                publish = workflow.split("  publish:\n", 1)[1]
                self.assertNotIn("contents: write", build)
                self.assertIn("contents: write", publish)

    def test_read_only_build_reserves_a_run_unique_wrapper_revision(self) -> None:
        for family, path in WORKFLOWS.items():
            with self.subTest(family=family):
                workflow = path.read_text(encoding="utf-8")
                build = workflow.split("  build:\n", 1)[1].split(
                    "  publish:\n", 1
                )[0]
                self.assertIn('WRAPPER_REVISION_EPOCH: "1000"', build)
                self.assertIn(
                    "run_offset=$((WRAPPER_REVISION_EPOCH + GITHUB_RUN_NUMBER))",
                    build,
                )
                self.assertIn('--run-offset "$run_offset"', build)


if __name__ == "__main__":
    unittest.main()
