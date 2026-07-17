from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from release_draft_state import (
    DRAFT_NOT_READY_EXIT,
    DraftNotReady,
    ensure_not_downgrade,
    next_wrapper_revision,
    prepare_plan,
    verify_tag_references,
    verified_draft,
    verified_ready_draft,
)


TAG = "sb-v1.13.14-w2"
COMMIT = "a" * 40
READY_ASSETS = ("core.so", "manifest.json")


def release(
    tag: str,
    *,
    draft: bool,
    release_id: int = 1,
    asset_ids: tuple[int, ...] = (),
    prerelease: bool = False,
    target_commitish: str = COMMIT,
) -> dict:
    return {
        "id": release_id,
        "tag_name": tag,
        "draft": draft,
        "prerelease": prerelease,
        "target_commitish": target_commitish,
        "assets": [
            {"id": asset_id, "name": f"asset-{asset_id}"}
            for asset_id in asset_ids
        ],
    }


def ready_release(
    *,
    assets: tuple[str, ...] = READY_ASSETS,
    target_commitish: str = COMMIT,
) -> dict:
    value = release(
        TAG,
        draft=True,
        release_id=44,
        asset_ids=tuple(range(1, len(assets) + 1)),
        target_commitish=target_commitish,
    )
    value["assets"] = [
        {
            "id": index,
            "name": name,
            "size": index * 1024,
            "digest": f"sha256:{index:064x}",
        }
        for index, name in enumerate(assets, 1)
    ]
    return value


class ReleaseDraftStateTest(unittest.TestCase):
    def test_missing_exact_tag_creates_new_draft(self) -> None:
        plan = prepare_plan(
            [release("sb-v1.13.13-w9", draft=True, asset_ids=(4,))], TAG, COMMIT
        )
        self.assertEqual(
            plan, {"create": True, "draftId": None, "assetIds": []}
        )

    def test_one_reusable_draft_returns_every_stale_asset_id(self) -> None:
        draft = release(TAG, draft=True, release_id=44, asset_ids=(9, 3, 7))
        plan = prepare_plan([draft], TAG, COMMIT)
        self.assertEqual(
            plan, {"create": False, "draftId": 44, "assetIds": [3, 7, 9]}
        )
        self.assertIs(verified_draft([draft], TAG, COMMIT), draft)

    def test_public_or_ambiguous_exact_tag_fails_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "already public"):
            prepare_plan([release(TAG, draft=False)], TAG, COMMIT)
        with self.assertRaisesRegex(ValueError, "multiple drafts"):
            prepare_plan(
                [
                    release(TAG, draft=True, release_id=1),
                    release(TAG, draft=True, release_id=2),
                ],
                TAG,
                COMMIT,
            )
        with self.assertRaisesRegex(ValueError, "prerelease"):
            prepare_plan([release(TAG, draft=True, prerelease=True)], TAG, COMMIT)

    def test_invalid_or_duplicate_asset_ids_fail_closed(self) -> None:
        duplicate = release(TAG, draft=True, asset_ids=(5, 5))
        with self.assertRaisesRegex(ValueError, "duplicate asset ids"):
            prepare_plan([duplicate], TAG, COMMIT)
        invalid = release(TAG, draft=True)
        invalid["assets"] = [{"id": 0, "name": "broken"}]
        with self.assertRaisesRegex(ValueError, "invalid asset id"):
            prepare_plan([invalid], TAG, COMMIT)

    def test_verify_requires_exactly_one_draft(self) -> None:
        with self.assertRaisesRegex(ValueError, "missing"):
            verified_draft([], TAG, COMMIT)

    def test_ready_verify_treats_missing_or_incomplete_visibility_as_transient(
        self,
    ) -> None:
        with self.assertRaisesRegex(DraftNotReady, "not visible"):
            verified_ready_draft([], TAG, COMMIT, list(READY_ASSETS))

        incomplete = ready_release(assets=("core.so",))
        with self.assertRaisesRegex(DraftNotReady, "asset set"):
            verified_ready_draft(
                [incomplete], TAG, COMMIT, list(READY_ASSETS)
            )

        missing_digest = ready_release()
        missing_digest["assets"][0]["digest"] = None
        with self.assertRaisesRegex(DraftNotReady, "metadata"):
            verified_ready_draft(
                [missing_digest], TAG, COMMIT, list(READY_ASSETS)
            )

    def test_ready_verify_returns_only_a_complete_exact_draft(self) -> None:
        draft = ready_release()
        self.assertIs(
            verified_ready_draft([draft], TAG, COMMIT, list(READY_ASSETS)),
            draft,
        )

    def test_ready_verify_does_not_retry_identity_or_provenance_failures(
        self,
    ) -> None:
        with self.assertRaises(ValueError) as invalid_commit:
            verified_ready_draft([], TAG, "not-a-commit", list(READY_ASSETS))
        self.assertNotIsInstance(invalid_commit.exception, DraftNotReady)

        cases = (
            [release(TAG, draft=False)],
            [
                ready_release(),
                {**ready_release(), "id": 45},
            ],
            [ready_release(target_commitish="b" * 40)],
        )
        for releases in cases:
            with self.subTest(releases=releases):
                with self.assertRaises(ValueError) as caught:
                    verified_ready_draft(
                        releases, TAG, COMMIT, list(READY_ASSETS)
                    )
                self.assertNotIsInstance(caught.exception, DraftNotReady)

    def test_ready_verify_rejects_malformed_or_duplicate_asset_names(self) -> None:
        malformed = ready_release()
        malformed["assets"][0]["name"] = "../core.so"
        duplicate = ready_release()
        duplicate["assets"][1]["name"] = "core.so"
        for draft in (malformed, duplicate):
            with self.subTest(draft=draft):
                with self.assertRaises(ValueError) as caught:
                    verified_ready_draft(
                        [draft], TAG, COMMIT, list(READY_ASSETS)
                    )
                self.assertNotIsInstance(caught.exception, DraftNotReady)

    def test_ready_verify_rejects_unexpected_valid_asset_without_retry(self) -> None:
        unexpected = ready_release(assets=READY_ASSETS + ("unexpected.so",))
        with self.assertRaisesRegex(ValueError, "unexpected asset") as caught:
            verified_ready_draft(
                [unexpected], TAG, COMMIT, list(READY_ASSETS)
            )
        self.assertNotIsInstance(caught.exception, DraftNotReady)

    def test_verify_ready_cli_uses_a_distinct_transient_exit_code(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            releases = Path(temporary) / "releases.json"
            releases.write_text(json.dumps([]), encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    str(Path(__file__).with_name("release_draft_state.py")),
                    "verify-ready",
                    "--releases",
                    str(releases),
                    "--tag",
                    TAG,
                    "--commit",
                    COMMIT,
                    "--expected-asset",
                    "core.so",
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        self.assertEqual(DRAFT_NOT_READY_EXIT, result.returncode)
        self.assertEqual("", result.stdout)
        self.assertIn("not visible yet", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_existing_draft_must_already_target_wrapper_commit(self) -> None:
        stale = release(TAG, draft=True, target_commitish="b" * 40)
        with self.assertRaisesRegex(ValueError, "different wrapper commit"):
            prepare_plan([stale], TAG, COMMIT)

    def test_incomplete_public_tag_and_draft_both_reserve_revisions(self) -> None:
        releases = [
            # The asset set is intentionally incomplete: a public tag is still
            # immutable and must force the next wrapper revision.
            release("sb-v1.13.14-w2", draft=False, asset_ids=(1,)),
            release("sb-v1.13.14-w7", draft=True, asset_ids=(2,)),
            release("sb-v1.13.13-w99", draft=False, asset_ids=(3,)),
        ]
        self.assertEqual(next_wrapper_revision(releases, "sb-v1.13.14-w"), 8)

    def test_stale_draft_tag_cannot_wedge_a_later_wrapper_commit(self) -> None:
        old_commit = "a" * 40
        new_commit = "b" * 40
        releases = [
            release("sb-v1.13.14-w2", draft=False),
            {
                **release("sb-v1.13.14-w3", draft=True, release_id=3),
                "target_commitish": old_commit,
            },
        ]
        revision = next_wrapper_revision(releases, "sb-v1.13.14-w")
        self.assertEqual(revision, 4)

        # The only existing ref belongs to the reserved draft at w3. The new
        # run verifies a fresh w4 tag instead of repeatedly rejecting w3.
        references = [[{
            "ref": "refs/tags/sb-v1.13.14-w3",
            "object": {"type": "commit", "sha": old_commit},
        }]]
        verify_tag_references(
            references,
            f"sb-v1.13.14-w{revision}",
            new_commit,
            allow_missing=True,
        )

    def test_duplicate_or_malformed_drafts_fail_closed(self) -> None:
        duplicate = release("sb-v1.13.14-w3", draft=True, release_id=3)
        with self.assertRaisesRegex(ValueError, "duplicated"):
            next_wrapper_revision(
                [duplicate, {**duplicate, "id": 4}], "sb-v1.13.14-w"
            )

        with self.assertRaisesRegex(ValueError, "malformed"):
            next_wrapper_revision(
                [release("sb-v1.13.14-w03", draft=True)],
                "sb-v1.13.14-w",
            )

        invalid_asset = release("sb-v1.13.14-w3", draft=True)
        invalid_asset["assets"] = [{"id": 0}]
        with self.assertRaisesRegex(ValueError, "invalid asset id"):
            next_wrapper_revision([invalid_asset], "sb-v1.13.14-w")

    def test_upstream_downgrade_is_rejected_by_semver_not_lexical_order(self) -> None:
        releases = [
            release("sb-v1.13.9-w99", draft=False),
            release("sb-v1.14.0-w2", draft=False),
            release("sb-v99.0.0-w1", draft=True),
            release("xray-v26.7.11", draft=False),
        ]
        ensure_not_downgrade(releases, "sing_box", "v1.14.0")
        with self.assertRaisesRegex(ValueError, "downgrade"):
            ensure_not_downgrade(releases, "sing_box", "v1.13.14")
        ensure_not_downgrade(releases, "xray", "v26.7.11")

    def test_malformed_public_family_tag_fails_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "malformed"):
            ensure_not_downgrade(
                [release("sb-v1.13.14-candidate", draft=False)],
                "sing_box",
                "v1.13.14",
            )

    def test_tag_reference_may_be_missing_before_publish_but_must_match_after(self) -> None:
        commit = "a" * 40
        verify_tag_references([[]], TAG, commit, allow_missing=True)
        with self.assertRaisesRegex(ValueError, "missing"):
            verify_tag_references([[]], TAG, commit)
        pages = [[{
            "ref": f"refs/tags/{TAG}",
            "object": {"type": "commit", "sha": commit},
        }]]
        verify_tag_references(pages, TAG, commit)

    def test_foreign_or_annotated_tag_fails_closed(self) -> None:
        commit = "a" * 40
        for target in (
            {"type": "commit", "sha": "b" * 40},
            {"type": "tag", "sha": commit},
        ):
            with self.subTest(target=target):
                with self.assertRaisesRegex(ValueError, "does not point"):
                    verify_tag_references(
                        [{"ref": f"refs/tags/{TAG}", "object": target}],
                        TAG,
                        commit,
                        allow_missing=True,
                    )


if __name__ == "__main__":
    unittest.main()
