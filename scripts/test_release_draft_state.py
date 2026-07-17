from __future__ import annotations

import unittest

from release_draft_state import (
    ensure_not_downgrade,
    next_wrapper_revision,
    prepare_plan,
    verify_tag_references,
    verified_draft,
)


TAG = "sb-v1.13.14-w2"
COMMIT = "a" * 40


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
