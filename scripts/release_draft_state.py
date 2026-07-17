#!/usr/bin/env python3
"""Select one exact-tag GitHub draft and enumerate every stale asset safely."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


MAX_RELEASES_BYTES = 64 * 1024 * 1024
MAX_REFERENCES_BYTES = 16 * 1024 * 1024
FAMILY_PREFIXES = {"sing_box": "sb", "xray": "xray"}
DRAFT_NOT_READY_EXIT = 75
ASSET_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,254}")
ASSET_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


class DraftNotReady(ValueError):
    """A newly-created draft has not fully propagated through the list API."""


def _load_json_bounded(path: Path, maximum: int, label: str) -> Any:
    with path.open("rb") as stream:
        raw = stream.read(maximum + 1)
    if len(raw) > maximum:
        raise ValueError(f"{label} exceeds the safety limit")
    return json.loads(raw)


def _load_releases(path: Path) -> list[dict[str, Any]]:
    value = _load_json_bounded(path, MAX_RELEASES_BYTES, "release list")
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise ValueError("release list must be an array of objects")
    return value


def _exact_matches(
    releases: list[dict[str, Any]], tag: str
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if not tag or any(character.isspace() for character in tag):
        raise ValueError("release tag is invalid")
    drafts: list[dict[str, Any]] = []
    published: list[dict[str, Any]] = []
    for release in releases:
        if release.get("tag_name") != tag:
            continue
        draft = release.get("draft")
        if draft is True:
            if release.get("prerelease") is not False:
                raise ValueError("matching draft must not be a prerelease")
            drafts.append(release)
        elif draft is False:
            published.append(release)
        else:
            raise ValueError("matching release has an invalid draft state")
    return drafts, published


def _require_commit(value: str) -> None:
    if re.fullmatch(r"[0-9a-f]{40}", value) is None:
        raise ValueError("wrapper commit is invalid")


def prepare_plan(
    releases: list[dict[str, Any]], tag: str, expected_commit: str
) -> dict[str, Any]:
    _require_commit(expected_commit)
    drafts, published = _exact_matches(releases, tag)
    if published:
        raise ValueError("the exact release tag is already public")
    if len(drafts) > 1:
        raise ValueError("the exact release tag has multiple drafts")
    if not drafts:
        return {"create": True, "draftId": None, "assetIds": []}

    draft = drafts[0]
    if draft.get("target_commitish") != expected_commit:
        raise ValueError("matching draft targets a different wrapper commit")
    draft_id = draft.get("id")
    assets = draft.get("assets")
    if type(draft_id) is not int or draft_id <= 0:
        raise ValueError("matching draft id is invalid")
    if not isinstance(assets, list):
        raise ValueError("matching draft assets are invalid")
    asset_ids: list[int] = []
    for asset in assets:
        asset_id = asset.get("id") if isinstance(asset, dict) else None
        if type(asset_id) is not int or asset_id <= 0:
            raise ValueError("matching draft contains an invalid asset id")
        asset_ids.append(asset_id)
    if len(asset_ids) != len(set(asset_ids)):
        raise ValueError("matching draft contains duplicate asset ids")
    return {
        "create": False,
        "draftId": draft_id,
        "assetIds": sorted(asset_ids),
    }


def verified_draft(
    releases: list[dict[str, Any]], tag: str, expected_commit: str
) -> dict[str, Any]:
    plan = prepare_plan(releases, tag, expected_commit)
    if plan["create"]:
        raise ValueError("verified draft is missing")
    drafts, _ = _exact_matches(releases, tag)
    return drafts[0]


def _expected_asset_names(values: list[str]) -> frozenset[str]:
    if not values:
        raise ValueError("at least one expected asset is required")
    names: set[str] = set()
    for value in values:
        if not isinstance(value, str) or ASSET_NAME.fullmatch(value) is None:
            raise ValueError("expected asset name is invalid")
        if value in names:
            raise ValueError("expected asset names are duplicated")
        names.add(value)
    return frozenset(names)


def verified_ready_draft(
    releases: list[dict[str, Any]],
    tag: str,
    expected_commit: str,
    expected_assets: list[str],
) -> dict[str, Any]:
    expected_names = _expected_asset_names(expected_assets)
    _require_commit(expected_commit)
    drafts, published = _exact_matches(releases, tag)
    if not drafts and not published:
        raise DraftNotReady("verified draft is not visible yet")

    # Identity and provenance errors are permanent for this run and must not
    # be hidden behind eventual-consistency retries.
    draft = verified_draft(releases, tag, expected_commit)
    assets = draft["assets"]
    names: set[str] = set()
    for asset in assets:
        name = asset.get("name")
        if not isinstance(name, str) or ASSET_NAME.fullmatch(name) is None:
            raise ValueError("matching draft contains an invalid asset name")
        if name in names:
            raise ValueError("matching draft contains duplicate asset names")
        names.add(name)
    if names - expected_names:
        raise ValueError("matching draft contains an unexpected asset")
    if names != expected_names:
        raise DraftNotReady("verified draft asset set is not ready")

    # GitHub may expose the asset entry before size/digest metadata reaches
    # the paginated releases endpoint. These fields remain mandatory: the
    # bounded caller retries, and never publishes a draft without them.
    for asset in assets:
        size = asset.get("size")
        digest = asset.get("digest")
        if (
            type(size) is not int
            or size <= 0
            or not isinstance(digest, str)
            or ASSET_DIGEST.fullmatch(digest) is None
        ):
            raise DraftNotReady(
                f"verified draft asset metadata is not ready: {asset['name']}"
            )
    return draft


def next_wrapper_revision(
    releases: list[dict[str, Any]], prefix: str, run_offset: int = 1
) -> int:
    if not prefix or any(character.isspace() for character in prefix):
        raise ValueError("release prefix is invalid")
    if type(run_offset) is not int or run_offset < 1 or run_offset > 2_147_483_647:
        raise ValueError("wrapper run offset is invalid")
    pattern = re.compile(re.escape(prefix) + r"([1-9][0-9]*)\Z")
    maximum = 1
    seen_tags: set[str] = set()
    for release in releases:
        tag = release.get("tag_name")
        if not isinstance(tag, str) or not tag.startswith(prefix):
            continue
        match = pattern.fullmatch(tag)
        draft = release.get("draft")
        if match is None:
            raise ValueError(f"matching wrapper tag is malformed: {tag}")
        if draft is not True and draft is not False:
            raise ValueError(f"matching wrapper release has invalid draft state: {tag}")
        if tag in seen_tags:
            raise ValueError(f"matching wrapper release is duplicated: {tag}")
        seen_tags.add(tag)

        if draft is True:
            # A failed run may already have created both a draft and its Git
            # tag. A publisher-only rerun keeps the original job output and
            # reuses that exact draft. A later workflow run must reserve the
            # revision instead of attempting to retarget its provenance.
            if release.get("prerelease") is not False:
                raise ValueError(f"matching draft must not be a prerelease: {tag}")
            draft_id = release.get("id")
            assets = release.get("assets")
            if type(draft_id) is not int or draft_id <= 0 or not isinstance(assets, list):
                raise ValueError(f"matching draft is malformed: {tag}")
            asset_ids: list[int] = []
            for asset in assets:
                asset_id = asset.get("id") if isinstance(asset, dict) else None
                if type(asset_id) is not int or asset_id <= 0:
                    raise ValueError(f"matching draft contains an invalid asset id: {tag}")
                asset_ids.append(asset_id)
            if len(asset_ids) != len(set(asset_ids)):
                raise ValueError(f"matching draft contains duplicate asset ids: {tag}")

        # Every exact public or draft tag reserves its revision. Public tags
        # remain reserved even when incomplete or accidentally prerelease.
        maximum = max(maximum, int(match.group(1)))
    # A contents:read workflow token cannot enumerate drafts. Adding a
    # monotonic per-run offset to the nondecreasing public maximum makes two
    # different runs choose different tags even when an older draft is hidden
    # from both of them. A rerun with the same public state remains stable.
    revision = maximum + run_offset
    if revision > 2_147_483_647:
        raise ValueError("next wrapper revision exceeds the supported range")
    return revision


def ensure_not_downgrade(
    releases: list[dict[str, Any]], family: str, upstream_tag: str
) -> None:
    prefix = FAMILY_PREFIXES.get(family)
    if prefix is None:
        raise ValueError("core family is invalid")
    target = re.fullmatch(r"v([0-9]+)\.([0-9]+)\.([0-9]+)", upstream_tag)
    if target is None:
        raise ValueError("upstream tag is invalid")
    target_version = tuple(int(part) for part in target.groups())
    pattern = re.compile(
        rf"{re.escape(prefix)}-v([0-9]+)\.([0-9]+)\.([0-9]+)"
        r"(?:-w([1-9][0-9]*))?\Z"
    )
    highest: tuple[tuple[int, int, int], int, str] | None = None
    for release in releases:
        if release.get("draft") is not False:
            continue
        tag = release.get("tag_name")
        if not isinstance(tag, str) or not tag.startswith(f"{prefix}-v"):
            continue
        match = pattern.fullmatch(tag)
        if match is None:
            raise ValueError(f"published {family} tag is malformed: {tag}")
        version = tuple(int(part) for part in match.groups()[:3])
        wrapper = int(match.group(4) or 0)
        candidate = (version, wrapper, tag)
        if highest is None or candidate[:2] > highest[:2]:
            highest = candidate
    if highest is not None and target_version < highest[0]:
        raise ValueError(
            f"upstream downgrade is forbidden: {upstream_tag} < {highest[2]}"
        )


def verify_tag_references(
    value: Any,
    tag: str,
    expected_commit: str,
    allow_missing: bool = False,
) -> None:
    if not tag or any(character.isspace() for character in tag):
        raise ValueError("release tag is invalid")
    _require_commit(expected_commit)
    if not isinstance(value, list):
        raise ValueError("tag reference response must be an array")
    references: list[Any] = []
    for item in value:
        if isinstance(item, list):
            references.extend(item)
        else:
            references.append(item)
    if not all(isinstance(reference, dict) for reference in references):
        raise ValueError("tag reference response contains a malformed entry")
    exact_name = f"refs/tags/{tag}"
    exact = [
        reference
        for reference in references
        if isinstance(reference, dict) and reference.get("ref") == exact_name
    ]
    if not exact:
        if allow_missing:
            return
        raise ValueError("exact release tag reference is missing")
    if len(exact) != 1:
        raise ValueError("exact release tag reference is ambiguous")
    target = exact[0].get("object")
    if (
        not isinstance(target, dict)
        or target.get("type") != "commit"
        or target.get("sha") != expected_commit
    ):
        raise ValueError("release tag does not point to the wrapper commit")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "mode",
        choices=(
            "guard-upstream",
            "next-revision",
            "prepare",
            "verify",
            "verify-ready",
            "verify-tag",
        ),
    )
    parser.add_argument("--releases", type=Path)
    parser.add_argument("--references", type=Path)
    parser.add_argument("--tag")
    parser.add_argument("--prefix")
    parser.add_argument("--run-offset", type=int)
    parser.add_argument("--commit")
    parser.add_argument("--family", choices=tuple(FAMILY_PREFIXES))
    parser.add_argument("--upstream-tag")
    parser.add_argument("--allow-missing", action="store_true")
    parser.add_argument("--expected-asset", action="append", default=[])
    args = parser.parse_args()

    if args.mode == "verify-tag":
        if (
            args.references is None
            or args.tag is None
            or args.commit is None
            or args.releases is not None
            or args.prefix is not None
            or args.run_offset is not None
            or args.family is not None
            or args.upstream_tag is not None
            or args.expected_asset
        ):
            parser.error("verify-tag requires --references, --tag and --commit")
        verify_tag_references(
            _load_json_bounded(
                args.references, MAX_REFERENCES_BYTES, "tag reference response"
            ),
            args.tag,
            args.commit,
            args.allow_missing,
        )
        print("release tag reference verified")
        return
    if args.releases is None or args.references is not None:
        parser.error(f"{args.mode} requires --releases")
    if args.allow_missing:
        parser.error("--allow-missing is only valid with verify-tag")
    releases = _load_releases(args.releases)
    if args.mode == "guard-upstream":
        if (
            args.family is None
            or args.upstream_tag is None
            or args.prefix is not None
            or args.run_offset is not None
            or args.tag is not None
            or args.commit is not None
            or args.expected_asset
        ):
            parser.error(
                "guard-upstream requires --family and --upstream-tag only"
            )
        ensure_not_downgrade(releases, args.family, args.upstream_tag)
        print("upstream version does not downgrade a published core")
        return
    if args.family is not None or args.upstream_tag is not None:
        parser.error(f"{args.mode} does not accept --family or --upstream-tag")
    if args.mode == "next-revision":
        if (
            args.prefix is None
            or args.tag is not None
            or args.commit is not None
            or args.expected_asset
        ):
            parser.error("next-revision requires --prefix and does not accept --tag")
        run_offset = 1 if args.run_offset is None else args.run_offset
        print(next_wrapper_revision(releases, args.prefix, run_offset))
        return
    if (
        args.tag is None
        or args.commit is None
        or args.prefix is not None
        or args.run_offset is not None
    ):
        parser.error(
            f"{args.mode} requires --tag and --commit and does not accept --prefix"
        )
    if args.mode == "prepare":
        if args.expected_asset:
            parser.error("prepare does not accept --expected-asset")
        value = prepare_plan(releases, args.tag, args.commit)
    elif args.mode == "verify":
        if args.expected_asset:
            parser.error("verify does not accept --expected-asset")
        value = verified_draft(releases, args.tag, args.commit)
    else:
        value = verified_ready_draft(
            releases, args.tag, args.commit, args.expected_asset
        )
    print(json.dumps(value, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    try:
        main()
    except DraftNotReady as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(DRAFT_NOT_READY_EXIT) from None
