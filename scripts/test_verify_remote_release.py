from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from verify_remote_release import (
    ABIS,
    MAX_MANIFEST_BYTES,
    _read_bounded,
    verify_remote_release,
)


UPSTREAM = "1" * 40
WRAPPER = "2" * 40
CORE_DIGEST = "3" * 64
SOURCE_DIGEST = "4" * 64


def fixture(family: str) -> tuple[dict, dict, bytes]:
    xray = family == "xray"
    upstream_tag = "v26.7.11" if xray else "v1.13.14"
    release_tag = f"{'xray' if xray else 'sb'}-{upstream_tag}-w2"
    entries = {}
    release_assets = []
    for index, (abi, (elf_class, machine, machine_name)) in enumerate(ABIS.items(), 1):
        name = f"libxray-{abi}.so" if xray else f"libexitfy-sb-{abi}.so"
        entries[abi] = {
            "name": name,
            "size": 1024 * 1024,
            "sha256": CORE_DIGEST,
            "elfClass": elf_class,
            "elfMachine": machine,
            "elfMachineName": machine_name,
            "exports": ["StartCore", "StopCore"],
        }
        release_assets.append({
            "id": index,
            "name": name,
            "size": 1024 * 1024,
            "digest": f"sha256:{CORE_DIGEST}",
        })
    upstream = {
        "repository": "XTLS/libXray" if xray else "SagerNet/sing-box",
        "tag": upstream_tag,
        "commit": UPSTREAM,
    }
    wrapper = {"repository": "kvuco/exitFy-cores", "commit": WRAPPER}
    if not xray:
        upstream["goVersion"] = "1.24.7"
        source_name = f"exitfy-sb-{upstream_tag}-source.tar.gz"
        wrapper.update({
            "ndkVersion": "27.2.12479018",
            "buildTags": ["badlinkname", "tfogo_checklinkname0", "with_quic", "with_utls"],
            "sourceBundle": {
                "name": source_name,
                "size": 1234,
                "sha256": SOURCE_DIGEST,
            },
        })
        release_assets.append({
            "id": 10,
            "name": source_name,
            "size": 1234,
            "digest": f"sha256:{SOURCE_DIGEST}",
        })
    manifest = {
        "schema": 2,
        "coreApi": 2,
        "configContract": 1,
        "family": family,
        "releaseTag": release_tag,
        "upstream": upstream,
        "wrapper": wrapper,
        "minAndroidApi": 26,
        "requiredExports": ["StartCore", "StopCore"],
        "assets": entries,
    }
    manifest_bytes = (json.dumps(manifest, sort_keys=True) + "\n").encode()
    release_assets.append({
        "id": 20,
        "name": "manifest.json",
        "size": len(manifest_bytes),
        "digest": "sha256:" + hashlib.sha256(manifest_bytes).hexdigest(),
    })
    release = {
        "tag_name": release_tag,
        "target_commitish": WRAPPER,
        "draft": False,
        "prerelease": False,
        "assets": release_assets,
    }
    return release, manifest, manifest_bytes


class RemoteReleaseTest(unittest.TestCase):
    def test_accepts_exact_xray_and_singbox_contracts(self) -> None:
        for family in ("xray", "sing_box"):
            with self.subTest(family=family):
                release, manifest, raw = fixture(family)
                verify_remote_release(release, manifest, raw, family, UPSTREAM, WRAPPER)

    def test_changed_remote_digest_forces_new_revision(self) -> None:
        release, manifest, raw = fixture("xray")
        release["assets"][0]["digest"] = "sha256:" + "9" * 64
        with self.assertRaisesRegex(ValueError, "remote core asset contract"):
            verify_remote_release(release, manifest, raw, "xray", UPSTREAM, WRAPPER)

    def test_changed_remote_size_forces_new_revision(self) -> None:
        release, manifest, raw = fixture("sing_box")
        release["assets"][0]["size"] += 1
        with self.assertRaisesRegex(ValueError, "remote core asset contract"):
            verify_remote_release(release, manifest, raw, "sing_box", UPSTREAM, WRAPPER)

    def test_tampered_manifest_asset_forces_new_revision(self) -> None:
        release, manifest, raw = fixture("xray")
        release["assets"][-1]["digest"] = "sha256:" + "8" * 64
        with self.assertRaisesRegex(ValueError, "remote manifest"):
            verify_remote_release(release, manifest, raw, "xray", UPSTREAM, WRAPPER)

    def test_manifest_read_is_bounded_before_json_parse(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            path.write_bytes(b"x" * (MAX_MANIFEST_BYTES + 1))
            with self.assertRaisesRegex(ValueError, "manifest exceeds"):
                _read_bounded(path, MAX_MANIFEST_BYTES, "manifest")

        release, manifest, raw = fixture("xray")
        oversized = raw + b" " * (MAX_MANIFEST_BYTES + 1 - len(raw))
        with self.assertRaisesRegex(ValueError, "manifest exceeds"):
            verify_remote_release(
                release, manifest, oversized, "xray", UPSTREAM, WRAPPER
            )

    def test_draft_requires_explicit_prepublication_mode(self) -> None:
        release, manifest, raw = fixture("xray")
        release["draft"] = True
        with self.assertRaisesRegex(ValueError, "not stable"):
            verify_remote_release(release, manifest, raw, "xray", UPSTREAM, WRAPPER)
        verify_remote_release(
            release, manifest, raw, "xray", UPSTREAM, WRAPPER, allow_draft=True
        )
        release["prerelease"] = True
        with self.assertRaisesRegex(ValueError, "not stable"):
            verify_remote_release(
                release, manifest, raw, "xray", UPSTREAM, WRAPPER, allow_draft=True
            )

    def test_incomplete_or_stale_release_is_not_current(self) -> None:
        release, manifest, raw = fixture("sing_box")
        release["assets"].pop(0)
        with self.assertRaises(ValueError):
            verify_remote_release(release, manifest, raw, "sing_box", UPSTREAM, WRAPPER)
        release, manifest, raw = fixture("sing_box")
        release["target_commitish"] = "f" * 40
        with self.assertRaisesRegex(ValueError, "commit pins"):
            verify_remote_release(release, manifest, raw, "sing_box", UPSTREAM, "f" * 40)

    def test_release_target_must_be_the_exact_wrapper_commit(self) -> None:
        release, manifest, raw = fixture("xray")
        release["target_commitish"] = "main"
        with self.assertRaisesRegex(ValueError, "target commit"):
            verify_remote_release(release, manifest, raw, "xray", UPSTREAM, WRAPPER)


if __name__ == "__main__":
    unittest.main()
