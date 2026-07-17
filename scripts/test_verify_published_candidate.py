from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import candidate_handoff
import verify_published_candidate
import verify_remote_release


EVENT = "a" * 40
UPSTREAM = "b" * 40
WRAPPER = "c" * 40
TAG = "v1.2.3"
RELEASE_TAG = "xray-v1.2.3-w2"


def canonical(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()


class PublishedCandidateTest(unittest.TestCase):
    def fixture(self) -> tuple[dict[str, object], dict[str, object]]:
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        artifacts = root / "artifacts"
        snapshot = root / "snapshot"
        artifacts.mkdir(mode=0o700)
        snapshot.mkdir(mode=0o700)
        for index, abi in enumerate(candidate_handoff.ABIS):
            (artifacts / f"libxray-{abi}.so").write_bytes(
                bytes([65 + index]) * (1024 * 1024 + index)
            )
        attestation_records = []
        for abi in candidate_handoff.ABIS:
            name = f"libxray-{abi}.so"
            raw = (artifacts / name).read_bytes()
            elf_class, machine = candidate_handoff.ABI_LAYOUT[abi]
            attestation_records.append(
                {
                    "path": name,
                    "size": len(raw),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "elfClass": elf_class,
                    "machine": machine,
                    "exports": candidate_handoff.REQUIRED_EXPORTS,
                    "loadAlignments": [candidate_handoff.MIN_ANDROID_PAGE_ALIGNMENT],
                }
            )
        attestation = root / "verified-cores.json"
        attestation.write_bytes(
            canonical(
                {"schema": 1, "family": "xray", "files": attestation_records}
            )
        )
        pins = {"go.mod": b"module example.invalid\n", "go.sum": b"sum\n"}
        records = []
        for name, raw in pins.items():
            (snapshot / name).write_bytes(raw)
            records.append(
                {
                    "path": name,
                    "file": name,
                    "size": len(raw),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                }
            )
        snapshot_raw = canonical(
            {
                "schema": 1,
                "modulePath": "github.com/xtls/libxray",
                "moduleVersion": "v1.2.3",
                "originCommit": UPSTREAM,
                "pins": records,
            }
        )
        (snapshot / "snapshot.json").write_bytes(snapshot_raw)
        snapshot_sha = hashlib.sha256(snapshot_raw).hexdigest()
        candidate = root / "candidate"
        handoff_sha = candidate_handoff.create_handoff(
            artifacts,
            snapshot,
            attestation,
            candidate,
            core_attestation_sha256=hashlib.sha256(
                attestation.read_bytes()
            ).hexdigest(),
            family="xray",
            event_commit=EVENT,
            upstream_tag=TAG,
            upstream_commit=UPSTREAM,
            go_version="1.24.7",
            release_tag=RELEASE_TAG,
            snapshot_sha256=snapshot_sha,
        )

        entries: dict[str, dict[str, object]] = {}
        release_assets: list[dict[str, object]] = []
        for index, (abi, layout) in enumerate(verify_remote_release.ABIS.items(), 1):
            name = f"libxray-{abi}.so"
            raw = (candidate / name).read_bytes()
            digest = hashlib.sha256(raw).hexdigest()
            elf_class, machine, machine_name = layout
            entries[abi] = {
                "name": name,
                "size": len(raw),
                "sha256": digest,
                "elfClass": elf_class,
                "elfMachine": machine,
                "elfMachineName": machine_name,
                "exports": ["StartCore", "StopCore"],
            }
            release_assets.append(
                {
                    "id": index,
                    "name": name,
                    "size": len(raw),
                    "digest": f"sha256:{digest}",
                }
            )
        manifest = {
            "schema": 2,
            "coreApi": 2,
            "configContract": 1,
            "family": "xray",
            "releaseTag": RELEASE_TAG,
            "upstream": {
                "repository": "XTLS/libXray",
                "tag": TAG,
                "commit": UPSTREAM,
            },
            "wrapper": {
                "repository": "kvuco/exitFy-cores",
                "commit": WRAPPER,
            },
            "minAndroidApi": 26,
            "requiredExports": ["StartCore", "StopCore"],
            "assets": entries,
        }
        manifest_raw = canonical(manifest)
        (candidate / "manifest.json").write_bytes(manifest_raw)
        release_assets.append(
            {
                "id": 20,
                "name": "manifest.json",
                "size": len(manifest_raw),
                "digest": f"sha256:{hashlib.sha256(manifest_raw).hexdigest()}",
            }
        )
        release = {
            "id": 30,
            "tag_name": RELEASE_TAG,
            "target_commitish": WRAPPER,
            "draft": False,
            "prerelease": False,
            "assets": release_assets,
        }
        release_path = root / "release.json"
        references_path = root / "references.json"
        remote_manifest = root / "remote-manifest.json"
        release_path.write_text(json.dumps(release), encoding="utf-8")
        references_path.write_text(
            json.dumps(
                [
                    {
                        "ref": f"refs/tags/{RELEASE_TAG}",
                        "object": {"type": "commit", "sha": WRAPPER},
                    }
                ]
            ),
            encoding="utf-8",
        )
        remote_manifest.write_bytes(manifest_raw)
        args: dict[str, object] = {
            "family": "xray",
            "candidate_directory": candidate,
            "release_path": release_path,
            "references_path": references_path,
            "remote_manifest_path": remote_manifest,
            "handoff_sha256": handoff_sha,
            "event_commit": EVENT,
            "upstream_tag": TAG,
            "upstream_commit": UPSTREAM,
            "go_version": "1.24.7",
            "release_tag": RELEASE_TAG,
            "snapshot_sha256": snapshot_sha,
            "wrapper_commit": WRAPPER,
        }
        return args, release

    def test_exact_published_release_is_idempotently_accepted(self) -> None:
        args, _ = self.fixture()
        verify_published_candidate.verify_published_candidate(**args)

    def test_remote_manifest_asset_target_and_local_bytes_must_all_match(self) -> None:
        args, release = self.fixture()
        Path(args["remote_manifest_path"]).write_bytes(b"{}\n")
        with self.assertRaisesRegex(ValueError, "manifest bytes"):
            verify_published_candidate.verify_published_candidate(**args)

        args, release = self.fixture()
        release["target_commitish"] = "d" * 40
        Path(args["release_path"]).write_text(json.dumps(release), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "identity"):
            verify_published_candidate.verify_published_candidate(**args)

        args, release = self.fixture()
        release["assets"][0]["digest"] = "sha256:" + "e" * 64
        Path(args["release_path"]).write_text(json.dumps(release), encoding="utf-8")
        with self.assertRaises(ValueError):
            verify_published_candidate.verify_published_candidate(**args)

        args, _ = self.fixture()
        core = Path(args["candidate_directory"]) / "libxray-x86.so"
        core.write_bytes(b"z" * core.stat().st_size)
        with self.assertRaises(ValueError):
            verify_published_candidate.verify_published_candidate(**args)


if __name__ == "__main__":
    unittest.main()
