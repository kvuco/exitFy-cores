from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

import candidate_handoff


EVENT = "a" * 40
UPSTREAM = "b" * 40


def canonical(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()


class CandidateHandoffTest(unittest.TestCase):
    def fixture(
        self, family: str = "xray"
    ) -> tuple[Path, Path, Path, dict[str, str]]:
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        artifacts = root / "artifacts"
        snapshot = root / "snapshot"
        artifacts.mkdir(mode=0o700)
        snapshot.mkdir(mode=0o700)
        tag = "v1.2.3"
        if family == "xray":
            names = [f"libxray-{abi}.so" for abi in candidate_handoff.ABIS]
            module_path = "github.com/xtls/libxray"
            pin_paths = ["go.mod", "go.sum"]
            release_tag = "xray-v1.2.3-w2"
        else:
            names = [f"libexitfy-sb-{abi}.so" for abi in candidate_handoff.ABIS]
            names.append("exitfy-sb-v1.2.3-source.tar.gz")
            module_path = "github.com/sagernet/sing-box"
            pin_paths = ["singbox/go.mod", "singbox/go.sum"]
            release_tag = "sb-v1.2.3-w2"
        for index, name in enumerate(names):
            payload = (name.encode() + b"\n") * (index + 1)
            if family == "sing_box" and name.endswith(".so"):
                payload = payload.ljust(1024 * 1024, b"x")
            (artifacts / name).write_bytes(payload)
        core_records = []
        for name in sorted(value for value in names if value.endswith(".so")):
            abi = next(abi for abi in candidate_handoff.ABIS if name.endswith(f"-{abi}.so"))
            elf_class, machine = candidate_handoff.ABI_LAYOUT[abi]
            raw = (artifacts / name).read_bytes()
            core_records.append(
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
            canonical({"schema": 1, "family": family, "files": core_records})
        )
        pin_values = {"go.mod": b"module example.invalid\n", "go.sum": b"sum\n"}
        records = []
        for path, name in zip(pin_paths, ("go.mod", "go.sum")):
            value = pin_values[name]
            (snapshot / name).write_bytes(value)
            records.append(
                {
                    "path": path,
                    "file": name,
                    "size": len(value),
                    "sha256": hashlib.sha256(value).hexdigest(),
                }
            )
        metadata = {
            "schema": 1,
            "modulePath": module_path,
            "moduleVersion": "v1.2.3",
            "originCommit": UPSTREAM,
            "pins": records,
        }
        snapshot_raw = canonical(metadata)
        (snapshot / "snapshot.json").write_bytes(snapshot_raw)
        values = {
            "family": family,
            "event_commit": EVENT,
            "upstream_tag": tag,
            "upstream_commit": UPSTREAM,
            "go_version": "1.24.7",
            "release_tag": release_tag,
            "snapshot_sha256": hashlib.sha256(snapshot_raw).hexdigest(),
        }
        return artifacts, snapshot, attestation, values

    def create(self, family: str = "xray") -> tuple[Path, str, dict[str, str]]:
        artifacts, snapshot, attestation, values = self.fixture(family)
        output = artifacts.parent / "candidate"
        digest = candidate_handoff.create_handoff(
            artifacts,
            snapshot,
            attestation,
            output,
            core_attestation_sha256=hashlib.sha256(
                attestation.read_bytes()
            ).hexdigest(),
            **values,
        )
        return output, digest, values

    def test_create_and_verify_binds_exact_xray_and_singbox_bytes(self) -> None:
        for family in ("xray", "sing_box"):
            with self.subTest(family=family):
                output, digest, values = self.create(family)
                candidate_handoff.verify_handoff(
                    output, expected_sha256=digest, **values
                )
                handoff = json.loads(
                    (output / candidate_handoff.HANDOFF_NAME).read_bytes()
                )
                self.assertEqual(
                    sorted(record["path"] for record in handoff["files"]),
                    [record["path"] for record in handoff["files"]],
                )
                self.assertEqual(handoff["eventCommit"], EVENT)
                self.assertEqual(handoff["schema"], 2)
                self.assertEqual(handoff["pinSnapshot"]["originCommit"], UPSTREAM)
                self.assertTrue((output / candidate_handoff.CORE_ATTESTATION_NAME).is_file())

    def test_mutation_extra_file_and_provenance_mismatch_fail_closed(self) -> None:
        output, digest, values = self.create()
        core = output / "libxray-x86.so"
        core.write_bytes(b"x" * core.stat().st_size)
        with self.assertRaisesRegex(ValueError, "bytes differ|ELF attestation"):
            candidate_handoff.verify_handoff(
                output, expected_sha256=digest, **values
            )

        output, digest, values = self.create()
        (output / "extra").write_bytes(b"extra")
        with self.assertRaisesRegex(ValueError, "file set"):
            candidate_handoff.verify_handoff(
                output, expected_sha256=digest, **values
            )

        output, digest, values = self.create()
        values["event_commit"] = "c" * 40
        with self.assertRaisesRegex(ValueError, "provenance"):
            candidate_handoff.verify_handoff(
                output, expected_sha256=digest, **values
            )

    def test_noncanonical_manifest_and_link_substitution_fail_closed(self) -> None:
        output, _, values = self.create()
        manifest = output / candidate_handoff.HANDOFF_NAME
        parsed = json.loads(manifest.read_bytes())
        manifest.write_text(json.dumps(parsed, indent=2) + "\n", encoding="utf-8")
        digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
        with self.assertRaisesRegex(ValueError, "canonical"):
            candidate_handoff.verify_handoff(
                output, expected_sha256=digest, **values
            )

        output, digest, values = self.create()
        core = output / "libxray-x86.so"
        victim = output.parent / "victim"
        victim.write_bytes(core.read_bytes())
        core.unlink()
        core.symlink_to(victim)
        with self.assertRaises((OSError, ValueError)):
            candidate_handoff.verify_handoff(
                output, expected_sha256=digest, **values
            )

        output, digest, values = self.create()
        core = output / "libxray-x86.so"
        victim = output.parent / "hardlink"
        os.link(core, victim)
        with self.assertRaisesRegex(ValueError, "single-link"):
            candidate_handoff.verify_handoff(
                output, expected_sha256=digest, **values
            )

    def test_snapshot_symlink_and_existing_destination_are_rejected(self) -> None:
        artifacts, snapshot, attestation, values = self.fixture()
        real = snapshot / "real.mod"
        (snapshot / "go.mod").rename(real)
        (snapshot / "go.mod").symlink_to(real.name)
        with self.assertRaises((OSError, ValueError)):
            candidate_handoff.create_handoff(
                artifacts,
                snapshot,
                attestation,
                artifacts.parent / "candidate",
                core_attestation_sha256=hashlib.sha256(
                    attestation.read_bytes()
                ).hexdigest(),
                **values,
            )

        artifacts, snapshot, attestation, values = self.fixture()
        output = artifacts.parent / "candidate"
        output.mkdir()
        with self.assertRaises((OSError, ValueError)):
            candidate_handoff.create_handoff(
                artifacts,
                snapshot,
                attestation,
                output,
                core_attestation_sha256=hashlib.sha256(
                    attestation.read_bytes()
                ).hexdigest(),
                **values,
            )

    def test_core_attestation_must_match_the_exact_copied_bytes(self) -> None:
        artifacts, snapshot, attestation, values = self.fixture()
        core = artifacts / "libxray-x86.so"
        core.write_bytes(b"x" * core.stat().st_size)
        with self.assertRaisesRegex(ValueError, "ELF attestation"):
            candidate_handoff.create_handoff(
                artifacts,
                snapshot,
                attestation,
                artifacts.parent / "candidate",
                core_attestation_sha256=hashlib.sha256(
                    attestation.read_bytes()
                ).hexdigest(),
                **values,
            )

        artifacts, snapshot, attestation, values = self.fixture()
        parsed = json.loads(attestation.read_bytes())
        parsed["files"][0]["exports"].append("Unexpected")
        attestation.write_bytes(canonical(parsed))
        with self.assertRaisesRegex(ValueError, "attestation record"):
            candidate_handoff.create_handoff(
                artifacts,
                snapshot,
                attestation,
                artifacts.parent / "candidate",
                core_attestation_sha256=hashlib.sha256(
                    attestation.read_bytes()
                ).hexdigest(),
                **values,
            )

        artifacts, snapshot, attestation, values = self.fixture()
        wrong_digest = "0" * 64
        with self.assertRaisesRegex(ValueError, "verifier output"):
            candidate_handoff.create_handoff(
                artifacts,
                snapshot,
                attestation,
                artifacts.parent / "candidate",
                core_attestation_sha256=wrong_digest,
                **values,
            )

    def test_allowed_final_manifest_must_still_be_a_regular_file(self) -> None:
        output, digest, values = self.create()
        target = output.parent / "manifest-target"
        target.write_bytes(b"{}\n")
        (output / "manifest.json").symlink_to(target)
        with self.assertRaises((OSError, ValueError)):
            candidate_handoff.verify_handoff(
                output,
                expected_sha256=digest,
                allowed_extra_files=frozenset({"manifest.json"}),
                **values,
            )


if __name__ == "__main__":
    unittest.main()
