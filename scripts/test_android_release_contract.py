from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import candidate_handoff
import verify_artifacts
import verify_remote_release


class AndroidReleaseContractTest(unittest.TestCase):
    def test_android_artifact_matrix_is_arm64_v8a_only(self) -> None:
        self.assertEqual(("arm64-v8a",), candidate_handoff.ABIS)
        self.assertEqual(
            {"arm64-v8a": (2, 183, "EM_AARCH64")},
            verify_artifacts.ABI_LAYOUT,
        )
        self.assertEqual(
            {"arm64-v8a": (64, 183, "EM_AARCH64")},
            verify_remote_release.ABIS,
        )

    def test_builders_use_only_the_api_29_arm64_compiler(self) -> None:
        for relative in (
            "scripts/build_android.sh",
            "scripts/build_singbox_android.sh",
        ):
            with self.subTest(relative=relative):
                source = (ROOT / relative).read_text(encoding="utf-8")
                invocations = [
                    line.strip()
                    for line in source.splitlines()
                    if line.startswith("build_one ")
                ]
                self.assertEqual(
                    ["build_one arm64-v8a arm64 aarch64-linux-android29-clang"],
                    invocations,
                )
                self.assertNotIn("android26-clang", source)
                self.assertNotIn("armeabi-v7a", source)
                self.assertNotRegex(source, r"build_one x86(?:_64)?\b")

    def test_manifest_tools_enforce_schema_3_and_api_29(self) -> None:
        for relative in (
            "scripts/generate_manifest.py",
            "scripts/generate_singbox_manifest.py",
            "scripts/verify_manifest.py",
            "scripts/verify_singbox_manifest.py",
            "scripts/verify_remote_release.py",
        ):
            with self.subTest(relative=relative):
                source = (ROOT / relative).read_text(encoding="utf-8")
                self.assertRegex(source, r"(?:get\(\"schema\"\)|\"schema\")\s*(?:!=|:)\s*3")
                self.assertRegex(
                    source,
                    r"(?:get\(\"minAndroidApi\"\)|\"minAndroidApi\")\s*(?:!=|:)\s*29",
                )

    def test_obsolete_android_smoke_assets_are_absent(self) -> None:
        for relative in (
            "scripts/android_smoke.c",
            "scripts/run_android_smoke.sh",
            "scripts/run_singbox_android_smoke.sh",
            "scripts/with_api26_emulator.sh",
        ):
            self.assertFalse((ROOT / relative).exists(), relative)


if __name__ == "__main__":
    unittest.main()
