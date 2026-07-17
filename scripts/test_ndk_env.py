from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("ndk_env.sh")


def fake_ndk(root: Path, version: str, *, reported: str | None = None) -> Path:
    ndk = root / version
    (ndk / "toolchains" / "llvm" / "prebuilt").mkdir(parents=True)
    (ndk / "source.properties").write_text(
        f"Pkg.Desc = Android NDK\nPkg.Revision = {reported or version}\n",
        encoding="utf-8",
    )
    return ndk


def find_ndk(**values: str) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    for name in (
        "ANDROID_NDK_HOME",
        "ANDROID_NDK_ROOT",
        "ANDROID_SDK_ROOT",
        "ANDROID_HOME",
        "NDK_VERSION",
    ):
        environment.pop(name, None)
    environment.update(values)
    return subprocess.run(
        ["bash", "-c", 'source "$1"; exitfy_find_ndk', "ndk-test", str(SCRIPT)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        check=False,
    )


class NdkEnvironmentTest(unittest.TestCase):
    def test_explicit_ndk_requires_exact_source_properties_revision(self) -> None:
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        exact = fake_ndk(root, "27.2.12479018")
        result = find_ndk(
            ANDROID_NDK_HOME=str(exact), NDK_VERSION="27.2.12479018"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), str(exact))

        mismatch = fake_ndk(root, "mismatch", reported="27.1.0")
        result = find_ndk(
            ANDROID_NDK_HOME=str(mismatch), NDK_VERSION="27.2.12479018"
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("revision mismatch", result.stderr)

        missing = root / "missing-properties"
        (missing / "toolchains" / "llvm" / "prebuilt").mkdir(parents=True)
        result = find_ndk(ANDROID_NDK_HOME=str(missing))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("source.properties is missing", result.stderr)

    def test_pinned_sdk_lookup_never_falls_back_to_another_revision(self) -> None:
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        fake_ndk(root / "ndk", "28.0.0")
        result = find_ndk(
            ANDROID_SDK_ROOT=str(root), NDK_VERSION="27.2.12479018"
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not installed", result.stderr)

        result = find_ndk(
            ANDROID_SDK_ROOT=str(root), NDK_VERSION="../27.2.12479018"
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("revision is invalid", result.stderr)

    def test_unpinned_lookup_uses_numeric_not_lexical_order(self) -> None:
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        fake_ndk(root / "ndk", "27.9.0")
        newest = fake_ndk(root / "ndk", "27.10.0")
        result = find_ndk(ANDROID_SDK_ROOT=str(root))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), str(newest))

        huge = fake_ndk(root / "ndk", "27.100000000000000000000.0")
        result = find_ndk(ANDROID_SDK_ROOT=str(root))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), str(huge))

    def test_malformed_or_mismatched_highest_revision_fails_closed(self) -> None:
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        fake_ndk(root / "ndk", "27.9.0")
        fake_ndk(root / "ndk", "27.10.0", reported="27.8.0")
        result = find_ndk(ANDROID_SDK_ROOT=str(root))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("revision mismatch", result.stderr)


if __name__ == "__main__":
    unittest.main()
