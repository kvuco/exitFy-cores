#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from verify_artifacts import verify_family


PREFIX = "libexitfy-sb"


def verify(directory: Path, *, attestation: Path | None = None):
    return verify_family(directory, "sing_box", attestation=attestation)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    parser.add_argument("--attestation", type=Path)
    args = parser.parse_args()
    verify(args.directory, attestation=args.attestation)


if __name__ == "__main__":
    main()
