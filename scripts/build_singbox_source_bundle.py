#!/usr/bin/env python3
from __future__ import annotations

import argparse
import gzip
import json
import os
import shutil
import stat
import subprocess
import tarfile
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BUILD_TAGS = "with_quic,with_utls,badlinkname,tfogo_checklinkname0"
SOURCE_FIELDS = (
    "GoFiles", "CgoFiles", "CFiles", "CXXFiles", "MFiles", "HFiles",
    "FFiles", "SFiles", "SwigFiles", "SwigCXXFiles", "SysoFiles",
    "EmbedFiles",
)


def public_files() -> list[Path]:
    output = subprocess.check_output(
        [
            "git", "-C", str(ROOT), "ls-files", "--cached", "--others",
            "--exclude-standard", "-z",
        ]
    )
    return sorted(
        {ROOT / value.decode("utf-8") for value in output.split(b"\0") if value}
    )


def copy_public_tree(target: Path) -> None:
    for source in public_files():
        relative = source.relative_to(ROOT)
        destination = target / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        if source.is_symlink():
            raise ValueError(f"source bundle does not allow symlinks: {relative}")
        shutil.copy2(source, destination)


def add_tree(archive: tarfile.TarFile, source: Path, prefix: str) -> None:
    for path in sorted(source.rglob("*")):
        if path.is_symlink():
            raise ValueError(f"source bundle does not allow symlinks: {path}")
        relative = path.relative_to(source).as_posix()
        name = f"{prefix}/{relative}"
        info = archive.gettarinfo(str(path), arcname=name)
        info.uid = 0
        info.gid = 0
        info.uname = ""
        info.gname = ""
        info.mtime = 0
        info.pax_headers = {}
        if path.is_dir():
            info.mode = 0o755
            archive.addfile(info)
            continue
        executable = bool(path.stat().st_mode & stat.S_IXUSR)
        info.mode = 0o755 if executable else 0o644
        with path.open("rb") as payload:
            archive.addfile(info, payload)


def json_stream(value: str):
    decoder = json.JSONDecoder()
    offset = 0
    while offset < len(value):
        while offset < len(value) and value[offset].isspace():
            offset += 1
        if offset >= len(value):
            return
        item, offset = decoder.raw_decode(value, offset)
        yield item


def command_json_documents(
    command: list[str], directory: Path, environment: dict[str, str]
) -> list[dict[str, object]]:
    output = subprocess.check_output(
        command, cwd=directory, env=environment, text=True
    )
    return list(json_stream(output))


def copy_file(source: Path, destination: Path) -> None:
    if source.is_symlink():
        raise ValueError(f"minimal vendor does not allow symlinks: {source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        if source.read_bytes() == destination.read_bytes():
            return
        destination.chmod(0o644)
    shutil.copy2(source, destination)


def build_minimal_vendor(module: Path, environment: dict[str, str]) -> None:
    packages: list[dict[str, object]] = []
    for goarch, goarm in (("arm64", ""), ("arm", "7"), ("386", ""), ("amd64", "")):
        list_environment = environment.copy()
        list_environment.update(
            {"GOOS": "android", "GOARCH": goarch, "CGO_ENABLED": "1"}
        )
        if goarm:
            list_environment["GOARM"] = goarm
        output = subprocess.check_output(
            ["go", "list", "-mod=mod", "-deps", "-json", "-tags", BUILD_TAGS,
             "./cmd/exitfy-sb"],
            cwd=module,
            env=list_environment,
            text=True,
        )
        packages.extend(json_stream(output))

    # `go mod vendor` treats almost every build tag as enabled and downloads
    # multi-gigabyte optional Cronet/TUN/Tailscale modules that exitFy does not
    # compile. Build the canonical minimal modules.txt from the explicit module
    # graph and the exact four-ABI package list instead.
    edit = json.loads(
        subprocess.check_output(
            ["go", "mod", "edit", "-json"],
            cwd=module,
            env=environment,
            text=True,
        )
    )
    if edit.get("Replace"):
        raise ValueError("minimal vendor does not allow module replacements")
    explicit = {
        item["Path"]: item["Version"] for item in edit.get("Require", [])
    }
    module_metadata = {
        item["Path"]: item
        for item in command_json_documents(
            ["go", "list", "-m", "-json", "all"], module, environment
        )
        if not item.get("Main")
    }
    minimal_vendor = module / ".vendor-minimal"
    if minimal_vendor.exists():
        shutil.rmtree(minimal_vendor)
    minimal_vendor.mkdir()

    module_roots: dict[str, Path] = {}
    module_packages: dict[str, set[str]] = {}
    for package in packages:
        module_info = package.get("Module") or {}
        if not module_info or module_info.get("Main"):
            continue
        import_path = package.get("ImportPath", "")
        package_dir = Path(package.get("Dir", ""))
        module_path = module_info.get("Path", "")
        module_dir = Path(module_info.get("Dir", ""))
        if not import_path or not package_dir.is_dir() or not module_path or not module_dir.is_dir():
            raise ValueError(f"incomplete Go package metadata for {import_path!r}")
        destination = minimal_vendor / import_path
        for field in SOURCE_FIELDS:
            for relative_name in package.get(field, []) or []:
                relative = Path(relative_name)
                if relative.is_absolute() or ".." in relative.parts:
                    raise ValueError(f"unsafe Go source path: {relative_name}")
                source = package_dir / relative
                if not source.is_file():
                    raise ValueError(f"listed Go source is missing: {source}")
                copy_file(source, destination / relative)
        module_roots[module_path] = module_dir
        module_packages.setdefault(module_path, set()).add(import_path)

    for module_path, module_dir in module_roots.items():
        destination = minimal_vendor / module_path
        for pattern in ("LICENSE*", "COPYING*", "NOTICE*", "AUTHORS*"):
            for source in sorted(module_dir.glob(pattern)):
                if source.is_file():
                    copy_file(source, destination / source.name)

    modules_lines: list[str] = []
    for module_path in sorted(set(explicit) | set(module_packages)):
        metadata = module_metadata.get(module_path) or {}
        version = explicit.get(module_path) or metadata.get("Version", "")
        if not version:
            raise ValueError(f"missing module version for {module_path}")
        modules_lines.append(f"# {module_path} {version}")
        annotations: list[str] = []
        if module_path in explicit:
            annotations.append("explicit")
        go_version = metadata.get("GoVersion", "")
        if go_version:
            annotations.append(f"go {go_version}")
        if annotations:
            modules_lines.append("## " + "; ".join(annotations))
        modules_lines.extend(sorted(module_packages.get(module_path, set())))
    (minimal_vendor / "modules.txt").write_text(
        "\n".join(modules_lines) + "\n", encoding="utf-8"
    )

    full_vendor = module / "vendor"
    if full_vendor.exists():
        shutil.rmtree(full_vendor)
    minimal_vendor.rename(full_vendor)
    for goarch, goarm in (("arm64", ""), ("arm", "7"), ("386", ""), ("amd64", "")):
        list_environment = environment.copy()
        list_environment.update(
            {"GOOS": "android", "GOARCH": goarch, "CGO_ENABLED": "1"}
        )
        if goarm:
            list_environment["GOARM"] = goarm
        subprocess.run(
            ["go", "list", "-mod=vendor", "-tags", BUILD_TAGS, "./cmd/exitfy-sb"],
            cwd=module,
            env=list_environment,
            check=True,
            stdout=subprocess.DEVNULL,
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--upstream-version", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    version = args.upstream_version.removeprefix("v")
    if not version or any(part == "" or not part.isdigit() for part in version.split(".")):
        raise ValueError("invalid upstream version")
    subprocess.run([str(ROOT / "scripts/audit_public_tree.py")], check=True)

    with tempfile.TemporaryDirectory(prefix="exitfy-sb-source-") as temporary:
        tree = Path(temporary) / f"exitfy-sb-source-{version}"
        tree.mkdir()
        copy_public_tree(tree)
        module = tree / "singbox"
        environment = os.environ.copy()
        environment["GOTOOLCHAIN"] = "local"
        build_minimal_vendor(module, environment)

        args.output.parent.mkdir(parents=True, exist_ok=True)
        staged = args.output.with_name(f".{args.output.name}.tmp")
        try:
            with staged.open("wb") as raw:
                with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
                    with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
                        add_tree(archive, tree, tree.name)
            os.replace(staged, args.output)
        finally:
            staged.unlink(missing_ok=True)
    print(f"wrote reproducible source bundle: {args.output}")


if __name__ == "__main__":
    main()
