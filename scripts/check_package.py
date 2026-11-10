#!/usr/bin/env python3
"""Reject AppleDouble/macOS metadata and unsafe paths from StarMem packages."""

from __future__ import annotations

import argparse
import glob
import pathlib
import subprocess
import sys
import tarfile


FORBIDDEN_COMPONENTS = {
    "__MACOSX",
    ".DS_Store",
    ".Spotlight-V100",
    ".Trashes",
    ".local-validation",
    ".starmem-cache",
    "__pycache__",
}
FORBIDDEN_TOP_LEVEL_DIRECTORIES = {"src-tauri", "starmem-memory-forensics"}
FORENSIC_IMAGE_SUFFIXES = {
    ".avml",
    ".core",
    ".dmp",
    ".e01",
    ".elf",
    ".lime",
    ".mem",
    ".qe",
    ".qemu",
    ".raw",
    ".vmsn",
    ".vmem",
    ".vmss",
    ".xen",
}
PREBUILT_ARTIFACT_SUFFIXES = {".exe", ".zip"}
GENERATED_EVIDENCE_SUFFIXES = {
    ".bmp",
    ".csv",
    ".db",
    ".db3",
    ".hive",
    ".journal",
    ".jsonl",
    ".ndjson",
    ".partial",
    ".pcap",
    ".pcapng",
    ".shm",
    ".sqlite",
    ".sqlite3",
    ".tsv",
    ".wal",
}
ALLOWED_PACKAGE_PATHS = {
    ".cargo_vcs_info.json",
    "Cargo.lock",
    "Cargo.toml",
    "Cargo.toml.orig",
    "LICENSE",
    "README.en.md",
    "README.md",
    "THIRD_PARTY_NOTICES.md",
    "benchmarks/command-equivalence.json",
    "build.rs",
    "docs/CRATE_INTEGRATION.md",
    "licenses/LICENSE-APACHE",
    "licenses/LICENSE-GPL",
    "licenses/LICENSE-MIT",
    "metadata/leaf-command-manifest.json",
    "schemas/command-registry-v1.schema.json",
    "schemas/command-registry-v2.schema.json",
    "schemas/evidence-envelope-v1.schema.json",
    "schemas/host-api-v1.schema.json",
    "schemas/leaf-command-manifest-v1.schema.json",
    "schemas/raw-object-v1.schema.json",
    "schemas/release-manifest-v1.schema.json",
}
REQUIRED_RELATIVE_PATHS = {
    "Cargo.lock",
    "LICENSE",
    "README.en.md",
    "README.md",
    "THIRD_PARTY_NOTICES.md",
    "benchmarks/command-equivalence.json",
    "build.rs",
    "docs/CRATE_INTEGRATION.md",
    "licenses/LICENSE-APACHE",
    "licenses/LICENSE-GPL",
    "licenses/LICENSE-MIT",
    "metadata/leaf-command-manifest.json",
    "schemas/command-registry-v2.schema.json",
    "schemas/evidence-envelope-v1.schema.json",
    "schemas/host-api-v1.schema.json",
    "schemas/leaf-command-manifest-v1.schema.json",
    "schemas/raw-object-v1.schema.json",
    "schemas/release-manifest-v1.schema.json",
}


def package_relative_name(name: str) -> str:
    """Remove Cargo's single crate-version archive directory, when present."""
    normalized = name.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    parts = pathlib.PurePosixPath(normalized).parts
    if len(parts) > 1 and parts[0].startswith("starmem-"):
        return "/".join(parts[1:])
    return "/".join(parts)


def path_problem(name: str) -> str | None:
    normalized = name.replace("\\", "/")
    parts = pathlib.PurePosixPath(normalized).parts
    if not parts:
        return "empty path"
    if pathlib.PurePosixPath(normalized).is_absolute() or ".." in parts:
        return "absolute or parent-traversal path"
    relative = package_relative_name(name)
    relative_parts = pathlib.PurePosixPath(relative).parts
    if relative_parts and relative_parts[0] in FORBIDDEN_TOP_LEVEL_DIRECTORIES:
        return "non-crate bundled project"
    for part in parts:
        if part.startswith("._"):
            return "AppleDouble sidecar"
        if part in FORBIDDEN_COMPONENTS:
            return "forbidden metadata or cache component"
    if pathlib.PurePosixPath(normalized).suffix.lower() in FORENSIC_IMAGE_SUFFIXES:
        return "forensic image or acquisition sidecar"
    if pathlib.PurePosixPath(normalized).suffix.lower() in PREBUILT_ARTIFACT_SUFFIXES:
        return "prebuilt binary or bundle artifact"
    if pathlib.PurePosixPath(normalized).suffix.lower() in GENERATED_EVIDENCE_SUFFIXES:
        return "generated evidence or export artifact"
    return None


def allowlist_problem(name: str) -> str | None:
    relative = package_relative_name(name)
    if relative in ALLOWED_PACKAGE_PATHS:
        return None
    if relative.startswith("src/") and relative.endswith(".rs"):
        return None
    if relative.startswith("tests/") and relative.endswith(".rs"):
        return None
    return "path is outside the crate publication allowlist"


def cargo_package_list(root: pathlib.Path) -> list[str]:
    completed = subprocess.run(
        ["cargo", "package", "--list", "--allow-dirty"],
        cwd=root, capture_output=True, text=True,
    )
    if completed.returncode != 0:
        raise RuntimeError("cargo package --list failed:\n" + completed.stderr)
    return [line.strip() for line in completed.stdout.splitlines() if line.strip()]


def check_names(origin: str, names: list[str], errors: list[str]) -> None:
    for name in names:
        problem = path_problem(name)
        if problem:
            errors.append(f"{origin}: {problem}: {name}")
            continue
        problem = allowlist_problem(name)
        if problem:
            errors.append(f"{origin}: {problem}: {name}")


def check_required_paths(origin: str, names: list[str], errors: list[str]) -> None:
    normalized = {package_relative_name(name) for name in names}
    for required in sorted(REQUIRED_RELATIVE_PATHS):
        if required not in normalized:
            errors.append(f"{origin}: required package path is absent: {required}")


def check_crate(path: pathlib.Path, errors: list[str]) -> None:
    try:
        with tarfile.open(path, "r:gz") as archive:
            members = archive.getmembers()
    except (OSError, tarfile.TarError) as exc:
        errors.append(f"{path}: cannot read crate archive: {exc}")
        return
    names = [
        member.name
        for member in members
        if member.isfile() or member.issym() or member.islnk()
    ]
    check_names(str(path), names, errors)
    check_required_paths(str(path), names, errors)
    for member in members:
        if member.ischr() or member.isblk() or member.isfifo():
            errors.append(f"{path}: special file is forbidden: {member.name}")
        if member.issym() or member.islnk():
            link_problem = path_problem(member.linkname)
            if link_problem or pathlib.PurePosixPath(member.linkname).is_absolute():
                errors.append(f"{path}: unsafe link target {member.linkname!r}: {member.name}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", default=".", help="Cargo package root")
    parser.add_argument("--crate", action="append", default=[], help="crate path or glob; may be repeated")
    args = parser.parse_args()
    root = pathlib.Path(args.source).resolve()
    errors: list[str] = []
    try:
        package_names = cargo_package_list(root)
    except RuntimeError as exc:
        parser.error(str(exc))
    check_names("cargo package --list", package_names, errors)
    check_required_paths("cargo package --list", package_names, errors)
    crate_paths: list[pathlib.Path] = []
    for pattern in args.crate:
        candidate = pathlib.Path(pattern)
        full_pattern = str(candidate if candidate.is_absolute() else root / candidate)
        matches = [pathlib.Path(value) for value in glob.glob(full_pattern)]
        if not matches:
            errors.append(f"crate glob matched nothing: {pattern}")
        crate_paths.extend(matches)
    for path in sorted(set(crate_paths)):
        check_crate(path, errors)
    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 1
    print(f"package list clean ({len(package_names)} paths); crate archives checked: {len(crate_paths)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
