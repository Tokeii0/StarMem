#!/usr/bin/env python3
"""Generate and verify a machine-readable StarMem release manifest."""

from __future__ import annotations

import argparse
import datetime as dt
import glob
import hashlib
import json
import os
import pathlib
import platform
import subprocess
import sys
import tempfile
from typing import Any


SCHEMA_VERSION = 1


class ManifestError(ValueError):
    pass


def validate_manifest_schema(document: Any, root: pathlib.Path) -> None:
    """Validate a release manifest with the checked-in versioned schema."""
    schema_path = root / "schemas" / "release-manifest-v1.schema.json"
    try:
        import jsonschema
    except ImportError as exc:  # pragma: no cover - CI installs the pinned dependency
        raise ManifestError(
            "jsonschema is required; install jsonschema==4.23.0 to validate release manifests"
        ) from exc
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(schema)
        validator = jsonschema.Draft202012Validator(
            schema,
            format_checker=jsonschema.FormatChecker(),
        )
        errors = sorted(
            validator.iter_errors(document),
            key=lambda error: tuple(str(item) for item in error.absolute_path),
        )
    except (OSError, json.JSONDecodeError, jsonschema.SchemaError) as exc:
        raise ManifestError(f"cannot load release manifest schema {schema_path}: {exc}") from exc
    if errors:
        error = errors[0]
        location = "/".join(str(item) for item in error.absolute_path) or "<root>"
        raise ManifestError(
            f"release manifest violates {schema_path.name} at {location}: {error.message}"
        )


def append_git_identity_errors(
    errors: list[str],
    *,
    current_git: dict[str, Any],
    manifest_git: dict[str, Any],
    allow_dirty: bool,
) -> None:
    current_commit = current_git.get("commit")
    manifest_commit = manifest_git.get("commit")
    if not current_commit:
        errors.append("cannot determine current Git commit")
    if not manifest_commit:
        errors.append("release manifest does not identify a Git commit")
    elif current_commit and manifest_commit != current_commit:
        errors.append(
            f"current Git commit {current_commit} differs from manifest commit {manifest_commit}"
        )
    if not allow_dirty:
        if current_git.get("dirty") is not False:
            errors.append("current Git worktree is dirty or its state is unknown")
        if manifest_git.get("dirty") is not False:
            errors.append("release manifest was generated from a dirty or unknown worktree")


def append_build_info_identity_errors(
    errors: list[str],
    *,
    info: dict[str, Any],
    label: str,
    target: str,
    git_commit: str | None,
    allow_dirty: bool,
) -> None:
    if info.get("rust_target") != target:
        errors.append(
            f"{label} rust_target {info.get('rust_target')!r} differs from manifest target {target!r}"
        )
    binary_commit = info.get("git_commit")
    if not binary_commit:
        errors.append(f"{label} does not identify a Git commit")
    elif git_commit and binary_commit != git_commit:
        errors.append(
            f"{label} Git commit {binary_commit} differs from manifest commit {git_commit}"
        )
    if not allow_dirty and info.get("dirty") is not False:
        errors.append(f"{label} was built from a dirty or unknown worktree")


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(8 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def command_text(command: list[str], cwd: pathlib.Path) -> str | None:
    try:
        completed = subprocess.run(command, cwd=cwd, capture_output=True, text=True, check=True)
    except (OSError, subprocess.CalledProcessError):
        return None
    return (completed.stdout or completed.stderr).strip() or None


def cargo_package(root: pathlib.Path) -> dict[str, Any]:
    raw = command_text(["cargo", "metadata", "--no-deps", "--format-version", "1", "--locked"], root)
    if raw is None:
        raise ManifestError("cargo metadata failed")
    metadata = json.loads(raw)
    root_manifest = str((root / "Cargo.toml").resolve())
    packages = [package for package in metadata["packages"] if str(pathlib.Path(package["manifest_path"]).resolve()) == root_manifest]
    if len(packages) != 1:
        raise ManifestError("cannot identify root Cargo package")
    package = packages[0]
    return {
        "name": package["name"],
        "version": package["version"],
        "license": package.get("license"),
        "rust_version": package.get("rust_version"),
    }


def source_build_id(root: pathlib.Path) -> str:
    files = [
        pathlib.Path("Cargo.toml"),
        pathlib.Path("build.rs"),
        pathlib.Path("benchmarks/command-equivalence.json"),
        pathlib.Path("metadata/leaf-command-manifest.json"),
    ]
    files.extend(
        path.relative_to(root)
        for path in (root / "src").rglob("*.rs")
        if path.is_file() and not path.is_symlink()
        and path.suffix == ".rs" and not path.name.startswith("._")
    )
    original_manifest = root / "Cargo.toml.orig"
    digest = hashlib.sha256()
    for name_path in sorted(files, key=lambda path: path.parts):
        name = name_path.as_posix()
        source = root / name_path
        if name == "Cargo.toml" and original_manifest.is_file():
            source = original_manifest
        content = source.read_bytes()
        encoded_name = name.encode("utf-8")
        digest.update(len(encoded_name).to_bytes(8, "little"))
        digest.update(encoded_name)
        digest.update(len(content).to_bytes(8, "little"))
        digest.update(content)
    lock = root / "Cargo.lock"
    digest.update(b"starmem-Cargo.lock")
    if lock.is_file():
        lock_bytes = lock.read_bytes()
        digest.update(len(lock_bytes).to_bytes(8, "little"))
        digest.update(lock_bytes)
    else:
        digest.update(b"absent")
    return digest.hexdigest()


def git_identity(root: pathlib.Path) -> dict[str, Any]:
    commit = command_text(["git", "rev-parse", "HEAD"], root)
    try:
        completed = subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=normal"],
            cwd=root,
            capture_output=True,
            text=True,
            check=True,
        )
        dirty = bool(completed.stdout.strip())
    except (OSError, subprocess.CalledProcessError):
        dirty = None
    return {"commit": commit, "dirty": dirty}


def binary_build_info(binary: pathlib.Path, root: pathlib.Path) -> dict[str, Any]:
    try:
        completed = subprocess.run(
            [str(binary), "--json", "--no-progress", "build-info"],
            cwd=root,
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        document = json.loads(completed.stdout)
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        raise ManifestError(f"cannot execute build-info for {binary}: {exc}") from exc
    data = document.get("data") if isinstance(document, dict) else None
    if not isinstance(data, dict):
        raise ManifestError(f"build-info did not return an Evidence Envelope: {binary}")
    required = {
        "version", "build_id", "git_commit", "dirty", "rust_target", "features",
        "evidence_schema_version", "command_registry_schema_version",
        "leaf_command_manifest_schema_version", "host_api_schema_version",
        "integration_api_version", "sqlite_schema_version", "raw_object_schema_version",
    }
    missing = sorted(required - set(data))
    if missing:
        raise ManifestError(f"build-info is missing {missing}: {binary}")
    return data


def artifact_specs(values: list[str], root: pathlib.Path) -> list[tuple[str, pathlib.Path]]:
    artifacts: list[tuple[str, pathlib.Path]] = []
    for value in values:
        if "=" not in value:
            raise ManifestError(f"artifact must be ROLE=PATH: {value}")
        role, pattern = value.split("=", 1)
        if not role or not pattern:
            raise ManifestError(f"artifact must be ROLE=PATH: {value}")
        candidate = pathlib.Path(pattern)
        absolute_pattern = str(candidate if candidate.is_absolute() else root / candidate)
        matches = sorted(pathlib.Path(path) for path in glob.glob(absolute_pattern))
        if not matches:
            raise ManifestError(f"artifact did not match a file: {pattern}")
        for match in matches:
            if not match.is_file():
                raise ManifestError(f"artifact is not a regular file: {match}")
            artifacts.append((role, match.resolve()))
    return artifacts


def relative_or_absolute(path: pathlib.Path, root: pathlib.Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


def paths_alias(left: pathlib.Path, right: pathlib.Path) -> bool:
    """Best-effort existing-file identity plus normalized-path alias detection."""
    try:
        if left.exists() and right.exists() and os.path.samefile(left, right):
            return True
    except OSError:
        pass
    left_key = os.path.normcase(str(left.resolve(strict=False)))
    right_key = os.path.normcase(str(right.resolve(strict=False)))
    return left_key == right_key


def publish_json_atomic(
    output: pathlib.Path,
    document: dict[str, Any],
    *,
    force: bool,
    protected_inputs: list[pathlib.Path],
) -> None:
    for protected in protected_inputs:
        if paths_alias(output, protected):
            raise ManifestError(f"release manifest output aliases protected input: {protected}")
    if output.exists() and not force:
        raise ManifestError(f"release manifest already exists (pass --force): {output}")
    if output.exists() and not output.is_file():
        raise ManifestError(f"release manifest target is not a regular file: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{output.name}.starmem-", suffix=".partial", dir=output.parent
    )
    temporary = pathlib.Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(document, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, output)
        try:
            directory_fd = os.open(output.parent, os.O_RDONLY)
        except OSError:
            directory_fd = None
        if directory_fd is not None:
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def generate(args: argparse.Namespace) -> int:
    root = pathlib.Path(args.root).resolve()
    git = git_identity(root)
    if not git["commit"]:
        raise ManifestError("release manifest requires a known Git commit")
    if git["dirty"] is not False and not args.allow_dirty:
        raise ManifestError("release manifest requires a clean Git worktree")
    package = cargo_package(root)
    artifacts = artifact_specs(args.artifact, root)
    supporting = [
        root / "Cargo.lock",
        root / "LICENSE",
        root / "licenses" / "NOTICE.md",
        root / "licenses" / "LICENSE-MIT",
        root / "licenses" / "LICENSE-APACHE",
        root / "licenses" / "LICENSE-GPL",
        root / "benchmarks" / "command-equivalence.json",
        root / "benchmarks" / "corpus.schema.json",
        root / "schemas" / "command-registry-v1.schema.json",
        root / "schemas" / "command-registry-v2.schema.json",
        root / "schemas" / "leaf-command-manifest-v1.schema.json",
        root / "metadata" / "leaf-command-manifest.json",
        root / "schemas" / "evidence-envelope-v1.schema.json",
        root / "schemas" / "raw-object-v1.schema.json",
        root / "schemas" / "release-manifest-v1.schema.json",
    ]
    missing = [str(path) for path in supporting if not path.is_file()]
    if missing:
        raise ManifestError(f"required release inputs are missing: {missing}")
    build_id = source_build_id(root)
    binary_artifacts = [path for role, path in artifacts if role == "binary"]
    if not binary_artifacts:
        raise ManifestError("at least one artifact must use role=binary")
    reported_build_info = []
    for binary in binary_artifacts:
        info = binary_build_info(binary, root)
        if info["build_id"] != build_id:
            raise ManifestError(
                f"binary build-info ID {info['build_id']} differs from source ID {build_id}: {binary}"
            )
        if info["version"] != package["version"]:
            raise ManifestError(
                f"binary version {info['version']} differs from Cargo package {package['version']}"
            )
        reported_build_info.append({
            "artifact": relative_or_absolute(binary, root),
            "report": info,
        })
    binary_targets = {item["report"]["rust_target"] for item in reported_build_info}
    if args.target:
        target = args.target
    elif len(binary_targets) == 1:
        target = next(iter(binary_targets))
    else:
        raise ManifestError(
            "role=binary artifacts report different Rust targets; pass one target per manifest"
        )
    identity_errors: list[str] = []
    for item in reported_build_info:
        append_build_info_identity_errors(
            identity_errors,
            info=item["report"],
            label=f"binary {item['artifact']}",
            target=target,
            git_commit=git["commit"],
            allow_dirty=args.allow_dirty,
        )
    if identity_errors:
        raise ManifestError("release binary identity check failed: " + "; ".join(identity_errors))
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "generated_utc": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "package": package,
        "target": target,
        "build": {
            "id": build_id,
            "id_algorithm": "build.rs source-and-crate-lock sha256",
            "binary_identity_check": "every binary reported the current source build ID at runtime",
            "git": git,
            "binary_build_info": reported_build_info,
            "rustc": command_text(["rustc", "-Vv"], root),
            "cargo": command_text(["cargo", "-V"], root),
            "host": {"platform": platform.platform(), "python": platform.python_version()},
        },
        "artifacts": [
            {
                "role": role,
                "path": relative_or_absolute(path, root),
                "size_bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            }
            for role, path in artifacts
        ],
        "release_inputs": [
            {
                "path": relative_or_absolute(path, root),
                "size_bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            }
            for path in supporting
        ],
    }
    validate_manifest_schema(manifest, root)
    output = pathlib.Path(args.output)
    if not output.is_absolute():
        output = root / output
    publish_json_atomic(
        output,
        manifest,
        force=args.force,
        protected_inputs=[path for _, path in artifacts] + supporting,
    )
    print(output)
    return 0


def verify(args: argparse.Namespace) -> int:
    root = pathlib.Path(args.root).resolve()
    path = pathlib.Path(args.manifest)
    if not path.is_absolute():
        path = root / path
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ManifestError(f"cannot read manifest: {exc}") from exc
    if not isinstance(manifest, dict) or manifest.get("schema_version") != SCHEMA_VERSION:
        raise ManifestError("unsupported release manifest schema_version")
    validate_manifest_schema(manifest, root)
    errors: list[str] = []
    binary_count = 0
    current_git = git_identity(root)
    manifest_git = manifest["build"]["git"]
    append_git_identity_errors(
        errors,
        current_git=current_git,
        manifest_git=manifest_git,
        allow_dirty=args.allow_dirty,
    )
    reported_info = {
        item.get("artifact"): item.get("report")
        for item in manifest.get("build", {}).get("binary_build_info", [])
        if isinstance(item, dict)
    }
    for artifact, info in reported_info.items():
        if isinstance(info, dict):
            append_build_info_identity_errors(
                errors,
                info=info,
                label=f"manifest build-info for {artifact}",
                target=manifest["target"],
                git_commit=manifest_git["commit"],
                allow_dirty=args.allow_dirty,
            )
    for group in ("artifacts", "release_inputs"):
        entries = manifest.get(group)
        if not isinstance(entries, list) or not entries:
            errors.append(f"{group} is empty")
            continue
        for entry in entries:
            candidate = pathlib.Path(entry.get("path", ""))
            if not candidate.is_absolute():
                candidate = root / candidate
            if not candidate.is_file():
                errors.append(f"missing {group} file: {candidate}")
                continue
            size = candidate.stat().st_size
            digest = sha256_file(candidate)
            if size != entry.get("size_bytes"):
                errors.append(f"size mismatch: {candidate}")
            if digest != entry.get("sha256"):
                errors.append(f"SHA-256 mismatch: {candidate}")
            if group == "artifacts" and entry.get("role") == "binary":
                binary_count += 1
                expected_info = reported_info.get(entry.get("path"))
                if not isinstance(expected_info, dict):
                    errors.append(f"manifest lacks build-info report for binary: {candidate}")
                else:
                    try:
                        actual_info = binary_build_info(candidate, root)
                    except ManifestError as exc:
                        errors.append(str(exc))
                    else:
                        append_build_info_identity_errors(
                            errors,
                            info=actual_info,
                            label=f"binary {candidate}",
                            target=manifest["target"],
                            git_commit=manifest_git["commit"],
                            allow_dirty=args.allow_dirty,
                        )
                        if actual_info != expected_info:
                            errors.append(f"binary build-info differs from manifest: {candidate}")
                        if actual_info.get("build_id") != manifest.get("build", {}).get("id"):
                            errors.append(f"binary build-info ID differs from manifest: {candidate}")
    if binary_count == 0:
        errors.append("release manifest contains no role=binary artifact")
    current_build_id = source_build_id(root)
    if current_build_id != manifest.get("build", {}).get("id"):
        errors.append("source build ID differs from manifest")
    current_package = cargo_package(root)
    if current_package != manifest.get("package"):
        errors.append("Cargo package identity differs from manifest")
    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 1
    print(f"verified {len(manifest['artifacts'])} artifacts and {len(manifest['release_inputs'])} release inputs")
    return 0


def parser() -> argparse.ArgumentParser:
    top = argparse.ArgumentParser(description=__doc__)
    commands = top.add_subparsers(dest="command", required=True)
    create = commands.add_parser("generate")
    create.add_argument("--root", default=".")
    create.add_argument("--output", required=True)
    create.add_argument("--target")
    create.add_argument("--force", action="store_true", help="replace an existing ordinary manifest")
    create.add_argument(
        "--allow-dirty",
        action="store_true",
        help="development-only override; release gates must not use this",
    )
    create.add_argument("--artifact", action="append", required=True, help="ROLE=PATH; PATH may contain a glob")
    create.set_defaults(handler=generate)
    check = commands.add_parser("verify")
    check.add_argument("manifest")
    check.add_argument("--root", default=".")
    check.add_argument(
        "--allow-dirty",
        action="store_true",
        help="development-only override for dirty state; target and Git commit still must match",
    )
    check.set_defaults(handler=verify)
    return top


def main() -> int:
    top = parser()
    args = top.parse_args()
    try:
        return int(args.handler(args))
    except (ManifestError, OSError, json.JSONDecodeError) as exc:
        top.error(str(exc))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
