#!/usr/bin/env python3
"""Validate checked-in StarMem schemas and representative versioned documents."""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import Any

try:
    import jsonschema
except ImportError as exc:  # pragma: no cover - exercised by the CI dependency step
    raise SystemExit(
        "jsonschema is required; install the pinned CI dependency jsonschema==4.23.0"
    ) from exc


def load(path: pathlib.Path) -> Any:
    with path.open(encoding="utf-8") as stream:
        return json.load(stream)


def checked_validator(schema: Any) -> jsonschema.Draft202012Validator:
    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(schema)


def evidence_document(command: str) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "command": command,
        "engine_identity": {
            "version": "0.2.0",
            "build_id": "schema-validation",
            "integration_api_version": 5,
        },
        "source_identity": {
            "format": "synthetic",
            "size": 0,
            "mtime": None,
            "sample_digest": {"algorithm": "sha256", "value": "00"},
            "symbol_identity": None,
            "components": [],
            "physical_layout": None,
        },
        "available": False,
        "complete": False,
        "scope": {
            "kind": "declared_by_command_registry",
            "description": None,
            "constraints": {},
        },
        "warnings": [],
        "limits": [],
        "missing_ranges": [],
        "raw_evidence": {"count": 0, "storage": "none", "references": []},
        "data": {},
    }


def raw_object_document() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "evidence_id": "0" * 64,
        "plugin_id": "schema.test",
        "object_type": "synthetic",
        "address_space": "physical",
        "address": "0x0000000000000000",
        "semantic_key": "schema-test",
        "fields": {},
        "validation": {"valid": True, "method": "synthetic", "checks": {}},
        "provenance": [
            {"source": "synthetic", "locator": None, "relation": "schema_validation"}
        ],
        "missing_ranges": [],
    }


def host_api_documents() -> list[dict[str, Any]]:
    return [
        {
            "integration_api_version": 5,
            "request_id": "schema-open-1",
            "image_path": "memory.raw",
            "platform": "windows",
            "image": {
                "metadata_path": None,
                "auto_discover_sidecars": True,
                "decode_cache_bytes": 67108864,
                "qevm_layout": None,
            },
            "symbols": {
                "profile_path": None,
                "pdb_path": None,
                "cache_root": None,
                "search_roots": [],
                "allow_compatible_local_symbols": True,
            },
        },
        {
            "host_api_schema_version": 1,
            "integration_api_version": 5,
            "platform": "windows",
            "source_identity": evidence_document("pslist")["source_identity"],
            "warnings": [],
        },
        {
            "integration_api_version": 5,
            "request_id": "schema-run-1",
            "command_id": "pslist",
            "arguments": {"result_limit": 1024},
        },
        {
            "host_api_schema_version": 1,
            "integration_api_version": 5,
            "request_id": "schema-run-1",
            "command_id": "pslist",
            "envelope": evidence_document("pslist"),
            "artifacts": [],
        },
        {
            "host_api_schema_version": 1,
            "integration_api_version": 5,
            "request_id": "schema-run-1",
            "command_id": "pslist",
            "phase": "analysis",
            "unit": "stages",
            "current": 1,
            "total": 2,
            "state": "running",
        },
        {
            "host_api_schema_version": 1,
            "integration_api_version": 5,
            "request_id": "schema-run-1",
            "command_id": "pslist",
            "code": "analysis.failed",
            "message": "synthetic schema validation error",
            "retryable": False,
            "context": {},
        },
        {
            "host_api_schema_version": 1,
            "integration_api_version": 5,
            "evidence_schema_version": 1,
            "raw_object_schema_version": 1,
            "command_registry_schema_version": 2,
            "sqlite_schema_version": 4,
            "version": "0.2.0",
            "build_id": "schema-validation",
            "registered_command_count": 150,
            "supported_platforms": ["windows"],
            "runnable_command_ids": ["pslist", "windows.process-string"],
        },
    ]


def validate(root: pathlib.Path) -> None:
    schemas = {
        "evidence": load(root / "schemas/evidence-envelope-v1.schema.json"),
        "raw_object": load(root / "schemas/raw-object-v1.schema.json"),
        "command_registry": load(root / "schemas/command-registry-v2.schema.json"),
        "leaf_manifest": load(root / "schemas/leaf-command-manifest-v1.schema.json"),
        "release_manifest": load(root / "schemas/release-manifest-v1.schema.json"),
        "host_api": load(root / "schemas/host-api-v1.schema.json"),
        "equivalence": load(root / "benchmarks/command-equivalence.schema.json"),
        "corpus": load(root / "benchmarks/corpus.schema.json"),
    }
    validators = {name: checked_validator(schema) for name, schema in schemas.items()}

    equivalence = load(root / "benchmarks/command-equivalence.json")
    leaf_manifest = load(root / "metadata/leaf-command-manifest.json")
    validators["equivalence"].validate(equivalence)
    validators["leaf_manifest"].validate(leaf_manifest)
    validators["corpus"].validate(load(root / "benchmarks/corpus.example.json"))
    validators["raw_object"].validate(raw_object_document())
    for document in host_api_documents():
        validators["host_api"].validate(document)

    commands = equivalence.get("commands", {})
    if not isinstance(commands, dict) or not commands:
        raise ValueError("equivalence table has no leaf commands")
    declarations = leaf_manifest.get("commands", {})
    if set(declarations) != set(commands):
        raise ValueError("leaf manifest and equivalence command sets differ")
    for command, declaration in declarations.items():
        if declaration.get("command_id") != command:
            raise ValueError(f"leaf manifest map key differs from command_id: {command}")
        if declaration.get("equivalence_id") != command:
            raise ValueError(f"leaf manifest equivalence_id differs from command_id: {command}")
    for command in commands:
        validators["evidence"].validate(evidence_document(command))
    registry_equivalence = checked_validator({
        "$schema": schemas["command_registry"]["$schema"],
        "$defs": schemas["command_registry"]["$defs"],
        "$ref": "#/$defs/equivalenceRecord",
    })
    for record in commands.values():
        registry_equivalence.validate(record)

    print(
        json.dumps(
            {
                "schemas_checked": len(schemas),
                "leaf_envelopes_validated": len(commands),
                "leaf_declarations_validated": len(declarations),
                "registry_equivalence_records_validated": len(commands),
                "equivalence_document": "valid",
                "corpus_document": "valid",
                "raw_object_document": "valid",
                "host_api_documents": "valid",
            },
            indent=2,
        )
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".")
    args = parser.parse_args()
    try:
        validate(pathlib.Path(args.root).resolve())
    except (OSError, ValueError, json.JSONDecodeError, jsonschema.ValidationError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
