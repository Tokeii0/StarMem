#!/usr/bin/env python3
"""Build the checked-in leaf-command declaration from audited CLI/catalog snapshots.

This maintenance helper is intentionally not run by the build.  The generated
document is reviewed and checked in; Rust and schema tests then treat it as the
authoritative leaf-command contract.  Snapshots are produced from Clap and the
collection catalog by the corresponding ignored developer tests.
"""

from __future__ import annotations

import argparse
import json
import pathlib
from typing import Any


MANIFEST_SCHEMA_VERSION = 1

OUTPUT_DIRECTORIES = {
    "desktop-reconstruct",
    "dump-logs",
    "dump-registry",
    "gdi-bitmap",
    "linux.proc.dump",
    "sqlite-recover",
}

OUTPUT_NAMES = {
    "collect": ("sqlite_database", "application/vnd.sqlite3"),
    "linux.module-extract": ("module_elf", "application/x-elf"),
    "mftdump": ("resident_data", "application/octet-stream"),
    "dumpfile": ("recovered_file", "application/octet-stream"),
    "pedump": ("pe_image", "application/vnd.microsoft.portable-executable"),
    "profile": ("profile", "application/json"),
    "packetscan": ("packet_capture", "application/x-pcapng"),
}

JSON_FILE_OUTPUTS = {
    "browser-history",
    "browser-session",
    "dnsscan",
    "event-timeline",
    "system-info",
}

LINUX_SCOPES = {
    "linux.lsmod": "linux_kernel_modules_list",
    "linux.module-extract": "linux_kernel_module_image",
    "linux.mountinfo": "linux_mount_namespace",
    "linux.kallsyms": "linux_core_and_module_kallsyms",
    "linux.kmsg": "linux_kernel_log",
    "linux.modxview": "linux_module_cross_view",
    "linux.check-syscall": "linux_syscall_table_entries",
}

COMMAND_SCOPES = {
    "windows.process-string": "windows_active_process_acquired_resident_literal_hits",
}


def load(path: pathlib.Path) -> Any:
    with path.open(encoding="utf-8") as stream:
        return json.load(stream)


def category_for(command_id: str, collection_category: str | None) -> str:
    if command_id == "build-info":
        return "release"
    if command_id == "collect":
        return "acquisition"
    if command_id.startswith("symbols.") or command_id == "profile":
        return "symbol"
    if command_id.startswith("linux."):
        return "linux"
    if command_id == "windows.process-string":
        return "process"
    if command_id in {"info", "crashinfo", "acquisition-info"}:
        return "acquisition"
    if command_id in {
        "browser-history",
        "browser-session",
        "cookiescan",
        "dnsscan",
        "downloadscan",
        "wechatscan",
    }:
        return "browser"
    mapping = {
        "内核对象": "kernel",
        "命令与交互": "windows",
        "导出": "file_system",
        "恶意代码": "malware",
        "执行与时间线": "timeline",
        "搜索": "file_system",
        "文件与对象": "file_system",
        "文件与磁盘": "file_system",
        "日志": "timeline",
        "服务与持久化": "windows",
        "注册表": "registry",
        "注册表与凭据": "registry",
        "系统与内存": "kernel",
        "网络与应用": "network",
        "进程与线程": "process",
        "进程与账户": "process",
        "进程内存": "process",
        "驱动与内核": "kernel",
    }
    try:
        return mapping[collection_category or ""]
    except KeyError as exc:
        raise ValueError(f"no registry category for {command_id}: {collection_category}") from exc


def corrected_argument_type(name: str, current: str) -> str:
    if name in {"db", "output", "output-dir", "cache"}:
        return "output_path"
    if name in {"input", "strings-file", "verify-db-root", "pdb", "profile", "isf", "image", "symbol-path"}:
        return "path"
    if name in {"file-object", "address", "base", "dtb", "kernel-slide", "namespace", "object", "task"}:
        return "address"
    if name in {"boot-time-unix-ns", "from", "to"}:
        return "timestamp"
    if name in {"context-bytes", "correlation-window-ms", "overlap-kib"}:
        return "integer"
    if name in {"encoding", "min-severity", "offset-kind", "source", "table", "view", "feature"}:
        return "choice"
    return current


def input_roles(arguments: list[dict[str, Any]], command_id: str) -> list[dict[str, Any]]:
    by_name = {argument["name"]: argument for argument in arguments}
    if command_id == "windows.process-string":
        return [
            {"role": "auxiliary_file", "required": False},
            {"role": "memory_image", "required": True},
            {"role": "pdb", "required": False},
            {"role": "search_pattern", "required": True},
            {"role": "symbol_store", "required": False},
        ]
    roles: dict[str, bool] = {}

    def add(role: str, required: bool) -> None:
        roles[role] = roles.get(role, False) or required

    if "image" in by_name:
        add("memory_image", bool(by_name["image"]["required"]))
        # The global VMware --metadata input is available to every image command.
        add("auxiliary_file", False)
    if "pdb" in by_name:
        add("pdb", bool(by_name["pdb"]["required"]))
    if "profile" in by_name:
        add("auxiliary_file", bool(by_name["profile"]["required"]))
    if "isf" in by_name:
        add("linux_isf", bool(by_name["isf"]["required"]))
    if "cache" in by_name or "symbol-path" in by_name:
        add("symbol_store", False)
    if "input" in by_name or "strings-file" in by_name or "verify-db-root" in by_name:
        required = any(
            bool(by_name[name]["required"])
            for name in ("input", "strings-file", "verify-db-root")
            if name in by_name
        )
        add("auxiliary_file", required)
    patterns = [argument for argument in arguments if argument["value_type"] == "pattern"]
    if patterns:
        required = any(bool(argument["required"]) for argument in patterns)
        if command_id == "scan":
            required = True  # Clap enforces the --text/--hex selector group at dispatch.
        add("search_pattern", required)
    return [{"role": role, "required": required} for role, required in sorted(roles.items())]


def outputs_for(command_id: str, arguments: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    outputs = [
        {
            "name": "evidence_report",
            "kind": "structured_report",
            "media_type": "application/json",
            "required": True,
        },
        {
            "name": "csv_report",
            "kind": "file",
            "media_type": "text/csv",
            "required": False,
        },
        {
            "name": "raw_objects",
            "kind": "file",
            "media_type": "application/x-ndjson",
            "required": False,
        },
    ]
    derived: list[dict[str, Any]] = []
    output_arguments = {
        argument["name"]: argument
        for argument in arguments
        if argument["name"] in {"db", "output", "output-dir"}
    }
    if output_arguments:
        argument = next(iter(output_arguments.values()))
        required = bool(argument["required"])
        if command_id in OUTPUT_DIRECTORIES:
            outputs.append(
                {
                    "name": "export_directory",
                    "kind": "directory",
                    "media_type": None,
                    "required": required,
                }
            )
            derived.append(
                {
                    "name": "owned_export_files",
                    "kind": "file",
                    "media_type": None,
                    "required": False,
                }
            )
        else:
            name, media_type = OUTPUT_NAMES.get(
                command_id,
                ("json_report" if command_id in JSON_FILE_OUTPUTS else "output_file", "application/json"),
            )
            outputs.append(
                {
                    "name": name,
                    "kind": "file",
                    "media_type": media_type,
                    "required": required,
                }
            )
    if "cache" in {argument["name"] for argument in arguments}:
        derived.append(
            {
                "name": "symbol_cache",
                "kind": "directory",
                "media_type": None,
                "required": False,
            }
        )
    if command_id == "linux.module-extract":
        derived.extend(
            [
                {
                    "name": "partial_module_elf",
                    "kind": "file",
                    "media_type": "application/x-elf",
                    "required": False,
                },
                {
                    "name": "recovery_manifest",
                    "kind": "file",
                    "media_type": "application/json",
                    "required": False,
                },
            ]
        )
    if command_id == "collect":
        for name in ("sqlite_wal", "sqlite_shm", "sqlite_journal"):
            derived.append(
                {
                    "name": name,
                    "kind": "file",
                    "media_type": "application/octet-stream",
                    "required": False,
                }
            )
    return outputs, derived


def is_parameterized(command_id: str, disposition: str, category: str | None) -> bool:
    if disposition != "skipped" or command_id in {"build-info", "collect"}:
        return False
    if command_id.startswith("symbols.") or command_id == "profile":
        return False
    if category == "Linux":
        return command_id in {"linux.proc.dump", "linux.module-extract"}
    return True


def generate(cli_path: pathlib.Path, collection_path: pathlib.Path, equivalence_path: pathlib.Path) -> dict[str, Any]:
    cli = load(cli_path)
    collection = load(collection_path)
    equivalence = load(equivalence_path)["commands"]
    cli_by_id = {entry["command_id"]: entry for entry in cli}
    collection_by_id = {entry["name"]: entry for entry in collection}
    if len(cli_by_id) != len(cli):
        raise ValueError("CLI snapshot contains duplicate command IDs")
    if len(collection_by_id) != len(collection):
        raise ValueError("collection snapshot contains duplicate command IDs")
    if set(cli_by_id) != set(equivalence):
        raise ValueError("CLI and equivalence command sets differ")
    if set(collection_by_id) != set(cli_by_id) - {"collect"}:
        raise ValueError("collection catalog must cover every CLI leaf except collect")

    commands: dict[str, Any] = {}
    for command_id in sorted(cli_by_id):
        cli_entry = cli_by_id[command_id]
        collection_entry = collection_by_id.get(command_id)
        arguments = []
        for source in cli_entry["arguments"]:
            argument = dict(source)
            argument["value_type"] = corrected_argument_type(
                argument["name"], argument["value_type"]
            )
            arguments.append(argument)
        disposition = (
            collection_entry["disposition"] if collection_entry else "skipped"
        )
        outputs, derived_outputs = outputs_for(command_id, arguments)
        commands[command_id] = {
            "command_id": command_id,
            "cli_path": cli_entry["cli_path"],
            "aliases": sorted(cli_entry["aliases"]),
            "help": cli_entry["help"],
            "arguments": arguments,
            "category": category_for(
                command_id,
                collection_entry["category"] if collection_entry else None,
            ),
            "input_roles": input_roles(arguments, command_id),
            "outputs": outputs,
            "derived_outputs": derived_outputs,
            "evidence_defaults": {
                "scope": (
                    "symbol_candidates"
                    if command_id == "symbols.linux"
                    else COMMAND_SCOPES.get(
                        command_id,
                        LINUX_SCOPES.get(command_id, f"command:{command_id}"),
                    )
                ),
                "adapter": "native-evidence-envelope-v1",
            },
            "collect_disposition": disposition,
            "collect_parameterized": is_parameterized(
                command_id,
                disposition,
                collection_entry["category"] if collection_entry else None,
            ),
            "equivalence_id": command_id,
        }
    return {
        "$schema": "../schemas/leaf-command-manifest-v1.schema.json",
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "commands": commands,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli-snapshot", type=pathlib.Path, required=True)
    parser.add_argument("--collection-snapshot", type=pathlib.Path, required=True)
    parser.add_argument(
        "--equivalence",
        type=pathlib.Path,
        default=pathlib.Path("benchmarks/command-equivalence.json"),
    )
    parser.add_argument(
        "--output",
        type=pathlib.Path,
        default=pathlib.Path("metadata/leaf-command-manifest.json"),
    )
    args = parser.parse_args()
    document = generate(args.cli_snapshot, args.collection_snapshot, args.equivalence)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"wrote {len(document['commands'])} leaf declarations to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
