#!/usr/bin/env python3
"""Reproducible StarMem/Volatility 3 corpus comparison runner.

The runner intentionally uses only the Python standard library.  It never downloads
symbols or images: every input must be supplied by the corpus manifest and the
STARMEM_* environment variables.
"""

from __future__ import annotations

import argparse
import collections
import ctypes
import datetime as dt
import hashlib
import json
import os
import pathlib
import platform
import shutil
import shlex
import signal
import subprocess
import sys
import time
import uuid
from typing import Any, Iterable


SCHEMA_VERSION = 1
MODES = {"exact", "subset", "expected_difference", "expected_failure"}
ENVELOPE_FIELDS = (
    "schema_version",
    "available",
    "complete",
    "scope",
    "warnings",
    "limits",
    "missing_ranges",
    "source_identity",
)


class ValidationError(ValueError):
    pass


def load_json(path: pathlib.Path) -> Any:
    try:
        with path.open("r", encoding="utf-8") as stream:
            return json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValidationError(f"cannot read JSON {path}: {exc}") from exc


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(8 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def validate_manifest(document: Any) -> None:
    require(isinstance(document, dict), "manifest root must be an object")
    require(document.get("schema_version") == SCHEMA_VERSION, "unsupported schema_version")
    require(isinstance(document.get("suite"), str) and document["suite"], "suite is required")
    images = document.get("images")
    cases = document.get("cases")
    require(isinstance(images, list) and images, "images must be a non-empty array")
    require(isinstance(cases, list) and cases, "cases must be a non-empty array")
    image_ids: set[str] = set()
    for index, image in enumerate(images):
        prefix = f"images[{index}]"
        require(isinstance(image, dict), f"{prefix} must be an object")
        image_id = image.get("id")
        require(isinstance(image_id, str) and image_id, f"{prefix}.id is required")
        require(image_id not in image_ids, f"duplicate image id: {image_id}")
        image_ids.add(image_id)
        require(isinstance(image.get("path"), str) and image["path"], f"{prefix}.path is required")
        require(not pathlib.Path(image["path"]).is_absolute(),
                f"{prefix}.path must be logical and relative to STARMEM_CORPUS_ROOT")
        digest = image.get("sha256")
        require(isinstance(digest, str) and len(digest) == 64, f"{prefix}.sha256 must be 64 hex digits")
        require(all(ch in "0123456789abcdefABCDEF" for ch in digest), f"{prefix}.sha256 is not hexadecimal")
        require(isinstance(image.get("size_bytes"), int) and image["size_bytes"] >= 0,
                f"{prefix}.size_bytes is required and must be non-negative")
        require(isinstance(image.get("container"), str) and image["container"],
                f"{prefix}.container is required")
        symbol_identity = image.get("symbol_identity", {})
        if symbol_identity:
            require(isinstance(symbol_identity, dict), f"{prefix}.symbol_identity must be an object")
            for material_index, material in enumerate(symbol_identity.get("materials", [])):
                material_prefix = f"{prefix}.symbol_identity.materials[{material_index}]"
                require(isinstance(material, dict), f"{material_prefix} must be an object")
                require(material.get("root") in {"shared", "windows", "linux"},
                        f"{material_prefix}.root is invalid")
                require(isinstance(material.get("path"), str) and material["path"]
                        and not pathlib.Path(material["path"]).is_absolute(),
                        f"{material_prefix}.path must be a logical relative path")
                material_digest = material.get("sha256")
                require(isinstance(material_digest, str) and len(material_digest) == 64
                        and all(ch in "0123456789abcdefABCDEF" for ch in material_digest),
                        f"{material_prefix}.sha256 must be 64 hex digits")
                require(isinstance(material.get("size_bytes"), int)
                        and material["size_bytes"] >= 0,
                        f"{material_prefix}.size_bytes is invalid")

    case_ids: set[str] = set()
    for index, case in enumerate(cases):
        prefix = f"cases[{index}]"
        require(isinstance(case, dict), f"{prefix} must be an object")
        case_id = case.get("id")
        require(isinstance(case_id, str) and case_id, f"{prefix}.id is required")
        require(case_id not in case_ids, f"duplicate case id: {case_id}")
        case_ids.add(case_id)
        require(case.get("image") in image_ids, f"{prefix}.image is unknown")
        require(case.get("mode") in MODES, f"{prefix}.mode must be one of {sorted(MODES)}")
        require(isinstance(case.get("timeout_seconds", 300), (int, float)) and case.get("timeout_seconds", 300) > 0,
                f"{prefix}.timeout_seconds must be positive")
        for tool in ("starmem", "volatility3"):
            config = case.get(tool)
            require(isinstance(config, dict), f"{prefix}.{tool} is required")
            argv = config.get("argv")
            require(isinstance(argv, list) and all(isinstance(value, str) for value in argv),
                    f"{prefix}.{tool}.argv must be a string array")
        comparison = case.get("comparison", {})
        require(isinstance(comparison, dict), f"{prefix}.comparison must be an object")
        keys = comparison.get("key_fields", [])
        require(isinstance(keys, list), f"{prefix}.comparison.key_fields must be an array")
        for key in keys:
            require(isinstance(key, dict) and isinstance(key.get("name"), str),
                    f"{prefix}.comparison.key_fields entries need a name")
            require(isinstance(key.get("starmem"), str) and isinstance(key.get("volatility3"), str),
                    f"{prefix}.comparison key paths are required")
        if case["mode"] in {"exact", "subset", "expected_difference"}:
            require(bool(keys), f"{prefix} comparison mode requires key_fields")
        if case["mode"] == "subset":
            require(comparison.get("subset_side", "starmem") in {"starmem", "volatility3"},
                    f"{prefix}.comparison.subset_side is invalid")
        if case["mode"] in {"expected_difference", "expected_failure"}:
            expected = case.get("expected")
            require(isinstance(expected, dict) and isinstance(expected.get("reason"), str) and expected["reason"],
                    f"{prefix}.expected.reason documents the intentional difference/failure")
        tags = set(case.get("tags", []))
        gates = case.get("gates", {})
        require(isinstance(gates, dict), f"{prefix}.gates must be an object")
        for group, rules in gates.items():
            require(isinstance(rules, list), f"{prefix}.gates.{group} must be an array")
            for gate_index, rule in enumerate(rules):
                gate_prefix = f"{prefix}.gates.{group}[{gate_index}]"
                require(isinstance(rule, dict) and isinstance(rule.get("path"), str),
                        f"{gate_prefix} needs a path")
                predicates = {"equals", "min_count", "max_count", "contains", "contains_warning_code"}
                require(bool(predicates.intersection(rule)), f"{gate_prefix} needs a predicate")
        envelope = case.get("envelope", {})
        star_rules = envelope.get("starmem", {}) if isinstance(envelope, dict) else {}
        star_equals = star_rules.get("equals", {}) if isinstance(star_rules, dict) else {}
        if case["mode"] != "expected_failure":
            require(isinstance(star_equals.get("available"), bool),
                    f"{prefix}.envelope.starmem.equals.available must be explicit")
            require(isinstance(star_equals.get("complete"), bool),
                    f"{prefix}.envelope.starmem.equals.complete must be explicit")
            require(isinstance(star_rules.get("warning_codes"), list),
                    f"{prefix}.envelope.starmem.warning_codes must be explicit")
            require(all(isinstance(code, str) and code for code in star_rules["warning_codes"]),
                    f"{prefix}.envelope.starmem.warning_codes must contain non-empty strings")
        resources = case.get("resources", {})
        require(isinstance(resources, dict), f"{prefix}.resources must be an object")
        for tool, limits in resources.items():
            require(tool in {"starmem", "volatility3"} and isinstance(limits, dict),
                    f"{prefix}.resources.{tool} is invalid")
            maximum_rss = limits.get("max_peak_rss_bytes")
            require(maximum_rss is None or isinstance(maximum_rss, int) and maximum_rss > 0,
                    f"{prefix}.resources.{tool}.max_peak_rss_bytes must be positive")
        if "memdump2_regression" in tags:
            require(isinstance(gates.get("positive"), list) and gates["positive"],
                    f"{prefix} needs a non-empty positive gate")
            require(isinstance(gates.get("completeness"), list) and gates["completeness"],
                    f"{prefix} needs a separate completeness gate")
            require(any("min_count" in rule and rule["min_count"] > 0 for rule in gates["positive"]),
                    f"{prefix} positive gate must require at least one recovered record")
            require(any(rule.get("path", "").endswith("complete") or "contains_warning_code" in rule
                        for rule in gates["completeness"]),
                    f"{prefix} completeness gate must inspect complete or a warning code")


def resolve_image(image: dict[str, Any], corpus_root: pathlib.Path) -> pathlib.Path:
    candidate = pathlib.Path(image["path"])
    return candidate if candidate.is_absolute() else corpus_root / candidate


def check_images(document: dict[str, Any], corpus_root: pathlib.Path) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for image in document["images"]:
        path = resolve_image(image, corpus_root)
        require(path.is_file(), f"image does not exist: {path}")
        size = path.stat().st_size
        if "size_bytes" in image:
            require(size == image["size_bytes"], f"size mismatch for {image['id']}: {size}")
        digest = sha256_file(path)
        require(digest.lower() == image["sha256"].lower(), f"SHA-256 mismatch for {image['id']}: {digest}")
        checked_materials = []
        symbol_roots = {
            "shared": os.environ.get("STARMEM_SYMBOL_ROOT", ""),
            "windows": os.environ.get("STARMEM_WINDOWS_SYMBOL_ROOT", os.environ.get("STARMEM_SYMBOL_ROOT", "")),
            "linux": os.environ.get("STARMEM_LINUX_SYMBOL_ROOT", os.environ.get("STARMEM_SYMBOL_ROOT", "")),
        }
        for material in image.get("symbol_identity", {}).get("materials", []):
            root_value = symbol_roots[material["root"]]
            require(bool(root_value), f"symbol root {material['root']} is required for {image['id']}")
            material_path = pathlib.Path(root_value) / material["path"]
            require(material_path.is_file(), f"symbol material does not exist: {material_path}")
            material_size = material_path.stat().st_size
            require(material_size == material["size_bytes"],
                    f"symbol size mismatch for {image['id']}:{material['path']}")
            material_digest = sha256_file(material_path)
            require(material_digest.lower() == material["sha256"].lower(),
                    f"symbol SHA-256 mismatch for {image['id']}:{material['path']}")
            checked_materials.append({
                "root": material["root"], "path": material["path"],
                "size_bytes": material_size, "sha256": material_digest,
            })
        results.append({
            "id": image["id"],
            "path": str(path),
            "size_bytes": size,
            "sha256": digest,
            "symbol_identity": image.get("symbol_identity"),
            "checked_symbol_materials": checked_materials,
        })
    return results


def substitute(values: Iterable[str], variables: dict[str, str]) -> list[str]:
    rendered: list[str] = []
    for value in values:
        for name, replacement in variables.items():
            value = value.replace("${" + name + "}", replacement)
        unresolved = value.find("${")
        require(unresolved < 0, f"unresolved variable in argument: {value}")
        rendered.append(value)
    return rendered


def command_from_env(name: str, fallback: list[str] | None = None) -> list[str]:
    raw = os.environ.get(name)
    if raw:
        return shlex.split(raw, posix=os.name != "nt")
    return list(fallback or [])


def tool_identity(command: list[str], cwd: pathlib.Path) -> dict[str, Any]:
    executable = pathlib.Path(command[0])
    if not executable.is_absolute():
        located = shutil.which(command[0])
        executable = pathlib.Path(located) if located else cwd / executable
    files = []
    for token in [str(executable), *command[1:]]:
        candidate = pathlib.Path(token)
        if not candidate.is_absolute():
            candidate = cwd / candidate
        if candidate.is_file():
            files.append({
                "path": str(candidate.resolve()),
                "size_bytes": candidate.stat().st_size,
                "sha256": sha256_file(candidate),
            })
    version = None
    try:
        completed = subprocess.run(
            [*command, "--version"], cwd=cwd, capture_output=True, text=True, timeout=15
        )
        candidate_version = (completed.stdout or completed.stderr).strip()
        if candidate_version:
            version = candidate_version.splitlines()[0]
    except (OSError, subprocess.SubprocessError):
        pass
    return {"launcher": command, "version": version, "files": files}


def _windows_rss(pid: int) -> int | None:
    if os.name != "nt":
        return None
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    PROCESS_VM_READ = 0x0010

    class Counters(ctypes.Structure):
        _fields_ = [
            ("cb", ctypes.c_ulong), ("PageFaultCount", ctypes.c_ulong),
            ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
            ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t),
        ]

    kernel32 = ctypes.windll.kernel32
    psapi = ctypes.windll.psapi
    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, False, pid)
    if not handle:
        return None
    try:
        counters = Counters()
        counters.cb = ctypes.sizeof(counters)
        if not psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
            return None
        return int(counters.WorkingSetSize)
    finally:
        kernel32.CloseHandle(handle)


def _posix_tree_rss(root_pid: int) -> int | None:
    try:
        output = subprocess.check_output(
            ["ps", "-axo", "pid=,ppid=,rss="], stderr=subprocess.DEVNULL, text=True
        )
    except (OSError, subprocess.SubprocessError):
        return None
    rows: dict[int, tuple[int, int]] = {}
    for line in output.splitlines():
        parts = line.split()
        if len(parts) == 3:
            try:
                rows[int(parts[0])] = (int(parts[1]), int(parts[2]) * 1024)
            except ValueError:
                continue
    wanted = {root_pid}
    changed = True
    while changed:
        changed = False
        for pid, (parent, _rss) in rows.items():
            if parent in wanted and pid not in wanted:
                wanted.add(pid)
                changed = True
    values = [rows[pid][1] for pid in wanted if pid in rows]
    return sum(values) if values else None


def terminate_process(process: subprocess.Popen[Any]) -> None:
    if process.poll() is not None:
        return
    if os.name == "nt":
        process.terminate()
    else:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        if os.name == "nt":
            process.kill()
        else:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


def run_command(command: list[str], stdout_path: pathlib.Path, stderr_path: pathlib.Path,
                timeout_seconds: float, cwd: pathlib.Path) -> dict[str, Any]:
    started = time.perf_counter()
    peak_rss = 0
    timed_out = False
    creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) if os.name == "nt" else 0
    with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
        try:
            process = subprocess.Popen(
                command, cwd=cwd, stdout=stdout, stderr=stderr,
                start_new_session=os.name != "nt", creationflags=creationflags,
            )
        except OSError as exc:
            return {
                "command": command, "exit_code": None, "timed_out": False,
                "wall_seconds": time.perf_counter() - started, "peak_rss_bytes": None,
                "rss_scope": "unavailable", "spawn_error": str(exc),
            }
        while process.poll() is None:
            elapsed = time.perf_counter() - started
            if elapsed >= timeout_seconds:
                timed_out = True
                terminate_process(process)
                break
            rss = _windows_rss(process.pid) if os.name == "nt" else _posix_tree_rss(process.pid)
            if rss is not None:
                peak_rss = max(peak_rss, rss)
            time.sleep(min(0.20, max(0.01, timeout_seconds - elapsed)))
        exit_code = process.poll()
    return {
        "command": command,
        "exit_code": exit_code,
        "timed_out": timed_out,
        "wall_seconds": round(time.perf_counter() - started, 6),
        "peak_rss_bytes": peak_rss or None,
        "rss_scope": "root_process" if os.name == "nt" else "process_tree_snapshot",
    }


def parse_json_output(path: pathlib.Path) -> tuple[Any | None, str | None]:
    try:
        text = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError) as exc:
        return None, str(exc)
    stripped = text.lstrip()
    if not stripped:
        return None, "stdout is empty"
    decoder = json.JSONDecoder()
    starts = [position for position in (stripped.find("{"), stripped.find("[")) if position >= 0]
    if not starts:
        return None, "stdout contains no JSON object or array"
    try:
        value, _end = decoder.raw_decode(stripped[min(starts):])
        return value, None
    except json.JSONDecodeError as exc:
        return None, str(exc)


def get_path(value: Any, path: str, default: Any = None) -> Any:
    if path in {"", "$"}:
        return value
    current = value
    for token in path.removeprefix("$.").split("."):
        if isinstance(current, dict) and token in current:
            current = current[token]
        elif isinstance(current, list) and token.isdigit() and int(token) < len(current):
            current = current[int(token)]
        else:
            return default
    return current


def transform(value: Any, operation: str | None) -> Any:
    if operation in {None, "identity"}:
        return value
    if operation == "int":
        if value is None:
            return None
        return int(value, 0) if isinstance(value, str) else int(value)
    if operation == "lower":
        return None if value is None else str(value).casefold()
    if operation == "basename_lower":
        if value is None:
            return None
        return str(value).replace("\\", "/").rsplit("/", 1)[-1].casefold()
    if operation == "windows_path":
        return None if value is None else str(value).replace("/", "\\").casefold()
    if operation == "timestamp_seconds":
        if value is None:
            return None
        if isinstance(value, (int, float)):
            return int(value)
        parsed = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return int(parsed.timestamp())
    if operation == "bool":
        return bool(value)
    raise ValidationError(f"unknown transform: {operation}")


def records_at(document: Any, config: dict[str, Any]) -> list[Any]:
    records = get_path(document, config.get("records_path", "$"), default=[])
    if isinstance(records, list):
        return records
    if isinstance(records, dict):
        return [records]
    return []


def normalized_multiset(document: Any, tool: str, tool_config: dict[str, Any],
                        comparison: dict[str, Any]) -> collections.Counter[tuple[Any, ...]]:
    result: collections.Counter[tuple[Any, ...]] = collections.Counter()
    for record in records_at(document, tool_config):
        row = []
        for field in comparison.get("key_fields", []):
            value = get_path(record, field[tool], default=None)
            row.append(transform(value, field.get("transform")))
        result[tuple(row)] += 1
    return result


def jsonable_tuple(value: tuple[Any, ...]) -> list[Any]:
    return list(value)


def summarize_counter(counter: collections.Counter[tuple[Any, ...]], limit: int = 100) -> dict[str, Any]:
    ordered = sorted(counter.items(), key=lambda item: repr(item[0]))
    return {
        "unique_count": len(counter),
        "record_count": sum(counter.values()),
        "items": [{"key": jsonable_tuple(key), "count": count} for key, count in ordered[:limit]],
        "items_truncated": len(ordered) > limit,
    }


def warning_summary(document: Any) -> list[dict[str, Any]]:
    warnings = get_path(document, "warnings", default=[])
    if not isinstance(warnings, list):
        return []
    result = []
    for warning in warnings:
        if isinstance(warning, dict):
            # Evidence Envelope v1 uses a stable `code`.  Accept legacy plugin `kind` only for
            # adapters that have not yet been wrapped in an envelope.
            result.append({
                "code": warning.get("code", warning.get("kind")),
                "message": warning.get("message"),
            })
        else:
            result.append({"code": None, "message": str(warning)})
    return result


def envelope_summary(document: Any) -> dict[str, Any]:
    if not isinstance(document, dict):
        return {"present_fields": [], "values": {}}
    present = [field for field in ENVELOPE_FIELDS if field in document]
    return {"present_fields": present, "values": {field: document[field] for field in present if field != "warnings"}}


def evaluate_envelope(case: dict[str, Any], documents: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    envelope = case.get("envelope", {})
    star_document = documents.get("starmem")
    if case.get("mode") != "expected_failure":
        if not isinstance(star_document, dict):
            errors.append("starmem output is not an Evidence Envelope object")
        else:
            for field in ENVELOPE_FIELDS:
                if field not in star_document:
                    errors.append(f"starmem envelope missing mandatory field {field}")
            for field in ("available", "complete"):
                if not isinstance(star_document.get(field), bool):
                    errors.append(f"starmem envelope {field} is not boolean")
            for warning in star_document.get("warnings", []):
                if not isinstance(warning, dict) or not isinstance(warning.get("code"), str):
                    errors.append("starmem envelope contains a warning without a stable code")
    for tool in ("starmem", "volatility3"):
        rules = envelope.get(tool, {}) if isinstance(envelope, dict) else {}
        document = documents.get(tool)
        for field in rules.get("required_fields", []):
            if not isinstance(document, dict) or field not in document:
                errors.append(f"{tool} envelope missing field {field}")
        for path, expected in rules.get("equals", {}).items():
            actual = get_path(document, path, default=object())
            if actual != expected:
                errors.append(f"{tool} envelope {path} is {actual!r}, expected {expected!r}")
        if "warning_codes" in rules:
            actual_codes = sorted(
                warning["code"] for warning in warning_summary(document)
                if warning["code"] is not None
            )
            expected_codes = sorted(rules["warning_codes"])
            if actual_codes != expected_codes:
                errors.append(
                    f"{tool} warning codes are {actual_codes!r}, expected {expected_codes!r}"
                )
    return errors


def evaluate_gate(rule: dict[str, Any], documents: dict[str, Any]) -> str | None:
    tool = rule.get("tool", "starmem")
    document = documents.get(tool)
    value = get_path(document, rule.get("path", "$"), default=None)
    if "equals" in rule and value != rule["equals"]:
        return f"{tool}:{rule.get('path', '$')} is {value!r}, expected {rule['equals']!r}"
    if "min_count" in rule:
        count = len(value) if isinstance(value, (list, dict, str)) else 0
        if count < rule["min_count"]:
            return f"{tool}:{rule.get('path', '$')} count {count} is below {rule['min_count']}"
    if "max_count" in rule:
        count = len(value) if isinstance(value, (list, dict, str)) else 0
        if count > rule["max_count"]:
            return f"{tool}:{rule.get('path', '$')} count {count} exceeds {rule['max_count']}"
    if "contains" in rule:
        if not isinstance(value, (list, str)) or rule["contains"] not in value:
            return f"{tool}:{rule.get('path', '$')} does not contain {rule['contains']!r}"
    if "contains_warning_code" in rule:
        codes = {item.get("code") for item in warning_summary(document)}
        if rule["contains_warning_code"] not in codes:
            return f"{tool} warnings do not contain code {rule['contains_warning_code']!r}"
    return None


def compare_case(case: dict[str, Any], executions: dict[str, dict[str, Any]],
                 documents: dict[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    for tool in ("starmem", "volatility3"):
        allowed = case.get("exit", {}).get(tool, [0])
        execution = executions[tool]
        if execution.get("spawn_error"):
            errors.append(f"{tool} spawn failed: {execution['spawn_error']}")
        elif execution["timed_out"]:
            errors.append(f"{tool} timed out")
        elif execution["exit_code"] not in allowed:
            errors.append(f"{tool} exit {execution['exit_code']} not in {allowed}")
        maximum_rss = case.get("resources", {}).get(tool, {}).get("max_peak_rss_bytes")
        observed_rss = execution.get("peak_rss_bytes")
        if maximum_rss is not None and observed_rss is not None and observed_rss > maximum_rss:
            errors.append(f"{tool} peak RSS {observed_rss} exceeds {maximum_rss}")

    errors.extend(evaluate_envelope(case, documents))
    gate_results: dict[str, list[dict[str, Any]]] = {}
    for group, rules in case.get("gates", {}).items():
        gate_results[group] = []
        for rule in rules:
            error = evaluate_gate(rule, documents)
            gate_results[group].append({"rule": rule, "passed": error is None, "error": error})
            if error:
                errors.append(f"{group} gate: {error}")

    comparison = case.get("comparison", {})
    left = normalized_multiset(documents.get("starmem"), "starmem", case["starmem"], comparison)
    right = normalized_multiset(documents.get("volatility3"), "volatility3", case["volatility3"], comparison)
    left_only = left - right
    right_only = right - left
    mode = case["mode"]
    expected_failure_observed = False
    if mode == "expected_failure":
        expected_tool = case.get("expected", {}).get("tool", "either")
        candidates = ("starmem", "volatility3") if expected_tool == "either" else (expected_tool,)
        expected_failure_observed = any(
            executions[tool].get("timed_out")
            or executions[tool].get("spawn_error")
            or executions[tool].get("exit_code") not in case.get("exit", {}).get(tool, [0])
            or documents.get(tool) is None
            or (isinstance(documents.get(tool), dict) and documents[tool].get("available") is False)
            for tool in candidates
        )
        errors = [error for error in errors if not any(error.startswith(tool + " ") for tool in candidates)]
        if not expected_failure_observed:
            errors.append("documented expected failure was not observed")
    elif mode == "exact" and (left_only or right_only):
        errors.append("normalized multisets are not equal")
    elif mode == "subset":
        side = comparison.get("subset_side", "starmem")
        violation = left_only if side == "starmem" else right_only
        if violation:
            errors.append(f"{side} normalized multiset is not a subset")
    elif mode == "expected_difference" and not (left_only or right_only):
        if not case.get("expected", {}).get("allow_equal", False):
            errors.append("expected normalized difference was not observed")

    envelopes = {tool: envelope_summary(documents.get(tool)) for tool in documents}
    warnings_by_tool = {tool: warning_summary(documents.get(tool)) for tool in documents}
    star_envelope_fields = set(envelopes["starmem"]["present_fields"])
    vol_envelope_fields = set(envelopes["volatility3"]["present_fields"])
    star_warning_codes = {item.get("code") for item in warnings_by_tool["starmem"]}
    vol_warning_codes = {item.get("code") for item in warnings_by_tool["volatility3"]}
    positive_results = gate_results.get("positive", [])
    completeness_results = gate_results.get("completeness", [])
    return {
        "passed": not errors,
        "errors": errors,
        "mode": mode,
        "expected_failure_observed": expected_failure_observed,
        "positive_evidence_pass": bool(positive_results)
        and all(item["passed"] for item in positive_results),
        "universe_completeness_pass": bool(completeness_results)
        and all(item["passed"] for item in completeness_results),
        "gates": gate_results,
        "starmem_set": summarize_counter(left),
        "volatility3_set": summarize_counter(right),
        "starmem_only": summarize_counter(left_only),
        "volatility3_only": summarize_counter(right_only),
        "exit_comparison": {
            "starmem": executions["starmem"].get("exit_code"),
            "volatility3": executions["volatility3"].get("exit_code"),
            "equal": executions["starmem"].get("exit_code") == executions["volatility3"].get("exit_code"),
        },
        "envelopes": envelopes,
        "envelope_field_difference": {
            "starmem_only": sorted(star_envelope_fields - vol_envelope_fields),
            "volatility3_only": sorted(vol_envelope_fields - star_envelope_fields),
            "shared": sorted(star_envelope_fields & vol_envelope_fields),
        },
        "warnings": warnings_by_tool,
        "warning_code_difference": {
            "starmem_only": sorted(value for value in star_warning_codes - vol_warning_codes if value is not None),
            "volatility3_only": sorted(value for value in vol_warning_codes - star_warning_codes if value is not None),
            "shared": sorted(value for value in star_warning_codes & vol_warning_codes if value is not None),
        },
    }


def run_suite(args: argparse.Namespace) -> int:
    manifest_path = pathlib.Path(args.manifest).resolve()
    manifest = load_json(manifest_path)
    validate_manifest(manifest)
    corpus_root = pathlib.Path(args.corpus_root or os.environ.get("STARMEM_CORPUS_ROOT", ".")).resolve()
    checked_images = check_images(manifest, corpus_root)
    image_map = {image["id"]: image for image in manifest["images"]}
    default_binary = [str(pathlib.Path("target/release/starmem" + (".exe" if os.name == "nt" else "")))]
    star_command = command_from_env("STARMEM_BIN", default_binary)
    if args.starmem:
        star_command = [args.starmem]
    vol_command = command_from_env("STARMEM_VOL3")
    require(star_command, "StarMem command is empty")
    require(vol_command, "STARMEM_VOL3 must name the Volatility 3 launcher")

    run_id = args.run_id or dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:8]
    output_root = pathlib.Path(args.output_root).resolve() / run_id
    output_root.mkdir(parents=True, exist_ok=False)
    variables_base = {
        "CORPUS_ROOT": str(corpus_root),
        "OUTPUT_DIR": str(output_root),
        "SYMBOL_ROOT": os.environ.get("STARMEM_SYMBOL_ROOT", ""),
        "WINDOWS_SYMBOL_ROOT": os.environ.get("STARMEM_WINDOWS_SYMBOL_ROOT", os.environ.get("STARMEM_SYMBOL_ROOT", "")),
        "LINUX_SYMBOL_ROOT": os.environ.get("STARMEM_LINUX_SYMBOL_ROOT", os.environ.get("STARMEM_SYMBOL_ROOT", "")),
    }
    selected = set(args.case or [])
    case_results: list[dict[str, Any]] = []
    for case in manifest["cases"]:
        if selected and case["id"] not in selected:
            continue
        case_dir = output_root / case["id"]
        case_dir.mkdir()
        image = image_map[case["image"]]
        image_path = resolve_image(image, corpus_root).resolve()
        variables = dict(variables_base, IMAGE=str(image_path), CASE_OUTPUT_DIR=str(case_dir))
        commands = {
            "starmem": star_command + substitute(case["starmem"]["argv"], variables),
            "volatility3": vol_command + substitute(case["volatility3"]["argv"], variables),
        }
        executions: dict[str, dict[str, Any]] = {}
        documents: dict[str, Any] = {}
        parse_errors: dict[str, str | None] = {}
        for tool in ("starmem", "volatility3"):
            executions[tool] = run_command(
                commands[tool], case_dir / f"{tool}.stdout.json", case_dir / f"{tool}.stderr.txt",
                float(case.get("timeout_seconds", 300)), manifest_path.parent.parent,
            )
            documents[tool], parse_errors[tool] = parse_json_output(case_dir / f"{tool}.stdout.json")
        comparison = compare_case(case, executions, documents)
        for tool, error in parse_errors.items():
            if error and case["mode"] != "expected_failure":
                comparison["errors"].append(f"{tool} JSON: {error}")
                comparison["passed"] = False
        result = {
            "id": case["id"], "image": case["image"], "mode": case["mode"],
            "executions": executions, "parse_errors": parse_errors, "comparison": comparison,
        }
        (case_dir / "result.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        case_results.append(result)
        print(f"[{'PASS' if comparison['passed'] else 'FAIL'}] {case['id']}")

    require(case_results, "no cases selected")
    summary = {
        "schema_version": SCHEMA_VERSION,
        "suite": manifest["suite"],
        "run_id": run_id,
        "created_utc": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "host": {"platform": platform.platform(), "python": platform.python_version()},
        "inputs": {
            "manifest": str(manifest_path),
            "manifest_sha256": sha256_file(manifest_path),
            "corpus_root": str(corpus_root),
            "symbol_roots": {
                "shared": variables_base["SYMBOL_ROOT"],
                "windows": variables_base["WINDOWS_SYMBOL_ROOT"],
                "linux": variables_base["LINUX_SYMBOL_ROOT"],
            },
            "images": checked_images,
        },
        "tools": {
            "starmem": tool_identity(star_command, manifest_path.parent.parent),
            "volatility3": tool_identity(vol_command, manifest_path.parent.parent),
        },
        "cases": case_results,
        "passed": all(result["comparison"]["passed"] for result in case_results),
    }
    (output_root / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"result: {output_root / 'summary.json'}")
    return 0 if summary["passed"] else 1


def extract_leaf_commands(binary: pathlib.Path) -> set[str]:
    def commands_for(prefix: list[str]) -> set[str]:
        completed = subprocess.run([str(binary), *prefix, "--help"], capture_output=True, text=True, check=True)
        lines = completed.stdout.splitlines()
        try:
            start = next(index for index, line in enumerate(lines) if line.strip() in {"Commands:", "命令:"}) + 1
        except StopIteration as exc:
            raise ValidationError(f"cannot locate command list in {' '.join(prefix) or 'root'} help") from exc
        result: set[str] = set()
        for line in lines[start:]:
            if not line.strip():
                break
            name = line.strip().split()[0]
            if name != "help":
                result.add(name)
        return result

    top = commands_for([])
    leaves = set(top)
    if "symbols" in top:
        leaves.remove("symbols")
        leaves.update("symbols." + item for item in commands_for(["symbols"]))
    return leaves


def validate_equivalence(path: pathlib.Path, binary: pathlib.Path | None) -> dict[str, Any]:
    table = load_json(path)
    require(isinstance(table, dict) and table.get("schema_version") == SCHEMA_VERSION,
            "equivalence table schema_version is unsupported")
    commands = table.get("commands")
    require(isinstance(commands, dict) and commands, "equivalence commands must be a non-empty object")
    allowed = {"exact", "partial", "composite", "no_equivalent"}
    required_entry_fields = {
        "status", "platform", "volatility3_plugins", "adapter", "external_tool",
        "comparable_fields", "set_key", "normalizer", "non_equivalent_fields",
        "prerequisites",
    }
    for name, entry in commands.items():
        require(isinstance(entry, dict), f"equivalence entry {name} must be an object")
        missing_fields = required_entry_fields - set(entry)
        require(not missing_fields, f"equivalence entry {name} lacks {sorted(missing_fields)}")
        require(entry.get("status") in allowed, f"equivalence entry {name} has invalid status")
        plugins = entry.get("volatility3_plugins")
        require(isinstance(plugins, list) and all(isinstance(item, str) for item in plugins),
                f"equivalence entry {name} has invalid volatility3_plugins")
        if entry["status"] == "no_equivalent":
            require(not plugins, f"no_equivalent entry {name} must have no plugins")
            require(entry["adapter"] is None and entry["external_tool"] is None,
                    f"no_equivalent entry {name} must explicitly use null adapter/external_tool")
        else:
            require(bool(plugins), f"mapped entry {name} must name at least one plugin")
            require(isinstance(entry["adapter"], str) and entry["adapter"],
                    f"mapped entry {name} needs an adapter")
            require(isinstance(entry["external_tool"], str) and entry["external_tool"],
                    f"mapped entry {name} needs an external_tool")
            require(bool(entry["set_key"]), f"mapped entry {name} needs a set_key")
            require(bool(entry["comparable_fields"]), f"mapped entry {name} needs comparable_fields")
        for field in ("set_key", "comparable_fields"):
            require(isinstance(entry[field], list) and all(isinstance(value, str) and value for value in entry[field]),
                    f"equivalence entry {name}.{field} must be a string array")
        require(isinstance(entry["normalizer"], str) and entry["normalizer"],
                f"equivalence entry {name} needs an explicit normalizer")
        differences = entry["non_equivalent_fields"]
        require(isinstance(differences, list), f"equivalence entry {name}.non_equivalent_fields must be an array")
        for difference in differences:
            require(isinstance(difference, dict)
                    and isinstance(difference.get("field"), str) and difference["field"]
                    and isinstance(difference.get("reason"), str) and difference["reason"],
                    f"equivalence entry {name} has an undocumented non-equivalent field")
        prerequisites = entry["prerequisites"]
        require(isinstance(prerequisites, dict)
                and set(prerequisites) == {"platform", "symbols", "acquisition_format"},
                f"equivalence entry {name} has incomplete prerequisites")
        require(isinstance(prerequisites["platform"], list) and prerequisites["platform"],
                f"equivalence entry {name} needs prerequisite platforms")
        require(isinstance(prerequisites["symbols"], str) and prerequisites["symbols"],
                f"equivalence entry {name} needs a symbol prerequisite")
        require(isinstance(prerequisites["acquisition_format"], list),
                f"equivalence entry {name} acquisition_format must be an explicit array")
    coverage = {"table_count": len(commands), "cli_checked": binary is not None}
    if binary is not None:
        leaves = extract_leaf_commands(binary)
        table_names = set(commands)
        coverage.update({
            "cli_count": len(leaves),
            "missing": sorted(leaves - table_names),
            "stale": sorted(table_names - leaves),
        })
        require(not coverage["missing"] and not coverage["stale"],
                f"equivalence coverage mismatch: missing={coverage['missing']} stale={coverage['stale']}")
    return coverage


def command_validate(args: argparse.Namespace) -> int:
    document = load_json(pathlib.Path(args.manifest))
    validate_manifest(document)
    if args.check_files:
        root = pathlib.Path(args.corpus_root or os.environ.get("STARMEM_CORPUS_ROOT", ".")).resolve()
        check_images(document, root)
    binary = pathlib.Path(args.starmem).resolve() if args.starmem else None
    coverage = validate_equivalence(pathlib.Path(args.equivalence), binary)
    print(json.dumps({"manifest": "valid", "equivalence": coverage}, ensure_ascii=False, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate = subparsers.add_parser("validate", help="validate manifest and command-equivalence coverage")
    validate.add_argument("manifest")
    validate.add_argument("--equivalence", default="benchmarks/command-equivalence.json")
    validate.add_argument("--starmem", help="also compare the table with live CLI leaf commands")
    validate.add_argument("--check-files", action="store_true", help="hash every corpus image")
    validate.add_argument("--corpus-root")
    validate.set_defaults(handler=command_validate)

    run = subparsers.add_parser("run", help="run and compare selected corpus cases")
    run.add_argument("manifest")
    run.add_argument("--case", action="append", help="case id; repeat to select more than one")
    run.add_argument("--starmem")
    run.add_argument("--corpus-root")
    run.add_argument("--output-root", default=".local-validation")
    run.add_argument("--run-id")
    run.set_defaults(handler=run_suite)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return int(args.handler(args))
    except ValidationError as exc:
        parser.error(str(exc))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
