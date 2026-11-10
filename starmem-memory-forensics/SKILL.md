---
name: starmem-memory-forensics
description: Use StarMem to perform verifiable Windows memory forensics on RAW, VMEM, crash-dump, EWF, and related memory images. Trigger for system triage, process and thread analysis, network evidence, filescan/MFT recovery, registry and credential artifacts, browser/clipboard/terminal evidence, GUI or desktop reconstruction, malware detection, SQLite collection, CTF questions, incident response, and validation of StarMem results. Also use when choosing StarMem plugins, interpreting incomplete evidence, or exporting recovered artifacts.
---

# StarMem memory forensics

Use the local StarMem CLI to extract structured, reproducible evidence. Preserve uncertainty: an incomplete result is evidence with limitations, not proof of absence.

## Locate the engine

Prefer `scripts/invoke-starmem.ps1`. It resolves the executable in this order: explicit `-Binary`, `STARMEM_BIN`, `starmem` on `PATH`, the current repository's release/debug targets, then `E:\mem` release/debug targets.

If the binary is missing and the StarMem source tree is available, build it only after telling the user:

```powershell
cargo build --release
```

Do not modify StarMem or LovelyMem merely to answer an evidence question.

## Core workflow

1. Resolve the exact image path and create a case-specific output directory outside the source tree.
2. Record image size and SHA-256 before analysis. Never modify the image.
3. Run a low-cost baseline before expensive scans: `info`, `windows-info`, `system-info`, `pslist`, and `netscan` or `netstat`.
4. Use the question or observed anomalies to select focused plugins. Read [references/plugin-guide.md](references/plugin-guide.md) for routing.
5. Request JSON or CSV for analysis. Use the human table only for a quick visual check.
6. Inspect `complete`, warnings, missing pages/bytes, evidence addresses, and source semantics before drawing conclusions. Read [references/evidence-interpretation.md](references/evidence-interpretation.md).
7. Hash every exported artifact and retain the exact command, StarMem version, image hash, symbol roots, thread count, and warnings in the final handoff.

## Resource discipline

- Default to 2 threads. For images above 15 GiB or memory-constrained hosts, use 1–2 threads.
- Do not run multiple full-image StarMem scans concurrently. Each CLI process may map the image and build independent scan state.
- Prefer focused plugins for large images. Use `collect` only when the user requests broad acquisition or the host has sufficient time, RAM, and disk.
- Use `--limit`, `--file-scan-limit`, `--process-space-limit`, and `--max-data-mib` with `collect` when scope must be bounded.
- Reuse a precise local PDB or shared symbol root with `--pdb` or repeatable `--symbol-path`. Use `--cache` for a writable symbol cache.
- If a command fails because requirements, symbols, or layers are unavailable, stop retrying the identical command. Diagnose the prerequisite or choose a plugin with independent evidence.

## Command patterns

Run a structured report through the wrapper:

```powershell
& "$skillDir\scripts\invoke-starmem.ps1" `
  -Image "E:\evidence\memory.raw" `
  -Plugin system-info `
  -Format Json `
  -ReportPath "E:\cases\case-01\system-info.json" `
  -Threads 2 `
  -SymbolPath "D:\Tools\MemProcFS\Symbols"
```

Run a parameterized plugin:

```powershell
& "$skillDir\scripts\invoke-starmem.ps1" `
  -Image "E:\evidence\memory.raw" `
  -Plugin handles `
  -Format Csv `
  -ReportPath "E:\cases\case-01\handles-828.csv" `
  -PluginArgs @('--pid', '828')
```

Before using a parameterized or exporting plugin, query its live help:

```powershell
& $starmem dumpfile --help
```

Never infer flags from another memory forensics tool; StarMem command contracts are authoritative.

## Recovery rules

- Find a file with `filescan`, then use `dumpfile --source auto` with the verified FILE_OBJECT address.
- If FILE_OBJECT recovery fails, inspect `mftscan`. Use `mftdump` only for a resident `$DATA` stream; do not claim a nonresident disk stream can be reconstructed from RAM.
- Use `pedump` only after identifying the correct process/kernel virtual address.
- Use `dump-registry` and `dump-logs` for external artifacts; keep them in a dedicated export directory.
- Use `packetscan -o` for PCAPNG only when packet bytes were recovered; timestamps may be unavailable.
- Treat a zero-byte file or a report with zero recovered bytes as failure unless the source artifact is proven empty.

## Reporting

Lead with the answer, then provide:

- image identity and SHA-256;
- commands and plugin versions;
- decisive rows with PID/address/path/time/source;
- completeness and warnings;
- hashes and paths of recovered artifacts;
- alternative interpretations or unavailable evidence.

For CTF questions, return the requested value concisely but retain the evidence chain needed to reproduce it.
