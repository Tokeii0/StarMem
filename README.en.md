<p align="center">
  <img src="docs/assets/starmem-mascot.png" width="208" alt="StarMem mascot">
</p>

<h1 align="center">StarMem</h1>

<p align="center"><strong>A Rust memory forensics engine for Windows and Linux images</strong></p>

<p align="center"><a href="README.md">简体中文</a> · English</p>

<p align="center">CLI · Rust crate · LGPL-3.0-only</p>

<p align="center">
  <a href="#installation">Install</a> ·
  <a href="#quick-start">Quick start</a> ·
  <a href="#supported-analysis">Supported analysis</a> ·
  <a href="#documentation">Docs</a> ·
  <a href="#development-and-contributing">Contribute</a>
</p>

StarMem extracts processes, network connections, resident files, and system activity from physical memory images. Use it to establish an incident-response baseline, recover bytes still present in memory, and pass evidence to scripts or other forensic tools for review. Structured reports record the evidence source, scan scope, missing pages, and limits.

## Installation

You need **Rust 1.89+** and a C/C++ toolchain for your target. The Windows MSVC target requires Visual Studio C++ Build Tools. Install from source.

```sh
git clone https://github.com/Tokeii0/StarMem.git
cd StarMem
cargo install --path . --locked
starmem --version
```

From an existing checkout, run the install command at the repository root. Make sure Cargo's `bin` directory is on your `PATH`. CI builds host binaries for Windows x64, Linux x64, and macOS arm64. Each successful run provides the binary, Cargo package, and verification manifest for download. [Build runs](https://github.com/Tokeii0/StarMem/actions/workflows/ci.yml)

## Quick start

Run `starmem info <image>` to identify the container and inspect its physical memory ranges. Choose commands based on **the system in the captured image**. Substitute your image and symbol paths in the examples.

### Windows image

```powershell
$starmem = "starmem"
$windowsImage = "E:\evidence\windows.raw"
$windowsSymbols = "D:\symbols\windows"

& $starmem info $windowsImage
& $starmem pslist $windowsImage --symbol-path $windowsSymbols
& $starmem netscan $windowsImage --symbol-path $windowsSymbols --csv .\connections.csv
```

This lists active processes and writes the recovered TCP and UDP endpoints to `connections.csv`.

### Linux image

```sh
starmem info ./linux.lime
starmem linux.info ./linux.lime
starmem linux.psaux ./linux.lime --symbol-path /path/to/linux-isf/symbols
starmem linux.sockstat ./linux.lime --symbol-path /path/to/linux-isf/symbols
```

`linux.info` identifies the kernel and host clues. The next two commands examine process command lines and active sockets.

Use `starmem --help-en` for the English command list and `starmem <command> --help-en` for command options. Nested commands also support it, for example `starmem symbols linux --help-en`. The default `--help` remains in Chinese. `--help-en` changes only the help text.

## Supported analysis

| Task | Windows | Linux |
| --- | --- | --- |
| System and processes | `system-info`, `pslist`, `psxview` | `linux.info`, `linux.psaux`, `linux.pstree` |
| Network and communications | `netscan`, `packetscan`, `pipescan` | `linux.sockstat`, `linux.ir-kernel --module routes` |
| Resident files | `filescan`, `dumpfile`, `mftdump`, `sqlite-recover` | `filescan`, `dumpfile`, `linux.lsof` |
| Execution, logs, and timelines | `windows.execution`, `windows.timeline`, `dump-logs` | `linux.bash`, `linux.kmsg`, `linux.ir --module journald` |
| Anomaly triage | `check-pslist`, `injected-regions`, `cobaltstrikescan` | `linux.modxview`, `linux.check-syscall`, `linux.ir --module triage` |

### Image formats

StarMem primarily analyzes **x86-64** guest systems. Some Windows commands support x86 PAE, depending on the plugin.

| Validation status | Format |
| --- | --- |
| Validated on captured images | RAW / `.mem`, flat VMware `.vmem`, Windows x64 crash dumps, and LiME |
| Physical memory supported | EWF / E01. StarMem identifies disk and volume images and rejects them for memory analysis. |
| Covered by synthetic tests | VMware VMEM + VMSS/VMSN, ELF physical cores including QEMU, Xen ELF64, AVML v2, and QEVM v3 |

Run `starmem info --help-en` for advanced container options. Analysis and recovery depend on the page tables, symbols, and pages present in the capture. See the [validation records](docs/VALIDATION.md).

### Symbols

- **Windows** accepts a PDB root via `--symbol-path`, or a file via `--pdb` or `--profile`. Automatic resolution prefers a PDB that matches the target kernel's CodeView GUID and age. The report flags fallback to a compatible layout.
- **Linux** accepts a compatible `symbols` or `symbols/linux` directory from another memory forensics tool, or a single `.json` or `.json.xz` ISF via `--symbol-path`. StarMem matches the full `linux_banner` and checks the required layout against the image. Use `starmem symbols linux <image> --offline --symbol-path <directory>` to diagnose local symbols.

Set `STARMEM_SYMBOL_PATH` for shared read-only symbol roots. Use `--cache` or `STARMEM_SYMBOL_CACHE` for a writable cache. Windows can fetch matching PDBs from Microsoft's symbol server. Linux can query a remote ISF index by full banner. Use `STARMEM_LINUX_ISF_URL` to select a compatible index and `STARMEM_LINUX_ISF_OFFLINE=1` to disable Linux symbol networking.

## Evidence and exports

| Output | Option |
| --- | --- |
| JSON report | `--json`. Plugin results appear in `data` inside the [Evidence Envelope v1](schemas/evidence-envelope-v1.schema.json). |
| CSV report | `--csv <file>`. Writes UTF-8 CSV by report section. Use `--csv -` for stdout. |
| Raw evidence objects | `--json --raw-objects <file.jsonl>`. Sorts supported objects by `evidence_id`. See [Raw Object v1](schemas/raw-object-v1.schema.json). |
| SQLite collection | `collect --db <file>`. Reuses the image context to run applicable read-only plugins. |

> [!IMPORTANT]
> Interpret empty results alongside `available`, `complete`, `scope`, `warnings`, `limits`, and `missing_ranges`. Completeness applies to the declared scope. For archival, compute the image's full SHA-256 separately and save the output of `starmem --json build-info` along with the command used.

```powershell
& $starmem --json --raw-objects .\pslist.objects.jsonl pslist $windowsImage --symbol-path $windowsSymbols
& $starmem collect $windowsImage --symbol-path $windowsSymbols --db .\evidence.sqlite
```

SQLite appends each analysis as a separate run. Filter plugin tables by `analysis_id` and check the run status in `plugin_runs`.

Exports protect inputs and existing outputs by default. `--force` allows replacement of declared regular outputs. A `.partial` artifact has unrecovered ranges. Review its missing ranges and recovered byte count together. See [interpreting evidence](starmem-memory-forensics/references/evidence-interpretation.md).

## Rust API

Rust and Tauri hosts can query `capabilities()` and `command_catalog()` through `starmem::api`, open a reusable image session with `Session::open`, and get structured results with `Session::run`. Long-running tasks can use `spawn_blocking` with request-scoped progress and cancellation.

Host API v1 exposes read-only Windows sessions. Linux is available through the CLI and lower-level Rust modules. See the [crate integration guide](docs/CRATE_INTEGRATION.md) for the version handshake, dependency pinning, and LovelyMem examples.

## Documentation

| Task | Guide |
| --- | --- |
| Windows investigation and recovery | [Windows forensics](docs/WINDOWS_FORENSICS.md) |
| Linux processes, files, and incident response | [Linux process and file forensics](LINUX_PROCESS_COMMANDS.md) · [Linux incident response](docs/LINUX_IR.md) |
| Engine internals and host integration | [Architecture](docs/ARCHITECTURE.md) · [Crate integration](docs/CRATE_INTEGRATION.md) |
| Validation and reproducibility | [Validation and test coverage](docs/VALIDATION.md) · [Benchmark reproduction](benchmarks/README.md) |

## Development and contributing

Contributions to docs, translations, tests, and forensic analysis are welcome. Start with the English quick start for contributors, then use the guide for a code map, checks, and a PR example. [Contributing to StarMem](CONTRIBUTING.md#english-quick-start)

## License

StarMem's original material is licensed under the GNU Lesser General Public License 3.0, identified by SPDX as `LGPL-3.0-only`. Include both license texts when distributing StarMem and follow the applicable source availability terms. [LGPL 3.0](LICENSE) · [GPL 3.0](licenses/LICENSE-GPL)

For distribution of a combined work linked with StarMem, see LGPL section 4. Third-party materials retain their own licenses, and previously granted rights remain in effect. [Crate integration guide](docs/CRATE_INTEGRATION.md) · [Third-party notices and prior licenses](THIRD_PARTY_NOTICES.md)
