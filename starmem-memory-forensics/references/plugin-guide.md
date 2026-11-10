# StarMem plugin routing guide

Use `starmem --help` as the authoritative catalog and `<plugin> --help` before parameterized commands. This guide selects representative plugins; it is not a frozen exhaustive list.

## Fast baseline

| Goal | Plugins | Notes |
|---|---|---|
| Image format and physical layout | `info` | Does not establish the full Windows context by itself. |
| Kernel, DTB, build, symbol identity | `windows-info` | Run early; precise symbols improve downstream parsing. |
| Host identity and time baseline | `system-info` | Includes OS/build, host/domain, timezone, boot and shutdown evidence. |
| Screen geometry | `screen-resolution` | Uses symbol-verified display evidence. |
| Active processes | `pslist` | Fast baseline; broken links may make the result incomplete. |
| Active network endpoints | `netstat`, `netscan` | `netstat` uses active structures; `netscan` searches pool remnants. |

## Processes, threads, and execution

- Parent/child story: `pstree`, `check-pslist`, `cmdline`, `envars`, `sessions`, `joblinks`.
- Hidden or exited processes: `psscan`, `psxview`.
- Threads: `threads`, `thrdscan`, `suspended-threads`, `suspicious-threads`, `orphan-kernel-threads`.
- Tokens and identity: `privileges`, `getsids`, `getservicesids`.
- Console and commands: `terminal-history`, `cmdscan`, `consoles`.
- Modules and memory: `dlllist`, `ldrmodules`, `iat`, `vad`, `memmap`, `pe-symbols`, `pedump`.
- Objects: `handles`, `mutantscan`, `symlinkscan`, `timers`.

Use PID, EPROCESS, create time, path, and command line together. A PID alone is not a stable cross-source identity because PIDs can be reused.

`pstree` preserves `_EPROCESS.InheritedFromUniqueProcessId` as the recorded PPID. Use
`check-pslist` when PPID spoofing is possible: it reports an alternative creator only when the
same active process retains handles to the child process and its earliest active thread. A high
confidence finding additionally requires a handle to the recorded parent with
`PROCESS_CREATE_PROCESS` access. Treat absent findings as inconclusive when handles were closed,
threads exited, or the report is incomplete.

## Network and application evidence

- Connections and listeners: `netscan`, `netstat`.
- Recovered packet bytes: `packetscan` and optional PCAPNG export.
- DNS/domain evidence: `dnsscan`.
- Download commands and URLs: `downloadscan`.
- Browser state: `browser-session`, `cookiescan`.
- WeChat key candidates: `wechatscan`.

Normalize protocol aliases such as TCP4/TCPv4 and TCP6/TCPv6 during correlation. Preserve the original protocol label in raw evidence.

## Files, NTFS, and exports

- FILE_OBJECT discovery: `filescan`.
- FILE_OBJECT recovery: `dumpfile` with `--source auto`, `cache`, `data`, or `image`.
- MFT records: `mftscan`, `mft-ads`, `mft-resident-data`.
- Resident stream recovery: `mftdump` with physical record address and optional stream/attribute selection.
- Disk remnants: `mbrscan`.

Prefer FILE_OBJECT recovery for nonresident files. MFT metadata proves allocation metadata, not the presence of disk clusters in RAM.

## Registry, accounts, and credentials

- Hive inventory and remnants: `hivelist`, `hivescan`.
- Targeted key inspection: `registry-printkey`.
- Hive export: `dump-registry`.
- Execution/persistence records: `userassist`, `amcache`, `shimcachemem`, `scheduled-tasks`.
- Accounts and operations: `accountscan`.
- Credential materials: `hashdump`, `cachedump`, `lsadump`.

Credential outputs are sensitive evidence. Do not expose them beyond the user's requested scope; retain source Hive and completeness warnings.

## Injected process memory

- Executable private memory: `malfind`, `cobaltstrikescan`.
- Data-only injection: `injected-regions`. It compares the protection recorded in the VAD with
  the effective protection carried by the PTEs, so it finds ranges that were allocated writable,
  written to, and then downgraded with `VirtualProtectEx`. `malfind` cannot see those - they are
  never executable. Findings require the whole range to be resident, because "every page is
  read-only" is only observable when every page was observed; `--include-partial` relaxes that
  and the records keep `pages_missing` so the weaker candidates stay identifiable.
- Getting the bytes out: `vaddump --pid <PID> -o <DIR>` writes one file per VAD, named by the
  process virtual address. Fully resident ranges are published as `.dmp`; ranges with holes are
  zero-filled to keep the layout but published as `.dmp.partial`, and zero fill is never counted
  in `recovered_bytes`. Prefer this over carving by physical offset: the offset is only valid for
  one acquisition, the virtual address is reproducible by any tool that walks the same page table.

## Kernel, drivers, services, and persistence

- Loaded/unlinked modules: `drivers`, `modscan`, `unloadedmodules`.
- Driver objects and integrity: `driver-inspect` (integrated tree, IRP and Fast I/O), `driverscan`, `drivermodule`, `driverirp`, `devicetree`.
- Kernel hooks: `callbacks`, `ssdt`, `getcellroutine`.
- Services: `svcscan`, `svclist`, `svcdiff`.
- Pool context: `bigpools`, `poolscanner`.

## User interaction, GUI, and desktop

- Clipboard: `clipboardscan`.
- Text remnants: `residualscan` with focused text when possible.
- Window object hierarchy: `windowstations`, `desktops`, `deskscan`, `gui-windows`, `windowtitles`.
- Bitmap candidates: `gdi-bitmap`.
- Display frame reconstruction: `desktop-reconstruct`.

Window titles and bitmap fragments do not alone prove what was visible on a monitor. Prefer verified DWM/composition evidence from `desktop-reconstruct` and disclose missing regions.

## Malware and integrity

- Executable private/writeable VADs: `malfind`.
- Image replacement: `hollowprocesses`, `processghosting`, `pebmasquerade`.
- System-call anomalies: `direct-system-calls`, `indirect-system-calls`, `unhooked-system-calls`.
- Telemetry/authentication tampering: `etwpatch`, `skeleton-key-check`.

Treat detections as triage findings. Corroborate with process identity, VAD bytes, modules, handles, network, and exported PE hashes.

## Logs and timeline

- Recover event logs and ETL: `dump-logs`.
- Parse exported events: `event-timeline`.

Record whether a log is complete or page-damaged. A missing event in an incomplete log is not proof the event never occurred.

## Broad SQLite collection

Use `collect IMAGE --db CASE.sqlite` to run all safe no-input read-only plugins in one reused session. The fixed metadata tables are `analyses` and `plugin_runs`; plugin data tables use names such as `pslist__processes` and `netscan__records`.

Inspect failures and incomplete runs first:

```sql
SELECT plugin, status, rows_written, duration_seconds, error
FROM plugin_runs
WHERE analysis_id = (SELECT id FROM latest_analysis)
ORDER BY status, plugin;
```
