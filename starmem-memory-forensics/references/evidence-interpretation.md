# Interpreting StarMem evidence

## Completeness

- `complete=true`: the plugin completed its intended traversal under the reported source assumptions. It does not certify that the acquisition itself contained every original page.
- `complete=false`: retain parsed records, state the limitation, and do not use nonappearance as proof of absence.
- Missing pages/bytes: describe the exact gap when available. Do not silently zero-fill evidentiary content.
- Warnings: separate structural corruption, unavailable swap/pagefile, missing symbols, unsupported format, and scan-limit truncation.

## Evidence anchors

Prefer records that expose reproducible anchors:

- physical address or file offset;
- kernel/user virtual address and owning DTB/process;
- EPROCESS, ETHREAD, FILE_OBJECT, Hive, VAD, or MFT record address;
- source layer or recovery source;
- hash and recovered byte count for exports.

Convert addresses only for comparison; retain the original representation. On x64 Windows, a 48-bit kernel pointer and its `ffff` sign-extended form may be the same canonical address.

## Structured outputs

- JSON preserves report sections and nested evidence most faithfully.
- CSV starts with a data-section column. Do not treat `warnings`, `summary`, or metadata sections as evidence rows.
- Arrays embedded in CSV cells remain JSON. Parse them instead of splitting on commas.
- SQLite collection preserves numeric and boolean types. Always scope queries by `analysis_id`.

## Cross-source correlation

Correlate by strong identity before merging:

1. canonical object address;
2. PID plus nonempty matching create time and compatible name/path;
3. stable artifact identity such as normalized file path plus MFT/FILE_OBJECT evidence;
4. endpoint tuple plus owner and state for network records.

Normalize case, slash escaping, protocol aliases, and canonical x64 pointers for comparison while retaining original source values. Do not merge merely because display text looks similar.

## Recovery claims

- Report logical size, recovered bytes, missing bytes, source, hash, and completeness.
- An empty output is not success unless the source was proven empty.
- `dumpfile --source auto` may fall back from cache to data/image sections; report the selected source.
- A nonresident MFT `$DATA` attribute describes disk clusters that a memory-only image may not contain. Refusal to export is correct.
- A resident MFT stream may be exported if its record and attribute are structurally verified.
- PCAPNG output contains recovered packet bytes; absent trustworthy timestamps must remain absent/zero rather than invented.
- Desktop reconstruction may be partial. Distinguish verified display surfaces from inferred window layout.

## Negative findings

State “not observed in the completed scope” only when:

- the relevant plugin completed;
- limits did not truncate the search;
- required symbols/layers were valid;
- acquisition gaps do not cover the searched evidence class.

Otherwise state “not recovered” and list the limiting conditions.

## Minimum provenance record

Record:

- StarMem executable version/hash;
- exact command line;
- image canonical path, size, SHA-256, and acquisition format;
- symbol PDB identity and search/cache roots;
- start/end time and thread count;
- output file hashes;
- report completeness, warnings, and errors.
