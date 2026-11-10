use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use rusqlite::{Connection, OpenFlags};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::output_policy::{OutputPolicy, OutputTarget};
use crate::session::AnalysisSession;
use crate::windows::files::{DumpSource, RecoveredExtent, recover_file_bytes};

#[derive(Debug, Clone)]
pub struct SqliteRecoverOptions {
    pub file_object: Option<u64>,
    pub path_contains: Option<String>,
    pub output_dir: PathBuf,
    pub source: DumpSource,
    pub include_sidecars: bool,
    pub tables: Vec<String>,
    pub file_scan_limit: usize,
    pub max_size: u64,
    pub force: bool,
}

#[derive(Debug, Serialize)]
pub struct SqliteRecoverReport {
    pub image: String,
    pub main: RecoveredSqliteArtifact,
    pub sidecars: Vec<RecoveredSqliteSidecar>,
    pub database: SqliteDatabaseManifest,
    pub complete: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct RecoveredSqliteArtifact {
    pub file_object: u64,
    pub original_name: Option<String>,
    pub output_path: String,
    pub source: DumpSource,
    pub logical_size: u64,
    pub output_size: u64,
    pub recovered_bytes: u64,
    pub missing_bytes: u64,
    pub sha256: String,
    pub complete: bool,
    pub extents: Vec<RecoveredExtent>,
}

#[derive(Debug, Serialize)]
pub struct RecoveredSqliteSidecar {
    pub kind: String,
    pub file_object: u64,
    pub original_name: Option<String>,
    pub output_path: String,
    pub source: DumpSource,
    pub logical_size: u64,
    pub recovered_bytes: u64,
    pub missing_bytes: u64,
    pub sha256: String,
    pub complete: bool,
    pub details: SidecarDetails,
    pub warnings: Vec<String>,
}

#[derive(Debug, Default, Serialize)]
pub struct SidecarDetails {
    pub header_valid: bool,
    pub page_size: Option<u32>,
    pub frame_count: Option<u64>,
    pub committed_frame_count: Option<u64>,
    pub initial_database_pages: Option<u32>,
    pub salt_1: Option<u32>,
    pub salt_2: Option<u32>,
    pub note: String,
}

#[derive(Debug, Serialize)]
pub struct SqliteDatabaseManifest {
    /// The SQLite connection used for schema/row inspection was opened on an
    /// isolated copy of the recovered main database. Recovered WAL/journal
    /// evidence is deliberately not applied implicitly.
    pub view_semantic: String,
    pub header_valid: bool,
    pub page_size: Option<u32>,
    pub declared_page_count: Option<u32>,
    pub logical_page_count: Option<u64>,
    pub fully_recovered_pages: Option<u64>,
    pub missing_page_count: Option<u64>,
    pub missing_page_ranges: Vec<PageRange>,
    pub tables: Vec<SqliteTableManifest>,
    pub query_complete: bool,
    pub query_error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PageRange {
    pub first_page: u64,
    pub last_page: u64,
}

#[derive(Debug, Serialize)]
pub struct SqliteTableManifest {
    pub name: String,
    pub root_page: i64,
    pub schema_sql: Option<String>,
    pub recovered_row_count: Option<u64>,
    pub row_count_attempted: bool,
    pub query_complete: bool,
    pub error: Option<String>,
}

struct PendingSqliteSidecar {
    report: RecoveredSqliteSidecar,
    bytes: Vec<u8>,
    output_path: PathBuf,
}

type SidecarCandidateScore = (bool, bool, u64, std::cmp::Reverse<u64>);

struct RecoveredSidecarCandidate {
    score: SidecarCandidateScore,
    dump: crate::windows::files::DumpFileReport,
    bytes: Vec<u8>,
    details: SidecarDetails,
    warnings: Vec<String>,
}

pub fn recover_sqlite(
    session: &AnalysisSession,
    options: &SqliteRecoverOptions,
) -> Result<SqliteRecoverReport> {
    ensure!(
        options.file_object.is_some() || options.path_contains.is_some(),
        "必须提供 --file-object 或 --path-contains"
    );
    ensure!(
        options.file_object.is_none() || options.path_contains.is_none(),
        "--file-object 与 --path-contains 互斥"
    );
    ensure!(options.file_scan_limit > 0, "文件扫描上限必须大于零");
    ensure!(options.max_size > 0, "最大恢复大小必须大于零");

    let mut directory_policy = OutputPolicy::new(options.force);
    for source in session.image().sources() {
        directory_policy.protect_file("memory_image_or_sidecar", &source.path);
    }
    directory_policy.output(OutputTarget::directory(
        "sqlite_recovery_directory",
        &options.output_dir,
    ));
    directory_policy.prepare_directories().with_context(|| {
        format!(
            "无法安全准备 SQLite 恢复目录 {}",
            options.output_dir.display()
        )
    })?;
    let output_dir = fs::canonicalize(&options.output_dir).with_context(|| {
        format!(
            "无法规范化 SQLite 恢复目录 {}",
            options.output_dir.display()
        )
    })?;

    let needs_filescan = options.file_object.is_none() || options.include_sidecars;
    let (file_records, files_complete, mut warnings) = if needs_filescan {
        let files = session.files(options.file_scan_limit)?;
        (files.records, files.complete, files.warnings)
    } else {
        (Vec::new(), true, Vec::new())
    };
    if !files_complete {
        warnings.push("filescan 未完整；主库路径选择或同目录 sidecar 发现也不完整".to_owned());
    }
    let main_file_object = if let Some(file_object) = options.file_object {
        file_object
    } else {
        select_file_object(
            &file_records,
            options.path_contains.as_deref().unwrap_or_default(),
            &mut warnings,
        )?
    };

    let (main_dump, main_bytes, source_warnings) = recover_best_file_bytes(
        session,
        main_file_object,
        options.source,
        options.max_size,
        true,
    )?;
    warnings.extend(source_warnings);
    ensure!(
        main_bytes.starts_with(b"SQLite format 3\0"),
        "FILE_OBJECT {main_file_object:#x} 的恢复内容不是 SQLite 3 数据库"
    );
    let base_name = main_dump
        .name
        .as_deref()
        .map(windows_basename)
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| format!("sqlite-{main_file_object:016x}"));
    let output_name = if main_dump.complete {
        sqlite_output_name(&base_name, false)
    } else {
        sqlite_output_name(&base_name, true)
    };
    let main_output = output_dir.join(output_name);
    let main_sha256 = sha256_hex(&main_bytes);
    let main_extents = main_dump.extents;
    let main = RecoveredSqliteArtifact {
        file_object: main_dump.file_object,
        original_name: main_dump.name.clone(),
        output_path: main_output.display().to_string(),
        source: main_dump.source,
        logical_size: main_dump.logical_size,
        output_size: main_dump.output_size,
        recovered_bytes: main_dump.recovered_bytes,
        missing_bytes: main_dump.missing_bytes,
        sha256: main_sha256,
        complete: main_dump.complete,
        extents: main_extents,
    };
    warnings.extend(main_dump.warnings);

    let mut pending_sidecars = Vec::new();
    let mut sidecar_recovery_complete = true;
    if options.include_sidecars
        && let Some(main_name) = main.original_name.as_deref()
    {
        for (kind, suffix) in [("wal", "-wal"), ("shm", "-shm"), ("journal", "-journal")] {
            let expected = format!("{main_name}{suffix}");
            let mut candidates = file_records
                .iter()
                .filter(|record| {
                    record
                        .name
                        .as_deref()
                        .is_some_and(|name| name.eq_ignore_ascii_case(&expected))
                })
                .map(|record| record.file_object)
                .collect::<Vec<_>>();
            candidates.sort_unstable();
            candidates.dedup();
            if candidates.is_empty() {
                continue;
            }
            match recover_sidecar(session, options, &candidates, kind, &main_output) {
                Ok(sidecar) => pending_sidecars.push(sidecar),
                Err(error) => {
                    sidecar_recovery_complete = false;
                    warnings.push(format!(
                        "SQLite {kind} sidecar 候选 {} 恢复失败：{error:#}",
                        candidates
                            .iter()
                            .map(|object| format!("{object:#x}"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                }
            }
        }
    }

    // Resolve every candidate and preflight every destination before publishing
    // any evidence file.  This prevents a late sidecar conflict from leaving a
    // main database that cannot be reproduced without --force.
    let mut output_policy = OutputPolicy::new(options.force);
    for source in session.image().sources() {
        output_policy.protect_file("memory_image_or_sidecar", &source.path);
    }
    let mut directory_target = OutputTarget::directory("sqlite_recovery", &output_dir)
        .with_owned_file(owned_output_relative(&output_dir, &main_output)?);
    ensure_no_automatic_sidecar_neighbors(&main_output)?;
    for sidecar in &pending_sidecars {
        directory_target = directory_target
            .with_owned_file(owned_output_relative(&output_dir, &sidecar.output_path)?);
    }
    output_policy.output(directory_target);
    output_policy.preflight()?;
    // Inspect an isolated, uniquely named copy before sidecars are published.
    // Opening the final path after writing `History-wal`/`History-journal`
    // would allow SQLite itself to consume those files and silently change the
    // meaning of row counts. Sidecars remain separately hashed evidence only.
    let protected_sources = session
        .image()
        .sources()
        .map(|source| source.path.as_path())
        .collect::<Vec<_>>();
    let (inspection_path, inspection_dir) =
        write_isolated_inspection_file(&output_dir, &main_bytes, &protected_sources)?;
    let mut database = inspect_database(
        &inspection_path,
        &main_bytes,
        main.logical_size,
        &main.extents,
        &options.tables,
    );
    let inspection_cleanup_complete =
        match cleanup_isolated_inspection(&inspection_path, &inspection_dir) {
            Ok(()) => true,
            Err(error) => {
                warnings.push(format!(
                    "无法完全删除 SQLite 隔离检查临时目录 {}：{error}",
                    inspection_dir.display()
                ));
                false
            }
        };
    if !main.complete {
        for table in &mut database.tables {
            if table.query_complete {
                table.query_complete = false;
                table.error = Some("主数据库存在缺页；行数仅是已恢复页面上的可查询结果".to_owned());
            }
        }
        database.query_complete = false;
        let missing_reason = "数据库存在未恢复字节；成功查询仅覆盖已恢复页面，不能视为整库完整";
        database.query_error = Some(match database.query_error.take() {
            Some(error) => format!("{error}；{missing_reason}"),
            None => missing_reason.to_owned(),
        });
    }
    write_evidence_file(&output_policy, &main_output, &main_bytes)?;
    let mut sidecars = Vec::with_capacity(pending_sidecars.len());
    for sidecar in pending_sidecars {
        write_evidence_file(&output_policy, &sidecar.output_path, &sidecar.bytes)?;
        sidecars.push(sidecar.report);
    }
    let complete = files_complete
        && sidecar_recovery_complete
        && inspection_cleanup_complete
        && main.complete
        && database.query_complete
        && sidecars.iter().all(|sidecar| sidecar.complete);
    if !main.complete {
        warnings.push(format!(
            "主数据库仅恢复 {}/{} 字节，已使用 .partial.sqlite 文件名并生成缺页清单",
            main.recovered_bytes, main.logical_size
        ));
    }

    Ok(SqliteRecoverReport {
        image: session.image().path().display().to_string(),
        main,
        sidecars,
        database,
        complete,
        warnings,
    })
}

fn select_file_object(
    records: &[crate::windows::files::FileScanRecord],
    needle: &str,
    warnings: &mut Vec<String>,
) -> Result<u64> {
    let needle = normalize_windows_path(needle);
    ensure!(!needle.is_empty(), "--path-contains 不能为空");
    let mut matches = records
        .iter()
        .filter(|record| {
            record
                .name
                .as_deref()
                .map(normalize_windows_path)
                .is_some_and(|path| path.contains(&needle))
        })
        .collect::<Vec<_>>();
    if matches.is_empty() {
        bail!("filescan 未找到路径包含 {needle:?} 的 FILE_OBJECT");
    }
    matches.sort_unstable_by_key(|record| {
        (
            std::cmp::Reverse(
                record
                    .name
                    .as_deref()
                    .is_some_and(|name| !is_sqlite_sidecar_path(name)),
            ),
            std::cmp::Reverse(record.shared_cache_map != 0),
            std::cmp::Reverse(record.data_section_object != 0),
            record.file_object,
        )
    });
    if matches.len() > 1 {
        warnings.push(format!(
            "路径筛选匹配 {} 个 FILE_OBJECT，优先排除 sidecar 并选择具有 SharedCacheMap/DataSectionObject 的 {:#x}",
            matches.len(),
            matches[0].file_object
        ));
    }
    Ok(matches[0].file_object)
}

fn recover_sidecar(
    session: &AnalysisSession,
    options: &SqliteRecoverOptions,
    file_objects: &[u64],
    kind: &str,
    main_output: &Path,
) -> Result<PendingSqliteSidecar> {
    let mut best: Option<RecoveredSidecarCandidate> = None;
    let mut candidate_warnings = Vec::new();
    for &file_object in file_objects {
        match recover_best_file_bytes(
            session,
            file_object,
            options.source,
            options.max_size,
            false,
        ) {
            Ok((dump, bytes, mut selection_warnings)) => {
                let details = inspect_sidecar(kind, &bytes);
                let score = (
                    details.header_valid,
                    dump.complete,
                    dump.recovered_bytes,
                    std::cmp::Reverse(dump.missing_bytes),
                );
                selection_warnings.extend(dump.warnings.iter().cloned());
                let replace = best
                    .as_ref()
                    .is_none_or(|candidate| score > candidate.score);
                if replace {
                    if let Some(previous) = best.take() {
                        candidate_warnings.push(format!(
                            "sidecar FILE_OBJECT {:#x} 未选中：已找到评分更高的同名候选",
                            previous.dump.file_object
                        ));
                    }
                    best = Some(RecoveredSidecarCandidate {
                        score,
                        dump,
                        bytes,
                        details,
                        warnings: selection_warnings,
                    });
                } else {
                    candidate_warnings.push(format!(
                        "sidecar FILE_OBJECT {file_object:#x} 未选中：文件头有效={} 恢复={}/{}",
                        details.header_valid, dump.recovered_bytes, dump.logical_size
                    ));
                }
            }
            Err(error) => candidate_warnings.push(format!(
                "sidecar FILE_OBJECT {file_object:#x} 无法恢复：{error:#}"
            )),
        }
    }
    let Some(RecoveredSidecarCandidate {
        dump,
        bytes,
        details,
        warnings: mut selection_warnings,
        ..
    }) = best
    else {
        bail!("所有同名 sidecar FILE_OBJECT 候选均无法恢复");
    };
    if file_objects.len() > 1 {
        selection_warnings.push(format!(
            "同名 sidecar 有 {} 个 FILE_OBJECT，比较文件头、完整性与恢复字节后选择 {:#x}",
            file_objects.len(),
            dump.file_object
        ));
    }
    selection_warnings.extend(candidate_warnings);
    // Never publish a recovered sidecar under SQLite's automatically consumed
    // `<database>-wal`/`-journal` name. A later analyst opening the extracted
    // main file must not accidentally replay volatile evidence into it.
    let output = append_path_suffix(main_output, &format!(".sidecar-{kind}"));
    let report = RecoveredSqliteSidecar {
        kind: kind.to_owned(),
        file_object: dump.file_object,
        original_name: dump.name,
        output_path: output.display().to_string(),
        source: dump.source,
        logical_size: dump.logical_size,
        recovered_bytes: dump.recovered_bytes,
        missing_bytes: dump.missing_bytes,
        sha256: sha256_hex(&bytes),
        complete: dump.complete && details.header_valid,
        details,
        warnings: selection_warnings,
    };
    Ok(PendingSqliteSidecar {
        report,
        bytes,
        output_path: output,
    })
}

fn inspect_sidecar(kind: &str, bytes: &[u8]) -> SidecarDetails {
    match kind {
        "wal" => inspect_wal(bytes),
        "journal" => inspect_journal(bytes),
        "shm" => SidecarDetails {
            header_valid: bytes.len() >= 48,
            note: "WAL-index shared memory 已原样恢复；该文件是易失协调状态，不直接合并到主库"
                .to_owned(),
            ..SidecarDetails::default()
        },
        _ => SidecarDetails::default(),
    }
}

fn recover_best_file_bytes(
    session: &AnalysisSession,
    file_object: u64,
    requested_source: DumpSource,
    max_size: u64,
    require_sqlite_header: bool,
) -> Result<(crate::windows::files::DumpFileReport, Vec<u8>, Vec<String>)> {
    if requested_source != DumpSource::Auto {
        let (report, bytes) = recover_file_bytes(
            session.image(),
            session.kernel(),
            session.profile(),
            file_object,
            requested_source,
            max_size,
        )?;
        return Ok((report, bytes, Vec::new()));
    }

    let mut best = None;
    let mut warnings = Vec::new();
    for source in [DumpSource::Cache, DumpSource::Data, DumpSource::Image] {
        match recover_file_bytes(
            session.image(),
            session.kernel(),
            session.profile(),
            file_object,
            source,
            max_size,
        ) {
            Ok((report, bytes)) if report.recovered_bytes > 0 => {
                let header_valid =
                    !require_sqlite_header || bytes.starts_with(b"SQLite format 3\0");
                let score = (
                    header_valid,
                    report.complete,
                    report.recovered_bytes,
                    std::cmp::Reverse(report.missing_bytes),
                );
                let replace = best
                    .as_ref()
                    .is_none_or(|(best_score, _, _)| score > *best_score);
                if replace {
                    best = Some((score, report, bytes));
                }
            }
            Ok((report, _)) => warnings.push(format!(
                "{source:?} 未恢复到 FILE_OBJECT {file_object:#x} 的有效字节：{}",
                report.warnings.join("；")
            )),
            Err(error) => warnings.push(format!(
                "{source:?} 恢复 FILE_OBJECT {file_object:#x} 失败：{error:#}"
            )),
        }
    }
    let Some((score, report, bytes)) = best else {
        bail!("FILE_OBJECT {file_object:#x} 没有可用的 SQLite/sidecar 恢复来源");
    };
    if require_sqlite_header && !score.0 {
        bail!("FILE_OBJECT {file_object:#x} 的所有恢复来源均没有 SQLite 3 文件头");
    }
    warnings.push(format!(
        "自动比较 Cache/Data/Image 后选择 {:?}：恢复 {}/{} 字节，完整={}",
        report.source, report.recovered_bytes, report.logical_size, report.complete
    ));
    Ok((report, bytes, warnings))
}

fn inspect_database(
    path: &Path,
    bytes: &[u8],
    logical_size: u64,
    extents: &[RecoveredExtent],
    requested_tables: &[String],
) -> SqliteDatabaseManifest {
    let header_valid = bytes.starts_with(b"SQLite format 3\0");
    let page_size = sqlite_page_size(bytes);
    let declared_page_count = read_be_u32(bytes, 28);
    let logical_page_count = page_size.map(|size| logical_size.div_ceil(u64::from(size)));
    let (fully_recovered_pages, missing_page_ranges) = page_size
        .zip(logical_page_count)
        .map(|(size, pages)| page_coverage(u64::from(size), pages, extents))
        .unwrap_or((0, Vec::new()));
    let missing_page_count = logical_page_count.map(|pages| pages - fully_recovered_pages);

    let (tables, query_complete, query_error) = match Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    ) {
        Ok(connection) => match inspect_tables(&connection, requested_tables) {
            Ok(result) => {
                let requested = requested_tables
                    .iter()
                    .map(|name| name.to_lowercase())
                    .collect::<BTreeSet<_>>();
                let found = result
                    .iter()
                    .map(|table| table.name.to_lowercase())
                    .collect::<BTreeSet<_>>();
                let missing = requested.difference(&found).cloned().collect::<Vec<_>>();
                let complete =
                    missing.is_empty() && result.iter().all(|table| table.query_complete);
                let error = (!missing.is_empty())
                    .then(|| format!("请求的 SQLite 表未找到：{}", missing.join(", ")));
                (result, complete, error)
            }
            Err(error) => (Vec::new(), false, Some(format!("{error:#}"))),
        },
        Err(error) => (
            Vec::new(),
            false,
            Some(format!("无法只读打开恢复数据库：{error}")),
        ),
    };

    SqliteDatabaseManifest {
        view_semantic: "recovered_main_database_only_sidecars_not_applied".to_owned(),
        header_valid,
        page_size,
        declared_page_count,
        logical_page_count,
        fully_recovered_pages: logical_page_count.map(|_| fully_recovered_pages),
        missing_page_count,
        missing_page_ranges,
        tables,
        query_complete,
        query_error,
    }
}

fn inspect_tables(
    connection: &Connection,
    requested_tables: &[String],
) -> Result<Vec<SqliteTableManifest>> {
    let wanted = requested_tables
        .iter()
        .map(|name| name.to_lowercase())
        .collect::<BTreeSet<_>>();
    let count_rows = !wanted.is_empty();
    let mut statement = connection.prepare(
        "SELECT name, rootpage, sql FROM sqlite_master WHERE type='table' ORDER BY name",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, Option<String>>(2)?,
        ))
    })?;
    let mut output = Vec::new();
    for row in rows {
        let (name, root_page, schema_sql) = row?;
        if !wanted.is_empty() && !wanted.contains(&name.to_lowercase()) {
            continue;
        }
        if !count_rows {
            output.push(SqliteTableManifest {
                name,
                root_page,
                schema_sql,
                recovered_row_count: None,
                row_count_attempted: false,
                query_complete: true,
                error: None,
            });
            continue;
        }
        let quoted = name.replace('"', "\"\"");
        let count =
            connection.query_row(&format!("SELECT COUNT(*) FROM \"{quoted}\""), [], |row| {
                row.get::<_, i64>(0)
            });
        match count {
            Ok(count) => output.push(SqliteTableManifest {
                name,
                root_page,
                schema_sql,
                recovered_row_count: u64::try_from(count).ok(),
                row_count_attempted: true,
                query_complete: true,
                error: None,
            }),
            Err(error) => output.push(SqliteTableManifest {
                name,
                root_page,
                schema_sql,
                recovered_row_count: None,
                row_count_attempted: true,
                query_complete: false,
                error: Some(error.to_string()),
            }),
        }
    }
    Ok(output)
}

fn page_coverage(
    page_size: u64,
    page_count: u64,
    extents: &[RecoveredExtent],
) -> (u64, Vec<PageRange>) {
    if page_size == 0 || page_count == 0 {
        return (0, Vec::new());
    }
    let logical_end = page_size.saturating_mul(page_count);
    let mut byte_ranges = extents
        .iter()
        .filter_map(|extent| {
            let extent_end = extent.file_offset.checked_add(extent.length)?;
            let start = extent.file_offset.min(logical_end);
            let end = extent_end.min(logical_end);
            (end > start).then_some((start, end))
        })
        .collect::<Vec<_>>();
    byte_ranges.sort_unstable();
    let mut merged_bytes = Vec::<(u64, u64)>::new();
    for (start, end) in byte_ranges {
        if let Some((_, previous_end)) = merged_bytes.last_mut()
            && start <= *previous_end
        {
            *previous_end = (*previous_end).max(end);
        } else {
            merged_bytes.push((start, end));
        }
    }

    let mut recovered_ranges = Vec::<PageRange>::new();
    for (start, end) in merged_bytes {
        // Page numbers are one-based. A page counts as recovered only when its
        // entire [start,end) byte interval is covered by merged extents.
        let first_zero_based = start.div_ceil(page_size);
        let last_one_based = (end / page_size).min(page_count);
        let first_one_based = first_zero_based.saturating_add(1);
        if first_one_based > last_one_based {
            continue;
        }
        if let Some(previous) = recovered_ranges.last_mut()
            && first_one_based <= previous.last_page.saturating_add(1)
        {
            previous.last_page = previous.last_page.max(last_one_based);
        } else {
            recovered_ranges.push(PageRange {
                first_page: first_one_based,
                last_page: last_one_based,
            });
        }
    }
    let fully_recovered = recovered_ranges
        .iter()
        .map(|range| range.last_page - range.first_page + 1)
        .sum();
    let mut missing = Vec::new();
    let mut cursor = 1u64;
    for recovered in recovered_ranges {
        if cursor < recovered.first_page {
            missing.push(PageRange {
                first_page: cursor,
                last_page: recovered.first_page - 1,
            });
        }
        cursor = recovered.last_page.saturating_add(1);
    }
    if cursor <= page_count {
        missing.push(PageRange {
            first_page: cursor,
            last_page: page_count,
        });
    }
    (fully_recovered, missing)
}

fn inspect_wal(bytes: &[u8]) -> SidecarDetails {
    let magic = read_be_u32(bytes, 0);
    let header_valid = matches!(magic, Some(0x377f_0682 | 0x377f_0683));
    let page_size = read_be_u32(bytes, 8).filter(|size| *size > 0);
    let frame_count = page_size.and_then(|size| {
        let frame_size = 24u64.checked_add(u64::from(size))?;
        Some((bytes.len() as u64).saturating_sub(32) / frame_size)
    });
    let committed_frame_count = page_size.map(|size| {
        let frame_size = 24usize + size as usize;
        bytes
            .get(32..)
            .into_iter()
            .flat_map(|frames| frames.chunks_exact(frame_size))
            .filter(|frame| read_be_u32(frame, 4).is_some_and(|pages| pages != 0))
            .count() as u64
    });
    SidecarDetails {
        header_valid,
        page_size,
        frame_count,
        committed_frame_count,
        initial_database_pages: None,
        salt_1: read_be_u32(bytes, 16),
        salt_2: read_be_u32(bytes, 20),
        note: if header_valid {
            "WAL 已独立恢复并校验文件头；未在证据文件上执行破坏性合并".to_owned()
        } else {
            "WAL 文件头缺失或无效，禁止自动合并".to_owned()
        },
    }
}

fn inspect_journal(bytes: &[u8]) -> SidecarDetails {
    const JOURNAL_MAGIC: [u8; 8] = [0xd9, 0xd5, 0x05, 0xf9, 0x20, 0xa1, 0x63, 0xd7];
    let header_valid = bytes.get(..8) == Some(JOURNAL_MAGIC.as_slice());
    SidecarDetails {
        header_valid,
        page_size: read_be_u32(bytes, 24).filter(|size| *size > 0),
        frame_count: read_be_u32(bytes, 8).map(u64::from),
        committed_frame_count: None,
        initial_database_pages: read_be_u32(bytes, 16),
        salt_1: None,
        salt_2: None,
        note: if header_valid {
            "rollback journal 已独立恢复；事务状态未知时不自动应用到主数据库".to_owned()
        } else {
            "rollback journal 文件头缺失或无效，禁止自动应用".to_owned()
        },
    }
}

fn sqlite_page_size(bytes: &[u8]) -> Option<u32> {
    if !bytes.starts_with(b"SQLite format 3\0") {
        return None;
    }
    match bytes.get(16..18)? {
        [0, 1] => Some(65_536),
        raw => {
            let value = u16::from_be_bytes([raw[0], raw[1]]) as u32;
            ((512..=32_768).contains(&value) && value.is_power_of_two()).then_some(value)
        }
    }
}

fn read_be_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let value = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_be_bytes(value.try_into().ok()?))
}

fn sqlite_output_name(base_name: &str, partial: bool) -> String {
    let safe = sanitize_filename(base_name);
    if partial {
        format!("{safe}.partial.sqlite")
    } else if safe.to_lowercase().ends_with(".sqlite") || safe.to_lowercase().ends_with(".db") {
        safe
    } else {
        format!("{safe}.sqlite")
    }
}

fn windows_basename(path: &str) -> String {
    path.trim_end_matches(['\\', '/'])
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(path)
        .to_owned()
}

fn normalize_windows_path(path: &str) -> String {
    path.trim().replace('/', "\\").to_lowercase()
}

fn is_sqlite_sidecar_path(path: &str) -> bool {
    let normalized = normalize_windows_path(path);
    ["-wal", "-shm", "-journal"]
        .iter()
        .any(|suffix| normalized.ends_with(suffix))
}

fn sanitize_filename(name: &str) -> String {
    let value = name
        .chars()
        .map(|character| match character {
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            character if character.is_control() => '_',
            character => character,
        })
        .collect::<String>();
    if value.trim_matches(['.', ' ']).is_empty() {
        "recovered".to_owned()
    } else {
        value
    }
}

fn write_isolated_inspection_file(
    output_dir: &Path,
    bytes: &[u8],
    protected_inputs: &[&Path],
) -> Result<(PathBuf, PathBuf)> {
    for attempt in 0..1024u32 {
        let directory =
            output_dir.join(format!(".starmem-inspect-{}-{attempt}", std::process::id()));
        match fs::create_dir(&directory) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("无法创建 SQLite 隔离检查目录 {}", directory.display())
                });
            }
        }
        let path = directory.join("main.sqlite");
        for protected_input in protected_inputs {
            ensure!(
                !paths_conflict(&path, protected_input),
                "SQLite 隔离检查临时文件不能覆盖输入镜像或 sidecar {}",
                protected_input.display()
            );
        }
        let mut file = match OpenOptions::new().create_new(true).write(true).open(&path) {
            Ok(file) => file,
            Err(error) => {
                let _ = fs::remove_dir(&directory);
                return Err(error)
                    .with_context(|| format!("无法创建 SQLite 隔离检查文件 {}", path.display()));
            }
        };
        if let Err(error) = file
            .write_all(bytes)
            .and_then(|()| file.flush())
            .and_then(|()| file.sync_all())
        {
            drop(file);
            let _ = fs::remove_file(&path);
            let _ = fs::remove_dir(&directory);
            return Err(error)
                .with_context(|| format!("无法写入 SQLite 隔离检查文件 {}", path.display()));
        }
        drop(file);
        return Ok((path, directory));
    }
    bail!("无法为 SQLite 隔离检查分配唯一临时文件")
}

fn owned_output_relative(root: &Path, path: &Path) -> Result<PathBuf> {
    path.strip_prefix(root)
        .map(Path::to_path_buf)
        .with_context(|| {
            format!(
                "SQLite 恢复输出 {} 不在本命令的目录 {} 内",
                path.display(),
                root.display()
            )
        })
}

fn cleanup_isolated_inspection(path: &Path, directory: &Path) -> std::io::Result<()> {
    // A main database whose header declares WAL mode can make SQLite create an
    // empty WAL/SHM pair even for a read-only query. These files live inside a
    // directory created exclusively by StarMem and are not recovered evidence.
    for candidate in [
        path.to_path_buf(),
        append_path_suffix(path, "-wal"),
        append_path_suffix(path, "-shm"),
        append_path_suffix(path, "-journal"),
    ] {
        match fs::remove_file(candidate) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    fs::remove_dir(directory)
}

fn write_evidence_file(policy: &OutputPolicy, path: &Path, bytes: &[u8]) -> Result<()> {
    policy
        .write_bytes_atomic(path, bytes)
        .with_context(|| format!("无法发布 SQLite 恢复文件 {}", path.display()))
}

fn ensure_no_automatic_sidecar_neighbors(main: &Path) -> Result<()> {
    for suffix in ["-wal", "-shm", "-journal"] {
        let candidate = append_path_suffix(main, suffix);
        ensure!(
            !candidate.exists(),
            "输出主库旁存在会被 SQLite 自动加载的文件 {}；请使用干净输出目录或先将该文件移出目录",
            candidate.display()
        );
    }
    Ok(())
}

fn append_path_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

fn paths_conflict(left: &Path, right: &Path) -> bool {
    if matches!(same_file::is_same_file(left, right), Ok(true)) {
        return true;
    }
    let left = comparable_path(left);
    let right = comparable_path(right);
    #[cfg(windows)]
    {
        left.to_string_lossy()
            .eq_ignore_ascii_case(&right.to_string_lossy())
    }
    #[cfg(not(windows))]
    {
        left == right
    }
}

fn comparable_path(path: &Path) -> PathBuf {
    if let Ok(canonical) = fs::canonicalize(path) {
        return canonical;
    }
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else if let Ok(current) = std::env::current_dir() {
        current.join(path)
    } else {
        path.to_path_buf()
    };
    let Some(file_name) = absolute.file_name() else {
        return absolute;
    };
    absolute
        .parent()
        .and_then(|parent| fs::canonicalize(parent).ok())
        .map(|parent| parent.join(file_name))
        .unwrap_or(absolute)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    hex::encode(digest.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_test_directory(label: &str) -> PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("starmem-{label}-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        directory
    }

    #[test]
    fn parses_sqlite_page_size() {
        let mut header = vec![0u8; 100];
        header[..16].copy_from_slice(b"SQLite format 3\0");
        header[16..18].copy_from_slice(&4096u16.to_be_bytes());
        assert_eq!(sqlite_page_size(&header), Some(4096));
        header[16..18].copy_from_slice(&1u16.to_be_bytes());
        assert_eq!(sqlite_page_size(&header), Some(65_536));
    }

    #[test]
    fn reports_missing_page_ranges_from_extents() {
        let extents = vec![
            RecoveredExtent {
                file_offset: 0,
                length: 4096,
                memory_address: 0,
                memory_kind: "test".to_owned(),
            },
            RecoveredExtent {
                file_offset: 8192,
                length: 8192,
                memory_address: 0,
                memory_kind: "test".to_owned(),
            },
        ];
        let (recovered, missing) = page_coverage(4096, 4, &extents);
        assert_eq!(recovered, 3);
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].first_page, 2);
        assert_eq!(missing[0].last_page, 2);
    }

    #[test]
    fn page_coverage_handles_large_sparse_databases_as_ranges() {
        let page_count = 8_000_000u64;
        let page_size = 512u64;
        let extents = vec![
            RecoveredExtent {
                file_offset: 0,
                length: page_size,
                memory_address: 0,
                memory_kind: "test".to_owned(),
            },
            RecoveredExtent {
                file_offset: (page_count - 1) * page_size,
                length: page_size,
                memory_address: 0,
                memory_kind: "test".to_owned(),
            },
        ];
        let (recovered, missing) = page_coverage(page_size, page_count, &extents);
        assert_eq!(recovered, 2);
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].first_page, 2);
        assert_eq!(missing[0].last_page, page_count - 1);
    }

    #[test]
    fn table_listing_skips_counts_and_missing_request_is_incomplete() {
        let directory = unique_test_directory("sqlite-tables");
        let path = directory.join("sample.sqlite");
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch("CREATE TABLE present(value TEXT); INSERT INTO present VALUES ('x');")
            .unwrap();
        drop(connection);
        let bytes = fs::read(&path).unwrap();
        let extents = vec![RecoveredExtent {
            file_offset: 0,
            length: bytes.len() as u64,
            memory_address: 0,
            memory_kind: "test".to_owned(),
        }];

        let listing = inspect_database(&path, &bytes, bytes.len() as u64, &extents, &[]);
        assert!(listing.query_complete);
        assert_eq!(listing.tables.len(), 1);
        assert!(!listing.tables[0].row_count_attempted);
        assert_eq!(listing.tables[0].recovered_row_count, None);

        let missing = inspect_database(
            &path,
            &bytes,
            bytes.len() as u64,
            &extents,
            &["absent".to_owned()],
        );
        assert!(!missing.query_complete);
        assert!(
            missing
                .query_error
                .as_deref()
                .is_some_and(|error| error.contains("absent"))
        );
        fs::remove_file(path).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn isolated_inspection_does_not_apply_adjacent_wal() {
        let directory = unique_test_directory("sqlite-isolation");
        let source = directory.join("History");
        let connection = Connection::open(&source).unwrap();
        connection
            .execute_batch(
                "PRAGMA journal_mode=WAL;
                 PRAGMA wal_autocheckpoint=0;
                 CREATE TABLE visits(id INTEGER PRIMARY KEY);
                 INSERT INTO visits VALUES (1);
                 PRAGMA wal_checkpoint(TRUNCATE);
                 INSERT INTO visits VALUES (2);",
            )
            .unwrap();
        let wal = PathBuf::from(format!("{}-wal", source.display()));
        assert!(wal.exists());
        let bytes = fs::read(&source).unwrap();
        let extents = vec![RecoveredExtent {
            file_offset: 0,
            length: bytes.len() as u64,
            memory_address: 0,
            memory_kind: "test".to_owned(),
        }];
        let protected = directory.join("memory.raw");
        let (isolated, isolated_dir) =
            write_isolated_inspection_file(&directory, &bytes, &[protected.as_path()]).unwrap();
        let report = inspect_database(
            &isolated,
            &bytes,
            bytes.len() as u64,
            &extents,
            &["visits".to_owned()],
        );
        assert_eq!(
            report.view_semantic,
            "recovered_main_database_only_sidecars_not_applied"
        );
        assert_eq!(report.tables[0].recovered_row_count, Some(1));
        cleanup_isolated_inspection(&isolated, &isolated_dir).unwrap();
        drop(connection);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn validates_wal_header_and_frames() {
        let mut wal = vec![0u8; 32 + 24 + 4096];
        wal[0..4].copy_from_slice(&0x377f_0682u32.to_be_bytes());
        wal[8..12].copy_from_slice(&4096u32.to_be_bytes());
        wal[32 + 4..32 + 8].copy_from_slice(&10u32.to_be_bytes());
        let details = inspect_wal(&wal);
        assert!(details.header_valid);
        assert_eq!(details.frame_count, Some(1));
        assert_eq!(details.committed_frame_count, Some(1));
    }

    #[test]
    fn output_conflict_detects_existing_hard_link_to_memory_image() {
        let directory = unique_test_directory("sqlite-output");
        let image = directory.join("memory.raw");
        let output = directory.join("History.sqlite");
        fs::write(&image, b"memory evidence").unwrap();
        if fs::hard_link(&image, &output).is_ok() {
            assert!(paths_conflict(&image, &output));
            let mut policy = OutputPolicy::new(true);
            policy.protect_file("memory_image", &image);
            policy.output(OutputTarget::file("sqlite.main", &output));
            assert!(write_evidence_file(&policy, &output, b"sqlite").is_err());
            assert_eq!(fs::read(&image).unwrap(), b"memory evidence");
            fs::remove_file(&output).unwrap();
        }
        fs::remove_file(&image).unwrap();
        fs::remove_dir(&directory).unwrap();
    }

    #[test]
    fn refuses_preexisting_automatically_loaded_sidecar_neighbor() {
        let directory = unique_test_directory("sqlite-neighbor");
        let main = directory.join("History.sqlite");
        let wal = append_path_suffix(&main, "-wal");
        fs::write(&wal, b"unrelated or stale WAL").unwrap();
        assert!(ensure_no_automatic_sidecar_neighbors(&main).is_err());
        fs::remove_file(wal).unwrap();
        fs::remove_dir(directory).unwrap();
    }
}
