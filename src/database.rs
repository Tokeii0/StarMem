use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, ensure};
use rusqlite::types::Value as SqlValue;
use rusqlite::{Connection, Transaction, params, params_from_iter};
use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::evidence::SourceIdentity;
use crate::output_policy::{OutputPolicy, OutputTarget, ProtectedInput};
use crate::raw_objects::{AggregateEvidence, RawObject, extract_raw_objects};

pub const DATABASE_SCHEMA_VERSION: i64 = 4;
const SCHEMA_VERSION: i64 = DATABASE_SCHEMA_VERSION;

#[derive(Debug, Clone)]
pub struct AnalysisIdentity {
    pub engine_version: String,
    pub engine_build_id: String,
    pub integration_api_version: u32,
    pub image_modified_nanos: u128,
    pub image_sample_sha256: String,
    pub execution_policy_json: String,
}

impl AnalysisIdentity {
    pub fn current(image_path: &Path, execution_policy_json: String) -> Result<Self> {
        let metadata = fs::metadata(image_path)
            .with_context(|| format!("无法读取内存镜像身份 {}", image_path.display()))?;
        let image_modified_nanos = metadata
            .modified()
            .ok()
            .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
            .map(|duration| duration.as_nanos())
            .unwrap_or_default();
        Ok(Self {
            engine_version: crate::VERSION.to_owned(),
            engine_build_id: crate::BUILD_ID.to_owned(),
            integration_api_version: crate::INTEGRATION_API_VERSION,
            image_modified_nanos,
            image_sample_sha256: image_sample_digest(image_path, metadata.len())?,
            execution_policy_json,
        })
    }

    fn legacy(engine_version: &str) -> Self {
        Self {
            engine_version: engine_version.to_owned(),
            engine_build_id: String::new(),
            integration_api_version: 0,
            image_modified_nanos: 0,
            image_sample_sha256: String::new(),
            execution_policy_json: "{}".to_owned(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DatabaseCollectionReport {
    pub database: PathBuf,
    pub analysis_id: i64,
    pub plugins_total: usize,
    pub plugins_executed: usize,
    pub plugins_succeeded: usize,
    pub plugins_incomplete: usize,
    pub plugins_failed: usize,
    pub plugins_skipped: usize,
    pub rows_written: usize,
    pub total_seconds: f64,
    pub available: bool,
    pub complete: bool,
}

#[derive(Debug, Clone)]
pub struct PluginOutcome {
    pub status: String,
    pub rows_written: usize,
    pub duration_seconds: f64,
    pub error: Option<String>,
}

#[derive(Debug)]
struct ReportRow {
    section: String,
    row_number: usize,
    cells: BTreeMap<String, Value>,
}

#[derive(Debug, Default)]
struct EnvelopeColumns {
    schema_version: Option<i64>,
    available: Option<bool>,
    source_identity_json: Option<String>,
    scope_json: Option<String>,
    warnings_json: Option<String>,
    warning_codes_json: Option<String>,
    limits_json: Option<String>,
    missing_ranges_json: Option<String>,
    raw_evidence_json: Option<String>,
    envelope_json: Option<String>,
}

pub struct SqliteReportStore {
    connection: Connection,
    path: PathBuf,
    analysis_id: i64,
    started: Instant,
    plugins_total: usize,
    plugins_executed: usize,
    plugins_succeeded: usize,
    plugins_incomplete: usize,
    plugins_failed: usize,
    plugins_skipped: usize,
    rows_written: usize,
}

impl SqliteReportStore {
    pub fn create(
        path: impl AsRef<Path>,
        image_path: &Path,
        image_format: &str,
        image_file_size: u64,
        mapped_physical_bytes: u64,
        engine_version: &str,
        plugins_total: usize,
    ) -> Result<Self> {
        Self::create_with_identity(
            path,
            image_path,
            image_format,
            image_file_size,
            mapped_physical_bytes,
            &AnalysisIdentity::legacy(engine_version),
            plugins_total,
        )
    }

    pub fn create_with_identity(
        path: impl AsRef<Path>,
        image_path: &Path,
        image_format: &str,
        image_file_size: u64,
        mapped_physical_bytes: u64,
        identity: &AnalysisIdentity,
        plugins_total: usize,
    ) -> Result<Self> {
        let sidecars = [
            image_path.with_extension("vmss"),
            image_path.with_extension("vmsn"),
        ]
        .into_iter()
        .filter(|sidecar| sidecar.is_file())
        .enumerate()
        .map(|(index, sidecar)| {
            ProtectedInput::file(format!("memory_image.sidecar[{index}]"), sidecar)
        })
        .collect::<Vec<_>>();
        let source_identity = SourceIdentity::from_path(image_path, image_format)?;
        Self::create_with_identity_and_inputs(
            path,
            image_path,
            image_format,
            image_file_size,
            mapped_physical_bytes,
            identity,
            &source_identity,
            plugins_total,
            &sidecars,
        )
    }

    /// Create an append-only collection database while rechecking every decoded image source
    /// and explicit profile/symbol input immediately before SQLite opens the target.
    #[allow(clippy::too_many_arguments)]
    pub fn create_with_identity_and_inputs(
        path: impl AsRef<Path>,
        image_path: &Path,
        image_format: &str,
        image_file_size: u64,
        mapped_physical_bytes: u64,
        identity: &AnalysisIdentity,
        source_identity: &SourceIdentity,
        plugins_total: usize,
        protected_inputs: &[ProtectedInput],
    ) -> Result<Self> {
        let requested_path = path.as_ref();
        ensure!(
            requested_path != Path::new("-"),
            "SQLite 数据库不能写入标准输出"
        );
        let mut output_policy = OutputPolicy::new(false);
        output_policy.protect_file("memory_image.primary", image_path);
        for input in protected_inputs {
            output_policy.protect(input.clone());
        }
        output_policy.output(
            OutputTarget::append_file("collect.sqlite", requested_path).with_sqlite_sidecars(),
        );
        output_policy.preflight()?;
        if let Some(parent) = requested_path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)
                .with_context(|| format!("无法创建数据库目录 {}", parent.display()))?;
        }
        let path = output_policy.recheck_append_file(requested_path)?;
        let connection = Connection::open(&path)
            .with_context(|| format!("无法打开 SQLite 数据库 {}", path.display()))?;
        let existing_version =
            connection.pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))?;
        ensure!(
            (0..=SCHEMA_VERSION).contains(&existing_version),
            "SQLite 数据库版本 {existing_version} 不受当前程序支持"
        );
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "NORMAL")?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        create_metadata_schema(&connection)?;
        if existing_version == 1 {
            migrate_schema_v1_to_v2(&connection)?;
        }
        if (1..=2).contains(&existing_version) {
            migrate_schema_v2_to_v3(&connection)?;
        }
        if (1..=3).contains(&existing_version) {
            migrate_schema_v3_to_v4(&connection)?;
        }
        create_identity_index(&connection)?;
        connection.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        let canonical_image_path = fs::canonicalize(image_path)
            .unwrap_or_else(|_| image_path.to_path_buf())
            .display()
            .to_string();
        // `image_path` intentionally remains a separate provenance column.  The versioned
        // SourceIdentity is portable and must never absorb a machine-local absolute path.
        let source_identity_json = serde_json::to_string(source_identity)?;
        connection.execute(
            "INSERT INTO analyses (
                image_path, image_format, image_file_size, mapped_physical_bytes,
                engine_version, engine_build_id, integration_api_version,
                image_modified_nanos, image_sample_sha256, execution_policy_json,
                evidence_schema_version, source_identity_json,
                started_unix, status, plugins_total
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, 'running', ?14)",
            params![
                &canonical_image_path,
                image_format,
                integer_or_text(image_file_size),
                integer_or_text(mapped_physical_bytes),
                identity.engine_version,
                identity.engine_build_id,
                i64::from(identity.integration_api_version),
                identity.image_modified_nanos.to_string(),
                identity.image_sample_sha256,
                identity.execution_policy_json,
                i64::from(crate::EVIDENCE_SCHEMA_VERSION),
                source_identity_json,
                unix_timestamp(),
                usize_to_i64(plugins_total),
            ],
        )?;
        let analysis_id = connection.last_insert_rowid();
        Ok(Self {
            connection,
            path,
            analysis_id,
            started: Instant::now(),
            plugins_total,
            plugins_executed: 0,
            plugins_succeeded: 0,
            plugins_incomplete: 0,
            plugins_failed: 0,
            plugins_skipped: 0,
            rows_written: 0,
        })
    }

    pub fn analysis_id(&self) -> i64 {
        self.analysis_id
    }

    pub fn store_report(
        &mut self,
        plugin: &str,
        display_name: &str,
        category: &str,
        report: &impl Serialize,
        duration_seconds: f64,
    ) -> Result<PluginOutcome> {
        let value = serde_json::to_value(report)
            .with_context(|| format!("无法序列化插件 {plugin} 的报告"))?;
        self.store_value(plugin, display_name, category, &value, duration_seconds)
    }

    pub fn store_value(
        &mut self,
        plugin: &str,
        display_name: &str,
        category: &str,
        report: &Value,
        duration_seconds: f64,
    ) -> Result<PluginOutcome> {
        let envelope = envelope_columns(report)?;
        let complete = report
            .as_object()
            .and_then(|object| object.get("complete"))
            .and_then(Value::as_bool)
            .or_else(|| {
                report
                    .as_object()
                    .and_then(|object| object.get("data"))
                    .and_then(Value::as_object)
                    .and_then(|object| object.get("complete"))
                    .and_then(Value::as_bool)
            });
        let status = match complete {
            Some(true) => "success",
            Some(false) => "incomplete",
            None => "unknown_completeness",
        };
        let warning_count = report
            .as_object()
            .and_then(|object| object.get("warnings"))
            .and_then(Value::as_array)
            .map(Vec::len)
            .unwrap_or(0);
        let data = report
            .as_object()
            .and_then(|object| object.get("data"))
            .unwrap_or(report);
        let rows = report_rows(data);
        let raw_bundle = report
            .get("source_identity")
            .cloned()
            .map(serde_json::from_value::<SourceIdentity>)
            .transpose()
            .with_context(|| format!("插件 {plugin} 的 source_identity 无效"))?
            .map(|source| extract_raw_objects(plugin, &source, data))
            .transpose()?;
        let transaction = self.connection.transaction()?;
        insert_plugin_run(
            &transaction,
            self.analysis_id,
            plugin,
            display_name,
            category,
            status,
            complete,
            duration_seconds,
            warning_count,
            None,
            &envelope,
        )?;
        let plugin_run_id = transaction.last_insert_rowid();
        let mut rows_written = 0usize;
        for row in rows {
            write_report_row(&transaction, self.analysis_id, plugin_run_id, plugin, row)?;
            rows_written += 1;
        }
        if let Some(bundle) = raw_bundle {
            write_raw_object_bundle(
                &transaction,
                self.analysis_id,
                plugin_run_id,
                &bundle.objects,
                &bundle.aggregates,
            )?;
        }
        transaction.execute(
            "UPDATE plugin_runs SET rows_written = ?1 WHERE id = ?2",
            params![usize_to_i64(rows_written), plugin_run_id],
        )?;
        transaction.commit()?;

        self.plugins_executed += 1;
        self.rows_written += rows_written;
        match complete {
            Some(true) => self.plugins_succeeded += 1,
            Some(false) | None => self.plugins_incomplete += 1,
        }
        Ok(PluginOutcome {
            status: status.to_owned(),
            rows_written,
            duration_seconds,
            error: None,
        })
    }

    pub fn record_failure(
        &mut self,
        plugin: &str,
        display_name: &str,
        category: &str,
        duration_seconds: f64,
        error: &str,
    ) -> Result<PluginOutcome> {
        self.connection.execute(
            "INSERT INTO plugin_runs (
                analysis_id, plugin, display_name, category, status,
                duration_seconds, error, started_unix, finished_unix
             ) VALUES (?1, ?2, ?3, ?4, 'failed', ?5, ?6, ?7, ?7)",
            params![
                self.analysis_id,
                plugin,
                display_name,
                category,
                duration_seconds,
                error,
                unix_timestamp(),
            ],
        )?;
        self.plugins_executed += 1;
        self.plugins_failed += 1;
        Ok(PluginOutcome {
            status: "failed".to_owned(),
            rows_written: 0,
            duration_seconds,
            error: Some(error.to_owned()),
        })
    }

    pub fn record_skipped(
        &mut self,
        plugin: &str,
        display_name: &str,
        category: &str,
        reason: &str,
    ) -> Result<PluginOutcome> {
        self.connection.execute(
            "INSERT INTO plugin_runs (
                analysis_id, plugin, display_name, category, status,
                error, started_unix, finished_unix
             ) VALUES (?1, ?2, ?3, ?4, 'skipped', ?5, ?6, ?6)",
            params![
                self.analysis_id,
                plugin,
                display_name,
                category,
                reason,
                unix_timestamp(),
            ],
        )?;
        self.plugins_skipped += 1;
        Ok(PluginOutcome {
            status: "skipped".to_owned(),
            rows_written: 0,
            duration_seconds: 0.0,
            error: Some(reason.to_owned()),
        })
    }

    pub fn finish(self) -> Result<DatabaseCollectionReport> {
        let total_seconds = self.started.elapsed().as_secs_f64();
        let status = if self.plugins_failed > 0 {
            "complete_with_errors"
        } else if self.plugins_incomplete > 0 {
            "complete_with_incomplete_results"
        } else {
            "complete"
        };
        self.connection.execute(
            "UPDATE analyses SET
                finished_unix = ?1, status = ?2, plugins_executed = ?3,
                plugins_succeeded = ?4, plugins_incomplete = ?5,
                plugins_failed = ?6, plugins_skipped = ?7,
                rows_written = ?8, total_seconds = ?9
             WHERE id = ?10",
            params![
                unix_timestamp(),
                status,
                usize_to_i64(self.plugins_executed),
                usize_to_i64(self.plugins_succeeded),
                usize_to_i64(self.plugins_incomplete),
                usize_to_i64(self.plugins_failed),
                usize_to_i64(self.plugins_skipped),
                usize_to_i64(self.rows_written),
                total_seconds,
                self.analysis_id,
            ],
        )?;
        self.connection.execute_batch("PRAGMA optimize")?;
        Ok(DatabaseCollectionReport {
            database: self.path,
            analysis_id: self.analysis_id,
            plugins_total: self.plugins_total,
            plugins_executed: self.plugins_executed,
            plugins_succeeded: self.plugins_succeeded,
            plugins_incomplete: self.plugins_incomplete,
            plugins_failed: self.plugins_failed,
            plugins_skipped: self.plugins_skipped,
            rows_written: self.rows_written,
            total_seconds,
            available: true,
            complete: self.plugins_failed == 0 && self.plugins_incomplete == 0,
        })
    }

    /// Persists a cooperative cancellation as a terminal analysis state.
    /// Partial plugin rows already committed remain queryable and are not
    /// misreported as a crashed/running collection on the next launch.
    pub fn mark_cancelled(&mut self) -> Result<()> {
        self.connection.execute(
            "UPDATE analyses SET
                finished_unix = ?1, status = 'cancelled', plugins_executed = ?2,
                plugins_succeeded = ?3, plugins_incomplete = ?4,
                plugins_failed = ?5, plugins_skipped = ?6,
                rows_written = ?7, total_seconds = ?8
             WHERE id = ?9",
            params![
                unix_timestamp(),
                usize_to_i64(self.plugins_executed),
                usize_to_i64(self.plugins_succeeded),
                usize_to_i64(self.plugins_incomplete),
                usize_to_i64(self.plugins_failed),
                usize_to_i64(self.plugins_skipped),
                usize_to_i64(self.rows_written),
                self.started.elapsed().as_secs_f64(),
                self.analysis_id,
            ],
        )?;
        Ok(())
    }
}

fn create_metadata_schema(connection: &Connection) -> Result<()> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS analyses (
            id INTEGER PRIMARY KEY,
            image_path TEXT NOT NULL,
            image_format TEXT NOT NULL,
            image_file_size,
            mapped_physical_bytes,
            engine_version TEXT NOT NULL,
            engine_build_id TEXT NOT NULL DEFAULT '',
            integration_api_version INTEGER NOT NULL DEFAULT 0,
            image_modified_nanos TEXT NOT NULL DEFAULT '0',
            image_sample_sha256 TEXT NOT NULL DEFAULT '',
            execution_policy_json TEXT NOT NULL DEFAULT '{}',
            evidence_schema_version INTEGER NOT NULL DEFAULT 0,
            source_identity_json TEXT NOT NULL DEFAULT '{}',
            started_unix INTEGER NOT NULL,
            finished_unix INTEGER,
            status TEXT NOT NULL,
            plugins_total INTEGER NOT NULL,
            plugins_executed INTEGER NOT NULL DEFAULT 0,
            plugins_succeeded INTEGER NOT NULL DEFAULT 0,
            plugins_incomplete INTEGER NOT NULL DEFAULT 0,
            plugins_failed INTEGER NOT NULL DEFAULT 0,
            plugins_skipped INTEGER NOT NULL DEFAULT 0,
            rows_written INTEGER NOT NULL DEFAULT 0,
            total_seconds REAL
        );
        CREATE TABLE IF NOT EXISTS plugin_runs (
            id INTEGER PRIMARY KEY,
            analysis_id INTEGER NOT NULL REFERENCES analyses(id),
            plugin TEXT NOT NULL,
            display_name TEXT NOT NULL,
            category TEXT NOT NULL,
            status TEXT NOT NULL,
            complete INTEGER,
            duration_seconds REAL NOT NULL DEFAULT 0,
            warning_count INTEGER NOT NULL DEFAULT 0,
            evidence_schema_version INTEGER,
            available INTEGER,
            source_identity_json TEXT,
            scope_json TEXT,
            warnings_json TEXT,
            warning_codes_json TEXT,
            limits_json TEXT,
            missing_ranges_json TEXT,
            raw_evidence_json TEXT,
            envelope_json TEXT,
            rows_written INTEGER NOT NULL DEFAULT 0,
            error TEXT,
            started_unix INTEGER NOT NULL,
            finished_unix INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_plugin_runs_analysis
            ON plugin_runs(analysis_id, plugin);
        CREATE TABLE IF NOT EXISTS raw_objects (
            analysis_id INTEGER NOT NULL REFERENCES analyses(id),
            plugin_run_id INTEGER NOT NULL REFERENCES plugin_runs(id),
            evidence_id TEXT NOT NULL,
            plugin_id TEXT NOT NULL,
            object_type TEXT NOT NULL,
            address_space TEXT NOT NULL,
            address_hex TEXT NOT NULL,
            semantic_key TEXT NOT NULL,
            fields_json TEXT NOT NULL,
            validation_json TEXT NOT NULL,
            provenance_json TEXT NOT NULL,
            missing_ranges_json TEXT NOT NULL,
            PRIMARY KEY (analysis_id, evidence_id)
        );
        CREATE INDEX IF NOT EXISTS idx_raw_objects_plugin
            ON raw_objects(analysis_id, plugin_id, object_type);
        CREATE TABLE IF NOT EXISTS aggregate_evidence (
            analysis_id INTEGER NOT NULL REFERENCES analyses(id),
            plugin_run_id INTEGER NOT NULL REFERENCES plugin_runs(id),
            plugin_id TEXT NOT NULL,
            aggregate_type TEXT NOT NULL,
            aggregate_key TEXT NOT NULL,
            evidence_id TEXT NOT NULL,
            ordinal INTEGER NOT NULL,
            PRIMARY KEY (
                analysis_id, plugin_run_id, aggregate_type, aggregate_key, evidence_id
            )
        );
        CREATE INDEX IF NOT EXISTS idx_aggregate_evidence_source
            ON aggregate_evidence(analysis_id, evidence_id);
        CREATE VIEW IF NOT EXISTS latest_analysis AS
            SELECT * FROM analyses ORDER BY id DESC LIMIT 1;",
    )?;
    Ok(())
}

fn migrate_schema_v1_to_v2(connection: &Connection) -> Result<()> {
    add_column_if_missing(
        connection,
        "analyses",
        "engine_build_id",
        "TEXT NOT NULL DEFAULT ''",
    )?;
    add_column_if_missing(
        connection,
        "analyses",
        "integration_api_version",
        "INTEGER NOT NULL DEFAULT 0",
    )?;
    add_column_if_missing(
        connection,
        "analyses",
        "image_modified_nanos",
        "TEXT NOT NULL DEFAULT '0'",
    )?;
    add_column_if_missing(
        connection,
        "analyses",
        "image_sample_sha256",
        "TEXT NOT NULL DEFAULT ''",
    )?;
    add_column_if_missing(
        connection,
        "analyses",
        "execution_policy_json",
        "TEXT NOT NULL DEFAULT '{}'",
    )?;
    Ok(())
}

fn migrate_schema_v2_to_v3(connection: &Connection) -> Result<()> {
    add_column_if_missing(
        connection,
        "analyses",
        "evidence_schema_version",
        "INTEGER NOT NULL DEFAULT 0",
    )?;
    add_column_if_missing(
        connection,
        "analyses",
        "source_identity_json",
        "TEXT NOT NULL DEFAULT '{}'",
    )?;
    for (name, definition) in [
        ("evidence_schema_version", "INTEGER"),
        ("available", "INTEGER"),
        ("source_identity_json", "TEXT"),
        ("scope_json", "TEXT"),
        ("warnings_json", "TEXT"),
        ("warning_codes_json", "TEXT"),
        ("limits_json", "TEXT"),
        ("missing_ranges_json", "TEXT"),
        ("raw_evidence_json", "TEXT"),
        ("envelope_json", "TEXT"),
    ] {
        add_column_if_missing(connection, "plugin_runs", name, definition)?;
    }
    Ok(())
}

fn migrate_schema_v3_to_v4(connection: &Connection) -> Result<()> {
    // Tables are created idempotently by create_metadata_schema. Keeping an explicit migration
    // step documents the boundary and allows future v4-only indexes to be added here.
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_raw_objects_address
         ON raw_objects(analysis_id, address_space, address_hex)",
        [],
    )?;
    Ok(())
}

fn add_column_if_missing(
    connection: &Connection,
    table: &str,
    column: &str,
    definition: &str,
) -> Result<()> {
    let mut statement =
        connection.prepare(&format!("PRAGMA table_info({})", quote_identifier(table)))?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<rusqlite::Result<BTreeSet<_>>>()?;
    if !columns.contains(column) {
        connection.execute(
            &format!(
                "ALTER TABLE {} ADD COLUMN {} {definition}",
                quote_identifier(table),
                quote_identifier(column)
            ),
            [],
        )?;
    }
    Ok(())
}

fn create_identity_index(connection: &Connection) -> Result<()> {
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_analyses_image_identity
         ON analyses(image_path, image_file_size, image_modified_nanos, image_sample_sha256)",
        [],
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn insert_plugin_run(
    transaction: &Transaction<'_>,
    analysis_id: i64,
    plugin: &str,
    display_name: &str,
    category: &str,
    status: &str,
    complete: Option<bool>,
    duration_seconds: f64,
    warning_count: usize,
    error: Option<&str>,
    envelope: &EnvelopeColumns,
) -> Result<()> {
    let now = unix_timestamp();
    transaction.execute(
        "INSERT INTO plugin_runs (
            analysis_id, plugin, display_name, category, status, complete,
            duration_seconds, warning_count, error, started_unix, finished_unix,
            evidence_schema_version, available, source_identity_json, scope_json,
            warnings_json, warning_codes_json, limits_json, missing_ranges_json,
            raw_evidence_json, envelope_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10,
                   ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)",
        params![
            analysis_id,
            plugin,
            display_name,
            category,
            status,
            complete.map(i64::from),
            duration_seconds,
            usize_to_i64(warning_count),
            error,
            now,
            envelope.schema_version,
            envelope.available.map(i64::from),
            envelope.source_identity_json,
            envelope.scope_json,
            envelope.warnings_json,
            envelope.warning_codes_json,
            envelope.limits_json,
            envelope.missing_ranges_json,
            envelope.raw_evidence_json,
            envelope.envelope_json,
        ],
    )?;
    Ok(())
}

fn envelope_columns(report: &Value) -> Result<EnvelopeColumns> {
    let Some(object) = report.as_object() else {
        return Ok(EnvelopeColumns::default());
    };
    let Some(schema_version) = object.get("schema_version").and_then(Value::as_u64) else {
        return Ok(EnvelopeColumns::default());
    };
    let warnings = object
        .get("warnings")
        .cloned()
        .unwrap_or_else(|| Value::Array(Vec::new()));
    let warning_codes = warnings
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|warning| warning.get("code").and_then(Value::as_str))
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    Ok(EnvelopeColumns {
        schema_version: i64::try_from(schema_version).ok(),
        available: object.get("available").and_then(Value::as_bool),
        source_identity_json: object
            .get("source_identity")
            .map(serde_json::to_string)
            .transpose()?,
        scope_json: object.get("scope").map(serde_json::to_string).transpose()?,
        warnings_json: Some(serde_json::to_string(&warnings)?),
        warning_codes_json: Some(serde_json::to_string(&warning_codes)?),
        limits_json: object
            .get("limits")
            .map(serde_json::to_string)
            .transpose()?,
        missing_ranges_json: object
            .get("missing_ranges")
            .map(serde_json::to_string)
            .transpose()?,
        raw_evidence_json: object
            .get("raw_evidence")
            .map(serde_json::to_string)
            .transpose()?,
        envelope_json: Some(serde_json::to_string(report)?),
    })
}

fn write_report_row(
    transaction: &Transaction<'_>,
    analysis_id: i64,
    plugin_run_id: i64,
    plugin: &str,
    row: ReportRow,
) -> Result<()> {
    let table = format!(
        "{}__{}",
        normalize_identifier(plugin),
        normalize_identifier(&row.section)
    );
    let table = quote_identifier(&table);
    transaction.execute(
        &format!(
            "CREATE TABLE IF NOT EXISTS {table} (
                analysis_id INTEGER NOT NULL,
                plugin_run_id INTEGER NOT NULL,
                row_number INTEGER NOT NULL
            )"
        ),
        [],
    )?;

    let existing = table_columns(transaction, &table)?;
    let mut normalized_cells = BTreeMap::new();
    for (key, value) in row.cells {
        normalized_cells.insert(normalize_identifier(&key), value);
    }
    for column in normalized_cells.keys() {
        if !existing.contains(column) {
            transaction.execute(
                &format!(
                    "ALTER TABLE {table} ADD COLUMN {}",
                    quote_identifier(column)
                ),
                [],
            )?;
        }
    }

    let mut columns = vec![
        "analysis_id".to_owned(),
        "plugin_run_id".to_owned(),
        "row_number".to_owned(),
    ];
    columns.extend(normalized_cells.keys().cloned());
    let column_sql = columns
        .iter()
        .map(|column| quote_identifier(column))
        .collect::<Vec<_>>()
        .join(", ");
    let placeholders = (1..=columns.len())
        .map(|index| format!("?{index}"))
        .collect::<Vec<_>>()
        .join(", ");
    let mut values = vec![
        SqlValue::Integer(analysis_id),
        SqlValue::Integer(plugin_run_id),
        SqlValue::Integer(usize_to_i64(row.row_number)),
    ];
    values.extend(normalized_cells.values().map(json_to_sql_value));
    transaction.execute(
        &format!("INSERT INTO {table} ({column_sql}) VALUES ({placeholders})"),
        params_from_iter(values),
    )?;
    Ok(())
}

fn write_raw_object_bundle(
    transaction: &Transaction<'_>,
    analysis_id: i64,
    plugin_run_id: i64,
    objects: &[RawObject],
    aggregates: &[AggregateEvidence],
) -> Result<()> {
    let object_ids = objects
        .iter()
        .map(|object| object.evidence_id.as_str())
        .collect::<BTreeSet<_>>();
    for aggregate in aggregates {
        ensure!(
            objects
                .iter()
                .filter(|object| { aggregate.source_evidence_ids.contains(&object.evidence_id) })
                .all(|object| object.plugin_id == aggregate.plugin_id),
            "聚合证据 {}:{} 的 plugin_id 与原始对象不一致",
            aggregate.aggregate_type,
            aggregate.aggregate_key
        );
        for evidence_id in &aggregate.source_evidence_ids {
            ensure!(
                object_ids.contains(evidence_id.as_str()),
                "聚合证据 {}:{} 引用了本批次不存在的 evidence_id {}",
                aggregate.aggregate_type,
                aggregate.aggregate_key,
                evidence_id
            );
        }
    }
    for object in objects {
        transaction.execute(
            "INSERT OR REPLACE INTO raw_objects (
                analysis_id, plugin_run_id, evidence_id, plugin_id, object_type,
                address_space, address_hex, semantic_key, fields_json,
                validation_json, provenance_json, missing_ranges_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                analysis_id,
                plugin_run_id,
                object.evidence_id,
                object.plugin_id,
                object.object_type,
                object.address_space,
                object.address,
                object.semantic_key,
                serde_json::to_string(&object.fields)?,
                serde_json::to_string(&object.validation)?,
                serde_json::to_string(&object.provenance)?,
                serde_json::to_string(&object.missing_ranges)?,
            ],
        )?;
    }
    for aggregate in aggregates {
        for (ordinal, evidence_id) in aggregate.source_evidence_ids.iter().enumerate() {
            transaction.execute(
                "INSERT OR REPLACE INTO aggregate_evidence (
                    analysis_id, plugin_run_id, plugin_id, aggregate_type,
                    aggregate_key, evidence_id, ordinal
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    analysis_id,
                    plugin_run_id,
                    aggregate.plugin_id,
                    aggregate.aggregate_type,
                    aggregate.aggregate_key,
                    evidence_id,
                    usize_to_i64(ordinal),
                ],
            )?;
        }
    }
    Ok(())
}

fn table_columns(transaction: &Transaction<'_>, quoted_table: &str) -> Result<BTreeSet<String>> {
    let mut statement = transaction.prepare(&format!("PRAGMA table_info({quoted_table})"))?;
    let rows = statement.query_map([], |row| row.get::<_, String>(1))?;
    Ok(rows.collect::<rusqlite::Result<BTreeSet<_>>>()?)
}

fn report_rows(value: &Value) -> Vec<ReportRow> {
    match value {
        Value::Object(object) => object_report_rows(object),
        Value::Array(items) => array_rows("records", items),
        value => vec![ReportRow {
            section: "summary".to_owned(),
            row_number: 1,
            cells: BTreeMap::from([("value".to_owned(), value.clone())]),
        }],
    }
}

fn object_report_rows(object: &Map<String, Value>) -> Vec<ReportRow> {
    let mut summary = BTreeMap::new();
    let mut sections = Vec::new();
    for (key, value) in object {
        if let Value::Array(items) = value {
            summary.insert(format!("{key}_count"), Value::from(items.len() as u64));
            sections.extend(array_rows(key, items));
        } else {
            flatten_value(key, value, &mut summary);
        }
    }
    let mut rows = Vec::new();
    if !summary.is_empty() || sections.is_empty() {
        rows.push(ReportRow {
            section: "summary".to_owned(),
            row_number: 1,
            cells: summary,
        });
    }
    rows.extend(sections);
    rows
}

fn array_rows(section: &str, items: &[Value]) -> Vec<ReportRow> {
    items
        .iter()
        .enumerate()
        .map(|(index, item)| {
            let mut cells = BTreeMap::new();
            match item {
                Value::Object(object) => {
                    for (key, value) in object {
                        flatten_value(key, value, &mut cells);
                    }
                }
                value => {
                    cells.insert("value".to_owned(), value.clone());
                }
            }
            ReportRow {
                section: section.to_owned(),
                row_number: index + 1,
                cells,
            }
        })
        .collect()
}

fn flatten_value(prefix: &str, value: &Value, output: &mut BTreeMap<String, Value>) {
    match value {
        Value::Object(object) => {
            if object.is_empty() {
                output.insert(prefix.to_owned(), Value::Object(Map::new()));
            } else {
                for (key, value) in object {
                    flatten_value(&format!("{prefix}_{key}"), value, output);
                }
            }
        }
        Value::Array(_) => {
            output.insert(prefix.to_owned(), value.clone());
        }
        value => {
            output.insert(prefix.to_owned(), value.clone());
        }
    }
}

fn json_to_sql_value(value: &Value) -> SqlValue {
    match value {
        Value::Null => SqlValue::Null,
        Value::Bool(value) => SqlValue::Integer(i64::from(*value)),
        Value::Number(value) => {
            if let Some(value) = value.as_i64() {
                SqlValue::Integer(value)
            } else if let Some(value) = value.as_u64() {
                integer_or_text(value)
            } else if let Some(value) = value.as_f64() {
                SqlValue::Real(value)
            } else {
                SqlValue::Text(value.to_string())
            }
        }
        Value::String(value) => SqlValue::Text(value.clone()),
        Value::Array(_) | Value::Object(_) => {
            SqlValue::Text(serde_json::to_string(value).unwrap_or_default())
        }
    }
}

fn integer_or_text(value: u64) -> SqlValue {
    i64::try_from(value)
        .map(SqlValue::Integer)
        .unwrap_or_else(|_| SqlValue::Text(value.to_string()))
}

fn normalize_identifier(value: &str) -> String {
    let mut output = String::new();
    let mut previous_underscore = false;
    for character in value.chars() {
        let character = character.to_ascii_lowercase();
        if character.is_ascii_alphanumeric() || character == '_' {
            output.push(character);
            previous_underscore = false;
        } else if !previous_underscore {
            output.push('_');
            previous_underscore = true;
        }
    }
    let output = output.trim_matches('_');
    let mut output = if output.is_empty() {
        "value".to_owned()
    } else {
        output.to_owned()
    };
    if output.starts_with(|character: char| character.is_ascii_digit()) {
        output.insert(0, '_');
    }
    output
}

fn quote_identifier(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn usize_to_i64(value: usize) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn image_sample_digest(path: &Path, size: u64) -> Result<String> {
    const SAMPLE_SIZE: u64 = 1024 * 1024;
    let mut file = fs::File::open(path)
        .with_context(|| format!("无法打开内存镜像以计算身份摘要 {}", path.display()))?;
    let chunk_len = size.min(SAMPLE_SIZE);
    let mut positions = BTreeSet::from([0]);
    if chunk_len > 0 {
        positions.insert((size.saturating_sub(chunk_len)) / 2);
        positions.insert(size.saturating_sub(chunk_len));
    }
    let mut digest = Sha256::new();
    digest.update(b"starmem-source-sample-v1\0");
    digest.update(size.to_le_bytes());
    let mut buffer = vec![0u8; usize::try_from(chunk_len).unwrap_or(SAMPLE_SIZE as usize)];
    for position in positions {
        file.seek(SeekFrom::Start(position))?;
        file.read_exact(&mut buffer)?;
        digest.update(position.to_le_bytes());
        digest.update(chunk_len.to_le_bytes());
        digest.update(&buffer);
    }
    Ok(hex::encode(digest.finalize()))
}

fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| i64::try_from(duration.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn writes_queryable_plugin_tables_and_metadata() {
        let path = std::env::temp_dir().join(format!(
            "starmem-db-test-{}-{}.sqlite",
            std::process::id(),
            unix_timestamp()
        ));
        let image = path.with_extension("raw");
        fs::write(&image, []).unwrap();
        let mut store =
            SqliteReportStore::create(&path, &image, "Raw", 4096, 4096, "test", 2).unwrap();
        let outcome = store
            .store_value(
                "pslist",
                "活动进程",
                "进程与线程",
                &json!({
                    "records": [{"pid": 4, "name": "System", "owners": [1, 2]}],
                    "complete": true,
                    "warnings": []
                }),
                0.25,
            )
            .unwrap();
        assert_eq!(outcome.rows_written, 2);
        store
            .record_skipped("dumpfile", "文件导出", "导出", "需要输出路径")
            .unwrap();
        let report = store.finish().unwrap();
        assert_eq!(report.plugins_succeeded, 1);
        assert_eq!(report.plugins_skipped, 1);

        let connection = Connection::open(&path).unwrap();
        let (pid, name, owners): (i64, String, String) = connection
            .query_row("SELECT pid, name, owners FROM pslist__records", [], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .unwrap();
        assert_eq!((pid, name.as_str()), (4, "System"));
        assert_eq!(owners, "[1,2]");
        let statuses = connection
            .query_row(
                "SELECT COUNT(*) FROM plugin_runs WHERE status IN ('success', 'skipped')",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap();
        assert_eq!(statuses, 2);
        drop(connection);
        fs::remove_file(path).ok();
        fs::remove_file(image).ok();
    }

    #[test]
    fn missing_top_level_complete_is_not_counted_as_success() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "starmem-db-unknown-completeness-{}-{nonce}.sqlite",
            std::process::id()
        ));
        let image = path.with_extension("raw");
        fs::write(&image, []).unwrap();
        let mut store =
            SqliteReportStore::create(&path, &image, "Raw", 4096, 4096, "test", 1).unwrap();
        let outcome = store
            .store_value(
                "legacy-report",
                "未声明完整性的报告",
                "测试",
                &json!({
                    "records": [{"complete": true, "value": "nested only"}],
                    "warnings": []
                }),
                0.1,
            )
            .unwrap();
        assert_eq!(outcome.status, "unknown_completeness");

        let report = store.finish().unwrap();
        assert_eq!(report.plugins_succeeded, 0);
        assert_eq!(report.plugins_incomplete, 1);

        let connection = Connection::open(&path).unwrap();
        let (plugin_status, complete): (String, Option<i64>) = connection
            .query_row(
                "SELECT status, complete FROM plugin_runs WHERE plugin = 'legacy-report'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(plugin_status, "unknown_completeness");
        assert_eq!(complete, None);
        let (analysis_status, succeeded, incomplete): (String, i64, i64) = connection
            .query_row(
                "SELECT status, plugins_succeeded, plugins_incomplete FROM latest_analysis",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(analysis_status, "complete_with_incomplete_results");
        assert_eq!(succeeded, 0);
        assert_eq!(incomplete, 1);
        drop(connection);
        fs::remove_file(path).ok();
        fs::remove_file(image).ok();
    }

    #[test]
    fn schema_v4_persists_envelope_raw_objects_and_aggregate_links() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "starmem-db-envelope-{}-{nonce}.sqlite",
            std::process::id()
        ));
        let image = path.with_extension("raw");
        fs::write(&image, b"memory evidence").unwrap();
        let mut store = SqliteReportStore::create(&path, &image, "Raw", 15, 15, "test", 1).unwrap();
        let envelope = json!({
            "schema_version": 1,
            "command": "windows.timeline",
            "engine_identity": {
                "version": crate::VERSION,
                "build_id": crate::BUILD_ID,
                "integration_api_version": crate::INTEGRATION_API_VERSION
            },
            "source_identity": {
                "format": "raw",
                "size": 15,
                "mtime": null,
                "sample_digest": {"algorithm": "test", "value": "00"},
                "symbol_identity": null
            },
            "available": true,
            "complete": false,
            "scope": {"kind": "active_process_list", "description": null, "constraints": {}},
            "warnings": [{
                "code": "head_blink_mismatch",
                "severity": "warning",
                "message": "bad backlink",
                "source": "windows.timeline",
                "context": {"address": 4096}
            }],
            "limits": [{
                "name": "limit", "kind": "output", "configured": 65536,
                "observed": 63, "reached": false
            }],
            "missing_ranges": [],
            "raw_evidence": {"count": 0, "storage": "none", "references": []},
            "data": {
                "events": [{
                    "timestamp": "2023-06-20T16:56:57Z",
                    "category": "process",
                    "action": "created",
                    "source": "psscan",
                    "pid": 88,
                    "process": "chrome.exe",
                    "object_address": "0xffff800000001000",
                    "physical_address": 8192,
                    "physical_addresses": [8192, 12288]
                }],
                "complete": false
            }
        });
        store
            .store_value(
                "windows.timeline",
                "Windows 时间线",
                "时间线",
                &envelope,
                0.1,
            )
            .unwrap();
        store.finish().unwrap();

        let connection = Connection::open(&path).unwrap();
        let (schema, available, codes, stored): (i64, i64, String, String) = connection
            .query_row(
                "SELECT evidence_schema_version, available, warning_codes_json, envelope_json
                 FROM plugin_runs WHERE plugin = 'windows.timeline'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(schema, 1);
        assert_eq!(available, 1);
        assert_eq!(
            serde_json::from_str::<Value>(&codes).unwrap(),
            json!(["head_blink_mismatch"])
        );
        assert_eq!(serde_json::from_str::<Value>(&stored).unwrap(), envelope);
        let raw_count: i64 = connection
            .query_row("SELECT COUNT(*) FROM raw_objects", [], |row| row.get(0))
            .unwrap();
        let link_count: i64 = connection
            .query_row("SELECT COUNT(*) FROM aggregate_evidence", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(raw_count, 3);
        assert_eq!(link_count, 3);
        let dangling_links: i64 = connection
            .query_row(
                "SELECT COUNT(*)
                 FROM aggregate_evidence AS aggregate_link
                 LEFT JOIN raw_objects AS raw
                   ON raw.analysis_id = aggregate_link.analysis_id
                  AND raw.evidence_id = aggregate_link.evidence_id
                 WHERE raw.evidence_id IS NULL",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(dangling_links, 0);
        let ordinals: String = connection
            .query_row(
                "SELECT group_concat(ordinal, ',') FROM (
                    SELECT ordinal FROM aggregate_evidence ORDER BY ordinal
                 )",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(ordinals, "0,1,2");
        drop(connection);
        fs::remove_file(path).ok();
        fs::remove_file(image).ok();
    }

    #[test]
    fn normalizes_sql_identifiers_without_losing_ascii_names() {
        assert_eq!(normalize_identifier("browser-session"), "browser_session");
        assert_eq!(
            normalize_identifier("timing.total_seconds"),
            "timing_total_seconds"
        );
        assert_eq!(normalize_identifier("123"), "_123");
    }

    #[test]
    fn migrates_v1_and_records_strong_analysis_identity() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "starmem-db-identity-{}-{nonce}.sqlite",
            std::process::id()
        ));
        let image = path.with_extension("raw");
        fs::write(&image, b"stable memory evidence").unwrap();
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "PRAGMA user_version = 1;
                 CREATE TABLE analyses (
                    id INTEGER PRIMARY KEY,
                    image_path TEXT NOT NULL,
                    image_format TEXT NOT NULL,
                    image_file_size,
                    mapped_physical_bytes,
                    engine_version TEXT NOT NULL,
                    started_unix INTEGER NOT NULL,
                    finished_unix INTEGER,
                    status TEXT NOT NULL,
                    plugins_total INTEGER NOT NULL,
                    plugins_executed INTEGER NOT NULL DEFAULT 0,
                    plugins_succeeded INTEGER NOT NULL DEFAULT 0,
                    plugins_incomplete INTEGER NOT NULL DEFAULT 0,
                    plugins_failed INTEGER NOT NULL DEFAULT 0,
                    plugins_skipped INTEGER NOT NULL DEFAULT 0,
                    rows_written INTEGER NOT NULL DEFAULT 0,
                    total_seconds REAL
                 );",
            )
            .unwrap();
        drop(connection);

        let identity = AnalysisIdentity::current(&image, r#"{"limit":100}"#.to_owned()).unwrap();
        let store =
            SqliteReportStore::create_with_identity(&path, &image, "Raw", 22, 22, &identity, 0)
                .unwrap();
        store.finish().unwrap();

        let connection = Connection::open(&path).unwrap();
        let version: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
        let (build_id, api_version, sample, policy, source_identity_json): (
            String,
            i64,
            String,
            String,
            String,
        ) = connection
            .query_row(
                "SELECT engine_build_id, integration_api_version,
                        image_sample_sha256, execution_policy_json, source_identity_json
                 FROM latest_analysis",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(build_id, crate::BUILD_ID);
        assert_eq!(api_version, i64::from(crate::INTEGRATION_API_VERSION));
        assert_eq!(sample.len(), 64);
        assert_eq!(policy, r#"{"limit":100}"#);
        let source_identity: SourceIdentity = serde_json::from_str(&source_identity_json).unwrap();
        assert_eq!(source_identity.format, "Raw");
        assert_eq!(source_identity.size, 22);
        assert_eq!(source_identity.sample_digest.value, sample);
        assert!(!source_identity_json.contains(&image.display().to_string()));
        drop(connection);
        fs::remove_file(path).ok();
        fs::remove_file(image).ok();
    }

    #[test]
    fn refuses_to_overwrite_the_memory_image_with_a_database() {
        let image = std::env::temp_dir().join(format!(
            "starmem-db-safety-{}-{}.raw",
            std::process::id(),
            unix_timestamp()
        ));
        fs::write(&image, b"memory evidence").unwrap();
        let error = SqliteReportStore::create(&image, &image, "Raw", 15, 15, "test", 1)
            .err()
            .expect("相同的数据库和镜像路径必须被拒绝");
        assert!(error.to_string().contains("受保护输入"));
        assert_eq!(fs::read(&image).unwrap(), b"memory evidence");
        fs::remove_file(image).ok();
    }

    #[test]
    fn refuses_explicit_nonstem_sidecar_as_database_target() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let primary = std::env::temp_dir().join(format!(
            "starmem-db-primary-{}-{nonce}.vmem",
            std::process::id()
        ));
        let metadata = std::env::temp_dir().join(format!(
            "starmem-db-explicit-metadata-{}-{nonce}.vmss",
            std::process::id()
        ));
        fs::write(&primary, b"primary memory evidence").unwrap();
        fs::write(&metadata, b"explicit sidecar evidence").unwrap();
        let identity = AnalysisIdentity::current(&primary, "{}".to_owned()).unwrap();
        let source_identity = SourceIdentity::from_path(&primary, "vmware_vmem").unwrap();
        let inputs = [ProtectedInput::file("memory_image.metadata", &metadata)];
        let error = SqliteReportStore::create_with_identity_and_inputs(
            &metadata,
            &primary,
            "vmware_vmem",
            23,
            23,
            &identity,
            &source_identity,
            0,
            &inputs,
        )
        .err()
        .expect("显式非同 stem metadata 必须作为受保护输入");
        assert!(error.to_string().contains("受保护输入"));
        assert_eq!(fs::read(&metadata).unwrap(), b"explicit sidecar evidence");
        fs::remove_file(primary).ok();
        fs::remove_file(metadata).ok();
    }
}
