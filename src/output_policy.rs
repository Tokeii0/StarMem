//! Shared output-path safety and atomic publication primitives.
//!
//! [`OutputPolicy`] is deliberately independent of the CLI.  A caller registers every
//! evidence input and every file that a command can create, performs a read-only preflight,
//! and then uses [`OutputPolicy::write_file_atomic`] for the actual publication.  The latter
//! repeats the path checks immediately before the final rename.  This protects against
//! accidental aliases and path changes made by the command itself; it is not intended as a
//! defence against a hostile local process racing the publication.

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};

/// Sidecars SQLite may open implicitly next to a database.
pub const SQLITE_SIDECAR_SUFFIXES: [&str; 3] = ["-wal", "-shm", "-journal"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectedPathKind {
    File,
    Directory,
}

/// A path which must never be replaced by an analysis output, even with `--force`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedInput {
    role: String,
    path: PathBuf,
    kind: ProtectedPathKind,
}

impl ProtectedInput {
    pub fn file(role: impl Into<String>, path: impl Into<PathBuf>) -> Self {
        Self {
            role: role.into(),
            path: path.into(),
            kind: ProtectedPathKind::File,
        }
    }

    pub fn directory(role: impl Into<String>, path: impl Into<PathBuf>) -> Self {
        Self {
            role: role.into(),
            path: path.into(),
            kind: ProtectedPathKind::Directory,
        }
    }

    pub fn role(&self) -> &str {
        &self.role
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn kind(&self) -> ProtectedPathKind {
        self.kind
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DerivedOutput {
    /// An explicitly computed sibling or sidecar path.
    Path(PathBuf),
    /// Append a suffix to the complete path (for example `.partial` or `-wal`).
    SiblingSuffix(String),
    /// Replace the extension (for example an adjacent JSON manifest).
    Extension(String),
}

impl DerivedOutput {
    fn resolve(&self, primary: &Path) -> PathBuf {
        match self {
            Self::Path(path) => path.clone(),
            Self::SiblingSuffix(suffix) => append_path_suffix(primary, suffix),
            Self::Extension(extension) => primary.with_extension(extension),
        }
    }
}

/// A command-owned output target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputWriteMode {
    /// Publish through a synchronized same-directory staging file and atomic replacement.
    AtomicReplace,
    /// Append/update an existing ordinary file in place (for example SQLite transactions).
    Append,
}

/// A command-owned output target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutputTarget {
    File {
        role: String,
        path: PathBuf,
        derived: Vec<DerivedOutput>,
        mode: OutputWriteMode,
    },
    /// The directory itself is never recursively replaced.  Only `owned_files` are eligible
    /// for replacement when `--force` is active.
    Directory {
        role: String,
        root: PathBuf,
        owned_files: Vec<PathBuf>,
    },
}

impl OutputTarget {
    pub fn file(role: impl Into<String>, path: impl Into<PathBuf>) -> Self {
        Self::File {
            role: role.into(),
            path: path.into(),
            derived: Vec::new(),
            mode: OutputWriteMode::AtomicReplace,
        }
    }

    /// Register an explicit in-place append/update target.
    ///
    /// Existing regular files are allowed regardless of `--force`.  Protected aliases,
    /// symlinks, directories, devices, and other non-regular targets remain forbidden.
    pub fn append_file(role: impl Into<String>, path: impl Into<PathBuf>) -> Self {
        Self::File {
            role: role.into(),
            path: path.into(),
            derived: Vec::new(),
            mode: OutputWriteMode::Append,
        }
    }

    pub fn directory(role: impl Into<String>, root: impl Into<PathBuf>) -> Self {
        Self::Directory {
            role: role.into(),
            root: root.into(),
            owned_files: Vec::new(),
        }
    }

    pub fn with_derived_path(mut self, path: impl Into<PathBuf>) -> Self {
        match &mut self {
            Self::File { derived, .. } => derived.push(DerivedOutput::Path(path.into())),
            Self::Directory { .. } => panic!("directory outputs use with_owned_file"),
        }
        self
    }

    pub fn with_sibling_suffix(mut self, suffix: impl Into<String>) -> Self {
        match &mut self {
            Self::File { derived, .. } => derived.push(DerivedOutput::SiblingSuffix(suffix.into())),
            Self::Directory { .. } => panic!("directory outputs use with_owned_file"),
        }
        self
    }

    pub fn with_extension(mut self, extension: impl Into<String>) -> Self {
        match &mut self {
            Self::File { derived, .. } => derived.push(DerivedOutput::Extension(extension.into())),
            Self::Directory { .. } => panic!("directory outputs use with_owned_file"),
        }
        self
    }

    pub fn with_sqlite_sidecars(mut self) -> Self {
        if let Self::File { derived, .. } = &mut self {
            derived.extend(
                SQLITE_SIDECAR_SUFFIXES
                    .into_iter()
                    .map(|suffix| DerivedOutput::SiblingSuffix(suffix.to_owned())),
            );
        } else {
            panic!("SQLite sidecars belong to a file output")
        }
        self
    }

    /// Declare a command-owned file relative to a directory output.
    ///
    /// Absolute paths and paths containing `..` are rejected during preflight.
    pub fn with_owned_file(mut self, relative_path: impl Into<PathBuf>) -> Self {
        match &mut self {
            Self::Directory { owned_files, .. } => owned_files.push(relative_path.into()),
            Self::File { .. } => panic!("file outputs use with_derived_path"),
        }
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedOutputFile {
    pub role: String,
    pub path: PathBuf,
    pub mode: OutputWriteMode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedOutputPlan {
    pub files: Vec<PlannedOutputFile>,
    pub directories: Vec<PathBuf>,
}

/// Central policy for all paths a command reads or writes.
#[derive(Debug, Clone, Default)]
pub struct OutputPolicy {
    force: bool,
    protected_inputs: Vec<ProtectedInput>,
    outputs: Vec<OutputTarget>,
}

impl OutputPolicy {
    pub fn new(force: bool) -> Self {
        Self {
            force,
            protected_inputs: Vec::new(),
            outputs: Vec::new(),
        }
    }

    pub fn force(&self) -> bool {
        self.force
    }

    pub fn protect(&mut self, input: ProtectedInput) -> &mut Self {
        self.protected_inputs.push(input);
        self
    }

    pub fn protect_file(&mut self, role: impl Into<String>, path: impl Into<PathBuf>) -> &mut Self {
        self.protect(ProtectedInput::file(role, path))
    }

    pub fn protect_directory(
        &mut self,
        role: impl Into<String>,
        path: impl Into<PathBuf>,
    ) -> &mut Self {
        self.protect(ProtectedInput::directory(role, path))
    }

    /// Register a primary input and its explicitly discovered metadata/profile sidecars.
    pub fn protect_file_with_sidecars<I, P>(
        &mut self,
        role: impl Into<String>,
        path: impl Into<PathBuf>,
        sidecars: I,
    ) -> &mut Self
    where
        I: IntoIterator<Item = P>,
        P: Into<PathBuf>,
    {
        let role = role.into();
        self.protect_file(role.clone(), path);
        for (index, sidecar) in sidecars.into_iter().enumerate() {
            self.protect_file(format!("{role}.sidecar[{index}]"), sidecar);
        }
        self
    }

    pub fn output(&mut self, target: OutputTarget) -> &mut Self {
        self.outputs.push(target);
        self
    }

    pub fn output_file(&mut self, role: impl Into<String>, path: impl Into<PathBuf>) -> &mut Self {
        self.output(OutputTarget::file(role, path))
    }

    pub fn protected_inputs(&self) -> &[ProtectedInput] {
        &self.protected_inputs
    }

    pub fn outputs(&self) -> &[OutputTarget] {
        &self.outputs
    }

    /// Validate all output paths without changing the filesystem.
    pub fn preflight(&self) -> Result<ValidatedOutputPlan> {
        let plan = self.expand_plan()?;

        for file in &plan.files {
            self.ensure_not_protected(&file.path, false)?;
            self.ensure_allowed_for_mode(&file.path, file.mode)?;
        }
        for directory in &plan.directories {
            self.ensure_not_protected(directory, true)?;
            validate_directory_root(directory)?;
        }

        for left_index in 0..plan.files.len() {
            for right in &plan.files[left_index + 1..] {
                ensure!(
                    !paths_alias(&plan.files[left_index].path, &right.path),
                    "输出 `{}` 与 `{}` 指向同一路径 {}",
                    plan.files[left_index].role,
                    right.role,
                    right.path.display()
                );
            }
        }
        for left_index in 0..plan.directories.len() {
            for right in &plan.directories[left_index + 1..] {
                ensure!(
                    !paths_alias(&plan.directories[left_index], right),
                    "多个目录输出指向同一路径 {}",
                    right.display()
                );
            }
        }
        for file in &plan.files {
            for directory in &plan.directories {
                ensure!(
                    !paths_alias(&file.path, directory),
                    "文件输出 {} 与目录输出指向同一路径",
                    file.path.display()
                );
            }
        }

        Ok(plan)
    }

    /// Create registered directory roots without deleting pre-existing content.
    pub fn prepare_directories(&self) -> Result<()> {
        let plan = self.preflight()?;
        for directory in &plan.directories {
            fs::create_dir_all(directory)
                .with_context(|| format!("无法创建输出目录 {}", directory.display()))?;
            // Resolve again after creation so a newly traversed symlink cannot redirect output
            // into a protected input directory.
            self.ensure_not_protected(directory, true)?;
        }
        Ok(())
    }

    /// Atomically publish a registered output file.
    ///
    /// The callback writes only to a unique same-directory staging file.  StarMem flushes and
    /// synchronizes it, rechecks the final target, renames it, and synchronizes the parent
    /// directory.  A callback or publication failure automatically removes the staging file.
    pub fn write_file_atomic<F>(&self, target: &Path, write: F) -> Result<()>
    where
        F: FnOnce(&mut File) -> Result<()>,
    {
        self.write_file_atomic_validated(target, write, |_| Ok(()))
    }

    /// Atomically publish a registered output only after validating the synchronized staging
    /// file.
    ///
    /// This is intended for evidence and cache formats whose identity cannot be established
    /// until the complete file has been written (for example PDB and ISF files).  Validation
    /// happens after `flush`/`sync_all` and before the repeated protected-path check and final
    /// rename.  A validation failure therefore leaves any prior destination untouched and the
    /// staging file is removed automatically.
    pub fn write_file_atomic_validated<F, V>(
        &self,
        target: &Path,
        write: F,
        validate: V,
    ) -> Result<()>
    where
        F: FnOnce(&mut File) -> Result<()>,
        V: FnOnce(&Path) -> Result<()>,
    {
        self.ensure_registered_file(target, OutputWriteMode::AtomicReplace)?;
        let publication_target = comparable_path(target);
        self.ensure_registered_file(&publication_target, OutputWriteMode::AtomicReplace)?;
        self.ensure_not_protected(&publication_target, false)?;
        self.ensure_replaceable(&publication_target)?;

        let parent = normalized_parent(&publication_target)?;
        fs::create_dir_all(&parent)
            .with_context(|| format!("无法创建输出目录 {}", parent.display()))?;
        self.ensure_not_protected(&publication_target, false)?;
        self.ensure_replaceable(&publication_target)?;

        let (staged_path, mut staged_file) = create_staging_file(&parent, &publication_target)?;
        let mut staged = StagingGuard::new(staged_path);
        let write_result = (|| -> Result<()> {
            write(&mut staged_file)?;
            staged_file
                .flush()
                .with_context(|| format!("无法刷新临时输出 {}", staged.path().display()))?;
            staged_file
                .sync_all()
                .with_context(|| format!("无法同步临时输出 {}", staged.path().display()))?;
            Ok(())
        })();
        drop(staged_file);
        write_result?;
        validate(staged.path())
            .with_context(|| format!("临时输出在发布前校验失败 {}", staged.path().display()))?;

        // Library-level publication check.  This intentionally repeats preflight after all
        // potentially fallible analysis and staging work.
        self.ensure_registered_file(&publication_target, OutputWriteMode::AtomicReplace)?;
        self.ensure_not_protected(&publication_target, false)?;
        self.ensure_replaceable(&publication_target)?;
        replace_file_atomically(staged.path(), &publication_target, self.force)
            .with_context(|| format!("无法原子发布输出文件 {}", publication_target.display()))?;
        staged.disarm();
        sync_directory(&parent)
            .with_context(|| format!("无法同步输出目录 {}", parent.display()))?;
        Ok(())
    }

    pub fn write_bytes_atomic(&self, target: &Path, bytes: &[u8]) -> Result<()> {
        self.write_file_atomic(target, |file| {
            file.write_all(bytes)
                .with_context(|| format!("无法写入输出文件 {}", target.display()))?;
            Ok(())
        })
    }

    /// Recheck an append/update target and all of its registered peers immediately before an
    /// external transactional writer (normally SQLite) opens it.
    ///
    /// Append targets deliberately bypass [`Self::write_file_atomic`], because replacing an
    /// existing SQLite database would destroy prior collection runs.  The returned path has a
    /// canonicalized existing ancestor and is suitable for passing to the writer.
    pub fn recheck_append_file(&self, target: &Path) -> Result<PathBuf> {
        self.ensure_registered_file(target, OutputWriteMode::Append)?;
        self.preflight()?;
        let target = comparable_path(target);
        self.ensure_registered_file(&target, OutputWriteMode::Append)?;
        self.ensure_not_protected(&target, false)?;
        self.ensure_appendable(&target)?;
        Ok(target)
    }

    /// Remove one explicitly registered ordinary output owned by this command.
    ///
    /// This is intentionally narrower than recursive cleanup: it requires `--force`, repeats
    /// the complete plan and protected-input checks, rejects links and non-regular files, and
    /// synchronizes the containing directory after deletion.
    pub fn remove_owned_file(&self, target: &Path) -> Result<bool> {
        ensure!(self.force, "删除旧输出 {} 需要 --force", target.display());
        self.ensure_registered_file(target, OutputWriteMode::AtomicReplace)?;
        self.preflight()?;
        self.ensure_not_protected(target, false)?;
        let Some(metadata) = symlink_metadata_if_present(target)? else {
            return Ok(false);
        };
        ensure!(
            metadata.file_type().is_file() && !metadata.file_type().is_symlink(),
            "只能删除已声明的普通输出文件，拒绝 {}",
            target.display()
        );
        // Repeat the protected-input check immediately before the destructive operation.
        self.ensure_registered_file(target, OutputWriteMode::AtomicReplace)?;
        self.ensure_not_protected(target, false)?;
        fs::remove_file(target).with_context(|| format!("无法删除旧输出 {}", target.display()))?;
        sync_directory(&normalized_parent(target)?)
            .with_context(|| format!("无法同步输出目录 {}", target.display()))?;
        Ok(true)
    }

    fn expand_plan(&self) -> Result<ValidatedOutputPlan> {
        let mut files = Vec::new();
        let mut directories = Vec::new();
        for target in &self.outputs {
            match target {
                OutputTarget::File {
                    role,
                    path,
                    derived,
                    mode,
                } => {
                    files.push(PlannedOutputFile {
                        role: role.clone(),
                        path: path.clone(),
                        mode: *mode,
                    });
                    files.extend(derived.iter().enumerate().map(|(index, derived)| {
                        PlannedOutputFile {
                            role: format!("{role}.derived[{index}]"),
                            path: derived.resolve(path),
                            mode: *mode,
                        }
                    }));
                }
                OutputTarget::Directory {
                    role,
                    root,
                    owned_files,
                } => {
                    directories.push(root.clone());
                    for relative in owned_files {
                        let relative = validated_relative_path(relative).with_context(|| {
                            format!(
                                "目录输出 `{role}` 包含非法 owned file {}",
                                relative.display()
                            )
                        })?;
                        files.push(PlannedOutputFile {
                            role: format!("{role}.owned"),
                            path: root.join(relative),
                            mode: OutputWriteMode::AtomicReplace,
                        });
                    }
                }
            }
        }
        Ok(ValidatedOutputPlan { files, directories })
    }

    fn ensure_registered_file(&self, target: &Path, mode: OutputWriteMode) -> Result<()> {
        let plan = self.expand_plan()?;
        ensure!(
            plan.files
                .iter()
                .any(|planned| planned.mode == mode && paths_alias(&planned.path, target)),
            "拒绝以 {:?} 模式写入未在 OutputPolicy 中声明的输出 {}",
            mode,
            target.display(),
        );
        Ok(())
    }

    fn ensure_allowed_for_mode(&self, path: &Path, mode: OutputWriteMode) -> Result<()> {
        match mode {
            OutputWriteMode::AtomicReplace => self.ensure_replaceable(path),
            OutputWriteMode::Append => self.ensure_appendable(path),
        }
    }

    fn ensure_not_protected(&self, output: &Path, _output_is_directory: bool) -> Result<()> {
        for input in &self.protected_inputs {
            let conflict = match input.kind {
                ProtectedPathKind::File => paths_alias(output, &input.path),
                ProtectedPathKind::Directory => path_is_within(output, &input.path),
            };
            ensure!(
                !conflict,
                "输出 {} 与受保护输入 `{}` ({}) 冲突；--force 永不允许覆盖输入",
                output.display(),
                input.role,
                input.path.display()
            );
        }
        Ok(())
    }

    fn ensure_replaceable(&self, path: &Path) -> Result<()> {
        let Some(metadata) = symlink_metadata_if_present(path)? else {
            return Ok(());
        };
        if !self.force {
            bail!(
                "输出 {} 已存在；使用 --force 明确允许替换普通输出文件",
                path.display()
            );
        }
        ensure!(
            metadata.file_type().is_file() && !metadata.file_type().is_symlink(),
            "--force 只能替换普通输出文件，拒绝替换 {}",
            path.display()
        );
        Ok(())
    }

    fn ensure_appendable(&self, path: &Path) -> Result<()> {
        let Some(metadata) = symlink_metadata_if_present(path)? else {
            return Ok(());
        };
        ensure!(
            metadata.file_type().is_file() && !metadata.file_type().is_symlink(),
            "Append 模式只能更新普通文件，拒绝使用 {}",
            path.display()
        );
        Ok(())
    }
}

/// Return true when two paths identify the same directory entry or file.
///
/// Existing hard links and symlinks are detected through filesystem identity.  Non-existing
/// paths are compared after absolutizing, lexically normalizing, and canonicalizing the nearest
/// existing ancestor.  Windows and macOS comparisons additionally reject case-only aliases.
pub fn paths_alias(left: &Path, right: &Path) -> bool {
    if matches!(same_file::is_same_file(left, right), Ok(true)) {
        return true;
    }
    comparable_paths_equal(&comparable_path(left), &comparable_path(right))
}

/// Return true when `candidate` is equal to or located below `directory`.
pub fn path_is_within(candidate: &Path, directory: &Path) -> bool {
    let candidate = comparable_path(candidate);
    let directory = comparable_path(directory);
    let candidate = comparable_components(&candidate);
    let directory = comparable_components(&directory);
    candidate.len() >= directory.len()
        && candidate
            .iter()
            .zip(directory.iter())
            .all(|(left, right)| left == right)
}

pub fn append_path_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

pub fn sqlite_sidecar_paths(path: &Path) -> [PathBuf; 3] {
    SQLITE_SIDECAR_SUFFIXES.map(|suffix| append_path_suffix(path, suffix))
}

fn validate_directory_root(path: &Path) -> Result<()> {
    if let Some(metadata) = symlink_metadata_if_present(path)? {
        if metadata.file_type().is_symlink() {
            let followed = fs::metadata(path)
                .with_context(|| format!("无法读取目录符号链接 {}", path.display()))?;
            ensure!(
                followed.is_dir(),
                "输出目录路径不是目录：{}",
                path.display()
            );
        } else {
            ensure!(
                metadata.is_dir(),
                "输出目录路径不是目录：{}",
                path.display()
            );
        }
    }
    Ok(())
}

fn validated_relative_path(path: &Path) -> Result<PathBuf> {
    ensure!(!path.as_os_str().is_empty(), "owned file 不能为空");
    ensure!(!path.is_absolute(), "owned file 必须是相对路径");
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(value) => normalized.push(value),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                bail!("owned file 不得包含父目录或路径根")
            }
        }
    }
    ensure!(!normalized.as_os_str().is_empty(), "owned file 不能为空");
    Ok(normalized)
}

fn normalized_parent(path: &Path) -> Result<PathBuf> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    Ok(comparable_path(parent))
}

fn symlink_metadata_if_present(path: &Path) -> Result<Option<fs::Metadata>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("无法检查输出路径 {}", path.display())),
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
    let normalized = lexical_normalize(&absolute);

    let mut existing = normalized.as_path();
    let mut suffix = Vec::<OsString>::new();
    loop {
        if let Ok(canonical) = fs::canonicalize(existing) {
            let mut resolved = canonical;
            for component in suffix.iter().rev() {
                resolved.push(component);
            }
            return resolved;
        }
        let Some(name) = existing.file_name() else {
            return normalized;
        };
        suffix.push(name.to_os_string());
        let Some(parent) = existing.parent() else {
            return normalized;
        };
        existing = parent;
    }
}

fn lexical_normalize(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                let _ = normalized.pop();
            }
            Component::Normal(value) => normalized.push(value),
        }
    }
    normalized
}

fn comparable_paths_equal(left: &Path, right: &Path) -> bool {
    comparable_components(left) == comparable_components(right)
}

fn comparable_components(path: &Path) -> Vec<String> {
    path.components()
        .map(|component| comparable_component(component.as_os_str()))
        .collect()
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
fn comparable_component(value: &std::ffi::OsStr) -> String {
    value.to_string_lossy().to_lowercase()
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn comparable_component(value: &std::ffi::OsStr) -> String {
    value.to_string_lossy().into_owned()
}

fn create_staging_file(parent: &Path, target: &Path) -> Result<(PathBuf, File)> {
    let file_name = target
        .file_name()
        .context("输出路径缺少文件名")?
        .to_string_lossy();
    for attempt in 0..4096u32 {
        let candidate = parent.join(format!(
            ".{file_name}.starmem-{}-{attempt}.tmp",
            std::process::id()
        ));
        match OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&candidate)
        {
            Ok(file) => return Ok((candidate, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("无法在 {} 创建同目录临时文件", parent.display()));
            }
        }
    }
    bail!("无法为输出 {} 分配唯一临时文件", target.display())
}

fn replace_file_atomically(staged: &Path, target: &Path, force: bool) -> io::Result<()> {
    if !force || symlink_metadata_if_present_io(target)?.is_none() {
        return fs::rename(staged, target);
    }

    #[cfg(not(windows))]
    {
        fs::rename(staged, target)
    }

    #[cfg(windows)]
    {
        replace_file_windows(staged, target)
    }
}

fn symlink_metadata_if_present_io(path: &Path) -> io::Result<Option<fs::Metadata>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

#[cfg(windows)]
fn replace_file_windows(staged: &Path, target: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;

    #[link(name = "Kernel32")]
    unsafe extern "system" {
        fn ReplaceFileW(
            replaced_file_name: *const u16,
            replacement_file_name: *const u16,
            backup_file_name: *const u16,
            replace_flags: u32,
            exclude: *mut std::ffi::c_void,
            reserved: *mut std::ffi::c_void,
        ) -> i32;
    }

    let target: Vec<u16> = target.as_os_str().encode_wide().chain(Some(0)).collect();
    let staged: Vec<u16> = staged.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: both strings are NUL-terminated and remain alive for the duration of the call;
    // optional pointers are null.  Staging and destination are in the same directory.
    let replaced = unsafe {
        ReplaceFileW(
            target.as_ptr(),
            staged.as_ptr(),
            std::ptr::null(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if replaced == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> io::Result<()> {
    // Windows ReplaceFileW durably switches the directory entry after the staged file itself
    // has been synchronized.  std does not expose a portable directory handle for sync_all.
    Ok(())
}

struct StagingGuard {
    path: PathBuf,
    armed: bool,
}

impl StagingGuard {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for StagingGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "starmem-output-policy-{label}-{}-{nonce}",
                std::process::id()
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn rejects_relative_alias_of_protected_input_even_with_force() {
        let directory = TestDirectory::new("relative");
        let input = directory.path().join("memory.raw");
        fs::write(&input, b"evidence").unwrap();
        let output = directory.path().join("nested/../memory.raw");
        fs::create_dir(directory.path().join("nested")).unwrap();

        let mut policy = OutputPolicy::new(true);
        policy.protect_file("memory_image", &input);
        policy.output_file("json", output);
        assert!(policy.preflight().is_err());
        assert_eq!(fs::read(input).unwrap(), b"evidence");
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_and_hard_link_aliases() {
        use std::os::unix::fs::symlink;

        let directory = TestDirectory::new("links");
        let input = directory.path().join("memory.raw");
        let symlink_path = directory.path().join("report.json");
        let hard_link = directory.path().join("report.csv");
        fs::write(&input, b"evidence").unwrap();
        symlink(&input, &symlink_path).unwrap();
        fs::hard_link(&input, &hard_link).unwrap();

        for output in [symlink_path, hard_link] {
            let mut policy = OutputPolicy::new(true);
            policy.protect_file("memory_image", &input);
            policy.output_file("report", output);
            assert!(policy.preflight().is_err());
        }
        assert_eq!(fs::read(input).unwrap(), b"evidence");
    }

    #[cfg(any(target_os = "windows", target_os = "macos"))]
    #[test]
    fn rejects_case_only_aliases_on_case_folding_platforms() {
        let directory = TestDirectory::new("case");
        let input = directory.path().join("Evidence.RAW");
        let output = directory.path().join("evidence.raw");
        let mut policy = OutputPolicy::new(true);
        policy.protect_file("memory_image", input);
        policy.output_file("report", output);
        assert!(policy.preflight().is_err());
    }

    #[test]
    fn protected_directory_rejects_descendant_outputs() {
        let directory = TestDirectory::new("protected-dir");
        let event_logs = directory.path().join("event-logs");
        fs::create_dir(&event_logs).unwrap();
        let mut policy = OutputPolicy::new(true);
        policy.protect_directory("event_log_directory", &event_logs);
        policy.output_file("timeline", event_logs.join("timeline.json"));
        assert!(policy.preflight().is_err());
    }

    #[test]
    fn default_refuses_existing_output_and_force_replaces_regular_file() {
        let directory = TestDirectory::new("force");
        let output = directory.path().join("report.json");
        fs::write(&output, b"old").unwrap();

        let mut default_policy = OutputPolicy::new(false);
        default_policy.output_file("report", &output);
        assert!(default_policy.preflight().is_err());

        let mut force_policy = OutputPolicy::new(true);
        force_policy.output_file("report", &output);
        force_policy.preflight().unwrap();
        force_policy.write_bytes_atomic(&output, b"new").unwrap();
        assert_eq!(fs::read(output).unwrap(), b"new");
    }

    #[test]
    fn directory_force_preserves_unowned_files() {
        let directory = TestDirectory::new("owned");
        let output_root = directory.path().join("recovery");
        fs::create_dir(&output_root).unwrap();
        let unrelated = output_root.join("analyst-notes.txt");
        let owned = output_root.join("manifest.json");
        fs::write(&unrelated, b"keep").unwrap();
        fs::write(&owned, b"old").unwrap();

        let mut policy = OutputPolicy::new(true);
        policy.output(
            OutputTarget::directory("recovery", &output_root).with_owned_file("manifest.json"),
        );
        policy.write_bytes_atomic(&owned, b"new").unwrap();
        assert_eq!(fs::read(unrelated).unwrap(), b"keep");
        assert_eq!(fs::read(owned).unwrap(), b"new");
    }

    #[test]
    fn owned_file_removal_requires_force_and_preserves_unowned_files() {
        let directory = TestDirectory::new("owned-removal");
        let output_root = directory.path().join("recovery");
        fs::create_dir(&output_root).unwrap();
        let unrelated = output_root.join("analyst-notes.txt");
        let owned = output_root.join("stale.partial");
        fs::write(&unrelated, b"keep").unwrap();
        fs::write(&owned, b"stale").unwrap();

        let target =
            OutputTarget::directory("recovery", &output_root).with_owned_file("stale.partial");
        let mut default_policy = OutputPolicy::new(false);
        default_policy.output(target.clone());
        assert!(default_policy.remove_owned_file(&owned).is_err());

        let mut force_policy = OutputPolicy::new(true);
        force_policy.output(target);
        assert!(force_policy.remove_owned_file(&owned).unwrap());
        assert!(!owned.exists());
        assert_eq!(fs::read(unrelated).unwrap(), b"keep");
    }

    #[test]
    fn rejects_owned_path_that_escapes_directory() {
        let directory = TestDirectory::new("escape");
        let mut policy = OutputPolicy::new(true);
        policy.output(
            OutputTarget::directory("recovery", directory.path()).with_owned_file("../image.raw"),
        );
        assert!(policy.preflight().is_err());
    }

    #[test]
    fn derived_outputs_are_checked_against_inputs_and_each_other() {
        let directory = TestDirectory::new("derived");
        let input = directory.path().join("dump.raw.partial");
        let output = directory.path().join("dump.raw");
        let mut policy = OutputPolicy::new(false);
        policy.protect_file("memory_image", input);
        policy.output(
            OutputTarget::file("dump", output)
                .with_sibling_suffix(".partial")
                .with_extension("json"),
        );
        assert!(policy.preflight().is_err());
    }

    #[test]
    fn sqlite_sidecars_are_explicitly_planned() {
        let directory = TestDirectory::new("sqlite");
        let database = directory.path().join("evidence.sqlite");
        let mut policy = OutputPolicy::new(false);
        policy.output(OutputTarget::file("sqlite", &database).with_sqlite_sidecars());
        let plan = policy.preflight().unwrap();
        assert_eq!(plan.files.len(), 4);
        assert!(
            plan.files
                .iter()
                .any(|file| file.path == append_path_suffix(&database, "-wal"))
        );
    }

    #[test]
    fn append_mode_accepts_an_existing_regular_database_and_sidecars() {
        let directory = TestDirectory::new("append-existing");
        let database = directory.path().join("collection.sqlite");
        let wal = append_path_suffix(&database, "-wal");
        fs::write(&database, b"existing database").unwrap();
        fs::write(&wal, b"existing wal").unwrap();

        let mut policy = OutputPolicy::new(false);
        policy.output(OutputTarget::append_file("collect", &database).with_sqlite_sidecars());
        let plan = policy.preflight().unwrap();
        assert!(
            plan.files
                .iter()
                .all(|file| file.mode == OutputWriteMode::Append)
        );
        let checked = policy.recheck_append_file(&database).unwrap();
        assert!(paths_alias(&checked, &database));
        assert!(policy.write_bytes_atomic(&database, b"replace").is_err());
        assert_eq!(fs::read(database).unwrap(), b"existing database");
    }

    #[test]
    fn append_mode_rejects_database_or_sidecar_aliasing_protected_input() {
        let directory = TestDirectory::new("append-protected");
        let input = directory.path().join("memory.raw");
        fs::write(&input, b"evidence").unwrap();

        let database_alias = directory.path().join("collection.sqlite");
        fs::hard_link(&input, &database_alias).unwrap();
        let mut database_policy = OutputPolicy::new(true);
        database_policy.protect_file("memory_image", &input);
        database_policy
            .output(OutputTarget::append_file("collect", &database_alias).with_sqlite_sidecars());
        assert!(database_policy.preflight().is_err());

        fs::remove_file(&database_alias).unwrap();
        fs::write(&database_alias, b"database").unwrap();
        let wal_alias = append_path_suffix(&database_alias, "-wal");
        fs::hard_link(&input, &wal_alias).unwrap();
        let mut sidecar_policy = OutputPolicy::new(true);
        sidecar_policy.protect_file("memory_image", &input);
        sidecar_policy
            .output(OutputTarget::append_file("collect", &database_alias).with_sqlite_sidecars());
        assert!(sidecar_policy.preflight().is_err());
        assert_eq!(fs::read(input).unwrap(), b"evidence");
    }

    #[test]
    fn append_mode_rejects_non_regular_targets() {
        let directory = TestDirectory::new("append-non-regular");
        let database = directory.path().join("collection.sqlite");
        fs::create_dir(&database).unwrap();
        let mut policy = OutputPolicy::new(true);
        policy.output(OutputTarget::append_file("collect", &database).with_sqlite_sidecars());
        assert!(policy.preflight().is_err());
        assert!(policy.recheck_append_file(&database).is_err());
    }

    #[test]
    fn failed_atomic_writer_removes_staging_file() {
        let directory = TestDirectory::new("cleanup");
        let output = directory.path().join("report.json");
        let mut policy = OutputPolicy::new(false);
        policy.output_file("report", &output);
        let error = policy
            .write_file_atomic(&output, |file| {
                file.write_all(b"partial")?;
                bail!("synthetic failure")
            })
            .unwrap_err();
        assert!(error.to_string().contains("synthetic failure"));
        assert!(!output.exists());
        let entries = fs::read_dir(directory.path()).unwrap().count();
        assert_eq!(entries, 0);
    }

    #[test]
    fn failed_atomic_validator_preserves_destination_and_removes_staging_file() {
        let directory = TestDirectory::new("validator-cleanup");
        let output = directory.path().join("symbol.pdb");
        fs::write(&output, b"known-good").unwrap();
        let mut policy = OutputPolicy::new(true);
        policy.output_file("symbol", &output);

        let error = policy
            .write_file_atomic_validated(
                &output,
                |file| {
                    file.write_all(b"bad-download")?;
                    Ok(())
                },
                |staged| {
                    assert_eq!(fs::read(staged)?, b"bad-download");
                    bail!("synthetic identity mismatch")
                },
            )
            .unwrap_err();
        assert!(error.to_string().contains("发布前校验失败"));
        assert_eq!(fs::read(&output).unwrap(), b"known-good");
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[test]
    fn refuses_unregistered_library_write() {
        let directory = TestDirectory::new("unregistered");
        let planned = directory.path().join("planned.json");
        let surprise = directory.path().join("surprise.json");
        let mut policy = OutputPolicy::new(false);
        policy.output_file("report", planned);
        assert!(policy.write_bytes_atomic(&surprise, b"no").is_err());
        assert!(!surprise.exists());
    }
}
