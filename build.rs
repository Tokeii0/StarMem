use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn collect_sources(path: &Path, files: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(path) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            collect_sources(&path, files);
        } else if file_type.is_file()
            && path.extension().is_some_and(|extension| extension == "rs")
            && !path
                .file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with("._"))
        {
            files.push(path);
        }
    }
}

fn main() {
    let manifest_dir = PathBuf::from(
        std::env::var_os("CARGO_MANIFEST_DIR").expect("Cargo 必须提供 CARGO_MANIFEST_DIR"),
    );
    let crate_lock = manifest_dir.join("Cargo.lock");
    let original_manifest = manifest_dir.join("Cargo.toml.orig");
    let source_manifest = if original_manifest.is_file() {
        original_manifest.clone()
    } else {
        manifest_dir.join("Cargo.toml")
    };

    println!("cargo:rerun-if-changed=Cargo.toml");
    // 源码快照可能没有 Cargo.toml.orig；监听不存在的文件会导致每次构建都失效。
    if original_manifest.is_file() {
        println!("cargo:rerun-if-changed=Cargo.toml.orig");
    }
    println!("cargo:rerun-if-changed={}", crate_lock.display());
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=benchmarks/command-equivalence.json");
    println!("cargo:rerun-if-changed=metadata/leaf-command-manifest.json");
    println!("cargo:rerun-if-env-changed=STARMEM_GIT_COMMIT");
    println!("cargo:rerun-if-env-changed=STARMEM_GIT_DIRTY");

    let mut files = vec![source_manifest.clone(), manifest_dir.join("build.rs")];
    files.extend([
        manifest_dir.join("benchmarks/command-equivalence.json"),
        manifest_dir.join("metadata/leaf-command-manifest.json"),
    ]);
    collect_sources(&manifest_dir.join("src"), &mut files);
    files.sort();

    let mut digest = Sha256::new();
    for path in files {
        let bytes = fs::read(&path)
            .unwrap_or_else(|error| panic!("无法读取构建输入 {}: {error}", path.display()));
        let name = if path == source_manifest {
            "Cargo.toml".to_owned()
        } else {
            path.strip_prefix(&manifest_dir)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/")
        };
        digest.update((name.len() as u64).to_le_bytes());
        digest.update(name.as_bytes());
        digest.update((bytes.len() as u64).to_le_bytes());
        digest.update(bytes);
    }
    digest.update(b"starmem-Cargo.lock");
    match fs::read(&crate_lock) {
        Ok(lock_bytes) => {
            digest.update((lock_bytes.len() as u64).to_le_bytes());
            digest.update(lock_bytes);
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            digest.update(b"absent");
        }
        Err(error) => panic!("无法读取 StarMem Cargo.lock: {error}"),
    }
    let build_id = digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    println!("cargo:rustc-env=STARMEM_BUILD_ID={build_id}");

    let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown".to_owned());
    println!("cargo:rustc-env=STARMEM_RUST_TARGET={target}");
    let mut features = std::env::vars()
        .filter_map(|(name, value)| {
            (value == "1")
                .then(|| name.strip_prefix("CARGO_FEATURE_").map(str::to_owned))
                .flatten()
        })
        .collect::<Vec<_>>();
    features.sort();
    println!("cargo:rustc-env=STARMEM_FEATURES={}", features.join(","));

    let git_commit = std::env::var("STARMEM_GIT_COMMIT")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| crate_git_output(&manifest_dir, &["rev-parse", "HEAD"]));
    let git_dirty = match std::env::var("STARMEM_GIT_DIRTY") {
        Ok(value) if matches!(value.as_str(), "true" | "false") => Some(value),
        Ok(value) => panic!("STARMEM_GIT_DIRTY 必须是 true 或 false，实际为 {value:?}"),
        Err(std::env::VarError::NotPresent) => crate_git_output(
            &manifest_dir,
            &["status", "--porcelain", "--untracked-files=normal"],
        )
        .map(|status| (!status.is_empty()).to_string()),
        Err(std::env::VarError::NotUnicode(_)) => {
            panic!("STARMEM_GIT_DIRTY 必须是 UTF-8 字符串")
        }
    };
    println!(
        "cargo:rustc-env=STARMEM_GIT_COMMIT={}",
        git_commit.as_deref().unwrap_or("")
    );
    println!(
        "cargo:rustc-env=STARMEM_GIT_DIRTY={}",
        git_dirty.as_deref().unwrap_or("unknown")
    );
}

fn crate_git_output(manifest_dir: &Path, arguments: &[&str]) -> Option<String> {
    // Cargo 在构建 path/vendor 依赖时会把构建脚本放进宿主工作区执行。
    // 只有 StarMem crate 根本身拥有 Git 元数据时才允许读取，避免向上穿透到宿主仓库。
    if !manifest_dir.join(".git").exists() {
        return None;
    }
    let top_level = git_output(manifest_dir, &["rev-parse", "--show-toplevel"])?;
    if !same_directory(manifest_dir, Path::new(&top_level)) {
        return None;
    }
    git_output(manifest_dir, arguments)
}

fn git_output(current_dir: &Path, arguments: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .args(arguments)
        .current_dir(current_dir)
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .env_remove("GIT_COMMON_DIR")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn same_directory(left: &Path, right: &Path) -> bool {
    match (left.canonicalize(), right.canonicalize()) {
        (Ok(left), Ok(right)) => left == right,
        _ => left == right,
    }
}
