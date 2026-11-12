//! Linux System.map contains addresses, not structure layouts. Keep its identity
//! separate from ISF and require runtime validation before using these addresses.
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use serde::Serialize;
use sha2::{Digest, Sha256};

const MAX_BYTES: u64 = 64 * 1024 * 1024;
const REQUIRED: &[&str] = &["linux_banner", "init_task", "_stext"];
pub(crate) const PAGE_TABLE_SYMBOLS: &[&str] =
    &["init_top_pgt", "init_level4_pgt", "swapper_pg_dir"];

#[derive(Debug, Clone, Serialize)]
pub struct LinuxSystemMapIdentity {
    pub sha256: String,
    pub symbol_count: usize,
}

#[derive(Debug)]
pub struct LinuxSystemMap {
    pub path: PathBuf,
    pub identity: LinuxSystemMapIdentity,
    symbols: BTreeMap<String, u64>,
}

impl LinuxSystemMap {
    pub fn load(path: &Path) -> Result<Self> {
        let file =
            File::open(path).with_context(|| format!("无法打开 System.map：{}", path.display()))?;
        ensure!(file.metadata()?.is_file(), "System.map 必须是普通文件");
        let mut bytes = Vec::new();
        file.take(MAX_BYTES + 1).read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 <= MAX_BYTES,
            "System.map 超过 64 MiB 上限"
        );
        Self::parse(path, &bytes)
    }

    fn parse(path: &Path, bytes: &[u8]) -> Result<Self> {
        let text = std::str::from_utf8(bytes)
            .context("System.map 必须是 UTF-8/ASCII 文本；压缩包请先解压")?;
        let mut symbols = BTreeMap::new();
        let mut ambiguous = BTreeSet::new();
        for (index, line) in text.trim_start_matches('\u{feff}').lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
            ensure!(
                fields.len() == 3
                    && fields[1].len() == 1
                    && fields[1].as_bytes()[0].is_ascii_alphabetic(),
                "System.map 第 {} 行不是“十六进制地址 类型 符号名”",
                index + 1
            );
            let address = u64::from_str_radix(fields[0], 16)
                .with_context(|| format!("System.map 第 {} 行地址无效", index + 1))?;
            if let Some(previous) = symbols.insert(fields[2].to_owned(), address)
                && previous != address
            {
                ambiguous.insert(fields[2].to_owned());
            }
        }
        // Local symbols can legitimately repeat; never select an arbitrary address.
        for name in ambiguous {
            symbols.remove(&name);
        }
        for name in REQUIRED {
            ensure!(
                symbols
                    .get(*name)
                    .is_some_and(|address| *address >= 0xffff_8000_0000_0000),
                "System.map 缺少唯一的 x86-64 内核符号 {name}"
            );
        }
        ensure!(
            PAGE_TABLE_SYMBOLS.iter().any(|name| symbols
                .get(*name)
                .is_some_and(|address| *address >= 0xffff_8000_0000_0000 && address & 0xfff == 0)),
            "System.map 缺少 x86-64 内核页表符号 init_top_pgt / init_level4_pgt / swapper_pg_dir"
        );
        Ok(Self {
            path: path.to_owned(),
            identity: LinuxSystemMapIdentity {
                sha256: hex::encode(Sha256::digest(bytes)),
                symbol_count: symbols.len(),
            },
            symbols,
        })
    }

    pub fn address(&self, name: &str) -> Option<u64> {
        self.symbols.get(name).copied()
    }

    pub(crate) fn symbols(&self) -> impl Iterator<Item = (&str, u64)> {
        self.symbols
            .iter()
            .map(|(name, address)| (name.as_str(), *address))
    }
}

/// Version suffixes such as System.map-3.10.0-123.el7.x86_64 are not extensions.
pub fn is_system_map_path(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    name == "system.map" || name.starts_with("system.map-") || name.ends_with(".map")
}

#[cfg(test)]
mod tests {
    use super::*;
    const MAP: &str = "ffffffff81000000 T _stext\nffffffff81500000 R linux_banner\nffffffff81800000 D init_task\nffffffff81900000 D init_level4_pgt\n";

    #[test]
    fn parses_versioned_maps_and_keeps_full_width_addresses() {
        let path = Path::new("System.map-3.10.0-123.el7.x86_64");
        assert!(is_system_map_path(path));
        let table = LinuxSystemMap::parse(path, MAP.as_bytes()).unwrap();
        assert_eq!(table.address("init_task"), Some(0xffff_ffff_8180_0000));
        assert_eq!(table.identity.symbol_count, 4);
    }

    #[test]
    fn rejects_malformed_missing_ambiguous_and_32bit_anchors() {
        for value in [
            "garbage".to_owned(),
            MAP.replace("linux_banner", "other"),
            format!("{MAP}ffffffff81801000 D init_task\n"),
            MAP.replace("ffffffff81500000", "c1500000"),
        ] {
            assert!(LinuxSystemMap::parse(Path::new("System.map"), value.as_bytes()).is_err());
        }
        let repeated = format!("{MAP}ffffffff81001000 t local\nffffffff81002000 t local\n");
        let table = LinuxSystemMap::parse(Path::new("System.map"), repeated.as_bytes()).unwrap();
        assert_eq!(table.address("local"), None);
        assert_ne!(
            table.identity.sha256,
            LinuxSystemMap::parse(Path::new("System.map"), MAP.as_bytes())
                .unwrap()
                .identity
                .sha256
        );
    }
}
