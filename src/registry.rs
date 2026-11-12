use std::collections::HashSet;
use std::ops::Range;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use crate::cancellation::CancellationToken;
use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;

/// Opt-in, shared limits for decoders consuming untrusted recovered Hive bytes.
#[derive(Debug, Clone)]
pub(crate) struct RegistryReadGuard {
    cancel: CancellationToken,
    cells: Arc<AtomicU64>,
    bytes: Arc<AtomicU64>,
    max_cells: u64,
    max_bytes: u64,
}

impl RegistryReadGuard {
    pub(crate) fn new(cancel: &CancellationToken, max_cells: u64, max_bytes: u64) -> Self {
        Self {
            cancel: cancel.clone(),
            cells: Arc::new(AtomicU64::new(0)),
            bytes: Arc::new(AtomicU64::new(0)),
            max_cells,
            max_bytes,
        }
    }
    pub(crate) fn check(&self) -> Result<()> {
        self.cancel.check_cancelled()?;
        ensure!(
            self.cells.load(Ordering::Relaxed) <= self.max_cells
                && self.bytes.load(Ordering::Relaxed) <= self.max_bytes,
            "STARMEM_REGISTRY_BUDGET: 注册表解析达到单元访问或累计字节预算"
        );
        Ok(())
    }
    fn charge(&self, cells: u64, bytes: usize) -> Result<()> {
        self.check()?;
        self.cells.fetch_add(cells, Ordering::Relaxed);
        self.bytes.fetch_add(bytes as u64, Ordering::Relaxed);
        self.check()
    }
}

const HIVE_BIN_BASE: usize = 0x1000;
const INVALID_CELL: u32 = u32::MAX;
const KEY_COMP_NAME: u16 = 0x20;
const VALUE_COMP_NAME: u16 = 0x1;
const MAX_LIST_DEPTH: usize = 32;
const MAX_ITEMS: usize = 1_000_000;

#[derive(Debug, Clone)]
pub struct RegistryHive {
    bytes: Vec<u8>,
    root_cell: u32,
    recovered_ranges: Option<Vec<Range<usize>>>,
    read_guard: Option<RegistryReadGuard>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RegistryKey {
    pub cell_index: u32,
    pub name: String,
    pub last_write_raw: u64,
    pub flags: u16,
}

#[derive(Debug, Clone, Serialize)]
pub struct RegistryValue {
    pub cell_index: u32,
    pub name: String,
    pub data_type: u32,
    pub data: RegistryValueData,
    #[serde(skip)]
    raw_data: Vec<u8>,
}

#[derive(Debug)]
pub struct RegistrySubkeyEnumeration {
    pub keys: Vec<RegistryKey>,
    pub warnings: Vec<String>,
}

#[derive(Debug)]
pub struct RegistryKeyLookup {
    pub key: Option<RegistryKey>,
    pub warnings: Vec<String>,
}

#[derive(Debug)]
pub struct RegistryValueEnumeration {
    pub values: Vec<RegistryValue>,
    pub declared_count: u32,
    pub listed_count: usize,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum RegistryValueData {
    None,
    String(String),
    MultiString(Vec<String>),
    Binary(String),
    Dword(u32),
    Qword(u64),
    Unknown(String),
}

#[derive(Debug)]
struct KeyNode {
    key: RegistryKey,
    subkey_count: u32,
    subkey_list: u32,
    value_count: u32,
    value_list: u32,
}

impl RegistryHive {
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        ensure!(
            bytes.len() >= HIVE_BIN_BASE + 0x20,
            "registry hive is too small"
        );
        ensure!(
            &bytes[..4] == b"regf",
            "registry hive has no regf signature"
        );
        ensure!(
            &bytes[HIVE_BIN_BASE..HIVE_BIN_BASE + 4] == b"hbin",
            "registry hive has no first hbin"
        );
        let root_cell = read_u32_at(&bytes, 0x24)?;
        ensure!(root_cell != INVALID_CELL, "registry hive has no root cell");
        let hive = Self {
            bytes,
            root_cell,
            recovered_ranges: None,
            read_guard: None,
        };
        hive.key_node(root_cell)
            .context("registry hive root cell is invalid")?;
        Ok(hive)
    }

    /// Parse a memory reconstruction without treating zero-filled holes as
    /// evidence. The regf header may be synthesized, but every consumed cell
    /// must be covered by the acquisition's actual recovered ranges.
    pub(crate) fn from_recovered_bytes(
        bytes: Vec<u8>,
        mut ranges: Vec<Range<usize>>,
    ) -> Result<Self> {
        ranges.sort_unstable_by_key(|range| range.start);
        let mut merged: Vec<Range<usize>> = Vec::new();
        for range in ranges {
            ensure!(
                range.start <= range.end && range.end <= bytes.len(),
                "invalid recovered hive range"
            );
            if range.is_empty() {
                continue;
            }
            if let Some(last) = merged.last_mut()
                && range.start <= last.end
            {
                last.end = last.end.max(range.end);
            } else {
                merged.push(range);
            }
        }
        let mut hive = Self::from_bytes(bytes)?;
        hive.recovered_ranges = Some(merged);
        hive.key_node(hive.root_cell)
            .context("registry root cell is not fully recovered")?;
        Ok(hive)
    }

    fn ensure_recovered(&self, start: usize, end: usize, cell_index: u32) -> Result<()> {
        if let Some(ranges) = &self.recovered_ranges {
            let index = ranges.partition_point(|range| range.start <= start);
            ensure!(
                index > 0 && ranges[index - 1].end >= end,
                "registry cell {cell_index:#x} intersects unrecovered hive bytes ({start:#x}..{end:#x})"
            );
        }
        Ok(())
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn set_read_guard(&mut self, guard: RegistryReadGuard) {
        self.read_guard = Some(guard);
    }

    fn check_read_guard(&self) -> Result<()> {
        if let Some(guard) = &self.read_guard {
            guard.check()?;
        }
        Ok(())
    }

    pub fn root(&self) -> Result<RegistryKey> {
        Ok(self.key_node(self.root_cell)?.key)
    }

    pub fn open_key(&self, path: &str) -> Result<Option<RegistryKey>> {
        Ok(self.open_key_best_effort(path)?.key)
    }

    pub fn open_key_best_effort(&self, path: &str) -> Result<RegistryKeyLookup> {
        let root = self.key_node(self.root_cell)?.key;
        self.open_subkey_best_effort(&root, path)
    }

    pub fn open_subkey_best_effort(
        &self,
        start: &RegistryKey,
        path: &str,
    ) -> Result<RegistryKeyLookup> {
        let mut current = start.clone();
        let mut warnings = Vec::new();
        for component in path
            .replace('/', "\\")
            .split('\\')
            .filter(|component| !component.is_empty())
        {
            let RegistrySubkeyEnumeration {
                keys,
                warnings: enumeration_warnings,
            } = self.subkeys_best_effort(&current)?;
            warnings.extend(
                enumeration_warnings
                    .into_iter()
                    .map(|warning| format!("while opening {path}: {warning}")),
            );
            let mut matched = None;
            for child in keys {
                if child.name.eq_ignore_ascii_case(component) {
                    matched = Some(child);
                    break;
                }
            }
            let Some(child) = matched else {
                return Ok(RegistryKeyLookup {
                    key: None,
                    warnings,
                });
            };
            current = child;
        }
        Ok(RegistryKeyLookup {
            key: Some(current),
            warnings,
        })
    }

    pub fn subkeys(&self, key: &RegistryKey) -> Result<Vec<RegistryKey>> {
        Ok(self.subkeys_best_effort(key)?.keys)
    }

    pub fn subkeys_best_effort(&self, key: &RegistryKey) -> Result<RegistrySubkeyEnumeration> {
        let node = self.key_node(key.cell_index)?;
        if node.subkey_count == 0 {
            return Ok(RegistrySubkeyEnumeration {
                keys: Vec::new(),
                warnings: Vec::new(),
            });
        }
        if node.subkey_list == INVALID_CELL {
            return Ok(RegistrySubkeyEnumeration {
                keys: Vec::new(),
                warnings: vec![format!(
                    "registry key {} declares {} stable subkey(s), but its subkey list is absent",
                    key.name, node.subkey_count
                )],
            });
        }
        let mut indices = Vec::with_capacity(node.subkey_count.min(4096) as usize);
        let mut warnings = Vec::new();
        self.collect_subkey_indices(
            node.subkey_list,
            0,
            &mut HashSet::new(),
            &mut indices,
            &mut warnings,
        )?;
        if node.subkey_count > MAX_ITEMS as u32 {
            warnings.push(format!(
                "registry key {} declares {} stable subkey(s); inspection was capped at {MAX_ITEMS}",
                key.name, node.subkey_count
            ));
        }
        indices.truncate(node.subkey_count.min(MAX_ITEMS as u32) as usize);
        let mut keys = Vec::with_capacity(indices.len());
        for index in indices {
            self.check_read_guard()?;
            match self.key_node(index) {
                Ok(node) => keys.push(node.key),
                Err(error) => warnings.push(format!(
                    "registry subkey {index:#x} under {} was skipped: {error:#}",
                    key.name
                )),
            }
        }
        let expected = usize::try_from(node.subkey_count.min(MAX_ITEMS as u32))?;
        if keys.len() < expected {
            warnings.push(format!(
                "registry key {} declares {expected} stable subkey(s), but {} were recoverable",
                key.name,
                keys.len()
            ));
        }
        Ok(RegistrySubkeyEnumeration { keys, warnings })
    }

    pub fn values(&self, key: &RegistryKey) -> Result<Vec<RegistryValue>> {
        Ok(self.values_best_effort(key)?.values)
    }

    pub fn values_best_effort(&self, key: &RegistryKey) -> Result<RegistryValueEnumeration> {
        let node = self.key_node(key.cell_index)?;
        if node.value_count == 0 {
            return Ok(RegistryValueEnumeration {
                values: Vec::new(),
                declared_count: 0,
                listed_count: 0,
                warnings: Vec::new(),
            });
        }
        let mut warnings = Vec::new();
        if node.value_list == INVALID_CELL {
            warnings.push(format!(
                "registry key {} declares {} value(s), but its value list is absent",
                key.name, node.value_count
            ));
            return Ok(RegistryValueEnumeration {
                values: Vec::new(),
                declared_count: node.value_count,
                listed_count: 0,
                warnings,
            });
        }
        // Preserve the strict API's historical behavior for an unreadable
        // value-list cell: there is no list to enumerate best-effort, so the
        // caller receives an error and can attach source-specific context.
        let list = self.cell(node.value_list)?;
        let count = usize::try_from(node.value_count.min(MAX_ITEMS as u32))?;
        let available = list.len() / 4;
        let listed_count = count.min(available);
        if available < count {
            warnings.push(format!(
                "registry key {} declares {} value(s), but its value list contains only {available} entrie(s)",
                key.name, node.value_count
            ));
        }
        if node.value_count > MAX_ITEMS as u32 {
            warnings.push(format!(
                "registry key {} declares {} value(s); inspection was capped at {MAX_ITEMS}",
                key.name, node.value_count
            ));
        }
        let mut values = Vec::with_capacity(listed_count);
        for index in 0..listed_count {
            self.check_read_guard()?;
            let cell_index = read_u32_at(list, index * 4)?;
            match self.value(cell_index) {
                Ok(value) => values.push(value),
                Err(error) => warnings.push(format!(
                    "registry value {cell_index:#x} under {} was skipped: {error:#}",
                    key.name
                )),
            }
        }
        if values.len() < listed_count {
            warnings.push(format!(
                "registry key {} lists {listed_count} value cell(s), but only {} were recoverable",
                key.name,
                values.len()
            ));
        }
        Ok(RegistryValueEnumeration {
            values,
            declared_count: node.value_count,
            listed_count,
            warnings,
        })
    }

    pub fn value_by_name(&self, key: &RegistryKey, name: &str) -> Result<Option<RegistryValue>> {
        Ok(self
            .values(key)?
            .into_iter()
            .find(|value| value.name.eq_ignore_ascii_case(name)))
    }

    pub fn query_value(&self, path: &str, name: &str) -> Result<Option<RegistryValue>> {
        let Some(key) = self.open_key(path)? else {
            return Ok(None);
        };
        self.value_by_name(&key, name)
    }

    /// Returns the optional UTF-16 class string stored in an NK cell.  The
    /// class is distinct from the key name and is required to reconstruct the
    /// Windows SYSTEM boot key without relying on an exported hive file.
    pub fn key_class(&self, key: &RegistryKey) -> Result<Option<String>> {
        let cell = self.cell(key.cell_index)?;
        ensure!(cell.len() >= 0x4c, "registry key node is truncated");
        let class_cell = read_u32_at(cell, 0x30)?;
        let class_length = usize::from(read_u16_at(cell, 0x4a)?);
        if class_cell == INVALID_CELL || class_length == 0 {
            return Ok(None);
        }
        let bytes = self.cell(class_cell)?;
        let bytes = bytes
            .get(..class_length)
            .context("registry key class exceeds its cell")?;
        ensure!(
            bytes.len() % 2 == 0,
            "registry key class has odd UTF-16 length"
        );
        let units = bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>();
        Ok(Some(String::from_utf16_lossy(&units)))
    }

    fn cell(&self, cell_index: u32) -> Result<&[u8]> {
        if let Some(guard) = &self.read_guard {
            guard.charge(1, 0)?;
        }
        ensure!(
            cell_index & 0x8000_0000 == 0,
            "volatile registry cell {cell_index:#x} is not part of the stable hive"
        );
        let offset = HIVE_BIN_BASE
            .checked_add(usize::try_from(cell_index)?)
            .context("registry cell offset overflow")?;
        self.ensure_recovered(offset, offset + 4, cell_index)?;
        let raw_size = read_i32_at(&self.bytes, offset)?;
        ensure!(
            raw_size < 0,
            "registry cell {cell_index:#x} is free or missing"
        );
        let size = usize::try_from(raw_size.unsigned_abs())?;
        ensure!(size >= 4, "registry cell {cell_index:#x} is too small");
        let end = offset
            .checked_add(size)
            .context("registry cell range overflow")?;
        ensure!(end <= self.bytes.len(), "registry cell exceeds hive image");
        self.ensure_recovered(offset, end, cell_index)?;
        if let Some(guard) = &self.read_guard {
            guard.charge(0, size)?;
        }
        Ok(&self.bytes[offset + 4..end])
    }

    fn key_node(&self, cell_index: u32) -> Result<KeyNode> {
        let cell = self.cell(cell_index)?;
        ensure!(cell.len() >= 0x4c, "key node is truncated");
        ensure!(
            &cell[..2] == b"nk",
            "cell {cell_index:#x} is not a key node"
        );
        let flags = read_u16_at(cell, 0x02)?;
        let name_length = usize::from(read_u16_at(cell, 0x48)?);
        let name_bytes = cell
            .get(0x4c..0x4cusize.saturating_add(name_length))
            .context("key name exceeds cell")?;
        let name = decode_name(name_bytes, flags & KEY_COMP_NAME != 0);
        Ok(KeyNode {
            key: RegistryKey {
                cell_index,
                name,
                last_write_raw: read_u64_at(cell, 0x04)?,
                flags,
            },
            subkey_count: read_u32_at(cell, 0x14)?,
            subkey_list: read_u32_at(cell, 0x1c)?,
            value_count: read_u32_at(cell, 0x24)?,
            value_list: read_u32_at(cell, 0x28)?,
        })
    }

    fn collect_subkey_indices(
        &self,
        list_cell: u32,
        depth: usize,
        visited: &mut HashSet<u32>,
        output: &mut Vec<u32>,
        warnings: &mut Vec<String>,
    ) -> Result<()> {
        ensure!(
            depth <= MAX_LIST_DEPTH,
            "registry subkey index nesting is too deep"
        );
        ensure!(
            visited.insert(list_cell),
            "registry subkey index cycle detected"
        );
        let cell = self.cell(list_cell)?;
        ensure!(cell.len() >= 4, "registry subkey index is truncated");
        let signature = &cell[..2];
        let count = usize::from(read_u16_at(cell, 2)?).min(MAX_ITEMS);
        match signature {
            b"lf" | b"lh" => {
                for index in 0..count.min(cell.len().saturating_sub(4) / 8) {
                    output.push(read_u32_at(cell, 4 + index * 8)?);
                }
            }
            b"li" => {
                for index in 0..count.min(cell.len().saturating_sub(4) / 4) {
                    output.push(read_u32_at(cell, 4 + index * 4)?);
                }
            }
            b"ri" => {
                for index in 0..count.min(cell.len().saturating_sub(4) / 4) {
                    self.check_read_guard()?;
                    let nested = read_u32_at(cell, 4 + index * 4)?;
                    if let Err(error) =
                        self.collect_subkey_indices(nested, depth + 1, visited, output, warnings)
                    {
                        warnings.push(format!(
                            "registry subkey index branch {nested:#x} was skipped: {error:#}"
                        ));
                    }
                    ensure!(
                        output.len() <= MAX_ITEMS,
                        "registry subkey result limit reached"
                    );
                }
            }
            _ => bail!("unknown registry subkey index signature {:02x?}", signature),
        }
        Ok(())
    }

    fn value(&self, cell_index: u32) -> Result<RegistryValue> {
        let cell = self.cell(cell_index)?;
        ensure!(cell.len() >= 0x14, "registry value cell is truncated");
        ensure!(&cell[..2] == b"vk", "cell {cell_index:#x} is not a value");
        let name_length = usize::from(read_u16_at(cell, 0x02)?);
        let data_length_raw = read_u32_at(cell, 0x04)?;
        let data_offset = read_u32_at(cell, 0x08)?;
        let data_type = read_u32_at(cell, 0x0c)?;
        let flags = read_u16_at(cell, 0x10)?;
        let name_bytes = cell
            .get(0x14..0x14usize.saturating_add(name_length))
            .context("registry value name exceeds cell")?;
        let name = decode_name(name_bytes, flags & VALUE_COMP_NAME != 0);
        let raw_data = self.value_data(data_length_raw, data_offset)?;
        let data = decode_value_data(data_type, &raw_data);
        Ok(RegistryValue {
            cell_index,
            name,
            data_type,
            data,
            raw_data,
        })
    }

    fn value_data(&self, data_length_raw: u32, data_offset: u32) -> Result<Vec<u8>> {
        let length = usize::try_from(data_length_raw & 0x7fff_ffff)?;
        if let Some(guard) = &self.read_guard {
            guard.charge(0, length)?;
        }
        if length == 0 {
            return Ok(Vec::new());
        }
        if data_length_raw & 0x8000_0000 != 0 {
            ensure!(
                length <= 4,
                "inline registry value is larger than four bytes"
            );
            return Ok(data_offset.to_le_bytes()[..length].to_vec());
        }

        let cell = self.cell(data_offset)?;
        if cell.starts_with(b"db") && cell.len() >= 8 {
            let segment_count = usize::from(read_u16_at(cell, 2)?).min(MAX_ITEMS);
            let segment_list = read_u32_at(cell, 4)?;
            let list = self.cell(segment_list)?;
            let mut output = Vec::with_capacity(length);
            for index in 0..segment_count.min(list.len() / 4) {
                let segment = self.cell(read_u32_at(list, index * 4)?)?;
                let remaining = length.saturating_sub(output.len());
                output.extend_from_slice(&segment[..segment.len().min(remaining)]);
                if output.len() == length {
                    break;
                }
            }
            ensure!(
                output.len() == length,
                "big registry value is missing segments"
            );
            return Ok(output);
        }
        ensure!(cell.len() >= length, "registry value data is truncated");
        Ok(cell[..length].to_vec())
    }
}

impl RegistryValue {
    pub fn raw_data(&self) -> &[u8] {
        &self.raw_data
    }

    pub fn as_string(&self) -> Option<&str> {
        match &self.data {
            RegistryValueData::String(value) => Some(value),
            _ => None,
        }
    }

    pub fn as_multi_string(&self) -> Option<&[String]> {
        match &self.data {
            RegistryValueData::MultiString(value) => Some(value),
            _ => None,
        }
    }

    pub fn as_u32(&self) -> Option<u32> {
        match self.data {
            RegistryValueData::Dword(value) => Some(value),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self.data {
            RegistryValueData::Qword(value) => Some(value),
            RegistryValueData::Dword(value) => Some(u64::from(value)),
            _ => None,
        }
    }
}

fn decode_name(bytes: &[u8], compressed: bool) -> String {
    if compressed {
        bytes.iter().map(|byte| char::from(*byte)).collect()
    } else {
        decode_utf16(bytes)
    }
}

fn decode_value_data(data_type: u32, bytes: &[u8]) -> RegistryValueData {
    match data_type {
        0 if bytes.is_empty() => RegistryValueData::None,
        1 | 2 | 6 => RegistryValueData::String(decode_utf16(bytes)),
        3 | 8 | 9 | 10 => RegistryValueData::Binary(hex::encode_upper(bytes)),
        4 if bytes.len() >= 4 => RegistryValueData::Dword(u32::from_le_bytes(
            bytes[..4].try_into().expect("length checked"),
        )),
        5 if bytes.len() >= 4 => RegistryValueData::Dword(u32::from_be_bytes(
            bytes[..4].try_into().expect("length checked"),
        )),
        7 => RegistryValueData::MultiString(
            decode_utf16_words(bytes)
                .split('\0')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .collect(),
        ),
        11 if bytes.len() >= 8 => RegistryValueData::Qword(u64::from_le_bytes(
            bytes[..8].try_into().expect("length checked"),
        )),
        _ => RegistryValueData::Unknown(hex::encode_upper(bytes)),
    }
}

fn decode_utf16(bytes: &[u8]) -> String {
    // REG_SZ/REG_EXPAND_SZ are single NUL-terminated strings. Recovered Hive
    // cells can retain slack bytes after the first terminator; exposing that
    // slack would append unrelated text to values such as TimeZoneKeyName.
    decode_utf16_words(bytes)
        .split('\0')
        .next()
        .unwrap_or_default()
        .to_owned()
}

fn decode_utf16_words(bytes: &[u8]) -> String {
    let words = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect::<Vec<_>>();
    String::from_utf16_lossy(&words)
}

fn read_u16_at(bytes: &[u8], offset: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(
        bytes
            .get(offset..offset + 2)
            .context("u16 read exceeds buffer")?
            .try_into()?,
    ))
}

fn read_u32_at(bytes: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .context("u32 read exceeds buffer")?
            .try_into()?,
    ))
}

fn read_i32_at(bytes: &[u8], offset: usize) -> Result<i32> {
    Ok(i32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .context("i32 read exceeds buffer")?
            .try_into()?,
    ))
}

fn read_u64_at(bytes: &[u8], offset: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        bytes
            .get(offset..offset + 8)
            .context("u64 read exceeds buffer")?
            .try_into()?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_registry_string_stops_at_the_first_nul() {
        let bytes = "China Standard Time\0stale cell text"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        assert_eq!(decode_utf16(&bytes), "China Standard Time");
    }

    #[test]
    fn walks_key_and_decodes_string_value() {
        let mut hive = vec![0u8; 0x3000];
        hive[..4].copy_from_slice(b"regf");
        hive[0x1000..0x1004].copy_from_slice(b"hbin");
        let mut next = 0x20u32;

        let string = "Demo\0"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        let data = push_cell(&mut hive, &mut next, &string);

        let mut value = vec![0u8; 0x14 + "ComputerName".len()];
        value[..2].copy_from_slice(b"vk");
        value[2..4].copy_from_slice(&("ComputerName".len() as u16).to_le_bytes());
        value[4..8].copy_from_slice(&(string.len() as u32).to_le_bytes());
        value[8..12].copy_from_slice(&data.to_le_bytes());
        value[12..16].copy_from_slice(&1u32.to_le_bytes());
        value[16..18].copy_from_slice(&VALUE_COMP_NAME.to_le_bytes());
        value[0x14..].copy_from_slice(b"ComputerName");
        let value_cell = push_cell(&mut hive, &mut next, &value);
        let value_list = push_cell(&mut hive, &mut next, &value_cell.to_le_bytes());

        let child = key_payload("Control", 0, INVALID_CELL, 1, value_list);
        let child_cell = push_cell(&mut hive, &mut next, &child);
        let mut index = vec![0u8; 8];
        index[..2].copy_from_slice(b"li");
        index[2..4].copy_from_slice(&1u16.to_le_bytes());
        index[4..8].copy_from_slice(&child_cell.to_le_bytes());
        let index_cell = push_cell(&mut hive, &mut next, &index);

        let root = key_payload("ROOT", 1, index_cell, 0, INVALID_CELL);
        let root_cell = push_cell(&mut hive, &mut next, &root);
        hive[0x24..0x28].copy_from_slice(&root_cell.to_le_bytes());
        hive[0x28..0x2c].copy_from_slice(&0x2000u32.to_le_bytes());

        let hive = RegistryHive::from_bytes(hive).unwrap();
        let control = hive.open_key("Control").unwrap().unwrap();
        let value = hive
            .value_by_name(&control, "computername")
            .unwrap()
            .unwrap();
        assert_eq!(value.as_string(), Some("Demo"));
    }

    #[test]
    fn keeps_valid_ri_branches_when_another_branch_is_missing() {
        let mut hive = vec![0u8; 0x3000];
        hive[..4].copy_from_slice(b"regf");
        hive[0x1000..0x1004].copy_from_slice(b"hbin");
        let mut next = 0x20u32;

        let child = key_payload("Recovered", 0, INVALID_CELL, 0, INVALID_CELL);
        let child_cell = push_cell(&mut hive, &mut next, &child);
        let mut leaf = vec![0u8; 8];
        leaf[..2].copy_from_slice(b"li");
        leaf[2..4].copy_from_slice(&1u16.to_le_bytes());
        leaf[4..8].copy_from_slice(&child_cell.to_le_bytes());
        let leaf_cell = push_cell(&mut hive, &mut next, &leaf);

        let missing_branch = 0x1800u32;
        let mut root_index = vec![0u8; 12];
        root_index[..2].copy_from_slice(b"ri");
        root_index[2..4].copy_from_slice(&2u16.to_le_bytes());
        root_index[4..8].copy_from_slice(&leaf_cell.to_le_bytes());
        root_index[8..12].copy_from_slice(&missing_branch.to_le_bytes());
        let root_index_cell = push_cell(&mut hive, &mut next, &root_index);

        let root = key_payload("ROOT", 1, root_index_cell, 0, INVALID_CELL);
        let root_cell = push_cell(&mut hive, &mut next, &root);
        hive[0x24..0x28].copy_from_slice(&root_cell.to_le_bytes());
        hive[0x28..0x2c].copy_from_slice(&0x2000u32.to_le_bytes());

        let hive = RegistryHive::from_bytes(hive).unwrap();
        let root = hive.root().unwrap();
        let result = hive.subkeys_best_effort(&root).unwrap();
        assert_eq!(result.keys.len(), 1);
        assert_eq!(result.keys[0].name, "Recovered");
        assert!(
            result
                .warnings
                .iter()
                .any(|warning| warning.contains("0x1800"))
        );

        let recovered_lookup = hive.open_key_best_effort("Recovered").unwrap();
        assert_eq!(recovered_lookup.key.unwrap().name, "Recovered");
        assert!(
            recovered_lookup
                .warnings
                .iter()
                .any(|warning| warning.contains("0x1800"))
        );

        let lookup = hive.open_key_best_effort("Missing").unwrap();
        assert!(lookup.key.is_none());
        assert!(
            lookup
                .warnings
                .iter()
                .any(|warning| warning.contains("0x1800"))
        );
    }

    #[test]
    fn reports_declared_value_cells_that_are_not_recoverable() {
        let mut hive = vec![0u8; 0x3000];
        hive[..4].copy_from_slice(b"regf");
        hive[0x1000..0x1004].copy_from_slice(b"hbin");
        let mut next = 0x20u32;

        let missing_value_cell = 0x1800u32;
        let value_list = push_cell(&mut hive, &mut next, &missing_value_cell.to_le_bytes());
        let root = key_payload("ROOT", 0, INVALID_CELL, 1, value_list);
        let root_cell = push_cell(&mut hive, &mut next, &root);
        hive[0x24..0x28].copy_from_slice(&root_cell.to_le_bytes());
        hive[0x28..0x2c].copy_from_slice(&0x2000u32.to_le_bytes());

        let hive = RegistryHive::from_bytes(hive).unwrap();
        let root = hive.root().unwrap();
        let result = hive.values_best_effort(&root).unwrap();
        assert_eq!(result.declared_count, 1);
        assert_eq!(result.listed_count, 1);
        assert!(result.values.is_empty());
        assert!(
            result
                .warnings
                .iter()
                .any(|warning| warning.contains("0x1800"))
        );
    }

    #[test]
    fn reports_subkey_declarations_above_the_inspection_cap() {
        let mut hive = vec![0u8; 0x3000];
        hive[..4].copy_from_slice(b"regf");
        hive[0x1000..0x1004].copy_from_slice(b"hbin");
        let mut next = 0x20u32;

        let mut empty_index = vec![0u8; 4];
        empty_index[..2].copy_from_slice(b"li");
        let index_cell = push_cell(&mut hive, &mut next, &empty_index);
        let root = key_payload(
            "ROOT",
            u32::try_from(MAX_ITEMS).unwrap() + 1,
            index_cell,
            0,
            INVALID_CELL,
        );
        let root_cell = push_cell(&mut hive, &mut next, &root);
        hive[0x24..0x28].copy_from_slice(&root_cell.to_le_bytes());
        hive[0x28..0x2c].copy_from_slice(&0x2000u32.to_le_bytes());

        let hive = RegistryHive::from_bytes(hive).unwrap();
        let result = hive.subkeys_best_effort(&hive.root().unwrap()).unwrap();
        assert!(
            result
                .warnings
                .iter()
                .any(|warning| warning.contains("inspection was capped"))
        );
    }

    #[test]
    fn reports_a_declared_subkey_list_that_is_absent() {
        let mut hive = vec![0u8; 0x3000];
        hive[..4].copy_from_slice(b"regf");
        hive[0x1000..0x1004].copy_from_slice(b"hbin");
        let mut next = 0x20u32;
        let root = key_payload("ROOT", 1, INVALID_CELL, 0, INVALID_CELL);
        let root_cell = push_cell(&mut hive, &mut next, &root);
        hive[0x24..0x28].copy_from_slice(&root_cell.to_le_bytes());
        hive[0x28..0x2c].copy_from_slice(&0x2000u32.to_le_bytes());

        let hive = RegistryHive::from_bytes(hive).unwrap();
        let result = hive.subkeys_best_effort(&hive.root().unwrap()).unwrap();
        assert!(result.keys.is_empty());
        assert!(
            result
                .warnings
                .iter()
                .any(|warning| warning.contains("subkey list is absent"))
        );
    }

    #[test]
    fn sparse_hive_does_not_treat_zero_filled_value_pages_as_recovered_data() {
        let mut bytes = vec![0u8; 0x5000];
        bytes[..4].copy_from_slice(b"regf");
        bytes[0x1000..0x1004].copy_from_slice(b"hbin");
        let mut next = 0x20u32;
        let data = push_cell(&mut bytes, &mut next, &vec![0u8; 0x2000]);
        let mut value = vec![0u8; 0x15];
        value[..2].copy_from_slice(b"vk");
        value[2..4].copy_from_slice(&1u16.to_le_bytes());
        value[4..8].copy_from_slice(&0x2000u32.to_le_bytes());
        value[8..12].copy_from_slice(&data.to_le_bytes());
        value[12..16].copy_from_slice(&3u32.to_le_bytes());
        value[16..18].copy_from_slice(&VALUE_COMP_NAME.to_le_bytes());
        value[0x14] = b'V';
        let vk = push_cell(&mut bytes, &mut next, &value);
        let list = push_cell(&mut bytes, &mut next, &vk.to_le_bytes());
        let root = push_cell(
            &mut bytes,
            &mut next,
            &key_payload("ROOT", 0, INVALID_CELL, 1, list),
        );
        bytes[0x24..0x28].copy_from_slice(&root.to_le_bytes());
        let whole = RegistryHive::from_bytes(bytes.clone()).unwrap();
        assert!(whole.query_value("", "V").unwrap().is_some());

        let sparse =
            RegistryHive::from_recovered_bytes(bytes.clone(), vec![0x3000..0x5000, 0x1000..0x2000])
                .unwrap();
        let values = sparse.values_best_effort(&sparse.root().unwrap()).unwrap();
        assert!(values.values.is_empty());
        assert!(
            values
                .warnings
                .iter()
                .any(|warning| warning.contains("unrecovered hive bytes"))
        );

        let adjacent =
            RegistryHive::from_recovered_bytes(bytes, vec![0x2000..0x5000, 0x1000..0x2000])
                .unwrap();
        assert!(adjacent.query_value("", "V").unwrap().is_some());
    }

    fn key_payload(
        name: &str,
        subkey_count: u32,
        subkey_list: u32,
        value_count: u32,
        value_list: u32,
    ) -> Vec<u8> {
        let mut key = vec![0u8; 0x4c + name.len()];
        key[..2].copy_from_slice(b"nk");
        key[2..4].copy_from_slice(&KEY_COMP_NAME.to_le_bytes());
        key[0x14..0x18].copy_from_slice(&subkey_count.to_le_bytes());
        key[0x1c..0x20].copy_from_slice(&subkey_list.to_le_bytes());
        key[0x24..0x28].copy_from_slice(&value_count.to_le_bytes());
        key[0x28..0x2c].copy_from_slice(&value_list.to_le_bytes());
        key[0x48..0x4a].copy_from_slice(&(name.len() as u16).to_le_bytes());
        key[0x4c..].copy_from_slice(name.as_bytes());
        key
    }

    fn push_cell(hive: &mut [u8], next: &mut u32, payload: &[u8]) -> u32 {
        let index = *next;
        let total = (payload.len() + 4).next_multiple_of(8);
        let offset = HIVE_BIN_BASE + index as usize;
        hive[offset..offset + 4].copy_from_slice(&(-(total as i32)).to_le_bytes());
        hive[offset + 4..offset + 4 + payload.len()].copy_from_slice(payload);
        *next += total as u32;
        index
    }
}
