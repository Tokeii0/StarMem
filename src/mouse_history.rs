//! Offline GetMouseMovePointsEx history, bound to the exact builds validated in memory.
//! Coordinates are encoded high/low words, not signed screen coordinates.
use crate::{
    address::X64AddressSpace,
    cancellation::{CancellationToken, is_cancellation_error},
    image::SourceLocation,
    profile::read_pdb_symbol_rvas,
    session::AnalysisSession,
    symbols::codeview_from_virtual_pe,
};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use std::collections::BTreeMap;

const CAPACITY: usize = 64;
const RECORD_BYTES: usize = 24;
const MAX_SESSIONS: usize = 64;
const LEGACY_KEYS: [&str; 2] = [
    "A9F6403F14074E9D8A07D0AA6F0C1CFF2",
    "21E2778DD2954987A9B7212463FFDC5E2",
];
const MODERN_KEYS: [(&str, &str); 3] = [
    ("win32k.sys", "CE65D0C30097A5960541475A160E2B141"),
    ("win32kbase.sys", "6639C8F2148709849D6A3825335828FA1"),
    ("win32kfull.sys", "8E48BC81DE922C88C2612515403284181"),
];

#[derive(Debug, Serialize)]
pub struct MouseModuleIdentity {
    pub module: String,
    pub base: u64,
    pub pdb_name: String,
    pub symbol_key: String,
    pub identity_dtb: u64,
    pub symbol_rvas: BTreeMap<String, u32>,
}
impl MouseModuleIdentity {
    fn global(&self, name: &str) -> Result<u64> {
        add(
            self.base,
            u64::from(
                *self
                    .symbol_rvas
                    .get(name)
                    .with_context(|| format!("精确 PDB 缺少 {name}"))?,
            ),
        )
    }
}

#[derive(Debug, Serialize)]
pub struct MouseSourceRange {
    pub virtual_address: u64,
    pub physical_address: u64,
    pub length: usize,
    pub source: SourceLocation,
}

#[derive(Debug, Serialize)]
pub struct MousePoint {
    pub session_id: u32,
    pub context_pid: u64,
    pub order: usize,
    pub slot: usize,
    pub normalized_x: u32,
    pub normalized_y: u32,
    pub pixel_x: Option<u32>,
    pub pixel_y: Option<u32>,
    pub raw_x: i32,
    pub raw_y: i32,
    pub tick_ms: u32,
    pub delta_ms: Option<i32>,
    pub extra_info: u64,
    pub dtb: u64,
    pub virtual_address: u64,
    pub physical_address: u64,
    pub file_offset: Option<u64>,
    pub source_ranges: Vec<MouseSourceRange>,
    pub raw_hex: String,
}

#[derive(Debug, Serialize)]
pub struct MouseSession {
    pub session_id: u32,
    pub context_pid: u64,
    pub eprocess: u64,
    pub dtb: u64,
    pub status: String,
    /// Completeness concerns the retained ring, never the user's entire history.
    pub complete: bool,
    pub record_count: usize,
    pub ring_address: Option<u64>,
    pub index_address: Option<u64>,
    pub ring_next_write_index: Option<u32>,
    pub session_state: Option<u64>,
    pub session_globals: Option<u64>,
    pub screen_size: Option<[u32; 2]>,
    pub coordinate_unit: String,
    pub cursor_at_read: Option<[i32; 2]>,
    pub latest_matches_cursor: Option<bool>,
    pub shared_tick_ms: Option<u64>,
    pub latest_point_minus_shared_tick_ms: Option<i32>,
    pub span_ms: Option<i32>,
    pub timestamp_order_nondecreasing: bool,
    pub missing_slots: Vec<usize>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct MouseHistoryReport {
    pub image: String,
    pub records: Vec<MousePoint>,
    pub sessions: Vec<MouseSession>,
    pub modules: Vec<MouseModuleIdentity>,
    pub complete: bool,
    pub status: String,
    pub ring_capacity: usize,
    pub session_limit: usize,
    pub record_limit: usize,
    pub warnings: Vec<String>,
    pub limitations: Vec<String>,
}

fn add(base: u64, offset: u64) -> Result<u64> {
    base.checked_add(offset).context("鼠标对象地址溢出")
}
fn pointer(value: u64) -> Result<u64> {
    ensure!(
        (0xffff_8000_0000_0000..u64::MAX - 0x10000).contains(&value) && value & 7 == 0,
        "无效的会话内核指针 {value:#x}"
    );
    Ok(value)
}
fn read<const N: usize>(space: &X64AddressSpace<'_>, address: u64) -> Result<[u8; N]> {
    let mut bytes = [0; N];
    space.read_virtual(address, &mut bytes)?;
    Ok(bytes)
}
fn u32_at(space: &X64AddressSpace<'_>, address: u64) -> Result<u32> {
    Ok(u32::from_le_bytes(read(space, address)?))
}
fn i32_pair(space: &X64AddressSpace<'_>, address: u64) -> Result<[i32; 2]> {
    let raw = read::<8>(space, address)?;
    Ok([
        i32::from_le_bytes(raw[..4].try_into()?),
        i32::from_le_bytes(raw[4..].try_into()?),
    ])
}
fn tick_delta(new: u32, old: u32) -> i32 {
    new.wrapping_sub(old) as i32
}

fn exact_module(
    session: &AnalysisSession,
    contexts: &[(u32, u64, u64, u64)],
    name: &str,
    base: u64,
    token: &CancellationToken,
) -> Result<MouseModuleIdentity> {
    let mut failures = Vec::new();
    for &(sid, _, _, dtb) in contexts {
        token.check_cancelled()?;
        let cv = match codeview_from_virtual_pe(session.image(), dtb, base) {
            Ok(cv) => cv,
            Err(e) => {
                failures.push(format!("会话 {sid}: {e:#}"));
                continue;
            }
        };
        ensure!(
            cv.pdb_name
                .eq_ignore_ascii_case(&name.replace(".sys", ".pdb")),
            "模块与 PDB 名称不符"
        );
        let path = session.symbol_store().resolve(&cv)?;
        token.check_cancelled()?;
        let mut pdb = pdb::PDB::open(std::fs::File::open(&path)?)?;
        ensure!(
            pdb.pdb_information()?
                .guid
                .to_string()
                .eq_ignore_ascii_case(&cv.guid)
                && pdb.debug_information()?.age() == Some(cv.age),
            "鼠标解析所用 PDB 身份不匹配"
        );
        let names: &[&str] = if name == "win32k.sys" {
            if LEGACY_KEYS.contains(&cv.symbol_key.as_str()) {
                &["gaptMouse", "gptInd", "gpsi", "gptCursorAsync"]
            } else {
                &["gLowSessionGlobalSlots", "gSessionGlobalSlots"]
            }
        } else {
            &[]
        };
        let symbols = if names.is_empty() {
            BTreeMap::new()
        } else {
            read_pdb_symbol_rvas(&path, names)?
        };
        return Ok(MouseModuleIdentity {
            module: name.into(),
            base,
            pdb_name: cv.pdb_name,
            symbol_key: cv.symbol_key,
            identity_dtb: dtb,
            symbol_rvas: symbols,
        });
    }
    anyhow::bail!("不能确认 {name} 的精确身份：{}", failures.join("；"))
}

fn validated_layout(modules: &[MouseModuleIdentity]) -> Option<bool> {
    let win32k = modules.iter().find(|m| m.module == "win32k.sys")?;
    if LEGACY_KEYS.contains(&win32k.symbol_key.as_str()) {
        return Some(true);
    }
    MODERN_KEYS
        .iter()
        .all(|(name, key)| {
            modules
                .iter()
                .any(|m| m.module == *name && m.symbol_key == *key)
        })
        .then_some(false)
}

#[derive(Debug)]
struct DecodedPoint {
    order: usize,
    slot: usize,
    raw_x: i32,
    raw_y: i32,
    normalized: [u32; 2],
    pixels: Option<[u32; 2]>,
    tick: u32,
    extra: u64,
}

fn decode_ring(
    slots: &[Option<[u8; RECORD_BYTES]>; CAPACITY],
    next: u32,
    dimensions: Option<[u32; 2]>,
) -> Result<(Vec<DecodedPoint>, Vec<String>)> {
    ensure!(next <= CAPACITY as u32, "环形索引 {next} 超出 0–64");
    let mut retained = Vec::new();
    // The getter walks newest to oldest and stops at the first uninitialized slot.
    // Do not promote stale bytes beyond that boundary into history.
    for age in 0..CAPACITY {
        let slot = (next as usize + CAPACITY - 1 - age) % CAPACITY;
        if let Some(raw) = slots[slot] {
            let x = u32::from_le_bytes(raw[..4].try_into()?);
            let y = u32::from_le_bytes(raw[4..8].try_into()?);
            if x >> 16 == 0 || y >> 16 == 0 {
                break;
            }
        }
        retained.push(slot);
    }
    retained.reverse();
    let mut points = Vec::new();
    let mut warnings = Vec::new();
    for (order, slot) in retained.into_iter().enumerate() {
        let Some(raw) = slots[slot] else {
            continue;
        };
        let x = u32::from_le_bytes(raw[..4].try_into()?);
        let y = u32::from_le_bytes(raw[4..8].try_into()?);
        let low = [x & 0xffff, y & 0xffff];
        let scale = [x >> 16, y >> 16];
        if low[0] > scale[0] || low[1] > scale[1] {
            warnings.push(format!("槽位 {slot} 的编码坐标超出对应范围，未作为有效点"));
            continue;
        }
        let normalized = [low[0] * 65535 / scale[0], low[1] * 65535 / scale[1]];
        let pixels = dimensions.map(|d| {
            [
                (u64::from(low[0]) * u64::from(d[0]) / u64::from(scale[0] + 1)) as u32,
                (u64::from(low[1]) * u64::from(d[1]) / u64::from(scale[1] + 1)) as u32,
            ]
        });
        points.push(DecodedPoint {
            order,
            slot,
            raw_x: x as i32,
            raw_y: y as i32,
            normalized,
            pixels,
            tick: u32::from_le_bytes(raw[8..12].try_into()?),
            extra: u64::from_le_bytes(raw[16..24].try_into()?),
        });
    }
    Ok((points, warnings))
}

fn source_ranges(
    session: &AnalysisSession,
    space: &X64AddressSpace<'_>,
    address: u64,
) -> Result<Vec<MouseSourceRange>> {
    let mut ranges: Vec<MouseSourceRange> = Vec::new();
    for i in 0..RECORD_BYTES {
        let va = add(address, i as u64)?;
        let physical = space.translate(va)?;
        let source = session
            .image()
            .source_location(physical)
            .context("鼠标记录没有可读源映射")?;
        if let Some(last) = ranges.last_mut() {
            let distance = last.length as u64;
            if last.physical_address + distance == physical
                && last.source.source_index == source.source_index
                && last.source.encoding == source.encoding
                && last
                    .source
                    .exact_byte_offset
                    .zip(source.exact_byte_offset)
                    .is_some_and(|(a, b)| a + distance == b)
            {
                last.length += 1;
                continue;
            }
        }
        ranges.push(MouseSourceRange {
            virtual_address: va,
            physical_address: physical,
            length: 1,
            source,
        });
    }
    Ok(ranges)
}

fn read_session(
    session: &AnalysisSession,
    module: &MouseModuleIdentity,
    legacy: bool,
    output: &mut MouseSession,
    token: &CancellationToken,
) -> Result<Vec<MousePoint>> {
    let space = X64AddressSpace::new(session.image(), output.dtb)?;
    let (array, index_address) = if legacy {
        let dimensions = (|| -> Result<[u32; 2]> {
            let psi = pointer(space.read_u64(module.global("gpsi")?)?)?;
            let a = i32_pair(&space, add(psi, 0x890)?)?;
            let b = i32_pair(&space, add(psi, 0xa14)?)?;
            ensure!(
                a == b && a.iter().all(|v| (1..=65536).contains(v)),
                "两处屏幕维度不一致或超出验证范围"
            );
            Ok([a[0] as u32, a[1] as u32])
        })();
        match dimensions {
            Ok(d) => {
                output.screen_size = Some(d);
                output.coordinate_unit = "screen_pixels".into();
            }
            Err(e) => output
                .warnings
                .push(format!("屏幕尺寸不可验证，仅提供比例坐标：{e:#}")),
        }
        output.cursor_at_read = module
            .global("gptCursorAsync")
            .and_then(|va| i32_pair(&space, va))
            .ok();
        (module.global("gaptMouse")?, module.global("gptInd")?)
    } else {
        let slot_address = if output.session_id == 0 {
            module.global("gLowSessionGlobalSlots")?
        } else {
            let slots = pointer(space.read_u64(module.global("gSessionGlobalSlots")?)?)?;
            add(slots, u64::from(output.session_id - 1) * 8)?
        };
        let state = pointer(space.read_u64(slot_address)?)?;
        let globals = pointer(space.read_u64(state)?)?;
        output.session_state = Some(state);
        output.session_globals = Some(globals);
        (add(globals, 0x3980)?, add(globals, 0x397c)?)
    };
    pointer(array)?;
    output.ring_address = Some(array);
    output.index_address = Some(index_address);
    let index = u32_at(&space, index_address)?;
    ensure!(index <= 64, "鼠标环形索引超出范围：{index}");
    output.ring_next_write_index = Some(index);
    let mut slots = [None; CAPACITY];
    for (slot, raw) in slots.iter_mut().enumerate() {
        token.check_cancelled()?;
        match read(&space, add(array, (slot * RECORD_BYTES) as u64)?) {
            Ok(data) => *raw = Some(data),
            Err(e) => {
                output.missing_slots.push(slot);
                output.complete = false;
                if output.missing_slots.len() == 1 {
                    output.warnings.push(format!("部分鼠标槽位不可读：{e:#}"));
                }
            }
        }
    }
    let (decoded, invalid) = decode_ring(&slots, index, output.screen_size)?;
    if !invalid.is_empty() {
        output.complete = false;
        output.warnings.extend(invalid);
    }
    let mut points: Vec<MousePoint> = Vec::new();
    for point in decoded {
        token.check_cancelled()?;
        let va = add(array, (point.slot * RECORD_BYTES) as u64)?;
        let ranges = source_ranges(session, &space, va)?;
        let physical = space.translate(va)?;
        let delta = points
            .last()
            .map(|last| tick_delta(point.tick, last.tick_ms));
        if delta.is_some_and(|d| d < 0) {
            output.timestamp_order_nondecreasing = false;
        }
        points.push(MousePoint {
            session_id: output.session_id,
            context_pid: output.context_pid,
            order: point.order,
            slot: point.slot,
            normalized_x: point.normalized[0],
            normalized_y: point.normalized[1],
            pixel_x: point.pixels.map(|p| p[0]),
            pixel_y: point.pixels.map(|p| p[1]),
            raw_x: point.raw_x,
            raw_y: point.raw_y,
            tick_ms: point.tick,
            delta_ms: delta,
            extra_info: point.extra,
            dtb: output.dtb,
            virtual_address: va,
            physical_address: physical,
            file_offset: session.image().physical_to_file_offset(physical),
            source_ranges: ranges,
            raw_hex: hex::encode(slots[point.slot].context("已解码槽位不可用")?),
        });
    }
    if !output.timestamp_order_nondecreasing {
        output
            .warnings
            .push("时间戳不按环内顺序递增；保留原顺序，不推导速度或 UTC".into());
    }
    if let (Some(first), Some(last)) = (points.first(), points.last()) {
        output.span_ms = Some(tick_delta(last.tick_ms, first.tick_ms));
        if points.len() > 1 && points.iter().all(|p| p.tick_ms == first.tick_ms) {
            output
                .warnings
                .push("所有保留点时间戳相同；记录顺序不能换算为速度".into());
        }
        output.latest_matches_cursor = output
            .cursor_at_read
            .zip(last.pixel_x.zip(last.pixel_y))
            .map(|(cursor, (x, y))| cursor == [x as i32, y as i32]);
        if output.latest_matches_cursor == Some(false) {
            output
                .warnings
                .push("最后保留点与采集时光标位置不一致；不强行对齐".into());
        }
        let tick = (|| -> Result<u64> {
            let multiplier = u32_at(&space, 0xfffff78000000004)?;
            let raw = read::<12>(&space, 0xfffff78000000320)?;
            let low = u32::from_le_bytes(raw[..4].try_into()?);
            let high = u32::from_le_bytes(raw[4..8].try_into()?);
            ensure!(
                high == u32::from_le_bytes(raw[8..].try_into()?),
                "共享时钟字段采集不一致"
            );
            let value = (u128::from((u64::from(high) << 32) | u64::from(low))
                * u128::from(multiplier))
                >> 24;
            Ok(u64::try_from(value)?)
        })();
        match tick {
            Ok(tick) => {
                output.shared_tick_ms = Some(tick);
                let difference = tick_delta(last.tick_ms, tick as u32);
                output.latest_point_minus_shared_tick_ms = Some(difference);
                if difference > 100 {
                    output.warnings.push(
                        "鼠标时间戳领先共享时钟；采集时差或时钟来源尚不明确，不换算 UTC".into(),
                    );
                }
            }
            Err(e) => output.warnings.push(format!("共享时钟不可核对：{e:#}")),
        }
    }
    output.record_count = points.len();
    output.status = if !output.complete {
        if points.is_empty() {
            "unavailable"
        } else {
            "partial"
        }
    } else if points.is_empty() {
        "not_observed"
    } else {
        "recovered"
    }
    .into();
    Ok(points)
}

pub fn analyze_mouse_history(
    session: &AnalysisSession,
    limit: usize,
    token: &CancellationToken,
) -> Result<MouseHistoryReport> {
    ensure!(!session.image().is_live(), "鼠标最近轨迹目前仅支持离线镜像");
    ensure!(
        !session.kernel().is_x86_pae(),
        "鼠标最近轨迹目前仅支持 Windows x64"
    );
    ensure!(limit > 0, "鼠标记录上限必须大于零");
    token.check_cancelled()?;
    let mut report = MouseHistoryReport {
        image: session.image().path().display().to_string(),
        records: Vec::new(),
        sessions: Vec::new(),
        modules: Vec::new(),
        complete: true,
        status: "not_observed".into(),
        ring_capacity: CAPACITY,
        session_limit: MAX_SESSIONS,
        record_limit: limit.min(MAX_SESSIONS * CAPACITY),
        warnings: Vec::new(),
        limitations: vec![
            "每会话最多保留最近 64 个位置；旧点会被覆盖，不是全天操作历史".into(),
            "记录不含完整按钮事件，不能据此认定点击、双击或人的手动操作".into(),
            "坐标可能来自硬件、远程桌面或输入注入；不与当前窗口强行关联".into(),
            "保留环内顺序和原始 32 位 tick，不换算 UTC；图中超过 1 秒的空档应断开".into(),
            "仅支持已验证的两个旧版 win32k PDB 和一个 Windows 11 精确模块组合".into(),
        ],
    };
    let processes = session.processes_cancellable(65_536, token)?;
    if !processes.complete {
        report.complete = false;
        report
            .warnings
            .push("进程枚举不完整，会话范围可能缺失".into());
    }
    let mut contexts = BTreeMap::new();
    for p in &processes.processes {
        if p.name.eq_ignore_ascii_case("csrss.exe")
            && let (Some(sid), Some(dtb)) = (p.details.session_id, p.details.directory_table_base)
        {
            if sid > 65535 {
                report.complete = false;
                report
                    .warnings
                    .push(format!("跳过超出验证范围的会话 ID {sid}"));
                continue;
            }
            contexts.entry(sid).or_insert((sid, p.pid, p.eprocess, dtb));
        }
    }
    if contexts.len() > MAX_SESSIONS {
        report.complete = false;
        report
            .warnings
            .push("达到 64 个会话上限，枚举结果不完整".into());
    }
    let contexts: Vec<_> = contexts.into_values().take(MAX_SESSIONS).collect();
    if contexts.is_empty() {
        report.complete = false;
        report.status = "unavailable".into();
        report
            .warnings
            .push("没有可读取的 csrss 会话地址空间".into());
        return Ok(report);
    }
    let drivers = session.drivers(4096)?;
    token.check_cancelled()?;
    if !drivers.complete {
        report.complete = false;
        report.warnings.push("模块枚举不完整".into());
    }
    for name in ["win32k.sys", "win32kbase.sys", "win32kfull.sys"] {
        if name != "win32k.sys"
            && report
                .modules
                .first()
                .is_some_and(|m| LEGACY_KEYS.contains(&m.symbol_key.as_str()))
        {
            break;
        }
        let Some(driver) = drivers
            .records
            .iter()
            .find(|d| d.name.eq_ignore_ascii_case(name))
        else {
            continue;
        };
        match exact_module(session, &contexts, name, driver.base, token) {
            Ok(module) => report.modules.push(module),
            Err(e) if is_cancellation_error(&e) => return Err(e),
            Err(e) => {
                report.complete = false;
                report.warnings.push(format!("{name} 身份不可验证：{e:#}"));
            }
        }
    }
    let layout = validated_layout(&report.modules);
    let module = report.modules.iter().find(|m| m.module == "win32k.sys");
    for (sid, pid, eprocess, dtb) in contexts {
        token.check_cancelled()?;
        let mut s = MouseSession {
            session_id: sid,
            context_pid: pid,
            eprocess,
            dtb,
            status: "unsupported".into(),
            complete: true,
            record_count: 0,
            ring_address: None,
            index_address: None,
            ring_next_write_index: None,
            session_state: None,
            session_globals: None,
            screen_size: None,
            coordinate_unit: "normalized_65535".into(),
            cursor_at_read: None,
            latest_matches_cursor: None,
            shared_tick_ms: None,
            latest_point_minus_shared_tick_ms: None,
            span_ms: None,
            timestamp_order_nondecreasing: true,
            missing_slots: Vec::new(),
            warnings: Vec::new(),
        };
        if let (Some(legacy), Some(module)) = (layout, module) {
            match read_session(session, module, legacy, &mut s, token) {
                Ok(mut points) => {
                    let room = report.record_limit.saturating_sub(report.records.len());
                    if points.len() > room {
                        points.drain(..points.len() - room);
                        if let Some(first) = points.first_mut() {
                            first.delta_ms = None;
                        }
                        s.span_ms = points
                            .first()
                            .zip(points.last())
                            .map(|(a, b)| tick_delta(b.tick_ms, a.tick_ms));
                        if points.is_empty() {
                            s.latest_matches_cursor = None;
                            s.latest_point_minus_shared_tick_ms = None;
                        }
                        s.complete = false;
                        s.status = "partial".into();
                        s.record_count = points.len();
                        s.warnings.push("达到本次报告记录上限，轨迹被截短".into());
                    }
                    report.records.extend(points);
                }
                Err(e) if is_cancellation_error(&e) => return Err(e),
                Err(e) => {
                    s.complete = false;
                    s.status = "unavailable".into();
                    s.warnings.push(format!("{e:#}"));
                }
            }
        } else {
            s.complete = false;
            s.status = if module.is_some() {
                "unsupported"
            } else {
                "unavailable"
            }
            .into();
            s.warnings
                .push("模块身份或布局不在已验证范围；没有套用其他版本的偏移".into());
        }
        report.complete &= s.complete;
        report.sessions.push(s);
    }
    report.status = if !report.complete {
        if !report.records.is_empty() {
            "partial"
        } else if layout.is_none() && module.is_some() {
            "unsupported"
        } else {
            "unavailable"
        }
    } else if report.records.is_empty() {
        "not_observed"
    } else {
        "recovered"
    }
    .into();
    token.check_cancelled()?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn slot(x: u16, tick: u32) -> [u8; 24] {
        let mut raw = [0; 24];
        raw[..4].copy_from_slice(&((999_u32 << 16) | u32::from(x)).to_le_bytes());
        raw[4..8].copy_from_slice(&((799_u32 << 16) | 100).to_le_bytes());
        raw[8..12].copy_from_slice(&tick.to_le_bytes());
        raw
    }
    #[test]
    fn full_ring_keeps_wrapped_order_and_repeated_ticks() {
        let slots = std::array::from_fn(|i| Some(slot(i as u16, 500)));
        let (points, warnings) = decode_ring(&slots, 61, Some([1000, 800])).unwrap();
        assert!(warnings.is_empty());
        assert_eq!(points.len(), 64);
        assert_eq!(points[0].slot, 61);
        assert_eq!(points[63].slot, 60);
        assert_eq!(points[0].pixels, Some([61, 100]));
        assert_eq!(points[0].normalized[0], 61 * 65535 / 999);
        assert_eq!(tick_delta(points[1].tick, points[0].tick), 0);
        assert_eq!(decode_ring(&slots, 64, None).unwrap().0[0].slot, 0);
        assert!(decode_ring(&slots, 65, None).is_err());
    }
    #[test]
    fn uninitialized_boundary_does_not_promote_older_residue() {
        let mut slots = [Some([0; 24]); 64];
        slots[0] = Some(slot(10, 10));
        slots[1] = Some(slot(20, 20));
        slots[60] = Some(slot(30, 30));
        let (points, _) = decode_ring(&slots, 2, None).unwrap();
        assert_eq!(points.iter().map(|p| p.slot).collect::<Vec<_>>(), [0, 1]);
    }
    #[test]
    fn missing_or_invalid_slots_remain_gaps() {
        let mut slots = std::array::from_fn(|i| Some(slot(i as u16, i as u32)));
        slots[1] = None;
        slots[3] = Some(slot(1000, 3));
        let (points, warnings) = decode_ring(&slots, 64, None).unwrap();
        assert_eq!(points.len(), 62);
        assert_eq!(points[1].order, 2);
        assert_eq!(warnings.len(), 1);
    }
    #[test]
    fn clocks_wrap_without_inventing_utc_or_speed() {
        assert_eq!(tick_delta(5, u32::MAX - 4), 10);
        assert_eq!(tick_delta(1, 2), -1);
        assert_eq!(tick_delta(338093, 318781), 19312);
    }
    #[test]
    fn unsupported_or_incomplete_module_sets_are_rejected() {
        let module = |name: &str, key: &str| MouseModuleIdentity {
            module: name.into(),
            symbol_key: key.into(),
            base: 0,
            pdb_name: String::new(),
            identity_dtb: 0,
            symbol_rvas: BTreeMap::new(),
        };
        assert_eq!(
            validated_layout(&[module("win32k.sys", LEGACY_KEYS[0])]),
            Some(true)
        );
        let mut modern: Vec<_> = MODERN_KEYS
            .iter()
            .map(|(name, key)| module(name, key))
            .collect();
        assert_eq!(validated_layout(&modern), Some(false));
        modern[2].symbol_key.push('0');
        assert_eq!(validated_layout(&modern), None);
        assert_eq!(validated_layout(&modern[..2]), None);
    }
}
