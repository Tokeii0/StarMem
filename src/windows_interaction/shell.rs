use super::{InteractionOptions, InteractionSection, formats};
use crate::{
    address::X64AddressSpace, cancellation::CancellationToken, clipboard::ClipboardScanOptions,
    registry::RegistryValueData, session::AnalysisSession,
    system::registry::print_registry_key_exact_loaded,
};
use anyhow::Result;
use serde_json::json;
use sha2::{Digest, Sha256};

pub(super) fn clipboard_files(
    session: &AnalysisSession,
    options: &InteractionOptions,
    token: &CancellationToken,
    section: &mut InteractionSection,
) -> Result<()> {
    token.check_cancelled()?;
    let report = match session.clipboard_scan_cancellable(
        &ClipboardScanOptions {
            limit: options.limit,
            max_data_size: options.max_file_bytes as usize,
        },
        token,
        |_| {},
    ) {
        Ok(r) => r,
        Err(e) => {
            if crate::cancellation::is_cancellation_error(&e) {
                return Err(e);
            }
            section.check("clipboard", "unavailable", format!("{e:#}"));
            return Ok(());
        }
    };
    if !report.complete {
        section.check("clipboard", "partial", report.warnings.join("；"));
    }
    section.check(
        "clipboard_formats",
        "checked",
        format!(
            "枚举 {} 个活动格式，其中 CF_HDROP {} 个",
            report.formats.len(),
            report.formats.iter().filter(|r| r.format_id == 15).count()
        ),
    );
    let processes = session.processes_cancellable(65_536, token)?;
    for format in report.formats.iter().filter(|r| r.format_id == 15) {
        token.check_cancelled()?;
        let scope = format!("session:{}:clip:{:#x}", format.session_id, format.clip_base);
        if format.delayed_render {
            section.check(
                scope,
                "unavailable",
                "CF_HDROP 为延迟渲染，没有驻留文件列表",
            );
            continue;
        }
        if !format.data_complete {
            section.check(scope, "missing_pages", "CF_HDROP 数据块不完整");
            continue;
        }
        let Some(length) = format
            .data_size
            .map(|n| n as usize)
            .filter(|n| *n <= options.max_file_bytes as usize)
        else {
            section.check(scope, "unavailable", "CF_HDROP 声明大小不可用或超预算");
            continue;
        };
        let data = (|| -> Result<Vec<u8>> {
            let mut bytes = vec![0; length];
            if let Some(object) = format.data_object {
                let dtb = processes
                    .processes
                    .iter()
                    .find(|p| {
                        p.name.eq_ignore_ascii_case("csrss.exe")
                            && p.details.session_id == Some(format.session_id)
                    })
                    .and_then(|p| p.details.directory_table_base)
                    .ok_or_else(|| anyhow::anyhow!("缺少剪贴板会话地址空间"))?;
                let space = X64AddressSpace::new(session.image(), dtb)?;
                let mut header = [0; 20];
                space.read_virtual(object, &mut header)?;
                anyhow::ensure!(
                    formats::u64le(&header, 0)? == format.handle
                        && formats::u32le(&header, 16)? as usize == length,
                    "剪贴板对象句柄/长度与所属格式不符"
                );
                let address = object
                    .checked_add(0x14)
                    .ok_or_else(|| anyhow::anyhow!("剪贴板地址溢出"))?;
                space.read_virtual(address, &mut bytes)?;
            } else {
                let address = format
                    .data_physical_address
                    .and_then(|p| p.checked_add(0x14))
                    .ok_or_else(|| anyhow::anyhow!("缺少剪贴板数据地址"))?;
                anyhow::ensure!(
                    length as u64 <= 0x1000 - (address & 0xfff),
                    "跨物理页的 Uscb 对象缺少虚拟映射，未猜测连续性"
                );
                session.image().read_physical(address, &mut bytes)?;
            }
            Ok(bytes)
        })();
        match data.and_then(|b|formats::hdrop(&b).map(|fields|(hex::encode(Sha256::digest(&b)),fields))) {
            Ok((sha256,fields))=>section.record("clipboard_file_list",json!({"session_id":format.session_id,"window_station":format.window_station,
                "clip_array":format.clip_base,"handle":format.handle,"data_object":format.data_object,
                "data_physical_object":format.data_physical_address,"data_size":format.data_size,"sha256":sha256}),fields),
            Err(e)=>section.check(scope,"unavailable",format!("{e:#}")),
        }
    }
    section.limitations.push("已验证 CF_HDROP 文件列表；注册格式名未解析时不猜测 Preferred DropEffect，也不推断复制来源或粘贴目标".into());
    Ok(())
}

pub(super) fn explorer(
    session: &AnalysisSession,
    options: &InteractionOptions,
    token: &CancellationToken,
    section: &mut InteractionSection,
) -> Result<()> {
    let processes = session.processes_cancellable(65_536, token)?;
    if !processes.complete {
        section.check("processes", "partial", "进程枚举不完整");
    }
    let hives = match session.hives(4096) {
        Ok(r) => r,
        Err(e) => {
            section.check("hives", "unavailable", format!("{e:#}"));
            return Ok(());
        }
    };
    if !hives.complete {
        section.check("hives", "partial", hives.warnings.join("；"));
    }
    let user_hives: Vec<_> = hives
        .records
        .iter()
        .filter(|h| {
            [&h.file_path, &h.user_name]
                .iter()
                .any(|s| s.to_ascii_lowercase().ends_with("ntuser.dat"))
        })
        .collect();
    section.check(
        "user_hives",
        if user_hives.is_empty() {
            "unavailable"
        } else {
            "checked"
        },
        format!(
            "已加载 Hive {} 个，匹配 NTUSER.DAT {} 个",
            hives.records.len(),
            user_hives.len()
        ),
    );
    for hive in user_hives {
        for (kind, key) in [
            (
                "typed_path",
                r"Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths",
            ),
            (
                "search_mru",
                r"Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery",
            ),
            (
                "open_save_mru",
                r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU",
            ),
            (
                "last_visited_mru",
                r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU",
            ),
        ] {
            token.check_cancelled()?;
            let report = print_registry_key_exact_loaded(
                session,
                &processes,
                hive.cmhive,
                &hive.root_path,
                key,
                true,
                options.limit,
            );
            let scope = format!("{:#x}:{key}", hive.cmhive);
            if !report.complete {
                let absent = format!("在 {} 中没有找到注册表键 {key}", hive.root_path);
                let verified_absence = report.available
                    && report.records.is_empty()
                    && report.warnings.len() == 1
                    && report.warnings[0] == absent;
                section.check(
                    &scope,
                    if verified_absence {
                        "not_observed"
                    } else if report.available {
                        "partial"
                    } else {
                        "unavailable"
                    },
                    report.warnings.join("；"),
                );
            }
            for record in report.records.iter().filter(|r| r.kind == "value") {
                let Some(data) = &record.data else {
                    continue;
                };
                if record.name.eq_ignore_ascii_case("MRUListEx") {
                    if let RegistryValueData::Binary(hex) = data {
                        match hex::decode(hex).ok().and_then(|b|mru_order(&b).ok()) {
                            Some(order)=>section.record("mru_order",json!({"cmhive":hive.cmhive,"hive":hive.root_path,"key":record.path,"value":record.name}),json!({"indices":order,"time_semantic":"order_only"})),
                            None=>section.check(&scope,"partial","MRUListEx 结构损坏"),
                        }
                    }
                    continue;
                }
                let fields = match (kind, data) {
                    ("typed_path", RegistryValueData::String(s)) => json!({"path":s}),
                    ("search_mru", RegistryValueData::Binary(s)) => {
                        let decoded = hex::decode(s).ok().and_then(|b| formats::utf16(&b).ok());
                        if decoded.is_none() {
                            section.check(
                                &scope,
                                "unsupported",
                                "搜索 MRU 不是完整 UTF-16，保留原始值",
                            );
                        }
                        json!({"query":decoded.map(|s|s.trim_end_matches('\0').to_owned()),"raw":s})
                    }
                    (_, RegistryValueData::Binary(s)) => {
                        match hex::decode(s)
                            .map_err(anyhow::Error::from)
                            .and_then(|b| formats::shell_pidl(&b, kind == "last_visited_mru"))
                        {
                            Ok(mut value) => {
                                value["raw_hex"] = json!(s);
                                if value["pidl_complete"] == false {
                                    section.check(
                                        &scope,
                                        "unsupported",
                                        "PIDL 含尚未支持的 Shell 项；仅保留已解析组件",
                                    );
                                }
                                value
                            }
                            Err(error) => {
                                section.check(
                                    &scope,
                                    "unsupported",
                                    format!("PIDL 未解码：{error:#}"),
                                );
                                json!({"raw_hex":s,"path_decoded":false})
                            }
                        }
                    }
                    _ => continue,
                };
                section.record(kind,json!({"cmhive":hive.cmhive,"hive":hive.root_path,"hive_path":hive.file_path,
                    "key":record.path,"value":record.name,"user_name":hive.user_name,
                    "container_key_last_write":record.last_write,"time_semantic":"container_time_not_item_access_time"}),fields);
            }
        }
    }
    section.limitations.push("本节恢复 Explorer 地址栏、搜索及打开/保存对话框的 MRU，解码常见文件系统 PIDL；不把历史记录当当前目录或选中文件。DirectUI 选择状态和未知 Shell 命名空间尚未适配".into());
    Ok(())
}

fn mru_order(bytes: &[u8]) -> Result<Vec<u32>> {
    anyhow::ensure!(bytes.len().is_multiple_of(4), "MRUListEx 非 DWORD 对齐");
    let mut order = Vec::new();
    for offset in (0..bytes.len()).step_by(4) {
        let value = formats::u32le(bytes, offset)?;
        if value == u32::MAX {
            return Ok(order);
        }
        anyhow::ensure!(!order.contains(&value), "MRUListEx 包含重复索引");
        order.push(value);
    }
    anyhow::bail!("MRUListEx 缺少终止标记")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mru_order_is_not_a_timestamp() {
        let b = [2u32, 0, 5, u32::MAX]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>();
        assert_eq!(mru_order(&b).unwrap(), [2, 0, 5]);
        assert!(mru_order(&b[..12]).is_err());
        let b = [2u32, 2, u32::MAX]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>();
        assert!(mru_order(&b).is_err());
    }
}
