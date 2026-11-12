use super::{InteractionOptions, InteractionSection, formats};
use crate::{
    address::X64AddressSpace,
    cancellation::CancellationToken,
    profile::{TypeLayout, read_pdb_symbol_rvas, read_pdb_type_layouts},
    session::AnalysisSession,
    symbols::codeview_from_virtual_pe,
    windows::{ProcessRecord, gui_plugins::WindowRecord, plugins::list_process_dlls},
};
use anyhow::{Context, Result, ensure};
use serde_json::json;
use std::collections::{BTreeMap, HashMap};

struct GuiSymbols {
    key: String,
    base: u64,
    identity_dtb: u64,
    symbols: BTreeMap<String, u32>,
    types: BTreeMap<String, TypeLayout>,
}
impl GuiSymbols {
    fn offset(&self, ty: &str, field: &str) -> Result<u64> {
        self.types
            .get(ty)
            .and_then(|t| t.fields.get(field))
            .map(|f| f.offset)
            .with_context(|| format!("精确 PDB {} 缺少 {ty}.{field}", self.key))
    }
    fn global(&self, name: &str) -> Result<u64> {
        self.base
            .checked_add(u64::from(
                *self
                    .symbols
                    .get(name)
                    .with_context(|| format!("精确 PDB 缺少 {name}"))?,
            ))
            .context("符号地址溢出")
    }
}

fn exact_symbols(
    session: &AnalysisSession,
    dtb: u64,
    base: u64,
    expected: &str,
) -> Result<GuiSymbols> {
    let cv = codeview_from_virtual_pe(session.image(), dtb, base)?;
    ensure!(
        cv.pdb_name.eq_ignore_ascii_case(expected),
        "模块 PDB 名称与期望不符"
    );
    let path = session.symbol_store().resolve(&cv)?;
    let mut pdb = pdb::PDB::open(std::fs::File::open(&path)?)?;
    ensure!(
        pdb.pdb_information()?
            .guid
            .to_string()
            .eq_ignore_ascii_case(&cv.guid)
            && pdb.debug_information()?.age() == Some(cv.age),
        "精确 PDB 身份不匹配"
    );
    Ok(GuiSymbols {
        key: cv.symbol_key,
        base,
        identity_dtb: dtb,
        symbols: read_pdb_symbol_rvas(&path, &["gpqForeground", "gpqCursor", "gSharedInfo"])?,
        types: read_pdb_type_layouts(
            &path,
            &[
                "tagQ",
                "tagCARET",
                "tagWND",
                "tagCLS",
                "tagIMC",
                "tagSHAREDINFO",
                "_SHAREDINFO",
                "_HANDLEENTRY",
                "tagHANDLEENTRY",
                "tagCLIENTIMC",
                "tagINPUTCONTEXT",
                "tagINPUTCONTEXTDX",
                "tagIMCC",
            ],
        )?,
    })
}

fn at(base: u64, offset: u64) -> Result<u64> {
    base.checked_add(offset).context("对象字段地址溢出")
}
fn u32_at(space: &X64AddressSpace<'_>, base: u64, offset: u64) -> Result<u32> {
    let mut bytes = [0; 4];
    space.read_virtual(at(base, offset)?, &mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}
fn bytes(space: &X64AddressSpace<'_>, address: u64, size: usize) -> Result<Vec<u8>> {
    ensure!(size <= 2 * 1024 * 1024, "GUI 对象超出 2 MiB 预算");
    let mut data = vec![0; size];
    space.read_virtual(address, &mut data)?;
    Ok(data)
}
fn kernel_pointer(p: u64) -> bool {
    (0xffff_8000_0000_0000..u64::MAX - 4096).contains(&p) && p & 7 == 0
}
fn user_pointer(p: u64) -> bool {
    (0x10000..0x0000_8000_0000_0000).contains(&p)
}
fn read_ascii_z(space: &X64AddressSpace<'_>, p: u64) -> Result<String> {
    let mut out = Vec::new();
    for i in 0..128 {
        let mut b = [0];
        space.read_virtual(at(p, i)?, &mut b)?;
        if b[0] == 0 {
            return Ok(String::from_utf8(out)?);
        }
        ensure!(b[0].is_ascii_graphic(), "类名包含非 ASCII 字节");
        out.push(b[0]);
    }
    anyhow::bail!("窗口类名过长")
}

pub(super) fn analyze(
    session: &AnalysisSession,
    options: &InteractionOptions,
    token: &CancellationToken,
    output: &mut BTreeMap<String, InteractionSection>,
) -> Result<()> {
    let processes = match session.processes_cancellable(65_536, token) {
        Ok(p) => p,
        Err(e) => {
            for name in ["focus", "edit", "ime"] {
                if let Some(s) = output.get_mut(name) {
                    s.check("processes", "unavailable", format!("{e:#}"));
                }
            }
            return Ok(());
        }
    };
    let windows = match session.windows(65_536) {
        Ok(w) => w,
        Err(e) => {
            for name in ["focus", "edit", "ime"] {
                if let Some(s) = output.get_mut(name) {
                    s.check("windows", "unavailable", format!("{e:#}"));
                }
            }
            return Ok(());
        }
    };
    for name in ["focus", "edit", "ime"] {
        if let Some(s) = output.get_mut(name)
            && (!windows.complete || !processes.complete)
        {
            s.check(
                "enumeration",
                "partial",
                format!("窗口或进程遍历不完整：{}", windows.warnings.join("；")),
            );
        }
    }
    let drivers = session.drivers(4096)?;
    let Some(win32k) = drivers
        .records
        .iter()
        .find(|d| d.name.eq_ignore_ascii_case("win32k.sys"))
    else {
        for name in ["focus", "edit", "ime"] {
            if let Some(s) = output.get_mut(name) {
                s.check("win32k", "unavailable", "没有可验证的 win32k.sys 模块");
            }
        }
        return Ok(());
    };
    let mut contexts = BTreeMap::new();
    for process in &processes.processes {
        if process.name.eq_ignore_ascii_case("csrss.exe")
            && let (Some(sid), Some(dtb)) = (
                process.details.session_id,
                process.details.directory_table_base,
            )
        {
            contexts.entry(sid).or_insert(dtb);
        }
    }
    if contexts.is_empty() {
        for name in ["focus", "edit", "ime"] {
            if let Some(s) = output.get_mut(name) {
                s.check("sessions", "unavailable", "没有可验证的 csrss 会话地址空间");
            }
        }
    }
    // PsLoadedModuleList identifies one loaded win32k image. Its CodeView page
    // may be resident in only one session; retain that exact identity while
    // reading each session's private data through its own DTB.
    let mut resolved = None;
    let mut identity_errors = Vec::new();
    for (&sid, &dtb) in &contexts {
        token.check_cancelled()?;
        match exact_symbols(session, dtb, win32k.base, "win32k.pdb") {
            Ok(symbols) => {
                resolved = Some(symbols);
                break;
            }
            Err(error) => identity_errors.push(format!("session:{sid}: {error:#}")),
        }
    }
    let Some(symbols) = resolved else {
        for name in ["focus", "edit", "ime"] {
            if let Some(s) = output.get_mut(name) {
                s.check("win32k_identity", "unavailable", identity_errors.join("；"));
            }
        }
        return Ok(());
    };
    let process_by_pid: HashMap<_, _> = processes.processes.iter().map(|p| (p.pid, p)).collect();
    for (sid, dtb) in contexts {
        token.check_cancelled()?;
        let scope = format!("session:{sid}");
        let space = X64AddressSpace::new(session.image(), dtb)?;
        if let Some(section) = output.get_mut("focus") {
            if symbols.offset("tagQ", "spwndFocus").is_err() {
                section.check(
                    &scope,
                    "unsupported",
                    format!("{} 未公开 tagQ 布局，不猜测版本偏移", symbols.key),
                );
            } else {
                for symbol in ["gpqForeground", "gpqCursor"] {
                    token.check_cancelled()?;
                    let result = focus_queue(
                        &space,
                        &symbols,
                        sid,
                        dtb,
                        symbol,
                        &windows.records,
                        section,
                    );
                    if let Err(e) = result {
                        section.check(format!("{scope}:{symbol}"), "unavailable", format!("{e:#}"));
                    }
                }
            }
            section.limitations.push(
                "只表示采集时的队列状态；不能把当前窗口关联到较早鼠标点或推断历史点击".into(),
            );
        }
        if !output.contains_key("edit") && !output.contains_key("ime") {
            continue;
        }
        if symbols.offset("tagWND", "pcls").is_err() {
            for name in ["edit", "ime"] {
                if let Some(s) = output.get_mut(name) {
                    s.check(&scope, "unsupported", "精确 win32k PDB 缺少 tagWND 布局");
                }
            }
            continue;
        }
        let mut imm_symbols = HashMap::<u64, Result<GuiSymbols, String>>::new();
        for window in windows.records.iter().filter(|w| w.session_id == sid) {
            token.check_cancelled()?;
            let Some(process) = window.pid.and_then(|pid| process_by_pid.get(&pid)).copied() else {
                continue;
            };
            let Some(process_dtb) = process.details.directory_table_base else {
                continue;
            };
            let user = X64AddressSpace::new(session.image(), process_dtb)?;
            if let Some(section) = output.get_mut("edit") {
                let class = window_class(&space, &user, &symbols, window.address);
                if let Ok(class) = class {
                    if class.eq_ignore_ascii_case("Edit") {
                        match edit_control(&space, &user, &symbols, window, process) {
                            Ok((evidence, fields)) => {
                                section.record("win32_edit", evidence, fields)
                            }
                            Err(e) => section.check(
                                format!("window:{:#x}", window.address),
                                "unavailable",
                                format!("{e:#}"),
                            ),
                        }
                    } else if class.to_ascii_lowercase().starts_with("richedit") {
                        section.check(
                            format!("window:{:#x}", window.address),
                            "unsupported",
                            "RichEdit 私有布局尚无精确版本适配",
                        );
                    }
                } else if let Err(e) = class {
                    section.check(
                        format!("window:{:#x}", window.address),
                        "unavailable",
                        format!("不能核对窗口类：{e:#}"),
                    );
                }
            }
            if let Some(section) = output.get_mut("ime") {
                let imc = symbols
                    .offset("tagWND", "hImc")
                    .and_then(|o| space.read_u64(at(window.address, o)?));
                match imc {
                    Ok(0) => (),
                    Ok(handle) => {
                        let layout = imm_symbols.entry(process.pid).or_insert_with(|| {
                            process_imm_symbols(session, process, process_dtb)
                                .map_err(|e| format!("{e:#}"))
                        });
                        match layout {
                            Ok(imm) => match ime_context(
                                &space,
                                &user,
                                &symbols,
                                imm,
                                window,
                                process,
                                handle,
                                &windows.records,
                            ) {
                                Ok(Some((evidence, fields))) => {
                                    section.record("imm_composition", evidence, fields)
                                }
                                Ok(None) => section.check(
                                    format!("window:{:#x}", window.address),
                                    "not_observed",
                                    "输入上下文未初始化、未关联活动窗口或没有组合缓冲",
                                ),
                                Err(e) => section.check(
                                    format!("window:{:#x}", window.address),
                                    "unavailable",
                                    format!("{e:#}"),
                                ),
                            },
                            Err(e) => section.check(
                                format!("pid:{}", process.pid),
                                "unsupported",
                                e.clone(),
                            ),
                        }
                    }
                    Err(e) => section.check(
                        format!("window:{:#x}", window.address),
                        "unavailable",
                        format!("{e:#}"),
                    ),
                }
            }
        }
    }
    if let Some(s) = output.get_mut("edit") {
        s.limitations.push("首版支持已验证旧版 x64 Win32 Edit；当前文本与有限撤销内容不等于文档未保存状态；现代 Notepad/Electron 与 RichEdit 私有对象另需适配".into());
    }
    if let Some(s) = output.get_mut("ime") {
        s.limitations.push("只解析精确类型可用的 IMM INPUTCONTEXT / COMPOSITIONSTRING；TSF、输入法私有候选对象与长期历史不在已覆盖范围".into());
    }
    let _ = options;
    Ok(())
}

fn focus_queue(
    space: &X64AddressSpace<'_>,
    symbols: &GuiSymbols,
    sid: u32,
    dtb: u64,
    name: &str,
    windows: &[WindowRecord],
    section: &mut InteractionSection,
) -> Result<()> {
    let address = symbols.global(name)?;
    let queue = space.read_u64(address)?;
    if queue == 0 {
        section.check(
            format!("session:{sid}:{name}"),
            "not_observed",
            "队列指针为空",
        );
        return Ok(());
    }
    ensure!(kernel_pointer(queue), "输入队列指针无效");
    for field in [
        "spwndActive",
        "spwndFocus",
        "spwndCapture",
        "spwndActivePrev",
    ] {
        let field_address = at(queue, symbols.offset("tagQ", field)?)?;
        let target = space.read_u64(field_address)?;
        if target == 0 {
            continue;
        }
        ensure!(kernel_pointer(target), "窗口指针无效");
        let matched = windows
            .iter()
            .find(|w| w.address == target && w.session_id == sid)
            .context("窗口指针未通过同会话窗口树交叉核对")?;
        section.record(
            "queue_window",
            json!({"session_id":sid,"dtb":dtb,"queue":queue,
            "symbol":name,"pdb_key":symbols.key,"symbol_identity_dtb":symbols.identity_dtb,
            "field_address":field_address,"physical_address":space.translate(field_address)?}),
            json!({"role":field,"window":matched}),
        );
    }
    if let (Ok(caret_offset), Ok(window_offset)) = (
        symbols.offset("tagQ", "caret"),
        symbols.offset("tagCARET", "spwnd"),
    ) {
        let caret = at(queue, caret_offset)?;
        let target = space.read_u64(at(caret, window_offset)?)?;
        if target != 0 {
            let matched = windows
                .iter()
                .find(|w| w.address == target && w.session_id == sid)
                .context("插入光标窗口未通过交叉核对")?;
            let mut coords = serde_json::Map::new();
            for field in ["x", "y", "cx", "cy"] {
                let value = u32_at(space, caret, symbols.offset("tagCARET", field)?)? as i32;
                coords.insert(field.into(), json!(value));
            }
            section.record("caret", json!({"session_id":sid,"dtb":dtb,"virtual_address":caret,"pdb_key":symbols.key}),
                json!({"window":matched,"coordinates":coords,"coordinate_space":"raw_caret_window_context"}));
        }
    }
    section.check(
        format!("session:{sid}:{name}"),
        "checked",
        "队列字段与同会话窗口树已核对",
    );
    Ok(())
}

fn window_class(
    kernel: &X64AddressSpace<'_>,
    user: &X64AddressSpace<'_>,
    symbols: &GuiSymbols,
    window: u64,
) -> Result<String> {
    let class = kernel.read_u64(at(window, symbols.offset("tagWND", "pcls")?)?)?;
    ensure!(kernel_pointer(class), "窗口类对象无效");
    let name = kernel.read_u64(at(class, symbols.offset("tagCLS", "lpszAnsiClassName")?)?)?;
    if user_pointer(name) {
        read_ascii_z(user, name)
    } else {
        read_ascii_z(kernel, name)
    }
}

fn edit_control(
    kernel: &X64AddressSpace<'_>,
    user: &X64AddressSpace<'_>,
    symbols: &GuiSymbols,
    window: &WindowRecord,
    process: &ProcessRecord,
) -> Result<(serde_json::Value, serde_json::Value)> {
    ensure!(
        [
            "21E2778DD2954987A9B7212463FFDC5E2",
            "A9F6403F14074E9D8A07D0AA6F0C1CFF2"
        ]
        .contains(&symbols.key.as_str()),
        "Win32 Edit 私有布局未适配该精确系统版本"
    );
    let size = symbols.types.get("tagWND").context("缺少 tagWND")?.size;
    ensure!(
        u32_at(
            kernel,
            window.address,
            symbols.offset("tagWND", "cbwndExtra")?
        )? >= 8,
        "窗口没有 EDIT 状态指针空间"
    );
    let state = kernel.read_u64(at(window.address, size)?)?;
    ensure!(user_pointer(state), "EDIT 状态指针不是用户态地址");
    let raw = bytes(user, state, 0x142)?;
    let hwnd = kernel.read_u64(window.address)?;
    ensure!(
        formats::u64le(&raw, 0x40)? == hwnd && hwnd != 0,
        "EDIT 的 HWND 反向归属不一致"
    );
    let chars = formats::u32le(&raw, 0x10)? as usize;
    let begin = formats::u32le(&raw, 0x18)? as usize;
    let end = formats::u32le(&raw, 0x20)? as usize;
    ensure!(
        chars <= 512 * 1024 && begin <= chars && end <= chars,
        "EDIT 长度或选区无效"
    );
    ensure!(
        formats::u16le(&raw, 0x34)? == 0,
        "EDIT 使用掩码/编码缓冲，未按明文解释"
    );
    let htext = formats::u64le(&raw, 0)?;
    ensure!(user_pointer(htext), "EDIT 文本句柄无效");
    let text_address = user.read_u64(htext)?;
    ensure!(user_pointer(text_address), "EDIT 文本地址无效");
    let text_raw = bytes(user, text_address, (chars + 1) * 2)?;
    ensure!(text_raw[chars * 2..] == [0, 0], "EDIT 文本长度与终止符不符");
    let text = formats::utf16(&text_raw[..chars * 2])?;
    let undo_len = formats::u32le(&raw, 0xb4)? as usize;
    let undo_address = formats::u64le(&raw, 0xa8)?;
    let undo = if undo_len > 0 {
        ensure!(
            undo_len <= 512 * 1024 && user_pointer(undo_address),
            "撤销缓冲范围无效"
        );
        Some(formats::utf16(&bytes(user, undo_address, undo_len * 2)?)?)
    } else {
        None
    };
    Ok((
        json!({"pid":process.pid,"eprocess":process.eprocess,"create_time_raw":process.details.create_time_raw,
        "session_id":window.session_id,"dtb":process.details.directory_table_base,"window_object":window.address,
        "hwnd":hwnd,"state_address":state,"text_address":text_address,"text_physical_address":user.translate(text_address)?,
        "pdb_key":symbols.key,"layout_basis":"win7_x64_edit_hwnd_length_selection_and_terminator_validated"}),
        json!({"text":text,"selection_start":begin,"selection_end":end,"undo_text":undo,"undo_address":undo_address,
            "parent_window":window.parent,"saved_state":"unknown"}),
    ))
}

fn process_imm_symbols(
    session: &AnalysisSession,
    process: &ProcessRecord,
    dtb: u64,
) -> Result<GuiSymbols> {
    ensure!(
        process.details.wow64 != Some(true),
        "WOW64 IMM 客户端布局尚未适配"
    );
    let modules = list_process_dlls(
        session.image(),
        session.kernel(),
        session.profile(),
        process,
        4096,
    )?;
    let module = modules
        .records
        .iter()
        .find(|m| m.name.eq_ignore_ascii_case("imm32.dll"))
        .context("没有已验证的 imm32.dll 加载器记录")?;
    let symbols = exact_symbols(session, dtb, module.base, "imm32.pdb")?;
    imm_offset(&symbols, "tagCLIENTIMC", "hInputContext")?;
    imm_offset(&symbols, "tagINPUTCONTEXT", "hCompStr")?;
    Ok(symbols)
}

fn imm_offset(symbols: &GuiSymbols, ty: &str, field: &str) -> Result<u64> {
    if let Ok(offset) = symbols.offset(ty, field) {
        return Ok(offset);
    }
    // Exact Win7 x64 imm32 build: ImmLockClientImc and InternalImmLockIMC
    // validate CLIENTIMC offsets 0/0xc; ImmGetCompositionStringA reads the
    // SDK INPUTCONTEXT.hCompStr at 0x120. Do not apply to another PDB identity.
    if symbols.key == "98F27BA5AEE541ECBEE00CD03AD50FEE2" {
        match (ty, field) {
            ("tagCLIENTIMC", "hInputContext") | ("tagINPUTCONTEXT", "hWnd") => return Ok(0),
            ("tagCLIENTIMC", "dwFlags") => return Ok(0xc),
            ("tagINPUTCONTEXT", "hCompStr") => return Ok(0x120),
            _ => (),
        }
    }
    anyhow::bail!("IMM 布局未适配精确 PDB {} 的 {ty}.{field}", symbols.key)
}

fn global_lock(space: &X64AddressSpace<'_>, handle: u64) -> Result<u64> {
    ensure!(user_pointer(handle), "IMCC 本地句柄无效");
    let pointer = if handle & 2 != 0 {
        space.read_u64(handle)?
    } else {
        handle
    };
    ensure!(user_pointer(pointer), "IMCC 缓冲指针无效");
    Ok(pointer)
}

#[allow(clippy::too_many_arguments)]
fn ime_context(
    kernel: &X64AddressSpace<'_>,
    user: &X64AddressSpace<'_>,
    symbols: &GuiSymbols,
    imm: &GuiSymbols,
    window: &WindowRecord,
    process: &ProcessRecord,
    handle: u64,
    windows: &[WindowRecord],
) -> Result<Option<(serde_json::Value, serde_json::Value)>> {
    let shared = symbols.global("gSharedInfo")?;
    let shared_type = if symbols.types.contains_key("tagSHAREDINFO") {
        "tagSHAREDINFO"
    } else {
        "_SHAREDINFO"
    };
    let entry_type = if symbols.types.contains_key("_HANDLEENTRY") {
        "_HANDLEENTRY"
    } else {
        "tagHANDLEENTRY"
    };
    let entry_size = symbols
        .types
        .get(entry_type)
        .context("缺少 USER 句柄表类型")?
        .size;
    ensure!((16..=64).contains(&entry_size), "USER 句柄记录大小无效");
    let table = kernel.read_u64(at(shared, symbols.offset(shared_type, "aheList")?)?)?;
    let entry = at(table, (handle & 0xffff) * entry_size)?;
    let mut kind = [0];
    kernel.read_virtual(at(entry, symbols.offset(entry_type, "bType")?)?, &mut kind)?;
    ensure!(kind[0] == 17, "USER 句柄不是 INPUTCONTEXT");
    let object = kernel.read_u64(at(entry, symbols.offset(entry_type, "phead")?)?)?;
    ensure!(
        kernel.read_u64(object)? == handle,
        "输入上下文句柄代次不匹配"
    );
    let client = kernel.read_u64(at(object, symbols.offset("tagIMC", "dwClientImcData")?)?)?;
    if client == 0 {
        return Ok(None);
    }
    ensure!(user_pointer(client), "CLIENTIMC 指针无效");
    let client_flags = u32_at(user, client, imm_offset(imm, "tagCLIENTIMC", "dwFlags")?)?;
    ensure!(client_flags & 0x40 == 0, "CLIENTIMC 已标记销毁");
    ensure!(
        client_flags & 1 != 0,
        "CLIENTIMC 未标记 Unicode，未将 ANSI 组合缓冲猜作 UTF-16"
    );
    let input_handle = user.read_u64(at(
        client,
        imm_offset(imm, "tagCLIENTIMC", "hInputContext")?,
    )?)?;
    if input_handle == 0 {
        return Ok(None);
    }
    let input = global_lock(user, input_handle)?;
    let target_hwnd = user.read_u64(at(input, imm_offset(imm, "tagINPUTCONTEXT", "hWnd")?)?)?;
    if target_hwnd == 0 {
        return Ok(None);
    }
    // HIMC can be associated with multiple windows. Check its active target
    // against the same process and session, preserving the HIMC back-reference.
    let target_window = windows
        .iter()
        .find(|candidate| {
            candidate.pid == Some(process.pid)
                && candidate.session_id == window.session_id
                && kernel.read_u64(candidate.address).ok() == Some(target_hwnd)
                && symbols
                    .offset("tagWND", "hImc")
                    .ok()
                    .and_then(|offset| at(candidate.address, offset).ok())
                    .and_then(|address| kernel.read_u64(address).ok())
                    == Some(handle)
        })
        .context("INPUTCONTEXT 活动目标未通过同进程窗口及 HIMC 反向核对")?;
    let comp_handle = user.read_u64(at(input, imm_offset(imm, "tagINPUTCONTEXT", "hCompStr")?)?)?;
    if comp_handle == 0 {
        return Ok(None);
    }
    let comp = global_lock(user, comp_handle)?;
    let length = u32_at(user, comp, 0)? as usize;
    let fields = formats::composition_string(&bytes(user, comp, length)?)?;
    Ok(Some((
        json!({"pid":process.pid,"window":window.address,"hwnd":target_hwnd,"himc":handle,
        "imc_object":object,"client_imc":client,"input_context":input,"composition":comp,
        "dtb":process.details.directory_table_base,"pdb_key":imm.key,"client_imc_flags":client_flags,
        "active_window_object":target_window.address,
        "layout_basis":if imm.types.contains_key("tagCLIENTIMC") && imm.types.contains_key("tagINPUTCONTEXT") {"exact_pdb_types"}else{"exact_win7_imm32_code_and_sdk_layout"},
        "physical_address":user.translate(comp)?}),
        fields,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_imm_layout_requires_exact_verified_module_identity() {
        let mut symbols = GuiSymbols {
            key: "98F27BA5AEE541ECBEE00CD03AD50FEE2".into(),
            base: 0,
            identity_dtb: 0,
            symbols: BTreeMap::new(),
            types: BTreeMap::new(),
        };
        assert_eq!(
            imm_offset(&symbols, "tagINPUTCONTEXT", "hCompStr").unwrap(),
            0x120
        );
        assert_eq!(imm_offset(&symbols, "tagCLIENTIMC", "dwFlags").unwrap(), 12);
        symbols.key = "another-build".into();
        assert!(imm_offset(&symbols, "tagINPUTCONTEXT", "hCompStr").is_err());
    }
}
