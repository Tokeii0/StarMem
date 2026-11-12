//! MSFS endpoints and bounded, structurally verified queued messages.
//! Private queue layouts are selected by the loaded driver's exact CodeView
//! identity, never by a mailslot-looking string or a guessed Windows version.

use super::WindowsKernelContext;
use super::files::scan_files_cancellable;
use super::pipe_plugins::{FileSystemDeviceEvidence, PipeOwnerRecord, validate_file_system_device};
use super::plugins::find_handle_owners;
use crate::address::X64AddressSpace;
use crate::cancellation::{CancellationToken, is_cancellation_error};
use crate::image::MemoryImage;
use crate::output_policy::OutputPolicy;
use crate::profile::KernelProfile;
use crate::symbols::codeview_from_virtual_pe;
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;

// Verified against MsCreateFcb, MsQueryInformation, MsAddDataQueueEntry and
// MsReadDataQueue from the image's MSFS PE. See docs/MAILSLOTS.md.
const MSFS_PDB_KEY: &str = "9FABAE7C6C935698994D842F89A5B15C1";
const FCB_HEADER: u32 = 0x0188_0604;
// MsCreateMailslotPrefix creates these namespace guards, not message queues.
const PROTECTED_PREFIX_HEADER: u32 = 0x0188_0609;
const QUEUE_HEAD: u64 = 0x130;

#[derive(Debug, Clone)]
pub struct MailslotOptions {
    pub file_limit: usize,
    pub process_limit: usize,
    pub handle_scan_limit: usize,
    pub limit: usize,
    pub message_limit: usize,
    pub max_message_bytes: usize,
    pub max_total_message_bytes: usize,
    pub output: Option<PathBuf>,
    pub force: bool,
}

impl Default for MailslotOptions {
    fn default() -> Self {
        Self {
            file_limit: 1_000_000,
            process_limit: 65_536,
            handle_scan_limit: 4_000_000,
            limit: 100_000,
            message_limit: 4096,
            max_message_bytes: 1024 * 1024,
            max_total_message_bytes: 16 * 1024 * 1024,
            output: None,
            force: false,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct MailslotRecord {
    pub file_object: u64,
    pub physical_address: u64,
    pub object_header: u64,
    pub raw_name: String,
    pub full_name: String,
    pub device_object: u64,
    pub driver_object: u64,
    pub driver_name: String,
    pub driver_base: Option<u64>,
    pub msfs_pdb_key: Option<String>,
    pub fs_context: Option<u64>,
    pub fs_context2: Option<u64>,
    pub fs_context_header: Option<u32>,
    pub endpoint_kind: String,
    pub endpoint_state: String,
    pub object_type_verified: bool,
    pub owners: Vec<PipeOwnerRecord>,
}

#[derive(Debug, Serialize)]
pub struct MailslotMemoryRange {
    pub virtual_address: u64,
    pub physical_address: u64,
    pub length: usize,
}

#[derive(Debug, Serialize)]
pub struct MailslotMessage {
    pub queue_fcb: u64,
    pub index: usize,
    pub entry_address: u64,
    pub buffer_address: u64,
    pub size: usize,
    pub recovered_bytes: usize,
    pub complete: bool,
    pub data_hex: Option<String>,
    pub utf8_text: Option<String>,
    pub sha256: Option<String>,
    pub memory_ranges: Vec<MailslotMemoryRange>,
    pub output: Option<PathBuf>,
    pub warning: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct MailslotQueue {
    pub fcb: u64,
    pub layout: Option<String>,
    pub state: Option<u32>,
    pub bytes_in_queue: Option<u32>,
    pub entries_in_queue: Option<u32>,
    pub maximum_message_size: Option<u32>,
    pub messages: Vec<MailslotMessage>,
    pub complete: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct MailslotReport {
    pub records: Vec<MailslotRecord>,
    pub queues: Vec<MailslotQueue>,
    pub file_objects_examined: usize,
    pub processes_examined: usize,
    pub handle_entries_examined: usize,
    pub recovered_messages: usize,
    pub recovered_bytes: usize,
    pub complete: bool,
    pub scope: String,
    pub warnings: Vec<String>,
}

pub fn scan_mailslots(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    options: &MailslotOptions,
    cancellation: &CancellationToken,
) -> Result<MailslotReport> {
    ensure!(!kernel.is_x86_pae(), "mailslots 当前需要 64 位 Windows");
    ensure!(
        options.file_limit > 0
            && options.process_limit > 0
            && options.handle_scan_limit > 0
            && options.limit > 0
            && options.message_limit > 0,
        "扫描和结果上限必须大于零"
    );
    ensure!(
        options.max_message_bytes > 0
            && options.max_message_bytes <= 16 * 1024 * 1024
            && options.max_total_message_bytes > 0
            && options.max_total_message_bytes <= 64 * 1024 * 1024,
        "单条消息上限须为 1–16777216 字节，总预算须为 1–67108864 字节"
    );
    cancellation.check_cancelled()?;
    let context_offset = profile.type_field("_FILE_OBJECT", "FsContext")?.offset;
    let context2_offset = profile.type_field("_FILE_OBJECT", "FsContext2")?.offset;
    let driver_start_offset = profile.type_field("_DRIVER_OBJECT", "DriverStart")?.offset;
    for (ty, fields) in [
        ("_DEVICE_OBJECT", &["Type", "Size", "DriverObject"][..]),
        ("_DRIVER_OBJECT", &["Type", "Size", "DriverName"][..]),
    ] {
        profile.type_layout(ty)?;
        for field in fields {
            profile.type_field(ty, field)?;
        }
    }
    let files = scan_files_cancellable(image, kernel, profile, options.file_limit, cancellation)?;
    let file_objects_examined = files.records.len();
    let mut complete = files.complete;
    let mut warnings = files.warnings;
    let space = X64AddressSpace::new(image, kernel.directory_table_base)?;
    let mut devices: HashMap<u64, Option<FileSystemDeviceEvidence>> = HashMap::new();
    let mut driver_keys = HashMap::new();
    let mut records = Vec::new();
    let mut fcb_layouts = BTreeMap::new();
    for file in files.records {
        cancellation.check_cancelled()?;
        let device = devices.entry(file.device_object).or_insert_with(|| {
            validate_file_system_device(&space, profile, file.device_object, "msfs")
        });
        let Some(device) = device else {
            continue;
        };
        let raw_name = file.name.unwrap_or_default();
        let Some(full_name) = normalize_name(&raw_name) else {
            continue;
        };
        if records.len() == options.limit {
            complete = false;
            warnings.push(format!(
                "mailslot FILE_OBJECT 达到 {} 条上限",
                options.limit
            ));
            break;
        }
        let (driver_base, key) = driver_keys.entry(device.driver_object).or_insert_with(|| {
            let base = space
                .read_u64(device.driver_object + driver_start_offset)
                .ok();
            let key = base
                .and_then(|base| {
                    codeview_from_virtual_pe(image, kernel.directory_table_base, base).ok()
                })
                .filter(|cv| cv.pdb_name.eq_ignore_ascii_case("msfs.pdb"))
                .map(|cv| cv.symbol_key);
            (base, key)
        });
        let fcb = space.read_u64(file.file_object + context_offset).ok();
        let context2 = space.read_u64(file.file_object + context2_offset).ok();
        let supported = key.as_deref() == Some(MSFS_PDB_KEY);
        let context_header = fcb
            .filter(|address| kernel_pointer(*address))
            .and_then(|address| {
                let mut bytes = [0; 4];
                space.read_virtual(address, &mut bytes).ok()?;
                Some(u32::from_le_bytes(bytes))
            });
        let endpoint_kind = classify_endpoint(supported, context_header, context2);
        if let Some(fcb) = fcb.filter(|address| kernel_pointer(*address)) {
            if endpoint_kind != "protected_prefix" {
                fcb_layouts.entry(fcb).or_insert(supported);
            }
        } else {
            complete = false;
            warnings.push(format!(
                "FILE_OBJECT {:#x} 的 FsContext 不可读或无效",
                file.file_object
            ));
        }
        records.push(MailslotRecord {
            file_object: file.file_object,
            physical_address: file.physical_address,
            object_header: file.object_header,
            raw_name,
            full_name,
            device_object: file.device_object,
            driver_object: device.driver_object,
            driver_name: device.driver_name.clone(),
            driver_base: *driver_base,
            msfs_pdb_key: key.clone(),
            fs_context: fcb,
            fs_context2: context2,
            fs_context_header: context_header,
            endpoint_kind: endpoint_kind.to_owned(),
            endpoint_state: "residual_pool_object".to_owned(),
            object_type_verified: file.object_type_verified,
            owners: Vec::new(),
        });
    }
    let targets = records
        .iter()
        .map(|record| record.file_object)
        .collect::<HashSet<_>>();
    let owners = find_handle_owners(
        image,
        kernel,
        profile,
        &targets,
        options.process_limit,
        options.handle_scan_limit,
    )?;
    cancellation.check_cancelled()?;
    complete &= owners.complete;
    warnings.extend(owners.warnings);
    let mut owner_map: HashMap<u64, Vec<PipeOwnerRecord>> = HashMap::new();
    for owner in owners.records {
        owner_map
            .entry(owner.object)
            .or_default()
            .push(PipeOwnerRecord {
                pid: owner.pid,
                process: owner.process,
                handle: owner.handle,
                handle_table_entry: owner.entry,
                object_header: owner.object_header,
                granted_access: owner.granted_access,
            });
    }
    for record in &mut records {
        if let Some(owners) = owner_map.remove(&record.file_object) {
            record.owners = owners;
            record.endpoint_state = "active_handle".to_owned();
        }
    }
    let mut queues = Vec::new();
    let mut budget = MessageBudget {
        entries: options.message_limit,
        bytes: options.max_total_message_bytes,
    };
    for (fcb, supported) in fcb_layouts {
        cancellation.check_cancelled()?;
        let mut queue = MailslotQueue {
            fcb,
            layout: None,
            state: None,
            bytes_in_queue: None,
            entries_in_queue: None,
            maximum_message_size: None,
            messages: Vec::new(),
            complete: false,
            warnings: Vec::new(),
        };
        if supported {
            queue.layout = Some("msfs_x64_9FABAE7C6C935698994D842F89A5B15C1".to_owned());
            let reader = |address, size| {
                let mut bytes = vec![0; size];
                space.read_virtual(address, &mut bytes)?;
                Ok(bytes)
            };
            if let Err(error) = read_queue(&reader, &mut queue, options, &mut budget, cancellation)
            {
                if is_cancellation_error(&error) {
                    return Err(error);
                }
                queue.complete = false;
                queue.warnings.push(format!("队列恢复未完成：{error:#}"));
            }
            for message in &mut queue.messages {
                if !message.complete {
                    continue;
                }
                let mut offset = 0;
                while offset < message.size {
                    let address = message.buffer_address + offset as u64;
                    let length = (4096 - (address & 4095) as usize).min(message.size - offset);
                    message.memory_ranges.push(MailslotMemoryRange {
                        virtual_address: address,
                        physical_address: space.translate(address)?,
                        length,
                    });
                    offset += length;
                }
                if let Some(directory) = &options.output {
                    let output =
                        directory.join(format!("mailslot-{fcb:016x}-{:04}.bin", message.index));
                    let bytes = hex::decode(message.data_hex.as_deref().unwrap_or_default())?;
                    let mut policy = OutputPolicy::new(options.force);
                    for source in image.sources() {
                        policy.protect_file("memory_image_or_sidecar", &source.path);
                    }
                    policy.output_file("mailslot_message", &output);
                    policy.prepare_directories()?;
                    policy.write_bytes_atomic(&output, &bytes)?;
                    message.output = Some(output);
                }
            }
        } else {
            queue.warnings.push(
                "MSFS 精确 PDB 身份没有已验证的私有队列布局；仅恢复端点和句柄归属，不猜测消息地址"
                    .to_owned(),
            );
        }
        complete &= queue.complete;
        warnings.extend(
            queue
                .warnings
                .iter()
                .map(|warning| format!("FCB {fcb:#x}：{warning}")),
        );
        queues.push(queue);
    }
    records.sort_by_key(|record| (record.full_name.to_ascii_lowercase(), record.file_object));
    Ok(MailslotReport {
        recovered_messages: queues.iter().flat_map(|q| &q.messages).filter(|m| m.complete).count(),
        recovered_bytes: queues.iter().flat_map(|q| &q.messages).map(|m| m.recovered_bytes).sum(),
        records, queues, file_objects_examined, processes_examined: owners.processes_examined,
        handle_entries_examined: owners.handle_entries_examined, complete, warnings,
        scope: "FILE_OBJECT → DEVICE_OBJECT → MSFS 驱动验证；活动句柄与池残留分开；保护前缀对象不作为消息队列；相同 FCB 的队列仅恢复一次。消息仅代表转储时尚在队列中的字节，不代表完整通信历史或明文；私有布局须精确匹配 MSFS CodeView 身份。".to_owned(),
    })
}

struct MessageBudget {
    entries: usize,
    bytes: usize,
}

fn read_queue(
    read: &impl Fn(u64, usize) -> Result<Vec<u8>>,
    queue: &mut MailslotQueue,
    options: &MailslotOptions,
    budget: &mut MessageBudget,
    cancellation: &CancellationToken,
) -> Result<()> {
    let fcb = read(queue.fcb, 0x188)?;
    ensure!(u32_at(&fcb, 0) == FCB_HEADER, "FCB 类型/长度不匹配");
    let state = u32_at(&fcb, 0x118);
    let bytes = u32_at(&fcb, 0x11c);
    let count = u32_at(&fcb, 0x120);
    queue.state = Some(state);
    queue.bytes_in_queue = Some(bytes);
    queue.entries_in_queue = Some(count);
    queue.maximum_message_size = Some(u32_at(&fcb, 0x124));
    ensure!(state <= 2, "未知队列状态 {state}");
    let head = queue.fcb.checked_add(QUEUE_HEAD).context("FCB 地址溢出")?;
    let mut link = u64_at(&fcb, 0x130);
    let tail = u64_at(&fcb, 0x138);
    if count == 0 {
        ensure!(
            link == head && tail == head && bytes == 0,
            "空队列计数与双链表不一致"
        );
        queue.complete = true;
        return Ok(());
    }
    // State 0 contains waiting readers, not stored messages. Do not dereference
    // their IRPs as payload. State 2 is empty and cannot have data entries.
    ensure!(
        state == 1,
        "队列有 {count} 项但不是已缓冲消息状态（可能为挂起读取请求）"
    );
    let mut previous = head;
    let mut visited = HashSet::new();
    let mut observed_bytes = 0u64;
    while link != head {
        cancellation.check_cancelled()?;
        ensure!(budget.entries > 0, "达到消息条数预算");
        ensure!(
            kernel_pointer(link) && visited.insert(link),
            "队列链接无效或成环"
        );
        ensure!(visited.len() <= count as usize, "队列链表超过声明数量");
        let entry = read(link.checked_sub(8).context("队列项地址下溢")?, 0x38)?;
        ensure!(u32_at(&entry, 0) == 1, "队列项不是缓冲消息类型");
        ensure!(u64_at(&entry, 0x10) == previous, "队列反向链接不匹配");
        ensure!(u64_at(&entry, 0x18) == 0, "队列项带 IRP，拒绝当作内联消息");
        let size = u32_at(&entry, 0x20) as usize;
        let buffer = u64_at(&entry, 0x28);
        ensure!(
            Some(buffer) == link.checked_add(0x30),
            "消息缓冲区不在已验证的内联位置"
        );
        let mut message = MailslotMessage {
            queue_fcb: queue.fcb,
            index: queue.messages.len(),
            entry_address: link - 8,
            buffer_address: buffer,
            size,
            recovered_bytes: 0,
            complete: false,
            data_hex: None,
            utf8_text: None,
            sha256: None,
            memory_ranges: Vec::new(),
            output: None,
            warning: None,
        };
        budget.entries -= 1;
        if size > options.max_message_bytes || size > budget.bytes {
            message.warning = Some("消息超过单项或总字节预算，正文未读取".to_owned());
        } else {
            budget.bytes -= size;
            match read(buffer, size) {
                Ok(body) => {
                    message.recovered_bytes = body.len();
                    message.complete = true;
                    message.sha256 = Some(hex::encode(Sha256::digest(&body)));
                    message.utf8_text = std::str::from_utf8(&body)
                        .ok()
                        .filter(|text| {
                            text.chars()
                                .all(|c| !c.is_control() || "\r\n\t".contains(c))
                        })
                        .map(str::to_owned);
                    message.data_hex = Some(hex::encode(body));
                }
                Err(error) => {
                    message.warning = Some(format!("消息缺页或不可读，未补零：{error:#}"))
                }
            }
        }
        if let Some(warning) = &message.warning {
            queue
                .warnings
                .push(format!("消息 {}：{warning}", message.index));
        }
        observed_bytes += size as u64;
        queue.messages.push(message);
        previous = link;
        link = u64_at(&entry, 8);
    }
    ensure!(
        previous == tail && visited.len() == count as usize && observed_bytes == u64::from(bytes),
        "队列尾、消息数量或总字节数与链表不一致"
    );
    queue.complete = queue.messages.iter().all(|message| message.complete);
    Ok(())
}

fn classify_endpoint(supported: bool, header: Option<u32>, context2: Option<u64>) -> &'static str {
    if !supported {
        return "unknown";
    }
    match header {
        Some(PROTECTED_PREFIX_HEADER) => "protected_prefix",
        Some(FCB_HEADER) => match context2 {
            Some(0) => "reader",
            Some(1) => "writer",
            _ => "unknown",
        },
        _ => "unknown",
    }
}

fn normalize_name(name: &str) -> Option<String> {
    let name = name.trim_matches('\0').trim();
    let lower = name.to_ascii_lowercase();
    let relative = if lower == r"\device\mailslot" || lower == r"\mailslot" {
        return None;
    } else if lower.starts_with(r"\device\mailslot\") {
        &name[r"\Device\Mailslot\".len()..]
    } else if lower.starts_with(r"\mailslot\") {
        &name[r"\Mailslot\".len()..]
    } else {
        name.trim_start_matches('\\')
    };
    (!relative.is_empty()).then(|| format!(r"\Device\Mailslot\{relative}"))
}
fn kernel_pointer(address: u64) -> bool {
    address >> 48 == 0xffff && address & 7 == 0
}
fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("bounded structure field"),
    )
}
fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("bounded structure field"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    const BASE: u64 = 0xffff_8000_0000_0000;
    #[test]
    fn protected_namespace_objects_are_not_reader_queues() {
        assert_eq!(
            classify_endpoint(true, Some(PROTECTED_PREFIX_HEADER), Some(0)),
            "protected_prefix"
        );
        assert_eq!(
            classify_endpoint(false, Some(PROTECTED_PREFIX_HEADER), Some(0)),
            "unknown"
        );
        assert_eq!(classify_endpoint(true, Some(FCB_HEADER), Some(0)), "reader");
        assert_eq!(classify_endpoint(true, Some(FCB_HEADER), Some(1)), "writer");
        assert_eq!(
            classify_endpoint(true, Some(0x0200_0609), Some(0)),
            "unknown"
        );
        assert_eq!(classify_endpoint(true, None, Some(0)), "unknown");
    }
    fn put32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn put64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
    fn fixture() -> (Vec<u8>, MailslotQueue) {
        let mut memory = vec![0; 0x5000];
        put32(&mut memory, 0x1000, FCB_HEADER);
        put32(&mut memory, 0x1118, 1);
        put32(&mut memory, 0x111c, 5);
        put32(&mut memory, 0x1120, 1);
        put64(&mut memory, 0x1130, BASE + 0x3008);
        put64(&mut memory, 0x1138, BASE + 0x3008);
        put32(&mut memory, 0x3000, 1);
        put64(&mut memory, 0x3008, BASE + 0x1130);
        put64(&mut memory, 0x3010, BASE + 0x1130);
        put32(&mut memory, 0x3020, 5);
        put64(&mut memory, 0x3028, BASE + 0x3038);
        memory[0x3038..0x303d].copy_from_slice(b"hello");
        let queue = MailslotQueue {
            fcb: BASE + 0x1000,
            layout: None,
            state: None,
            bytes_in_queue: None,
            entries_in_queue: None,
            maximum_message_size: None,
            messages: Vec::new(),
            complete: false,
            warnings: Vec::new(),
        };
        (memory, queue)
    }
    fn run(
        memory: &[u8],
        queue: &mut MailslotQueue,
        bytes: usize,
        missing_payload: bool,
    ) -> Result<()> {
        read_queue(
            &|address, size| {
                ensure!(
                    !(missing_payload && address == BASE + 0x3038),
                    "fixture missing page"
                );
                let offset = usize::try_from(address.checked_sub(BASE).context("bad address")?)?;
                Ok(memory
                    .get(offset..offset + size)
                    .context("unmapped fixture")?
                    .to_vec())
            },
            queue,
            &MailslotOptions::default(),
            &mut MessageBudget { entries: 10, bytes },
            &CancellationToken::new(),
        )
    }
    #[test]
    fn recovers_only_exact_message_bytes_with_digest() {
        let (memory, mut queue) = fixture();
        run(&memory, &mut queue, 100, false).unwrap();
        assert!(queue.complete);
        assert_eq!(queue.messages[0].data_hex.as_deref(), Some("68656c6c6f"));
        assert_eq!(
            queue.messages[0].sha256.as_deref(),
            Some("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
        );
    }
    #[test]
    fn rejects_wrong_fcb_and_backlink() {
        let (mut memory, mut queue) = fixture();
        put32(&mut memory, 0x1000, 0x0188_0605);
        assert!(run(&memory, &mut queue, 100, false).is_err());
        put32(&mut memory, 0x1000, FCB_HEADER);
        put64(&mut memory, 0x3010, BASE + 0x2000);
        assert!(run(&memory, &mut queue, 100, false).is_err());
        assert!(queue.messages.is_empty());
    }
    #[test]
    fn rejects_cycles_and_count_mismatch() {
        let (mut memory, mut queue) = fixture();
        put64(&mut memory, 0x3008, BASE + 0x3008);
        assert!(run(&memory, &mut queue, 100, false).is_err());
        let (mut memory, mut queue) = fixture();
        put32(&mut memory, 0x111c, 6);
        assert!(run(&memory, &mut queue, 100, false).is_err());
        assert!(!queue.complete);
    }
    #[test]
    fn missing_and_over_budget_payloads_are_not_zero_filled() {
        for (budget, missing) in [(4, false), (100, true)] {
            let (memory, mut queue) = fixture();
            run(&memory, &mut queue, budget, missing).unwrap();
            assert!(!queue.complete);
            assert_eq!(queue.messages[0].recovered_bytes, 0);
            assert!(queue.messages[0].data_hex.is_none());
            assert!(queue.messages[0].sha256.is_none());
        }
    }
    #[test]
    fn does_not_read_irps_as_message_bodies() {
        let (mut memory, mut queue) = fixture();
        put64(&mut memory, 0x3018, BASE + 0x4000);
        assert!(run(&memory, &mut queue, 100, false).is_err());
        assert!(queue.messages.is_empty());
    }
    #[test]
    fn cancellation_stops_queue_walk() {
        let (_, mut queue) = fixture();
        let (memory, _) = fixture();
        let token = CancellationToken::new();
        token.request_cancel();
        let error = read_queue(
            &|a, size| Ok(memory[(a - BASE) as usize..(a - BASE) as usize + size].to_vec()),
            &mut queue,
            &MailslotOptions::default(),
            &mut MessageBudget {
                entries: 10,
                bytes: 100,
            },
            &token,
        )
        .unwrap_err();
        assert!(is_cancellation_error(&error));
    }
}
