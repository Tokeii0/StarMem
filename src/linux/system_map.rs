use super::*;
use crate::linux_system_map::{LinuxSystemMap, PAGE_TABLE_SYMBOLS};

/// The map establishes the runtime identity first. Only exact ISF types whose
/// addresses agree with the selected map may enrich that session.
pub(super) fn open_with_symbols(
    image: MemoryImage,
    path: &std::path::Path,
    store: &SymbolStore,
    cancellation: &CancellationToken,
) -> Result<LinuxAnalysisSession> {
    let map = LinuxSystemMap::load(path)?;
    let mut session = open(image, &map, cancellation)?;
    let Some(completed) = crate::linux_symbols::system_map::complete(
        &session.image,
        store,
        &map,
        &session.kernel.banner,
        cancellation,
    )?
    else {
        session.warnings.push(LinuxProcessWarning {
            kind: "system_map_types_unavailable".into(), list_entry: None,
            message: "自动补齐未找到与完整 banner 匹配的本地 ISF 类型来源；保留基础进程分析。请将同一内核构建的 ISF 放入符号目录后重新导入；只有 System.map 无法生成结构体类型。".into(),
        });
        return Ok(session);
    };
    cancellation.check_cancelled()?;
    let profile = profile_from_volatility_isf(&completed.table)?;
    let space = LinuxX64AddressSpace::new(&session.image, session.kernel.directory_table_base)?;
    let init = InitTaskCandidate {
        physical_address: session.kernel.init_task_physical,
        virtual_address: session.kernel.init_task,
        tasks_next: space.read_u64(session.kernel.init_task + profile.tasks)?,
        tasks_prev: space.read_u64(session.kernel.init_task + profile.tasks + 8)?,
    };
    let banner = BannerEvidence {
        physical_address: session.kernel.banner_physical_address,
        text: session.kernel.banner.clone(),
    };
    validate_selected_runtime_context(&space, &profile, &init, Some(&completed.table), &banner)
        .context("自动生成的 ISF 未通过运行时内核验证")?;
    validate_mapped_tasks(&space, &profile, &init, 8)
        .context("自动生成的 ISF 未通过活动任务链验证")?;
    cancellation.check_cancelled()?;
    session.kernel.profile_source = profile.source.into();
    session.kernel.profile_fingerprint = profile.fingerprint.clone();
    session.kernel.task_struct_size = profile.task_size;
    session.kernel.task_struct_offsets = profile
        .reported_offsets()
        .into_iter()
        .map(|(name, offset)| (name.to_owned(), offset))
        .collect();
    session.profile = profile;
    session
        .warnings
        .retain(|warning| warning.kind != "system_map_address_only");
    session.warnings.push(LinuxProcessWarning {
        kind: "system_map_isf_generated".into(), list_entry: None,
        message: format!(
            "已自动生成 ISF {}（SHA-256={}）；类型来源 {}（SHA-256={}），System.map SHA-256={}，已核对 {} 个同名符号地址、完整 banner、运行时页表及活动任务链。结构类型来自精确匹配的 ISF，缺页仍按实际读取范围报告。",
            completed.table.path().display(), completed.table.file_sha256(),
            completed.source.display(), completed.source_sha256, map.identity.sha256,
            completed.addresses_verified,
        ),
    });
    session.kernel.symbol_table = Some(completed.table);
    Ok(session)
}

/// Use map addresses only to propose candidates. Physical addresses come from
/// the image layer (including LiME gaps), and strict page tables verify them.
pub(super) fn open(
    image: MemoryImage,
    map: &LinuxSystemMap,
    cancellation: &crate::cancellation::CancellationToken,
) -> Result<LinuxAnalysisSession> {
    let linked_banner = map
        .address("linux_banner")
        .context("System.map 缺少 linux_banner")?;
    let linked_task = map
        .address("init_task")
        .context("System.map 缺少 init_task")?;
    let linked_text = map.address("_stext").context("System.map 缺少 _stext")?;
    // System.map supplies the relative task/page-table locations. Scan only the
    // banner with the existing bounded SIMD scanner, then inspect each task locally.
    let scan = crate::scan::scan_exact_cancellable(
        &image,
        LINUX_BANNER_PATTERN,
        DISCOVERY_LIMIT_PER_PATTERN,
        DISCOVERY_CHUNK_SIZE,
        cancellation,
    )?;
    ensure!(
        !scan.truncated,
        "Linux banner 候选扫描达到上限，无法完整验证 System.map"
    );
    let mut reasons = Vec::new();
    for hit in &scan.hits {
        cancellation.check_cancelled()?;
        let Some(text) = read_physical_c_string(&image, hit.physical_address, 512) else {
            continue;
        };
        let text = normalize_linux_banner(text);
        if linux_release(&text).is_none() {
            continue;
        }
        let banner = BannerEvidence {
            physical_address: hit.physical_address,
            text,
        };
        // A page-aligned slide cannot change the offset within a page.
        if banner.physical_address & 0xfff != linked_banner & 0xfff {
            continue;
        }
        let physical = |address: u64| -> Option<u64> {
            let delta = i128::from(address) - i128::from(linked_banner);
            u64::try_from(i128::from(banner.physical_address) + delta).ok()
        };
        let Some(task_physical) = physical(linked_task) else {
            continue;
        };
        for name in PAGE_TABLE_SYMBOLS {
            let Some(root) = map.address(name).and_then(physical) else {
                continue;
            };
            let Ok(space) = LinuxX64AddressSpace::new(&image, root) else {
                continue;
            };
            for comm in (0x100..0x3000).step_by(8) {
                cancellation.check_cancelled()?;
                let Some(swapper) = task_physical.checked_add(comm) else {
                    continue;
                };
                if !read_fixed_name_physical(&image, swapper, 16)
                    .is_ok_and(|name| name == "swapper" || name == "swapper/0")
                {
                    continue;
                }
                for parent in (0x100..comm).step_by(8) {
                    let Ok(task_virtual) = image.read_u64_physical(task_physical + parent) else {
                        continue;
                    };
                    let Some(slide) = task_virtual.checked_sub(linked_task) else {
                        continue;
                    };
                    if slide > 0x4000_0000
                        || slide & 0xfff != 0
                        || image.read_u64_physical(task_physical + parent + 8).ok()
                            != Some(task_virtual)
                    {
                        continue;
                    }
                    let candidate = (|| -> Result<(LinuxTaskProfile, LinuxKernelTextEvidence)> {
                        ensure!(
                            space.translate(task_virtual)? == task_physical,
                            "System.map init_task 映射不一致"
                        );
                        let runtime_banner = linked_banner
                            .checked_add(slide)
                            .context("linux_banner 地址溢出")?;
                        ensure!(
                            space.translate(runtime_banner)? == banner.physical_address,
                            "System.map linux_banner 与 init_task 不共享同一 slide"
                        );
                        let mut text = vec![0; banner.text.len() + 2];
                        space.read_virtual(runtime_banner, &mut text)?;
                        let end = text
                            .iter()
                            .position(|byte| *byte == 0)
                            .context("linux_banner 未终止")?;
                        ensure!(
                            std::str::from_utf8(&text[..end])?.trim_end() == banner.text,
                            "System.map 运行时 banner 不匹配"
                        );
                        let layout = finish_inferred_task_layout_diagnosed(
                            &space,
                            task_physical,
                            task_virtual,
                            parent,
                            comm,
                        )
                        .map_err(|error| {
                            anyhow::anyhow!("System.map task_struct 推断失败：{error}")
                        })?;
                        let mut profile = task_profile_from_inferred_layout(
                            &layout,
                            "system_map:strict_page_tables",
                        )?;
                        profile.source = "system_map_validated_memory";
                        profile
                            .fingerprint
                            .push_str(&format!("; system_map_sha256={}", map.identity.sha256));
                        let init = InitTaskCandidate {
                            physical_address: task_physical,
                            virtual_address: task_virtual,
                            tasks_next: space.read_u64(task_virtual + profile.tasks)?,
                            tasks_prev: space.read_u64(task_virtual + profile.tasks + 8)?,
                        };
                        validate_mapped_tasks(&space, &profile, &init, layout.task_count)?;
                        let runtime_text =
                            linked_text.checked_add(slide).context("_stext 地址溢出")?;
                        let text_physical = space.translate(runtime_text)?;
                        ensure!(
                            Some(text_physical) == physical(linked_text),
                            "System.map _stext 映射不一致"
                        );
                        let mut bytes = [0; 32];
                        space.read_virtual(runtime_text, &mut bytes)?;
                        ensure!(
                            bytes.iter().any(|byte| *byte != 0),
                            "System.map _stext 为空页"
                        );
                        Ok((
                            profile,
                            LinuxKernelTextEvidence {
                                virtual_address: runtime_text,
                                physical_address: text_physical,
                                symbol_source: "system_map:runtime_validated".into(),
                                kernel_offset: Some(slide),
                                phys_base: None,
                                first_bytes_hex: hex::encode(bytes),
                                bytes_verified: bytes.len(),
                            },
                        ))
                    })();
                    match candidate {
                        Ok((profile, kernel_text)) => {
                            cancellation.check_cancelled()?;
                            let kernel = LinuxKernelContext {
                                architecture: "x86_64_4level".into(),
                                banner: banner.text.clone(),
                                banner_physical_address: banner.physical_address,
                                directory_table_base: root,
                                page_table_source: format!("system_map:{name}:runtime_validated"),
                                vmcoreinfo_physical_address: None,
                                init_task: task_virtual,
                                init_task_physical: task_physical,
                                profile_source: profile.source.into(),
                                profile_fingerprint: profile.fingerprint.clone(),
                                btf_physical_address: None,
                                task_struct_size: profile.task_size,
                                task_struct_offsets: profile
                                    .reported_offsets()
                                    .into_iter()
                                    .map(|(name, offset)| (name.to_owned(), offset))
                                    .collect(),
                                symbol_table: None,
                                system_map: Some(map.identity.clone()),
                            };
                            return Ok(LinuxAnalysisSession {
                                image,
                                profile,
                                kernel,
                                scan: DiscoveryScanStats {
                                    bytes_scanned: scan.bytes_scanned,
                                    elapsed_seconds: scan.elapsed_seconds,
                                    gib_per_second: scan.gib_per_second,
                                },
                                kernel_text: Some(kernel_text),
                                kernel_text_diagnostic: None,
                                warnings: vec![LinuxProcessWarning {
                                    kind: "system_map_address_only".into(),
                                    list_entry: None,
                                    message: format!(
                                        "System.map {}（SHA-256={}）已通过 linux_banner、init_task、_stext 和四级页表现场校验；基础任务字段由内存推断并复验，task_struct_size 仅表示推断字段的覆盖范围。System.map 不包含结构体类型，命令行、网络、文件等完整分析仍需与完整 banner 匹配的 ISF。",
                                        map.path.display(),
                                        map.identity.sha256
                                    ),
                                }],
                            });
                        }
                        Err(error) => {
                            record_runtime_reason(&mut reasons, format_args!("{error:#}"))
                        }
                    }
                }
            }
        }
    }
    bail!(
        "用户指定的 System.map 未通过运行时内核地址、页表及任务链校验；请核对精确内核构建和镜像完整性，不会改用其他符号。{}",
        reasons.join("；")
    )
}

/// Map-backed addresses establish the kernel anchor, not the task layout. Require
/// a consistent prefix in addition to the cross-task field inference. The normal
/// walker retains later torn links as incomplete evidence instead of discarding it.
fn validate_mapped_tasks(
    space: &LinuxX64AddressSpace<'_>,
    profile: &LinuxTaskProfile,
    init: &InitTaskCandidate,
    task_count: usize,
) -> Result<()> {
    validate_runtime_head(space, profile, init)?;
    let head = init.virtual_address + profile.tasks;
    let mut previous = head;
    let mut link = init.tasks_next;
    let mut visited = HashSet::new();
    for _ in 0..task_count.min(8) {
        ensure!(
            link != head
                && is_kernel_pointer(link)
                && link >= profile.tasks
                && visited.insert(link),
            "System.map 基础任务验证遇到无效指针或提前闭环"
        );
        ensure!(
            space.read_u64(link + 8)? == previous,
            "System.map 基础任务验证遇到不一致的反向链接"
        );
        let record = read_process_record(space, profile, link - profile.tasks, link)?;
        ensure!(
            (1..=4_194_304).contains(&record.pid)
                && record.pid == record.tgid
                && record.ppid.is_some(),
            "System.map 基础任务 PID/TGID 或父进程验证失败"
        );
        previous = link;
        link = space.read_u64(link)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const BASE: u64 = 0xffff_ffff_8100_0000;
    const PHYSICAL: usize = 0x20_0000;
    const TASKS: usize = 9;
    fn write_u64(bytes: &mut [u8], at: usize, value: u64) {
        bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn fixture(slide: u64) -> (tempfile::TempDir, std::path::PathBuf, SymbolStore) {
        let temp = tempfile::tempdir().unwrap();
        let image = temp.path().join("linux.raw");
        let map = temp.path().join("System.map-test");
        let base = BASE + slide;
        let mut bytes = vec![0; PHYSICAL + 0x20000];
        write_u64(
            &mut bytes,
            PHYSICAL + 0x1000 + 511 * 8,
            PHYSICAL as u64 + 0x2003,
        );
        write_u64(
            &mut bytes,
            PHYSICAL + 0x2000 + 510 * 8,
            PHYSICAL as u64 + 0x5003,
        );
        write_u64(
            &mut bytes,
            PHYSICAL + 0x5000 + (((base >> 21) & 511) as usize) * 8,
            PHYSICAL as u64 + 0x83,
        );
        bytes[PHYSICAL + 0x3000..PHYSICAL + 0x3020].fill(0x90);
        let banner = b"Linux version 3.10.0-test (fixture) #1 SMP\n\0";
        bytes[PHYSICAL + 0x4000..PHYSICAL + 0x4000 + banner.len()].copy_from_slice(banner);
        for index in 0..TASKS {
            let task = PHYSICAL + 0x8000 + index * 0x1000;
            write_u64(
                &mut bytes,
                task,
                if index == TASKS - 1 {
                    0x82
                } else {
                    u64::from(index != 0)
                },
            );
            write_u64(
                &mut bytes,
                task + 0x180,
                base + 0x8000 + ((index + 1) % TASKS) as u64 * 0x1000 + 0x180,
            );
            write_u64(
                &mut bytes,
                task + 0x188,
                base + 0x8000 + ((index + TASKS - 1) % TASKS) as u64 * 0x1000 + 0x180,
            );
            bytes[task + 0x1d0..task + 0x1d4].copy_from_slice(&(index as u32).to_le_bytes());
            bytes[task + 0x1d4..task + 0x1d8].copy_from_slice(&(index as u32).to_le_bytes());
            write_u64(&mut bytes, task + 0x1e0, base + 0x8000);
            write_u64(&mut bytes, task + 0x1e8, base + 0x8000);
            let name = if index == 0 {
                "swapper/0".into()
            } else {
                format!("process{index}")
            };
            bytes[task + 0x300..task + 0x300 + name.len()].copy_from_slice(name.as_bytes());
        }
        fs::write(&image, bytes).unwrap();
        fs::write(
            &map,
            format!(
                "{:x} T _stext\n{:x} R linux_banner\n{:x} D init_task\n{:x} D init_level4_pgt\n",
                BASE + 0x3000,
                BASE + 0x4000,
                BASE + 0x8000,
                BASE + 0x1000
            ),
        )
        .unwrap();
        let store = SymbolStore::new(temp.path().join("cache")).with_linux_system_map(map);
        (temp, image, store)
    }

    #[test]
    fn system_map_validates_runtime_with_and_without_kaslr() {
        for slide in [0, 0x20_0000] {
            let (_temp, path, store) = fixture(slide);
            let session = LinuxAnalysisSession::from_image_with_symbol_store(
                MemoryImage::open(&path).unwrap(),
                &store,
            )
            .unwrap();
            let report = session.processes(100).unwrap();
            assert!(report.complete);
            assert_eq!(report.processes.len(), TASKS - 1);
            assert_eq!(report.kernel.init_task, BASE + slide + 0x8000);
            assert!(report.kernel.system_map.is_some());
            assert!(session.kernel_text().unwrap().system_map.is_some());
            assert!(report.kernel.symbol_table.is_none());
            assert_eq!(report.kernel.task_struct_offsets["pid"], 0x1d0);
            let last = report.processes.last().unwrap();
            assert_eq!(last.state_raw, 0x82);
            assert_eq!(last.state, "unknown(0x82)");
            let args = session.psaux(None, 4096, 100).unwrap();
            assert_eq!(args.records.len(), TASKS - 1);
            assert!(!args.complete);
        }
    }

    #[test]
    fn system_map_rejects_wrong_addresses_and_broken_page_tables() {
        let (_temp, path, store) = fixture(0);
        let map = store.linux_system_map().unwrap();
        let original = fs::read_to_string(map).unwrap();
        fs::write(
            map,
            original.replace("ffffffff81004000", "ffffffff81004040"),
        )
        .unwrap();
        assert!(
            LinuxAnalysisSession::from_image_with_symbol_store(
                MemoryImage::open(&path).unwrap(),
                &store
            )
            .is_err()
        );
        fs::write(map, original).unwrap();
        let mut bytes = fs::read(&path).unwrap();
        write_u64(
            &mut bytes,
            PHYSICAL + 0x1000 + 511 * 8,
            PHYSICAL as u64 + 0x2002,
        ); // Not present.
        fs::write(&path, bytes).unwrap();
        assert!(
            LinuxAnalysisSession::from_image_with_symbol_store(
                MemoryImage::open(&path).unwrap(),
                &store
            )
            .is_err()
        );
    }

    #[test]
    fn system_map_preserves_partial_tasks_but_rejects_a_broken_prefix() {
        let (_temp, path, store) = fixture(0);
        let mut bytes = fs::read(&path).unwrap();
        let last = PHYSICAL + 0x8000 + (TASKS - 1) * 0x1000;
        write_u64(&mut bytes, last + 0x180, BASE + 0x9000 + 0x180);
        fs::write(&path, &bytes).unwrap();
        let session = LinuxAnalysisSession::from_image_with_symbol_store(
            MemoryImage::open(&path).unwrap(),
            &store,
        )
        .unwrap();
        let report = session.processes(100).unwrap();
        assert_eq!(report.processes.len(), TASKS - 1);
        assert!(!report.complete);
        assert_eq!(report.stop_reason, LinuxProcessListStopReason::Cycle);
        assert!(
            report
                .warnings
                .iter()
                .any(|warning| warning.kind == "cycle")
        );
        drop(session);
        write_u64(&mut bytes, PHYSICAL + 0x9000 + 0x188, BASE + 0xa000 + 0x180);
        fs::write(&path, &bytes).unwrap();
        assert!(
            LinuxAnalysisSession::from_image_with_symbol_store(
                MemoryImage::open(&path).unwrap(),
                &store,
            )
            .is_err()
        );
    }

    #[test]
    fn system_map_cancelled_open_returns_the_typed_cancellation() {
        let (_temp, path, store) = fixture(0);
        let token = crate::cancellation::CancellationToken::new();
        token.request_cancel();
        let result = LinuxAnalysisSession::from_image_with_system_map(
            MemoryImage::open(&path).unwrap(),
            store.linux_system_map().unwrap(),
            &token,
        );
        assert!(crate::cancellation::is_cancellation_error(
            &result.err().unwrap()
        ));
    }

    #[test]
    fn system_map_does_not_silently_use_builtin_type_layouts() {
        let (_temp, path, store) = fixture(0);
        let mut session = LinuxAnalysisSession::from_image_with_symbol_store(
            MemoryImage::open(&path).unwrap(),
            &store,
        )
        .unwrap();
        // Even a known banner cannot turn address-only selection into type symbols.
        session.kernel.banner = UBUNTU_4_13_0_36_XENIAL.into();
        assert!(
            session
                .cmdline(None, 100, 4096)
                .unwrap_err()
                .to_string()
                .contains("System.map")
        );
        assert!(
            session
                .files(100)
                .unwrap_err()
                .to_string()
                .contains("System.map")
        );
        let args = session.psaux(None, 100, 4096).unwrap();
        assert_eq!(args.records.len(), TASKS - 1);
        assert_eq!(args.command_lines_recovered, 0);
        assert!(!args.complete);
        assert!(
            args.records
                .iter()
                .all(|record| record.command_line_source == "task_struct.comm_fallback")
        );
    }

    fn install_type_source(store: &SymbolStore) -> std::path::PathBuf {
        use base64::Engine;
        let field = |offset: u64, kind: serde_json::Value| serde_json::json!({"offset": offset, "type": kind});
        let pointer =
            serde_json::json!({"kind":"pointer", "subtype":{"kind":"struct","name":"task_struct"}});
        let document = serde_json::json!({
            "metadata": {"format":"6.2.0"},
            "base_types": {"long unsigned int":{"size":8},"int":{"size":4},"char":{"size":1}},
            "enums": {},
            "user_types": {
                "task_struct": {"kind":"struct", "size":1024, "fields": {
                    "state": field(0, serde_json::json!({"kind":"base","name":"long unsigned int"})),
                    "tasks": field(0x180, serde_json::json!({"kind":"struct","name":"list_head"})),
                    "pid": field(0x1d0, serde_json::json!({"kind":"base","name":"int"})),
                    "tgid": field(0x1d4, serde_json::json!({"kind":"base","name":"int"})),
                    "real_parent": field(0x1e0, pointer.clone()), "parent":field(0x1e8, pointer),
                    "comm": field(0x300, serde_json::json!({"kind":"array","count":16,"subtype":{"kind":"base","name":"char"}}))
                }},
                "list_head": {"kind":"struct", "size":16,"fields":{}}
            },
            "symbols": {
                "_stext":{"address":BASE+0x3000}, "init_task":{"address":BASE+0x8000},
                "init_level4_pgt":{"address":BASE+0x1000},
                "linux_banner":{"address":BASE+0x4000,
                    "constant_data":base64::engine::general_purpose::STANDARD.encode(b"Linux version 3.10.0-test (fixture) #1 SMP\n\0")}
            }
        });
        let root = store.writable_root().join("linux");
        fs::create_dir_all(&root).unwrap();
        let path = root.join("types.json.xz");
        let mut writer =
            lzma_rust2::XzWriter::new(Vec::new(), lzma_rust2::XzOptions::with_preset(1)).unwrap();
        std::io::Write::write_all(&mut writer, &serde_json::to_vec(&document).unwrap()).unwrap();
        fs::write(&path, writer.finish().unwrap()).unwrap();
        path
    }

    #[test]
    fn system_map_generates_isf_from_exact_types_and_reuses_cache() {
        for slide in [0, 0x20_0000] {
            let (_temp, path, store) = fixture(slide);
            let source = install_type_source(&store);
            let original = fs::read(&source).unwrap();
            let session = LinuxAnalysisSession::from_image_with_symbol_store(
                MemoryImage::open(&path).unwrap(),
                &store,
            )
            .unwrap();
            let table = session.kernel.symbol_table.as_ref().unwrap();
            assert_eq!(session.kernel.profile_source, "volatility3_isf");
            assert!(session.kernel.system_map.is_some());
            assert!(
                session
                    .warnings
                    .iter()
                    .any(|w| w.kind == "system_map_isf_generated")
            );
            assert!(
                !session
                    .warnings
                    .iter()
                    .any(|w| w.kind == "system_map_address_only")
            );
            assert_eq!(session.processes(100).unwrap().processes.len(), TASKS - 1);
            // This small fixture has task types only. Readers must now report the
            // actual missing layout, rather than reject the preserved map provenance.
            assert!(
                !format!("{:#}", session.files(100).unwrap_err()).contains("System.map 不包含")
            );
            assert!(
                !format!("{:#}", session.cmdline(None, 100, 4096).unwrap_err())
                    .contains("System.map 不包含")
            );
            let provenance: serde_json::Value = serde_json::from_slice(
                &fs::read(table.path().with_file_name("provenance.json")).unwrap(),
            )
            .unwrap();
            assert_eq!(provenance["addresses_verified"], 4);
            assert_eq!(provenance["isf_sha256"], table.file_sha256());
            let repeated = LinuxAnalysisSession::from_image_with_symbol_store(
                MemoryImage::open(&path).unwrap(),
                &store,
            )
            .unwrap();
            assert_eq!(
                repeated.kernel.symbol_table.as_ref().unwrap().file_sha256(),
                table.file_sha256()
            );
            assert_eq!(fs::read(source).unwrap(), original);
            let kernel = open_linux_kernel_session(
                MemoryImage::open(&path).unwrap(),
                &store,
                [LinuxSymbolFeature::Task],
                LinuxKernelSessionOptions::default(),
            )
            .unwrap();
            assert!(
                kernel
                    .evidence
                    .symbol_warnings
                    .iter()
                    .any(|w| w.kind == "system_map_isf_generated")
            );
        }
    }

    #[test]
    fn system_map_completion_rejects_non_anchor_conflicts_and_bad_runtime_types() {
        for invalid_layout in [false, true] {
            let (_temp, path, store) = fixture(0);
            let source = install_type_source(&store);
            let bytes = fs::read(&source).unwrap();
            let mut value: serde_json::Value =
                serde_json::from_reader(lzma_rust2::XzReader::new(bytes.as_slice(), true)).unwrap();
            if invalid_layout {
                value["user_types"]["task_struct"]["fields"]["pid"]["offset"] = 0x1cc.into();
            } else {
                value["symbols"]["modules"] = serde_json::json!({"address":BASE+0x6000});
                let map = store.linux_system_map().unwrap();
                fs::write(
                    map,
                    format!(
                        "{}{:x} D modules\n",
                        fs::read_to_string(map).unwrap(),
                        BASE + 0x7000
                    ),
                )
                .unwrap();
            }
            // Replace only this fixture's compressed source with an uncompressed file.
            fs::remove_file(&source).unwrap();
            fs::write(
                source.with_extension("json"),
                serde_json::to_vec(&value).unwrap(),
            )
            .unwrap();
            let error = LinuxAnalysisSession::from_image_with_symbol_store(
                MemoryImage::open(&path).unwrap(),
                &store,
            )
            .err()
            .unwrap();
            let message = format!("{error:#}");
            assert!(
                message.contains(if invalid_layout {
                    "运行时"
                } else {
                    "modules 地址不符"
                }),
                "{message}"
            );
        }
    }

    #[test]
    fn system_map_completion_never_borrows_types_from_another_build() {
        use base64::Engine;
        let (_temp, path, store) = fixture(0);
        let source = install_type_source(&store);
        let bytes = fs::read(&source).unwrap();
        let mut value: serde_json::Value =
            serde_json::from_reader(lzma_rust2::XzReader::new(bytes.as_slice(), true)).unwrap();
        value["symbols"]["linux_banner"]["constant_data"] =
            base64::engine::general_purpose::STANDARD
                .encode(b"Linux version 3.10.0-test (other-build) #1 SMP\n\0")
                .into();
        fs::remove_file(&source).unwrap();
        fs::write(
            source.with_extension("json"),
            serde_json::to_vec(&value).unwrap(),
        )
        .unwrap();
        let session = LinuxAnalysisSession::from_image_with_symbol_store(
            MemoryImage::open(&path).unwrap(),
            &store,
        )
        .unwrap();
        assert!(session.kernel.symbol_table.is_none());
        assert!(
            session
                .warnings
                .iter()
                .any(|w| w.kind == "system_map_types_unavailable")
        );
        assert!(!store.writable_root().join("linux-system-map-isf").exists());
    }

    #[test]
    fn cancelled_system_map_completion_does_not_publish_isf() {
        let (_temp, path, store) = fixture(0);
        install_type_source(&store);
        let map = LinuxSystemMap::load(store.linux_system_map().unwrap()).unwrap();
        let cancellation = CancellationToken::new();
        cancellation.request_cancel();
        let error = crate::linux_symbols::system_map::complete(
            &MemoryImage::open(path).unwrap(),
            &store,
            &map,
            "Linux version 3.10.0-test (fixture) #1 SMP",
            &cancellation,
        )
        .err()
        .unwrap();
        assert!(crate::cancellation::is_cancellation_error(&error));
        assert!(!store.writable_root().join("linux-system-map-isf").exists());
    }
}
