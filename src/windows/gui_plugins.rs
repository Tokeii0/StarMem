use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use anyhow::{Result, ensure};
use serde::Serialize;

use super::{ProcessRecord, WindowsKernelContext, list_processes};
use crate::address::{VirtualAddressRegion, X64AddressSpace};
use crate::image::MemoryImage;
use crate::profile::KernelProfile;
use crate::scan::scan_exact_4;

const GUI_TAGS: [[u8; 4]; 2] = [*b"Wind", *b"Desk"];
const GUI_SCAN_TAGS: [[u8; 4]; 4] = [*b"Wind", *b"Win\xe4", *b"Desk", *b"Des\xeb"];
const MAX_GUI_OBJECTS: usize = 65_536;

#[derive(Debug, Serialize)]
pub struct GuiReport<T> {
    pub records: Vec<T>,
    pub bytes_scanned: u64,
    pub scan_seconds: f64,
    pub raw_tag_hits: usize,
    pub pool_candidates: usize,
    pub session_spaces_examined: usize,
    pub missing_pages: usize,
    pub missing_bytes: u64,
    pub complete: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WindowStationRecord {
    pub address: u64,
    pub physical_address: Option<u64>,
    pub name: String,
    pub session_id: u32,
    pub next: Option<u64>,
    pub desktop_list: Option<u64>,
    pub pool_scanned: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct DesktopRecord {
    pub address: u64,
    pub physical_address: Option<u64>,
    pub name: String,
    pub window_station: u64,
    pub window_station_name: String,
    pub session_id: u32,
    pub layout: String,
    pub linked: bool,
    pub pool_scanned: bool,
    pub thread_owners: Vec<GuiThreadOwner>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub struct WindowRect {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
}

impl WindowRect {
    pub fn width(self) -> u32 {
        self.right.saturating_sub(self.left) as u32
    }

    pub fn height(self) -> u32 {
        self.bottom.saturating_sub(self.top) as u32
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct GuiThreadOwner {
    pub thread_info: u64,
    pub eprocess: u64,
    pub pid: u64,
    pub process: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct WindowRecord {
    pub address: u64,
    pub window_station: String,
    pub session_id: u32,
    pub desktop: String,
    pub title: Option<String>,
    pub procedure: Option<u64>,
    pub process: Option<String>,
    pub pid: Option<u64>,
    pub parent: Option<u64>,
    pub next: Option<u64>,
    pub child: Option<u64>,
    pub style: Option<u32>,
    pub ex_style: Option<u32>,
    pub visible: Option<bool>,
    pub window_rect: Option<WindowRect>,
    pub client_rect: Option<WindowRect>,
    pub tree_depth: usize,
    pub z_order: usize,
    pub layout: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct WindowTitleRecord {
    pub address: u64,
    pub title: String,
    pub title_characters: usize,
    pub process: Option<String>,
    pub pid: Option<u64>,
    pub session_id: u32,
    pub window_station: String,
    pub desktop: String,
    pub has_titled_parent: bool,
    pub depth: usize,
    pub parent: Option<u64>,
    pub parent_title: Option<String>,
    pub child: Option<u64>,
    pub next: Option<u64>,
    pub procedure: Option<u64>,
    pub duplicate_title_count: usize,
    pub visible: Option<bool>,
    pub window_rect: Option<WindowRect>,
    pub client_rect: Option<WindowRect>,
    pub tree_depth: usize,
    pub z_order: usize,
    pub layout: String,
}

#[derive(Clone, Copy)]
struct DesktopLayout {
    name: &'static str,
    parent: u64,
    next: u64,
    desk_info: u64,
    pti_list: u64,
    top_window: u64,
}

// These are distinct public x64 GUI layout candidates. No OS build number is used: candidates compete using live
// parent/session/name/list/window invariants in the captured address space.
const DESKTOP_LAYOUTS: &[DesktopLayout] = &[
    DesktopLayout {
        name: "win10_17134_plus",
        parent: 0x28,
        next: 0x20,
        desk_info: 0x08,
        pti_list: 0xa8,
        top_window: 0x18,
    },
    DesktopLayout {
        name: "win10_15063_16299",
        parent: 0x28,
        next: 0x20,
        desk_info: 0x08,
        pti_list: 0xa8,
        top_window: 0x10,
    },
    DesktopLayout {
        name: "win10_10586",
        parent: 0x28,
        next: 0x10,
        desk_info: 0x08,
        pti_list: 0xa0,
        top_window: 0x10,
    },
    DesktopLayout {
        name: "windows_8",
        parent: 0x18,
        next: 0x10,
        desk_info: 0x08,
        pti_list: 0xa0,
        top_window: 0x10,
    },
    DesktopLayout {
        name: "windows_7",
        parent: 0x20,
        next: 0x18,
        desk_info: 0x08,
        pti_list: 0xa8,
        top_window: 0x10,
    },
];

#[derive(Clone, Copy)]
struct ThreadLayout {
    list_link: u64,
    process_info: u64,
}

const THREAD_LAYOUTS: &[ThreadLayout] = &[
    ThreadLayout {
        list_link: 0x2e0,
        process_info: 0x1a0,
    },
    ThreadLayout {
        list_link: 0x2d8,
        process_info: 0x1a0,
    },
    ThreadLayout {
        list_link: 0x2c8,
        process_info: 0x190,
    },
    ThreadLayout {
        list_link: 0x290,
        process_info: 0x178,
    },
    ThreadLayout {
        list_link: 0x280,
        process_info: 0x170,
    },
    ThreadLayout {
        list_link: 0x260,
        process_info: 0x158,
    },
];

#[derive(Clone, Copy)]
struct WindowLayout {
    name: &'static str,
    next: u64,
    parent: u64,
    child: u64,
    direct_name: Option<u64>,
    string_name: u64,
    direct_procedure: Option<u64>,
    procedure_holder: Option<(u64, u64)>,
    style: u64,
}

struct WindowCandidate {
    score: usize,
    layout: WindowLayout,
    next: u64,
    parent: u64,
    child: u64,
    title: Option<String>,
    procedure: Option<u64>,
    style: Option<u32>,
    ex_style: Option<u32>,
    visible: Option<bool>,
    window_rect: Option<WindowRect>,
    client_rect: Option<WindowRect>,
}

const WINDOW_LAYOUTS: &[WindowLayout] = &[
    WindowLayout {
        name: "win10_18362_plus",
        next: 0x58,
        parent: 0x68,
        child: 0x70,
        direct_name: Some(0xb8),
        string_name: 0xe8,
        direct_procedure: None,
        procedure_holder: Some((0x28, 0x78)),
        style: 0x44,
    },
    WindowLayout {
        name: "win10_17134_17763",
        next: 0x40,
        parent: 0x50,
        child: 0x58,
        direct_name: Some(0xa8),
        string_name: 0xe8,
        direct_procedure: None,
        procedure_holder: Some((0x28, 0x78)),
        style: 0x44,
    },
    WindowLayout {
        name: "win10_15063_16299",
        next: 0x58,
        parent: 0x68,
        child: 0x70,
        direct_name: None,
        string_name: 0xe8,
        direct_procedure: Some(0xa0),
        procedure_holder: None,
        style: 0x44,
    },
    WindowLayout {
        name: "legacy_x64",
        next: 0x48,
        parent: 0x58,
        child: 0x60,
        direct_name: None,
        string_name: 0xd8,
        direct_procedure: Some(0x90),
        procedure_holder: None,
        style: 0x34,
    },
];

#[derive(Clone)]
struct PoolCandidate {
    physical_header: u64,
    allocation_size: u64,
    tag: [u8; 4],
}

#[derive(Clone)]
struct SessionSpace {
    session_id: u32,
    pid: u64,
    dtb: u64,
}

#[derive(Clone)]
struct StationNode {
    record: WindowStationRecord,
}

#[derive(Clone)]
struct DesktopNode {
    record: DesktopRecord,
    layout: DesktopLayout,
    desk_info: u64,
    next: u64,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum BuildDepth {
    Stations,
    Desktops,
    Windows,
}

struct GuiGraph {
    stations: Vec<StationNode>,
    desktops: Vec<DesktopNode>,
    windows: Vec<WindowRecord>,
    bytes_scanned: u64,
    scan_seconds: f64,
    raw_tag_hits: usize,
    pool_candidates: usize,
    session_spaces_examined: usize,
    missing_pages: usize,
    missing_bytes: u64,
    complete: bool,
    warnings: Vec<String>,
}

pub fn window_stations(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    limit: usize,
) -> Result<GuiReport<WindowStationRecord>> {
    let graph = build_gui_graph(image, kernel, profile, limit, BuildDepth::Stations)?;
    let truncated = graph.stations.len() > limit;
    finish_report(
        graph
            .stations
            .iter()
            .map(|station| station.record.clone())
            .take(limit)
            .collect(),
        graph,
        truncated,
        limit,
    )
}

pub fn desktops(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    limit: usize,
    pool_scanned: bool,
) -> Result<GuiReport<DesktopRecord>> {
    let graph = build_gui_graph(image, kernel, profile, limit, BuildDepth::Desktops)?;
    let matching = graph
        .desktops
        .iter()
        .filter(|desktop| {
            if pool_scanned {
                desktop.record.pool_scanned
            } else {
                desktop.record.linked
            }
        })
        .count();
    let truncated = matching > limit;
    let records = graph
        .desktops
        .iter()
        .filter(|desktop| {
            if pool_scanned {
                desktop.record.pool_scanned
            } else {
                desktop.record.linked
            }
        })
        .map(|desktop| desktop.record.clone())
        .take(limit)
        .collect();
    finish_report(records, graph, truncated, limit)
}

pub fn windows(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    limit: usize,
) -> Result<GuiReport<WindowRecord>> {
    let graph = build_gui_graph(image, kernel, profile, limit, BuildDepth::Windows)?;
    let truncated = graph.windows.len() > limit;
    let records = graph.windows.iter().take(limit).cloned().collect();
    finish_report(records, graph, truncated, limit)
}

pub fn window_titles(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    limit: usize,
) -> Result<GuiReport<WindowTitleRecord>> {
    ensure!(
        limit > 0,
        "window title result limit must be greater than zero"
    );
    let graph = build_gui_graph(image, kernel, profile, MAX_GUI_OBJECTS, BuildDepth::Windows)?;
    let (records, truncated) = build_window_title_records(&graph.windows, limit);
    finish_report(records, graph, truncated, limit)
}

fn build_window_title_records(
    windows: &[WindowRecord],
    limit: usize,
) -> (Vec<WindowTitleRecord>, bool) {
    let parents = windows
        .iter()
        .map(|window| (window.address, window.parent))
        .collect::<HashMap<_, _>>();
    let title_by_address = windows
        .iter()
        .filter_map(|window| {
            window
                .title
                .as_deref()
                .filter(|title| !title.trim().is_empty())
                .map(|title| (window.address, title.to_owned()))
        })
        .collect::<HashMap<_, _>>();
    let mut duplicate_counts = HashMap::<String, usize>::new();
    for title in title_by_address.values() {
        *duplicate_counts
            .entry(normalized_title_key(title))
            .or_default() += 1;
    }

    let mut records = windows
        .iter()
        .filter_map(|window| {
            let title = window
                .title
                .as_deref()
                .filter(|title| !title.trim().is_empty())?;
            let parent_title = window
                .parent
                .and_then(|parent| title_by_address.get(&parent).cloned());
            let duplicate_title_count = duplicate_counts
                .get(&normalized_title_key(title))
                .copied()
                .unwrap_or(1);
            Some(WindowTitleRecord {
                address: window.address,
                title: title.to_owned(),
                title_characters: title.chars().count(),
                process: window.process.clone(),
                pid: window.pid,
                session_id: window.session_id,
                window_station: window.window_station.clone(),
                desktop: window.desktop.clone(),
                has_titled_parent: parent_title.is_some(),
                depth: window_title_depth(window.address, &parents),
                parent: window.parent,
                parent_title,
                child: window.child,
                next: window.next,
                procedure: window.procedure,
                duplicate_title_count,
                visible: window.visible,
                window_rect: window.window_rect,
                client_rect: window.client_rect,
                tree_depth: window.tree_depth,
                z_order: window.z_order,
                layout: window.layout.clone(),
            })
        })
        .collect::<Vec<_>>();
    let truncated = records.len() > limit;
    records.truncate(limit);
    (records, truncated)
}

fn normalized_title_key(title: &str) -> String {
    title.trim().to_lowercase()
}

fn window_title_depth(address: u64, parents: &HashMap<u64, Option<u64>>) -> usize {
    let mut depth = 0usize;
    let mut current = address;
    let mut seen = HashSet::new();
    seen.insert(current);
    while let Some(Some(parent)) = parents.get(&current) {
        if !parents.contains_key(parent) || !seen.insert(*parent) {
            break;
        }
        depth = depth.saturating_add(1);
        current = *parent;
    }
    depth
}

fn finish_report<T>(
    records: Vec<T>,
    mut graph: GuiGraph,
    truncated: bool,
    limit: usize,
) -> Result<GuiReport<T>> {
    if truncated {
        graph.complete = false;
        graph
            .warnings
            .push(format!("GUI result limit {limit} reached"));
    }
    Ok(GuiReport {
        records,
        bytes_scanned: graph.bytes_scanned,
        scan_seconds: graph.scan_seconds,
        raw_tag_hits: graph.raw_tag_hits,
        pool_candidates: graph.pool_candidates,
        session_spaces_examined: graph.session_spaces_examined,
        missing_pages: graph.missing_pages,
        missing_bytes: graph.missing_bytes,
        complete: graph.complete,
        warnings: graph.warnings,
    })
}

fn build_gui_graph(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    limit: usize,
    depth: BuildDepth,
) -> Result<GuiGraph> {
    ensure!(limit > 0, "GUI result limit must be greater than zero");
    let processes = list_processes(image, kernel, profile, 65_536)?;
    let sessions = select_session_spaces(&processes.processes);
    let mut warnings = processes
        .warnings
        .iter()
        .map(|warning| format!("pslist/{}: {}", warning.kind, warning.message))
        .collect::<Vec<_>>();
    if sessions.is_empty() {
        warnings.push("no process page table could represent a GUI session".to_owned());
    }

    let scan = scan_exact_4(image, &GUI_SCAN_TAGS, 1_000_000, 64 * 1024 * 1024)?;
    let candidates = validate_pool_candidates(image, &scan.hits);
    let target_pages = candidates
        .iter()
        .flat_map(allocation_pages)
        .collect::<HashSet<_>>();
    let process_map = processes
        .processes
        .iter()
        .map(|process| (process.eprocess, (process.pid, process.name.clone())))
        .collect::<HashMap<_, _>>();
    // Newer kernels expose most session-pool pages through the shared kernel
    // page tables, while older kernels keep them only in the owning session
    // page table.  Keep the fast shared lookup and supplement it once per
    // distinct session DTB; candidates still compete by live invariants.
    let shared_reverse = X64AddressSpace::new(image, kernel.directory_table_base)?
        .reverse_translate_pages(&target_pages, VirtualAddressRegion::Kernel, 8)?;

    let mut station_map = BTreeMap::<(u32, u64), StationNode>::new();
    let mut scanned_desktops = Vec::<(u32, u64, u64, DesktopLayout, u64, u64)>::new();
    let mut missing_pages = HashSet::new();
    let mut invalid_gui_links = 0usize;
    for session in &sessions {
        let space = match X64AddressSpace::new(image, session.dtb) {
            Ok(space) => space,
            Err(error) => {
                warnings.push(format!(
                    "会话 {} 的代表进程 PID {} 使用了无效 DTB：{error:#}",
                    session.session_id, session.pid
                ));
                continue;
            }
        };
        let session_reverse = if session.dtb == kernel.directory_table_base {
            None
        } else {
            match space.reverse_translate_pages(&target_pages, VirtualAddressRegion::Kernel, 8) {
                Ok(reverse) => Some(reverse),
                Err(error) => {
                    warnings.push(format!(
                        "会话 {} 的 GUI 物理页反向映射失败：{error:#}",
                        session.session_id
                    ));
                    None
                }
            }
        };
        for candidate in &candidates {
            let page = candidate.physical_header & !0xfff;
            let mut virtual_pages = Vec::new();
            if let Some(pages) = session_reverse
                .as_ref()
                .and_then(|reverse| reverse.get(&page))
            {
                virtual_pages.extend_from_slice(pages);
            }
            if let Some(pages) = shared_reverse.get(&page) {
                virtual_pages.extend_from_slice(pages);
            }
            virtual_pages.sort_unstable();
            virtual_pages.dedup();
            for virtual_page in virtual_pages {
                let pool_header = virtual_page + (candidate.physical_header & 0xfff);
                match &candidate.tag {
                    b"Wind" => {
                        if let Some(node) = find_station_in_allocation(
                            &space,
                            kernel,
                            profile,
                            session.session_id,
                            pool_header,
                            candidate,
                        ) {
                            station_map
                                .entry((session.session_id, node.record.address))
                                .or_insert(node);
                        }
                    }
                    b"Desk" => {
                        if let Some((body, header, layout, parent, desk_info, next)) =
                            find_desktop_in_allocation(
                                &space,
                                kernel,
                                profile,
                                session.session_id,
                                pool_header,
                                candidate,
                            )
                        {
                            let _ = (desk_info, next);
                            scanned_desktops.push((
                                session.session_id,
                                body,
                                header,
                                layout,
                                parent,
                                candidate.physical_header + (body - pool_header),
                            ));
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    // Follow station chains after pool validation.  This recovers active
    // entries even when their pool header page was not captured.
    let seeds = station_map.values().cloned().collect::<Vec<_>>();
    for seed in seeds {
        let Some(session) = sessions
            .iter()
            .find(|session| session.session_id == seed.record.session_id)
        else {
            continue;
        };
        let space = X64AddressSpace::new(image, session.dtb)?;
        let mut next = seed.record.next.unwrap_or(0);
        let mut traversed = 0usize;
        while next != 0 && traversed < 15 {
            if station_map.contains_key(&(session.session_id, next)) {
                break;
            }
            let Some(node) = decode_station_body(
                &space,
                kernel,
                profile,
                session.session_id,
                next,
                None,
                false,
            ) else {
                if !record_missing_pages(
                    &space,
                    session.session_id,
                    next,
                    0x100,
                    &mut missing_pages,
                ) {
                    invalid_gui_links += 1;
                }
                warnings.push(format!(
                    "会话 {} 的窗口站链在不可读或无效地址 {next:#x} 处停止",
                    session.session_id
                ));
                break;
            };
            next = node.record.next.unwrap_or(0);
            station_map.insert((session.session_id, node.record.address), node);
            traversed += 1;
        }
    }
    let missing_session_stations = sessions
        .iter()
        .filter(|session| {
            !station_map
                .keys()
                .any(|(session_id, _)| *session_id == session.session_id)
        })
        .map(|session| session.session_id)
        .collect::<Vec<_>>();
    for session_id in &missing_session_stations {
        warnings.push(format!(
            "共享及会话物理页反向映射均未为会话 {session_id} 找到有效窗口站"
        ));
    }

    let mut desktop_map = BTreeMap::<(u32, u64), DesktopNode>::new();
    if depth >= BuildDepth::Desktops {
        for station in station_map.values() {
            let Some(session) = sessions
                .iter()
                .find(|session| session.session_id == station.record.session_id)
            else {
                continue;
            };
            let space = X64AddressSpace::new(image, session.dtb)?;
            let mut address = station.record.desktop_list.unwrap_or(0);
            let mut seen = HashSet::new();
            while address != 0 && seen.len() < 256 && seen.insert(address) {
                let Some(mut desktop) = decode_desktop_body(
                    &space,
                    kernel,
                    profile,
                    station,
                    address,
                    None,
                    false,
                    &process_map,
                ) else {
                    if !record_missing_pages(
                        &space,
                        station.record.session_id,
                        address,
                        0xe0,
                        &mut missing_pages,
                    ) {
                        invalid_gui_links += 1;
                    }
                    warnings.push(format!(
                        "{} 的桌面链表在不可读或无效地址 {address:#x} 处停止",
                        station.record.name
                    ));
                    break;
                };
                desktop.record.linked = true;
                address = desktop.next;
                desktop_map.insert((desktop.record.session_id, desktop.record.address), desktop);
            }
        }

        // Correlate independently scanned Desktop objects with the station graph.
        for (session_id, body, header, layout_hint, parent, physical) in scanned_desktops {
            let Some(station) = station_map.get(&(session_id, parent)) else {
                continue;
            };
            let Some(session) = sessions
                .iter()
                .find(|session| session.session_id == session_id)
            else {
                continue;
            };
            let space = X64AddressSpace::new(image, session.dtb)?;
            if let Some(desktop) = decode_desktop_body(
                &space,
                kernel,
                profile,
                station,
                body,
                Some((header, layout_hint)),
                true,
                &process_map,
            ) {
                let entry = desktop_map
                    .entry((session_id, body))
                    .or_insert_with(|| desktop.clone());
                entry.record.pool_scanned = true;
                entry.record.physical_address = Some(physical);
            }
        }
    }

    let mut windows = Vec::new();
    let mut thread_owner_cache = HashMap::new();
    if depth >= BuildDepth::Windows {
        for desktop in desktop_map.values() {
            if !desktop.record.linked {
                continue;
            }
            let Some(session) = sessions
                .iter()
                .find(|session| session.session_id == desktop.record.session_id)
            else {
                continue;
            };
            let space = X64AddressSpace::new(image, session.dtb)?;
            let top = space
                .read_u64(desktop.desk_info + desktop.layout.top_window)
                .unwrap_or(0);
            if top == 0 {
                continue;
            }
            let mut queue = VecDeque::from([(top, 0usize, 0usize)]);
            let mut seen = HashSet::new();
            while let Some((address, tree_depth, z_order)) = queue.pop_front() {
                if address == 0 || !seen.insert(address) || seen.len() > limit.min(MAX_GUI_OBJECTS)
                {
                    continue;
                }
                let Some(mut window) = decode_window(
                    &space,
                    desktop,
                    address,
                    &process_map,
                    &mut thread_owner_cache,
                ) else {
                    if !record_missing_pages(
                        &space,
                        desktop.record.session_id,
                        address,
                        0x130,
                        &mut missing_pages,
                    ) {
                        invalid_gui_links += 1;
                    }
                    continue;
                };
                window.tree_depth = tree_depth;
                window.z_order = z_order;
                if let Some(next) = window.next {
                    queue.push_back((next, tree_depth, z_order.saturating_add(1)));
                }
                if let Some(child) = window.child {
                    queue.push_back((child, tree_depth.saturating_add(1), 0));
                }
                windows.push(window);
            }
        }
    }

    let mut stations = station_map.into_values().collect::<Vec<_>>();
    stations.sort_unstable_by_key(|station| (station.record.session_id, station.record.address));
    let mut desktops = desktop_map.into_values().collect::<Vec<_>>();
    desktops.sort_unstable_by_key(|desktop| (desktop.record.session_id, desktop.record.address));
    windows.sort_unstable_by_key(|window| (window.session_id, window.address));
    windows.dedup_by_key(|window| (window.session_id, window.address));

    if stations.is_empty() {
        warnings.push("未恢复到通过结构验证的窗口站对象".to_owned());
    }
    if scan.truncated {
        warnings.push("GUI 池标签扫描达到原始命中安全上限".to_owned());
    }
    let missing_page_count = missing_pages.len();
    let missing_bytes = missing_page_count as u64 * 0x1000;
    if missing_page_count != 0 {
        warnings.push(format!(
            "沿有效指针遍历时有 {missing_page_count} 个 GUI 对象页面（{missing_bytes} 字节）不驻留"
        ));
    }
    if invalid_gui_links != 0 {
        warnings.push(format!(
            "有 {invalid_gui_links} 条已验证 GUI 链接指向驻留但结构无效的对象"
        ));
    }
    let complete = processes.complete
        && !scan.truncated
        && missing_bytes == 0
        && invalid_gui_links == 0
        && missing_session_stations.is_empty()
        && !stations.is_empty()
        && !sessions.is_empty();
    Ok(GuiGraph {
        stations,
        desktops,
        windows,
        bytes_scanned: scan.bytes_scanned,
        scan_seconds: scan.elapsed_seconds,
        raw_tag_hits: scan.hits.len(),
        pool_candidates: candidates.len(),
        session_spaces_examined: sessions.len(),
        missing_pages: missing_page_count,
        missing_bytes,
        complete,
        warnings,
    })
}

fn select_session_spaces(processes: &[ProcessRecord]) -> Vec<SessionSpace> {
    fn priority(name: &str) -> u8 {
        if name.eq_ignore_ascii_case("csrss.exe") {
            6
        } else if name.eq_ignore_ascii_case("winlogon.exe") {
            5
        } else if name.eq_ignore_ascii_case("dwm.exe") {
            4
        } else if name.eq_ignore_ascii_case("explorer.exe") {
            3
        } else if name.eq_ignore_ascii_case("sihost.exe") {
            2
        } else {
            1
        }
    }
    let mut selected = BTreeMap::<u32, (u8, SessionSpace)>::new();
    for process in processes {
        let Some(session_id) = process
            .details
            .session_id
            .or(process.details.token_session_id)
        else {
            continue;
        };
        let Some(dtb) = process
            .details
            .directory_table_base
            .or(process.details.user_directory_table_base)
            .filter(|dtb| *dtb != 0)
        else {
            continue;
        };
        let rank = priority(&process.name);
        let candidate = SessionSpace {
            session_id,
            pid: process.pid,
            dtb,
        };
        if selected
            .get(&session_id)
            .is_none_or(|(existing, _)| rank > *existing)
        {
            selected.insert(session_id, (rank, candidate));
        }
    }
    selected.into_values().map(|(_, session)| session).collect()
}

fn validate_pool_candidates(
    image: &MemoryImage,
    hits: &[crate::scan::MultiScanHit],
) -> Vec<PoolCandidate> {
    let mut candidates = Vec::new();
    for hit in hits {
        if hit.physical_address & 0xf != 4 {
            continue;
        }
        let Some(header_address) = hit.physical_address.checked_sub(4) else {
            continue;
        };
        let mut header = [0u8; 16];
        if image.read_physical(header_address, &mut header).is_err()
            || header[4..8] != GUI_SCAN_TAGS[hit.pattern_index]
        {
            continue;
        }
        let tag_index = hit.pattern_index / 2;
        let allocation_size = u64::from(header[2]) * 16;
        let minimum = if tag_index == 0 { 0xe0 } else { 0x120 };
        if allocation_size < minimum
            || allocation_size > 0x10_000
            || header[1] > 16
            || !(1..=15).contains(&header[3])
        {
            continue;
        }
        candidates.push(PoolCandidate {
            physical_header: header_address,
            allocation_size,
            tag: GUI_TAGS[tag_index],
        });
    }
    candidates.sort_unstable_by_key(|candidate| candidate.physical_header);
    candidates.dedup_by_key(|candidate| candidate.physical_header);
    candidates
}

fn allocation_pages(candidate: &PoolCandidate) -> Vec<u64> {
    let start = candidate.physical_header & !0xfff;
    let end = candidate
        .physical_header
        .saturating_add(candidate.allocation_size)
        .saturating_add(0xfff)
        & !0xfff;
    (start..end).step_by(0x1000).collect()
}

fn find_station_in_allocation(
    space: &X64AddressSpace<'_>,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    session_id: u32,
    pool_header: u64,
    candidate: &PoolCandidate,
) -> Option<StationNode> {
    let body_offset = profile.type_field("_OBJECT_HEADER", "Body").ok()?.offset;
    let last = pool_header
        .checked_add(candidate.allocation_size)?
        .checked_sub(body_offset + 0x98)?;
    let mut header = (pool_header + 0x1f) & !0xf;
    while header <= last {
        if valid_object_header(space, profile, header) {
            let body = header + body_offset;
            if let Some(node) = decode_station_body(
                space,
                kernel,
                profile,
                session_id,
                body,
                Some(candidate.physical_header + (body - pool_header)),
                true,
            ) {
                return Some(node);
            }
        }
        header += 0x10;
    }
    None
}

fn decode_station_body(
    space: &X64AddressSpace<'_>,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    expected_session: u32,
    body: u64,
    physical_address: Option<u64>,
    pool_scanned: bool,
) -> Option<StationNode> {
    let session_id = read_u32(space, body)?;
    if session_id >= 256 || session_id != expected_session {
        return None;
    }
    let next = optional_kernel_pointer(space.read_u64(body + 0x08).ok()?)?;
    let desktop_list = optional_kernel_pointer(space.read_u64(body + 0x10).ok()?)?;
    let body_offset = profile.type_field("_OBJECT_HEADER", "Body").ok()?.offset;
    let header = body.checked_sub(body_offset)?;
    let name = object_name(space, kernel, profile, header)?;
    if name.chars().count() < 2 {
        return None;
    }
    Some(StationNode {
        record: WindowStationRecord {
            address: body,
            physical_address,
            name,
            session_id,
            next,
            desktop_list,
            pool_scanned,
        },
    })
}

fn find_desktop_in_allocation(
    space: &X64AddressSpace<'_>,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    expected_session: u32,
    pool_header: u64,
    candidate: &PoolCandidate,
) -> Option<(u64, u64, DesktopLayout, u64, u64, u64)> {
    let body_offset = profile.type_field("_OBJECT_HEADER", "Body").ok()?.offset;
    let last = pool_header
        .checked_add(candidate.allocation_size)?
        .checked_sub(body_offset + 0xe0)?;
    let mut best: Option<(usize, u64, u64, DesktopLayout, u64, u64, u64)> = None;
    let mut header = (pool_header + 0x1f) & !0xf;
    while header <= last {
        if !valid_object_header(space, profile, header) {
            header += 0x10;
            continue;
        }
        let body = header + body_offset;
        let Some(name) = object_name(space, kernel, profile, header) else {
            header += 0x10;
            continue;
        };
        if name.is_empty() {
            header += 0x10;
            continue;
        }
        for layout in DESKTOP_LAYOUTS {
            let Some(parent) = space.read_u64(body + layout.parent).ok() else {
                continue;
            };
            if !is_kernel_pointer(parent) {
                continue;
            }
            let Some(parent_sid) = read_u32(space, parent) else {
                continue;
            };
            if parent_sid != expected_session || parent_sid >= 256 {
                continue;
            }
            let Some(desk_info) = space.read_u64(body + layout.desk_info).ok() else {
                continue;
            };
            let Some(next) = space.read_u64(body + layout.next).ok() else {
                continue;
            };
            if !is_kernel_pointer(desk_info) || optional_kernel_pointer(next).is_none() {
                continue;
            }
            let top = space.read_u64(desk_info + layout.top_window).ok();
            let score = 10 + usize::from(top.is_some_and(valid_optional_kernel_pointer));
            if best
                .as_ref()
                .is_none_or(|(best_score, ..)| score > *best_score)
            {
                best = Some((score, body, header, *layout, parent, desk_info, next));
            }
        }
        header += 0x10;
    }
    best.map(|(_, body, header, layout, parent, desk_info, next)| {
        (body, header, layout, parent, desk_info, next)
    })
}

#[allow(clippy::too_many_arguments)]
fn decode_desktop_body(
    space: &X64AddressSpace<'_>,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    station: &StationNode,
    body: u64,
    hint: Option<(u64, DesktopLayout)>,
    pool_scanned: bool,
    process_map: &HashMap<u64, (u64, String)>,
) -> Option<DesktopNode> {
    let body_offset = profile.type_field("_OBJECT_HEADER", "Body").ok()?.offset;
    let header = hint
        .map(|value| value.0)
        .unwrap_or(body.checked_sub(body_offset)?);
    let name = object_name(space, kernel, profile, header)?;
    let layouts = hint
        .map(|value| vec![value.1])
        .unwrap_or_else(|| DESKTOP_LAYOUTS.to_vec());
    let mut best: Option<(usize, DesktopLayout, u64, u64)> = None;
    for layout in layouts {
        let Ok(parent) = space.read_u64(body + layout.parent) else {
            continue;
        };
        if parent != station.record.address {
            continue;
        }
        let Ok(desk_info) = space.read_u64(body + layout.desk_info) else {
            continue;
        };
        let Ok(next) = space.read_u64(body + layout.next) else {
            continue;
        };
        if !is_kernel_pointer(desk_info) || optional_kernel_pointer(next).is_none() {
            continue;
        }
        let top = space.read_u64(desk_info + layout.top_window).ok();
        let score = 10 + usize::from(top.is_some_and(valid_optional_kernel_pointer));
        if best
            .as_ref()
            .is_none_or(|(best_score, ..)| score > *best_score)
        {
            best = Some((score, layout, desk_info, next));
        }
    }
    let (_, layout, desk_info, next) = best?;
    let thread_owners = desktop_threads(space, body, layout, process_map);
    Some(DesktopNode {
        record: DesktopRecord {
            address: body,
            physical_address: None,
            name,
            window_station: station.record.address,
            window_station_name: station.record.name.clone(),
            session_id: station.record.session_id,
            layout: layout.name.to_owned(),
            linked: false,
            pool_scanned,
            thread_owners,
        },
        layout,
        desk_info,
        next,
    })
}

fn desktop_threads(
    space: &X64AddressSpace<'_>,
    desktop: u64,
    desktop_layout: DesktopLayout,
    process_map: &HashMap<u64, (u64, String)>,
) -> Vec<GuiThreadOwner> {
    let mut best = Vec::new();
    let mut head_offsets = vec![desktop_layout.pti_list];
    head_offsets.extend((0..=0xd0).step_by(8));
    head_offsets.sort_unstable();
    head_offsets.dedup();
    for head_offset in head_offsets {
        let head = desktop + head_offset;
        let Some(first) = space.read_u64(head).ok() else {
            continue;
        };
        let Some(last) = space.read_u64(head + 8).ok() else {
            continue;
        };
        if first == head && last == head {
            continue;
        }
        if !is_kernel_pointer(first)
            || !is_kernel_pointer(last)
            || space.read_u64(first + 8).ok() != Some(head)
            || space.read_u64(last).ok() != Some(head)
        {
            continue;
        }
        for layout in THREAD_LAYOUTS {
            let mut link = first;
            let mut seen = HashSet::new();
            let mut owners = Vec::new();
            while link != head && seen.len() < 4096 && seen.insert(link) {
                let Some(thread_info) = link.checked_sub(layout.list_link) else {
                    break;
                };
                let Some(process_info) = space.read_u64(thread_info + layout.process_info).ok()
                else {
                    break;
                };
                let Some(eprocess) = space.read_u64(process_info).ok() else {
                    break;
                };
                let Some((pid, process)) = process_map.get(&eprocess) else {
                    break;
                };
                owners.push(GuiThreadOwner {
                    thread_info,
                    eprocess,
                    pid: *pid,
                    process: process.clone(),
                });
                let Some(next) = space.read_u64(link).ok() else {
                    break;
                };
                if next != head && !is_kernel_pointer(next) {
                    break;
                }
                link = next;
            }
            owners.sort();
            owners.dedup();
            if owners.len() > best.len() {
                best = owners;
            }
        }
    }
    best
}

fn decode_window(
    space: &X64AddressSpace<'_>,
    desktop: &DesktopNode,
    address: u64,
    process_map: &HashMap<u64, (u64, String)>,
    thread_owner_cache: &mut HashMap<(u32, u64), Option<(u64, String)>>,
) -> Option<WindowRecord> {
    if space.read_u64(address + 0x20).ok()? != address
        || space.read_u64(address + 0x18).ok()? != desktop.record.address
    {
        return None;
    }
    let thread_info = space.read_u64(address + 0x10).ok()?;
    if !is_kernel_pointer(thread_info) {
        return None;
    }
    let owner = thread_owner_cache
        .entry((desktop.record.session_id, thread_info))
        .or_insert_with(|| process_for_thread(space, thread_info, process_map))
        .clone();
    let mut best: Option<WindowCandidate> = None;
    for layout in WINDOW_LAYOUTS {
        let Ok(next) = space.read_u64(address + layout.next) else {
            continue;
        };
        let Ok(parent) = space.read_u64(address + layout.parent) else {
            continue;
        };
        let Ok(child) = space.read_u64(address + layout.child) else {
            continue;
        };
        if !valid_optional_kernel_pointer(next)
            || !valid_optional_kernel_pointer(parent)
            || !valid_optional_kernel_pointer(child)
        {
            continue;
        }
        let direct_title = layout
            .direct_name
            .and_then(|offset| space.read_u64(address + offset).ok())
            .and_then(|pointer| read_utf16_z(space, pointer, 256));
        let title =
            direct_title.or_else(|| read_large_unicode(space, address + layout.string_name));
        let procedure = if let Some(offset) = layout.direct_procedure {
            space.read_u64(address + offset).ok()
        } else if let Some((holder_offset, procedure_offset)) = layout.procedure_holder {
            space
                .read_u64(address + holder_offset)
                .ok()
                .filter(|pointer| is_kernel_pointer(*pointer))
                .and_then(|holder| space.read_u64(holder + procedure_offset).ok())
        } else {
            None
        }
        .filter(|pointer| *pointer > 0x1000);
        let style = read_u32(space, address + layout.style);
        let ex_style = read_u32(space, address + 0x30);
        let visible = read_u32(space, address + 0x34).map(|state| state & 0x1000_0000 != 0);
        let window_rect = read_window_rect(space, address + 0x70);
        let client_rect = read_window_rect(space, address + 0x80);
        let linked_neighbors = [next, parent, child]
            .into_iter()
            .filter(|pointer| {
                *pointer != 0 && space.read_u64(*pointer + 0x20).ok() == Some(*pointer)
            })
            .count();
        let score = 5
            + usize::from(owner.is_some()) * 3
            + usize::from(title.as_deref().is_some_and(|title| !title.is_empty())) * 2
            + usize::from(procedure.is_some())
            + usize::from(window_rect.is_some()) * 2
            + usize::from(client_rect.is_some())
            + linked_neighbors * 2;
        if best
            .as_ref()
            .is_none_or(|candidate| score > candidate.score)
        {
            best = Some(WindowCandidate {
                score,
                layout: *layout,
                next,
                parent,
                child,
                title,
                procedure,
                style,
                ex_style,
                visible,
                window_rect,
                client_rect,
            });
        }
    }
    let candidate = best?;
    let (pid, process) = owner
        .map(|(pid, process)| (Some(pid), Some(process)))
        .unwrap_or((None, None));
    Some(WindowRecord {
        address,
        window_station: desktop.record.window_station_name.clone(),
        session_id: desktop.record.session_id,
        desktop: desktop.record.name.clone(),
        title: candidate.title,
        procedure: candidate.procedure,
        process,
        pid,
        parent: (candidate.parent != 0).then_some(candidate.parent),
        next: (candidate.next != 0).then_some(candidate.next),
        child: (candidate.child != 0).then_some(candidate.child),
        style: candidate.style,
        ex_style: candidate.ex_style,
        visible: candidate.visible,
        window_rect: candidate.window_rect,
        client_rect: candidate.client_rect,
        tree_depth: 0,
        z_order: 0,
        layout: candidate.layout.name.to_owned(),
    })
}

fn process_for_thread(
    space: &X64AddressSpace<'_>,
    thread_info: u64,
    process_map: &HashMap<u64, (u64, String)>,
) -> Option<(u64, String)> {
    for layout in THREAD_LAYOUTS {
        let Ok(process_info) = space.read_u64(thread_info + layout.process_info) else {
            continue;
        };
        let Ok(eprocess) = space.read_u64(process_info) else {
            continue;
        };
        if let Some((pid, process)) = process_map.get(&eprocess) {
            return Some((*pid, process.clone()));
        }
    }
    // Newer win32k builds can move tagTHREADINFO::ppi while preserving the
    // invariant that tagPROCESSINFO begins with its owning EPROCESS pointer.
    // Search the small captured thread-info body once and cross-check every
    // candidate against the already validated active-process object map.
    let mut bytes = vec![0u8; 0x300];
    space.read_virtual(thread_info, &mut bytes).ok()?;
    for chunk in bytes.chunks_exact(8) {
        let process_info = u64::from_le_bytes(chunk.try_into().ok()?);
        if !is_kernel_pointer(process_info) {
            continue;
        }
        let Ok(eprocess) = space.read_u64(process_info) else {
            continue;
        };
        if let Some((pid, process)) = process_map.get(&eprocess) {
            return Some((*pid, process.clone()));
        }
    }
    None
}

fn valid_object_header(space: &X64AddressSpace<'_>, profile: &KernelProfile, header: u64) -> bool {
    let pointer_offset = profile
        .type_field("_OBJECT_HEADER", "PointerCount")
        .map(|field| field.offset)
        .unwrap_or(0);
    let Some(pointer_count) = space
        .read_u64(header + pointer_offset)
        .ok()
        .map(|value| value as i64)
    else {
        return false;
    };
    (0..0x100_0000).contains(&pointer_count)
}

fn object_name(
    space: &X64AddressSpace<'_>,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    header: u64,
) -> Option<String> {
    let info_mask_offset = profile
        .type_field("_OBJECT_HEADER", "InfoMask")
        .ok()?
        .offset;
    let info_mask = read_u8(space, header + info_mask_offset)?;
    let index = info_mask & 3;
    if index & 2 == 0 {
        return None;
    }
    let table = kernel.kernel_base + u64::from(profile.symbol_rva("ObpInfoMaskToOffset").ok()?);
    let offset = read_u8(space, table + u64::from(index))?;
    if offset == 0 {
        return None;
    }
    let name_field = profile
        .type_field("_OBJECT_HEADER_NAME_INFO", "Name")
        .ok()?
        .offset;
    read_unicode_string(
        space,
        profile,
        header.checked_sub(u64::from(offset))? + name_field,
        1024,
    )
}

fn read_unicode_string(
    space: &X64AddressSpace<'_>,
    profile: &KernelProfile,
    address: u64,
    max_bytes: usize,
) -> Option<String> {
    let length_offset = profile.type_field("_UNICODE_STRING", "Length").ok()?.offset;
    let buffer_offset = profile.type_field("_UNICODE_STRING", "Buffer").ok()?.offset;
    let length = usize::from(read_u16(space, address + length_offset)?);
    let buffer = space.read_u64(address + buffer_offset).ok()?;
    if length == 0 || length > max_bytes || length % 2 != 0 || !is_kernel_pointer(buffer) {
        return None;
    }
    read_utf16_bytes(space, buffer, length)
}

fn read_large_unicode(space: &X64AddressSpace<'_>, address: u64) -> Option<String> {
    let length = usize::try_from(read_u32(space, address)?).ok()?;
    let buffer = space.read_u64(address + 8).ok()?;
    if length == 0 || length > 512 || length % 2 != 0 || !valid_pointer(buffer) {
        return None;
    }
    read_utf16_bytes(space, buffer, length)
}

fn read_utf16_z(space: &X64AddressSpace<'_>, address: u64, max_units: usize) -> Option<String> {
    if !valid_pointer(address) {
        return None;
    }
    let mut bytes = vec![0u8; max_units.checked_mul(2)?];
    space.read_virtual(address, &mut bytes).ok()?;
    let length = bytes
        .chunks_exact(2)
        .position(|pair| pair == [0, 0])
        .unwrap_or(max_units)
        * 2;
    read_utf16_slice(&bytes[..length])
}

fn read_utf16_bytes(space: &X64AddressSpace<'_>, address: u64, length: usize) -> Option<String> {
    let mut bytes = vec![0u8; length];
    space.read_virtual(address, &mut bytes).ok()?;
    read_utf16_slice(&bytes)
}

fn read_utf16_slice(bytes: &[u8]) -> Option<String> {
    let value = String::from_utf16_lossy(
        &bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>(),
    );
    (!value.is_empty()
        && !value.contains('\u{fffd}')
        && value
            .chars()
            .all(|character| !character.is_control() || matches!(character, '\r' | '\n' | '\t')))
    .then_some(value)
}

fn optional_kernel_pointer(pointer: u64) -> Option<Option<u64>> {
    if pointer == 0 {
        Some(None)
    } else if is_kernel_pointer(pointer) {
        Some(Some(pointer))
    } else {
        None
    }
}

fn record_missing_pages(
    space: &X64AddressSpace<'_>,
    session_id: u32,
    address: u64,
    length: u64,
    missing: &mut HashSet<(u32, u64)>,
) -> bool {
    let start = address & !0xfff;
    let end = address.saturating_add(length).saturating_add(0xfff) & !0xfff;
    let mut found = false;
    for page in (start..end).step_by(0x1000) {
        let mut byte = [0u8; 1];
        if space.read_virtual(page, &mut byte).is_err() {
            missing.insert((session_id, page));
            found = true;
        }
    }
    found
}

fn valid_optional_kernel_pointer(pointer: u64) -> bool {
    pointer == 0 || is_kernel_pointer(pointer)
}

fn valid_pointer(pointer: u64) -> bool {
    (0x1_0000..0x0000_8000_0000_0000).contains(&pointer) || is_kernel_pointer(pointer)
}

fn is_kernel_pointer(pointer: u64) -> bool {
    pointer >> 48 == 0xffff && pointer & 7 == 0
}

fn read_u8(space: &X64AddressSpace<'_>, address: u64) -> Option<u8> {
    let mut bytes = [0u8; 1];
    space.read_virtual(address, &mut bytes).ok()?;
    Some(bytes[0])
}

fn read_u16(space: &X64AddressSpace<'_>, address: u64) -> Option<u16> {
    let mut bytes = [0u8; 2];
    space.read_virtual(address, &mut bytes).ok()?;
    Some(u16::from_le_bytes(bytes))
}

fn read_u32(space: &X64AddressSpace<'_>, address: u64) -> Option<u32> {
    let mut bytes = [0u8; 4];
    space.read_virtual(address, &mut bytes).ok()?;
    Some(u32::from_le_bytes(bytes))
}

fn read_window_rect(space: &X64AddressSpace<'_>, address: u64) -> Option<WindowRect> {
    let mut bytes = [0u8; 16];
    space.read_virtual(address, &mut bytes).ok()?;
    let rect = WindowRect {
        left: i32::from_le_bytes(bytes[0..4].try_into().ok()?),
        top: i32::from_le_bytes(bytes[4..8].try_into().ok()?),
        right: i32::from_le_bytes(bytes[8..12].try_into().ok()?),
        bottom: i32::from_le_bytes(bytes[12..16].try_into().ok()?),
    };
    let coordinates = [rect.left, rect.top, rect.right, rect.bottom];
    if coordinates
        .into_iter()
        .any(|value| !(-1_000_000..=1_000_000).contains(&value))
        || rect.right < rect.left
        || rect.bottom < rect.top
        || rect.width() > 131_072
        || rect.height() > 131_072
    {
        return None;
    }
    Some(rect)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_canonical_aligned_kernel_pointers() {
        assert!(is_kernel_pointer(0xffff_f800_0000_1000));
        assert!(!is_kernel_pointer(0xffff_f800_0000_1001));
        assert!(!is_kernel_pointer(0x7ff6_0000_1000));
    }

    #[test]
    fn layout_selection_is_not_keyed_by_build_number() {
        assert!(DESKTOP_LAYOUTS.len() >= 5);
        assert!(WINDOW_LAYOUTS.len() >= 4);
        assert!(
            THREAD_LAYOUTS
                .iter()
                .all(|layout| layout.list_link != 0 && layout.process_info != 0)
        );
    }

    #[test]
    fn window_titles_keep_each_window_and_describe_hierarchy() {
        let windows = vec![
            WindowRecord {
                address: 0x1000,
                window_station: "WinSta0".to_owned(),
                session_id: 1,
                desktop: "Default".to_owned(),
                title: Some("Document".to_owned()),
                procedure: Some(0x5000),
                process: Some("editor.exe".to_owned()),
                pid: Some(42),
                parent: Some(0xffff_8000_0000_1000),
                next: None,
                child: Some(0x2000),
                style: Some(0x1000_0000),
                ex_style: Some(0),
                visible: Some(true),
                window_rect: Some(WindowRect {
                    left: 0,
                    top: 0,
                    right: 800,
                    bottom: 600,
                }),
                client_rect: None,
                tree_depth: 0,
                z_order: 0,
                layout: "test".to_owned(),
            },
            WindowRecord {
                address: 0x2000,
                window_station: "WinSta0".to_owned(),
                session_id: 1,
                desktop: "Default".to_owned(),
                title: Some("document".to_owned()),
                procedure: None,
                process: Some("editor.exe".to_owned()),
                pid: Some(42),
                parent: Some(0x1000),
                next: None,
                child: None,
                style: Some(0x1000_0000),
                ex_style: Some(0),
                visible: Some(true),
                window_rect: None,
                client_rect: None,
                tree_depth: 1,
                z_order: 0,
                layout: "test".to_owned(),
            },
            WindowRecord {
                address: 0x3000,
                window_station: "WinSta0".to_owned(),
                session_id: 1,
                desktop: "Default".to_owned(),
                title: Some("  ".to_owned()),
                procedure: None,
                process: Some("editor.exe".to_owned()),
                pid: Some(42),
                parent: None,
                next: None,
                child: None,
                style: Some(0),
                ex_style: Some(0),
                visible: Some(false),
                window_rect: None,
                client_rect: None,
                tree_depth: 0,
                z_order: 1,
                layout: "test".to_owned(),
            },
        ];

        let (records, truncated) = build_window_title_records(&windows, 10);
        assert!(!truncated);
        assert_eq!(records.len(), 2);
        assert!(!records[0].has_titled_parent);
        assert_eq!(records[0].depth, 0);
        assert_eq!(records[0].duplicate_title_count, 2);
        assert!(records[1].has_titled_parent);
        assert_eq!(records[1].depth, 1);
        assert_eq!(records[1].parent_title.as_deref(), Some("Document"));
        assert_eq!(records[1].duplicate_title_count, 2);

        let (limited, truncated) = build_window_title_records(&windows, 1);
        assert!(truncated);
        assert_eq!(limited.len(), 1);
    }
}
