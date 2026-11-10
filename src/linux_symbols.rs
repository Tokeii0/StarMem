//! Volatility 3-compatible Linux ISF discovery and parsing.
//!
//! StarMem deliberately consumes the same dwarf2json JSON/JSON.XZ files in
//! Volatility's `symbols/linux` tree.  A table is selected only when its
//! base64-encoded `linux_banner.constant_data` exactly matches a banner
//! recovered from the image; filenames and release-only similarities are not
//! identities.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::env;
use std::fs::{self, File};
use std::io::{Read, copy};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use lzma_rust2::XzReader;
use reqwest::Url;
use reqwest::blocking::Client;
use reqwest::redirect::Policy;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::image::MemoryImage;
use crate::output_policy::{OutputPolicy, OutputTarget};
use crate::symbols::SymbolStore;

const MAX_ISF_BYTES: u64 = 512 * 1024 * 1024;
const MAX_ISF_FILES: usize = 100_000;
const MAX_DISCOVERY_WARNINGS: usize = 16;
const MAX_REMOTE_INDEX_BYTES: u64 = 16 * 1024 * 1024;
const MAX_REMOTE_INDEX_ENTRIES: usize = 100_000;
const MAX_REMOTE_ISF_BYTES: u64 = 256 * 1024 * 1024;
const MAX_REMOTE_CANDIDATES: usize = 16;
const REMOTE_INDEX_TTL: Duration = Duration::from_secs(24 * 60 * 60);
const DEFAULT_REMOTE_ISF_INDEX: &str = "https://raw.githubusercontent.com/Abyss-W4tcher/volatility3-symbols/master/banners/banners.json";

const BASE_REQUIRED_SYMBOLS: &[&str] = &["_stext", "linux_banner"];

const TASK_TYPES: &[&str] = &["task_struct"];
const TASK_RETAINED_TYPES: &[&str] = &[
    "mm_struct",
    "vm_area_struct",
    "files_struct",
    "fdtable",
    "cred",
    "kernel_cap_struct",
    "kernel_cap_t",
    "kuid_t",
    "kgid_t",
    "signal_struct",
    "list_head",
    "pid",
    "upid",
    "pid_namespace",
    "idr",
    "xarray",
    "radix_tree_root",
    "xa_node",
    "radix_tree_node",
    "hlist_head",
    "hlist_node",
];
const TASK_SYMBOLS: &[&str] = &["init_task"];
const TASK_FIELDS: &[LinuxSymbolFieldRequirement] = &[
    LinuxSymbolFieldRequirement::one("task_struct", &["tasks"]),
    LinuxSymbolFieldRequirement::one("task_struct", &["pid"]),
    LinuxSymbolFieldRequirement::one("task_struct", &["tgid"]),
    LinuxSymbolFieldRequirement::one("task_struct", &["comm"]),
    LinuxSymbolFieldRequirement::one("task_struct", &["real_parent"]),
    LinuxSymbolFieldRequirement::any("task_struct", &["__state", "state"]),
];

const VFS_TYPES: &[&str] = &[
    "super_block",
    "file_system_type",
    "dentry",
    "inode",
    "address_space",
    "file",
    "path",
    "qstr",
];
const VFS_RETAINED_TYPES: &[&str] = &[
    "radix_tree_root",
    "xarray",
    "page",
    "folio",
    "mount",
    "vfsmount",
];
const VFS_SYMBOLS: &[&str] = &["super_blocks"];
const VFS_RETAINED_SYMBOLS: &[&str] = &["vmemmap_base", "max_pfn", "page_offset_base"];
const VFS_FIELDS: &[LinuxSymbolFieldRequirement] = &[
    LinuxSymbolFieldRequirement::one("super_block", &["s_root"]),
    LinuxSymbolFieldRequirement::one("super_block", &["s_type"]),
    LinuxSymbolFieldRequirement::one("dentry", &["d_parent"]),
    LinuxSymbolFieldRequirement::one("dentry", &["d_name"]),
    LinuxSymbolFieldRequirement::one("dentry", &["d_inode"]),
    LinuxSymbolFieldRequirement::one("qstr", &["len"]),
    LinuxSymbolFieldRequirement::one("qstr", &["name"]),
    LinuxSymbolFieldRequirement::one("inode", &["i_mode"]),
    LinuxSymbolFieldRequirement::one("inode", &["i_mapping"]),
    LinuxSymbolFieldRequirement::one("inode", &["i_ino"]),
    LinuxSymbolFieldRequirement::one("address_space", &["nrpages"]),
];

const NETWORK_TYPES: &[&str] = &[
    "task_struct",
    "file",
    "socket_alloc",
    "socket",
    "sock",
    "sock_common",
    "unix_sock",
    "unix_address",
    "sockaddr_un",
    "nsproxy",
    "net",
    "ns_common",
    "possible_net_t",
];
const NETWORK_FIELDS: &[LinuxSymbolFieldRequirement] = &[
    LinuxSymbolFieldRequirement::one("file", &["private_data"]),
    LinuxSymbolFieldRequirement::one("socket", &["sk"]),
    LinuxSymbolFieldRequirement::one("sock", &["__sk_common"]),
    LinuxSymbolFieldRequirement::one("task_struct", &["nsproxy"]),
    LinuxSymbolFieldRequirement::one("nsproxy", &["net_ns"]),
];

const MODULE_TYPES: &[&str] = &["list_head", "module", "module_layout"];
const MODULE_RETAINED_TYPES: &[&str] = &["module_kobject", "kobject", "kset"];
const MODULE_SYMBOLS: &[&str] = &["modules"];
const MODULE_RETAINED_SYMBOLS: &[&str] = &[
    "module_kset",
    "module_sysfs_initialized",
    // These globals provide the only bounded address universe accepted by the
    // restricted semantic module scan.  If a kernel does not expose them the
    // source remains explicitly unavailable instead of falling back to a loose
    // whole-memory string scan.
    "module_addr_min",
    "module_addr_max",
];
const MODULE_FIELDS: &[LinuxSymbolFieldRequirement] = &[
    LinuxSymbolFieldRequirement::one("module", &["list"]),
    LinuxSymbolFieldRequirement::one("module", &["name"]),
    LinuxSymbolFieldRequirement::any("module", &["core_layout", "module_core"]),
];

const MOUNT_TYPES: &[&str] = &[
    "task_struct",
    "mnt_namespace",
    "mount",
    "vfsmount",
    "nsproxy",
    "path",
    "dentry",
    "qstr",
    "super_block",
    "file_system_type",
];
const MOUNT_SYMBOLS: &[&str] = &["init_task"];
const MOUNT_FIELDS: &[LinuxSymbolFieldRequirement] = &[
    LinuxSymbolFieldRequirement::one("task_struct", &["nsproxy"]),
    LinuxSymbolFieldRequirement::one("nsproxy", &["mnt_ns"]),
    LinuxSymbolFieldRequirement::any("mnt_namespace", &["list", "mounts"]),
    LinuxSymbolFieldRequirement::one("mount", &["mnt_list"]),
    LinuxSymbolFieldRequirement::one("mount", &["mnt"]),
    LinuxSymbolFieldRequirement::one("mount", &["mnt_parent"]),
    LinuxSymbolFieldRequirement::one("mount", &["mnt_mountpoint"]),
    LinuxSymbolFieldRequirement::one("vfsmount", &["mnt_root"]),
    LinuxSymbolFieldRequirement::one("vfsmount", &["mnt_sb"]),
    LinuxSymbolFieldRequirement::one("dentry", &["d_parent"]),
    LinuxSymbolFieldRequirement::one("dentry", &["d_name"]),
    LinuxSymbolFieldRequirement::one("qstr", &["len"]),
    LinuxSymbolFieldRequirement::one("qstr", &["name"]),
    LinuxSymbolFieldRequirement::one("super_block", &["s_type"]),
    LinuxSymbolFieldRequirement::one("file_system_type", &["name"]),
];

const KALLSYMS_SYMBOLS: &[&str] = &[
    "kallsyms_num_syms",
    "kallsyms_names",
    "kallsyms_markers",
    "kallsyms_token_table",
    "kallsyms_token_index",
];
const KALLSYMS_SYMBOL_ALTERNATIVES: &[&[&str]] = &[&["kallsyms_addresses", "kallsyms_offsets"]];
const KALLSYMS_RETAINED_TYPES: &[&str] = &["mod_kallsyms", "module_kallsyms"];
const KALLSYMS_RETAINED_SYMBOLS: &[&str] = &["kallsyms_relative_base"];

const KMSG_TYPE_ALTERNATIVES: &[&[&str]] =
    &[&["printk_log", "log", "printk_ringbuffer", "prb_desc_ring"]];
const KMSG_SYMBOL_ALTERNATIVES: &[&[&str]] = &[&["log_buf", "prb", "printk_rb_static"]];
const KMSG_RETAINED_TYPES: &[&str] = &[
    "prb_data_ring",
    "prb_data_blk_lpos",
    "prb_desc",
    "printk_info",
    "dev_printk_info",
    "atomic_long_t",
    "atomic64_t",
];
const KMSG_RETAINED_SYMBOLS: &[&str] = &[
    "log_buf_len",
    "log_first_idx",
    "log_next_idx",
    "clear_seq",
    "log_first_seq",
    "log_next_seq",
];

const HOOK_RETAINED_TYPES: &[&str] = &["module", "module_layout"];
const HOOK_SYMBOLS: &[&str] = &["sys_call_table"];
const HOOK_RETAINED_SYMBOLS: &[&str] = &[
    "_etext",
    "_sinittext",
    "_einittext",
    "ia32_sys_call_table",
    "x32_sys_call_table",
];

const NO_NAMES: &[&str] = &[];
const NO_ALTERNATIVES: &[&[&str]] = &[];
const NO_FIELDS: &[LinuxSymbolFieldRequirement] = &[];

// Optional incident-response structures. Their absence disables the affected analysis only,
// rather than rejecting a valid kernel/session for unrelated plugins.
const IR_TYPES: &[&str] = &[
    "super_block",
    "inode",
    "address_space",
    "pg_data_t",
    "pglist_data",
    "nodemask_t",
    "zone",
    "cpuinfo_x86",
    "percpu_counter",
    "cpumask",
    "hstate",
    "tk_read_base",
    "atomic_t",
    "atomic64_t",
    "netns_ipv4",
    "fib_table",
    "netns_ipv6",
    "trie",
    "tnode",
    "key_vector",
    "fib_alias",
    "fib_info",
    "fib_nh",
    "fib_nh_common",
    "fib6_table",
    "fib6_node",
    "fib6_info",
    "fib6_nh",
    "rt6_info",
    "rt6key",
    "nexthop",
    "nh_info",
    "nh_group",
    "nh_grp_entry",
    "dst_entry",
    "possible_net_t",
    "hlist_head",
    "hlist_node",
    "seqcount",
    "seqcount_raw_spinlock",
    "task_struct",
    "pid",
    "upid",
    "pid_namespace",
    "pid_link",
    "resource",
    "tk_data",
    "timekeeper",
    "timespec",
    "timespec64",
    "uts_namespace",
    "new_utsname",
    "net",
    "ns_common",
    "list_head",
    "net_device",
    "net_device_stats",
    "in_device",
    "in_ifaddr",
    "inet6_dev",
    "inet6_ifaddr",
    "in6_addr",
    "neigh_table",
    "neigh_hash_table",
    "neighbour",
    "notifier_block",
    "blocking_notifier_head",
    "atomic_notifier_head",
    "raw_notifier_head",
    "gate_struct",
    "gate_struct64",
    "idt_desc",
    "desc_struct",
    "tty_driver",
    "tty_struct",
    "tty_operations",
    "tty_ldisc",
    "tty_ldisc_ops",
    "bpf_prog",
    "bpf_prog_aux",
    "idr",
    "xarray",
    "xa_node",
    "radix_tree_root",
    "radix_tree_node",
    "kprobe",
    "hlist_head",
    "hlist_node",
    "ftrace_ops",
    "tracepoint",
    "tracepoint_func",
    "nf_hook_entries",
    "nf_hook_entry",
    "nf_hook_ops",
    "netns_nf",
    "perf_event",
    "perf_event_attr",
    "pmu",
    "thread_struct",
    "thread_union",
    "vm_struct",
    "bpf_ksym",
    "module",
    "module_layout",
    "mod_kallsyms",
    "elf64_sym",
    "fb_info",
    "fb_var_screeninfo",
    "fb_fix_screeninfo",
    "fb_bitfield",
    "seq_operations",
    "tcp_seq_afinfo",
    "udp_seq_afinfo",
    "file_operations",
    "file_system_type",
    "proc_dir_entry",
];
const IR_SYMBOLS: &[&str] = &[
    "_totalram_pages",
    "totalram_pages",
    "__start_BTF",
    "__stop_BTF",
    "vm_zone_stat",
    "vm_node_stat",
    "total_swap_pages",
    "nr_swap_pages",
    "blockdev_superblock",
    "swapper_spaces",
    "nr_swapper_spaces",
    "totalcma_pages",
    "node_data",
    "contig_page_data",
    "node_states",
    "nr_node_ids",
    "nr_online_nodes",
    "totalreserve_pages",
    "vm_committed_as",
    "sysctl_overcommit_memory",
    "sysctl_overcommit_ratio",
    "sysctl_overcommit_kbytes",
    "hstates",
    "hugetlb_max_hstate",
    "__per_cpu_offset",
    "__cpu_online_mask",
    "__cpu_possible_mask",
    "__cpu_dying_mask",
    "nr_cpu_ids",
    "default_hstate_idx",
    "nr_vmalloc_pages",
    "pcpu_nr_populated",
    "pcpu_nr_units",
    "num_poisoned_pages",
    "iomem_resource",
    "ioport_resource",
    "tk_core",
    "timekeeper",
    "wall_to_monotonic",
    "init_uts_ns",
    "net_namespace_list",
    "init_net",
    "arp_tbl",
    "nd_tbl",
    "keyboard_notifier_list",
    "idt_table",
    "tty_drivers",
    "prog_idr",
    "kprobe_table",
    "ftrace_ops_list",
    "ftrace_list_end",
    "__start___tracepoints",
    "__stop___tracepoints",
    "__start___tracepoints_ptrs",
    "__stop___tracepoints_ptrs",
    "tracepoint_module_list",
    "nr_registered_fb",
    "num_registered_fb",
    "registered_fb",
    "pid_hash",
    "pidhash_shift",
    "init_pid_ns",
    "tcp4_seq_afinfo",
    "tcp6_seq_afinfo",
    "udp4_seq_afinfo",
    "udp6_seq_afinfo",
    "tcp4_seq_ops",
    "tcp6_seq_ops",
    "udp_seq_ops",
    "udp6_seq_ops",
    "nf_hooks",
    "boot_cpu_data",
    "_stext",
    "_etext",
    "_text",
    "_end",
    "init_task",
    "fair_sched_class",
    "idle_sched_class",
    "rt_sched_class",
    "dl_sched_class",
    "stop_sched_class",
    "ext_sched_class",
    "modules",
    "kallsyms_num_syms",
    "kallsyms_names",
    "kallsyms_markers",
    "kallsyms_token_table",
    "kallsyms_token_index",
    "kallsyms_addresses",
    "kallsyms_offsets",
    "kallsyms_relative_base",
];

const LINUX_SYMBOL_FEATURE_REGISTRY: &[LinuxSymbolFeatureRequirements] = &[
    LinuxSymbolFeatureRequirements::new(
        LinuxSymbolFeature::IncidentResponse,
        NO_NAMES,
        NO_ALTERNATIVES,
        IR_TYPES,
        NO_NAMES,
        NO_ALTERNATIVES,
        IR_SYMBOLS,
    ),
    LinuxSymbolFeatureRequirements::new(
        LinuxSymbolFeature::Task,
        TASK_TYPES,
        NO_ALTERNATIVES,
        TASK_RETAINED_TYPES,
        TASK_SYMBOLS,
        NO_ALTERNATIVES,
        NO_NAMES,
    )
    .with_required_fields(TASK_FIELDS),
    LinuxSymbolFeatureRequirements::new(
        LinuxSymbolFeature::Vfs,
        VFS_TYPES,
        NO_ALTERNATIVES,
        VFS_RETAINED_TYPES,
        VFS_SYMBOLS,
        NO_ALTERNATIVES,
        VFS_RETAINED_SYMBOLS,
    )
    .with_required_fields(VFS_FIELDS),
    LinuxSymbolFeatureRequirements::new(
        LinuxSymbolFeature::Network,
        NETWORK_TYPES,
        NO_ALTERNATIVES,
        NO_NAMES,
        NO_NAMES,
        NO_ALTERNATIVES,
        NO_NAMES,
    )
    .with_required_fields(NETWORK_FIELDS),
    LinuxSymbolFeatureRequirements::new(
        LinuxSymbolFeature::Modules,
        MODULE_TYPES,
        NO_ALTERNATIVES,
        MODULE_RETAINED_TYPES,
        MODULE_SYMBOLS,
        NO_ALTERNATIVES,
        MODULE_RETAINED_SYMBOLS,
    )
    .with_required_fields(MODULE_FIELDS),
    LinuxSymbolFeatureRequirements::new(
        LinuxSymbolFeature::Mount,
        MOUNT_TYPES,
        NO_ALTERNATIVES,
        NO_NAMES,
        MOUNT_SYMBOLS,
        NO_ALTERNATIVES,
        NO_NAMES,
    )
    .with_required_fields(MOUNT_FIELDS),
    LinuxSymbolFeatureRequirements::new(
        LinuxSymbolFeature::Kallsyms,
        NO_NAMES,
        NO_ALTERNATIVES,
        KALLSYMS_RETAINED_TYPES,
        KALLSYMS_SYMBOLS,
        KALLSYMS_SYMBOL_ALTERNATIVES,
        KALLSYMS_RETAINED_SYMBOLS,
    ),
    LinuxSymbolFeatureRequirements::new(
        LinuxSymbolFeature::Kmsg,
        NO_NAMES,
        KMSG_TYPE_ALTERNATIVES,
        KMSG_RETAINED_TYPES,
        NO_NAMES,
        KMSG_SYMBOL_ALTERNATIVES,
        KMSG_RETAINED_SYMBOLS,
    ),
    LinuxSymbolFeatureRequirements::new(
        LinuxSymbolFeature::Hooks,
        NO_NAMES,
        NO_ALTERNATIVES,
        HOOK_RETAINED_TYPES,
        HOOK_SYMBOLS,
        NO_ALTERNATIVES,
        HOOK_RETAINED_SYMBOLS,
    ),
];

/// Linux plugin family whose types and symbols must survive ISF compaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinuxSymbolFeature {
    IncidentResponse,
    Task,
    Vfs,
    Network,
    Modules,
    Mount,
    Kallsyms,
    Kmsg,
    Hooks,
}

impl LinuxSymbolFeature {
    pub const ALL: [Self; 9] = [
        Self::IncidentResponse,
        Self::Task,
        Self::Vfs,
        Self::Network,
        Self::Modules,
        Self::Mount,
        Self::Kallsyms,
        Self::Kmsg,
        Self::Hooks,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::IncidentResponse => "incident_response",
            Self::Task => "task",
            Self::Vfs => "vfs",
            Self::Network => "network",
            Self::Modules => "modules",
            Self::Mount => "mount",
            Self::Kallsyms => "kallsyms",
            Self::Kmsg => "kmsg",
            Self::Hooks => "hooks",
        }
    }
}

impl std::fmt::Display for LinuxSymbolFeature {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::str::FromStr for LinuxSymbolFeature {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "incident_response" | "incident-response" | "ir" => Ok(Self::IncidentResponse),
            "task" => Ok(Self::Task),
            "vfs" => Ok(Self::Vfs),
            "network" => Ok(Self::Network),
            "modules" => Ok(Self::Modules),
            "mount" => Ok(Self::Mount),
            "kallsyms" => Ok(Self::Kallsyms),
            "kmsg" => Ok(Self::Kmsg),
            "hooks" => Ok(Self::Hooks),
            other => Err(format!("未知 Linux symbol feature: {other}")),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct LinuxSymbolFieldRequirement {
    pub type_name: &'static str,
    pub any_of: &'static [&'static str],
}

impl LinuxSymbolFieldRequirement {
    pub const fn one(type_name: &'static str, any_of: &'static [&'static str]) -> Self {
        Self { type_name, any_of }
    }

    pub const fn any(type_name: &'static str, any_of: &'static [&'static str]) -> Self {
        Self { type_name, any_of }
    }

    fn display_name(self) -> String {
        format!("{}.({})", self.type_name, self.any_of.join("|"))
    }
}

#[derive(Debug, Clone, Copy)]
pub struct LinuxSymbolFeatureRequirements {
    pub feature: LinuxSymbolFeature,
    pub required_types: &'static [&'static str],
    pub alternative_types: &'static [&'static [&'static str]],
    pub retained_types: &'static [&'static str],
    pub required_symbols: &'static [&'static str],
    pub alternative_symbols: &'static [&'static [&'static str]],
    pub retained_symbols: &'static [&'static str],
    pub required_fields: &'static [LinuxSymbolFieldRequirement],
}

impl LinuxSymbolFeatureRequirements {
    const fn new(
        feature: LinuxSymbolFeature,
        required_types: &'static [&'static str],
        alternative_types: &'static [&'static [&'static str]],
        retained_types: &'static [&'static str],
        required_symbols: &'static [&'static str],
        alternative_symbols: &'static [&'static [&'static str]],
        retained_symbols: &'static [&'static str],
    ) -> Self {
        Self {
            feature,
            required_types,
            alternative_types,
            retained_types,
            required_symbols,
            alternative_symbols,
            retained_symbols,
            required_fields: NO_FIELDS,
        }
    }

    const fn with_required_fields(
        mut self,
        required_fields: &'static [LinuxSymbolFieldRequirement],
    ) -> Self {
        self.required_fields = required_fields;
        self
    }
}

/// Declarative registry used by ISF loading, diagnostics and future Linux plugins.
pub fn linux_symbol_feature_registry() -> &'static [LinuxSymbolFeatureRequirements] {
    LINUX_SYMBOL_FEATURE_REGISTRY
}

fn legacy_features() -> BTreeSet<LinuxSymbolFeature> {
    [
        LinuxSymbolFeature::Task,
        LinuxSymbolFeature::IncidentResponse,
        LinuxSymbolFeature::Vfs,
        LinuxSymbolFeature::Network,
    ]
    .into_iter()
    .collect()
}

fn normalize_features(
    features: impl IntoIterator<Item = LinuxSymbolFeature>,
) -> BTreeSet<LinuxSymbolFeature> {
    let mut features = features.into_iter().collect::<BTreeSet<_>>();
    if features.is_empty() {
        features = legacy_features();
    }
    // Incident-response summaries reuse the existing log, module and syscall readers.
    // Retain those layouts during ISF compaction so task sessions can run them too.
    if features.contains(&LinuxSymbolFeature::IncidentResponse) {
        features.extend([
            LinuxSymbolFeature::Modules,
            LinuxSymbolFeature::Kmsg,
            LinuxSymbolFeature::Hooks,
        ]);
    }
    // linux.kallsyms intentionally covers both the core table and verified
    // module ELF symbol tables.  Expand that dependency centrally so CLI,
    // diagnostics, cache compaction and library callers cannot accidentally
    // produce an ISF that is sufficient for only half of the declared scope.
    if features.contains(&LinuxSymbolFeature::Kallsyms) {
        features.insert(LinuxSymbolFeature::Modules);
    }
    features
}

fn requirements_for_features(
    features: &BTreeSet<LinuxSymbolFeature>,
) -> impl Iterator<Item = &'static LinuxSymbolFeatureRequirements> {
    LINUX_SYMBOL_FEATURE_REGISTRY
        .iter()
        .filter(|requirements| features.contains(&requirements.feature))
}

fn retained_type_names(features: &BTreeSet<LinuxSymbolFeature>) -> BTreeSet<&'static str> {
    requirements_for_features(features)
        .flat_map(|requirements| {
            requirements
                .required_types
                .iter()
                .copied()
                .chain(requirements.retained_types.iter().copied())
                .chain(
                    requirements
                        .alternative_types
                        .iter()
                        .flat_map(|alternatives| alternatives.iter().copied()),
                )
        })
        .collect()
}

fn retained_symbol_names(features: &BTreeSet<LinuxSymbolFeature>) -> BTreeSet<&'static str> {
    BASE_REQUIRED_SYMBOLS
        .iter()
        .copied()
        .chain(
            requirements_for_features(features).flat_map(|requirements| {
                requirements
                    .required_symbols
                    .iter()
                    .copied()
                    .chain(requirements.retained_symbols.iter().copied())
                    .chain(
                        requirements
                            .alternative_symbols
                            .iter()
                            .flat_map(|alternatives| alternatives.iter().copied()),
                    )
            }),
        )
        .collect()
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxSymbolRequirementGaps {
    pub missing_types: Vec<String>,
    pub missing_symbols: Vec<String>,
    pub missing_fields: Vec<String>,
}

impl LinuxSymbolRequirementGaps {
    pub fn is_empty(&self) -> bool {
        self.missing_types.is_empty()
            && self.missing_symbols.is_empty()
            && self.missing_fields.is_empty()
    }
}

/// Path-free, deterministic identity for symbol material consumed by StarMem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxSymbolIdentity {
    pub schema_version: u32,
    pub provider: String,
    pub format: String,
    pub producer: Option<String>,
    pub banner_sha256: String,
    pub isf_sha256: String,
    pub vmlinux_sha256: Vec<String>,
    pub features: Vec<LinuxSymbolFeature>,
    pub canonical_sha256: String,
}

#[derive(Debug, Serialize)]
struct LinuxSymbolIdentityPayload<'a> {
    schema_version: u32,
    provider: &'static str,
    format: &'a str,
    producer: Option<&'a str>,
    banner_sha256: String,
    isf_sha256: &'a str,
    vmlinux_sha256: &'a [String],
    features: Vec<LinuxSymbolFeature>,
}

#[derive(Debug, Clone)]
pub struct LinuxIsf {
    path: PathBuf,
    format: String,
    producer: Option<String>,
    banner: String,
    file_sha256: String,
    vmlinux_sha256: Vec<String>,
    base_types: BTreeMap<String, IsfBaseType>,
    user_types: BTreeMap<String, IsfUserType>,
    enums: BTreeMap<String, IsfEnum>,
    symbols: BTreeMap<String, IsfSymbol>,
    features: BTreeSet<LinuxSymbolFeature>,
    fingerprint: String,
}

impl LinuxIsf {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn format(&self) -> &str {
        &self.format
    }

    pub fn producer(&self) -> Option<&str> {
        self.producer.as_deref()
    }

    pub fn banner(&self) -> &str {
        &self.banner
    }

    pub fn file_sha256(&self) -> &str {
        &self.file_sha256
    }

    pub fn vmlinux_sha256(&self) -> &[String] {
        &self.vmlinux_sha256
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    pub fn features(&self) -> &BTreeSet<LinuxSymbolFeature> {
        &self.features
    }

    pub fn identity(&self) -> Result<LinuxSymbolIdentity> {
        let payload = LinuxSymbolIdentityPayload {
            schema_version: 1,
            provider: "volatility3_isf",
            format: &self.format,
            producer: self.producer.as_deref(),
            banner_sha256: sha256_hex(self.banner.as_bytes()),
            isf_sha256: &self.file_sha256,
            vmlinux_sha256: &self.vmlinux_sha256,
            features: self.features.iter().copied().collect(),
        };
        let canonical = canonical_json_bytes(&serde_json::to_value(&payload)?)?;
        Ok(LinuxSymbolIdentity {
            schema_version: payload.schema_version,
            provider: payload.provider.to_owned(),
            format: payload.format.to_owned(),
            producer: payload.producer.map(str::to_owned),
            banner_sha256: payload.banner_sha256,
            isf_sha256: payload.isf_sha256.to_owned(),
            vmlinux_sha256: payload.vmlinux_sha256.to_vec(),
            features: payload.features,
            canonical_sha256: sha256_hex(&canonical),
        })
    }

    pub fn requirement_gaps(&self) -> LinuxSymbolRequirementGaps {
        self.requirement_gaps_for(&self.features)
    }

    pub fn requirement_gaps_for(
        &self,
        features: &BTreeSet<LinuxSymbolFeature>,
    ) -> LinuxSymbolRequirementGaps {
        let mut gaps = LinuxSymbolRequirementGaps::default();
        for symbol in BASE_REQUIRED_SYMBOLS {
            if self.symbol_address(symbol).is_err() {
                gaps.missing_symbols.push((*symbol).to_owned());
            }
        }
        for requirements in requirements_for_features(features) {
            for type_name in requirements.required_types {
                if !self.user_types.contains_key(*type_name) {
                    gaps.missing_types.push((*type_name).to_owned());
                }
            }
            for alternatives in requirements.alternative_types {
                if !alternatives
                    .iter()
                    .any(|name| self.user_types.contains_key(*name))
                {
                    gaps.missing_types.push(alternatives.join("|"));
                }
            }
            for symbol in requirements.required_symbols {
                if self.symbol_address(symbol).is_err() {
                    gaps.missing_symbols.push((*symbol).to_owned());
                }
            }
            for alternatives in requirements.alternative_symbols {
                if !alternatives
                    .iter()
                    .any(|name| self.symbol_address(name).is_ok())
                {
                    gaps.missing_symbols.push(alternatives.join("|"));
                }
            }
            for field in requirements.required_fields {
                let present = field
                    .any_of
                    .iter()
                    .any(|name| self.field(field.type_name, name).ok().flatten().is_some());
                if !present {
                    gaps.missing_fields.push(field.display_name());
                }
            }
        }
        gaps.missing_types.sort();
        gaps.missing_types.dedup();
        gaps.missing_symbols.sort();
        gaps.missing_symbols.dedup();
        gaps.missing_fields.sort();
        gaps.missing_fields.dedup();
        gaps
    }

    pub fn symbol_address(&self, name: &str) -> Result<u64> {
        let address = self
            .symbols
            .get(name)
            .and_then(|symbol| symbol.address)
            .and_then(IsfInteger::nonnegative_u64)
            .with_context(|| format!("Volatility 3 ISF 缺少符号 {name}"))?;
        ensure!(address != 0, "Volatility 3 ISF 符号 {name} 地址为零");
        Ok(address)
    }

    pub fn type_size(&self, name: &str) -> Result<u64> {
        let size = self
            .user_types
            .get(name)
            .map(|kind| kind.size)
            .with_context(|| format!("Volatility 3 ISF 缺少类型 {name}"))?;
        u64::try_from(size).with_context(|| format!("Volatility 3 ISF 类型 {name} 大小无效"))
    }

    /// DWARF names anonymous global structures differently for every kernel build.
    pub fn symbol_type_name(&self, name: &str) -> Result<&str> {
        self.symbols
            .get(name)
            .and_then(|symbol| symbol.kind.as_ref())
            .and_then(|kind| kind.name.as_deref())
            .with_context(|| format!("ISF 符号 {name} 没有命名类型"))
    }

    pub(crate) fn symbol_struct_type(&self, name: &str) -> Result<&str> {
        self.symbols
            .get(name)
            .and_then(|symbol| symbol.kind.as_ref())
            .filter(|kind| kind.kind == "struct")
            .and_then(|kind| kind.name.as_deref())
            .with_context(|| format!("ISF 符号 {name} 不是命名结构"))
    }

    pub fn symbol_array_element_size(&self, name: &str) -> Result<u64> {
        let kind = self
            .symbols
            .get(name)
            .and_then(|symbol| symbol.kind.as_ref())
            .with_context(|| format!("ISF 符号 {name} 没有类型"))?;
        ensure!(kind.kind == "array", "ISF 符号 {name} 不是数组");
        self.type_ref_size(kind.subtype.as_deref().context("ISF 数组缺少元素类型")?)
    }

    pub(crate) fn symbol_array_struct_type(&self, name: &str) -> Result<&str> {
        let kind = self
            .symbols
            .get(name)
            .and_then(|symbol| symbol.kind.as_ref())
            .filter(|kind| kind.kind == "array")
            .context("ISF 符号不是数组")?;
        let element = kind
            .subtype
            .as_deref()
            .filter(|kind| kind.kind == "struct")
            .context("ISF 数组元素不是结构")?;
        element.name.as_deref().context("ISF 数组元素没有类型名")
    }

    pub fn symbol_array_count(&self, name: &str) -> Result<u64> {
        let kind = self
            .symbols
            .get(name)
            .and_then(|symbol| symbol.kind.as_ref())
            .with_context(|| format!("ISF 符号 {name} 没有数组类型"))?;
        ensure!(kind.kind == "array", "ISF 符号 {name} 不是数组");
        let count = kind
            .count
            .and_then(|count| u64::try_from(count).ok())
            .filter(|count| *count > 0)
            .with_context(|| format!("ISF 数组 {name} 缺少有效元素数"))?;
        Ok(count)
    }

    /// Scalar/atomic storage, excluding pointers, arrays and opaque function symbols.
    pub(crate) fn symbol_counter_layout(&self, name: &str) -> Result<(u64, u64)> {
        let kind = self
            .symbols
            .get(name)
            .and_then(|symbol| symbol.kind.as_ref())
            .with_context(|| format!("ISF 符号 {name} 没有类型"))?;
        self.counter_layout(kind)
    }

    pub(crate) fn symbol_array_counter_layout(&self, name: &str) -> Result<(u64, u64, u64)> {
        let kind = self
            .symbols
            .get(name)
            .and_then(|symbol| symbol.kind.as_ref())
            .filter(|kind| kind.kind == "array")
            .context("ISF 符号不是数组")?;
        let element = kind.subtype.as_deref().context("ISF 数组缺少元素类型")?;
        let (offset, width) = self.counter_layout(element)?;
        Ok((self.type_ref_size(element)?, offset, width))
    }

    fn counter_layout(&self, kind: &IsfTypeRef) -> Result<(u64, u64)> {
        if kind.kind == "base" {
            let width = self.type_ref_size(kind)?;
            ensure!(matches!(width, 4 | 8), "ISF 计数器宽度不是 4/8 字节");
            return Ok((0, width));
        }
        ensure!(kind.kind == "struct", "ISF 计数器不是标量或 atomic 结构");
        let name = kind.name.as_deref().context("ISF atomic 结构没有名称")?;
        let field = self
            .field(name, "counter")?
            .context("ISF atomic 结构缺少 counter")?;
        ensure!(field.kind.kind == "base", "ISF counter 不是标量");
        let width = self.type_ref_size(field.kind)?;
        ensure!(
            matches!(width, 4 | 8)
                && field
                    .offset
                    .checked_add(width)
                    .is_some_and(|end| self.type_ref_size(kind).is_ok_and(|size| end <= size)),
            "ISF counter 宽度无效或越出结构"
        );
        Ok((field.offset, width))
    }

    /// A zero array declaration still carries an element type; its extent must
    /// be justified separately, never inferred from an adjacent symbol.
    pub(crate) fn symbol_pointer_array_layout(&self, name: &str, target: &str) -> Result<u64> {
        let kind = self
            .symbols
            .get(name)
            .and_then(|symbol| symbol.kind.as_ref())
            .filter(|kind| kind.kind == "array")
            .context("ISF 符号不是数组")?;
        let element = kind.subtype.as_deref().context("ISF 数组缺少元素类型")?;
        ensure!(
            element.kind == "pointer"
                && element.subtype.as_deref().is_some_and(
                    |kind| kind.kind == "struct" && kind.name.as_deref() == Some(target)
                ),
            "ISF 数组元素不是指向 {target} 的指针"
        );
        u64::try_from(kind.count.context("ISF 数组没有 count 声明")?).context("ISF 数组长度为负")
    }

    pub fn field_offset(&self, type_name: &str, field_name: &str) -> Result<u64> {
        self.field(type_name, field_name)?
            .map(|field| field.offset)
            .with_context(|| format!("Volatility 3 ISF 缺少字段 {type_name}.{field_name}"))
    }

    pub fn optional_field_offset(&self, type_name: &str, field_name: &str) -> Result<Option<u64>> {
        Ok(self.field(type_name, field_name)?.map(|field| field.offset))
    }

    pub fn field_offset_any(&self, type_name: &str, field_names: &[&str]) -> Result<u64> {
        for field_name in field_names {
            if let Some(field) = self.field(type_name, field_name)? {
                return Ok(field.offset);
            }
        }
        bail!(
            "Volatility 3 ISF 缺少字段 {}.({})",
            type_name,
            field_names.join("|")
        )
    }

    pub fn optional_field_offset_any(
        &self,
        type_name: &str,
        field_names: &[&str],
    ) -> Result<Option<u64>> {
        for field_name in field_names {
            if let Some(field) = self.field(type_name, field_name)? {
                return Ok(Some(field.offset));
            }
        }
        Ok(None)
    }

    pub fn field_size(&self, type_name: &str, field_name: &str) -> Result<u64> {
        let field = self
            .field(type_name, field_name)?
            .with_context(|| format!("Volatility 3 ISF 缺少字段 {type_name}.{field_name}"))?;
        self.type_ref_size(field.kind)
            .with_context(|| format!("无法确定 {type_name}.{field_name} 的大小"))
    }

    pub(crate) fn field_scalar_layout(
        &self,
        type_name: &str,
        field_name: &str,
    ) -> Result<(u64, u64)> {
        let field = self
            .field(type_name, field_name)?
            .context("ISF 缺少标量字段")?;
        ensure!(
            field.kind.kind == "base",
            "ISF 字段 {type_name}.{field_name} 不是标量"
        );
        let width = self.type_ref_size(field.kind)?;
        ensure!(
            matches!(width, 4 | 8)
                && field
                    .offset
                    .checked_add(width)
                    .is_some_and(|end| self.type_size(type_name).is_ok_and(|size| end <= size)),
            "ISF 标量字段 {type_name}.{field_name} 宽度无效或越界"
        );
        Ok((field.offset, width))
    }

    pub(crate) fn field_pointer_scalar_layout(
        &self,
        type_name: &str,
        field_name: &str,
    ) -> Result<(u64, u64)> {
        let field = self
            .field(type_name, field_name)?
            .context("ISF 缺少指针字段")?;
        ensure!(
            field.kind.kind == "pointer" && self.type_ref_size(field.kind)? == 8,
            "ISF 字段 {type_name}.{field_name} 不是 64 位指针"
        );
        let target = field
            .kind
            .subtype
            .as_deref()
            .filter(|ty| ty.kind == "base")
            .context("ISF 指针目标不是标量")?;
        ensure!(
            field
                .offset
                .checked_add(8)
                .is_some_and(|end| self.type_size(type_name).is_ok_and(|size| end <= size)),
            "ISF 指针字段 {type_name}.{field_name} 越界"
        );
        Ok((field.offset, self.type_ref_size(target)?))
    }

    /// Return the storage bit range for a DWARF bitfield.  Ordinary integer
    /// fields return `None`; callers still use `field_size` for their width.
    pub fn field_bit_range(&self, type_name: &str, field_name: &str) -> Result<Option<(u8, u8)>> {
        let field = self
            .field(type_name, field_name)?
            .with_context(|| format!("Volatility 3 ISF 缺少字段 {type_name}.{field_name}"))?;
        if field.kind.kind != "bitfield" {
            return Ok(None);
        }
        let position = u8::try_from(
            field
                .kind
                .bit_position
                .context("Volatility 3 ISF bitfield 缺少 bit_position")?,
        )
        .context("Volatility 3 ISF bit_position 无效")?;
        let length = u8::try_from(
            field
                .kind
                .bit_length
                .context("Volatility 3 ISF bitfield 缺少 bit_length")?,
        )
        .context("Volatility 3 ISF bit_length 无效")?;
        ensure!(
            length > 0 && length <= 64,
            "Volatility 3 ISF bit_length 越界"
        );
        ensure!(
            u16::from(position) + u16::from(length) <= 64,
            "Volatility 3 ISF bitfield 位范围越界"
        );
        Ok(Some((position, length)))
    }

    pub fn field_size_any(&self, type_name: &str, field_names: &[&str]) -> Result<u64> {
        for field_name in field_names {
            if let Some(field) = self.field(type_name, field_name)? {
                return self
                    .type_ref_size(field.kind)
                    .with_context(|| format!("无法确定 {type_name}.{field_name} 的大小"));
            }
        }
        bail!(
            "Volatility 3 ISF 缺少字段 {}.({})",
            type_name,
            field_names.join("|")
        )
    }

    /// Distinguish pointer layouts using the exact ISF, including anonymous fields.
    pub fn field_pointer_target_type(&self, type_name: &str, field_name: &str) -> Result<&str> {
        let field = self
            .field(type_name, field_name)?
            .with_context(|| format!("Volatility 3 ISF 缺少字段 {type_name}.{field_name}"))?;
        ensure!(
            field.kind.kind == "pointer",
            "ISF 字段 {type_name}.{field_name} 不是指针"
        );
        let target = field
            .kind
            .subtype
            .as_deref()
            .context("ISF 指针缺少目标类型")?;
        ensure!(
            matches!(target.kind.as_str(), "struct" | "union"),
            "ISF 指针目标不是结构类型"
        );
        target.name.as_deref().context("ISF 指针目标没有类型名")
    }

    pub fn field_array_count(&self, type_name: &str, field_name: &str) -> Result<u64> {
        let field = self
            .field(type_name, field_name)?
            .with_context(|| format!("Volatility 3 ISF 缺少字段 {type_name}.{field_name}"))?;
        ensure!(
            field.kind.kind == "array",
            "Volatility 3 ISF 字段 {type_name}.{field_name} 不是数组"
        );
        let count = field.kind.count.with_context(|| {
            format!("Volatility 3 ISF 数组 {type_name}.{field_name} 缺少 count")
        })?;
        u64::try_from(count)
            .with_context(|| format!("Volatility 3 ISF 数组 {type_name}.{field_name} count 无效"))
    }

    pub(crate) fn field_array_struct_type(
        &self,
        type_name: &str,
        field_name: &str,
    ) -> Result<&str> {
        let field = self
            .field(type_name, field_name)?
            .context("ISF 缺少数组字段")?;
        ensure!(field.kind.kind == "array", "ISF 字段不是数组");
        field
            .kind
            .subtype
            .as_deref()
            .filter(|kind| kind.kind == "struct")
            .and_then(|kind| kind.name.as_deref())
            .context("ISF 数组元素不是命名结构")
    }

    pub fn enum_constant(&self, enum_name: &str, constant: &str) -> Result<u64> {
        let value = self
            .enums
            .get(enum_name)
            .and_then(|kind| kind.constants.get(constant))
            .copied()
            .with_context(|| format!("Volatility 3 ISF 缺少枚举常量 {enum_name}.{constant}"))?;
        u64::try_from(value)
            .with_context(|| format!("Volatility 3 ISF 枚举常量 {enum_name}.{constant} 为负数"))
    }

    fn field<'a>(&'a self, type_name: &str, field_name: &str) -> Result<Option<ResolvedField<'a>>> {
        let mut matches = Vec::new();
        let mut stack = HashSet::new();
        self.collect_fields(type_name, field_name, 0, &mut stack, &mut matches)?;
        matches.sort_unstable_by_key(|field| field.offset);
        matches.dedup_by_key(|field| field.offset);
        ensure!(
            matches.len() <= 1,
            "Volatility 3 ISF 字段 {type_name}.{field_name} 通过匿名结构解析到多个不同偏移"
        );
        Ok(matches.pop())
    }

    fn collect_fields<'a>(
        &'a self,
        type_name: &str,
        field_name: &str,
        base: u64,
        stack: &mut HashSet<String>,
        output: &mut Vec<ResolvedField<'a>>,
    ) -> Result<()> {
        if !stack.insert(type_name.to_owned()) {
            return Ok(());
        }
        let Some(kind) = self.user_types.get(type_name) else {
            stack.remove(type_name);
            return Ok(());
        };
        if let Some(field) = kind.fields.get(field_name) {
            let field_offset =
                u64::try_from(field.offset).context("Volatility 3 ISF 字段偏移为负数或过大")?;
            output.push(ResolvedField {
                offset: base
                    .checked_add(field_offset)
                    .context("Volatility 3 ISF 字段偏移溢出")?,
                kind: &field.kind,
            });
        }
        for field in kind.fields.values().filter(|field| field.anonymous) {
            let Some(nested_name) = field.kind.name.as_deref() else {
                continue;
            };
            let field_offset =
                u64::try_from(field.offset).context("Volatility 3 ISF 匿名字段偏移为负数或过大")?;
            let nested_base = base
                .checked_add(field_offset)
                .context("Volatility 3 ISF 匿名字段偏移溢出")?;
            self.collect_fields(nested_name, field_name, nested_base, stack, output)?;
        }
        stack.remove(type_name);
        Ok(())
    }

    fn type_ref_size(&self, kind: &IsfTypeRef) -> Result<u64> {
        match kind.kind.as_str() {
            "base" => self
                .base_types
                .get(kind.name.as_deref().unwrap_or_default())
                .map(|base| base.size)
                .context("ISF base type 不存在")
                .and_then(|size| u64::try_from(size).context("ISF base type 大小无效")),
            "struct" | "union" => self
                .user_types
                .get(kind.name.as_deref().unwrap_or_default())
                .map(|kind| kind.size)
                .context("ISF user type 不存在")
                .and_then(|size| u64::try_from(size).context("ISF user type 大小无效")),
            "enum" => self
                .enums
                .get(kind.name.as_deref().unwrap_or_default())
                .map(|kind| kind.size)
                .context("ISF enum 不存在")
                .and_then(|size| u64::try_from(size).context("ISF enum 大小无效")),
            "pointer" => Ok(8),
            "array" => {
                let count = u64::try_from(kind.count.context("ISF array 缺少 count")?)
                    .context("ISF array count 无效")?;
                let subtype = kind.subtype.as_deref().context("ISF array 缺少 subtype")?;
                self.type_ref_size(subtype)?
                    .checked_mul(count)
                    .context("ISF array 大小溢出")
            }
            "bitfield" => {
                let subtype = kind
                    .bitfield_type
                    .as_deref()
                    .or(kind.subtype.as_deref())
                    .context("ISF bitfield 缺少底层存储类型")?;
                self.type_ref_size(subtype)
            }
            other => bail!("不支持的 Volatility 3 ISF type kind：{other}"),
        }
    }

    fn equivalence_key(&self) -> String {
        let mut parts = vec![sha256_hex(self.banner.as_bytes())];
        parts.extend(self.vmlinux_sha256.iter().cloned());
        for symbol in retained_symbol_names(&self.features) {
            if let Ok(address) = self.symbol_address(symbol) {
                parts.push(format!("{symbol}={address:#x}"));
            }
        }
        let layout = format!(
            "{:?};{:?};{:?}",
            self.base_types, self.user_types, self.enums
        );
        parts.push(format!("layout_sha256={}", sha256_hex(layout.as_bytes())));
        parts.join(";")
    }

    #[cfg(test)]
    fn from_document(path: PathBuf, file_sha256: String, document: IsfDocument) -> Result<Self> {
        Self::from_document_with_features(path, file_sha256, document, legacy_features())
    }

    fn from_document_with_features(
        path: PathBuf,
        file_sha256: String,
        document: IsfDocument,
        features: BTreeSet<LinuxSymbolFeature>,
    ) -> Result<Self> {
        let format = document.metadata.format.clone();
        ensure!(!format.is_empty(), "Volatility 3 ISF metadata.format 为空");
        let major = format.split('.').next().unwrap_or_default();
        ensure!(
            matches!(major, "5" | "6"),
            "不支持的 Volatility 3 ISF 格式 {format}"
        );

        let banner_symbol = document
            .symbols
            .get("linux_banner")
            .context("ISF 缺少 linux_banner 符号")?;
        let constant_data = banner_symbol
            .constant_data
            .as_deref()
            .context("ISF linux_banner 缺少 constant_data")?;
        let banner_bytes = BASE64_STANDARD
            .decode(constant_data)
            .context("ISF linux_banner.constant_data 不是有效 base64")?;
        let banner_end = banner_bytes
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(banner_bytes.len());
        let banner = std::str::from_utf8(&banner_bytes[..banner_end])
            .context("ISF linux_banner 不是 UTF-8")?
            .trim_end()
            .to_owned();
        ensure!(
            banner.starts_with("Linux version "),
            "ISF linux_banner.constant_data 不是 Linux version banner"
        );

        let producer = document.metadata.producer.as_ref().map(|producer| {
            if producer.version.is_empty() {
                producer.name.clone()
            } else {
                format!("{} {}", producer.name, producer.version)
            }
        });
        let mut vmlinux_sha256 = document
            .metadata
            .linux
            .iter()
            .flat_map(|linux| linux.symbols.iter().chain(linux.types.iter()))
            .filter(|artifact| artifact.hash_type.eq_ignore_ascii_case("sha256"))
            .map(|artifact| artifact.hash_value.to_ascii_lowercase())
            .filter(|hash| hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .collect::<Vec<_>>();
        vmlinux_sha256.sort();
        vmlinux_sha256.dedup();

        let mut retained_names = BTreeSet::new();
        for root in retained_type_names(&features) {
            collect_anonymous_types(&document.user_types, root, &mut retained_names);
        }
        let retained_symbols = retained_symbol_names(&features);
        if features.contains(&LinuxSymbolFeature::IncidentResponse) {
            for (name, symbol) in &document.symbols {
                if retained_symbols.contains(name.as_str())
                    && let Some(kind) = symbol
                        .kind
                        .as_ref()
                        .filter(|kind| matches!(kind.kind.as_str(), "struct" | "union"))
                    && let Some(name) = kind.name.as_deref()
                {
                    collect_anonymous_types(&document.user_types, name, &mut retained_names);
                }
            }
        }
        let user_types = document
            .user_types
            .into_iter()
            .filter(|(name, _)| retained_names.contains(name))
            .collect::<BTreeMap<_, _>>();
        let symbols = document
            .symbols
            .into_iter()
            .filter(|(name, _)| retained_symbols.contains(name.as_str()))
            .collect::<BTreeMap<_, _>>();
        let mut enums = BTreeMap::new();
        if let Some(pageflags) = document.enums.get("pageflags") {
            enums.insert("pageflags".to_owned(), pageflags.clone());
        }
        if features.contains(&LinuxSymbolFeature::IncidentResponse) {
            for name in [
                "zone_stat_item",
                "node_stat_item",
                "node_states",
                "zone_watermarks",
                "zone_type",
            ] {
                if let Some(kind) = document.enums.get(name) {
                    enums.insert(name.to_owned(), kind.clone());
                }
            }
        }
        for user_type in user_types.values() {
            for field in user_type.fields.values() {
                retain_referenced_enum(&document.enums, &field.kind, &mut enums);
            }
        }

        ensure!(
            document
                .base_types
                .get("long unsigned int")
                .is_some_and(|kind| kind.size == 8),
            "StarMem Linux ISF 当前仅支持 64 位小端内核"
        );
        let banner_sha256 = sha256_hex(banner.as_bytes());
        let vmlinux_label = if vmlinux_sha256.is_empty() {
            "unknown".to_owned()
        } else {
            vmlinux_sha256.join(",")
        };
        let fingerprint = format!(
            "Volatility 3 ISF; format={format}; producer={}; path={}; file_sha256={file_sha256}; banner_sha256={banner_sha256}; vmlinux_sha256={vmlinux_label}",
            producer.as_deref().unwrap_or("unknown"),
            path.display()
        );
        Ok(Self {
            path,
            format,
            producer,
            banner,
            file_sha256,
            vmlinux_sha256,
            base_types: document.base_types,
            user_types,
            enums,
            symbols,
            features,
            fingerprint,
        })
    }
}

#[derive(Debug)]
struct ResolvedField<'a> {
    offset: u64,
    kind: &'a IsfTypeRef,
}

#[derive(Debug)]
pub struct LinuxIsfResolution {
    pub table: Option<Arc<LinuxIsf>>,
    pub warnings: Vec<LinuxIsfWarning>,
    pub files_considered: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxIsfWarning {
    pub kind: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxSymbolDiagnosticOptions {
    #[serde(default)]
    pub features: BTreeSet<LinuxSymbolFeature>,
    pub isf: Option<PathBuf>,
    #[serde(default)]
    pub install: bool,
    #[serde(default)]
    pub fetch: bool,
    #[serde(default)]
    pub offline: bool,
    #[serde(default)]
    pub refresh_index: bool,
}

impl Default for LinuxSymbolDiagnosticOptions {
    fn default() -> Self {
        Self {
            features: legacy_features(),
            isf: None,
            install: false,
            fetch: false,
            offline: false,
            refresh_index: false,
        }
    }
}

impl LinuxSymbolDiagnosticOptions {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.install || self.isf.is_some(),
            "--install 必须与 --isf FILE_OR_ARCHIVE 一起使用"
        );
        ensure!(
            !(self.fetch && self.offline),
            "--fetch 与 --offline 不能同时使用"
        );
        ensure!(
            !(self.refresh_index && self.offline),
            "--refresh-index 与 --offline 不能同时使用"
        );
        Ok(())
    }

    fn normalized_features(&self) -> BTreeSet<LinuxSymbolFeature> {
        normalize_features(self.features.iter().copied())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinuxSymbolCandidateStatus {
    Selected,
    Rejected,
    Ambiguous,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinuxSymbolSelectionStatus {
    Selected,
    NoMatch,
    Ambiguous,
    RuntimeRejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinuxSymbolRuntimeValidationStatus {
    NotPerformed,
    Passed,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxSymbolRuntimeCheck {
    pub name: String,
    pub passed: Option<bool>,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxSymbolRuntimeValidation {
    pub status: LinuxSymbolRuntimeValidationStatus,
    pub checks: Vec<LinuxSymbolRuntimeCheck>,
}

impl LinuxSymbolRuntimeValidation {
    pub fn not_performed(message: impl Into<String>) -> Self {
        Self {
            status: LinuxSymbolRuntimeValidationStatus::NotPerformed,
            checks: vec![LinuxSymbolRuntimeCheck {
                name: "runtime_validation".to_owned(),
                passed: None,
                message: message.into(),
            }],
        }
    }

    pub fn passed(checks: Vec<LinuxSymbolRuntimeCheck>) -> Self {
        Self {
            status: LinuxSymbolRuntimeValidationStatus::Passed,
            checks,
        }
    }

    pub fn failed(checks: Vec<LinuxSymbolRuntimeCheck>) -> Self {
        Self {
            status: LinuxSymbolRuntimeValidationStatus::Failed,
            checks,
        }
    }
}

/// Image-aware validation is supplied by `LinuxKernelSession` during future CLI wiring.
pub trait LinuxSymbolRuntimeValidator {
    fn validate(&self, table: &LinuxIsf) -> Result<LinuxSymbolRuntimeValidation>;
}

impl<F> LinuxSymbolRuntimeValidator for F
where
    F: Fn(&LinuxIsf) -> Result<LinuxSymbolRuntimeValidation>,
{
    fn validate(&self, table: &LinuxIsf) -> Result<LinuxSymbolRuntimeValidation> {
        self(table)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxSymbolDiagnosticReason {
    pub code: String,
    pub message: String,
}

impl LinuxSymbolDiagnosticReason {
    fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxSymbolCandidateDiagnostic {
    pub path: String,
    pub status: LinuxSymbolCandidateStatus,
    pub exact_banner_match: Option<bool>,
    pub identity: Option<LinuxSymbolIdentity>,
    pub rejection_reasons: Vec<LinuxSymbolDiagnosticReason>,
    pub missing: LinuxSymbolRequirementGaps,
    pub runtime_validation: LinuxSymbolRuntimeValidation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxSymbolDiagnosticEffects {
    pub install_requested: bool,
    pub fetch_requested: bool,
    pub refresh_index_requested: bool,
    pub offline: bool,
    pub network_accessed: bool,
    pub cache_written: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxSymbolDiagnosticReport {
    pub available: bool,
    pub complete: bool,
    pub selection: LinuxSymbolSelectionStatus,
    pub requested_features: Vec<LinuxSymbolFeature>,
    pub files_considered: usize,
    pub selected_identity: Option<LinuxSymbolIdentity>,
    pub candidates: Vec<LinuxSymbolCandidateDiagnostic>,
    pub warnings: Vec<LinuxIsfWarning>,
    pub effects: LinuxSymbolDiagnosticEffects,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxIsfInstallReport {
    pub source: String,
    pub destination: String,
    pub installed: bool,
    pub identity: LinuxSymbolIdentity,
}

pub fn install_linux_isf(
    store: &SymbolStore,
    image_path: &Path,
    image_banners: &[String],
    source: &Path,
    features: impl IntoIterator<Item = LinuxSymbolFeature>,
    force: bool,
) -> Result<LinuxIsfInstallReport> {
    let image_sidecars = [
        image_path.with_extension("vmss"),
        image_path.with_extension("vmsn"),
    ]
    .into_iter()
    .filter(|path| path.is_file())
    .collect::<Vec<_>>();
    let mut protected_inputs = vec![image_path];
    protected_inputs.extend(image_sidecars.iter().map(PathBuf::as_path));
    install_linux_isf_protecting(
        store,
        &protected_inputs,
        image_banners,
        source,
        features,
        force,
    )
}

/// Install an explicit ISF while protecting every source selected by the decoded image,
/// including an explicitly selected VMware metadata file whose stem differs from the VMEM.
pub fn install_linux_isf_for_image(
    store: &SymbolStore,
    image: &MemoryImage,
    image_banners: &[String],
    source: &Path,
    features: impl IntoIterator<Item = LinuxSymbolFeature>,
    force: bool,
) -> Result<LinuxIsfInstallReport> {
    let protected_inputs = image
        .sources()
        .map(|source| source.path.as_path())
        .collect::<Vec<_>>();
    install_linux_isf_protecting(
        store,
        &protected_inputs,
        image_banners,
        source,
        features,
        force,
    )
}

fn install_linux_isf_protecting(
    store: &SymbolStore,
    protected_image_inputs: &[&Path],
    image_banners: &[String],
    source: &Path,
    features: impl IntoIterator<Item = LinuxSymbolFeature>,
    force: bool,
) -> Result<LinuxIsfInstallReport> {
    let features = normalize_features(features);
    let table = load_linux_isf_for_features(source, features.iter().copied())?;
    ensure!(
        image_banners.iter().any(|banner| banner == table.banner()),
        "待安装 ISF 的完整 linux_banner 与镜像不匹配"
    );
    let missing = table.requirement_gaps_for(&features);
    ensure!(
        missing.is_empty(),
        "待安装 ISF 缺少请求 feature 的类型/符号/字段：{:?}",
        missing
    );
    let identity = table.identity()?;
    let lower_name = source
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let suffix = if lower_name.ends_with(".json.xz") {
        ".json.xz"
    } else {
        ".json"
    };
    let destination = store
        .writable_root()
        .join("linux")
        .join("installed")
        .join(format!("{}{suffix}", table.file_sha256()));
    if let Ok(existing) = load_linux_isf_for_features(&destination, features.iter().copied())
        && existing.file_sha256() == table.file_sha256()
    {
        return Ok(LinuxIsfInstallReport {
            source: source.display().to_string(),
            destination: destination.display().to_string(),
            installed: false,
            identity,
        });
    }
    let mut policy = OutputPolicy::new(force);
    for image_input in protected_image_inputs {
        policy.protect_file("memory_image_or_sidecar", *image_input);
    }
    policy.protect_file("isf_source", source);
    policy.output(OutputTarget::file("linux_isf_cache", &destination));
    policy.preflight()?;
    policy.write_file_atomic_validated(
        &destination,
        |output| {
            let mut input = File::open(source)
                .with_context(|| format!("无法重新打开待安装 ISF {}", source.display()))?;
            copy(&mut input, output)?;
            Ok(())
        },
        |staged| {
            let staged =
                load_linux_isf_from_storage(staged, &destination, features.iter().copied())?;
            ensure!(
                staged.file_sha256() == table.file_sha256(),
                "待安装 ISF 在解析与发布之间已变化"
            );
            Ok(())
        },
    )?;
    let installed = load_linux_isf_for_features(&destination, features.iter().copied())?;
    ensure!(
        installed.file_sha256() == table.file_sha256(),
        "安装后 ISF 哈希复验失败"
    );
    Ok(LinuxIsfInstallReport {
        source: source.display().to_string(),
        destination: destination.display().to_string(),
        installed: true,
        identity,
    })
}

/// Diagnose local ISF candidates only. This function never performs network access or cache writes,
/// even when future-facing action flags are present in `options`.
pub fn diagnose_local_linux_symbols(
    store: &SymbolStore,
    image_banners: &[String],
    options: &LinuxSymbolDiagnosticOptions,
    runtime_validator: Option<&dyn LinuxSymbolRuntimeValidator>,
) -> Result<LinuxSymbolDiagnosticReport> {
    options.validate()?;
    ensure!(
        !image_banners.is_empty(),
        "symbols linux 诊断缺少镜像 Linux banner"
    );
    let features = options.normalized_features();
    let mut warnings = Vec::new();
    let mut discovery_complete = true;
    let mut paths = Vec::new();
    let mut seen_paths = HashSet::new();

    if let Some(explicit) = options.isf.as_deref() {
        let mut explicit_paths = Vec::new();
        if explicit.is_file() {
            explicit_paths.push(explicit.to_path_buf());
        } else if explicit.is_dir() {
            if let Err(error) = collect_isf_paths(explicit, &mut explicit_paths) {
                discovery_complete = false;
                push_warning(
                    &mut warnings,
                    "linux_isf_explicit_discovery",
                    format!("无法枚举显式 ISF 路径 {}：{error:#}", explicit.display()),
                );
            }
        } else {
            explicit_paths.push(explicit.to_path_buf());
        }
        explicit_paths.sort();
        for path in explicit_paths {
            let identity_path = fs::canonicalize(&path).unwrap_or_else(|_| path.clone());
            if seen_paths.insert(identity_path) {
                paths.push(path);
            }
        }
    }

    for root in linux_symbol_roots(store) {
        let mut root_paths = Vec::new();
        if let Err(error) = collect_isf_paths(&root, &mut root_paths) {
            discovery_complete = false;
            push_warning(
                &mut warnings,
                "linux_isf_discovery",
                format!("无法枚举 Linux ISF 根目录 {}：{error:#}", root.display()),
            );
        }
        root_paths.sort();
        for path in root_paths {
            let identity_path = fs::canonicalize(&path).unwrap_or_else(|_| path.clone());
            if seen_paths.insert(identity_path) {
                paths.push(path);
            }
        }
    }
    paths.sort();
    ensure!(
        paths.len() <= MAX_ISF_FILES,
        "Linux ISF 候选超过安全上限 {MAX_ISF_FILES}"
    );

    let requested_actions = options.install || options.fetch || options.refresh_index;
    if requested_actions {
        discovery_complete = false;
        push_warning(
            &mut warnings,
            "linux_symbol_actions_not_performed",
            "本地纯诊断 API 不执行 install/fetch/refresh-index；应由显式 CLI action handler 在通过输出策略后执行"
                .to_owned(),
        );
    }

    let banner_set = image_banners
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();
    let mut candidates = Vec::with_capacity(paths.len());
    let mut eligible = Vec::new();
    for path in paths {
        let path_display = path.display().to_string();
        let table = match load_linux_isf_for_features(&path, features.iter().copied()) {
            Ok(table) => table,
            Err(error) => {
                discovery_complete = false;
                candidates.push(LinuxSymbolCandidateDiagnostic {
                    path: path_display,
                    status: LinuxSymbolCandidateStatus::Rejected,
                    exact_banner_match: None,
                    identity: None,
                    rejection_reasons: vec![LinuxSymbolDiagnosticReason::new(
                        "linux_isf_invalid",
                        format!("ISF 解析失败：{error:#}"),
                    )],
                    missing: LinuxSymbolRequirementGaps::default(),
                    runtime_validation: LinuxSymbolRuntimeValidation::not_performed(
                        "候选未通过静态解析",
                    ),
                });
                continue;
            }
        };
        let exact_banner_match = banner_set.contains(table.banner());
        let identity = table.identity()?;
        let missing = table.requirement_gaps_for(&features);
        let mut rejection_reasons = Vec::new();
        if !exact_banner_match {
            rejection_reasons.push(LinuxSymbolDiagnosticReason::new(
                "linux_isf_banner_mismatch",
                "linux_banner.constant_data 与镜像完整 banner 不同",
            ));
        }
        if !missing.is_empty() {
            rejection_reasons.push(LinuxSymbolDiagnosticReason::new(
                "linux_isf_requirements_missing",
                "候选缺少请求 feature 所需的类型、符号或字段",
            ));
        }
        let report_index = candidates.len();
        candidates.push(LinuxSymbolCandidateDiagnostic {
            path: path_display,
            status: LinuxSymbolCandidateStatus::Rejected,
            exact_banner_match: Some(exact_banner_match),
            identity: Some(identity),
            rejection_reasons,
            missing,
            runtime_validation: LinuxSymbolRuntimeValidation::not_performed(
                "候选尚未进入运行时验证",
            ),
        });
        if exact_banner_match && candidates[report_index].missing.is_empty() {
            eligible.push((report_index, table));
        }
    }

    let mut groups = BTreeMap::<String, Vec<(usize, LinuxIsf)>>::new();
    for (index, table) in eligible {
        groups
            .entry(table.equivalence_key())
            .or_default()
            .push((index, table));
    }

    let mut selection = LinuxSymbolSelectionStatus::NoMatch;
    let mut selected_identity = None;
    let mut runtime_passed = false;
    if groups.len() > 1 {
        selection = LinuxSymbolSelectionStatus::Ambiguous;
        for group in groups.values() {
            for (index, _) in group {
                candidates[*index].status = LinuxSymbolCandidateStatus::Ambiguous;
                candidates[*index]
                    .rejection_reasons
                    .push(LinuxSymbolDiagnosticReason::new(
                        "linux_isf_ambiguous",
                        "多个精确 banner 候选具有不同的符号或布局身份",
                    ));
                candidates[*index].runtime_validation =
                    LinuxSymbolRuntimeValidation::not_performed("候选身份存在歧义");
            }
        }
        push_warning(
            &mut warnings,
            "linux_isf_ambiguous",
            "多个精确 banner 候选不等价；拒绝自动选择".to_owned(),
        );
    } else if let Some((_, mut group)) = groups.into_iter().next() {
        group.sort_by(|left, right| candidates[left.0].path.cmp(&candidates[right.0].path));
        let (selected_index, selected_table) = group.remove(0);
        for (duplicate_index, _) in group {
            candidates[duplicate_index]
                .rejection_reasons
                .push(LinuxSymbolDiagnosticReason::new(
                    "linux_isf_equivalent_duplicate",
                    "候选与已选择 ISF 等价，但优先级较低",
                ));
        }
        let runtime = match runtime_validator {
            Some(validator) => validator.validate(&selected_table).unwrap_or_else(|error| {
                LinuxSymbolRuntimeValidation::failed(vec![LinuxSymbolRuntimeCheck {
                    name: "runtime_validation".to_owned(),
                    passed: Some(false),
                    message: format!("运行时验证失败：{error:#}"),
                }])
            }),
            None => LinuxSymbolRuntimeValidation::not_performed(
                "未提供 LinuxKernelSession 运行时验证器",
            ),
        };
        runtime_passed = runtime.status == LinuxSymbolRuntimeValidationStatus::Passed;
        candidates[selected_index].runtime_validation = runtime;
        if candidates[selected_index].runtime_validation.status
            == LinuxSymbolRuntimeValidationStatus::Failed
        {
            selection = LinuxSymbolSelectionStatus::RuntimeRejected;
            candidates[selected_index].status = LinuxSymbolCandidateStatus::Rejected;
            candidates[selected_index]
                .rejection_reasons
                .push(LinuxSymbolDiagnosticReason::new(
                    "linux_isf_runtime_validation_failed",
                    "候选未通过镜像运行时验证",
                ));
        } else {
            selection = LinuxSymbolSelectionStatus::Selected;
            candidates[selected_index].status = LinuxSymbolCandidateStatus::Selected;
            selected_identity = candidates[selected_index].identity.clone();
            if !runtime_passed {
                push_warning(
                    &mut warnings,
                    "linux_isf_runtime_not_validated",
                    "已选择精确 banner 候选，但尚未验证 slide、运行时 banner、页表和内核对象"
                        .to_owned(),
                );
            }
        }
    } else {
        push_warning(
            &mut warnings,
            "linux_isf_no_usable_candidate",
            "本地候选中没有同时满足完整 banner 和 feature 需求的 ISF".to_owned(),
        );
    }

    let available = selected_identity.is_some();
    let complete = available && discovery_complete && runtime_passed;
    Ok(LinuxSymbolDiagnosticReport {
        available,
        complete,
        selection,
        requested_features: features.into_iter().collect(),
        files_considered: candidates.len(),
        selected_identity,
        candidates,
        warnings,
        effects: LinuxSymbolDiagnosticEffects {
            install_requested: options.install,
            fetch_requested: options.fetch,
            refresh_index_requested: options.refresh_index,
            offline: options.offline,
            network_accessed: false,
            cache_written: false,
        },
    })
}

pub(crate) fn resolve_linux_isf(
    store: &SymbolStore,
    image_banners: &[String],
) -> Result<LinuxIsfResolution> {
    resolve_linux_isf_for_features(store, image_banners, legacy_features())
}

pub fn resolve_linux_isf_for_features(
    store: &SymbolStore,
    image_banners: &[String],
    features: impl IntoIterator<Item = LinuxSymbolFeature>,
) -> Result<LinuxIsfResolution> {
    let features = normalize_features(features);
    let roots = linux_symbol_roots(store);
    let mut paths = Vec::new();
    let mut seen_paths = HashSet::new();
    let mut warnings = Vec::new();
    for root in roots {
        let mut root_paths = Vec::new();
        if let Err(error) = collect_isf_paths(&root, &mut root_paths) {
            push_warning(
                &mut warnings,
                "linux_isf_discovery",
                format!("无法枚举 Linux ISF 根目录 {}：{error:#}", root.display()),
            );
        }
        root_paths.sort();
        for path in root_paths {
            if seen_paths.insert(path.clone()) {
                paths.push(path);
            }
        }
    }
    ensure!(
        paths.len() <= MAX_ISF_FILES,
        "Linux ISF 候选超过安全上限 {MAX_ISF_FILES}"
    );
    let files_considered = paths.len();
    let banners = image_banners
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();
    let mut selected: Option<LinuxIsf> = None;
    for path in paths {
        let table = match load_linux_isf_for_features(&path, features.iter().copied()) {
            Ok(table) => table,
            Err(error) => {
                push_warning(
                    &mut warnings,
                    "linux_isf_invalid",
                    format!(
                        "忽略无法解析的 Volatility 3 ISF {}：{error:#}",
                        path.display()
                    ),
                );
                continue;
            }
        };
        if !banners.contains(table.banner()) {
            continue;
        }
        if let Some(existing) = &selected {
            ensure!(
                existing.equivalence_key() == table.equivalence_key(),
                "多个 Volatility 3 ISF 的 linux_banner 都与镜像精确匹配，但 vmlinux 身份或关键布局不一致：{} 与 {}",
                existing.path().display(),
                table.path().display()
            );
            continue;
        }
        selected = Some(table);
    }
    if selected.is_none() && files_considered > 0 {
        let releases = image_banners
            .iter()
            .filter_map(|banner| {
                banner
                    .strip_prefix("Linux version ")?
                    .split_ascii_whitespace()
                    .next()
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
            .join(", ");
        push_warning(
            &mut warnings,
            "linux_isf_no_exact_banner",
            format!(
                "检查了 {files_considered} 个 Volatility 3 ISF，但没有 linux_banner.constant_data 与镜像完整 banner 精确相同的表（镜像 release：{releases}）；未按文件名或相似版本降级匹配"
            ),
        );
    }
    Ok(LinuxIsfResolution {
        table: selected.map(Arc::new),
        warnings,
        files_considered,
    })
}

/// Resolve an exact Linux ISF from a Volatility-compatible remote banner
/// index.  Callers invoke this only after all local symbol roots and exact
/// embedded layouts have missed.  Network and cache failures are evidence
/// warnings rather than proof that no matching symbol table exists.
pub fn resolve_remote_linux_isf(
    store: &SymbolStore,
    image_banners: &[String],
) -> Result<LinuxIsfResolution> {
    let Some(source) = remote_source_from_environment() else {
        return Ok(LinuxIsfResolution {
            table: None,
            warnings: vec![LinuxIsfWarning {
                kind: "linux_isf_remote_disabled".to_owned(),
                message:
                    "Linux 远程 ISF 兜底已由 STARMEM_LINUX_ISF_OFFLINE/STARMEM_LINUX_ISF_URL 禁用"
                        .to_owned(),
            }],
            files_considered: 0,
        });
    };
    match resolve_remote_linux_isf_from_source(store, image_banners, &source) {
        Ok(resolution) => Ok(resolution),
        Err(error) => Ok(LinuxIsfResolution {
            table: None,
            warnings: vec![LinuxIsfWarning {
                kind: "linux_isf_remote_unavailable".to_owned(),
                message: format!(
                    "Linux 远程 ISF 兜底不可用（索引 {}）：{error:#}；这不表示远程仓库中不存在匹配符号",
                    source.index_url
                ),
            }],
            files_considered: 0,
        }),
    }
}

/// Force the next remote resolution to obtain a fresh index.
///
/// The prior cache is retained until a fetched and parsed replacement is atomically published;
/// refresh failures therefore cannot destroy the last usable index.
pub fn refresh_remote_linux_isf(
    store: &SymbolStore,
    image_banners: &[String],
) -> Result<LinuxIsfResolution> {
    let Some(source) = remote_source_from_environment() else {
        bail!("远程 Linux ISF 已由环境策略禁用");
    };
    resolve_remote_linux_isf_from_source_with_refresh(store, image_banners, &source, true)
}

#[derive(Debug, Clone)]
struct RemoteIsfSource {
    index_url: String,
    default_repository: bool,
    allow_loopback_http: bool,
}

#[derive(Debug, Deserialize)]
struct RemoteIsfIndex {
    version: u64,
    #[serde(default)]
    linux: BTreeMap<String, Vec<String>>,
}

fn remote_source_from_environment() -> Option<RemoteIsfSource> {
    if env_flag("STARMEM_LINUX_ISF_OFFLINE") {
        return None;
    }
    match env::var("STARMEM_LINUX_ISF_URL") {
        Ok(value)
            if matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "0" | "false" | "off" | "none"
            ) =>
        {
            None
        }
        Ok(value) if !value.trim().is_empty() => Some(RemoteIsfSource {
            index_url: value.trim().to_owned(),
            default_repository: false,
            allow_loopback_http: false,
        }),
        _ => Some(RemoteIsfSource {
            index_url: DEFAULT_REMOTE_ISF_INDEX.to_owned(),
            default_repository: true,
            allow_loopback_http: false,
        }),
    }
}

fn env_flag(name: &str) -> bool {
    env::var(name).is_ok_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

fn resolve_remote_linux_isf_from_source(
    store: &SymbolStore,
    image_banners: &[String],
    source: &RemoteIsfSource,
) -> Result<LinuxIsfResolution> {
    resolve_remote_linux_isf_from_source_with_refresh(store, image_banners, source, false)
}

fn resolve_remote_linux_isf_from_source_with_refresh(
    store: &SymbolStore,
    image_banners: &[String],
    source: &RemoteIsfSource,
    force_index_refresh: bool,
) -> Result<LinuxIsfResolution> {
    let client = Client::builder()
        .user_agent(concat!("starmem/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(180))
        .redirect(Policy::limited(5))
        .build()
        .context("无法初始化 Linux ISF 下载客户端")?;
    let mut warnings = Vec::new();
    let index = load_remote_isf_index(&client, store, source, &mut warnings, force_index_refresh)?;
    let candidate_urls = remote_urls_for_banners(&index, image_banners)?;
    let files_considered = candidate_urls.len();
    if candidate_urls.is_empty() {
        let releases = image_banners
            .iter()
            .filter_map(|banner| {
                banner
                    .strip_prefix("Linux version ")?
                    .split_ascii_whitespace()
                    .next()
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
            .join(", ");
        push_warning(
            &mut warnings,
            "linux_isf_remote_no_exact_banner",
            format!(
                "远程 Volatility 3 ISF 索引 {} 中没有与镜像完整 banner 精确匹配的条目（release：{releases}）；未执行模糊版本下载",
                source.index_url
            ),
        );
        return Ok(LinuxIsfResolution {
            table: None,
            warnings,
            files_considered,
        });
    }

    let banners = image_banners
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();
    let mut selected: Option<(LinuxIsf, String, bool)> = None;
    for candidate_url in candidate_urls {
        let result = download_remote_isf(&client, store, source, &candidate_url, &banners);
        let (table, downloaded) = match result {
            Ok(value) => value,
            Err(error) => {
                push_warning(
                    &mut warnings,
                    "linux_isf_remote_candidate_invalid",
                    format!("忽略远程 Linux ISF {candidate_url}：{error:#}"),
                );
                continue;
            }
        };
        if let Some((existing, existing_url, _)) = &selected {
            ensure!(
                existing.equivalence_key() == table.equivalence_key(),
                "远程索引为同一完整 linux_banner 返回了不等价的 ISF：{existing_url} 与 {candidate_url}"
            );
            continue;
        }
        selected = Some((table, candidate_url, downloaded));
    }

    let table = selected.map(|(table, url, downloaded)| {
        push_warning(
            &mut warnings,
            if downloaded {
                "linux_isf_remote_downloaded"
            } else {
                "linux_isf_remote_cached"
            },
            format!(
                "{}远程 Volatility 3 Linux ISF：{url} -> {}（file_sha256={}）；仍须通过 init_task slide、运行时 linux_banner、页表和任务链现场验证",
                if downloaded { "已下载并缓存" } else { "已复用缓存的" },
                table.path().display(),
                table.file_sha256()
            ),
        );
        Arc::new(table)
    });
    if table.is_none() {
        push_warning(
            &mut warnings,
            "linux_isf_remote_candidates_rejected",
            "远程索引存在精确 banner 条目，但所有下载候选均未通过 ISF 解析和完整 banner 复验"
                .to_owned(),
        );
    }
    Ok(LinuxIsfResolution {
        table,
        warnings,
        files_considered,
    })
}

fn load_remote_isf_index(
    client: &Client,
    store: &SymbolStore,
    source: &RemoteIsfSource,
    warnings: &mut Vec<LinuxIsfWarning>,
    force_refresh: bool,
) -> Result<RemoteIsfIndex> {
    let cache_path = remote_index_cache_path(store, &source.index_url);
    if !force_refresh
        && cache_is_fresh(&cache_path)
        && let Ok(index) = read_remote_isf_index(&cache_path)
    {
        return Ok(index);
    }

    let fetched = fetch_bounded_bytes(
        client,
        source,
        &source.index_url,
        RemoteRequestKind::Index,
        MAX_REMOTE_INDEX_BYTES,
    )
    .and_then(|bytes| parse_remote_isf_index(&bytes).map(|index| (bytes, index)));
    match fetched {
        Ok((bytes, index)) => {
            if let Err(error) = persist_atomic(&cache_path, &bytes) {
                push_warning(
                    warnings,
                    "linux_isf_remote_index_cache_failed",
                    format!(
                        "远程 ISF 索引已获取但无法缓存到 {}：{error:#}",
                        cache_path.display()
                    ),
                );
            }
            Ok(index)
        }
        Err(download_error) => match read_remote_isf_index(&cache_path) {
            Ok(index) => {
                push_warning(
                    warnings,
                    "linux_isf_remote_stale_index",
                    format!(
                        "远程 ISF 索引刷新失败，改用缓存 {}：{download_error:#}",
                        cache_path.display()
                    ),
                );
                Ok(index)
            }
            Err(cache_error) => {
                bail!("索引下载失败：{download_error:#}；本地索引缓存也不可用：{cache_error:#}")
            }
        },
    }
}

fn remote_index_cache_path(store: &SymbolStore, index_url: &str) -> PathBuf {
    store
        .writable_root()
        .join(".linux-isf-remote")
        .join(sha256_hex(index_url.as_bytes()))
        .join("banners.json")
}

fn cache_is_fresh(path: &Path) -> bool {
    fs::metadata(path)
        .and_then(|metadata| metadata.modified())
        .ok()
        .and_then(|modified| modified.elapsed().ok())
        .is_some_and(|age| age <= REMOTE_INDEX_TTL)
}

fn read_remote_isf_index(path: &Path) -> Result<RemoteIsfIndex> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("无法读取远程 ISF 索引缓存元数据 {}", path.display()))?;
    ensure!(
        metadata.len() <= MAX_REMOTE_INDEX_BYTES,
        "远程 ISF 索引缓存超过 {} MiB 安全上限",
        MAX_REMOTE_INDEX_BYTES / 1024 / 1024
    );
    let bytes =
        fs::read(path).with_context(|| format!("无法读取远程 ISF 索引缓存 {}", path.display()))?;
    parse_remote_isf_index(&bytes)
}

fn parse_remote_isf_index(bytes: &[u8]) -> Result<RemoteIsfIndex> {
    ensure!(
        bytes.len() as u64 <= MAX_REMOTE_INDEX_BYTES,
        "远程 ISF 索引超过 {} MiB 安全上限",
        MAX_REMOTE_INDEX_BYTES / 1024 / 1024
    );
    let index: RemoteIsfIndex = serde_json::from_slice(bytes).context("远程 ISF 索引 JSON 无效")?;
    ensure!(
        index.version == 1,
        "不支持的远程 ISF 索引版本 {}",
        index.version
    );
    ensure!(
        index.linux.len() <= MAX_REMOTE_INDEX_ENTRIES,
        "远程 ISF 索引条目超过安全上限 {MAX_REMOTE_INDEX_ENTRIES}"
    );
    Ok(index)
}

fn remote_urls_for_banners(
    index: &RemoteIsfIndex,
    image_banners: &[String],
) -> Result<Vec<String>> {
    let banners = image_banners
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();
    let mut urls = BTreeSet::new();
    for (encoded_banner, candidates) in &index.linux {
        let Ok(bytes) = BASE64_STANDARD.decode(encoded_banner) else {
            continue;
        };
        let end = bytes
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(bytes.len());
        let Ok(banner) = std::str::from_utf8(&bytes[..end]) else {
            continue;
        };
        if !banners.contains(banner.trim_end()) {
            continue;
        }
        for url in candidates {
            urls.insert(url.clone());
            ensure!(
                urls.len() <= MAX_REMOTE_CANDIDATES,
                "同一镜像 banner 的远程 ISF 候选超过安全上限 {MAX_REMOTE_CANDIDATES}"
            );
        }
    }
    Ok(urls.into_iter().collect())
}

#[derive(Debug, Clone, Copy)]
enum RemoteRequestKind {
    Index,
    Symbol,
}

fn fetch_bounded_bytes(
    client: &Client,
    source: &RemoteIsfSource,
    input_url: &str,
    kind: RemoteRequestKind,
    limit: u64,
) -> Result<Vec<u8>> {
    let url = validate_remote_url(source, input_url, kind)?;
    let response = client
        .get(url)
        .send()
        .with_context(|| format!("下载失败：{input_url}"))?;
    ensure!(
        response.status().is_success(),
        "远程服务器为 {input_url} 返回状态 {}",
        response.status()
    );
    validate_remote_url(source, response.url().as_str(), kind)?;
    if let Some(length) = response.content_length() {
        ensure!(
            length <= limit,
            "远程响应长度 {length} 超过安全上限 {limit}"
        );
    }
    let mut bytes = Vec::new();
    response
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("读取远程响应失败：{input_url}"))?;
    ensure!(bytes.len() as u64 <= limit, "远程响应超过安全上限 {limit}");
    Ok(bytes)
}

fn validate_remote_url(
    source: &RemoteIsfSource,
    input: &str,
    kind: RemoteRequestKind,
) -> Result<Url> {
    let url = Url::parse(input).with_context(|| format!("远程 ISF URL 无效：{input}"))?;
    ensure!(
        url.username().is_empty() && url.password().is_none(),
        "远程 ISF URL 不允许嵌入凭据"
    );
    match url.scheme() {
        "https" => {}
        "http" if source.allow_loopback_http && url_host_is_loopback(&url) => {}
        scheme => bail!("远程 ISF URL 必须使用 HTTPS（收到 {scheme}）"),
    }
    let lower_path = url.path().to_ascii_lowercase();
    if matches!(kind, RemoteRequestKind::Symbol) {
        ensure!(
            lower_path.ends_with(".json") || lower_path.ends_with(".json.xz"),
            "远程 ISF URL 必须指向 .json 或 .json.xz"
        );
    }
    if source.default_repository {
        let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
        let trusted = match kind {
            RemoteRequestKind::Index => {
                host == "raw.githubusercontent.com"
                    && lower_path
                        == "/abyss-w4tcher/volatility3-symbols/master/banners/banners.json"
            }
            RemoteRequestKind::Symbol => {
                (host == "github.com"
                    && lower_path.starts_with("/abyss-w4tcher/volatility3-symbols/raw/"))
                    || (host == "raw.githubusercontent.com"
                        && lower_path.starts_with("/abyss-w4tcher/volatility3-symbols/"))
            }
        };
        ensure!(trusted, "默认远程索引返回了仓库范围外的 URL：{url}");
    }
    Ok(url)
}

fn url_host_is_loopback(url: &Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn download_remote_isf(
    client: &Client,
    store: &SymbolStore,
    source: &RemoteIsfSource,
    input_url: &str,
    image_banners: &HashSet<&str>,
) -> Result<(LinuxIsf, bool)> {
    let url = validate_remote_url(source, input_url, RemoteRequestKind::Symbol)?;
    let suffix = if url.path().to_ascii_lowercase().ends_with(".json.xz") {
        ".json.xz"
    } else {
        ".json"
    };
    let destination = store
        .writable_root()
        .join("linux")
        .join("remote")
        .join(format!("{}{}", sha256_hex(input_url.as_bytes()), suffix));
    if let Ok(table) = load_linux_isf(&destination)
        && image_banners.contains(table.banner())
    {
        return Ok((table, false));
    }

    let response = client
        .get(url)
        .send()
        .with_context(|| format!("Linux ISF 下载失败：{input_url}"))?;
    ensure!(
        response.status().is_success(),
        "远程服务器为 {input_url} 返回状态 {}",
        response.status()
    );
    validate_remote_url(source, response.url().as_str(), RemoteRequestKind::Symbol)?;
    if let Some(length) = response.content_length() {
        ensure!(
            length <= MAX_REMOTE_ISF_BYTES,
            "远程 ISF 长度 {length} 超过 {} MiB 安全上限",
            MAX_REMOTE_ISF_BYTES / 1024 / 1024
        );
    }

    let mut policy = OutputPolicy::new(true);
    policy.output(OutputTarget::file("linux_isf_remote_cache", &destination));
    policy.preflight()?;
    let mut response = response.take(MAX_REMOTE_ISF_BYTES + 1);
    policy.write_file_atomic_validated(
        &destination,
        |output| {
            let copied = copy(&mut response, output).context("写入临时 Linux ISF 失败")?;
            ensure!(
                copied <= MAX_REMOTE_ISF_BYTES,
                "远程 ISF 超过 {} MiB 安全上限",
                MAX_REMOTE_ISF_BYTES / 1024 / 1024
            );
            Ok(())
        },
        |staged| {
            let downloaded = load_linux_isf_from_storage(staged, &destination, legacy_features())?;
            ensure!(
                image_banners.contains(downloaded.banner()),
                "下载 ISF 的 linux_banner 与镜像完整 banner 不同"
            );
            Ok(())
        },
    )?;
    Ok((load_linux_isf(&destination)?, true))
}

fn persist_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut policy = OutputPolicy::new(true);
    policy.output(OutputTarget::file("linux_isf_index_cache", path));
    policy.preflight()?;
    policy.write_bytes_atomic(path, bytes)
}

fn linux_symbol_roots(store: &SymbolStore) -> Vec<PathBuf> {
    let mut roots = store.search_roots().to_vec();
    // The writable StarMem cache also contains small Windows CodeView JSON
    // records.  Linux ISFs, when cached there, live under an explicit `linux`
    // subtree so those unrelated records are never misreported as bad ISFs.
    roots.push(store.writable_root().join("linux"));
    if let Some(paths) = env::var_os("VOLATILITY3_SYMBOL_PATH") {
        roots.extend(env::split_paths(&paths));
    }
    if let Ok(current) = env::current_dir() {
        roots.push(current.join("symbols"));
        roots.push(current.join("volatility3").join("symbols"));
    }
    if let Ok(executable) = env::current_exe()
        && let Some(parent) = executable.parent()
    {
        roots.push(parent.join("symbols"));
    }
    roots.retain(|root| !root.as_os_str().is_empty());
    let mut seen = HashSet::new();
    roots
        .into_iter()
        .filter(|root| seen.insert(root.clone()))
        .collect()
}

fn collect_isf_paths(root: &Path, output: &mut Vec<PathBuf>) -> Result<()> {
    if root.is_file() {
        if is_supported_isf(root) {
            output.push(root.to_path_buf());
        }
        return Ok(());
    }
    if !root.is_dir() {
        return Ok(());
    }
    let conventional_linux = root.join("linux");
    let root = if conventional_linux.is_dir() {
        conventional_linux
    } else {
        root.to_path_buf()
    };
    let mut pending = vec![root];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)
            .with_context(|| format!("无法读取目录 {}", directory.display()))?
        {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if file_type.is_symlink() {
                continue;
            }
            let path = entry.path();
            if file_type.is_dir() {
                pending.push(path);
            } else if file_type.is_file() && is_supported_isf(&path) {
                output.push(path);
                ensure!(
                    output.len() <= MAX_ISF_FILES,
                    "Linux ISF 候选超过安全上限 {MAX_ISF_FILES}"
                );
            }
        }
    }
    Ok(())
}

fn is_supported_isf(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    name.ends_with(".json") || name.ends_with(".json.xz")
}

fn load_linux_isf(path: &Path) -> Result<LinuxIsf> {
    load_linux_isf_for_features(path, legacy_features())
}

pub fn load_linux_isf_for_features(
    path: &Path,
    features: impl IntoIterator<Item = LinuxSymbolFeature>,
) -> Result<LinuxIsf> {
    load_linux_isf_from_storage(path, path, features)
}

/// Load bytes from `storage_path` while deriving compression and the stable report path from
/// `format_path`.  Atomic publication uses a `.tmp` staging name, so format detection must not
/// depend on that transient filename.
fn load_linux_isf_from_storage(
    storage_path: &Path,
    format_path: &Path,
    features: impl IntoIterator<Item = LinuxSymbolFeature>,
) -> Result<LinuxIsf> {
    let features = normalize_features(features);
    let source = fs::read(storage_path)
        .with_context(|| format!("无法读取 Volatility 3 ISF {}", storage_path.display()))?;
    ensure!(
        source.len() as u64 <= MAX_ISF_BYTES,
        "Volatility 3 ISF 文件超过 {} MiB 安全上限",
        MAX_ISF_BYTES / 1024 / 1024
    );
    let file_sha256 = sha256_hex(&source);
    let name = format_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let json = if name.ends_with(".json.xz") {
        let reader = XzReader::new(source.as_slice(), true);
        let mut limited = reader.take(MAX_ISF_BYTES + 1);
        let mut output = Vec::new();
        limited
            .read_to_end(&mut output)
            .with_context(|| format!("无法解压 Volatility 3 ISF {}", storage_path.display()))?;
        ensure!(
            output.len() as u64 <= MAX_ISF_BYTES,
            "Volatility 3 ISF 解压后超过 {} MiB 安全上限",
            MAX_ISF_BYTES / 1024 / 1024
        );
        output
    } else {
        source
    };
    let document: IsfDocument = serde_json::from_slice(&json)
        .with_context(|| format!("Volatility 3 ISF JSON 无效：{}", storage_path.display()))?;
    LinuxIsf::from_document_with_features(
        format_path.to_path_buf(),
        file_sha256,
        document,
        features,
    )
}

fn collect_anonymous_types(
    types: &BTreeMap<String, IsfUserType>,
    name: &str,
    output: &mut BTreeSet<String>,
) {
    if !output.insert(name.to_owned()) {
        return;
    }
    let Some(kind) = types.get(name) else {
        return;
    };
    for field in kind.fields.values().filter(|field| field.anonymous) {
        if let Some(nested) = field.kind.name.as_deref() {
            collect_anonymous_types(types, nested, output);
        }
    }
}

fn retain_referenced_enum(
    available: &BTreeMap<String, IsfEnum>,
    kind: &IsfTypeRef,
    output: &mut BTreeMap<String, IsfEnum>,
) {
    if kind.kind == "enum"
        && let Some(name) = kind.name.as_deref()
        && let Some(value) = available.get(name)
    {
        output.insert(name.to_owned(), value.clone());
    }
    if let Some(subtype) = kind.subtype.as_deref() {
        retain_referenced_enum(available, subtype, output);
    }
}

fn push_warning(warnings: &mut Vec<LinuxIsfWarning>, kind: &str, message: String) {
    if warnings.len() < MAX_DISCOVERY_WARNINGS {
        warnings.push(LinuxIsfWarning {
            kind: kind.to_owned(),
            message,
        });
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn canonical_json_bytes(value: &serde_json::Value) -> Result<Vec<u8>> {
    fn append(value: &serde_json::Value, output: &mut String) -> Result<()> {
        match value {
            serde_json::Value::Null => output.push_str("null"),
            serde_json::Value::Bool(value) => {
                output.push_str(if *value { "true" } else { "false" })
            }
            serde_json::Value::Number(value) => output.push_str(&value.to_string()),
            serde_json::Value::String(value) => output.push_str(&serde_json::to_string(value)?),
            serde_json::Value::Array(values) => {
                output.push('[');
                for (index, value) in values.iter().enumerate() {
                    if index > 0 {
                        output.push(',');
                    }
                    append(value, output)?;
                }
                output.push(']');
            }
            serde_json::Value::Object(values) => {
                output.push('{');
                let mut entries = values.iter().collect::<Vec<_>>();
                entries.sort_unstable_by(|left, right| left.0.cmp(right.0));
                for (index, (key, value)) in entries.into_iter().enumerate() {
                    if index > 0 {
                        output.push(',');
                    }
                    output.push_str(&serde_json::to_string(key)?);
                    output.push(':');
                    append(value, output)?;
                }
                output.push('}');
            }
        }
        Ok(())
    }

    let mut output = String::new();
    append(value, &mut output)?;
    Ok(output.into_bytes())
}

#[derive(Debug, Deserialize)]
struct IsfDocument {
    metadata: IsfMetadata,
    #[serde(default)]
    base_types: BTreeMap<String, IsfBaseType>,
    #[serde(default)]
    user_types: BTreeMap<String, IsfUserType>,
    #[serde(default)]
    enums: BTreeMap<String, IsfEnum>,
    #[serde(default)]
    symbols: BTreeMap<String, IsfSymbol>,
}

#[derive(Debug, Deserialize)]
struct IsfMetadata {
    #[serde(default)]
    format: String,
    #[serde(default)]
    producer: Option<IsfProducer>,
    #[serde(default)]
    linux: Option<IsfLinuxMetadata>,
}

#[derive(Debug, Deserialize)]
struct IsfProducer {
    #[serde(default)]
    name: String,
    #[serde(default)]
    version: String,
}

#[derive(Debug, Deserialize)]
struct IsfLinuxMetadata {
    #[serde(default)]
    symbols: Vec<IsfArtifact>,
    #[serde(default)]
    types: Vec<IsfArtifact>,
}

#[derive(Debug, Deserialize)]
struct IsfArtifact {
    #[serde(default)]
    hash_type: String,
    #[serde(default)]
    hash_value: String,
}

#[derive(Debug, Clone, Deserialize)]
struct IsfBaseType {
    size: i64,
}

#[derive(Debug, Clone, Deserialize)]
struct IsfUserType {
    size: i64,
    #[serde(default)]
    fields: BTreeMap<String, IsfField>,
}

#[derive(Debug, Clone, Deserialize)]
struct IsfField {
    offset: i64,
    #[serde(rename = "type")]
    kind: IsfTypeRef,
    #[serde(default)]
    anonymous: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct IsfTypeRef {
    #[serde(default)]
    kind: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    count: Option<i64>,
    #[serde(default)]
    subtype: Option<Box<IsfTypeRef>>,
    #[serde(default, rename = "type")]
    bitfield_type: Option<Box<IsfTypeRef>>,
    #[serde(default)]
    bit_position: Option<i64>,
    #[serde(default)]
    bit_length: Option<i64>,
}

#[derive(Debug, Clone, Deserialize)]
struct IsfEnum {
    size: i64,
    #[serde(default)]
    constants: BTreeMap<String, i64>,
}

#[derive(Debug, Clone, Deserialize)]
struct IsfSymbol {
    #[serde(default)]
    address: Option<IsfInteger>,
    #[serde(default)]
    constant_data: Option<String>,
    #[serde(default, rename = "type")]
    kind: Option<IsfTypeRef>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(untagged)]
enum IsfInteger {
    Unsigned(u64),
    Signed(i64),
}

impl IsfInteger {
    fn nonnegative_u64(self) -> Option<u64> {
        match self {
            Self::Unsigned(value) => Some(value),
            Self::Signed(value) => u64::try_from(value).ok(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::thread;

    use lzma_rust2::{XzOptions, XzWriter};

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    fn synthetic_document() -> String {
        let banner = BASE64_STANDARD.encode(b"Linux version 9.9.9-test #1 SMP\n\0");
        format!(
            r#"{{
                "metadata": {{
                    "format": "6.2.0",
                    "producer": {{"name": "dwarf2json", "version": "test"}},
                    "linux": {{
                        "symbols": [{{"hash_type": "sha256", "hash_value": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}],
                        "types": []
                    }}
                }},
                "base_types": {{
                    "long unsigned int": {{"size": 8}},
                    "unsigned int": {{"size": 4}},
                    "int": {{"size": 4}},
                    "char": {{"size": 1}}
                }},
                "user_types": {{
                    "task_struct": {{
                        "size": 1024,
                        "fields": {{
                            "unnamed_field": {{"offset": 64, "anonymous": true, "type": {{"kind": "struct", "name": "anon_task"}}}},
                            "comm": {{"offset": 128, "type": {{"kind": "array", "count": 16, "subtype": {{"kind": "base", "name": "char"}}}}}}
                        }}
                    }},
                    "anon_task": {{
                        "size": 64,
                        "fields": {{"pid": {{"offset": 8, "type": {{"kind": "base", "name": "int"}}}}}}
                    }},
                    "sock": {{
                        "size": 64,
                        "fields": {{
                            "sk_type": {{"offset": 20, "type": {{"kind": "bitfield", "bit_position": 16, "bit_length": 16, "type": {{"kind": "base", "name": "unsigned int"}}}}}}
                        }}
                    }}
                }},
                "enums": {{}},
                "symbols": {{
                    "_stext": {{"address": 18446744071578845184}},
                    "linux_banner": {{"address": 18446744071562067968, "constant_data": "{banner}"}},
                    "init_task": {{"address": 18446744071562072064}}
                }}
            }}"#
        )
    }

    fn synthetic_module_document(banner: &str, module_size: u64) -> String {
        let banner = BASE64_STANDARD.encode(format!("{banner}\n\0"));
        format!(
            r#"{{
                "metadata": {{
                    "format": "6.2.0",
                    "producer": {{"name": "dwarf2json", "version": "test"}},
                    "linux": {{
                        "symbols": [{{"hash_type": "sha256", "hash_value": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}],
                        "types": []
                    }}
                }},
                "base_types": {{
                    "long unsigned int": {{"size": 8}},
                    "char": {{"size": 1}}
                }},
                "user_types": {{
                    "list_head": {{"size": 16, "fields": {{}}}},
                    "module_layout": {{"size": {module_size}, "fields": {{}}}},
                    "module": {{
                        "size": 256,
                        "fields": {{
                            "list": {{"offset": 0, "type": {{"kind": "struct", "name": "list_head"}}}},
                            "name": {{"offset": 24, "type": {{"kind": "array", "count": 56, "subtype": {{"kind": "base", "name": "char"}}}}}},
                            "core_layout": {{"offset": 96, "type": {{"kind": "struct", "name": "module_layout"}}}}
                        }}
                    }},
                    "module_kobject": {{"size": 64, "fields": {{}}}},
                    "kobject": {{"size": 64, "fields": {{}}}},
                    "kset": {{"size": 64, "fields": {{}}}},
                    "unrelated_type": {{"size": 8, "fields": {{}}}}
                }},
                "enums": {{}},
                "symbols": {{
                    "_stext": {{"address": 18446744071578845184}},
                    "linux_banner": {{"address": 18446744071562067968, "constant_data": "{banner}"}},
                    "modules": {{"address": 18446744071562100736}},
                    "module_kset": {{"address": 18446744071562104832}},
                    "unrelated_symbol": {{"address": 18446744071562108928}}
                }}
            }}"#
        )
    }

    struct PassingRuntimeValidator;

    impl LinuxSymbolRuntimeValidator for PassingRuntimeValidator {
        fn validate(&self, _table: &LinuxIsf) -> Result<LinuxSymbolRuntimeValidation> {
            Ok(LinuxSymbolRuntimeValidation::passed(vec![
                LinuxSymbolRuntimeCheck {
                    name: "runtime_banner".to_owned(),
                    passed: Some(true),
                    message: "runtime linux_banner matched".to_owned(),
                },
            ]))
        }
    }

    #[test]
    fn parses_banner_and_anonymous_fields() {
        let json = synthetic_document();
        let document: IsfDocument = serde_json::from_str(&json).unwrap();
        let table = LinuxIsf::from_document(
            PathBuf::from("kernel.json"),
            sha256_hex(json.as_bytes()),
            document,
        )
        .unwrap();
        assert_eq!(table.banner(), "Linux version 9.9.9-test #1 SMP");
        assert_eq!(table.field_offset("task_struct", "pid").unwrap(), 72);
        assert_eq!(table.field_array_count("task_struct", "comm").unwrap(), 16);
        assert_eq!(table.field_size("task_struct", "comm").unwrap(), 16);
        assert_eq!(table.field_size("sock", "sk_type").unwrap(), 4);
        assert_eq!(
            table.field_bit_range("sock", "sk_type").unwrap(),
            Some((16, 16))
        );
        assert_eq!(
            table.symbol_address("init_task").unwrap(),
            0xffff_ffff_8000_1000
        );
        assert_eq!(
            table.symbol_address("_stext").unwrap(),
            0xffff_ffff_8100_0000
        );
    }

    #[test]
    fn feature_registry_is_complete_and_unique() {
        let features = linux_symbol_feature_registry()
            .iter()
            .map(|entry| entry.feature)
            .collect::<BTreeSet<_>>();
        assert_eq!(features.len(), LinuxSymbolFeature::ALL.len());
        assert_eq!(
            features,
            LinuxSymbolFeature::ALL.into_iter().collect::<BTreeSet<_>>()
        );
    }

    #[test]
    fn kallsyms_feature_expands_module_symbol_dependencies() {
        let features = normalize_features([LinuxSymbolFeature::Kallsyms]);
        assert!(features.contains(&LinuxSymbolFeature::Kallsyms));
        assert!(features.contains(&LinuxSymbolFeature::Modules));

        let retained_types = retained_type_names(&features);
        assert!(retained_types.contains("module"));
        assert!(retained_types.contains("mod_kallsyms"));
        assert!(retained_types.contains("module_kallsyms"));

        let retained_symbols = retained_symbol_names(&features);
        assert!(retained_symbols.contains("modules"));
        assert!(retained_symbols.contains("module_addr_min"));
        assert!(retained_symbols.contains("module_addr_max"));
    }

    #[test]
    fn module_feature_compaction_retains_only_declared_material() {
        let banner = "Linux version 6.8.0-module-test #1 SMP";
        let json = synthetic_module_document(banner, 64);
        let document: IsfDocument = serde_json::from_str(&json).unwrap();
        let table = LinuxIsf::from_document_with_features(
            PathBuf::from("module.json"),
            sha256_hex(json.as_bytes()),
            document,
            [LinuxSymbolFeature::Modules].into_iter().collect(),
        )
        .unwrap();
        assert!(table.user_types.contains_key("module"));
        assert!(table.user_types.contains_key("module_kobject"));
        assert!(!table.user_types.contains_key("unrelated_type"));
        assert!(table.symbols.contains_key("modules"));
        assert!(table.symbols.contains_key("module_kset"));
        assert!(!table.symbols.contains_key("unrelated_symbol"));
        assert!(table.requirement_gaps().is_empty());
    }

    #[test]
    fn symbol_identity_is_path_free_and_canonical() {
        let banner = "Linux version 6.8.0-identity-test #1 SMP";
        let json = synthetic_module_document(banner, 64);
        let make_table = |path: &str| {
            LinuxIsf::from_document_with_features(
                PathBuf::from(path),
                sha256_hex(json.as_bytes()),
                serde_json::from_str(&json).unwrap(),
                [LinuxSymbolFeature::Modules].into_iter().collect(),
            )
            .unwrap()
        };
        let first = make_table("/Users/alice/symbols/kernel.json")
            .identity()
            .unwrap();
        let second = make_table("C:\\Users\\bob\\symbols\\kernel.json")
            .identity()
            .unwrap();
        assert_eq!(first, second);
        assert_eq!(first.canonical_sha256.len(), 64);
        let serialized = serde_json::to_string(&first).unwrap();
        assert!(!serialized.contains("alice"));
        assert!(!serialized.contains("bob"));
    }

    #[test]
    fn symbol_cli_option_conflicts_are_rejected_without_side_effects() {
        let fetch_offline = LinuxSymbolDiagnosticOptions {
            fetch: true,
            offline: true,
            ..Default::default()
        };
        assert!(fetch_offline.validate().is_err());
        let install_without_isf = LinuxSymbolDiagnosticOptions {
            install: true,
            ..Default::default()
        };
        assert!(install_without_isf.validate().is_err());
        let refresh_offline = LinuxSymbolDiagnosticOptions {
            refresh_index: true,
            offline: true,
            ..Default::default()
        };
        assert!(refresh_offline.validate().is_err());
    }

    #[test]
    fn local_diagnostics_select_and_runtime_validate_exact_candidate() {
        let root = env::temp_dir().join(format!(
            "starmem-linux-symbol-diagnostic-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        let symbol_root = root.join("symbols/linux");
        fs::create_dir_all(&symbol_root).unwrap();
        let banner = "Linux version 6.8.0-diagnostic-test #1 SMP";
        fs::write(
            symbol_root.join("module.json"),
            synthetic_module_document(banner, 64),
        )
        .unwrap();
        let store = SymbolStore::new(root.join("cache")).with_search_root(root.join("symbols"));
        let options = LinuxSymbolDiagnosticOptions {
            features: [LinuxSymbolFeature::Modules].into_iter().collect(),
            ..Default::default()
        };
        let report = diagnose_local_linux_symbols(
            &store,
            &[banner.to_owned()],
            &options,
            Some(&PassingRuntimeValidator),
        )
        .unwrap();
        assert!(report.available);
        assert!(report.complete);
        assert_eq!(report.selection, LinuxSymbolSelectionStatus::Selected);
        assert_eq!(report.files_considered, 1);
        assert_eq!(
            report.candidates[0].runtime_validation.status,
            LinuxSymbolRuntimeValidationStatus::Passed
        );
        assert!(!report.effects.network_accessed);
        assert!(!report.effects.cache_written);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn local_diagnostics_report_ambiguous_non_equivalent_candidates() {
        let root = env::temp_dir().join(format!(
            "starmem-linux-symbol-ambiguous-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        let symbol_root = root.join("symbols/linux");
        fs::create_dir_all(&symbol_root).unwrap();
        let banner = "Linux version 6.8.0-ambiguous-test #1 SMP";
        fs::write(
            symbol_root.join("first.json"),
            synthetic_module_document(banner, 64),
        )
        .unwrap();
        fs::write(
            symbol_root.join("second.json"),
            synthetic_module_document(banner, 96),
        )
        .unwrap();
        let store = SymbolStore::new(root.join("cache")).with_search_root(root.join("symbols"));
        let options = LinuxSymbolDiagnosticOptions {
            features: [LinuxSymbolFeature::Modules].into_iter().collect(),
            ..Default::default()
        };
        let report = diagnose_local_linux_symbols(
            &store,
            &[banner.to_owned()],
            &options,
            Some(&PassingRuntimeValidator),
        )
        .unwrap();
        assert!(!report.available);
        assert!(!report.complete);
        assert_eq!(report.selection, LinuxSymbolSelectionStatus::Ambiguous);
        assert_eq!(
            report
                .candidates
                .iter()
                .filter(|candidate| candidate.status == LinuxSymbolCandidateStatus::Ambiguous)
                .count(),
            2
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn invalid_local_candidate_prevents_a_complete_diagnostic() {
        let root = env::temp_dir().join(format!(
            "starmem-linux-symbol-incomplete-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        let symbol_root = root.join("symbols/linux");
        fs::create_dir_all(&symbol_root).unwrap();
        let banner = "Linux version 6.8.0-incomplete-test #1 SMP";
        fs::write(
            symbol_root.join("valid.json"),
            synthetic_module_document(banner, 64),
        )
        .unwrap();
        fs::write(symbol_root.join("broken.json"), b"not-json").unwrap();
        let store = SymbolStore::new(root.join("cache")).with_search_root(root.join("symbols"));
        let options = LinuxSymbolDiagnosticOptions {
            features: [LinuxSymbolFeature::Modules].into_iter().collect(),
            ..Default::default()
        };
        let report = diagnose_local_linux_symbols(
            &store,
            &[banner.to_owned()],
            &options,
            Some(&PassingRuntimeValidator),
        )
        .unwrap();
        assert!(report.available);
        assert!(!report.complete);
        assert!(report.candidates.iter().any(|candidate| {
            candidate
                .rejection_reasons
                .iter()
                .any(|reason| reason.code == "linux_isf_invalid")
        }));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reads_xz_and_resolves_only_an_exact_banner() {
        let root = env::temp_dir().join(format!(
            "starmem-linux-isf-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        let linux = root.join("symbols").join("linux");
        fs::create_dir_all(&linux).unwrap();
        let json = synthetic_document();
        fs::write(linux.join("kernel.json"), json.as_bytes()).unwrap();
        let mut compressed = Vec::new();
        {
            let mut writer = XzWriter::new(&mut compressed, XzOptions::with_preset(1)).unwrap();
            writer.write_all(json.as_bytes()).unwrap();
            writer.finish().unwrap();
        }
        let xz_path = linux.join("kernel.json.xz");
        fs::write(&xz_path, compressed).unwrap();

        let decoded = load_linux_isf(&xz_path).unwrap();
        assert_eq!(decoded.banner(), "Linux version 9.9.9-test #1 SMP");
        let store = SymbolStore::new(root.join("cache")).with_search_root(root.join("symbols"));
        let resolution =
            resolve_linux_isf(&store, &["Linux version 9.9.9-test #1 SMP".to_owned()]).unwrap();
        assert_eq!(resolution.files_considered, 2);
        assert!(resolution.table.is_some());

        let mismatch =
            resolve_linux_isf(&store, &["Linux version 9.9.9-different #1 SMP".to_owned()])
                .unwrap();
        assert!(mismatch.table.is_none());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn validates_xz_staging_bytes_using_the_final_format_name() {
        let root = env::temp_dir().join(format!(
            "starmem-linux-isf-staging-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let json = synthetic_document();
        let mut compressed = Vec::new();
        {
            let mut writer = XzWriter::new(&mut compressed, XzOptions::with_preset(1)).unwrap();
            writer.write_all(json.as_bytes()).unwrap();
            writer.finish().unwrap();
        }
        let staging = root.join(".kernel.json.xz.starmem-1-0.tmp");
        let destination = root.join("kernel.json.xz");
        fs::write(&staging, compressed).unwrap();

        let decoded =
            load_linux_isf_from_storage(&staging, &destination, legacy_features()).unwrap();
        assert_eq!(decoded.banner(), "Linux version 9.9.9-test #1 SMP");
        assert_eq!(decoded.path(), destination);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn downloads_an_exact_remote_isf_and_reuses_the_local_cache() {
        let root = env::temp_dir().join(format!(
            "starmem-linux-remote-isf-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let banner = "Linux version 9.9.9-test #1 SMP";
        let symbol_url = format!("http://{address}/kernel.json");
        let encoded_banner = BASE64_STANDARD.encode(format!("{banner}\n\0"));
        let index = serde_json::json!({
            "version": 1,
            "linux": {encoded_banner: [symbol_url.clone()]}
        })
        .to_string()
        .into_bytes();
        let symbol = synthetic_document().into_bytes();
        let server = thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = Vec::new();
                loop {
                    let mut chunk = [0u8; 1024];
                    let count = stream.read(&mut chunk).unwrap();
                    if count == 0 {
                        break;
                    }
                    request.extend_from_slice(&chunk[..count]);
                    if request.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                let first_line = String::from_utf8_lossy(&request)
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .to_owned();
                let body = if first_line.starts_with("GET /index.json ") {
                    &index
                } else if first_line.starts_with("GET /kernel.json ") {
                    &symbol
                } else {
                    panic!("unexpected HTTP request: {first_line}");
                };
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .unwrap();
                stream.write_all(body).unwrap();
            }
        });

        let store = SymbolStore::new(root.join("cache"));
        let source = RemoteIsfSource {
            index_url: format!("http://{address}/index.json"),
            default_repository: false,
            allow_loopback_http: true,
        };
        let banners = vec![banner.to_owned()];
        let resolution = resolve_remote_linux_isf_from_source(&store, &banners, &source).unwrap();
        server.join().unwrap();
        let downloaded = resolution.table.unwrap();
        assert_eq!(downloaded.banner(), banner);
        assert!(
            downloaded
                .path()
                .starts_with(root.join("cache/linux/remote"))
        );
        assert!(
            resolution
                .warnings
                .iter()
                .any(|warning| warning.kind == "linux_isf_remote_downloaded")
        );

        let cached = resolve_linux_isf(&store, &banners).unwrap();
        assert_eq!(cached.files_considered, 1);
        assert_eq!(cached.table.unwrap().banner(), banner);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn remote_index_matching_never_falls_back_to_a_similar_release() {
        let exact = "Linux version 6.8.0-49-generic #49-Ubuntu";
        let encoded = BASE64_STANDARD.encode(format!("{exact}\n\0"));
        let index = RemoteIsfIndex {
            version: 1,
            linux: BTreeMap::from([(
                encoded,
                vec!["https://example.test/kernel.json.xz".to_owned()],
            )]),
        };
        let urls = remote_urls_for_banners(
            &index,
            &["Linux version 6.8.0-50-generic #50-Ubuntu".to_owned()],
        )
        .unwrap();
        assert!(urls.is_empty());
    }

    #[test]
    fn default_remote_source_rejects_plain_http_and_out_of_repository_urls() {
        let source = RemoteIsfSource {
            index_url: DEFAULT_REMOTE_ISF_INDEX.to_owned(),
            default_repository: true,
            allow_loopback_http: false,
        };
        assert!(
            validate_remote_url(
                &source,
                "http://127.0.0.1/kernel.json.xz",
                RemoteRequestKind::Symbol,
            )
            .is_err()
        );
        assert!(
            validate_remote_url(
                &source,
                "https://example.test/kernel.json.xz",
                RemoteRequestKind::Symbol,
            )
            .is_err()
        );
    }
}
