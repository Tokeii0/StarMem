//! Active Linux socket evidence recovered from validated process file descriptors.
//!
//! `linux.sockstat` deliberately starts from the same active task and FD traversal as
//! `linux.lsof`.  A socket record is accepted only when the sockfs inode container,
//! `file.private_data`, `socket.file`, and `sock.sk_socket` agree.  This is an active
//! descriptor view; orphaned and freed sockets require a future independent scanner.

use std::collections::{BTreeMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::{Context, Result, ensure};
use serde::Serialize;

use crate::image::MemoryImage;
use crate::linux::{
    LinuxKernelContext, LinuxX64AddressSpace, UBUNTU_4_13_0_36_XENIAL, UBUNTU_5_4_0_84_BIONIC,
    UBUNTU_6_8_0_49_NOBLE, is_kernel_pointer,
};
use crate::linux_process::{LinuxLsofRecord, LinuxLsofReport, LinuxProcessArtifactWarning};

const AF_UNIX: u16 = 1;
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;
const MAX_SOCKET_FAMILY: u16 = 46;
const MAX_WARNING_DETAILS: usize = 64;

#[derive(Debug, Clone, Copy)]
struct IntegerField {
    offset: u64,
    storage_bytes: u8,
    bit_position: u8,
    bit_length: u8,
}

impl IntegerField {
    const fn plain(offset: u64, storage_bytes: u8) -> Self {
        Self {
            offset,
            storage_bytes,
            bit_position: 0,
            bit_length: storage_bytes * 8,
        }
    }

    const fn bitfield(offset: u64, storage_bytes: u8, bit_position: u8, bit_length: u8) -> Self {
        Self {
            offset,
            storage_bytes,
            bit_position,
            bit_length,
        }
    }

    fn from_isf(
        isf: &crate::linux_symbols::LinuxIsf,
        type_name: &str,
        field_name: &str,
    ) -> Result<Self> {
        let storage_bytes = u8::try_from(isf.field_size(type_name, field_name)?)
            .context("Linux ISF 整数字段宽度无效")?;
        ensure!(
            matches!(storage_bytes, 1 | 2 | 4 | 8),
            "Linux ISF 字段 {type_name}.{field_name} 的存储宽度不受支持：{storage_bytes}"
        );
        let (bit_position, bit_length) = isf
            .field_bit_range(type_name, field_name)?
            .unwrap_or((0, storage_bytes * 8));
        ensure!(
            u16::from(bit_position) + u16::from(bit_length) <= u16::from(storage_bytes) * 8,
            "Linux ISF 字段 {type_name}.{field_name} 的 bitfield 超出底层存储宽度"
        );
        Ok(Self {
            offset: isf.field_offset(type_name, field_name)?,
            storage_bytes,
            bit_position,
            bit_length,
        })
    }

    fn read(self, space: &LinuxX64AddressSpace<'_>, base: u64) -> Result<u64> {
        let address = base
            .checked_add(self.offset)
            .context("Linux socket 字段地址溢出")?;
        let raw = read_unsigned(space, address, self.storage_bytes)?;
        let mask = if self.bit_length == 64 {
            u64::MAX
        } else {
            (1u64 << self.bit_length) - 1
        };
        Ok((raw >> self.bit_position) & mask)
    }
}

#[derive(Debug, Clone, Copy)]
struct ExactLinuxSocketProfile {
    source: &'static str,
    fingerprint: &'static str,
    file_private_data: u64,
    socket_alloc_socket: u64,
    socket_alloc_vfs_inode: u64,
    socket_state: IntegerField,
    socket_type: IntegerField,
    socket_file: u64,
    socket_sk: u64,
    socket_ops: u64,
    sock_common: u64,
    skc_daddr: u64,
    skc_rcv_saddr: u64,
    skc_dport: u64,
    skc_num: u64,
    skc_family: u64,
    skc_state: u64,
    skc_bound_dev_if: u64,
    skc_net: u64,
    skc_v6_daddr: u64,
    skc_v6_rcv_saddr: u64,
    sock_type: IntegerField,
    sock_protocol: IntegerField,
    sock_socket: u64,
    unix_addr: u64,
    unix_peer: u64,
    unix_address_len: u64,
    unix_address_name: u64,
    sockaddr_un_sun_path: u64,
    unix_path_capacity: usize,
    task_nsproxy: u64,
    nsproxy_net_ns: u64,
    socket_net_field: &'static str,
    net_inum: u64,
    net_inum_field: &'static str,
}

impl ExactLinuxSocketProfile {
    fn from_isf(isf: &crate::linux_symbols::LinuxIsf) -> Result<Self> {
        let namespace = SocketNamespaceLayout::from_isf(isf)?;
        let sock_common = isf.field_offset("sock", "__sk_common")?;
        let common = |field: &str| -> Result<u64> {
            sock_common
                .checked_add(isf.field_offset("sock_common", field)?)
                .with_context(|| format!("sock_common.{field} 偏移溢出"))
        };
        let profile = Self {
            source: "volatility3_isf_sockstat",
            fingerprint: "Volatility 3 ISF; exact linux_banner; runtime-validated socket layout",
            file_private_data: isf.field_offset("file", "private_data")?,
            socket_alloc_socket: isf.field_offset("socket_alloc", "socket")?,
            socket_alloc_vfs_inode: isf.field_offset("socket_alloc", "vfs_inode")?,
            socket_state: IntegerField::from_isf(isf, "socket", "state")?,
            socket_type: IntegerField::from_isf(isf, "socket", "type")?,
            socket_file: isf.field_offset("socket", "file")?,
            socket_sk: isf.field_offset("socket", "sk")?,
            socket_ops: isf.field_offset("socket", "ops")?,
            sock_common,
            skc_daddr: common("skc_daddr")?,
            skc_rcv_saddr: common("skc_rcv_saddr")?,
            skc_dport: common("skc_dport")?,
            skc_num: common("skc_num")?,
            skc_family: common("skc_family")?,
            skc_state: common("skc_state")?,
            skc_bound_dev_if: common("skc_bound_dev_if")?,
            skc_net: common(namespace.socket_net_field)?,
            skc_v6_daddr: common("skc_v6_daddr")?,
            skc_v6_rcv_saddr: common("skc_v6_rcv_saddr")?,
            sock_type: IntegerField::from_isf(isf, "sock", "sk_type")?,
            sock_protocol: IntegerField::from_isf(isf, "sock", "sk_protocol")?,
            sock_socket: isf.field_offset("sock", "sk_socket")?,
            unix_addr: isf.field_offset("unix_sock", "addr")?,
            unix_peer: isf.field_offset("unix_sock", "peer")?,
            unix_address_len: isf.field_offset("unix_address", "len")?,
            unix_address_name: isf.field_offset("unix_address", "name")?,
            sockaddr_un_sun_path: isf.field_offset("sockaddr_un", "sun_path")?,
            unix_path_capacity: usize::try_from(isf.field_array_count("sockaddr_un", "sun_path")?)
                .context("sockaddr_un.sun_path 长度无效")?,
            task_nsproxy: isf.field_offset("task_struct", "nsproxy")?,
            nsproxy_net_ns: isf.field_offset("nsproxy", "net_ns")?,
            socket_net_field: namespace.socket_net_field,
            net_inum: namespace.net_inum,
            net_inum_field: namespace.net_inum_field,
        };
        ensure!(
            profile.socket_alloc_vfs_inode > 0,
            "socket_alloc.vfs_inode 偏移为零"
        );
        ensure!(
            profile.unix_path_capacity <= 4096,
            "UNIX socket 路径容量超出安全范围"
        );
        Ok(profile)
    }

    fn for_banner(banner: &str) -> Option<Self> {
        let common = |fingerprint,
                      socket_alloc_vfs_inode,
                      socket_file,
                      socket_sk,
                      sock_type,
                      sock_protocol,
                      sock_socket,
                      unix_addr,
                      unix_peer,
                      unix_address_name,
                      task_nsproxy| Self {
            source: "exact_banner_sockstat_profile",
            fingerprint,
            file_private_data: 0xc8,
            socket_alloc_socket: 0,
            socket_alloc_vfs_inode,
            socket_state: IntegerField::plain(0, 4),
            socket_type: IntegerField::plain(4, 2),
            socket_file,
            socket_sk,
            socket_ops: socket_sk + 8,
            sock_common: 0,
            skc_daddr: 0,
            skc_rcv_saddr: 4,
            skc_dport: 0x0c,
            skc_num: 0x0e,
            skc_family: 0x10,
            skc_state: 0x12,
            skc_bound_dev_if: 0x14,
            skc_net: 0x30,
            skc_v6_daddr: 0x38,
            skc_v6_rcv_saddr: 0x48,
            sock_type,
            sock_protocol,
            sock_socket,
            unix_addr,
            unix_peer,
            unix_address_len: 4,
            unix_address_name,
            sockaddr_un_sun_path: 2,
            unix_path_capacity: 108,
            task_nsproxy,
            nsproxy_net_ns: 0x28,
            socket_net_field: "skc_net.net",
            net_inum: 0x88,
            net_inum_field: "ns.inum",
        };
        Some(match banner {
            UBUNTU_4_13_0_36_XENIAL => common(
                "Ubuntu Xenial HWE 4.13.0-36.40; exact banner/build-id socket layout",
                0x30,
                0x18,
                0x20,
                IntegerField::bitfield(0x1f8, 4, 16, 16),
                IntegerField::bitfield(0x1f8, 4, 8, 8),
                0x258,
                0x2c8,
                0x320,
                0x0c,
                0xaf0,
            ),
            UBUNTU_5_4_0_84_BIONIC => common(
                "Ubuntu Bionic HWE 5.4.0-84.94; exact banner/build-id socket layout",
                0x80,
                0x10,
                0x18,
                IntegerField::bitfield(0x210, 4, 16, 16),
                IntegerField::bitfield(0x210, 4, 8, 8),
                0x278,
                0x2f8,
                0x350,
                0x0c,
                0xac8,
            ),
            UBUNTU_6_8_0_49_NOBLE => common(
                "Ubuntu Noble 6.8.0-49.49; exact banner/build-id socket layout",
                0x80,
                0x10,
                0x18,
                IntegerField::plain(0x202, 2),
                IntegerField::plain(0x204, 2),
                0x270,
                0x2f8,
                0x350,
                0x08,
                0xc18,
            ),
            _ => return None,
        })
    }

    fn evidence(self, kernel: &LinuxKernelContext) -> LinuxSocketProfileEvidence {
        let offsets = [
            ("file.private_data", self.file_private_data),
            ("socket_alloc.socket", self.socket_alloc_socket),
            ("socket_alloc.vfs_inode", self.socket_alloc_vfs_inode),
            ("socket.file", self.socket_file),
            ("socket.sk", self.socket_sk),
            ("socket.ops", self.socket_ops),
            ("sock.__sk_common", self.sock_common),
            ("sock_common.skc_daddr", self.skc_daddr),
            ("sock_common.skc_rcv_saddr", self.skc_rcv_saddr),
            ("sock_common.skc_dport", self.skc_dport),
            ("sock_common.skc_num", self.skc_num),
            ("sock_common.skc_family", self.skc_family),
            ("sock_common.skc_state", self.skc_state),
            ("sock_common.skc_bound_dev_if", self.skc_bound_dev_if),
            ("sock_common.skc_v6_daddr", self.skc_v6_daddr),
            ("sock_common.skc_v6_rcv_saddr", self.skc_v6_rcv_saddr),
            ("sock.sk_socket", self.sock_socket),
            ("unix_sock.addr", self.unix_addr),
            ("unix_sock.peer", self.unix_peer),
            ("unix_address.len", self.unix_address_len),
            ("unix_address.name", self.unix_address_name),
            ("sockaddr_un.sun_path", self.sockaddr_un_sun_path),
            ("task_struct.nsproxy", self.task_nsproxy),
            ("nsproxy.net_ns", self.nsproxy_net_ns),
        ]
        .into_iter()
        .map(|(name, offset)| (name.to_owned(), offset))
        .chain([
            (
                format!("sock_common.{}", self.socket_net_field),
                self.skc_net,
            ),
            (format!("net.{}", self.net_inum_field), self.net_inum),
        ])
        .collect();
        let integer_fields = [
            ("socket.state", self.socket_state),
            ("socket.type", self.socket_type),
            ("sock.sk_type", self.sock_type),
            ("sock.sk_protocol", self.sock_protocol),
        ]
        .into_iter()
        .map(|(name, field)| {
            (
                name.to_owned(),
                LinuxSocketIntegerFieldEvidence {
                    offset: field.offset,
                    storage_bytes: field.storage_bytes,
                    bit_position: field.bit_position,
                    bit_length: field.bit_length,
                },
            )
        })
        .collect();
        LinuxSocketProfileEvidence {
            source: self.source.to_owned(),
            fingerprint: if self.source == "volatility3_isf_sockstat" {
                kernel
                    .symbol_table
                    .as_deref()
                    .map(|table| table.fingerprint().to_owned())
                    .unwrap_or_else(|| self.fingerprint.to_owned())
            } else {
                self.fingerprint.to_owned()
            },
            offsets,
            integer_fields,
        }
    }
}

fn exact_profile(kernel: &LinuxKernelContext) -> Result<ExactLinuxSocketProfile> {
    if let Some(isf) = kernel.symbol_table.as_deref() {
        return ExactLinuxSocketProfile::from_isf(isf).or_else(|isf_error| {
            ExactLinuxSocketProfile::for_banner(&kernel.banner).with_context(|| {
                format!(
                    "精确匹配的 Volatility 3 ISF 缺少可用 socket 布局（{isf_error:#}），且当前 Linux 构建没有内置完整 banner/build-id socket profile"
                )
            })
        });
    }
    ExactLinuxSocketProfile::for_banner(&kernel.banner).context(
        "当前 Linux 构建没有精确匹配的 Volatility 3 ISF 或完整 banner/build-id socket 布局；拒绝按相似版本猜测偏移",
    )
}

#[derive(Debug, Clone, Serialize)]
pub struct LinuxSocketIntegerFieldEvidence {
    pub offset: u64,
    pub storage_bytes: u8,
    pub bit_position: u8,
    pub bit_length: u8,
}

#[derive(Debug, Clone, Serialize)]
pub struct LinuxSocketProfileEvidence {
    pub source: String,
    pub fingerprint: String,
    pub offsets: BTreeMap<String, u64>,
    pub integer_fields: BTreeMap<String, LinuxSocketIntegerFieldEvidence>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LinuxSockstatRecord {
    pub task: u64,
    pub task_hex: String,
    pub pid: i32,
    pub process_name: String,
    pub fd: u32,
    pub file: u64,
    pub file_hex: String,
    pub inode: u64,
    pub inode_hex: String,
    pub inode_number: Option<u64>,
    pub socket: u64,
    pub socket_hex: String,
    pub sock: u64,
    pub sock_hex: String,
    pub socket_ops: u64,
    pub socket_ops_hex: String,
    pub family: String,
    pub family_raw: u16,
    pub socket_type: String,
    pub socket_type_raw: u16,
    pub protocol: Option<String>,
    pub protocol_raw: u16,
    pub state: String,
    pub socket_state_raw: u32,
    pub sock_state_raw: u8,
    pub local_address: Option<String>,
    pub local_port: Option<u16>,
    pub remote_address: Option<String>,
    pub remote_port: Option<u16>,
    pub bound_device_ifindex: Option<i32>,
    pub unix_peer_sock: Option<u64>,
    pub unix_peer_sock_hex: Option<String>,
    pub socket_net_namespace: Option<u32>,
    pub task_net_namespace: Option<u32>,
    pub namespace_status: String,
    pub complete: bool,
    pub field_errors: Vec<String>,
    pub validation: String,
}

#[derive(Debug, Serialize)]
pub struct LinuxSockstatReport {
    pub source: String,
    pub kernel: LinuxKernelContext,
    pub profile: LinuxSocketProfileEvidence,
    pub records: Vec<LinuxSockstatRecord>,
    pub family_counts: BTreeMap<String, usize>,
    pub socket_fd_candidates: usize,
    pub records_recovered: usize,
    pub unique_sockets: usize,
    pub processes_with_sockets: usize,
    pub unrecoverable_candidates: usize,
    pub partial_records: usize,
    pub unsupported_family_records: usize,
    pub process_list_complete: bool,
    pub lsof_complete: bool,
    pub complete: bool,
    pub max_fds: usize,
    pub scope: String,
    pub warnings_suppressed: usize,
    pub warnings: Vec<LinuxProcessArtifactWarning>,
}

pub fn analyze_sockstat(
    image: &MemoryImage,
    kernel: &LinuxKernelContext,
    lsof: &LinuxLsofReport,
) -> Result<LinuxSockstatReport> {
    let profile = exact_profile(kernel)?;
    let space = LinuxX64AddressSpace::new(image, kernel.directory_table_base)?;
    let candidates = lsof
        .records
        .iter()
        .filter(|record| record.file_type.as_deref() == Some("socket"))
        .collect::<Vec<_>>();
    let socket_fd_candidates = candidates.len();
    let mut records = Vec::with_capacity(socket_fd_candidates);
    let mut warnings = lsof.warnings.clone();
    let mut warning_details = 0usize;
    let mut warnings_suppressed = 0usize;
    let mut unrecoverable_candidates = 0usize;

    for candidate in candidates {
        match parse_open_socket(&space, profile, candidate) {
            Ok(record) => {
                if !record.complete {
                    push_socket_warning(
                        &mut warnings,
                        &mut warning_details,
                        &mut warnings_suppressed,
                        LinuxProcessArtifactWarning::new(
                            "socket_fields_partial",
                            format!(
                                "PID {} FD {} socket 字段部分恢复：{}",
                                record.pid,
                                record.fd,
                                record.field_errors.join("；")
                            ),
                            Some(record.pid),
                            Some(record.sock),
                        ),
                    );
                }
                records.push(record);
            }
            Err(error) => {
                unrecoverable_candidates += 1;
                push_socket_warning(
                    &mut warnings,
                    &mut warning_details,
                    &mut warnings_suppressed,
                    LinuxProcessArtifactWarning::new(
                        "socket_unrecoverable",
                        format!(
                            "PID {} FD {} 的 socket inode 不能通过 file/socket/sock 反向链接校验：{error:#}",
                            candidate.pid, candidate.fd
                        ),
                        Some(candidate.pid),
                        Some(candidate.file),
                    ),
                );
            }
        }
    }
    if warnings_suppressed > 0 {
        warnings.push(LinuxProcessArtifactWarning::new(
            "socket_warning_limit",
            format!("另有 {warnings_suppressed} 条 socket 结构告警未展开"),
            None,
            None,
        ));
    }

    records.sort_by_key(|record| (record.pid, record.fd, record.sock));
    let unique_sockets = records
        .iter()
        .map(|record| record.sock)
        .collect::<HashSet<_>>()
        .len();
    let processes_with_sockets = records
        .iter()
        .map(|record| record.pid)
        .collect::<HashSet<_>>()
        .len();
    let partial_records = records.iter().filter(|record| !record.complete).count();
    let unsupported_family_records = records
        .iter()
        .filter(|record| !matches!(record.family_raw, AF_UNIX | AF_INET | AF_INET6))
        .count();
    let mut family_counts = BTreeMap::new();
    for record in &records {
        *family_counts.entry(record.family.clone()).or_insert(0) += 1;
    }
    let complete = lsof.complete && unrecoverable_candidates == 0 && partial_records == 0;

    Ok(LinuxSockstatReport {
        source: "active_tasks.files.fdtable.sockfs_inode.socket.sock".to_owned(),
        kernel: kernel.clone(),
        profile: profile.evidence(kernel),
        records_recovered: records.len(),
        records,
        family_counts,
        socket_fd_candidates,
        unique_sockets,
        processes_with_sockets,
        unrecoverable_candidates,
        partial_records,
        unsupported_family_records,
        process_list_complete: lsof.process_list_complete,
        lsof_complete: lsof.complete,
        complete,
        max_fds: lsof.max_fds,
        scope: "仅活动线程组主进程中经过验证的打开 socket FD；未执行 slab 扫描，孤立、已关闭和已释放 socket 不在本命令范围内".to_owned(),
        warnings_suppressed,
        warnings,
    })
}

fn push_socket_warning(
    warnings: &mut Vec<LinuxProcessArtifactWarning>,
    details: &mut usize,
    suppressed: &mut usize,
    warning: LinuxProcessArtifactWarning,
) {
    if *details < MAX_WARNING_DETAILS {
        warnings.push(warning);
        *details += 1;
    } else {
        *suppressed += 1;
    }
}

#[derive(Default)]
struct EndpointEvidence {
    local_address: Option<String>,
    local_port: Option<u16>,
    remote_address: Option<String>,
    remote_port: Option<u16>,
    unix_peer_sock: Option<u64>,
}

fn parse_open_socket(
    space: &LinuxX64AddressSpace<'_>,
    profile: ExactLinuxSocketProfile,
    descriptor: &LinuxLsofRecord,
) -> Result<LinuxSockstatRecord> {
    let inode = descriptor.inode.context("lsof 记录缺少 socket inode")?;
    ensure!(is_kernel_pointer(inode), "socket inode 指针无效");
    let socket_alloc = inode
        .checked_sub(profile.socket_alloc_vfs_inode)
        .context("inode 低于 socket_alloc.vfs_inode 偏移")?;
    let socket = socket_alloc
        .checked_add(profile.socket_alloc_socket)
        .context("socket_alloc.socket 地址溢出")?;
    ensure!(is_kernel_pointer(socket), "socket_alloc.socket 地址无效");

    let private_data = space
        .read_u64(descriptor.file + profile.file_private_data)
        .context("无法读取 file.private_data")?;
    ensure!(
        private_data == socket,
        "file.private_data 未反向指向 socket"
    );
    let socket_file = space
        .read_u64(socket + profile.socket_file)
        .context("无法读取 socket.file")?;
    ensure!(
        socket_file == descriptor.file,
        "socket.file 未反向指向当前 file"
    );
    let sock = space
        .read_u64(socket + profile.socket_sk)
        .context("无法读取 socket.sk")?;
    ensure!(is_kernel_pointer(sock), "socket.sk 指针无效");
    let sock_socket = space
        .read_u64(sock + profile.sock_socket)
        .context("无法读取 sock.sk_socket")?;
    ensure!(sock_socket == socket, "sock.sk_socket 未反向指向 socket");
    let socket_ops = space
        .read_u64(socket + profile.socket_ops)
        .context("无法读取 socket.ops")?;
    ensure!(is_kernel_pointer(socket_ops), "socket.ops 指针无效");

    let socket_type_raw =
        u16::try_from(profile.socket_type.read(space, socket)?).context("socket.type 超出 u16")?;
    let sock_type_raw =
        u16::try_from(profile.sock_type.read(space, sock)?).context("sock.sk_type 超出 u16")?;
    ensure!(
        socket_type_raw != 0 && socket_type_raw <= 10,
        "socket.type 超出合理范围：{socket_type_raw}"
    );
    ensure!(
        socket_type_raw == sock_type_raw,
        "socket.type={socket_type_raw} 与 sock.sk_type={sock_type_raw} 不一致"
    );
    let family_raw = read_u16_le(space, sock + profile.skc_family)?;
    ensure!(
        family_raw < MAX_SOCKET_FAMILY,
        "sock_common.skc_family 超出合理范围：{family_raw}"
    );
    let socket_state_raw = u32::try_from(profile.socket_state.read(space, socket)?)
        .context("socket.state 超出 u32")?;
    ensure!(socket_state_raw <= 4, "socket.state 超出合理范围");
    let sock_state_raw = read_u8(space, sock + profile.skc_state)?;
    let protocol_raw = u16::try_from(profile.sock_protocol.read(space, sock)?)
        .context("sock.sk_protocol 超出 u16")?;
    ensure!(protocol_raw <= 255, "sock.sk_protocol 超出合理范围");

    let mut field_errors = Vec::new();
    let endpoint = match read_endpoint(space, profile, sock, family_raw, socket_type_raw) {
        Ok(endpoint) => endpoint,
        Err(error) => {
            field_errors.push(format!("端点恢复失败：{error:#}"));
            EndpointEvidence::default()
        }
    };
    let bound_device_ifindex = match space.read_i32(sock + profile.skc_bound_dev_if) {
        Ok(index) if index >= 0 => Some(index),
        Ok(index) => {
            field_errors.push(format!("skc_bound_dev_if 为负数：{index}"));
            None
        }
        Err(error) => {
            field_errors.push(format!("无法读取 skc_bound_dev_if：{error:#}"));
            None
        }
    };
    let socket_net_namespace = match read_socket_net_namespace(space, profile, sock) {
        Ok(value) => value,
        Err(error) => {
            field_errors.push(format!("socket net namespace 恢复失败：{error:#}"));
            None
        }
    };
    let task_net_namespace = match read_task_net_namespace(space, profile, descriptor.task) {
        Ok(value) => value,
        Err(error) => {
            field_errors.push(format!("task net namespace 恢复失败：{error:#}"));
            None
        }
    };
    let namespace_status = match (socket_net_namespace, task_net_namespace) {
        (Some(socket), Some(task)) if socket == task => "matched",
        (Some(_), Some(_)) => "different_valid_namespaces",
        (Some(_), None) => "socket_only",
        (None, Some(_)) => "task_only",
        (None, None) => "unavailable",
    }
    .to_owned();

    Ok(LinuxSockstatRecord {
        task: descriptor.task,
        task_hex: descriptor.task_hex.clone(),
        pid: descriptor.pid,
        process_name: descriptor.process_name.clone(),
        fd: descriptor.fd,
        file: descriptor.file,
        file_hex: descriptor.file_hex.clone(),
        inode,
        inode_hex: format_address(inode),
        inode_number: descriptor.inode_number,
        socket,
        socket_hex: format_address(socket),
        sock,
        sock_hex: format_address(sock),
        socket_ops,
        socket_ops_hex: format_address(socket_ops),
        family: socket_family_name(family_raw),
        family_raw,
        socket_type: socket_type_name(socket_type_raw),
        socket_type_raw,
        protocol: protocol_name(family_raw, protocol_raw),
        protocol_raw,
        state: socket_state_name(
            family_raw,
            socket_type_raw,
            socket_state_raw,
            sock_state_raw,
        ),
        socket_state_raw,
        sock_state_raw,
        local_address: endpoint.local_address,
        local_port: endpoint.local_port,
        remote_address: endpoint.remote_address,
        remote_port: endpoint.remote_port,
        bound_device_ifindex,
        unix_peer_sock: endpoint.unix_peer_sock,
        unix_peer_sock_hex: endpoint.unix_peer_sock.map(format_address),
        socket_net_namespace,
        task_net_namespace,
        namespace_status,
        complete: field_errors.is_empty(),
        field_errors,
        validation: "sockfs inode container; file.private_data == socket; socket.file == file; sock.sk_socket == socket; socket.type == sock.sk_type; canonical socket.ops".to_owned(),
    })
}

fn read_endpoint(
    space: &LinuxX64AddressSpace<'_>,
    profile: ExactLinuxSocketProfile,
    sock: u64,
    family: u16,
    socket_type: u16,
) -> Result<EndpointEvidence> {
    match family {
        AF_INET => {
            let mut local = [0u8; 4];
            let mut remote = [0u8; 4];
            space.read_virtual(sock + profile.skc_rcv_saddr, &mut local)?;
            space.read_virtual(sock + profile.skc_daddr, &mut remote)?;
            Ok(EndpointEvidence {
                local_address: Some(Ipv4Addr::from(local).to_string()),
                local_port: (socket_type != 3)
                    .then(|| read_u16_le(space, sock + profile.skc_num))
                    .transpose()?,
                remote_address: Some(Ipv4Addr::from(remote).to_string()),
                remote_port: (socket_type != 3)
                    .then(|| read_u16_be_bytes(space, sock + profile.skc_dport))
                    .transpose()?,
                unix_peer_sock: None,
            })
        }
        AF_INET6 => {
            let mut local = [0u8; 16];
            let mut remote = [0u8; 16];
            space.read_virtual(sock + profile.skc_v6_rcv_saddr, &mut local)?;
            space.read_virtual(sock + profile.skc_v6_daddr, &mut remote)?;
            Ok(EndpointEvidence {
                local_address: Some(Ipv6Addr::from(local).to_string()),
                local_port: (socket_type != 3)
                    .then(|| read_u16_le(space, sock + profile.skc_num))
                    .transpose()?,
                remote_address: Some(Ipv6Addr::from(remote).to_string()),
                remote_port: (socket_type != 3)
                    .then(|| read_u16_be_bytes(space, sock + profile.skc_dport))
                    .transpose()?,
                unix_peer_sock: None,
            })
        }
        AF_UNIX => {
            let local_address = read_unix_name(space, profile, sock)?;
            let peer = space.read_u64(sock + profile.unix_peer)?;
            let unix_peer_sock = if peer == 0 {
                None
            } else {
                ensure!(is_kernel_pointer(peer), "unix_sock.peer 指针无效");
                Some(peer)
            };
            let remote_address = unix_peer_sock
                .map(|peer| read_unix_name(space, profile, peer))
                .transpose()?
                .flatten();
            Ok(EndpointEvidence {
                local_address,
                remote_address,
                unix_peer_sock,
                ..EndpointEvidence::default()
            })
        }
        _ => Ok(EndpointEvidence::default()),
    }
}

fn read_unix_name(
    space: &LinuxX64AddressSpace<'_>,
    profile: ExactLinuxSocketProfile,
    sock: u64,
) -> Result<Option<String>> {
    let address = space.read_u64(sock + profile.unix_addr)?;
    if address == 0 {
        return Ok(None);
    }
    ensure!(is_kernel_pointer(address), "unix_sock.addr 指针无效");
    let length = space.read_i32(address + profile.unix_address_len)?;
    ensure!(length >= 0, "unix_address.len 为负数");
    let length = usize::try_from(length)?;
    let path_offset = usize::try_from(profile.sockaddr_un_sun_path)?;
    if length <= path_offset {
        return Ok(None);
    }
    let path_length = length - path_offset;
    ensure!(
        path_length <= profile.unix_path_capacity,
        "unix_address.len 超出 sockaddr_un.sun_path"
    );
    let name = address + profile.unix_address_name;
    ensure!(
        read_u16_le(space, name)? == AF_UNIX,
        "unix_address.name.sun_family 不是 AF_UNIX"
    );
    let mut bytes = vec![0u8; path_length];
    space.read_virtual(name + profile.sockaddr_un_sun_path, &mut bytes)?;
    if bytes.first() == Some(&0) {
        return Ok(Some(format!("@{}", escape_unix_bytes(&bytes[1..]))));
    }
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    Ok((end > 0).then(|| display_unix_bytes(&bytes[..end])))
}

#[derive(Debug, Clone, Copy)]
struct SocketNamespaceLayout {
    socket_net_field: &'static str,
    net_inum: u64,
    net_inum_field: &'static str,
}

impl SocketNamespaceLayout {
    fn from_isf(isf: &crate::linux_symbols::LinuxIsf) -> Result<Self> {
        // Before possible_net_t/ns_common, these were struct net *skc_net
        // and net.proc_inum. Choose by the ISF types, never by a guessed offset.
        let socket_net_field = if isf
            .field_pointer_target_type("sock_common", "skc_net")
            .is_ok_and(|target| target == "net")
        {
            "skc_net"
        } else {
            "skc_net.net"
        };
        ensure!(
            isf.field_pointer_target_type("sock_common", socket_net_field)? == "net"
                && isf.field_size("sock_common", socket_net_field)? == 8,
            "sock_common 网络命名空间字段不是 64 位 struct net 指针"
        );
        let net_inum_field = if isf.optional_field_offset("net", "ns")?.is_some() {
            "ns.inum"
        } else {
            "proc_inum"
        };
        let (net_inum, width) = isf.field_scalar_layout("net", net_inum_field)?;
        ensure!(width == 4, "网络命名空间 inode 字段不是 32 位整数");
        Ok(Self {
            socket_net_field,
            net_inum,
            net_inum_field,
        })
    }
}

fn read_socket_net_namespace(
    space: &LinuxX64AddressSpace<'_>,
    profile: ExactLinuxSocketProfile,
    sock: u64,
) -> Result<Option<u32>> {
    let net = space.read_u64(sock + profile.skc_net)?;
    read_net_namespace(space, profile, net)
}

fn read_task_net_namespace(
    space: &LinuxX64AddressSpace<'_>,
    profile: ExactLinuxSocketProfile,
    task: u64,
) -> Result<Option<u32>> {
    let nsproxy = space.read_u64(task + profile.task_nsproxy)?;
    if nsproxy == 0 {
        return Ok(None);
    }
    ensure!(is_kernel_pointer(nsproxy), "task_struct.nsproxy 指针无效");
    let net = space.read_u64(nsproxy + profile.nsproxy_net_ns)?;
    read_net_namespace(space, profile, net)
}

fn read_net_namespace(
    space: &LinuxX64AddressSpace<'_>,
    profile: ExactLinuxSocketProfile,
    net: u64,
) -> Result<Option<u32>> {
    if net == 0 {
        return Ok(None);
    }
    ensure!(is_kernel_pointer(net), "struct net 指针无效");
    Ok(Some(space.read_u32(net + profile.net_inum)?))
}

fn read_unsigned(space: &LinuxX64AddressSpace<'_>, address: u64, width: u8) -> Result<u64> {
    let mut bytes = [0u8; 8];
    space.read_virtual(address, &mut bytes[..usize::from(width)])?;
    Ok(u64::from_le_bytes(bytes))
}

fn read_u8(space: &LinuxX64AddressSpace<'_>, address: u64) -> Result<u8> {
    let mut bytes = [0u8; 1];
    space.read_virtual(address, &mut bytes)?;
    Ok(bytes[0])
}

fn read_u16_le(space: &LinuxX64AddressSpace<'_>, address: u64) -> Result<u16> {
    let mut bytes = [0u8; 2];
    space.read_virtual(address, &mut bytes)?;
    Ok(u16::from_le_bytes(bytes))
}

fn read_u16_be_bytes(space: &LinuxX64AddressSpace<'_>, address: u64) -> Result<u16> {
    let mut bytes = [0u8; 2];
    space.read_virtual(address, &mut bytes)?;
    Ok(u16::from_be_bytes(bytes))
}

fn socket_family_name(value: u16) -> String {
    let name = match value {
        0 => "AF_UNSPEC",
        1 => "AF_UNIX",
        2 => "AF_INET",
        3 => "AF_AX25",
        4 => "AF_IPX",
        5 => "AF_APPLETALK",
        6 => "AF_NETROM",
        7 => "AF_BRIDGE",
        8 => "AF_ATMPVC",
        9 => "AF_X25",
        10 => "AF_INET6",
        11 => "AF_ROSE",
        12 => "AF_DECNET",
        13 => "AF_NETBEUI",
        14 => "AF_SECURITY",
        15 => "AF_KEY",
        16 => "AF_NETLINK",
        17 => "AF_PACKET",
        18 => "AF_ASH",
        19 => "AF_ECONET",
        20 => "AF_ATMSVC",
        21 => "AF_RDS",
        22 => "AF_SNA",
        23 => "AF_IRDA",
        24 => "AF_PPPOX",
        25 => "AF_WANPIPE",
        26 => "AF_LLC",
        27 => "AF_IB",
        28 => "AF_MPLS",
        29 => "AF_CAN",
        30 => "AF_TIPC",
        31 => "AF_BLUETOOTH",
        32 => "AF_IUCV",
        33 => "AF_RXRPC",
        34 => "AF_ISDN",
        35 => "AF_PHONET",
        36 => "AF_IEEE802154",
        37 => "AF_CAIF",
        38 => "AF_ALG",
        39 => "AF_NFC",
        40 => "AF_VSOCK",
        41 => "AF_KCM",
        42 => "AF_QIPCRTR",
        43 => "AF_SMC",
        44 => "AF_XDP",
        45 => "AF_MCTP",
        _ => return format!("AF_{value}"),
    };
    name.to_owned()
}

fn socket_type_name(value: u16) -> String {
    match value {
        1 => "STREAM".to_owned(),
        2 => "DGRAM".to_owned(),
        3 => "RAW".to_owned(),
        4 => "RDM".to_owned(),
        5 => "SEQPACKET".to_owned(),
        6 => "DCCP".to_owned(),
        10 => "PACKET".to_owned(),
        _ => format!("TYPE_{value}"),
    }
}

fn protocol_name(family: u16, value: u16) -> Option<String> {
    if family == AF_UNIX {
        return None;
    }
    if !matches!(family, AF_INET | AF_INET6) {
        return Some(format!("PROTOCOL_{value}"));
    }
    Some(
        match value {
            0 => "IP",
            1 => "ICMP",
            2 => "IGMP",
            4 => "IPIP",
            6 => "TCP",
            17 => "UDP",
            33 => "DCCP",
            41 => "IPV6",
            47 => "GRE",
            50 => "ESP",
            51 => "AH",
            58 => "ICMPV6",
            94 => "BEETPH",
            103 => "PIM",
            108 => "COMP",
            132 => "SCTP",
            136 => "UDPLITE",
            255 => "RAW",
            _ => return Some(format!("IPPROTO_{value}")),
        }
        .to_owned(),
    )
}

fn socket_state_name(family: u16, socket_type: u16, socket_state: u32, sock_state: u8) -> String {
    if socket_type == 1 && matches!(family, AF_UNIX | AF_INET | AF_INET6) {
        return match sock_state {
            1 => "ESTABLISHED".to_owned(),
            2 => "SYN_SENT".to_owned(),
            3 => "SYN_RECV".to_owned(),
            4 => "FIN_WAIT1".to_owned(),
            5 => "FIN_WAIT2".to_owned(),
            6 => "TIME_WAIT".to_owned(),
            7 => "CLOSE".to_owned(),
            8 => "CLOSE_WAIT".to_owned(),
            9 => "LAST_ACK".to_owned(),
            10 => "LISTEN".to_owned(),
            11 => "CLOSING".to_owned(),
            12 => "NEW_SYN_RECV".to_owned(),
            _ => format!("TCP_STATE_{sock_state}"),
        };
    }
    match socket_state {
        0 => "FREE".to_owned(),
        1 => "UNCONNECTED".to_owned(),
        2 => "CONNECTING".to_owned(),
        3 => "CONNECTED".to_owned(),
        4 => "DISCONNECTING".to_owned(),
        _ => format!("SOCKET_STATE_{socket_state}"),
    }
}

fn display_unix_bytes(bytes: &[u8]) -> String {
    std::str::from_utf8(bytes)
        .ok()
        .filter(|text| !text.chars().any(char::is_control))
        .map(str::to_owned)
        .unwrap_or_else(|| escape_unix_bytes(bytes))
}

fn escape_unix_bytes(bytes: &[u8]) -> String {
    let mut output = String::new();
    for byte in bytes {
        match byte {
            b' '..=b'~' if *byte != b'\\' => output.push(char::from(*byte)),
            b'\\' => output.push_str("\\\\"),
            _ => output.push_str(&format!("\\x{byte:02x}")),
        }
    }
    output
}

fn format_address(address: u64) -> String {
    format!("{address:#018x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_layout_supports_legacy_pointers_and_named_wrappers() {
        let mut types = serde_json::json!({
            "sock_common": { "size": 112, "fields": {
                "skc_net": { "offset": 48, "type": { "kind": "pointer", "subtype": { "kind": "struct", "name": "net" } } }
            } },
            "net": { "size": 256, "fields": {
                "proc_inum": { "offset": 72, "type": { "kind": "base", "name": "unsigned int" } }
            } }
        });
        let legacy = crate::linux_symbols::test_isf(types.clone());
        let layout = SocketNamespaceLayout::from_isf(&legacy).unwrap();
        assert_eq!(layout.socket_net_field, "skc_net");
        assert_eq!(layout.net_inum, 72);
        assert_eq!(layout.net_inum_field, "proc_inum");

        types["sock_common"]["fields"]["skc_net"]["type"] =
            serde_json::json!({"kind": "struct", "name": "possible_net_t"});
        types["possible_net_t"] = serde_json::json!({"size": 8, "fields": {
            "net": {"offset": 0, "type": {"kind": "pointer", "subtype": {"kind": "struct", "name": "net"}}}
        }});
        types["net"]["fields"] = serde_json::json!({"ns": {"offset": 120, "type": {"kind": "struct", "name": "ns_common"}}});
        types["ns_common"] = serde_json::json!({"size": 24, "fields": {
            "inum": {"offset": 16, "type": {"kind": "base", "name": "unsigned int"}}
        }});
        let wrapped = crate::linux_symbols::test_isf(types.clone());
        let layout = SocketNamespaceLayout::from_isf(&wrapped).unwrap();
        assert_eq!(layout.socket_net_field, "skc_net.net");
        assert_eq!(
            wrapped
                .field_offset("sock_common", layout.socket_net_field)
                .unwrap(),
            48
        );
        assert_eq!(layout.net_inum, 136);
        assert_eq!(layout.net_inum_field, "ns.inum");
        types["ns_common"]["fields"]["inum"]["type"]["name"] = "long unsigned int".into();
        assert!(SocketNamespaceLayout::from_isf(&crate::linux_symbols::test_isf(types)).is_err());
    }

    #[test]
    fn exact_profiles_are_bound_to_full_banners() {
        let old = ExactLinuxSocketProfile::for_banner(UBUNTU_4_13_0_36_XENIAL).unwrap();
        assert_eq!(old.socket_alloc_vfs_inode, 0x30);
        assert_eq!(old.sock_socket, 0x258);
        assert_eq!(old.sock_type.bit_position, 16);

        let middle = ExactLinuxSocketProfile::for_banner(UBUNTU_5_4_0_84_BIONIC).unwrap();
        assert_eq!(middle.task_nsproxy, 0xac8);
        assert_eq!(middle.unix_address_name, 0x0c);

        let new = ExactLinuxSocketProfile::for_banner(UBUNTU_6_8_0_49_NOBLE).unwrap();
        assert_eq!(new.sock_protocol.offset, 0x204);
        assert_eq!(new.sock_protocol.storage_bytes, 2);
        assert_eq!(new.unix_address_name, 0x08);

        assert!(ExactLinuxSocketProfile::for_banner("Linux version 6.8.0-49-generic").is_none());
    }

    #[test]
    fn names_network_constants_without_inventing_unknown_values() {
        assert_eq!(socket_family_name(AF_INET6), "AF_INET6");
        assert_eq!(socket_family_name(46), "AF_46");
        assert_eq!(socket_type_name(1), "STREAM");
        assert_eq!(protocol_name(AF_INET, 6).as_deref(), Some("TCP"));
        assert_eq!(protocol_name(AF_UNIX, 0), None);
        assert_eq!(socket_state_name(AF_INET, 1, 3, 10), "LISTEN");
    }

    #[test]
    fn unix_names_preserve_abstract_and_nonprintable_bytes() {
        assert_eq!(display_unix_bytes(b"/run/test.sock"), "/run/test.sock");
        assert_eq!(escape_unix_bytes(b"dbus\0name"), "dbus\\x00name");
        assert_eq!(escape_unix_bytes(b"a\\b"), "a\\\\b");
    }
}
