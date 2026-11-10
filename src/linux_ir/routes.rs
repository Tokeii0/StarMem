//! Read registered IPv4/IPv6 FIB routes. All object offsets come from the exact ISF.
//! Runtime trees are bounded independently of the output count; cache exceptions and
//! policy-rule evaluation are outside this snapshot enumeration.
use super::*;
use std::cell::Cell;
use std::net::{Ipv4Addr, Ipv6Addr};

mod ipv6;
mod nexthops;

const MAX_WORK: usize = 1_000_000;

struct BudgetMemory<'a, M> {
    inner: &'a M,
    cancel: &'a CancellationToken,
    remaining: Cell<u64>,
    exhausted: Cell<bool>,
}

impl<M: LinuxKernelMemory> LinuxKernelMemory for BudgetMemory<'_, M> {
    fn read_virtual(&self, address: u64, bytes: &mut [u8]) -> Result<()> {
        self.cancel.check_cancelled()?;
        let Some(left) = self.remaining.get().checked_sub(bytes.len() as u64) else {
            self.exhausted.set(true);
            anyhow::bail!("路由读取达到 --max-bytes 总预算");
        };
        self.remaining.set(left);
        self.inner.read_virtual(address, bytes)
    }
    fn translate(&self, address: u64) -> Result<u64> {
        self.inner.translate(address)
    }
    fn isf(&self) -> &LinuxIsf {
        self.inner.isf()
    }
    fn kernel_slide(&self) -> u64 {
        self.inner.kernel_slide()
    }
    fn source_path(&self) -> Option<&std::path::Path> {
        self.inner.source_path()
    }
}

pub(super) fn analyze(
    memory: &impl LinuxKernelMemory,
    options: &LinuxIrOptions,
    cancel: &CancellationToken,
    report: &mut LinuxIrReport,
) -> Result<()> {
    let m = BudgetMemory {
        inner: memory,
        cancel,
        remaining: Cell::new(options.max_bytes),
        exhausted: Cell::new(false),
    };
    report.scope = "已登记网络 namespace 的 IPv4/IPv6 FIB 路由（含旧内核树内缓存条目）；不含策略规则求值、组播表、独立缓存例外或已脱链对象；不模拟数据包选路与封装".into();
    let nets = list(
        &m,
        m.runtime_symbol("net_namespace_list")?,
        m.isf().field_offset("net", "list")?,
        options.limit.min(MAX_WORK),
        cancel,
        report,
    )?;
    ensure!(!nets.is_empty(), "没有可核对的已登记网络 namespace");
    let mut walker = Walker {
        m: &m,
        cancel,
        report,
        work_left: MAX_WORK,
        checked_families: 0,
    };
    for net in nets {
        if !walker.running() {
            break;
        }
        let id = member(&m, net, "net", "ns").and_then(|ns| field(&m, ns, "ns_common", "inum"));
        if let Err(error) = &id {
            walker.warn(format!("namespace {net:#x} 标识不可读：{error:#}"));
        }
        for family in [4, 6] {
            if !walker.running() {
                break;
            }
            let result = walker.family(net, id.as_ref().ok().copied(), family);
            walker.note(net, result)?;
        }
    }
    cancel.check_cancelled()?;
    if m.exhausted.get() {
        walker
            .report
            .warn("路由读取达到 --max-bytes 总预算，剩余范围尚未核对");
    }
    if walker.checked_families == 0 && walker.report.records.is_empty() {
        walker
            .report
            .unavailable("没有成功读取任何 namespace 的 FIB 表范围");
    }
    walker.report.scope.push_str(&format!(
        "；已读取 {} 个地址族表范围，请求读取 {} / {} 字节",
        walker.checked_families,
        options.max_bytes - m.remaining.get(),
        options.max_bytes
    ));
    Ok(())
}

struct Walker<'a, M> {
    m: &'a BudgetMemory<'a, M>,
    cancel: &'a CancellationToken,
    report: &'a mut LinuxIrReport,
    work_left: usize,
    checked_families: usize,
}

#[derive(Clone, Copy)]
struct Table {
    net: u64,
    net_id: Option<u64>,
    address: u64,
    id: u64,
}

impl<M: LinuxKernelMemory> Walker<'_, M> {
    fn running(&self) -> bool {
        !self.m.exhausted.get() && !self.report.limit_reached
    }

    fn warn(&mut self, message: String) {
        // Reserve space for terminal budget/coverage notices even after many bad slots.
        if self.report.warnings.len() < 120 {
            self.report.warn(message);
        } else {
            self.report.complete = false;
        }
    }

    fn step(&mut self) -> Result<bool> {
        self.cancel.check_cancelled()?;
        if !self.running() {
            return Ok(false);
        }
        if self.work_left == 0 {
            self.report.limit_reached = true;
            self.report
                .warn(format!("路由遍历达到 {MAX_WORK} 个节点/指针槽上限"));
            return Ok(false);
        }
        self.work_left -= 1;
        Ok(true)
    }

    fn note(&mut self, address: u64, result: Result<()>) -> Result<()> {
        if let Err(error) = result {
            if crate::cancellation::is_cancellation_error(&error) {
                return Err(error);
            }
            self.warn(format!("对象 {address:#x}：{error:#}"));
        }
        Ok(())
    }

    fn detail(&mut self, row: &mut Value, result: Result<()>) -> Result<()> {
        if let Err(error) = result {
            if crate::cancellation::is_cancellation_error(&error) {
                return Err(error);
            }
            row["details_complete"] = json!(false);
            row["detail_error"] = json!(format!("{error:#}"));
            self.warn(format!(
                "路由 {} 详情不完整：{error:#}",
                row["route_address"]
            ));
        }
        Ok(())
    }

    fn family(&mut self, net: u64, net_id: Option<u64>, family: u8) -> Result<()> {
        let m = self.m;
        let (name, ty, rule_field, table_ty, link, id_field) = if family == 4 {
            (
                "ipv4",
                "netns_ipv4",
                "rules_ops",
                "fib_table",
                "tb_hlist",
                "tb_id",
            )
        } else {
            (
                "ipv6",
                "netns_ipv6",
                "fib6_rules_ops",
                "fib6_table",
                "tb6_hlist",
                "tb6_id",
            )
        };
        // These members are compiled under the same MULTIPLE_TABLES guards as the
        // hash-size constants. Never infer the count from readable memory after an array.
        if m.isf().optional_field_offset("net", name)?.is_none() {
            return Ok(());
        }
        let multiple = m.isf().optional_field_offset(ty, rule_field)?.is_some();
        let count = if multiple {
            256
        } else if family == 4 {
            2
        } else {
            1
        };
        let namespace = member(m, net, "net", name)?;
        let hash = pointer(field(m, namespace, ty, "fib_table_hash")?)?;
        let head_size = m.isf().type_size("hlist_head")?;
        ensure!(head_size == 8, "不支持的 x64 hlist_head 布局");
        let offset = m.isf().field_offset(table_ty, link)?;
        let mut seen = HashSet::new();
        let mut readable_buckets = 0;
        for bucket in 0..count {
            if !self.step()? {
                break;
            }
            let head = add(hash, bucket * head_size)?;
            let entries = self.hlist(head, offset);
            match entries {
                Err(error) => self.note(head, Err(error))?,
                Ok(entries) => {
                    readable_buckets += 1;
                    for table in entries {
                        if !self.running() {
                            break;
                        }
                        let read = (|| -> Result<()> {
                            ensure!(seen.insert(table), "FIB 表重复出现在哈希桶中");
                            let id = field(m, table, table_ty, id_field)?;
                            ensure!(
                                id > 0 && id <= u32::MAX as u64 && id & (count - 1) == bucket,
                                "IPv{family} FIB 表号与所属哈希桶不匹配"
                            );
                            let table = Table {
                                net,
                                net_id,
                                address: table,
                                id,
                            };
                            if family == 4 {
                                self.ipv4(table)
                            } else {
                                self.ipv6(table, namespace)
                            }
                        })();
                        self.note(table, read)?;
                    }
                }
            }
        }
        if readable_buckets > 0 {
            self.checked_families += 1;
        }
        Ok(())
    }

    /// Return the validated prefix; a damaged next node cannot erase earlier objects.
    fn hlist(&mut self, head: u64, offset: u64) -> Result<Vec<u64>> {
        let m = self.m;
        let mut previous_slot = member(m, head, "hlist_head", "first")?;
        let mut node = number(m, previous_slot, 8)?;
        let mut seen = HashSet::new();
        let mut output = Vec::new();
        while node != 0 && self.step()? {
            let read = (|| -> Result<()> {
                pointer(node)?;
                ensure!(seen.insert(node), "hlist 出现循环");
                ensure!(
                    field(m, node, "hlist_node", "pprev")? == previous_slot,
                    "hlist 回链不匹配"
                );
                output.push(pointer(
                    node.checked_sub(offset).context("hlist 容器地址下溢")?,
                )?);
                previous_slot = member(m, node, "hlist_node", "next")?;
                node = number(m, previous_slot, 8)?;
                Ok(())
            })();
            if read.is_err() {
                self.note(node, read)?;
                break;
            }
        }
        Ok(output)
    }

    fn ipv4(&mut self, table: Table) -> Result<()> {
        let m = self.m;
        let trie = pointer(field(m, table.address, "fib_table", "tb_data")?)?;
        ensure!(
            m.isf().field_array_count("trie", "kv")? == 1,
            "不支持的 IPv4 trie 根布局"
        );
        m.isf().field_array_count("key_vector", "tnode")?;
        let root = member(m, trie, "trie", "kv")?;
        ensure!(
            field(m, root, "key_vector", "pos")? == 32
                && field(m, root, "key_vector", "bits")? == 0
                && field(m, root, "key_vector", "key")? == 0,
            "IPv4 trie 根标记无效"
        );
        let mut stack = vec![V4Step::Children {
            node: root,
            key: 0,
            pos: 32,
            index: 0,
            count: 1,
        }];
        let mut seen = HashSet::new();
        while let Some(step) = stack.pop() {
            if !self.step()? {
                break;
            }
            let address = step.address();
            let result = (|| -> Result<()> {
                match step {
                    V4Step::Children {
                        node,
                        key,
                        pos,
                        index,
                        count,
                    } => {
                        // Resume one slot at a time: a corrupt bits field never allocates 2^bits pointers.
                        if index + 1 < count {
                            stack.push(V4Step::Children {
                                node,
                                key,
                                pos,
                                index: index + 1,
                                count,
                            });
                        }
                        let slot = add(member(m, node, "key_vector", "tnode")?, index * 8)?;
                        let child = number(m, slot, 8)?;
                        if child != 0 {
                            stack.push(V4Step::Node {
                                node: child,
                                parent: node,
                                parent_key: key,
                                parent_pos: pos,
                                index,
                            });
                        }
                    }
                    V4Step::Node {
                        node,
                        parent,
                        parent_key,
                        parent_pos,
                        index,
                    } => {
                        pointer(node)?;
                        ensure!(seen.insert(node), "IPv4 trie 节点重复或循环");
                        let owner = node
                            .checked_sub(m.isf().field_offset("tnode", "kv")?)
                            .context("tnode 容器地址下溢")?;
                        ensure!(
                            field(m, owner, "tnode", "parent")? == parent,
                            "IPv4 trie 父节点不匹配"
                        );
                        let key = field(m, node, "key_vector", "key")?;
                        let pos = field(m, node, "key_vector", "pos")?;
                        let bits = field(m, node, "key_vector", "bits")?;
                        ensure!(
                            key <= u32::MAX as u64
                                && pos < 32
                                && bits <= 32
                                && pos + bits <= parent_pos,
                            "IPv4 trie 键或位范围无效"
                        );
                        ensure!(
                            (key ^ parent_key) >> parent_pos == index,
                            "IPv4 trie 键与父节点槽位不匹配"
                        );
                        if bits == 0 {
                            ensure!(pos == 0, "IPv4 叶节点位置无效");
                            self.ipv4_leaf(table, node, key as u32)?;
                        } else {
                            ensure!(
                                key & ((1u64 << (pos + bits)) - 1) == 0,
                                "IPv4 分支键不是规范前缀"
                            );
                            stack.push(V4Step::Children {
                                node,
                                key,
                                pos,
                                index: 0,
                                count: 1u64 << bits,
                            });
                        }
                    }
                }
                Ok(())
            })();
            self.note(address, result)?;
        }
        Ok(())
    }

    fn ipv4_leaf(&mut self, table: Table, leaf: u64, key: u32) -> Result<()> {
        let m = self.m;
        for alias in self.hlist(
            member(m, leaf, "key_vector", "leaf")?,
            m.isf().field_offset("fib_alias", "fa_list")?,
        )? {
            if !self.running() {
                break;
            }
            let result = (|| -> Result<()> {
                // Main/local tables may share tb_data. Only the alias determines its table.
                if field(m, alias, "fib_alias", "tb_id")? != table.id {
                    return Ok(());
                }
                let suffix = field(m, alias, "fib_alias", "fa_slen")?;
                ensure!(
                    suffix <= 32 && u64::from(key) & ((1u64 << suffix) - 1) == 0,
                    "IPv4 路由前缀无效"
                );
                let prefix = 32 - suffix;
                let destination = Ipv4Addr::from(key).to_string();
                let mut row = base_row(table, alias, leaf, "IPv4", destination, prefix);
                row["route_type"] = json!(field(m, alias, "fib_alias", "fa_type")?);
                for field_name in ["fa_tos", "fa_dscp"] {
                    if let Some(value) = optional(m, alias, "fib_alias", field_name)? {
                        row[field_name] = json!(value);
                    }
                }
                let details = (|| -> Result<()> {
                    let info = field(m, alias, "fib_alias", "fa_info")?;
                    row["fib_info"] = json!(info);
                    self.ipv4_info(table, info, &mut row)
                })();
                self.detail(&mut row, details)?;
                self.report.push(row);
                Ok(())
            })();
            self.note(alias, result)?;
        }
        Ok(())
    }

    fn ipv4_info(&mut self, table: Table, info: u64, row: &mut Value) -> Result<()> {
        let m = self.m;
        pointer(info)?;
        ensure!(
            field(m, info, "fib_info", "fib_net")? == table.net,
            "fib_info 属于不同网络 namespace"
        );
        if let Some(id) = optional(m, info, "fib_info", "fib_tb_id")? {
            ensure!(id == table.id, "fib_info 表号与路由不匹配");
        }
        for (name, key) in [
            ("fib_protocol", "protocol"),
            ("fib_scope", "route_scope"),
            ("fib_priority", "metric"),
            ("fib_flags", "flags"),
            ("fib_dead", "fib_dead"),
        ] {
            row[key] = json!(field(m, info, "fib_info", name)?);
        }
        row["preferred_source"] = json!(ipv4_address(
            m,
            member(m, info, "fib_info", "fib_prefsrc")?
        )?);
        self.ipv4_nexthops(table, info, row)
    }
}

enum V4Step {
    Children {
        node: u64,
        key: u64,
        pos: u64,
        index: u64,
        count: u64,
    },
    Node {
        node: u64,
        parent: u64,
        parent_key: u64,
        parent_pos: u64,
        index: u64,
    },
}
impl V4Step {
    fn address(&self) -> u64 {
        match self {
            Self::Children { node, .. } | Self::Node { node, .. } => *node,
        }
    }
}

fn optional(m: &impl LinuxKernelMemory, object: u64, ty: &str, name: &str) -> Result<Option<u64>> {
    m.isf()
        .optional_field_offset(ty, name)?
        .map(|_| field(m, object, ty, name))
        .transpose()
}
fn ipv4_address(m: &impl LinuxKernelMemory, address: u64) -> Result<String> {
    let mut bytes = [0; 4];
    m.read_virtual(address, &mut bytes)?;
    Ok(Ipv4Addr::from(bytes).to_string())
}
fn ipv6_address(m: &impl LinuxKernelMemory, address: u64) -> Result<u128> {
    let mut bytes = [0; 16];
    m.read_virtual(address, &mut bytes)?;
    Ok(u128::from_be_bytes(bytes))
}
fn base_row(
    table: Table,
    route: u64,
    node: u64,
    family: &str,
    destination: String,
    prefix: u64,
) -> Value {
    json!({"family":family,"destination":destination,"prefix_length":prefix,
        "destination_prefix":format!("{destination}/{prefix}"),"net_namespace":table.net,"net_ns_id":table.net_id,
        "table_address":table.address,"table_id":table.id,"route_address":route,"fib_node":node,
        "details_complete":true,"nexthops":[],"basis":"registered_namespace_table_tree_and_route_links"})
}
