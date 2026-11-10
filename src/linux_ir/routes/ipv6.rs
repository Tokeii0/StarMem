use super::*;

#[derive(Clone, Copy, Default)]
struct Constraint {
    mask: u128,
    value: u128,
}
impl Constraint {
    fn branch(mut self, bit: u64, right: bool) -> Self {
        let mask = 1u128 << (127 - bit);
        self.mask |= mask;
        if right {
            self.value |= mask;
        }
        self
    }
    fn matches(self, address: u128) -> bool {
        address & self.mask == self.value
    }
}

#[derive(Clone, Copy, Default)]
struct Path {
    destination: Constraint,
    source: Constraint,
    source_tree: bool,
    destination_length: u64,
}

struct Node {
    address: u64,
    parent: u64,
    minimum_bit: u64,
    root: bool,
    path: Path,
}

impl<M: LinuxKernelMemory> Walker<'_, M> {
    pub(super) fn ipv6(&mut self, table: Table, namespace: u64) -> Result<()> {
        let m = self.m;
        let ty = m.isf().field_pointer_target_type("fib6_node", "leaf")?;
        ensure!(
            matches!(ty, "rt6_info" | "fib6_info"),
            "不支持的 IPv6 FIB 叶节点类型 {ty}"
        );
        let sentinel_name = if ty == "rt6_info" {
            "ip6_null_entry"
        } else {
            "fib6_null_entry"
        };
        let sentinel = pointer(field(m, namespace, "netns_ipv6", sentinel_name)?)?;
        let root = member(m, table.address, "fib6_table", "tb6_root")?;
        let mut stack = vec![Node {
            address: root,
            parent: 0,
            minimum_bit: 0,
            root: true,
            path: Path::default(),
        }];
        let mut seen = HashSet::new();
        let mut routes_seen = HashSet::new();
        while let Some(node) = stack.pop() {
            if !self.step()? {
                break;
            }
            let result = (|| -> Result<()> {
                pointer(node.address)?;
                ensure!(seen.insert(node.address), "IPv6 FIB 节点重复或循环");
                ensure!(
                    field(m, node.address, "fib6_node", "parent")? == node.parent,
                    "IPv6 FIB 父节点不匹配"
                );
                let bit = field(m, node.address, "fib6_node", "fn_bit")?;
                let flags = field(m, node.address, "fib6_node", "fn_flags")?;
                ensure!(bit <= 128 && bit >= node.minimum_bit, "IPv6 FIB 位范围无效");
                ensure!(
                    (flags & 2 != 0) == node.root && (!node.root || bit == 0),
                    "IPv6 FIB 根标记无效"
                );
                // Intermediate leaf pointers are inherited lookup hints. Only RTN_RTINFO
                // nodes own routes; the per-namespace null entry is a sentinel even at root.
                if flags & 4 != 0 {
                    let result = self.ipv6_leaf(table, &node, bit, ty, sentinel, &mut routes_seen);
                    self.note(node.address, result)?;
                }
                for (name, right) in [("right", true), ("left", false), ("subtree", false)] {
                    if !self.running() {
                        break;
                    }
                    let child_result = (|| -> Result<()> {
                        let Some(child) = optional(m, node.address, "fib6_node", name)? else {
                            ensure!(name == "subtree", "IPv6 FIB 缺少 {name} 指针");
                            return Ok(());
                        };
                        if child == 0 {
                            return Ok(());
                        }
                        let mut path = node.path;
                        let is_subtree = name == "subtree";
                        if is_subtree {
                            ensure!(!path.source_tree, "IPv6 来源子树再次嵌套来源子树");
                            path.source_tree = true;
                            path.destination_length = bit;
                        } else {
                            ensure!(bit < 128, "IPv6 /128 节点仍有子分支");
                            if path.source_tree {
                                path.source = path.source.branch(bit, right);
                            } else {
                                path.destination = path.destination.branch(bit, right);
                            }
                        }
                        stack.push(Node {
                            address: child,
                            parent: node.address,
                            minimum_bit: if is_subtree { 0 } else { bit + 1 },
                            root: is_subtree,
                            path,
                        });
                        Ok(())
                    })();
                    self.note(node.address, child_result)?;
                }
                Ok(())
            })();
            self.note(node.address, result)?;
        }
        Ok(())
    }

    fn ipv6_leaf(
        &mut self,
        table: Table,
        node: &Node,
        bit: u64,
        ty: &str,
        sentinel: u64,
        seen: &mut HashSet<u64>,
    ) -> Result<()> {
        let m = self.m;
        let modern = ty == "fib6_info";
        let stem = if modern { "fib6" } else { "rt6i" };
        let mut route = field(m, node.address, "fib6_node", "leaf")?;
        ensure!(route != 0, "IPv6 路由节点的叶指针为空");
        while route != 0 && route != sentinel && self.step()? {
            pointer(route)?;
            ensure!(seen.insert(route), "IPv6 路由链重复或循环");
            // Read the link separately so a broken detail field does not discard later routes.
            let next = if modern {
                field(m, route, ty, "fib6_next")
            } else {
                field(m, member(m, route, ty, "dst")?, "dst_entry", "rt6_next")
            };
            let result = (|| -> Result<()> {
                ensure!(
                    field(m, route, ty, &format!("{stem}_table"))? == table.address,
                    "IPv6 路由指向不同 FIB 表"
                );
                ensure!(
                    field(m, route, ty, &format!("{stem}_node"))? == node.address,
                    "IPv6 路由节点回链不匹配"
                );
                let (destination, prefix) = key(m, member(m, route, ty, &format!("{stem}_dst"))?)?;
                let (source, source_prefix) =
                    key(m, member(m, route, ty, &format!("{stem}_src"))?)?;
                ensure!(
                    node.path.destination.matches(destination) && node.path.source.matches(source),
                    "IPv6 路由前缀与树路径不匹配"
                );
                if node.path.source_tree {
                    ensure!(
                        prefix == node.path.destination_length && source_prefix == bit,
                        "IPv6 来源子树与路由前缀长度不匹配"
                    );
                } else {
                    ensure!(
                        prefix == bit && source_prefix == 0,
                        "IPv6 FIB 节点与路由前缀长度不匹配"
                    );
                }
                let mut row = base_row(
                    table,
                    route,
                    node.address,
                    "IPv6",
                    Ipv6Addr::from(destination).to_string(),
                    prefix,
                );
                row["source_prefix"] = json!(format!("{}/{source_prefix}", Ipv6Addr::from(source)));
                row["fib_layout"] = json!(ty);
                let details = (|| -> Result<()> {
                    for (suffix, key) in [
                        ("flags", "flags"),
                        ("metric", "metric"),
                        ("protocol", "protocol"),
                        ("nsiblings", "sibling_count"),
                    ] {
                        row[key] = json!(field(m, route, ty, &format!("{stem}_{suffix}"))?);
                    }
                    if let Some(value) = optional(m, route, ty, &format!("{stem}_type"))? {
                        row["route_type"] = json!(value);
                    }
                    let preferred = member(m, route, ty, &format!("{stem}_prefsrc"))?;
                    row["preferred_source"] = json!(
                        Ipv6Addr::from(ipv6_address(m, member(m, preferred, "rt6key", "addr")?)?)
                            .to_string()
                    );
                    self.ipv6_nexthops(table, route, modern, &mut row)
                })();
                self.detail(&mut row, details)?;
                self.report.push(row);
                Ok(())
            })();
            self.note(route, result)?;
            match next {
                Ok(next) => route = next,
                Err(error) => {
                    self.note(route, Err(error))?;
                    break;
                }
            }
        }
        Ok(())
    }
}

fn key(m: &impl LinuxKernelMemory, address: u64) -> Result<(u128, u64)> {
    let prefix = field(m, address, "rt6key", "plen")?;
    let address = ipv6_address(m, member(m, address, "rt6key", "addr")?)?;
    ensure!(prefix <= 128, "IPv6 前缀长度无效");
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    ensure!(address & !mask == 0, "IPv6 路由不是规范前缀");
    Ok((address, prefix))
}
