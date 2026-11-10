use super::*;

impl<M: LinuxKernelMemory> Walker<'_, M> {
    pub(super) fn ipv4_nexthops(&mut self, table: Table, info: u64, row: &mut Value) -> Result<()> {
        let m = self.m;
        if let Some(nh) = optional(m, info, "fib_info", "nh")?.filter(|nh| *nh != 0) {
            return self.nexthop_object(table, nh, row);
        }
        let count = field(m, info, "fib_info", "fib_nhs")?;
        ensure!(count <= MAX_WORK as u64, "IPv4 下一跳数量无效");
        // fib_nh_is_v6 describes IPv6 gateway use, not a different array element type.
        let ty = "fib_nh";
        let size = m.isf().type_size(ty)?;
        ensure!(size > 0, "下一跳结构大小无效");
        m.isf().field_array_count("fib_info", "fib_nh")?;
        let array = member(m, info, "fib_info", "fib_nh")?;
        row["nexthop_count"] = json!(count);
        for index in 0..count {
            if !self.step()? {
                truncated(row);
                break;
            }
            let nh = add(
                array,
                index.checked_mul(size).context("下一跳数组偏移溢出")?,
            )?;
            let mut hop = json!({"nexthop_address":nh,"index":index,"complete":true});
            let result = (|| -> Result<()> {
                ensure!(field(m, nh, ty, "nh_parent")? == info, "fib_nh 归属不匹配");
                if m.isf().optional_field_offset(ty, "nh_common")?.is_some() {
                    self.common_hop(table, member(m, nh, ty, "nh_common")?, &mut hop)
                } else {
                    let gateway = ipv4_address(m, member(m, nh, ty, "nh_gw")?)?;
                    hop["gateway"] = if gateway == "0.0.0.0" {
                        Value::Null
                    } else {
                        json!(gateway)
                    };
                    hop["gateway_family"] = json!(if gateway == "0.0.0.0" {
                        "direct"
                    } else {
                        "IPv4"
                    });
                    hop["flags"] = json!(field(m, nh, ty, "nh_flags")?);
                    hop["scope"] = json!(field(m, nh, ty, "nh_scope")?);
                    hop["weight"] = json!(optional(m, nh, ty, "nh_weight")?);
                    self.device(
                        table,
                        field(m, nh, ty, "nh_dev")?,
                        Some(field(m, nh, ty, "nh_oif")?),
                        &mut hop,
                    )
                }
            })();
            self.append_hop(row, hop, result)?;
        }
        summarize(row);
        Ok(())
    }

    pub(super) fn ipv6_nexthops(
        &mut self,
        table: Table,
        route: u64,
        modern: bool,
        row: &mut Value,
    ) -> Result<()> {
        let m = self.m;
        if modern {
            row["expires_jiffies"] = json!(field(m, route, "fib6_info", "expires")?);
            if let Some(nh) = optional(m, route, "fib6_info", "nh")?.filter(|nh| *nh != 0) {
                return self.nexthop_object(table, nh, row);
            }
        }
        let nh = if modern {
            m.isf().field_array_count("fib6_info", "fib6_nh")?;
            member(m, route, "fib6_info", "fib6_nh")?
        } else {
            member(m, route, "rt6_info", "dst")?
        };
        row["nexthop_count"] = json!(1);
        let mut hop = json!({"nexthop_address":nh,"index":0,"complete":true});
        let result = if modern {
            self.common_hop(table, member(m, nh, "fib6_nh", "nh_common")?, &mut hop)
        } else {
            (|| -> Result<()> {
                row["expires_jiffies"] = json!(field(m, nh, "dst_entry", "expires")?);
                let gateway = ipv6_address(m, member(m, route, "rt6_info", "rt6i_gateway")?)?;
                let has_gateway = field(m, route, "rt6_info", "rt6i_flags")? & 2 != 0;
                hop["gateway"] = if has_gateway {
                    json!(Ipv6Addr::from(gateway).to_string())
                } else {
                    Value::Null
                };
                hop["gateway_family"] = json!(if has_gateway { "IPv6" } else { "direct" });
                self.device(table, field(m, nh, "dst_entry", "dev")?, None, &mut hop)
            })()
        };
        self.append_hop(row, hop, result)?;
        summarize(row);
        Ok(())
    }

    fn common_hop(&self, table: Table, nh: u64, row: &mut Value) -> Result<()> {
        let m = self.m;
        let family = field(m, nh, "fib_nh_common", "nhc_family")?;
        ensure!(matches!(family, 2 | 10), "下一跳地址族无效：{family}");
        row["family"] = json!(if family == 2 { "IPv4" } else { "IPv6" });
        let gateway_family = field(m, nh, "fib_nh_common", "nhc_gw_family")?;
        // The named union starts at its ISF offset; all union members start at zero.
        let gateway = member(m, nh, "fib_nh_common", "nhc_gw")?;
        row["gateway_family"] = json!(match gateway_family {
            0 => "direct",
            2 => "IPv4",
            10 => "IPv6",
            _ => anyhow::bail!("下一跳网关地址族无效"),
        });
        row["gateway"] = match gateway_family {
            0 => Value::Null,
            2 => json!(ipv4_address(m, gateway)?),
            _ => json!(Ipv6Addr::from(ipv6_address(m, gateway)?).to_string()),
        };
        row["flags"] = json!(field(m, nh, "fib_nh_common", "nhc_flags")?);
        row["scope"] = json!(field(m, nh, "fib_nh_common", "nhc_scope")?);
        row["weight"] = json!(optional(m, nh, "fib_nh_common", "nhc_weight")?);
        row["encapsulation_address"] = json!(optional(m, nh, "fib_nh_common", "nhc_lwtstate")?);
        self.device(
            table,
            field(m, nh, "fib_nh_common", "nhc_dev")?,
            Some(field(m, nh, "fib_nh_common", "nhc_oif")?),
            row,
        )
    }

    fn device(&self, table: Table, device: u64, index: Option<u64>, row: &mut Value) -> Result<()> {
        let m = self.m;
        row["device"] = json!(device);
        if device == 0 {
            return Ok(());
        }
        pointer(device)?;
        let owner = member(m, device, "net_device", "nd_net")?;
        if let Some(net) = optional(m, owner, "possible_net_t", "net")? {
            ensure!(net == table.net, "下一跳设备属于不同网络 namespace");
        } else {
            ensure!(
                m.isf().type_size("possible_net_t")? == 0
                    && table.net == m.runtime_symbol("init_net")?,
                "无法核对下一跳设备的 namespace"
            );
        }
        let actual_index = field(m, device, "net_device", "ifindex")?;
        ensure!(
            actual_index > 0 && actual_index <= i32::MAX as u64,
            "设备 ifindex 无效"
        );
        if let Some(index) = index.filter(|index| *index != 0) {
            ensure!(index == actual_index, "下一跳 ifindex 与设备不匹配");
        }
        row["ifindex"] = json!(actual_index);
        row["interface"] = json!(inline_string(m, device, "net_device", "name")?);
        Ok(())
    }

    fn single_object(&self, table: Table, object: u64, row: &mut Value) -> Result<()> {
        let m = self.m;
        pointer(object)?;
        ensure!(
            field(m, object, "nexthop", "net")? == table.net,
            "nexthop 属于不同 namespace"
        );
        ensure!(
            field(m, object, "nexthop", "is_group")? == 0,
            "不支持嵌套 nexthop 组"
        );
        row["nexthop_id"] = json!(field(m, object, "nexthop", "id")?);
        let info = pointer(field(m, object, "nexthop", "nh_info")?)?;
        ensure!(
            field(m, info, "nh_info", "nh_parent")? == object,
            "nh_info 归属不匹配"
        );
        row["reject"] = json!(field(m, info, "nh_info", "reject_nh")? != 0);
        row["nh_info"] = json!(info);
        self.common_hop(table, member(m, info, "nh_info", "fib_nhc")?, row)
    }

    fn nexthop_object(&mut self, table: Table, object: u64, row: &mut Value) -> Result<()> {
        let m = self.m;
        pointer(object)?;
        ensure!(
            field(m, object, "nexthop", "net")? == table.net,
            "nexthop 属于不同 namespace"
        );
        row["nexthop_object"] = json!(object);
        row["nexthop_id"] = json!(field(m, object, "nexthop", "id")?);
        if field(m, object, "nexthop", "is_group")? == 0 {
            row["nexthop_count"] = json!(1);
            let mut hop = json!({"nexthop_address":object,"index":0,"complete":true});
            let result = self.single_object(table, object, &mut hop);
            self.append_hop(row, hop, result)?;
        } else {
            let group = pointer(field(m, object, "nexthop", "nh_grp")?)?;
            let count = field(m, group, "nh_group", "num_nh")?;
            ensure!(count > 0 && count <= MAX_WORK as u64, "nexthop 组数量无效");
            row["nexthop_count"] = json!(count);
            row["nexthop_group"] = json!(group);
            row["resilient_group"] = json!(optional(m, group, "nh_group", "resilient")?);
            m.isf().field_array_count("nh_group", "nh_entries")?;
            let array = member(m, group, "nh_group", "nh_entries")?;
            let size = m.isf().type_size("nh_grp_entry")?;
            ensure!(size > 0, "nexthop 组元素大小无效");
            for index in 0..count {
                if !self.step()? {
                    truncated(row);
                    break;
                }
                let entry = add(
                    array,
                    index.checked_mul(size).context("nexthop 组偏移溢出")?,
                )?;
                let mut hop = json!({"group_entry":entry,"index":index,"complete":true});
                let result = (|| -> Result<()> {
                    ensure!(
                        field(m, entry, "nh_grp_entry", "nh_parent")? == object,
                        "nexthop 组元素归属不匹配"
                    );
                    let child = pointer(field(m, entry, "nh_grp_entry", "nh")?)?;
                    hop["nexthop_address"] = json!(child);
                    self.single_object(table, child, &mut hop)?;
                    hop["weight"] = json!(field(m, entry, "nh_grp_entry", "weight")?);
                    Ok(())
                })();
                self.append_hop(row, hop, result)?;
            }
        }
        summarize(row);
        Ok(())
    }

    fn append_hop(&mut self, row: &mut Value, mut hop: Value, result: Result<()>) -> Result<()> {
        if let Err(error) = result {
            if crate::cancellation::is_cancellation_error(&error) {
                return Err(error);
            }
            hop["complete"] = json!(false);
            hop["error"] = json!(format!("{error:#}"));
            row["details_complete"] = json!(false);
            self.warn(format!(
                "路由 {} 下一跳不完整：{error:#}",
                row["route_address"]
            ));
        }
        row["nexthops"]
            .as_array_mut()
            .context("路由下一跳数组无效")?
            .push(hop);
        Ok(())
    }
}

fn truncated(row: &mut Value) {
    row["details_complete"] = json!(false);
    row["nexthops_truncated"] = json!(true);
}
fn summarize(row: &mut Value) {
    for (key, out) in [("gateway", "gateways"), ("interface", "interfaces")] {
        let mut values = Vec::new();
        for hop in row["nexthops"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|hop| hop["complete"] == true)
        {
            if let Some(value) = hop[key].as_str().filter(|value| !value.is_empty())
                && !values.contains(&value)
            {
                values.push(value);
            }
        }
        row[out] = json!(values.join("; "));
    }
}
