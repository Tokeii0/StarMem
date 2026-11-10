use super::*;
use std::net::Ipv6Addr;

const K: u64 = 0xffff800100000000;
const HEAD: u64 = K + 0x100;
const NET: u64 = K + 0x1000;
const HASH4: u64 = K + 0x3000;
const HASH6: u64 = K + 0x4000;
const TABLE4: u64 = K + 0x10000;
const TRIE: u64 = K + 0x12000;
const LEAF4: u64 = K + 0x13008;
const ALIAS: u64 = K + 0x14000;
const INFO: u64 = K + 0x15000;
const DEV: u64 = K + 0x16000;
const TABLE6: u64 = K + 0x20000;
const ROOT6: u64 = TABLE6 + 24;
const NODE6: u64 = K + 0x21000;
const ROUTE6: u64 = K + 0x22000;
const NULL6: u64 = K + 0x23000;

fn scalar(offset: u64, name: &str) -> Value {
    json!({"offset":offset,"type":{"kind":"base","name":name}})
}
fn ptr(offset: u64, name: &str) -> Value {
    json!({"offset":offset,"type":{"kind":"pointer","subtype":{"kind":"struct","name":name}}})
}
fn embedded(offset: u64, name: &str) -> Value {
    json!({"offset":offset,"type":{"kind":"struct","name":name}})
}
fn array(offset: u64, count: u64, name: &str) -> Value {
    json!({"offset":offset,"type":{"kind":"array","count":count,"subtype":{"kind":if name == "char" {"base"} else {"struct"},"name":name}}})
}
fn ty(size: u64, fields: Value) -> Value {
    json!({"size":size,"fields":fields})
}
fn zero(m: &mut Memory, address: u64, size: usize) {
    m.put(address, &vec![0; size]);
}
fn word(m: &mut Memory, address: u64, value: u32) {
    m.put(address, &value.to_le_bytes());
}
fn ip6(m: &mut Memory, address: u64, text: &str) {
    m.put(address, &text.parse::<Ipv6Addr>().unwrap().octets());
}
fn route_options() -> LinuxIrOptions {
    LinuxIrOptions {
        module: "routes".into(),
        ..Default::default()
    }
}
fn run(m: &impl LinuxKernelMemory) -> LinuxIrReport {
    run_kernel(m, &route_options(), &CancellationToken::default()).unwrap()
}

fn fixture(modern: bool, multiple: bool) -> Memory {
    let mut types = json!({
        "list_head":ty(16,json!({"next":ptr(0,"list_head"),"prev":ptr(8,"list_head")})),
        "hlist_head":ty(8,json!({"first":ptr(0,"hlist_node")})),
        "hlist_node":ty(16,json!({"next":ptr(0,"hlist_node"),"pprev":u64_field(8)})),
        "ns_common":ty(8,json!({"inum":u64_field(0)})),
        "possible_net_t":ty(8,json!({"net":ptr(0,"net")})),
        "net":ty(256,json!({"ns":embedded(0,"ns_common"),"list":embedded(16,"list_head"),"ipv4":embedded(128,"netns_ipv4"),"ipv6":embedded(192,"netns_ipv6")})),
        "netns_ipv4":ty(16,json!({"fib_table_hash":ptr(0,"hlist_head")})),
        "netns_ipv6":ty(32,json!({"fib_table_hash":ptr(0,"hlist_head"),if modern {"fib6_null_entry"} else {"ip6_null_entry"}:ptr(8,if modern {"fib6_info"} else {"rt6_info"})})),
        "fib_table":ty(32,json!({"tb_hlist":embedded(0,"hlist_node"),"tb_id":u64_field(16),"tb_data":u64_field(24)})),
        "trie":ty(16,json!({"kv":array(0,1,"key_vector")})),
        "tnode":ty(24,json!({"parent":ptr(0,"key_vector"),"kv":array(8,1,"key_vector")})),
        "key_vector":ty(16,json!({"key":scalar(0,"unsigned int"),"pos":scalar(4,"char"),"bits":scalar(5,"char"),"leaf":embedded(8,"hlist_head"),"tnode":array(8,0,"key_vector")})),
        "fib_alias":ty(32,json!({"fa_list":embedded(0,"hlist_node"),"fa_info":ptr(16,"fib_info"),"fa_slen":scalar(24,"char"),"fa_type":scalar(25,"char"),"fa_tos":scalar(26,"char"),"tb_id":scalar(28,"unsigned int")})),
        "fib_info":ty(88,json!({"fib_net":ptr(0,"net"),"fib_tb_id":u64_field(8),"fib_flags":u64_field(16),"fib_dead":u64_field(24),"fib_protocol":u64_field(32),"fib_scope":u64_field(40),"fib_priority":u64_field(48),"fib_prefsrc":array(56,4,"char"),"fib_nhs":u64_field(64),"fib_nh_is_v6":u64_field(72),"nh":ptr(80,"nexthop"),"fib_nh":array(88,0,"fib_nh")})),
        "fib_nh":ty(64,json!({"nh_common":embedded(0,"fib_nh_common"),"nh_parent":ptr(56,"fib_info")})),
        "fib_nh_common":ty(56,json!({"nhc_dev":ptr(0,"net_device"),"nhc_oif":u64_field(8),"nhc_family":scalar(16,"char"),"nhc_gw_family":scalar(17,"char"),"nhc_flags":scalar(18,"char"),"nhc_scope":scalar(19,"char"),"nhc_gw":array(20,16,"char"),"nhc_weight":u64_field(40),"nhc_lwtstate":u64_field(48)})),
        "net_device":ty(32,json!({"nd_net":embedded(0,"possible_net_t"),"ifindex":u64_field(8),"name":array(16,16,"char")})),
        "fib6_table":ty(80,json!({"tb6_hlist":embedded(0,"hlist_node"),"tb6_id":u64_field(16),"tb6_root":embedded(24,"fib6_node")})),
        "fib6_node":ty(56,json!({"parent":ptr(0,"fib6_node"),"left":ptr(8,"fib6_node"),"right":ptr(16,"fib6_node"),"subtree":ptr(24,"fib6_node"),"leaf":ptr(32,if modern {"fib6_info"} else {"rt6_info"}),"fn_bit":u64_field(40),"fn_flags":u64_field(48)})),
        "rt6key":ty(24,json!({"addr":array(0,16,"char"),"plen":u64_field(16)})),
        "fib6_info":ty(152,json!({"fib6_table":ptr(0,"fib6_table"),"fib6_next":ptr(8,"fib6_info"),"fib6_node":ptr(16,"fib6_node"),"fib6_dst":embedded(24,"rt6key"),"fib6_src":embedded(48,"rt6key"),"fib6_prefsrc":embedded(72,"rt6key"),"fib6_flags":u64_field(96),"fib6_metric":u64_field(104),"fib6_protocol":u64_field(112),"fib6_nsiblings":u64_field(120),"fib6_type":u64_field(128),"expires":u64_field(136),"nh":ptr(144,"nexthop"),"fib6_nh":array(152,0,"fib6_nh")})),
        "fib6_nh":ty(56,json!({"nh_common":embedded(0,"fib_nh_common")})),
        "dst_entry":ty(24,json!({"dev":ptr(0,"net_device"),"rt6_next":ptr(8,"rt6_info"),"expires":u64_field(16)})),
        "rt6_info":ty(160,json!({"dst":embedded(0,"dst_entry"),"rt6i_table":ptr(24,"fib6_table"),"rt6i_node":ptr(32,"fib6_node"),"rt6i_dst":embedded(40,"rt6key"),"rt6i_src":embedded(64,"rt6key"),"rt6i_prefsrc":embedded(88,"rt6key"),"rt6i_flags":u64_field(112),"rt6i_metric":u64_field(120),"rt6i_protocol":u64_field(128),"rt6i_nsiblings":u64_field(136),"rt6i_gateway":array(144,16,"char")})),
        "nexthop":ty(32,json!({"net":ptr(0,"net"),"id":u64_field(8),"is_group":u64_field(16),"nh_info":ptr(24,"nh_info"),"nh_grp":ptr(24,"nh_group")})),
        "nh_info":ty(72,json!({"nh_parent":ptr(0,"nexthop"),"fib_nhc":embedded(8,"fib_nh_common"),"reject_nh":u64_field(64)})),
        "nh_group":ty(8,json!({"num_nh":u64_field(0),"nh_entries":array(8,0,"nh_grp_entry")})),
        "nh_grp_entry":ty(24,json!({"nh":ptr(0,"nexthop"),"weight":u64_field(8),"nh_parent":ptr(16,"nexthop")}))
    });
    if multiple {
        types["netns_ipv4"]["fields"]["rules_ops"] = u64_field(8);
        types["netns_ipv6"]["fields"]["fib6_rules_ops"] = u64_field(16);
    }
    let mut m = Memory::new(
        types,
        json!({"net_namespace_list":{"address":HEAD},"init_net":{"address":NET}}),
    );
    zero(&mut m, NET, 256);
    m.u64(NET, 4026531993);
    m.u64(HEAD, NET + 16);
    m.u64(HEAD + 8, NET + 16);
    m.u64(NET + 16, HEAD);
    m.u64(NET + 24, HEAD);
    m.u64(NET + 128, HASH4);
    m.u64(NET + 192, HASH6);
    m.u64(NET + 200, NULL6);
    zero(&mut m, HASH4, if multiple { 2048 } else { 16 });
    zero(&mut m, HASH6, if multiple { 2048 } else { 8 });
    let bucket4 = HASH4 + if multiple { 254 * 8 } else { 0 };
    let bucket6 = HASH6 + if multiple { 254 * 8 } else { 0 };
    zero(&mut m, TABLE4, 32);
    m.u64(TABLE4 + 8, bucket4);
    m.u64(bucket4, TABLE4);
    m.u64(TABLE4 + 16, 254);
    m.u64(TABLE4 + 24, TRIE);
    zero(&mut m, TRIE, 16);
    m.put(TRIE + 4, &[32]);
    m.u64(TRIE + 8, LEAF4);
    zero(&mut m, LEAF4 - 8, 24);
    m.u64(LEAF4 - 8, TRIE);
    m.u64(LEAF4 + 8, ALIAS);
    zero(&mut m, ALIAS, 32);
    m.u64(ALIAS + 8, LEAF4 + 8);
    m.u64(ALIAS + 16, INFO);
    m.put(ALIAS + 24, &[32, 1]);
    word(&mut m, ALIAS + 28, 254);
    zero(&mut m, INFO, 216);
    m.u64(INFO, NET);
    m.u64(INFO + 8, 254);
    m.u64(INFO + 32, 3);
    m.u64(INFO + 48, 100);
    m.u64(INFO + 64, 2);
    m.u64(INFO + 72, 1);
    zero(&mut m, DEV, 32);
    m.u64(DEV, NET);
    m.u64(DEV + 8, 2);
    m.put(DEV + 16, b"eth0\0");
    common(&mut m, INFO + 88, 2);
    m.put(INFO + 108, &[10, 0, 0, 1]);
    m.u64(INFO + 144, INFO);
    common(&mut m, INFO + 152, 10);
    ip6(&mut m, INFO + 172, "2001:db8::1");
    m.u64(INFO + 208, INFO);
    zero(&mut m, TABLE6, 80);
    m.u64(TABLE6 + 8, bucket6);
    m.u64(TABLE6 + 16, 254);
    m.u64(bucket6, TABLE6);
    m.u64(ROOT6 + 8, NODE6);
    m.u64(ROOT6 + 32, NULL6);
    m.u64(ROOT6 + 48, 7);
    zero(&mut m, NODE6, 56);
    m.u64(NODE6, ROOT6);
    m.u64(NODE6 + 32, ROUTE6);
    m.u64(NODE6 + 40, 32);
    m.u64(NODE6 + 48, 4);
    if modern {
        zero(&mut m, ROUTE6, 208);
        m.u64(ROUTE6, TABLE6);
        m.u64(ROUTE6 + 16, NODE6);
        ip6(&mut m, ROUTE6 + 24, "2001:db8::");
        m.u64(ROUTE6 + 40, 32);
        m.u64(ROUTE6 + 104, 256);
        m.u64(ROUTE6 + 128, 1);
        common(&mut m, ROUTE6 + 152, 10);
        ip6(&mut m, ROUTE6 + 172, "fe80::1");
    } else {
        zero(&mut m, ROUTE6, 160);
        m.u64(ROUTE6, DEV);
        m.u64(ROUTE6 + 24, TABLE6);
        m.u64(ROUTE6 + 32, NODE6);
        ip6(&mut m, ROUTE6 + 40, "2001:db8::");
        m.u64(ROUTE6 + 56, 32);
        m.u64(ROUTE6 + 112, 2);
        m.u64(ROUTE6 + 120, 256);
        ip6(&mut m, ROUTE6 + 144, "fe80::1");
    }
    m
}

fn common(m: &mut Memory, address: u64, gateway_family: u8) {
    m.u64(address, DEV);
    m.u64(address + 8, 2);
    m.put(address + 16, &[2, gateway_family, 0, 0]);
    m.u64(address + 40, 1);
}

#[test]
fn routes_decode_both_families_multipath_and_v4_via_v6_without_casting_array() {
    let report = run(&fixture(true, true));
    assert!(report.available && report.complete, "{:?}", report.warnings);
    assert_eq!(report.record_count, 2);
    let v4 = &report.records[0];
    assert_eq!(v4["destination_prefix"], "0.0.0.0/0");
    assert_eq!(v4["net_ns_id"], 4026531993u64);
    assert_eq!(v4["nexthops"][1]["gateway"], "2001:db8::1");
    assert_eq!(v4["nexthops"][1]["nexthop_address"], INFO + 152);
    let v6 = &report.records[1];
    assert_eq!(v6["destination_prefix"], "2001:db8::/32");
    assert_eq!(v6["interfaces"], "eth0");
    assert_eq!(v6["route_address"], ROUTE6);
}

#[test]
fn routes_exact_leaf_type_selects_legacy_ipv6_even_when_modern_type_exists() {
    let report = run(&fixture(false, true));
    assert!(report.complete, "{:?}", report.warnings);
    assert_eq!(report.record_count, 2);
    assert_eq!(report.records[1]["fib_layout"], "rt6_info");
    assert_eq!(report.records[1]["gateways"], "fe80::1");
}

#[test]
fn routes_small_configured_hashes_do_not_scan_unallocated_following_memory() {
    let report = run(&fixture(true, false));
    assert!(report.complete, "{:?}", report.warnings);
    assert_eq!(report.record_count, 2);
}

#[test]
fn routes_direct_gateway_and_unreadable_table_ranges_remain_distinct() {
    let mut m = fixture(false, true);
    m.u64(ROUTE6 + 112, 0);
    let report = run(&m);
    assert!(report.complete, "{:?}", report.warnings);
    assert!(report.records[1]["nexthops"][0]["gateway"].is_null());
    assert_eq!(report.records[1]["nexthops"][0]["gateway_family"], "direct");
    m.u64(NET + 128, K + 0xbad000);
    m.u64(NET + 192, K + 0xdead000);
    let report = run(&m);
    assert!(!report.available && !report.complete);
    assert_eq!(report.record_count, 0);
}

#[test]
fn routes_shared_main_local_trie_filters_alias_ownership_without_duplicate_rows() {
    let mut m = fixture(true, true);
    let local = K + 0x11000;
    let alias = ALIAS + 128;
    let info = INFO + 512;
    zero(&mut m, local, 32);
    m.u64(local + 8, HASH4 + 255 * 8);
    m.u64(HASH4 + 255 * 8, local);
    m.u64(local + 16, 255);
    m.u64(local + 24, TRIE);
    zero(&mut m, alias, 32);
    m.u64(ALIAS, alias);
    m.u64(alias + 8, ALIAS);
    m.u64(alias + 16, info);
    m.put(alias + 25, &[2]);
    word(&mut m, alias + 28, 255);
    zero(&mut m, info, 88);
    m.u64(info, NET);
    m.u64(info + 8, 255);
    let report = run(&m);
    assert!(report.complete, "{:?}", report.warnings);
    assert_eq!(report.record_count, 3);
    assert_eq!(report.records[1]["table_id"], 255);
    assert_eq!(report.records[1]["destination_prefix"], "0.0.0.0/32");
}

#[test]
fn routes_broken_fib_info_retains_prefix_but_never_binds_foreign_device() {
    let mut m = fixture(true, true);
    m.u64(DEV, NET + 4096);
    let report = run(&m);
    assert!(!report.complete);
    assert_eq!(report.record_count, 2);
    assert_eq!(report.records[0]["interfaces"], "");
    assert_eq!(report.records[0]["gateways"], "");
    assert_eq!(report.records[0]["nexthops"][0]["complete"], false);
    assert!(report.records[0]["nexthops"][0]["interface"].is_null());
    m.u64(INFO, NET + 4096);
    let report = run(&m);
    assert_eq!(report.records[0]["destination_prefix"], "0.0.0.0/0");
    assert_eq!(report.records[0]["details_complete"], false);
    assert_eq!(report.records[0]["nexthops"], json!([]));
}

#[test]
fn routes_broken_family_and_branch_preserve_other_verified_routes() {
    let mut m = fixture(true, true);
    m.u64(NET + 128, K + 0xdead000);
    let report = run(&m);
    assert!(!report.complete);
    assert_eq!(report.record_count, 1);
    assert_eq!(report.records[0]["family"], "IPv6");
    let mut m = fixture(true, true);
    m.u64(ROOT6 + 16, K + 0xdead000);
    let report = run(&m);
    assert!(!report.complete);
    assert_eq!(report.record_count, 2);
    assert!(
        report
            .warnings
            .iter()
            .any(|w| w.contains("synthetic missing byte"))
    );
}

#[test]
fn routes_skip_inherited_ipv6_hints_and_reject_wrong_route_backlink() {
    let mut m = fixture(true, true);
    m.u64(ROOT6 + 48, 3);
    m.u64(ROOT6 + 32, ROUTE6);
    let report = run(&m);
    assert!(report.complete, "{:?}", report.warnings);
    assert_eq!(report.record_count, 2);
    m.u64(ROUTE6 + 16, ROOT6);
    let report = run(&m);
    assert!(!report.complete);
    assert_eq!(report.record_count, 1);
}

#[test]
fn routes_ipv6_source_subtree_checks_both_prefixes() {
    let mut m = fixture(true, true);
    let root = K + 0x24000;
    let node = root + 128;
    m.u64(NODE6 + 48, 0);
    m.u64(NODE6 + 24, root);
    zero(&mut m, root, 56);
    m.u64(root, NODE6);
    m.u64(root + 8, node);
    m.u64(root + 48, 2);
    zero(&mut m, node, 56);
    m.u64(node, root);
    m.u64(node + 32, ROUTE6);
    m.u64(node + 40, 64);
    m.u64(node + 48, 4);
    m.u64(ROUTE6 + 16, node);
    ip6(&mut m, ROUTE6 + 48, "2001:db8:abcd::");
    m.u64(ROUTE6 + 64, 64);
    let report = run(&m);
    assert!(report.complete, "{:?}", report.warnings);
    assert_eq!(report.records[1]["source_prefix"], "2001:db8:abcd::/64");
    m.put(ROUTE6 + 48, &[0x80]);
    let report = run(&m);
    assert!(!report.complete);
    assert_eq!(report.record_count, 1);
}

#[test]
fn routes_limits_and_damaged_large_child_arrays_are_bounded() {
    let m = fixture(true, true);
    let mut options = route_options();
    options.limit = 1;
    let report = run_kernel(&m, &options, &CancellationToken::default()).unwrap();
    assert_eq!(report.record_count, 1);
    assert!(report.limit_reached);
    let mut m = fixture(true, true);
    let branch = K + 0x25008;
    zero(&mut m, branch - 8, 24);
    m.u64(branch - 8, TRIE);
    m.put(branch + 5, &[32]);
    m.u64(TRIE + 8, branch);
    options.limit = 65536;
    options.max_bytes = 8192;
    let report = run_kernel(&m, &options, &CancellationToken::default()).unwrap();
    assert!(!report.complete);
    assert!(report.warnings.iter().any(|w| w.contains("总预算")));
    assert!(report.record_count < 3);
}

#[test]
fn routes_nexthop_groups_preserve_entry_weights_and_partial_members() {
    let mut m = fixture(true, true);
    let object = K + 0x30000;
    let group = object + 128;
    let child = object + 256;
    let info = object + 384;
    zero(&mut m, object, 512);
    m.u64(INFO + 80, object);
    m.u64(object, NET);
    m.u64(object + 8, 42);
    m.u64(object + 16, 1);
    m.u64(object + 24, group);
    m.u64(group, 2);
    m.u64(group + 8, child);
    m.u64(group + 16, 7);
    m.u64(group + 24, object);
    m.u64(group + 32, K + 0xbad000);
    m.u64(group + 40, 3);
    m.u64(group + 48, object);
    m.u64(child, NET);
    m.u64(child + 8, 43);
    m.u64(child + 24, info);
    m.u64(info, child);
    common(&mut m, info + 8, 2);
    m.put(info + 28, &[192, 0, 2, 1]);
    let report = run(&m);
    assert!(!report.complete);
    let hops = &report.records[0]["nexthops"];
    assert_eq!(hops[0]["weight"], 7);
    assert_eq!(hops[0]["nexthop_id"], 43);
    assert_eq!(hops[1]["complete"], false);
    assert_eq!(report.records[0]["gateways"], "192.0.2.1");
    assert_eq!(report.records[0]["details_complete"], false);
}

#[test]
fn routes_missing_info_pointer_and_cyclic_alias_keep_valid_prefixes() {
    let mut m = fixture(true, true);
    for byte in ALIAS + 16..ALIAS + 24 {
        m.bytes.remove(&byte);
    }
    let report = run(&m);
    assert_eq!(report.record_count, 2);
    assert!(!report.complete);
    assert_eq!(report.records[0]["destination_prefix"], "0.0.0.0/0");
    let mut m = fixture(true, true);
    m.u64(ALIAS, ALIAS);
    let report = run(&m);
    assert_eq!(report.record_count, 2);
    assert!(!report.complete);
    assert!(report.warnings.iter().any(|w| w.contains("循环")));
}

#[test]
fn routes_later_ipv4_slot_survives_a_bad_sibling() {
    let mut m = fixture(true, true);
    let branch = K + 0x25008;
    zero(&mut m, branch - 8, 32);
    m.u64(branch - 8, TRIE);
    m.put(branch + 4, &[31, 1]);
    m.u64(TRIE + 8, branch);
    m.u64(branch + 8, K + 0xbad000);
    m.u64(branch + 16, LEAF4);
    m.u64(LEAF4 - 8, branch);
    word(&mut m, LEAF4, 0x80000000);
    m.put(ALIAS + 24, &[31]);
    let report = run(&m);
    assert_eq!(report.record_count, 2);
    assert!(!report.complete);
    assert_eq!(report.records[0]["destination_prefix"], "128.0.0.0/1");
    // A bit-valid key in the wrong parent slot must not become a route.
    word(&mut m, LEAF4, 0);
    let report = run(&m);
    assert_eq!(report.record_count, 1);
}

#[test]
fn routes_enumerate_a_second_namespace_without_reusing_first_namespace_tables() {
    let mut m = fixture(true, true);
    let net = NET + 4096;
    let hash = K + 0x6000;
    zero(&mut m, net, 256);
    m.u64(net, 4026532999);
    m.u64(NET + 16, net + 16);
    m.u64(net + 16, HEAD);
    m.u64(net + 24, NET + 16);
    m.u64(HEAD + 8, net + 16);
    // Two valid empty hashes belong to the second namespace; no evidence is copied across.
    zero(&mut m, hash, 4096);
    m.u64(net + 128, hash);
    m.u64(net + 192, hash + 2048);
    m.u64(net + 200, NULL6 + 4096);
    let report = run(&m);
    assert!(report.complete, "{:?}", report.warnings);
    assert_eq!(report.record_count, 2);
    assert!(report.scope.contains("4 个地址族"));
    assert!(report.records.iter().all(|row| row["net_namespace"] == NET));
}

#[test]
fn routes_cancellation_during_reads_propagates_instead_of_partial_success() {
    use crate::cancellation::{CancellationHandle, is_cancellation_error};
    use std::cell::Cell;
    struct Cancelling {
        memory: Memory,
        handle: CancellationHandle,
        reads: Cell<usize>,
    }
    impl LinuxKernelMemory for Cancelling {
        fn read_virtual(&self, a: u64, b: &mut [u8]) -> Result<()> {
            self.reads.set(self.reads.get() + 1);
            if self.reads.get() == 30 {
                self.handle.cancel();
            }
            self.memory.read_virtual(a, b)
        }
        fn translate(&self, a: u64) -> Result<u64> {
            self.memory.translate(a)
        }
        fn isf(&self) -> &LinuxIsf {
            self.memory.isf()
        }
        fn kernel_slide(&self) -> u64 {
            0
        }
        fn source_path(&self) -> Option<&std::path::Path> {
            None
        }
    }
    let m = Cancelling {
        memory: fixture(true, true),
        handle: CancellationHandle::new(),
        reads: Cell::new(0),
    };
    let error = run_kernel(&m, &route_options(), &m.handle.token()).unwrap_err();
    assert!(is_cancellation_error(&error));
    assert!(m.reads.get() <= 31);
}
