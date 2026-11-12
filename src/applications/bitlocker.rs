//! Independently implemented parser for published FVEc / CNG pool layouts.
//! These are structural key candidates, never a claim that a disk was unlocked.
//! Format references and compatibility boundaries: docs/APPLICATION_FORENSICS.md.
use super::{ApplicationOptions, ApplicationRecord, ApplicationReport};
use crate::{
    address::{VirtualAddressRegion, X64AddressSpace},
    cancellation::CancellationToken,
    scan::scan_patterns_cancellable,
    session::AnalysisSession,
};
use anyhow::Result;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::HashSet;

struct Key {
    offset: usize,
    bytes: Vec<u8>,
    tweak: Vec<u8>,
    tweak_offset: Option<usize>,
    mode: u16,
    cipher: &'static str,
    layout: &'static str,
}

fn parse_pool(blob: &[u8]) -> Vec<Key> {
    if blob.len() < 16 {
        return vec![];
    }
    let mut out = Vec::new();
    if &blob[4..8] == b"FVEc" && matches!(blob.len(), 0x210 | 0x3f0) {
        let mode = u16::from_le_bytes([blob[0x2c], blob[0x2d]]);
        let (n, cipher) = match mode {
            0x8000 => (16, "AES-128 + Elephant diffuser"),
            0x8001 => (32, "AES-256 + Elephant diffuser"),
            0x8002 => (16, "AES-CBC-128"),
            0x8003 => (32, "AES-CBC-256"),
            _ => return out,
        };
        if mode < 0x8002 && blob.len() != 0x3f0 {
            return out;
        }
        let key = blob[0x30..0x30 + n].to_vec();
        let tweak = if mode < 0x8002 {
            blob[0x210..0x210 + n].to_vec()
        } else {
            vec![]
        };
        if key.iter().any(|x| *x != 0) {
            out.push(Key {
                offset: 0x30,
                bytes: key,
                tweak,
                tweak_offset: (mode < 0x8002).then_some(0x210),
                mode,
                cipher,
                layout: "fvec_windows7_x64",
            });
        }
        return out;
    }
    let tag = &blob[4..8];
    let min = if tag == b"None" {
        0x4d0
    } else if tag == b"Cngb" {
        0x2a0
    } else {
        return out;
    };
    if blob.len() < min || blob.len() > 4096 {
        return out;
    }
    for at in (16..blob.len().saturating_sub(0xbc) + 1).step_by(4) {
        if blob.get(at..at + 4) != Some(b"RUUU") || blob.get(at + 0x20..at + 0x24) != Some(b"KSSM")
        {
            continue;
        }
        let size =
            u32::from_le_bytes(blob[at + 0x54..at + 0x58].try_into().unwrap_or_default()) as usize;
        if !matches!(size, 16 | 32 | 64) {
            continue;
        }
        let key = &blob[at + 0x58..];
        if key[..16].iter().all(|x| *x == 0) {
            continue;
        }
        let xts = key[..16] == blob[at + 0x9c..at + 0xac];
        let cbc = key[..16] == blob[at + 0x7c..at + 0x8c];
        // Ambiguous copies are not enough to select an encryption algorithm.
        if xts == cbc {
            continue;
        }
        let (n, mode, cipher) = if xts {
            if key[..32] == blob[at + 0x9c..at + 0xbc] {
                (64, 0x8005, "AES-XTS-256")
            } else {
                (32, 0x8004, "AES-XTS-128")
            }
        } else if key[..32] == blob[at + 0x7c..at + 0x9c] {
            (32, 0x8003, "AES-CBC-256")
        } else {
            (16, 0x8002, "AES-CBC-128")
        };
        if size != n && !(xts && size == n / 2) {
            continue;
        }
        out.push(Key {
            offset: at + 0x58,
            bytes: key[..n].to_vec(),
            tweak: vec![],
            tweak_offset: None,
            mode,
            cipher,
            layout: if tag == b"None" {
                "cng_none_x64"
            } else {
                "cngb_x64_partial_context"
            },
        });
    }
    // A modern allocation may carry the data and Elephant diffuser keys in
    // two CBC contexts. Never export each half as an independent CBC FVEK.
    let mut unique = Vec::<Key>::new();
    for key in out {
        if !unique
            .iter()
            .any(|k| k.mode == key.mode && k.bytes == key.bytes)
        {
            unique.push(key);
        }
    }
    if tag == b"None" && unique.len() > 1 {
        if unique.len() != 2
            || unique[0].mode != unique[1].mode
            || !matches!(unique[0].mode, 0x8002 | 0x8003)
        {
            return vec![];
        }
        let tweak = unique.pop().expect("two checked contexts");
        unique[0].tweak_offset = Some(tweak.offset);
        unique[0].tweak = tweak.bytes;
        unique[0].mode -= 2;
        unique[0].cipher = if unique[0].mode == 0x8000 {
            "AES-128 + Elephant diffuser"
        } else {
            "AES-256 + Elephant diffuser"
        };
        unique[0].layout = "cng_none_x64_diffuser_pair";
    }
    unique
}

pub(super) fn analyze(
    session: &AnalysisSession,
    opt: &ApplicationOptions,
    token: &CancellationToken,
    report: &mut ApplicationReport,
) -> Result<()> {
    if session.kernel().is_x86_pae() || !session.symbol_layout_exactness().is_exact() {
        report.source(
            "bitlocker_kernel",
            false,
            false,
            0,
            vec!["内核密钥解析当前需要 Windows x64 与精确符号".into()],
            json!(null),
        );
        return Ok(());
    }
    // Searching CNG signatures before pool headers avoids truncating on the
    // many unrelated allocations carrying the generic None tag.
    let scan = scan_patterns_cancellable(
        session.image(),
        &[b"RUUU", b"FVEc", b"Cngb"],
        opt.anchor_limit,
        16 * 1024 * 1024,
        token,
    )?;
    let pages: HashSet<_> = scan
        .hits
        .iter()
        .map(|h| h.physical_address & !4095)
        .collect();
    let space = X64AddressSpace::new(session.image(), session.kernel().directory_table_base)?;
    let mapped = space.reverse_translate_pages_detailed_with_limits(
        &pages,
        VirtualAddressRegion::Kernel,
        8,
        33_554_432,
        262144,
    )?;
    let mut seen = HashSet::new();
    let mut pools = 0;
    let mut unreadable = 0;
    let mut ambiguous = 0;
    for hit in &scan.hits {
        token.check_cancelled()?;
        if report.truncated {
            break;
        }
        let Some(aliases) = mapped.mappings.get(&(hit.physical_address & !4095)) else {
            continue;
        };
        for alias in aliases {
            let va = alias + (hit.physical_address & 4095);
            if space.translate(va).ok() != Some(hit.physical_address) {
                continue;
            }
            let headers: Vec<u64> = if hit.pattern_index == 0 {
                (0..256)
                    .map(|i| (va & !15).saturating_sub(i * 16))
                    .collect()
            } else {
                vec![va.saturating_sub(4)]
            };
            for header in headers {
                token.check_cancelled()?;
                let mut head = [0u8; 16];
                if header & 15 != 0 || space.read_virtual(header, &mut head).is_err() {
                    continue;
                }
                let size = head[2] as usize * 16;
                let tag = &head[4..8];
                if !matches!(tag, b"None" | b"FVEc" | b"Cngb")
                    || head[3] == 0
                    || !(0x200..=4096).contains(&size)
                    || va < header + 4
                    || va >= header + size as u64
                {
                    continue;
                }
                if hit.pattern_index == 0 && va + 0xbc > header + size as u64 {
                    continue;
                }
                let Ok(pa) = space.translate(header) else {
                    continue;
                };
                if !seen.insert(pa) {
                    break;
                }
                let mut blob = vec![0u8; size];
                if space.read_virtual(header, &mut blob).is_err() {
                    unreadable += 1;
                    break;
                }
                pools += 1;
                let keys = parse_pool(&blob);
                if keys.is_empty() {
                    ambiguous += 1;
                    break;
                }
                let hash = hex::encode(Sha256::digest(&blob));
                let mut ranges = Vec::new();
                let mut off = 0;
                while off < size {
                    let v = header + off as u64;
                    let n = (size - off).min(4096 - (v as usize & 4095));
                    let p = space.translate(v)?;
                    ranges.push(json!({"virtual_address":v,"physical_address":p,"byte_length":n,"source_location":session.image().source_location(p)}));
                    off += n;
                }
                for k in keys {
                    let mut export = Vec::from(k.mode.to_le_bytes());
                    let mut material = [0u8; 64];
                    material[..k.bytes.len()].copy_from_slice(&k.bytes);
                    if !k.tweak.is_empty() {
                        material[32..32 + k.tweak.len()].copy_from_slice(&k.tweak);
                    }
                    export.extend(material);
                    let context_only = k.layout == "cngb_x64_partial_context";
                    report.push(ApplicationRecord{artifact_kind:"bitlocker_key_candidate".into(),source:"bitlocker_kernel".into(),pid:None,path:None,
                        summary:format!("{} · {}，未验证卷",k.cipher,if context_only {"CNG 上下文候选"} else {"FVEK 结构候选"}),
                        evidence:json!({"virtual_address":header,"physical_address":pa,"key_virtual_address":header+k.offset as u64,
                            "tweak_virtual_address":k.tweak_offset.map(|o|header+o as u64),"tweak_offset_in_pool":k.tweak_offset,
                            "key_offset_in_pool":k.offset,"byte_length":size,"pool_tag":String::from_utf8_lossy(tag),"pool_type_raw":head[3],
                            "directory_table_base":session.kernel().directory_table_base,"sha256":hash,"ranges":ranges}),
                        data:json!({"cipher":k.cipher,"algorithm_id":format!("{:#06x}",k.mode),"key_hex":hex::encode(&k.bytes),"key_bytes":k.bytes.len(),
                            "key_sha256":hex::encode(Sha256::digest(&k.bytes)),"tweak_hex":hex::encode(&k.tweak),"dislocker_fvek_hex":(!context_only).then(||hex::encode(export)),
                            "layout":k.layout,"sensitive":true,"validation":if context_only{"cng_context_only"}else{"structure_only"},"volume_verified":false,
                            "semantics":"内核池布局、CNG 标记及重复密钥字段校验的候选；未给定磁盘卷验证，CNG 可被其他组件使用；Cngb 尚未跨池关联，单上下文算法不能确定卷算法，不导出 FVEK"})});
                }
                break;
            }
        }
    }
    let complete = !scan.truncated
        && !mapped.traversal_limit_reached
        && !mapped.mapping_limit_exceeded
        && !mapped.alias_storage_limit_exceeded
        && mapped.page_table_read_failures == 0
        && unreadable == 0
        && !report.truncated;
    report.source("bitlocker_kernel",true,complete,pools,
        if complete{vec![]}else{vec!["密钥扫描存在锚点/页表预算、缺页或报告截断；未命中不证明没有驻留密钥".into()]},
        json!({"anchor_hits":scan.hits.len(),"bytes_scanned":scan.bytes_scanned,"unreadable_pools":unreadable,"rejected_layouts":ambiguous,
            "anchor_scan_truncated":scan.truncated,"target_pages":mapped.target_pages,"mapped_target_pages":mapped.mapped_target_pages,
            "page_table_entries_examined":mapped.page_table_entries_examined,"page_table_entry_limit":mapped.page_table_entry_limit,
            "traversal_limit_reached":mapped.traversal_limit_reached,"mapping_limit_exceeded":mapped.mapping_limit_exceeded,
            "alias_storage_limit_exceeded":mapped.alias_storage_limit_exceeded,"page_table_read_failures":mapped.page_table_read_failures,
            "layout_scope":["FVEc Windows 7 x64","None/Cngb CNG x64"],"disk_validation":false}));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cng_xts_modes_use_disk_format_ids_and_reject_zero_or_ambiguous() {
        for n in [32, 64] {
            let mut b = vec![0u8; 0x5b0];
            b[4..8].copy_from_slice(b"None");
            let s = 0x44;
            b[s..s + 4].copy_from_slice(b"RUUU");
            b[s + 0x20..s + 0x24].copy_from_slice(b"KSSM");
            b[s + 0x54..s + 0x58].copy_from_slice(&(n as u32).to_le_bytes());
            for i in 0..n {
                b[s + 0x58 + i] = (i + 1) as u8;
            }
            let copy = b[s + 0x58..s + 0x58 + n / 2].to_vec();
            b[s + 0x9c..s + 0x9c + n / 2].copy_from_slice(&copy);
            let out = parse_pool(&b);
            assert_eq!(out.len(), 1);
            assert_eq!(out[0].bytes.len(), n);
            assert_eq!(out[0].mode, if n == 32 { 0x8004 } else { 0x8005 });
            b[s + 0x58..s + 0x68].fill(0);
            assert!(parse_pool(&b).is_empty());
        }
        assert!(parse_pool(&[0; 32]).is_empty());
    }
    #[test]
    fn fvec_cipher_and_diffuser_require_correct_allocation() {
        let mut b = vec![0; 0x210];
        b[4..8].copy_from_slice(b"FVEc");
        b[0x2c..0x2e].copy_from_slice(&0x8002u16.to_le_bytes());
        b[0x30..0x40].fill(7);
        assert_eq!(parse_pool(&b)[0].bytes.len(), 16);
        b[0x2c] = 0;
        assert!(parse_pool(&b).is_empty());
    }

    #[test]
    fn paired_cbc_contexts_form_one_diffuser_candidate() {
        let mut b = vec![0; 0x580];
        b[4..8].copy_from_slice(b"None");
        for (s, value) in [(0x44, 7), (0x2d4, 9)] {
            b[s..s + 4].copy_from_slice(b"RUUU");
            b[s + 0x20..s + 0x24].copy_from_slice(b"KSSM");
            b[s + 0x54..s + 0x58].copy_from_slice(&16u32.to_le_bytes());
            b[s + 0x58..s + 0x68].fill(value);
            b[s + 0x68] = 1; // Expanded schedule differs after a 16-byte key.
            b[s + 0x7c..s + 0x8c].fill(value);
        }
        let a = parse_pool(&b);
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].mode, 0x8000);
        assert_eq!(a[0].bytes, [7; 16]);
        assert_eq!(a[0].tweak, [9; 16]);
        assert_eq!(a[0].tweak_offset, Some(0x32c));
    }
}
