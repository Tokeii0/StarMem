//! Non-destructive, bounded WAL views. See SQLite file format sections 4.1/4.2.
use crate::{cancellation::CancellationToken, windows::files::RecoveredExtent};
use anyhow::{Result, ensure};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub(super) fn covered(extents: &[RecoveredExtent], offset: u64, length: u64) -> bool {
    let Some(end) = offset.checked_add(length) else {
        return false;
    };
    let mut pos = offset;
    while pos < end {
        let Some(next) = extents
            .iter()
            .filter(|e| e.file_offset <= pos)
            .filter_map(|e| e.file_offset.checked_add(e.length))
            .filter(|e| *e > pos)
            .max()
        else {
            return false;
        };
        pos = next.min(end);
    }
    true
}

fn be(b: &[u8], off: usize) -> u32 {
    u32::from_be_bytes(b[off..off + 4].try_into().expect("bounded WAL field"))
}
fn checksum(b: &[u8], mut s: (u32, u32), little: bool) -> (u32, u32) {
    for c in b.chunks_exact(8) {
        let a = c[..4].try_into().expect("word");
        let d = c[4..].try_into().expect("word");
        let (a, d) = if little {
            (u32::from_le_bytes(a), u32::from_le_bytes(d))
        } else {
            (u32::from_be_bytes(a), u32::from_be_bytes(d))
        };
        s.0 = s.0.wrapping_add(a).wrapping_add(s.1);
        s.1 = s.1.wrapping_add(d).wrapping_add(s.0);
    }
    s
}

pub(super) struct WalView {
    /// Page -> (one-based frame, WAL offset of the page payload).
    pub pages: BTreeMap<u32, (usize, usize)>,
    pub page_size: usize,
    pub database_pages: usize,
    pub commit_frame: usize,
    pub complete: bool,
    pub diagnostics: Value,
}

pub(super) fn inspect(
    b: &[u8],
    ranges: &[RecoveredExtent],
    token: &CancellationToken,
) -> Result<WalView> {
    ensure!(b.len() >= 32 && covered(ranges, 0, 32), "WAL 头缺页");
    let magic = be(b, 0);
    ensure!(matches!(magic, 0x377f0682 | 0x377f0683), "WAL magic 无效");
    ensure!(be(b, 4) == 3007000, "WAL 版本不支持");
    let ps = be(b, 8) as usize;
    ensure!(
        (512..=65536).contains(&ps) && ps.is_power_of_two(),
        "WAL 页大小无效"
    );
    let little = magic == 0x377f0682;
    let mut cs = checksum(&b[..24], (0, 0), little);
    ensure!(cs == (be(b, 24), be(b, 28)), "WAL 头校验和不匹配");
    let mut pending = BTreeMap::new();
    let mut committed = BTreeMap::new();
    let mut last = 0;
    let mut db_pages = 0;
    let mut valid = 0;
    let mut stop = "end";
    for (i, off) in (32..b.len()).step_by(ps + 24).enumerate() {
        token.check_cancelled()?;
        if off + 24 + ps > b.len() || !covered(ranges, off as u64, (ps + 24) as u64) {
            stop = "missing_or_partial_frame";
            break;
        }
        if b[off + 8..off + 16] != b[16..24] {
            stop = "salt_mismatch";
            break;
        }
        cs = checksum(&b[off..off + 8], cs, little);
        cs = checksum(&b[off + 24..off + 24 + ps], cs, little);
        if cs != (be(b, off + 16), be(b, off + 20)) {
            stop = "checksum_mismatch";
            break;
        }
        let page = be(b, off);
        if page == 0 || page as u64 * ps as u64 > 16 * 1024 * 1024 {
            stop = "page_budget_or_invalid_number";
            break;
        }
        pending.insert(page, (i + 1, off + 24));
        valid = i + 1;
        let size = be(b, off + 4) as usize;
        if size > 0 {
            ensure!(
                size.checked_mul(ps).is_some_and(|n| n <= 16 * 1024 * 1024),
                "WAL 数据库超过 16 MiB 重建预算"
            );
            last = i + 1;
            db_pages = size;
            committed = pending.clone();
            committed.retain(|p, _| *p as usize <= size);
            // Pages removed by a committed shrink cannot reappear from old transactions.
            pending.retain(|p, _| *p as usize <= size);
        }
    }
    ensure!(last > 0, "没有连续验证的已提交 WAL 帧");
    Ok(WalView {
        pages: committed,
        page_size: ps,
        database_pages: db_pages,
        commit_frame: last,
        complete: stop == "end" && valid == last,
        diagnostics: json!({"verified_frames":valid,"last_commit_frame":last,"stop_reason":stop,"uncommitted_tail_frames":valid-last,"salts":[be(b,16),be(b,20)]}),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn wal() -> Vec<u8> {
        let mut b = vec![0; 32 + 2 * (512 + 24)];
        for (off, v) in [
            (0, 0x377f0682u32),
            (4, 3007000),
            (8, 512),
            (16, 17),
            (20, 31),
        ] {
            b[off..off + 4].copy_from_slice(&v.to_be_bytes());
        }
        let mut cs = checksum(&b[..24], (0, 0), true);
        b[24..28].copy_from_slice(&cs.0.to_be_bytes());
        b[28..32].copy_from_slice(&cs.1.to_be_bytes());
        for i in 0..2 {
            let off = 32 + i * 536;
            b[off..off + 4].copy_from_slice(&1u32.to_be_bytes());
            if i == 0 {
                b[off + 4..off + 8].copy_from_slice(&1u32.to_be_bytes());
            }
            let salts = b[16..24].to_vec();
            b[off + 8..off + 16].copy_from_slice(&salts);
            b[off + 24] = i as u8 + 5;
            cs = checksum(&b[off..off + 8], cs, true);
            cs = checksum(&b[off + 24..off + 536], cs, true);
            b[off + 16..off + 20].copy_from_slice(&cs.0.to_be_bytes());
            b[off + 20..off + 24].copy_from_slice(&cs.1.to_be_bytes());
        }
        b
    }
    fn range(len: usize) -> Vec<RecoveredExtent> {
        vec![RecoveredExtent {
            file_offset: 0,
            length: len as u64,
            memory_address: 0,
            memory_kind: "test".into(),
        }]
    }
    #[test]
    fn rejects_corruption_and_never_applies_uncommitted_tail() {
        let mut b = wal();
        let r = inspect(&b, &range(b.len()), &CancellationToken::new()).unwrap();
        assert_eq!(r.commit_frame, 1);
        assert_eq!(r.pages[&1], (1, 56));
        assert!(!r.complete);
        b[60] ^= 1;
        assert!(inspect(&b, &range(b.len()), &CancellationToken::new()).is_err());
        assert!(inspect(&wal(), &range(100), &CancellationToken::new()).is_err());
    }
}
