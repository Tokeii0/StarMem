//! SQLite default x64 page cache used by the observed WCDB build. Every link
//! is checked in both directions; missing bytes never become a cached page.
//! Layout references: sqlite/sqlite src/pcache.h and src/pcache1.c.
use anyhow::{Result, anyhow, ensure};
use std::collections::{BTreeMap, HashSet};

pub(super) struct CachePage {
    pub number: u32,
    pub data_address: u64,
    pub header_address: u64,
    pub extra_address: u64,
    pub bucket_address: u64,
    pub bytes: Vec<u8>,
}

pub(super) struct Cache {
    pub header_address: u64,
    pub cache_address: u64,
    pub pager_address: u64,
    pub pcache_address: u64,
    pub hash_address: u64,
    pub page_size: usize,
    pub declared_pages: u32,
    pub pages: BTreeMap<u32, CachePage>,
    pub warnings: Vec<String>,
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().expect("fixed layout"))
}
fn u64_at(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().expect("fixed layout"))
}
fn pointer(p: u64) -> bool {
    (0x10000..0x0000_8000_0000_0000).contains(&p) && p.is_multiple_of(8)
}

fn required(
    read: &mut impl FnMut(u64, usize) -> Result<Option<Vec<u8>>>,
    va: u64,
    len: usize,
) -> Result<Vec<u8>> {
    let b = read(va, len)?.ok_or_else(|| anyhow!("缓存结构缺页：0x{va:x}"))?;
    ensure!(b.len() == len, "缓存结构读取不完整");
    Ok(b)
}

/// `read` must return only fully resident bytes from the selected process.
pub(super) fn recover(
    header_va: u64,
    page_limit: usize,
    read: &mut impl FnMut(u64, usize) -> Result<Option<Vec<u8>>>,
) -> Result<Cache> {
    let header = required(read, header_va, 100)?;
    ensure!(
        header.starts_with(b"SQLite format 3\0"),
        "SQLite 文件头无效"
    );
    let raw_size = u16::from_be_bytes([header[16], header[17]]);
    let size = if raw_size == 1 {
        65536
    } else {
        usize::from(raw_size)
    };
    ensure!(
        (512..=65536).contains(&size) && size.is_power_of_two(),
        "SQLite 页大小无效"
    );
    ensure!(
        usize::from(header[20]) < size && header[56..60] == [0, 0, 0, 1],
        "未支持的 SQLite 保留区或文本编码"
    );
    let header_address = header_va
        .checked_add(size as u64)
        .ok_or_else(|| anyhow!("缓存地址溢出"))?;
    let first = required(read, header_address, 56)?;
    let extra = u64_at(&first, 8);
    let cache_address = u64_at(&first, 32);
    ensure!(
        u64_at(&first, 0) == header_va
            && u32_at(&first, 16) == 1
            && pointer(extra)
            && pointer(cache_address),
        "SQLite 页缓存首节点不匹配"
    );
    let pg = required(read, extra, 72)?;
    let pcache_address = u64_at(&pg, 24);
    let pager_address = u64_at(&pg, 40);
    ensure!(
        u64_at(&pg, 0) == header_address
            && u64_at(&pg, 8) == header_va
            && u64_at(&pg, 16) == extra + 72
            && u32_at(&pg, 48) == 1
            && pointer(pcache_address)
            && pointer(pager_address),
        "SQLite PgHdr 互指校验失败"
    );
    let c = required(read, cache_address, 72)?;
    let n_hash = u32_at(&c, 60) as usize;
    let declared_pages = u32_at(&c, 56);
    let hash_address = u64_at(&c, 64);
    ensure!(
        u32_at(&c, 16) as usize == size
            && (72..=4096).contains(&u32_at(&c, 20))
            && u32_at(&c, 24) as usize >= size + 56 + u32_at(&c, 20) as usize
            && u32_at(&c, 24) as usize <= size + 8192
            && (1..=65536).contains(&n_hash)
            && pointer(hash_address),
        "未支持或损坏的 x64 PCache1 布局"
    );
    let mut result = Cache {
        header_address: header_va,
        cache_address,
        pcache_address,
        pager_address,
        hash_address,
        page_size: size,
        declared_pages,
        pages: BTreeMap::new(),
        warnings: Vec::new(),
    };
    let mut seen = HashSet::new();
    let mut numbers = HashSet::new();
    'buckets: for start in (0..n_hash).step_by(256) {
        let count = (n_hash - start).min(256);
        let Some(buckets) = read(hash_address + (start * 8) as u64, count * 8)? else {
            result.warning(format!("哈希桶 {start}..{} 缺页", start + count));
            continue;
        };
        for bucket in start..start + count {
            let bucket_address = hash_address + (bucket * 8) as u64;
            let mut node = u64_at(&buckets, (bucket - start) * 8);
            while node != 0 {
                if seen.len() >= page_limit {
                    result.warning(format!("缓存节点达到 {page_limit} 项上限"));
                    break 'buckets;
                }
                if !pointer(node) || !seen.insert(node) {
                    result.warning(format!("哈希桶 {bucket} 存在无效指针或重复节点"));
                    break;
                }
                let Some(h) = read(node, 56)? else {
                    result.warning(format!("缓存节点 0x{node:x} 缺页"));
                    break;
                };
                let number = u32_at(&h, 16);
                let data_address = u64_at(&h, 0);
                let extra_address = u64_at(&h, 8);
                if u64_at(&h, 32) != cache_address
                    || number == 0
                    || number as usize % n_hash != bucket
                    || !pointer(data_address)
                    || !pointer(extra_address)
                    || data_address.checked_add(size as u64) != Some(node)
                {
                    result.warning(format!("缓存节点 0x{node:x} 归属或页号校验失败"));
                    break;
                }
                let Some(g) = read(extra_address, 72)? else {
                    result.warning(format!("页 {number} 的 PgHdr 缺页"));
                    break;
                };
                if u64_at(&g, 0) != node
                    || u64_at(&g, 8) != data_address
                    || u64_at(&g, 16) != extra_address + 72
                    || u64_at(&g, 24) != pcache_address
                    || u64_at(&g, 40) != pager_address
                    || u32_at(&g, 48) != number
                {
                    result.warning(format!("页 {number} 的 PgHdr 互指或 Pager 校验失败"));
                    break;
                }
                node = u64_at(&h, 24);
                if !numbers.insert(number) {
                    result.pages.remove(&number);
                    result.warning(format!("页 {number} 出现多个缓存版本，排除该页"));
                    continue;
                }
                // Bound the sparse logical address space as well as resident bytes.
                if u64::from(number) * size as u64 > 64 * 1024 * 1024 {
                    result.warning(format!("页 {number} 超过单库 64 MiB 逻辑范围"));
                    continue;
                }
                match read(data_address, size)? {
                    Some(bytes) => {
                        result.pages.insert(
                            number,
                            CachePage {
                                number,
                                data_address,
                                header_address: u64_at(&g, 0),
                                extra_address,
                                bucket_address,
                                bytes,
                            },
                        );
                    }
                    None => result.warning(format!("页 {number} 数据未完整驻留，排除整页")),
                }
            }
        }
    }
    ensure!(result.pages.contains_key(&1), "缓存首数据库页未完整驻留");
    if seen.len() != declared_pages as usize {
        result.warning(format!(
            "缓存声明 {declared_pages} 页，核对 {} 个节点",
            seen.len()
        ));
    }
    Ok(result)
}

impl Cache {
    fn warning(&mut self, message: String) {
        if self.warnings.len() < 128 {
            self.warnings.push(message);
        } else if self.warnings.len() == 128 {
            self.warnings.push("其他缓存告警已省略".into());
        }
    }
    /// Holes exist only as parser address space. Consumers must reject every
    /// schema/row range touching a hole before retaining any evidence.
    pub fn parser_bytes(&self) -> Vec<u8> {
        let length = self.pages.keys().next_back().copied().unwrap_or(1) as usize * self.page_size;
        let mut bytes = vec![0; length];
        for page in self.pages.values() {
            let at = (page.number as usize - 1) * self.page_size;
            bytes[at..at + self.page_size].copy_from_slice(&page.bytes);
        }
        bytes
    }
    pub fn resident(&self, offset: u64, length: u64) -> bool {
        if length == 0 {
            return true;
        }
        let Some(end) = offset.checked_add(length - 1) else {
            return false;
        };
        (offset / self.page_size as u64..=end / self.page_size as u64).all(|index| {
            u32::try_from(index + 1)
                .ok()
                .is_some_and(|n| self.pages.contains_key(&n))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn put32(b: &mut [u8], n: usize, v: u32) {
        b[n..n + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn put64(b: &mut [u8], n: usize, v: u64) {
        b[n..n + 8].copy_from_slice(&v.to_le_bytes());
    }
    fn fixture() -> BTreeMap<u64, Vec<u8>> {
        let mut memory = BTreeMap::new();
        let mut c = vec![0; 72];
        for (n, v) in [(16, 4096), (20, 208), (24, 4360), (56, 2), (60, 16)] {
            put32(&mut c, n, v);
        }
        put64(&mut c, 64, 0x18000);
        memory.insert(0x10000, c);
        let mut buckets = vec![0; 128];
        for number in 1..=2u32 {
            let va = 0x20000 + u64::from(number - 1) * 0x4000;
            let h = va + 4096;
            let g = h + 56;
            let mut b = vec![number as u8; 4096];
            if number == 1 {
                b[..100].fill(0);
                b[..16].copy_from_slice(b"SQLite format 3\0");
                b[16..18].copy_from_slice(&4096u16.to_be_bytes());
                b[59] = 1;
            }
            memory.insert(va, b);
            let mut header = vec![0; 56];
            put64(&mut header, 0, va);
            put64(&mut header, 8, g);
            put32(&mut header, 16, number);
            put64(&mut header, 32, 0x10000);
            memory.insert(h, header);
            let mut pg = vec![0; 72];
            for (n, v) in [(0, h), (8, va), (16, g + 72), (24, 0x11000), (40, 0x12000)] {
                put64(&mut pg, n, v);
            }
            put32(&mut pg, 48, number);
            memory.insert(g, pg);
            put64(&mut buckets, number as usize * 8, h);
        }
        memory.insert(0x18000, buckets);
        memory
    }
    fn read(memory: &BTreeMap<u64, Vec<u8>>, at: u64, len: usize) -> Result<Option<Vec<u8>>> {
        Ok(memory.range(..=at).next_back().and_then(|(&start, b)| {
            let offset = (at - start) as usize;
            b.get(offset..offset.checked_add(len)?).map(|b| b.to_vec())
        }))
    }
    #[test]
    fn cache_requires_reciprocal_metadata_and_hash_bucket_ownership() {
        let memory = fixture();
        let c = recover(0x20000, 10, &mut |a, n| read(&memory, a, n)).unwrap();
        assert_eq!(c.pages.len(), 2);
        assert!(c.warnings.is_empty());
        assert!(c.resident(4090, 20));
        let mut corrupt = memory.clone();
        put64(corrupt.get_mut(&0x25038).unwrap(), 40, 0x13000);
        let c = recover(0x20000, 10, &mut |a, n| read(&corrupt, a, n)).unwrap();
        assert_eq!(c.pages.len(), 1);
        assert!(!c.resident(4090, 20));
        assert!(c.warnings.iter().any(|w| w.contains("Pager")));
    }
    #[test]
    fn missing_page_and_node_budget_never_create_zero_evidence() {
        let mut memory = fixture();
        memory.remove(&0x24000);
        let c = recover(0x20000, 10, &mut |a, n| read(&memory, a, n)).unwrap();
        assert!(!c.resident(4096, 1));
        assert_eq!(c.parser_bytes().len(), 4096);
        let memory = fixture();
        let c = recover(0x20000, 1, &mut |a, n| read(&memory, a, n)).unwrap();
        assert_eq!(c.pages.len(), 1);
        assert!(c.warnings.iter().any(|w| w.contains("上限")));
    }
    #[test]
    fn arbitrary_sqlite_literal_is_not_a_page_cache() {
        let mut memory = fixture();
        put64(memory.get_mut(&0x21000).unwrap(), 0, 0x24000);
        assert!(recover(0x20000, 10, &mut |a, n| read(&memory, a, n)).is_err());
    }
}
