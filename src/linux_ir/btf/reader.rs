use super::*;
use std::collections::BTreeMap;

/// Only caches pages inside the BTF symbol range. Failed pages are never zero-filled.
pub(super) struct Reader<'a, M> {
    memory: &'a M,
    cancel: &'a CancellationToken,
    pub start: u64,
    total: u64,
    budget: u64,
    pub attempted: u64,
    pub checked: u64,
    pub missing: Vec<Value>,
    pub missing_count: usize,
    pages: BTreeMap<u64, std::result::Result<Vec<u8>, String>>,
}

impl<'a, M: LinuxKernelMemory> Reader<'a, M> {
    pub fn new(
        memory: &'a M,
        cancel: &'a CancellationToken,
        start: u64,
        total: u64,
        budget: u64,
    ) -> Self {
        Self {
            memory,
            cancel,
            start,
            total,
            budget,
            attempted: 0,
            checked: 0,
            missing: Vec::new(),
            missing_count: 0,
            pages: BTreeMap::new(),
        }
    }

    fn page(&mut self, offset: u64) -> Result<(u64, &[u8])> {
        self.cancel.check_cancelled()?;
        ensure!(offset < self.total, "BTF 读取偏移超出符号范围");
        let address = add(self.start, offset)?;
        let base = (address & !4095).max(self.start);
        let relative = base - self.start;
        if !self.pages.contains_key(&relative) {
            let length = (4096 - (base & 4095)).min(self.total - relative);
            ensure!(
                self.attempted + length <= self.budget,
                "BTF 读取预算已用尽（{} 字节）",
                self.budget
            );
            self.attempted += length;
            let mut bytes = vec![0; length as usize];
            let page = match self.memory.read_virtual(base, &mut bytes) {
                Ok(()) => {
                    self.checked += length;
                    Ok(bytes)
                }
                Err(error) => {
                    if crate::cancellation::is_cancellation_error(&error) {
                        return Err(error);
                    }
                    self.missing_count += 1;
                    if self.missing.len() < 128 {
                        self.missing.push(json!({"btf_offset":relative,"virtual_address":base,"length":length,"reason":format!("{error:#}")}));
                    }
                    Err(format!("BTF 偏移 {relative:#x} 的驻留页不可读：{error:#}"))
                }
            };
            self.pages.insert(relative, page);
        }
        match self.pages.get(&relative).context("BTF 页缓存缺失")? {
            Ok(bytes) => Ok((relative, bytes)),
            Err(error) => anyhow::bail!("{error}"),
        }
    }

    pub fn read(&mut self, offset: u64, length: usize) -> Result<Vec<u8>> {
        ensure!(add(offset, length as u64)? <= self.total, "BTF 字段越界");
        let mut result = Vec::with_capacity(length);
        while result.len() < length {
            let at = offset + result.len() as u64;
            let (base, page) = self.page(at)?;
            let begin = (at - base) as usize;
            let count = (length - result.len()).min(page.len() - begin);
            result.extend_from_slice(&page[begin..begin + count]);
        }
        Ok(result)
    }

    pub fn name(&mut self, section: u64, length: u64, offset: u32) -> Result<String> {
        ensure!((offset as u64) < length, "名称偏移超出 BTF 字符串表");
        let mut bytes = Vec::new();
        let begin = add(section, offset as u64)?;
        let end = add(section, length)?;
        while begin + (bytes.len() as u64) < end && bytes.len() < 4096 {
            let at = begin + bytes.len() as u64;
            let (base, page) = self.page(at)?;
            let within = (at - base) as usize;
            let count = (page.len() - within)
                .min((end - at) as usize)
                .min(4096 - bytes.len());
            let chunk = &page[within..within + count];
            if let Some(nul) = chunk.iter().position(|byte| *byte == 0) {
                bytes.extend_from_slice(&chunk[..nul]);
                return String::from_utf8(bytes).context("BTF 名称不是有效 UTF-8");
            }
            bytes.extend_from_slice(chunk);
        }
        anyhow::bail!("BTF 名称未在字符串区段及 4096 字节范围内以 NUL 结束")
    }

    pub fn checked_prefix(&self) -> u64 {
        let mut end = 0;
        for (&start, page) in &self.pages {
            if start != end {
                break;
            }
            match page {
                Ok(bytes) => end += bytes.len() as u64,
                Err(_) => break,
            }
        }
        end
    }
}
