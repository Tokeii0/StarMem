//! Inspect file-to-physical mappings without recovering each file into a buffer.
use super::*;

#[derive(Debug, Serialize)]
pub struct FileMemoryMap {
    pub file_object: u64,
    pub name: Option<String>,
    pub source: DumpSource,
    pub logical_size: u64,
    pub mapped_bytes: u64,
    pub unmapped_bytes: u64,
    pub complete: bool,
    /// File and physical offsets are both contiguous within each extent.
    pub ranges: Vec<RecoveredExtent>,
    pub warnings: Vec<String>,
}

/// Reuses the validated FILE_OBJECT/VACB/subsection walker, but records page
/// mappings instead of reading or allocating file contents. Callers must verify
/// bytes in the target ranges separately; mapped bytes are not recovered bytes.
pub fn map_file_memory(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    file_object: u64,
    source: DumpSource,
    max_size: u64,
    cancellation: &CancellationToken,
) -> Result<FileMemoryMap> {
    ensure!(
        matches!(source, DumpSource::Cache | DumpSource::Data),
        "文件物理区间反查仅支持缓存或数据节"
    );
    cancellation.check_cancelled()?;
    let mut sink = MappingSink {
        image,
        cancellation,
        ranges: Vec::new(),
        position: 0,
    };
    let report = dump_file_to_sink(
        image,
        kernel,
        profile,
        file_object,
        &mut sink,
        source,
        max_size,
    )?;
    cancellation.check_cancelled()?;
    Ok(FileMemoryMap {
        file_object: report.file_object,
        name: report.name,
        source: report.source,
        logical_size: report.logical_size,
        mapped_bytes: report.recovered_bytes,
        unmapped_bytes: report.missing_bytes,
        complete: report.complete,
        ranges: sink.ranges,
        warnings: report.warnings,
    })
}

struct MappingSink<'a> {
    image: &'a MemoryImage,
    cancellation: &'a CancellationToken,
    ranges: Vec<RecoveredExtent>,
    position: u64,
}

impl MappingSink<'_> {
    fn record(&mut self, physical: u64, offset: u64, length: usize) -> Result<bool> {
        self.cancellation.check_cancelled()?;
        // Page-table presence alone does not establish that the image acquired
        // that physical page. Require coverage by actual image spans as well.
        let end = physical
            .checked_add(length as u64)
            .context("文件映射区间溢出")?;
        let spans = self.image.spans();
        let mut position = physical;
        let index = spans.partition_point(|span| span.end() <= physical);
        for span in &spans[index..] {
            if span.start > position {
                return Ok(false);
            }
            position = position.max(span.end());
            if position >= end {
                push_extent(
                    &mut self.ranges,
                    offset,
                    length as u64,
                    physical,
                    "physical",
                );
                return Ok(true);
            }
        }
        Ok(false)
    }
}

impl Write for MappingSink<'_> {
    fn write(&mut self, _bytes: &[u8]) -> std::io::Result<usize> {
        Err(Error::new(
            ErrorKind::Unsupported,
            "文件映射反查不能写入文件内容",
        ))
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl Seek for MappingSink<'_> {
    fn seek(&mut self, from: SeekFrom) -> std::io::Result<u64> {
        match from {
            SeekFrom::Start(position) => {
                self.position = position;
                Ok(position)
            }
            _ => Err(Error::new(
                ErrorKind::Unsupported,
                "文件映射反查仅支持绝对偏移",
            )),
        }
    }
}
impl RecoverySink for MappingSink<'_> {
    fn resize(&mut self, length: u64) -> std::io::Result<()> {
        if length == 0 {
            self.ranges.clear();
        }
        Ok(())
    }
    fn copy_virtual_page(
        &mut self,
        space: &WindowsAddressSpace<'_>,
        memory: u64,
        offset: u64,
        length: usize,
    ) -> Result<bool> {
        self.cancellation.check_cancelled()?;
        match space.translate(memory) {
            Ok(physical) => self.record(physical, offset, length),
            Err(_) => Ok(false),
        }
    }
    fn copy_physical_page(
        &mut self,
        _image: &MemoryImage,
        physical: u64,
        offset: u64,
        length: usize,
    ) -> Result<bool> {
        self.record(physical, offset, length)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapping_records_pages_without_content_writes_and_respects_cancellation() {
        let path = std::env::temp_dir().join(format!(
            "starmem-file-map-{}-{}.raw",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.write_all(&vec![0x5a; 0x4000]).unwrap();
        drop(file);
        let image = MemoryImage::open(&path).unwrap();
        let handle = crate::cancellation::CancellationHandle::new();
        let token = handle.token();
        let mut sink = MappingSink {
            image: &image,
            cancellation: &token,
            ranges: Vec::new(),
            position: 0,
        };
        assert!(sink.copy_physical_page(&image, 0x1000, 0, 0x1000).unwrap());
        assert!(
            sink.copy_physical_page(&image, 0x2000, 0x1000, 0x1000)
                .unwrap()
        );
        assert_eq!(sink.ranges.len(), 1);
        assert_eq!(sink.ranges[0].length, 0x2000);
        assert_eq!(sink.ranges[0].memory_address, 0x1000);
        assert!(!sink.copy_physical_page(&image, 0x4000, 0x2000, 1).unwrap());
        assert!(sink.write(b"content writes are forbidden").is_err());
        let mut recovery = Cursor::new(Vec::new());
        assert!(recovery.copy_physical_page(&image, 0x1000, 0, 32).unwrap());
        assert_eq!(recovery.into_inner(), vec![0x5a; 32]);
        handle.cancel();
        assert!(sink.copy_physical_page(&image, 0x1000, 0, 16).is_err());
        drop(sink);
        drop(image);
        std::fs::remove_file(path).unwrap();
    }
}
