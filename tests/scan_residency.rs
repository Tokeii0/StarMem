//! Large scans must not populate the session's permanent mmap working set.
use std::io::{Seek, SeekFrom, Write};

use starmem::{cancellation::CancellationToken, image::MemoryImage, scan::scan_exact_cancellable};

#[test]
fn bulk_scan_preserves_unaligned_boundary_hits_without_retaining_image_pages() {
    let mut file = tempfile::Builder::new().suffix(".raw").tempfile().unwrap();
    let length = 64 * 1024 * 1024;
    file.as_file().set_len(length).unwrap();
    // Cross both a scanner chunk and a temporary mapping window boundary.
    let needle = b"Linux version residency-fixture";
    let offset = 8 * 1024 * 1024 - 5;
    file.seek(SeekFrom::Start(offset)).unwrap();
    file.write_all(needle).unwrap();
    file.flush().unwrap();
    let image = MemoryImage::open(file.path()).unwrap();
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(2)
        .build()
        .unwrap();
    let report = pool
        .install(|| {
            scan_exact_cancellable(
                &image,
                needle,
                16,
                8 * 1024 * 1024,
                &CancellationToken::new(),
            )
        })
        .unwrap();
    assert!(report.complete);
    assert_eq!(report.bytes_scanned, length);
    assert_eq!(report.hits.len(), 1);
    assert_eq!(report.hits[0].physical_address, offset);
    assert_eq!(report.hits[0].file_offset, offset);

    // Query page residency, not a timing-dependent process peak. Merely getting
    // the permanent map's address must not fault any of its data pages in.
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::{
            ProcessStatus::{PSAPI_WORKING_SET_EX_INFORMATION, QueryWorkingSetEx},
            Threading::GetCurrentProcess,
        };
        let bytes = image.direct_bytes().unwrap();
        let mut pages: Vec<_> = (1024 * 1024..bytes.len())
            .step_by(64 * 1024)
            .map(|offset| PSAPI_WORKING_SET_EX_INFORMATION {
                VirtualAddress: bytes.as_ptr().wrapping_add(offset) as *mut _,
                ..Default::default()
            })
            .collect();
        let ok = unsafe {
            QueryWorkingSetEx(
                GetCurrentProcess(),
                pages.as_mut_ptr().cast(),
                std::mem::size_of_val(pages.as_slice()) as u32,
            )
        };
        assert_ne!(ok, 0, "{}", std::io::Error::last_os_error());
        let resident = pages
            .iter()
            .filter(|page| unsafe { page.VirtualAttributes.Flags & 1 != 0 })
            .count();
        assert!(
            resident < 16,
            "scan retained {resident}/{} sampled image pages",
            pages.len()
        );
    }
}

#[test]
fn linux_loading_scans_honor_pre_cancelled_requests() {
    use starmem::{
        cancellation::is_cancellation_error, linux::LinuxAnalysisSession,
        linux_info::analyze_linux_info_cancellable, symbols::SymbolStore,
    };
    let mut file = tempfile::Builder::new().suffix(".raw").tempfile().unwrap();
    file.write_all(&[0; 8192]).unwrap();
    let cancellation = CancellationToken::new();
    cancellation.request_cancel();
    let image = MemoryImage::open(file.path()).unwrap();
    let error = analyze_linux_info_cancellable(&image, &cancellation).unwrap_err();
    assert!(is_cancellation_error(&error));
    let symbols = SymbolStore::new(file.path().with_extension("symbols"));
    let error = match LinuxAnalysisSession::from_image_with_symbol_store_cancellable(
        image,
        &symbols,
        &cancellation,
    ) {
        Err(error) => error,
        Ok(_) => panic!("cancelled session was opened"),
    };
    assert!(is_cancellation_error(&error));
}

#[test]
fn parallel_bulk_reads_keep_offsets_and_original_source_identity() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("source.raw");
    let bytes: Vec<u8> = (0..20 * 1024 * 1024usize)
        .map(|offset| (offset.wrapping_mul(31) ^ (offset >> 12)) as u8)
        .collect();
    std::fs::write(&path, &bytes).unwrap();
    let image = MemoryImage::open(&path).unwrap();
    // A renamed/replaced path must not redirect an already opened image.
    std::fs::rename(&path, directory.path().join("original.raw")).unwrap();
    std::fs::write(&path, vec![0xcc; bytes.len()]).unwrap();
    std::thread::scope(|scope| {
        for offset in [13usize, 4093, 9 * 1024 * 1024 + 7] {
            let image = &image;
            let bytes = &bytes;
            scope.spawn(move || {
                let mut actual = vec![0; 8 * 1024 * 1024 + 71];
                for _ in 0..3 {
                    image.read_backing(offset as u64, &mut actual).unwrap();
                    assert_eq!(actual, bytes[offset..offset + actual.len()]);
                }
            });
        }
    });
    let mut past_end = vec![0; 64 * 1024];
    assert!(
        image
            .read_backing(bytes.len() as u64 - 1, &mut past_end)
            .is_err()
    );
}
