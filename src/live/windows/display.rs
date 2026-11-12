use std::time::Instant;

use windows_sys::Win32::System::Memory::MEM_PRIVATE;

use super::*;
use crate::live::display::{DisplayBuffer, DisplayFrame, DisplayGeometry};

fn open_selected(expected: &VmwareProcessIdentity) -> Result<WindowsProcess> {
    let process = WindowsProcess::open(expected.pid)?;
    ensure!(
        process.identity()? == *expected,
        "VMware 进程身份已改变，请重新发现"
    );
    ensure!(
        expected.executable.file_name().is_some_and(|name| name
            .to_string_lossy()
            .eq_ignore_ascii_case("vmware-vmx.exe")),
        "只能读取所选 VMware 进程"
    );
    Ok(process)
}

fn matches_buffer(info: &MEMORY_BASIC_INFORMATION, length: u64) -> bool {
    info.State == MEM_COMMIT
        && info.Type == MEM_PRIVATE
        && info.Protect == PAGE_READWRITE
        && info.AllocationProtect == PAGE_READWRITE
        && info.BaseAddress == info.AllocationBase
        && info.RegionSize as u64 == length
}

pub(in crate::live) fn discover(
    expected: &VmwareProcessIdentity,
    geometry: DisplayGeometry,
    cancellation: &CancellationToken,
) -> Result<Vec<DisplayBuffer>> {
    let process = open_selected(expected)?;
    let length = geometry.allocation_length()?;
    let mut buffers = Vec::new();
    let mut address = 0usize;
    for _ in 0..MAX_REGIONS {
        cancellation.check_cancelled()?;
        let Some(info) = process.query(address)? else {
            process.check_running()?;
            return Ok(buffers);
        };
        let next = (info.BaseAddress as usize)
            .checked_add(info.RegionSize)
            .context("显示内存枚举地址溢出")?;
        ensure!(next > address, "显示内存枚举未前进");
        if matches_buffer(&info, length) {
            ensure!(buffers.len() < 16, "显示缓冲候选超过 16 个，需缩小几何条件");
            buffers.push(DisplayBuffer {
                process: expected.clone(),
                host_address: info.BaseAddress as u64,
                allocation_length: length,
                geometry,
            });
        }
        address = next;
    }
    bail!("显示内存枚举超过区域预算")
}

fn validate(process: &WindowsProcess, buffer: &DisplayBuffer) -> Result<()> {
    process.check_running()?;
    ensure!(
        buffer.allocation_length == buffer.geometry.allocation_length()?,
        "显示缓冲范围与几何不一致"
    );
    let address = usize::try_from(buffer.host_address).context("显示缓冲地址溢出")?;
    let info = process.query(address)?.context("显示缓冲已释放")?;
    ensure!(
        info.BaseAddress as u64 == buffer.host_address
            && matches_buffer(&info, buffer.allocation_length),
        "显示缓冲范围或属性已改变，请重新发现"
    );
    Ok(())
}

pub(in crate::live) fn capture(
    buffer: &DisplayBuffer,
    cancellation: &CancellationToken,
) -> Result<DisplayFrame> {
    let process = open_selected(&buffer.process)?;
    capture_from_process(&process, buffer, cancellation)
}

fn capture_from_process(
    process: &WindowsProcess,
    buffer: &DisplayBuffer,
    cancellation: &CancellationToken,
) -> Result<DisplayFrame> {
    cancellation.check_cancelled()?;
    validate(process, buffer)?;
    let started = Instant::now();
    let started_unix_ms = unix_ms()?;
    let mut bytes = vec![0u8; buffer.geometry.byte_length()?];
    for (index, chunk) in bytes.chunks_mut(64 * 1024).enumerate() {
        cancellation.check_cancelled()?;
        process.check_running()?;
        let read = process.read(buffer.host_address + (index * 64 * 1024) as u64, chunk);
        ensure!(
            read.error.is_none() && read.copied == chunk.len(),
            "显示像素读取不完整：{}/{}，{}",
            read.copied,
            chunk.len(),
            read.error.as_deref().unwrap_or("短读取")
        );
    }
    validate(process, buffer)?;
    cancellation.check_cancelled()?;
    let finished_unix_ms = unix_ms()?;
    let elapsed_micros = started.elapsed().as_micros().try_into().unwrap_or(u64::MAX);
    let buffer_sha256 = hex::encode(Sha256::digest(&bytes));
    Ok(DisplayFrame {
        source_kind: "vmware_host_memory_candidate",
        buffer: buffer.clone(),
        started_unix_ms,
        finished_unix_ms,
        elapsed_micros,
        atomic_snapshot: false,
        current_scanout_proven: false,
        read_bytes: bytes.len(),
        buffer_sha256,
        bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::System::Memory::{MEM_RELEASE, MEM_RESERVE, VirtualAlloc, VirtualFree};

    struct Allocation(*mut std::ffi::c_void);
    impl Drop for Allocation {
        fn drop(&mut self) {
            unsafe {
                VirtualFree(self.0, 0, MEM_RELEASE);
            }
        }
    }

    #[test]
    fn reads_fresh_display_pixels_strips_padding_and_rejects_freed_buffer() {
        let geometry = DisplayGeometry {
            width: 64,
            height: 64,
            stride: 260,
        };
        let length = geometry.allocation_length().unwrap();
        let raw = unsafe {
            VirtualAlloc(
                std::ptr::null(),
                length as usize,
                MEM_RESERVE | MEM_COMMIT,
                PAGE_READWRITE,
            )
        };
        assert!(!raw.is_null());
        let allocation = Allocation(raw);
        let process = WindowsProcess::open(std::process::id()).unwrap();
        let buffer = DisplayBuffer {
            process: process.identity().unwrap(),
            host_address: raw as u64,
            allocation_length: length,
            geometry,
        };
        let token = CancellationToken::new();
        assert!(capture(&buffer, &token).is_err()); // Public API rejects a non-VMware process.
        unsafe {
            std::ptr::write_bytes(raw.cast::<u8>(), 7, length as usize);
        }
        let frame = capture_from_process(&process, &buffer, &token).unwrap();
        assert_eq!(frame.read_bytes, 64 * 260);
        let mut bmp = Vec::new();
        frame.write_bmp(&mut bmp).unwrap();
        assert_eq!(bmp.len(), 54 + 64 * 64 * 4);
        assert!(bmp[54..].iter().all(|byte| *byte == 7));
        unsafe {
            *raw.cast::<u8>() = 9;
        }
        let changed = capture_from_process(&process, &buffer, &token).unwrap();
        assert_ne!(frame.buffer_sha256, changed.buffer_sha256);
        assert_eq!(changed.bytes[0], 9);
        let cancelled = CancellationToken::new();
        cancelled.request_cancel();
        assert!(capture_from_process(&process, &buffer, &cancelled).is_err());
        drop(allocation);
        assert!(capture_from_process(&process, &buffer, &token).is_err());
    }
}
