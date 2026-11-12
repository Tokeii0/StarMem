//! Experimental host-side VMware display-buffer reads. Geometry is supplied
//! explicitly; allocation-size matching discovers candidates, not scanout state.
use std::io::Write;

use anyhow::{Result, ensure};
use serde::Serialize;

use super::VmwareProcessIdentity;
use crate::cancellation::CancellationToken;

const MAX_FRAME_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct DisplayGeometry {
    pub width: u32,
    pub height: u32,
    pub stride: u32,
}

impl DisplayGeometry {
    pub fn byte_length(self) -> Result<usize> {
        ensure!(
            (64..=8192).contains(&self.width) && (64..=8192).contains(&self.height),
            "显示缓冲尺寸必须为 64–8192"
        );
        ensure!(
            self.stride >= self.width * 4
                && self.stride <= self.width * 4 + 4096
                && self.stride.is_multiple_of(4),
            "BGRX 行跨度无效"
        );
        let length = u64::from(self.stride) * u64::from(self.height);
        ensure!(
            length <= MAX_FRAME_BYTES as u64,
            "显示缓冲超过 64 MiB 读取预算"
        );
        Ok(length as usize)
    }

    #[cfg(any(windows, test))]
    pub(crate) fn allocation_length(self) -> Result<u64> {
        Ok((self.byte_length()? as u64).div_ceil(4096) * 4096)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DisplayBuffer {
    pub process: VmwareProcessIdentity,
    pub host_address: u64,
    pub allocation_length: u64,
    pub geometry: DisplayGeometry,
}

#[derive(Debug, Serialize)]
pub struct DisplayFrame {
    pub source_kind: &'static str,
    pub buffer: DisplayBuffer,
    pub started_unix_ms: u64,
    pub finished_unix_ms: u64,
    pub elapsed_micros: u64,
    pub atomic_snapshot: bool,
    pub current_scanout_proven: bool,
    pub read_bytes: usize,
    /// Hash covers the entire read buffer, including any row padding.
    pub buffer_sha256: String,
    #[serde(skip)]
    pub(crate) bytes: Vec<u8>,
}

impl DisplayFrame {
    /// Writes actual BGRX pixels as a top-down BMP, excluding row padding.
    /// The caller controls atomic publication of the destination file.
    pub fn write_bmp(&self, mut writer: impl Write) -> Result<()> {
        let shape = self.buffer.geometry;
        ensure!(
            self.bytes.len() == shape.byte_length()?,
            "显示缓冲字节不完整"
        );
        let pixels = shape.width * shape.height * 4;
        let mut header = [0u8; 54];
        header[..2].copy_from_slice(b"BM");
        header[2..6].copy_from_slice(&(54 + pixels).to_le_bytes());
        header[10..14].copy_from_slice(&54u32.to_le_bytes());
        header[14..18].copy_from_slice(&40u32.to_le_bytes());
        header[18..22].copy_from_slice(&(shape.width as i32).to_le_bytes());
        header[22..26].copy_from_slice(&(-(shape.height as i32)).to_le_bytes());
        header[26..28].copy_from_slice(&1u16.to_le_bytes());
        header[28..30].copy_from_slice(&32u16.to_le_bytes());
        header[34..38].copy_from_slice(&pixels.to_le_bytes());
        writer.write_all(&header)?;
        for row in self.bytes.chunks_exact(shape.stride as usize) {
            writer.write_all(&row[..shape.width as usize * 4])?;
        }
        writer.flush()?;
        Ok(())
    }
}

/// Finds at most 16 private, committed RW allocations of the supplied rounded
/// frame size. No screenshot API, VNC connection, or guest program is used.
pub fn discover_display_buffers(
    process: &VmwareProcessIdentity,
    geometry: DisplayGeometry,
    cancellation: &CancellationToken,
) -> Result<Vec<DisplayBuffer>> {
    geometry.byte_length()?;
    cancellation.check_cancelled()?;
    #[cfg(windows)]
    {
        super::windows::display::discover(process, geometry, cancellation)
    }
    #[cfg(not(windows))]
    {
        let _ = process;
        anyhow::bail!("VMware 显示内存读取仅支持 Windows 主机")
    }
}

/// Reopens and verifies the exact process and allocation. Failure/cancellation
/// returns no frame; successful reads are still non-atomic candidate images.
pub fn capture_display_buffer(
    buffer: &DisplayBuffer,
    cancellation: &CancellationToken,
) -> Result<DisplayFrame> {
    buffer.geometry.byte_length()?;
    cancellation.check_cancelled()?;
    #[cfg(windows)]
    {
        super::windows::display::capture(buffer, cancellation)
    }
    #[cfg(not(windows))]
    {
        anyhow::bail!("VMware 显示内存读取仅支持 Windows 主机")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn geometry_enforces_buffer_budget_and_stride() {
        let valid = DisplayGeometry {
            width: 1379,
            height: 860,
            stride: 5516,
        };
        assert_eq!(valid.byte_length().unwrap(), 4_743_760);
        assert_eq!(valid.allocation_length().unwrap(), 4_747_264);
        assert!(
            DisplayGeometry {
                stride: 5512,
                ..valid
            }
            .byte_length()
            .is_err()
        );
        assert!(
            DisplayGeometry {
                stride: 5517,
                ..valid
            }
            .byte_length()
            .is_err()
        );
        assert!(
            DisplayGeometry {
                width: 8192,
                height: 8192,
                stride: 32768
            }
            .byte_length()
            .is_err()
        );
    }
}
