use super::*;
use std::io::Write;
use std::path::Path;

pub(super) fn dump(
    m: &impl LinuxKernelMemory,
    info: u64,
    path: &Path,
    budget: u64,
    cancel: &CancellationToken,
) -> Result<u64> {
    let var = member(m, info, "fb_info", "var")?;
    let fix = member(m, info, "fb_info", "fix")?;
    ensure!(
        field(m, fix, "fb_fix_screeninfo", "type")? == 0
            && field(m, fix, "fb_fix_screeninfo", "visual")? == 2,
        "帧缓冲仅支持 packed-pixel truecolor；其他格式需备选引擎"
    );
    let width = field(m, var, "fb_var_screeninfo", "xres")?;
    let height = field(m, var, "fb_var_screeninfo", "yres")?;
    ensure!(
        (1..=16384).contains(&width) && (1..=16384).contains(&height),
        "帧缓冲尺寸越界"
    );
    let bpp = field(m, var, "fb_var_screeninfo", "bits_per_pixel")?;
    ensure!(matches!(bpp, 16 | 24 | 32), "帧缓冲位深不受支持");
    let stride = field(m, fix, "fb_fix_screeninfo", "line_length")?;
    let length = field(m, fix, "fb_fix_screeninfo", "smem_len")?;
    let x = field(m, var, "fb_var_screeninfo", "xoffset")?;
    let y = field(m, var, "fb_var_screeninfo", "yoffset")?;
    let line_bytes = width * (bpp / 8);
    let start_x = x.checked_mul(bpp / 8).context("像素偏移溢出")?;
    ensure!(
        start_x
            .checked_add(line_bytes)
            .is_some_and(|end| end <= stride),
        "可见像素超过行跨度"
    );
    let last_row = y.checked_add(height - 1).context("垂直偏移溢出")?;
    let last_end = last_row
        .checked_mul(stride)
        .and_then(|n| n.checked_add(start_x))
        .and_then(|n| n.checked_add(line_bytes))
        .context("帧缓冲范围溢出")?;
    ensure!(last_end <= length, "可见区域超过帧缓冲容量");
    let output_bytes = width * height * 4 + 54;
    ensure!(
        output_bytes <= budget,
        "BMP 需要 {output_bytes} 字节，超过 --max-bytes={budget}"
    );
    let base = pointer(field(m, info, "fb_info", "screen_base")?)?;
    let channel = |name: &str| -> Result<(u32, u32)> {
        let at = member(m, var, "fb_var_screeninfo", name)?;
        let offset = field(m, at, "fb_bitfield", "offset")?;
        let bits = field(m, at, "fb_bitfield", "length")?;
        ensure!(
            bits > 0
                && bits <= 16
                && offset + bits <= bpp
                && field(m, at, "fb_bitfield", "msb_right")? == 0,
            "颜色通道布局不受支持"
        );
        Ok((offset as u32, bits as u32))
    };
    let channels = [channel("blue")?, channel("green")?, channel("red")?];
    let mut policy = crate::output_policy::OutputPolicy::new(false);
    for input in m.source_paths() {
        policy.protect_file("Linux memory image", input);
    }
    policy.output_file("Linux framebuffer BMP", path);
    policy.preflight()?;
    policy.write_file_atomic(path, |writer| {
        writer.write_all(&bmp_header(width as u32, height as u32))?;
        let mut source = vec![0; line_bytes as usize];
        let mut row = vec![0; width as usize * 4];
        for line in 0..height {
            cancel.check_cancelled()?;
            let address = add(base, (y + line) * stride + start_x)?;
            // A missing row aborts atomic publication: no filled-in screenshot is presented.
            m.read_virtual(address, &mut source)
                .with_context(|| format!("帧缓冲第 {line} 行缺失，未发布 BMP"))?;
            for (pixel, output) in source
                .chunks_exact(bpp as usize / 8)
                .zip(row.chunks_exact_mut(4))
            {
                let mut raw = [0u8; 4];
                raw[..pixel.len()].copy_from_slice(pixel);
                let value = u32::from_le_bytes(raw);
                for (byte, (shift, bits)) in output.iter_mut().zip(channels) {
                    *byte = color_channel(value, shift, bits);
                }
                output[3] = 255;
            }
            writer.write_all(&row)?;
        }
        cancel.check_cancelled()?;
        Ok(())
    })?;
    Ok(output_bytes)
}

pub(super) fn color_channel(value: u32, shift: u32, bits: u32) -> u8 {
    let mask = (1u32 << bits) - 1;
    (((value >> shift) & mask) * 255 / mask) as u8
}

pub(super) fn bmp_header(width: u32, height: u32) -> [u8; 54] {
    let mut bytes = [0; 54];
    bytes[..2].copy_from_slice(b"BM");
    bytes[2..6].copy_from_slice(&(54 + width * height * 4).to_le_bytes());
    bytes[10..14].copy_from_slice(&54u32.to_le_bytes());
    bytes[14..18].copy_from_slice(&40u32.to_le_bytes());
    bytes[18..22].copy_from_slice(&width.to_le_bytes());
    bytes[22..26].copy_from_slice(&(-(height as i32)).to_le_bytes());
    bytes[26..28].copy_from_slice(&1u16.to_le_bytes());
    bytes[28..30].copy_from_slice(&32u16.to_le_bytes());
    bytes[34..38].copy_from_slice(&(width * height * 4).to_le_bytes());
    bytes
}
