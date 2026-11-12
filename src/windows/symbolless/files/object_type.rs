//! Decode two complete ObGetObjectType leaf forms, using target PE exports only.
use anyhow::{Context, Result, ensure};
use serde::Serialize;

use crate::address::X64AddressSpace;
use crate::image::MemoryImage;
use crate::windows::symbolless::{ProbeReport, export, pe_size, pointer};

#[derive(Debug, Clone, Serialize)]
pub struct ObjectTypeEvidence {
    pub accessor_address: u64,
    pub accessor_bytes: String,
    pub type_index_from_body: i64,
    pub header_from_body: Option<i64>,
    pub cookie_address: Option<u64>,
    pub type_table: u64,
    pub file_type_object: u64,
}

pub(super) struct ObjectTypeResolver {
    pub evidence: ObjectTypeEvidence,
}

fn rip_target(address: u64, code: &[u8], displacement: usize) -> Option<u64> {
    let relative = i32::from_le_bytes(code.get(displacement..displacement + 4)?.try_into().ok()?);
    address
        .checked_add(displacement as u64 + 4)?
        .checked_add_signed(i64::from(relative))
}

fn decode(address: u64, code: &[u8]) -> Option<ObjectTypeEvidence> {
    let (index, header, cookie, table) = if code.get(..3) == Some(&[0x0f, 0xb6, 0x41])
        && code.get(4..7) == Some(&[0x48, 0x8d, 0x0d])
        && code.get(11..16) == Some(&[0x48, 0x8b, 0x04, 0xc1, 0xc3])
    {
        (
            code[3] as i8 as i64,
            None,
            None,
            rip_target(address, code, 7)?,
        )
    } else if code.get(..3) == Some(&[0x48, 0x8d, 0x41])
        && code.get(4..7) == Some(&[0x0f, 0xb6, 0x49])
        && code.get(8..21)
            == Some(&[
                0x48, 0xc1, 0xe8, 0x08, 0x0f, 0xb6, 0xc0, 0x48, 0x33, 0xc1, 0x0f, 0xb6, 0x0d,
            ])
        && code.get(25..31) == Some(&[0x48, 0x33, 0xc1, 0x48, 0x8d, 0x0d])
        && code.get(35..40) == Some(&[0x48, 0x8b, 0x04, 0xc1, 0xc3])
    {
        (
            code[7] as i8 as i64,
            Some(code[3] as i8 as i64),
            Some(rip_target(address, code, 21)?),
            rip_target(address, code, 31)?,
        )
    } else {
        return None;
    };
    if index >= 0 || header.is_some_and(|offset| offset >= 0) || !pointer(table) {
        return None;
    }
    Some(ObjectTypeEvidence {
        accessor_address: address,
        accessor_bytes: hex::encode(code),
        type_index_from_body: index,
        header_from_body: header,
        cookie_address: cookie,
        type_table: table,
        file_type_object: 0,
    })
}

impl ObjectTypeResolver {
    pub fn load(image: &MemoryImage, kernel: &ProbeReport) -> Result<Self> {
        let space = X64AddressSpace::new(image, kernel.kernel_dtb)?;
        let size = pe_size(&space, kernel.kernel_base)?;
        let address = export(
            image,
            kernel.kernel_dtb,
            kernel.kernel_base,
            size,
            "ObGetObjectType",
        )?;
        let mut code = [0; 40];
        space.read_virtual(address, &mut code)?;
        let mut evidence =
            decode(address, &code).context("ObGetObjectType 不是支持的完整叶函数")?;
        evidence.file_type_object = space.read_u64(export(
            image,
            kernel.kernel_dtb,
            kernel.kernel_base,
            size,
            "IoFileObjectType",
        )?)?;
        ensure!(
            pointer(evidence.file_type_object),
            "IoFileObjectType 导出值无效"
        );
        Ok(Self { evidence })
    }

    pub fn is_file(&self, space: &X64AddressSpace<'_>, body: u64) -> Result<bool> {
        let mut value = [0];
        space.read_virtual(
            body.checked_add_signed(self.evidence.type_index_from_body)
                .context("对象头地址下溢")?,
            &mut value,
        )?;
        let mut index = value[0];
        if let (Some(header), Some(cookie)) =
            (self.evidence.header_from_body, self.evidence.cookie_address)
        {
            space.read_virtual(cookie, &mut value)?;
            let header_address = body.checked_add_signed(header).context("对象头地址下溢")?;
            index ^= ((header_address >> 8) as u8) ^ value[0];
        }
        Ok(
            space.read_u64(self.evidence.type_table + u64::from(index) * 8)?
                == self.evidence.file_type_object,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn refuses_an_incomplete_or_semantically_different_accessor() {
        let address = 0xffff_f800_0000_0000;
        let mut code = [
            0x0f, 0xb6, 0x41, 0xe8, 0x48, 0x8d, 0x0d, 0xf5, 0, 0, 0, 0x48, 0x8b, 0x04, 0xc1, 0xc3,
        ];
        assert_eq!(decode(address, &code).unwrap().type_table, address + 0x100);
        code[15] = 0x90;
        assert!(decode(address, &code).is_none());
        code[15] = 0xc3;
        code[14] = 0xc2;
        assert!(decode(address, &code).is_none());
    }
}
