use std::{fs, path::Path};

use anyhow::{Context, Result, anyhow, bail};

pub struct PeImage {
    data: Vec<u8>,
    sections: Vec<PeSection>,
    image_base: u64,
}

struct PeSection {
    virtual_address: u32,
    virtual_size: u32,
    raw_offset: u32,
    raw_size: u32,
}

impl PeImage {
    pub fn read(path: &Path) -> Result<Self> {
        let data = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
        if data.get(..2) != Some(b"MZ") {
            bail!("{} is not a PE image", path.display());
        }

        let pe_offset = read_u32(&data, 0x3C)? as usize;
        if data.get(pe_offset..pe_offset + 4) != Some(b"PE\0\0") {
            bail!("{} has invalid PE signature", path.display());
        }

        let coff = pe_offset + 4;
        let section_count = read_u16(&data, coff + 2)? as usize;
        let optional_header_size = read_u16(&data, coff + 16)? as usize;
        let optional_header = coff + 20;
        let section_table = coff + 20 + optional_header_size;
        let optional_magic = read_u16(&data, optional_header)?;
        let image_base = match optional_magic {
            0x20B => read_u64(&data, optional_header + 24)?,
            0x10B => read_u32(&data, optional_header + 28)? as u64,
            _ => bail!(
                "{} has unsupported PE optional header magic",
                path.display()
            ),
        };

        let mut sections = Vec::with_capacity(section_count);
        for index in 0..section_count {
            let section_offset = section_table + index * 40;
            sections.push(PeSection {
                virtual_size: read_u32(&data, section_offset + 8)?,
                virtual_address: read_u32(&data, section_offset + 12)?,
                raw_size: read_u32(&data, section_offset + 16)?,
                raw_offset: read_u32(&data, section_offset + 20)?,
            });
        }

        Ok(Self {
            data,
            sections,
            image_base,
        })
    }

    pub fn image_base(&self) -> u64 {
        self.image_base
    }

    pub fn read_u32_rva(&self, rva: u32) -> Result<u32> {
        let offset = self.rva_to_offset(rva)?;
        read_u32(&self.data, offset)
    }

    pub fn read_u16_rva(&self, rva: u32) -> Result<u16> {
        let offset = self.rva_to_offset(rva)?;
        read_u16(&self.data, offset)
    }

    pub fn read_i32_rva(&self, rva: u32) -> Result<i32> {
        let offset = self.rva_to_offset(rva)?;
        read_i32(&self.data, offset)
    }

    pub fn read_u64_rva(&self, rva: u32) -> Result<u64> {
        let offset = self.rva_to_offset(rva)?;
        read_u64(&self.data, offset)
    }

    #[allow(dead_code)]
    pub fn read_bytes_rva(&self, rva: u32, size: usize) -> Result<&[u8]> {
        let offset = self.rva_to_offset(rva)?;
        self.data
            .get(offset..offset + size)
            .ok_or_else(|| anyhow!("RVA byte range 0x{rva:X} size 0x{size:X} is out of range"))
    }

    pub fn rva_to_offset(&self, rva: u32) -> Result<usize> {
        for section in &self.sections {
            let size = section.virtual_size.max(section.raw_size);
            if rva >= section.virtual_address && rva < section.virtual_address + size {
                return Ok((section.raw_offset + (rva - section.virtual_address)) as usize);
            }
        }

        Err(anyhow!("RVA 0x{rva:X} is outside PE sections"))
    }

    #[allow(dead_code)]
    pub fn scan_rip_relative_xrefs(&self, target_va: u64) -> Vec<u32> {
        let mut matches = Vec::new();
        for section in &self.sections {
            let start = section.raw_offset as usize;
            let end = start.saturating_add(section.raw_size as usize);
            if end > self.data.len() || end < start + 4 {
                continue;
            }

            for offset in start..end - 4 {
                let displacement =
                    i32::from_le_bytes(self.data[offset..offset + 4].try_into().unwrap());
                let displacement_rva = section.virtual_address + (offset - start) as u32;
                let rip_after_displacement =
                    self.image_base + displacement_rva as u64 + std::mem::size_of::<i32>() as u64;
                if rip_after_displacement.wrapping_add_signed(displacement as i64) == target_va {
                    matches.push(displacement_rva);
                }
            }
        }
        matches
    }

    pub fn scan_pattern(&self, pattern: &[Option<u8>]) -> Vec<u32> {
        let mut matches = Vec::new();
        if pattern.is_empty() {
            return matches;
        }

        for section in &self.sections {
            let start = section.raw_offset as usize;
            let end = start.saturating_add(section.raw_size as usize);
            if end > self.data.len() || end < start + pattern.len() {
                continue;
            }

            for offset in start..=end - pattern.len() {
                if pattern.iter().enumerate().all(|(index, expected)| {
                    expected.is_none_or(|byte| self.data[offset + index] == byte)
                }) {
                    matches.push(section.virtual_address + (offset - start) as u32);
                }
            }
        }

        matches
    }
}

fn read_u16(data: &[u8], offset: usize) -> Result<u16> {
    let bytes = data
        .get(offset..offset + 2)
        .ok_or_else(|| anyhow!("read out of range at 0x{offset:X}"))?;
    Ok(u16::from_le_bytes(bytes.try_into()?))
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32> {
    let bytes = data
        .get(offset..offset + 4)
        .ok_or_else(|| anyhow!("read out of range at 0x{offset:X}"))?;
    Ok(u32::from_le_bytes(bytes.try_into()?))
}

fn read_i32(data: &[u8], offset: usize) -> Result<i32> {
    let bytes = data
        .get(offset..offset + 4)
        .ok_or_else(|| anyhow!("read out of range at 0x{offset:X}"))?;
    Ok(i32::from_le_bytes(bytes.try_into()?))
}

fn read_u64(data: &[u8], offset: usize) -> Result<u64> {
    let bytes = data
        .get(offset..offset + 8)
        .ok_or_else(|| anyhow!("read out of range at 0x{offset:X}"))?;
    Ok(u64::from_le_bytes(bytes.try_into()?))
}
