use anyhow::{Context, Result};
use std::{collections::HashMap, fs, path::Path};

use crate::{
    pe_image::PeImage,
    static_layout::inspect_game_assembly,
};

use super::*;
use super::super::*;
impl LayoutMetadata {
    pub fn load(
        game_assembly: &Path,
        global_data: Vec<u8>,
        startup_metadata: &Path,
    ) -> Result<Self> {
        let mut layout = inspect_game_assembly(game_assembly)?;
        discover_type_layout_keys(&mut layout, &global_data)?;
        let startup_data = fs::read(startup_metadata)
            .with_context(|| format!("failed to read {}", startup_metadata.display()))?;
        let pe = PeImage::read(game_assembly)?;
        let image_base = pe.image_base();
        let (
            il2cpp_type_table_ptr_offset,
            _method_pointer_table_ptr_offset,
            generic_inst_table_ptr_offset,
        ) = (0x68, 0x88, 0x20);
        let mut il2cpp_type_table_rva = va_to_rva(
            pe.read_u64_rva(layout.descriptor_rva + il2cpp_type_table_ptr_offset)
                .unwrap_or(0),
            image_base,
            "Il2CppType table",
        )
        .unwrap_or(0);

        if il2cpp_type_table_rva == 0 {
            // Dynamically scan for il2cpp_type_table in GameAssembly.dll
            let data = std::fs::read(game_assembly)
                .with_context(|| format!("failed to read {}", game_assembly.display()))?;
            for offset in (0..data.len().saturating_sub(16)).step_by(16) {
                let mut score = 0;
                let mut curr = offset;
                while curr + 16 <= data.len() {
                    let kind = data[curr + 10];
                    let byref = data[curr + 11];
                    if kind > 0 && kind < 0x50 && (byref == 0 || byref == 1 || byref == 0x80 || byref == 0x81) {
                        score += 1;
                    } else {
                        break;
                    }
                    curr += 16;
                    if score > 10000 {
                        // Found it! Map file offset to RVA using pe.read_u64_rva
                        let expected_val = u64::from_le_bytes(data[offset..offset+8].try_into().unwrap());
                        for rva_offset in (0x0..0x2000).step_by(0x200) {
                            let candidate_rva = (offset + rva_offset) as u32;
                            if let Ok(val) = pe.read_u64_rva(candidate_rva) {
                                if val == expected_val {
                                    il2cpp_type_table_rva = candidate_rva;
                                    break;
                                }
                            }
                        }
                        break;
                    }
                }
                if il2cpp_type_table_rva != 0 {
                    println!("  dynamically discovered type table RVA: 0x{:X}", il2cpp_type_table_rva);
                    break;
                }
            }
        }
        let mut sorted_rvas = Vec::new();
        for rva in (0..pe.raw_data().len() as u32 - 8).step_by(8) {
            if let Ok(val) = pe.read_u64_rva(rva) {
                if val >= image_base && val < image_base + pe.raw_data().len() as u64 {
                    sorted_rvas.push((val - image_base) as u32);
                }
            }
        }
        sorted_rvas.sort_unstable();

        let mut method_pointer_table_rva = 0;
        if let Ok(va) = pe.read_u64_rva(layout.metadata_registration_rva + 0x40) {
            method_pointer_table_rva = (va - image_base) as u32;
        }

        if method_pointer_table_rva == 0 {
            let data = pe.raw_data();
            let mut best_offset = 0;
            let mut best_score = 0;
            for offset in (0..data.len().saturating_sub(8)).step_by(8) {
                let mut score = 0;
                let mut current = offset;
                while current + 8 <= data.len() {
                    let val = u64::from_le_bytes(data[current..current+8].try_into().unwrap());
                    if val >= image_base + 0x1000 && val < image_base + 0x30000000 && val != image_base + 0x1020 && val != image_base + 0x2FCA210 {
                        score += 1;
                    } else {
                        break;
                    }
                    current += 8;
                    if score > 200000 {
                        best_offset = offset;
                        best_score = score;
                        break;
                    }
                }
                if best_score > 200000 {
                    break;
                }
            }
            if best_score > 200000 {
                let mut true_start = best_offset;
                while true_start >= 8 {
                    let test_offset = true_start - 8;
                    let val = u64::from_le_bytes(data[test_offset..test_offset+8].try_into().unwrap());
                    if val >= image_base + 0x1000 && val < image_base + 0x30000000 && val != image_base + 0x1020 && val != image_base + 0x2FCA210 {
                        true_start = test_offset;
                    } else {
                        break;
                    }
                }
                if let Some(rva) = pe.file_offset_to_rva(true_start) {
                    method_pointer_table_rva = rva;
                    println!("  dynamically discovered method pointer table RVA: 0x{:X}", rva);
                }
            }
        }

        let mut generic_inst_table_rva = va_to_rva(
            pe.read_u64_rva(layout.descriptor_rva + generic_inst_table_ptr_offset).unwrap_or(0),
            image_base,
            "generic inst table",
        ).unwrap_or(0);

        if true {
            let data = pe.raw_data();
            let mut best_offset = 0;
            let mut best_score = 0;
            for offset in (0..data.len().saturating_sub(16)).step_by(16) {
                let mut score = 0;
                let mut current = offset;
                while current + 16 <= data.len() {
                    let argc = u32::from_le_bytes(data[current..current+4].try_into().unwrap());
                    let padding = u32::from_le_bytes(data[current+4..current+8].try_into().unwrap());
                    let ptr_hi = data[current+15];
                    if argc > 0 && argc < 30 && padding == 0 && (ptr_hi == 0x01 || ptr_hi == 0x00 || ptr_hi == 0x7F || ptr_hi == 0x02) {
                        score += 1;
                    } else {
                        break;
                    }
                    current += 16;
                    if score > 1000 {
                        best_offset = offset;
                        best_score = score;
                        break;
                    }
                }
                if best_score > 1000 {
                    break;
                }
            }
            if best_score > 1000 {
                let mut true_start = best_offset;
                while true_start >= 16 {
                    let test = true_start - 16;
                    let argc = u32::from_le_bytes(data[test..test+4].try_into().unwrap());
                    let padding = u32::from_le_bytes(data[test+4..test+8].try_into().unwrap());
                    let ptr_hi = data[test+15];
                    if argc > 0 && argc < 30 && padding == 0 && (ptr_hi == 0x01 || ptr_hi == 0x00 || ptr_hi == 0x7F || ptr_hi == 0x02) {
                        true_start = test;
                    } else {
                        break;
                    }
                }
                if let Some(rva) = pe.file_offset_to_rva(true_start) {
                    generic_inst_table_rva = rva;
                    println!("  dynamically discovered generic inst table RVA: 0x{:X}", rva);
                }
            }
        }
        let method_attribute_xor = discover_method_attribute_xor(&pe)?;

        let mut metadata = Self {
            layout,
            global_data,
            startup_data,
            pe,
            image_base,
            il2cpp_type_table_rva,
            method_pointer_table_rva,
            generic_inst_table_rva,
            method_attribute_xor,
            images: Vec::new(),
            types: Vec::new(),
            string_cache: HashMap::new(),
            type_name_cache: HashMap::new(),
            generic_container_cache: HashMap::new(),
        };
        metadata.images = metadata.read_images()?;

        let max_types = metadata.images.iter().map(|img| img.type_start + img.type_count).max().unwrap_or(0);
        if max_types > 0 {
            metadata.layout.descriptor_count_80 = max_types as u32;
        }

        metadata.types = metadata.read_types()?;
        Ok(metadata)
    }

}
