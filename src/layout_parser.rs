use std::{fs, path::Path};

use anyhow::{Context, Result, anyhow};

use crate::static_layout::StaticLayout;

const IMAGE_ENTRY_SIZE: usize = 40;
const ASSEMBLY_LINK_ENTRY_SIZE: usize = 16;
const ASSEMBLY_NAME_ENTRY_SIZE: usize = 44;
const TYPE_ENTRY_SIZE: usize = 0x46;
const METHOD_ENTRY_SIZE: usize = 26;
const INTERFACE_PAIR_SIZE: usize = 8;
const STRING_PAYLOAD_INCREMENT: u64 = 0x3E69_3CD2_3A41_FDEF;
const STRING_PAYLOAD_SEED_MUL: u64 = 0x907C_4962_2D94_D21A;
const STRING_PAYLOAD_SEED_ADD: u64 = 0x75B6_79DA_F67C_3F24;

pub fn inspect_metadata_sections(
    layout: &StaticLayout,
    global_data: &[u8],
    startup_path: Option<&Path>,
) -> Result<()> {
    let Some(startup_path) = startup_path else {
        println!("Metadata section preview skipped: startup-metadata.dat not found.");
        return Ok(());
    };

    let startup_data = fs::read(startup_path)
        .with_context(|| format!("failed to read {}", startup_path.display()))?;

    println!("Metadata section preview:");
    print_image_preview(layout, global_data, &startup_data)?;
    print_assembly_preview(layout, global_data, &startup_data)?;
    print_type_preview(layout, global_data, &startup_data)?;
    print_method_preview(layout, global_data, &startup_data)?;
    print_interface_pair_preview(layout, &startup_data)?;
    Ok(())
}

fn print_image_preview(
    layout: &StaticLayout,
    global_data: &[u8],
    startup_data: &[u8],
) -> Result<()> {
    let image_count = layout.header_count_134_div40 as usize;
    let image_table = layout.startup_image_table_offset as usize;
    require_range(
        startup_data,
        image_table,
        image_count.saturating_mul(IMAGE_ENTRY_SIZE),
        "startup image table",
    )?;

    println!(
        "  image table: offset 0x{:X}, count {}",
        image_table, image_count
    );

    let preview_count = image_count.min(10);
    for index in 0..preview_count {
        let entry_offset = image_table + index * IMAGE_ENTRY_SIZE;
        let name_index = decode_image_name_index(startup_data, entry_offset, index)?;
        let type_start = decode_image_type_start(startup_data, entry_offset, index)?;
        let type_count = decode_image_type_count(startup_data, entry_offset, index)?;
        let name = decode_string(global_data, layout, name_index)?;
        println!(
            "    image[{index}] type_range={type_start}..{} name_index=0x{name_index:08X} name={name}",
            type_start + type_count
        );
    }

    Ok(())
}

fn print_assembly_preview(
    layout: &StaticLayout,
    global_data: &[u8],
    startup_data: &[u8],
) -> Result<()> {
    let assembly_count = layout.header_count_178 as usize;
    let link_table = layout.startup_assembly_table_offset as usize;
    let name_table = layout.startup_assembly_name_table_offset as usize;
    require_range(
        startup_data,
        link_table,
        assembly_count.saturating_mul(ASSEMBLY_LINK_ENTRY_SIZE),
        "startup assembly link table",
    )?;
    require_range(
        startup_data,
        name_table,
        assembly_count.saturating_mul(ASSEMBLY_NAME_ENTRY_SIZE),
        "startup assembly name table",
    )?;

    println!(
        "  assembly table: link offset 0x{:X}, name offset 0x{:X}, count {}",
        link_table, name_table, assembly_count
    );

    let preview_count = assembly_count.min(10);
    for index in 0..preview_count {
        let link_offset = link_table + index * ASSEMBLY_LINK_ENTRY_SIZE;
        let name_offset = name_table + index * ASSEMBLY_NAME_ENTRY_SIZE;
        let image_index = decode_assembly_image_index(startup_data, link_offset, index)?;
        let name_index = decode_assembly_name_index(startup_data, name_offset, index)?;
        let name = decode_string(global_data, layout, name_index)?;
        println!(
            "    assembly[{index}] image_index={image_index} name_index=0x{name_index:08X} name={name}"
        );
    }

    Ok(())
}

fn print_type_preview(
    layout: &StaticLayout,
    global_data: &[u8],
    startup_data: &[u8],
) -> Result<()> {
    let image_table = layout.startup_image_table_offset as usize;
    let first_image_entry = image_table;
    let type_start = decode_image_type_start(startup_data, first_image_entry, 0)? as usize;
    let type_count = decode_image_type_count(startup_data, first_image_entry, 0)? as usize;
    let type_table = layout.payload_offset as usize + layout.global_type_table_offset as usize;
    require_range(
        global_data,
        type_table + type_start * TYPE_ENTRY_SIZE,
        type_count.saturating_mul(TYPE_ENTRY_SIZE),
        "global type table",
    )?;

    println!(
        "  type table: offset 0x{:X}, first image type count {}",
        type_table, type_count
    );

    let preview_count = type_count.min(12);
    for local_index in 0..preview_count {
        let type_index = type_start + local_index;
        let entry_offset = type_table + type_index * TYPE_ENTRY_SIZE;
        let namespace_index = decode_type_namespace_index(global_data, entry_offset)?;
        let name_index = decode_type_name_index(global_data, entry_offset)?;
        let method_start = decode_type_method_start(global_data, entry_offset)?;
        let method_count = decode_type_method_count(global_data, entry_offset)?;
        let namespace = decode_string(global_data, layout, namespace_index)?;
        let name = decode_string(global_data, layout, name_index)?;
        let method_range = format_method_range(method_start, method_count);
        if namespace.is_empty() {
            println!("    type[{type_index}] {method_range} name={name}");
        } else {
            println!("    type[{type_index}] {method_range} name={namespace}.{name}");
        }
    }

    Ok(())
}

fn print_method_preview(
    layout: &StaticLayout,
    global_data: &[u8],
    startup_data: &[u8],
) -> Result<()> {
    let image_table = layout.startup_image_table_offset as usize;
    let first_image_entry = image_table;
    let type_start = decode_image_type_start(startup_data, first_image_entry, 0)? as usize;
    let type_count = decode_image_type_count(startup_data, first_image_entry, 0)? as usize;
    let type_table = layout.payload_offset as usize + layout.global_type_table_offset as usize;
    let method_table = layout.payload_offset as usize + layout.global_method_table_offset as usize;
    require_range(
        global_data,
        type_table + type_start * TYPE_ENTRY_SIZE,
        type_count.saturating_mul(TYPE_ENTRY_SIZE),
        "global type table",
    )?;

    let Some((type_index, entry_offset, method_start, method_count)) =
        find_first_type_with_methods(global_data, type_table, type_start, type_count)?
    else {
        println!("  method table: no methods found in first image");
        return Ok(());
    };

    let method_start_usize = method_start as usize;
    let method_count_usize = method_count as usize;
    require_range(
        global_data,
        method_table + method_start_usize * METHOD_ENTRY_SIZE,
        method_count_usize.saturating_mul(METHOD_ENTRY_SIZE),
        "global method table",
    )?;

    let namespace = decode_string(
        global_data,
        layout,
        decode_type_namespace_index(global_data, entry_offset)?,
    )?;
    let type_name = decode_string(
        global_data,
        layout,
        decode_type_name_index(global_data, entry_offset)?,
    )?;
    let full_type_name = if namespace.is_empty() {
        type_name
    } else {
        format!("{namespace}.{type_name}")
    };

    println!(
        "  method table: offset 0x{:X}, first method type[{}] {} range={}..{}",
        method_table,
        type_index,
        full_type_name,
        method_start,
        method_start + method_count as u32
    );

    let preview_count = method_count_usize.min(10);
    for local_index in 0..preview_count {
        let method_index = method_start_usize + local_index;
        let entry_offset = method_table + method_index * METHOD_ENTRY_SIZE;
        let name_index = decode_method_name_index(global_data, entry_offset, method_index)?;
        let name = decode_string(global_data, layout, name_index)?;
        println!("    method[{method_index}] name_index=0x{name_index:08X} name={name}");
    }

    Ok(())
}

fn print_interface_pair_preview(layout: &StaticLayout, startup_data: &[u8]) -> Result<()> {
    let pair_count = layout.header_count_bc as usize;
    let pair_table = layout.startup_section_164_offset as usize;
    require_range(
        startup_data,
        pair_table,
        pair_count.saturating_mul(INTERFACE_PAIR_SIZE),
        "startup interface pair table",
    )?;

    println!(
        "  interface-pair-like table: offset 0x{:X}, count {}",
        pair_table, pair_count
    );

    let preview_count = pair_count.min(8);
    for index in 0..preview_count {
        let entry_offset = pair_table + index * INTERFACE_PAIR_SIZE;
        let first = read_u32(startup_data, entry_offset)?;
        let second = read_u32(startup_data, entry_offset + 4)?;
        println!("    pair[{index}] = (0x{first:X}, 0x{second:X})");
    }

    Ok(())
}

fn decode_image_name_index(data: &[u8], entry_offset: usize, image_index: usize) -> Result<u32> {
    let key = image_key(image_index as u32);
    Ok(read_u32(data, entry_offset + 0x0C)? ^ key ^ 0x4D64_8371)
}

fn decode_image_type_start(data: &[u8], entry_offset: usize, image_index: usize) -> Result<u32> {
    let key = image_key(image_index as u32);
    Ok((read_u32(data, entry_offset + 0x14)? ^ key ^ 0x7BAB_EEA0) ^ 0x235A_EAF5)
}

fn decode_image_type_count(data: &[u8], entry_offset: usize, image_index: usize) -> Result<u32> {
    let key = image_key(image_index as u32);
    Ok((read_u32(data, entry_offset + 0x04)? ^ key ^ 0x10FE_A394) ^ 0x7C06_D18C)
}

fn image_key(index: u32) -> u32 {
    ((index.wrapping_mul(0xE07C) ^ 0x7538_159E).wrapping_mul(0x120D_0703) ^ 0x6032_C9D3)
        .wrapping_add(0x2EBB_0085)
}

fn decode_type_namespace_index(data: &[u8], entry_offset: usize) -> Result<u32> {
    Ok(read_u32(data, entry_offset + 0x24)?.wrapping_add(0xF1D3_2D89))
}

fn decode_type_name_index(data: &[u8], entry_offset: usize) -> Result<u32> {
    Ok(read_u32(data, entry_offset + 0x28)?.wrapping_add(0xE9FD_68F8))
}

fn decode_type_method_start(data: &[u8], entry_offset: usize) -> Result<u32> {
    Ok(read_u32(data, entry_offset + 0x08)? ^ 0x1A7A_F5FE)
}

fn decode_type_method_count(data: &[u8], entry_offset: usize) -> Result<u16> {
    Ok(read_u16(data, entry_offset + 0x34)?.wrapping_add(0x5F93))
}

fn decode_method_name_index(data: &[u8], entry_offset: usize, method_index: usize) -> Result<u32> {
    Ok((read_u32(data, entry_offset)? ^ method_key(method_index as u64)) ^ 0x0E71_4BC1)
}

fn method_key(index: u64) -> u32 {
    let value = (index.wrapping_mul(0x31E1) ^ 0x3391_4937)
        .wrapping_mul(0x2C03_F17D)
        .wrapping_shr(0x17)
        .wrapping_mul(0x540C_C9F4)
        .wrapping_shr(0x15);
    (value as u32).wrapping_add(0x71BC_7861)
}

fn find_first_type_with_methods(
    data: &[u8],
    type_table: usize,
    type_start: usize,
    type_count: usize,
) -> Result<Option<(usize, usize, u32, u16)>> {
    for local_index in 0..type_count {
        let type_index = type_start + local_index;
        let entry_offset = type_table + type_index * TYPE_ENTRY_SIZE;
        let method_start = decode_type_method_start(data, entry_offset)?;
        let method_count = decode_type_method_count(data, entry_offset)?;
        if method_start != u32::MAX && method_count != 0 {
            return Ok(Some((type_index, entry_offset, method_start, method_count)));
        }
    }

    Ok(None)
}

fn format_method_range(method_start: u32, method_count: u16) -> String {
    if method_start == u32::MAX || method_count == 0 {
        "methods=-".to_owned()
    } else {
        format!(
            "methods={}..{}",
            method_start,
            method_start + method_count as u32
        )
    }
}

fn decode_assembly_image_index(
    data: &[u8],
    entry_offset: usize,
    assembly_index: usize,
) -> Result<u32> {
    let key = assembly_link_key(assembly_index as u64);
    Ok(read_u32(data, entry_offset + 4)? ^ key ^ 0x508B_7D78)
}

fn decode_assembly_name_index(
    data: &[u8],
    entry_offset: usize,
    assembly_index: usize,
) -> Result<u32> {
    let key = assembly_name_key(assembly_index as u64);
    Ok(read_u32(data, entry_offset + 0x1C)?.wrapping_add(0x8DE9_829F) ^ key)
}

fn assembly_link_key(index: u64) -> u32 {
    let value = index.wrapping_mul(0x964E).wrapping_add(0x1E4C_D4BD) ^ 0x5D38_EA25;
    let value = value.wrapping_mul(0x582B_0E07) ^ 0x4922_44BA;
    value.wrapping_mul(0x6846_21B5).wrapping_shr(0x13) as u32
}

fn assembly_name_key(index: u64) -> u32 {
    let value = index
        .wrapping_mul(0x1EB4_DFA5_55DF)
        .wrapping_add(0x2354_CA5D_B8A6_FF)
        .wrapping_shr(0x0D);
    value
        .wrapping_mul(0x305D_EFD3)
        .wrapping_add(0x016D_7189_FD9C)
        .wrapping_shr(9) as u32
}

fn decode_string(global_data: &[u8], layout: &StaticLayout, index: u32) -> Result<String> {
    if index == u32::MAX {
        return Ok(String::new());
    }

    let signed_index = index as i32;
    let (length, string_offset_mask) = if signed_index < 0 {
        (((index >> 23) & 0xFF) as usize, 0x007F_FFFF)
    } else {
        (((index >> 25) & 0x3F) as usize, 0x01FF_FFFF)
    };
    if length == 0 {
        return Ok(String::new());
    }

    let string_offset = (index & string_offset_mask) as usize;
    let data_offset =
        layout.payload_offset as usize + layout.global_string_data_offset as usize + string_offset;
    let qword_count = length.div_ceil(8);
    require_range(
        global_data,
        data_offset,
        qword_count * 8,
        "global string payload",
    )?;

    let mut key = STRING_PAYLOAD_SEED_ADD
        .wrapping_add(STRING_PAYLOAD_SEED_MUL.wrapping_mul(string_offset as u64));
    let mut out = Vec::with_capacity(qword_count * 8);
    for chunk_index in 0..qword_count {
        let encrypted = read_u64(global_data, data_offset + chunk_index * 8)?;
        out.extend_from_slice(&(encrypted ^ key).to_le_bytes());
        key = key.wrapping_add(STRING_PAYLOAD_INCREMENT);
    }

    out.truncate(length);
    String::from_utf8(out).map_err(|error| anyhow!("invalid decoded UTF-8 string: {error}"))
}

fn require_range(data: &[u8], offset: usize, size: usize, label: &str) -> Result<()> {
    let end = offset
        .checked_add(size)
        .ok_or_else(|| anyhow!("{label} range overflows"))?;
    if end > data.len() {
        return Err(anyhow!(
            "{label} range 0x{offset:X}..0x{end:X} exceeds buffer length 0x{:X}",
            data.len()
        ));
    }
    Ok(())
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32> {
    let bytes = data
        .get(offset..offset + 4)
        .ok_or_else(|| anyhow!("read out of range at 0x{offset:X}"))?;
    Ok(u32::from_le_bytes(bytes.try_into()?))
}

fn read_u16(data: &[u8], offset: usize) -> Result<u16> {
    let bytes = data
        .get(offset..offset + 2)
        .ok_or_else(|| anyhow!("read out of range at 0x{offset:X}"))?;
    Ok(u16::from_le_bytes(bytes.try_into()?))
}

fn read_u64(data: &[u8], offset: usize) -> Result<u64> {
    let bytes = data
        .get(offset..offset + 8)
        .ok_or_else(|| anyhow!("read out of range at 0x{offset:X}"))?;
    Ok(u64::from_le_bytes(bytes.try_into()?))
}
