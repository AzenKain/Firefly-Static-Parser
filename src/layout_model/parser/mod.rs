mod loader;
mod reader;

use anyhow::{Context, Result, anyhow};
use std::collections::HashMap;

use crate::{
    pe_image::PeImage,
    static_layout::{LayoutKeys, StaticLayout},
};

use super::TYPE_ENTRY_SIZE;
struct MethodHeader {
    name_index: u32,
    parameter_start: i32,
    return_type_index: u32,
    flags: u16,
    parameter_count: usize,
}

struct TypeDefinitionHeader {
    namespace_index: u32,
    name_index: u32,
    raw_field_start: u32,
    field_start: u32,
    field_count: usize,
    method_start: u32,
    method_count: usize,
    flags: u32,
    raw_base_type: u32,
    generic_container: u16,
    interface_start: Option<usize>,
    interface_count: usize,
}

fn discover_type_layout_keys(layout: &mut StaticLayout, global_data: &[u8]) -> Result<()> {
    let type_count_from_size = (layout.global_metadata_usage_type_table_offset.saturating_sub(layout.global_type_table_offset)) / TYPE_ENTRY_SIZE as u32;
    let type_count = (layout.descriptor_count_80.min(type_count_from_size)) as usize;
    if type_count == 0 {
        return Err(anyhow!(
            "cannot discover type layout keys from an empty type table"
        ));
    }

    let type_table_offset =
        layout.payload_offset as usize + layout.global_type_table_offset as usize;
    require_range(
        global_data,
        type_table_offset,
        TYPE_ENTRY_SIZE,
        "global type table",
    )?;

    let module_name = decode_type_name_at(global_data, layout, type_table_offset)?.1;
    if module_name != "<Module>" {
        return Err(anyhow!(
            "cannot discover type layout keys: type[0] is {module_name:?}, expected <Module>"
        ));
    }

    layout.keys.type_base_none = read_u32(global_data, type_table_offset + 0x04)?;
    layout.keys.type_attribute_key = read_u32(global_data, type_table_offset + 0x14)? ^ 0x700;

    let mut raw_base_counts = HashMap::<u32, usize>::new();
    for type_index in 0..type_count {
        let Some(entry_offset) = type_entry_offset_raw(layout, type_index) else {
            break;
        };
        require_range(
            global_data,
            entry_offset,
            TYPE_ENTRY_SIZE,
            "global type table",
        )?;
        let raw_base = read_u32(global_data, entry_offset + 0x04)?;
        *raw_base_counts.entry(raw_base).or_default() += 1;
    }

    let scan_count = type_count.min(50_000);
    for type_index in 0..scan_count {
        let Some(entry_offset) = type_entry_offset_raw(layout, type_index) else {
            break;
        };
        require_range(
            global_data,
            entry_offset,
            TYPE_ENTRY_SIZE,
            "global type table",
        )?;
        let raw_base = read_u32(global_data, entry_offset + 0x04)?;
        let (namespace, name) = decode_type_name_at(global_data, layout, entry_offset)?;

        match (namespace.as_str(), name.as_str()) {
            ("System", "ValueType") => layout.keys.type_base_object = raw_base,
            ("System", "Enum") => layout.keys.type_base_value_type = raw_base,
            ("System", "AttributeTargets") => layout.keys.type_base_enum = raw_base,
            _ => {}
        }

        if layout.keys.type_base_object != 0
            && layout.keys.type_base_value_type != 0
            && layout.keys.type_base_enum != 0
        {
            break;
        }
    }

    if layout.keys.type_base_object == 0 {
        layout.keys.type_base_object =
            most_common_type_sentinel(&raw_base_counts, &[layout.keys.type_base_none]).ok_or_else(
                || anyhow!("failed to discover object base sentinel from type table"),
            )?;
    }
    layout.keys.type_parent_key = layout.keys.type_base_object.wrapping_sub(1);

    if layout.keys.type_base_value_type == 0 {
        layout.keys.type_base_value_type = most_common_type_sentinel(
            &raw_base_counts,
            &[layout.keys.type_base_none, layout.keys.type_base_object],
        )
        .ok_or_else(|| anyhow!("failed to discover value-type base sentinel from type table"))?;
    }

    if layout.keys.type_base_enum == 0 {
        layout.keys.type_base_enum = most_common_type_sentinel(
            &raw_base_counts,
            &[
                layout.keys.type_base_none,
                layout.keys.type_base_object,
                layout.keys.type_base_value_type,
            ],
        )
        .ok_or_else(|| anyhow!("failed to discover enum base sentinel from type table"))?;
    }

    println!("Discovered type layout keys:");
    println!(
        "  type attribute xor: 0x{:X}",
        layout.keys.type_attribute_key
    );
    println!("  type parent key: 0x{:X}", layout.keys.type_parent_key);
    println!("  base none sentinel: 0x{:X}", layout.keys.type_base_none);
    println!(
        "  base object sentinel: 0x{:X}",
        layout.keys.type_base_object
    );
    println!(
        "  base value-type sentinel: 0x{:X}",
        layout.keys.type_base_value_type
    );
    println!("  base enum sentinel: 0x{:X}", layout.keys.type_base_enum);

    Ok(())
}

fn type_entry_offset_raw(layout: &StaticLayout, type_index: usize) -> Option<usize> {
    layout
        .payload_offset
        .checked_add(layout.global_type_table_offset)?
        .try_into()
        .ok()
        .and_then(|base: usize| base.checked_add(type_index.checked_mul(TYPE_ENTRY_SIZE)?))
}

fn decode_type_name_at(
    global_data: &[u8],
    layout: &StaticLayout,
    entry_offset: usize,
) -> Result<(String, String)> {
    let namespace_index = read_u32(global_data, entry_offset + 0x24)?.wrapping_add(0xF1D3_2D89);
    let name_index = read_u32(global_data, entry_offset + 0x28)?.wrapping_add(0xE9FD_68F8);
    Ok((
        decode_string_raw(global_data, layout, namespace_index)?,
        decode_string_raw(global_data, layout, name_index)?,
    ))
}

fn most_common_type_sentinel(
    raw_base_counts: &HashMap<u32, usize>,
    excluded_values: &[u32],
) -> Option<u32> {
    raw_base_counts
        .iter()
        .filter(|(value, count)| {
            **count > 100
                && **value > 0x4000_0000
                && !excluded_values.iter().any(|excluded| excluded == *value)
        })
        .max_by_key(|(_, count)| **count)
        .map(|(value, _)| *value)
}

fn decode_string_raw(global_data: &[u8], layout: &StaticLayout, index: u32) -> Result<String> {
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

    let mut key = string_payload_key(layout, string_offset);
    let mut out = Vec::with_capacity(qword_count * 8);
    for chunk_index in 0..qword_count {
        let encrypted = read_u64(global_data, data_offset + chunk_index * 8)?;
        out.extend_from_slice(&(encrypted ^ key).to_le_bytes());
        key = key.wrapping_add(string_payload_increment(layout));
    }

    out.truncate(length);
    String::from_utf8(out).map_err(|error| anyhow!("invalid decoded UTF-8 string: {error}"))
}

fn method_json_alias(name: &str) -> &str {
    match name {
        "System.Int32" => "int",
        "System.UInt32" => "uint",
        "System.Int16" => "short",
        "System.UInt16" => "ushort",
        "System.Int64" => "long",
        "System.UInt64" => "ulong",
        "System.Byte" => "byte",
        "System.SByte" => "sbyte",
        "System.Boolean" => "bool",
        "System.Single" => "float",
        "System.Double" => "double",
        "System.String" => "string",
        "System.Char" => "char",
        "System.Object" => "object",
        "System.Void" => "void",
        "System.Decimal" => "decimal",
        "System.DateTime" => "DateTime",
        other => other,
    }
}

fn image_key(index: u32) -> u32 {
    ((index.wrapping_mul(0xE07C) ^ 0x7538_159E).wrapping_mul(0x120D_0703) ^ 0x6032_C9D3)
        .wrapping_add(0x2EBB_0085)
}

fn method_key(index: u64) -> u32 {
    let value = (index.wrapping_mul(0x31E1) ^ 0x3391_4937)
        .wrapping_mul(0x2C03_F17D)
        .wrapping_shr(0x17)
        .wrapping_mul(0x540C_C9F4)
        .wrapping_shr(0x15);
    (value as u32).wrapping_add(0x71BC_7861)
}

fn string_payload_key(layout: &StaticLayout, string_offset: usize) -> u64 {
    layout.keys.string_payload_seed_add.wrapping_add(
        layout
            .keys
            .string_payload_seed_mul
            .wrapping_mul(string_offset as u64),
    )
}

fn string_payload_increment(layout: &StaticLayout) -> u64 {
    layout.keys.string_payload_increment
}

fn parameter_key(index: u64) -> u32 {
    let value = index
        .wrapping_mul(0x072E_1D74_B12B)
        .wrapping_add(0x0191_1D05_AFF5)
        .wrapping_shr(0x0B);
    (value as u32)
        .wrapping_mul(0x58B8_70A2)
        .wrapping_add(0x83CF_7B44)
}

fn field_key(raw_field_start: u32, local_index: u32) -> u32 {
    0xAD41_6BB9_u32
        .wrapping_sub(raw_field_start.wrapping_mul(0x2C5D_CB00))
        .wrapping_add(local_index.wrapping_mul(0xD3A2_3500))
}

fn generic_parameter_key(index: u64) -> u32 {
    let value = 0x09DC_5DB7_1F0E_B440_u64
        .wrapping_add(0x617F_E3CC_452C_u64.wrapping_mul(index))
        .wrapping_shr(9)
        .wrapping_add(0x2AD8_C631)
        ^ 0x5278_374D;
    value.wrapping_mul(0x4AAD_BD4B).wrapping_shr(0x0F) as u32
}

fn generic_container_key(index: u64) -> u32 {
    let value = 0x0A64_CAD6_0FA0_52C0_u64
        .wrapping_add(0x3D69_13E0_AF40_u64.wrapping_mul(index))
        .wrapping_shr(0x17)
        .wrapping_mul(0x770E_3FE8)
        .wrapping_shr(0x0B)
        .wrapping_mul(0x2C9A_0EA3)
        .wrapping_shr(0x17);
    value as u32
}

fn strip_generic_arity(name: &str) -> String {
    name.split('.')
        .map(|segment| match segment.rsplit_once('`') {
            Some((prefix, arity)) if arity.chars().all(|ch| ch.is_ascii_digit()) => prefix,
            _ => segment,
        })
        .collect::<Vec<_>>()
        .join(".")
}

fn generic_arity(name: &str) -> Option<usize> {
    let (_, arity) = name.rsplit_once('`')?;
    arity.parse().ok()
}

fn fallback_generic_parameter_names(type_name: &str, arity: usize) -> Vec<String> {
    if arity == 1 {
        return vec!["T".to_owned()];
    }

    if arity == 2 && (type_name.contains("Dictionary") || type_name.contains("KeyValuePair")) {
        return vec!["TKey".to_owned(), "TValue".to_owned()];
    }

    (1..=arity).map(|index| format!("T{index}")).collect()
}

fn parent_type_index(raw_base_type: u32, keys: LayoutKeys) -> Option<u32> {
    if matches!(
        raw_base_type,
        value if value == keys.type_base_none
            || value == keys.type_base_object
            || value == keys.type_base_value_type
            || value == keys.type_base_enum
    ) {
        return None;
    }

    Some(raw_base_type.wrapping_sub(keys.type_parent_key))
}

fn shorten_declaration_reference(name: &str) -> String {
    name.rsplit('.').next().unwrap_or(name).to_owned()
}

fn va_to_rva(va: u64, image_base: u64, label: &str) -> Result<u32> {
    let rva = va
        .checked_sub(image_base)
        .ok_or_else(|| anyhow!("{label} VA 0x{va:X} is below image base 0x{image_base:X}"))?;
    u32::try_from(rva).with_context(|| format!("{label} RVA 0x{rva:X} does not fit in u32"))
}

fn discover_method_attribute_xor(pe: &PeImage) -> Result<u16> {
    if let Some(instruction_rva) = pe.scan_pattern(&method_attribute_xor_pattern()).into_iter().next() {
        let target_rva = rip_relative_target_rva(pe, instruction_rva, 8)?;
        return pe.read_u16_rva(target_rva);
    }

    Err(anyhow!(
        "failed to find method attribute xor movdqa pattern"
    ))
}

fn method_attribute_xor_pattern() -> Vec<Option<u8>> {
    vec![
        Some(0x66),
        Some(0x0F),
        Some(0x6F),
        Some(0x05),
        None,
        None,
        None,
        None,
        Some(0x4C),
        Some(0x89),
        Some(0xC5),
        Some(0x4C),
        Some(0x89),
        Some(0x44),
        Some(0x24),
        Some(0x38),
    ]
}

fn rip_relative_target_rva(
    pe: &PeImage,
    instruction_rva: u32,
    instruction_len: u32,
) -> Result<u32> {
    let displacement = pe.read_i32_rva(instruction_rva + instruction_len - 4)?;
    let target = instruction_rva as i64 + instruction_len as i64 + displacement as i64;
    if target < 0 || target > u32::MAX as i64 {
        return Err(anyhow!(
            "RIP-relative instruction at RVA 0x{instruction_rva:X} targets out-of-range RVA 0x{target:X}"
        ));
    }
    Ok(target as u32)
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
