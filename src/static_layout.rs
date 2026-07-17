use std::path::Path;

use anyhow::{Result, anyhow};

use crate::pe_image::PeImage;

#[derive(Debug)]
pub struct StaticLayout {
    pub keys: LayoutKeys,
    pub static_initializer_rva: u32,
    pub metadata_registration_rva: u32,
    pub descriptor_rva: u32,
    pub metadata_cache_rva: u32,
    pub embedded_header_rva: u32,
    pub payload_offset: u32,
    pub descriptor_count_80: u32,
    pub header_size_1a8: u32,
    pub header_size_1f8: u32,
    pub header_size_74: u32,
    pub header_count_134_div40: u32,
    pub header_count_178: u32,
    pub header_count_bc: u32,
    pub startup_section_164_offset: u32,
    pub startup_image_table_offset: u32,
    pub startup_assembly_table_offset: u32,
    pub startup_assembly_name_table_offset: u32,
    pub global_type_table_offset: u32,
    pub global_field_table_offset: u32,
    pub global_property_table_offset: u32,
    pub global_type_field_offset_map_offset: u32,
    pub global_field_offset_group_table_offset: u32,
    pub global_field_offset_table_offset: u32,
    pub global_method_index_map_offset: u32,
    pub global_method_table_offset: u32,
    pub global_parameter_table_offset: u32,
    pub global_nested_type_table_offset: u32,
    pub global_interface_type_table_offset: u32,
    pub global_generic_container_table_offset: u32,
    pub global_generic_parameter_table_offset: u32,
    pub global_metadata_usage_type_table_offset: u32,
    pub global_metadata_usage_range_offset: u32,
    pub global_metadata_usage_pair_offset: u32,
    pub global_string_literal_table_offset: u32,
    pub global_string_literal_data_offset: u32,
    pub global_field_default_value_table_offset: u32,
    pub global_field_default_value_data_offset: u32,
    pub field_default_value_count: u32,
    pub global_string_data_offset: u32,
}

#[derive(Clone, Copy, Debug)]
pub struct LayoutKeys {
    pub type_attribute_key: u32,
    pub type_parent_key: u32,
    pub type_base_none: u32,
    pub type_base_object: u32,
    pub type_base_value_type: u32,
    pub type_base_enum: u32,
    pub string_payload_increment: u64,
    pub string_payload_seed_mul: u64,
    pub string_payload_seed_add: u64,
}

impl Default for LayoutKeys {
    fn default() -> Self {
        Self {
            type_attribute_key: 0,
            type_parent_key: 0,
            type_base_none: 0,
            type_base_object: 0,
            type_base_value_type: 0,
            type_base_enum: 0,
            string_payload_increment: 0,
            string_payload_seed_mul: 0,
            string_payload_seed_add: 0,
        }
    }
}

pub fn inspect_game_assembly(path: &Path) -> Result<StaticLayout> {
    let image = PeImage::read(path)?;
    let globals = discover_static_metadata_globals(&image)?;
    let payload_offset = discover_external_payload_offset(&image)?;
    let keys = discover_layout_keys_from_image(&image)?;
    if !layout_rvas_are_valid(&image, &globals) {
        return Err(anyhow!(
            "invalid RVAs for current layout computation; \
            metadata_registration_rva=0x{:X}, descriptor_rva=0x{:X}, \
            embedded_header_rva=0x{:X}",
            globals.metadata_registration_rva,
            globals.descriptor_rva,
            globals.embedded_header_rva
        ));
    }

    let header = globals.embedded_header_rva;
    let descriptor_count_80 = image
        .read_u32_rva(globals.descriptor_rva + 0x80)?
        ^ 0x69BD_97F1;
    let header_size_1a8 = image.read_u32_rva(header + 0x1A8)? ^ 0x729B1A9E;
    let header_size_1f8 = image.read_u32_rva(header + 0x1F8)? ^ 0x1608C2C8;
    let header_size_74 = image.read_u32_rva(header + 0x74)? ^ 0x080E_F250;
    let header_count_134_div40 = (image.read_u32_rva(header + 0x134)? ^ 0x1021_0728) / 40;
    let header_count_178 = sar_u32(image.read_u32_rva(header + 0x178)?, 4) ^ 0x05CC_1AE1;
    let header_count_bc = sar_u32(image.read_u32_rva(header + 0xBC)?, 3) ^ 0x079F_C2EC;
    let startup_section_164_offset = image.read_u32_rva(header + 0x164)? ^ 0x7F5C_5934;
    let startup_image_table_offset = image
        .read_u32_rva(header + 0x150)?
        .wrapping_add(0xD882_615E);
    let startup_assembly_table_offset = image
        .read_u32_rva(header + 0x158)?
        .wrapping_add(0xE03E_EAC1);
    let startup_assembly_name_table_offset =
        image.read_u32_rva(header + 0xD0)?.wrapping_add(0xDFCF_C6B0);
    let global_type_table_offset = image.read_u32_rva(header + 0x84)? ^ 0x6853_1D3F;
    let global_field_table_offset = image.read_u32_rva(header + 0x20)?.wrapping_add(0xB2FC_E189);
    let global_property_table_offset = image.read_u32_rva(header + 0x40)? ^ 0x3C68_5CDB;
    let global_type_field_offset_map_offset = image
        .read_u32_rva(header + 0x180)?
        .wrapping_add(0xE4DB_E763);
    let global_field_offset_group_table_offset =
        image.read_u32_rva(header + 0x9C)?.wrapping_add(0xBC7E_C9D7);
    let global_field_offset_table_offset = image.read_u32_rva(header + 0x148)? ^ 0x329E_1172;
    let global_method_index_map_offset = 0;
    let global_method_table_offset = image
        .read_u32_rva(header + 0x14C)?
        .wrapping_add(0xF3A0_4294);
    let global_parameter_table_offset =
        image.read_u32_rva(header + 0x30)?.wrapping_add(0xDCF5_FDBE);
    let global_nested_type_table_offset = image.read_u32_rva(header + 0x12C)? ^ 0x26F0_FC20;
    let global_interface_type_table_offset = image.read_u32_rva(header + 0x1C8)? ^ 0x042F_9275;
    let global_generic_container_table_offset =
        image.read_u32_rva(header + 0xF0)?.wrapping_add(0x9D48_920F);
    let global_generic_parameter_table_offset = image
        .read_u32_rva(header + 0x140)?
        .wrapping_add(0xDAAC_7309);
    let global_metadata_usage_type_table_offset =
        image.read_u32_rva(header + 0x38)?.wrapping_add(0xF778_F1AB);
    let global_metadata_usage_range_offset = image
        .read_u32_rva(header + 0x1D0)?
        .wrapping_add(0xC9A6_64A5);
    let global_metadata_usage_pair_offset = image
        .read_u32_rva(header + 0x190)?
        .wrapping_add(0xED79_1073);
    let global_string_literal_table_offset = image.read_u32_rva(header + 0x1F0)? ^ 0x56C7_D20D;
    let global_string_literal_data_offset =
        image.read_u32_rva(header + 0x08)?.wrapping_add(0xF711_4E59);
    let global_field_default_value_table_offset = image.read_u32_rva(header + 0x1FC)? ^ 0x6238_CDB0;
    let global_field_default_value_data_offset =
        image.read_u32_rva(header + 0x3C)?.wrapping_add(0x978B_E7A5);
    let field_default_value_count = (image.read_u32_rva(header + 0x1DC)? ^ 0x3E0C_72F0) / 12;
    let global_string_data_offset = image
        .read_u32_rva(header + 0x1B4)?
        .wrapping_add(0x8D43_A4EE);

    let layout = StaticLayout {
        keys,
        static_initializer_rva: globals.initializer_rva,
        metadata_registration_rva: globals.metadata_registration_rva,
        descriptor_rva: globals.descriptor_rva,
        metadata_cache_rva: globals.metadata_cache_rva,
        embedded_header_rva: globals.embedded_header_rva,
        payload_offset,
        descriptor_count_80,
        header_size_1a8,
        header_size_1f8,
        header_size_74,
        header_count_134_div40,
        header_count_178,
        header_count_bc,
        startup_section_164_offset,
        startup_image_table_offset,
        startup_assembly_table_offset,
        startup_assembly_name_table_offset,
        global_type_table_offset,
        global_field_table_offset,
        global_property_table_offset,
        global_type_field_offset_map_offset,
        global_field_offset_group_table_offset,
        global_field_offset_table_offset,
        global_method_index_map_offset,
        global_method_table_offset,
        global_parameter_table_offset,
        global_nested_type_table_offset,
        global_interface_type_table_offset,
        global_generic_container_table_offset,
        global_generic_parameter_table_offset,
        global_metadata_usage_type_table_offset,
        global_metadata_usage_range_offset,
        global_metadata_usage_pair_offset,
        global_string_literal_table_offset,
        global_string_literal_data_offset,
        global_field_default_value_table_offset,
        global_field_default_value_data_offset,
        field_default_value_count,
        global_string_data_offset,
    };

    print_layout(&layout);
    Ok(layout)
}

#[cfg(windows)]
pub fn discover_custom_metadata_loader_rva(path: &Path) -> Result<u32> {
    let image = PeImage::read(path)?;
    discover_custom_metadata_loader_rva_from_image(&image)
}

fn print_layout(layout: &StaticLayout) {
    println!("Static layout:");
    println!(
        "  static initializer RVA: 0x{:X}",
        layout.static_initializer_rva
    );
    println!(
        "  metadata registration RVA: 0x{:X}",
        layout.metadata_registration_rva
    );
    println!("  descriptor RVA: 0x{:X}", layout.descriptor_rva);
    println!("  metadata cache RVA: 0x{:X}", layout.metadata_cache_rva);
    println!("  embedded header RVA: 0x{:X}", layout.embedded_header_rva);
    println!("  external payload offset: 0x{:X}", layout.payload_offset);
    println!(
        "  decoded descriptor[0x80] count: {}",
        layout.descriptor_count_80
    );
    println!("  decoded header[0x1A8] size: {}", layout.header_size_1a8);
    println!("  decoded header[0x1F8] size: {}", layout.header_size_1f8);
    println!("  decoded header[0x74] size: {}", layout.header_size_74);
    println!(
        "  decoded header[0x134] / 40 count: {}",
        layout.header_count_134_div40
    );
    println!("  decoded header[0x178] count: {}", layout.header_count_178);
    println!("  decoded header[0xBC] count: {}", layout.header_count_bc);
    println!(
        "  decoded startup section[0x164] offset: 0x{:X}",
        layout.startup_section_164_offset
    );
    println!(
        "  decoded startup image table offset: 0x{:X}",
        layout.startup_image_table_offset
    );
    println!(
        "  decoded startup assembly table offset: 0x{:X}",
        layout.startup_assembly_table_offset
    );
    println!(
        "  decoded startup assembly name table offset: 0x{:X}",
        layout.startup_assembly_name_table_offset
    );
    println!(
        "  decoded global type table offset: 0x{:X}",
        layout.global_type_table_offset
    );
    println!(
        "  decoded global field table offset: 0x{:X}",
        layout.global_field_table_offset
    );
    println!(
        "  decoded global property table offset: 0x{:X}",
        layout.global_property_table_offset
    );
    println!(
        "  decoded global type field-offset map offset: 0x{:X}",
        layout.global_type_field_offset_map_offset
    );
    println!(
        "  decoded global field-offset group table offset: 0x{:X}",
        layout.global_field_offset_group_table_offset
    );
    println!(
        "  decoded global field-offset table offset: 0x{:X}",
        layout.global_field_offset_table_offset
    );
    println!(
        "  decoded global method index map offset: 0x{:X}",
        layout.global_method_index_map_offset
    );
    println!(
        "  decoded global method table offset: 0x{:X}",
        layout.global_method_table_offset
    );
    println!(
        "  decoded global parameter table offset: 0x{:X}",
        layout.global_parameter_table_offset
    );
    println!(
        "  decoded global nested type table offset: 0x{:X}",
        layout.global_nested_type_table_offset
    );
    println!(
        "  decoded global interface type table offset: 0x{:X}",
        layout.global_interface_type_table_offset
    );
    println!(
        "  decoded global generic container table offset: 0x{:X}",
        layout.global_generic_container_table_offset
    );
    println!(
        "  decoded global generic parameter table offset: 0x{:X}",
        layout.global_generic_parameter_table_offset
    );
    println!(
        "  decoded metadata usage type table offset: 0x{:X}",
        layout.global_metadata_usage_type_table_offset
    );
    println!(
        "  decoded metadata usage range offset: 0x{:X}",
        layout.global_metadata_usage_range_offset
    );
    println!(
        "  decoded metadata usage pair offset: 0x{:X}",
        layout.global_metadata_usage_pair_offset
    );
    println!(
        "  decoded string literal table offset: 0x{:X}",
        layout.global_string_literal_table_offset
    );
    println!(
        "  decoded string literal data offset: 0x{:X}",
        layout.global_string_literal_data_offset
    );
    println!(
        "  decoded field default value table offset: 0x{:X}",
        layout.global_field_default_value_table_offset
    );
    println!(
        "  decoded field default value data offset: 0x{:X}",
        layout.global_field_default_value_data_offset
    );
    println!(
        "  decoded field default value count: {}",
        layout.field_default_value_count
    );
    println!(
        "  decoded global string data offset: 0x{:X}",
        layout.global_string_data_offset
    );
    println!(
        "  discovered string payload seed mul: 0x{:X}",
        layout.keys.string_payload_seed_mul
    );
    println!(
        "  discovered string payload seed add: 0x{:X}",
        layout.keys.string_payload_seed_add
    );
    println!(
        "  discovered string payload increment: 0x{:X}",
        layout.keys.string_payload_increment
    );
}

struct StaticMetadataGlobals {
    initializer_rva: u32,
    metadata_registration_rva: u32,
    descriptor_rva: u32,
    metadata_cache_rva: u32,
    embedded_header_rva: u32,
}

fn discover_static_metadata_globals(image: &PeImage) -> Result<StaticMetadataGlobals> {
    for initializer_rva in image.scan_pattern(&static_metadata_initializer_pattern()) {
        let metadata_registration_rva = lea_target_rva(image, initializer_rva)?;
        let descriptor_rva = lea_target_rva(image, initializer_rva + 14)?;
        let metadata_cache_rva = lea_target_rva(image, initializer_rva + 28)?;
        let embedded_header_rva = lea_target_rva(image, initializer_rva + 56)?;

        if is_valid_static_globals_candidate(
            image,
            metadata_registration_rva,
            descriptor_rva,
            metadata_cache_rva,
            embedded_header_rva,
        ) {
            return Ok(StaticMetadataGlobals {
                initializer_rva,
                metadata_registration_rva,
                descriptor_rva,
                metadata_cache_rva,
                embedded_header_rva,
            });
        }
    }

    Err(anyhow!(
        "failed to discover static metadata globals initializer"
    ))
}

fn layout_rvas_are_valid(image: &PeImage, globals: &StaticMetadataGlobals) -> bool {
    let header = globals.embedded_header_rva;
    let check_rva = |rva: u32| -> bool { image.read_u32_rva(rva).is_ok() };
    let required_rvas = [
        globals.descriptor_rva + 0x80,
        header + 0x1A8,
        header + 0x1F8,
        header + 0x74,
        header + 0x134,
        header + 0x178,
        header + 0xBC,
        header + 0x164,
        header + 0x150,
        header + 0x158,
        header + 0xD0,
        header + 0x84,
        header + 0x20,
        header + 0x40,
        header + 0x180,
        header + 0x9C,
        header + 0x148,
        header + 0x14C,
        header + 0x30,
        header + 0x12C,
        header + 0x1C8,
        header + 0xF0,
        header + 0x140,
        header + 0x38,
        header + 0x1D0,
        header + 0x190,
        header + 0x1F0,
        header + 0x08,
        header + 0x1FC,
        header + 0x3C,
        header + 0x1DC,
        header + 0x1B4,
    ];

    required_rvas.into_iter().all(check_rva)
}

fn is_valid_static_globals_candidate(
    image: &PeImage,
    metadata_registration_rva: u32,
    descriptor_rva: u32,
    metadata_cache_rva: u32,
    embedded_header_rva: u32,
) -> bool {
    is_valid_current_static_globals_candidate(
        image,
        metadata_registration_rva,
        descriptor_rva,
        metadata_cache_rva,
        embedded_header_rva,
    )
}

fn is_valid_current_static_globals_candidate(
    image: &PeImage,
    metadata_registration_rva: u32,
    descriptor_rva: u32,
    metadata_cache_rva: u32,
    embedded_header_rva: u32,
) -> bool {
    println!("Checking candidate: desc={:x} cache={:x} head={:x}", descriptor_rva, metadata_cache_rva, embedded_header_rva);
    let header_method_span = image
        .read_u32_rva(embedded_header_rva + 0x1F8)
        .map(|value| value ^ 0x1608_C2C8)
        .unwrap_or_default();
    if !(1_000_000..500_000_000).contains(&header_method_span) {
        println!("  failed header_method_span check: {}", header_method_span);
        return false;
    }

    let pointers = [
        image.read_u64_rva(metadata_registration_rva + 0x88),
    ];

    let all_valid = pointers
        .iter()
        .all(|pointer| pointer.as_ref().is_ok_and(|&va| va_points_into_image(image, va)));

    all_valid
}

fn va_points_into_image(image: &PeImage, va: u64) -> bool {
    let image_base = image.image_base();
    let Some(relative) = va.checked_sub(image_base) else {
        return false;
    };
    let Ok(rva) = u32::try_from(relative) else {
        return false;
    };
    image.rva_to_offset(rva).is_ok()
}

fn discover_external_payload_offset(image: &PeImage) -> Result<u32> {
    for initializer_rva in image.scan_pattern(&metadata_payload_initializer_pattern()) {
        let global_name_rva = lea_target_rva(image, initializer_rva)?;
        let startup_name_rva = lea_target_rva(image, initializer_rva + 15)?;
        if !rva_has_c_string(image, global_name_rva, b"global-metadata.dat")
            || !rva_has_c_string(image, startup_name_rva, b"startup-metadata.dat")
        {
            continue;
        }

        let payload_offset = image.read_u32_rva(initializer_rva + 46)?;
        if payload_offset != 0 {
            return Ok(payload_offset);
        }
    }

    Err(anyhow!(
        "failed to discover external payload offset from metadata initializer"
    ))
}

#[cfg(windows)]
fn discover_custom_metadata_loader_rva_from_image(image: &PeImage) -> Result<u32> {
    for initializer_rva in image.scan_pattern(&metadata_payload_initializer_pattern()) {
        let global_name_rva = lea_target_rva(image, initializer_rva)?;
        let startup_name_rva = lea_target_rva(image, initializer_rva + 15)?;
        if !rva_has_c_string(image, global_name_rva, b"global-metadata.dat")
            || !rva_has_c_string(image, startup_name_rva, b"startup-metadata.dat")
        {
            continue;
        }

        return call_target_rva(image, initializer_rva + 7);
    }

    Err(anyhow!(
        "failed to discover custom metadata loader RVA from metadata initializer"
    ))
}

fn discover_layout_keys_from_image(image: &PeImage) -> Result<LayoutKeys> {
    for seed_rva in image.scan_pattern(&string_payload_seed_pattern()) {
        let seed_mul = image.read_u64_rva(seed_rva + 2)?;
        let seed_add = image.read_u64_rva(seed_rva + 16)?;
        if seed_mul == 0 || seed_add == 0 {
            continue;
        }

        let Some(increment) = discover_string_payload_increment(image, seed_rva + 25)? else {
            continue;
        };

        return Ok(LayoutKeys {
            string_payload_increment: increment,
            string_payload_seed_mul: seed_mul,
            string_payload_seed_add: seed_add,
            ..LayoutKeys::default()
        });
    }

    Err(anyhow!(
        "failed to discover string payload keys from GameAssembly code"
    ))
}

fn string_payload_seed_pattern() -> Vec<Option<u8>> {
    vec![
        Some(0x48),
        Some(0xB9),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(0x48),
        Some(0x0F),
        Some(0xAF),
        Some(0xC8),
        Some(0x48),
        Some(0xBA),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(0x48),
        Some(0x01),
        Some(0xCA),
    ]
}

fn discover_string_payload_increment(image: &PeImage, search_rva: u32) -> Result<Option<u64>> {
    let bytes = image.read_bytes_rva(search_rva, 0x200)?;
    for offset in 0..bytes.len().saturating_sub(10) {
        if bytes[offset] != 0x49 || !matches!(bytes[offset + 1], 0xB9 | 0xBB) {
            continue;
        }

        let immediate_rva = search_rva + offset as u32 + 2;
        let value = image.read_u64_rva(immediate_rva)?;
        if value != 0 {
            return Ok(Some(value));
        }
    }

    Ok(None)
}

fn static_metadata_initializer_pattern() -> Vec<Option<u8>> {
    let mut pattern = vec![None; 80];
    for offset in [0, 14, 28, 42, 56] {
        pattern[offset] = Some(0x48);
        pattern[offset + 1] = Some(0x8D);
        pattern[offset + 2] = Some(0x05);
        pattern[offset + 7] = Some(0x48);
        pattern[offset + 8] = Some(0x89);
        pattern[offset + 9] = Some(0x05);
    }
    pattern[70] = Some(0xC7);
    pattern[71] = Some(0x05);
    pattern
}

fn metadata_payload_initializer_pattern() -> Vec<Option<u8>> {
    vec![
        Some(0x48),
        Some(0x8D),
        Some(0x0D),
        None,
        None,
        None,
        None,
        Some(0xE8),
        None,
        None,
        None,
        None,
        Some(0x48),
        Some(0x89),
        Some(0xC6),
        Some(0x48),
        Some(0x8D),
        Some(0x0D),
        None,
        None,
        None,
        None,
        Some(0xE8),
        None,
        None,
        None,
        None,
        Some(0x48),
        Some(0x8B),
        Some(0x0D),
        None,
        None,
        None,
        None,
        Some(0x8B),
        Some(0x49),
        Some(0x04),
        Some(0x89),
        Some(0x0D),
        None,
        None,
        None,
        None,
        Some(0x48),
        Some(0x81),
        Some(0xC6),
        None,
        None,
        None,
        None,
        Some(0x48),
        Some(0x89),
        Some(0x35),
        None,
        None,
        None,
        None,
        Some(0x48),
        Some(0x89),
        Some(0x05),
        None,
        None,
        None,
        None,
    ]
}

fn rva_has_c_string(image: &PeImage, rva: u32, expected: &[u8]) -> bool {
    let size = expected.len() + 1;
    image
        .read_bytes_rva(rva, size)
        .is_ok_and(|bytes| bytes[..expected.len()] == *expected && bytes[expected.len()] == 0)
}

fn lea_target_rva(image: &PeImage, instruction_rva: u32) -> Result<u32> {
    let bytes = image.read_bytes_rva(instruction_rva, 3)?;
    if bytes[0] != 0x48 || bytes[1] != 0x8D || bytes[2] & 0xC7 != 0x05 {
        return Err(anyhow!(
            "expected RIP-relative LEA at RVA 0x{instruction_rva:X}"
        ));
    }

    let displacement = image.read_i32_rva(instruction_rva + 3)?;
    let target = instruction_rva as i64 + 7 + displacement as i64;
    if target < 0 || target > u32::MAX as i64 {
        return Err(anyhow!(
            "RIP-relative LEA at RVA 0x{instruction_rva:X} targets out-of-range RVA 0x{target:X}"
        ));
    }
    Ok(target as u32)
}

#[cfg(windows)]
fn call_target_rva(image: &PeImage, instruction_rva: u32) -> Result<u32> {
    let opcode = image.read_bytes_rva(instruction_rva, 1)?[0];
    if opcode != 0xE8 {
        return Err(anyhow!(
            "expected relative CALL at RVA 0x{instruction_rva:X}"
        ));
    }

    let displacement = image.read_i32_rva(instruction_rva + 1)?;
    let target = instruction_rva as i64 + 5 + displacement as i64;
    if target < 0 || target > u32::MAX as i64 {
        return Err(anyhow!(
            "relative CALL at RVA 0x{instruction_rva:X} targets out-of-range RVA 0x{target:X}"
        ));
    }
    Ok(target as u32)
}

fn sar_u32(value: u32, bits: u32) -> u32 {
    ((value as i32) >> bits) as u32
}
