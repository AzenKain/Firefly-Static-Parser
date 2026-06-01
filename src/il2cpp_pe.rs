use anyhow::{Context, Result, bail};
use il2cpp_dumper::{
    disassembler::Architecture,
    formats::pe::Pe,
    il2cpp::{
        base::{Il2Cpp, VaSegment},
        metadata::Metadata,
    },
};

pub fn init_pe(data: Vec<u8>, metadata: &Metadata) -> Result<Il2Cpp> {
    let mut pe = Pe::new(data).context("failed to parse PE file")?;
    let version = metadata.version;

    pe.stream.version = version;
    pe.stream.is_32bit = pe.is_32bit;

    let method_count = metadata
        .method_defs
        .iter()
        .filter(|m| m.method_index >= 0)
        .count();
    let type_count = metadata.type_defs.len();
    let image_count = metadata.image_defs.len();
    let metadata_usage_count = metadata.metadata_usages_count;

    let mut code_registration = 0_u64;
    let mut metadata_registration = 0_u64;

    if let Some((cr, mr)) = pe.symbol_search().context("PE symbol search failed")? {
        code_registration = cr;
        metadata_registration = mr;
    }

    if code_registration == 0 || metadata_registration == 0 {
        let mut helper = pe.get_section_helper(
            method_count,
            type_count,
            metadata_usage_count,
            image_count,
            version,
        );
        if let Some(cr) = helper.find_code_registration() {
            code_registration = cr;
        }
        if let Some(mr) = helper.find_metadata_registration() {
            metadata_registration = mr;
        }
    }

    if code_registration == 0 || metadata_registration == 0 {
        bail!("failed to find CodeRegistration/MetadataRegistration automatically");
    }

    println!("IL2CPP version: {version}");
    println!("CodeRegistration: 0x{code_registration:X}");
    println!("MetadataRegistration: 0x{metadata_registration:X}");

    let image_base = pe.image_base();
    let va_segments = pe
        .sections
        .iter()
        .map(|section| VaSegment {
            vaddr: section.virtual_address as u64 + image_base,
            memsz: section.virtual_size as u64,
            offset: section.pointer_to_raw_data as u64,
        })
        .collect();

    let mut il2cpp = Il2Cpp::new(pe.stream.clone(), version, pe.is_32bit);
    il2cpp.va_segments = va_segments;
    il2cpp.image_base = image_base;
    il2cpp.is_pe = true;
    il2cpp.arch = Some(if pe.is_32bit {
        Architecture::X86
    } else {
        Architecture::X64
    });

    il2cpp
        .init(code_registration, metadata_registration, &|addr| {
            pe.map_vatr(addr)
        })
        .context("failed to initialize IL2CPP registrations")?;

    if let Ok(exports) = pe.list_exported_symbols() {
        il2cpp.exported_symbols = exports.iter().map(|(name, _)| name.clone()).collect();
        for (name, rva) in exports {
            if name.starts_with("il2cpp_") || name.starts_with("mono_") {
                il2cpp.api_export_rvas.insert(name, rva);
            }
        }
    }

    Ok(il2cpp)
}
