use std::{collections::{BTreeMap, HashMap}, fs};

use anyhow::{Context, Result, anyhow};

use crate::{
    args::InputPaths,
    layout_model::{LayoutField, LayoutMetadata, LayoutMethod, LayoutTypeDef},
};

pub fn generate_layout_outputs(paths: &InputPaths, global_data: Vec<u8>) -> Result<()> {
    let startup_metadata = paths
        .startup_metadata
        .as_ref()
        .ok_or_else(|| anyhow!("startup-metadata.dat is required for static output"))?;

    println!("Generating static dump.cs/methods.json...");
    let mut metadata = LayoutMetadata::load(&paths.game_assembly, global_data, startup_metadata)?;
    fs::create_dir_all(&paths.output_dir)
        .with_context(|| format!("failed to create {}", paths.output_dir.display()))?;

    let dump_cs = build_dump_cs(&mut metadata)?;
    fs::write(paths.output_dir.join("dump.cs"), dump_cs)
        .with_context(|| "failed to write static dump.cs")?;

    let methods_json = build_methods_json(&mut metadata)?;
    fs::write(paths.output_dir.join("methods.json"), methods_json)
        .with_context(|| "failed to write static methods.json")?;

    println!("Static output done.");
    Ok(())
}

fn build_dump_cs(metadata: &mut LayoutMetadata) -> Result<String> {
    let mut output = String::new();
    output.push_str("// FirelfyShelter static asm parse\n\n");

    for (index, image) in metadata.images().iter().enumerate() {
        output.push_str(&format!("// Image {index}: {}\n", image.name));
    }

    for image_index in 0..metadata.images().len() {
        let image = metadata.images()[image_index].clone();
        println!("  dump.cs image {image_index}: {}", image.name);
        for type_index in image.type_start..image.type_start + image.type_count {
            let type_def = metadata.type_def(type_index)?.clone();
            output.push_str(&write_type(metadata, &type_def, type_index)?);
        }
    }

    Ok(output)
}

fn build_methods_json(metadata: &mut LayoutMetadata) -> Result<String> {
    let mut methods = BTreeMap::new();

    for image_index in 0..metadata.images().len() {
        let image = metadata.images()[image_index].clone();
        println!("  methods.json image {image_index}: {}", image.name);
        for type_index in image.type_start..image.type_start + image.type_count {
            let type_def = metadata.type_def(type_index)?.clone();
            let Some(method_start) = type_def.method_start else {
                continue;
            };
            let type_name = metadata.type_def_display_name(type_index, true)?;

            for method_index in method_start..method_start + type_def.method_count {
                let method = metadata.read_method(method_index)?;
                let key = format!(
                    "{type_name}::{}({})",
                    method.name,
                    method.method_json_params.join(",")
                );
                methods.insert(key, format!("0x{:x}", method.rva));
            }
        }
    }

    serde_json::to_string_pretty(&methods).context("failed to serialize static methods.json")
}

fn write_type(
    metadata: &mut LayoutMetadata,
    type_def: &LayoutTypeDef,
    type_index: usize,
) -> Result<String> {
    let mut output = String::new();
    output.push_str(&format!("\n// Namespace: {}\n", type_def.namespace));
    output.push_str(&format!("// TypeDefIndex: {type_index}\n"));
    if type_def.flags & 0x2000 != 0 {
        output.push_str("[Serializable]\n");
    }
    let mut suffixes = Vec::new();
    if let Some(parent_name) = metadata.read_parent_name(type_def)? {
        suffixes.push(parent_name);
    }
    suffixes.extend(metadata.read_interface_names(type_def)?);
    output.push_str(&format!("{} {}", type_prefix(type_def), type_def.name));
    if !suffixes.is_empty() {
        output.push_str(&format!(" : {}", suffixes.join(", ")));
    }
    output.push_str("\n{");
    output.push_str("\n\t// Fields\n");
    let mut enum_values = HashMap::new();
    if type_def.is_enum {
        if let Ok(values) = metadata.read_enum_values(type_index, type_def) {
            for val in values {
                enum_values.insert(val.name, val.value);
            }
        }
    }
    for field in metadata.read_fields(type_index, type_def)? {
        let enum_val = enum_values.get(&field.name).copied();
        output.push_str(&write_field(&field, enum_val));
    }
    output.push_str("\n\t// Methods\n");

    if let Some(method_start) = type_def.method_start {
        for method_index in method_start..method_start + type_def.method_count {
            let method = metadata.read_method(method_index)?;
            output.push_str(&write_method(&method));
        }
    }

    output.push_str("}\n");
    Ok(output)
}

fn write_field(field: &LayoutField, enum_val: Option<i32>) -> String {
    if let Some(val) = enum_val {
        format!(
            "\t{}{} {} = {}; // 0x{:x}\n",
            field_prefix(field.flags),
            field.type_name,
            field.name,
            val,
            field.offset
        )
    } else {
        format!(
            "\t{}{} {}; // 0x{:x}\n",
            field_prefix(field.flags),
            field.type_name,
            field.name,
            field.offset
        )
    }
}

fn write_method(method: &LayoutMethod) -> String {
    let mut output = String::new();
    output.push('\n');
    if method.va == 0 {
        output.push_str("\t// RVA: 0x0 VA: 0x0\n\t");
    } else {
        output.push_str(&format!(
            "\t// RVA: 0x{:x} VA: 0x{:x}\n\t",
            method.rva, method.va
        ));
    }
    output.push_str(&method_prefix(method.flags));
    output.push_str(&format!(
        "{} {}({}) {{ }}\n",
        method.return_type,
        method.name,
        method.dump_params.join(", ")
    ));
    output
}

fn type_visibility(flags: u32) -> &'static str {
    match flags & 0x7 {
        1 | 2 => "public",
        3 => "private",
        4 => "protected",
        5 => "internal",
        6 => "protected internal",
        _ => "internal",
    }
}

fn type_prefix(type_def: &LayoutTypeDef) -> String {
    let visibility = type_visibility(type_def.flags);
    let kind = if type_def.flags & 0x20 != 0 {
        "interface"
    } else if type_def.is_enum {
        "enum"
    } else if type_def.is_value_type {
        "struct"
    } else {
        "class"
    };

    if kind == "class" {
        let is_abstract = type_def.flags & 0x80 != 0;
        if is_abstract && type_def.flags & 0x100 != 0 {
            return format!("{visibility} static class");
        }
        if is_abstract {
            return format!("{visibility} abstract class");
        }
        let is_sealed = type_def.flags & 0x700 == 0;
        if is_sealed {
            return format!("{visibility} sealed class");
        }
    }

    format!("{visibility} {kind}")
}

fn method_prefix(flags: u16) -> String {
    let access = match flags & 0x7 {
        1 => "private ",
        2 | 3 => "internal ",
        4 => "protected ",
        5 => "protected internal ",
        6 => "public ",
        _ => "",
    };
    let mut output = String::from(access);

    if flags & 0x10 != 0 {
        output.push_str("static ");
    }

    if flags & 0x0400 != 0 {
        output.push_str("abstract ");
        if flags & 0x0100 == 0 {
            output.push_str("override ");
        }
    } else if flags & 0x20 != 0 && (flags & 0x40 != 0 || flags & 0x0100 == 0) {
        output.push_str("sealed override ");
    } else if flags & 0x40 != 0 {
        if flags & 0x0100 != 0 {
            output.push_str("virtual ");
        } else {
            output.push_str("override ");
        }
    }

    if flags & 0x2000 != 0 {
        output.push_str("extern ");
    }

    output
}

fn field_prefix(flags: u16) -> String {
    let access = match flags & 0x7 {
        1 => "private ",
        2 => "private protected ",
        3 => "internal ",
        4 => "protected ",
        5 => "protected internal ",
        6 => "public ",
        _ => "",
    };
    if flags & 0x40 != 0 {
        return format!("{access}const ");
    }

    let static_part = if flags & 0x10 != 0 { "static " } else { "" };
    let readonly_part = if flags & 0x20 != 0 { "readonly " } else { "" };
    format!("{access}{static_part}{readonly_part}")
}
