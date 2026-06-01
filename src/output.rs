use std::{collections::BTreeMap, fs, path::Path};

use anyhow::{Result, anyhow};
use il2cpp_dumper::{
    config::Config,
    executor::Il2CppExecutor,
    il2cpp::{
        base::Il2Cpp,
        metadata::Metadata,
        structures::{Il2CppMethodDefinition, Il2CppTypeDefinition},
    },
    output::decompiler::Il2CppDecompiler,
};

pub fn generate_outputs(
    executor: &mut Il2CppExecutor,
    metadata: &mut Metadata,
    il2cpp: &mut Il2Cpp,
    config: &Config,
    output_dir: &Path,
) -> Result<()> {
    let output_dir_str = output_dir.to_string_lossy().to_string();

    println!("Generating dump.cs...");
    Il2CppDecompiler::decompile(executor, metadata, il2cpp, config, &output_dir_str, |_| {})?;

    let dump_cs_path = output_dir.join("dump.cs");
    if dump_cs_path.exists() {
        let content = fs::read_to_string(&dump_cs_path)?;
        let mut new_content = String::with_capacity(content.len() + 60);
        new_content.push_str("// FirelfyShelter static asm parse\n\n");
        new_content.push_str(&content);
        fs::write(&dump_cs_path, new_content)?;
    }

    println!("Generating methods.json...");
    write_methods_json(executor, metadata, il2cpp, output_dir)?;

    println!("Done.");
    Ok(())
}

fn write_methods_json(
    executor: &mut Il2CppExecutor,
    metadata: &mut Metadata,
    il2cpp: &mut Il2Cpp,
    output_dir: &Path,
) -> Result<()> {
    let mut methods = BTreeMap::new();
    let image_defs = metadata.image_defs.clone();

    for image_def in &image_defs {
        let image_name = metadata.get_string_from_index(image_def.name_index)?;
        let type_end = image_def.type_start as usize + image_def.type_count as usize;

        for type_def_index in image_def.type_start as usize..type_end {
            let type_def = metadata.type_defs[type_def_index].clone();
            let type_name =
                executor.get_type_def_name(&type_def, type_def_index, metadata, il2cpp, true, true);

            write_type_methods(
                &mut methods,
                executor,
                metadata,
                il2cpp,
                &image_name,
                &type_name,
                &type_def,
            )?;
        }
    }

    let output = serde_json::to_string_pretty(&methods)?;
    fs::write(output_dir.join("methods.json"), output)?;
    Ok(())
}

fn write_type_methods(
    methods: &mut BTreeMap<String, String>,
    executor: &mut Il2CppExecutor,
    metadata: &mut Metadata,
    il2cpp: &mut Il2Cpp,
    image_name: &str,
    type_name: &str,
    type_def: &Il2CppTypeDefinition,
) -> Result<()> {
    let method_end = type_def.method_start as usize + type_def.method_count as usize;

    for method_index in type_def.method_start as usize..method_end {
        let method_def = metadata.method_defs[method_index].clone();
        let key = format!(
            "{type_name}::{}",
            format_method_params(executor, metadata, il2cpp, &method_def)?
        );
        let pointer = il2cpp.get_method_pointer(image_name, &method_def);
        methods.insert(key, format!("0x{pointer:X}"));
    }

    Ok(())
}

fn format_method_params(
    executor: &mut Il2CppExecutor,
    metadata: &mut Metadata,
    il2cpp: &mut Il2Cpp,
    method_def: &Il2CppMethodDefinition,
) -> Result<String> {
    let method_name = metadata.get_string_from_index(method_def.name_index as i32)?;
    let mut params = Vec::with_capacity(method_def.parameter_count as usize);

    for offset in 0..method_def.parameter_count as usize {
        let param_index = method_def.parameter_start + offset as i32;
        if param_index < 0 {
            return Err(anyhow!("negative parameter index for {method_name}"));
        }

        let param = metadata
            .parameter_defs
            .get(param_index as usize)
            .ok_or_else(|| anyhow!("parameter index out of range for {method_name}"))?
            .clone();

        let ty = il2cpp
            .types
            .get(param.type_index as usize)
            .ok_or_else(|| anyhow!("type index out of range for {method_name}"))?
            .clone();
        params.push(executor.get_type_name(&ty, metadata, il2cpp, false, false));
    }

    Ok(format!("{method_name}({})", params.join(",")))
}
