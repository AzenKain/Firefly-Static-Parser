use std::fs;

use anyhow::{Context, Result};
use il2cpp_dumper::{executor::Il2CppExecutor, il2cpp::metadata::Metadata};

use crate::{
    args::InputPaths,
    config::static_config,
    il2cpp_pe::init_pe,
    metadata::{CUSTOM_METADATA_MAGIC, prepare_metadata_data},
    layout_model::output::generate_layout_outputs,
    output::generate_outputs,
};

pub fn run() -> Result<()> {
    let paths = InputPaths::from_env();

    println!("GameAssembly: {}", paths.game_assembly.display());
    println!("Metadata: {}", paths.metadata.display());
    if let Some(startup_metadata) = &paths.startup_metadata {
        println!("Startup metadata: {}", startup_metadata.display());
    } else {
        println!("Startup metadata: not found");
    }
    println!("Output: {}", paths.output_dir.display());

    fs::create_dir_all(&paths.output_dir)
        .with_context(|| format!("failed to create {}", paths.output_dir.display()))?;

    let raw_metadata = fs::read(&paths.metadata)
        .with_context(|| format!("failed to read {}", paths.metadata.display()))?;
    if raw_metadata.starts_with(CUSTOM_METADATA_MAGIC) {
        return generate_layout_outputs(
            &paths.game_assembly,
            paths.startup_metadata.as_deref(),
            &paths.output_dir,
            raw_metadata,
        );
    }

    let metadata_data = prepare_metadata_data(&paths)?;
    let mut metadata =
        Metadata::new(metadata_data).context("failed to parse global-metadata.dat")?;

    let game_assembly_data = fs::read(&paths.game_assembly)
        .with_context(|| format!("failed to read {}", paths.game_assembly.display()))?;
    let mut il2cpp = init_pe(game_assembly_data, &metadata)?;
    let mut executor = Il2CppExecutor::new(&metadata, &mut il2cpp)?;

    let config = static_config();
    generate_outputs(
        &mut executor,
        &mut metadata,
        &mut il2cpp,
        &config,
        &paths.output_dir,
    )
}
