use std::fs;

use anyhow::{Context, Result, bail};

use crate::{
    args::InputPaths,
    obfuscated::{ObfuscatedFiles, load_obfuscated_metadata},
};

pub const STANDARD_METADATA_MAGIC: u32 = 0xFAB1_1BAF;
pub const CUSTOM_METADATA_MAGIC: &[u8; 4] = b"MHY\0";

pub fn prepare_metadata_data(paths: &InputPaths) -> Result<Vec<u8>> {
    let metadata_data = fs::read(&paths.metadata)
        .with_context(|| format!("failed to read {}", paths.metadata.display()))?;

    if has_standard_metadata_magic(&metadata_data) {
        return Ok(metadata_data);
    }

    if metadata_data.starts_with(CUSTOM_METADATA_MAGIC) {
        println!("Detected custom metadata, staging global/startup metadata for loader...");
        return load_obfuscated_metadata(ObfuscatedFiles {
            game_assembly: paths.game_assembly.clone(),
            global_path: paths.metadata.clone(),
            global_data: metadata_data,
            startup_path: paths.startup_metadata.clone(),
        });
    }

    bail!(
        "unsupported metadata format: wrong magic 0x{:08X}",
        read_u32_le(&metadata_data).unwrap_or_default()
    );
}

pub fn has_standard_metadata_magic(data: &[u8]) -> bool {
    read_u32_le(data) == Some(STANDARD_METADATA_MAGIC)
}

pub fn read_u32_le(data: &[u8]) -> Option<u32> {
    data.get(..4)
        .map(|bytes| u32::from_le_bytes(bytes.try_into().expect("slice has four bytes")))
}
