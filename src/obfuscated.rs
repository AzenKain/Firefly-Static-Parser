use std::path::PathBuf;

use anyhow::{Result, bail};

use crate::metadata::{has_standard_metadata_magic, read_u32_le};

const HSR_METADATA_LOADER_RVA: usize = 0x3948920;

pub struct ObfuscatedFiles {
    pub game_assembly: PathBuf,
    pub global_path: PathBuf,
    pub global_data: Vec<u8>,
    pub startup_path: Option<PathBuf>,
}

#[cfg(windows)]
pub fn load_obfuscated_metadata(files: ObfuscatedFiles) -> Result<Vec<u8>> {
    use std::{
        ffi::{CString, OsStr},
        os::windows::ffi::OsStrExt,
    };

    use anyhow::Context;
    use windows_sys::Win32::{Foundation::FreeLibrary, System::LibraryLoader::LoadLibraryW};

    type LoadMetadata = unsafe extern "C" fn(*const i8) -> *const u8;

    if !files.game_assembly.exists() {
        bail!(
            "GameAssembly.dll not found at {}",
            files.game_assembly.display()
        );
    }

    match crate::static_layout::inspect_game_assembly(&files.game_assembly) {
        Ok(layout) => {
            if let Err(error) = crate::layout_parser::inspect_metadata_sections(
                &layout,
                &files.global_data,
                files.startup_path.as_deref(),
            ) {
                println!("Warning: failed to inspect custom metadata sections: {error:#}");
            }
        }
        Err(error) => {
            println!("Warning: failed to inspect custom static layout: {error:#}");
        }
    }

    let staged = stage_metadata_for_custom_loader(&files)?;

    let game_assembly = files
        .game_assembly
        .canonicalize()
        .with_context(|| format!("failed to resolve {}", files.game_assembly.display()))?;
    let wide_path: Vec<u16> = OsStr::new(&game_assembly)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let module = unsafe { LoadLibraryW(wide_path.as_ptr()) };
    if module.is_null() {
        bail!("failed to load {}", game_assembly.display());
    }

    let loaded = (|| -> Result<Vec<u8>> {
        let func_addr = module as usize + HSR_METADATA_LOADER_RVA;
        let load_metadata: LoadMetadata = unsafe { std::mem::transmute(func_addr) };

        if staged.startup_staged {
            let startup_name = CString::new("startup-metadata.dat")?;
            let startup_ptr = unsafe { load_metadata(startup_name.as_ptr()) };
            if startup_ptr.is_null() {
                println!("Warning: GameAssembly loader returned null for startup-metadata.dat");
            } else {
                println!("Loaded startup-metadata.dat through GameAssembly metadata loader.");
            }
        }

        let metadata_name = CString::new("global-metadata.dat")?;
        let metadata_ptr = unsafe { load_metadata(metadata_name.as_ptr()) };
        if metadata_ptr.is_null() {
            bail!("GameAssembly metadata loader returned null for global-metadata.dat");
        }

        let loaded_metadata =
            unsafe { std::slice::from_raw_parts(metadata_ptr, files.global_data.len()).to_vec() };

        if !has_standard_metadata_magic(&loaded_metadata) {
            bail!(
                "Obfuscated metadata loader did not produce standard IL2CPP metadata. \
                 got magic 0x{:08X}; startup staged: {}; staged dir: {}",
                read_u32_le(&loaded_metadata).unwrap_or_default(),
                staged.startup_staged,
                staged.staged_dir.display()
            );
        }

        Ok(loaded_metadata)
    })();

    unsafe {
        FreeLibrary(module);
    }

    loaded
}

#[cfg(not(windows))]
pub fn load_obfuscated_metadata(_files: ObfuscatedFiles) -> Result<Vec<u8>> {
    bail!("Obfuscated metadata loading through GameAssembly.dll is only supported on Windows")
}

#[cfg(windows)]
struct StagedObfuscatedMetadata {
    staged_dir: PathBuf,
    startup_staged: bool,
}

#[cfg(windows)]
fn stage_metadata_for_custom_loader(files: &ObfuscatedFiles) -> Result<StagedObfuscatedMetadata> {
    use std::fs;

    use anyhow::{Context, anyhow};

    let exe_path = std::env::current_exe().context("failed to resolve current executable path")?;
    let exe_dir = exe_path
        .parent()
        .ok_or_else(|| anyhow!("current executable has no parent directory"))?;
    let staged_dir = exe_dir.join("Data").join("Metadata");
    fs::create_dir_all(&staged_dir)
        .with_context(|| format!("failed to create {}", staged_dir.display()))?;

    let staged_global = staged_dir.join("global-metadata.dat");
    fs::write(&staged_global, &files.global_data).with_context(|| {
        format!(
            "failed to stage {} as {}",
            files.global_path.display(),
            staged_global.display()
        )
    })?;

    let mut startup_staged = false;
    if let Some(startup_path) = &files.startup_path {
        let startup_data = fs::read(startup_path)
            .with_context(|| format!("failed to read {}", startup_path.display()))?;
        let staged_startup = staged_dir.join("startup-metadata.dat");
        fs::write(&staged_startup, startup_data).with_context(|| {
            format!(
                "failed to stage {} as {}",
                startup_path.display(),
                staged_startup.display()
            )
        })?;
        startup_staged = true;
    }

    Ok(StagedObfuscatedMetadata {
        staged_dir,
        startup_staged,
    })
}
