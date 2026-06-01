#[path = "../src/layout_model.rs"]
mod layout_model;
#[path = "../src/static_layout.rs"]
mod static_layout;
#[path = "../src/pe_image.rs"]
mod pe_image;

use std::fs;
use std::path::{Path, PathBuf};
use layout_model::LayoutMetadata;

fn resolve_file(name: &str) -> Option<PathBuf> {
    let direct = PathBuf::from(name);
    if direct.exists() {
        return Some(direct);
    }
    let parent = Path::new("..").join(name);
    if parent.exists() {
        return Some(parent);
    }
    None
}

fn load_test_metadata() -> Option<LayoutMetadata> {
    let game_assembly = resolve_file("GameAssembly.dll")?;
    let global_metadata = resolve_file("global-metadata.dat")?;
    let startup_metadata = resolve_file("startup-metadata.dat")?;

    let global_data = fs::read(&global_metadata).ok()?;
    LayoutMetadata::load(&game_assembly, global_data, &startup_metadata).ok()
}

#[test]
fn test_metadata_loads() {
    let metadata = load_test_metadata();
    assert!(metadata.is_some(), "Failed to load test metadata files. Make sure GameAssembly.dll, global-metadata.dat, and startup-metadata.dat exist in parent/local directory.");
}

#[test]
fn test_images_not_empty() {
    let metadata = match load_test_metadata() {
        Some(m) => m,
        None => return, // Skip test if files not found
    };

    let images = metadata.images();
    assert!(!images.is_empty(), "Images list should not be empty");

    // Check if mscorlib.dll is present
    let has_mscorlib = images.iter().any(|img| img.name == "mscorlib.dll");
    assert!(has_mscorlib, "mscorlib.dll should be present in images");
}

#[test]
fn test_core_types_present() {
    let mut metadata = match load_test_metadata() {
        Some(m) => m,
        None => return, // Skip test if files not found
    };

    let images = metadata.images().to_vec();
    let total_types = images.iter().map(|img| img.type_start + img.type_count).max().unwrap_or(0);
    assert!(total_types > 0, "Total type count should be greater than zero");

    let mut found_object = false;
    let mut found_string = false;

    for idx in 0..total_types {
        if let Ok(type_def) = metadata.type_def(idx) {
            if type_def.name == "Object" && type_def.namespace == "System" {
                found_object = true;
            }
            if type_def.name == "String" && type_def.namespace == "System" {
                found_string = true;
            }
        }
    }

    assert!(found_object, "System.Object type should be present");
    assert!(found_string, "System.String type should be present");
}

#[test]
fn test_methods_and_fields_parsing() {
    let mut metadata = match load_test_metadata() {
        Some(m) => m,
        None => return, // Skip test if files not found
    };

    let images = metadata.images().to_vec();
    let total_types = images.iter().map(|img| img.type_start + img.type_count).max().unwrap_or(0);

    // Search for a non-trivial type to inspect its fields and methods
    for idx in 0..total_types {
        if let Ok(type_def) = metadata.type_def(idx) {
            if type_def.name == "Boolean" && type_def.namespace == "System" {
                let type_def_clone = type_def.clone();
                // Read fields of System.Boolean
                let fields = metadata.read_fields(idx, &type_def_clone).unwrap_or_default();
                assert!(!fields.is_empty(), "System.Boolean should have at least one field (m_value)");
                assert!(fields.iter().any(|f| f.name == "m_value"), "System.Boolean should contain field m_value");

                // Read methods of System.Boolean
                if let Some(method_start) = type_def_clone.method_start {
                    assert!(type_def_clone.method_count > 0);
                    let first_method = metadata.read_method(method_start).unwrap();
                    assert!(!first_method.name.is_empty(), "Method name should not be empty");
                }
                break;
            }
        }
    }
}
