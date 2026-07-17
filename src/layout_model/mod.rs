pub mod output;
pub mod parser;

use crate::{pe_image::PeImage, static_layout::StaticLayout};
use std::collections::HashMap;

pub const IMAGE_ENTRY_SIZE: usize = 40;
pub const TYPE_ENTRY_SIZE: usize = 0x46;
pub const FIELD_ENTRY_SIZE: usize = 8;
pub const METHOD_ENTRY_SIZE: usize = 26;
pub const PARAMETER_ENTRY_SIZE: usize = 8;
pub const NESTED_TYPE_ENTRY_SIZE: usize = 4;
pub const INTERFACE_TYPE_ENTRY_SIZE: usize = 4;
pub const GENERIC_CLASS_ENTRY_SIZE: usize = 8;
pub const GENERIC_CONTAINER_ENTRY_SIZE: usize = 16;
pub const GENERIC_INST_ENTRY_SIZE: usize = 0x10;
pub const GENERIC_PARAMETER_ENTRY_SIZE: usize = 14;
pub const FIELD_DEFAULT_VALUE_ENTRY_SIZE: usize = 12;

#[derive(Clone, Debug)]
pub struct LayoutImage {
    pub name: String,
    pub type_start: usize,
    pub type_count: usize,
}

#[derive(Clone, Debug)]
pub struct LayoutTypeDef {
    pub namespace: String,
    pub name: String,
    pub field_start: Option<usize>,
    pub field_count: usize,
    pub raw_field_start: u32,
    pub method_start: Option<usize>,
    pub method_count: usize,
    pub interface_start: Option<usize>,
    pub interface_count: usize,
    pub parent_type_index: Option<u32>,
    pub flags: u32,
    pub generic_container: Option<u32>,
    pub declaring_type: Option<usize>,
    pub is_value_type: bool,
    pub is_enum: bool,
}

#[derive(Clone, Debug)]
pub struct LayoutField {
    pub index: usize,
    pub name: String,
    pub type_name: String,
    pub flags: u16,
    pub offset: u32,
}

#[derive(Clone, Debug)]
pub struct LayoutEnumValue {
    pub name: String,
    pub value: i32,
}

#[derive(Clone, Debug)]
pub struct LayoutMethod {

    pub name: String,
    pub return_type: String,
    pub method_json_params: Vec<String>,
    pub dump_params: Vec<String>,
    pub flags: u16,
    pub va: u64,
    pub rva: u64,
}

#[derive(Clone, Copy)]
pub(crate) struct Il2CppTypeEntry {
    pub(crate) data: u32,
    pub(crate) kind: u8,
    pub(crate) bits: u8,
}

pub struct LayoutMetadata {
    pub layout: StaticLayout,
    pub global_data: Vec<u8>,
    pub startup_data: Vec<u8>,
    pub pe: PeImage,
    pub(crate) image_base: u64,
    pub(crate) il2cpp_type_table_rva: u32,
    pub(crate) method_pointer_table_rva: u32,
    pub(crate) generic_inst_table_rva: u32,
    pub(crate) method_attribute_xor: u16,
    pub(crate) images: Vec<LayoutImage>,
    pub(crate) types: Vec<LayoutTypeDef>,
    pub(crate) string_cache: HashMap<u32, String>,
    pub(crate) type_name_cache: HashMap<(u32, bool), String>,
    pub(crate) generic_container_cache: HashMap<u32, Option<Vec<String>>>,
}
