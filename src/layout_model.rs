use std::{collections::HashMap, fs, path::Path};

use anyhow::{Context, Result, anyhow};

use crate::{
    pe_image::PeImage,
    static_layout::{StaticLayout, inspect_game_assembly},
};

const IMAGE_ENTRY_SIZE: usize = 40;
const TYPE_ENTRY_SIZE: usize = 0x46;
const FIELD_ENTRY_SIZE: usize = 8;
const METHOD_ENTRY_SIZE: usize = 26;
const PARAMETER_ENTRY_SIZE: usize = 8;
const NESTED_TYPE_ENTRY_SIZE: usize = 4;
const INTERFACE_TYPE_ENTRY_SIZE: usize = 4;
const GENERIC_CLASS_ENTRY_SIZE: usize = 8;
const GENERIC_CONTAINER_ENTRY_SIZE: usize = 16;
const GENERIC_INST_ENTRY_SIZE: usize = 0x10;
const GENERIC_PARAMETER_ENTRY_SIZE: usize = 14;
const TYPE_ATTRIBUTE_KEY: u32 = 0x0112_7490;
const TYPE_PARENT_KEY: u32 = 0x48F9_5547;
const TYPE_BASE_NONE: u32 = 0x48F9_5546;
const TYPE_BASE_OBJECT: u32 = 0x48F9_5548;
const TYPE_BASE_VALUE_TYPE: u32 = 0x48FF_2B27;
const TYPE_BASE_ENUM: u32 = 0x48F9_6832;
const STRING_PAYLOAD_INCREMENT: u64 = 0x3E69_3CD2_3A41_FDEF;
const STRING_PAYLOAD_SEED_MUL: u64 = 0x907C_4962_2D94_D21A;
const STRING_PAYLOAD_SEED_ADD: u64 = 0x75B6_79DA_F67C_3F24;

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
    pub name: String,
    pub type_name: String,
    pub flags: u16,
    pub offset: u32,
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
struct Il2CppTypeEntry {
    data: u32,
    kind: u8,
    bits: u8,
}

pub struct LayoutMetadata {
    layout: StaticLayout,
    global_data: Vec<u8>,
    startup_data: Vec<u8>,
    pe: PeImage,
    image_base: u64,
    il2cpp_type_table_rva: u32,
    method_pointer_table_rva: u32,
    generic_inst_table_rva: u32,
    method_attribute_xor: u16,
    images: Vec<LayoutImage>,
    types: Vec<LayoutTypeDef>,
    string_cache: HashMap<u32, String>,
    type_name_cache: HashMap<(u32, bool), String>,
    generic_container_cache: HashMap<u32, Option<Vec<String>>>,
}

impl LayoutMetadata {
    pub fn load(
        game_assembly: &Path,
        global_data: Vec<u8>,
        startup_metadata: &Path,
    ) -> Result<Self> {
        let layout = inspect_game_assembly(game_assembly)?;
        let startup_data = fs::read(startup_metadata)
            .with_context(|| format!("failed to read {}", startup_metadata.display()))?;
        let pe = PeImage::read(game_assembly)?;
        let image_base = pe.image_base();
        let il2cpp_type_table_rva = va_to_rva(
            pe.read_u64_rva(layout.descriptor_rva + 0x68)?,
            image_base,
            "Il2CppType table",
        )?;
        let method_pointer_table_rva = va_to_rva(
            pe.read_u64_rva(layout.metadata_registration_rva + 0x88)?,
            image_base,
            "method pointer table",
        )?;
        let generic_inst_table_rva = va_to_rva(
            pe.read_u64_rva(layout.descriptor_rva + 0x20)?,
            image_base,
            "generic inst table",
        )?;
        let method_attribute_xor = discover_method_attribute_xor(&pe)?;

        let mut metadata = Self {
            layout,
            global_data,
            startup_data,
            pe,
            image_base,
            il2cpp_type_table_rva,
            method_pointer_table_rva,
            generic_inst_table_rva,
            method_attribute_xor,
            images: Vec::new(),
            types: Vec::new(),
            string_cache: HashMap::new(),
            type_name_cache: HashMap::new(),
            generic_container_cache: HashMap::new(),
        };
        metadata.images = metadata.read_images()?;
        metadata.types = metadata.read_types()?;
        Ok(metadata)
    }

    pub fn images(&self) -> &[LayoutImage] {
        &self.images
    }

    pub fn type_def(&self, index: usize) -> Result<&LayoutTypeDef> {
        self.types
            .get(index)
            .ok_or_else(|| anyhow!("type index {index} is out of range"))
    }

    pub fn read_method(&mut self, method_index: usize) -> Result<LayoutMethod> {
        let entry_offset = self.method_entry_offset(method_index)?;
        let key = method_key(method_index as u64);
        let name_index = (read_u32(&self.global_data, entry_offset)? ^ key) ^ 0x0E71_4BC1;
        let parameter_start =
            (read_u32(&self.global_data, entry_offset + 4)? ^ key ^ 0x0098_89B8) as i32;
        let return_type_index =
            read_u32(&self.global_data, entry_offset + 8)?.wrapping_add(0x9AC1_F4E3) ^ key;
        let flags = self.method_attributes(entry_offset, key)?;
        let parameter_count = (self.global_data[entry_offset + 0x18] ^ key as u8 ^ 0xA8) as usize;
        let mut name = self.decode_string(name_index)?;
        if name.is_empty() {
            name = format!("Method_{method_index}");
        }
        let return_type = self.type_name(return_type_index, false)?;
        let mut method_json_params = Vec::with_capacity(parameter_count);
        let mut dump_params = Vec::with_capacity(parameter_count);

        if parameter_count != 0 && parameter_start >= 0 {
            for index in 0..parameter_count {
                let parameter = self.read_parameter((parameter_start as usize) + index)?;
                method_json_params.push(self.type_name(parameter, true)?);
                dump_params.push(self.type_name(parameter, false)?);
            }
        }

        let va = self.method_pointer(method_index)?;
        let rva = va.checked_sub(self.image_base).unwrap_or_default();

        Ok(LayoutMethod {
            name,
            return_type,
            method_json_params,
            dump_params,
            flags,
            va,
            rva,
        })
    }

    pub fn type_def_display_name(
        &mut self,
        type_index: usize,
        method_json_style: bool,
    ) -> Result<String> {
        let type_def_name = self.type_def(type_index)?.name.clone();
        let full_name = self.type_def_full_name(type_index)?;
        let Some(arity) = generic_arity(&type_def_name) else {
            return Ok(full_name);
        };

        let names = self
            .type_generic_parameter_names(type_index)?
            .filter(|names| names.len() == arity)
            .unwrap_or_else(|| fallback_generic_parameter_names(&type_def_name, arity));
        let names = if method_json_style {
            names
                .into_iter()
                .map(|name| method_json_alias(&name).to_owned())
                .collect::<Vec<_>>()
        } else {
            names
        };
        Ok(format!(
            "{}<{}>",
            strip_generic_arity(&full_name),
            names.join(",")
        ))
    }

    pub fn read_fields(
        &mut self,
        type_index: usize,
        type_def: &LayoutTypeDef,
    ) -> Result<Vec<LayoutField>> {
        let Some(field_start) = type_def.field_start else {
            return Ok(Vec::new());
        };

        let mut fields = Vec::with_capacity(type_def.field_count);
        for local_index in 0..type_def.field_count {
            let field_index = field_start + local_index;
            let entry_offset = self.layout.payload_offset as usize
                + self.layout.global_field_table_offset as usize
                + field_index * FIELD_ENTRY_SIZE;
            require_range(
                &self.global_data,
                entry_offset,
                FIELD_ENTRY_SIZE,
                "global field table",
            )?;

            let key = field_key(type_def.raw_field_start, local_index as u32);
            let name_index = read_u32(&self.global_data, entry_offset)?
                .wrapping_add(key)
                .wrapping_add(0x2AAF_C785);
            let field_type_index = read_u32(&self.global_data, entry_offset + 4)?.wrapping_add(key);

            let mut name = self.decode_string(name_index)?;
            if name.is_empty() {
                name = format!("Field_{field_index}");
            }
            let type_name = self.type_name(field_type_index, false)?;
            let flags = self.il2cpp_type_attrs(field_type_index)?;
            let mut offset = self
                .field_offset(type_index, local_index)
                .unwrap_or_default();
            if type_def.is_value_type && flags & (0x10 | 0x40) == 0 && offset >= 0x10 {
                offset -= 0x10;
            }

            fields.push(LayoutField {
                name,
                type_name,
                flags,
                offset,
            });
        }

        Ok(fields)
    }

    fn read_images(&mut self) -> Result<Vec<LayoutImage>> {
        let image_count = self.layout.header_count_134_div40 as usize;
        let image_table = self.layout.startup_image_table_offset as usize;
        require_range(
            &self.startup_data,
            image_table,
            image_count.saturating_mul(IMAGE_ENTRY_SIZE),
            "startup image table",
        )?;

        let mut images = Vec::with_capacity(image_count);
        for index in 0..image_count {
            let entry_offset = image_table + index * IMAGE_ENTRY_SIZE;
            let name_index = self.decode_image_name_index(entry_offset, index)?;
            let type_start = self.decode_image_type_start(entry_offset, index)? as usize;
            let type_count = self.decode_image_type_count(entry_offset, index)? as usize;
            let name = self.decode_string(name_index)?;
            images.push(LayoutImage {
                name,
                type_start,
                type_count,
            });
        }

        Ok(images)
    }

    fn read_types(&mut self) -> Result<Vec<LayoutTypeDef>> {
        let type_count = self
            .images
            .iter()
            .map(|image| image.type_start + image.type_count)
            .max()
            .unwrap_or_default();
        let mut types = Vec::with_capacity(type_count);
        for index in 0..type_count {
            let entry_offset = self.type_entry_offset(index)?;
            let namespace_index =
                read_u32(&self.global_data, entry_offset + 0x24)?.wrapping_add(0xF1D3_2D89);
            let name_index =
                read_u32(&self.global_data, entry_offset + 0x28)?.wrapping_add(0xE9FD_68F8);
            let raw_field_start = read_u32(&self.global_data, entry_offset + 0x20)?;
            let field_start = raw_field_start.wrapping_sub(0x7485_3864);
            let field_count =
                read_u16(&self.global_data, entry_offset + 0x32)?.wrapping_add(0x444D) as usize;
            let method_start = read_u32(&self.global_data, entry_offset + 0x08)? ^ 0x1A7A_F5FE;
            let method_count =
                read_u16(&self.global_data, entry_offset + 0x34)?.wrapping_add(0x5F93) as usize;
            let flags = read_u32(&self.global_data, entry_offset + 0x14)? ^ TYPE_ATTRIBUTE_KEY;
            let raw_base_type = read_u32(&self.global_data, entry_offset + 0x04)?;
            let generic_container =
                read_u16(&self.global_data, entry_offset + 0x3C)?.wrapping_add(0x5404);
            let namespace = self.decode_string(namespace_index)?;
            let mut name = self.decode_string(name_index)?;
            if name.is_empty() {
                name = format!("Type_{index}");
            }

            types.push(LayoutTypeDef {
                namespace,
                name,
                field_start: (field_count != 0).then_some(field_start as usize),
                field_count,
                raw_field_start,
                method_start: (method_start != u32::MAX).then_some(method_start as usize),
                method_count,
                interface_start: Some(
                    (read_u16(&self.global_data, entry_offset + 0x36)? ^ 0xC28C) as usize,
                ),
                interface_count: (self.global_data[entry_offset + 0x44] ^ 0xC7) as usize,
                parent_type_index: parent_type_index(raw_base_type),
                flags,
                generic_container: (generic_container != u16::MAX)
                    .then_some(generic_container as u32),
                declaring_type: None,
                is_value_type: raw_base_type == TYPE_BASE_VALUE_TYPE
                    || raw_base_type == TYPE_BASE_ENUM,
                is_enum: raw_base_type == TYPE_BASE_ENUM,
            });
        }

        for parent_index in 0..type_count {
            let entry_offset = self.type_entry_offset(parent_index)?;
            let nested_count = self.global_data[entry_offset + 0x43].wrapping_add(4) as usize;
            if nested_count == 0 {
                continue;
            }

            let nested_start =
                (read_u16(&self.global_data, entry_offset + 0x3A)? ^ 0xB2C0) as usize;
            let nested_table_offset = self.layout.payload_offset as usize
                + self.layout.global_nested_type_table_offset as usize
                + nested_start * NESTED_TYPE_ENTRY_SIZE;
            require_range(
                &self.global_data,
                nested_table_offset,
                nested_count * NESTED_TYPE_ENTRY_SIZE,
                "global nested type table",
            )?;

            for local_index in 0..nested_count {
                let nested_index = read_u32(
                    &self.global_data,
                    nested_table_offset + local_index * NESTED_TYPE_ENTRY_SIZE,
                )? as usize;
                if nested_index < types.len() {
                    types[nested_index].declaring_type = Some(parent_index);
                }
            }
        }

        Ok(types)
    }

    pub fn read_parent_name(&mut self, type_def: &LayoutTypeDef) -> Result<Option<String>> {
        type_def
            .parent_type_index
            .map(|type_index| self.type_declaration_reference_name(type_index))
            .transpose()
    }

    pub fn read_interface_names(&mut self, type_def: &LayoutTypeDef) -> Result<Vec<String>> {
        let Some(interface_start) = type_def.interface_start else {
            return Ok(Vec::new());
        };
        if type_def.interface_count == 0 {
            return Ok(Vec::new());
        }

        let entry_offset = self.layout.payload_offset as usize
            + self.layout.global_interface_type_table_offset as usize
            + interface_start * INTERFACE_TYPE_ENTRY_SIZE;
        require_range(
            &self.global_data,
            entry_offset,
            type_def.interface_count * INTERFACE_TYPE_ENTRY_SIZE,
            "global interface type table",
        )?;

        let mut names = Vec::with_capacity(type_def.interface_count);
        for local_index in 0..type_def.interface_count {
            let type_index = read_i32(
                &self.global_data,
                entry_offset + local_index * INTERFACE_TYPE_ENTRY_SIZE,
            )?;
            if type_index < 0 {
                continue;
            }
            names.push(self.type_declaration_reference_name(type_index as u32)?);
        }
        Ok(names)
    }

    fn type_generic_parameter_names(&mut self, type_index: usize) -> Result<Option<Vec<String>>> {
        let Some(generic_container) = self.type_def(type_index)?.generic_container else {
            return Ok(None);
        };
        if let Some(names) = self.generic_container_cache.get(&generic_container) {
            return Ok(names.clone());
        }

        let entry_offset = self.layout.payload_offset as usize
            + self.layout.global_generic_container_table_offset as usize
            + generic_container as usize * GENERIC_CONTAINER_ENTRY_SIZE;
        if entry_offset
            .checked_add(GENERIC_CONTAINER_ENTRY_SIZE)
            .is_none_or(|end| end > self.global_data.len())
        {
            self.generic_container_cache.insert(generic_container, None);
            return Ok(None);
        }

        let key = generic_container_key(generic_container as u64);
        let parameter_count =
            (read_u32(&self.global_data, entry_offset)?.wrapping_add(0xF331_4477) ^ key) as usize;
        let parameter_start =
            read_u32(&self.global_data, entry_offset + 0x0C)?.wrapping_add(0xF12A_F1B1) ^ key;
        if parameter_count == 0 || parameter_count > 64 {
            self.generic_container_cache.insert(generic_container, None);
            return Ok(None);
        }

        let mut names = Vec::with_capacity(parameter_count);
        for index in 0..parameter_count {
            let parameter_index = parameter_start.wrapping_add(index as u32);
            names.push(
                self.generic_parameter_name(parameter_index)?
                    .unwrap_or_else(|| format!("T{index}")),
            );
        }
        self.generic_container_cache
            .insert(generic_container, Some(names.clone()));
        Ok(Some(names))
    }

    fn read_parameter(&self, parameter_index: usize) -> Result<u32> {
        let entry_offset = self.layout.payload_offset as usize
            + self.layout.global_parameter_table_offset as usize
            + parameter_index * PARAMETER_ENTRY_SIZE;
        require_range(
            &self.global_data,
            entry_offset,
            PARAMETER_ENTRY_SIZE,
            "global parameter table",
        )?;

        let key = parameter_key(parameter_index as u64);
        Ok((read_u32(&self.global_data, entry_offset)? ^ 0x67E9_0DC5).wrapping_sub(key))
    }

    fn type_name(&mut self, type_index: u32, method_json_style: bool) -> Result<String> {
        if let Some(name) = self.type_name_cache.get(&(type_index, method_json_style)) {
            return Ok(name.clone());
        }

        let entry = self.read_il2cpp_type(type_index)?;
        let mut name = match entry.kind {
            0x01 => "System.Void".to_owned(),
            0x02 => "System.Boolean".to_owned(),
            0x03 => "System.Char".to_owned(),
            0x04 => "System.SByte".to_owned(),
            0x05 => "System.Byte".to_owned(),
            0x06 => "System.Int16".to_owned(),
            0x07 => "System.UInt16".to_owned(),
            0x08 => "System.Int32".to_owned(),
            0x09 => "System.UInt32".to_owned(),
            0x0A => "System.Int64".to_owned(),
            0x0B => "System.UInt64".to_owned(),
            0x0C => "System.Single".to_owned(),
            0x0D => "System.Double".to_owned(),
            0x10 => "System.TypedReference".to_owned(),
            0x0E => "System.String".to_owned(),
            0x11 | 0x12 | 0x1C => self.type_def_full_name(entry.data as usize)?,
            0x0F => format!("{}*", self.type_name(entry.data, method_json_style)?),
            0x13 | 0x1E => self
                .generic_parameter_name(entry.data)?
                .unwrap_or_else(|| format!("T{}", entry.data)),
            0x1D => format!("{}[]", self.type_name(entry.data, method_json_style)?),
            0x18 => "System.IntPtr".to_owned(),
            0x19 => "System.UIntPtr".to_owned(),
            0x15 => self
                .generic_inst_name(entry.data, method_json_style)?
                .unwrap_or_else(|| format!("GenericInst_{}", entry.data)),
            other => format!("Il2CppType_0x{other:X}_{}", entry.data),
        };

        if entry.bits & 0x40 != 0 {
            name.push('&');
        }

        if method_json_style {
            name = method_json_alias(&name).to_owned();
        }

        self.type_name_cache
            .insert((type_index, method_json_style), name.clone());
        Ok(name)
    }

    fn generic_parameter_name(&mut self, parameter_index: u32) -> Result<Option<String>> {
        let entry_offset = self.layout.payload_offset as usize
            + self.layout.global_generic_parameter_table_offset as usize
            + parameter_index as usize * GENERIC_PARAMETER_ENTRY_SIZE;
        if entry_offset
            .checked_add(GENERIC_PARAMETER_ENTRY_SIZE)
            .is_none_or(|end| end > self.global_data.len())
        {
            return Ok(None);
        }

        let key = generic_parameter_key(parameter_index as u64);
        let name_index = read_u32(&self.global_data, entry_offset)?
            .wrapping_sub(key)
            .wrapping_add(0xBB77_7EDD);
        let name = self.decode_string(name_index)?;
        if name.is_empty() {
            Ok(None)
        } else {
            Ok(Some(name))
        }
    }

    fn generic_inst_name(
        &mut self,
        generic_class_index: u32,
        method_json_style: bool,
    ) -> Result<Option<String>> {
        let class_offset = self.layout.startup_section_164_offset as usize
            + generic_class_index as usize * GENERIC_CLASS_ENTRY_SIZE;
        if class_offset
            .checked_add(GENERIC_CLASS_ENTRY_SIZE)
            .is_none_or(|end| end > self.startup_data.len())
        {
            return Ok(None);
        }

        let type_def_index = read_u32(&self.startup_data, class_offset)? as usize;
        let class_inst_index = read_i32(&self.startup_data, class_offset + 4)?;
        if class_inst_index < 0 {
            return Ok(None);
        }

        let inst_rva = self
            .generic_inst_table_rva
            .checked_add(
                (class_inst_index as u32)
                    .checked_mul(GENERIC_INST_ENTRY_SIZE as u32)
                    .ok_or_else(|| {
                        anyhow!("generic inst index {class_inst_index} overflows table byte offset")
                    })?,
            )
            .ok_or_else(|| anyhow!("generic inst index {class_inst_index} overflows table RVA"))?;
        let arg_count = self.pe.read_u32_rva(inst_rva)? as usize;
        let arg_table_va = self.pe.read_u64_rva(inst_rva + 8)?;
        let arg_table_rva = va_to_rva(arg_table_va, self.image_base, "generic inst args table")?;

        let mut args = Vec::with_capacity(arg_count);
        for arg_index in 0..arg_count {
            let arg_va = self.pe.read_u64_rva(
                arg_table_rva
                    .checked_add((arg_index as u32).checked_mul(8).ok_or_else(|| {
                        anyhow!("generic arg index {arg_index} overflows table byte offset")
                    })?)
                    .ok_or_else(|| anyhow!("generic arg index {arg_index} overflows table RVA"))?,
            )?;
            let type_index = self.il2cpp_type_pointer_to_index(arg_va)?;
            args.push(self.type_name(type_index, method_json_style)?);
        }

        let base = self.type_def_full_name(type_def_index)?;
        let base = strip_generic_arity(&base);
        Ok(Some(format!("{base}<{}>", args.join(","))))
    }

    fn type_declaration_reference_name(&mut self, type_index: u32) -> Result<String> {
        let entry = self.read_il2cpp_type(type_index)?;
        match entry.kind {
            0x11 | 0x12 | 0x1C => self.type_def_short_name(entry.data as usize),
            0x15 => self
                .generic_inst_definition_name(entry.data)?
                .or_else(|| Some(format!("GenericInst_{}", entry.data)))
                .context("generic inst declaration name unexpectedly missing"),
            _ => {
                let name = self.type_name(type_index, false)?;
                Ok(shorten_declaration_reference(&name))
            }
        }
    }

    fn generic_inst_definition_name(&self, generic_class_index: u32) -> Result<Option<String>> {
        let class_offset = self.layout.startup_section_164_offset as usize
            + generic_class_index as usize * GENERIC_CLASS_ENTRY_SIZE;
        if class_offset
            .checked_add(GENERIC_CLASS_ENTRY_SIZE)
            .is_none_or(|end| end > self.startup_data.len())
        {
            return Ok(None);
        }

        let type_def_index = read_u32(&self.startup_data, class_offset)? as usize;
        self.type_def_short_name(type_def_index).map(Some)
    }

    fn type_def_short_name(&self, type_index: usize) -> Result<String> {
        let mut chain = Vec::new();
        let mut current_index = Some(type_index);
        while let Some(index) = current_index {
            let type_def = self.type_def(index)?;
            chain.push(index);
            current_index = type_def.declaring_type;
            if chain.len() > self.types.len() {
                return Err(anyhow!(
                    "declaring type cycle detected at type index {type_index}"
                ));
            }
        }
        chain.reverse();

        Ok(chain
            .into_iter()
            .map(|index| self.type_def(index).map(|type_def| type_def.name.clone()))
            .collect::<Result<Vec<_>>>()?
            .join("."))
    }

    fn type_def_full_name(&self, type_index: usize) -> Result<String> {
        let mut chain = Vec::new();
        let mut current_index = Some(type_index);
        while let Some(index) = current_index {
            let type_def = self.type_def(index)?;
            chain.push(index);
            current_index = type_def.declaring_type;
            if chain.len() > self.types.len() {
                return Err(anyhow!(
                    "declaring type cycle detected at type index {type_index}"
                ));
            }
        }
        chain.reverse();

        let root = self.type_def(chain[0])?;
        let mut name = if root.namespace.is_empty() {
            root.name.clone()
        } else {
            format!("{}.{}", root.namespace, root.name)
        };
        for nested_index in chain.into_iter().skip(1) {
            name.push('.');
            name.push_str(&self.type_def(nested_index)?.name);
        }
        Ok(name)
    }

    fn read_il2cpp_type(&self, type_index: u32) -> Result<Il2CppTypeEntry> {
        let rva = self
            .il2cpp_type_table_rva
            .checked_add(type_index.checked_mul(8).ok_or_else(|| {
                anyhow!("Il2CppType index {type_index} overflows table byte offset")
            })?)
            .ok_or_else(|| anyhow!("Il2CppType index {type_index} overflows table RVA"))?;
        let raw = self.pe.read_u64_rva(rva)?;
        Ok(Il2CppTypeEntry {
            data: raw as u32,
            kind: (raw >> 48) as u8,
            bits: (raw >> 56) as u8,
        })
    }

    fn read_il2cpp_type_raw(&self, type_index: u32) -> Result<u64> {
        let rva = self
            .il2cpp_type_table_rva
            .checked_add(type_index.checked_mul(8).ok_or_else(|| {
                anyhow!("Il2CppType index {type_index} overflows table byte offset")
            })?)
            .ok_or_else(|| anyhow!("Il2CppType index {type_index} overflows table RVA"))?;
        self.pe.read_u64_rva(rva)
    }

    fn il2cpp_type_attrs(&self, type_index: u32) -> Result<u16> {
        Ok((self.read_il2cpp_type_raw(type_index)? >> 32) as u16)
    }

    fn il2cpp_type_pointer_to_index(&self, type_va: u64) -> Result<u32> {
        let type_rva = va_to_rva(type_va, self.image_base, "Il2CppType pointer")?;
        let byte_offset = type_rva
            .checked_sub(self.il2cpp_type_table_rva)
            .ok_or_else(|| {
                anyhow!(
                    "Il2CppType pointer RVA 0x{type_rva:X} is before table RVA 0x{:X}",
                    self.il2cpp_type_table_rva
                )
            })?;
        if byte_offset % 8 != 0 {
            return Err(anyhow!(
                "Il2CppType pointer RVA 0x{type_rva:X} is not aligned to an Il2CppType entry"
            ));
        }
        Ok(byte_offset / 8)
    }

    fn field_offset(&self, type_index: usize, local_field_index: usize) -> Result<u32> {
        let map_offset = self.layout.payload_offset as usize
            + self.layout.global_type_field_offset_map_offset as usize
            + type_index * 4;
        require_range(
            &self.global_data,
            map_offset,
            4,
            "global type field-offset map",
        )?;
        let selector = read_i32(&self.global_data, map_offset)?;
        if selector < 0 {
            return Ok(0);
        }

        let group_offset = self.layout.payload_offset as usize
            + self.layout.global_field_offset_group_table_offset as usize
            + selector as usize * 12;
        require_range(
            &self.global_data,
            group_offset,
            12,
            "global field-offset group table",
        )?;
        let offset_start = read_u32(&self.global_data, group_offset + 8)? as usize;

        let offset_entry = self.layout.payload_offset as usize
            + self.layout.global_field_offset_table_offset as usize
            + (offset_start + local_field_index) * 4;
        require_range(
            &self.global_data,
            offset_entry,
            4,
            "global field-offset table",
        )?;
        Ok(read_u32(&self.global_data, offset_entry)? & 0x00FF_FFFF)
    }

    fn method_pointer(&self, method_index: usize) -> Result<u64> {
        let rva = self
            .method_pointer_table_rva
            .checked_add((method_index as u32).checked_mul(8).ok_or_else(|| {
                anyhow!("method pointer index {method_index} overflows table byte offset")
            })?)
            .ok_or_else(|| anyhow!("method pointer index {method_index} overflows table RVA"))?;
        self.pe.read_u64_rva(rva)
    }

    fn method_attributes(&self, entry_offset: usize, key: u32) -> Result<u16> {
        Ok(read_u16(&self.global_data, entry_offset + 0x0E)?
            ^ key as u16
            ^ self.method_attribute_xor)
    }

    fn decode_image_name_index(&self, entry_offset: usize, image_index: usize) -> Result<u32> {
        let key = image_key(image_index as u32);
        Ok(read_u32(&self.startup_data, entry_offset + 0x0C)? ^ key ^ 0x4D64_8371)
    }

    fn decode_image_type_start(&self, entry_offset: usize, image_index: usize) -> Result<u32> {
        let key = image_key(image_index as u32);
        Ok((read_u32(&self.startup_data, entry_offset + 0x14)? ^ key ^ 0x7BAB_EEA0) ^ 0x235A_EAF5)
    }

    fn decode_image_type_count(&self, entry_offset: usize, image_index: usize) -> Result<u32> {
        let key = image_key(image_index as u32);
        Ok((read_u32(&self.startup_data, entry_offset + 0x04)? ^ key ^ 0x10FE_A394) ^ 0x7C06_D18C)
    }

    fn type_entry_offset(&self, type_index: usize) -> Result<usize> {
        let offset = self.layout.payload_offset as usize
            + self.layout.global_type_table_offset as usize
            + type_index * TYPE_ENTRY_SIZE;
        require_range(
            &self.global_data,
            offset,
            TYPE_ENTRY_SIZE,
            "global type table",
        )?;
        Ok(offset)
    }

    fn method_entry_offset(&self, method_index: usize) -> Result<usize> {
        let offset = self.layout.payload_offset as usize
            + self.layout.global_method_table_offset as usize
            + method_index * METHOD_ENTRY_SIZE;
        require_range(
            &self.global_data,
            offset,
            METHOD_ENTRY_SIZE,
            "global method table",
        )?;
        Ok(offset)
    }

    fn decode_string(&mut self, index: u32) -> Result<String> {
        if let Some(value) = self.string_cache.get(&index) {
            return Ok(value.clone());
        }

        let value = decode_string_raw(&self.global_data, &self.layout, index)?;
        self.string_cache.insert(index, value.clone());
        Ok(value)
    }
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

    let mut key = STRING_PAYLOAD_SEED_ADD
        .wrapping_add(STRING_PAYLOAD_SEED_MUL.wrapping_mul(string_offset as u64));
    let mut out = Vec::with_capacity(qword_count * 8);
    for chunk_index in 0..qword_count {
        let encrypted = read_u64(global_data, data_offset + chunk_index * 8)?;
        out.extend_from_slice(&(encrypted ^ key).to_le_bytes());
        key = key.wrapping_add(STRING_PAYLOAD_INCREMENT);
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

fn parameter_key(index: u64) -> u32 {
    let value = index
        .wrapping_mul(0x72E1_D74B_12B)
        .wrapping_add(0x1911_D05A_FF5)
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

fn parent_type_index(raw_base_type: u32) -> Option<u32> {
    if matches!(
        raw_base_type,
        TYPE_BASE_NONE | TYPE_BASE_OBJECT | TYPE_BASE_VALUE_TYPE | TYPE_BASE_ENUM
    ) {
        return None;
    }

    Some(raw_base_type.wrapping_sub(TYPE_PARENT_KEY))
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
    for instruction_rva in pe.scan_pattern(&method_attribute_xor_pattern()) {
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
