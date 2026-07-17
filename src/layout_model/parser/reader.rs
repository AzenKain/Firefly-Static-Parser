use anyhow::{Context, Result, anyhow};

use super::*;
use super::super::*;

use super::super::{IMAGE_ENTRY_SIZE, TYPE_ENTRY_SIZE, FIELD_ENTRY_SIZE, METHOD_ENTRY_SIZE, PARAMETER_ENTRY_SIZE, NESTED_TYPE_ENTRY_SIZE, INTERFACE_TYPE_ENTRY_SIZE, GENERIC_CLASS_ENTRY_SIZE, GENERIC_CONTAINER_ENTRY_SIZE, GENERIC_INST_ENTRY_SIZE, GENERIC_PARAMETER_ENTRY_SIZE, FIELD_DEFAULT_VALUE_ENTRY_SIZE};
impl LayoutMetadata {
    pub fn images(&self) -> &[LayoutImage] {
        &self.images
    }

    pub fn type_def(&self, index: usize) -> Result<&LayoutTypeDef> {
        self.types
            .get(index)
            .ok_or_else(|| anyhow!("type index {index} is out of range"))
    }

    pub fn decode_string(&mut self, index: u32) -> Result<String> {
        if let Some(s) = self.string_cache.get(&index) {
            return Ok(s.clone());
        }
        let s = super::decode_string_raw(&self.global_data, &self.layout, index)?;
        self.string_cache.insert(index, s.clone());
        Ok(s)
    }

    pub fn read_method(&mut self, method_index: usize) -> Result<LayoutMethod> {
        let entry_offset = self.method_entry_offset(method_index)?;
        let decoded = self.decode_method_header(method_index, entry_offset)?;
        let mut name = self.decode_string(decoded.name_index)?;
        if name.is_empty() {
            name = format!("Method_{method_index}");
        }
        let return_type = self
            .type_name(decoded.return_type_index, false)
            .with_context(|| {
                format!(
                    "failed to decode return type 0x{:X} for method index {method_index} ({name})",
                    decoded.return_type_index
                )
            })?;
        let mut method_json_params = Vec::with_capacity(decoded.parameter_count);
        let mut dump_params = Vec::with_capacity(decoded.parameter_count);

        if decoded.parameter_count != 0 && decoded.parameter_start >= 0 {
            for index in 0..decoded.parameter_count {
                let parameter_index = (decoded.parameter_start as usize) + index;
                let parameter = self.read_parameter(parameter_index).with_context(|| {
                    format!(
                        "failed to read parameter {parameter_index} for method index {method_index} ({name})"
                    )
                })?;
                method_json_params
                    .push(self.type_name(parameter, true).with_context(|| {
                        format!(
                            "failed to decode json parameter type 0x{parameter:X} \
                             at parameter {parameter_index} for method index {method_index} ({name})"
                        )
                    })?);
                dump_params
                    .push(self.type_name(parameter, false).with_context(|| {
                        format!(
                            "failed to decode dump parameter type 0x{parameter:X} \
                             at parameter {parameter_index} for method index {method_index} ({name})"
                        )
                    })?);
            }
        }

        let va = self.method_pointer(method_index)?;
        let rva = va.checked_sub(self.image_base).unwrap_or_default();

        Ok(LayoutMethod {

            name,
            return_type,
            method_json_params,
            dump_params,
            flags: decoded.flags,
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
                index: field_index,
                name,
                type_name,
                flags,
                offset,
            });
        }

        Ok(fields)
    }

    pub fn read_enum_values(
        &mut self,
        type_index: usize,
        type_def: &LayoutTypeDef,
    ) -> Result<Vec<LayoutEnumValue>> {
        if !type_def.is_enum {
            return Ok(Vec::new());
        }

        let mut values = Vec::new();
        for field in self.read_fields(type_index, type_def)? {
            if field.name == "value__" {
                continue;
            }
            if field.flags & 0x40 == 0 {
                continue;
            }

            let data = self
                .read_field_default_value_data(field.index, std::mem::size_of::<i32>())?
                .with_context(|| {
                    format!(
                        "enum {} field {} has no default-value table entry",
                        self.type_def_full_name(type_index)
                            .unwrap_or_else(|_| type_def.name.clone()),
                        field.name
                    )
                })?;
            let value = i32::from_le_bytes(data.try_into().map_err(|_| {
                anyhow!(
                    "enum {} field {} default value is not i32-sized",
                    type_def.name,
                    field.name
                )
            })?);
            values.push(LayoutEnumValue {
                name: field.name,
                value,
            });
        }

        Ok(values)
    }

    pub fn read_field_default_value_data(
        &self,
        field_index: usize,
        size: usize,
    ) -> Result<Option<Vec<u8>>> {
        let table_offset = self.layout.payload_offset as usize
            + self.layout.global_field_default_value_table_offset as usize;
        let field_index = i32::try_from(field_index)
            .with_context(|| format!("field index {field_index} does not fit in i32"))?;

        let mut low = 0_usize;
        let mut high = self.layout.field_default_value_count as usize;
        while low < high {
            let mid = low + (high - low) / 2;
            let entry_offset = table_offset + mid * FIELD_DEFAULT_VALUE_ENTRY_SIZE;
            require_range(
                &self.global_data,
                entry_offset,
                FIELD_DEFAULT_VALUE_ENTRY_SIZE,
                "field default value table",
            )?;
            let entry_field_index = read_i32(&self.global_data, entry_offset + 8)?;
            match entry_field_index.cmp(&field_index) {
                std::cmp::Ordering::Less => low = mid + 1,
                std::cmp::Ordering::Greater => high = mid,
                std::cmp::Ordering::Equal => {
                    let data_index = read_i32(&self.global_data, entry_offset + 4)?;
                    if data_index < 0 {
                        return Ok(None);
                    }

                    let data_offset = self.layout.payload_offset as usize
                        + self.layout.global_field_default_value_data_offset as usize
                        + data_index as usize;
                    require_range(
                        &self.global_data,
                        data_offset,
                        size,
                        "field default value data",
                    )?;
                    return Ok(Some(
                        self.global_data[data_offset..data_offset + size].to_vec(),
                    ));
                }
            }
        }

        Ok(None)
    }

    pub(crate) fn read_images(&mut self) -> Result<Vec<LayoutImage>> {
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

    pub(crate) fn read_types(&mut self) -> Result<Vec<LayoutTypeDef>> {
        let type_count = self
            .images
            .iter()
            .map(|image| image.type_start + image.type_count)
            .max()
            .unwrap_or_default();
        let mut types = Vec::with_capacity(type_count);
        for index in 0..type_count {
            let entry_offset = self.type_entry_offset(index)?;
            let decoded_type = self.decode_type_definition_header(index, entry_offset)?;
            let namespace_index = decoded_type.namespace_index;
            let name_index = decoded_type.name_index;
            let raw_field_start = decoded_type.raw_field_start;
            let field_start = decoded_type.field_start;
            let field_count = decoded_type.field_count;
            let method_start = decoded_type.method_start;
            let method_count = decoded_type.method_count;
            let flags = decoded_type.flags;
            let raw_base_type = decoded_type.raw_base_type;
            let generic_container = decoded_type.generic_container;
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
                interface_start: decoded_type.interface_start,
                interface_count: decoded_type.interface_count,
                parent_type_index: parent_type_index(raw_base_type, self.layout.keys),
                flags,
                generic_container: (generic_container != u16::MAX)
                    .then_some(generic_container as u32),
                declaring_type: None,
                is_value_type: raw_base_type == self.layout.keys.type_base_value_type
                    || raw_base_type == self.layout.keys.type_base_enum,
                is_enum: raw_base_type == self.layout.keys.type_base_enum,
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

    pub(crate) fn type_generic_parameter_names(&mut self, type_index: usize) -> Result<Option<Vec<String>>> {
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

    pub(crate) fn read_parameter(&self, parameter_index: usize) -> Result<u32> {
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

    pub fn type_name(&mut self, type_index: u32, method_json_style: bool) -> Result<String> {
        if let Some(name) = self.type_name_cache.get(&(type_index, method_json_style)) {
            return Ok(name.clone());
        }

        let entry = self
            .read_il2cpp_type(type_index)
            .with_context(|| format!("failed to read Il2CppType index 0x{type_index:X}"))?;
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

    pub(crate) fn generic_parameter_name(&mut self, parameter_index: u32) -> Result<Option<String>> {
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

    pub(crate) fn generic_inst_name(
        &mut self,
        generic_class_index: u32,
        method_json_style: bool,
    ) -> Result<Option<String>> {
        self.generic_inst_name_inner(generic_class_index, method_json_style)
    }

    pub(crate) fn generic_inst_name_inner(
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
        if type_def_index >= self.types.len() {
            return Ok(None);
        }
        let class_inst_index = read_i32(&self.startup_data, class_offset + 4)?;
        if class_inst_index < 0 {
            return Ok(None);
        }
        if self.generic_inst_table_rva == 0 {
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

    pub(crate) fn type_declaration_reference_name(&mut self, type_index: u32) -> Result<String> {
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

    pub(crate) fn generic_inst_definition_name(&self, generic_class_index: u32) -> Result<Option<String>> {
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

    pub(crate) fn type_def_short_name(&self, type_index: usize) -> Result<String> {
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

    pub fn type_def_full_name(&self, type_index: usize) -> Result<String> {
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

    pub(crate) fn read_il2cpp_type(&self, type_index: u32) -> Result<Il2CppTypeEntry> {
        let rva = self
            .il2cpp_type_table_rva
            .checked_add(type_index.checked_mul(16).ok_or_else(|| {
                anyhow!("Il2CppType index {type_index} overflows table byte offset")
            })?)
            .ok_or_else(|| anyhow!("Il2CppType index {type_index} overflows table RVA"))?;
        let raw_data = self.pe.read_u64_rva(rva)?;
        let bits = self.pe.read_u32_rva(rva + 8)?;
        let data = if raw_data >= self.image_base {
            match self.il2cpp_type_pointer_to_index(raw_data) {
                Ok(index) => index,
                Err(_) => return self.read_pointed_il2cpp_type(raw_data),
            }
        } else {
            raw_data as u32
        };
        Ok(Il2CppTypeEntry {
            data,
            kind: (bits >> 16) as u8,
            bits: (bits >> 24) as u8,
        })
    }

    pub(crate) fn read_pointed_il2cpp_type(&self, type_va: u64) -> Result<Il2CppTypeEntry> {
        let type_rva = va_to_rva(type_va, self.image_base, "Il2CppType pointer")?;
        let raw_data = self.pe.read_u64_rva(type_rva)?;
        let bits = self.pe.read_u32_rva(type_rva + 8)?;
        let kind = if bits <= 0x1F {
            bits as u8
        } else {
            (bits >> 16) as u8
        };
        let data = if raw_data >= self.image_base {
            self.il2cpp_type_pointer_to_index(raw_data)
                .unwrap_or_default()
        } else {
            raw_data as u32
        };
        Ok(Il2CppTypeEntry {
            data,
            kind,
            bits: (bits >> 24) as u8,
        })
    }

    pub(crate) fn read_il2cpp_type_raw(&self, type_index: u32) -> Result<u64> {
        let rva = self
            .il2cpp_type_table_rva
            .checked_add(type_index.checked_mul(16).ok_or_else(|| {
                anyhow!("Il2CppType index {type_index} overflows table byte offset")
            })?)
            .ok_or_else(|| anyhow!("Il2CppType index {type_index} overflows table RVA"))?;
        let raw_data = self.pe.read_u64_rva(rva)?;
        let bits = self.pe.read_u32_rva(rva + 8)?;
        Ok(((bits as u64) << 32) | (raw_data as u32 as u64))
    }

    pub(crate) fn il2cpp_type_attrs(&self, type_index: u32) -> Result<u16> {
        Ok((self.read_il2cpp_type_raw(type_index)? >> 32) as u16)
    }

    pub(crate) fn il2cpp_type_pointer_to_index(&self, type_va: u64) -> Result<u32> {
        let type_rva = va_to_rva(type_va, self.image_base, "Il2CppType pointer")?;
        let byte_offset = type_rva
            .checked_sub(self.il2cpp_type_table_rva)
            .ok_or_else(|| {
                anyhow!(
                    "Il2CppType pointer RVA 0x{type_rva:X} is before table RVA 0x{:X}",
                    self.il2cpp_type_table_rva
                )
            })?;
        let entry_size = 16;
        if byte_offset % entry_size != 0 {
            return Err(anyhow!(
                "Il2CppType pointer RVA 0x{type_rva:X} is not aligned to an Il2CppType entry"
            ));
        }
        Ok(byte_offset / entry_size)
    }

    pub(crate) fn field_offset(&self, type_index: usize, local_field_index: usize) -> Result<u32> {
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

    pub(crate) fn method_pointer(&self, method_index: usize) -> Result<u64> {
        if self.method_pointer_table_rva == 0 {
            return Ok(0);
        }
        let rva = self
            .method_pointer_table_rva
            .checked_add((method_index as u32).checked_mul(8).ok_or_else(|| {
                anyhow!("method pointer index {method_index} overflows table byte offset")
            })?)
            .ok_or_else(|| anyhow!("method pointer index {method_index} overflows table RVA"))?;
        self.pe.read_u64_rva(rva).map_err(|e| anyhow!("failed to read method pointer for {method_index} at 0x{:x}: {}", rva, e))
    }

    fn decode_method_header(
        &self,
        method_index: usize,
        entry_offset: usize,
    ) -> Result<MethodHeader> {
        let key = method_key(method_index as u64);
        Ok(MethodHeader {
            name_index: (read_u32(&self.global_data, entry_offset)? ^ key) ^ 0x0E71_4BC1,
            parameter_start: (read_u32(&self.global_data, entry_offset + 4)? ^ key ^ 0x0098_89B8)
                as i32,
            return_type_index: read_u32(&self.global_data, entry_offset + 8)?
                .wrapping_add(0x9AC1_F4E3)
                ^ key,
            flags: self.method_attributes(entry_offset, key)?,
            parameter_count: (self.global_data[entry_offset + 0x18] ^ key as u8 ^ 0xA8) as usize,
        })
    }

    pub(crate) fn method_attributes(&self, entry_offset: usize, key: u32) -> Result<u16> {
        Ok(read_u16(&self.global_data, entry_offset + 0x0E)?
            ^ key as u16
            ^ self.method_attribute_xor)
    }

    pub(crate) fn decode_image_name_index(&self, entry_offset: usize, image_index: usize) -> Result<u32> {
        let key = image_key(image_index as u32);
        Ok(read_u32(&self.startup_data, entry_offset + 0x0C)? ^ key ^ 0x4D64_8371)
    }

    pub(crate) fn decode_image_type_start(&self, entry_offset: usize, image_index: usize) -> Result<u32> {
        let key = image_key(image_index as u32);
        Ok((read_u32(&self.startup_data, entry_offset + 0x14)? ^ key ^ 0x7BAB_EEA0) ^ 0x235A_EAF5)
    }

    pub(crate) fn decode_image_type_count(&self, entry_offset: usize, image_index: usize) -> Result<u32> {
        let key = image_key(image_index as u32);
        Ok((read_u32(&self.startup_data, entry_offset + 0x04)? ^ key ^ 0x10FE_A394) ^ 0x7C06_D18C)
    }

    fn decode_type_definition_header(
        &self,
        _type_index: usize,
        entry_offset: usize,
    ) -> Result<TypeDefinitionHeader> {
        let raw_field_start = read_u32(&self.global_data, entry_offset + 0x20)?;
        Ok(TypeDefinitionHeader {
            namespace_index: read_u32(&self.global_data, entry_offset + 0x24)?
                .wrapping_add(0xF1D3_2D89),
            name_index: read_u32(&self.global_data, entry_offset + 0x28)?.wrapping_add(0xE9FD_68F8),
            raw_field_start,
            field_start: raw_field_start.wrapping_sub(0x7485_3864),
            field_count: read_u16(&self.global_data, entry_offset + 0x32)?.wrapping_add(0x444D)
                as usize,
            method_start: read_u32(&self.global_data, entry_offset + 0x08)? ^ 0x1A7A_F5FE,
            method_count: read_u16(&self.global_data, entry_offset + 0x34)?.wrapping_add(0x5F93)
                as usize,
            flags: read_u32(&self.global_data, entry_offset + 0x14)?
                ^ self.layout.keys.type_attribute_key,
            raw_base_type: read_u32(&self.global_data, entry_offset + 0x04)?,
            generic_container: read_u16(&self.global_data, entry_offset + 0x3C)?
                .wrapping_add(0x5404),
            interface_start: Some(
                (read_u16(&self.global_data, entry_offset + 0x36)? ^ 0xC28C) as usize,
            ),
            interface_count: (self.global_data[entry_offset + 0x44] ^ 0xC7) as usize,
        })
    }

    pub(crate) fn type_entry_offset(&self, type_index: usize) -> Result<usize> {
        let offset = self.layout.payload_offset as usize
            + self.layout.global_type_table_offset as usize
            + type_index * self.type_entry_size();
        require_range(
            &self.global_data,
            offset,
            self.type_entry_size(),
            "global type table",
        )?;
        Ok(offset)
    }

    pub(crate) fn method_entry_offset(&self, method_index: usize) -> Result<usize> {
        let offset = self.layout.payload_offset as usize
            + self.layout.global_method_table_offset as usize
            + method_index * self.method_entry_size();
        require_range(
            &self.global_data,
            offset,
            self.method_entry_size(),
            "global method table",
        )?;
        Ok(offset)
    }

    pub(crate) fn type_entry_size(&self) -> usize {
        TYPE_ENTRY_SIZE
    }

    pub(crate) fn method_entry_size(&self) -> usize {
        METHOD_ENTRY_SIZE
    }

}
