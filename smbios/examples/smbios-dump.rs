use smbios::error::Error;
use smbios::*;
use std::io::Write;

macro_rules! write_header {
    ($dst: expr, $table: ident) => {
        write!(
            $dst,
            "Handle 0x{:04X}, DMI type {}, {} bytes\n",
            $table.handle(),
            $table.table_ty(),
            $table.length()
        )?;
    };
}

macro_rules! write_title {
    ($dst: expr, $value: expr) => {
        write!($dst, "{}\n", $value)?;
    };
}

macro_rules! write_kv {
    ($dst: expr, $key: tt, $value: expr $(, $values: expr)*) => {
        if let Some(v) = $value {
            write!($dst, "\t{}: {}", $key, v)?;
            $(
                write!($dst, "{}", $values)?;
            )*
            write!($dst, "\n")?;
        }
    };
}

macro_rules! write_format_kv {
    ($dst: expr, $key: tt, $format: literal, $value: expr $(, $values: expr)*) => {
        if let Some(v) = $value {
            write!($dst, "\t{}: {}", $key, format!($format, v))?;
            $(
                write!($dst, "{}", $values)?;
            )*
            write!($dst, "\n")?;
        }
    };
}

macro_rules! write_iter {
    ($dst: expr, $key: tt, $value: expr) => {
        if let Some(iter) = $value {
            if !$key.is_empty() {
                write!($dst, "\t{}:\n", $key)?;
            }

            for i in iter {
                write_item!($dst, i);
            }
        }
    };
}

macro_rules! write_format_iter {
    ($dst: expr, $key: tt, $format: literal, $value: expr) => {
        if let Some(iter) = $value {
            if !$key.is_empty() {
                write!($dst, "\t{}:\n", $key)?;
            }

            for i in iter {
                write_format_item!($dst, $format, i);
            }
        }
    };
}

macro_rules! write_item {
    ($dst: expr, $($value: expr),+) => {
        write!($dst, "\t\t")?;
        $(
            write!($dst, "{}", $value)?;
        )*
        write!($dst, "\n")?;
    };
}

macro_rules! write_format_item {
    ($dst: expr, $format: literal, $($value: expr),+) => {
        write!($dst, "\t\t")?;
        $(
            write!($dst, $format, $value)?;
        )*
        write!($dst, "\n")?;
    };
}

fn main() -> Result<(), Error> {
    let smbios = smbios::get_smbios()?;

    let mut data = smbios.smbios_table_data.clone();
    while !data.is_empty() {
        let table = RawSmbiosTable::from(&mut data);
        match table.table_ty {
            0 => dump_type0(&Bios::from_raw_table(&table), &mut std::io::stdout()).unwrap(),
            1 => dump_type1(
                &System::from_raw_table(&table),
                &mut std::io::stdout(),
                &smbios,
            )
            .unwrap(),
            2 => dump_type2(&BaseBoard::from_raw_table(&table), &mut std::io::stdout()).unwrap(),
            3 => dump_type3(&Chassis::from_raw_table(&table), &mut std::io::stdout()).unwrap(),
            4 => dump_type4(
                &Processor::from_raw_table(&table),
                &mut std::io::stdout(),
                &smbios,
            )
            .unwrap(),
            5 => dump_type5(
                &MemoryController::from_raw_table(&table),
                &mut std::io::stdout(),
            )
            .unwrap(),
            6 => dump_type6(
                &MemoryModule::from_raw_table(&table),
                &mut std::io::stdout(),
            )
            .unwrap(),
            7 => dump_type7(&Cache::from_raw_table(&table), &mut std::io::stdout()).unwrap(),
            8 => dump_type8(
                &PortConnector::from_raw_table(&table),
                &mut std::io::stdout(),
            )
            .unwrap(),
            9 => dump_type9(&SystemSlots::from_raw_table(&table), &mut std::io::stdout()).unwrap(),
            10 => dump_type10(
                &OnBoardDevices::from_raw_table(&table),
                &mut std::io::stdout(),
            )
            .unwrap(),
            11 => dump_type11(
                &OemStrings::from_raw_table(&table),
                &mut std::io::stdout(),
                &table,
            )
            .unwrap(),
            12 => dump_type12(
                &SystemConfigurationOptions::from_raw_table(&table),
                &mut std::io::stdout(),
                &table,
            )
            .unwrap(),
            13 => dump_type13(
                &BiosLanguage::from_raw_table(&table),
                &mut std::io::stdout(),
                &table,
            )
            .unwrap(),
            14 => dump_type14(
                &GroupAssociations::from_raw_table(&table),
                &mut std::io::stdout(),
            )
            .unwrap(),
            15 => dump_type15(
                &SystemEventLog::from_raw_table(&table),
                &mut std::io::stdout(),
            )
            .unwrap(),
            16 => dump_type16(
                &PhysicalMemoryArray::from_raw_table(&table),
                &mut std::io::stdout(),
            )
            .unwrap(),
            17 => dump_type17(
                &MemoryDevice::from_raw_table(&table),
                &mut std::io::stdout(),
            )
            .unwrap(),
            18 => dump_type18(
                &B32MemoryError::from_raw_table(&table),
                &mut std::io::stdout(),
            )
            .unwrap(),
            19 => dump_type19(
                &MemoryArrayMappedAddress::from_raw_table(&table),
                &mut std::io::stdout(),
            )
            .unwrap(),
            20 => dump_type20(
                &MemoryDeviceMappedAddress::from_raw_table(&table),
                &mut std::io::stdout(),
            )
            .unwrap(),
            21 => dump_type21(
                &BuiltinPointingDevice::from_raw_table(&table),
                &mut std::io::stdout(),
            )
            .unwrap(),
            22 => dump_type22(
                &PortableBattery::from_raw_table(&table),
                &mut std::io::stdout(),
            )
            .unwrap(),
            23 => {
                dump_type23(&SystemReset::from_raw_table(&table), &mut std::io::stdout()).unwrap()
            }
            24 => dump_type24(
                &HardwareSecurity::from_raw_table(&table),
                &mut std::io::stdout(),
            )
            .unwrap(),
            25 => dump_type25(
                &SystemPowerControls::from_raw_table(&table),
                &mut std::io::stdout(),
            )
            .unwrap(),
            26 => dump_type26(
                &VoltageProbe::from_raw_table(&table),
                &mut std::io::stdout(),
            )
            .unwrap(),
            27 => dump_type27(
                &CoolingDevice::from_raw_table(&table),
                &mut std::io::stdout(),
            )
            .unwrap(),
            28 => dump_type28(
                &TemperatureProbe::from_raw_table(&table),
                &mut std::io::stdout(),
            )
            .unwrap(),
            29 => dump_type29(
                &ElectricalCurrentProbe::from_raw_table(&table),
                &mut std::io::stdout(),
            )
            .unwrap(),
            30 => dump_type30(
                &OutOfBandRemoteAccess::from_raw_table(&table),
                &mut std::io::stdout(),
            )
            .unwrap(),
            32 => dump_type32(&SystemBoot::from_raw_table(&table), &mut std::io::stdout()).unwrap(),
            33 => dump_type33(
                &B64MemoryError::from_raw_table(&table),
                &mut std::io::stdout(),
            )
            .unwrap(),
            34 => dump_type34(
                &ManagementDevice::from_raw_table(&table),
                &mut std::io::stdout(),
            )
            .unwrap(),
            35 => dump_type35(
                &ManagementDeviceComponent::from_raw_table(&table),
                &mut std::io::stdout(),
            )
            .unwrap(),
            36 => dump_type36(
                &ManagementDeviceThresholdData::from_raw_table(&table),
                &mut std::io::stdout(),
            )
            .unwrap(),
            37 => dump_type37(
                &MemoryChannel::from_raw_table(&table),
                &mut std::io::stdout(),
            )
            .unwrap(),
            38 => dump_type38(&IpmiDevice::from_raw_table(&table), &mut std::io::stdout()).unwrap(),
            39 => dump_type39(
                &SystemPowerSupply::from_raw_table(&table),
                &mut std::io::stdout(),
            )
            .unwrap(),
            40 => dump_type40(&Additional::from_raw_table(&table), &mut std::io::stdout()).unwrap(),
            41 => dump_type41(
                &OnboardDevicesExtended::from_raw_table(&table),
                &mut std::io::stdout(),
            )
            .unwrap(),
            42 => dump_type42(
                &ManagementControllerHostInterface::from_raw_table(&table),
                &mut std::io::stdout(),
            )
            .unwrap(),
            43 => dump_type43(&TpmDevice::from_raw_table(&table), &mut std::io::stdout()).unwrap(),
            44 => dump_type44(
                &ProcessorAdditional::from_raw_table(&table),
                &mut std::io::stdout(),
            )
            .unwrap(),
            45 => dump_type45(
                &FirmwareInventory::from_raw_table(&table),
                &mut std::io::stdout(),
            )
            .unwrap(),
            46 => dump_type46(
                &StringProperty::from_raw_table(&table),
                &mut std::io::stdout(),
            )
            .unwrap(),
            126 => {
                let mut w = std::io::stdout();
                let t = Inactive::from_raw_table(&table);
                write_header!(w, t);
                write_title!(w, get_table_name_by_id(126).unwrap());
            }
            127 => {
                let mut w = std::io::stdout();
                let t = EnfOfTable::from_raw_table(&table);
                write_header!(w, t);
                write_title!(w, get_table_name_by_id(127).unwrap());
            }
            _ => dump_raw(&table, &mut std::io::stdout()).unwrap(),
        }

        println!();
    }

    Ok(())
}

fn dump_raw(table: &RawSmbiosTable, writer: &mut impl Write) -> std::io::Result<()> {
    writeln!(
        writer,
        "Handle 0x{:04X}, DMI type {}, {} bytes",
        table.handle, table.table_ty, table.length
    )?;

    // Byte Array
    writeln!(writer, "\tHeader and Data:")?;
    let mut body = vec![table.table_ty, table.length];
    body.extend_from_slice(&table.handle.to_le_bytes());
    body.extend_from_slice(&table.body);
    write_bytearray(writer, &body)?;

    if !table.tailer.is_empty() {
        writeln!(writer, "\tStrings:")?;
        for bytes in &table.tailer {
            // Byte Array
            write_bytearray(writer, bytes)?;

            // String
            if let Ok(s) = String::from_utf8(bytes.to_vec()) {
                writeln!(writer, "\t\t{}", s)?;
            }
        }
    }

    Ok(())
}

fn dump_type0(table: &Bios, writer: &mut impl Write) -> std::io::Result<()> {
    write_header!(writer, table);
    write_title!(writer, get_table_name_by_id(0).unwrap());
    write_kv!(writer, "Vendor", table.vendor());
    write_kv!(writer, "Version", table.bios_version());
    write_kv!(writer, "Release Date", table.bios_release_date());
    write_format_kv!(writer, "Address", "0x{:04X}", table.bios_starting_address());
    write_kv!(writer, "Runtime Size", table.runtime_size_kb(), "kB");
    write_kv!(writer, "ROM Size", table.bios_rom_size_ex(), "kB");
    write_iter!(writer, "Charracteristics", table.bios_characteristics_str());
    write_iter!(writer, "", table.bios_characteristics_ex_str());
    write_kv!(writer, "BIOS Revisione", table.system_bios_release());
    write_kv!(
        writer,
        "Firmware Revisione",
        table.embedded_ctrl_firmware_release()
    );
    Ok(())
}

fn dump_type1(
    table: &System,
    writer: &mut impl Write,
    smbios: &RawSmbiosData,
) -> std::io::Result<()> {
    write_header!(writer, table);
    write_title!(writer, get_table_name_by_id(1).unwrap());
    write_kv!(writer, "Manufacturer", table.manufacturer());
    write_kv!(writer, "Product Name", table.product_name());
    write_kv!(writer, "Version", table.version());
    write_kv!(writer, "Serial Number", table.serial_number());
    write_kv!(writer, "UUID", table.get_uuid(smbios));
    write_kv!(writer, "Wake-up Type", table.wakeup_ty_str());
    write_kv!(writer, "SKU Number", table.sku_number());
    write_kv!(writer, "Family", table.family());
    Ok(())
}

fn dump_type2(table: &BaseBoard, writer: &mut impl Write) -> std::io::Result<()> {
    write_header!(writer, table);
    write_title!(writer, get_table_name_by_id(2).unwrap());
    write_kv!(writer, "Manufacturer", table.manufacturer());
    write_kv!(writer, "Product Name", table.product());
    write_kv!(writer, "Version", table.version());
    write_kv!(writer, "Serial Number", table.serial_number());
    write_kv!(writer, "Asset Tag", table.asset_tag());
    write_iter!(writer, "Features", table.feature_flags_str());
    write_kv!(writer, "Location In Chassis", table.location());
    write_kv!(writer, "Chassis Handle", table.chassis_handle());
    write_kv!(writer, "Type", table.board_ty_str());
    Ok(())
}

fn dump_type3(table: &Chassis, writer: &mut impl Write) -> std::io::Result<()> {
    write_header!(writer, table);
    write_title!(writer, get_table_name_by_id(3).unwrap());
    write_kv!(writer, "Manufacturer", table.manufacturer());
    write_kv!(writer, "Type", table.ty_str());
    write_kv!(
        writer,
        "Lock",
        table
            .ty_lock()
            .map(|l| if l { "Present" } else { "Not Present" })
    );
    write_kv!(writer, "Version", table.version());
    write_kv!(writer, "Serial Number", table.serial_number());
    write_kv!(writer, "Assert Tag", table.asset_tag_number());
    write_kv!(writer, "Boot-up State", table.boot_up_state_str());
    write_kv!(writer, "Power Supply State", table.power_supply_state_str());
    write_kv!(writer, "Thermal State", table.thermal_state_str());
    write_kv!(writer, "Security Status", table.security_status_str());
    write_format_kv!(writer, "OEM Information", "0x{:08X}", table.oem_defined());
    write_kv!(writer, "Height", table.height(), " U");
    write_kv!(writer, "Number of Power Cords", table.num_power_cords());
    if let Some(contained_elements) = table.contained_elements() {
        let count = table.contained_element_count().unwrap();
        let len = table.contained_element_record_length().unwrap();
        write_kv!(writer, "Contained Elements", Some(count));
        for i in 0..count {
            let idx = (i * len) as usize;
            let ty = contained_elements[idx];
            let ty_str = if (ty & 0x80) > 0 {
                get_table_name_by_id(ty & 0x7F).unwrap()
            } else {
                get_board_ty_str(ty & 0x7F)
            };
            let min = contained_elements[idx + 1];
            let max = contained_elements[idx + 2];
            write_item!(writer, format!("{} ({}-{})", ty_str, min, max));
        }
    }
    write_kv!(writer, "SKU Number", table.sku_number());
    Ok(())
}

fn dump_type4(
    table: &Processor,
    writer: &mut impl Write,
    smbios: &RawSmbiosData,
) -> std::io::Result<()> {
    write_header!(writer, table);
    write_title!(writer, get_table_name_by_id(4).unwrap());
    write_kv!(writer, "Socket Designation", table.socket_designation());
    write_kv!(writer, "Type", table.processor_ty_str());
    write_kv!(writer, "Family", table.processor_family_str());
    write_kv!(writer, "Manufacturer", table.processor_manufacturer());
    // TODO: processor_id
    write_kv!(writer, "Version", table.processor_version());
    write_kv!(writer, "Voltage", table.voltage_str());
    write_kv!(writer, "External Clock", table.external_clock(), " MHz");
    write_kv!(writer, "Max Speed", table.max_speed(), " MHz");
    write_kv!(writer, "Current Speed", table.current_speed(), " MHz");
    write_kv!(writer, "Status", table.status_str());
    write_kv!(writer, "Upgrade", table.processor_upgrade_str());
    write_cache(
        writer,
        "L1 Cache Handle",
        "L1",
        table.l1_cache_handle(),
        smbios,
    )?;
    write_cache(
        writer,
        "L2 Cache Handle",
        "L2",
        table.l2_cache_handle(),
        smbios,
    )?;
    write_cache(
        writer,
        "L3 Cache Handle",
        "L3",
        table.l3_cache_handle(),
        smbios,
    )?;
    write_kv!(writer, "Serial Number", table.serial_number());
    write_kv!(writer, "Asset Tag", table.asset_tag());
    write_kv!(writer, "Part Number", table.part_number());
    write_kv!(writer, "Core Count", table.core_count_mixed());
    write_kv!(writer, "Core Enabled", table.core_enabled_mixed());
    write_kv!(writer, "Thread Count", table.thread_count_mixed());
    write_iter!(
        writer,
        "Charactaristics",
        table.processor_characteristics_str()
    );
    Ok(())
}

fn dump_type5(table: &MemoryController, writer: &mut impl Write) -> std::io::Result<()> {
    write_header!(writer, table);
    write_title!(writer, get_table_name_by_id(5).unwrap());
    write_kv!(
        writer,
        "Error Detectng Method",
        table.error_detecting_method_str()
    );
    write_iter!(
        writer,
        "Error Correcting Capabilities",
        table.error_correcting_capability_str()
    );
    write_kv!(
        writer,
        "Supported Interleave",
        table.supported_interleave_str()
    );
    write_kv!(writer, "Current Interleave", table.current_interleave_str());
    write_kv!(
        writer,
        "Maximum Memory Module Size",
        table.maximum_memory_module_size_mb(),
        " MB"
    );
    write_kv!(
        writer,
        "Maximum Total Module Size",
        table.maximum_memory_total_size_mb(),
        " MB"
    );
    write_kv!(writer, "Supported Memory Speeds", table.supported_speeds());
    write_iter!(
        writer,
        "Supported Memory Types",
        table.supported_memory_tys_str()
    );
    write_kv!(
        writer,
        "Supported Memory Types",
        table.supported_memory_tys()
    );
    write_kv!(
        writer,
        "Memory Module Voltage",
        table.memory_module_voltage()
    );
    write_kv!(
        writer,
        "Associated Memory Slots",
        table.num_associated_memory_slots()
    );
    write_format_iter!(
        writer,
        "",
        "0x{:04X}",
        table.memory_moddule_configuration_handles()
    );
    write_iter!(
        writer,
        "Enabled Error Correcting Capabilities",
        table.enabled_error_correcting_capabilities_str()
    );
    Ok(())
}

fn dump_type6(table: &MemoryModule, writer: &mut impl Write) -> std::io::Result<()> {
    write_header!(writer, table);
    write_title!(writer, get_table_name_by_id(6).unwrap());
    write_kv!(writer, "Socket Designation", table.socket_designation());
    write_kv!(
        writer,
        "Bank Connections",
        memory_module_connection(table.bank_connections())
    );
    write_kv!(writer, "Current Speed", table.current_speed(), " ns");
    write_iter!(writer, "Type", table.current_memory_ty_str());
    write_kv!(
        writer,
        "Installed Size",
        memory_module_size(table.installed_size())
    );
    write_kv!(
        writer,
        "Enabled Size",
        memory_module_size(table.enabled_size())
    );
    write_kv!(writer, "Error Status", table.error_status());
    Ok(())
}

fn dump_type7(table: &Cache, writer: &mut impl Write) -> std::io::Result<()> {
    write_header!(writer, table);
    write_title!(writer, get_table_name_by_id(7).unwrap());
    write_kv!(writer, "Socket Designation", table.socket_designation());
    write_kv!(writer, "Configuration", table.enabled());
    write_kv!(writer, "Configuration", table.cache_socketed());
    write_kv!(writer, "Configuration", table.cache_level());
    write_kv!(writer, "Operational Mode", table.operational_mode());
    write_kv!(writer, "Location", table.location());
    if table.installed_cache_size2().is_some() {
        write_kv!(writer, "Installed Size", table.installed_cache_size2());
    } else {
        write_kv!(writer, "Installed Size", table.installed_size());
    }
    if table.maximum_cache_size2().is_some() {
        write_kv!(writer, "Maximum Size", table.maximum_cache_size2());
    } else {
        write_kv!(writer, "Maximum Size", table.maximum_cache_size());
    }
    write_iter!(writer, "Supprted SRAM Types", table.supported_sram_ty_str());
    write_iter!(writer, "Installed SRAM Type", table.current_sram_ty_str());
    write_kv!(writer, "Speed", table.cache_speed(), " ns");
    write_kv!(
        writer,
        "Error Correction Type",
        table.error_correction_ty_str()
    );
    write_kv!(writer, "System Type", table.system_cache_ty_str());
    write_kv!(writer, "Associativity", table.associativity_str());
    Ok(())
}

fn dump_type8(table: &PortConnector, writer: &mut impl Write) -> std::io::Result<()> {
    write_header!(writer, table);
    write_title!(writer, get_table_name_by_id(8).unwrap());
    write_kv!(
        writer,
        "Internal Reference Designator",
        table.internal_reference_designator()
    );
    write_kv!(
        writer,
        "Internal Connector Type",
        table.internal_connector_ty_str()
    );
    write_kv!(
        writer,
        "External Reference Designator",
        table.external_reference_designator()
    );
    write_kv!(
        writer,
        "External Connector Type",
        table.external_connector_ty_str()
    );
    write_kv!(writer, "Port Type", table.port_ty_str());
    Ok(())
}

fn dump_type9(table: &SystemSlots, writer: &mut impl Write) -> std::io::Result<()> {
    write_header!(writer, table);
    write_title!(writer, get_table_name_by_id(9).unwrap());
    write_kv!(writer, "Designation", table.slot_designation());
    if let (Some(_), Some(_)) = (table.slot_ty(), table.slot_data_bus_width()) {
        let t = format!(
            "{} {}",
            table.slot_ty_str().unwrap(),
            table.slot_data_bus_width_str().unwrap()
        );
        write_kv!(writer, "Type", Some(t));
    } else if table.slot_ty().is_some() {
        write_kv!(writer, "Type", table.slot_ty_str());
    }
    write_kv!(writer, "Current Usage", table.current_usage_str());
    write_kv!(writer, "Length", table.slot_length_str());
    write_kv!(writer, "ID", table.slot_id());
    write_iter!(writer, "Characteristics", table.slot_characteristics1_str());
    write_iter!(writer, "", table.slot_characteristics2_str());
    write_bus_address(
        writer,
        "Bus Address",
        table.segment_group_number(),
        table.bus_number(),
        table.device_function_number(),
    )?;
    write_kv!(writer, "Data Bus Width", table.data_bus_width());
    write_kv!(writer, "Peer Devices", table.peer_grouping_count());
    if let Some(peers) = table.peer_groups() {
        for (i, peer) in peers.iter().enumerate() {
            let key = format!("Peer Device {}", i);
            write_bus_address(
                writer,
                &key,
                (*peer).segment_group_number(),
                (*peer).bus_number(),
                (*peer).device_function_number(),
            )?;
        }
    }
    write_kv!(writer, "PCI Express Generation", table.slot_information());
    write_kv!(
        writer,
        "Slot Physical Width",
        table.slot_physical_width_str()
    );
    write_format_kv!(
        writer,
        "Pitch",
        "{:.2}",
        table.slot_pitch().map(|p| p / 100),
        " mm"
    );
    write_kv!(writer, "Height", table.slot_height_str());
    Ok(())
}

fn dump_type10(table: &OnBoardDevices, writer: &mut impl Write) -> std::io::Result<()> {
    write_header!(writer, table);
    //write_title!(writer, get_table_name_by_id(10).unwrap());
    if let Some(devices) = table.get_device() {
        for (i, (enabled, device, desc)) in devices.iter().enumerate() {
            write_title!(writer, format!("On Board Device {} Information", i + 1));
            write_kv!(writer, "Type", Some(device));
            write_kv!(
                writer,
                "Status",
                Some(if *enabled { "Enabled" } else { "Disabled" })
            );
            write_kv!(writer, "Description", Some(desc));
        }
    }
    Ok(())
}

fn dump_type11(
    table: &OemStrings,
    writer: &mut impl Write,
    raw: &RawSmbiosTable,
) -> std::io::Result<()> {
    write_header!(writer, table);
    write_title!(writer, get_table_name_by_id(11).unwrap());
    if let Some(count) = table.count() {
        for i in 1..=count {
            let key = format!("String {}", i);
            write_kv!(writer, key, raw.get_string_by_index(i));
        }
    }
    Ok(())
}

fn dump_type12(
    table: &SystemConfigurationOptions,
    writer: &mut impl Write,
    raw: &RawSmbiosTable,
) -> std::io::Result<()> {
    write_header!(writer, table);
    write_title!(writer, get_table_name_by_id(12).unwrap());
    if let Some(count) = table.count() {
        for i in 1..=count {
            let key = format!("Option {}", i);
            write_kv!(writer, key, raw.get_string_by_index(i));
        }
    }
    Ok(())
}

fn dump_type13(
    table: &BiosLanguage,
    writer: &mut impl Write,
    raw: &RawSmbiosTable,
) -> std::io::Result<()> {
    write_header!(writer, table);
    write_title!(writer, get_table_name_by_id(13).unwrap());
    write_kv!(
        writer,
        "Language Description Format",
        table.get_language_format()
    );
    write_kv!(
        writer,
        "Installable Languages",
        table.installable_languages()
    );
    if let Some(n) = table.installable_languages() {
        for i in 1..=n {
            if let Some(lang) = raw.get_string_by_index(i) {
                write_item!(writer, lang);
            }
        }
    }
    write_kv!(
        writer,
        "Currently Installed Language",
        table
            .current_language()
            .and_then(|i| raw.get_string_by_index(i))
    );
    Ok(())
}

fn dump_type14(table: &GroupAssociations, writer: &mut impl Write) -> std::io::Result<()> {
    write_header!(writer, table);
    write_title!(writer, get_table_name_by_id(14).unwrap());
    write_kv!(writer, "Name", table.group_name());
    write_kv!(writer, "Items", table.items().map(|i| i.len()));
    if let Some(items) = table.items() {
        for item in items {
            let value = format!(
                "{:04X} ({})",
                item.item_handle().unwrap(),
                get_table_name_by_id(item.item_ty().unwrap()).unwrap()
            );
            write_item!(writer, value);
        }
    }
    Ok(())
}

fn dump_type15(table: &SystemEventLog, writer: &mut impl Write) -> std::io::Result<()> {
    write_header!(writer, table);
    write_title!(writer, get_table_name_by_id(15).unwrap());
    // TODO:
    Ok(())
}

fn dump_type16(table: &PhysicalMemoryArray, writer: &mut impl Write) -> std::io::Result<()> {
    write_header!(writer, table);
    write_title!(writer, get_table_name_by_id(16).unwrap());
    write_kv!(writer, "Location", table.location_str());
    write_kv!(writer, "Use", table.array_use_str());
    write_kv!(
        writer,
        "Error Correction Type",
        table.memory_error_correction_str()
    );
    if table
        .maximum_capacity()
        .map(|c| c == 0x8000_0000)
        .unwrap_or_default()
    {
        write_kv!(writer, "Maxumum Capacity", table.ex_maximum_capacity());
    } else {
        write_kv!(writer, "Maximum Capacity", table.maximum_capacity());
    }
    write_format_kv!(
        writer,
        "Error Information Handle",
        "0x{:04X}",
        table.memory_error_information_handle()
    );
    write_kv!(writer, "Number Of Devices", table.num_memory_devices());
    Ok(())
}

fn dump_type17(table: &MemoryDevice, writer: &mut impl Write) -> std::io::Result<()> {
    write_header!(writer, table);
    write_title!(writer, get_table_name_by_id(17).unwrap());
    write_format_kv!(
        writer,
        "Array Handle",
        "0x{:04X}",
        table.physical_memory_array_handle()
    );
    write_format_kv!(
        writer,
        "Error Information Handle",
        "0x{:04X}",
        table.memory_error_information_handle()
    );
    write_kv!(writer, "Total Width", table.total_width(), " bits");
    write_kv!(writer, "Data Width", table.data_width(), " bits");
    if table.extended_size().is_some() && table.size().map(|s| s == 0x7FFF).unwrap_or_default() {
        write_kv!(writer, "Size", table.extended_size());
    } else {
        write_kv!(writer, "Size", table.size());
    }
    write_kv!(writer, "Form Factor", table.form_factor_str());
    write_kv!(writer, "Set", table.device_set());
    write_kv!(writer, "Locator", table.device_locator());
    write_kv!(writer, "Bank Locator", table.bank_locator());
    write_kv!(writer, "Type", table.memory_ty_str());
    write_iter!(writer, "Type Detail", table.ty_detail_str());
    if table.extended_speed().is_some() {
        write_kv!(writer, "Speed", table.extended_speed(), " MT/s");
    } else {
        write_kv!(writer, "Speed", table.speed(), " MT/s");
    }
    write_kv!(writer, "Manufacturer", table.manufacturer());
    write_kv!(writer, "Serial Number", table.serial_number());
    write_kv!(writer, "Asset Tag", table.asset_tag());
    write_kv!(writer, "Part Number", table.part_number());
    write_kv!(writer, "Rank", table.attributes().map(|a| a & 0x0F));
    if table.extended_configured_memory_speed().is_some() {
        write_kv!(
            writer,
            "Configured Memory Speed",
            table.extended_configured_memory_speed(),
            " MT/s"
        );
    } else {
        write_kv!(
            writer,
            "Configured Memory Speed",
            table.configured_memory_speed(),
            " MT/s"
        );
    }
    write_kv!(writer, "Minimum Voltage", table.minimum_voltage(), " V");
    write_kv!(writer, "Maximum Voltage", table.maximum_voltage(), " V");
    write_kv!(
        writer,
        "Configured Voltage",
        table.configured_voltage(),
        " V"
    );
    write_kv!(writer, "Memory Technology", table.memory_technology_str());
    write_iter!(
        writer,
        "Memory Operating Mode Capability",
        table.memory_operating_mode_capability_str()
    );
    write_kv!(writer, "Firmware Version", table.firmware_version());
    // TODO:
    write_format_kv!(
        writer,
        "Module Product ID",
        "0x{:04X}",
        table.module_product_id()
    );
    // TODO:
    write_format_kv!(
        writer,
        "Module Subsustem Controller Product ID",
        "0x{:04X}",
        table.memory_subsystem_ctrl_product_id()
    );
    write_kv!(writer, "Non-Volatile Size", table.volatile_size());
    write_kv!(writer, "Volatile Size", table.volatile_size());
    write_kv!(writer, "Cache Size", table.cache_size());
    write_kv!(writer, "Logical Size", table.logical_size());
    Ok(())
}

fn dump_type18(table: &B32MemoryError, writer: &mut impl Write) -> std::io::Result<()> {
    write_header!(writer, table);
    write_title!(writer, get_table_name_by_id(18).unwrap());
    write_kv!(writer, "Type", table.error_ty_str());
    write_kv!(writer, "Granularity", table.error_granularity_str());
    write_kv!(writer, "Operation", table.error_operation_str());
    write_format_kv!(
        writer,
        "Vendor Syndrome",
        "0x{:08X}",
        table.vendor_syndrome()
    );
    write_format_kv!(
        writer,
        "Memory Array Address",
        "0x{:08X}",
        table.memory_array_error_address()
    );
    write_format_kv!(
        writer,
        "Device Address",
        "0x{:08X}",
        table.device_error_address()
    );
    write_format_kv!(writer, "Resolution", "0x{:08X}", table.error_resolution());
    Ok(())
}

fn dump_type19(table: &MemoryArrayMappedAddress, writer: &mut impl Write) -> std::io::Result<()> {
    write_header!(writer, table);
    write_title!(writer, get_table_name_by_id(19).unwrap());
    if table.ex_starting_address().is_some()
        && table
            .starting_address()
            .map(|s| s == 0xFFFF_FFFF)
            .unwrap_or_default()
    {
        write_format_kv!(
            writer,
            "Starting Address",
            "0x{:016X}",
            table.ex_starting_address()
        );
        write_format_kv!(
            writer,
            "Ending Address",
            "0x{:016X}",
            table.ex_ending_address()
        );
    } else {
        // TODO:
    }
    write_format_kv!(
        writer,
        "Physical Array Handle",
        "0x{:04X}",
        table.memory_array_handle()
    );
    write_kv!(writer, "Partition Width", table.partition_width());
    Ok(())
}

fn dump_type20(table: &MemoryDeviceMappedAddress, writer: &mut impl Write) -> std::io::Result<()> {
    write_header!(writer, table);
    write_title!(writer, get_table_name_by_id(20).unwrap());
    if table.ex_starting_address().is_some()
        && table
            .starting_address()
            .map(|s| s == 0xFFFF_FFFF)
            .unwrap_or_default()
    {
        write_format_kv!(
            writer,
            "Starting Address",
            "0x{:016X}",
            table.ex_starting_address()
        );
        write_format_kv!(
            writer,
            "Ending Address",
            "0x{:016X}",
            table.ex_ending_address()
        );
    } else {
        // TODO:
    }
    write_format_kv!(
        writer,
        "Physical Device Handle",
        "0x{:04X}",
        table.memory_device_handle()
    );
    write_format_kv!(
        writer,
        "Memory Array Mapped Address Handle",
        "0x{:04X}",
        table.memory_array_mapped_address_handle()
    );
    write_kv!(
        writer,
        "Partition Row Position",
        table.partition_row_position()
    );
    write_kv!(writer, "Interleave Position", table.interleave_position());
    write_kv!(
        writer,
        "Interleaved Data Depth",
        table.interleaved_data_depth()
    );
    Ok(())
}

fn dump_type21(table: &BuiltinPointingDevice, writer: &mut impl Write) -> std::io::Result<()> {
    write_header!(writer, table);
    write_title!(writer, get_table_name_by_id(21).unwrap());
    // TODO:
    Ok(())
}

fn dump_type22(table: &PortableBattery, writer: &mut impl Write) -> std::io::Result<()> {
    write_header!(writer, table);
    write_title!(writer, get_table_name_by_id(22).unwrap());
    // TODO:
    Ok(())
}

fn dump_type23(table: &SystemReset, writer: &mut impl Write) -> std::io::Result<()> {
    write_header!(writer, table);
    write_title!(writer, get_table_name_by_id(23).unwrap());
    write_kv!(
        writer,
        "Status",
        table
            .enabled()
            .map(|e| if e { "Enabled" } else { "Disabled" })
    );
    write_kv!(
        writer,
        "Watchdog Time",
        table
            .watchdog_timer()
            .map(|w| if w { "Present" } else { "Not Present" })
    );
    if table.watchdog_timer().unwrap_or_default() {
        write_kv!(writer, "Boot Option", table.boot_option());
        write_kv!(writer, "Boot Option On Limit", table.boot_option_on_limit());
        write_kv!(writer, "Reset Count", table.reset_count());
        write_kv!(writer, "Reset Limit", table.reset_limit());
        write_kv!(writer, "Timer Interval", table.timer_interval());
        write_kv!(writer, "Timeout", table.timeout());
    }
    Ok(())
}

fn dump_type24(table: &HardwareSecurity, writer: &mut impl Write) -> std::io::Result<()> {
    write_header!(writer, table);
    write_title!(writer, get_table_name_by_id(24).unwrap());
    // TODO:
    Ok(())
}

fn dump_type25(table: &SystemPowerControls, writer: &mut impl Write) -> std::io::Result<()> {
    write_header!(writer, table);
    write_title!(writer, get_table_name_by_id(25).unwrap());
    // TODO:
    Ok(())
}

fn dump_type26(table: &VoltageProbe, writer: &mut impl Write) -> std::io::Result<()> {
    write_header!(writer, table);
    write_title!(writer, get_table_name_by_id(26).unwrap());
    write_kv!(writer, "Description", table.description());
    write_kv!(writer, "Location", table.location_str());
    write_kv!(writer, "Status", table.status_str());
    write_format_kv!(
        writer,
        "Maximum Value",
        "{:.3} V",
        table.maximum_value().map(|v| v as f32 / 1000f32)
    );
    write_format_kv!(
        writer,
        "Minimum Value",
        "{:.3} V",
        table.minimum_value().map(|v| v as f32 / 1000f32)
    );
    write_format_kv!(
        writer,
        "Resolution",
        "{:.1} mV",
        table.resolution().map(|v| v as f32 / 10f32)
    );
    write_format_kv!(
        writer,
        "Torelance",
        "{:.3} V",
        table.tolerance().map(|v| v as f32 / 1000f32)
    );
    write_format_kv!(
        writer,
        "Accuracy",
        "{:.2}%",
        table.accuracy().map(|v| v as f32 / 100f32)
    );
    write_format_kv!(
        writer,
        "OEM-specific Information",
        "{:08X}",
        table.oem_defined()
    );
    write_format_kv!(
        writer,
        "Nominal Value",
        "{:.3} V",
        table.nominal_value().map(|v| v as f32 / 1000f32)
    );
    Ok(())
}

fn dump_type27(table: &CoolingDevice, writer: &mut impl Write) -> std::io::Result<()> {
    write_header!(writer, table);
    write_title!(writer, get_table_name_by_id(27).unwrap());
    write_format_kv!(
        writer,
        "Temperature Probe Handle",
        "{:04X}",
        table.temperature_probe_handle()
    );
    write_kv!(writer, "Type", table.device_ty_str());
    write_kv!(writer, "Status", table.status_str());
    write_kv!(writer, "Cooling Unit Group", table.cooling_unit_group());
    write_format_kv!(
        writer,
        "OEM-specific Information",
        "{:08X}",
        table.oem_defined()
    );
    write_kv!(writer, "Nominal Speed", table.nominal_speed(), " rpm");
    write_kv!(writer, "Description", table.description());
    Ok(())
}

fn dump_type28(table: &TemperatureProbe, writer: &mut impl Write) -> std::io::Result<()> {
    write_header!(writer, table);
    write_title!(writer, get_table_name_by_id(28).unwrap());
    write_kv!(writer, "Description", table.description());
    write_kv!(writer, "Location", table.location_str());
    write_kv!(writer, "Status", table.status_str());
    write_format_kv!(
        writer,
        "Maximum Value",
        "{:.1} deg C",
        table.maximum_value().map(|v| v as f32 / 10f32)
    );
    write_format_kv!(
        writer,
        "Minimum Value",
        "{:.1} deg C",
        table.minimum_value().map(|v| v as f32 / 10f32)
    );
    write_format_kv!(
        writer,
        "Resolution",
        "{:.3} deg C",
        table.resolution().map(|v| v as f32 / 1000f32)
    );
    write_format_kv!(
        writer,
        "Tolerance",
        "{:.1} deg C",
        table.tolerance().map(|v| v as f32 / 10f32)
    );
    write_format_kv!(
        writer,
        "Accuracy",
        "{:.2}%",
        table.accuracy().map(|v| v as f32 / 100f32)
    );
    write_format_kv!(
        writer,
        "OEM-specific Information",
        "{:08X}",
        table.oem_defined()
    );
    write_format_kv!(
        writer,
        "Nominal Value",
        "{:.1} deg C",
        table.nominal_value().map(|v| v as f32 / 10f32)
    );
    Ok(())
}

fn dump_type29(table: &ElectricalCurrentProbe, writer: &mut impl Write) -> std::io::Result<()> {
    write_header!(writer, table);
    write_title!(writer, get_table_name_by_id(29).unwrap());
    write_kv!(writer, "Description", table.description());
    write_kv!(writer, "Location", table.location_str());
    write_kv!(writer, "Status", table.status_str());
    write_format_kv!(
        writer,
        "Maximum Value",
        "{:.3} A",
        table.maximum_value().map(|v| v as f32 / 1000f32)
    );
    write_format_kv!(
        writer,
        "Minimum Value",
        "{:.3} A",
        table.minimum_value().map(|v| v as f32 / 1000f32)
    );
    write_format_kv!(
        writer,
        "Resolution",
        "{:.1} mA",
        table.resolution().map(|v| v as f32 / 10f32)
    );
    write_format_kv!(
        writer,
        "Tolerance",
        "{:.3} A",
        table.tolerance().map(|v| v as f32 / 1000f32)
    );
    write_format_kv!(
        writer,
        "Accuracy",
        "{:.2}%",
        table.accuracy().map(|v| v as f32 / 100f32)
    );
    write_format_kv!(
        writer,
        "OEM-specific Information",
        "{:08X}",
        table.oem_defined()
    );
    write_format_kv!(
        writer,
        "Nominal Value",
        "{:.3} A",
        table.nominal_value().map(|v| v as f32 / 1000f32)
    );
    Ok(())
}

fn dump_type30(table: &OutOfBandRemoteAccess, writer: &mut impl Write) -> std::io::Result<()> {
    write_header!(writer, table);
    write_title!(writer, get_table_name_by_id(30).unwrap());
    // TODO:
    Ok(())
}

fn dump_type32(table: &SystemBoot, writer: &mut impl Write) -> std::io::Result<()> {
    write_header!(writer, table);
    write_title!(writer, get_table_name_by_id(32).unwrap());
    write_kv!(writer, "Status", table.boot_status_str());
    Ok(())
}

fn dump_type33(table: &B64MemoryError, writer: &mut impl Write) -> std::io::Result<()> {
    write_header!(writer, table);
    write_title!(writer, get_table_name_by_id(33).unwrap());
    // TODO:
    Ok(())
}

fn dump_type34(table: &ManagementDevice, writer: &mut impl Write) -> std::io::Result<()> {
    write_header!(writer, table);
    write_title!(writer, get_table_name_by_id(34).unwrap());
    write_kv!(writer, "Description", table.description());
    write_kv!(writer, "Type", table.ty_str());
    write_format_kv!(writer, "Address", "0x{:08X}", table.address());
    write_kv!(writer, "Address Type", table.address_ty_str());
    Ok(())
}

fn dump_type35(table: &ManagementDeviceComponent, writer: &mut impl Write) -> std::io::Result<()> {
    write_header!(writer, table);
    write_title!(writer, get_table_name_by_id(35).unwrap());
    write_kv!(writer, "Description", table.description());
    write_format_kv!(
        writer,
        "Management Device Handle",
        "0x{:04X}",
        table.management_device_handle()
    );
    write_format_kv!(
        writer,
        "Component Handle",
        "0x{:04X}",
        table.component_handle()
    );
    write_format_kv!(
        writer,
        "Threshold Handle",
        "0x{:04X}",
        table.threshold_handle()
    );
    Ok(())
}

fn dump_type36(
    table: &ManagementDeviceThresholdData,
    writer: &mut impl Write,
) -> std::io::Result<()> {
    write_header!(writer, table);
    write_title!(writer, get_table_name_by_id(36).unwrap());
    write_kv!(
        writer,
        "Lower Non-critical Threshold",
        table.lower_threshold_non_critical()
    );
    write_kv!(
        writer,
        "Upper Non-critical Threshold",
        table.upper_threshold_non_critical()
    );
    write_kv!(
        writer,
        "Lower Critical Threshold",
        table.lower_threshold_critical()
    );
    write_kv!(
        writer,
        "Upper Critical Threshold",
        table.upper_threshold_critical()
    );
    write_kv!(
        writer,
        "Lower Non-recoverable Threshold",
        table.lower_threshold_non_recoverable()
    );
    write_kv!(
        writer,
        "Upper Non-recoverable Threshold",
        table.upper_threshold_non_recoverable()
    );
    Ok(())
}

fn dump_type37(table: &MemoryChannel, writer: &mut impl Write) -> std::io::Result<()> {
    write_header!(writer, table);
    write_title!(writer, get_table_name_by_id(37).unwrap());
    // TODO:
    Ok(())
}

fn dump_type38(table: &IpmiDevice, writer: &mut impl Write) -> std::io::Result<()> {
    write_header!(writer, table);
    write_title!(writer, get_table_name_by_id(38).unwrap());
    // TODO:
    Ok(())
}

fn dump_type39(table: &SystemPowerSupply, writer: &mut impl Write) -> std::io::Result<()> {
    write_header!(writer, table);
    write_title!(writer, get_table_name_by_id(39).unwrap());
    write_kv!(writer, "Power Unit Group", table.power_unit_group());
    write_kv!(writer, "Location", table.location());
    write_kv!(writer, "Name", table.device_name());
    write_kv!(writer, "Manufacturer", table.manufacturer());
    write_kv!(writer, "Serial Number", table.serial_number());
    write_kv!(writer, "Asset Tag", table.asset_tag_number());
    write_kv!(writer, "Model Part Number", table.model_part_number());
    write_kv!(writer, "Revision", table.revision_level());
    write_format_kv!(
        writer,
        "Max Power Capacity",
        "{} W",
        table.max_power_capacity()
    );
    write_kv!(writer, "Status", table.status_str());
    write_kv!(writer, "Type", table.ty_str());
    write_kv!(
        writer,
        "Input Voltage Range Switching",
        table.range_switching_str()
    );
    write_kv!(
        writer,
        "Plugged",
        table.unplugged().map(|f| if f { "No" } else { "Yes" })
    );
    write_kv!(
        writer,
        "Hot Replaceable",
        table
            .hot_replaceable()
            .map(|f| if f { "Yes" } else { "No" })
    );
    write_format_kv!(
        writer,
        "Input Voltage Probe Handle",
        "0x{:04X}",
        table.input_voltage_probe_handle()
    );
    write_format_kv!(
        writer,
        "Cooling Device Handle",
        "0x{:04X}",
        table.cooling_device_handle()
    );
    write_format_kv!(
        writer,
        "Input Current Probe Handle",
        "0x{:04X}",
        table.input_current_probe_handle()
    );
    Ok(())
}

fn dump_type40(table: &Additional, writer: &mut impl Write) -> std::io::Result<()> {
    write_header!(writer, table);
    write_title!(writer, get_table_name_by_id(40).unwrap());
    // TODO:
    Ok(())
}

fn dump_type41(table: &OnboardDevicesExtended, writer: &mut impl Write) -> std::io::Result<()> {
    write_header!(writer, table);
    write_title!(writer, get_table_name_by_id(41).unwrap());
    write_kv!(
        writer,
        "Reference Designation",
        table.reference_designation()
    );
    write_kv!(writer, "Type", table.device_ty_str());
    write_kv!(
        writer,
        "Status",
        table
            .device_status()
            .map(|s| if s { "Enabled" } else { "Disabled" })
    );
    write_kv!(writer, "Type Instance", table.device_ty_instance());
    write_bus_address(
        writer,
        "Bus Address",
        table.segment_group_number(),
        table.bus_number(),
        table.device_function_number(),
    )?;
    Ok(())
}

fn dump_type42(
    table: &ManagementControllerHostInterface,
    writer: &mut impl Write,
) -> std::io::Result<()> {
    write_header!(writer, table);
    write_title!(writer, get_table_name_by_id(42).unwrap());
    // TODO:
    Ok(())
}

fn dump_type43(table: &TpmDevice, writer: &mut impl Write) -> std::io::Result<()> {
    write_header!(writer, table);
    write_title!(writer, get_table_name_by_id(43).unwrap());
    write_kv!(writer, "Vendor ID", table.vendor_id_str());
    write_kv!(writer, "Specification Version", table.spec_version());
    write_kv!(writer, "Firmware Revision", table.firmware_version());
    write_kv!(writer, "Description", table.description());
    write_iter!(writer, "Characteristics", table.characteristics_str());
    write_format_kv!(
        writer,
        "OEM-specific Information",
        "0x{:08X}",
        table.oem_defined()
    );
    Ok(())
}

fn dump_type44(table: &ProcessorAdditional, writer: &mut impl Write) -> std::io::Result<()> {
    write_header!(writer, table);
    write_title!(writer, get_table_name_by_id(44).unwrap());
    // TODO:
    Ok(())
}

fn dump_type45(table: &FirmwareInventory, writer: &mut impl Write) -> std::io::Result<()> {
    write_header!(writer, table);
    write_title!(writer, get_table_name_by_id(45).unwrap());
    // TODO:
    Ok(())
}

fn dump_type46(table: &StringProperty, writer: &mut impl Write) -> std::io::Result<()> {
    write_header!(writer, table);
    write_title!(writer, get_table_name_by_id(46).unwrap());
    // TODO:
    Ok(())
}

fn memory_module_connection(value: Option<u8>) -> Option<String> {
    value.map(|v| {
        if v == 0xFF {
            "None".to_string()
        } else if (v & 0xF0) == 0xF0 {
            format!("{}", v & 0xF0)
        } else if (v & 0x0F) == 0x0F {
            format!("{}", v >> 4)
        } else {
            format!("{} {}", v >> 4, v & 0x0F)
        }
    })
}

fn memory_module_size(value: Option<u8>) -> Option<String> {
    value.map(|v| {
        let conn = if (v & 0x80) != 0 {
            "(Double-bank Connection)"
        } else {
            "(Single-bank Connection)"
        };

        match v & 0x7F {
            0x7D => format!("Not Determinable {}", conn),
            0x7E => format!("Disabled {}", conn),
            0x7F => "Not Installed".to_string(),
            v => format!("{} MB {}", v, conn),
        }
    })
}

fn write_bus_address(
    writer: &mut impl Write,
    key: &str,
    seg: Option<u16>,
    bus: Option<u8>,
    dev_func: Option<u8>,
) -> std::io::Result<()> {
    if let (Some(seg), Some(bus), Some(dev_func)) = (seg, bus, dev_func) {
        if !(seg == 0xFFFF && bus == 0xFF && dev_func == 0xFF) {
            let slot = format!(
                "{:04x}:{:02x}:{:02x}.{}",
                seg,
                bus,
                dev_func >> 3,
                dev_func & 0x07,
            );
            write_kv!(writer, key, Some(slot));
        }
    }

    Ok(())
}

fn write_cache(
    writer: &mut impl Write,
    key: &str,
    level: &str,
    value: Option<u16>,
    smbios: &RawSmbiosData,
) -> std::io::Result<()> {
    if let Some(value) = value {
        if value == 0xFFFF {
            if smbios.is_later(2, 3) {
                write_kv!(writer, key, Some("Not Provided"));
            } else {
                write_format_kv!(writer, key, "No {} Cache", Some(level));
            }
        } else {
            write_format_kv!(writer, key, "0x{:04X}", Some(value));
        }
    }
    Ok(())
}

fn write_bytearray(writer: &mut impl Write, bytes: &[u8]) -> std::io::Result<()> {
    write!(writer, "\t\t")?;
    for (i, byte) in bytes.iter().enumerate() {
        write!(writer, "{:02X}", byte)?;

        let num = i + 1;
        if num != 1 && (num % 16) == 0 && num < bytes.len() {
            writeln!(writer)?;
            write!(writer, "\t\t")?;
        } else if num != bytes.len() {
            write!(writer, " ")?;
        }
    }
    writeln!(writer)?;
    Ok(())
}
