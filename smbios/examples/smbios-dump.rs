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
    write!(
        writer,
        "Handle 0x{:04X}, DMI type {}, {} bytes\n",
        table.handle, table.table_ty, table.length
    )?;

    // Byte Array
    write!(writer, "\tHeader and Data:\n")?;
    let mut body = vec![table.table_ty, table.length];
    body.extend_from_slice(&table.handle.to_le_bytes());
    body.extend_from_slice(&table.body);
    write_bytearray(writer, &body)?;

    if !table.tailer.is_empty() {
        write!(writer, "\tStrings:\n")?;
        for bytes in &table.tailer {
            // Byte Array
            write_bytearray(writer, bytes)?;

            // String
            if let Ok(s) = String::from_utf8(bytes.to_vec()) {
                write!(writer, "\t\t{}\n", s)?;
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
    // TODO:
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
    // TODO:
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
    // TODO:
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
    // TODO:
    Ok(())
}

fn dump_type17(table: &MemoryDevice, writer: &mut impl Write) -> std::io::Result<()> {
    write_header!(writer, table);
    write_title!(writer, get_table_name_by_id(17).unwrap());
    // TODO:
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
    // TODO:
    Ok(())
}

fn dump_type20(table: &MemoryDeviceMappedAddress, writer: &mut impl Write) -> std::io::Result<()> {
    write_header!(writer, table);
    write_title!(writer, get_table_name_by_id(20).unwrap());
    // TODO:
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
    // TODO:
    Ok(())
}

fn dump_type27(table: &CoolingDevice, writer: &mut impl Write) -> std::io::Result<()> {
    write_header!(writer, table);
    write_title!(writer, get_table_name_by_id(27).unwrap());
    // TODO:
    Ok(())
}

fn dump_type28(table: &TemperatureProbe, writer: &mut impl Write) -> std::io::Result<()> {
    write_header!(writer, table);
    write_title!(writer, get_table_name_by_id(28).unwrap());
    // TODO:
    Ok(())
}

fn dump_type29(table: &ElectricalCurrentProbe, writer: &mut impl Write) -> std::io::Result<()> {
    write_header!(writer, table);
    write_title!(writer, get_table_name_by_id(29).unwrap());
    // TODO:
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
    // TODO:
    Ok(())
}

fn dump_type35(table: &ManagementDeviceComponent, writer: &mut impl Write) -> std::io::Result<()> {
    write_header!(writer, table);
    write_title!(writer, get_table_name_by_id(35).unwrap());
    // TODO:
    Ok(())
}

fn dump_type36(
    table: &ManagementDeviceThresholdData,
    writer: &mut impl Write,
) -> std::io::Result<()> {
    write_header!(writer, table);
    write_title!(writer, get_table_name_by_id(36).unwrap());
    // TODO:
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
    // TODO:
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
    // TODO:
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
    // TODO:
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
            write!(writer, "\n")?;
            write!(writer, "\t\t")?;
        } else if num != bytes.len() {
            write!(writer, " ")?;
        }
    }
    write!(writer, "\n")?;
    Ok(())
}
