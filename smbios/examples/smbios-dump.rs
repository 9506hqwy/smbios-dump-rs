use smbios::error::Error;
use smbios::{
    BaseBoardInformation, BiosInformation, RawSmbiosData, RawSmbiosTable, SystemInformation,
};
use std::io::Write;

fn main() -> Result<(), Error> {
    let smbios = smbios::get_smbios()?;

    let mut data = smbios.smbios_table_data.clone();
    while !data.is_empty() {
        let table = RawSmbiosTable::from(&mut data);
        match table.table_ty {
            0 => dump_type0(
                &BiosInformation::from_raw_table(&table),
                &mut std::io::stdout(),
            )
            .unwrap(),
            1 => dump_type1(
                &SystemInformation::from_raw_table(&table),
                &mut std::io::stdout(),
                &smbios,
            )
            .unwrap(),
            2 => dump_type2(
                &BaseBoardInformation::from_raw_table(&table),
                &mut std::io::stdout(),
            )
            .unwrap(),
            _ => dump_raw(&table, &mut std::io::stdout()).unwrap(),
        }

        println!();
    }

    Ok(())
}

pub fn dump_raw(table: &RawSmbiosTable, writer: &mut impl Write) -> std::io::Result<()> {
    writer.write_fmt(format_args!(
        "Handle 0x{:04X}, DMI type {}, {} bytes\n",
        table.handle, table.table_ty, table.length
    ))?;

    // Byte Array
    writer.write_fmt(format_args!("\tHeader and Data:\n"))?;
    let mut body = vec![table.table_ty, table.length];
    body.extend_from_slice(&table.handle.to_le_bytes());
    body.extend_from_slice(&table.body);
    write_bytearray(writer, &body)?;

    if !table.tailer.is_empty() {
        writer.write_fmt(format_args!("\tStrings:\n"))?;
        for bytes in &table.tailer {
            // Byte Array
            write_bytearray(writer, bytes)?;

            // String
            if let Ok(s) = String::from_utf8(bytes.to_vec()) {
                writer.write_fmt(format_args!("\t\t{}\n", s))?;
            }
        }
    }

    Ok(())
}

pub fn dump_type0(table: &BiosInformation, writer: &mut impl Write) -> std::io::Result<()> {
    writer.write_fmt(format_args!(
        "Handle 0x{:04X}, DMI type {}, {} bytes\n",
        table.handle(),
        table.table_ty(),
        table.length()
    ))?;

    writer.write_fmt(format_args!("BIOS Information\n"))?;
    writer.write_fmt(format_args!(
        "\tVendor: {}\n",
        table.vendor().as_ref().unwrap()
    ))?;
    writer.write_fmt(format_args!(
        "\tVersion: {}\n",
        table.bios_version().as_ref().unwrap()
    ))?;
    writer.write_fmt(format_args!(
        "\tRelease Date: {}\n",
        table.bios_release_date().as_ref().unwrap()
    ))?;
    writer.write_fmt(format_args!(
        "\tAddress: 0x{:04X}\n",
        table.bios_starting_address().unwrap()
    ))?;
    writer.write_fmt(format_args!(
        "\tRuntimme Size: {} kB\n",
        (0x10000 - (table.bios_starting_address().unwrap() as u32)) * 16 / 1024
    ))?;
    writer.write_fmt(format_args!(
        "\tROM Size: {} kB\n",
        ((table.bios_rom_size().unwrap() as u16) + 1) * 64
    ))?;
    writer.write_fmt(format_args!("\tCharracteristics:\n"))?;
    for name in table.bios_characteristics_str().unwrap() {
        writer.write_fmt(format_args!("\t\t{}\n", name))?;
    }
    if let Some(chars_ex) = table.bios_characteristics_ex_str() {
        for name in chars_ex {
            writer.write_fmt(format_args!("\t\t{}\n", name))?;
        }
    }

    if let Some(major) = table.system_bios_major_release() {
        if let Some(minor) = table.system_bios_minor_release() {
            writer.write_fmt(format_args!("\tBIOS Revisione: {}.{}\n", major, minor))?;
        }
    }

    if let Some(major) = table.embedded_ctrl_firmware_major_release() {
        if let Some(minor) = table.embedded_ctrl_firmware_minor_release() {
            writer.write_fmt(format_args!("\tFirmware Revisione: {}.{}\n", major, minor))?;
        }
    }

    Ok(())
}

pub fn dump_type1(
    table: &SystemInformation,
    writer: &mut impl Write,
    smbios: &RawSmbiosData,
) -> std::io::Result<()> {
    writer.write_fmt(format_args!(
        "Handle 0x{:04X}, DMI type {}, {} bytes\n",
        table.handle(),
        table.table_ty(),
        table.length()
    ))?;

    writer.write_fmt(format_args!("System Information\n"))?;
    writer.write_fmt(format_args!(
        "\tManufacturer: {}\n",
        table.manufacturer().as_ref().unwrap()
    ))?;
    writer.write_fmt(format_args!(
        "\tProduct Name: {}\n",
        table.product_name().as_ref().unwrap()
    ))?;
    writer.write_fmt(format_args!(
        "\tVersion: {}\n",
        table.version().as_ref().unwrap()
    ))?;
    writer.write_fmt(format_args!(
        "\tSerial Number: {}\n",
        table.serial_number().as_ref().unwrap()
    ))?;
    if table.uuid().is_some() {
        writer.write_fmt(format_args!(
            "\tUUID: {}\n",
            table.get_uuid(smbios).unwrap()
        ))?;
    }
    if table.wakeup_type().is_some() {
        writer.write_fmt(format_args!(
            "\tWake-up Type: {}\n",
            table.wakeup_type_str().unwrap()
        ))?;
    }
    if let Some(sku_number) = table.sku_number() {
        writer.write_fmt(format_args!("\tSKU Number: {}\n", sku_number))?;
    }
    if let Some(family) = table.family() {
        writer.write_fmt(format_args!("\tFamily: {}\n", family))?;
    }

    Ok(())
}

pub fn dump_type2(table: &BaseBoardInformation, writer: &mut impl Write) -> std::io::Result<()> {
    writer.write_fmt(format_args!(
        "Handle 0x{:04X}, DMI type {}, {} bytes\n",
        table.handle(),
        table.table_ty(),
        table.length()
    ))?;

    writer.write_fmt(format_args!("Base Board Information\n"))?;
    if let Some(manufacturer) = table.manufacturer() {
        writer.write_fmt(format_args!("\tManufacturer: {}\n", manufacturer))?;
    }
    if let Some(product) = table.product() {
        writer.write_fmt(format_args!("\tProduct Name: {}\n", product))?;
    }
    if let Some(version) = table.version() {
        writer.write_fmt(format_args!("\tVersion: {}\n", version))?;
    }
    if let Some(serial_number) = table.serial_number() {
        writer.write_fmt(format_args!("\tSerial Number: {}\n", serial_number))?;
    }
    if let Some(asset_tag) = table.asset_tag() {
        writer.write_fmt(format_args!("\tAsset Tag: {}\n", asset_tag))?;
    }
    if let Some(_feature_flags) = table.feature_flags() {
        writer.write_fmt(format_args!("\tFeatures:\n"))?;
        for name in table.feature_flags_str().unwrap() {
            writer.write_fmt(format_args!("\t\t{}\n", name))?;
        }
    }
    if let Some(location) = table.location() {
        writer.write_fmt(format_args!("\tLocation In Chassis: {}\n", location))?;
    }
    if let Some(chassis_handle) = table.chassis_handle() {
        writer.write_fmt(format_args!("\tChassis Handle: 0x{:04X}\n", chassis_handle))?;
    }
    if table.board_ty().is_some() {
        writer.write_fmt(format_args!("\tType: {}\n", table.board_ty_str().unwrap()))?;
    }

    Ok(())
}

fn write_bytearray(writer: &mut impl Write, bytes: &[u8]) -> std::io::Result<()> {
    writer.write_fmt(format_args!("\t\t"))?;
    for (i, byte) in bytes.iter().enumerate() {
        writer.write_fmt(format_args!("{:02X}", byte))?;

        let num = i + 1;
        if num != 1 && (num % 16) == 0 && num < bytes.len() {
            writer.write_fmt(format_args!("\n"))?;
            writer.write_fmt(format_args!("\t\t"))?;
        } else if num != bytes.len() {
            writer.write_fmt(format_args!(" "))?;
        }
    }
    writer.write_fmt(format_args!("\n"))?;
    Ok(())
}
