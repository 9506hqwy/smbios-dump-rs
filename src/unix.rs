use super::RawSmbiosData;
use bytes::{Buf, Bytes};
use std::fs;
use std::io::Error;

const DMI_PATH: &str = "/sys/firmware/dmi/tables/DMI";
const SMBIOS_ENTRY_POINT_PATH: &str = "/sys/firmware/dmi/tables/smbios_entry_point";

pub fn get_smbios() -> Result<RawSmbiosData, Error> {
    let bytes = fs::read(SMBIOS_ENTRY_POINT_PATH)?;
    let bytes = Bytes::from(bytes);

    if String::from_utf8_lossy(&bytes.slice(0..4)) == "_SM_" {
        Ok(get_smbios2(bytes)?)
    } else if String::from_utf8_lossy(&bytes.slice(0..5)) == "_SM3_" {
        Ok(get_smbios3(bytes)?)
    } else {
        panic!();
    }
}

pub fn get_smbios2(entry: Bytes) -> Result<RawSmbiosData, Error> {
    let mut entry = entry;
    let _anchor = [
        entry.get_u8(),
        entry.get_u8(),
        entry.get_u8(),
        entry.get_u8(),
    ];
    let _entry_checksum = entry.get_u8();
    let _entry_length = entry.get_u8();
    let smbios_major_version = entry.get_u8();
    let smbios_minior_version = entry.get_u8();
    let _max_structure_size = entry.get_u16();
    let dmi_revision = entry.get_u8();
    let _formatted_ares = [
        entry.get_u8(),
        entry.get_u8(),
        entry.get_u8(),
        entry.get_u8(),
        entry.get_u8(),
    ];
    let _inter_anchor = [
        entry.get_u8(),
        entry.get_u8(),
        entry.get_u8(),
        entry.get_u8(),
        entry.get_u8(),
    ];
    let _inter_checksum = entry.get_u8();
    let length = entry.get_u16() as u32;
    let _structure_table_address = entry.get_u32();
    let _num_smbios = entry.get_u16();
    let _smbios_bcd_revision = entry.get_u8();

    let smbios_table_data = fs::read(DMI_PATH)?;
    let smbios_table_data = Bytes::from(smbios_table_data);

    Ok(RawSmbiosData {
        used_20_calling_method: 1,
        smbios_major_version,
        smbios_minior_version,
        dmi_revision,
        length,
        smbios_table_data,
    })
}

pub fn get_smbios3(entry: Bytes) -> Result<RawSmbiosData, Error> {
    let mut entry = entry;
    let _anchor = [
        entry.get_u8(),
        entry.get_u8(),
        entry.get_u8(),
        entry.get_u8(),
        entry.get_u8(),
    ];
    let _entry_checksum = entry.get_u8();
    let _entry_length = entry.get_u8();
    let smbios_major_version = entry.get_u8();
    let smbios_minior_version = entry.get_u8();
    let dmi_revision = entry.get_u8();
    let _entry_revision = entry.get_u8();
    let _reserved = entry.get_u8();
    let _structure_table_max_size = entry.get_u32_le();
    let _structure_table_address = entry.get_u64_le();

    let smbios_table_data = fs::read(DMI_PATH)?;
    let smbios_table_data = Bytes::from(smbios_table_data);

    Ok(RawSmbiosData {
        used_20_calling_method: 0,
        smbios_major_version,
        smbios_minior_version,
        dmi_revision,
        length: 0,
        smbios_table_data,
    })
}
