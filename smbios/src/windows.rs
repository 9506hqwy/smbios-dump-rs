use super::RawSmbiosData;
use bytes::Bytes;
use windows::Win32::System::SystemInformation::{
    EnumSystemFirmwareTables, FIRMWARE_TABLE_PROVIDER, GetSystemFirmwareTable,
};
use windows::core::Error;

pub const FIRMWARE_TABLE_ACPI: u32 = 0x41435049; // 'ACPI'
pub const FIRMWARE_TABLE_FIRM: u32 = 0x4649524D; // 'FIRM'
pub const FIRMWARE_TABLE_RSMB: u32 = 0x52534D42; // 'RSMB'

pub fn get_smbios() -> Result<RawSmbiosData, Error> {
    let tables = enum_system_firmware_table(FIRMWARE_TABLE_RSMB)?;

    let smbios_bytes = get_system_firmware_table(FIRMWARE_TABLE_RSMB, tables[0])?;
    let mut smbios_bytes = Bytes::from(smbios_bytes);

    Ok(RawSmbiosData::from(&mut smbios_bytes))
}

fn enum_system_firmware_table(signature: u32) -> Result<Vec<u32>, Error> {
    // https://docs.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-enumsystemfirmwaretables

    let sig = FIRMWARE_TABLE_PROVIDER(signature);

    let size = unsafe { EnumSystemFirmwareTables(sig, None) };
    if size == 0 {
        return Err(Error::from_thread());
    }

    let mut buffer = vec![0u8; size as usize];

    let size = unsafe { EnumSystemFirmwareTables(sig, Some(buffer.as_mut_slice())) };
    if size == 0 {
        return Err(Error::from_thread());
    }

    Ok(buffer
        .chunks_exact(4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
        .collect())
}

fn get_system_firmware_table(signature: u32, table_id: u32) -> Result<Vec<u8>, Error> {
    // https://docs.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemfirmwaretable

    let sig = FIRMWARE_TABLE_PROVIDER(signature);

    let size = unsafe { GetSystemFirmwareTable(sig, table_id, None) };
    if size == 0 {
        return Err(Error::from_thread());
    }

    let mut buffer = vec![0u8; size as usize];

    let size = unsafe { GetSystemFirmwareTable(sig, table_id, Some(buffer.as_mut_slice())) };
    if size == 0 {
        return Err(Error::from_thread());
    }

    Ok(buffer)
}
