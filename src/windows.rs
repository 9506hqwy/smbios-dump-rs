use super::RawSmbiosData;
use bytes::Bytes;
use windows::core::Error;
use windows::Win32::System::SystemInformation::{
    EnumSystemFirmwareTables, GetSystemFirmwareTable, FIRMWARE_TABLE_ID, FIRMWARE_TABLE_PROVIDER,
};

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

    let size = unsafe { EnumSystemFirmwareTables(sig, std::ptr::null_mut(), 0) };
    if size == 0 {
        return Err(Error::from_win32());
    }

    let mut buffer = vec![0u32; (size / 4) as usize];

    let size = unsafe {
        let buf = buffer.as_mut_ptr() as *mut FIRMWARE_TABLE_ID;
        EnumSystemFirmwareTables(sig, buf, size)
    };
    if size == 0 {
        return Err(Error::from_win32());
    }

    Ok(buffer)
}

fn get_system_firmware_table(signature: u32, table_id: u32) -> Result<Vec<u8>, Error> {
    // https://docs.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemfirmwaretable

    let sig = FIRMWARE_TABLE_PROVIDER(signature);
    let id = FIRMWARE_TABLE_ID(table_id);

    let size = unsafe { GetSystemFirmwareTable(sig, id, std::ptr::null_mut(), 0) };
    if size == 0 {
        return Err(Error::from_win32());
    }

    let mut buffer = vec![0u8; size as usize];

    let size = unsafe {
        let buf = buffer.as_mut_ptr() as *mut std::ffi::c_void;
        GetSystemFirmwareTable(sig, id, buf, size)
    };
    if size == 0 {
        return Err(Error::from_win32());
    }

    Ok(buffer)
}
