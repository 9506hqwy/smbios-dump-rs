pub mod error;

#[cfg(target_family = "unix")]
mod unix;
#[cfg(target_family = "windows")]
mod windows;

#[cfg(target_family = "unix")]
pub use self::unix::get_smbios;
#[cfg(target_family = "windows")]
pub use self::windows::get_smbios;
use bytes::{Buf, Bytes};
use smbios_derive::SMBIOS;

use uuid::Uuid;

pub struct RawSmbiosData {
    pub used_20_calling_method: u8,
    pub smbios_major_version: u8,
    pub smbios_minior_version: u8,
    pub dmi_revision: u8,
    pub length: u32,
    pub smbios_table_data: Bytes,
}

impl RawSmbiosData {
    pub fn is_later(&self, major: u8, minor: u8) -> bool {
        self.smbios_major_version > major
            || self.smbios_major_version == major && self.smbios_minior_version >= minor
    }
}

impl From<&mut Bytes> for RawSmbiosData {
    fn from(buf: &mut Bytes) -> Self {
        let used_20_calling_method = buf.get_u8();
        let smbios_major_version = buf.get_u8();
        let smbios_minior_version = buf.get_u8();
        let dmi_revision = buf.get_u8();
        let length = buf.get_u32_le();
        let smbios_table_data = buf.split_off(0);

        RawSmbiosData {
            used_20_calling_method,
            smbios_major_version,
            smbios_minior_version,
            dmi_revision,
            length,
            smbios_table_data,
        }
    }
}

pub struct RawSmbiosTable {
    pub table_ty: u8,
    pub length: u8,
    pub handle: u16,
    pub body: Bytes,
    pub tailer: Vec<Vec<u8>>,
}

impl RawSmbiosTable {
    pub fn get_string_by_index(&self, index: u8) -> Option<String> {
        let i: usize = (index as usize) - 1;
        self.tailer
            .get(i)
            .map(|v| String::from_utf8_lossy(v).to_string())
    }
}

impl From<&mut Bytes> for RawSmbiosTable {
    fn from(buf: &mut Bytes) -> Self {
        let table_ty = buf.get_u8();
        let length = buf.get_u8();
        let handle = buf.get_u16_le();
        let body = buf.split_to((length - 4) as usize);
        let mut tailer = vec![];
        let mut value = vec![];
        while buf.remaining() != 0 {
            let mut c = buf.get_u8();
            while c != 0 {
                value.push(c);
                c = buf.get_u8();
            }

            if !value.is_empty() {
                tailer.push(value);
            }

            c = buf.get_u8();
            if c == 0 {
                break;
            } else {
                value = vec![c];
            }
        }

        RawSmbiosTable {
            table_ty,
            length,
            handle,
            body,
            tailer,
        }
    }
}

#[derive(SMBIOS)]
pub struct BiosInformation {
    table_ty: u8,
    length: u8,
    handle: u16,
    vendor: Option<String>,
    bios_version: Option<String>,
    bios_starting_address: Option<u16>,
    bios_release_date: Option<String>,
    bios_rom_size: Option<u8>,
    bios_characteristics: Option<u64>,
    bios_characteristics_ex: Option<[u8; 2]>,
    system_bios_major_release: Option<u8>,
    system_bios_minor_release: Option<u8>,
    embedded_ctrl_firmware_major_release: Option<u8>,
    embedded_ctrl_firmware_minor_release: Option<u8>,
    ex_bios_rom_size: Option<u16>,
}

impl BiosInformation {
    pub fn bios_characteristics_str(&self) -> Option<Vec<String>> {
        let chars = vec![
            "",
            "",
            "",
            "BIOS characteristics not supported",
            "ISA is supported",
            "MCA is supported",
            "EISA is supported",
            "PCI is supported",
            "PC Card (PCMCIA) is supported",
            "PNP is supported",
            "APM is supported",
            "BIOS is upgradeable",
            "BIOS shadowing is allowed",
            "VLB is supported",
            "ESCD support is available",
            "Boot from CD is supported",
            "Selectable boot is supported",
            "BIOS ROM is socketed",
            "Boot from PC Card (PCMCIA) is supported",
            "EDD is supported",
            "Japanese floppy for NEC 9800 1.2 MB is supported (int 13h)",
            "Japanese floppy for Toshiba 1.2 MB is supported (int 13h)",
            "5.25\"/360 kB floppy services are supported (int 13h)",
            "5.25\"/1.2 MB floppy services are supported (int 13h)",
            "3.5\"/720 kB floppy services are supported (int 13h)",
            "3.5\"/2.88 MB floppy services are supported (int 13h)",
            "Print screen service is supported (int 5h)",
            "8042 keyboard services are supported (int 9h)",
            "Serial services are supported (int 14h)",
            "Printer services are supported (int 17h)",
            "CGA/mono video services are supported (int 10h)",
            "NEC PC-98",
        ];

        match self.bios_characteristics() {
            Some(value) => {
                let mut v = vec![];
                for (i, name) in chars.iter().enumerate() {
                    let bit_flag = 1 << i;
                    if (bit_flag & value) != 0 {
                        v.push(name.to_string());
                    }
                }

                Some(v)
            }
            _ => None,
        }
    }

    pub fn bios_characteristics_ex_str(&self) -> Option<Vec<String>> {
        let char1 = vec![
            "ACPI is supported",
            "USB legacy is supported",
            "AGP is supported",
            "I2O boot is supported",
            "LS-120 boot is supported",
            "ATAPI Zip drive boot is supported",
            "IEEE 1394 boot is supported",
            "Smart battery is supported",
        ];

        let char2 = vec![
            "BIOS boot specification is supported",
            "Function key-initiated network boot is supported",
            "Targeted content distribution is supported",
            "UEFI is supported",
            "System is a virtual machine",
            "Manufacturing mode is supported",
            "Manufacturing mode is enabled",
        ];

        match self.bios_characteristics_ex() {
            Some(value) => {
                let mut v = vec![];
                for (i, name) in char1.iter().enumerate() {
                    let bit_flag = 1 << i;
                    if (bit_flag & value[0]) != 0 {
                        v.push(name.to_string());
                    }
                }

                for (i, name) in char2.iter().enumerate() {
                    let bit_flag = 1 << i;
                    if (bit_flag & value[1]) != 0 {
                        v.push(name.to_string());
                    }
                }

                Some(v)
            }
            _ => None,
        }
    }
}

#[derive(SMBIOS)]
pub struct SystemInformation {
    table_ty: u8,
    length: u8,
    handle: u16,
    manufacturer: Option<String>,
    product_name: Option<String>,
    version: Option<String>,
    serial_number: Option<String>,
    uuid: Option<[u8; 16]>,
    wakeup_type: Option<u8>,
    sku_number: Option<String>,
    family: Option<String>,
}

impl SystemInformation {
    pub fn get_uuid(&self, smbios: &RawSmbiosData) -> Option<Uuid> {
        self.uuid.map(|u| {
            if smbios.is_later(2, 6) {
                Uuid::from_bytes_le(u)
            } else {
                Uuid::from_bytes(u)
            }
        })
    }

    pub fn wakeup_type_str(&self) -> Option<&'static str> {
        self.wakeup_type.map(|w| match w {
            0 => "Reserved",
            1 => "Other",
            2 => "Unknown",
            3 => "APM Timer",
            4 => "Modem Ring",
            5 => "LAN Remote",
            6 => "Power Switch",
            7 => "PCI PME#",
            8 => "AC Power Restored",
            _ => unreachable!(),
        })
    }
}

#[derive(SMBIOS)]
pub struct BaseBoardInformation {
    table_ty: u8,
    length: u8,
    handle: u16,
    manufacturer: Option<String>,
    product: Option<String>,
    version: Option<String>,
    serial_number: Option<String>,
    asset_tag: Option<String>,
    feature_flags: Option<u8>,
    location: Option<String>,
    chassis_handle: Option<u16>,
    board_ty: Option<u8>,
    num_contained_object: Option<u8>,
    #[smbios(length = "num_contained_object")]
    contained_object_handle: Option<Vec<u16>>,
}

impl BaseBoardInformation {
    pub fn feature_flags_str(&self) -> Option<Vec<String>> {
        let feats = vec![
            "Board is a hosting board",
            "Board requires at least one daughter board",
            "Board is removable",
            "Board is replaceable",
            "Board is hot swappable",
            "",
            "",
        ];

        match self.feature_flags() {
            Some(value) => {
                let mut v = vec![];
                for (i, name) in feats.iter().enumerate() {
                    let bit_flag = 1 << i;
                    if (bit_flag & value) != 0 {
                        v.push(name.to_string());
                    }
                }

                Some(v)
            }
            _ => None,
        }
    }

    pub fn board_ty_str(&self) -> Option<&'static str> {
        self.board_ty().map(|b| match b {
            1 => "Unknown",
            2 => "Other",
            3 => "Server Blade",
            4 => "Connectivity Switch",
            5 => "System Management Module",
            6 => "Processor Module",
            7 => "I/O Module",
            8 => "Memory Module",
            9 => "Daughter Board",
            10 => "Motherboard",
            11 => "Processor+Memory Module",
            12 => "Processor+I/O Module",
            13 => "Interconnect Board",
            _ => unreachable!(),
        })
    }
}
