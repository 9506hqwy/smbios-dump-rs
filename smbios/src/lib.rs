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
use std::collections::HashMap;
use std::sync::OnceLock;
use uuid::Uuid;

static TABLE_NAMES: OnceLock<HashMap<u8, &'static str>> = OnceLock::new();

fn init_table() -> HashMap<u8, &'static str> {
    let mut names = HashMap::new();
    names.insert(0, "BIOS Information");
    names.insert(1, "System Information");
    names.insert(2, "Baseboard Information");
    names.insert(3, "Chassis Information");
    names.insert(4, "Processor Information");
    names.insert(5, "Memory Controller Information");
    names.insert(6, "Memory Module Information");
    names.insert(7, "Cache Information");
    names.insert(8, "Port Connector Information");
    names.insert(9, "System Slots");
    names.insert(10, "On Board Devices Information");
    names.insert(11, "OEM Strings");
    names.insert(12, "System Configuration Options");
    names.insert(13, "BIOS Language Information");
    names.insert(14, "Group Associations");
    names.insert(15, "System Event Log");
    names.insert(16, "Physical Memory Array");
    names.insert(17, "Memory Device");
    names.insert(18, "32-bit Memory Error Information");
    names.insert(19, "Memory Array Mapped Address");
    names.insert(20, "Memory Device Mapped Address");
    names.insert(21, "Built-in Pointing Device");
    names.insert(22, "Portable Battery");
    names.insert(23, "System Reset");
    names.insert(24, "Hardware Security");
    names.insert(25, "System Power Controls");
    names.insert(26, "Voltage Probe");
    names.insert(27, "Cooling Device");
    names.insert(28, "Temperature Probe");
    names.insert(29, "Electrical Current Probe");
    names.insert(30, "Out of Band Remote Access");
    names.insert(31, "Boot Integrity Service Enty Point");
    names.insert(32, "System Boot Information");
    names.insert(33, "64-bit Memory Error Information");
    names.insert(34, "Management Device");
    names.insert(35, "Management Device Component");
    names.insert(36, "Management Device Threashold Data");
    names.insert(37, "Memory Channel");
    names.insert(38, "IPMI Device Information");
    names.insert(39, "System Power Supply");
    names.insert(40, "Additional Information");
    names.insert(41, "Onboard Devices Extended Information");
    names.insert(42, "Management Controller Host Interface");
    names.insert(43, "TPM Device");
    names.insert(44, "Processor Additional Information");
    names.insert(45, "Firmware Inventory Information");
    names.insert(46, "String Property");
    names.insert(126, "Inactive");
    names.insert(127, "End of Table");
    names
}

pub fn get_table_name_by_id(id: u8) -> Option<&'static str> {
    if id >= 128 {
        Some("OEM-specific")
    } else {
        TABLE_NAMES.get_or_init(init_table).get(&id).cloned()
    }
}

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
        if index < 1 {
            return None;
        }

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
pub struct Bios {
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

impl Bios {
    pub fn bios_rom_size_ex(&self) -> Option<u16> {
        self.bios_rom_size().map(|size| {
            if size == 0xFF {
                self.ex_bios_rom_size.unwrap()
            } else {
                ((size as u16) + 1) * 64
            }
        })
    }

    pub fn bios_characteristics_str(&self) -> Option<Vec<String>> {
        let chars = [
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

        self.bios_characteristics()
            .map(|v| get_flag_strings(v, &chars))
    }

    pub fn bios_characteristics_ex_str(&self) -> Option<Vec<String>> {
        let char1 = [
            "ACPI is supported",
            "USB legacy is supported",
            "AGP is supported",
            "I2O boot is supported",
            "LS-120 boot is supported",
            "ATAPI Zip drive boot is supported",
            "IEEE 1394 boot is supported",
            "Smart battery is supported",
        ];

        let char2 = [
            "BIOS boot specification is supported",
            "Function key-initiated network boot is supported",
            "Targeted content distribution is supported",
            "UEFI is supported",
            "System is a virtual machine",
            "Manufacturing mode is supported",
            "Manufacturing mode is enabled",
        ];

        self.bios_characteristics_ex().map(|v| {
            let mut r1 = get_flag_strings(v[0] as u64, &char1);
            let mut r2 = get_flag_strings(v[1] as u64, &char2);
            r1.append(&mut r2);
            r1
        })
    }

    pub fn system_bios_release(&self) -> Option<String> {
        if let (Some(major), Some(minor)) = (
            self.system_bios_major_release(),
            self.system_bios_minor_release(),
        ) {
            return Some(format!("{major}.{minor}"));
        }

        None
    }

    pub fn embedded_ctrl_firmware_release(&self) -> Option<String> {
        if let (Some(major), Some(minor)) = (
            self.embedded_ctrl_firmware_major_release(),
            self.embedded_ctrl_firmware_minor_release(),
        ) {
            return Some(format!("{major}.{minor}"));
        }

        None
    }

    pub fn runtime_size_kb(&self) -> Option<u32> {
        self.bios_starting_address()
            .map(|a| (0x10000 - (a as u32)) * 16 / 1024)
    }
}

#[derive(SMBIOS)]
pub struct System {
    table_ty: u8,
    length: u8,
    handle: u16,
    manufacturer: Option<String>,
    product_name: Option<String>,
    version: Option<String>,
    serial_number: Option<String>,
    uuid: Option<[u8; 16]>,
    wakeup_ty: Option<u8>,
    sku_number: Option<String>,
    family: Option<String>,
}

impl System {
    pub fn get_uuid(&self, smbios: &RawSmbiosData) -> Option<Uuid> {
        self.uuid.map(|u| {
            if smbios.is_later(2, 6) {
                Uuid::from_bytes_le(u)
            } else {
                Uuid::from_bytes(u)
            }
        })
    }

    pub fn wakeup_ty_str(&self) -> Option<&'static str> {
        self.wakeup_ty.map(|w| match w {
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
pub struct BaseBoard {
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

impl BaseBoard {
    pub fn feature_flags_str(&self) -> Option<Vec<String>> {
        let feats = [
            "Board is a hosting board",
            "Board requires at least one daughter board",
            "Board is removable",
            "Board is replaceable",
            "Board is hot swappable",
            "",
            "",
        ];

        self.feature_flags()
            .map(|v| get_flag_strings(v as u64, &feats))
    }

    pub fn board_ty_str(&self) -> Option<&'static str> {
        self.board_ty().map(get_board_ty_str)
    }
}

#[derive(SMBIOS)]
pub struct Chassis {
    table_ty: u8,
    length: u8,
    handle: u16,
    manufacturer: Option<String>,
    ty: Option<u8>,
    version: Option<String>,
    serial_number: Option<String>,
    asset_tag_number: Option<String>,
    boot_up_state: Option<u8>,
    power_supply_state: Option<u8>,
    thermal_state: Option<u8>,
    security_status: Option<u8>,
    oem_defined: Option<u32>,
    height: Option<u8>,
    num_power_cords: Option<u8>,
    contained_element_count: Option<u8>,
    contained_element_record_length: Option<u8>,
    #[smbios(
        length = "contained_element_count.map(|c| contained_element_record_length.map(|l| c * l)).flatten()"
    )]
    contained_elements: Option<Vec<u8>>,
    sku_number: Option<String>,
}

impl Chassis {
    pub fn ty_str(&self) -> Option<&'static str> {
        self.ty().map(|t| match t & 0x3F {
            0x01 => "Other",
            0x02 => "Unknown",
            0x03 => "Desktop",
            0x04 => "Low Profile Desktop",
            0x05 => "Pizza Box",
            0x06 => "Mini Tower",
            0x07 => "Tower",
            0x08 => "Portable",
            0x09 => "Laptop",
            0x0A => "Notebook",
            0x0B => "Hand Held",
            0x0C => "Docking Station",
            0x0D => "All In One",
            0x0E => "Sub Notebook",
            0x0F => "Space-saving",
            0x10 => "Lunch Box",
            0x11 => "Main Server Chassis",
            0x12 => "Expansion Chassis",
            0x13 => "SubChassis",
            0x14 => "Bus Expansion Chassis",
            0x15 => "Peripheral Chassis",
            0x16 => "RAID Chassis",
            0x17 => "Rack Mount Chassis",
            0x18 => "Sealed-case PC",
            0x19 => "Multi-system chassis",
            0x1A => "Compact PCI",
            0x1B => "Advanced TCA",
            0x1C => "Blade",
            0x1D => "Blade Enclosure",
            0x1E => "Tablet",
            0x1F => "Convertible",
            0x20 => "Detachable",
            0x21 => "IoT Gateway",
            0x22 => "Embedded PC",
            0x23 => "Mini PC",
            0x24 => "Stick PC",
            _ => unreachable!(),
        })
    }

    pub fn ty_lock(&self) -> Option<bool> {
        self.ty().map(|t| (t & 0x80) != 0)
    }

    pub fn boot_up_state_str(&self) -> Option<&'static str> {
        self.boot_up_state.map(|s| self.get_chassis_state(s))
    }

    pub fn power_supply_state_str(&self) -> Option<&'static str> {
        self.power_supply_state.map(|s| self.get_chassis_state(s))
    }

    pub fn thermal_state_str(&self) -> Option<&'static str> {
        self.thermal_state.map(|s| self.get_chassis_state(s))
    }

    pub fn security_status_str(&self) -> Option<&'static str> {
        self.security_status
            .map(|s| self.get_chassis_security_status(s))
    }

    fn get_chassis_state(&self, state: u8) -> &'static str {
        match state {
            0x01 => "Other",
            0x02 => "Unknown",
            0x03 => "Safe",
            0x04 => "Warning",
            0x05 => "Critical",
            0x06 => "Non-recoverable",
            _ => unreachable!(),
        }
    }

    fn get_chassis_security_status(&self, state: u8) -> &'static str {
        match state {
            0x01 => "Other",
            0x02 => "Unknown",
            0x03 => "None",
            0x04 => "External interface locked out",
            0x05 => "External interface enabled",
            _ => unreachable!(),
        }
    }
}

#[derive(SMBIOS)]
pub struct Processor {
    table_ty: u8,
    length: u8,
    handle: u16,
    socket_designation: Option<String>,
    processor_ty: Option<u8>,
    processor_family: Option<u8>,
    processor_manufacturer: Option<String>,
    processor_id: Option<u64>,
    processor_version: Option<String>,
    voltage: Option<u8>,
    external_clock: Option<u16>,
    max_speed: Option<u16>,
    current_speed: Option<u16>,
    status: Option<u8>,
    processor_upgrade: Option<u8>,
    l1_cache_handle: Option<u16>,
    l2_cache_handle: Option<u16>,
    l3_cache_handle: Option<u16>,
    serial_number: Option<String>,
    asset_tag: Option<String>,
    part_number: Option<String>,
    core_count: Option<u8>,
    core_enabled: Option<u8>,
    thread_count: Option<u8>,
    processor_characteristics: Option<u16>,
    processor_family2: Option<u16>,
    core_count2: Option<u16>,
    core_enabled2: Option<u16>,
    thread_count2: Option<u16>,
    thread_enabled: Option<u16>,
}

impl Processor {
    pub fn processor_ty_str(&self) -> Option<&'static str> {
        self.processor_ty().map(|t| match t {
            0x01 => "Other",
            0x02 => "Unknown",
            0x03 => "Central Processor",
            0x04 => "Central Processor",
            0x05 => "DSP Processor",
            0x06 => "Video Processor",
            _ => unreachable!(),
        })
    }

    pub fn processor_family_str(&self) -> Option<&'static str> {
        self.processor_family().map(|f| match f {
            0x01 => "Other",
            0x02 => "Unknown",
            0x03 => "8086",
            0x04 => "80286",
            0x05 => "Intel386 processor",
            0x06 => "Intel486 processor",
            0x07 => "8087",
            0x08 => "80287",
            0x09 => "80387",
            0x0A => "80487",
            0x0B => "Intel Pentium processor",
            0x0C => "Pentium Pro processor",
            0x0D => "Pentium II processor",
            0x0E => "Pentium processor with MMX technology",
            0x0F => "Intel Celeron processor",

            0x10 => "Pentium II Xeon processor",
            0x11 => "Pentium III processor",
            0x12 => "M1 Family",
            0x13 => "M2 Family",
            0x14 => "Intel Celeron M processor",
            0x15 => "Intel Pentium 4 HT processor",
            //0x16 => "",
            //0x17 => "",
            0x18 => "AMD Duron Processor Family",
            0x19 => "K5 Family",
            0x1A => "K6 Family",
            0x1B => "K6-2",
            0x1C => "K6-3",
            0x1D => "AMD Athlon Processor Family",
            0x1E => "AMD29000 Family",
            0x1F => "K6-2+",

            0x20 => "Power PC Family",
            0x21 => "Power PC 601",
            0x22 => "Power PC 603",
            0x23 => "Power PC 603+",
            0x24 => "Power PC 604",
            0x25 => "Power PC 620",
            0x26 => "Power PC x704",
            0x27 => "Power PC 750",
            0x28 => "Intel Core Duo processor",
            0x29 => "Intel Core Duo mobile processor",
            0x2A => "Intel Core Solo mobile processor",
            0x2B => "Intel Atom processor",
            0x2C => "Intel Core M processor",
            0x2D => "Intel Core m3 processor",
            0x2E => "Intel Core m5 processor",
            0x2F => "Intel Core m7 processor",

            0x30 => "Alpha Family",
            0x31 => "Alpha 21064",
            0x32 => "Alpha 21066",
            0x33 => "Alpha 21164",
            0x34 => "Alpha 21164PC",
            0x35 => "Alpha 21164a",
            0x36 => "Alpha 21264",
            0x37 => "Alpha 21364",
            0x38 => "AMD Turion II Ultra Dual-Core Mobile M Processor Family",
            0x39 => "AMD Turion II Dual-Core Mobile M Processor Family",
            0x3A => "AMD Athlon II Dual-Core M Processor Family",
            0x3B => "AMD Opteron 6100 Series Processor",
            0x3C => "AMD Opteron 4100 Series Processor",
            0x3D => "AMD Opteron 6200 Series Processor",
            0x3E => "AMD Opteron 4200 Series Processor",
            0x3F => "AMD FX Series Processor",

            0x40 => "MIPS Family",
            0x41 => "MIPS R4000",
            0x42 => "MIPS R4200",
            0x43 => "MIPS R4400",
            0x44 => "MIPS R4600",
            0x45 => "MIPS R10000",
            0x46 => "AMD C-Series Processor",
            0x47 => "AMD E-Series Processor",
            0x48 => "AMD A-Series Processor",
            0x49 => "AMD G-Series Processor",
            0x4A => "AMD Z-Series Processor",
            0x4B => "AMD R-Series Processor",
            0x4C => "AMD Opteron 4300 Series Processor",
            0x4D => "AMD Opteron 6300 Series Processor",
            0x4E => "AMD Opteron 3300 Series Processor",
            0x4F => "AMD FirePro Series Processor",

            0x50 => "SPARC Family",
            0x51 => "SuperSPARC",
            0x52 => "microSPARC II",
            0x53 => "microSPARC IIep",
            0x54 => "UltraSPARC",
            0x55 => "UltraSPARC II",
            0x56 => "UltraSPARC Iii",
            0x57 => "UltraSPARC III",
            0x58 => "UltraSPARC IIIi",
            //0x59 => "",
            //0x5A => "",
            //0x5B => "",
            //0x5C => "",
            //0x5D => "",
            //0x5E => "",
            //0x5F => "",
            0x60 => "68040 Family",
            0x61 => "68xxx",
            0x62 => "68000",
            0x63 => "68010",
            0x64 => "68020",
            0x65 => "68030",
            0x66 => "AMD Athlon X4 Quad-Core Processor Family",
            0x67 => "AMD Opteron X1000 Series Processor",
            0x68 => "AMD Opteron X2000 Series APU",
            0x69 => "AMD Opteron A-Series Processor",
            0x6A => "AMD Opteron X3000 Series APU",
            0x6B => "AMD Zen Processor Family",
            //0x6C => "",
            //0x6D => "",
            //0x6E => "",
            //0x6F => "",
            0x70 => "Hobbit Family",
            //0x71 => "",
            //0x72 => "",
            //0x73 => "",
            //0x74 => "",
            //0x75 => "",
            //0x76 => "",
            //0x77 => "",
            0x78 => "Crusoe TM5000 Family",
            0x79 => "Crusoe TM3000 Family",
            0x7A => "Efficeon TM8000 Family",
            //0x7B => "",
            //0x7C => "",
            //0x7D => "",
            //0x7E => "",
            //0x7F => "",
            0x80 => "Weitek",
            //0x81 => "",
            0x82 => "Itanium processor",
            0x83 => "AMD Athlon 64 Processor Family",
            0x84 => "AMD Opteron Processor Family",
            0x85 => "AMD Sempron Processor Family",
            0x86 => "AMD Turion 64 Mobile Technology",
            0x87 => "Dual-Core AMD Opteron Processor Family",
            0x88 => "AMD Athlon 64 X2 Dual-Core Processor Family",
            0x89 => "AMD Turion 64 X2 Mobile Technology",
            0x8A => "Quad-Core AMD Opteron Processor Family",
            0x8B => "Third-Generation AMD Opteron Processor Family",
            0x8C => "AMD Phenom FX Quad-Core Processor Family",
            0x8D => "AMD Phenom X4 Quad-Core Processor Family",
            0x8E => "AMD Phenom X2 Dual-Core Processor Family",
            0x8F => "AMD Athlon X2 Dual-Core Processor Family",

            0x90 => "PA-RISC Family",
            0x91 => "PA-RISC 8500",
            0x92 => "PA-RISC 8000",
            0x93 => "PA-RISC 7300LC",
            0x94 => "PA-RISC 7200",
            0x95 => "PA-RISC 7100LC",
            0x96 => "PA-RISC 7100",
            //0x97 => "",
            //0x98 => "",
            //0x99 => "",
            //0x9A => "",
            //0x9B => "",
            //0x9C => "",
            //0x9D => "",
            //0x9E => "",
            //0x9F => "",
            0xA0 => "V30 Family",
            0xA1 => "Quad-Core Intel Xeon processor 3200 Series",
            0xA2 => "Dual-Core Intel Xeon processor 3000 Series",
            0xA3 => "Quad-Core Intel Xeon processor 5300 Series",
            0xA4 => "Dual-Core Intel Xeon processor 5100 Series",
            0xA5 => "Dual-Core Intel Xeon processor 5000 Series",
            0xA6 => "Dual-Core Intel Xeon processor LV",
            0xA7 => "Dual-Core Intel Xeon processor ULV",
            0xA8 => "Dual-Core Intel Xeon processor 7100 Series",
            0xA9 => "Quad-Core Intel Xeon processor 5400 Series",
            0xAA => "Quad-Core Intel Xeon processor",
            0xAB => "Dual-Core Intel Xeon processor 5200 Series",
            0xAC => "Dual-Core Intel Xeon processor 7200 Series",
            0xAD => "Quad-Core Intel Xeon processor 7300 Series",
            0xAE => "Quad-Core Intel Xeon processor 7400 Series",
            0xAF => "Multi-Core Intel Xeon processor 7400 Series",

            0xB0 => "Pentium III Xeon processor",
            0xB1 => "Pentium III Processor with Intel  SpeedStep Technology",
            0xB2 => "Pentium 4 Processor",
            0xB3 => "Intel Xeon processor",
            0xB4 => "AS400 Family",
            0xB5 => "Intel Xeon processor MP",
            0xB6 => "AMD Athlon XP Processor Family",
            0xB7 => "AMD Athlon MP Processor Family",
            0xB8 => "Intel Itanium 2 processor",
            0xB9 => "Intel Pentium M processor",
            0xBA => "Intel Celeron D processor",
            0xBB => "Intel Pentium D processor",
            0xBC => "Intel Pentium Processor Extreme Edition",
            0xBD => "Intel Core Solo Processor",
            //0xBE => "",
            0xBF => "Intel Core 2 Duo Processor",

            0xC0 => "Intel Core 2 Solo processor",
            0xC1 => "Intel Core 2 Extreme processor",
            0xC2 => "Intel Core 2 Quad processor",
            0xC3 => "Intel Core 2 Extreme mobile processor",
            0xC4 => "Intel Core 2 Duo mobile processor",
            0xC5 => "Intel Core 2 Solo mobile processor",
            0xC6 => "Intel Core i7 processor",
            0xC7 => "Dual-Core Intel Celeron processor",
            0xC8 => "IBM390 Family",
            0xC9 => "G4",
            0xCA => "G5",
            0xCB => "ESA/390 G6",
            0xCC => "z/Architecture base",
            0xCD => "Intel Core i5 processor",
            0xCE => "Intel Core i3 processor",
            0xCF => "Intel Core i9 processor",

            //0xD0 => "",
            //0xD1 => "",
            0xD2 => "VIA C7-M Processor Family",
            0xD3 => "VIA C7-D Processor Family",
            0xD4 => "VIA C7 Processor Family",
            0xD5 => "VIA Eden Processor Family",
            0xD6 => "Multi-Core Intel Xeon processor",
            0xD7 => "Dual-Core Intel Xeon processor 3xxx Series",
            0xD8 => "Quad-Core Intel Xeon processor 3xxx Series",
            0xD9 => "VIA Nano Processor Family",
            0xDA => "Dual-Core Intel Xeon processor 5xxx Series",
            0xDB => "Quad-Core Intel Xeon processor 5xxx Series",
            //0xDC => "",
            0xDD => "Dual-Core Intel Xeon processor 7xxx Series",
            0xDE => "Quad-Core Intel Xeon processor 7xxx Series",
            0xDF => "Multi-Core Intel Xeon processor 7xxx Series",

            0xE0 => "Multi-Core Intel Xeon processor 3400 Series",
            //0xE1 => "",
            //0xE2 => "",
            //0xE3 => "",
            0xE4 => "AMD Opteron 3000 Series Processor",
            0xE5 => "AMD Sempron II Processor",
            0xE6 => "Embedded AMD Opteron Quad-Core Processor Family",
            0xE7 => "AMD Phenom Triple-Core Processor Family",
            0xE8 => "AMD Turion Ultra Dual-Core Mobile Processor Family",
            0xE9 => "AMD Turion Dual-Core Mobile Processor Family",
            0xEA => "AMD Athlon Dual-Core Processor Family",
            0xEB => "AMD Sempron SI Processor Family",
            0xEC => "AMD Phenom II Processor Family",
            0xED => "AMD Athlon II Processor Family",
            0xEE => "Six-Core AMD Opteron Processor Family",
            0xEF => "AMD Sempron M Processor Family",

            //0xF0 => "",
            //0xF1 => "",
            //0xF2 => "",
            //0xF3 => "",
            //0xF4 => "",
            //0xF5 => "",
            //0xF6 => "",
            //0xF7 => "",
            //0xF8 => "",
            //0xF9 => "",
            0xFA => "i860",
            0xFB => "i960",
            //0xFC => "",
            //0xFD => "",
            0xFE => self.processor_family2_str().unwrap(),
            0xFF => "Reserved",

            _ => unreachable!(),
        })
    }

    pub fn voltage_str(&self) -> Option<String> {
        self.voltage().map(|v| match v & 0x80 {
            0 => {
                let vols = ["5.0 V", "3.3 V", "2.9 V"];
                let value = v & 0x03;
                let v = get_flag_strings(value as u64, &vols);
                v.join(" ")
            }
            _ => {
                let vol = v & 0x7F;
                format!("{:.1} V", (vol as f32) / 10.0)
            }
        })
    }

    pub fn status_str(&self) -> Option<&'static str> {
        self.status().map(|s| {
            if (s & 0x40) == 0 {
                return "Unpopulated";
            }

            match s & 0x0F {
                0x00 => "Unknown",
                0x01 => "Enabled",
                0x02 => "Disabled by User",
                0x03 => "Disabled By BIOS",
                0x04 => "Idle",
                0x07 => "Other",
                _ => unreachable!(),
            }
        })
    }

    pub fn processor_upgrade_str(&self) -> Option<&'static str> {
        self.processor_upgrade().map(|u| match u {
            0x01 => "Other",
            0x02 => "Unknown",
            0x03 => "Daughter Board",
            0x04 => "ZIF Socket",
            0x05 => "Replaceable Piggy Back",
            0x06 => "None",
            0x07 => "LIF Socket",
            0x08 => "Slot 1",
            0x09 => "Slot 2",
            0x0A => "370-pin socket",
            0x0B => "Slot A",
            0x0C => "Slot M",
            0x0D => "Socket 423",
            0x0E => "Socket A (Socket 462)",
            0x0F => "Socket 478",

            0x10 => "Socket 754",
            0x11 => "Socket 940",
            0x12 => "Socket 939",
            0x13 => "Socket mPGA604",
            0x14 => "Socket LGA771",
            0x15 => "Socket LGA775",
            0x16 => "Socket S1",
            0x17 => "Socket AM2",
            0x18 => "Socket F (1207)",
            0x19 => "Socket LGA1366",
            0x1A => "Socket G34",
            0x1B => "Socket AM3",
            0x1C => "Socket C32",
            0x1D => "Socket LGA1156",
            0x1E => "Socket LGA1567",
            0x1F => "Socket PGA988A",

            0x20 => "Socket BGA1288",
            0x21 => "Socket rPGA988B",
            0x22 => "Socket BGA1023",
            0x23 => "Socket BGA1224",
            0x24 => "Socket LGA1155",
            0x25 => "Socket LGA1356",
            0x26 => "Socket LGA2011",
            0x27 => "Socket FS1",
            0x28 => "Socket FS2",
            0x29 => "Socket FM1",
            0x2A => "Socket FM2",
            0x2B => "Socket LGA2011-3",
            0x2C => "Socket LGA1356-3",
            0x2D => "Socket LGA1150",
            0x2E => "Socket BGA1168",
            0x2F => "Socket BGA1234",

            0x30 => "Socket BGA1364",
            0x31 => "Socket AM4",
            0x32 => "Socket LGA1151",
            0x33 => "Socket BGA1356",
            0x34 => "Socket BGA1440",
            0x35 => "Socket BGA1515",
            0x36 => "Socket LGA3647-1",
            0x37 => "Socket SP3",
            0x38 => "Socket SP3r2",
            0x39 => "Socket LGA2066",
            0x3A => "Socket BGA1392",
            0x3B => "Socket BGA1510",
            0x3C => "Socket BGA1528",
            0x3D => "Socket LGA4189",
            0x3E => "Socket LGA1200",
            0x3F => "Socket LGA4677",

            0x40 => "Socket LGA1700",
            0x41 => "Socket BGA1744",
            0x42 => "Socket BGA1781",
            0x43 => "Socket BGA1211",
            0x44 => "Socket BGA2422",
            0x45 => "Socket LGA1211",
            0x46 => "Socket LGA2422",
            0x47 => "Socket LGA5773",
            0x48 => "Socket BGA5773",

            _ => unreachable!(),
        })
    }

    pub fn core_count_mixed(&self) -> Option<u16> {
        self.count_mixed(self.core_count(), self.core_count2())
    }

    pub fn core_enabled_mixed(&self) -> Option<u16> {
        self.count_mixed(self.core_enabled, self.core_enabled2())
    }

    pub fn thread_count_mixed(&self) -> Option<u16> {
        self.count_mixed(self.thread_count(), self.thread_count2())
    }

    pub fn processor_characteristics_str(&self) -> Option<Vec<String>> {
        let chars = vec![
            "Reserved",
            "Unknown",
            "64-bit Capable",
            "Multi-Core",
            "Hardware Thread",
            "Execute Protection",
            "Enhanced Virtualization",
            "Power/Performance Control",
            "128-bit Capable",
            "Arm64 SoC ID",
        ];

        self.processor_characteristics()
            .map(|v| get_flag_strings(v as u64, &chars))
    }

    pub fn processor_family2_str(&self) -> Option<&'static str> {
        self.processor_family2().map(|f| match f {
            0x0100 => "ARMv7",
            0x0101 => "ARMv8",
            0x0102 => "ARMv9",
            //0x0103 => "",
            0x0104 => "SH-3",
            0x0105 => "SH-4",
            0x0118 => "ARM",
            0x0119 => "StrongARM",
            0x012C => "6x86",
            0x012D => "MediaGX",
            0x012E => "MII",
            0x0140 => "WinChip",
            0x015E => "DSP",
            0x01F4 => "Video Processor",
            0x0200 => "RISC-V RV32",
            0x0201 => "RISC-V RV64",
            0x0202 => "RISC-V RV128",
            0x0258 => "LoongArch",
            0x0259 => "Loongson 1 Processor Family",
            0x025A => "Loongson 2 Processor Family",
            0x025B => "Loongson 3 Processor Family",
            0x025C => "Loongson 2K Processor Family",
            0x025D => "Loongson 3A Processor Family",
            0x025E => "Loongson 3B Processor Family",
            0x025F => "Loongson 3C Processor Family",
            0x0260 => "Loongson 3D Processor Family",
            0x0261 => "Loongson 3E Processor Family",
            0x0262 => "Dual-Core Loongson 2K Processor 2xxx Series",
            0x026C => "Quad-Core Loongson 3A Processor 5xxx Series",
            0x026D => "Multi-Core Loongson 3A Processor 5xxx Series",
            0x026E => "Quad-Core Loongson 3B Processor 5xxx Series",
            0x026F => "Multi-Core Loongson 3B Processor 5xxx Series",
            0x0270 => "Multi-Core Loongson 3C Processor 5xxx Series",
            0x0271 => "Multi-Core Loongson 3D Processor 5xxx Series",
            _ => unreachable!(),
        })
    }

    fn count_mixed(&self, count1: Option<u8>, count2: Option<u16>) -> Option<u16> {
        count1.map(|c1| match count2 {
            Some(c2) => {
                if c1 == 0xFF {
                    c2
                } else {
                    c1 as u16
                }
            }
            _ => c1 as u16,
        })
    }
}

#[derive(SMBIOS)]
pub struct MemoryController {
    table_ty: u8,
    length: u8,
    handle: u16,
    error_detecting_method: Option<u8>,
    error_correcting_capability: Option<u8>,
    supported_interleave: Option<u8>,
    current_interleave: Option<u8>,
    maximum_memory_module_size: Option<u8>,
    supported_speeds: Option<u16>,
    supported_memory_tys: Option<u16>,
    memory_module_voltage: Option<u8>,
    num_associated_memory_slots: Option<u8>,
    #[smbios(length = "num_associated_memory_slots")]
    memory_moddule_configuration_handles: Option<Vec<u16>>,
    enabled_error_correcting_capabilities: Option<u8>,
}

impl MemoryController {
    pub fn error_detecting_method_str(&self) -> Option<&'static str> {
        self.error_detecting_method().map(|e| match e {
            0x01 => "Other",
            0x02 => "Unknown",
            0x03 => "None",
            0x04 => "8-bit Parity",
            0x05 => "32-bit ECC",
            0x06 => "64-bit ECC",
            0x07 => "128-bit ECC",
            0x08 => "CRC",
            _ => unreachable!(),
        })
    }

    pub fn error_correcting_capability_str(&self) -> Option<Vec<String>> {
        self.error_correcting_capability()
            .map(|e| self.get_error_correcting_capability(e))
    }

    pub fn supported_interleave_str(&self) -> Option<&'static str> {
        self.supported_interleave()
            .map(|i| self.get_memory_interleave(i))
    }

    pub fn current_interleave_str(&self) -> Option<&'static str> {
        self.current_interleave()
            .map(|i| self.get_memory_interleave(i))
    }

    pub fn maximum_memory_module_size_mb(&self) -> Option<u32> {
        self.maximum_memory_module_size().map(|s| 1 << s)
    }

    pub fn maximum_memory_total_size_mb(&self) -> Option<u32> {
        if let (Some(module), Some(count)) = (
            self.maximum_memory_module_size(),
            self.num_associated_memory_slots(),
        ) {
            return Some((1u32 << module) * (count as u32));
        }

        None
    }

    pub fn supported_memory_tys_str(&self) -> Option<Vec<String>> {
        self.supported_memory_tys().map(get_memory_ty_str)
    }

    pub fn enabled_error_correcting_capabilities_str(&self) -> Option<Vec<String>> {
        self.enabled_error_correcting_capabilities()
            .map(|s| self.get_error_correcting_capability(s))
    }

    fn get_error_correcting_capability(&self, value: u8) -> Vec<String> {
        let caps = [
            "Other",
            "Unknown",
            "None",
            "Single-Bit Error Correcting",
            "Double-Bit Error Correcting",
            "Error Scrubbing",
        ];

        get_flag_strings(value as u64, &caps)
    }

    fn get_memory_interleave(&self, value: u8) -> &'static str {
        match value {
            0x01 => "Other",
            0x02 => "Unknown",
            0x03 => "One-Way Interleave",
            0x04 => "Two-Way Interleave",
            0x05 => "Four-Way Interleave",
            0x06 => "Eight-Way Interleave",
            0x07 => "Sixteen-Way Interleave",
            _ => unreachable!(),
        }
    }
}

#[derive(SMBIOS)]
pub struct MemoryModule {
    table_ty: u8,
    length: u8,
    handle: u16,
    socket_designation: Option<String>,
    bank_connections: Option<u8>,
    current_speed: Option<u8>,
    current_memory_ty: Option<u16>,
    installed_size: Option<u8>,
    enabled_size: Option<u8>,
    error_status: Option<u8>,
}

impl MemoryModule {
    pub fn current_memory_ty_str(&self) -> Option<Vec<String>> {
        self.current_memory_ty().map(get_memory_ty_str)
    }
}

#[derive(SMBIOS)]
pub struct Cache {
    table_ty: u8,
    length: u8,
    handle: u16,
    socket_designation: Option<String>,
    cache_configuration: Option<u16>,
    maximum_cache_size: Option<u16>,
    installed_size: Option<u16>,
    supported_sram_ty: Option<u16>,
    current_sram_ty: Option<u16>,
    cache_speed: Option<u8>,
    error_correction_ty: Option<u8>,
    system_cache_ty: Option<u8>,
    associativity: Option<u8>,
    maximum_cache_size2: Option<u32>,
    installed_cache_size2: Option<u32>,
}

impl Cache {
    pub fn operational_mode(&self) -> Option<&'static str> {
        self.cache_configuration().map(|c| match (c & 0x0300) >> 8 {
            0b00 => "Write Through",
            0b01 => "Write Back",
            0b10 => "Varies with Memory Address",
            0b11 => "Unknown",
            _ => unreachable!(),
        })
    }

    pub fn enabled(&self) -> Option<&'static str> {
        self.cache_configuration().map(|c| match (c & 0x0080) >> 7 {
            0b0 => "Disabled",
            0b1 => "Enabled",
            _ => unreachable!(),
        })
    }

    pub fn location(&self) -> Option<&'static str> {
        self.cache_configuration().map(|c| match (c & 0x0060) >> 5 {
            0b00 => "Internal",
            0b01 => "External",
            0b10 => "Reserved",
            0b11 => "Unknown",
            _ => unreachable!(),
        })
    }

    pub fn cache_socketed(&self) -> Option<&'static str> {
        self.cache_configuration().map(|c| match (c & 0x0008) >> 3 {
            0b0 => "Not Socketed",
            0b1 => "Socketed",
            _ => unreachable!(),
        })
    }

    pub fn cache_level(&self) -> Option<u8> {
        self.cache_configuration().map(|c| ((c & 0x0007) as u8) + 1)
    }

    pub fn supported_sram_ty_str(&self) -> Option<Vec<String>> {
        self.supported_sram_ty().map(|v| self.get_sram_ty(v))
    }

    pub fn current_sram_ty_str(&self) -> Option<Vec<String>> {
        self.current_sram_ty().map(|v| self.get_sram_ty(v))
    }

    pub fn error_correction_ty_str(&self) -> Option<&'static str> {
        self.error_correction_ty().map(|t| match t {
            0x01 => "Other",
            0x02 => "Unknown",
            0x03 => "None",
            0x04 => "Parity",
            0x05 => "Single-bit ECC",
            0x06 => "Multi-bit ECC",
            _ => unreachable!(),
        })
    }

    pub fn system_cache_ty_str(&self) -> Option<&'static str> {
        self.system_cache_ty().map(|t| match t {
            0x01 => "Other",
            0x02 => "Unknown",
            0x03 => "Instruction",
            0x04 => "Data",
            0x05 => "Unified",
            _ => unreachable!(),
        })
    }

    pub fn associativity_str(&self) -> Option<&'static str> {
        self.associativity().map(|a| match a {
            0x01 => "Other",
            0x02 => "Unknown",
            0x03 => "Direct Mapped",
            0x04 => "2-way Set-Associative",
            0x05 => "4-way Set-Associative",
            0x06 => "Fully Associative",
            0x07 => "8-way Set-Associative",
            0x08 => "16-way Set-Associative",
            0x09 => "12-way Set-Associative",
            0x0A => "24-way Set-Associative",
            0x0B => "32-way Set-Associative",
            0x0C => "48-way Set-Associative",
            0x0D => "64-way Set-Associative",
            0x0E => "20-way Set-Associative",
            _ => unreachable!(),
        })
    }

    pub fn get_sram_ty(&self, value: u16) -> Vec<String> {
        let types = [
            "Other",
            "Unknown",
            "Non-Burst",
            "Burst",
            "Pipeline Burst",
            "Synchronous",
            "Asynchronous",
        ];

        get_flag_strings(value as u64, &types)
    }
}

#[derive(SMBIOS)]
pub struct PortConnector {
    table_ty: u8,
    length: u8,
    handle: u16,
    internal_reference_designator: Option<String>,
    internal_connector_ty: Option<u8>,
    external_reference_designator: Option<String>,
    external_connector_ty: Option<u8>,
    port_ty: Option<u8>,
}

impl PortConnector {
    pub fn internal_connector_ty_str(&self) -> Option<&'static str> {
        self.internal_connector_ty
            .map(|t| self.get_port_connector_ty(t))
    }

    pub fn external_connector_ty_str(&self) -> Option<&'static str> {
        self.external_connector_ty
            .map(|t| self.get_port_connector_ty(t))
    }

    pub fn port_ty_str(&self) -> Option<&'static str> {
        self.port_ty().map(|t| match t {
            0x00 => "None",
            0x01 => "Parallel Port XT/AT Compatible",
            0x02 => "Parallel Port PS/2",
            0x03 => "Parallel Port ECP",
            0x04 => "Parallel Port EPP",
            0x05 => "Parallel Port ECP/EPP",
            0x06 => "Serial Port XT/AT Compatible",
            0x07 => "Serial Port 16450 Compatible",
            0x08 => "Serial Port 16550 Compatible",
            0x09 => "Serial Port 16550A Compatible",
            0x0A => "SCSI Port",
            0x0B => "MIDI Port",
            0x0C => "Joy Stick Port",
            0x0D => "Keyboard Port",
            0x0E => "Mouse Port",
            0x0F => "SSA SCSI",
            0x10 => "USB",
            0x11 => "FireWire (IEEE P1394)",
            0x12 => "PCMCIA Type I",
            0x13 => "PCMCIA Type II",
            0x14 => "PCMCIA Type III",
            0x15 => "Card bus",
            0x16 => "Access Bus Port",
            0x17 => "SCSI II",
            0x18 => "SCSI Wide",
            0x19 => "PC-98",
            0x1A => "PC-98-Hireso",
            0x1B => "PC-H98",
            0x1C => "Video Port",
            0x1D => "Audio Port",
            0x1E => "Modem Port",
            0x1F => "Network Port",
            0x20 => "SATA",
            0x21 => "SAS",
            0x22 => "MFDP (Multi-Function Display Port)",
            0x23 => "Thunderbolt",
            0xA0 => "8251 Compatible",
            0xA1 => "8251 FIFO Compatible",
            0xFF => "Other",
            _ => unreachable!(),
        })
    }

    fn get_port_connector_ty(&self, value: u8) -> &'static str {
        match value {
            0x00 => "None",
            0x01 => "Centronics",
            0x02 => "Mini Centronics",
            0x03 => "Proprietary",
            0x04 => "DB-25 pin male",
            0x05 => "DB-25 pin female",
            0x06 => "DB-15 pin male",
            0x07 => "DB-15 pin female",
            0x08 => "DB-9 pin male",
            0x09 => "DB-9 pin female",
            0x0A => "RJ-11",
            0x0B => "RJ-45",
            0x0C => "50-pin MiniSCSI",
            0x0D => "Mini-DIN",
            0x0E => "Micro-DIN",
            0x0F => "PS/2",
            0x10 => "Infrared",
            0x11 => "HP-HIL",
            0x12 => "Access Bus (USB)",
            0x13 => "SSA SCSI",
            0x14 => "Circular DIN-8 male",
            0x15 => "Circular DIN-8 female",
            0x16 => "On Board IDE",
            0x17 => "On Board Floppy",
            0x18 => "9-pin Dual Inline (pin 10 cut)",
            0x19 => "25-pin Dual Inline (pin 26 cut)",
            0x1A => "50-pin Dual Inline",
            0x1B => "68-pin Dual Inline",
            0x1C => "On Board Sound Input from CD-ROM",
            0x1D => "Mini-Centronics Type-14",
            0x1E => "Mini-Centronics Type-26",
            0x1F => "Mini-jack (headphones)",
            0x20 => "BNC",
            0x21 => "1394",
            0x22 => "SAS/SATA Plug Receptacle",
            0x23 => "USB Type-C Receptacle",
            0xA0 => "PC-98",
            0xA1 => "PC-98Hireso",
            0xA2 => "PC-H98",
            0xA3 => "PC-98Note",
            0xA4 => "PC-98Full",
            0xFF => "Other",
            _ => unreachable!(),
        }
    }
}

#[derive(SMBIOS)]
pub struct SystemSlotsPeerDevice {
    segment_group_number: Option<u16>,
    bus_number: Option<u8>,
    device_function_number: Option<u8>,
    data_bus_width: Option<u8>,
}

impl SystemSlotsPeerDevice {
    pub fn device_number(&self) -> Option<u8> {
        self.device_function_number().map(|n| n >> 3)
    }

    pub fn function_number(&self) -> Option<u8> {
        self.device_function_number().map(|n| n & 0x07)
    }
}

#[derive(SMBIOS)]
pub struct SystemSlots {
    table_ty: u8,
    length: u8,
    handle: u16,
    slot_designation: Option<String>,
    slot_ty: Option<u8>,
    slot_data_bus_width: Option<u8>,
    current_usage: Option<u8>,
    slot_length: Option<u8>,
    slot_id: Option<u16>,
    slot_characteristics1: Option<u8>,
    slot_characteristics2: Option<u8>,
    segment_group_number: Option<u16>,
    bus_number: Option<u8>,
    device_function_number: Option<u8>,
    data_bus_width: Option<u8>,
    peer_grouping_count: Option<u8>,
    #[smbios(length = "peer_grouping_count")]
    peer_groups: Option<Vec<SystemSlotsPeerDevice>>,
    slot_information: Option<u8>,
    slot_physical_width: Option<u8>,
    slot_pitch: Option<u8>,
    slot_height: Option<u8>,
}

impl SystemSlots {
    pub fn slot_ty_str(&self) -> Option<&'static str> {
        self.slot_ty().map(|t| match t {
            0x01 => "Other",
            0x02 => "Unknown",
            0x03 => "ISA",
            0x04 => "MCA",
            0x05 => "EISA",
            0x06 => "PCI",
            0x07 => "PCMCIA",
            0x08 => "VL-VESA",
            0x09 => "Proprietary",
            0x0A => "Processor Card Slot",
            0x0B => "Proprietary Memory Card Slot",
            0x0C => "I/O Riser Card Slot",
            0x0D => "NuBus",
            0x0E => "PCI - 66MHz Capable",
            0x0F => "AGP",
            0x10 => "AGP 2X",
            0x11 => "AGP 4X",
            0x12 => "PCI-X",
            0x13 => "AGP 8X",
            0x14 => "M.2 Socket 1-DP",
            0x15 => "M.2 Socket 1-SD",
            0x16 => "M.2 Socket 2",
            0x17 => "M.2 Socket 3",
            0x18 => "MXM Type I",
            0x19 => "MXM Type II",
            0x1A => "MXM Type III (standard connector)",
            0x1B => "MXM Type III (HE connector)",
            0x1C => "MXM Type IV",
            0x1D => "MXM 3.0 Type A",
            0x1E => "MXM 3.0 Type B",
            0x1F => "PCI Express Gen 2 SFF-8639",
            0x20 => "PCI Express Gen 3 SFF-8639",
            0x21 => "PCI Express Mini 52-pin with bottom-side keep-outs",
            0x22 => "PCI Express Mini 52-pin without bottom-side keep-outs",
            0x23 => "PCI Express Mini 76-pin",
            0x24 => "PCI Express Gen 4 SFF-8639",
            0x25 => "PCI Express Gen 5 SFF-8639",
            0x26 => "OCP NIC 3.0 Small Form Factor",
            0x27 => "OCP NIC 3.0 Large Form Factor",
            0x28 => "OCP NIC Prior to 3.0",
            0x30 => "CXL Flexbus 1.0",
            0xA0 => "PC-98/C20",
            0xA1 => "PC-98/C24",
            0xA2 => "PC-98/E",
            0xA3 => "PC-98/Local Bus",
            0xA4 => "PC-98/Card",
            0xA5 => "PCI Express",
            0xA6 => "PCI Express x1",
            0xA7 => "PCI Express x2",
            0xA8 => "PCI Express x4",
            0xA9 => "PCI Express x8",
            0xAA => "PCI Express x16",
            0xAB => "PCI Express Gen 2",
            0xAC => "PCI Express Gen 2 x1",
            0xAD => "PCI Express Gen 2 x2",
            0xAE => "PCI Express Gen 2 x4",
            0xAF => "PCI Express Gen 2 x8",
            0xB0 => "PCI Express Gen 2 x16",
            0xB1 => "PCI Express Gen 3",
            0xB2 => "PCI Express Gen 3 x1",
            0xB3 => "PCI Express Gen 3 x2",
            0xB4 => "PCI Express Gen 3 x4",
            0xB5 => "PCI Express Gen 3 x8",
            0xB6 => "PCI Express Gen 3 x16",
            // 0xB7 => "",
            0xB8 => "PCI Express Gen 4",
            0xB9 => "PCI Express Gen 4 x1",
            0xBA => "PCI Express Gen 4 x2",
            0xBB => "PCI Express Gen 4 x4",
            0xBC => "PCI Express Gen 4 x8",
            0xBD => "PCI Express Gen 4 x16",
            0xBE => "PCI Express Gen 5",
            0xBF => "PCI Express Gen 5 x1",
            0xC0 => "PCI Express Gen 5 x2",
            0xC1 => "PCI Express Gen 5 x4",
            0xC2 => "PCI Express Gen 5 x8",
            0xC3 => "PCI Express Gen 5 x16",
            0xC4 => "PCI Express Gen 6 and Beyond",
            0xC5 => "Enterprise and Datacenter 1U E1 Form Factor Slot",
            0xC6 => "Enterprise and Datacenter 3\" E3 Form Factor Slot",
            _ => unreachable!(),
        })
    }

    pub fn slot_data_bus_width_str(&self) -> Option<&'static str> {
        self.slot_data_bus_width()
            .map(|t| self.get_data_bus_width_str(t))
    }

    pub fn current_usage_str(&self) -> Option<&'static str> {
        self.current_usage().map(|u| match u {
            0x01 => "Other",
            0x02 => "Unknown",
            0x03 => "Available",
            0x04 => "In use",
            0x05 => "Unavailable",
            _ => unreachable!(),
        })
    }

    pub fn slot_length_str(&self) -> Option<&'static str> {
        self.slot_length().map(|l| match l {
            0x01 => "Other",
            0x02 => "Unknown",
            0x03 => "Short Length",
            0x04 => "Long Length",
            0x05 => "2.5\" drive form factor",
            0x06 => "2.5\" drive form factor",
            _ => unreachable!(),
        })
    }

    pub fn slot_characteristics1_str(&self) -> Option<Vec<String>> {
        let chars = vec![
            "Characteristics unknown",
            "Provides 5.0 volts",
            "Provides 3.3 volts",
            "Slot’s opening is shared with another slot",
            "PC Card slot supports PC Card-16",
            "PC Card slot supports CardBus",
            "PC Card slot supports Zoom Video",
            "PC Card slot supports Modem Ring Resume",
        ];

        self.slot_characteristics1()
            .map(|v| get_flag_strings(v as u64, &chars))
    }

    pub fn slot_characteristics2_str(&self) -> Option<Vec<String>> {
        let chars = vec![
            "PCI slot supports Power Management Event signal",
            "Slot supports hot-plug devices",
            "PCI slot supports SMBus signal",
            "PCIe slot supports bifurcation",
            "Slot supports async/surprise removal",
            "Flexbus slot, CXL 1.0 capable",
            "Flexbus slot, CXL 2.0 capable",
            "Reserved",
        ];

        self.slot_characteristics2()
            .map(|v| get_flag_strings(v as u64, &chars))
    }

    pub fn device_number(&self) -> Option<u8> {
        self.device_function_number().map(|n| n >> 3)
    }

    pub fn function_number(&self) -> Option<u8> {
        self.device_function_number().map(|n| n & 0x07)
    }

    pub fn slot_physical_width_str(&self) -> Option<&'static str> {
        self.slot_physical_width()
            .map(|p| self.get_data_bus_width_str(p))
    }

    pub fn slot_height_str(&self) -> Option<&'static str> {
        self.slot_height().map(|h| match h {
            0x00 => "Not applicable",
            0x01 => "Other",
            0x02 => "Unknown",
            0x03 => "Full height",
            0x04 => "Low-profile",
            _ => unreachable!(),
        })
    }

    pub fn get_data_bus_width_str(&self, value: u8) -> &'static str {
        match value {
            0x01 => "Other",
            0x02 => "Unknown",
            0x03 => "8 bit",
            0x04 => "16 bit",
            0x05 => "32 bit",
            0x06 => "64 bit",
            0x07 => "128 bit",
            0x08 => "1x or x1",
            0x09 => "2x or x2",
            0x0A => "4x or x4",
            0x0B => "8x or x8",
            0x0C => "12x or x12",
            0x0D => "16x or x16",
            0x0E => "32x or x32",
            _ => unreachable!(),
        }
    }
}

#[derive(SMBIOS)]
pub struct OnBoardDevicesDevice {
    device_ty: Option<u8>,
    description_string: Option<String>,
}

#[derive(SMBIOS)]
pub struct OnBoardDevices {
    table_ty: u8,
    length: u8,
    handle: u16,
    #[smbios(length = "Some((length - 4) / 2)")]
    devices: Option<Vec<OnBoardDevicesDevice>>,
}

impl OnBoardDevices {
    pub fn get_device(&self) -> Option<Vec<(bool, &'static str, &str)>> {
        self.devices().map(|devices| {
            let mut devs = vec![];
            for device in devices {
                if let (Some(ty), Some(desc)) = (device.device_ty(), device.description_string()) {
                    let enabled = 0x80 & ty == 0x80;
                    let dev = self.get_device_ty_str(0x7F & ty);
                    devs.push((enabled, dev, desc));
                }
            }
            devs
        })
    }

    fn get_device_ty_str(&self, value: u8) -> &'static str {
        match value {
            0x01 => "Other",
            0x02 => "Unknown",
            0x03 => "Video",
            0x04 => "SCSI Controller",
            0x05 => "Ethernet",
            0x06 => "Tocken Ring",
            0x07 => "Sound",
            0x08 => "PATA Controller",
            0x09 => "SATA Controller",
            0x0A => "SAS Controller",
            _ => unreachable!(),
        }
    }
}

#[derive(SMBIOS)]
pub struct OemStrings {
    table_ty: u8,
    length: u8,
    handle: u16,
    count: Option<u8>,
}

#[derive(SMBIOS)]
pub struct SystemConfigurationOptions {
    table_ty: u8,
    length: u8,
    handle: u16,
    count: Option<u8>,
}

#[derive(SMBIOS)]
pub struct BiosLanguage {
    table_ty: u8,
    length: u8,
    handle: u16,
    installable_languages: Option<u8>,
    flags: Option<u8>,
    reserved: Option<[u8; 15]>,
    current_language: Option<u8>,
}

impl BiosLanguage {
    pub fn get_language_format(&self) -> Option<&'static str> {
        self.flags().map(|f| {
            if (0x01 & f) == 0x01 {
                "Abbreviated"
            } else {
                "Long"
            }
        })
    }
}

#[derive(SMBIOS)]
pub struct GroupAssociationsItem {
    item_ty: Option<u8>,
    item_handle: Option<u16>,
}

#[derive(SMBIOS)]
pub struct GroupAssociations {
    table_ty: u8,
    length: u8,
    handle: u16,
    group_name: Option<String>,
    #[smbios(length = "Some(((length - 5) / 3) as u8)")]
    items: Option<Vec<GroupAssociationsItem>>,
}

#[derive(SMBIOS)]
pub struct SystemEventLog {
    table_ty: u8,
    length: u8,
    handle: u16,
    log_area_length: Option<u16>,
    log_header_start_offset: Option<u16>,
    log_data_start_offset: Option<u16>,
    access_method: Option<u8>,
    log_status: Option<u8>,
    log_change_token: Option<u32>,
    access_method_address: Option<u32>,
    log_header_format: Option<u8>,
    num_supported_log_ty_desc: Option<u8>,
    length_each_log_ty_desc: Option<u8>,
    #[smbios(
        length = "num_supported_log_ty_desc.map(|n| length_each_log_ty_desc.map(|l| n * l)).flatten()"
    )]
    list_supported_event_log_ty_desc: Option<Vec<u8>>,
}

#[derive(SMBIOS)]
pub struct PhysicalMemoryArray {
    table_ty: u8,
    length: u8,
    handle: u16,
    location: Option<u8>,
    array_use: Option<u8>,
    memory_error_correction: Option<u8>,
    maximum_capacity: Option<u32>,
    memory_error_information_handle: Option<u16>,
    num_memory_devices: Option<u16>,
    ex_maximum_capacity: Option<u64>,
}

impl PhysicalMemoryArray {
    pub fn location_str(&self) -> Option<&'static str> {
        self.location.map(|l| match l {
            0x01 => "Other",
            0x02 => "Unknown",
            0x03 => "System board or motherboard",
            0x04 => "ISA add-on card",
            0x05 => "EISA add-on card",
            0x06 => "PCI add-on card",
            0x07 => "MCA add-on card",
            0x08 => "PCMCIA add-on card",
            0x09 => "Proprietary add-on card",
            0x0A => "NuBus",
            0xA0 => "PC-98/C20 add-on card",
            0xA1 => "PC-98/C24 add-on card",
            0xA2 => "PC-98/E add-on card",
            0xA3 => "PC-98/Local bus add-on card",
            0xA4 => "CXL add-on card",
            _ => unreachable!(),
        })
    }

    pub fn array_use_str(&self) -> Option<&'static str> {
        self.array_use().map(|u| match u {
            0x01 => "Other",
            0x02 => "Unknown",
            0x03 => "System memory",
            0x04 => "Video memory",
            0x05 => "Flash memory",
            0x06 => "Non-volatile RAM",
            0x07 => "Cache memory",
            _ => unreachable!(),
        })
    }

    pub fn memory_error_correction_str(&self) -> Option<&'static str> {
        self.memory_error_correction().map(|e| match e {
            0x01 => "Other",
            0x02 => "Unknown",
            0x03 => "None",
            0x04 => "Parity",
            0x05 => "Single-bit ECC",
            0x06 => "Multi-bit ECC",
            0x07 => "CRC",
            _ => unreachable!(),
        })
    }
}

#[derive(SMBIOS)]
pub struct MemoryDevice {
    table_ty: u8,
    length: u8,
    handle: u16,
    physical_memory_array_handle: Option<u16>,
    memory_error_information_handle: Option<u16>,
    total_width: Option<u16>,
    data_width: Option<u16>,
    size: Option<u16>,
    form_factor: Option<u8>,
    device_set: Option<u8>,
    device_locator: Option<String>,
    bank_locator: Option<String>,
    memory_ty: Option<u8>,
    ty_detail: Option<u16>,
    speed: Option<u16>,
    manufacturer: Option<String>,
    serial_number: Option<String>,
    asset_tag: Option<String>,
    part_number: Option<String>,
    attributes: Option<u8>,
    extended_size: Option<u32>,
    configured_memory_speed: Option<u16>,
    minimum_voltage: Option<u16>,
    maximum_voltage: Option<u16>,
    configured_voltage: Option<u16>,
    memory_technology: Option<u8>,
    memory_operating_mode_capability: Option<u16>,
    firmware_version: Option<String>,
    module_manufacturer_id: Option<u16>,
    module_product_id: Option<u16>,
    memory_subsystem_ctrl_manufacturer_id: Option<u16>,
    memory_subsystem_ctrl_product_id: Option<u16>,
    non_volatile_size: Option<u64>,
    volatile_size: Option<u64>,
    cache_size: Option<u64>,
    logical_size: Option<u64>,
    extended_speed: Option<u32>,
    extended_configured_memory_speed: Option<u32>,
}

impl MemoryDevice {
    pub fn form_factor_str(&self) -> Option<&'static str> {
        self.form_factor().map(|f| match f {
            0x01 => "Other",
            0x02 => "Unknown",
            0x03 => "SIMM",
            0x04 => "SIP",
            0x05 => "Chip",
            0x06 => "DIP",
            0x07 => "ZIP",
            0x08 => "Proprietary Card",
            0x09 => "DIMM",
            0x0A => "TSOP",
            0x0B => "Row of chips",
            0x0C => "RIMM",
            0x0D => "SODIMM",
            0x0E => "SRIMM",
            0x0F => "FB-DIMM",
            0x10 => "Die",
            _ => unreachable!(),
        })
    }

    pub fn memory_ty_str(&self) -> Option<&'static str> {
        self.memory_ty().map(|t| match t {
            0x01 => "Other",
            0x02 => "Unknown",
            0x03 => "DRAM",
            0x04 => "EDRAM",
            0x05 => "VRAM",
            0x06 => "SRAM",
            0x07 => "RAM",
            0x08 => "ROM",
            0x09 => "FLASH",
            0x0A => "EEPROM",
            0x0B => "FEPROM",
            0x0C => "EPROM",
            0x0D => "CDRAM",
            0x0E => "3DRAM",
            0x0F => "SDRAM",
            0x10 => "SGRAM",
            0x11 => "RDRAM",
            0x12 => "DDR",
            0x13 => "DDR2",
            0x14 => "DDR2 FB-DIMM",
            0x18 => "DDR3",
            0x19 => "FBD2",
            0x1A => "DDR4",
            0x1B => "LPDDR",
            0x1C => "LPDDR2",
            0x1D => "LPDDR3",
            0x1E => "LPDDR4",
            0x1F => "Logical non-volatile device",
            0x20 => "HBM",
            0x21 => "HBM2",
            0x22 => "DDR5",
            0x23 => "LPDDR5",
            0x24 => "HBM3",
            _ => unreachable!(),
        })
    }

    pub fn ty_detail_str(&self) -> Option<Vec<String>> {
        let details = vec![
            "Reserved",
            "Other",
            "Unknown",
            "Fast-paged",
            "Static column",
            "Pseudo-static",
            "RAMBUS",
            "Synchronous",
            "CMOS",
            "EDO",
            "Window DRAM",
            "Cache DRAM",
            "Non-volatile",
            "Registered",
            "Unbuffered",
            "LRDIMM",
        ];

        self.ty_detail()
            .map(|v| get_flag_strings(v as u64, &details))
    }

    pub fn memory_technology_str(&self) -> Option<&'static str> {
        self.memory_technology().map(|t| match t {
            0x01 => "Other",
            0x02 => "Unknown",
            0x03 => "DRAM",
            0x04 => "NVDIMM-N",
            0x05 => "NVDIMM-F",
            0x06 => "NVDIMM-P",
            0x07 => "Intel Optane",
            _ => unreachable!(),
        })
    }

    pub fn memory_operating_mode_capability_str(&self) -> Option<Vec<String>> {
        let caps = vec![
            "Reserved",
            "Other",
            "Unknown",
            "Volatile memory",
            "Byte-accessible persistent memory",
            "Block-accessible persistent memory",
        ];

        self.ty_detail().map(|v| get_flag_strings(v as u64, &caps))
    }
}

#[derive(SMBIOS)]
pub struct B32MemoryError {
    table_ty: u8,
    length: u8,
    handle: u16,
    error_ty: Option<u8>,
    error_granularity: Option<u8>,
    error_operation: Option<u8>,
    vendor_syndrome: Option<u32>,
    memory_array_error_address: Option<u32>,
    device_error_address: Option<u32>,
    error_resolution: Option<u32>,
}

impl B32MemoryError {
    pub fn error_ty_str(&self) -> Option<&'static str> {
        self.error_ty().map(|t| match t {
            0x01 => "Other",
            0x02 => "Unknown",
            0x03 => "OK",
            0x04 => "Bad read",
            0x05 => "Parity error",
            0x06 => "Single-bit error",
            0x07 => "Double-bit error",
            0x08 => "Multi-bit error",
            0x09 => "Nibble error",
            0x0A => "Checksum error",
            0x0B => "CRC error",
            0x0C => "Corrected single-bit error",
            0x0D => "Corrected error",
            0x0E => "Uncorrectable error",
            _ => unreachable!(),
        })
    }

    pub fn error_granularity_str(&self) -> Option<&'static str> {
        self.error_granularity().map(|t| match t {
            0x01 => "Other",
            0x02 => "Unknown",
            0x03 => "Device level",
            0x04 => "Memory partition level",
            _ => unreachable!(),
        })
    }

    pub fn error_operation_str(&self) -> Option<&'static str> {
        self.error_operation().map(|t| match t {
            0x01 => "Other",
            0x02 => "Unknown",
            0x03 => "Read",
            0x04 => "Write",
            0x05 => "Partial write",
            _ => unreachable!(),
        })
    }
}

#[derive(SMBIOS)]
pub struct MemoryArrayMappedAddress {
    table_ty: u8,
    length: u8,
    handle: u16,
    starting_address: Option<u32>,
    ending_address: Option<u32>,
    memory_array_handle: Option<u16>,
    partition_width: Option<u8>,
    ex_starting_address: Option<u64>,
    ex_ending_address: Option<u64>,
}

#[derive(SMBIOS)]
pub struct MemoryDeviceMappedAddress {
    table_ty: u8,
    length: u8,
    handle: u16,
    starting_address: Option<u32>,
    ending_address: Option<u32>,
    memory_device_handle: Option<u16>,
    memory_array_mapped_address_handle: Option<u16>,
    partition_row_position: Option<u8>,
    interleave_position: Option<u8>,
    interleaved_data_depth: Option<u8>,
    ex_starting_address: Option<u64>,
    ex_ending_address: Option<u64>,
}

#[derive(SMBIOS)]
pub struct BuiltinPointingDevice {
    table_ty: u8,
    length: u8,
    handle: u16,
    ty: Option<u8>,
    interface: Option<u8>,
    num_buttons: Option<u8>,
}

#[derive(SMBIOS)]
pub struct PortableBattery {
    table_ty: u8,
    length: u8,
    handle: u16,
    location: Option<String>,
    manufacturer: Option<String>,
    manufacturer_date: Option<String>,
    serial_number: Option<String>,
    device_name: Option<String>,
    device_chemistry: Option<u8>,
    design_capacity: Option<u16>,
    design_voltage: Option<u16>,
    sbds_version_number: Option<String>,
    maximum_error_in_battery_data: Option<u8>,
    sbds_serial_number: Option<u16>,
    sbds_manufacturer_date: Option<u16>,
    sbds_device_chemistry: Option<String>,
    design_capacity_multiplier: Option<u8>,
    oem_specific: Option<u32>,
}

#[derive(SMBIOS)]
pub struct SystemReset {
    table_ty: u8,
    length: u8,
    handle: u16,
    capabilities: Option<u8>,
    reset_count: Option<u16>,
    reset_limit: Option<u16>,
    timer_interval: Option<u16>,
    timeout: Option<u16>,
}

impl SystemReset {
    pub fn enabled(&self) -> Option<bool> {
        self.capabilities().map(|cap| (cap & 0x01) == 0x01)
    }

    pub fn boot_option(&self) -> Option<&'static str> {
        self.capabilities()
            .map(|cap| self.get_boot_option(cap >> 1))
    }

    pub fn boot_option_on_limit(&self) -> Option<&'static str> {
        self.capabilities()
            .map(|cap| self.get_boot_option(cap >> 3))
    }

    pub fn watchdog_timer(&self) -> Option<bool> {
        self.capabilities().map(|cap| (cap & 0x20) == 0x20)
    }

    fn get_boot_option(&self, value: u8) -> &'static str {
        match value & 0x03 {
            0x01 => "Operating system",
            0x02 => "System utilities",
            0x03 => "Do not reboot",
            _ => unreachable!(),
        }
    }
}

#[derive(SMBIOS)]
pub struct HardwareSecurity {
    table_ty: u8,
    length: u8,
    handle: u16,
    hardware_security_settings: Option<u8>,
}

#[derive(SMBIOS)]
pub struct SystemPowerControls {
    table_ty: u8,
    length: u8,
    handle: u16,
    next_scheduled_power_on_month: Option<u8>,
    next_scheduled_power_on_day_of_month: Option<u8>,
    next_scheduled_power_on_hour: Option<u8>,
    next_scheduled_power_on_minute: Option<u8>,
    next_scheduled_power_on_second: Option<u8>,
}

#[derive(SMBIOS)]
pub struct VoltageProbe {
    table_ty: u8,
    length: u8,
    handle: u16,
    description: Option<String>,
    location_and_status: Option<u8>,
    maximum_value: Option<u16>,
    minimum_value: Option<u16>,
    resolution: Option<u16>,
    tolerance: Option<u16>,
    accuracy: Option<u16>,
    oem_defined: Option<u32>,
    nominal_value: Option<u16>,
}

impl VoltageProbe {
    pub fn location_str(&self) -> Option<&'static str> {
        self.location_and_status().map(|l| match l & 0x1F {
            0x01 => "Other",
            0x02 => "Unknown",
            0x03 => "Processor",
            0x04 => "Disk",
            0x05 => "Peripheral Bay",
            0x06 => "System Management Module",
            0x07 => "Motherboard",
            0x08 => "Memory Module",
            0x09 => "Processor Module",
            0x0A => "Power Unit",
            0x0B => "Add-in Card",
            _ => unreachable!(),
        })
    }

    pub fn status_str(&self) -> Option<&'static str> {
        self.location_and_status().map(|s| match s >> 5 {
            0x01 => "Other",
            0x02 => "Unknown",
            0x03 => "OK",
            0x04 => "Non-critical",
            0x05 => "Critical",
            0x06 => "Non-recoverable",
            _ => unreachable!(),
        })
    }
}

#[derive(SMBIOS)]
pub struct CoolingDevice {
    table_ty: u8,
    length: u8,
    handle: u16,
    temperature_probe_handle: Option<u16>,
    device_ty_and_status: Option<u8>,
    cooling_unit_group: Option<u8>,
    oem_defined: Option<u32>,
    nominal_speed: Option<u16>,
    description: Option<String>,
}

impl CoolingDevice {
    pub fn device_ty_str(&self) -> Option<&'static str> {
        self.device_ty_and_status().map(|t| match t & 0x1F {
            0x01 => "Other",
            0x02 => "Unknown",
            0x03 => "Fan",
            0x04 => "Centrifugal Blower",
            0x05 => "Chip Fan",
            0x06 => "Cabinet Fan",
            0x07 => "Power Supply Fan",
            0x08 => "Heat Pipe",
            0x09 => "Integrated Refrigeration",
            0x0A => "Active Cooling",
            0x0B => "Passive Cooling",
            _ => unreachable!(),
        })
    }

    pub fn status_str(&self) -> Option<&'static str> {
        self.device_ty_and_status().map(|s| match s >> 5 {
            0x01 => "Other",
            0x02 => "Unknown",
            0x03 => "OK",
            0x04 => "Non-critical",
            0x05 => "Critical",
            0x06 => "Non-recoverable",
            _ => unreachable!(),
        })
    }
}

#[derive(SMBIOS)]
pub struct TemperatureProbe {
    table_ty: u8,
    length: u8,
    handle: u16,
    description: Option<String>,
    location_and_status: Option<u8>,
    maximum_value: Option<u16>,
    minimum_value: Option<u16>,
    resolution: Option<u16>,
    tolerance: Option<u16>,
    accuracy: Option<u16>,
    oem_defined: Option<u32>,
    nominal_value: Option<u16>,
}

impl TemperatureProbe {
    pub fn location_str(&self) -> Option<&'static str> {
        self.location_and_status().map(|l| match l & 0x1F {
            0x01 => "Other",
            0x02 => "Unknown",
            0x03 => "Processor",
            0x04 => "Disk",
            0x05 => "Peripheral Bay",
            0x06 => "System Management Module",
            0x07 => "Motherboard",
            0x08 => "Memory Module",
            0x09 => "Processor Module",
            0x0A => "Power Unit",
            0x0B => "Add-in Card",
            0x0C => "Front Panel Board",
            0x0D => "Back Panel Board",
            0x0E => "Power System Board",
            0x0F => "Drive Back Plane",
            _ => unreachable!(),
        })
    }

    pub fn status_str(&self) -> Option<&'static str> {
        self.location_and_status().map(|s| match s >> 5 {
            0x01 => "Other",
            0x02 => "Unknown",
            0x03 => "OK",
            0x04 => "Non-critical",
            0x05 => "Critical",
            0x06 => "Non-recoverable",
            _ => unreachable!(),
        })
    }
}

#[derive(SMBIOS)]
pub struct ElectricalCurrentProbe {
    table_ty: u8,
    length: u8,
    handle: u16,
    description: Option<String>,
    location_and_status: Option<u8>,
    maximum_value: Option<u16>,
    minimum_value: Option<u16>,
    resolution: Option<u16>,
    tolerance: Option<u16>,
    accuracy: Option<u16>,
    oem_defined: Option<u32>,
    nominal_value: Option<u16>,
}

impl ElectricalCurrentProbe {
    pub fn location_str(&self) -> Option<&'static str> {
        self.location_and_status().map(|l| match l & 0x1F {
            0x01 => "Other",
            0x02 => "Unknown",
            0x03 => "Processor",
            0x04 => "Disk",
            0x05 => "Peripheral Bay",
            0x06 => "System Management Module",
            0x07 => "Motherboard",
            0x08 => "Memory Module",
            0x09 => "Processor Module",
            0x0A => "Power Unit",
            0x0B => "Add-in Card",
            _ => unreachable!(),
        })
    }

    pub fn status_str(&self) -> Option<&'static str> {
        self.location_and_status().map(|s| match s >> 5 {
            0x01 => "Other",
            0x02 => "Unknown",
            0x03 => "OK",
            0x04 => "Non-critical",
            0x05 => "Critical",
            0x06 => "Non-recoverable",
            _ => unreachable!(),
        })
    }
}

#[derive(SMBIOS)]
pub struct OutOfBandRemoteAccess {
    table_ty: u8,
    length: u8,
    handle: u16,
    manufacturer_name: Option<String>,
    connections: Option<u8>,
}

#[derive(SMBIOS)]
pub struct SystemBoot {
    table_ty: u8,
    length: u8,
    handle: u16,
    reserved: Option<[u8; 6]>,
    #[smbios(length = "Some(length - 10)")]
    boot_status: Option<Vec<u8>>,
}

impl SystemBoot {
    pub fn boot_status_str(&self) -> Option<&'static str> {
        self.boot_status().map(|s| match s[0] {
            0x00 => "No errors detected",
            0x01 => "No bootable media",
            0x02 => "Operating system failed to load",
            0x03 => "Firmware-detected hardware failure,",
            0x04 => "Operating system-detected hardware failure",
            0x05 => "User-requested boot",
            0x06 => "System security violation",
            0x07 => "Previously requested image",
            0x08 => "System watchdog timer expired",
            0x80..=0xBF => "Vendor/OEM-specific implementations",
            0xC0..=0xFF => "Product-specific implementations",
            _ => unreachable!(),
        })
    }
}

#[derive(SMBIOS)]
pub struct B64MemoryError {
    table_ty: u8,
    length: u8,
    handle: u16,
    error_ty: Option<u8>,
    error_granularity: Option<u8>,
    error_operation: Option<u8>,
    vendor_syndrome: Option<u32>,
    memory_array_error_address: Option<u64>,
    device_error_address: Option<u64>,
    error_resolution: Option<u64>,
}

#[derive(SMBIOS)]
pub struct ManagementDevice {
    table_ty: u8,
    length: u8,
    handle: u16,
    description: Option<String>,
    ty: Option<u8>,
    address: Option<u32>,
    address_ty: Option<u8>,
}

impl ManagementDevice {
    pub fn ty_str(&self) -> Option<&'static str> {
        self.ty().map(|s| match s {
            0x01 => "Other",
            0x02 => "Unknown",
            0x03 => "National Semiconductor LM75",
            0x04 => "National Semiconductor LM78",
            0x05 => "National Semiconductor LM79",
            0x06 => "National Semiconductor LM80",
            0x07 => "National Semiconductor LM81",
            0x08 => "Analog Devices ADM9240",
            0x09 => "Dallas Semiconductor DS1780",
            0x0A => "Maxim 1617",
            0x0B => "Genesys GL518SM",
            0x0C => "Winbond W83781D",
            0x0D => "Holtek HT82H791",
            _ => unreachable!(),
        })
    }

    pub fn address_ty_str(&self) -> Option<&'static str> {
        self.ty().map(|s| match s {
            0x01 => "Other",
            0x02 => "Unknown",
            0x03 => "I/O Port",
            0x04 => "Memory",
            0x05 => "SM Bus",
            _ => unreachable!(),
        })
    }
}

#[derive(SMBIOS)]
pub struct ManagementDeviceComponent {
    table_ty: u8,
    length: u8,
    handle: u16,
    description: Option<String>,
    management_device_handle: Option<u16>,
    component_handle: Option<u16>,
    threshold_handle: Option<u16>,
}

#[derive(SMBIOS)]
pub struct ManagementDeviceThresholdData {
    table_ty: u8,
    length: u8,
    handle: u16,
    lower_threshold_non_critical: Option<u16>,
    upper_threshold_non_critical: Option<u16>,
    lower_threshold_critical: Option<u16>,
    upper_threshold_critical: Option<u16>,
    lower_threshold_non_recoverable: Option<u16>,
    upper_threshold_non_recoverable: Option<u16>,
}

#[derive(SMBIOS)]
pub struct MemoryChannel {
    table_ty: u8,
    length: u8,
    handle: u16,
    channel_ty: Option<u8>,
    maximum_channel_load: Option<u8>,
    memory_device_count: Option<u8>,
    meory1_device_load: Option<u8>,
    memory_device1_handle: Option<u16>,
    #[smbios(length = "memory_device_count")]
    memory_device_load: Option<Vec<u8>>,
    #[smbios(length = "memory_device_count")]
    memory_device_handle: Option<Vec<u16>>,
}

#[derive(SMBIOS)]
pub struct IpmiDevice {
    table_ty: u8,
    length: u8,
    handle: u16,
    interface_ty: Option<u8>,
    ipmi_specification_revision: Option<u8>,
    i2c_target_address: Option<u8>,
    nv_storage_device_adderss: Option<u8>,
    base_address: Option<u64>,
    base_address_modifier: Option<u8>,
    interrupt_number: Option<u8>,
}

#[derive(SMBIOS)]
pub struct SystemPowerSupply {
    table_ty: u8,
    length: u8,
    handle: u16,
    power_unit_group: Option<u8>,
    location: Option<String>,
    device_name: Option<String>,
    manufacturer: Option<String>,
    serial_number: Option<String>,
    asset_tag_number: Option<String>,
    model_part_number: Option<String>,
    revision_level: Option<String>,
    max_power_capacity: Option<u16>,
    power_supply_characteristics: Option<u16>,
    input_voltage_probe_handle: Option<u16>,
    cooling_device_handle: Option<u16>,
    input_current_probe_handle: Option<u16>,
}

impl SystemPowerSupply {
    pub fn hot_replaceable(&self) -> Option<bool> {
        self.power_supply_characteristics.map(|c| c & 0x01 != 0x00)
    }

    pub fn present(&self) -> Option<bool> {
        self.power_supply_characteristics.map(|c| c & 0x02 != 0x00)
    }

    pub fn range_switching(&self) -> Option<u8> {
        self.power_supply_characteristics
            .map(|c| ((c >> 3) & 0x0F) as u8)
    }

    pub fn range_switching_str(&self) -> Option<&'static str> {
        self.status().map(|s| match s {
            0x01 => "Other",
            0x02 => "Unknown",
            0x03 => "Manual",
            0x04 => "Auto-switch",
            0x05 => "Wide range",
            0x06 => "Not applicable",
            _ => unreachable!(),
        })
    }

    pub fn status(&self) -> Option<u8> {
        self.power_supply_characteristics
            .map(|c| ((c >> 7) & 0x07) as u8)
    }

    pub fn status_str(&self) -> Option<&'static str> {
        self.status().map(|s| match s {
            0x01 => "Other",
            0x02 => "Unknown",
            0x03 => "OK",
            0x04 => "Non-critical",
            0x05 => "Critical",
            _ => unreachable!(),
        })
    }

    pub fn ty(&self) -> Option<u8> {
        self.power_supply_characteristics
            .map(|c| ((c >> 10) & 0x0F) as u8)
    }

    pub fn ty_str(&self) -> Option<&'static str> {
        self.ty().map(|s| match s {
            0x01 => "Other",
            0x02 => "Unknown",
            0x03 => "Linear",
            0x04 => "Switching",
            0x05 => "Battery",
            0x06 => "UPS",
            0x07 => "Converter",
            0x08 => "Regulator",
            _ => unreachable!(),
        })
    }

    pub fn unplugged(&self) -> Option<bool> {
        self.power_supply_characteristics.map(|c| c & 0x04 != 0x00)
    }
}

#[derive(SMBIOS)]
pub struct Additional {
    table_ty: u8,
    length: u8,
    handle: u16,
    num_additional_information_entities: Option<u8>,
    #[smbios(length = "num_additional_information_entities")]
    additional_information_entities: Option<Vec<u8>>,
}

#[derive(SMBIOS)]
pub struct OnboardDevicesExtended {
    table_ty: u8,
    length: u8,
    handle: u16,
    reference_designation: Option<String>,
    device_ty: Option<u8>,
    device_ty_instance: Option<u8>,
    segment_group_number: Option<u16>,
    bus_number: Option<u8>,
    device_function_number: Option<u8>,
}

impl OnboardDevicesExtended {
    pub fn device_status(&self) -> Option<bool> {
        self.device_ty().map(|t| (t & 0x80) == 0x80)
    }

    pub fn device_ty_str(&self) -> Option<&'static str> {
        self.device_ty().map(|t| match t & 0x3F {
            0x01 => "Other",
            0x02 => "Unknown",
            0x03 => "Video",
            0x04 => "SCSI Controller",
            0x05 => "Ethernet",
            0x06 => "Token Ring",
            0x07 => "Sound",
            0x08 => "PATA Controller",
            0x09 => "SATA Controller",
            0x0A => "SAS Controller",
            0x0B => "Wireless LAN",
            0x0C => "Bluetooth",
            0x0D => "WWAN",
            0x0E => "eMMC",
            0x0F => "NVMe Controller",
            0x10 => "UFS Controller",
            _ => unreachable!(),
        })
    }

    pub fn device_number(&self) -> Option<u8> {
        self.device_function_number().map(|n| n >> 3)
    }

    pub fn function_number(&self) -> Option<u8> {
        self.device_function_number().map(|n| n & 0x07)
    }
}

#[derive(SMBIOS)]
pub struct ManagementControllerHostInterface {
    table_ty: u8,
    length: u8,
    handle: u16,
    interface_ty: Option<u8>,
    interface_ty_specific_data_length: Option<u8>,
    #[smbios(length = "interface_ty_specific_data_length")]
    interface_ty_specific_data: Option<Vec<u8>>,
    num_protocol_records: Option<u8>,
    #[smbios(length = "num_protocol_records")]
    protocol_records: Option<Vec<u8>>,
}

#[derive(SMBIOS)]
pub struct TpmDevice {
    table_ty: u8,
    length: u8,
    handle: u16,
    vendor_id: Option<[u8; 4]>,
    major_spec_version: Option<u8>,
    minor_spec_version: Option<u8>,
    firmware_version1: Option<u32>,
    firmawre_version2: Option<u32>,
    description: Option<String>,
    characteristics: Option<u64>,
    oem_defined: Option<u32>,
}

impl TpmDevice {
    pub fn characteristics_str(&self) -> Option<Vec<String>> {
        let chars = [
            "",
            "",
            "",
            "TPM Device Characteristics are not supported",
            "Family configurable via firmware update",
            "Family configurable via platform software support",
            "Family configurable via OEM proprietary mechanism",
        ];

        self.characteristics().map(|v| get_flag_strings(v, &chars))
    }

    pub fn firmware_version(&self) -> Option<String> {
        match self.major_spec_version() {
            Some(0x01) => {
                if let Some(v) = self.firmware_version1() {
                    return Some(format!("{}.{}", (v >> 16) & 0xFF, v >> 24));
                }

                None
            }
            Some(0x02) => {
                if let Some(v) = self.firmware_version1() {
                    return Some(format!("{}.{}", v >> 16, v & 0xFFFF));
                }

                None
            }
            _ => None,
        }
    }

    pub fn spec_version(&self) -> Option<String> {
        if let (Some(major), Some(minor)) = (self.major_spec_version(), self.minor_spec_version()) {
            return Some(format!("{major}.{minor}"));
        }

        None
    }

    pub fn vendor_id_str(&self) -> Option<String> {
        self.vendor_id.map(|id| {
            id.map(|c| if c.is_ascii() { c as char } else { '.' })
                .iter()
                .collect::<String>()
        })
    }
}

#[derive(SMBIOS)]
pub struct ProcessorAdditional {
    table_ty: u8,
    length: u8,
    handle: u16,
    referenced_handle: Option<u16>,
    #[smbios(length = "Some(length - 6)")]
    processor_specific_block: Option<Vec<u8>>,
}

#[derive(SMBIOS)]
pub struct FirmwareInventory {
    table_ty: u8,
    length: u8,
    handle: u16,
    firmware_component_name: Option<String>,
    firmware_version: Option<String>,
    version_format: Option<u8>,
    firmware_id: Option<u8>,
    firmware_id_format: Option<u8>,
    release_date: Option<String>,
    manufacturer: Option<String>,
    lowerest_supported_firmware_version: Option<String>,
    image_size: Option<u64>,
    characteristics: Option<u16>,
    state: Option<u8>,
    num_associated_components: Option<u8>,
    #[smbios(length = "num_associated_components")]
    associated_component_handles: Option<Vec<u16>>,
}

#[derive(SMBIOS)]
pub struct StringProperty {
    table_ty: u8,
    length: u8,
    handle: u16,
    string_property_id: Option<u16>,
    string_property_value: Option<String>,
    parent_handle: Option<u16>,
}

#[derive(SMBIOS)]
pub struct Inactive {
    table_ty: u8,
    length: u8,
    handle: u16,
}

#[derive(SMBIOS)]
pub struct EnfOfTable {
    table_ty: u8,
    length: u8,
    handle: u16,
}

pub fn get_board_ty_str(ty: u8) -> &'static str {
    match ty {
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
    }
}

fn get_memory_ty_str(value: u16) -> Vec<String> {
    let types = [
        "Other",
        "Unknown",
        "Standard",
        "Fast Page Mode",
        "EDO",
        "Parity",
        "ECC",
        "SIMM",
        "DIMM",
        "Burst EDO",
        "SDRAM",
    ];

    get_flag_strings(value as u64, &types)
}

fn get_flag_strings(value: u64, flags: &[&'static str]) -> Vec<String> {
    let mut v = vec![];
    for (i, name) in flags.iter().enumerate() {
        let bit_flag = 1 << i;
        if (bit_flag & value) != 0 {
            v.push(name.to_string());
        }
    }
    v
}
