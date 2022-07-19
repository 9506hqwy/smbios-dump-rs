pub mod error;
#[cfg(target_family = "unix")]
pub mod unix;
#[cfg(target_family = "windows")]
pub mod windows;

use self::error::Error;
#[cfg(target_family = "unix")]
use self::unix::get_smbios;
#[cfg(target_family = "windows")]
use self::windows::get_smbios;
use bytes::{Buf, Bytes};
use std::io::Write;
use uuid::Uuid;

fn main() -> Result<(), Error> {
    let smbios = get_smbios()?;

    let mut data = smbios.smbios_table_data.clone();
    while !data.is_empty() {
        let table = RawSmbiosTable::from(&mut data);
        match table.table_ty {
            0 => BiosInformation::from_table(&smbios, &table)
                .dump(&mut std::io::stdout())
                .unwrap(),
            1 => SystemInformation::from_table(&smbios, &table)
                .dump(&mut std::io::stdout())
                .unwrap(),
            2 => BaseBoardInformation::from_table(&smbios, &table)
                .dump(&mut std::io::stdout())
                .unwrap(),
            _ => table.dump(&mut std::io::stdout()).unwrap(),
        }

        println!();
    }

    Ok(())
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
        if self.smbios_major_version < major {
            false
        } else if self.smbios_major_version > major {
            true
        } else {
            self.smbios_minior_version >= minor
        }
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
    pub fn dump(&self, writer: &mut impl Write) -> std::io::Result<()> {
        writer.write_fmt(format_args!(
            "Handle 0x{:04X}, DMI type {}, {} bytes\n",
            self.handle, self.table_ty, self.length
        ))?;

        // Byte Array
        writer.write_fmt(format_args!("\tHeader and Data:\n"))?;
        let mut body = vec![self.table_ty, self.length];
        body.extend_from_slice(&self.handle.to_le_bytes());
        body.extend_from_slice(&self.body);
        self.write_bytearray(writer, &body)?;

        if !self.tailer.is_empty() {
            writer.write_fmt(format_args!("\tStrings:\n"))?;
            for bytes in &self.tailer {
                // Byte Array
                self.write_bytearray(writer, bytes)?;

                // String
                if let Ok(s) = String::from_utf8(bytes.to_vec()) {
                    writer.write_fmt(format_args!("\t\t{}\n", s))?;
                }
            }
        }
        Ok(())
    }

    pub fn get_string_by_index(&self, index: u8) -> Option<String> {
        let i: usize = (index as usize) - 1;
        self.tailer
            .get(i)
            .map(|v| String::from_utf8_lossy(v).to_string())
    }

    fn write_bytearray(&self, writer: &mut impl Write, bytes: &[u8]) -> std::io::Result<()> {
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

pub struct BiosInformation {
    pub table_ty: u8,
    pub length: u8,
    pub handle: u16,
    pub vendor: String,
    pub bios_version: String,
    pub bios_starting_address: u16,
    pub bios_release_date: String,
    pub bios_rom_size: u8,
    pub bios_characteristics: u64,
    pub bios_characteristics_ex: Option<[u8; 2]>,
    pub system_bios_major_release: Option<u8>,
    pub system_bios_minor_release: Option<u8>,
    pub embedded_ctrl_firmware_major_release: Option<u8>,
    pub embedded_ctrl_firmware_minor_release: Option<u8>,
    pub ex_bios_rom_size: Option<u16>,
}

impl BiosInformation {
    pub fn from_table(smbios: &RawSmbiosData, table: &RawSmbiosTable) -> Self {
        let mut data = table.body.clone();

        let vendor_idx = data.get_u8();
        let bios_version_idx = data.get_u8();
        let bios_starting_address = data.get_u16_le();
        let bios_release_date_idx = data.get_u8();
        let bios_rom_size = data.get_u8();
        let bios_characteristics = data.get_u64_le();
        let bios_characteristics_ex = if smbios.is_later(2, 4) {
            Some([data.get_u8(), data.get_u8()])
        } else {
            None
        };
        let system_bios_major_release = if smbios.is_later(2, 4) {
            Some(data.get_u8())
        } else {
            None
        };
        let system_bios_minor_release = if smbios.is_later(2, 4) {
            Some(data.get_u8())
        } else {
            None
        };
        let embedded_ctrl_firmware_major_release = if smbios.is_later(2, 4) {
            Some(data.get_u8())
        } else {
            None
        };
        let embedded_ctrl_firmware_minor_release = if smbios.is_later(2, 4) {
            Some(data.get_u8())
        } else {
            None
        };
        let ex_bios_rom_size = if smbios.is_later(3, 1) {
            Some(data.get_u16())
        } else {
            None
        };

        let vendor = table.get_string_by_index(vendor_idx).unwrap();
        let bios_version = table.get_string_by_index(bios_version_idx).unwrap();
        let bios_release_date = table.get_string_by_index(bios_release_date_idx).unwrap();

        BiosInformation {
            table_ty: table.table_ty,
            length: table.length,
            handle: table.handle,
            vendor,
            bios_version,
            bios_starting_address,
            bios_release_date,
            bios_rom_size,
            bios_characteristics,
            bios_characteristics_ex,
            system_bios_major_release,
            system_bios_minor_release,
            embedded_ctrl_firmware_major_release,
            embedded_ctrl_firmware_minor_release,
            ex_bios_rom_size,
        }
    }

    pub fn dump(&self, writer: &mut impl Write) -> std::io::Result<()> {
        writer.write_fmt(format_args!(
            "Handle 0x{:04X}, DMI type {}, {} bytes\n",
            self.handle, self.table_ty, self.length
        ))?;

        writer.write_fmt(format_args!("BIOS Information\n"))?;
        writer.write_fmt(format_args!("\tVendor: {}\n", self.vendor))?;
        writer.write_fmt(format_args!("\tVersion: {}\n", self.bios_version))?;
        writer.write_fmt(format_args!("\tRelease Date: {}\n", self.bios_release_date))?;
        writer.write_fmt(format_args!(
            "\tAddress: 0x{:04X}\n",
            self.bios_starting_address
        ))?;
        writer.write_fmt(format_args!(
            "\tRuntimme Size: {} kB\n",
            (0x10000 - (self.bios_starting_address as u32)) * 16 / 1024
        ))?;
        writer.write_fmt(format_args!(
            "\tROM Size: {} kB\n",
            ((self.bios_rom_size as u16) + 1) * 64
        ))?;
        self.dump_char(writer, self.bios_characteristics)?;
        if let Some(char_ex) = self.bios_characteristics_ex {
            self.dump_char_ex1(writer, char_ex[0])?;
            self.dump_char_ex2(writer, char_ex[1])?;
        }

        if let Some(major) = self.system_bios_major_release {
            if let Some(minor) = self.system_bios_minor_release {
                writer.write_fmt(format_args!("\tBIOS Revisione: {}.{}\n", major, minor))?;
            }
        }

        if let Some(major) = self.embedded_ctrl_firmware_major_release {
            if let Some(minor) = self.embedded_ctrl_firmware_minor_release {
                writer.write_fmt(format_args!("\tFirmware Revisione: {}.{}\n", major, minor))?;
            }
        }

        Ok(())
    }

    fn dump_char(&self, writer: &mut impl Write, value: u64) -> std::io::Result<()> {
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

        writer.write_fmt(format_args!("\tCharracteristics:\n"))?;
        for (i, name) in chars.iter().enumerate() {
            let bit_flag = 1 << i;
            if (bit_flag & value) != 0 {
                writer.write_fmt(format_args!("\t\t{}\n", name))?;
            }
        }

        Ok(())
    }

    fn dump_char_ex1(&self, writer: &mut impl Write, value: u8) -> std::io::Result<()> {
        let chars = vec![
            "ACPI is supported",
            "USB legacy is supported",
            "AGP is supported",
            "I2O boot is supported",
            "LS-120 boot is supported",
            "ATAPI Zip drive boot is supported",
            "IEEE 1394 boot is supported",
            "Smart battery is supported",
        ];

        for (i, name) in chars.iter().enumerate() {
            let bit_flag = 1 << i;
            if (bit_flag & value) != 0 {
                writer.write_fmt(format_args!("\t\t{}\n", name))?;
            }
        }

        Ok(())
    }

    fn dump_char_ex2(&self, writer: &mut impl Write, value: u8) -> std::io::Result<()> {
        let chars = vec![
            "BIOS boot specification is supported",
            "Function key-initiated network boot is supported",
            "Targeted content distribution is supported",
            "UEFI is supported",
            "System is a virtual machine",
            "Manufacturing mode is supported",
            "Manufacturing mode is enabled",
        ];

        for (i, name) in chars.iter().enumerate() {
            let bit_flag = 1 << i;
            if (bit_flag & value) != 0 {
                writer.write_fmt(format_args!("\t\t{}\n", name))?;
            }
        }

        Ok(())
    }
}

pub struct SystemInformation {
    pub table_ty: u8,
    pub length: u8,
    pub handle: u16,
    pub manufacturer: String,
    pub product_name: String,
    pub version: String,
    pub serial_number: String,
    pub uuid: Option<Uuid>,
    pub wakeup_type: Option<u8>,
    pub sku_number: Option<String>,
    pub family: Option<String>,
}

impl SystemInformation {
    pub fn from_table(smbios: &RawSmbiosData, table: &RawSmbiosTable) -> Self {
        let mut data = table.body.clone();

        let manufacturer_idx = data.get_u8();
        let product_name_idx = data.get_u8();
        let version_idx = data.get_u8();
        let serial_number_idx = data.get_u8();
        let uuid = if smbios.is_later(2, 1) {
            let mut u = [0u8; 16];
            for i in &mut u {
                *i = data.get_u8();
            }
            if smbios.is_later(2, 6) {
                Some(Uuid::from_bytes_le(u))
            } else {
                Some(Uuid::from_bytes(u))
            }
        } else {
            None
        };
        let wakeup_type = if smbios.is_later(2, 1) {
            Some(data.get_u8())
        } else {
            None
        };
        let sku_number_idx = if smbios.is_later(2, 4) {
            Some(data.get_u8())
        } else {
            None
        };
        let family_idx = if smbios.is_later(2, 4) {
            Some(data.get_u8())
        } else {
            None
        };

        let manufacturer = table.get_string_by_index(manufacturer_idx).unwrap();
        let product_name = table.get_string_by_index(product_name_idx).unwrap();
        let version = table.get_string_by_index(version_idx).unwrap();
        let serial_number = table.get_string_by_index(serial_number_idx).unwrap();
        let sku_number = sku_number_idx.map(|v| table.get_string_by_index(v).unwrap());
        let family = family_idx.map(|v| table.get_string_by_index(v).unwrap());

        SystemInformation {
            table_ty: table.table_ty,
            length: table.length,
            handle: table.handle,
            manufacturer,
            product_name,
            version,
            serial_number,
            uuid,
            wakeup_type,
            sku_number,
            family,
        }
    }

    pub fn dump(&self, writer: &mut impl Write) -> std::io::Result<()> {
        writer.write_fmt(format_args!(
            "Handle 0x{:04X}, DMI type {}, {} bytes\n",
            self.handle, self.table_ty, self.length
        ))?;

        writer.write_fmt(format_args!("System Information\n"))?;
        writer.write_fmt(format_args!("\tManufacturer: {}\n", self.manufacturer))?;
        writer.write_fmt(format_args!("\tProduct Name: {}\n", self.product_name))?;
        writer.write_fmt(format_args!("\tVersion: {}\n", self.version))?;
        writer.write_fmt(format_args!("\tSerial Number: {}\n", self.serial_number))?;
        if self.uuid.is_some() {
            writer.write_fmt(format_args!("\tUUID: {}\n", self.uuid.unwrap()))?;
        }
        if self.wakeup_type.is_some() {
            writer.write_fmt(format_args!("\tWake-up Type: {}\n", self.wakeup_type_str()))?;
        }
        if let Some(sku_number) = &self.sku_number {
            writer.write_fmt(format_args!("\tSKU Number: {}\n", sku_number))?;
        }
        if let Some(family) = &self.family {
            writer.write_fmt(format_args!("\tFamily: {}\n", family))?;
        }

        Ok(())
    }

    fn wakeup_type_str(&self) -> &'static str {
        match self.wakeup_type.unwrap() {
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
        }
    }
}

pub struct BaseBoardInformation {
    pub table_ty: u8,
    pub length: u8,
    pub handle: u16,
    pub manufacturer: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    pub serial_number: Option<String>,
    pub asset_tag: Option<String>,
    pub feature_flags: Option<u8>,
    pub location: Option<String>,
    pub chassis_handle: Option<u16>,
    pub board_ty: Option<u8>,
    pub num_contained_object: Option<u8>,
    pub contained_object_handle: Option<Vec<u16>>,
}

impl BaseBoardInformation {
    pub fn from_table(_smbios: &RawSmbiosData, table: &RawSmbiosTable) -> Self {
        let mut data = table.body.clone();

        let manufacturer_idx = if data.remaining() > 0 {
            Some(data.get_u8())
        } else {
            None
        };
        let product_idx = if data.remaining() > 0 {
            Some(data.get_u8())
        } else {
            None
        };
        let version_idx = if data.remaining() > 0 {
            Some(data.get_u8())
        } else {
            None
        };
        let serial_number_idx = if data.remaining() > 0 {
            Some(data.get_u8())
        } else {
            None
        };
        let asset_tag_idx = if data.remaining() > 0 {
            Some(data.get_u8())
        } else {
            None
        };
        let feature_flags = if data.remaining() > 0 {
            Some(data.get_u8())
        } else {
            None
        };
        let location_idx = if data.remaining() > 0 {
            Some(data.get_u8())
        } else {
            None
        };
        let chassis_handle = if data.remaining() > 0 {
            Some(data.get_u16())
        } else {
            None
        };
        let board_ty = if data.remaining() > 0 {
            Some(data.get_u8())
        } else {
            None
        };
        let num_contained_object = if data.remaining() > 0 {
            Some(data.get_u8())
        } else {
            None
        };
        let contained_object_handle = if let Some(num) = num_contained_object {
            let mut tmp = vec![];
            for _ in 0..num {
                tmp.push(data.get_u16());
            }
            Some(tmp)
        } else {
            None
        };

        let manufacturer = manufacturer_idx.map(|idx| table.get_string_by_index(idx).unwrap());
        let product = product_idx.map(|idx| table.get_string_by_index(idx).unwrap());
        let version = version_idx.map(|idx| table.get_string_by_index(idx).unwrap());
        let serial_number = serial_number_idx.map(|idx| table.get_string_by_index(idx).unwrap());
        let asset_tag = asset_tag_idx.map(|idx| table.get_string_by_index(idx).unwrap());
        let location = location_idx.map(|idx| table.get_string_by_index(idx).unwrap());

        BaseBoardInformation {
            table_ty: table.table_ty,
            length: table.length,
            handle: table.handle,
            manufacturer,
            product,
            version,
            serial_number,
            asset_tag,
            feature_flags,
            location,
            chassis_handle,
            board_ty,
            num_contained_object,
            contained_object_handle,
        }
    }

    pub fn dump(&self, writer: &mut impl Write) -> std::io::Result<()> {
        writer.write_fmt(format_args!(
            "Handle 0x{:04X}, DMI type {}, {} bytes\n",
            self.handle, self.table_ty, self.length
        ))?;

        writer.write_fmt(format_args!("Base Board Information\n"))?;
        if let Some(manufacturer) = &self.manufacturer {
            writer.write_fmt(format_args!("\tManufacturer: {}\n", manufacturer))?;
        }
        if let Some(product) = &self.product {
            writer.write_fmt(format_args!("\tProduct Name: {}\n", product))?;
        }
        if let Some(version) = &self.version {
            writer.write_fmt(format_args!("\tVersion: {}\n", version))?;
        }
        if let Some(serial_number) = &self.serial_number {
            writer.write_fmt(format_args!("\tSerial Number: {}\n", serial_number))?;
        }
        if let Some(asset_tag) = &self.asset_tag {
            writer.write_fmt(format_args!("\tAsset Tag: {}\n", asset_tag))?;
        }
        if let Some(feature_flags) = self.feature_flags {
            self.dump_feature_flag(writer, feature_flags)?;
        }
        if let Some(location) = &self.location {
            writer.write_fmt(format_args!("\tLocation In Chassis: {}\n", location))?;
        }
        if let Some(chassis_handle) = &self.chassis_handle {
            writer.write_fmt(format_args!("\tChassis Handle: 0x{:04X}\n", chassis_handle))?;
        }
        if self.board_ty.is_some() {
            writer.write_fmt(format_args!("\tType: {}\n", self.board_ty_str()))?;
        }

        Ok(())
    }

    fn dump_feature_flag(&self, writer: &mut impl Write, value: u8) -> std::io::Result<()> {
        let feats = vec![
            "Board is a hosting board",
            "Board requires at least one daughter board",
            "Board is removable",
            "Board is replaceable",
            "Board is hot swappable",
            "",
            "",
        ];

        writer.write_fmt(format_args!("\tFeatures:\n"))?;
        for (i, name) in feats.iter().enumerate() {
            let bit_flag = 1 << i;
            if (bit_flag & value) != 0 {
                writer.write_fmt(format_args!("\t\t{}\n", name))?;
            }
        }

        Ok(())
    }

    fn board_ty_str(&self) -> &'static str {
        match self.board_ty.unwrap() {
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
}
