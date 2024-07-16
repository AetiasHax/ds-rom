use std::{
    fmt::Display,
    mem::{align_of, size_of},
};

use bitfield_struct::bitfield;
use bytemuck::{Pod, PodCastError, Zeroable};
use serde::{Deserialize, Serialize};
use snafu::{Backtrace, Snafu};

use crate::{
    rom::Logo,
    str::{AsciiArray, BlobSize},
};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Header {
    pub title: AsciiArray<12>,
    pub gamecode: AsciiArray<4>,
    pub makercode: AsciiArray<2>,
    pub unitcode: u8,
    pub seed_select: u8,
    pub capacity: Capacity,
    pub reserved0: [u8; 7],
    pub dsi_flags: DsiFlags,
    pub ds_flags: DsFlags,
    pub rom_version: u8,
    pub autostart: u8,
    pub arm9: ProgramOffset,
    pub arm7: ProgramOffset,
    pub file_names: TableOffset,
    pub file_allocs: TableOffset,
    pub arm9_overlays: TableOffset,
    pub arm7_overlays: TableOffset,
    pub normal_cmd_setting: u32,
    pub key1_cmd_setting: u32,
    pub banner_offset: u32,
    pub secure_area_crc: u16,
    pub secure_area_delay: Delay,
    pub arm9_autoload_callback: u32,
    pub arm7_autoload_callback: u32,
    pub secure_area_disable: u64,
    pub rom_size_ds: u32,
    pub header_size: u32,
    pub arm9_build_info_offset: u32,
    pub arm7_build_info_offset: u32,
    pub ds_rom_region_end: u16,
    pub dsi_rom_region_end: u16,
    pub rom_nand_end: u16,
    pub rw_nand_end: u16,
    pub reserved1: [u8; 0x18],
    pub reserved2: [u8; 0x10],
    pub logo: [u8; 0x9c],
    pub logo_crc: u16,
    pub header_crc: u16,
    pub debug_rom_offset: u32,
    pub debug_size: u32,
    pub debug_ram_addr: u32,
    pub reserved3: [u8; 4],
    pub reserved4: [u8; 0x10],
    // The below fields are only used on DSi titles
    /// MBK1 to MBK5
    pub memory_banks_wram: [u32; 5],
    /// MBK6 to MBK8
    pub memory_banks_arm9: [u32; 3],
    /// MBK6 to MBK8
    pub memory_banks_arm7: [u32; 3],
    /// MBK9
    pub memory_bank_9: u32,
    pub region_flags: RegionFlags,
    pub access_control: AccessControl,
    pub arm7_scfg_ext7_setting: u32,
    pub dsi_flags_2: DsiFlags2,
    pub arm9i: ProgramOffset,
    pub arm7i: ProgramOffset,
    pub digest_ds_area: TableOffset,
    pub digest_dsi_area: TableOffset,
    pub digest_sector_hashtable: TableOffset,
    pub digest_block_hashtable: TableOffset,
    pub digest_sector_size: u32,
    pub digest_sector_count: u32,
    pub banner_size: u32,
    pub sd_shared2_0000_size: u8,
    pub sd_shared2_0001_size: u8,
    pub eula_version: u8,
    pub use_ratings: bool,
    pub rom_size_dsi: u32,
    pub sd_shared2_0002_size: u8,
    pub sd_shared2_0003_size: u8,
    pub sd_shared2_0004_size: u8,
    pub sd_shared2_0005_size: u8,
    pub arm9i_build_info_offset: u32,
    pub arm7i_build_info_offset: u32,
    pub modcrypt_area_1: TableOffset,
    pub modcrypt_area_2: TableOffset,
    pub gamecode_rev: AsciiArray<4>,
    pub file_type: u32,
    pub sd_public_sav_size: u32,
    pub sd_private_sav_size: u32,
    pub reserved5: [u8; 0xb0],
    pub age_ratings: [u8; 0x10],
    pub sha1_hmac_arm9_with_secure_area: [u8; 0x14],
    pub sha1_hmac_arm7: [u8; 0x14],
    pub sha1_hmac_digest: [u8; 0x14],
    pub sha1_hmac_banner: [u8; 0x14],
    pub sha1_hmac_arm9i: [u8; 0x14],
    pub sha1_hmac_arm7i: [u8; 0x14],
    pub sha1_hmac_reserved1: [u8; 0x14],
    pub sha1_hmac_reserved2: [u8; 0x14],
    pub sha1_hmac_arm9: [u8; 0x14],
    pub reserved6: [u8; 0xa4c],
    pub debug_args: [u8; 0x180],
    pub rsa_sha1: [u8; 0x80],
    pub reserved7: [u8; 0x3000],
}

unsafe impl Zeroable for Header {}
unsafe impl Pod for Header {}

#[derive(Debug, Snafu)]
pub enum RawHeaderError {
    #[snafu(display("expected {expected:#x} bytes for header but had only {actual:#x}:\n{backtrace}"))]
    DataTooSmall { expected: usize, actual: usize, backtrace: Backtrace },
    #[snafu(display("expected {expected}-alignment for header but got {actual}-alignment:\n{backtrace}"))]
    Misaligned { expected: usize, actual: usize, backtrace: Backtrace },
}

impl Header {
    pub fn borrow_from_slice(data: &'_ [u8]) -> Result<&'_ Self, RawHeaderError> {
        let size = size_of::<Self>();
        if data.len() < size {
            DataTooSmallSnafu { expected: size, actual: data.len() }.fail()
        } else {
            let addr = data as *const [u8] as *const () as usize;
            match bytemuck::try_from_bytes(&data[..size]) {
                Ok(header) => Ok(header),
                Err(PodCastError::TargetAlignmentGreaterAndInputNotAligned) => {
                    MisalignedSnafu { expected: align_of::<Self>(), actual: 1usize << addr.trailing_zeros() }.fail()
                }
                Err(PodCastError::AlignmentMismatch) => panic!(),
                Err(PodCastError::OutputSliceWouldHaveSlop) => panic!(),
                Err(PodCastError::SizeMismatch) => unreachable!(),
            }
        }
    }

    pub fn borrow_from_slice_mut(data: &'_ mut [u8]) -> Result<&'_ mut Self, RawHeaderError> {
        let size = size_of::<Self>();
        if data.len() < size {
            DataTooSmallSnafu { expected: size, actual: data.len() }.fail()
        } else {
            let addr = data as *const [u8] as *const () as usize;
            match bytemuck::try_from_bytes_mut(&mut data[..size]) {
                Ok(header) => Ok(header),
                Err(PodCastError::TargetAlignmentGreaterAndInputNotAligned) => {
                    MisalignedSnafu { expected: align_of::<Self>(), actual: 1usize << addr.trailing_zeros() }.fail()
                }
                Err(PodCastError::AlignmentMismatch) => panic!(),
                Err(PodCastError::OutputSliceWouldHaveSlop) => panic!(),
                Err(PodCastError::SizeMismatch) => unreachable!(),
            }
        }
    }

    pub fn display(&self, indent: usize) -> DisplayHeader {
        DisplayHeader { header: self, indent }
    }
}

pub struct DisplayHeader<'a> {
    header: &'a Header,
    indent: usize,
}

impl<'a> Display for DisplayHeader<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let i = format!("{:indent$}", "", indent = self.indent);
        let header = &self.header;
        writeln!(f, "{i}Title ................... : {}", header.title)?;
        writeln!(f, "{i}Gamecode ................ : {}", header.gamecode)?;
        writeln!(f, "{i}Makercode ............... : {}", header.makercode)?;
        writeln!(f, "{i}Unitcode ................ : {}", header.unitcode)?;
        writeln!(f, "{i}DS flags ................ : {}", header.ds_flags)?;
        writeln!(f, "{i}DSi flags ............... : {}", header.dsi_flags)?;
        writeln!(f, "{i}Capacity ................ : {}", header.capacity)?;
        writeln!(f, "{i}ROM size (DS) ........... : {} ({:#x})", BlobSize(header.rom_size_ds as usize), header.rom_size_ds)?;
        writeln!(f, "{i}ROM version ............. : {}", header.rom_version)?;
        write!(f, "{i}ARM9 program\n{}", header.arm9.display(self.indent + 2))?;
        writeln!(f, "{i}ARM9 autoload callback .. : {:#x}", header.arm9_autoload_callback)?;
        writeln!(f, "{i}ARM9 build info offset .. : {:#x}", header.arm9_build_info_offset)?;
        write!(f, "{i}ARM7 program\n{}", header.arm7.display(self.indent + 2))?;
        writeln!(f, "{i}ARM7 autoload callback .. : {:#x}", header.arm7_autoload_callback)?;
        writeln!(f, "{i}ARM7 build info offset .. : {:#x}", header.arm7_build_info_offset)?;
        write!(f, "{i}File name table\n{}", header.file_names.display(self.indent + 2))?;
        write!(f, "{i}File allocation table\n{}", header.file_allocs.display(self.indent + 2))?;
        writeln!(f, "{i}Banner\n{i}  Offset: {:#x}", header.banner_offset)?;
        writeln!(f, "{i}Normal cmd setting ...... : {:#x}", header.normal_cmd_setting)?;
        writeln!(f, "{i}KEY1 cmd setting ........ : {:#x}", header.key1_cmd_setting)?;
        writeln!(f, "{i}Seed select ............. : {:#x}", header.seed_select)?;
        writeln!(f, "{i}Autostart ............... : {:#x}", header.autostart)?;
        writeln!(f, "{i}Secure area disable ..... : {:#x}", header.secure_area_disable)?;
        writeln!(f, "{i}Secure area delay ....... : {} ({:#x})", header.secure_area_delay, header.secure_area_delay.0)?;
        writeln!(f, "{i}Secure area CRC ......... : {:#x}", header.secure_area_crc)?;
        writeln!(f, "{i}Logo CRC ................ : {:#x}", header.logo_crc)?;
        writeln!(f, "{i}Header CRC .............. : {:#x}", header.header_crc)?;
        write!(f, "{i}Logo .................... : ")?;
        match Logo::decompress(&self.header.logo) {
            Ok(logo) => writeln!(f, "\n{logo}")?,
            Err(_) => writeln!(f, "Failed to decompress")?,
        };
        writeln!(f, "{i}DS ROM region end ....... : {:#x}", header.ds_rom_region_end)?;
        writeln!(f, "{i}DSi ROM region end ...... : {:#x}", header.dsi_rom_region_end)?;
        writeln!(f, "{i}ROM NAND end ............ : {:#x}", header.rom_nand_end)?;
        writeln!(f, "{i}RW NAND end ............. : {:#x}", header.rw_nand_end)?;
        writeln!(f, "{i}Debug ROM offset ........ : {:#x}", header.debug_rom_offset)?;
        writeln!(f, "{i}Debug size .............. : {:#x}", header.debug_size)?;
        writeln!(f, "{i}Debug RAM address ....... : {:#x}", header.debug_ram_addr)?;
        writeln!(f, "{i}Header size ............. : {:#x}", header.header_size)?;
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub struct Capacity(pub u8);

impl Capacity {
    pub fn from_size(size: u32) -> Self {
        let bits = 32 - size.leading_zeros() as u8;
        Self(bits.saturating_sub(17))
    }
}

impl Display for Capacity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            0..=2 => write!(f, "{}kB", 128 << self.0),
            3.. => write!(f, "{}MB", 1 << (self.0 - 3)),
        }
    }
}

#[bitfield(u8)]
pub struct DsiFlags {
    dsi_title: bool,
    modcrypted: bool,
    modcrypt_debug_key: bool,
    disable_debug: bool,
    #[bits(4)]
    reserved: u8,
}

macro_rules! write_flag {
    ($f:ident, $comma:ident, $flag:expr, $name:literal) => {
        #[allow(unused_assignments)]
        if $flag {
            if $comma {
                write!($f, ", ")?;
            }
            write!($f, $name)?;
            $comma = true;
        }
    };
}

impl Display for DsiFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0 == 0x00 {
            write!(f, "Normal")
        } else {
            let mut comma = false;
            write_flag!(f, comma, self.dsi_title(), "DSi title");
            write_flag!(f, comma, self.modcrypted(), "Modcrypted");
            write_flag!(f, comma, self.modcrypt_debug_key(), "Modcrypt debug key");
            write_flag!(f, comma, self.disable_debug(), "Disable debug");
            Ok(())
        }
    }
}

#[bitfield(u8)]
#[derive(Serialize, Deserialize)]
pub struct DsFlags {
    permit_jump: bool,
    permit_tmpjump: bool,
    #[bits(4)]
    reserved: u8,
    korea_region: bool,
    china_region: bool,
}

impl Display for DsFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0 == 0x00 {
            write!(f, "Normal")
        } else {
            let mut comma = false;
            write_flag!(f, comma, self.china_region(), "China");
            write_flag!(f, comma, self.korea_region(), "Korea");
            write_flag!(f, comma, self.permit_jump(), "Permit jump");
            write_flag!(f, comma, self.permit_tmpjump(), "Permit tmpjump");
            Ok(())
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Zeroable, Pod, Default)]
pub struct ProgramOffset {
    pub offset: u32,
    pub entry: u32,
    pub base_addr: u32,
    pub size: u32,
}

impl ProgramOffset {
    pub fn display(&self, indent: usize) -> DisplayProgramOffset {
        DisplayProgramOffset { offset: self, indent }
    }
}

pub struct DisplayProgramOffset<'a> {
    offset: &'a ProgramOffset,
    indent: usize,
}

impl<'a> Display for DisplayProgramOffset<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let i = format!("{:indent$}", "", indent = self.indent);
        let offset = &self.offset;
        writeln!(f, "{i}Offset ........ : {:#x}", offset.offset)?;
        writeln!(f, "{i}Entrypoint .... : {:#x}", offset.entry)?;
        writeln!(f, "{i}Base address .. : {:#x}", offset.base_addr)?;
        writeln!(f, "{i}Size .......... : {:#x}", offset.size)?;
        Ok(())
    }
}

#[repr(C)]
#[derive(Clone, Copy, Zeroable, Pod, Default)]
pub struct TableOffset {
    pub offset: u32,
    pub size: u32,
}

impl TableOffset {
    pub fn display(&self, indent: usize) -> DisplayTableOffset {
        DisplayTableOffset { offset: self, indent }
    }
}

pub struct DisplayTableOffset<'a> {
    offset: &'a TableOffset,
    indent: usize,
}

impl<'a> Display for DisplayTableOffset<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let i = format!("{:indent$}", "", indent = self.indent);
        let offset = &self.offset;
        writeln!(f, "{i}Offset .. : {:#x}", offset.offset)?;
        writeln!(f, "{i}Size .... : {:#x}", offset.size)?;
        Ok(())
    }
}

#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct Delay(pub u16);

impl Display for Delay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:.1}ms", self.0 as f32 / 131.072)
    }
}

#[bitfield(u32)]
pub struct RegionFlags {
    japan: bool,
    usa: bool,
    europe: bool,
    australia: bool,
    china: bool,
    korea: bool,
    #[bits(26)]
    reserved: u32,
}

impl Display for RegionFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0 == 0x00 {
            write!(f, "None")
        } else if self.0 == 0xffffffff {
            write!(f, "Region free")
        } else {
            let mut comma = false;
            write_flag!(f, comma, self.japan(), "Japan");
            write_flag!(f, comma, self.usa(), "USA");
            write_flag!(f, comma, self.europe(), "Europe");
            write_flag!(f, comma, self.australia(), "Australia");
            write_flag!(f, comma, self.china(), "China");
            write_flag!(f, comma, self.korea(), "Korea");
            Ok(())
        }
    }
}

#[bitfield(u32)]
pub struct AccessControl {
    common_client_key: bool,
    aes_slot_b: bool,
    aes_slot_c: bool,
    sd_card: bool,
    nand_access: bool,
    card_power_on: bool,
    shared2_file: bool,
    sign_jpeg_for_launcher: bool,
    card_ds_mode: bool,
    ssl_client_cert: bool,
    sign_jpeg_for_user: bool,
    photo_read: bool,
    photo_write: bool,
    sd_card_read: bool,
    sd_card_write: bool,
    card_save_read: bool,
    card_save_write: bool,
    #[bits(14)]
    reserved: u32,
    debugger_common_client_key: bool,
}

#[bitfield(u32)]
pub struct DsiFlags2 {
    /// Touchscreen/Sound Controller (TSC) in DSi (true) or DS (false) mode
    tsc_dsi_mode: bool,
    require_eula_agreement: bool,
    /// If true, use banner.sav to override default banner icon
    dynamic_icon: bool,
    /// If true, show Wi-Fi Connection icon in launcher
    launcher_wfc_icon: bool,
    /// If true, show DS Wireless icon in launcher
    launcher_wireless_icon: bool,
    has_icon_sha1: bool,
    has_header_rsa: bool,
    developer_app: bool,
    #[bits(24)]
    reserved: u32,
}
