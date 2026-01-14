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

/// ROM header.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Header {
    /// Short game title, normally in uppercase letters.
    pub title: AsciiArray<12>,
    /// 4-character game code in uppercase letters.
    pub gamecode: AsciiArray<4>,
    /// 2-character maker code, normally "01".
    pub makercode: AsciiArray<2>,
    /// Unit code, depends on which platform (DS, DSi) this game is for.
    pub unitcode: u8,
    /// Encryption seed select.
    pub seed_select: u8,
    /// ROM capacity, powers of two starting from 128kB.
    pub capacity: Capacity,
    /// Reserved, zero.
    pub reserved0: [u8; 7],
    /// DSi-specific flags.
    pub dsi_flags: DsiFlags,
    /// Flags for both DS and DSi.
    pub ds_flags: DsFlags,
    /// ROM version, usually zero.
    pub rom_version: u8,
    /// Autostart, can skip "Health and Safety" screen.
    pub autostart: u8,
    /// ARM9 program offset.
    pub arm9: ProgramOffset,
    /// ARM7 program offset.
    pub arm7: ProgramOffset,
    /// File Name Table (FNT) offset.
    pub file_names: TableOffset,
    /// File Allocation Table (FAT) offset.
    pub file_allocs: TableOffset,
    /// ARM9 overlay table offset.
    pub arm9_overlays: TableOffset,
    /// ARM7 overlay table offset.
    pub arm7_overlays: TableOffset,
    /// Port 0x40001a4 setting for normal commands.
    pub normal_cmd_setting: u32,
    /// Port 0x40001a4 setting for KEY1 commands.
    pub key1_cmd_setting: u32,
    /// Banner offset.
    pub banner_offset: u32,
    /// CRC checksum of ARM9 secure area.
    pub secure_area_crc: u16,
    /// Delay to wait for secure area.
    pub secure_area_delay: Delay,
    /// ARM9 autoload callback.
    pub arm9_autoload_callback: u32,
    /// ARM7 autoload callback.
    pub arm7_autoload_callback: u32,
    /// Can be set to encrypted "NmMdOnly" to disable secure area de/encryption.
    pub secure_area_disable: u64,
    /// Total ROM size. If this is a DSi game, this value excludes the DSi area.
    pub rom_size_ds: u32,
    /// Size of header, always 0x4000.
    pub header_size: u32,
    /// ARM9 build info offset, see [`super::BuildInfo`].
    pub arm9_build_info_offset: u32,
    /// ARM7 build info offset, see [`super::BuildInfo`].
    pub arm7_build_info_offset: u32,
    /// DS ROM region end in multiples of 0x80000. Zero for non-DSi games.
    pub ds_rom_region_end: u16,
    /// DSi ROM region end in multiples of 0x80000. Zero for non-DSi games.
    pub dsi_rom_region_end: u16,
    /// NAND end of ROM area in multiples of 0x20000 (0x80000 on DSi).
    pub rom_nand_end: u16,
    /// NAND end of RW area in multiples of 0x20000 (0x80000 on DSi).
    pub rw_nand_end: u16,
    /// Reserved, zero.
    pub reserved1: [u8; 0x18],
    /// Reserved, zero.
    pub reserved2: [u8; 0x10],
    /// Compressed logo, see [`Logo`].
    pub logo: [u8; 0x9c],
    /// CRC checksum of [`Self::logo`].
    pub logo_crc: u16,
    /// CRC checksum of everything before this member.
    pub header_crc: u16,
    /// Debug ROM offset, only for debug builds.
    pub debug_rom_offset: u32,
    /// Debug ROM size, only for debug builds.
    pub debug_size: u32,
    /// Debug RAM address, only for debug builds.
    pub debug_ram_addr: u32,
    /// Reserved, zero
    pub reserved3: [u8; 4],
    /// Reserved, zero
    pub reserved4: [u8; 0x10],
    // The below fields only exists on games released after the DSi, and are otherwise zero.
    /// MBK1 to MBK5
    pub memory_banks_wram: [u32; 5],
    /// MBK6 to MBK8
    pub memory_banks_arm9: [u32; 3],
    /// MBK6 to MBK8
    pub memory_banks_arm7: [u32; 3],
    /// MBK9
    pub memory_bank_9: u32,
    /// Region flags.
    pub region_flags: RegionFlags,
    /// Access control.
    pub access_control: AccessControl,
    /// ARM7 SCFG_EXT7 setting.
    pub arm7_scfg_ext7_setting: u32,
    /// DSi-exclusive flags.
    pub dsi_flags_2: DsiFlags2,
    /// ARM9i program offset.
    pub arm9i: ProgramOffset,
    /// ARM7i program offset.
    pub arm7i: ProgramOffset,
    /// DS area digest range.
    pub digest_ds_area: TableOffset,
    /// DSi area digest range.
    pub digest_dsi_area: TableOffset,
    /// Digest sector hashtable offset.
    pub digest_sector_hashtable: TableOffset,
    /// Digest block hashtable offset.
    pub digest_block_hashtable: TableOffset,
    /// Digest sector size.
    pub digest_sector_size: u32,
    /// Digest sector count.
    pub digest_sector_count: u32,
    /// Banner size.
    pub banner_size: u32,
    /// SD/MMC size of shared2/0000 file
    pub sd_shared2_0000_size: u8,
    /// SD/MMC size of shared2/0001 file
    pub sd_shared2_0001_size: u8,
    /// EULA version.
    pub eula_version: u8,
    /// Use age ratings.
    pub use_ratings: bool,
    /// Total ROM size, including DSi area.
    pub rom_size_dsi: u32,
    /// SD/MMC size of shared/0002 file
    pub sd_shared2_0002_size: u8,
    /// SD/MMC size of shared/0003 file
    pub sd_shared2_0003_size: u8,
    /// SD/MMC size of shared/0004 file
    pub sd_shared2_0004_size: u8,
    /// SD/MMC size of shared/0005 file
    pub sd_shared2_0005_size: u8,
    /// ARM9i build info offset.
    pub arm9i_build_info_offset: u32,
    /// ARM7i build info offset.
    pub arm7i_build_info_offset: u32,
    /// Modcrypt area 1 offset.
    pub modcrypt_area_1: TableOffset,
    /// Modcrypt area 1 offset.
    pub modcrypt_area_2: TableOffset,
    /// Same as [`Self::gamecode`] but byte.reversed.
    pub gamecode_rev: AsciiArray<4>,
    /// File type.
    pub file_type: u32,
    /// SD/MMC public.sav file size.
    pub sd_public_sav_size: u32,
    /// SD/MMC private.sav file size.
    pub sd_private_sav_size: u32,
    /// Reserved, zero.
    pub reserved5: [u8; 0xb0],
    /// Age ratings.
    pub age_ratings: [u8; 0x10],
    /// SHA1-HMAC of ARM9 program including secure area.
    pub sha1_hmac_arm9_with_secure_area: [u8; 0x14],
    /// SHA1-HMAC of ARM7 program.
    pub sha1_hmac_arm7: [u8; 0x14],
    /// SHA1-HMAC of digest section.
    pub sha1_hmac_digest: [u8; 0x14],
    /// SHA1-HMAC of banner.
    pub sha1_hmac_banner: [u8; 0x14],
    /// SHA1-HMAC of decrypted ARM9i.
    pub sha1_hmac_arm9i: [u8; 0x14],
    /// SHA1-HMAC of decrypted ARM7i.
    pub sha1_hmac_arm7i: [u8; 0x14],
    /// Unknown SHA1-HMAC, defined by some games.
    pub sha1_hmac_unk1: [u8; 0x14],
    /// Unknown SHA1-HMAC, defined by some games.
    pub sha1_hmac_unk2: [u8; 0x14],
    /// SHA1-HMAC of ARM9 program excluding secure area.
    pub sha1_hmac_arm9: [u8; 0x14],
    /// Reserved, zero.
    pub reserved6: [u8; 0xa4c],
    /// Used for passing arguments in debug environment.
    pub debug_args: [u8; 0x180],
    /// RSA-SHA1 signature up to [`Self::debug_args`].
    pub rsa_sha1: [u8; 0x80],
    /// Reserved, zero.
    pub reserved7: [u8; 0x3000],
}

unsafe impl Zeroable for Header {}
unsafe impl Pod for Header {}

/// Errors related to [`Header`].
#[derive(Debug, Snafu)]
pub enum RawHeaderError {
    /// Occurs when the input is too small to contain a header.
    #[snafu(display("expected {expected:#x} bytes for header but had only {actual:#x}:\n{backtrace}"))]
    DataTooSmall {
        /// Expected size.
        expected: usize,
        /// Actual input size.
        actual: usize,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// Occurs when the input is less aligned than [`Header`].
    #[snafu(display("expected {expected}-alignment for header but got {actual}-alignment:\n{backtrace}"))]
    Misaligned {
        /// Expected alignment.
        expected: usize,
        /// Actual input alignment.
        actual: usize,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
}

impl Header {
    /// Returns the version of this [`Header`].
    pub fn version(&self) -> HeaderVersion {
        if self.dsi_flags_2.0 != 0 {
            HeaderVersion::DsPostDsi
        } else {
            HeaderVersion::Original
        }
    }

    fn check_size(data: &'_ [u8]) -> Result<(), RawHeaderError> {
        let size = size_of::<Self>();
        if data.len() < size {
            DataTooSmallSnafu { expected: size, actual: data.len() }.fail()
        } else {
            Ok(())
        }
    }

    fn handle_pod_cast<T>(result: Result<T, PodCastError>, addr: usize) -> Result<T, RawHeaderError> {
        match result {
            Ok(build_info) => Ok(build_info),
            Err(PodCastError::TargetAlignmentGreaterAndInputNotAligned) => {
                MisalignedSnafu { expected: align_of::<Self>(), actual: 1usize << addr.trailing_zeros() }.fail()
            }
            Err(PodCastError::AlignmentMismatch) => panic!(),
            Err(PodCastError::OutputSliceWouldHaveSlop) => panic!(),
            Err(PodCastError::SizeMismatch) => unreachable!(),
        }
    }

    /// Reinterprets a `&[u8]` as a reference to [`Header`].
    ///
    /// # Errors
    ///
    /// This function will return an error if the input is too small or not aligned enough.
    pub fn borrow_from_slice(data: &'_ [u8]) -> Result<&'_ Self, RawHeaderError> {
        let size = size_of::<Self>();
        Self::check_size(data)?;
        let addr = data as *const [u8] as *const () as usize;
        Self::handle_pod_cast(bytemuck::try_from_bytes(&data[..size]), addr)
    }

    /// Reinterprets a `&mut [u8]` as a mutable reference to [`Header`].
    ///
    /// # Errors
    ///
    /// This function will return an error if the input is too small or not aligned enough.
    pub fn borrow_from_slice_mut(data: &'_ mut [u8]) -> Result<&'_ mut Self, RawHeaderError> {
        let size = size_of::<Self>();
        Self::check_size(data)?;
        let addr = data as *const [u8] as *const () as usize;
        Self::handle_pod_cast(bytemuck::try_from_bytes_mut(&mut data[..size]), addr)
    }

    /// Creates a [`DisplayHeader`] which implements [`Display`].
    pub fn display(&self, indent: usize) -> DisplayHeader<'_> {
        DisplayHeader { header: self, indent }
    }
}

/// Can be used to display values inside [`Header`].
pub struct DisplayHeader<'a> {
    header: &'a Header,
    indent: usize,
}

impl Display for DisplayHeader<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let i = " ".repeat(self.indent);
        let header = &self.header;
        writeln!(f, "{i}Header version .......... : {}", header.version())?;
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

/// Header version. Used for determining which fields are relevant in the header.
#[derive(PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Clone, Copy)]
pub enum HeaderVersion {
    /// Original, before DSi release.
    Original,
    /// DS game after DSi release but no DSi-specific features used.
    DsPostDsi,
}

impl Display for HeaderVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HeaderVersion::Original => write!(f, "Original"),
            HeaderVersion::DsPostDsi => write!(f, "DS after DSi release"),
        }
    }
}

/// ROM capacity.
#[derive(Clone, Copy)]
pub struct Capacity(pub u8);

impl Capacity {
    /// Calculates the needed capacity from a given ROM size.
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

/// DSi-specific flags.
#[bitfield(u8)]
pub struct DsiFlags {
    /// If `true`, the ROM has a DSi area.
    dsi_title: bool,
    /// If `true`, the ROM is modcrypted.
    modcrypted: bool,
    /// If `true`, use debug key, otherwise retail key.
    modcrypt_debug_key: bool,
    /// Disable debug?
    disable_debug: bool,
    /// Reserved, zero.
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

/// Flags for both DS and DSi.
#[bitfield(u8)]
#[derive(Serialize, Deserialize)]
pub struct DsFlags {
    /// Permit jump.
    permit_jump: bool,
    /// Permit tmpjump.
    permit_tmpjump: bool,
    /// Reserved, zero.
    #[bits(4)]
    reserved: u8,
    /// Released in Korea if `true`.
    korea_region: bool,
    /// Released in China if `true`.
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

/// Program offset, used for ARM9, ARM7, ARM9i and ARM7i.
#[repr(C)]
#[derive(Clone, Copy, Zeroable, Pod, Default)]
pub struct ProgramOffset {
    /// ROM offset to start of program.
    pub offset: u32,
    /// Entrypoint function address.
    pub entry: u32,
    /// Base RAM address.
    pub base_addr: u32,
    /// Program size in the ROM.
    pub size: u32,
}

impl ProgramOffset {
    /// Creates a [`DisplayProgramOffset`] which implements [`Display`].
    pub fn display(&self, indent: usize) -> DisplayProgramOffset<'_> {
        DisplayProgramOffset { offset: self, indent }
    }
}

/// Can be used to display values inside [`ProgramOffset`].
pub struct DisplayProgramOffset<'a> {
    offset: &'a ProgramOffset,
    indent: usize,
}

impl Display for DisplayProgramOffset<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let i = " ".repeat(self.indent);
        let offset = &self.offset;
        writeln!(f, "{i}Offset ........ : {:#x}", offset.offset)?;
        writeln!(f, "{i}Entrypoint .... : {:#x}", offset.entry)?;
        writeln!(f, "{i}Base address .. : {:#x}", offset.base_addr)?;
        writeln!(f, "{i}Size .......... : {:#x}", offset.size)?;
        Ok(())
    }
}

/// Offset to a table in the ROM.
#[repr(C)]
#[derive(Clone, Copy, Zeroable, Pod, Default)]
pub struct TableOffset {
    /// ROM offset to start of table.
    pub offset: u32,
    /// Table size in the ROM.
    pub size: u32,
}

impl TableOffset {
    /// Creates a [`DisplayTableOffset`] which implements [`Display`].
    pub fn display(&self, indent: usize) -> DisplayTableOffset<'_> {
        DisplayTableOffset { offset: self, indent }
    }
}

/// Can be used to display values inside [`TableOffset`].
pub struct DisplayTableOffset<'a> {
    offset: &'a TableOffset,
    indent: usize,
}

impl Display for DisplayTableOffset<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let i = " ".repeat(self.indent);
        let offset = &self.offset;
        writeln!(f, "{i}Offset .. : {:#x}", offset.offset)?;
        writeln!(f, "{i}Size .... : {:#x}", offset.size)?;
        Ok(())
    }
}

/// Secure area delay.
#[derive(Clone, Copy, Serialize, Deserialize, Default)]
pub struct Delay(pub u16);

impl Display for Delay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:.1}ms", self.0 as f32 / 131.072)
    }
}

/// Region flags, only used in DSi titles.
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

/// Access control flags.
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

/// DSi-specific flags.
#[bitfield(u32)]
#[derive(Serialize, Deserialize)]
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
