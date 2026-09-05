use std::{
    mem::{offset_of, size_of},
    str::FromStr,
};

use serde::{Deserialize, Serialize};
use snafu::Snafu;

use super::{
    BuildContext, DigestParams, Rom,
    raw::{
        self, AccessControl, Capacity, Delay, DsFlags, DsiFlags, DsiFlags2, HeaderVersion, ProgramOffset, RegionFlags,
        TableOffset,
    },
};
use crate::{
    crc::CRC_16_MODBUS,
    str::{AsciiArray, AsciiArrayError},
};
/// ROM header.
#[derive(Serialize, Deserialize, Default)]
pub struct Header {
    /// Values for the original header version, [`HeaderVersion::Original`].
    #[serde(flatten)]
    pub original: HeaderOriginal,
    /// Values for DS games after DSi release, [`HeaderVersion::DsPostDsi`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ds_post_dsi: Option<HeaderDsPostDsi>,
    /// Values for DSi-enhanced and DSi-exclusive games, [`HeaderVersion::Dsi`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dsi: Option<HeaderDsi>,
}

/// Values for the original header version, [`HeaderVersion::Original`].
#[derive(Serialize, Deserialize, Default)]
pub struct HeaderOriginal {
    /// Short game title, normally in uppercase letters.
    pub title: String,
    /// 4-character game code in uppercase letters.
    pub gamecode: AsciiArray<4>,
    /// 2-character maker code, normally "01".
    pub makercode: AsciiArray<2>,
    /// Unit code, depends on which platform (DS, DSi) this game is for.
    pub unitcode: u8,
    /// Encryption seed select.
    pub seed_select: u8,
    /// Flags for both DS and DSi.
    pub ds_flags: DsFlags,
    /// ROM version, usually zero.
    pub rom_version: u8,
    /// Autostart, can skip "Health and Safety" screen.
    pub autostart: u8,
    /// Port 0x40001a4 setting for normal commands.
    pub normal_cmd_setting: u32,
    /// Port 0x40001a4 setting for KEY1 commands.
    pub key1_cmd_setting: u32,
    /// Delay to wait for secure area.
    pub secure_area_delay: Delay,
    /// NAND end of ROM area in multiples of 0x20000 (0x80000 on DSi).
    pub rom_nand_end: u16,
    /// NAND end of RW area in multiples of 0x20000 (0x80000 on DSi).
    pub rw_nand_end: u16,
    /// Whether the header has the ARM9 build info offset.
    pub has_arm9_build_info_offset: bool,
    /// Whether the ARM9 build info offset in the header is relative to the start of the ARM9 program instead of the start of
    /// the ROM. Seen in DSi titles.
    #[serde(default)]
    pub arm9_build_info_offset_is_relative: bool,
    /// Whether the header has the ARM7 build info offset.
    #[serde(default)]
    pub has_arm7_build_info_offset: bool,
    /// Whether the ARM7 build info offset in the header is relative to the start of the ARM7 program instead of the start of
    /// the ROM. Seen in DSi titles.
    #[serde(default)]
    pub arm7_build_info_offset_is_relative: bool,
}

/// Values for DS games after DSi release, [`HeaderVersion::DsPostDsi`].
#[derive(Serialize, Deserialize)]
pub struct HeaderDsPostDsi {
    /// DSi-exclusive flags.
    pub dsi_flags_2: DsiFlags2,
    /// SHA1-HMAC of banner. Ignored on DSi ROMs, which recompute it from the banner while building.
    pub sha1_hmac_banner: [u8; 0x14],
    /// Unknown SHA1-HMAC, defined by some games.
    pub sha1_hmac_unk1: [u8; 0x14],
    /// Unknown SHA1-HMAC, defined by some games.
    pub sha1_hmac_unk2: [u8; 0x14],
    /// RSA-SHA1 signature up to [`raw::Header::debug_args`].
    pub rsa_sha1: Box<[u8]>,
}

/// Values for DSi-enhanced and DSi-exclusive games, [`HeaderVersion::Dsi`].
///
/// Everything derived from ROM contents (the ARM9i/ARM7i and digest table offsets, the total DSi ROM size, the Modcrypt
/// areas and every SHA1-HMAC) is recomputed by [`Header::build`] and therefore absent here.
#[derive(Serialize, Deserialize, Clone)]
pub struct HeaderDsi {
    /// DSi-specific flags, including whether the ROM is Modcrypted.
    pub dsi_flags: DsiFlags,
    /// MBK1 to MBK5.
    pub memory_banks_wram: [u32; 5],
    /// MBK6 to MBK8 for the ARM9.
    pub memory_banks_arm9: [u32; 3],
    /// MBK6 to MBK8 for the ARM7.
    pub memory_banks_arm7: [u32; 3],
    /// MBK9.
    pub memory_bank_9: u32,
    /// Region flags.
    pub region_flags: RegionFlags,
    /// Access control.
    pub access_control: AccessControl,
    /// ARM7 SCFG_EXT7 setting.
    pub arm7_scfg_ext7_setting: u32,
    /// DS ROM region end in multiples of 0x80000. The DSi area starts here, so a rebuild raises this value if the DS area no
    /// longer fits below it.
    pub ds_rom_region_end: u16,
    /// DSi ROM region end in multiples of 0x80000. Preserved as-is, since a single ROM does not reveal how it is derived.
    pub dsi_rom_region_end: u16,
    /// Shape of the digest tables.
    #[serde(flatten)]
    pub digest: DigestParams,
    /// SD/MMC size of shared2/0000 file.
    pub sd_shared2_0000_size: u8,
    /// SD/MMC size of shared2/0001 file.
    pub sd_shared2_0001_size: u8,
    /// SD/MMC size of shared2/0002 file.
    pub sd_shared2_0002_size: u8,
    /// SD/MMC size of shared2/0003 file.
    pub sd_shared2_0003_size: u8,
    /// SD/MMC size of shared2/0004 file.
    pub sd_shared2_0004_size: u8,
    /// SD/MMC size of shared2/0005 file.
    pub sd_shared2_0005_size: u8,
    /// EULA version.
    pub eula_version: u8,
    /// Use age ratings.
    pub use_ratings: bool,
    /// Age ratings.
    pub age_ratings: [u8; 0x10],
    /// File type.
    pub file_type: u32,
    /// SD/MMC public.sav file size.
    pub sd_public_sav_size: u32,
    /// SD/MMC private.sav file size.
    pub sd_private_sav_size: u32,
}

/// Returns the build info offset to put in the ROM header, which is either absolute or relative to the start of the program
/// depending on how the game stores it.
fn build_info_offset(present: bool, relative: bool, offset: Option<u32>, program_offset: u32) -> u32 {
    match offset {
        Some(offset) if present && relative => offset,
        Some(offset) if present => offset + program_offset,
        _ => 0,
    }
}

/// Errors related to [`Header::build`].
#[derive(Snafu, Debug)]
pub enum HeaderBuildError {
    /// See [`AsciiArrayError`].
    #[snafu(transparent)]
    AsciiArray {
        /// Source error.
        source: AsciiArrayError,
    },
}

impl Header {
    /// Loads from a raw header.
    pub fn load_raw(header: &raw::Header) -> Self {
        let version = header.version();
        Self {
            original: HeaderOriginal {
                title: header.title.to_string(),
                gamecode: header.gamecode,
                makercode: header.makercode,
                unitcode: header.unitcode,
                seed_select: header.seed_select,
                ds_flags: header.ds_flags,
                rom_version: header.rom_version,
                autostart: header.autostart,
                normal_cmd_setting: header.normal_cmd_setting,
                key1_cmd_setting: header.key1_cmd_setting,
                secure_area_delay: header.secure_area_delay,
                rom_nand_end: header.rom_nand_end,
                rw_nand_end: header.rw_nand_end,
                has_arm9_build_info_offset: header.arm9_build_info_offset != 0,
                arm9_build_info_offset_is_relative: header.arm9_build_info_offset != 0
                    && header.arm9_build_info_offset <= header.arm9.offset,
                has_arm7_build_info_offset: header.arm7_build_info_offset != 0,
                arm7_build_info_offset_is_relative: header.arm7_build_info_offset != 0
                    && header.arm7_build_info_offset <= header.arm7.offset,
            },
            dsi: (version >= HeaderVersion::Dsi).then_some(HeaderDsi {
                dsi_flags: header.dsi_flags,
                memory_banks_wram: header.memory_banks_wram,
                memory_banks_arm9: header.memory_banks_arm9,
                memory_banks_arm7: header.memory_banks_arm7,
                memory_bank_9: header.memory_bank_9,
                region_flags: header.region_flags,
                access_control: header.access_control,
                arm7_scfg_ext7_setting: header.arm7_scfg_ext7_setting,
                ds_rom_region_end: header.ds_rom_region_end,
                dsi_rom_region_end: header.dsi_rom_region_end,
                digest: DigestParams {
                    sector_size: header.digest_sector_size,
                    block_sector_count: header.digest_sector_count,
                },
                sd_shared2_0000_size: header.sd_shared2_0000_size,
                sd_shared2_0001_size: header.sd_shared2_0001_size,
                sd_shared2_0002_size: header.sd_shared2_0002_size,
                sd_shared2_0003_size: header.sd_shared2_0003_size,
                sd_shared2_0004_size: header.sd_shared2_0004_size,
                sd_shared2_0005_size: header.sd_shared2_0005_size,
                eula_version: header.eula_version,
                use_ratings: header.use_ratings,
                age_ratings: header.age_ratings,
                file_type: header.file_type,
                sd_public_sav_size: header.sd_public_sav_size,
                sd_private_sav_size: header.sd_private_sav_size,
            }),
            ds_post_dsi: (version >= HeaderVersion::DsPostDsi).then_some(HeaderDsPostDsi {
                dsi_flags_2: header.dsi_flags_2,
                sha1_hmac_banner: header.sha1_hmac_banner,
                sha1_hmac_unk1: header.sha1_hmac_unk1,
                sha1_hmac_unk2: header.sha1_hmac_unk2,
                rsa_sha1: Box::new(header.rsa_sha1),
            }),
        }
    }

    /// Builds a raw header.
    ///
    /// # Panics
    ///
    /// Panics if a value is missing in the `context`.
    ///
    /// # Errors
    ///
    /// This function will return an error if the title contains a non-ASCII character.
    pub fn build(&self, context: &BuildContext, rom: &Rom) -> Result<raw::Header, HeaderBuildError> {
        let logo = rom.header_logo().compress();
        let arm9 = rom.arm9();
        let arm7 = rom.arm7();
        let arm9_offset = context.arm9_offset.expect("ARM9 offset must be known");
        let arm7_offset = context.arm7_offset.expect("ARM7 offset must be known");
        let mut header = raw::Header {
            title: AsciiArray::from_str(&self.original.title)?,
            gamecode: self.original.gamecode,
            makercode: self.original.makercode,
            unitcode: self.original.unitcode,
            seed_select: self.original.seed_select,
            capacity: Capacity::from_size(context.rom_size.expect("ROM size must be known")),
            reserved0: [0; 7],
            dsi_flags: DsiFlags::new(),
            ds_flags: self.original.ds_flags,
            rom_version: self.original.rom_version,
            autostart: self.original.autostart,
            arm9: ProgramOffset {
                offset: arm9_offset,
                entry: arm9.entry_function(),
                base_addr: arm9.base_address(),
                size: arm9.full_data().len() as u32,
            },
            arm7: ProgramOffset {
                offset: arm7_offset,
                entry: arm7.entry_function(),
                base_addr: arm7.base_address(),
                size: arm7.full_data().len() as u32,
            },
            file_names: context.fnt_offset.expect("FNT offset must be known"),
            file_allocs: context.fat_offset.expect("FAT offset must be known"),
            arm9_overlays: context.arm9_ovt_offset.unwrap_or_default(),
            arm7_overlays: context.arm7_ovt_offset.unwrap_or_default(),
            normal_cmd_setting: self.original.normal_cmd_setting,
            key1_cmd_setting: self.original.key1_cmd_setting,
            banner_offset: context.banner_offset.map(|b| b.offset).expect("Banner offset must be known"),
            secure_area_crc: if let Some(key) = context.blowfish_key {
                arm9.secure_area_crc(key, self.original.gamecode.to_le_u32())
            } else {
                0
            },
            secure_area_delay: self.original.secure_area_delay,
            arm9_autoload_callback: context.arm9_autoload_callback.expect("ARM9 autoload callback must be known"),
            arm7_autoload_callback: context.arm7_autoload_callback.expect("ARM7 autoload callback must be known"),
            secure_area_disable: 0,
            rom_size_ds: context.rom_size.expect("ROM size must be known"),
            header_size: size_of::<raw::Header>() as u32,
            arm9_build_info_offset: build_info_offset(
                self.original.has_arm9_build_info_offset,
                self.original.arm9_build_info_offset_is_relative,
                context.arm9_build_info_offset,
                arm9_offset,
            ),
            arm7_build_info_offset: build_info_offset(
                self.original.has_arm7_build_info_offset,
                self.original.arm7_build_info_offset_is_relative,
                context.arm7_build_info_offset,
                arm7_offset,
            ),
            ds_rom_region_end: 0,
            dsi_rom_region_end: 0,
            rom_nand_end: self.original.rom_nand_end,
            rw_nand_end: self.original.rw_nand_end,
            reserved1: [0; 0x18],
            reserved2: [0; 0x10],
            logo,
            logo_crc: CRC_16_MODBUS.checksum(&logo),
            header_crc: 0, // gets updated below
            debug_rom_offset: 0,
            debug_size: 0,
            debug_ram_addr: 0,
            reserved3: [0; 0x4],
            reserved4: [0; 0x10],
            // The below fields are for DSi only and are not supported yet
            memory_banks_wram: [0; 5],
            memory_banks_arm9: [0; 3],
            memory_banks_arm7: [0; 3],
            memory_bank_9: 0,
            region_flags: RegionFlags::new(),
            access_control: AccessControl::new(),
            arm7_scfg_ext7_setting: 0,
            dsi_flags_2: DsiFlags2::new(),
            arm9i: ProgramOffset::default(),
            arm7i: ProgramOffset::default(),
            digest_ds_area: TableOffset::default(),
            digest_dsi_area: TableOffset::default(),
            digest_sector_hashtable: TableOffset::default(),
            digest_block_hashtable: TableOffset::default(),
            digest_sector_size: 0,
            digest_sector_count: 0,
            banner_size: 0,
            sd_shared2_0000_size: 0,
            sd_shared2_0001_size: 0,
            eula_version: 0,
            use_ratings: false,
            rom_size_dsi: 0,
            sd_shared2_0002_size: 0,
            sd_shared2_0003_size: 0,
            sd_shared2_0004_size: 0,
            sd_shared2_0005_size: 0,
            arm9i_build_info_offset: 0,
            arm7i_build_info_offset: 0,
            modcrypt_area_1: TableOffset::default(),
            modcrypt_area_2: TableOffset::default(),
            gamecode_rev: AsciiArray([0; 4]),
            file_type: 0,
            sd_public_sav_size: 0,
            sd_private_sav_size: 0,
            reserved5: [0; 0xb0],
            age_ratings: [0; 0x10],
            sha1_hmac_arm9_with_secure_area: [0; 0x14],
            sha1_hmac_arm7: [0; 0x14],
            sha1_hmac_digest: [0; 0x14],
            sha1_hmac_banner: [0; 0x14],
            sha1_hmac_arm9i: [0; 0x14],
            sha1_hmac_arm7i: [0; 0x14],
            sha1_hmac_unk1: [0; 0x14],
            sha1_hmac_unk2: [0; 0x14],
            sha1_hmac_arm9: [0; 0x14],
            reserved6: [0; 0xa4c],
            debug_args: [0; 0x180],
            rsa_sha1: [0; 0x80],
            reserved7: [0; 0x3000],
        };

        if let Some(ds_post_dsi) = &self.ds_post_dsi {
            header.dsi_flags_2 = ds_post_dsi.dsi_flags_2;
            header.sha1_hmac_banner = ds_post_dsi.sha1_hmac_banner;
            header.sha1_hmac_unk1 = ds_post_dsi.sha1_hmac_unk1;
            header.sha1_hmac_unk2 = ds_post_dsi.sha1_hmac_unk2;
            header.rsa_sha1.copy_from_slice(&ds_post_dsi.rsa_sha1);
        }

        if let (Some(dsi), Some(context)) = (&self.dsi, &context.dsi) {
            header.dsi_flags = dsi.dsi_flags;
            header.memory_banks_wram = dsi.memory_banks_wram;
            header.memory_banks_arm9 = dsi.memory_banks_arm9;
            header.memory_banks_arm7 = dsi.memory_banks_arm7;
            header.memory_bank_9 = dsi.memory_bank_9;
            header.region_flags = dsi.region_flags;
            header.access_control = dsi.access_control;
            header.arm7_scfg_ext7_setting = dsi.arm7_scfg_ext7_setting;
            header.ds_rom_region_end = context.ds_rom_region_end;
            header.dsi_rom_region_end = context.dsi_rom_region_end;
            header.digest_sector_size = dsi.digest.sector_size;
            header.digest_sector_count = dsi.digest.block_sector_count;
            header.sd_shared2_0000_size = dsi.sd_shared2_0000_size;
            header.sd_shared2_0001_size = dsi.sd_shared2_0001_size;
            header.sd_shared2_0002_size = dsi.sd_shared2_0002_size;
            header.sd_shared2_0003_size = dsi.sd_shared2_0003_size;
            header.sd_shared2_0004_size = dsi.sd_shared2_0004_size;
            header.sd_shared2_0005_size = dsi.sd_shared2_0005_size;
            header.eula_version = dsi.eula_version;
            header.use_ratings = dsi.use_ratings;
            header.age_ratings = dsi.age_ratings;
            header.file_type = dsi.file_type;
            header.sd_public_sav_size = dsi.sd_public_sav_size;
            header.sd_private_sav_size = dsi.sd_private_sav_size;

            let mut gamecode_rev = self.original.gamecode;
            gamecode_rev.0.reverse();
            header.gamecode_rev = gamecode_rev;

            header.arm9i = context.arm9i;
            header.arm7i = context.arm7i;
            header.arm9i_build_info_offset = context.arm9i_build_info_offset;
            header.arm7i_build_info_offset = context.arm7i_build_info_offset;
            header.modcrypt_area_1 = context.modcrypt_area_1;
            header.modcrypt_area_2 = context.modcrypt_area_2;
            header.digest_ds_area = context.digest_ds_area;
            header.digest_dsi_area = context.digest_dsi_area;
            header.digest_sector_hashtable = context.digest_sector_hashtable;
            header.digest_block_hashtable = context.digest_block_hashtable;
            header.rom_size_dsi = context.rom_size_dsi;
            header.banner_size = context.banner_size;

            header.sha1_hmac_banner = context.sha1_hmac_banner;
            header.sha1_hmac_arm9_with_secure_area = context.sha1_hmac_arm9_with_secure_area;
            header.sha1_hmac_arm9 = context.sha1_hmac_arm9;
            header.sha1_hmac_arm7 = context.sha1_hmac_arm7;
            header.sha1_hmac_digest = context.sha1_hmac_digest;
            header.sha1_hmac_arm9i = context.sha1_hmac_arm9i;
            header.sha1_hmac_arm7i = context.sha1_hmac_arm7i;
        }

        header.header_crc = CRC_16_MODBUS.checksum(&bytemuck::bytes_of(&header)[0..offset_of!(raw::Header, header_crc)]);
        Ok(header)
    }

    /// Returns the version of this [`Header`].
    pub fn version(&self) -> HeaderVersion {
        if self.dsi.is_some() {
            HeaderVersion::Dsi
        } else if self.ds_post_dsi.is_some() {
            HeaderVersion::DsPostDsi
        } else {
            HeaderVersion::Original
        }
    }
}
