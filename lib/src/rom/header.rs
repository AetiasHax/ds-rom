use std::mem::{offset_of, size_of};

use serde::{Deserialize, Serialize};
use snafu::Snafu;

use crate::{
    str::{AsciiArray, AsciiArrayError},
    CRC_16_MODBUS,
};

use super::{
    raw::{
        self, AccessControl, Capacity, Delay, DsFlags, DsiFlags, DsiFlags2, HeaderVersion, ProgramOffset, RegionFlags,
        TableOffset,
    },
    BuildContext, LogoError, RawArm9Error, Rom,
};

#[derive(Serialize, Deserialize)]
pub struct Header {
    #[serde(flatten)]
    pub original: HeaderOriginal,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ds_post_dsi: Option<HeaderDsPostDsi>,
}

#[derive(Serialize, Deserialize)]
pub struct HeaderOriginal {
    pub title: String,
    pub gamecode: AsciiArray<4>,
    pub makercode: AsciiArray<2>,
    pub unitcode: u8,
    pub seed_select: u8,
    pub ds_flags: DsFlags,
    pub autostart: u8,
    pub normal_cmd_setting: u32,
    pub key1_cmd_setting: u32,
    pub secure_area_delay: Delay,
    pub rom_nand_end: u16,
    pub rw_nand_end: u16,
}

#[derive(Serialize, Deserialize)]
pub struct HeaderDsPostDsi {
    pub dsi_flags_2: DsiFlags2,
    pub sha1_hmac_banner: [u8; 0x14],
    pub sha1_hmac_unk1: [u8; 0x14],
    pub sha1_hmac_unk2: [u8; 0x14],
    pub rsa_sha1: Box<[u8]>,
}

#[derive(Snafu, Debug)]
pub enum HeaderLoadError {
    #[snafu(transparent)]
    Logo { source: LogoError },
}

#[derive(Snafu, Debug)]
pub enum HeaderBuildError {
    #[snafu(transparent)]
    AsciiArray { source: AsciiArrayError },
    #[snafu(transparent)]
    RawArm9 { source: RawArm9Error },
}

impl Header {
    pub fn load_raw(header: &raw::Header) -> Result<Self, HeaderLoadError> {
        let version = header.version();
        Ok(Self {
            original: HeaderOriginal {
                title: header.title.to_string(),
                gamecode: header.gamecode,
                makercode: header.makercode,
                unitcode: header.unitcode,
                seed_select: header.seed_select,
                ds_flags: header.ds_flags,
                autostart: header.autostart,
                normal_cmd_setting: header.normal_cmd_setting,
                key1_cmd_setting: header.key1_cmd_setting,
                secure_area_delay: header.secure_area_delay,
                rom_nand_end: header.rom_nand_end,
                rw_nand_end: header.rw_nand_end,
            },
            ds_post_dsi: (version <= HeaderVersion::DsPostDsi).then_some(HeaderDsPostDsi {
                dsi_flags_2: header.dsi_flags_2,
                sha1_hmac_banner: header.sha1_hmac_banner,
                sha1_hmac_unk1: header.sha1_hmac_unk1,
                sha1_hmac_unk2: header.sha1_hmac_unk2,
                rsa_sha1: Box::new(header.rsa_sha1),
            }),
        })
    }

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
            rom_version: 0,
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
                arm9.secure_area_crc(key, self.original.gamecode.to_le_u32())?
            } else {
                0
            },
            secure_area_delay: self.original.secure_area_delay,
            arm9_autoload_callback: context.arm9_autoload_callback.expect("ARM9 autoload callback must be known"),
            arm7_autoload_callback: context.arm7_autoload_callback.expect("ARM7 autoload callback must be known"),
            secure_area_disable: 0,
            rom_size_ds: context.rom_size.expect("ROM size must be known"),
            header_size: size_of::<raw::Header>() as u32,
            arm9_build_info_offset: context.arm9_build_info_offset.map(|offset| offset + arm9_offset).unwrap_or(0),
            arm7_build_info_offset: context.arm7_build_info_offset.map(|offset| offset + arm7_offset).unwrap_or(0),
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

        header.header_crc = CRC_16_MODBUS.checksum(&bytemuck::bytes_of(&header)[0..offset_of!(raw::Header, header_crc)]);
        Ok(header)
    }
}
