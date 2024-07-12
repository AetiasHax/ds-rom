use std::mem::{offset_of, size_of};

use snafu::Snafu;

use crate::{
    str::{AsciiArray, AsciiArrayError},
    CRC_16_MODBUS,
};

use super::{
    raw::{self, AccessControl, Capacity, Delay, DsFlags, DsiFlags, DsiFlags2, ProgramOffset, RegionFlags, TableOffset},
    BuildContext, LogoError, Rom,
};

pub struct Header {
    title: String,
    gamecode: AsciiArray<4>,
    makercode: AsciiArray<2>,
    unitcode: u8,
    seed_select: u8,
    ds_flags: DsFlags,
    autostart: u8,
    normal_cmd_setting: u32,
    key1_cmd_setting: u32,
    secure_area_delay: Delay,
    rom_nand_end: u16,
    rw_nand_end: u16,
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
}

impl TryFrom<raw::Header> for Header {
    type Error = HeaderLoadError;

    fn try_from(header: raw::Header) -> Result<Self, Self::Error> {
        Ok(Self {
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
        })
    }
}

impl Header {
    pub fn build(&self, context: &BuildContext, rom: &Rom) -> Result<raw::Header, HeaderBuildError> {
        let logo = rom.header_logo().compress();
        let arm9 = rom.arm9();
        let arm7 = rom.arm7();
        let mut header = raw::Header {
            title: AsciiArray::from_str(&self.title)?,
            gamecode: self.gamecode,
            makercode: self.makercode,
            unitcode: self.unitcode,
            seed_select: self.seed_select,
            capacity: Capacity::from_size(context.rom_size.expect("ROM size must be known")),
            reserved0: [0; 7],
            dsi_flags: DsiFlags::new(),
            ds_flags: self.ds_flags,
            rom_version: 0,
            autostart: self.autostart,
            arm9: ProgramOffset {
                offset: context.arm9_offset.expect("ARM9 offset must be known"),
                entry: arm9.entry_function(),
                base_addr: arm9.base_address(),
                size: arm9.full_data().len() as u32,
            },
            arm7: ProgramOffset {
                offset: context.arm7_offset.expect("ARM7 offset must be known"),
                entry: arm7.entry_function(),
                base_addr: arm7.base_address(),
                size: arm7.full_data().len() as u32,
            },
            file_names: context.fnt_offset.expect("FNT offset must be known"),
            file_allocs: context.fat_offset.expect("FAT offset must be known"),
            arm9_overlays: context.arm9_ovt_offset.unwrap_or_default(),
            arm7_overlays: context.arm7_ovt_offset.unwrap_or_default(),
            normal_cmd_setting: self.normal_cmd_setting,
            key1_cmd_setting: self.key1_cmd_setting,
            banner_offset: context.banner_offset.map(|b| b.offset).expect("Banner offset must be known"),
            secure_area_crc: context
                .blowfish_key
                .map_or(0, |key| arm9.secure_area_crc(key, u32::from_le_bytes(self.gamecode.0)).unwrap()),
            secure_area_delay: self.secure_area_delay,
            arm9_autoload_callback: context.arm9_autoload_callback.expect("ARM9 autoload callback must be known"),
            arm7_autoload_callback: context.arm7_autoload_callback.expect("ARM7 autoload callback must be known"),
            secure_area_disable: 0,
            rom_size_ds: context.rom_size.expect("ROM size must be known"),
            header_size: size_of::<raw::Header>() as u32,
            arm9_build_info_offset: context.arm9_build_info_offset.unwrap_or(0),
            arm7_build_info_offset: context.arm7_build_info_offset.unwrap_or(0),
            ds_rom_region_end: 0,
            dsi_rom_region_end: 0,
            rom_nand_end: self.rom_nand_end,
            rw_nand_end: self.rw_nand_end,
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
            sha1_hmac_reserved1: [0; 0x14],
            sha1_hmac_reserved2: [0; 0x14],
            sha1_hmac_arm9: [0; 0x14],
            reserved6: [0; 0xa4c],
            debug_args: [0; 0x180],
            rsa_sha1: [0; 0x80],
            reserved7: [0; 0x3000],
        };
        header.header_crc = CRC_16_MODBUS.checksum(&bytemuck::bytes_of(&header)[0..offset_of!(raw::Header, header_crc)]);
        Ok(header)
    }
}
