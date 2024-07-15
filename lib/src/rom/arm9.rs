use std::{borrow::Cow, io, mem::replace, ops::Range};

use serde::{Deserialize, Serialize};
use snafu::{Backtrace, Snafu};

use crate::{
    compress::lz77::Lz77,
    crypto::blowfish::{Blowfish, BlowfishError, BlowfishKey, BlowfishLevel},
    CRC_16_MODBUS,
};

use super::{
    raw::{AutoloadInfo, AutoloadKind, BuildInfo, RawAutoloadInfoError, RawBuildInfoError},
    Autoload,
};

#[derive(Clone)]
pub struct Arm9<'a> {
    data: Cow<'a, [u8]>,
    offsets: Arm9Offsets,
}

#[derive(Serialize, Deserialize, Clone, Copy)]
pub struct Arm9Offsets {
    pub base_address: u32,
    pub entry_function: u32,
    pub build_info_offset: usize,
}

const SECURE_AREA_ID: [u8; 8] = [0xff, 0xde, 0xff, 0xe7, 0xff, 0xde, 0xff, 0xe7];
const SECURE_AREA_ENCRY_OBJ: &[u8] = "encryObj".as_bytes();

const LZ77: Lz77 = Lz77 {};

const COMPRESSION_START: usize = 0x4000;

#[derive(Debug, Snafu)]
pub enum RawArm9Error {
    #[snafu(display("expected {expected:#x} bytes for {section} but had only {actual:#x}:\n{backtrace}"))]
    DataTooSmall { expected: usize, actual: usize, section: &'static str, backtrace: Backtrace },
    #[snafu(transparent)]
    Blowfish { source: BlowfishError },
    #[snafu(display("invalid encryption, 'encryObj' not found"))]
    NotEncryObj { backtrace: Backtrace },
    #[snafu(transparent)]
    RawBuildInfo { source: RawBuildInfoError },
    #[snafu(transparent)]
    Io { source: io::Error },
}

#[derive(Debug, Snafu)]
pub enum Arm9AutoloadError {
    #[snafu(transparent)]
    RawBuildInfo { source: RawBuildInfoError },
    #[snafu(transparent)]
    RawAutoloadInfo { source: RawAutoloadInfoError },
    #[snafu(display("ARM9 program must be decompressed before accessing autoload blocks:\n{backtrace}"))]
    Compressed { backtrace: Backtrace },
    #[snafu(display("autoload block {kind} could not be found:\n{backtrace}"))]
    NotFound { kind: AutoloadKind, backtrace: Backtrace },
}

impl<'a> Arm9<'a> {
    pub fn new<T: Into<Cow<'a, [u8]>>>(data: T, config: Arm9Offsets) -> Self {
        Arm9 { data: data.into(), offsets: config }
    }

    pub fn is_encrypted(&self) -> bool {
        self.data.len() < 8 || self.data[0..8] != SECURE_AREA_ID
    }

    pub fn decrypt(&mut self, key: &BlowfishKey, gamecode: u32) -> Result<(), RawArm9Error> {
        if !self.is_encrypted() {
            return Ok(());
        }

        if self.data.len() < 0x800 {
            DataTooSmallSnafu { expected: 0x800usize, actual: self.data.len(), section: "secure area" }.fail()?;
        }

        let mut secure_area = [0u8; 0x800];
        secure_area.clone_from_slice(&self.data[0..0x800]);

        let blowfish = Blowfish::new(key, gamecode, BlowfishLevel::Level2)?;
        blowfish.decrypt(&mut secure_area[0..8])?;

        let blowfish = Blowfish::new(key, gamecode, BlowfishLevel::Level3)?;
        blowfish.decrypt(&mut secure_area)?;

        if &secure_area[0..8] != SECURE_AREA_ENCRY_OBJ {
            NotEncryObjSnafu {}.fail()?;
        }

        secure_area[0..8].copy_from_slice(&SECURE_AREA_ID);
        self.data.to_mut()[0..0x800].copy_from_slice(&secure_area);
        Ok(())
    }

    pub fn encrypt(&mut self, key: &BlowfishKey, gamecode: u32) -> Result<(), RawArm9Error> {
        if self.is_encrypted() {
            return Ok(());
        }

        if self.data.len() < 0x800 {
            DataTooSmallSnafu { expected: 0x800usize, actual: self.data.len(), section: "secure area" }.fail()?;
        }

        if self.data[0..8] != SECURE_AREA_ID {
            NotEncryObjSnafu {}.fail()?;
        }

        let secure_area = self.encrypted_secure_area(key, gamecode)?;
        self.data.to_mut()[0..0x800].copy_from_slice(&secure_area);
        Ok(())
    }

    pub fn encrypted_secure_area(&self, key: &BlowfishKey, gamecode: u32) -> Result<[u8; 0x800], RawArm9Error> {
        let mut secure_area = [0u8; 0x800];
        secure_area.clone_from_slice(&self.data[0..0x800]);
        if self.is_encrypted() {
            return Ok(secure_area);
        }

        secure_area[0..8].copy_from_slice(SECURE_AREA_ENCRY_OBJ);

        let blowfish = Blowfish::new(key, gamecode, BlowfishLevel::Level3)?;
        blowfish.encrypt(&mut secure_area)?;

        let blowfish = Blowfish::new(key, gamecode, BlowfishLevel::Level2)?;
        blowfish.encrypt(&mut secure_area[0..8])?;

        Ok(secure_area)
    }

    pub fn secure_area_crc(&self, key: &BlowfishKey, gamecode: u32) -> Result<u16, RawArm9Error> {
        let secure_area = self.encrypted_secure_area(key, gamecode)?;
        let checksum = CRC_16_MODBUS.checksum(&secure_area);
        Ok(checksum)
    }

    pub fn build_info(&self) -> Result<&BuildInfo, RawBuildInfoError> {
        BuildInfo::borrow_from_slice(&self.data[self.offsets.build_info_offset as usize..])
    }

    fn build_info_mut(&mut self) -> Result<&mut BuildInfo, RawBuildInfoError> {
        BuildInfo::borrow_from_slice_mut(&mut self.data.to_mut()[self.offsets.build_info_offset as usize..])
    }

    pub fn is_compressed(&self) -> Result<bool, RawBuildInfoError> {
        Ok(self.build_info()?.is_compressed())
    }

    pub fn decompress(&mut self) -> Result<(), RawArm9Error> {
        if !self.is_compressed()? {
            return Ok(());
        }

        let data: Cow<[u8]> = LZ77.decompress(&self.data).into_vec().into();
        let old_data = replace(&mut self.data, data);
        let build_info = match self.build_info_mut() {
            Ok(build_info) => build_info,
            Err(e) => {
                self.data = old_data;
                return Err(e.into());
            }
        };
        build_info.compressed_code_end = 0;
        Ok(())
    }

    pub fn compress(&mut self) -> Result<(), RawArm9Error> {
        if self.is_compressed()? {
            return Ok(());
        }

        let data: Cow<[u8]> = LZ77.compress(&self.data, COMPRESSION_START)?.into_vec().into();
        let length = data.len();
        let old_data = replace(&mut self.data, data);
        let base_address = self.base_address();
        let build_info = match self.build_info_mut() {
            Ok(build_info) => build_info,
            Err(e) => {
                self.data = old_data;
                return Err(e.into());
            }
        };
        build_info.compressed_code_end = base_address + length as u32;
        Ok(())
    }

    fn get_autoload_infos(&self, build_info: &BuildInfo) -> Result<&[AutoloadInfo], Arm9AutoloadError> {
        let start = (build_info.autoload_infos_start - self.base_address()) as usize;
        let end = (build_info.autoload_infos_end - self.base_address()) as usize;
        let autoload_info = AutoloadInfo::borrow_from_slice(&self.data[start..end])?;
        Ok(autoload_info)
    }

    pub fn autoload_infos(&self) -> Result<&[AutoloadInfo], Arm9AutoloadError> {
        let build_info: &BuildInfo = self.build_info()?;
        if build_info.is_compressed() {
            CompressedSnafu {}.fail()?;
        }
        self.get_autoload_infos(build_info)
    }

    pub fn autoloads(&self) -> Result<Box<[Autoload]>, Arm9AutoloadError> {
        let build_info = self.build_info()?;
        if build_info.is_compressed() {
            CompressedSnafu {}.fail()?;
        }
        let autoload_infos = self.get_autoload_infos(build_info)?;

        let mut autoloads = vec![];
        let mut load_offset = build_info.autoload_blocks - self.base_address();
        for autoload_info in autoload_infos {
            let start = load_offset as usize;
            let end = start + autoload_info.code_size as usize;
            let data = &self.data[start..end];
            autoloads.push(Autoload::new(data, *autoload_info));
            load_offset += autoload_info.code_size;
        }

        Ok(autoloads.into_boxed_slice())
    }

    pub fn code(&self) -> Result<&[u8], RawBuildInfoError> {
        let build_info = self.build_info()?;
        Ok(&self.data[..(build_info.bss_start - self.base_address()) as usize])
    }

    pub fn full_data(&self) -> &[u8] {
        &self.data
    }

    pub fn base_address(&self) -> u32 {
        self.offsets.base_address
    }

    pub fn entry_function(&self) -> u32 {
        self.offsets.entry_function
    }

    pub fn bss(&self) -> Result<Range<u32>, RawBuildInfoError> {
        let build_info = self.build_info()?;
        Ok(build_info.bss_start..build_info.bss_end)
    }

    pub fn offsets(&self) -> &Arm9Offsets {
        &self.offsets
    }
}

impl<'a> AsRef<[u8]> for Arm9<'a> {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}
