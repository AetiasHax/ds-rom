use std::{borrow::Cow, io, mem::replace};

use snafu::{Backtrace, Snafu};

use crate::{
    compress::lz77::Lz77,
    crypto::blowfish::{Blowfish, BlowfishError, BlowfishLevel},
};

use super::raw::{BuildInfo, RawBuildInfoError};

pub struct Arm9<'a> {
    data: Cow<'a, [u8]>,
    base_address: u32,
    build_info_offset: usize,
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

impl<'a> Arm9<'a> {
    pub fn new<T: Into<Cow<'a, [u8]>>>(data: T, base_address: u32, build_info_offset: usize) -> Self {
        Arm9 { data: data.into(), base_address, build_info_offset }
    }

    pub fn is_encrypted(&self) -> bool {
        self.data.len() < 8 || self.data[0..8] != SECURE_AREA_ID
    }

    pub fn decrypt(&mut self, key: &[u8], gamecode: u32) -> Result<(), RawArm9Error> {
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

    pub fn encrypt(&mut self, key: &[u8], gamecode: u32) -> Result<(), RawArm9Error> {
        if self.data.len() < 0x800 {
            DataTooSmallSnafu { expected: 0x800usize, actual: self.data.len(), section: "secure area" }.fail()?;
        }

        if self.data[0..8] != SECURE_AREA_ID {
            NotEncryObjSnafu {}.fail()?;
        }

        let mut secure_area = [0u8; 0x800];
        secure_area.clone_from_slice(&self.data[0..0x800]);
        secure_area[0..8].copy_from_slice(SECURE_AREA_ENCRY_OBJ);

        let blowfish = Blowfish::new(key, gamecode, BlowfishLevel::Level3)?;
        blowfish.encrypt(&mut secure_area)?;

        let blowfish = Blowfish::new(key, gamecode, BlowfishLevel::Level2)?;
        blowfish.encrypt(&mut secure_area[0..8])?;

        self.data.to_mut()[0..0x800].copy_from_slice(&secure_area);
        Ok(())
    }

    pub fn build_info(&self) -> Result<&BuildInfo, RawBuildInfoError> {
        BuildInfo::borrow_from_slice(&self.data[self.build_info_offset as usize..])
    }

    fn build_info_mut(&mut self) -> Result<&mut BuildInfo, RawBuildInfoError> {
        BuildInfo::borrow_from_slice_mut(&mut self.data.to_mut()[self.build_info_offset as usize..])
    }

    pub fn decompress(&mut self) -> Result<(), RawArm9Error> {
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
        let data: Cow<[u8]> = LZ77.compress(&self.data, COMPRESSION_START)?.into_vec().into();
        let length = data.len();
        let old_data = replace(&mut self.data, data);
        let base_address = self.base_address;
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

    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

impl<'a> AsRef<[u8]> for Arm9<'a> {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}
