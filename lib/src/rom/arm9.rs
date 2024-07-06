use std::borrow::Cow;

use snafu::{Backtrace, Snafu};

use crate::crypto::blowfish::{Blowfish, BlowfishError, BlowfishLevel};

pub struct Arm9<'a> {
    data: Cow<'a, [u8]>,
}

pub const SECURE_AREA_ID: [u8; 8] = [0xff, 0xde, 0xff, 0xe7, 0xff, 0xde, 0xff, 0xe7];
pub const SECURE_AREA_ENCRY_OBJ: &[u8] = "encryObj".as_bytes();

#[derive(Debug, Snafu)]
pub enum RawArm9Error {
    #[snafu(display("expected {expected:#x} bytes for secure area but had only {actual:#x}:\n{backtrace}"))]
    DataTooSmall { expected: usize, actual: usize, backtrace: Backtrace },
    #[snafu(transparent)]
    Blowfish { source: BlowfishError },
    #[snafu(display("invalid encryption, 'encryObj' not found"))]
    NotEncryObj { backtrace: Backtrace },
}

impl<'a> Arm9<'a> {
    pub fn new<T: Into<Cow<'a, [u8]>>>(data: T) -> Self {
        Arm9 { data: data.into() }
    }

    pub fn is_encrypted(&self) -> bool {
        self.data.len() < 8 || self.data[0..8] != SECURE_AREA_ID
    }

    pub fn decrypt(&mut self, key: &[u8], gamecode: u32) -> Result<(), RawArm9Error> {
        if self.data.len() < 0x800 {
            DataTooSmallSnafu { expected: 0x800usize, actual: self.data.len() }.fail()?;
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
            DataTooSmallSnafu { expected: 0x800usize, actual: self.data.len() }.fail()?;
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
}

impl<'a> AsRef<[u8]> for Arm9<'a> {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}
