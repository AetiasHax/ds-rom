use std::{borrow::Cow, io, mem::replace, ops::Range};

use serde::{Deserialize, Serialize};
use snafu::{Backtrace, Snafu};

use crate::{
    compress::lz77::Lz77,
    crc::CRC_16_MODBUS,
    crypto::blowfish::{Blowfish, BlowfishError, BlowfishKey, BlowfishLevel},
};

use super::{
    raw::{AutoloadInfo, AutoloadKind, BuildInfo, HeaderVersion, RawAutoloadInfoError, RawBuildInfoError},
    Autoload,
};

/// ARM9 program.
#[derive(Clone)]
pub struct Arm9<'a> {
    data: Cow<'a, [u8]>,
    header_version: HeaderVersion,
    offsets: Arm9Offsets,
}

/// Offsets in the ARM9 program.
#[derive(Serialize, Deserialize, Clone, Copy)]
pub struct Arm9Offsets {
    /// Base address.
    pub base_address: u32,
    /// Entrypoint function address.
    pub entry_function: u32,
    /// Build info offset.
    pub build_info: u32,
    /// Autoload callback address.
    pub autoload_callback: u32,
}

const SECURE_AREA_ID: [u8; 8] = [0xff, 0xde, 0xff, 0xe7, 0xff, 0xde, 0xff, 0xe7];
const SECURE_AREA_ENCRY_OBJ: &[u8] = "encryObj".as_bytes();

const LZ77: Lz77 = Lz77 {};

const COMPRESSION_START: usize = 0x4000;

/// Errors related to [`Arm9`].
#[derive(Debug, Snafu)]
pub enum Arm9Error {
    /// Occurs when the program is too small to contain a secure area.
    #[snafu(display("expected {expected:#x} bytes for secure area but had only {actual:#x}:\n{backtrace}"))]
    DataTooSmall {
        /// Expected minimum size.
        expected: usize,
        /// Actual size.
        actual: usize,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// See [`BlowfishError`].
    #[snafu(transparent)]
    Blowfish {
        /// Source error.
        source: BlowfishError,
    },
    /// Occurs when the string "encryObj" is not found when de/encrypting the secure area.
    #[snafu(display("invalid encryption, 'encryObj' not found"))]
    NotEncryObj {
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// See [`RawBuildInfoError`].
    #[snafu(transparent)]
    RawBuildInfo {
        /// Source error.
        source: RawBuildInfoError,
    },
    /// See [`io::Error`].
    #[snafu(transparent)]
    Io {
        /// Source error.
        source: io::Error,
    },
}

/// Errors related to ARM9 autoloads.
#[derive(Debug, Snafu)]
pub enum Arm9AutoloadError {
    /// See [`RawBuildInfoError`].
    #[snafu(transparent)]
    RawBuildInfo {
        /// Source error.
        source: RawBuildInfoError,
    },
    /// See [`RawAutoloadInfoError`].
    #[snafu(transparent)]
    RawAutoloadInfo {
        /// Source error.
        source: RawAutoloadInfoError,
    },
    /// Occurs when trying to access autoload blocks while the ARM9 program is compressed.
    #[snafu(display("ARM9 program must be decompressed before accessing autoload blocks:\n{backtrace}"))]
    Compressed {
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// Occurs when trying to access a kind of autoload block which doesn't exist in the ARM9 program.
    #[snafu(display("autoload block {kind} could not be found:\n{backtrace}"))]
    NotFound {
        /// Kind of autoload.
        kind: AutoloadKind,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
}

impl<'a> Arm9<'a> {
    /// Creates a new ARM9 program from raw data.
    pub fn new<T: Into<Cow<'a, [u8]>>>(data: T, header_version: HeaderVersion, offsets: Arm9Offsets) -> Self {
        Arm9 { data: data.into(), header_version, offsets }
    }

    /// Creates a new ARM9 program with raw data and two autoloads (ITCM and DTCM).
    ///
    /// # Errors
    ///
    /// See [`Self::build_info_mut`].
    pub fn with_two_tcms(
        mut data: Vec<u8>,
        itcm: Autoload,
        dtcm: Autoload,
        header_version: HeaderVersion,
        offsets: Arm9Offsets,
    ) -> Result<Self, RawBuildInfoError> {
        let autoload_infos = [itcm.info().clone(), dtcm.info().clone()];

        let autoload_blocks = data.len() as u32 + offsets.base_address;
        data.extend(itcm.into_data().into_iter());
        data.extend(dtcm.into_data().into_iter());
        let autoload_infos_start = data.len() as u32 + offsets.base_address;
        data.extend(bytemuck::bytes_of(&autoload_infos));
        let autoload_infos_end = data.len() as u32 + offsets.base_address;

        let mut arm9 = Self { data: data.into(), header_version, offsets };

        let build_info = arm9.build_info_mut()?;
        build_info.autoload_blocks = autoload_blocks;
        build_info.autoload_infos_start = autoload_infos_start;
        build_info.autoload_infos_end = autoload_infos_end;

        Ok(arm9)
    }

    /// Returns whether the secure area is encrypted.
    pub fn is_encrypted(&self) -> bool {
        self.data.len() < 8 || self.data[0..8] != SECURE_AREA_ID
    }

    /// Decrypts the secure area. Does nothing if already decrypted.
    ///
    /// # Errors
    ///
    /// This function will return an error if the program is too small to contain a secure area, [`Blowfish::decrypt`] fails or
    /// "encryObj" was not found.
    pub fn decrypt(&mut self, key: &BlowfishKey, gamecode: u32) -> Result<(), Arm9Error> {
        if !self.is_encrypted() {
            return Ok(());
        }

        if self.data.len() < 0x4000 {
            DataTooSmallSnafu { expected: 0x4000usize, actual: self.data.len() }.fail()?;
        }

        let mut secure_area = [0u8; 0x4000];
        secure_area.clone_from_slice(&self.data[0..0x4000]);

        let blowfish = Blowfish::new(key, gamecode, BlowfishLevel::Level2);
        blowfish.decrypt(&mut secure_area[0..8])?;

        let blowfish = Blowfish::new(key, gamecode, BlowfishLevel::Level3);
        blowfish.decrypt(&mut secure_area[0..0x800])?;

        if &secure_area[0..8] != SECURE_AREA_ENCRY_OBJ {
            NotEncryObjSnafu {}.fail()?;
        }

        secure_area[0..8].copy_from_slice(&SECURE_AREA_ID);
        self.data.to_mut()[0..0x4000].copy_from_slice(&secure_area);
        Ok(())
    }

    /// Encrypts the secure area. Does nothing if already encrypted.
    ///
    /// # Errors
    ///
    /// This function will return an error if the program is too small to contain a secure area, or the secure area ID was not
    /// found.
    pub fn encrypt(&mut self, key: &BlowfishKey, gamecode: u32) -> Result<(), Arm9Error> {
        if self.is_encrypted() {
            return Ok(());
        }

        if self.data.len() < 0x4000 {
            DataTooSmallSnafu { expected: 0x4000usize, actual: self.data.len() }.fail()?;
        }

        if self.data[0..8] != SECURE_AREA_ID {
            NotEncryObjSnafu {}.fail()?;
        }

        let secure_area = self.encrypted_secure_area(key, gamecode);
        self.data.to_mut()[0..0x4000].copy_from_slice(&secure_area);
        Ok(())
    }

    /// Returns an encrypted copy of the secure area.
    pub fn encrypted_secure_area(&self, key: &BlowfishKey, gamecode: u32) -> [u8; 0x4000] {
        let mut secure_area = [0u8; 0x4000];
        secure_area.copy_from_slice(&self.data[0..0x4000]);
        if self.is_encrypted() {
            return secure_area;
        }

        secure_area[0..8].copy_from_slice(SECURE_AREA_ENCRY_OBJ);

        let blowfish = Blowfish::new(key, gamecode, BlowfishLevel::Level3);
        blowfish.encrypt(&mut secure_area[0..0x800]).unwrap();

        let blowfish = Blowfish::new(key, gamecode, BlowfishLevel::Level2);
        blowfish.encrypt(&mut secure_area[0..8]).unwrap();

        secure_area
    }

    /// Returns a CRC checksum of the encrypted secure area.
    pub fn secure_area_crc(&self, key: &BlowfishKey, gamecode: u32) -> u16 {
        let secure_area = self.encrypted_secure_area(key, gamecode);
        let checksum = CRC_16_MODBUS.checksum(&secure_area);
        checksum
    }

    /// Returns a reference to the build info.
    ///
    /// # Errors
    ///
    /// See [`BuildInfo::borrow_from_slice`].
    pub fn build_info(&self) -> Result<&BuildInfo, RawBuildInfoError> {
        BuildInfo::borrow_from_slice(&self.data[self.offsets.build_info as usize..])
    }

    /// Returns a mutable reference to the build info.
    ///
    /// # Errors
    ///
    /// See [`BuildInfo::borrow_from_slice_mut`].
    pub fn build_info_mut(&mut self) -> Result<&mut BuildInfo, RawBuildInfoError> {
        BuildInfo::borrow_from_slice_mut(&mut self.data.to_mut()[self.offsets.build_info as usize..])
    }

    /// Returns whether this ARM9 program is compressed.
    ///
    /// # Errors
    ///
    /// See [`Self::build_info`].
    pub fn is_compressed(&self) -> Result<bool, RawBuildInfoError> {
        Ok(self.build_info()?.is_compressed())
    }

    /// Decompresses this ARM9 program. Does nothing if already decompressed.
    ///
    /// # Errors
    ///
    /// See [`Self::is_compressed`] and [`Self::build_info_mut`].
    pub fn decompress(&mut self) -> Result<(), Arm9Error> {
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

    /// Compresses this ARM9 program. Does nothing if already compressed.
    ///
    /// # Errors
    ///
    /// See [`Self::is_compressed`], [`Lz77::compress`] and [`Self::build_info_mut`].
    pub fn compress(&mut self) -> Result<(), Arm9Error> {
        if self.is_compressed()? {
            return Ok(());
        }

        let data: Cow<[u8]> = LZ77.compress(self.header_version, &self.data, COMPRESSION_START)?.into_vec().into();
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

    /// Returns the autoload infos of this [`Arm9`].
    ///
    /// # Errors
    ///
    /// This function will return an error if [`Self::build_info`] or [`Self::get_autoload_infos`] fails or this ARM9 program
    /// is compressed.
    pub fn autoload_infos(&self) -> Result<&[AutoloadInfo], Arm9AutoloadError> {
        let build_info: &BuildInfo = self.build_info()?;
        if build_info.is_compressed() {
            CompressedSnafu {}.fail()?;
        }
        self.get_autoload_infos(build_info)
    }

    /// Returns the autoloads of this [`Arm9`].
    ///
    /// # Errors
    ///
    /// This function will return an error if [`Self::build_info`] or [`Self::get_autoload_infos`] fails or this ARM9 program
    /// is compressed.
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

    /// Returns the code of this ARM9 program.
    ///
    /// # Errors
    ///
    /// See [`Self::build_info`].
    pub fn code(&self) -> Result<&[u8], RawBuildInfoError> {
        let build_info = self.build_info()?;
        Ok(&self.data[..(build_info.bss_start - self.base_address()) as usize])
    }

    /// Returns a reference to the full data.
    pub fn full_data(&self) -> &[u8] {
        &self.data
    }

    /// Returns the base address.
    pub fn base_address(&self) -> u32 {
        self.offsets.base_address
    }

    /// Returns the entry function address.
    pub fn entry_function(&self) -> u32 {
        self.offsets.entry_function
    }

    /// Returns the build info offset.
    pub fn build_info_offset(&self) -> u32 {
        self.offsets.build_info
    }

    /// Returns the autoload callback address.
    pub fn autoload_callback(&self) -> u32 {
        self.offsets.autoload_callback
    }

    /// Returns the [`Range`] of uninitialized data in this ARM9 program.
    ///
    /// # Errors
    ///
    /// See [`Self::build_info`].
    pub fn bss(&self) -> Result<Range<u32>, RawBuildInfoError> {
        let build_info = self.build_info()?;
        Ok(build_info.bss_start..build_info.bss_end)
    }

    /// Returns a reference to the ARM9 offsets.
    pub fn offsets(&self) -> &Arm9Offsets {
        &self.offsets
    }
}

impl<'a> AsRef<[u8]> for Arm9<'a> {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}
