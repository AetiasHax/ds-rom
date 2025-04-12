use std::{borrow::Cow, io, mem::replace, ops::Range};

use serde::{Deserialize, Serialize};
use snafu::{Backtrace, Snafu};

use super::{
    raw::{
        AutoloadInfo, AutoloadInfoEntry, AutoloadKind, BuildInfo, HmacSha1Signature, HmacSha1SignatureError,
        RawAutoloadInfoError, RawBuildInfoError, NITROCODE_BYTES,
    },
    Autoload, OverlayTable,
};
use crate::{
    compress::lz77::{Lz77, Lz77DecompressError},
    crc::CRC_16_MODBUS,
    crypto::blowfish::{Blowfish, BlowfishError, BlowfishKey, BlowfishLevel},
};

/// ARM9 program.
#[derive(Clone)]
pub struct Arm9<'a> {
    data: Cow<'a, [u8]>,
    offsets: Arm9Offsets,
    originally_compressed: bool,
    originally_encrypted: bool,
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
    /// Offset to overlay HMAC-SHA1 signature table.
    pub overlay_signatures: u32,
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
    /// See [`Lz77DecompressError`].
    #[snafu(transparent)]
    Lz77Decompress {
        /// Source error.
        source: Lz77DecompressError,
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

/// Errors related to [`Arm9::overlay_signatures`] and [`Arm9::overlay_signatures_mut`].
#[derive(Debug, Snafu)]
pub enum Arm9OverlaySignaturesError {
    /// See [`OverlaySignatureError`].
    #[snafu(transparent)]
    HmacSha1Signature {
        /// Source error.
        source: HmacSha1SignatureError,
    },
    /// See [`RawBuildInfoError`].
    #[snafu(transparent)]
    RawBuildInfo {
        /// Source error.
        source: RawBuildInfoError,
    },
    /// Occurs when trying to access overlay signatures while the ARM9 program is compressed.
    #[snafu(display("ARM9 program must be decompressed before accessing overlay signatures:\n{backtrace}"))]
    OverlaySignaturesCompressed {
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
}

/// Errors related to [`Arm9::hmac_sha1_key`].
#[derive(Debug, Snafu)]
pub enum Arm9HmacSha1KeyError {
    /// See [`RawBuildInfoError`].
    #[snafu(transparent)]
    RawBuildInfo {
        /// Source error.
        source: RawBuildInfoError,
    },
    /// Occurs when trying to access the HMAC-SHA1 key while the ARM9 program is compressed.
    #[snafu(display("ARM9 program must be decompressed before accessing HMAC-SHA1 key:\n{backtrace}"))]
    HmacSha1KeyCompressed {
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
}

/// Options for [`Arm9::with_two_tcms`].
pub struct Arm9WithTcmsOptions {
    /// Whether the program was compressed originally.
    pub originally_compressed: bool,
    /// Whether the program was encrypted originally.
    pub originally_encrypted: bool,
}

impl<'a> Arm9<'a> {
    /// Creates a new ARM9 program from raw data.
    pub fn new<T: Into<Cow<'a, [u8]>>>(data: T, offsets: Arm9Offsets) -> Result<Self, RawBuildInfoError> {
        let mut arm9 = Arm9 { data: data.into(), offsets, originally_compressed: false, originally_encrypted: false };
        arm9.originally_compressed = arm9.is_compressed()?;
        arm9.originally_encrypted = arm9.is_encrypted();
        Ok(arm9)
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
        offsets: Arm9Offsets,
        options: Arm9WithTcmsOptions,
    ) -> Result<Self, RawBuildInfoError> {
        let autoload_infos = [*itcm.info().entry(), *dtcm.info().entry()];

        let autoload_blocks = data.len() as u32 + offsets.base_address;
        data.extend(itcm.into_data().iter());
        data.extend(dtcm.into_data().iter());
        let autoload_infos_start = data.len() as u32 + offsets.base_address;
        data.extend(bytemuck::bytes_of(&autoload_infos));
        let autoload_infos_end = data.len() as u32 + offsets.base_address;

        let Arm9WithTcmsOptions { originally_compressed, originally_encrypted } = options;
        let mut arm9 = Self { data: data.into(), offsets, originally_compressed, originally_encrypted };

        let build_info = arm9.build_info_mut()?;
        build_info.autoload_blocks = autoload_blocks;
        build_info.autoload_infos_start = autoload_infos_start;
        build_info.autoload_infos_end = autoload_infos_end;

        Ok(arm9)
    }

    /// Creates a new ARM9 program with raw data and a list of autoloads.
    ///
    /// # Errors
    ///
    /// See [`Self::build_info_mut`].
    pub fn with_autoloads(
        mut data: Vec<u8>,
        autoloads: &[Autoload],
        offsets: Arm9Offsets,
        options: Arm9WithTcmsOptions,
    ) -> Result<Self, RawBuildInfoError> {
        let autoload_blocks = data.len() as u32 + offsets.base_address;

        for autoload in autoloads {
            data.extend(autoload.full_data());
        }

        let autoload_infos_start = data.len() as u32 + offsets.base_address;
        for autoload in autoloads {
            data.extend(bytemuck::bytes_of(autoload.info().entry()));
        }
        let autoload_infos_end = data.len() as u32 + offsets.base_address;

        let Arm9WithTcmsOptions { originally_compressed, originally_encrypted } = options;
        let mut arm9 = Self { data: data.into(), offsets, originally_compressed, originally_encrypted };

        let build_info = arm9.build_info_mut()?;
        build_info.autoload_blocks = autoload_blocks;
        build_info.autoload_infos_start = autoload_infos_start;
        build_info.autoload_infos_end = autoload_infos_end;

        Ok(arm9)
    }

    /// Returns whether the secure area is encrypted. See [`Self::originally_encrypted`] for whether the secure area was
    /// encrypted originally.
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
        CRC_16_MODBUS.checksum(&secure_area)
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

    /// Returns whether this ARM9 program is compressed. See [`Self::originally_compressed`] for whether the program was
    /// compressed originally.
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

        let data: Cow<[u8]> = LZ77.decompress(&self.data)?.into_vec().into();
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

    fn get_autoload_info_entries(&self, build_info: &BuildInfo) -> Result<&[AutoloadInfoEntry], Arm9AutoloadError> {
        let start = (build_info.autoload_infos_start - self.base_address()) as usize;
        let end = (build_info.autoload_infos_end - self.base_address()) as usize;
        let autoload_info = AutoloadInfoEntry::borrow_from_slice(&self.data[start..end])?;
        Ok(autoload_info)
    }

    /// Returns the autoload infos of this [`Arm9`].
    ///
    /// # Errors
    ///
    /// This function will return an error if [`Self::build_info`] or [`Self::get_autoload_infos`] fails or this ARM9 program
    /// is compressed.
    pub fn autoload_infos(&self) -> Result<Vec<AutoloadInfo>, Arm9AutoloadError> {
        let build_info: &BuildInfo = self.build_info()?;
        if build_info.is_compressed() {
            CompressedSnafu {}.fail()?;
        }
        Ok(self
            .get_autoload_info_entries(build_info)?
            .iter()
            .enumerate()
            .map(|(index, entry)| AutoloadInfo::new(*entry, index as u32))
            .collect())
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
        let autoload_infos = self.autoload_infos()?;

        let mut autoloads = vec![];
        let mut load_offset = build_info.autoload_blocks - self.base_address();
        for autoload_info in autoload_infos {
            let start = load_offset as usize;
            let end = start + autoload_info.code_size() as usize;
            let data = &self.data[start..end];
            autoloads.push(Autoload::new(data, autoload_info));
            load_offset += autoload_info.code_size();
        }

        Ok(autoloads.into_boxed_slice())
    }

    /// Returns the number of unknown autoloads of this [`Arm9`].
    ///
    /// # Errors
    ///
    /// See [`Self::autoloads`].
    pub fn num_unknown_autoloads(&self) -> Result<usize, Arm9AutoloadError> {
        Ok(self.autoloads()?.iter().filter(|a| matches!(a.kind(), AutoloadKind::Unknown(_))).count())
    }

    /// Returns the HMAC-SHA1 key in this ARM9 program.
    pub fn hmac_sha1_key(&self) -> Result<Option<[u8; 64]>, Arm9HmacSha1KeyError> {
        if self.is_compressed()? {
            HmacSha1KeyCompressedSnafu {}.fail()?
        }

        // Credits to pleonex: https://scenegate.github.io/Ekona/docs/specs/cartridge/security.html#overlays
        let Some((i, _)) = self.data.chunks(4).enumerate().filter(|(_, chunk)| *chunk == NITROCODE_BYTES).nth(1) else {
            return Ok(None);
        };
        let start = i * 4;
        let end = start + 64;
        if end > self.data.len() {
            return Ok(None);
        }
        let mut key = [0u8; 64];
        key.copy_from_slice(&self.data[start..end]);
        Ok(Some(key))
    }

    fn overlay_table_signature_range(&self) -> Result<Option<Range<usize>>, Arm9OverlaySignaturesError> {
        let overlay_signatures_offset = self.overlay_signatures_offset() as usize;
        if overlay_signatures_offset == 0 {
            return Ok(None);
        }

        if self.is_compressed()? {
            OverlaySignaturesCompressedSnafu {}.fail()?;
        }

        // The overlay table signature is located right before the overlay signatures
        let start = overlay_signatures_offset - size_of::<HmacSha1Signature>();
        let end = overlay_signatures_offset;
        if end > self.data.len() {
            return Ok(None);
        }
        return Ok(Some(start..end));
    }

    /// Returns the ARM9 overlay table signature.
    ///
    /// # Errors
    ///
    /// This function will return an error if the ARM9 program is compressed or if [`HmacSha1Signature::borrow_from_slice`] fails.
    pub fn overlay_table_signature(&self) -> Result<Option<&HmacSha1Signature>, Arm9OverlaySignaturesError> {
        let Some(range) = self.overlay_table_signature_range()? else {
            return Ok(None);
        };
        let data = &self.data[range];

        let signature = HmacSha1Signature::borrow_from_slice(data)?;
        Ok(Some(signature.first().unwrap()))
    }

    /// Returns a mutable reference to the ARM9 overlay table signature.
    ///
    /// # Errors
    ///
    /// This function will return an error if the ARM9 program is compressed or if [`HmacSha1Signature::borrow_from_slice_mut`]
    /// fails.
    pub fn overlay_table_signature_mut(&mut self) -> Result<Option<&mut HmacSha1Signature>, Arm9OverlaySignaturesError> {
        let Some(range) = self.overlay_table_signature_range()? else {
            return Ok(None);
        };
        let data = &mut self.data.to_mut()[range];

        let signature = HmacSha1Signature::borrow_from_slice_mut(data)?;
        Ok(Some(signature.first_mut().unwrap()))
    }

    fn overlay_signatures_range(&self, num_overlays: usize) -> Result<Option<Range<usize>>, Arm9OverlaySignaturesError> {
        let start = self.overlay_signatures_offset() as usize;
        if start == 0 {
            return Ok(None);
        }

        if self.is_compressed()? {
            OverlaySignaturesCompressedSnafu {}.fail()?;
        }

        let end = start + size_of::<HmacSha1Signature>() * num_overlays;
        if end > self.data.len() {
            return Ok(None);
        }
        return Ok(Some(start..end));
    }

    /// Returns the ARM9 overlay signature table.
    ///
    /// # Errors
    ///
    /// This function will return an error if the ARM9 program is compressed or if [`HmacSha1Signature::borrow_from_slice`]
    /// fails.
    pub fn overlay_signatures(&self, num_overlays: usize) -> Result<Option<&[HmacSha1Signature]>, Arm9OverlaySignaturesError> {
        let Some(range) = self.overlay_signatures_range(num_overlays)? else {
            return Ok(None);
        };
        let data = &self.data[range];
        Ok(Some(HmacSha1Signature::borrow_from_slice(data)?))
    }

    /// Returns a mutable reference to the ARM9 overlay signature table.
    ///
    /// # Errors
    ///
    /// This function will return an error if the ARM9 program is compressed or if [`HmacSha1Signature::borrow_from_slice_mut`]
    /// fails.
    pub fn overlay_signatures_mut(
        &mut self,
        num_overlays: usize,
    ) -> Result<Option<&mut [HmacSha1Signature]>, Arm9OverlaySignaturesError> {
        let Some(range) = self.overlay_signatures_range(num_overlays)? else {
            return Ok(None);
        };
        let data = &mut self.data.to_mut()[range];
        Ok(Some(HmacSha1Signature::borrow_from_slice_mut(data)?))
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

    /// Returns the end address.
    pub fn end_address(&self) -> Result<u32, RawBuildInfoError> {
        let build_info = self.build_info()?;
        Ok(build_info.bss_end)
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

    /// Returns the offset to the overlay HMAC-SHA1 signature table.
    pub fn overlay_signatures_offset(&self) -> u32 {
        self.offsets.overlay_signatures
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

    /// Returns whether the ARM9 program was compressed originally. See [`Self::is_compressed`] for the current state.
    pub fn originally_compressed(&self) -> bool {
        self.originally_compressed
    }

    /// Returns whether the ARM9 program was encrypted originally. See [`Self::is_encrypted`] for the current state.
    pub fn originally_encrypted(&self) -> bool {
        self.originally_encrypted
    }

    pub(crate) fn update_overlay_signatures(
        &mut self,
        arm9_overlay_table: &OverlayTable,
    ) -> Result<(), Arm9OverlaySignaturesError> {
        let arm9_overlays = arm9_overlay_table.overlays();
        let Some(signatures) = self.overlay_signatures_mut(arm9_overlays.len())? else {
            return Ok(());
        };
        for overlay in arm9_overlays {
            if let Some(signature) = overlay.signature() {
                signatures[overlay.id() as usize] = signature;
            }
        }

        if let Some(signature) = arm9_overlay_table.signature() {
            let Some(table_signature) = self.overlay_table_signature_mut()? else {
                return Ok(());
            };
            *table_signature = signature;
        }

        Ok(())
    }
}

impl AsRef<[u8]> for Arm9<'_> {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}
