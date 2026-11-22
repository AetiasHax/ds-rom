use std::{borrow::Cow, io, mem::replace, ops::Range, str::Utf8Error};

use serde::{Deserialize, Serialize};
use snafu::{Backtrace, Snafu};

use super::{
    Autoload, OverlayTable,
    raw::{
        AutoloadInfo, AutoloadInfoEntry, AutoloadKind, BuildInfo, HmacSha1Signature, HmacSha1SignatureError, NITROCODE_BYTES,
        RawAutoloadInfoError, RawBuildInfoError,
    },
};
use crate::{
    compress::lz77::{Lz77, Lz77CompressError, Lz77DecompressError},
    crc::CRC_16_MODBUS,
    crypto::{
        blowfish::{Blowfish, BlowfishError, BlowfishKey, BlowfishLevel},
        dsprot::{DsProtDecryptOptions, DsProtDecryptResult, DsProtEncryptOptions, DsProtError, DsProtInfo, DsProtState},
    },
    error::{DataOutOfBoundsError, OverflowError, slice_data, slice_data_mut},
    rom::{AutoloadError, LibraryEntry},
};

/// ARM9 program.
#[derive(Clone, PartialEq, Eq)]
pub struct Arm9<'a> {
    data: Cow<'a, [u8]>,
    offsets: Arm9Offsets,
    originally_compressed: bool,
    originally_encrypted: bool,
    dsprot_state: DsProtState,
    has_footer: bool,
}

/// Offsets in the ARM9 program.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
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

/// Number of zero-bytes in the secure area for it to be considered unencrypted. This applies to a
/// few retail games with a secure area which, after decryption, does not start with "encryObj" like
/// it normally does.
const SECURE_AREA_UNENCRYPTED_THRESHOLD: usize = 256;

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
    /// See [`OverflowError`].
    #[snafu(transparent)]
    Overflow {
        /// Source error.
        source: OverflowError,
    },
    /// See [`DataOutOfBoundsError`]
    #[snafu(transparent)]
    DataOutOfBounds {
        /// Source error.
        source: DataOutOfBoundsError,
    },
    /// See [`Lz77CompressError`]
    #[snafu(transparent)]
    Lz77Compress {
        /// Source error.
        source: Lz77CompressError,
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
    /// See [`AutoloadError`].
    #[snafu(transparent)]
    Autoload {
        /// Source error.
        source: AutoloadError,
    },
    /// See [`OverflowError`].
    #[snafu(transparent)]
    Overflow {
        /// Source error.
        source: OverflowError,
    },
    /// See [`Arm9Error`].
    #[snafu(transparent)]
    Arm9 {
        /// Source error.
        source: Arm9Error,
    },
    /// See [`DataOutOfBoundsError`]
    #[snafu(transparent)]
    DataOutOfBounds {
        /// Source error.
        source: DataOutOfBoundsError,
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
    /// See [`Arm9Error`].
    #[snafu(transparent)]
    Arm9 {
        /// Source error.
        source: Arm9Error,
    },
    /// Occurs when trying to access overlay signatures while the ARM9 program is compressed.
    #[snafu(display("ARM9 program must be decompressed before accessing overlay signatures:\n{backtrace}"))]
    OverlaySignaturesCompressed {
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// See [`OverflowError`].
    #[snafu(transparent)]
    Overflow {
        /// Source error.
        source: OverflowError,
    },
    /// See [`DataOutOfBoundsError`]
    #[snafu(transparent)]
    DataOutOfBounds {
        /// Source error.
        source: DataOutOfBoundsError,
    },
}

/// Errors related to [`Arm9::hmac_sha1_key`].
#[derive(Debug, Snafu)]
pub enum Arm9HmacSha1KeyError {
    /// See [`Arm9Error`].
    #[snafu(transparent)]
    Arm9 {
        /// Source error.
        source: Arm9Error,
    },
    /// Occurs when trying to access the HMAC-SHA1 key while the ARM9 program is compressed.
    #[snafu(display("ARM9 program must be decompressed before accessing HMAC-SHA1 key:\n{backtrace}"))]
    HmacSha1KeyCompressed {
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// See [`DataOutOfBoundsError`]
    #[snafu(transparent)]
    DataOutOfBounds {
        /// Source error.
        source: DataOutOfBoundsError,
    },
}

/// Errors related to [`Arm9::decrypt_dsprot`] and [`Arm9::encrypt_dsprot`].
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum Arm9DsProtInfoError {
    /// See [`Arm9Error`].
    #[snafu(transparent)]
    Arm9 {
        /// Source error.
        source: Arm9Error,
    },
    /// Occurs when trying to detect DS Protect while the ARM9 program is compressed.
    #[snafu(display("ARM9 program must be decompressed before detecting DS Protect:\n{backtrace}"))]
    Compressed {
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// See [`DsProtError`].
    #[snafu(transparent)]
    DsProtError {
        /// Source error.
        source: DsProtError,
    },
}

/// Errors related to [`Arm9::libraries`].
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum Arm9LibrariesError {
    /// See [`Utf8Error`].
    #[snafu(transparent)]
    Utf8 {
        /// Source error.
        source: Utf8Error,
    },
    /// See [`OverflowError`].
    #[snafu(transparent)]
    Overflow {
        /// Source error.
        source: OverflowError,
    },
    /// See [`DataOutOfBoundsError`]
    #[snafu(transparent)]
    DataOutOfBounds {
        /// Source error.
        source: DataOutOfBoundsError,
    },
}

/// Options for [`Arm9::new`].
pub struct Arm9Options {
    /// Whether the program has an [`Arm9Footer`](super::raw::Arm9Footer).
    pub has_footer: bool,
}

/// Options for [`Arm9::with_autoloads`].
pub struct Arm9WithTcmsOptions {
    /// Whether the program was compressed originally.
    pub originally_compressed: bool,
    /// Whether the program was encrypted originally.
    pub originally_encrypted: bool,
    /// Current state of DS Protect. Can be absent, encrypted or unencrypted.
    pub dsprot_state: DsProtState,
    /// Whether the program has an [`Arm9Footer`](super::raw::Arm9Footer).
    pub has_footer: bool,
}

impl<'a> Arm9<'a> {
    /// Creates a new ARM9 program from raw data.
    pub fn new<T: Into<Cow<'a, [u8]>>>(
        data: T,
        offsets: Arm9Offsets,
        options: Arm9Options,
    ) -> Result<Self, Arm9AutoloadError> {
        let Arm9Options { has_footer } = options;
        let mut arm9 = Arm9 {
            data: data.into(),
            offsets,
            originally_compressed: false,
            originally_encrypted: false,
            dsprot_state: DsProtState::None,
            has_footer,
        };
        arm9.originally_compressed = arm9.is_compressed()?;
        arm9.originally_encrypted = arm9.is_encrypted();
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
    ) -> Result<Self, Arm9AutoloadError> {
        let autoload_blocks = (data.len() as u32)
            .checked_add(offsets.base_address)
            .ok_or_else(|| OverflowError::new("autoload blocks offset"))?;

        for autoload in autoloads {
            data.extend(autoload.full_data());
        }

        let autoload_infos_start = (data.len() as u32)
            .checked_add(offsets.base_address)
            .ok_or_else(|| OverflowError::new("autoload infos start offset"))?;
        for autoload in autoloads {
            data.extend(autoload.info().entry().to_bytes());
        }
        let autoload_infos_end = (data.len() as u32)
            .checked_add(offsets.base_address)
            .ok_or_else(|| OverflowError::new("autoload infos end offset"))?;

        let Arm9WithTcmsOptions { originally_compressed, originally_encrypted, dsprot_state, has_footer } = options;
        let mut arm9 =
            Self { data: data.into(), offsets, originally_compressed, originally_encrypted, dsprot_state, has_footer };

        let build_info = arm9.build_info_mut()?;
        build_info.autoload_blocks = autoload_blocks;
        build_info.autoload_infos_start = autoload_infos_start;
        build_info.autoload_infos_end = autoload_infos_end;

        Ok(arm9)
    }

    /// Returns whether this ARM9 program is followed by an [`Arm9Footer`](super::raw::Arm9Footer) in the ROM. Most ROMs have
    /// one, but some (mainly DSi-enhanced ones) put the build info offset in the ROM header instead and have no footer.
    pub fn has_footer(&self) -> bool {
        self.has_footer
    }

    /// Returns whether the secure area is encrypted. See [`Self::originally_encrypted`] for whether the secure area was
    /// encrypted originally.
    pub fn is_encrypted(&self) -> bool {
        #[allow(clippy::indexing_slicing)] // data.len() is checked
        if self.data.len() >= 8 && self.data[0..8] == SECURE_AREA_ID {
            false
        } else if self.data.len() >= 0x800 {
            let zero_count = self.data[0..0x800].iter().filter(|&&b| b == 0).count();
            zero_count < SECURE_AREA_UNENCRYPTED_THRESHOLD
        } else {
            true
        }
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
        #[allow(clippy::indexing_slicing)] // data.len() is checked
        secure_area.clone_from_slice(&self.data[0..0x4000]);

        let blowfish = Blowfish::new(key, gamecode, BlowfishLevel::Level2);
        blowfish.decrypt(&mut secure_area[0..8])?;

        let blowfish = Blowfish::new(key, gamecode, BlowfishLevel::Level3);
        blowfish.decrypt(&mut secure_area[0..0x800])?;

        if &secure_area[0..8] != SECURE_AREA_ENCRY_OBJ {
            log::warn!("Failed to decrypt secure area");
        }

        secure_area[0..8].copy_from_slice(&SECURE_AREA_ID);
        #[allow(clippy::indexing_slicing)] // data.len() is checked
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

        let secure_area = self.encrypted_secure_area(key, gamecode)?;
        #[allow(clippy::indexing_slicing)] // data.len() is checked
        self.data.to_mut()[0..0x4000].copy_from_slice(&secure_area);
        Ok(())
    }

    /// Returns an encrypted copy of the secure area.
    pub fn encrypted_secure_area(&self, key: &BlowfishKey, gamecode: u32) -> Result<[u8; 0x4000], Arm9Error> {
        if self.data.len() < 0x4000 {
            DataTooSmallSnafu { expected: 0x4000usize, actual: self.data.len() }.fail()?;
        }

        let mut secure_area = [0u8; 0x4000];
        #[allow(clippy::indexing_slicing)] // data.len() is checked
        secure_area.copy_from_slice(&self.data[0..0x4000]);
        #[allow(clippy::indexing_slicing)] // data.len() is checked
        if self.data[0..8] != SECURE_AREA_ID {
            return Ok(secure_area);
        }

        secure_area[0..8].copy_from_slice(SECURE_AREA_ENCRY_OBJ);

        let blowfish = Blowfish::new(key, gamecode, BlowfishLevel::Level3);
        blowfish.encrypt_unchecked(&mut secure_area[0..0x800]);

        let blowfish = Blowfish::new(key, gamecode, BlowfishLevel::Level2);
        blowfish.encrypt_unchecked(&mut secure_area[0..8]);

        Ok(secure_area)
    }

    /// Returns a CRC checksum of the encrypted secure area.
    pub fn secure_area_crc(&self, key: &BlowfishKey, gamecode: u32) -> Result<u16, Arm9Error> {
        let secure_area = self.encrypted_secure_area(key, gamecode)?;
        Ok(CRC_16_MODBUS.checksum(&secure_area))
    }

    /// Returns a reference to the build info.
    ///
    /// # Errors
    ///
    /// See [`BuildInfo::borrow_from_slice`].
    pub fn build_info(&self) -> Result<&BuildInfo, Arm9Error> {
        Ok(BuildInfo::borrow_from_slice(slice_data(&self.data, self.offsets.build_info.., || "build info")?)?)
    }

    /// Returns a mutable reference to the build info.
    ///
    /// # Errors
    ///
    /// See [`BuildInfo::borrow_from_slice_mut`].
    pub fn build_info_mut(&mut self) -> Result<&mut BuildInfo, Arm9Error> {
        Ok(BuildInfo::borrow_from_slice_mut(slice_data_mut(self.data.to_mut(), self.offsets.build_info.., || "build info")?)?)
    }

    /// Returns the library version strings in this [`Arm9`].
    ///
    /// # Errors
    ///
    /// This function will return an error if a library string is not valid UTF-8.
    pub fn libraries(&self) -> Result<Box<[LibraryEntry<'_>]>, Arm9LibrariesError> {
        let libraries_start = (self.offsets.build_info)
            .checked_add(size_of::<BuildInfo>() as u32)
            .ok_or_else(|| OverflowError::new("libraries start offset"))?;
        let mut address = self
            .base_address()
            .checked_add(libraries_start as u32)
            .ok_or_else(|| OverflowError::new("libraries start address"))?;
        let mut data = slice_data(&self.data, libraries_start.., || "libraries")?;

        #[allow(clippy::indexing_slicing)] // data.is_empty() was checked
        if data.is_empty() || data[0] != b'[' {
            return Ok(Box::new([]));
        }

        let mut libraries = Vec::new();

        'outer: while let Some((end_pos, _)) = data.iter().enumerate().find(|(_, c)| **c == b']') {
            #[allow(clippy::arithmetic_side_effects)] // can't overflow
            let end = end_pos + 1;

            #[allow(clippy::indexing_slicing)] // end is always in-bounds
            let version_string = str::from_utf8(&data[..end])?;

            libraries.push(LibraryEntry::new(address, version_string));

            address = address.checked_add(end as u32).ok_or_else(|| OverflowError::new("next library address"))?;
            #[allow(clippy::indexing_slicing)] // end is always in-bounds
            {
                data = &data[end..];
            }

            loop {
                match data.first() {
                    Some(b'\0') => {
                        if let Some(next_address) = address.checked_add(1)
                            && let Some(next_data) = data.get(1..)
                        {
                            address = next_address;
                            data = next_data;
                        } else {
                            break 'outer;
                        }
                    }
                    Some(b'[') => break,
                    _ => break 'outer,
                }
            }
        }

        Ok(libraries.into_boxed_slice())
    }

    /// Returns whether this ARM9 program is compressed. See [`Self::originally_compressed`] for whether the program was
    /// compressed originally.
    ///
    /// # Errors
    ///
    /// See [`Self::build_info`].
    pub fn is_compressed(&self) -> Result<bool, Arm9Error> {
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

        let data: Cow<[u8]> = LZ77.decompress(&self.data)?.decompressed.into();
        let old_data = replace(&mut self.data, data);
        let build_info = match self.build_info_mut() {
            Ok(build_info) => build_info,
            Err(e) => {
                self.data = old_data;
                return Err(e);
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
        let compressed_code_end =
            self.base_address().checked_add(length as u32).ok_or_else(|| OverflowError::new("compressed code end address"))?;
        let old_data = replace(&mut self.data, data);
        let build_info = match self.build_info_mut() {
            Ok(build_info) => build_info,
            Err(e) => {
                self.data = old_data;
                return Err(e);
            }
        };
        build_info.compressed_code_end = compressed_code_end;
        Ok(())
    }

    fn get_autoload_info_entries(&self, build_info: &BuildInfo) -> Result<Vec<AutoloadInfoEntry>, Arm9AutoloadError> {
        let start = build_info
            .autoload_infos_start
            .checked_sub(self.base_address())
            .ok_or_else(|| OverflowError::new("autoload infos start offset"))?;
        let end = build_info
            .autoload_infos_end
            .checked_sub(self.base_address())
            .ok_or_else(|| OverflowError::new("autoload infos end offset"))?;
        // The autoload blocks are located right before the autoload list
        let blocks_size = build_info
            .autoload_infos_start
            .checked_sub(build_info.autoload_blocks)
            .ok_or_else(|| OverflowError::new("autoload blocks size"))?;
        let data = slice_data(&self.data, start..end, || "autoload info entries")?;
        let autoload_info = AutoloadInfoEntry::parse_list(data, blocks_size)?;
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
            .into_iter()
            .enumerate()
            .map(|(index, entry)| AutoloadInfo::new(entry, index as u32))
            .collect())
    }

    /// Returns the autoloads of this [`Arm9`].
    ///
    /// # Errors
    ///
    /// This function will return an error if [`Self::build_info`] or [`Self::get_autoload_infos`] fails or this ARM9 program
    /// is compressed.
    pub fn autoloads(&self) -> Result<Box<[Autoload<'_>]>, Arm9AutoloadError> {
        let build_info = self.build_info()?;
        if build_info.is_compressed() {
            CompressedSnafu {}.fail()?;
        }
        let autoload_infos = self.autoload_infos()?;

        let mut autoloads = vec![];
        let mut load_offset = build_info
            .autoload_blocks
            .checked_sub(self.base_address())
            .ok_or_else(|| OverflowError::new("first autoload block offset"))?;
        for autoload_info in autoload_infos {
            let start = load_offset;
            let end =
                start.checked_add(autoload_info.code_size()).ok_or_else(|| OverflowError::new("autoload block end offset"))?;
            let data = slice_data(&self.data, start..end, || "autoload block")?;
            autoloads.push(Autoload::new(data, autoload_info)?);
            load_offset = load_offset
                .checked_add(autoload_info.code_size())
                .ok_or_else(|| OverflowError::new("next autoload block offset"))?;
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
        #[allow(clippy::arithmetic_side_effects)] // small number
        let start = i as u32 * 4;
        #[allow(clippy::arithmetic_side_effects)] // small number
        let end = start + 64;
        if end as usize > self.data.len() {
            return Ok(None);
        }
        let mut key = [0u8; 64];
        key.copy_from_slice(slice_data(&self.data, start..end, || "HMAC-SHA1 key")?);
        Ok(Some(key))
    }

    fn overlay_table_signature_range(&self) -> Result<Option<Range<u32>>, Arm9OverlaySignaturesError> {
        let overlay_signatures_offset = self.overlay_signatures_offset();
        if overlay_signatures_offset == 0 {
            return Ok(None);
        }

        if self.is_compressed()? {
            OverlaySignaturesCompressedSnafu {}.fail()?;
        }

        // The overlay table signature is located right before the overlay signatures
        let start = overlay_signatures_offset
            .checked_sub(size_of::<HmacSha1Signature>() as u32)
            .ok_or_else(|| OverflowError::new("overlay table signature offset"))?;
        let end = overlay_signatures_offset;
        if end as usize > self.data.len() {
            return Ok(None);
        }
        Ok(Some(start..end))
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
        let data = slice_data(&self.data, range, || "overlay table signature")?;
        debug_assert_eq!(data.len(), size_of::<HmacSha1Signature>());

        let signature = HmacSha1Signature::borrow_from_slice(data)?;
        #[allow(clippy::unwrap_used)] // range is always size_of::<HmacSha1Signature>() bytes long
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
        let data = slice_data_mut(self.data.to_mut(), range, || "overlay table signature")?;
        debug_assert_eq!(data.len(), size_of::<HmacSha1Signature>());

        let signature = HmacSha1Signature::borrow_from_slice_mut(data)?;
        #[allow(clippy::unwrap_used)] // range is always size_of::<HmacSha1Signature>() bytes long
        Ok(Some(signature.first_mut().unwrap()))
    }

    fn overlay_signatures_range(&self, num_overlays: usize) -> Result<Option<Range<u32>>, Arm9OverlaySignaturesError> {
        let start = self.overlay_signatures_offset();
        if start == 0 {
            return Ok(None);
        }

        if self.is_compressed()? {
            OverlaySignaturesCompressedSnafu {}.fail()?;
        }

        let num_overlays = u32::try_from(num_overlays).map_err(|_| OverflowError::new("number of overlays"))?;
        let signatures_size = (size_of::<HmacSha1Signature>() as u32)
            .checked_mul(num_overlays)
            .ok_or_else(|| OverflowError::new("overlay signatures size"))?;
        let end = start.checked_add(signatures_size).ok_or_else(|| OverflowError::new("overlay signatures end offset"))?;
        if end as usize > self.data.len() {
            return Ok(None);
        }
        Ok(Some(start..end))
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
        let data = slice_data(&self.data, range, || "overlay signatures")?;
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
        let data = slice_data_mut(self.data.to_mut(), range, || "overlay signatures")?;
        Ok(Some(HmacSha1Signature::borrow_from_slice_mut(data)?))
    }

    /// Returns the code of this ARM9 program.
    ///
    /// # Errors
    ///
    /// See [`Self::build_info`].
    pub fn code(&self) -> Result<&[u8], Arm9Error> {
        let build_info = self.build_info()?;
        let end =
            build_info.bss_start.checked_sub(self.base_address()).ok_or_else(|| OverflowError::new("ARM9 code end offset"))?;
        Ok(slice_data(&self.data, ..end, || "ARM9 code")?)
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
    pub fn end_address(&self) -> Result<u32, Arm9Error> {
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
    pub fn bss(&self) -> Result<Range<u32>, Arm9Error> {
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
            if let Some(signature) = overlay.signature()
                && let Some(dest_signature) = signatures.get_mut(overlay.id() as usize)
            {
                *dest_signature = signature;
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

    /// Decrypts all functions in this ARM9 program that were encrypted by DS Protect. Does nothing
    /// if [`Arm9::dsprot_state`] is [`DsProtState::Unencrypted`].
    ///
    /// # Errors
    ///
    /// This function will return an error if [`DsProtInfo::decrypt`] fails.
    pub fn decrypt_dsprot(
        &mut self,
        options: &DsProtDecryptOptions,
    ) -> Result<Option<&DsProtDecryptResult>, Arm9DsProtInfoError> {
        if self.dsprot_state.is_unencrypted() {
            // Can't flatten this code due to conditional reference return (known borrow checker limitation)
            #[allow(clippy::unreachable)]
            if let DsProtState::Unencrypted(result) = &self.dsprot_state {
                Ok(Some(result))
            } else {
                unreachable!();
            }
        } else {
            let dsprot_info = if self.is_compressed()? {
                return arm9_ds_prot_info_error::CompressedSnafu.fail();
            } else if let Some(dsprot_info) = DsProtInfo::detect(&self.data) {
                dsprot_info
            } else {
                // DS Protect is not used
                return Ok(None);
            };

            let base_address = self.base_address();
            let result = dsprot_info.decrypt(self.data.to_mut(), base_address, options)?;
            self.dsprot_state = DsProtState::Unencrypted(result);
            #[allow(clippy::unreachable)]
            let DsProtState::Unencrypted(result) = &self.dsprot_state else { unreachable!() };
            Ok(Some(result))
        }
    }

    /// Encrypts DS Protect functions in this ARM9 program. This can only be done if
    /// [`Arm9::dsprot_state`] is [`DsProtState::Unencrypted`].
    ///
    /// # Errors
    ///
    /// This function will return an error if [`DsProtInfo::decrypt`] fails.
    pub fn encrypt_dsprot(&mut self, options: &DsProtEncryptOptions) -> Result<(), Arm9DsProtInfoError> {
        let dsprot_state = std::mem::replace(&mut self.dsprot_state, DsProtState::None);
        let DsProtState::Unencrypted(dsprot_result) = dsprot_state else {
            return Ok(());
        };

        let base_address = self.base_address();
        dsprot_result.encrypt(self.data.to_mut(), base_address, options)?;
        self.dsprot_state = DsProtState::Encrypted(dsprot_result);

        Ok(())
    }

    /// Returns the [`DsProtState`] of this ARM9 program.
    pub fn dsprot_state(&self) -> &DsProtState {
        &self.dsprot_state
    }

    pub(crate) fn set_dsprot_state(&mut self, dsprot_state: DsProtState) {
        self.dsprot_state = dsprot_state;
    }
}

impl AsRef<[u8]> for Arm9<'_> {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}
