use std::{backtrace::Backtrace, borrow::Cow};

use serde::{Deserialize, Serialize};
use snafu::Snafu;

use super::{
    Arm9, Arm9OverlaySignaturesError,
    raw::{self, HmacSha1Signature, OverlayFlags, RawFatError, RawHeaderError},
};
use crate::{
    compress::lz77::{Lz77, Lz77CompressError, Lz77DecompressError},
    crypto::{
        dsprot::{DsProtDecryptOptions, DsProtDecryptResult, DsProtEncryptOptions, DsProtError, DsProtInfo, DsProtState},
        hmac_sha1::HmacSha1,
    },
    error::{DataOutOfBoundsError, OverflowError, slice_data},
    rom::{Arm9HmacSha1KeyError, raw::FileAlloc},
};

/// An overlay module for ARM9/ARM7.
#[derive(Clone, PartialEq, Eq)]
pub struct Overlay<'a> {
    originally_compressed: bool,
    originally_signed: bool,
    info: OverlayInfo,
    signature: Option<HmacSha1Signature>,
    data: Cow<'a, [u8]>,
    dsprot_state: DsProtState,
}

const LZ77: Lz77 = Lz77 {};

/// Options for creating an [`Overlay`].
pub struct OverlayOptions {
    /// Whether the overlay was originally compressed.
    pub originally_compressed: bool,
    /// Whether the overlay was originally signed.
    pub originally_signed: bool,
    /// Overlay info.
    pub info: OverlayInfo,
    /// Current state of DS Protect. Can be absent, encrypted or unencrypted.
    pub dsprot_state: DsProtState,
}

/// Errors related to [`Overlay`].
#[derive(Debug, Snafu)]
pub enum OverlayError {
    /// See [`RawHeaderError`].
    #[snafu(transparent)]
    RawHeader {
        /// Source error.
        source: RawHeaderError,
    },
    /// See [`RawFatError`].
    #[snafu(transparent)]
    RawFat {
        /// Source error.
        source: RawFatError,
    },
    /// See [`Arm9OverlaySignaturesError`].
    #[snafu(transparent)]
    Arm9OverlaySignatures {
        /// Source error.
        source: Arm9OverlaySignaturesError,
    },
    /// Occurs when trying to create a signed ARM7 overlay, but signing ARM7 overlays is not supported.
    #[snafu(display("signing ARM7 overlays is not supported:\n{backtrace}"))]
    SignedArm7Overlay {
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// Occurs when trying to compute the signature but the overlay is not in its originally compressed state.
    #[snafu(display("cannot compute signature for overlay that is not in its originally compressed state:\n{backtrace}"))]
    OverlayCompression {
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// Occurs when trying to compute the signature while parsing the ROM, but the original signature was not found in ARM9.
    #[snafu(transparent)]
    Arm9HmacSha1Key {
        /// Source error.
        source: Arm9HmacSha1KeyError,
    },
    /// Occurs when constructing a new [`Overlay`] but the overlay file is not in the FAT.
    #[snafu(display("overlay {overlay_id} with file ID {file_id} is not in the FAT:\n{backtrace}"))]
    NotInFat {
        /// The overlay's ID.
        overlay_id: u32,
        /// The overlay's file ID.
        file_id: u32,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// See [`DataOutOfBoundsError`]
    #[snafu(transparent)]
    DataOutOfBounds {
        /// Source error.
        source: DataOutOfBoundsError,
    },
    /// Occurs when trying to access the overlay's [code](Overlay::code) while it is compressed.
    #[snafu(display("cannot access the code of overlay {overlay_id} while it is compressed:\n{backtrace}"))]
    Compressed {
        /// The overlay's ID.
        overlay_id: u16,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
}

/// Errors related to [`Overlay::decrypt_dsprot`] and [`Overlay::encrypt_dsprot`].
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum OverlayDsProtError {
    /// Occurs when trying to detect DS Protect while the overlay is compressed.
    #[snafu(display("overlay must be decompressed before detecting DS Protect:\n{backtrace}"))]
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

impl<'a> Overlay<'a> {
    /// Creates a new [`Overlay`] from plain data.
    pub fn new<T: Into<Cow<'a, [u8]>>>(data: T, options: OverlayOptions) -> Result<Self, OverlayError> {
        let OverlayOptions { originally_compressed, originally_signed, info, dsprot_state } = options;
        let data = data.into();

        Ok(Self { originally_compressed, originally_signed, info, signature: None, data, dsprot_state })
    }

    /// Parses an ARM9 [`Overlay`] from a ROM.
    ///
    /// # Errors
    ///
    /// This function will return an error if the overlay is signed and the ARM9 program does not contain overlay signatures.
    pub fn parse_arm9(overlay: &raw::Overlay, rom: &'a raw::Rom, arm9: &Arm9) -> Result<Self, OverlayError> {
        let fat = rom.fat()?;

        let alloc: &FileAlloc = fat
            .get(overlay.file_id as usize)
            .ok_or_else(|| NotInFatSnafu { overlay_id: overlay.id, file_id: overlay.file_id }.build())?;
        let data = slice_data(rom.data(), alloc.range(), || format!("file offset range of ARM9 overlay {}", overlay.id))?;

        let mut parsed_overlay = Self {
            originally_compressed: overlay.flags.is_compressed(),
            originally_signed: overlay.flags.is_signed(),
            info: OverlayInfo::new(overlay),
            signature: None,
            data: Cow::Borrowed(data),
            dsprot_state: DsProtState::None,
        };

        if overlay.flags.is_signed() {
            let num_overlays = rom.num_arm9_overlays()?;
            let signatures = arm9.overlay_signatures(num_overlays)?;
            if let Some(signatures) = signatures {
                parsed_overlay.signature = signatures.get(overlay.id as usize).copied();
            } else if let Some(key) = arm9.hmac_sha1_key()? {
                // Compute the signature if it's missing
                parsed_overlay.sign(&HmacSha1::new(key))?;
            } else {
                log::error!(
                    "ARM9 overlay {} was marked as signed, but no signature or HMAC-SHA1 key was found in ARM9",
                    overlay.id
                );
            }
        }

        Ok(parsed_overlay)
    }

    /// Parses an ARM7 [`Overlay`] from a ROM.
    ///
    /// # Errors
    ///
    /// This function will return an error if the overlay is signed, as ARM7 overlay signatures are not supported.
    pub fn parse_arm7(overlay: &raw::Overlay, rom: &'a raw::Rom) -> Result<Self, OverlayError> {
        let fat = rom.fat()?;

        let alloc: &FileAlloc = fat
            .get(overlay.file_id as usize)
            .ok_or_else(|| NotInFatSnafu { overlay_id: overlay.id, file_id: overlay.file_id }.build())?;
        let data = slice_data(rom.data(), alloc.range(), || format!("file offset range of ARM7 overlay {}", overlay.id))?;

        if overlay.flags.is_signed() {
            return SignedArm7OverlaySnafu {}.fail();
        }

        let overlay = Self {
            originally_compressed: overlay.flags.is_compressed(),
            originally_signed: overlay.flags.is_signed(),
            info: OverlayInfo::new(overlay),
            signature: None,
            data: Cow::Borrowed(data),
            dsprot_state: DsProtState::None,
        };

        Ok(overlay)
    }

    /// Builds a raw overlay table entry.
    pub fn build(&self) -> raw::Overlay {
        let mut flags = OverlayFlags::new();
        flags.set_is_compressed(self.is_compressed());
        flags.set_is_signed(self.is_signed());
        if self.is_compressed() {
            flags.set_size(self.data.len());
        }

        raw::Overlay {
            id: self.id() as u32,
            base_addr: self.base_address(),
            code_size: self.code_size(),
            bss_size: self.bss_size(),
            ctor_start: self.ctor_start(),
            ctor_end: self.ctor_end(),
            file_id: self.file_id(),
            flags,
        }
    }

    /// Returns the ID of this [`Overlay`].
    pub fn id(&self) -> u16 {
        self.info.id as u16
    }

    /// Returns the base address of this [`Overlay`].
    pub fn base_address(&self) -> u32 {
        self.info.base_address
    }

    /// Returns the end address of this [`Overlay`].
    ///
    /// # Errors
    ///
    /// This function will return an error if the base address, code size and .bss size add up to more than 32 bits, which
    /// can happen if the overlay table is malformed.
    pub fn end_address(&self) -> Result<u32, OverflowError> {
        self.info
            .base_address
            .checked_add(self.info.code_size)
            .and_then(|address| address.checked_add(self.info.bss_size))
            .ok_or_else(|| OverflowError::new(format!("end address of overlay {}", self.info.id)))
    }

    /// Returns the size of initialized data in this [`Overlay`].
    pub fn code_size(&self) -> u32 {
        self.info.code_size
    }

    /// Returns the size of uninitialized data in this [`Overlay`].
    pub fn bss_size(&self) -> u32 {
        self.info.bss_size
    }

    /// Returns the offset to the start of the .ctor section.
    pub fn ctor_start(&self) -> u32 {
        self.info.ctor_start
    }

    /// Returns the offset to the end of the .ctor section.
    pub fn ctor_end(&self) -> u32 {
        self.info.ctor_end
    }

    /// Returns the file ID of this [`Overlay`].
    pub fn file_id(&self) -> u32 {
        self.info.file_id
    }

    /// Returns whether this [`Overlay`] is compressed. See [`Self::originally_compressed`] for whether this overlay was
    /// compressed originally.
    pub fn is_compressed(&self) -> bool {
        self.info.compressed
    }

    /// Returns whether this [`Overlay`] has a signature. See [`Self::originally_signed`] for whether this overlay was
    /// signed originally.
    pub fn is_signed(&self) -> bool {
        self.signature.is_some()
    }

    /// Decompresses this [`Overlay`], but does nothing if already decompressed.
    pub fn decompress(&mut self) -> Result<(), Lz77DecompressError> {
        if !self.is_compressed() {
            return Ok(());
        }
        self.data = LZ77.decompress(&self.data)?.decompressed.into();
        self.info.compressed = false;
        Ok(())
    }

    /// Compresses this [`Overlay`], but does nothing if already compressed.
    ///
    /// # Errors
    ///
    /// This function will return an error if an I/O operation fails.
    pub fn compress(&mut self) -> Result<(), Lz77CompressError> {
        if self.is_compressed() {
            return Ok(());
        }
        self.data = LZ77.compress(&self.data, 0)?.into_vec().into();
        self.info.compressed = true;
        Ok(())
    }

    /// Returns a reference to the code of this [`Overlay`].
    ///
    /// # Errors
    ///
    /// This function will return an error if the overlay is compressed or if [`Self::code_size`] is
    /// larger than the actual size of the overlay's contents.
    pub fn code(&self) -> Result<&[u8], OverlayError> {
        if self.is_compressed() {
            return CompressedSnafu { overlay_id: self.id() }.fail();
        }
        Ok(slice_data(&self.data, ..self.code_size(), || format!("code of overlay {}", self.id()))?)
    }

    /// Returns a reference to the full data of this [`Overlay`].
    pub fn full_data(&self) -> &[u8] {
        &self.data
    }

    /// Returns a reference to the info of this [`Overlay`].
    pub fn info(&self) -> &OverlayInfo {
        &self.info
    }

    /// Returns whether this [`Overlay`] was compressed originally. See [`Self::is_compressed`] for the current state.
    pub fn originally_compressed(&self) -> bool {
        self.originally_compressed
    }

    /// Returns whether this [`Overlay`] was compressed signed. See [`Self::is_signed`] for the current state.
    pub fn originally_signed(&self) -> bool {
        self.originally_signed
    }

    /// Computes the signature of this [`Overlay`] using the given HMAC-SHA1 key.
    pub fn compute_signature(&self, hmac_sha1: &HmacSha1) -> Result<HmacSha1Signature, OverlayError> {
        if self.is_compressed() != self.originally_compressed {
            OverlayCompressionSnafu {}.fail()?;
        }

        Ok(HmacSha1Signature::from_hmac_sha1(hmac_sha1, self.data.as_ref()))
    }

    /// Returns the signature of this [`Overlay`], if it exists.
    pub fn signature(&self) -> Option<HmacSha1Signature> {
        self.signature
    }

    /// Verifies the signature of this [`Overlay`] using the given HMAC-SHA1 key.
    pub fn verify_signature(&self, hmac_sha1: &HmacSha1) -> Result<bool, OverlayError> {
        let Some(signature) = self.signature() else {
            return Ok(true);
        };

        let computed_signature = self.compute_signature(hmac_sha1)?;
        Ok(computed_signature == signature)
    }

    /// Signs this [`Overlay`] using the given HMAC-SHA1 key.
    pub fn sign(&mut self, hmac_sha1: &HmacSha1) -> Result<(), OverlayError> {
        self.signature = Some(self.compute_signature(hmac_sha1)?);
        Ok(())
    }

    /// Decrypts all functions in this overlay that were encrypted by DS Protect. Does nothing if
    /// [`Overlay::dsprot_state`] is [`DsProtState::Unencrypted`].
    ///
    /// # Errors
    ///
    /// This function will return an error if [`DsProtInfo::decrypt`] fails.
    #[allow(clippy::unreachable)] // borrow checker limitation
    pub fn decrypt_dsprot(
        &mut self,
        options: &DsProtDecryptOptions,
    ) -> Result<Option<&DsProtDecryptResult>, OverlayDsProtError> {
        if self.dsprot_state.is_unencrypted() {
            // Can't flatten this code due to conditional reference return (known borrow checker limitation)
            if let DsProtState::Unencrypted(result) = &self.dsprot_state {
                Ok(Some(result))
            } else {
                unreachable!();
            }
        } else {
            let dsprot_info = if self.is_compressed() {
                return overlay_ds_prot_error::CompressedSnafu.fail();
            } else if let Some(dsprot_info) = DsProtInfo::detect(&self.data) {
                dsprot_info
            } else {
                // DS Protect is not used
                return Ok(None);
            };

            let base_address = self.base_address();
            let result = dsprot_info.decrypt(self.data.to_mut(), base_address, options)?;
            self.dsprot_state = DsProtState::Unencrypted(result);
            let DsProtState::Unencrypted(result) = &self.dsprot_state else { unreachable!() };
            Ok(Some(result))
        }
    }

    /// Encrypts DS Protect functions in this overlay. This can only be done if
    /// [`Overlay::dsprot_state`] is [`DsProtState::Unencrypted`].
    ///
    /// # Errors
    ///
    /// This function will return an error if [`DsProtInfo::decrypt`] fails.
    pub fn encrypt_dsprot(&mut self, options: &DsProtEncryptOptions) -> Result<(), OverlayDsProtError> {
        let dsprot_state = std::mem::replace(&mut self.dsprot_state, DsProtState::None);
        let DsProtState::Unencrypted(dsprot_result) = dsprot_state else {
            self.dsprot_state = dsprot_state; // revert replace
            return Ok(());
        };

        let base_address = self.base_address();
        dsprot_result.encrypt(self.data.to_mut(), base_address, options)?;
        self.dsprot_state = DsProtState::Encrypted(dsprot_result);

        Ok(())
    }

    /// Returns the [`DsProtState`] of this overlay.
    pub fn dsprot_state(&self) -> &DsProtState {
        &self.dsprot_state
    }

    pub(crate) fn set_dsprot_state(&mut self, dsprot_state: DsProtState) {
        self.dsprot_state = dsprot_state;
    }
}

/// Info of an [`Overlay`], similar to an entry in the overlay table.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct OverlayInfo {
    /// Overlay ID.
    pub id: u32,
    /// Base address.
    pub base_address: u32,
    /// Initialized size.
    pub code_size: u32,
    /// Uninitialized size.
    pub bss_size: u32,
    /// Offset to start of .ctor section.
    pub ctor_start: u32,
    /// Offset to end of .ctor section.
    pub ctor_end: u32,
    /// File ID for the FAT.
    pub file_id: u32,
    /// Whether the overlay is compressed.
    pub compressed: bool,
}

impl OverlayInfo {
    /// Creates a new [`OverlayInfo`] from raw data.
    pub fn new(overlay: &raw::Overlay) -> Self {
        Self {
            id: overlay.id,
            base_address: overlay.base_addr,
            code_size: overlay.code_size,
            bss_size: overlay.bss_size,
            ctor_start: overlay.ctor_start,
            ctor_end: overlay.ctor_end,
            file_id: overlay.file_id,
            compressed: overlay.flags.is_compressed(),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn make_overlay(base_address: u32, code_size: u32, bss_size: u32) -> Overlay<'static> {
        let info = OverlayInfo {
            id: 0,
            base_address,
            code_size,
            bss_size,
            ctor_start: 0,
            ctor_end: 0,
            file_id: 0,
            compressed: false,
        };
        let options =
            OverlayOptions { originally_compressed: false, originally_signed: false, info, dsprot_state: DsProtState::None };
        Overlay::new(vec![], options).unwrap()
    }

    #[test]
    fn end_address() {
        assert_eq!(make_overlay(0x02000000, 0x100, 0x20).end_address().unwrap(), 0x02000120);
        assert_eq!(make_overlay(0xffffffe0, 0x10, 0xf).end_address().unwrap(), u32::MAX);
    }

    #[test]
    fn end_address_overflow_is_error() {
        assert!(make_overlay(0xfffffff0, 0x10, 0).end_address().is_err());
        assert!(make_overlay(0xfffffff0, 0x8, 0x8).end_address().is_err());
        assert!(make_overlay(0x02000000, 0, u32::MAX).end_address().is_err());
    }
}
