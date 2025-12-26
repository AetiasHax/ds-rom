use std::{backtrace::Backtrace, fmt::Display};

use bytemuck::{Pod, PodCastError, Zeroable};
use serde::{Deserialize, Serialize};
use snafu::Snafu;

use crate::{crypto::rsa::RsaSignature, rom::raw::RawHeaderError};

/// Contains the RSA signature used to verify the integrity of the ROM header and the ARM9 and ARM7
/// programs, after it is transferred for Download Play.
#[repr(C)]
#[derive(Zeroable, Pod, Clone, Copy, Serialize, Deserialize)]
pub struct MultibootSignature {
    magic: u32,
    rsa_signature: RsaSignature,
    key_seed: u32,
}

/// Magic number at the start of a multiboot signature.
pub const MULTIBOOT_SIGNATURE_MAGIC: u32 = 0x00016361;

/// Errors related to [`MultibootSignature`].
#[derive(Debug, Snafu)]
pub enum RawMultibootSignatureError {
    /// See [`RawHeaderError`].
    #[snafu(transparent)]
    RawHeader {
        /// Source error.
        source: RawHeaderError,
    },
    /// Occurs when the input is too small to contain a [`MultibootSignature`].
    #[snafu(display("expected {expected:#x} bytes for multiboot signature but had only {actual:#x}:\n{backtrace}"))]
    DataTooSmall {
        /// Expected size.
        expected: usize,
        /// Actual input size.
        actual: usize,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// Occurs when the input is less aligned than [`MultibootSignature`].
    #[snafu(display("expected {expected}-alignment but got {actual}-alignment:\n{backtrace}"))]
    Misaligned {
        /// Expected alignment.
        expected: usize,
        /// Actual alignment.
        actual: usize,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// Occurs when the magic number does not match [`MULTIBOOT_SIGNATURE_MAGIC`].
    #[snafu(display("expected magic number {expected:#010x} but got {actual:#010x}:\n{backtrace}"))]
    InvalidMagic {
        /// Expected magic number.
        expected: u32,
        /// Actual magic number.
        actual: u32,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
}

impl MultibootSignature {
    fn check_size(data: &'_ [u8]) -> Result<(), RawMultibootSignatureError> {
        let size = size_of::<Self>();
        if data.len() < size {
            DataTooSmallSnafu { expected: size, actual: data.len() }.fail()
        } else {
            Ok(())
        }
    }

    fn handle_pod_cast<T>(result: Result<T, PodCastError>, addr: usize) -> Result<T, RawMultibootSignatureError> {
        match result {
            Ok(build_info) => Ok(build_info),
            Err(PodCastError::TargetAlignmentGreaterAndInputNotAligned) => {
                MisalignedSnafu { expected: align_of::<Self>(), actual: 1usize << addr.trailing_zeros() }.fail()
            }
            Err(PodCastError::AlignmentMismatch) => panic!(),
            Err(PodCastError::OutputSliceWouldHaveSlop) => panic!(),
            Err(PodCastError::SizeMismatch) => unreachable!(),
        }
    }

    /// Reinterprets a `&[u8]` as a reference to [`MultibootSignature`].
    ///
    /// # Errors
    ///
    /// This function will return an error if the input is too small or not aligned enough.
    pub fn borrow_from_slice(data: &[u8]) -> Result<&Self, RawMultibootSignatureError> {
        let size = size_of::<Self>();
        Self::check_size(data)?;
        let addr = data as *const [u8] as *const () as usize;
        let multiboot_signature: &Self = Self::handle_pod_cast(bytemuck::try_from_bytes(&data[..size]), addr)?;
        if multiboot_signature.magic != MULTIBOOT_SIGNATURE_MAGIC {
            return InvalidMagicSnafu { expected: MULTIBOOT_SIGNATURE_MAGIC, actual: multiboot_signature.magic }.fail();
        }
        Ok(multiboot_signature)
    }

    /// Creates a [`DisplayMultibootSignature`] which implements [`Display`].
    pub fn display(&self, indent: usize) -> DisplayMultibootSignature<'_> {
        DisplayMultibootSignature { multiboot_signature: self, indent }
    }

    /// Returns the magic number of this [`MultibootSignature`]. This is always equal to [`MULTIBOOT_SIGNATURE_MAGIC`].
    pub fn magic(&self) -> u32 {
        self.magic
    }

    /// Returns the [`RsaSignature`] of this [`MultibootSignature`].
    pub fn rsa_signature(&self) -> &RsaSignature {
        &self.rsa_signature
    }

    /// Returns the RSA key seed of this [`MultibootSignature`].
    pub fn key_seed(&self) -> u32 {
        self.key_seed
    }
}

/// Can be used to display values inside [`MultibootSignature`].
pub struct DisplayMultibootSignature<'a> {
    multiboot_signature: &'a MultibootSignature,
    indent: usize,
}

impl Display for DisplayMultibootSignature<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let i = " ".repeat(self.indent);
        let multiboot_signature = &self.multiboot_signature;
        writeln!(f, "{i}Magic number ... : {:#010x}", multiboot_signature.magic)?;
        writeln!(f, "{i}RSA key seed ... : {:#010x}", multiboot_signature.key_seed)?;
        writeln!(f, "{i}RSA signature .. :\n{}", multiboot_signature.rsa_signature.display(self.indent + 2))?;
        Ok(())
    }
}
