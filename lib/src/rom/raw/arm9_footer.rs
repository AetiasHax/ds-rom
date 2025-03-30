use std::{
    fmt::Display,
    mem::{align_of, size_of},
};

use bytemuck::{Pod, PodCastError, Zeroable};
use snafu::{Backtrace, Snafu};

use super::{RawHeaderError, NITROCODE};

/// Footer of the ARM9 program.
#[repr(C)]
#[derive(Clone, Copy, Zeroable, Pod)]
pub struct Arm9Footer {
    nitrocode: u32,
    /// Offset to [super::BuildInfo].
    pub build_info_offset: u32,
    /// Offset to the overlay HMAC-SHA1 signature table.
    pub overlay_signatures_offset: u32,
}

/// Errors related to [`Arm9Footer`].
#[derive(Debug, Snafu)]
pub enum Arm9FooterError {
    /// See [RawHeaderError].
    #[snafu(transparent)]
    RawHeader {
        /// Source error.
        source: RawHeaderError,
    },
    /// Occurs when the given input is not the expected size for an ARM9 footer.
    #[snafu(display("ARM9 footer must be {expected} bytes but got {actual} bytes:\n{backtrace}"))]
    WrongSize {
        /// Expected ARM9 footer size.
        expected: usize,
        /// Actual input size.
        actual: usize,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// Occurs when the given input less aligned than [Arm9Footer].
    #[snafu(display("expected {expected}-alignment for ARM9 footer but got {actual}-alignment:\n{backtrace}"))]
    Misaligned {
        /// Expected alignment.
        expected: usize,
        /// Actual input alignment.
        actual: usize,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// Occurs when nitrocode was not found in the input.
    #[snafu(display("expected nitrocode {expected:#x} in ARM9 footer but got {actual:#x}:\n{backtrace}"))]
    NoNitrocode {
        /// Expected value.
        expected: u32,
        /// Actual input value.
        actual: u32,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
}

impl Arm9Footer {
    /// Creates a new [`Arm9Footer`].
    pub fn new(build_info_offset: u32, overlay_signatures_offset: u32) -> Self {
        Self { nitrocode: NITROCODE, build_info_offset, overlay_signatures_offset }
    }

    fn check_size(data: &'_ [u8]) -> Result<(), Arm9FooterError> {
        if data.len() != size_of::<Self>() {
            WrongSizeSnafu { expected: size_of::<Self>(), actual: data.len() }.fail()
        } else {
            Ok(())
        }
    }

    fn handle_pod_cast<T>(result: Result<T, PodCastError>, addr: usize) -> Result<T, Arm9FooterError> {
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

    fn check_nitrocode(&self) -> Result<(), Arm9FooterError> {
        if self.nitrocode != NITROCODE {
            NoNitrocodeSnafu { expected: NITROCODE, actual: self.nitrocode }.fail()
        } else {
            Ok(())
        }
    }

    /// Reinterprets a `&[u8]` as a reference to [`Arm9Footer`].
    ///
    /// # Errors
    ///
    /// This function will return an error if the input has the wrong size or alignment, or doesn't contain the nitrocode.
    pub fn borrow_from_slice(data: &'_ [u8]) -> Result<&'_ Self, Arm9FooterError> {
        Self::check_size(data)?;
        let addr = data as *const [u8] as *const () as usize;
        let footer: &Self = Self::handle_pod_cast(bytemuck::try_from_bytes(data), addr)?;
        footer.check_nitrocode()?;
        Ok(footer)
    }

    /// Reinterprets a `&mut [u8]` as a mutable reference to [`Arm9Footer`].
    ///
    /// # Errors
    ///
    /// This function will return an error if the input has the wrong size or alignment, or doesn't contain the nitrocode.
    pub fn borrow_from_slice_mut(data: &'_ mut [u8]) -> Result<&'_ mut Self, Arm9FooterError> {
        Self::check_size(data)?;
        let addr = data as *const [u8] as *const () as usize;
        let footer: &mut Self = Self::handle_pod_cast(bytemuck::try_from_bytes_mut(data), addr)?;
        footer.check_nitrocode()?;
        Ok(footer)
    }

    /// Creates a [`DisplayArm9Footer`] which implements [`Display`].
    pub fn display(&self, indent: usize) -> DisplayArm9Footer {
        DisplayArm9Footer { footer: self, indent }
    }
}

/// Can be used to display values in [`Arm9Footer`].
pub struct DisplayArm9Footer<'a> {
    footer: &'a Arm9Footer,
    indent: usize,
}

impl Display for DisplayArm9Footer<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let i = " ".repeat(self.indent);
        writeln!(f, "{i} Build info offset .......... : {:#x}", self.footer.build_info_offset)?;
        writeln!(f, "{i} Overlay signatures offset .. : {:#x}", self.footer.overlay_signatures_offset)
    }
}
