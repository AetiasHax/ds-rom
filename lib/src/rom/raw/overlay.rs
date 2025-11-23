use std::{
    fmt::Display,
    mem::{align_of, size_of},
};

use bitfield_struct::bitfield;
use bytemuck::{Pod, PodCastError, Zeroable};
use snafu::{Backtrace, Snafu};

use super::{RawArm9Error, RawHeaderError};
use crate::rom::Arm9OverlaySignaturesError;

/// An entry in an overlay table. This is the raw struct, see the plain one [here](super::super::Overlay).
#[repr(C)]
#[derive(Clone, Copy, Zeroable, Pod)]
pub struct Overlay {
    /// Overlay ID.
    pub id: u32,
    /// Base address.
    pub base_addr: u32,
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
    /// Flags and compressed size.
    pub flags: OverlayFlags,
}

/// Errors related to [`Overlay`].
#[derive(Snafu, Debug)]
pub enum RawOverlayError {
    /// See [`RawHeaderError`].
    #[snafu(transparent)]
    RawHeader {
        /// Source error.
        source: RawHeaderError,
    },
    /// See [`RawHeaderError`].
    #[snafu(transparent)]
    RawArm9 {
        /// Source error.
        source: RawArm9Error,
    },
    /// See [`Arm9OverlaySignaturesError`].
    #[snafu(transparent)]
    Arm9OverlaySignatures {
        /// Source error.
        source: Arm9OverlaySignaturesError,
    },
    /// Occurs when the input is not evenly divisible into a slice of [`Overlay`].
    #[snafu(display("the overlay table must be a multiple of {} bytes:\n{backtrace}", size_of::<Overlay>()))]
    InvalidSize {
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// Occurs when the input is less aligned than [`Overlay`].
    #[snafu(display("expected {expected}-alignment for overlay table but got {actual}-alignment:\n{backtrace}"))]
    Misaligned {
        /// Expected alignment.
        expected: usize,
        /// Actual input alignment.
        actual: usize,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
}

impl Overlay {
    fn check_size(data: &[u8]) -> Result<(), RawOverlayError> {
        let size = size_of::<Self>();
        if data.len() % size != 0 {
            InvalidSizeSnafu {}.fail()
        } else {
            Ok(())
        }
    }

    fn handle_pod_cast<T>(result: Result<T, PodCastError>, addr: usize) -> Result<T, RawOverlayError> {
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

    /// Reinterprets a `&[u8]` as a reference to [`Overlay`].
    ///
    /// # Errors
    ///
    /// This function will return an error if the input is the wrong size, or not aligned enough.
    pub fn borrow_from_slice(data: &'_ [u8]) -> Result<&'_ [Self], RawOverlayError> {
        Self::check_size(data)?;
        let addr = data as *const [u8] as *const () as usize;
        Self::handle_pod_cast(bytemuck::try_cast_slice(data), addr)
    }

    /// Creates a [`DisplayOverlay`] which implements [`Display`].
    pub fn display(&self, indent: usize) -> DisplayOverlay {
        DisplayOverlay { overlay: self, indent }
    }
}

/// Can be used to display values in [`Overlay`].
pub struct DisplayOverlay<'a> {
    overlay: &'a Overlay,
    indent: usize,
}

impl Display for DisplayOverlay<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let i = " ".repeat(self.indent);
        let overlay = &self.overlay;
        writeln!(f, "{i}ID ............... : {}", overlay.id)?;
        writeln!(f, "{i}File ID .......... : {}", overlay.file_id)?;
        writeln!(f, "{i}Base address ..... : {:#x}", overlay.base_addr)?;
        writeln!(f, "{i}Code size ........ : {:#x}", overlay.code_size)?;
        writeln!(f, "{i}.bss size ........ : {:#x}", overlay.bss_size)?;
        writeln!(f, "{i}.ctor start ...... : {:#x}", overlay.ctor_start)?;
        writeln!(f, "{i}.ctor end ........ : {:#x}", overlay.ctor_end)?;
        writeln!(f, "{i}Compressed size .. : {:#x}", overlay.flags.size())?;
        writeln!(f, "{i}Is compressed .... : {}", overlay.flags.is_compressed())?;
        writeln!(f, "{i}Is signed ........ : {}", overlay.flags.is_signed())?;
        writeln!(f, "{i}Reserved flags ... : {:#x}", overlay.flags.reserved())?;
        Ok(())
    }
}

/// Overlay flags and compressed size.
#[bitfield(u32)]
pub struct OverlayFlags {
    /// Compressed size, zero if not compressed.
    #[bits(24)]
    pub size: usize,
    pub is_compressed: bool,
    pub is_signed: bool,
    #[bits(6)]
    pub reserved: u8,
}

unsafe impl Zeroable for OverlayFlags {}
unsafe impl Pod for OverlayFlags {}
