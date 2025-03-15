use std::{
    fmt::Display,
    mem::{align_of, size_of},
};

use bytemuck::{Pod, PodCastError, Zeroable};
use snafu::{Backtrace, Snafu};

use super::{RawHeaderError, NITROCODE};

/// Build info for the ARM9 module. This is the raw version, see the plain one [here](super::super::BuildInfo).
#[repr(C)]
#[derive(Clone, Copy, Zeroable, Pod)]
pub struct BuildInfo {
    /// Offset to the start of [`super::AutoloadInfo`]s.
    pub autoload_infos_start: u32,
    /// Offset to the end of [`super::AutoloadInfo`]s.
    pub autoload_infos_end: u32,
    /// Offset to where the autoload blocks start.
    pub autoload_blocks: u32,
    /// Offset to the start of uninitialized data in this module.
    pub bss_start: u32,
    /// Offset to the end of uninitialized data in this module.
    pub bss_end: u32,
    /// Size of this module after compression.
    pub compressed_code_end: u32,
    /// SDK version? Value is higher for newer games, but it's unclear what this value is for.
    pub sdk_version: u32,
    nitrocode: u32,
    nitrocode_rev: u32,
}

/// Errors related to [`BuildInfo`].
#[derive(Debug, Snafu)]
pub enum RawBuildInfoError {
    /// See [`RawHeaderError`].
    #[snafu(transparent)]
    RawHeader {
        /// Source error.
        source: RawHeaderError,
    },
    /// Occurs when the input is too small to fit [`BuildInfo`].
    #[snafu(display("expected {expected:#x} bytes for build info but had only {actual:#x}:\n{backtrace}"))]
    DataTooSmall {
        /// Expected size.
        expected: usize,
        /// Actual input size.
        actual: usize,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// Occurs when the input is less aligned than [`BuildInfo`].
    #[snafu(display("expected {expected}-alignment for build info but got {actual}-alignment:\n{backtrace}"))]
    Misaligned {
        /// Expected alignment.
        expected: usize,
        /// Actual input alignment.
        actual: usize,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// Occurs when the input does not contain the nitrocode.
    #[snafu(display("expected nitrocode {expected:#x} at the end of build info but got {actual:#x}:\n{backtrace}"))]
    NoNitrocode {
        /// Expected value.
        expected: u32,
        /// Actual value.
        actual: u32,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
}

impl BuildInfo {
    fn check_size(data: &'_ [u8]) -> Result<(), RawBuildInfoError> {
        let size = size_of::<Self>();
        if data.len() < size {
            DataTooSmallSnafu { expected: size, actual: data.len() }.fail()
        } else {
            Ok(())
        }
    }

    fn handle_pod_cast<T>(result: Result<T, PodCastError>, addr: usize) -> Result<T, RawBuildInfoError> {
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

    fn check_nitrocode(&self) -> Result<(), RawBuildInfoError> {
        if self.nitrocode != NITROCODE {
            NoNitrocodeSnafu { expected: NITROCODE, actual: self.nitrocode }.fail()
        } else if self.nitrocode_rev != NITROCODE.swap_bytes() {
            NoNitrocodeSnafu { expected: NITROCODE.swap_bytes(), actual: self.nitrocode_rev }.fail()
        } else {
            Ok(())
        }
    }

    /// Reinterprets a `&[u8]` as a reference to [`BuildInfo`].
    ///
    /// # Errors
    ///
    /// This function will return an error if the input is too small, not aligned enough or doesn't contain the nitrocode.
    pub fn borrow_from_slice(data: &'_ [u8]) -> Result<&'_ Self, RawBuildInfoError> {
        let size = size_of::<Self>();
        Self::check_size(data)?;
        let addr = data as *const [u8] as *const () as usize;
        let build_info: &Self = Self::handle_pod_cast(bytemuck::try_from_bytes(&data[..size]), addr)?;
        build_info.check_nitrocode()?;
        Ok(build_info)
    }

    /// Reinterprets a `&mut [u8]` as a mutable reference to [`BuildInfo`].
    ///
    /// # Errors
    ///
    /// This function will return an error if the input is too small, not aligned enough or doesn't contain the nitrocode.
    pub fn borrow_from_slice_mut(data: &'_ mut [u8]) -> Result<&'_ mut Self, RawBuildInfoError> {
        let size = size_of::<Self>();
        Self::check_size(data)?;
        let addr = data as *const [u8] as *const () as usize;
        let build_info: &mut Self = Self::handle_pod_cast(bytemuck::try_from_bytes_mut(&mut data[..size]), addr)?;
        build_info.check_nitrocode()?;
        Ok(build_info)
    }

    /// Returns whether this [`BuildInfo`] is compressed.
    pub fn is_compressed(&self) -> bool {
        self.compressed_code_end != 0
    }

    /// Creates a [`DisplayBuildInfo`] which implements [`Display`].
    pub fn display(&self, indent: usize) -> DisplayBuildInfo {
        DisplayBuildInfo { build_info: self, indent }
    }
}

/// Can be used to display values inside [`BuildInfo`].
pub struct DisplayBuildInfo<'a> {
    build_info: &'a BuildInfo,
    indent: usize,
}

impl Display for DisplayBuildInfo<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let i = format!("{:indent$}", "", indent = self.indent);
        let build_info = &self.build_info;
        writeln!(f, "{i}Autoload infos start .. : {:#x}", build_info.autoload_infos_start)?;
        writeln!(f, "{i}Autoload infos end .... : {:#x}", build_info.autoload_infos_end)?;
        writeln!(f, "{i}Autoload blocks ....... : {:#x}", build_info.autoload_blocks)?;
        writeln!(f, "{i}.bss start ............ : {:#x}", build_info.bss_start)?;
        writeln!(f, "{i}.bss end .............. : {:#x}", build_info.bss_end)?;
        writeln!(f, "{i}Compressed code end ... : {:#x}", build_info.compressed_code_end)?;
        writeln!(f, "{i}SDK version ........... : {:#x}", build_info.sdk_version)?;
        Ok(())
    }
}
