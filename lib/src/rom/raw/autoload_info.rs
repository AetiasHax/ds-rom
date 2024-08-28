use std::{
    fmt::Display,
    mem::{align_of, size_of},
};

use bytemuck::{Pod, PodCastError, Zeroable};
use serde::{Deserialize, Serialize};
use snafu::{Backtrace, Snafu};

use super::RawBuildInfoError;

/// Info about an autoload block.
#[repr(C)]
#[derive(Clone, Copy, Zeroable, Pod, Deserialize, Serialize)]
pub struct AutoloadInfo {
    /// Base address of the autoload module.
    pub base_address: u32,
    /// Size of the module's initialized area.
    pub code_size: u32,
    /// Size of the module's uninitialized area.
    pub bss_size: u32,
}

/// Autoload kind.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Deserialize, Serialize)]
pub enum AutoloadKind {
    /// Instruction TCM (Tightly Coupled Memory). Mainly used to make functions have fast and predictable load times.
    Itcm,
    /// Data TCM (Tightly Coupled Memory). Mainly used to make data have fast and predictable access times.
    Dtcm,
    /// Unknown autoload kind.
    Unknown,
}

/// Errors related to [`AutoloadInfo`].
#[derive(Debug, Snafu)]
pub enum RawAutoloadInfoError {
    /// See [`RawBuildInfoError`].
    #[snafu(transparent)]
    RawBuildInfo {
        /// Source error.
        source: RawBuildInfoError,
    },
    /// Occurs when the input is not evenly divisible into a slice of [`AutoloadInfo`].
    #[snafu(display("autoload infos must be a multiple of {} bytes:\n{backtrace}", size_of::<AutoloadInfo>()))]
    InvalidSize {
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// Occurs when the input is less aligned than [`AutoloadInfo`].
    #[snafu(display("expected {expected}-alignment for autoload infos but got {actual}-alignment:\n{backtrace}"))]
    Misaligned {
        /// Expected alignment.
        expected: usize,
        /// Actual input alignment.
        actual: usize,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
}

impl AutoloadInfo {
    fn check_size(data: &'_ [u8]) -> Result<(), RawAutoloadInfoError> {
        let size = size_of::<Self>();
        if data.len() % size != 0 {
            InvalidSizeSnafu {}.fail()
        } else {
            Ok(())
        }
    }

    fn handle_pod_cast<T>(result: Result<T, PodCastError>, addr: usize) -> Result<T, RawAutoloadInfoError> {
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

    /// Reinterprets a `&[u8]` as a slice of [`AutoloadInfo`].
    ///
    /// # Errors
    ///
    /// This function will return an error if the input has the wrong size or alignment.
    pub fn borrow_from_slice(data: &'_ [u8]) -> Result<&'_ [Self], RawAutoloadInfoError> {
        Self::check_size(data)?;
        let addr = data as *const [u8] as *const () as usize;
        Self::handle_pod_cast(bytemuck::try_cast_slice(data), addr)
    }

    /// Returns the kind of this [`AutoloadInfo`].
    pub fn kind(&self) -> AutoloadKind {
        match self.base_address {
            0x1ff8000 => AutoloadKind::Itcm,
            0x27e0000 => AutoloadKind::Dtcm,
            _ => AutoloadKind::Unknown,
        }
    }

    /// Creates a [`DisplayAutoloadInfo`] which implements [`Display`].
    pub fn display(&self, indent: usize) -> DisplayAutoloadInfo {
        DisplayAutoloadInfo { info: self, indent }
    }
}

/// Can be used to display values inside [`AutoloadInfo`].
pub struct DisplayAutoloadInfo<'a> {
    info: &'a AutoloadInfo,
    indent: usize,
}

impl<'a> Display for DisplayAutoloadInfo<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let i = format!("{:indent$}", "", indent = self.indent);
        let info = &self.info;
        writeln!(f, "{i}Type .......... : {}", info.kind())?;
        writeln!(f, "{i}Base address .. : {:#x}", info.base_address)?;
        writeln!(f, "{i}Code size ..... : {:#x}", info.code_size)?;
        writeln!(f, "{i}.bss size ..... : {:#x}", info.bss_size)?;
        Ok(())
    }
}

impl Display for AutoloadKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AutoloadKind::Itcm => write!(f, "ITCM"),
            AutoloadKind::Dtcm => write!(f, "DTCM"),
            AutoloadKind::Unknown => write!(f, "Unknown"),
        }
    }
}
