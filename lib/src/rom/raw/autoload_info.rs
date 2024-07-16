use std::{
    fmt::Display,
    mem::{align_of, size_of},
};

use bytemuck::{Pod, PodCastError, Zeroable};
use serde::{Deserialize, Serialize};
use snafu::{Backtrace, Snafu};

use super::RawBuildInfoError;

#[repr(C)]
#[derive(Clone, Copy, Zeroable, Pod, Deserialize, Serialize)]
pub struct AutoloadInfo {
    pub base_address: u32,
    pub code_size: u32,
    pub bss_size: u32,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AutoloadKind {
    Itcm,
    Dtcm,
    Unknown,
}

#[derive(Debug, Snafu)]
pub enum RawAutoloadInfoError {
    #[snafu(transparent)]
    RawBuildInfo { source: RawBuildInfoError },
    #[snafu(display("autoload infos must be a multiple of {} bytes:\n{backtrace}", size_of::<AutoloadInfo>()))]
    InvalidSize { backtrace: Backtrace },
    #[snafu(display("expected {expected}-alignment for autoload infos but got {actual}-alignment:\n{backtrace}"))]
    Misaligned { expected: usize, actual: usize, backtrace: Backtrace },
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

    pub fn borrow_from_slice(data: &'_ [u8]) -> Result<&'_ [Self], RawAutoloadInfoError> {
        Self::check_size(data)?;
        let addr = data as *const [u8] as *const () as usize;
        Self::handle_pod_cast(bytemuck::try_cast_slice(data), addr)
    }

    pub fn kind(&self) -> AutoloadKind {
        match self.base_address {
            0x1ff8000 => AutoloadKind::Itcm,
            0x27e0000 => AutoloadKind::Dtcm,
            _ => AutoloadKind::Unknown,
        }
    }

    pub fn display(&self, indent: usize) -> DisplayAutoloadInfo {
        DisplayAutoloadInfo { info: self, indent }
    }
}

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
