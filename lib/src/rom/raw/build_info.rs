use std::{
    fmt::Display,
    mem::{align_of, size_of},
};

use bytemuck::{Pod, PodCastError, Zeroable};
use snafu::{Backtrace, Snafu};

use super::RawHeaderError;

const NITROCODE: u32 = (0x2106c0de as u32).swap_bytes();

#[repr(C)]
#[derive(Clone, Copy, Zeroable, Pod)]
pub struct BuildInfo {
    pub autoload_infos_start: u32,
    pub autoload_infos_end: u32,
    pub autoload_blocks: u32,
    pub bss_start: u32,
    pub bss_end: u32,
    pub compressed_code_end: u32,
    pub sdk_version: u32,
    nitrocode: u32,
    nitrocode_rev: u32,
}

#[derive(Debug, Snafu)]
pub enum RawBuildInfoError {
    #[snafu(transparent)]
    RawHeader { source: RawHeaderError },
    #[snafu(display("expected {expected:#x} bytes for build info but had only {actual:#x}:\n{backtrace}"))]
    DataTooSmall { expected: usize, actual: usize, backtrace: Backtrace },
    #[snafu(display("expected {expected}-alignment for build info but got {actual}-alignment:\n{backtrace}"))]
    Misaligned { expected: usize, actual: usize, backtrace: Backtrace },
    #[snafu(display("expected nitrocode {expected:#x} at the end of build info but got {actual:#x}:\n{backtrace}"))]
    NoNitrocode { expected: u32, actual: u32, backtrace: Backtrace },
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
                MisalignedSnafu { expected: align_of::<Self>(), actual: 1usize << addr.leading_zeros() }.fail()
            }
            Err(PodCastError::AlignmentMismatch) => panic!(),
            Err(PodCastError::OutputSliceWouldHaveSlop) => panic!(),
            Err(PodCastError::SizeMismatch) => unreachable!(),
        }
    }

    pub fn check_nitrocode(&self) -> Result<(), RawBuildInfoError> {
        if self.nitrocode != NITROCODE {
            NoNitrocodeSnafu { expected: NITROCODE, actual: self.nitrocode }.fail()
        } else if self.nitrocode_rev != NITROCODE.swap_bytes() {
            NoNitrocodeSnafu { expected: NITROCODE.swap_bytes(), actual: self.nitrocode_rev }.fail()
        } else {
            Ok(())
        }
    }

    pub fn borrow_from_slice(data: &'_ [u8]) -> Result<&'_ Self, RawBuildInfoError> {
        let size = size_of::<Self>();
        Self::check_size(data)?;
        let addr = data as *const [u8] as *const () as usize;
        let build_info: &Self = Self::handle_pod_cast(bytemuck::try_from_bytes(&data[..size]), addr)?;
        build_info.check_nitrocode().map(|_| build_info)
    }
    pub fn borrow_from_slice_mut(data: &'_ mut [u8]) -> Result<&'_ mut Self, RawBuildInfoError> {
        let size = size_of::<Self>();
        Self::check_size(data)?;
        let addr = data as *const [u8] as *const () as usize;
        let build_info: &mut Self = Self::handle_pod_cast(bytemuck::try_from_bytes_mut(&mut data[..size]), addr)?;
        build_info.check_nitrocode().map(|_| build_info)
    }

    pub fn is_compressed(&self) -> bool {
        self.compressed_code_end != 0
    }

    pub fn display(&self, indent: usize) -> DisplayBuildInfo {
        DisplayBuildInfo { build_info: self, indent }
    }
}

pub struct DisplayBuildInfo<'a> {
    build_info: &'a BuildInfo,
    indent: usize,
}

impl<'a> Display for DisplayBuildInfo<'a> {
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
