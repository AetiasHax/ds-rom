use std::mem::{align_of, size_of};

use bytemuck::{Pod, PodCastError, Zeroable};
use snafu::{Backtrace, Snafu};

use super::{RawHeaderError, NITROCODE};

#[repr(C)]
#[derive(Clone, Copy, Zeroable, Pod)]
pub struct Arm9Footer {
    nitrocode: u32,
    pub build_info_offset: u32,
    reserved: u32,
}

#[derive(Debug, Snafu)]
pub enum Arm9FooterError {
    #[snafu(transparent)]
    RawHeader { source: RawHeaderError },
    #[snafu(display("ARM9 footer must be {expected} bytes but got {actual} bytes:\n{backtrace}"))]
    WrongSize { expected: usize, actual: usize, backtrace: Backtrace },
    #[snafu(display("expected {expected}-alignment for ARM9 footer but got {actual}-alignment:\n{backtrace}"))]
    Misaligned { expected: usize, actual: usize, backtrace: Backtrace },
    #[snafu(display("expected nitrocode {expected:#x} in ARM9 footer but got {actual:#x}:\n{backtrace}"))]
    NoNitrocode { expected: u32, actual: u32, backtrace: Backtrace },
}

impl Arm9Footer {
    pub fn new(build_info_offset: u32) -> Self {
        Self { nitrocode: NITROCODE, build_info_offset, reserved: 0 }
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

    pub fn borrow_from_slice(data: &'_ [u8]) -> Result<&'_ Self, Arm9FooterError> {
        Self::check_size(data)?;
        let addr = data as *const [u8] as *const () as usize;
        let footer: &Self = Self::handle_pod_cast(bytemuck::try_from_bytes(data), addr)?;
        footer.check_nitrocode()?;
        Ok(footer)
    }

    pub fn borrow_from_slice_mut(data: &'_ mut [u8]) -> Result<&'_ mut Self, Arm9FooterError> {
        Self::check_size(data)?;
        let addr = data as *const [u8] as *const () as usize;
        let footer: &mut Self = Self::handle_pod_cast(bytemuck::try_from_bytes_mut(data), addr)?;
        footer.check_nitrocode()?;
        Ok(footer)
    }
}
