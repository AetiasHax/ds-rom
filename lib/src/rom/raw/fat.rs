use std::mem::{align_of, size_of};

use bytemuck::{Pod, PodCastError, Zeroable};
use snafu::{Backtrace, Snafu};

use super::RawHeaderError;

#[repr(C)]
#[derive(Clone, Copy, Zeroable, Pod)]
pub struct FileAlloc {
    pub start: u32,
    pub end: u32,
}

#[derive(Debug, Snafu)]
pub enum RawFatError {
    #[snafu(transparent)]
    RawHeader { source: RawHeaderError },
    #[snafu(display("file allocation table must be a multiple of {} bytes", size_of::<FileAlloc>()))]
    InvalidSize { backtrace: Backtrace },
    #[snafu(display("expected {expected}-alignment for autoload infos but got {actual}-alignment:\n{backtrace}"))]
    Misaligned { expected: usize, actual: usize, backtrace: Backtrace },
}

impl FileAlloc {
    fn check_size(data: &'_ [u8]) -> Result<(), RawFatError> {
        let size = size_of::<Self>();
        if data.len() % size != 0 {
            InvalidSizeSnafu {}.fail()
        } else {
            Ok(())
        }
    }

    fn handle_pod_cast<T>(result: Result<T, PodCastError>, addr: usize) -> Result<T, RawFatError> {
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

    pub fn borrow_from_slice(data: &'_ [u8]) -> Result<&'_ [Self], RawFatError> {
        Self::check_size(data)?;
        let addr = data as *const [u8] as *const () as usize;
        Self::handle_pod_cast(bytemuck::try_cast_slice(data), addr)
    }

    pub fn into_file(self, rom: &[u8]) -> &[u8] {
        &rom[self.start as usize..self.end as usize]
    }
}
