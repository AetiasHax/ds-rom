use std::{
    mem::{align_of, size_of},
    ops::Range,
};

use bytemuck::{Pod, PodCastError, Zeroable};
use snafu::{Backtrace, Snafu};

use super::RawHeaderError;

/// A file allocation which tells where a file starts and ends in the ROM.
#[repr(C)]
#[derive(Clone, Copy, Zeroable, Pod, Default)]
pub struct FileAlloc {
    /// Start offset.
    pub start: u32,
    /// End offset.
    pub end: u32,
}

/// Errors related to [`FileAlloc`].
#[derive(Debug, Snafu)]
pub enum RawFatError {
    /// See [`RawHeaderError`].
    #[snafu(transparent)]
    RawHeader {
        /// Source error.
        source: RawHeaderError,
    },
    /// Occurs when the input is not evenly divisible into a slice of [`FileAlloc`].
    #[snafu(display("file allocation table must be a multiple of {} bytes", size_of::<FileAlloc>()))]
    InvalidSize {
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// Occurs when the input is less aligned than [`FileAlloc`].
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
                MisalignedSnafu { expected: align_of::<Self>(), actual: 1usize << addr.trailing_zeros() }.fail()
            }
            Err(PodCastError::AlignmentMismatch) => panic!(),
            Err(PodCastError::OutputSliceWouldHaveSlop) => panic!(),
            Err(PodCastError::SizeMismatch) => unreachable!(),
        }
    }

    /// Reinterprets a `&[u8]` as a reference to [`FileAlloc`].
    ///
    /// # Errors
    ///
    /// This function will return an error if the input the wrong size or not aligned enough.
    pub fn borrow_from_slice(data: &'_ [u8]) -> Result<&'_ [Self], RawFatError> {
        Self::check_size(data)?;
        let addr = data as *const [u8] as *const () as usize;
        Self::handle_pod_cast(bytemuck::try_cast_slice(data), addr)
    }

    /// Returns the contents of this file taken directly from the ROM.
    pub fn into_file(self, rom: &[u8]) -> &[u8] {
        &rom[self.start as usize..self.end as usize]
    }

    /// Returns a ROM offset [`Range`] for this file.
    pub fn range(self) -> Range<usize> {
        self.start as usize..self.end as usize
    }
}
