use std::{mem::size_of, ops::Range};

use bytemuck::{Pod, Zeroable};
use snafu::{Backtrace, Snafu};

use super::RawHeaderError;
use crate::error::{DataOutOfBoundsError, OverflowError, SliceCastError, handle_pod_cast, slice_data};

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
    /// See [`SliceCastError`].
    #[snafu(transparent)]
    SliceCast {
        /// Source error.
        source: SliceCastError,
    },
    #[snafu(transparent)]
    /// Source error.
    Overflow {
        /// Source error.
        source: OverflowError,
    },
    /// See [`DataOutOfBoundsError`]
    #[snafu(transparent)]
    DataOutOfBounds {
        /// Source error.
        source: DataOutOfBoundsError,
    },
}

impl FileAlloc {
    fn check_size(data: &'_ [u8]) -> Result<(), RawFatError> {
        let size = size_of::<Self>();
        if !data.len().is_multiple_of(size) {
            InvalidSizeSnafu {}.fail()
        } else {
            Ok(())
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
        Ok(handle_pod_cast(bytemuck::try_cast_slice(data), addr)?)
    }

    /// Returns the contents of this file taken directly from the ROM.
    pub fn into_file(self, rom: &[u8]) -> Result<&[u8], DataOutOfBoundsError> {
        slice_data(rom, self.start..self.end, || "file contents")
    }

    /// Returns a ROM offset [`Range`] for this file.
    pub fn range(self) -> Range<u32> {
        self.start..self.end
    }
}
