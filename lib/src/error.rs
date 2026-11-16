use std::{
    backtrace::Backtrace,
    borrow::Cow,
    fmt::LowerHex,
    ops::{Range, RangeFrom, RangeFull, RangeInclusive, RangeTo, RangeToInclusive},
};

use bytemuck::{Pod, PodCastError};
use snafu::Snafu;

/// Occurs when computing a value causes overflow, which indicates that the ROM is malformed.
#[derive(Debug, Snafu)]
#[snafu(display("unable to compute {what} due to overflow:\n{backtrace}"))]
pub struct OverflowError {
    /// The value being computed.
    what: Cow<'static, str>,
    /// Backtrace to the source of the error.
    backtrace: Backtrace,
}

impl OverflowError {
    pub(crate) fn new(what: impl Into<Cow<'static, str>>) -> Self {
        OverflowSnafu { what }.build()
    }
}

/// Any type of range of [`u32`] for accessing parts of the ROM. Used by [`DataOutOfBoundsError`].
#[derive(Debug, Clone, derive_more::From)]
pub enum OffsetRange {
    /// Exclusive range: `x..y`
    Range(Range<u32>),
    /// Inclusive range: `x..=y`
    RangeInclusive(RangeInclusive<u32>),
    /// Range from: `x..`
    RangeFrom(RangeFrom<u32>),
    /// Range to: `..y`
    RangeTo(RangeTo<u32>),
    /// Inclusive range to: `..=y`
    RangeToInclusive(RangeToInclusive<u32>),
    /// Full range: `..`
    RangeFull(RangeFull),
}

impl OffsetRange {
    fn get<'a, T, Fn, S>(&self, slice: &'a [T], what: Fn) -> Result<&'a [T], DataOutOfBoundsError>
    where
        S: Into<Cow<'static, str>>,
        Fn: FnOnce() -> S,
    {
        let data: Option<&[T]> = match self {
            OffsetRange::Range(range) => slice.get(range.start as usize..range.end as usize),
            OffsetRange::RangeInclusive(range) => slice.get(*range.start() as usize..=*range.end() as usize),
            OffsetRange::RangeFrom(range) => slice.get(range.start as usize..),
            OffsetRange::RangeTo(range) => slice.get(..range.end as usize),
            OffsetRange::RangeToInclusive(range) => slice.get(..=range.end as usize),
            OffsetRange::RangeFull(_) => slice.get(..),
        };
        data.ok_or_else(|| DataOutOfBoundsError::new(what(), self.clone()))
    }

    fn get_mut<'a, T, Fn, S>(&self, slice: &'a mut [T], what: Fn) -> Result<&'a mut [T], DataOutOfBoundsError>
    where
        S: Into<Cow<'static, str>>,
        Fn: FnOnce() -> S,
    {
        let data: Option<&mut [T]> = match self {
            OffsetRange::Range(range) => slice.get_mut(range.start as usize..range.end as usize),
            OffsetRange::RangeInclusive(range) => slice.get_mut(*range.start() as usize..=*range.end() as usize),
            OffsetRange::RangeFrom(range) => slice.get_mut(range.start as usize..),
            OffsetRange::RangeTo(range) => slice.get_mut(..range.end as usize),
            OffsetRange::RangeToInclusive(range) => slice.get_mut(..=range.end as usize),
            OffsetRange::RangeFull(_) => slice.get_mut(..),
        };
        data.ok_or_else(|| DataOutOfBoundsError::new(what(), self.clone()))
    }
}

impl LowerHex for OffsetRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OffsetRange::Range(range) => write!(f, "{:#x}..{:#x}", range.start, range.end),
            OffsetRange::RangeInclusive(range) => write!(f, "{:#x}..={:#x}", range.start(), range.end()),
            OffsetRange::RangeFrom(range) => write!(f, "{:#x}..", range.start),
            OffsetRange::RangeTo(range) => write!(f, "..{:#x}", range.end),
            OffsetRange::RangeToInclusive(range) => write!(f, "..={:#x}", range.end),
            OffsetRange::RangeFull(_) => write!(f, ".."),
        }
    }
}

/// Occurs when trying to access part of the ROM, but the offset range goes outside the ROM or a section of the ROM.
#[derive(Debug, Snafu)]
#[snafu(display("{what} is out of bounds ({range:#x}):\n{backtrace}"))]
pub struct DataOutOfBoundsError {
    /// The thing being accessed.
    what: Cow<'static, str>,
    /// The offset range.
    range: OffsetRange,
    /// Backtrace to the source of the error.
    backtrace: Backtrace,
}

impl DataOutOfBoundsError {
    pub(crate) fn new(what: impl Into<Cow<'static, str>>, range: impl Into<OffsetRange>) -> Self {
        DataOutOfBoundsSnafu { what, range }.build()
    }
}

pub(crate) fn slice_data<Fn, S>(data: &[u8], range: impl Into<OffsetRange>, what: Fn) -> Result<&'_ [u8], DataOutOfBoundsError>
where
    S: Into<Cow<'static, str>>,
    Fn: FnOnce() -> S,
{
    range.into().get(data, what)
}

pub(crate) fn slice_data_mut<S: Into<Cow<'static, str>>>(
    data: &mut [u8],
    range: impl Into<OffsetRange>,
    what: impl FnOnce() -> S,
) -> Result<&'_ mut [u8], DataOutOfBoundsError> {
    range.into().get_mut(data, what)
}

/// Occurs when the input is less aligned than expected.
#[derive(Debug, Snafu)]
#[snafu(display("expected {expected}-alignment but got {actual}-alignment:\n{backtrace}"))]
pub struct MisalignedError {
    /// Expected alignment.
    expected: usize,
    /// Actual input alignment.
    actual: usize,
    /// Backtrace to the source of the error.
    backtrace: Backtrace,
}

impl MisalignedError {
    pub(crate) fn new(expected: usize, actual: usize) -> Self {
        MisalignedSnafu { expected, actual }.build()
    }
}

/// Errors related to casting byte slices to plain-old-data types.
#[derive(Debug, Snafu)]
pub enum SliceCastError {
    /// See [`PodCastError`].
    #[snafu(display("{error}:\n{backtrace}"))]
    PodCast {
        /// Source error.
        error: PodCastError,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// See [`MisalignedError`].
    #[snafu(transparent)]
    Misaligned {
        /// Source error.
        source: MisalignedError,
    },
}

/// The result of a [`bytemuck`] cast from bytes, used by [`handle_pod_cast`] to know which alignment the cast needed.
pub(crate) trait PodCastTarget {
    /// The alignment of the referenced type, not of the reference itself.
    const ALIGN: usize;
}

impl<T: Pod> PodCastTarget for &T {
    const ALIGN: usize = align_of::<T>();
}

impl<T: Pod> PodCastTarget for &mut T {
    const ALIGN: usize = align_of::<T>();
}

impl<T: Pod> PodCastTarget for &[T] {
    const ALIGN: usize = align_of::<T>();
}

impl<T: Pod> PodCastTarget for &mut [T] {
    const ALIGN: usize = align_of::<T>();
}

/// Converts the result of a [`bytemuck`] cast from the bytes at `addr` into a [`SliceCastError`].
pub(crate) fn handle_pod_cast<T: PodCastTarget>(result: Result<T, PodCastError>, addr: usize) -> Result<T, SliceCastError> {
    match result {
        Ok(target) => Ok(target),
        // The input is misaligned, so addr is nonzero and the shift is less than usize::BITS
        #[allow(clippy::arithmetic_side_effects)]
        Err(PodCastError::TargetAlignmentGreaterAndInputNotAligned) => {
            Err(MisalignedError::new(T::ALIGN, 1usize << addr.trailing_zeros()))?
        }
        Err(error) => PodCastSnafu { error }.fail(),
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;

    /// Returns 12 bytes that are exactly 1-aligned.
    fn misaligned_bytes(buf: &[u32; 4]) -> &[u8] {
        &bytemuck::cast_slice::<u32, u8>(buf)[1..13]
    }

    fn misaligned_error(result: Result<impl Sized, SliceCastError>) -> (usize, usize) {
        match result {
            Err(SliceCastError::Misaligned { source }) => (source.expected, source.actual),
            _ => panic!("expected a misaligned error"),
        }
    }

    #[test]
    fn handle_pod_cast_reports_target_alignment() {
        let buf = [0u32; 4];
        let data = misaligned_bytes(&buf);
        let addr = data.as_ptr() as usize;

        let result = handle_pod_cast(bytemuck::try_from_bytes::<[u32; 3]>(data), addr);
        assert_eq!(misaligned_error(result), (4, 1));
        let result = handle_pod_cast(bytemuck::try_cast_slice::<u8, u16>(data), addr);
        assert_eq!(misaligned_error(result), (2, 1));

        // 4 bytes into a u64 buffer is exactly 4-aligned
        let buf = [0u64; 2];
        let data = &bytemuck::cast_slice::<u64, u8>(&buf)[4..12];
        let result = handle_pod_cast(bytemuck::try_cast_slice::<u8, u64>(data), data.as_ptr() as usize);
        assert_eq!(misaligned_error(result), (8, 4));
    }

    #[test]
    fn handle_pod_cast_passes_through_other_errors() {
        let buf = [0u32; 4];
        let data = &bytemuck::cast_slice::<u32, u8>(&buf)[..3];
        let result = handle_pod_cast(bytemuck::try_cast_slice::<u8, u16>(data), data.as_ptr() as usize);
        assert!(matches!(result, Err(SliceCastError::PodCast { .. })));
    }
}
