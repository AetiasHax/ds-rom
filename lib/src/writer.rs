use std::borrow::Cow;

use snafu::Snafu;

use crate::error::OverflowError;

/// Writes binary data to a `Vec<u8>`. Replacement for [`std::io::Cursor`] with a `u32` position
/// instead of `usize` so we can check when the position overflows past 32 bits.
pub struct ByteWriter {
    data: Vec<u8>,
    /// Invariant: `pos <= data.len()`.
    pos: u32,
}

#[derive(Debug, Snafu)]
pub enum ByteWriterError {
    /// See [`OverflowError`].
    #[snafu(transparent)]
    Overflow {
        /// Source error.
        source: OverflowError,
    },
    /// Occurs when trying to move the writer, or write at a position, past the end of the written data.
    #[snafu(display("writer position {pos:#x} is higher than the data length {length:#x}"))]
    PositionOutOfBounds {
        /// The requested position.
        pos: u32,
        /// The length of the written data.
        length: u32,
    },
    /// Occurs when an alignment is not a power of two, e.g. from a malformed config.
    #[snafu(display("alignment {alignment:#x} for {what} is not a power of two"))]
    InvalidAlignment {
        /// The invalid alignment.
        alignment: u32,
        /// The value being aligned.
        what: Cow<'static, str>,
    },
}

impl ByteWriter {
    pub fn with_capacity(capacity: usize) -> Self {
        Self { data: Vec::with_capacity(capacity), pos: 0 }
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn data_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }

    pub fn position(&self) -> u32 {
        self.pos
    }

    pub fn set_position(&mut self, pos: u32) -> Result<(), ByteWriterError> {
        if pos > self.len() {
            return PositionOutOfBoundsSnafu { pos, length: self.len() }.fail();
        }
        self.pos = pos;
        Ok(())
    }

    pub fn len(&self) -> u32 {
        self.data.len() as u32
    }

    #[inline(always)]
    fn offset_pos(&self, distance: u32) -> Result<u32, OverflowError> {
        writer_pos(self.pos, distance)
    }

    pub fn fill(&mut self, value: u8, length: usize) -> Result<(), ByteWriterError> {
        let length = u32::try_from(length).map_err(|_| OverflowError::new("zero-write length"))?;
        let new_pos = self.offset_pos(length)?;
        let overwrite_end = self.len().min(new_pos);
        #[allow(clippy::indexing_slicing)] // range is guaranteed to be in bounds
        self.data[self.pos as usize..overwrite_end as usize].fill(value);
        self.pos = new_pos;
        self.data.resize(self.pos as usize, value);
        Ok(())
    }

    pub fn align(&mut self, value: u8, alignment: u32) -> Result<(), ByteWriterError> {
        let aligned_pos = align_up(self.pos, alignment, "writer position")?;
        #[allow(clippy::arithmetic_side_effects)] // aligning never decreases the position
        let padding = aligned_pos - self.pos;
        self.fill(value, padding as usize)?;
        Ok(())
    }

    #[inline(always)]
    fn copy_part_to(&mut self, source: &[u8], pos: u32) -> Result<u32, ByteWriterError> {
        if pos > self.len() {
            return PositionOutOfBoundsSnafu { pos, length: self.len() }.fail();
        }
        let length = length_of(source)?;
        let copy_end = writer_pos(pos, length)?;
        let overwrite_end = self.len().min(copy_end);
        #[allow(clippy::arithmetic_side_effects)] // pos <= len and pos <= copy_end, so pos <= overwrite_end
        let overwrite_length = overwrite_end - pos;
        #[allow(clippy::indexing_slicing)] // range is guaranteed to be in bounds
        {
            self.data[pos as usize..overwrite_end as usize].copy_from_slice(&source[..overwrite_length as usize]);
            self.data.extend_from_slice(&source[overwrite_length as usize..]);
        }
        Ok(copy_end)
    }

    pub fn copy_to(&mut self, source: &[u8], pos: u32) -> Result<(), ByteWriterError> {
        self.copy_part_to(source, pos)?;
        Ok(())
    }

    pub fn copy(&mut self, source: &[u8]) -> Result<(), ByteWriterError> {
        self.pos = self.copy_part_to(source, self.pos)?;
        Ok(())
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.data
    }
}

/// Rounds `value` up to a multiple of `alignment`, which must be a power of two. `what` names the value in errors.
pub fn align_up(value: u32, alignment: u32, what: &'static str) -> Result<u32, ByteWriterError> {
    if !alignment.is_power_of_two() {
        return InvalidAlignmentSnafu { alignment, what }.fail();
    }
    #[allow(clippy::arithmetic_side_effects)] // alignment is a power of two, so it's not zero
    let mask = alignment - 1;
    let value = value.checked_add(mask).ok_or_else(|| OverflowError::new(what))?;
    Ok(value & !mask)
}

#[inline(always)]
fn writer_pos(pos: u32, offset: u32) -> Result<u32, OverflowError> {
    pos.checked_add(offset).ok_or_else(|| OverflowError::new("writer position"))
}

#[inline(always)]
fn length_of(source: &[u8]) -> Result<u32, OverflowError> {
    u32::try_from(source.len()).map_err(|_| OverflowError::new("source data length"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn copy_to_overwrites_and_extends() {
        let mut writer = ByteWriter::with_capacity(0);
        writer.copy(&[1, 2, 3, 4]).unwrap();
        writer.copy_to(&[5, 6, 7], 2).unwrap();
        assert_eq!(writer.data(), &[1, 2, 5, 6, 7]);
        assert_eq!(writer.position(), 4, "copy_to must not move the position");
    }

    #[test]
    fn align() {
        let mut writer = ByteWriter::with_capacity(0);
        writer.copy(&[1, 2, 3]).unwrap();
        writer.align(0xff, 8).unwrap();
        assert_eq!(writer.data(), &[1, 2, 3, 0xff, 0xff, 0xff, 0xff, 0xff]);
        writer.align(0xff, 8).unwrap();
        assert_eq!(writer.position(), 8, "aligning an aligned position must do nothing");
        writer.align(0xff, 1).unwrap();
        assert_eq!(writer.position(), 8);
    }

    #[test]
    fn align_invalid_alignment_is_error() {
        let mut writer = ByteWriter::with_capacity(0);
        writer.copy(&[1, 2, 3]).unwrap();
        for alignment in [0, 3, 0x30] {
            assert!(matches!(writer.align(0xff, alignment), Err(ByteWriterError::InvalidAlignment { .. })));
        }
        assert_eq!(writer.data(), &[1, 2, 3]);
    }

    #[test]
    fn align_up_values() {
        assert_eq!(align_up(0, 4, "x").unwrap(), 0);
        assert_eq!(align_up(1, 4, "x").unwrap(), 4);
        assert_eq!(align_up(0x1001, 0x200, "x").unwrap(), 0x1200);
        assert_eq!(align_up(u32::MAX, 1, "x").unwrap(), u32::MAX);
        assert!(matches!(align_up(u32::MAX, 2, "x"), Err(ByteWriterError::Overflow { .. })));
        assert!(matches!(align_up(5, 0, "x"), Err(ByteWriterError::InvalidAlignment { .. })));
    }

    #[test]
    fn copy_to_past_end_is_error() {
        let mut writer = ByteWriter::with_capacity(0);
        writer.copy(&[1, 2, 3, 4]).unwrap();
        assert!(matches!(writer.copy_to(&[5], 5), Err(ByteWriterError::PositionOutOfBounds { .. })));
        assert_eq!(writer.data(), &[1, 2, 3, 4]);
    }

    #[test]
    fn set_position_past_end_is_error() {
        let mut writer = ByteWriter::with_capacity(0);
        writer.copy(&[1, 2, 3, 4]).unwrap();
        writer.set_position(2).unwrap();
        assert!(matches!(writer.set_position(5), Err(ByteWriterError::PositionOutOfBounds { pos: 5, length: 4 })));
        assert_eq!(writer.position(), 2);
        writer.set_position(4).unwrap();
        assert_eq!(writer.position(), 4);
    }
}
