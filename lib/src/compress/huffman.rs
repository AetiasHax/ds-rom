use std::backtrace::Backtrace;

use bitreader::{BitReader, BitReaderError};
use rust_bitwriter::BitWriter;
use snafu::Snafu;

/// De/compresses data with [Huffman coding](https://en.wikipedia.org/wiki/Huffman_coding), one nibble at a time. This struct
/// is not represented as a tree (like it is formally) but instead the Huffman codes are found in an array of length 16, one
/// for each possible nibble value (2^4).
pub struct NibbleHuffman {
    /// Huffman codes for each nibble value, i.e. `codes[n]` encodes the value `n`. The codes must not be prefixed by any other
    /// code in the array, and must be at most 8 bits long.
    pub codes: [NibbleHuffmanCode; 16],
}

/// A huffman code for [NibbleHuffman].
pub struct NibbleHuffmanCode {
    /// The number of bits in [`Self::bits`].
    pub length: u8,
    /// The code for the corresponding nibble.
    pub bits: u8,
}

/// Errors related to [`NibbleHuffman`].
#[derive(Debug, Snafu)]
pub enum NibbleHuffmanError {
    /// Occurs when the [`NibbleHuffman`] contains invalid Huffman codes making it impossible to
    /// decompress certain bit sequences.
    #[snafu(display("decoder contains invalid huffman codes:\n{backtrace}"))]
    InvalidCodes {
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// See [`BitReaderError`].
    #[snafu(transparent)]
    BitReader {
        /// Source error.
        source: BitReaderError,
    },
    /// See [`std::io::Error`].
    #[snafu(transparent)]
    Io {
        /// Source error.
        source: std::io::Error,
    },
}

impl NibbleHuffman {
    fn decompress_nibble(&self, reader: &mut BitReader) -> Result<u8, NibbleHuffmanError> {
        let (bits_read, value) = self
            .codes
            .iter()
            .enumerate()
            .find_map(|(index, code)| {
                if code.length > u8::BITS as u8 {
                    return Some(InvalidCodesSnafu.fail());
                }
                let (bits_read, shift) = if code.length as u64 > reader.remaining() {
                    let rem = reader.remaining() as u8;
                    #[allow(clippy::arithmetic_side_effects)] // code.length > rem
                    (rem, code.length - rem)
                } else {
                    (code.length, 0)
                };
                let value = match reader.peek_u8(bits_read) {
                    // Past the end of `data`, pretend it's padded with zeros. If all 8 bits are padding, `checked_shl`
                    // returns `None` and the value is zero.
                    Ok(bits) => bits.checked_shl(shift.into()).unwrap_or(0),
                    Err(e) => return Some(Err(e.into())),
                };
                if value == code.bits {
                    Some(Ok((bits_read, index as u8)))
                } else {
                    None
                }
            })
            .transpose()?
            .ok_or_else(|| InvalidCodesSnafu.build())?;
        reader.skip(bits_read as u64)?;
        Ok(value)
    }

    /// Decompresses `data` into the `out` slice. It will decompress until `out` is filled, padding zeros past the end of
    /// `data`.
    pub fn decompress_to_slice(&self, data: &[u8], out: &mut [u8]) -> Result<(), NibbleHuffmanError> {
        let mut reader = BitReader::new(data);

        for byte in out.iter_mut() {
            let low = self.decompress_nibble(&mut reader)?;
            let high = self.decompress_nibble(&mut reader)?;
            *byte = (high << 4) | low;
        }
        Ok(())
    }

    fn compress_nibble(&self, writer: &mut BitWriter, data: u8) -> Result<(), NibbleHuffmanError> {
        debug_assert!(data < 16);
        #[allow(clippy::indexing_slicing)] // `& 0xf` added for safety
        let code = &self.codes[data as usize & 0xf];
        writer.write_u8(code.bits, code.length)?;
        Ok(())
    }

    /// Compresses `bytes` into the `out` slice. It will truncate the compressed result to fit into `out`.
    pub fn compress_to_slice(&self, bytes: &[u8], out: &mut [u8]) -> Result<(), NibbleHuffmanError> {
        let mut writer = BitWriter::new();

        for byte in bytes.iter() {
            let low = byte & 0xf;
            let high = byte >> 4;
            self.compress_nibble(&mut writer, low)?;
            self.compress_nibble(&mut writer, high)?;
        }

        let _ = writer.close();
        let data = writer.data();
        let len = out.len().min(data.len());
        #[allow(clippy::indexing_slicing)] // len is always in bounds
        out[..len].copy_from_slice(&data[..len]);
        Ok(())
    }

    /// Does the opposite of [Self::data_to_diff16]. If `data` consists of 16-bit integers that look like A, B-A, C-B and so
    /// on, this function will recover the original data A, B, C.
    ///
    /// # Panics
    ///
    /// Panics if `data.len()` is not a multiple of 2.
    pub fn diff16_to_data(&self, data: &mut [u8]) {
        assert!(data.len().is_multiple_of(2));
        let mut prev = 0;
        for chunk in data.as_chunks_mut::<2>().0 {
            let curr = u16::from_le_bytes(*chunk);
            let value = curr.wrapping_add(prev);
            chunk.copy_from_slice(&value.to_le_bytes());
            prev = value;
        }
    }

    /// Differentiates every 16-bit integer in `data`. For example, if the 16-bit integers are called A, B, C and so on, then
    /// they will be differentiated to A, B-A, C-B and so on.
    ///
    /// If `data` has a lot of repeating values, this will result in plenty of zeros. This benefits Huffman compression, as it
    /// compresses better if some values occur more often than others.
    ///
    /// # Panics
    ///
    /// Panics if `data.len()` is not a multiple of 2.
    pub fn data_to_diff16(&self, data: &mut [u8]) {
        assert!(data.len().is_multiple_of(2));
        let mut prev = 0;
        for chunk in data.as_chunks_mut::<2>().0 {
            let curr = u16::from_le_bytes(*chunk);
            let value = curr.wrapping_sub(prev);
            chunk.copy_from_slice(&value.to_le_bytes());
            prev = curr;
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn codes(length: u8) -> NibbleHuffman {
        NibbleHuffman { codes: std::array::from_fn(|n| NibbleHuffmanCode { length, bits: n as u8 }) }
    }

    #[test]
    fn decompress_full_length_codes_past_end() {
        // Every byte needs two 8-bit codes, so the second output byte is decoded entirely from zero padding.
        let huffman = codes(8);
        let mut out = [0xffu8; 2];
        huffman.decompress_to_slice(&[0x01, 0x02], &mut out).unwrap();
        assert_eq!(out, [0x21, 0x00]);
    }

    #[test]
    fn decompress_too_long_codes_is_error() {
        let huffman = codes(9);
        let mut out = [0u8; 1];
        assert!(matches!(huffman.decompress_to_slice(&[], &mut out), Err(NibbleHuffmanError::InvalidCodes { .. })));
    }
}
