use std::{
    backtrace::Backtrace,
    borrow::Cow,
    fmt::Display,
    io::{self, Write},
};

use snafu::Snafu;

use crate::error::{DataOutOfBoundsError, OverflowError, slice_data};

/// De/compresses data using a backwards [LZ77])(https://en.wikipedia.org/wiki/LZ77_and_LZ78#LZ77) algorithm. "Backwards"
/// refers to starting the de/compression from the end of the file and moving towards the beginning.
pub struct Lz77 {}

const LENGTH_BITS: usize = 4;
const DISTANCE_BITS: usize = 12;
const MIN_SUBSEQUENCE: usize = 3;

const LENGTH_MASK: usize = (1 << LENGTH_BITS) - 1;
const DISTANCE_MASK: usize = (1 << DISTANCE_BITS) - 1;

const MAX_SUBSEQUENCE: usize = MIN_SUBSEQUENCE + LENGTH_MASK;
const LOOKAHEAD: usize = 1 << DISTANCE_BITS;
const MAX_DISTANCE: usize = DISTANCE_MASK + MIN_SUBSEQUENCE;

/// Upper bound of decompressed size divided by compressed size.
const MAX_EXPANSION_RATIO: usize = 9;
// 1 flag byte + 8 pairs (17 bytes total) can expand to at most `8 * MAX_SUBSEQUENCE = 144` bytes.
// 144 / 17 ~= 8.47 which rounds up to 9.
const _: () = assert!(8 * MAX_SUBSEQUENCE <= MAX_EXPANSION_RATIO * (1 + 8 * 2));

/// Length-distance pair
#[derive(Clone, Copy, Debug)]
pub struct Pair {
    length: usize,
    distance: usize,
}

impl Pair {
    /// Encodes this length-distance pair into two big-endian bytes.
    #[allow(clippy::arithmetic_side_effects)] // length and distance are always above MIN_SUBSEQUENCE
    pub fn to_be_bytes(&self) -> [u8; 2] {
        let length = (self.length - MIN_SUBSEQUENCE) & LENGTH_MASK;
        let distance = (self.distance - MIN_SUBSEQUENCE) & DISTANCE_MASK;
        let value = ((length << DISTANCE_BITS) | distance) as u16;
        value.to_be_bytes()
    }

    /// Decodes two little-endian bytes into a length-distance pair.
    #[allow(clippy::arithmetic_side_effects)] // small numbers
    pub fn from_le_bytes(bytes: [u8; 2]) -> Self {
        let value = u16::from_le_bytes(bytes) as usize;
        let distance = (value & DISTANCE_MASK) + MIN_SUBSEQUENCE;
        let length = ((value >> DISTANCE_BITS) & LENGTH_MASK) + MIN_SUBSEQUENCE;
        Self { length, distance }
    }

    /// Decodes two big-endian bytes into a length-distance pair.
    #[allow(clippy::arithmetic_side_effects)] // small numbers
    pub fn from_be_bytes(bytes: [u8; 2]) -> Self {
        let value = u16::from_be_bytes(bytes) as usize;
        let distance = (value & DISTANCE_MASK) + MIN_SUBSEQUENCE;
        let length = ((value >> DISTANCE_BITS) & LENGTH_MASK) + MIN_SUBSEQUENCE;
        Self { length, distance }
    }

    /// Number of bytes saved by this length-distance pair.
    #[allow(clippy::arithmetic_side_effects)] // length is always above 2
    pub fn bytes_saved(&self) -> usize {
        self.length - 2
    }
}

impl Display for Pair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#x}+{:#x} ({:04x})", self.distance, self.length, u16::from_be_bytes(self.to_be_bytes()))
    }
}

/// Errors related to [`Lz77::decompress`].
#[derive(Debug, Snafu)]
pub enum Lz77DecompressError {
    /// Occurs when a byte literal is expected directly after a flag byte, but there are no more bytes to read.
    #[snafu(display("expected literal after flag {flags:#x} at offset {offset:#x}:\n{backtrace}"))]
    NoLiteral {
        /// Offset of flag byte.
        offset: usize,
        /// Value of flag byte.
        flags: u8,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// Occurs when a length-distance pair is expected directly after a flag byte, but there are no more bytes to read.
    #[snafu(display("expected length-distanced pair after flag {flags:#x} at offset {offset:#x}:\n{backtrace}"))]
    NoPair {
        /// Offset of flag byte.
        offset: usize,
        /// Value of flag byte.
        flags: u8,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// Occurs when the first byte of a length-distance pair was read, but there is no second byte.
    #[snafu(display("expected second byte of length-distance pair at offset {offset:#x}:\n{backtrace}"))]
    IncompletePair {
        /// Offset of first byte.
        offset: usize,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// Occurs when a length-distance pair would point to data that is not within the decompressed stream.
    #[snafu(display("length-distance pair {pair} at offset {offset:#x} points outside of decompressed stream:\n{backtrace}"))]
    OutOfBounds {
        /// The erroneous length-distance pair.
        pair: Pair,
        /// Offset of length-distance pair.
        offset: usize,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// See [`io::Error`].
    #[snafu(transparent)]
    Io {
        /// Source error.
        source: io::Error,
    },
    /// Occurs when the provided data is too small to fit an LZ77-compressed binary
    #[snafu(display("the provided data is too small:\n{backtrace}"))]
    TooSmall {
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// See [`OverflowError`].
    #[snafu(transparent)]
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

/// Errors related to [`Lz77::compress`].
#[derive(Debug, Snafu)]
pub enum Lz77CompressError {
    /// See [`io::Error`].
    #[snafu(transparent)]
    Io {
        /// Source error.
        source: io::Error,
    },
    /// See [`DataOutOfBoundsError`]
    #[snafu(transparent)]
    DataOutOfBounds {
        /// Source error.
        source: DataOutOfBoundsError,
    },
}

/// The result of [`Lz77::decompress`].
pub struct Lz77DecompressResult<'a> {
    /// The decompressed data.
    pub decompressed: Vec<u8>,
    /// LZ77 tokens in the compressed data.
    pub tokens: Tokens<'a>,
}

impl Lz77 {
    fn compress_bytes(&self, bytes: &[u8], compressed: &mut Vec<u8>) -> Result<usize, io::Error> {
        let mut tokens = Tokens::compress(bytes);
        tokens.drop_wasteful_tokens()?;
        tokens.write(compressed)
    }

    #[allow(clippy::arithmetic_side_effects)] // small numbers
    fn write_footer(
        &self,
        compressed: &mut Vec<u8>,
        bytes: &[u8],
        start: usize,
        num_identical: usize,
    ) -> Result<(), Lz77CompressError> {
        let padding = ((!compressed.len()).wrapping_add(1) & 3) as u8;
        for _ in 0..padding {
            compressed.push(0xff);
        }
        let total_size = compressed.len() + 8;
        let read_offset = padding + 8;
        let write_offset: u32 = (bytes.len() - total_size) as u32;
        let total_size = total_size - num_identical - start;
        let total_size_bytes = total_size.to_le_bytes();
        compressed.write_all(&[total_size_bytes[0], total_size_bytes[1], total_size_bytes[2]])?;
        compressed.push(read_offset);
        compressed.write_all(&write_offset.to_le_bytes())?;
        Ok(())
    }

    /// Compresses `bytes[start..]` and returns the result. All bytes before `start` are included in the output. Due to version
    /// differences in the compression algorithm, there is a `version` parameter taken from the ROM header.
    ///
    /// # Errors
    ///
    /// This function will return an error if an I/O operation fails.
    pub fn compress(&self, bytes: &[u8], start: usize) -> Result<Box<[u8]>, Lz77CompressError> {
        let mut compressed = Vec::with_capacity(bytes.len());

        let (uncompressed, bytes_to_compress) =
            bytes.split_at_checked(start).ok_or_else(|| DataOutOfBoundsError::new("bytes to compress", start as u32..))?;
        let num_identical = self.compress_bytes(bytes_to_compress, &mut compressed)?;
        for i in (0..start).rev() {
            #[allow(clippy::indexing_slicing)] // i is always less than start i.e. uncompresssed.len()
            compressed.push(uncompressed[i]);
        }
        compressed.reverse();

        self.write_footer(&mut compressed, bytes, start, num_identical)?;

        Ok(compressed.into_boxed_slice())
    }

    #[allow(clippy::indexing_slicing)] // length is checked
    #[allow(clippy::arithmetic_side_effects)] // length is at least 8
    fn read_footer(&self, bytes: &[u8]) -> Result<(usize, usize, usize), Lz77DecompressError> {
        let length = bytes.len();
        if length < 8 {
            return TooSmallSnafu.fail();
        }
        let total_size = {
            let mut buf = [0u8; 3];
            buf.copy_from_slice(&bytes[length - 8..length - 5]);
            u32::from_le_bytes([buf[0], buf[1], buf[2], 0]) as usize
        };
        let read_offset = bytes[length - 5] as usize;
        let write_offset = {
            let mut buf = [0u8; 4];
            buf.copy_from_slice(&bytes[length - 4..length]);
            u32::from_le_bytes(buf) as usize
        };
        Ok((total_size, read_offset, write_offset))
    }

    /// Parses the LZ77 tokens in the `bytes` slice.
    #[deprecated(note = "use decompress() instead")]
    pub fn parse_tokens<'a>(&self, bytes: &'a [u8]) -> Result<Tokens<'a>, Lz77DecompressError> {
        let result = self.decompress(bytes)?;
        Ok(result.tokens)
    }

    /// Decompresses `bytes` and returns the result.
    pub fn decompress<'a>(&self, bytes: &'a [u8]) -> Result<Lz77DecompressResult<'a>, Lz77DecompressError> {
        let (total_size, read_offset, write_offset) = self.read_footer(bytes)?;
        let num_identical =
            bytes.len().checked_sub(total_size).ok_or_else(|| OverflowError::new("number of identical bytes"))?;
        let decompressed_size =
            bytes.len().checked_add(write_offset).ok_or_else(|| OverflowError::new("decompressed binary size"))?;
        // Cap the decompression buffer to prevent unnecessary huge allocation (write_offset can be anything)
        let max_decompressed_size = bytes.len().saturating_mul(MAX_EXPANSION_RATIO);
        let mut decompressed = Vec::with_capacity(decompressed_size.min(max_decompressed_size));
        let lz77_tokens_end = num_identical
            .checked_add(total_size)
            .and_then(|x| x.checked_sub(read_offset))
            .ok_or_else(|| OverflowError::new("decompress start position"))?;
        let lz77_tokens_bytes = slice_data(bytes, ..lz77_tokens_end as u32, || "LZ77 tokens")?;
        let tokens = Tokens::decompress(lz77_tokens_bytes, num_identical, &mut decompressed)?;

        for i in (0..num_identical).rev() {
            #[allow(clippy::indexing_slicing)] // num_identical is always less than bytes.size()
            decompressed.push(bytes[i]);
        }
        decompressed.reverse();

        Ok(Lz77DecompressResult { decompressed, tokens })
    }
}

#[derive(Clone)]
enum Token<'a> {
    Literal(u8),
    Pair((Pair, Cow<'a, [u8]>)),
}

impl Token<'_> {
    fn bytes_saved(&self) -> isize {
        match self {
            Token::Literal(_) => 0,
            Token::Pair((pair, _)) => pair.bytes_saved() as isize,
        }
    }
}

impl Display for Token<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Literal(byte) => write!(f, "{byte:02x}"),
            Self::Pair((pair, bytes)) => write!(f, "{pair} {bytes:02x?}"),
        }
    }
}

/// Represents LZ77 tokens of a compressed stream.
pub struct Tokens<'a> {
    tokens: Vec<Token<'a>>,
    bytes_saved: isize,
    dropped_tokens: usize,
}

impl<'a> Tokens<'a> {
    fn find_match(bytes: &[u8], pos: usize) -> Option<Pair> {
        debug_assert!(pos < bytes.len());
        #[allow(clippy::arithmetic_side_effects)] // pos is always less than bytes.len()
        let max_lookahead = (LOOKAHEAD + MAX_SUBSEQUENCE).min(bytes.len() - pos - 1);
        (MIN_SUBSEQUENCE - 1..max_lookahead)
            .fold(None, |best_pair, i| {
                let needle = pos;
                #[allow(clippy::arithmetic_side_effects)] // small number
                let haystack = pos + 1 + i;
                #[allow(clippy::indexing_slicing)] // haystack is at most bytes.len() - 1
                if bytes[needle] != bytes[haystack] {
                    return best_pair;
                }
                let mut length = 0;
                #[allow(clippy::indexing_slicing)] // needle - length is at least 0
                #[allow(clippy::arithmetic_side_effects)] // ^
                while needle >= length
                    && bytes[needle - length] == bytes[haystack - length]
                    && haystack > pos + length
                    && length < MAX_SUBSEQUENCE
                {
                    length += 1;
                }
                #[allow(clippy::arithmetic_side_effects)] // haystack > needle
                let distance = haystack - needle;
                if length > best_pair.map_or(0, |p: Pair| p.length) && distance <= MAX_DISTANCE {
                    Some(Pair { length, distance })
                } else {
                    best_pair
                }
            })
            .and_then(|p| (p.length >= MIN_SUBSEQUENCE).then_some(p))
    }

    fn compress(bytes: &'a [u8]) -> Self {
        let mut tokens = vec![];

        let mut read = bytes.len();
        let mut bytes_saved = 0;
        while read > 0 {
            #[allow(clippy::arithmetic_side_effects)] // small number
            if (tokens.len() % 8) == 0 {
                bytes_saved -= 1;
            }
            #[allow(clippy::arithmetic_side_effects)] // read is at least 1
            let pair = Self::find_match(bytes, read - 1);
            #[allow(clippy::arithmetic_side_effects)]
            #[allow(clippy::indexing_slicing)] // bytes range is always in bounds
            if let Some(pair) = pair {
                let new_read = read - pair.length;
                bytes_saved += pair.bytes_saved() as isize;
                tokens.push(Token::Pair((pair, Cow::Borrowed(&bytes[new_read..read]))));
                read = new_read;
            } else {
                read -= 1;
                tokens.push(Token::Literal(bytes[read]));
            }
        }

        Self { tokens, bytes_saved, dropped_tokens: 0 }
    }

    fn drop_wasteful_tokens(&mut self) -> Result<(), io::Error> {
        let mut best_token_index = None;

        let mut bytes_saved = 0;
        'outer: for (i, chunk) in self.tokens.chunks(8).enumerate() {
            #[allow(clippy::arithmetic_side_effects)] // small numbers
            for (j, token) in chunk.iter().enumerate() {
                let index = i * 8 + j;
                if (index % 8) == 0 {
                    bytes_saved -= 1;
                }
                bytes_saved += token.bytes_saved();

                if bytes_saved > self.bytes_saved {
                    best_token_index = Some(index);
                    break 'outer;
                }
            }
        }

        let Some(best_token_index) = best_token_index else {
            return Ok(());
        };
        #[allow(clippy::arithmetic_side_effects)] // best_token_index is always less than self.tokens.len()
        {
            self.dropped_tokens = self.tokens.len() - best_token_index - 1;
        }

        Ok(())
    }

    fn make_flags_for_chunk(chunk: &[Token]) -> u8 {
        debug_assert!(chunk.len() <= 8);
        let mut flags = 0;
        for i in 0..8 {
            flags <<= 1;
            if let Some(Token::Pair(_)) = chunk.get(i) {
                flags |= 1;
            }
        }
        flags
    }

    fn write(self, compressed: &mut Vec<u8>) -> Result<usize, io::Error> {
        #[allow(clippy::arithmetic_side_effects)] // dropped_tokens is at most self.tokens.len()
        let last_token_index = self.tokens.len() - self.dropped_tokens;
        'outer: for (i, chunk) in self.tokens.chunks(8).enumerate() {
            let flags = Self::make_flags_for_chunk(chunk);
            #[allow(clippy::arithmetic_side_effects)] // small number
            let index = i * 8;
            if index >= last_token_index {
                break 'outer;
            }

            compressed.push(flags);
            for (j, token) in chunk.iter().enumerate() {
                #[allow(clippy::arithmetic_side_effects)] // small number
                let index = index + j;
                if index >= last_token_index {
                    break 'outer;
                }

                match token {
                    Token::Literal(byte) => compressed.push(*byte),
                    Token::Pair((pair, _)) => {
                        compressed.write_all(&pair.to_be_bytes())?;
                    }
                }
            }
        }

        let mut num_identical = 0;
        #[allow(clippy::indexing_slicing)] // last_token_index is always in bounds
        for token in &self.tokens[last_token_index..] {
            #[allow(clippy::arithmetic_side_effects)] // small number
            match token {
                Token::Literal(byte) => {
                    num_identical += 1;
                    compressed.push(*byte);
                }
                Token::Pair((_, bytes)) => {
                    num_identical += bytes.len();
                    for &byte in bytes.iter().rev() {
                        compressed.push(byte);
                    }
                }
            }
        }

        Ok(num_identical)
    }

    fn decompress(bytes: &'a [u8], start: usize, decompressed: &mut Vec<u8>) -> Result<Self, Lz77DecompressError> {
        let mut tokens = vec![];
        let mut iter = bytes.iter().cloned().enumerate().skip(start).rev().peekable();
        let mut bytes_saved = 0;

        while let Some((offset, mut flags)) = iter.next() {
            #[allow(clippy::arithmetic_side_effects)] // small number
            {
                bytes_saved -= 1;
            }
            for _ in 0..8 {
                if (flags & 0x80) == 0 {
                    let literal = iter.next().ok_or_else(|| NoLiteralSnafu { offset, flags }.build())?.1;
                    decompressed.push(literal);
                    tokens.push(Token::Literal(literal));
                } else {
                    let (offset, first) = iter.next().ok_or_else(|| NoPairSnafu { offset, flags }.build())?;
                    let pair = [first, iter.next().ok_or_else(|| IncompletePairSnafu { offset }.build())?.1];
                    let pair = Pair::from_be_bytes(pair);

                    #[allow(clippy::arithmetic_side_effects)] // small number
                    {
                        bytes_saved += pair.bytes_saved() as isize;
                    }

                    let Some(start) = decompressed.len().checked_sub(pair.distance) else {
                        return OutOfBoundsSnafu { pair, offset }.fail();
                    };
                    #[allow(clippy::arithmetic_side_effects)] // small number
                    let end = start + pair.length;
                    if end > decompressed.len() {
                        OutOfBoundsSnafu { pair, offset }.fail()?;
                    }

                    #[allow(clippy::indexing_slicing)] // range is checked
                    let bytes: Vec<u8> = decompressed[start..end].to_vec();
                    decompressed.extend_from_slice(&bytes);
                    tokens.push(Token::Pair((pair, Cow::Owned(bytes))));
                }
                if iter.peek().is_none() {
                    break;
                }
                flags <<= 1;
            }
        }

        Ok(Self { tokens, bytes_saved, dropped_tokens: 0 })
    }
}

impl Display for Tokens<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut bytes_saved: isize = 0;
        #[allow(clippy::arithmetic_side_effects)] // small number
        for chunk in self.tokens.chunks(8) {
            let flags = Self::make_flags_for_chunk(chunk);
            bytes_saved -= 1;
            writeln!(f, "saved: {bytes_saved} | {flags:02x} (flags)")?;
            for token in chunk {
                bytes_saved += token.bytes_saved();
                writeln!(f, "saved: {bytes_saved} | {token}")?;
            }
        }
        writeln!(f, "Bytes saved: {}", self.bytes_saved)?;
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn decompress_huge_write_offset_does_not_allocate() {
        // Footer only: total_size = 8, read_offset = 8, write_offset = 0xffffffff
        let bytes = [0x08, 0x00, 0x00, 0x08, 0xff, 0xff, 0xff, 0xff];
        let result = Lz77 {}.decompress(&bytes).unwrap();
        assert!(result.decompressed.is_empty());
        assert!(result.decompressed.capacity() <= bytes.len() * MAX_EXPANSION_RATIO);
    }
}
