use std::{
    backtrace::Backtrace,
    borrow::Cow,
    fmt::Display,
    io::{self, Write},
};

use snafu::Snafu;

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

/// Length-distance pair
#[derive(Clone, Copy, Debug)]
pub struct Pair {
    length: usize,
    distance: usize,
}

impl Pair {
    /// Encodes this length-distance pair into two big-endian bytes.
    pub fn to_be_bytes(&self) -> [u8; 2] {
        let length = (self.length - MIN_SUBSEQUENCE) & LENGTH_MASK;
        let distance = (self.distance - MIN_SUBSEQUENCE) & DISTANCE_MASK;
        let value = ((length << DISTANCE_BITS) | distance) as u16;
        value.to_be_bytes()
    }

    /// Decodes two little-endian bytes into a length-distance pair.
    pub fn from_le_bytes(bytes: [u8; 2]) -> Self {
        let value = u16::from_le_bytes(bytes) as usize;
        let distance = (value & DISTANCE_MASK) + MIN_SUBSEQUENCE;
        let length = ((value >> DISTANCE_BITS) & LENGTH_MASK) + MIN_SUBSEQUENCE;
        Self { length, distance }
    }

    /// Decodes two big-endian bytes into a length-distance pair.
    pub fn from_be_bytes(bytes: [u8; 2]) -> Self {
        let value = u16::from_be_bytes(bytes) as usize;
        let distance = (value & DISTANCE_MASK) + MIN_SUBSEQUENCE;
        let length = ((value >> DISTANCE_BITS) & LENGTH_MASK) + MIN_SUBSEQUENCE;
        Self { length, distance }
    }

    /// Number of bytes saved by this length-distance pair.
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
    /// See [`Lz77ParseError`].
    #[snafu(transparent)]
    Parse {
        /// Source error.
        source: Lz77ParseError,
    },
    /// See [`io::Error`].
    #[snafu(transparent)]
    Io {
        /// Source error.
        source: io::Error,
    },
}

impl Lz77 {
    fn compress_bytes(&self, bytes: &[u8], compressed: &mut Vec<u8>) -> Result<usize, io::Error> {
        let mut tokens = Tokens::compress(bytes);
        tokens.drop_wasteful_tokens()?;
        tokens.write(compressed)
    }

    fn write_footer(
        &self,
        compressed: &mut Vec<u8>,
        bytes: &[u8],
        start: usize,
        num_identical: usize,
    ) -> Result<(), io::Error> {
        let padding = ((!compressed.len() + 1) & 3) as u8;
        for _ in 0..padding {
            compressed.push(0xff);
        }
        let total_size = compressed.len() + 8;
        let read_offset = padding + 8;
        let write_offset: u32 = (bytes.len() - total_size) as u32;
        let total_size = total_size - num_identical - start;
        let total_size_bytes = total_size.to_le_bytes();
        compressed.write(&[total_size_bytes[0], total_size_bytes[1], total_size_bytes[2]])?;
        compressed.push(read_offset);
        compressed.write(&write_offset.to_le_bytes())?;
        Ok(())
    }

    /// Compresses `bytes[start..]` and returns the result. All bytes before `start` are included in the output. Due to version
    /// differences in the compression algorithm, there is a `version` parameter taken from the ROM header.
    ///
    /// # Errors
    ///
    /// This function will return an error if an I/O operation fails.
    pub fn compress(&self, bytes: &[u8], start: usize) -> Result<Box<[u8]>, io::Error> {
        let mut compressed = Vec::with_capacity(bytes.len());
        let num_identical = self.compress_bytes(&bytes[start..], &mut compressed)?;
        for i in (0..start).rev() {
            compressed.push(bytes[i]);
        }
        compressed.reverse();

        self.write_footer(&mut compressed, bytes, start, num_identical)?;

        Ok(compressed.into_boxed_slice())
    }

    fn read_footer(&self, bytes: &[u8]) -> (usize, usize, usize) {
        let length = bytes.len();
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
        (total_size, read_offset, write_offset)
    }

    /// Parses the LZ77 tokens in the `bytes` slice.
    pub fn parse_tokens<'a>(&self, bytes: &'a [u8]) -> Result<Tokens<'a>, Lz77ParseError> {
        let (total_size, read_offset, write_offset) = self.read_footer(bytes);
        let num_identical = bytes.len() - total_size;
        let mut decompressed = Vec::with_capacity(bytes.len() + write_offset);
        let tokens = Tokens::decompress(&bytes[..num_identical + total_size - read_offset], num_identical, &mut decompressed)?;

        Ok(tokens)
    }

    /// Decompresses `bytes` and returns the result.
    pub fn decompress(&self, bytes: &[u8]) -> Result<Box<[u8]>, Lz77DecompressError> {
        let (total_size, read_offset, write_offset) = self.read_footer(bytes);
        let num_identical = bytes.len() - total_size;
        let mut decompressed = Vec::with_capacity(bytes.len() + write_offset);
        let _ = Tokens::decompress(&bytes[..num_identical + total_size - read_offset], num_identical, &mut decompressed)?;

        for i in (0..num_identical).rev() {
            decompressed.push(bytes[i]);
        }
        decompressed.reverse();

        Ok(decompressed.into_boxed_slice())
    }
}

#[derive(Clone)]
enum Token<'a> {
    Literal(u8),
    Pair((Pair, Cow<'a, [u8]>)),
}

impl<'a> Token<'a> {
    fn bytes_saved(&self) -> isize {
        match self {
            Token::Literal(_) => 0,
            Token::Pair((pair, _)) => pair.bytes_saved() as isize,
        }
    }
}

impl<'a> Display for Token<'a> {
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

/// Errors related to [`Tokens::decompress`].
#[derive(Debug, Snafu)]
pub enum Lz77ParseError {
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
    #[snafu(display(
        "length-distance pair {pair} at offset {offset:#x} points outside of decompressed stream:\n{backtrace}"
    ))]
    OutOfBounds {
        /// The erroneous length-distance pair.
        pair: Pair,
        /// Offset of length-distance pair.
        offset: usize,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
}

impl<'a> Tokens<'a> {
    fn find_match(bytes: &[u8], pos: usize) -> Option<Pair> {
        let max_lookahead = (LOOKAHEAD + MAX_SUBSEQUENCE).min(bytes.len() - pos - 1);
        (MIN_SUBSEQUENCE - 1..max_lookahead)
            .fold(None, |best_pair, i| {
                let needle = pos;
                let haystack = pos + 1 + i;
                if bytes[needle] != bytes[haystack] {
                    return best_pair;
                }
                let mut length = 0;
                while needle >= length
                    && bytes[needle - length] == bytes[haystack - length]
                    && haystack > pos + length
                    && length < MAX_SUBSEQUENCE
                {
                    length += 1;
                }
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
            if (tokens.len() % 8) == 0 {
                bytes_saved -= 1;
            }
            if let Some(pair) = Self::find_match(bytes, read - 1) {
                read -= pair.length;
                bytes_saved += pair.bytes_saved() as isize;
                tokens.push(Token::Pair((pair, Cow::Borrowed(&bytes[read..read + pair.length]))));
            } else {
                read -= 1;
                tokens.push(Token::Literal(bytes[read]));
            }
        }

        return Self { tokens, bytes_saved, dropped_tokens: 0 };
    }

    fn drop_wasteful_tokens(&mut self) -> Result<(), io::Error> {
        let mut best_token_index = None;

        let mut bytes_saved = 0;
        'outer: for (i, chunk) in self.tokens.chunks(8).enumerate() {
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
        self.dropped_tokens = self.tokens.len() - best_token_index - 1;

        Ok(())
    }

    fn make_flags_for_chunk(chunk: &[Token]) -> u8 {
        chunk.iter().fold(0u8, |acc, token| (acc << 1) | matches!(token, Token::Pair(_)) as u8) << (8 - chunk.len() as u8)
    }

    fn write(self, compressed: &mut Vec<u8>) -> Result<usize, io::Error> {
        let last_token_index = self.tokens.len() - self.dropped_tokens;
        'outer: for (i, chunk) in self.tokens.chunks(8).enumerate() {
            let flags = Self::make_flags_for_chunk(chunk);
            let index = i * 8;
            if index >= last_token_index {
                break 'outer;
            }

            compressed.push(flags);
            for (j, token) in chunk.iter().enumerate() {
                let index = index + j;
                if index >= last_token_index {
                    break 'outer;
                }

                match token {
                    Token::Literal(byte) => compressed.push(*byte),
                    Token::Pair((pair, _)) => {
                        compressed.write(&pair.to_be_bytes())?;
                    }
                }
            }
        }

        let mut num_identical = 0;
        for token in &self.tokens[last_token_index..] {
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

    fn decompress(bytes: &'a [u8], start: usize, decompressed: &mut Vec<u8>) -> Result<Self, Lz77ParseError> {
        let mut tokens = vec![];
        let mut iter = bytes.iter().cloned().enumerate().skip(start).rev().peekable();
        let mut bytes_saved = 0;

        while let Some((offset, mut flags)) = iter.next() {
            bytes_saved -= 1;
            for _ in 0..8 {
                if (flags & 0x80) == 0 {
                    let literal = iter.next().ok_or_else(|| NoLiteralSnafu { offset, flags }.build())?.1;
                    decompressed.push(literal);
                    tokens.push(Token::Literal(literal));
                } else {
                    let (offset, first) = iter.next().ok_or_else(|| NoPairSnafu { offset, flags }.build())?;
                    let pair = [first, iter.next().ok_or_else(|| IncompletePairSnafu { offset }.build())?.1];
                    let pair = Pair::from_be_bytes(pair);

                    bytes_saved += pair.bytes_saved() as isize;

                    if pair.distance > decompressed.len() {
                        OutOfBoundsSnafu { pair, offset }.fail()?;
                    }
                    let start = decompressed.len() - pair.distance;
                    let end = start + pair.length;
                    if end > decompressed.len() {
                        OutOfBoundsSnafu { pair, offset }.fail()?;
                    }

                    for i in start..end {
                        decompressed.push(decompressed[i]);
                    }
                    let bytes = decompressed[start..end].to_vec();
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

impl<'a> Display for Tokens<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut bytes_saved: isize = 0;
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
