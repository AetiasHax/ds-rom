use std::{
    backtrace::Backtrace,
    borrow::Cow,
    fmt::Display,
    io::{self, Write},
};

use snafu::Snafu;

use crate::rom::raw::HeaderVersion;

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
    pub fn to_be_bytes(&self) -> [u8; 2] {
        let length = (self.length - MIN_SUBSEQUENCE) & LENGTH_MASK;
        let distance = (self.distance - MIN_SUBSEQUENCE) & DISTANCE_MASK;
        let value = ((length << DISTANCE_BITS) | distance) as u16;
        value.to_be_bytes()
    }

    pub fn from_le_bytes(bytes: [u8; 2]) -> Self {
        let value = u16::from_le_bytes(bytes) as usize;
        let distance = (value & DISTANCE_MASK) + MIN_SUBSEQUENCE;
        let length = ((value >> DISTANCE_BITS) & LENGTH_MASK) + MIN_SUBSEQUENCE;
        Self { length, distance }
    }

    pub fn from_be_bytes(bytes: [u8; 2]) -> Self {
        let value = u16::from_be_bytes(bytes) as usize;
        let distance = (value & DISTANCE_MASK) + MIN_SUBSEQUENCE;
        let length = ((value >> DISTANCE_BITS) & LENGTH_MASK) + MIN_SUBSEQUENCE;
        Self { length, distance }
    }

    pub fn bytes_saved(&self) -> usize {
        self.length - MIN_SUBSEQUENCE
    }
}

impl Display for Pair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#x}+{:#x} ({:04x})", self.distance, self.length, u16::from_be_bytes(self.to_be_bytes()))
    }
}

#[derive(Clone, Copy, Debug)]
struct BlockInfo {
    pos: usize,
    bytes_saved: isize,
    flags: u8,
    flag_count: u8,
}

impl Display for BlockInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "pos={:#x}, bytes_saved={}, flags=0x{:02x}, flag_count={}, read={}, written={}",
            self.pos,
            self.bytes_saved,
            self.flags,
            self.flag_count,
            self.bytes_read(),
            self.bytes_written()
        )
    }
}

impl BlockInfo {
    fn bytes_written(&self) -> usize {
        1 + self.flag_count as usize + self.flags.count_ones() as usize
    }

    fn bytes_read(&self) -> usize {
        (self.bytes_written() as isize + self.bytes_saved) as usize
    }
}

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
    fn find_match(&self, bytes: &[u8], pos: usize) -> Option<Pair> {
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

    fn should_stop_ignoring_blocks(&self, version: HeaderVersion, saved: isize, next_block: Option<&&BlockInfo>) -> bool {
        match version {
            HeaderVersion::Original => saved < 0 && next_block.map_or(true, |b| b.bytes_saved >= 0),
            HeaderVersion::DsPostDsi => saved <= 0,
        }
    }

    fn compress_bytes(&self, version: HeaderVersion, bytes: &[u8], compressed: &mut Vec<u8>) -> Result<usize, io::Error> {
        let mut block_infos = Vec::with_capacity(bytes.len() / 8);

        let mut read = bytes.len();
        let mut flags = 0;
        let mut flag_count = 0;
        let mut flag_pos = compressed.len();
        compressed.push(0); // placeholder for flag byte
        let mut bytes_saved = 0; // current block only
        while read > 0 {
            flags <<= 1;
            if let Some(pair) = self.find_match(bytes, read - 1) {
                // write length-distance pair
                read -= pair.length;
                let encoded = pair.to_be_bytes();
                compressed.write(&encoded)?;
                flags |= 1;
                let saved = (pair.length - encoded.len()) as isize;
                bytes_saved += saved;
            } else {
                // write literal
                read -= 1;
                compressed.write(&[bytes[read]])?;
            }

            flag_count += 1;
            if flag_count == 8 {
                // write flag byte
                compressed[flag_pos] = flags;
                bytes_saved -= 1;
                flag_pos = compressed.len();
                block_infos.push(BlockInfo { pos: compressed.len(), bytes_saved, flags, flag_count });
                bytes_saved = 0;
                compressed.push(0); // placeholder for flag byte
                flags = 0;
                flag_count = 0;
            }
        }

        if flag_count != 0 {
            // trailing flag byte
            flags <<= 8 - flag_count;
            bytes_saved -= 1;
            block_infos.push(BlockInfo { pos: compressed.len(), bytes_saved, flags, flag_count });
            bytes_saved = 0;
            compressed[flag_pos] = flags;
        } else {
            compressed.pop(); // remove unused flag byte placeholder
        }

        let mut num_identical: usize = 0;

        // Save more bytes by ignoring blocks that have no length-distance pairs in them
        let mut iter = block_infos.iter().rev().peekable();
        let mut block_bytes_saved = 0;
        let mut block_bytes_read = 0;
        let mut last_block = None;
        while let Some(block) = iter.next() {
            block_bytes_saved += block.bytes_saved;
            if block.bytes_saved != 0 {
                if self.should_stop_ignoring_blocks(version, bytes_saved - block_bytes_saved, iter.peek()) {
                    if bytes_saved > 0 {
                        num_identical += block_bytes_read + block.flags.trailing_zeros() as usize;
                    }
                    last_block = Some(block);
                    break;
                }
                num_identical += block_bytes_read;
                bytes_saved -= block_bytes_saved;

                // reset
                block_bytes_saved = 0;
                block_bytes_read = 0;
            }
            block_bytes_read += block.bytes_read();
        }

        // Remove leftover length-distance pairs depending on bytes saved
        if bytes_saved > 1 {
            if let Some(block) = last_block {
                flags = block.flags;
                read = block.pos - 1;

                for _ in 0..8 {
                    read -= 1;
                    if flags & 0x01 != 0 {
                        if bytes_saved <= 1 {
                            break;
                        }
                        let pair = Pair::from_le_bytes([compressed[read + 1], compressed[read]]);
                        let pair_bytes_saved = pair.length as isize - 2;
                        if bytes_saved >= pair_bytes_saved {
                            bytes_saved -= pair_bytes_saved;
                            num_identical += pair.length;
                        } else {
                            break;
                        }
                        read -= 1;
                    } else {
                        num_identical += 1;
                    }
                    flags >>= 1;
                }
            }
        }

        // Remove remaining bytes saved from the compressed file
        // `bytes_saved` is always positive or zero here
        compressed.resize((compressed.len() as isize - bytes_saved) as usize, 0);

        let write = compressed.len() - 1;
        for i in 0..num_identical {
            compressed[write - i] = bytes[i];
        }

        Ok(num_identical)
    }

    fn compress_bytes2(&self, version: HeaderVersion, bytes: &[u8], compressed: &mut Vec<u8>) -> Result<usize, io::Error> {
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
    pub fn compress(&self, version: HeaderVersion, bytes: &[u8], start: usize) -> Result<Box<[u8]>, io::Error> {
        let mut compressed = Vec::with_capacity(bytes.len());
        // let num_identical = self.compress_bytes(version, &bytes[start..], &mut compressed)?;
        let num_identical = self.compress_bytes2(version, &bytes[start..], &mut compressed)?;
        for i in (0..start).rev() {
            compressed.push(bytes[i]);
        }
        compressed.reverse();

        self.write_footer(&mut compressed, bytes, start, num_identical)?;

        Ok(compressed.into_boxed_slice())
    }

    fn decompress_bytes(&self, bytes: &[u8], decompressed: &mut Vec<u8>) {
        let mut read: isize = bytes.len() as isize - 1;

        while read > 0 {
            let mut flags = bytes[read as usize];
            read -= 1;
            for _ in 0..8 {
                if (flags & 0x80) == 0 {
                    // read literal
                    decompressed.push(bytes[read as usize]);
                    read -= 1;
                } else {
                    // read length-distance pair
                    let encoded = [bytes[read as usize - 1], bytes[read as usize]];
                    read -= 2;
                    let pair = Pair::from_le_bytes(encoded);
                    let pos = decompressed.len();
                    for i in 0..pair.length {
                        decompressed.push(decompressed[pos - pair.distance + i]);
                    }
                }
                if read < 0 {
                    break;
                }
                flags <<= 1;
            }
        }
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
            Token::Pair((pair, _)) => pair.length as isize - 2,
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

pub struct Tokens<'a> {
    tokens: Vec<Token<'a>>,
    extra_bytes: Vec<u8>,
}

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
        while read > 0 {
            if let Some(pair) = Self::find_match(bytes, read - 1) {
                read -= pair.length;
                tokens.push(Token::Pair((pair, Cow::Borrowed(&bytes[read..read + pair.length]))));
            } else {
                read -= 1;
                tokens.push(Token::Literal(bytes[read]));
            }
        }

        return Self { tokens, extra_bytes: vec![].into() };
    }

    fn drop_wasteful_tokens(&mut self) -> Result<(), io::Error> {
        let mut tokens_to_drop = 0;
        let mut flag_bytes_saved: isize = 0;
        for (index, token) in self.tokens.iter().enumerate().rev() {
            let Token::Pair((pair, _)) = token else { continue };
            flag_bytes_saved -= pair.bytes_saved() as isize;
            if (index % 8) == 7 {
                flag_bytes_saved += 1;
            }
            if flag_bytes_saved >= 0 {
                tokens_to_drop = (self.tokens.len() - 1) - index;
            }
        }

        for _ in 0..tokens_to_drop {
            let last_token = self.tokens.last().unwrap().clone();
            match last_token {
                Token::Literal(byte) => {
                    self.extra_bytes.push(byte);
                }
                Token::Pair((_, bytes)) => {
                    self.extra_bytes.write(&bytes)?;
                }
            }
            self.tokens.pop();
        }

        Ok(())
    }

    fn write(mut self, compressed: &mut Vec<u8>) -> Result<usize, io::Error> {
        for chunk in self.tokens.chunks(8) {
            let flags = chunk.iter().fold(0u8, |acc, token| (acc << 1) | matches!(token, Token::Pair(_)) as u8)
                << (8 - chunk.len() as u8);
            compressed.push(flags);
            for token in chunk {
                match token {
                    Token::Literal(byte) => compressed.push(*byte),
                    Token::Pair((pair, _)) => {
                        compressed.write(&pair.to_be_bytes())?;
                    }
                }
            }
        }

        self.extra_bytes.reverse();
        compressed.write(&self.extra_bytes)?;

        Ok(self.extra_bytes.len())
    }

    fn decompress(bytes: &'a [u8], start: usize, decompressed: &mut Vec<u8>) -> Result<Self, Lz77ParseError> {
        let mut tokens = vec![];
        let mut iter = bytes.iter().cloned().enumerate().skip(start).rev().peekable();

        while let Some((offset, mut flags)) = iter.next() {
            for _ in 0..8 {
                if (flags & 0x80) == 0 {
                    let literal = iter.next().ok_or_else(|| NoLiteralSnafu { offset, flags }.build())?.1;
                    decompressed.push(literal);
                    tokens.push(Token::Literal(literal));
                } else {
                    let (offset, first) = iter.next().ok_or_else(|| NoPairSnafu { offset, flags }.build())?;
                    let pair = [first, iter.next().ok_or_else(|| IncompletePairSnafu { offset }.build())?.1];
                    let pair = Pair::from_be_bytes(pair);

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

        Ok(Self { tokens, extra_bytes: vec![] })
    }
}

impl<'a> Display for Tokens<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut bytes_saved: isize = 0;
        for chunk in self.tokens.rchunks(8).rev() {
            for token in chunk {
                bytes_saved += token.bytes_saved();
                writeln!(f, "saved: {bytes_saved} | {token}")?;
            }
            bytes_saved -= 1;
        }
        writeln!(f, "Extra: {:x?}", self.extra_bytes)?;
        Ok(())
    }
}
