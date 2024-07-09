use std::io::{self, Write};

pub struct Lz77 {}

const LENGTH_BITS: usize = 4;
const DISTANCE_BITS: usize = 12;
const MIN_SUBSEQUENCE: usize = 3;
const MIN_DISTANCE: usize = 3;

const LENGTH_MASK: usize = (1 << LENGTH_BITS) - 1;
const DISTANCE_MASK: usize = (1 << DISTANCE_BITS) - 1;

const MAX_SUBSEQUENCE: usize = MIN_SUBSEQUENCE + LENGTH_MASK;
const LOOKAHEAD: usize = 1 << DISTANCE_BITS;

/// Length-distance pair
#[derive(Clone, Copy)]
struct Pair {
    length: usize,
    distance: usize,
}

impl Pair {
    pub fn to_le_bytes(&self) -> [u8; 2] {
        let length = (self.length - MIN_SUBSEQUENCE) & LENGTH_MASK;
        let distance = (self.distance - MIN_DISTANCE) & DISTANCE_MASK;
        let value = ((length << DISTANCE_BITS) | distance) as u16;
        value.to_le_bytes()
    }

    pub fn from_le_bytes(bytes: [u8; 2]) -> Self {
        let value = u16::from_le_bytes(bytes) as usize;
        let distance = (value & DISTANCE_MASK) + MIN_DISTANCE;
        let length = ((value >> DISTANCE_BITS) & LENGTH_MASK) + MIN_SUBSEQUENCE;
        Self { length, distance }
    }
}

#[derive(Clone, Copy)]
struct BlockInfo {
    pos: usize,
    total_bytes_saved: usize,
    flags: u8,
}

impl Lz77 {
    fn find_match(&self, bytes: &[u8], pos: usize) -> Option<Pair> {
        let max_lookahead = (LOOKAHEAD + MIN_DISTANCE + MAX_SUBSEQUENCE).min(bytes.len() - pos - 1);
        (0..max_lookahead)
            .fold(None, |best_pair, i| {
                let needle = pos;
                let haystack = pos + 1 + i;
                if bytes[needle] != bytes[haystack] {
                    return best_pair;
                }
                let mut length = 0;
                while needle >= length
                    && bytes[pos + needle - length] == bytes[pos + haystack - length]
                    && haystack > pos + length
                    && length < MAX_SUBSEQUENCE
                {
                    length += 1;
                }
                let distance = haystack - needle - MIN_SUBSEQUENCE;
                if length > best_pair.map_or(0, |p: Pair| p.length) && distance <= DISTANCE_MASK {
                    Some(Pair { length, distance })
                } else {
                    best_pair
                }
            })
            .and_then(|p| (p.length >= MIN_SUBSEQUENCE).then_some(p))
    }

    fn compress_bytes(&self, bytes: &[u8], compressed: &mut Vec<u8>) -> Result<usize, io::Error> {
        let mut block_infos = vec![];

        let mut read = bytes.len();
        let mut flags = 0;
        let mut flag_count = 0;
        let mut flag_pos = compressed.len();
        let mut bytes_saved = 0;
        while read > 0 {
            flags <<= 1;
            if let Some(pair) = self.find_match(bytes, read - 1) {
                // write length-distance pair
                read -= pair.length;
                let encoded = pair.to_le_bytes();
                compressed.write(&encoded)?;
                flags |= 1;
                bytes_saved += pair.length - encoded.len();
            } else {
                // write literal
                read -= 1;
                compressed.write(&[bytes[read]])?;
            }

            flag_count += 1;
            if flag_count == 8 {
                // write flag byte
                flag_count = 0;
                compressed[flag_pos] = flags;
                bytes_saved -= 1;
                flag_pos = compressed.len();
                block_infos.push(BlockInfo { pos: compressed.len(), total_bytes_saved: bytes_saved, flags });
                flags = 0;
            }
        }

        if flag_count != 0 {
            // trailing flag byte
            flags <<= 8 - flag_count;
            block_infos.push(BlockInfo { pos: compressed.len(), total_bytes_saved: bytes_saved, flags });
            compressed[flag_pos] = flags;
        } else {
            compressed.pop();
        }

        let mut num_identical = 0;
        for i in 0..block_infos.len() - 1 {
            let block = block_infos[i];
            if block.total_bytes_saved != bytes_saved {
                continue;
            }
            // Save more bytes by ignoring blocks that have no length-distance pairs in them
            let mut flag_bytes_saved = block_infos[..=i].iter().rev().take_while(|b| b.flags != 0).count();
            num_identical = block.pos - compressed.len();
            compressed.pop();

            // See if it's possible to remove some tokens based on the number of flag bytes saved
            flags = block.flags;
            for _ in 0..8 {
                if flag_bytes_saved <= 0 {
                    break;
                }
                if (flags & 0x80) != 0 {
                    if flag_bytes_saved < 2 {
                        break;
                    }
                    num_identical += 2;
                    flag_bytes_saved -= 2;
                } else {
                    num_identical += 1;
                    flag_bytes_saved -= 1;
                }
                flags >>= 1;
            }

            compressed.write(&bytes[..num_identical])?;
            let write = compressed.len();
            while compressed[write + num_identical] == bytes[read + num_identical] {
                num_identical += 1;
            }
            break;
        }

        Ok(num_identical)
    }

    fn write_footer(
        &self,
        compressed: &mut Vec<u8>,
        bytes: &[u8],
        start: usize,
        num_identical: usize,
    ) -> Result<(), io::Error> {
        let padding = (3 ^ (compressed.len() & 3)) as u8;
        for _ in 0..padding {
            compressed.push(0xff);
        }
        let total_size = compressed.len() + 8;
        let read_offset = padding + 8;
        let write_offset = bytes.len() - total_size - start;
        let total_size = total_size - num_identical;
        let total_size_bytes = total_size.to_le_bytes();
        compressed.write(&[total_size_bytes[0], total_size_bytes[1], total_size_bytes[2]])?;
        compressed.push(read_offset);
        compressed.write(&write_offset.to_le_bytes())?;
        Ok(())
    }

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

    pub fn decompress(&self, bytes: &[u8]) -> Box<[u8]> {
        let (total_size, read_offset, write_offset) = self.read_footer(bytes);

        let num_identical = bytes.len() - total_size;
        let mut decompressed = Vec::with_capacity(bytes.len() + write_offset);
        self.decompress_bytes(&bytes[num_identical..num_identical + total_size - read_offset], &mut decompressed);

        for i in (0..num_identical).rev() {
            decompressed.push(bytes[i]);
        }
        decompressed.reverse();

        decompressed.into_boxed_slice()
    }
}
