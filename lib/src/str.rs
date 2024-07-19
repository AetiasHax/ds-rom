use std::fmt::Display;

use bytemuck::{Pod, Zeroable};
use serde::{de, Deserialize, Serialize};
use snafu::{Backtrace, Snafu};

/// A fixed-size ASCII string.
#[derive(Clone, Copy)]
pub struct AsciiArray<const N: usize>(pub [u8; N]);

/// Errors related to [`AsciiArray`].
#[derive(Debug, Snafu)]
pub enum AsciiArrayError {
    /// Occurs when an input character is not in ASCII.
    #[snafu(display("the provided string '{string}' contains one or more non-ASCII characters:\n{backtrace}"))]
    NotAscii {
        /// The invalid string.
        string: String,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
}

impl<const N: usize> AsciiArray<N> {
    /// Loads from a `&str`.
    ///
    /// # Errors
    ///
    /// This function will return an error if the string contains a non-ASCII character.
    pub fn from_str(string: &str) -> Result<Self, AsciiArrayError> {
        let mut chars = [0u8; N];
        for (i, ch) in string.chars().take(N).enumerate() {
            if !ch.is_ascii() {
                return NotAsciiSnafu { string: string.to_string() }.fail();
            }
            chars[i] = ch as u8;
        }
        Ok(Self(chars))
    }
}

impl AsciiArray<4> {
    /// Converts a four-character ASCII string to a `u32`.
    pub fn to_le_u32(&self) -> u32 {
        u32::from_le_bytes(self.0)
    }
}

impl<const N: usize> Display for AsciiArray<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for ch in self.0 {
            if ch == 0 {
                break;
            }
            write!(f, "{}", ch as char)?;
        }
        Ok(())
    }
}

impl<const N: usize> Serialize for AsciiArray<N> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de, const N: usize> Deserialize<'de> for AsciiArray<N> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let string: String = Deserialize::deserialize(deserializer)?;
        Ok(Self::from_str(&string).map_err(de::Error::custom)?)
    }
}

/// A fixed-size 16-bit Unicode string.
#[derive(Clone, Copy)]
pub struct Unicode16Array<const N: usize>(pub [u16; N]);

unsafe impl<const N: usize> Zeroable for Unicode16Array<N> {}
unsafe impl<const N: usize> Pod for Unicode16Array<N> {}

impl<const N: usize> Unicode16Array<N> {
    /// Loads from a `&str`.
    pub fn from_str(string: &str) -> Self {
        let mut chars = [0u16; N];
        let mut i = 0;
        for ch in string.chars() {
            let mut codepoints = [0u16; 2];
            ch.encode_utf16(&mut codepoints);

            let len = if codepoints[1] != 0 { 2 } else { 1 };
            if i + len >= N {
                break;
            }

            for j in 0..len {
                chars[i] = codepoints[j];
                i += 1;
            }
        }
        Self(chars)
    }
}

impl<const N: usize> Display for Unicode16Array<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for ch in self.0 {
            if ch == 0 {
                break;
            }
            let Some(ch) = char::from_u32(ch as u32) else {
                break;
            };
            write!(f, "{ch}")?;
        }
        Ok(())
    }
}

pub(crate) struct BlobSize(pub usize);

impl Display for BlobSize {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let size = self.0;
        match size {
            0..=0x3ff => write!(f, "{}B", size),
            0x400..=0xfffff => write!(f, "{:.1}kB", size as f32 / 0x400 as f32),
            0x100000.. => write!(f, "{:.1}MB", size as f32 / 0x100000 as f32),
        }
    }
}

/// For debugging purposes.
#[allow(unused)]
pub(crate) fn write_hex(f: &mut std::fmt::Formatter<'_>, data: &[u8]) -> std::fmt::Result {
    for (offset, chunk) in data.chunks(16).enumerate() {
        write!(f, "{:08x} ", offset * 16)?;
        for byte in chunk {
            write!(f, " {byte:02x}")?;
        }
        writeln!(f)?;
    }
    writeln!(f)?;
    Ok(())
}

/// For debugging purposes.
#[allow(unused)]
pub(crate) fn print_hex(data: &[u8]) {
    for (offset, chunk) in data.chunks(16).enumerate() {
        print!("{:08x} ", offset * 16);
        for byte in chunk {
            print!(" {byte:02x}");
        }
        println!();
    }
    println!();
}
