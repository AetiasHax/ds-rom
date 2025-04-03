use std::backtrace::Backtrace;

use sha1::{Digest, Sha1};
use snafu::Snafu;

/// Performs HMAC-SHA1 hashing to generate signatures.
#[derive(Clone)]
pub struct HmacSha1 {
    inner_pad: [u8; 64],
    outer_pad: [u8; 64],
}

impl HmacSha1 {
    /// Creates a new [`HmacSha1`] instance with the given key.
    pub fn new(key: [u8; 64]) -> Self {
        let mut inner_pad = [0x36; 64];
        let mut outer_pad = [0x5c; 64];
        inner_pad.iter_mut().zip(key.iter()).for_each(|(i, k)| *i ^= *k);
        outer_pad.iter_mut().zip(key.iter()).for_each(|(o, k)| *o ^= *k);
        Self { inner_pad, outer_pad }
    }

    /// Computes the HMAC-SHA1 hash of the given data using the key.
    pub fn compute(&self, data: &[u8]) -> [u8; 20] {
        let mut sha1 = Sha1::new();
        sha1.update(self.inner_pad);
        sha1.update(data);
        let inner_hash = sha1.finalize_reset();

        sha1.update(self.outer_pad);
        sha1.update(inner_hash);
        let outer_hash = sha1.finalize();

        outer_hash.into()
    }
}

/// Errors related to parsing a HMAC-SHA1 key from bytes.
#[derive(Debug, Snafu)]
pub enum HmacSha1FromBytesError {
    /// Occurs when the key is not 64 bytes long.
    #[snafu(display("key must be 64 bytes long, but got {} bytes:\n{backtrace}", length))]
    InvalidKeyLength {
        /// Actual key length.
        length: usize,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
}

impl TryFrom<&[u8]> for HmacSha1 {
    type Error = HmacSha1FromBytesError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != 64 {
            return InvalidKeyLengthSnafu { length: value.len() }.fail();
        }
        let mut key = [0; 64];
        key.copy_from_slice(value);
        Ok(Self::new(key))
    }
}
