use std::{backtrace::Backtrace, fmt::Display, num::ParseIntError, str::FromStr};

use bytemuck::{Pod, PodCastError, Zeroable};
use serde::{Deserialize, Deserializer, Serialize};
use snafu::Snafu;

use crate::crypto::hmac_sha1::HmacSha1;

/// HMAC-SHA1 signature, used for overlays and overlay tables.
#[repr(C)]
#[derive(Clone, Copy, Zeroable, Pod, PartialEq, Eq)]
pub struct HmacSha1Signature {
    /// The HMAC-SHA1 hash.
    pub hash: [u8; 20],
}

/// Errors related to [`HmacSha1Signature`].
#[derive(Debug, Snafu)]
pub enum HmacSha1SignatureError {
    /// Occurs when the input is not evenly divisible into a slice of [`HmacSha1Signature`].
    #[snafu(display("the HMAC-SHA1 signature table must be a multiple of {} bytes:\n{backtrace}", size_of::<HmacSha1Signature>()))]
    InvalidSize {
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// Occurs when the input is less aligned than [`HmacSha1Signature`].
    #[snafu(display("expected {expected}-alignment for HMAC-SHA1 signature table but got {actual}-alignment:\n{backtrace}"))]
    Misaligned {
        /// Expected alignment.
        expected: usize,
        /// Actual input alignment.
        actual: usize,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
}

impl HmacSha1Signature {
    /// Creates a new [`HmacSha1Signature`] by hashing the given data.
    pub fn from_hmac_sha1(hmac_sha1: &HmacSha1, data: &[u8]) -> Self {
        let hash = hmac_sha1.compute(data);
        Self { hash }
    }

    /// Sets the hash to the given value.
    pub fn set(&mut self, hash: [u8; 20]) {
        self.hash = hash;
    }

    fn check_size(data: &[u8]) -> Result<(), HmacSha1SignatureError> {
        let size = size_of::<Self>();
        if data.len() % size != 0 {
            InvalidSizeSnafu {}.fail()
        } else {
            Ok(())
        }
    }

    fn handle_pod_cast<T>(result: Result<T, PodCastError>, addr: usize) -> Result<T, HmacSha1SignatureError> {
        match result {
            Ok(signatures) => Ok(signatures),
            Err(PodCastError::TargetAlignmentGreaterAndInputNotAligned) => {
                MisalignedSnafu { expected: size_of::<Self>(), actual: addr }.fail()
            }
            Err(PodCastError::AlignmentMismatch) => panic!(),
            Err(PodCastError::OutputSliceWouldHaveSlop) => panic!(),
            Err(PodCastError::SizeMismatch) => unreachable!(),
        }
    }

    /// Reinterprets a `&[u8]` as a slice of [`HmacSha1Signature`].
    ///
    /// # Errors
    ///
    /// This function will return an error if the input is the wrong size, or not aligned enough.
    pub fn borrow_from_slice(data: &'_ [u8]) -> Result<&'_ [Self], HmacSha1SignatureError> {
        Self::check_size(data)?;
        let addr = data as *const [u8] as *const () as usize;
        Self::handle_pod_cast(bytemuck::try_cast_slice(data), addr)
    }

    /// Reinterprets a `&mut [u8]` as a mutable slice of [`HmacSha1Signature`].
    ///
    /// # Errors
    ///
    /// This function will return an error if the input is the wrong size, or not aligned enough.
    pub fn borrow_from_slice_mut(data: &'_ mut [u8]) -> Result<&'_ mut [Self], HmacSha1SignatureError> {
        Self::check_size(data)?;
        let addr = data as *const [u8] as *const () as usize;
        Self::handle_pod_cast(bytemuck::try_cast_slice_mut(data), addr)
    }
}

impl Display for HmacSha1Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in &self.hash {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

/// Errors related to parsing an HMAC-SHA1 signature from a string.
#[derive(Debug, Snafu)]
pub enum HmacSha1SignatureParseError {
    /// Occurs when the input is not a valid length.
    #[snafu(display("invalid length: {length}:\n{backtrace}"))]
    InvalidLength {
        /// The invalid length.
        length: usize,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// Occurs when the input is not a valid hex string.
    #[snafu(display("invalid hex string '{string}':{error}\n{backtrace}"))]
    ParseInt {
        /// The original error.
        error: ParseIntError,
        /// The invalid hex string.
        string: String,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
}

impl FromStr for HmacSha1Signature {
    type Err = HmacSha1SignatureParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 40 {
            return InvalidLengthSnafu { length: s.len() }.fail();
        }

        let mut hash = [0u8; 20];
        for i in 0..20 {
            let byte_str = &s[i * 2..i * 2 + 2];
            hash[i] = u8::from_str_radix(byte_str, 16)
                .map_err(|error| ParseIntSnafu { error, string: byte_str.to_string() }.build())?;
        }

        Ok(Self { hash })
    }
}

impl Serialize for HmacSha1Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.to_string().as_str())
    }
}

impl<'de> Deserialize<'de> for HmacSha1Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::from_str(&s).map_err(serde::de::Error::custom)
    }
}
