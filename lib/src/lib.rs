//! Extracts and builds Nintendo DS ROMs.

#![warn(missing_docs)]

/// Compression algorithms.
pub mod compress;
/// CRC checksum algorithms.
pub mod crc;
/// Encryption algorithms.
pub mod crypto;
/// Common error types.
pub mod error;
pub(crate) mod io;
/// ROM structs.
pub mod rom;
/// String utilities.
pub mod str;
pub(crate) mod util;
pub(crate) mod writer;
