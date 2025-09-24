//! Extracts and builds Nintendo DS ROMs.

#![warn(missing_docs)]

/// Compression algorithms.
pub mod compress;
/// CRC checksum algorithms.
pub mod crc;
/// Encryption algorithms.
pub mod crypto;
pub(crate) mod io;
/// ROM structs.
pub mod rom;
/// String utilities.
pub mod str;

pub use io::{AccessList, FileAccess, AccessMode::*};