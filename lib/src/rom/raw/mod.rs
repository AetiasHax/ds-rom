mod arm9_footer;
mod autoload_info;
mod banner;
mod build_info;
mod fat;
mod fnt;
mod header;
mod hmac_sha1_signature;
mod overlay;
mod rom;

pub use arm9_footer::*;
pub use autoload_info::*;
pub use banner::*;
pub use build_info::*;
pub use fat::*;
pub use fnt::*;
pub use header::*;
pub use hmac_sha1_signature::*;
pub use overlay::*;
pub use rom::*;

/// Nitrocode, interpreted as `2` (ni), `10` (tō), `6` (roku), `c0de`.
pub const NITROCODE: u32 = 0x2106c0de_u32.swap_bytes();

/// Nitrocode as a byte array.
pub const NITROCODE_BYTES: [u8; 4] = NITROCODE.to_le_bytes();
