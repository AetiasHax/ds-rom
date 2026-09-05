use std::borrow::Cow;

use serde::{Deserialize, Serialize};

use crate::crypto::modcrypt::Modcrypt;

/// Offsets and sizes of a DSi-exclusive program, see [`DsiProgram`].
#[derive(Serialize, Deserialize, Clone, Copy, Default)]
pub struct DsiProgramOffsets {
    /// Entrypoint function address.
    pub entry_function: u32,
    /// Base RAM address.
    pub base_address: u32,
    /// Build info offset, relative to the start of the program.
    pub build_info_offset: u32,
    /// Number of bytes at the start of the program that are Modcrypted in the ROM, or zero if it is stored in the clear.
    #[serde(default)]
    pub modcrypt_size: u32,
}

/// A DSi-exclusive program, either ARM9i or ARM7i. It is stored here as the plain blob the ROM
/// holds, with no footer or autoloads parsed, but the start of the program may be
/// [Modcrypted](Modcrypt).
///
/// The blob is not necessarily uncompressed. Pokemon Black 2's ARM9i is BLZ-compressed: 0x21c40
/// bytes decompressing to 0x6aef0, and it runs at 0x02700000 rather than the 0x02400000 the header
/// loads it at. Its decompressed image ends in a 16-byte autoload info entry, base 0x02700000 and
/// size 0x6aee0, at exactly the address base plus size names. Note that the decompressed length is
/// `blob_len - 4 + inc_len` and not the `dec_len + comp_len + inc_len` the usual BLZ formula gives,
/// which is 6 bytes short and misplaces every byte the backward pass writes.
///
/// The data is held *decrypted*, which is the form that the digest tables and the program's own SHA1-HMAC cover.
#[derive(Clone)]
pub struct DsiProgram<'a> {
    data: Cow<'a, [u8]>,
    offsets: DsiProgramOffsets,
}

impl<'a> DsiProgram<'a> {
    /// Creates a new [`DsiProgram`] from decrypted data.
    pub fn new<T: Into<Cow<'a, [u8]>>>(data: T, offsets: DsiProgramOffsets) -> Self {
        Self { data: data.into(), offsets }
    }

    /// De/encrypts the Modcrypt area at the start of this program in place. AES-CTR is symmetric, so this both encrypts and
    /// decrypts. Does nothing if this program is not Modcrypted.
    pub fn apply_modcrypt(&mut self, modcrypt: &Modcrypt, counter: [u8; 16]) {
        let size = (self.offsets.modcrypt_size as usize).min(self.data.len());
        if size == 0 {
            return;
        }
        modcrypt.apply(counter, &mut self.data.to_mut()[..size]);
    }

    /// Returns whether this program is Modcrypted in the ROM.
    pub fn is_modcrypted(&self) -> bool {
        self.offsets.modcrypt_size != 0
    }

    /// Returns the decrypted data of this program.
    pub fn full_data(&self) -> &[u8] {
        &self.data
    }

    /// Returns the offsets of this program.
    pub fn offsets(&self) -> &DsiProgramOffsets {
        &self.offsets
    }
}
