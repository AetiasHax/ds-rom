use aes::{
    Aes128,
    cipher::{BlockCipherEncrypt, KeyInit, array::Array},
};

/// Constant added by the DSi AES key scrambler, see [`scramble_key`].
const SCRAMBLER_CONSTANT: u128 = 0xfffefb4e295902582a680f5f1a4f3e79;

/// First 8 bytes of the retail Modcrypt Key_X, see [`Modcrypt::retail`].
const RETAIL_KEY_X_PREFIX: &[u8; 8] = b"Nintendo";

/// Size of one AES block.
const BLOCK_SIZE: usize = 16;

/// Combines `key_x` and `key_y` into an AES key, the same way the DSi AES hardware does when the last word of Key_Y is
/// written:
///
/// ```text
/// Key = ((Key_X XOR Key_Y) + 0xfffefb4e295902582a680f5f1a4f3e79) ROL 42
/// ```
///
/// The AES registers hold their keys in reverse byte order, so `key_x` and `key_y` are read as little-endian while the result
/// is written back as big-endian.
fn scramble_key(key_x: [u8; 16], key_y: [u8; 16]) -> [u8; 16] {
    let key_x = u128::from_le_bytes(key_x);
    let key_y = u128::from_le_bytes(key_y);
    let key = (key_x ^ key_y).wrapping_add(SCRAMBLER_CONSTANT).rotate_left(42);
    key.to_be_bytes()
}

/// Modcrypt cipher, an AES-128-CTR stream used to encrypt the ARM9i and ARM7i programs of a DSi title.
///
/// The DSi AES hardware consumes and produces each 16-byte block in reverse byte order, so this reverses every keystream
/// block instead, which is equivalent and leaves the data in place.
pub struct Modcrypt {
    cipher: Aes128,
}

impl Modcrypt {
    /// Creates a [`Modcrypt`] from an AES key directly.
    pub fn new(key: [u8; 16]) -> Self {
        Self { cipher: Aes128::new(&Array(key)) }
    }

    /// Creates the retail [`Modcrypt`] for a title, where:
    ///
    /// ```text
    /// Key_X[0..8]  = "Nintendo"
    /// Key_X[8..C]  = gamecode, forwards
    /// Key_X[C..10] = gamecode, backwards
    /// Key_Y[0..10] = first 16 bytes of the ARM9i SHA1-HMAC
    /// ```
    pub fn retail(gamecode: [u8; 4], sha1_hmac_arm9i: &[u8; 20]) -> Self {
        let mut key_x = [0u8; 16];
        key_x[0..8].copy_from_slice(RETAIL_KEY_X_PREFIX);
        key_x[8..12].copy_from_slice(&gamecode);
        key_x[12..16].copy_from_slice(&gamecode);
        key_x[12..16].reverse();

        let mut key_y = [0u8; 16];
        key_y.copy_from_slice(&sha1_hmac_arm9i[0..16]);

        Self::new(scramble_key(key_x, key_y))
    }

    /// Creates the debug [`Modcrypt`], whose key is the first 16 bytes of the ROM header.
    pub fn debug(header_start: &[u8; 16]) -> Self {
        Self::new(*header_start)
    }

    /// De/encrypts `data` in place, starting from the given counter. AES-CTR is symmetric, so this both encrypts and
    /// decrypts.
    ///
    /// The counter for Modcrypt area 1 is the first 16 bytes of the ARM9 SHA1-HMAC, and for area 2 the first 16 bytes of the
    /// ARM7 SHA1-HMAC. Use [`Self::counter`] to convert one into a counter.
    pub fn apply(&self, counter: [u8; 16], data: &mut [u8]) {
        let mut counter = u128::from_be_bytes(counter);
        for chunk in data.chunks_mut(BLOCK_SIZE) {
            let mut keystream = Array(counter.to_be_bytes());
            self.cipher.encrypt_block(&mut keystream);
            keystream.0.reverse();
            // A trailing partial block consumes the first bytes of the reversed keystream. Modcrypt areas are block-aligned
            // in practice, so this only guards against a malformed header.
            for (byte, key_byte) in chunk.iter_mut().zip(keystream.0.iter()) {
                *byte ^= *key_byte;
            }
            counter = counter.wrapping_add(1);
        }
    }

    /// Turns a SHA1-HMAC into an AES counter by taking its first 16 bytes in reverse order.
    pub fn counter(sha1_hmac: &[u8; 20]) -> [u8; 16] {
        let mut counter = [0u8; 16];
        counter.copy_from_slice(&sha1_hmac[0..16]);
        counter.reverse();
        counter
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FIPS-197 appendix C.1, to check that the AES block cipher underneath does what we expect.
    #[test]
    fn test_aes128_block() {
        let key: [u8; 16] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
        let mut block =
            Array([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        Aes128::new(&Array(key)).encrypt_block(&mut block);
        assert_eq!(block.0, [0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a]);
    }

    /// De/encrypting is the same operation, so applying it twice must be the identity.
    #[test]
    fn test_modcrypt_roundtrip() {
        let hmac = [0x5au8; 20];
        let modcrypt = Modcrypt::retail(*b"IREO", &hmac);
        let counter = Modcrypt::counter(&[0xa5u8; 20]);
        let plain = (0..0x40u8).collect::<Vec<_>>();

        let mut data = plain.clone();
        modcrypt.apply(counter, &mut data);
        assert_ne!(data, plain);
        modcrypt.apply(counter, &mut data);
        assert_eq!(data, plain);
    }
}
