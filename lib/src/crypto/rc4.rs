/// Generates a pseudorandom keystream using the RC4 stream cipher.
pub struct Rc4 {
    x: Option<u8>,
    i: u8,
    j: u8,
    s: [u8; 256],
}

impl Rc4 {
    /// Initializes the RC4 permutation using a variable-length key.
    pub fn new(key: &[u8], x: Option<u8>) -> Self {
        // Identity permutation
        let mut s = [0; 256];
        for i in 0..256 {
            s[i] = i as u8;
        }

        let mut j = 0usize;
        for i in 0..256 {
            // Accessing S in reverse is a deviation from standard RC4
            j = (j + s[255 - i] as usize + key[i % key.len()] as usize) & 0xff;
            s.swap(j, 255 - i);
        }

        Self { x, i: 0, j: 0, s }
    }

    fn s(&self, index: u8) -> u8 {
        self.s[index as usize]
    }

    /// Yields the next byte in the keystream.
    pub fn byte(&mut self) -> u8 {
        let x = self.x.unwrap_or(0);
        self.i = self.i.wrapping_add(1).wrapping_add(x);
        self.j = self.j.wrapping_add(self.s(self.i)).wrapping_add(x);

        self.s.swap(self.i as usize, self.j as usize);

        let t = self.s(self.i).wrapping_add(self.s(self.j));
        self.s(t)
    }

    /// Fills `out` with new bytes from the keystream.
    pub fn bytes(&mut self, out: &mut [u8]) {
        for o in out.iter_mut() {
            *o = self.byte();
        }
    }

    /// Decrypts the next byte in an encrypted payload.
    pub fn decrypt_byte(&mut self, b: u8) -> u8 {
        let result = self.byte() ^ b;
        if let Some(x) = self.x.as_mut() {
            *x = b;
        }
        result
    }

    /// Updates the x value using a callback receiving the current value and returning the new value.
    pub fn update_x<F: FnOnce(u8) -> u8>(&mut self, f: F) {
        if let Some(x) = self.x.as_mut() {
            *x = f(*x);
        }
    }
}

#[test]
fn test_rc4() {
    let mut rc4 =
        Rc4::new(&[0xda, 0x6a, 0x00, 0x00, 0x68, 0xb2, 0x6a, 0x00, 0x68, 0x00, 0xb2, 0x6a, 0x02, 0x00, 0x00, 0xb2], None);

    let mut keystream = [0; 32];
    rc4.bytes(&mut keystream);
    assert_eq!(keystream, [
        0x4e, 0x73, 0xc1, 0x63, 0x22, 0x16, 0x6e, 0xe5, 0xfd, 0xb9, 0x78, 0x1f, 0x11, 0xab, 0x28, 0xeb, 0xd3, 0x19, 0xd5,
        0xac, 0x6c, 0x00, 0x14, 0x65, 0xb7, 0x1d, 0x44, 0x34, 0x46, 0x1d, 0x85, 0x44
    ])
}

#[test]
fn test_rc4_x() {
    let mut rc4 = Rc4::new(
        &[0xe3, 0x94, 0x00, 0x00, 0x8c, 0x6f, 0x94, 0x00, 0x8c, 0x00, 0x6f, 0x94, 0x18, 0x00, 0x00, 0x6f],
        Some(0xaa),
    );

    let mut keystream = [0; 32];
    rc4.bytes(&mut keystream);
    assert_eq!(keystream, [
        0xb6, 0x03, 0x59, 0x09, 0x01, 0x73, 0x29, 0xbd, 0x19, 0x4a, 0x69, 0xbf, 0xfc, 0x00, 0xe4, 0xfc, 0x89, 0x1b, 0x61,
        0x88, 0x70, 0xe1, 0x66, 0x5e, 0x0e, 0x15, 0xfb, 0xed, 0x36, 0x77, 0x22, 0xab
    ])
}
