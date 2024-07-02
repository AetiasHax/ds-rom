use std::mem::{align_of, size_of};

use bytemuck::{Pod, PodCastError, Zeroable};
use snafu::{Backtrace, Snafu};

#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct Blowfish {
    subkeys: [u32; 18],
    sbox: [[u32; 0x100]; 4],
}

#[derive(Debug, Snafu)]
pub enum BlowfishError {
    #[snafu(display("data must have an even number of blocks for Blowfish encryption/decryption:\n{backtrace}"))]
    OddBlockCount { backtrace: Backtrace },
    #[snafu(display("expected {expected}-alignment for Blowfish key but got {actual}-alignment:\n{backtrace}"))]
    Misaligned { expected: usize, actual: usize, backtrace: Backtrace },
    #[snafu(display("expected {expected:#x} bytes for Blowfish key but got {actual:#x}:\n{backtrace}"))]
    KeySize { expected: usize, actual: usize, backtrace: Backtrace },
}

impl Blowfish {
    fn f(&self, x: u32) -> u32 {
        let x = x as usize;
        let mut f;
        f = self.sbox[0][(x >> 24) & 0xff];
        f = f.wrapping_add(self.sbox[1][(x >> 16) & 0xff]);
        f ^= self.sbox[2][(x >> 8) & 0xff];
        f = f.wrapping_add(self.sbox[3][x & 0xff]);
        f
    }

    fn encrypt_block(&self, left: &mut u32, right: &mut u32) {
        let mut x = *right;
        let mut y = *left;
        for i in 0..16 {
            let tmp = x ^ self.subkeys[i];
            x = y ^ self.f(tmp);
            y = tmp;
        }
        *left = x ^ self.subkeys[16];
        *right = y ^ self.subkeys[17];
    }

    pub fn encrypt(&self, data: &mut [u8]) -> Result<(), BlowfishError> {
        if data.len() % 8 != 0 {
            OddBlockCountSnafu {}.fail()?;
        }
        for chunk in data.chunks_exact_mut(8) {
            let mut left = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            let mut right = u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]);
            self.encrypt_block(&mut left, &mut right);
            chunk[0..4].copy_from_slice(&left.to_le_bytes());
            chunk[4..8].copy_from_slice(&right.to_le_bytes());
        }
        Ok(())
    }

    fn decrypt_block(&self, left: &mut u32, right: &mut u32) {
        let mut x = *right;
        let mut y = *left;
        for i in (2..18).rev() {
            let tmp = x ^ self.subkeys[i];
            x = self.f(tmp) ^ y;
            y = tmp;
        }
        *left = x ^ self.subkeys[1];
        *right = y ^ self.subkeys[0];
    }

    pub fn decrypt(&self, data: &mut [u8]) -> Result<(), BlowfishError> {
        if data.len() % 8 != 0 {
            OddBlockCountSnafu {}.fail()?;
        }
        for chunk in data.chunks_mut(8) {
            let mut left = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            let mut right = u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]);
            self.decrypt_block(&mut left, &mut right);
            chunk[0..4].copy_from_slice(&left.to_le_bytes());
            chunk[4..8].copy_from_slice(&right.to_le_bytes());
        }
        Ok(())
    }

    fn apply_code(&mut self, code0: &mut u32, code1: &mut u32, code2: &mut u32) {
        self.encrypt_block(code1, code2);
        self.encrypt_block(code0, code1);
        for i in 0..9 {
            self.subkeys[2 * i] ^= code0.swap_bytes();
            self.subkeys[2 * i + 1] ^= code1.swap_bytes();
        }

        let mut scratch0 = 0;
        let mut scratch1 = 0;
        for i in 0..9 {
            self.encrypt_block(&mut scratch0, &mut scratch1);
            self.subkeys[2 * i] = scratch1;
            self.subkeys[2 * i + 1] = scratch0;
        }
        for i in 0..4 {
            for j in 0..0x80 {
                self.encrypt_block(&mut scratch0, &mut scratch1);
                self.sbox[i][2 * j] = scratch1;
                self.sbox[i][2 * j + 1] = scratch0;
            }
        }
    }

    pub fn new(key: &[u8], seed: u32, level: BlowfishLevel) -> Result<Self, BlowfishError> {
        let mut blowfish = match bytemuck::try_from_bytes::<Blowfish>(key) {
            Ok(blowfish) => *blowfish,
            Err(PodCastError::TargetAlignmentGreaterAndInputNotAligned) => {
                let addr = key as *const [u8] as *const () as usize;
                return Err(MisalignedSnafu { expected: align_of::<Self>(), actual: 1usize << addr.leading_zeros() }.build());
            }
            Err(PodCastError::SizeMismatch) => {
                return Err(KeySizeSnafu { expected: size_of::<Self>(), actual: key.len() }.build())
            }
            Err(PodCastError::OutputSliceWouldHaveSlop) => panic!(),
            Err(PodCastError::AlignmentMismatch) => panic!(),
        };

        let mut code0 = seed;
        let mut code1 = seed >> 1;
        let mut code2 = seed << 1;
        blowfish.apply_code(&mut code0, &mut code1, &mut code2);

        if level >= BlowfishLevel::Level2 {
            blowfish.apply_code(&mut code0, &mut code1, &mut code2);
        }

        if level >= BlowfishLevel::Level3 {
            code1 <<= 1;
            code2 >>= 1;
            blowfish.apply_code(&mut code0, &mut code1, &mut code2);
        }

        Ok(blowfish)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BlowfishLevel {
    Level1,
    Level2,
    Level3,
}
