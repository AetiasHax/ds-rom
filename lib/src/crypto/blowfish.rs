use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom},
    mem::size_of,
    path::Path,
};

use bytemuck::{Pod, Zeroable};
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

    pub fn new(key: &BlowfishKey, seed: u32, level: BlowfishLevel) -> Result<Self, BlowfishError> {
        let mut blowfish = Self { subkeys: [0; 18], sbox: [[0; 0x100]; 4] };
        bytemuck::bytes_of_mut(&mut blowfish).copy_from_slice(&key.0);

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

pub struct BlowfishKey([u8; 0x1048]);

#[derive(Snafu, Debug)]
pub enum BlowfishKeyError {
    #[snafu(transparent)]
    Io { source: io::Error },
    #[snafu(display("expected ARM7 BIOS to be at least {expected} bytes long but got {actual} bytes:\n{backtrace}"))]
    TooSmall { expected: usize, actual: usize, backtrace: Backtrace },
}

impl BlowfishKey {
    pub fn from_arm7_bios<P: AsRef<Path>>(path: P) -> Result<Self, BlowfishKeyError> {
        let mut file = File::open(path)?;
        let size = file.metadata()?.len() as usize;
        if size < 0x30 + size_of::<Self>() {
            return TooSmallSnafu { expected: 0x30 + size_of::<Self>(), actual: size }.fail();
        }

        let mut key = [0; size_of::<Self>()];
        file.seek(SeekFrom::Start(0x30))?;
        file.read_exact(&mut key)?;

        Ok(Self(key))
    }
}
