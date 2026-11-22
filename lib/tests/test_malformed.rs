#![allow(clippy::panic_in_result_fn, clippy::indexing_slicing, clippy::arithmetic_side_effects)]

//! Feeds malformed input to the functions used to check for and load a ROM. Errors are fine, panics are not.

use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Result, anyhow, bail};
use ds_rom::{
    crypto::dsprot::DsProtDecryptOptions,
    rom::{Rom, raw},
};

use crate::common::RomsTest;

mod common;

/// Extracts the ROM, then decompresses and decrypts every module and reads its contents.
fn load_all_modules(bytes: &[u8]) -> Result<()> {
    let raw_rom = raw::Rom::new(bytes);
    let mut rom = Rom::extract(&raw_rom)?;

    let decrypt_options = DsProtDecryptOptions { decode_relocations: false };
    for overlay in rom.arm9_overlays_mut() {
        overlay.decompress()?;
        overlay.decrypt_dsprot(&decrypt_options)?;
    }
    for overlay in rom.arm7_overlays_mut() {
        overlay.decompress()?;
    }

    let arm9 = rom.arm9_mut();
    arm9.decompress()?;
    arm9.decrypt_dsprot(&decrypt_options)?;

    let arm9 = rom.arm9();
    for autoload in arm9.autoloads()?.iter() {
        let _ = (autoload.code(), autoload.base_address(), autoload.bss_size(), autoload.kind());
    }
    let _ = (arm9.code()?, arm9.bss()?);
    for overlay in rom.arm9_overlays().iter().chain(rom.arm7_overlays()) {
        let _ = (overlay.code(), overlay.base_address(), overlay.bss_size());
    }
    Ok(())
}

/// Runs [`load_all_modules`] and fails if it panics.
fn load_without_panic(bytes: &[u8], what: &str) -> Result<Result<()>> {
    catch_unwind(AssertUnwindSafe(|| load_all_modules(bytes))).map_err(|_| anyhow!("panicked on {what}"))
}

/// Deterministic pseudo-random number generator (xorshift64).
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed | 1)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    /// Returns a number in `0..max`.
    fn below(&mut self, max: usize) -> usize {
        (self.next_u64() % max as u64) as usize
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next_u64() as u8).collect()
    }
}

/// Deterministic pseudo-random bytes.
fn random_bytes(len: usize, seed: u64) -> Vec<u8> {
    Rng::new(seed).bytes(len)
}

/// Returns `prefix` followed by pseudo-random bytes, `len` bytes in total.
fn with_prefix(prefix: &[u8], len: usize, seed: u64) -> Vec<u8> {
    let mut bytes = random_bytes(len, seed);
    bytes[..prefix.len()].copy_from_slice(prefix);
    bytes
}

#[test]
fn test_non_roms_are_errors() -> Result<()> {
    let text = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit.\n".repeat(0x1000);
    let inputs: Vec<(&str, Vec<u8>)> = vec![
        ("empty file", vec![]),
        ("one byte", vec![0]),
        ("text file", text),
        ("zeros (header size)", vec![0; 0x4000]),
        ("zeros (128 KiB)", vec![0; 0x20000]),
        ("0xff (1 MiB)", vec![0xff; 0x100000]),
        ("random (header size)", random_bytes(0x4000, 1)),
        ("random (1 MiB)", random_bytes(0x100000, 2)),
        ("PNG image", with_prefix(b"\x89PNG\r\n\x1a\n\0\0\0\x0dIHDR", 0x10000, 3)),
        ("ELF executable", with_prefix(b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0\x03\0\x3e\0", 0x10000, 4)),
        ("PE executable", with_prefix(b"MZ\x90\0\x03\0\0\0\x04\0\0\0\xff\xff\0\0", 0x10000, 5)),
        ("GBA ROM", with_prefix(&[0x2e, 0, 0, 0xea], 0x40000, 6)),
    ];
    for (what, bytes) in inputs {
        let result = load_without_panic(&bytes, what)?;
        assert!(result.is_err(), "{what} was loaded as a ROM");
    }
    Ok(())
}

/// Number of header words to replace in [`test_modified_rom_does_not_panic`]. Each one means loading the whole ROM, so
/// only a random sample is tested per run.
const HEADER_MUTATIONS: usize = 50;

/// Number of times each region is corrupted in [`test_modified_rom_does_not_panic`].
const REGION_CORRUPTIONS: usize = 10;

/// Modifies a ROM at random and checks that loading it never panics. The ROM and modifications are picked from a seed,
/// which is printed so that a failure can be reproduced by setting the `DS_ROM_TEST_SEED` environment variable.
#[test]
fn test_modified_rom_does_not_panic() -> Result<()> {
    let seed = match std::env::var("DS_ROM_TEST_SEED") {
        Ok(seed) => seed.parse()?,
        Err(_) => SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos() as u64,
    };
    let mut rng = Rng::new(seed);

    // Pick a ROM at random, since which ROMs are available differs between machines
    let test = RomsTest::new()?;
    let roms = test.roms()?;
    if roms.is_empty() {
        bail!("no ROMs found in {}", test.roms_dir.display());
    }
    let path = &roms[rng.below(roms.len())];
    let rom_name = path.display();
    println!("Modifying {rom_name} with DS_ROM_TEST_SEED={seed}");

    let mut bytes = std::fs::read(path)?;
    let length = bytes.len() as u32;

    load_without_panic(&bytes, &format!("unmodified {rom_name}"))??;

    // Replace words of the header with values that tend to break offsets and sizes
    for _ in 0..HEADER_MUTATIONS {
        let offset = rng.below(0x170 / 4) * 4;
        let original: [u8; 4] = bytes[offset..offset + 4].try_into()?;
        let original_value = u32::from_le_bytes(original);
        let values = [0, u32::MAX, original_value ^ 0x8000_0000, length, rng.next_u64() as u32];
        let value = values[rng.below(values.len())];
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        load_without_panic(&bytes, &format!("{rom_name} with header word {offset:#x} = {value:#x} (seed {seed})"))?.ok();
        bytes[offset..offset + 4].copy_from_slice(&original);
    }

    // Truncate the ROM at various points
    for truncated_length in [0x10, 0x15f, 0x160, 0x200, 0x1000, 0x4000, 0x4800, 0x8000, length / 2, length - 1] {
        let truncated = &bytes[..truncated_length as usize];
        load_without_panic(truncated, &format!("{rom_name} truncated to {truncated_length:#x} bytes"))?.ok();
    }

    // Corrupt the start of the ARM9 program and the ARM9 overlay table
    let (arm9_offset, ovt) = {
        let raw_rom = raw::Rom::new(bytes.as_slice());
        let header = raw_rom.header()?;
        (header.arm9.offset as usize, header.arm9_overlays)
    };
    let mut regions = vec![("ARM9 program", arm9_offset + 0x800)];
    if ovt.size > 0 {
        regions.push(("ARM9 overlay table", ovt.offset as usize));
    }
    for (region, start) in regions {
        let end = (start + 0x100).min(bytes.len());
        let Some(original) = bytes.get(start..end).map(<[u8]>::to_vec) else {
            continue;
        };
        for _ in 0..REGION_CORRUPTIONS {
            bytes[start..end].copy_from_slice(&rng.bytes(end - start));
            load_without_panic(&bytes, &format!("{rom_name} with corrupted {region} (seed {seed})"))?.ok();
        }
        bytes[start..end].copy_from_slice(&original);
    }

    Ok(())
}
