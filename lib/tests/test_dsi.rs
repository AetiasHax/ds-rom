use std::{fs, path::Path};

use anyhow::{Result, anyhow};
use ds_rom::{
    crypto::{blowfish::BlowfishKey, hmac_sha1::HmacSha1, modcrypt::Modcrypt},
    rom::{Rom, RomLoadOptions, raw},
};

use crate::common::RomsTest;
mod common;

/// Everything the digest tables and content SHA1-HMACs of a DSi ROM should hash, recomputed here from the ROM itself so that
/// a build cannot pass by copying stale values out of the ROM it was extracted from.
struct DsiHashes {
    sector_hashtable: Vec<u8>,
    block_hashtable: Vec<u8>,
    digest_master: [u8; 20],
    arm9_with_secure_area: [u8; 20],
    arm9: [u8; 20],
    arm7: [u8; 20],
    banner: [u8; 20],
    arm9i: [u8; 20],
    arm7i: [u8; 20],
}

/// Rebuilds the digest form of `rom`: the ARM9 secure area encrypted and the Modcrypt areas decrypted, which is what the DSi
/// hashes rather than what the ROM stores.
fn digest_form(rom: &[u8], key: &BlowfishKey) -> Result<Vec<u8>> {
    let raw_rom = raw::Rom::new(rom.to_vec());
    let header = raw_rom.header()?;
    let mut form = rom.to_vec();

    let arm9 = raw_rom.arm9()?;
    let encrypted = arm9.encrypted_secure_area(key, header.gamecode.to_le_u32());
    let start = header.arm9.offset as usize;
    form[start..start + encrypted.len()].copy_from_slice(&encrypted);

    if header.dsi_flags.modcrypted() {
        let modcrypt = Modcrypt::retail(header.gamecode.0, &header.sha1_hmac_arm9i);
        for (area, counter) in
            [(header.modcrypt_area_1, header.sha1_hmac_arm9_with_secure_area), (header.modcrypt_area_2, header.sha1_hmac_arm7)]
        {
            if area.size == 0 {
                continue;
            }
            let start = area.offset as usize;
            modcrypt.apply(Modcrypt::counter(&counter), &mut form[start..start + area.size as usize]);
        }
    }
    Ok(form)
}

fn compute_hashes(rom: &[u8], key: &BlowfishKey) -> Result<DsiHashes> {
    let raw_rom = raw::Rom::new(rom.to_vec());
    let header = raw_rom.header()?;
    let mut plain_arm9 = raw_rom.arm9()?;
    plain_arm9.decompress()?;
    let hmac = HmacSha1::new(plain_arm9.hmac_sha1_key()?.ok_or_else(|| anyhow!("no HMAC-SHA1 key"))?);

    let form = digest_form(rom, key)?;
    let sector_size = header.digest_sector_size as usize;
    let per_block = header.digest_sector_count as usize;

    // Sector hashes over the NTR region followed by the TWL region, padded with zeroed entries up to a whole block.
    let mut sector_hashtable = Vec::new();
    for region in [header.digest_ds_area, header.digest_dsi_area] {
        let start = region.offset as usize;
        for sector in form[start..start + region.size as usize].chunks(sector_size) {
            sector_hashtable.extend_from_slice(&hmac.compute(sector));
        }
    }
    let num_blocks = (sector_hashtable.len() / 20).div_ceil(per_block);
    sector_hashtable.resize(num_blocks * per_block * 20, 0);

    let mut block_hashtable = Vec::new();
    for block in sector_hashtable.chunks(per_block * 20) {
        block_hashtable.extend_from_slice(&hmac.compute(block));
    }

    let arm9_start = header.arm9.offset as usize;
    let arm9_full = &form[arm9_start..arm9_start + header.arm9.size as usize];
    let arm7_start = header.arm7.offset as usize;
    let arm9i_start = header.arm9i.offset as usize;
    let arm7i_start = header.arm7i.offset as usize;

    Ok(DsiHashes {
        digest_master: hmac.compute(&block_hashtable),
        sector_hashtable,
        block_hashtable,
        arm9_with_secure_area: hmac.compute(arm9_full),
        arm9: hmac.compute(&arm9_full[0x4000..]),
        arm7: hmac.compute(&form[arm7_start..arm7_start + header.arm7.size as usize]),
        banner: hmac.compute(&form[header.banner_offset as usize..][..header.banner_size as usize]),
        arm9i: hmac.compute(&form[arm9i_start..arm9i_start + header.arm9i.size as usize]),
        arm7i: hmac.compute(&form[arm7i_start..arm7i_start + header.arm7i.size as usize]),
    })
}

/// Checks that every hash a DSi ROM stores actually describes its own contents.
fn assert_self_consistent(rom: &[u8], key: &BlowfishKey, label: &str) -> Result<DsiHashes> {
    let hashes = compute_hashes(rom, key)?;
    let raw_rom = raw::Rom::new(rom.to_vec());
    let header = raw_rom.header()?;

    let stored = |offset: u32, size: u32| &rom[offset as usize..(offset + size) as usize];
    assert_eq!(
        stored(header.digest_sector_hashtable.offset, header.digest_sector_hashtable.size),
        hashes.sector_hashtable.as_slice(),
        "{label}: digest sector hashtable"
    );
    assert_eq!(
        stored(header.digest_block_hashtable.offset, header.digest_block_hashtable.size),
        hashes.block_hashtable.as_slice(),
        "{label}: digest block hashtable"
    );
    assert_eq!(header.sha1_hmac_digest, hashes.digest_master, "{label}: digest master hash");
    assert_eq!(header.sha1_hmac_arm9_with_secure_area, hashes.arm9_with_secure_area, "{label}: ARM9 hash with secure area");
    assert_eq!(header.sha1_hmac_arm9, hashes.arm9, "{label}: ARM9 hash");
    assert_eq!(header.sha1_hmac_arm7, hashes.arm7, "{label}: ARM7 hash");
    assert_eq!(header.sha1_hmac_banner, hashes.banner, "{label}: banner hash");
    assert_eq!(header.sha1_hmac_arm9i, hashes.arm9i, "{label}: ARM9i hash");
    assert_eq!(header.sha1_hmac_arm7i, hashes.arm7i, "{label}: ARM7i hash");
    Ok(hashes)
}

fn build(extract_path: &Path, key: &BlowfishKey) -> Result<Vec<u8>> {
    let rom = Rom::load(extract_path.join("config.yaml"), RomLoadOptions { key: Some(key), ..Default::default() })?;
    Ok(rom.build(Some(key))?.data().to_vec())
}

/// Flips a bit in the middle of a file, leaving its size alone so the ROM layout does not move.
fn flip_a_bit(path: &Path) -> Result<()> {
    let mut data = fs::read(path)?;
    assert!(!data.is_empty(), "{} is empty", path.display());
    let middle = data.len() / 2;
    data[middle] ^= 0xff;
    fs::write(path, data)?;
    Ok(())
}

#[test]
fn test_dsi_hashes_are_regenerated() -> Result<()> {
    let test = RomsTest::new()?;
    for path in test.roms()? {
        let path = path?;
        let file_name = path.file_name().unwrap().to_string_lossy().to_string();
        if file_name.starts_with("build_") {
            continue;
        }

        let original = fs::read(&path)?;
        let raw_rom = raw::Rom::from_file(&path)?;
        if !raw_rom.header()?.has_dsi_area() {
            println!("skipping {file_name}, not a DSi ROM");
            continue;
        }

        // The extract directory must not end in `.nds`, or the ROM iterator would pick it up as a ROM on the next run.
        let base_name = path.file_stem().unwrap().to_string_lossy();
        let extract_path = test.roms_dir.join(format!("dsi_test_{base_name}"));
        if extract_path.exists() {
            fs::remove_dir_all(&extract_path)?;
        }
        Rom::extract(&raw_rom)?.save(&extract_path, Some(&test.key))?;

        // The ROM we extracted from is Nintendo's own output, so an unmodified rebuild that matches it byte for byte proves
        // the recomputed tables and hashes are right, not merely self-consistent.
        let rebuilt = build(&extract_path, &test.key)?;
        assert!(rebuilt == original, "{file_name}: unmodified rebuild did not match");
        let before = assert_self_consistent(&rebuilt, &test.key, "unmodified")?;

        // Now change the DS area, the banner and the ARM9i, and check the hashes follow the new contents. Touching the ARM9i
        // also moves the Modcrypt key, since Key_Y is the ARM9i hash.
        flip_a_bit(&extract_path.join("dsi/arm9i.bin"))?;

        let banner_config = extract_path.join("banner/banner.yaml");
        let banner_yaml = fs::read_to_string(&banner_config)?;
        assert!(banner_yaml.contains("Nintendo"), "banner title not found");
        fs::write(&banner_config, banner_yaml.replacen("Nintendo", "Nintendk", 1))?;
        let asset = fs::read_dir(extract_path.join("files"))?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .find(|p| p.is_file() && fs::metadata(p).map(|m| m.len() > 16).unwrap_or(false))
            .ok_or_else(|| anyhow!("no asset file to modify"))?;
        println!("modifying {}", asset.display());
        flip_a_bit(&asset)?;

        let modified = build(&extract_path, &test.key)?;
        assert_eq!(modified.len(), original.len(), "{file_name}: modified ROM changed size");
        assert!(modified != original, "{file_name}: modified ROM is identical to the original");
        let after = assert_self_consistent(&modified, &test.key, "modified")?;

        // Every hash that covers changed data must actually have changed. If any of these were copied out of the original
        // header instead of recomputed, the rebuilt ROM would be silently corrupt.
        assert_ne!(before.digest_master, after.digest_master, "digest master did not change");
        assert_ne!(before.sector_hashtable, after.sector_hashtable, "sector hashtable did not change");
        assert_ne!(before.block_hashtable, after.block_hashtable, "block hashtable did not change");
        assert_ne!(before.arm9i, after.arm9i, "ARM9i hash did not change");
        assert_ne!(before.banner, after.banner, "banner hash did not change");

        // The ARM9 and ARM7 were untouched, so their hashes must not move.
        assert_eq!(before.arm9_with_secure_area, after.arm9_with_secure_area, "ARM9 hash changed unexpectedly");
        assert_eq!(before.arm7, after.arm7, "ARM7 hash changed unexpectedly");

        // A new Modcrypt key means the stored ARM9i ciphertext must differ beyond the one flipped bit.
        let raw_modified = raw::Rom::new(modified.clone());
        let header = raw_modified.header()?;
        let area = header.modcrypt_area_1;
        let differing = original[area.offset as usize..(area.offset + area.size) as usize]
            .iter()
            .zip(&modified[area.offset as usize..(area.offset + area.size) as usize])
            .filter(|(a, b)| a != b)
            .count();
        println!("{differing:#x} of {:#x} Modcrypt bytes changed", area.size);
        assert!(differing > area.size as usize / 4, "Modcrypt area barely changed, key was probably not re-derived");

        fs::remove_dir_all(&extract_path)?;
    }
    Ok(())
}
