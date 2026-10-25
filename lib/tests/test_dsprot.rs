use anyhow::Result;
use ds_rom::{
    crypto::dsprot::{DsProtDecryptOptions, DsProtEncryptOptions},
    rom::{Rom, raw},
};
use log::LevelFilter;

use crate::common::RomsTest;

mod common;

#[test]
fn test_dsprot_decrypt_encrypt() -> Result<()> {
    env_logger::builder().filter_level(LevelFilter::Info).init();

    let test = RomsTest::new()?;
    for path in test.roms()? {
        log::info!("Decrypting and re-encrypting {}", path.display());

        // Extract
        let raw_rom = raw::Rom::from_file(&path)?;
        let rom = Rom::extract(&raw_rom)?;

        let decrypt_options = DsProtDecryptOptions { decode_relocations: true };
        let encrypt_options = DsProtEncryptOptions { encode_relocations: true };

        // Decrypt and re-encrypt
        let arm9 = rom.arm9();
        if arm9.dsprot_state().is_encrypted() {
            let mut arm9_clone = arm9.clone();
            let compressed = arm9_clone.is_compressed()?;
            if compressed {
                arm9_clone.decompress()?;
            }
            arm9_clone.decrypt_dsprot(&decrypt_options)?;
            arm9_clone.encrypt_dsprot(&encrypt_options)?;
            if compressed {
                arm9_clone.compress()?;
            }
            assert!(arm9 == &arm9_clone, "DS Protect re-encryption failed in ARM9 program of {}", path.display());
            log::info!("DS Protect re-encrypted in ARM9 program");
        }
        for overlay in rom.arm9_overlays() {
            if overlay.dsprot_state().is_encrypted() {
                let mut overlay_clone = overlay.clone();
                let compressed = overlay.is_compressed();
                if compressed {
                    overlay_clone.decompress()?;
                }
                overlay_clone.decrypt_dsprot(&decrypt_options)?;
                overlay_clone.encrypt_dsprot(&encrypt_options)?;
                if compressed {
                    overlay_clone.compress()?;
                }
                assert!(
                    overlay == &overlay_clone,
                    "DS Protect re-encryption failed in ARM9 overlay {} of {}",
                    overlay.id(),
                    path.display(),
                );
                log::info!("DS Protect re-encrypted in ARM9 overlay {}", overlay.id());
            }
        }
    }
    Ok(())
}
