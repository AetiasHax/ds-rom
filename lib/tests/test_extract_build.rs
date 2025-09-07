use std::{ffi::OsStr, fs};

use anyhow::Result;
use ds_rom::{
    crypto::blowfish::BlowfishKey,
    rom::{raw, Rom},
};
use log::LevelFilter;

#[test]
fn test_extract_build() -> Result<()> {
    env_logger::builder().filter_level(LevelFilter::Info).init();

    let cwd = std::env::current_dir()?;
    let roms_dir = cwd.join("tests/roms/");
    let arm7_bios = roms_dir.join("arm7_bios.bin");
    assert!(arm7_bios.exists());
    assert!(arm7_bios.is_file());

    let key = BlowfishKey::from_arm7_bios_path(arm7_bios)?;

    for entry in roms_dir.read_dir()? {
        let entry = entry?;
        let path = entry.path();
        if path.extension() != Some(OsStr::new("nds")) {
            continue;
        }
        let file_name = path.file_name().unwrap().to_string_lossy();
        if file_name.starts_with("build_") {
            continue;
        }

        // Extract
        let extension = path.extension().unwrap().to_string_lossy();
        let base_name = file_name.strip_suffix(extension.as_ref()).unwrap().strip_suffix(".").unwrap();
        let extract_path = roms_dir.join(base_name);

        let raw_rom = raw::Rom::from_file(&path)?;
        let rom = Rom::extract(&raw_rom)?;
        rom.save(&extract_path, Some(&key))?;

        // Build
        let build_path = path.with_file_name(format!("build_{file_name}"));
        let config_path = extract_path.join("config.yaml");

        let (rom, _paths) = Rom::load(&config_path, Default::default())?;
        let raw_rom = rom.build(Some(&key))?;
        raw_rom.save(&build_path)?;

        // Compare
        let target = fs::read(&path)?;
        let build = fs::read(&build_path)?;
        assert!(target == build, "{} did not match", file_name);

        // Delete
        fs::remove_file(&build_path)?;
        fs::remove_dir_all(&extract_path)?;
    }
    Ok(())
}
