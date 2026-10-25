use std::fs;

use anyhow::Result;
use ds_rom::rom::{Rom, RomLoadOptions, raw};
use log::LevelFilter;

use crate::common::RomsTest;
mod common;

#[test]
fn test_extract_build() -> Result<()> {
    env_logger::builder().filter_level(LevelFilter::Info).init();

    let test = RomsTest::new()?;
    for path in test.roms()? {
        let file_name = path.file_name().unwrap().to_string_lossy();
        if file_name.starts_with("build_") {
            continue;
        }

        // Extract
        let extension = path.extension().unwrap().to_string_lossy();
        let base_name = file_name.strip_suffix(extension.as_ref()).unwrap().strip_suffix(".").unwrap();
        let extract_path = test.roms_dir.join(base_name);

        let raw_rom = raw::Rom::from_file(&path)?;
        let rom = Rom::extract(&raw_rom)?;
        rom.save(&extract_path, Some(&test.key))?;

        // Build
        let build_path = path.with_file_name(format!("build_{file_name}"));
        let config_path = extract_path.join("config.yaml");

        let rom = Rom::load(&config_path, RomLoadOptions { key: Some(&test.key), ..Default::default() })?;
        let raw_rom = rom.build(Some(&test.key))?;
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
