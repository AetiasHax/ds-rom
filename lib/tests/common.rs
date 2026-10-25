use std::{ffi::OsStr, path::PathBuf};

use anyhow::{Result, anyhow};
use ds_rom::crypto::blowfish::BlowfishKey;

#[allow(unused)]
pub struct RomsTest {
    pub roms_dir: PathBuf,
    pub key: BlowfishKey,
}

impl RomsTest {
    pub fn new() -> Result<Self> {
        let cwd = std::env::current_dir()?;
        let roms_dir = cwd.join("tests/roms/");
        let arm7_bios = roms_dir.join("arm7_bios.bin");
        assert!(arm7_bios.exists());
        assert!(arm7_bios.is_file());

        let key = BlowfishKey::from_arm7_bios_path(arm7_bios)?;

        Ok(Self { roms_dir, key })
    }

    pub fn roms(&self) -> Result<Vec<PathBuf>> {
        let mut iter = self
            .roms_dir
            .read_dir()?
            .filter_map(|entry| {
                let entry = match entry {
                    Ok(entry) => entry,
                    Err(e) => return Some(Err(anyhow!(e))),
                };
                let path = entry.path();
                if path.extension() != Some(OsStr::new("nds")) {
                    None
                } else {
                    Some(Ok(path))
                }
            })
            .collect::<Result<Vec<_>>>()?;
        iter.sort_unstable();
        Ok(iter)
    }
}
