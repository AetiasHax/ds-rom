use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::Args;
use nds_io::{
    crypto::blowfish::BlowfishKey,
    rom::{raw, Rom, RomSaveError},
};

#[derive(Debug, Args)]
pub struct Build {
    /// Input path
    #[arg(short = 'r', long)]
    path: PathBuf,

    /// Nintendo DS ARM7 BIOS file
    #[arg(short = '7', long)]
    arm7_bios: Option<PathBuf>,

    /// Output ROM
    #[arg(short = 'o', long)]
    rom: PathBuf,
}

impl Build {
    pub fn run(&self) -> Result<()> {
        let key = if let Some(arm7_bios) = &self.arm7_bios { Some(BlowfishKey::from_arm7_bios(arm7_bios)?) } else { None };
        let rom = match Rom::load(&self.path, key.as_ref()) {
            Err(RomSaveError::BlowfishKeyNeeded) => {
                bail!("The ROM is encrypted, please provide ARM7 BIOS");
            }
            result => result?,
        };
        let raw_rom = rom.build(key.as_ref())?;
        raw_rom.save(&self.rom)?;
        Ok(())
    }
}
