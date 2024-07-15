use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::Args;
use nds_io::{
    crypto::blowfish::BlowfishKey,
    rom::{raw, Rom, RomSaveError},
};

#[derive(Debug, Args)]
pub struct Extract {
    /// Nintendo DS game ROM
    #[arg(short = 'r', long)]
    rom: PathBuf,

    /// Nintendo DS ARM7 BIOS file
    #[arg(short = '7', long)]
    arm7_bios: Option<PathBuf>,

    /// Output path
    #[arg(short = 'o', long)]
    path: PathBuf,
}

impl Extract {
    pub fn run(&self) -> Result<()> {
        let raw_rom = raw::Rom::from_file(&self.rom)?;
        let key = if let Some(arm7_bios) = &self.arm7_bios { Some(BlowfishKey::from_arm7_bios(arm7_bios)?) } else { None };
        let rom = Rom::extract(&raw_rom)?;

        match rom.save(&self.path, key.as_ref()) {
            Err(RomSaveError::BlowfishKeyNeeded) => {
                bail!("The ROM is encrypted, please provide ARM7 BIOS");
            }
            result => Ok(result?),
        }
    }
}
