use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use nds_io::rom::{raw, Rom};

#[derive(Debug, Args)]
pub struct Extract {
    /// Nintendo DS game ROM
    #[arg(short = 'r', long)]
    rom: PathBuf,
}

impl Extract {
    pub fn run(&self) -> Result<()> {
        let raw_rom = raw::Rom::from_file(&self.rom)?;
        let rom = Rom::extract(&raw_rom)?;
        Ok(())
    }
}
