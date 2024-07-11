use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    mem::size_of,
    path::PathBuf,
};

use anyhow::{bail, Result};
use clap::Args;
use nds_io::{
    crypto::blowfish::Blowfish,
    rom::{self, raw, Logo, Overlay},
};

use crate::print_hex;

#[derive(Debug, Args)]
pub struct Dump {
    /// Nintendo DS game ROM
    #[arg(short = 'r', long)]
    rom: PathBuf,

    /// Shows the contents of the ROM header.
    #[arg(short = 'H', long)]
    show_header: bool,

    /// Nintendo DS ARM7 BIOS file
    #[arg(short = '7', long)]
    arm7_bios: Option<PathBuf>,

    /// Prints the contents of the ARM9 program. If an ARM7 BIOS is provided, the contents will be decrypted.
    #[arg(short = 'n', long)]
    print_arm9: bool,

    /// Prints the contents of the ARM7 program.
    #[arg(short = 's', long)]
    print_arm7: bool,

    /// Encrypts the secure area.
    #[arg(short = 'e', long)]
    encrypt: bool,

    /// Changes the header logo to this PNG.
    #[arg(short = 'l', long)]
    header_logo: Option<PathBuf>,

    /// Prints the contents of the ARM9 overlay table.
    #[arg(short = 'N', long)]
    print_arm9_ovt: bool,

    /// Prints the contents of the ARM7 overlay table.
    #[arg(short = 'S', long)]
    print_arm7_ovt: bool,

    /// Compresses code modules.
    #[arg(short = 'c', long)]
    compress: bool,

    /// Decompresses code modules.
    #[arg(short = 'd', long)]
    decompress: bool,

    /// Prints contents as raw bytes.
    #[arg(short = 'R', long)]
    raw: bool,

    /// Prints information about autoload blocks.
    #[arg(short = 'A', long)]
    print_autoload_info: bool,

    /// Prints the contents of an autoload block.
    #[arg(short = 'a', long, value_name = "INDEX")]
    print_autoload: Option<usize>,

    /// Shows the contents of the file name table.
    #[arg(short = 'f', long)]
    show_fnt: bool,

    /// Shows the contents of the banner.
    #[arg(short = 'b', long)]
    show_banner: bool,

    /// Prints the contents of an ARM9 overlay.
    #[arg(short = 'y', long, value_name = "INDEX")]
    print_arm9_overlay: Option<usize>,

    /// Prints the contents of an ARM7 overlay.
    #[arg(short = 'Y', long, value_name = "INDEX")]
    print_arm7_overlay: Option<usize>,
}

impl Dump {
    pub fn run(&self) -> Result<()> {
        let key = if let Some(ref arm7_bios) = self.arm7_bios {
            let mut file = File::open(arm7_bios)?;
            let size = file.metadata()?.len() as usize;
            if size < 0x30 + size_of::<Blowfish>() {
                bail!("No key found in ARM7 BIOS, file should be at least {} bytes long", size_of::<Blowfish>());
            }
            let mut key = [0u8; size_of::<Blowfish>()];
            file.seek(SeekFrom::Start(0x30))?;
            file.read_exact(&mut key)?;
            Some(key)
        } else {
            None
        };

        let header_logo = if let Some(ref header_logo) = self.header_logo { Some(Logo::from_png(header_logo)?) } else { None };

        let rom = raw::Rom::from_file(self.rom.clone())?;
        let mut header = rom.header()?.clone();
        let arm9 = {
            let mut arm9 = rom.arm9()?;
            if arm9.is_encrypted() && key.is_some() {
                let Some(key) = key else { unreachable!() };
                let gamecode = u32::from_le_bytes(header.gamecode.0);
                arm9.decrypt(&key, gamecode)?;
            }
            if self.encrypt && !arm9.is_encrypted() && key.is_some() {
                let Some(key) = key else { unreachable!() };
                let gamecode = u32::from_le_bytes(header.gamecode.0);
                arm9.encrypt(&key, gamecode)?;
            }
            if self.decompress && arm9.build_info()?.is_compressed() {
                arm9.decompress()?;
            }
            if self.compress && !arm9.build_info()?.is_compressed() {
                arm9.compress()?;
            }
            arm9
        };

        if let Some(logo) = header_logo {
            header.logo.copy_from_slice(&logo.compress());
        }

        if self.show_header {
            println!("ROM header:\n{}", header.display(2));
        }

        if self.show_banner {
            let banner = rom.banner()?;
            println!("ROM banner:\n{}", banner.display(2));
        }

        if self.print_arm9 {
            print_hex(arm9.as_ref(), self.raw, arm9.base_address())?;
        }

        if self.print_autoload_info {
            let autoload_infos = arm9.autoload_infos()?;
            for autoload_info in autoload_infos {
                println!("Autoload info:\n{}", autoload_info.display(2));
            }
        }

        if let Some(index) = self.print_autoload {
            let autoloads = arm9.autoloads()?;
            if index >= autoloads.len() {
                bail!("Cannot print autoload at index {index}, max index is {}", autoloads.len() - 1);
            }
            let autoload = &autoloads[index];
            print_hex(autoload.full_data(), self.raw, autoload.base_address())?;
        }

        if self.print_arm9_ovt {
            let arm9_ovt = rom.arm9_overlay_table()?;
            if arm9_ovt.is_empty() {
                println!("The ROM has no ARM9 overlays");
            }
            for overlay in arm9_ovt {
                println!("ARM9 Overlay:\n{}", overlay.display(2));
            }
        }

        if let Some(index) = self.print_arm9_overlay {
            let fat = rom.fat()?;
            let arm9_ovt = rom.arm9_overlay_table()?;
            let mut overlay = Overlay::parse(&arm9_ovt[index], &fat);

            if self.decompress && overlay.is_compressed() {
                overlay.decompress();
            }
            if self.compress && !overlay.is_compressed() {
                overlay.compress()?;
            }

            print_hex(overlay.full_data(), self.raw, overlay.base_address())?;
        }

        if self.print_arm7 {
            let arm7 = rom.arm7()?;
            print_hex(arm7.full_data(), self.raw, arm7.base_address())?;
        }

        if self.print_arm7_ovt {
            let arm7_ovt = rom.arm7_overlay_table()?;
            if arm7_ovt.is_empty() {
                println!("The ROM has no ARM7 overlays");
            }
            for overlay in arm7_ovt {
                println!("ARM7 Overlay:\n{}", overlay.display(2));
            }
        }

        if let Some(index) = self.print_arm7_overlay {
            let fat = rom.fat()?;
            let arm7_ovt = rom.arm7_overlay_table()?;
            let overlay = Overlay::parse(&arm7_ovt[index], &fat);
            print_hex(overlay.full_data(), self.raw, overlay.base_address())?;
        }

        if self.show_fnt {
            let fnt = rom.fnt()?;
            let fat = rom.fat()?;
            let root = rom::File::parse(&fnt, &fat);
            println!("Files:\n{}", root.display(2));
        }
        Ok(())
    }
}
