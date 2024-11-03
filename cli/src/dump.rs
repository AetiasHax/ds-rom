use std::path::PathBuf;

use anyhow::{bail, Result};
use argp::FromArgs;
use ds_rom::{
    compress::lz77::Lz77,
    crypto::blowfish::BlowfishKey,
    rom::{self, raw, Logo, Overlay},
};

use crate::print_hex;

/// Prints information about a ROM
#[derive(FromArgs)]
#[argp(subcommand, name = "dump")]
pub struct Dump {
    /// Nintendo DS game ROM
    #[argp(option, short = 'r')]
    rom: PathBuf,

    /// Shows the contents of the ROM header.
    #[argp(switch, short = 'H')]
    show_header: bool,

    /// Nintendo DS ARM7 BIOS file
    #[argp(option, short = '7')]
    arm7_bios: Option<PathBuf>,

    /// Prints the contents of the ARM9 program. If an ARM7 BIOS is provided, the contents will be decrypted.
    #[argp(switch, short = 'n')]
    print_arm9: bool,

    /// Shows the contents of the ARM9 build info.
    #[argp(switch, short = 'i')]
    show_build_info: bool,

    /// Prints the contents of the ARM7 program.
    #[argp(switch, short = 's')]
    print_arm7: bool,

    /// Encrypts the secure area.
    #[argp(switch, short = 'e')]
    encrypt: bool,

    /// Changes the header logo to this PNG.
    #[argp(option, short = 'l')]
    header_logo: Option<PathBuf>,

    /// Prints the contents of the ARM9 overlay table.
    #[argp(switch, short = 'N')]
    print_arm9_ovt: bool,

    /// Prints the contents of the ARM7 overlay table.
    #[argp(switch, short = 'S')]
    print_arm7_ovt: bool,

    /// Compresses code modules.
    #[argp(switch, short = 'c')]
    compress: bool,

    /// Decompresses code modules.
    #[argp(switch, short = 'd')]
    decompress: bool,

    /// Compare LZ77 compression algorithm output to the ROM. Use in combination with "print" switches.
    #[argp(switch, short = 'L')]
    compare_lz77: bool,

    /// Shows the LZ77 tokens of a compressed module. Use in combination with "print" switches.
    #[argp(switch, short = 'z')]
    show_lz77_tokens: bool,

    /// Prints contents as raw bytes.
    #[argp(switch, short = 'R')]
    raw: bool,

    /// Prints information about autoload blocks.
    #[argp(switch, short = 'A')]
    print_autoload_info: bool,

    /// Prints the contents of an autoload block.
    #[argp(option, short = 'a')]
    print_autoload: Option<usize>,

    /// Shows the contents of the file name table.
    #[argp(switch, short = 'f')]
    show_fnt: bool,

    /// Shows the contents of the banner.
    #[argp(switch, short = 'b')]
    show_banner: bool,

    /// Prints the contents of an ARM9 overlay.
    #[argp(option, short = 'y')]
    print_arm9_overlay: Option<usize>,

    /// Prints the contents of an ARM7 overlay.
    #[argp(option, short = 'Y')]
    print_arm7_overlay: Option<usize>,
}

impl Dump {
    pub fn run(&self) -> Result<()> {
        let key =
            if let Some(arm7_bios) = &self.arm7_bios { Some(BlowfishKey::from_arm7_bios_path(arm7_bios)?) } else { None };

        let header_logo = if let Some(header_logo) = &self.header_logo { Some(Logo::from_png(header_logo)?) } else { None };

        let rom = raw::Rom::from_file(self.rom.clone())?;
        let mut header = rom.header()?.clone();
        let arm9 = {
            let mut arm9 = rom.arm9()?;
            if arm9.is_encrypted() && key.is_some() {
                let Some(key) = &key else { unreachable!() };
                arm9.decrypt(&key, header.gamecode.to_le_u32())?;
            }
            if self.encrypt && !arm9.is_encrypted() && key.is_some() {
                let Some(key) = &key else { unreachable!() };
                arm9.encrypt(&key, header.gamecode.to_le_u32())?;
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
            if self.compare_lz77 {
                let mut recompressed = arm9.clone();
                recompressed.decompress()?;
                recompressed.compress()?;

                Self::compare_lz77(arm9.full_data(), recompressed.full_data(), 0x4000, arm9.base_address() as usize);
            }

            if self.show_lz77_tokens {
                let tokens = Lz77 {}.parse_tokens(arm9.full_data())?;
                println!("{tokens}");
            }

            if !self.compare_lz77 && !self.show_lz77_tokens {
                print_hex(arm9.as_ref(), self.raw, arm9.base_address())?;
            }
        }

        if self.show_build_info {
            let build_info = arm9.build_info()?;
            println!("ARM9 build info:\n{}", build_info.display(2));
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
            let mut overlay = Overlay::parse(&arm9_ovt[index], fat, &rom)?;

            if self.decompress && overlay.is_compressed() {
                overlay.decompress()?;
            }
            if self.compress && !overlay.is_compressed() {
                overlay.compress()?;
            }

            if self.compare_lz77 {
                let mut recompressed = overlay.clone();
                recompressed.decompress()?;
                recompressed.compress()?;

                Self::compare_lz77(overlay.full_data(), recompressed.full_data(), 0, overlay.base_address() as usize);
            }

            if self.show_lz77_tokens {
                let tokens = Lz77 {}.parse_tokens(overlay.full_data())?;
                println!("{tokens}");
            }

            if !self.compare_lz77 && !self.show_lz77_tokens {
                print_hex(overlay.full_data(), self.raw, overlay.base_address())?;
            }
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
            let overlay = Overlay::parse(&arm7_ovt[index], fat, &rom)?;
            print_hex(overlay.full_data(), self.raw, overlay.base_address())?;
        }

        if self.show_fnt {
            let fnt = rom.fnt()?;
            let fat = rom.fat()?;
            let root = rom::FileSystem::parse(&fnt, fat, &rom)?;
            println!("Files:\n{}", root.display(2));
        }
        Ok(())
    }

    fn compare_lz77(data_before: &[u8], data_after: &[u8], start: usize, base_address: usize) {
        let before = data_before.len();
        let after = data_after.len();

        let mut equal = true;
        if before != after {
            println!("Wrong size: before = {before:#x}, after = {after:#x}");
            equal = false;
        }

        let before = data_before.iter().enumerate().skip(start).rev();
        let after = data_after.iter().enumerate().skip(start).rev();

        for ((addr_before, value_before), (addr_after, value_after)) in before.zip(after) {
            let addr_before = addr_before + base_address;
            let addr_after = addr_after + base_address;
            if value_before != value_after {
                println!("{addr_before:08x}: {value_before:02x}  =>  {addr_after:08x}: {value_after:02x}");
                equal = false;
            }
        }

        if equal {
            println!("Compression matched");
        }
    }
}
