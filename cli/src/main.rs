use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    mem::size_of,
    path::PathBuf,
};

use anyhow::{bail, Result};
use clap::Parser;
use nds_io::{
    crypto::blowfish::Blowfish,
    rom::{raw, Logo},
};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
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
}

fn main() -> Result<()> {
    let args = Args::parse();

    let key = if let Some(ref arm7_bios) = args.arm7_bios {
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

    let header_logo = if let Some(ref header_logo) = args.header_logo { Some(Logo::from_png(header_logo)?) } else { None };

    let rom = raw::Rom::from_file(args.rom.clone())?;
    let mut header = rom.header()?.clone();
    let arm9 = {
        let mut arm9 = rom.arm9()?;
        if arm9.is_encrypted() && key.is_some() {
            let Some(key) = key else { unreachable!() };
            let gamecode = u32::from_le_bytes(header.gamecode.0);
            arm9.decrypt(&key, gamecode)?;
        }
        if args.encrypt && !arm9.is_encrypted() && key.is_some() {
            let Some(key) = key else { unreachable!() };
            let gamecode = u32::from_le_bytes(header.gamecode.0);
            arm9.encrypt(&key, gamecode)?;
        }
        if args.decompress && arm9.build_info()?.is_compressed() {
            arm9.decompress()?;
        }
        if args.compress && !arm9.build_info()?.is_compressed() {
            arm9.compress()?;
        }
        arm9
    };

    if let Some(logo) = header_logo {
        header.logo.copy_from_slice(&logo.compress());
    }

    if args.show_header {
        println!("ROM header:\n{}", header.display(2));
    }

    if args.print_arm9 {
        print_hex(arm9.as_ref(), &args, arm9.base_address())?;
    }

    if args.print_autoload_info {
        let autoload_infos = arm9.autoload_infos()?;
        for autoload_info in autoload_infos {
            println!("Autoload info:\n{}", autoload_info.display(2));
        }
    }

    if let Some(index) = args.print_autoload {
        let autoloads = arm9.autoloads()?;
        if index >= autoloads.len() {
            bail!("Cannot print autoload at index {index}, max index is {}", autoloads.len() - 1);
        }
        let autoload = &autoloads[index];
        print_hex(autoload.full_data(), &args, autoload.base_address())?;
    }

    if args.print_arm9_ovt {
        let arm9_ovt = rom.arm9_overlay_table()?;
        if arm9_ovt.is_empty() {
            println!("The ROM has no ARM9 overlays");
        }
        for overlay in arm9_ovt {
            println!("ARM9 Overlay:\n{}", overlay.display(2));
        }
    }

    if args.print_arm7 {
        let arm7 = rom.arm7()?;
        print_hex(arm7.full_data(), &args, arm7.base_address())?;
    }

    if args.print_arm7_ovt {
        let arm7_ovt = rom.arm7_overlay_table()?;
        if arm7_ovt.is_empty() {
            println!("The ROM has no ARM7 overlays");
        }
        for overlay in arm7_ovt {
            println!("ARM7 Overlay:\n{}", overlay.display(2));
        }
    }

    Ok(())
}

fn print_hex(data: &[u8], args: &Args, base: u32) -> Result<()> {
    if args.raw {
        std::io::stdout().write(data)?;
    } else {
        for (offset, chunk) in data.chunks(16).enumerate() {
            print!("{:08x} ", base as usize + offset * 16);
            for byte in chunk {
                print!(" {byte:02x}");
            }
            println!();
        }
    }
    Ok(())
}
