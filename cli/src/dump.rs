use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand};
use ds_rom::{
    compress::lz77::Lz77,
    crypto::{blowfish::BlowfishKey, hmac_sha1::HmacSha1},
    rom::{self, raw, Arm9, Logo, Overlay, Rom},
};

use crate::print_hex;

/// Prints information about a ROM
#[derive(Args)]
pub struct Dump {
    /// Nintendo DS game ROM
    #[arg(long, short = 'r')]
    rom: PathBuf,

    /// Nintendo DS ARM7 BIOS file
    #[arg(long, short = '7')]
    arm7_bios: Option<PathBuf>,

    /// Encrypts the secure area.
    #[arg(long, short = 'e')]
    encrypt: bool,

    /// Compresses code modules.
    #[arg(long, short = 'c')]
    compress: bool,

    /// Decompresses code modules.
    #[arg(long, short = 'd')]
    decompress: bool,

    #[command(subcommand)]
    command: DumpCommand,
}

impl Dump {
    pub fn run(&self) -> Result<()> {
        let key =
            if let Some(arm7_bios) = &self.arm7_bios { Some(BlowfishKey::from_arm7_bios_path(arm7_bios)?) } else { None };

        let rom = raw::Rom::from_file(self.rom.clone())?;
        let header = rom.header()?;
        let mut arm9 = rom.arm9()?;
        if arm9.is_encrypted() && key.is_some() {
            let Some(key) = &key else { unreachable!() };
            arm9.decrypt(key, header.gamecode.to_le_u32())?;
        }
        if self.encrypt && !arm9.is_encrypted() && key.is_some() {
            let Some(key) = &key else { unreachable!() };
            arm9.encrypt(key, header.gamecode.to_le_u32())?;
        }
        if self.decompress && arm9.build_info()?.is_compressed() {
            arm9.decompress()?;
        }
        if self.compress && !arm9.build_info()?.is_compressed() {
            arm9.compress()?;
        }

        match &self.command {
            DumpCommand::Header(dump_header) => dump_header.run(&rom),
            DumpCommand::Arm9(dump_arm9) => dump_arm9.run(&arm9),
            DumpCommand::BuildInfo(dump_build_info) => dump_build_info.run(&arm9),
            DumpCommand::Arm7(dump_arm7) => dump_arm7.run(&rom),
            DumpCommand::Arm9OverlayTable(dump_arm9_overlay_table) => dump_arm9_overlay_table.run(&rom),
            DumpCommand::Arm7OverlayTable(dump_arm7_overlay_table) => dump_arm7_overlay_table.run(&rom),
            DumpCommand::AutoloadInfo(dump_autoload_info) => dump_autoload_info.run(&mut arm9),
            DumpCommand::Autoload(dump_autoload) => dump_autoload.run(&mut arm9),
            DumpCommand::Fnt(dump_fnt) => dump_fnt.run(&rom),
            DumpCommand::Banner(dump_banner) => dump_banner.run(&rom),
            DumpCommand::Arm9Overlay(dump_arm9_overlay) => dump_arm9_overlay.run(&rom, self.decompress, self.compress),
            DumpCommand::Arm7Overlay(dump_arm7_overlay) => dump_arm7_overlay.run(&rom),
            DumpCommand::Arm9Footer(dump_arm9_footer) => dump_arm9_footer.run(&rom),
            DumpCommand::Arm9OverlaySignatures(dump_arm9_overlay_signatures) => dump_arm9_overlay_signatures.run(&rom),
        }
    }
}

#[derive(Subcommand)]
enum DumpCommand {
    Header(DumpHeader),
    Arm9(DumpArm9),
    #[command(name = "build-info")]
    BuildInfo(DumpBuildInfo),
    Arm7(DumpArm7),
    #[command(name = "arm9-ovt")]
    Arm9OverlayTable(DumpArm9OverlayTable),
    #[command(name = "arm7-ovt")]
    Arm7OverlayTable(DumpArm7OverlayTable),
    #[command(name = "autoload-info")]
    AutoloadInfo(DumpAutoloadInfo),
    Autoload(DumpAutoload),
    Fnt(DumpFnt),
    Banner(DumpBanner),
    #[command(name = "arm9-ov")]
    Arm9Overlay(DumpArm9Overlay),
    #[command(name = "arm7-ov")]
    Arm7Overlay(DumpArm7Overlay),
    #[command(name = "arm9-footer")]
    Arm9Footer(DumpArm9Footer),
    #[command(name = "arm9-ov-sigs")]
    Arm9OverlaySignatures(DumpArm9OverlaySignatures),
}

/// Shows the contents of the ROM header.
#[derive(Args)]
struct DumpHeader {
    /// Changes the header logo to this PNG.
    #[arg(long, short = 'l')]
    header_logo: Option<PathBuf>,
}

impl DumpHeader {
    pub fn run(&self, rom: &raw::Rom) -> Result<()> {
        let mut header = *rom.header()?;

        if let Some(header_logo) = &self.header_logo {
            let logo = Logo::from_png(header_logo)?;
            header.logo.copy_from_slice(&logo.compress());
        }

        println!("ROM header:\n{}", header.display(2));

        Ok(())
    }
}

/// Prints the contents of the ARM9 program.
#[derive(Args)]
struct DumpArm9 {
    /// Compare LZ77 compression algorithm output to the ROM.
    #[arg(long, short = 'L')]
    compare_lz77: bool,

    /// Shows the LZ77 tokens of a compressed module.
    #[arg(long, short = 'z')]
    show_lz77_tokens: bool,

    /// Prints contents as raw bytes.
    #[arg(long, short = 'R')]
    raw: bool,
}

impl DumpArm9 {
    pub fn run(&self, arm9: &Arm9) -> Result<()> {
        if self.compare_lz77 {
            let mut recompressed = arm9.clone();
            recompressed.decompress()?;
            recompressed.compress()?;

            compare_lz77(arm9.full_data(), recompressed.full_data(), 0x4000, arm9.base_address() as usize);
        }

        if self.show_lz77_tokens {
            let tokens = Lz77 {}.parse_tokens(arm9.full_data())?;
            println!("{tokens}");
        }

        if !self.compare_lz77 && !self.show_lz77_tokens {
            print_hex(arm9.as_ref(), self.raw, arm9.base_address())?;
        }

        Ok(())
    }
}

/// Shows the contents of the ARM9 build info.
#[derive(Args)]
struct DumpBuildInfo {}

impl DumpBuildInfo {
    pub fn run(&self, arm9: &Arm9) -> Result<()> {
        let build_info = arm9.build_info()?;
        println!("ARM9 build info:\n{}", build_info.display(2));

        Ok(())
    }
}

/// Prints the contents of the ARM7 program.
#[derive(Args)]
struct DumpArm7 {
    /// Prints contents as raw bytes.
    #[arg(long, short = 'R')]
    raw: bool,
}

impl DumpArm7 {
    pub fn run(&self, rom: &raw::Rom) -> Result<()> {
        let arm7 = rom.arm7()?;
        print_hex(arm7.full_data(), self.raw, arm7.base_address())?;

        Ok(())
    }
}

/// Prints the contents of the ARM9 overlay table.
#[derive(Args)]
struct DumpArm9OverlayTable {}

impl DumpArm9OverlayTable {
    pub fn run(&self, rom: &raw::Rom) -> Result<()> {
        let arm9_ovt = rom.arm9_overlay_table()?;
        if arm9_ovt.is_empty() {
            println!("The ROM has no ARM9 overlays");
        }
        for overlay in arm9_ovt {
            println!("ARM9 Overlay:\n{}", overlay.display(2));
        }

        Ok(())
    }
}

/// Prints the contents of the ARM7 overlay table.
#[derive(Args)]
struct DumpArm7OverlayTable {}

impl DumpArm7OverlayTable {
    pub fn run(&self, rom: &raw::Rom) -> Result<()> {
        let arm7_ovt = rom.arm7_overlay_table()?;
        if arm7_ovt.is_empty() {
            println!("The ROM has no ARM7 overlays");
        }
        for overlay in arm7_ovt {
            println!("ARM7 Overlay:\n{}", overlay.display(2));
        }

        Ok(())
    }
}

/// Prints information about autoload blocks.
#[derive(Args)]
struct DumpAutoloadInfo {}

impl DumpAutoloadInfo {
    pub fn run(&self, arm9: &mut Arm9) -> Result<()> {
        arm9.decompress()?;
        let autoload_infos = arm9.autoload_infos()?;
        for autoload_info in autoload_infos {
            println!("Autoload info:\n{}", autoload_info.display(2));
        }

        Ok(())
    }
}

/// Prints the contents of an autoload block.
#[derive(Args)]
struct DumpAutoload {
    /// The autoload block's index.
    index: usize,

    /// Prints contents as raw bytes.
    #[arg(long, short = 'R')]
    raw: bool,
}

impl DumpAutoload {
    pub fn run(&self, arm9: &mut Arm9) -> Result<()> {
        arm9.decompress()?;
        let autoloads = arm9.autoloads()?;
        if self.index >= autoloads.len() {
            bail!("Cannot print autoload at index {}, max index is {}", self.index, autoloads.len() - 1);
        }
        let autoload = &autoloads[self.index];
        print_hex(autoload.full_data(), self.raw, autoload.base_address())?;

        Ok(())
    }
}

/// Shows the contents of the file name table.
#[derive(Args)]
struct DumpFnt {}

impl DumpFnt {
    pub fn run(&self, rom: &raw::Rom) -> Result<()> {
        let fnt = rom.fnt()?;
        let fat = rom.fat()?;
        let root = rom::FileSystem::parse(&fnt, fat, rom)?;
        println!("Files:\n{}", root.display(2));

        Ok(())
    }
}

/// Shows the contents of the banner.
#[derive(Args)]
struct DumpBanner {}

impl DumpBanner {
    pub fn run(&self, rom: &raw::Rom) -> Result<()> {
        let banner = rom.banner()?;
        println!("ROM banner:\n{}", banner.display(2));

        Ok(())
    }
}

/// Prints the contents of an ARM9 overlay.
#[derive(Args)]
struct DumpArm9Overlay {
    /// The overlay index.
    index: usize,

    /// Compare LZ77 compression algorithm output to the ROM.
    #[arg(long, short = 'L')]
    compare_lz77: bool,

    /// Shows the LZ77 tokens of a compressed module.
    #[arg(long, short = 'z')]
    show_lz77_tokens: bool,

    /// Prints contents as raw bytes.
    #[arg(long, short = 'R')]
    raw: bool,
}

impl DumpArm9Overlay {
    pub fn run(&self, rom: &raw::Rom, decompress: bool, compress: bool) -> Result<()> {
        let arm9_ovt = rom.arm9_overlay_table()?;
        let mut arm9 = rom.arm9()?;
        arm9.decompress()?;
        let mut overlay = Overlay::parse_arm9(&arm9_ovt[self.index], rom, &arm9)?;

        if decompress && overlay.is_compressed() {
            overlay.decompress()?;
        }
        if compress && !overlay.is_compressed() {
            overlay.compress()?;
        }

        if self.compare_lz77 {
            let mut recompressed = overlay.clone();
            recompressed.decompress()?;
            recompressed.compress()?;

            compare_lz77(overlay.full_data(), recompressed.full_data(), 0, overlay.base_address() as usize);
        }

        if self.show_lz77_tokens {
            let tokens = Lz77 {}.parse_tokens(overlay.full_data())?;
            println!("{tokens}");
        }

        if !self.compare_lz77 && !self.show_lz77_tokens {
            print_hex(overlay.full_data(), self.raw, overlay.base_address())?;
        }

        Ok(())
    }
}

/// Prints the contents of an ARM7 overlay.
#[derive(Args)]
struct DumpArm7Overlay {
    /// The overlay index.
    index: usize,

    /// Prints contents as raw bytes.
    #[arg(long, short = 'R')]
    raw: bool,
}

impl DumpArm7Overlay {
    pub fn run(&self, rom: &raw::Rom) -> Result<()> {
        let arm7_ovt = rom.arm7_overlay_table()?;
        let overlay = Overlay::parse_arm7(&arm7_ovt[self.index], rom)?;
        print_hex(overlay.full_data(), self.raw, overlay.base_address())?;

        Ok(())
    }
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

/// Prints the contents of the ARM9 footer.
#[derive(Args)]
struct DumpArm9Footer {}

impl DumpArm9Footer {
    pub fn run(&self, rom: &raw::Rom) -> Result<()> {
        let arm9_footer = rom.arm9_footer()?;
        println!("ARM9 footer:\n{}", arm9_footer.display(2));

        Ok(())
    }
}

/// Prints the ARM9 overlay signatures.
#[derive(Args)]
struct DumpArm9OverlaySignatures {
    #[arg(long, short = 'c')]
    compute: bool,
    #[arg(long, short = 'v')]
    verify: bool,
}

impl DumpArm9OverlaySignatures {
    pub fn run(&self, raw_rom: &raw::Rom) -> Result<()> {
        let rom = Rom::extract(raw_rom)?;

        if self.verify {
            let mut arm9 = rom.arm9().clone();
            arm9.decompress()?;
            let hmac_sha1_key = arm9.hmac_sha1_key()?.context("Failed to get HMAC-SHA1 key")?;
            let hmac_sha1 = HmacSha1::new(hmac_sha1_key);
            for overlay in rom.arm9_overlays() {
                if overlay.is_signed() {
                    if overlay.verify_signature(&hmac_sha1)? {
                        println!("ARM9 overlay {} signature is valid", overlay.id());
                    } else {
                        println!("ARM9 overlay {} signature is invalid", overlay.id());
                    }
                } else {
                    println!("ARM9 overlay {} has no signature", overlay.id());
                }
            }
            return Ok(());
        }

        if self.compute {
            let mut arm9 = rom.arm9().clone();
            arm9.decompress()?;
            let hmac_sha1_key = arm9.hmac_sha1_key()?.context("Failed to get HMAC-SHA1 key")?;
            let hmac_sha1 = HmacSha1::new(hmac_sha1_key);
            for overlay in rom.arm9_overlays() {
                let signature = overlay.compute_signature(&hmac_sha1)?;
                println!("ARM9 overlay {} signature: {}", overlay.id(), signature);
            }
        } else {
            for overlay in rom.arm9_overlays() {
                if let Some(signature) = overlay.signature() {
                    println!("ARM9 overlay {} signature: {}", overlay.id(), signature);
                } else {
                    println!("ARM9 overlay {} has no signature", overlay.id());
                }
            }
        }

        Ok(())
    }
}
