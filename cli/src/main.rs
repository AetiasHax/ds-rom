use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use nds_io::rom::raw;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    rom: PathBuf,

    #[arg(short, long)]
    show_header: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let rom = raw::Rom::from_file(args.rom)?;
    let header = rom.header()?;
    if args.show_header {
        println!("ROM header:\n{}", header.display(2));
    }
    Ok(())
}
