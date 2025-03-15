mod build;
mod dump;
mod extract;

use std::io::Write;

use anyhow::Result;
use build::Build;
use clap::{Parser, Subcommand};
use dump::Dump;
use extract::Extract;
use log::LevelFilter;

/// Command-line interface for extracting/building Nintendo DS ROMs.
#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Dump(Dump),
    Extract(Extract),
    Build(Build),
}

impl Command {
    fn run(&self) -> Result<()> {
        match self {
            Command::Dump(dump) => dump.run(),
            Command::Extract(extract) => extract.run(),
            Command::Build(build) => build.run(),
        }
    }
}

fn main() -> Result<()> {
    env_logger::builder().filter_level(LevelFilter::Info).init();

    let args: Cli = Cli::parse();
    args.command.run()
}

pub fn print_hex(data: &[u8], raw: bool, base: u32) -> Result<()> {
    if raw {
        std::io::stdout().write_all(data)?;
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
