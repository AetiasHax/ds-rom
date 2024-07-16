mod build;
mod dump;
mod extract;

use std::io::Write;

use anyhow::Result;
use build::Build;
use clap::{Parser, Subcommand};
use dump::Dump;
use extract::Extract;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
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
    let args = Args::parse();
    args.command.run()
}

pub fn print_hex(data: &[u8], raw: bool, base: u32) -> Result<()> {
    if raw {
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
