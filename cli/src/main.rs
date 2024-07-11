mod dump;

use std::io::Write;

use anyhow::Result;
use clap::{Parser, Subcommand};
use dump::Dump;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Dump(Dump),
}

impl Command {
    fn run(&self) -> Result<()> {
        match self {
            Command::Dump(dump) => dump.run(),
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
