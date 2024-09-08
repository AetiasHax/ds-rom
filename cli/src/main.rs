mod build;
mod dump;
mod extract;

use std::io::Write;

use anyhow::Result;
use argp::FromArgs;
use build::Build;
use dump::Dump;
use extract::Extract;

/// Command-line interface for extracting/building Nintendo DS ROMs.
#[derive(FromArgs)]
struct Args {
    #[argp(subcommand)]
    command: Command,
}

#[derive(FromArgs)]
#[argp(subcommand)]
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
    let args: Args = argp::parse_args_or_exit(argp::DEFAULT);
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
