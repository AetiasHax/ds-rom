/// Like [`println!`], but returns an [`std::io::Error`] instead of panicking when writing to stdout fails, e.g. when the
/// output is piped into `head`.
macro_rules! rprintln {
    ($($arg:tt)*) => {
        ::std::io::Write::write_fmt(&mut ::std::io::stdout(), format_args!("{}\n", format_args!($($arg)*)))
    };
}

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

    #[arg(long)]
    debug: bool,
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
    let args: Cli = Cli::parse();
    env_logger::builder().filter_level(if args.debug { LevelFilter::Debug } else { LevelFilter::Info }).init();

    match args.command.run() {
        // The reader closed stdout early, e.g. `dsrom dump ... | head`. Stop quietly like other command-line tools.
        Err(error) if error.downcast_ref::<std::io::Error>().is_some_and(|e| e.kind() == std::io::ErrorKind::BrokenPipe) => {
            Ok(())
        }
        result => result,
    }
}

pub fn print_hex(data: &[u8], raw: bool, base: u32) -> Result<()> {
    let mut stdout = std::io::stdout().lock();
    if raw {
        stdout.write_all(data)?;
    } else {
        const ROW_LENGTH: usize = 16;
        for (offset, chunk) in data.chunks(ROW_LENGTH).enumerate() {
            #[allow(clippy::arithmetic_side_effects)] // offset is effectively divided by ROW_LENGTH already
            {
                write!(stdout, "{:08x} ", (base as usize).wrapping_add(offset * ROW_LENGTH))?;
            }
            for byte in chunk {
                write!(stdout, " {byte:02x}")?;
            }
            for _ in chunk.len()..ROW_LENGTH {
                write!(stdout, "   ")?;
            }
            write!(stdout, "  ")?;
            for &byte in chunk {
                let ch = char::from(byte);
                write!(stdout, "{}", if ch.is_ascii_graphic() { ch } else { '.' })?;
            }
            writeln!(stdout)?;
        }
    }
    Ok(())
}
