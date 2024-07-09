use std::{
    borrow::Cow,
    fs::File,
    io::{self, Read},
    path::Path,
};

use snafu::{Backtrace, ResultExt, Snafu};

use crate::rom::Arm9;

use super::{Header, Overlay, RawHeaderError, RawOverlayError};

#[derive(Debug, Snafu)]
pub enum RomReadError {
    #[snafu(display("io error: {source}:\n{backtrace}"))]
    Io { source: io::Error, backtrace: Backtrace },
}

pub struct Rom<'a> {
    data: Cow<'a, [u8]>,
}

impl<'a> Rom<'a> {
    pub fn new<T: Into<Cow<'a, [u8]>>>(data: T) -> Self {
        Self { data: data.into() }
    }

    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, RomReadError> {
        let mut file = File::open(path).context(IoSnafu {})?;
        let size = file.metadata().context(IoSnafu {})?.len();
        let mut buf = vec![0; size as usize];
        file.read_exact(&mut buf).context(IoSnafu)?;
        let data: Cow<[u8]> = buf.into();
        Ok(Self::new(data))
    }

    pub fn header(&self) -> Result<&Header, RawHeaderError> {
        Header::borrow_from_slice(self.data.as_ref())
    }

    pub fn arm9(&self) -> Result<Arm9, RawHeaderError> {
        let header = self.header()?;
        let start = header.arm9.offset as usize;
        let end = start + header.arm9.size as usize;
        let data = self.data[start..end].to_owned();

        let build_info_offset = (header.build_info_offset - header.arm9.offset) as usize;

        Ok(Arm9::new(data, header.arm9.base_addr, build_info_offset))
    }

    pub fn arm9_overlay_table(&self) -> Result<&[Overlay], RawOverlayError> {
        let header = self.header()?;
        let data = &self.data[header.arm9_overlays.offset as usize..];
        Overlay::borrow_from_slice(data)
    }
}

#[test]
fn test_new() {
    let my_rom = [0u8; 0x4000];
    let rom = Rom::new(&my_rom[..]);
    let _header = rom.header().unwrap();
    let rom = Rom::new(Cow::Borrowed(&my_rom[..]));
    let _header = rom.header().unwrap();
}
