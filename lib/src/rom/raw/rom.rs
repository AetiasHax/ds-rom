use std::{borrow::Cow, fs::File, io::Read, path::Path};

use crate::ReadError;

use super::Header;

pub struct Rom<T> {
    data: T,
}

impl<T: AsRef<[u8]>> Rom<T> {
    pub fn new(data: T) -> Self {
        Self { data }
    }

    pub fn header(&self) -> Result<&Header, ReadError> {
        Header::borrow_from_slice(&self.data)
    }
}

impl Rom<Cow<'_, [u8]>> {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, ReadError> {
        let mut file = File::open(path).map_err(ReadError::from)?;
        let size = file.metadata().map_err(ReadError::from)?.len();
        let mut buf = vec![0; size as usize];
        file.read_exact(&mut buf).map_err(ReadError::from)?;
        let data: Cow<[u8]> = buf.into();
        Ok(Self::new(data))
    }
}

#[test]
fn test_new() {
    let my_rom = [0u8; 0x4000];
    println!("{:x}", my_rom.as_ptr() as usize);
    let rom = Rom::new(&my_rom[..]);
    let _header = rom.header().unwrap();
    let rom = Rom::new(Cow::Borrowed(&my_rom[..]));
    let _header = rom.header().unwrap();
}
