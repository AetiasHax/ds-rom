use std::{
    borrow::Cow,
    fs::{self, File},
    io::{self, Read},
    mem::size_of,
    path::Path,
};

use snafu::{Backtrace, ResultExt, Snafu};

use crate::rom::{Arm7, Arm7Offsets, Arm9, Arm9Offsets};

use super::{
    Arm9Footer, Arm9FooterError, Banner, FileAlloc, Fnt, Header, Overlay, RawBannerError, RawFatError, RawFntError,
    RawHeaderError, RawOverlayError,
};

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
        let data = &self.data[start..end];

        let build_info_offset = if header.arm9_build_info_offset == 0 {
            0
        } else if header.arm9_build_info_offset > header.arm9.offset {
            header.arm9_build_info_offset - header.arm9.offset
        } else {
            // `arm9_build_info_offset` is not an absolute ROM offset in DSi titles
            header.arm9_build_info_offset
        };

        Ok(Arm9::new(
            Cow::Borrowed(data),
            Arm9Offsets {
                base_address: header.arm9.base_addr,
                entry_function: header.arm9.entry,
                build_info: build_info_offset,
                autoload_callback: header.arm9_autoload_callback,
            },
        ))
    }

    pub fn arm9_footer(&self) -> Result<&Arm9Footer, Arm9FooterError> {
        let header = self.header()?;
        let start = (header.arm9.offset + header.arm9.size) as usize;
        let end = start + size_of::<Arm9Footer>();
        let data = &self.data[start..end];
        Arm9Footer::borrow_from_slice(data)
    }

    pub fn arm9_footer_mut(&mut self) -> Result<&mut Arm9Footer, Arm9FooterError> {
        let header = self.header()?;
        let start = (header.arm9.offset + header.arm9.size) as usize;
        let end = start + size_of::<Arm9Footer>();
        let data = &mut self.data.to_mut()[start..end];
        Arm9Footer::borrow_from_slice_mut(data)
    }

    pub fn arm9_overlay_table(&self) -> Result<&[Overlay], RawOverlayError> {
        let header = self.header()?;
        let start = header.arm9_overlays.offset as usize;
        let end = start + header.arm9_overlays.size as usize;
        if start == 0 && end == 0 {
            Ok(&[])
        } else {
            let data = &self.data[start..end];
            Overlay::borrow_from_slice(data)
        }
    }

    pub fn num_arm9_overlays(&self) -> Result<usize, RawHeaderError> {
        let header = self.header()?;
        let start = header.arm9_overlays.offset as usize;
        let end = start + header.arm9_overlays.size as usize;
        Ok((end - start) / size_of::<Overlay>())
    }

    pub fn arm7(&self) -> Result<Arm7, RawHeaderError> {
        let header = self.header()?;
        let start = header.arm7.offset as usize;
        let end = start + header.arm7.size as usize;
        let data = &self.data[start..end];

        let build_info_offset =
            if header.arm7_build_info_offset == 0 { 0 } else { header.arm7_build_info_offset - header.arm7.offset };

        Ok(Arm7::new(
            Cow::Borrowed(data),
            Arm7Offsets {
                base_address: header.arm7.base_addr,
                entry_function: header.arm7.entry,
                build_info: build_info_offset,
                autoload_callback: header.arm7_autoload_callback,
            },
        ))
    }

    pub fn arm7_overlay_table(&self) -> Result<&[Overlay], RawOverlayError> {
        let header = self.header()?;
        let start = header.arm7_overlays.offset as usize;
        let end = start + header.arm7_overlays.size as usize;
        if start == 0 && end == 0 {
            Ok(&[])
        } else {
            let data = &self.data[start..end];
            Overlay::borrow_from_slice(data)
        }
    }

    pub fn num_arm7_overlays(&self) -> Result<usize, RawHeaderError> {
        let header = self.header()?;
        let start = header.arm7_overlays.offset as usize;
        let end = start + header.arm7_overlays.size as usize;
        Ok((end - start) / size_of::<Overlay>())
    }

    pub fn fnt(&self) -> Result<Fnt, RawFntError> {
        let header = self.header()?;
        let start = header.file_names.offset as usize;
        let end = start + header.file_names.size as usize;
        let data = &self.data[start..end];
        Fnt::borrow_from_slice(data)
    }

    pub fn fat(&self) -> Result<&[FileAlloc], RawFatError> {
        let header = self.header()?;
        let start = header.file_allocs.offset as usize;
        let end = start + header.file_allocs.size as usize;
        let data = &self.data[start..end];
        let allocs = FileAlloc::borrow_from_slice(data)?;
        Ok(allocs)
    }

    pub fn banner(&self) -> Result<Banner, RawBannerError> {
        let header = self.header()?;
        let start = header.banner_offset as usize;
        let data = &self.data[start..];
        Banner::borrow_from_slice(data)
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<(), io::Error> {
        fs::write(path, self.data())
    }
}
