use std::{borrow::Cow, io::Read, mem::size_of, path::Path};

use snafu::Snafu;

use super::{
    Arm9Footer, Arm9FooterError, Banner, FileAlloc, Fnt, Header, Overlay, RawBannerError, RawFatError, RawFntError,
    RawHeaderError, RawOverlayError,
};
use crate::{
    io::{open_file, write_file, FileError},
    rom::{Arm7, Arm7Offsets, Arm9, Arm9Offsets},
};

/// A raw DS ROM, see the plain struct [here](super::super::Rom).
pub struct Rom<'a> {
    data: Cow<'a, [u8]>,
}

/// Errors related to [`Rom::arm9`].
#[derive(Debug, Snafu)]
pub enum RawArm9Error {
    /// See [`RawHeaderError`].
    #[snafu(transparent)]
    RawHeader {
        /// Source error.
        source: RawHeaderError,
    },
    /// See [`Arm9FooterError`].
    #[snafu(transparent)]
    Arm9Footer {
        /// Source error.
        source: Arm9FooterError,
    },
}

impl<'a> Rom<'a> {
    /// Creates a new ROM from raw data.
    pub fn new<T: Into<Cow<'a, [u8]>>>(data: T) -> Self {
        Self { data: data.into() }
    }

    /// Loads from a ROM file.
    ///
    /// # Errors
    ///
    /// This function will return an error if an I/O operation fails.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, FileError> {
        let mut file = open_file(path)?;
        let size = file.metadata()?.len();
        let mut buf = vec![0; size as usize];
        file.read_exact(&mut buf)?;
        let data: Cow<[u8]> = buf.into();
        Ok(Self::new(data))
    }

    /// Returns the header of this [`Rom`].
    ///
    /// # Errors
    ///
    /// See [`Header::borrow_from_slice`].
    pub fn header(&self) -> Result<&Header, RawHeaderError> {
        Header::borrow_from_slice(self.data.as_ref())
    }

    /// Returns the ARM9 program of this [`Rom`].
    ///
    /// # Errors
    ///
    /// See [`Self::header`].
    pub fn arm9(&self) -> Result<Arm9, RawArm9Error> {
        let header = self.header()?;
        let start = header.arm9.offset as usize;
        let end = start + header.arm9.size as usize;
        let data = &self.data[start..end];

        let build_info_offset = if header.arm9_build_info_offset == 0 {
            let footer = self.arm9_footer()?;
            footer.build_info_offset
        } else if header.arm9_build_info_offset > header.arm9.offset {
            header.arm9_build_info_offset - header.arm9.offset
        } else {
            // `arm9_build_info_offset` is not an absolute ROM offset in DSi titles
            header.arm9_build_info_offset
        };

        Ok(Arm9::new(
            Cow::Borrowed(data),
            header.version(),
            Arm9Offsets {
                base_address: header.arm9.base_addr,
                entry_function: header.arm9.entry,
                build_info: build_info_offset,
                autoload_callback: header.arm9_autoload_callback,
            },
        ))
    }

    /// Returns a reference to the ARM9 footer of this [`Rom`].
    ///
    /// # Errors
    ///
    /// See [`Self::header`] and [`Arm9Footer::borrow_from_slice`].
    pub fn arm9_footer(&self) -> Result<&Arm9Footer, Arm9FooterError> {
        let header = self.header()?;
        let start = (header.arm9.offset + header.arm9.size) as usize;
        let end = start + size_of::<Arm9Footer>();
        let data = &self.data[start..end];
        Arm9Footer::borrow_from_slice(data)
    }

    /// Returns a mutable reference to the ARM9 footer of this [`Rom`].
    ///
    /// # Errors
    ///
    /// See [`Self::header`] and [`Arm9Footer::borrow_from_slice_mut`].
    pub fn arm9_footer_mut(&mut self) -> Result<&mut Arm9Footer, Arm9FooterError> {
        let header = self.header()?;
        let start = (header.arm9.offset + header.arm9.size) as usize;
        let end = start + size_of::<Arm9Footer>();
        let data = &mut self.data.to_mut()[start..end];
        Arm9Footer::borrow_from_slice_mut(data)
    }

    /// Returns the ARM9 overlay table of this [`Rom`].
    ///
    /// # Errors
    ///
    /// See [`Self::header`] and [`Overlay::borrow_from_slice`].
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

    /// Returns the number of ARM9 overlays in this [`Rom`].
    ///
    /// # Errors
    ///
    /// See [`Self::header`].
    pub fn num_arm9_overlays(&self) -> Result<usize, RawHeaderError> {
        let header = self.header()?;
        let start = header.arm9_overlays.offset as usize;
        let end = start + header.arm9_overlays.size as usize;
        Ok((end - start) / size_of::<Overlay>())
    }

    /// Returns the ARM7 program of this [`Rom`].
    ///
    /// # Errors
    ///
    /// See [`Self::header`].
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

    /// Returns the ARM7 overlay table of this [`Rom`].
    ///
    /// # Errors
    ///
    /// See [`Self::header`] and [`Overlay::borrow_from_slice`].
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

    /// Returns the number of ARM7 overlays in this [`Rom`].
    ///
    /// # Errors
    ///
    /// See [`Self::header`].
    pub fn num_arm7_overlays(&self) -> Result<usize, RawHeaderError> {
        let header = self.header()?;
        let start = header.arm7_overlays.offset as usize;
        let end = start + header.arm7_overlays.size as usize;
        Ok((end - start) / size_of::<Overlay>())
    }

    /// Returns the FNT of this [`Rom`].
    ///
    /// # Errors
    ///
    /// See [`Self::header`] and [`Fnt::borrow_from_slice`].
    pub fn fnt(&self) -> Result<Fnt, RawFntError> {
        let header = self.header()?;
        let start = header.file_names.offset as usize;
        let end = start + header.file_names.size as usize;
        let data = &self.data[start..end];
        Fnt::borrow_from_slice(data)
    }

    /// Returns the FAT of this [`Rom`].
    ///
    /// # Errors
    ///
    /// See [`Self::header`] and [`FileAlloc::borrow_from_slice`].
    pub fn fat(&self) -> Result<&[FileAlloc], RawFatError> {
        let header = self.header()?;
        let start = header.file_allocs.offset as usize;
        let end = start + header.file_allocs.size as usize;
        let data = &self.data[start..end];
        let allocs = FileAlloc::borrow_from_slice(data)?;
        Ok(allocs)
    }

    /// Returns the banner of this [`Rom`].
    ///
    /// # Errors
    ///
    /// See [`Self::header`] and [`Banner::borrow_from_slice`].
    pub fn banner(&self) -> Result<Banner, RawBannerError> {
        let header = self.header()?;
        let start = header.banner_offset as usize;
        let data = &self.data[start..];
        Banner::borrow_from_slice(data)
    }

    /// Returns a reference to the data of this [`Rom`].
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Saves this ROM to a new file.
    ///
    /// # Errors
    ///
    /// This function will return an error if an I/O operation fails.
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<(), FileError> {
        write_file(path, self.data())
    }
}
