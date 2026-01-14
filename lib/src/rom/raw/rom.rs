use std::{borrow::Cow, collections::BTreeSet, io::Read, mem::size_of, path::Path};

use snafu::Snafu;

use super::{
    Arm9Footer, Arm9FooterError, Banner, FileAlloc, Fnt, Header, Overlay, OverlayTable, RawBannerError, RawBuildInfoError,
    RawFatError, RawFntError, RawHeaderError, RawOverlayError,
};
use crate::{
    io::{open_file, write_file, FileError},
    rom::{Arm7, Arm7Offsets, Arm9, Arm9Offsets, RomConfigAlignment},
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
    /// See [`RawBuildInfoError`].
    #[snafu(transparent)]
    RawBuildInfo {
        /// Source error.
        source: RawBuildInfoError,
    },
}

/// Errors related to [`Rom::alignments`].
#[derive(Debug, Snafu)]
pub enum RomAlignmentsError {
    /// See [`RawHeaderError`].
    #[snafu(transparent)]
    RawHeader {
        /// Source error.
        source: RawHeaderError,
    },
    /// See [`RawFatError`].
    #[snafu(transparent)]
    RawFat {
        /// Source error.
        source: RawFatError,
    },
    /// See [`RawOverlayError`].
    #[snafu(transparent)]
    RawOverlay {
        /// Source error.
        source: RawOverlayError,
    },
    /// See [`RawFntError`].
    #[snafu(transparent)]
    RawBanner {
        /// Source error.
        source: RawBannerError,
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
    pub fn arm9(&self) -> Result<Arm9<'_>, RawArm9Error> {
        let header = self.header()?;
        let start = header.arm9.offset as usize;
        let end = start + header.arm9.size as usize;
        let data = &self.data[start..end];

        let footer = self.arm9_footer()?;
        let build_info_offset = if header.arm9_build_info_offset == 0 {
            footer.build_info_offset
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
                overlay_signatures: footer.overlay_signatures_offset,
            },
        )?)
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

    /// Returns the ARM9 overlays of this [`Rom`].
    ///
    /// # Errors
    ///
    /// See [`Self::header`] and [`Overlay::borrow_from_slice`].
    pub fn arm9_overlays(&self) -> Result<&[Overlay], RawOverlayError> {
        let header = self.header()?;
        let start = header.arm9_overlays.offset as usize;
        let end = start + header.arm9_overlays.size as usize;
        if start == 0 && end == 0 {
            Ok(&[])
        } else {
            let data = &self.data[start..end];
            Ok(Overlay::borrow_from_slice(data)?)
        }
    }

    /// Returns the ARM9 overlay table of this [`Rom`].
    ///
    /// # Errors
    ///
    /// See [`Self::arm9`] and [`Self::arm9_overlay_table_with`].
    pub fn arm9_overlay_table(&self) -> Result<OverlayTable<'_>, RawOverlayError> {
        let arm9 = self.arm9()?;
        self.arm9_overlay_table_with(&arm9)
    }

    /// Returns the ARM9 overlay table of this [`Rom`], using the table signature from the provided ARM9 program.
    ///
    /// # Errors
    ///
    /// See [`Self::arm9_overlays`] and [`Arm9::overlay_table_signature`].
    pub fn arm9_overlay_table_with(&self, arm9: &Arm9) -> Result<OverlayTable<'_>, RawOverlayError> {
        let overlays = self.arm9_overlays()?;
        let signature = arm9.overlay_table_signature()?.cloned();
        Ok(OverlayTable::new(overlays, signature))
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
    pub fn arm7(&self) -> Result<Arm7<'_>, RawHeaderError> {
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
    pub fn arm7_overlays(&self) -> Result<&[Overlay], RawOverlayError> {
        let header = self.header()?;
        let start = header.arm7_overlays.offset as usize;
        let end = start + header.arm7_overlays.size as usize;
        if start == 0 && end == 0 {
            Ok(&[])
        } else {
            let data = &self.data[start..end];
            Ok(Overlay::borrow_from_slice(data)?)
        }
    }

    /// Returns the ARM7 overlay table of this [`Rom`].
    ///
    /// # Errors
    ///
    /// See [`Self::arm7_overlays`].
    pub fn arm7_overlay_table(&self) -> Result<OverlayTable<'_>, RawOverlayError> {
        let overlays = self.arm7_overlays()?;
        Ok(OverlayTable::new(overlays, None))
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
    pub fn fnt(&self) -> Result<Fnt<'_>, RawFntError> {
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
    pub fn banner(&self) -> Result<Banner<'_>, RawBannerError> {
        let header = self.header()?;
        let start = header.banner_offset as usize;
        let data = &self.data[start..];
        Banner::borrow_from_slice(data)
    }

    /// Returns the padding value in the file image block of this [`Rom`].
    ///
    /// # Errors
    ///
    /// See [`Self::fat`], [`Self::arm9_overlays`] and [`Self::arm7_overlays`].
    pub fn file_image_padding_value(&self) -> Result<u8, RomAlignmentsError> {
        let fat = self.fat()?;
        let arm9_overlays = self.arm9_overlays()?;
        let arm7_overlays = self.arm7_overlays()?;
        let arm9_overlay_files = arm9_overlays.iter().map(|overlay| overlay.file_id).collect::<BTreeSet<u32>>();
        let arm7_overlay_files = arm7_overlays.iter().map(|overlay| overlay.file_id).collect::<BTreeSet<u32>>();

        // Get sorted list of adjacent files that are in the file image block (i.e. not overlays)
        let mut files: Vec<&FileAlloc> = fat
            .iter()
            .enumerate()
            .filter(|(i, _)| !arm9_overlay_files.contains(&(*i as u32)) && !arm7_overlay_files.contains(&(*i as u32)))
            .map(|(_, file)| file)
            .collect();
        files.sort_by_key(|file| file.start);

        // Find a gap between two adjacent files, and return the padding byte between them
        let Some(gap) = files.windows(2).find(|pair| pair[0].end != pair[1].start) else {
            return Ok(0xff);
        };
        Ok(self.data[gap[0].end as usize])
    }

    /// Returns the section padding value of this [`Rom`].
    ///
    /// # Errors
    ///
    /// See [`Self::header`], [`Self::banner`], [`Self::fat`], [`Self::arm9_overlays`] and [`Self::arm7_overlays`].
    pub fn section_padding_value(&self) -> Result<u8, RomAlignmentsError> {
        let header = self.header()?;
        let banner = self.banner()?;
        let fat = self.fat()?;
        let arm9_overlays = self.arm9_overlays()?;
        let arm7_overlays = self.arm7_overlays()?;

        // Get sorted list of adjacent sections in the ROM
        let mut sections = vec![
            header.arm9.offset..header.arm9.offset + header.arm9.size + size_of::<Arm9Footer>() as u32,
            header.arm7.offset..header.arm7.offset + header.arm7.size,
            header.file_names.offset..header.file_names.offset + header.file_names.size,
            header.file_allocs.offset..header.file_allocs.offset + header.file_allocs.size,
            header.arm9_overlays.offset..header.arm9_overlays.offset + header.arm9_overlays.size,
            header.arm7_overlays.offset..header.arm7_overlays.offset + header.arm7_overlays.size,
        ];
        sections.push(header.banner_offset..header.banner_offset + banner.version().banner_size() as u32);
        arm9_overlays.iter().for_each(|overlay| {
            let file = &fat[overlay.file_id as usize];
            sections.push(file.start..file.end);
        });
        arm7_overlays.iter().for_each(|overlay| {
            let file = &fat[overlay.file_id as usize];
            sections.push(file.start..file.end);
        });
        sections.retain(|section| section.start != section.end);
        sections.sort_by_key(|section| section.start);

        // Find a gap between two adjacent sections, and return the padding byte between them
        let Some(gap) = sections.windows(2).find(|pair| pair[0].end != pair[1].start) else {
            return Ok(0xff);
        };
        log::debug!("Gap between sections: {:#010x} - {:#010x}", gap[0].end, gap[1].start);
        Ok(self.data[gap[0].end as usize])
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

    /// Returns the alignment of ROM sections.
    ///
    /// # Errors
    ///
    /// See [`Self::header`], [`Self::fat`], and [`Self::arm9_overlay_table`].
    pub fn alignments(&self) -> Result<RomConfigAlignment, RomAlignmentsError> {
        // Collect all overlay files into a set.
        fn get_overlay_files(overlay_table: &[Overlay]) -> BTreeSet<u32> {
            overlay_table.iter().map(|overlay| overlay.file_id).collect()
        }

        const DEFAULT_ALIGNMENT: u32 = 0x4;

        // Get the alignment of the current section, by looking at the address of the next section.
        fn get_alignment(next_section: u32) -> u32 {
            if next_section.trailing_zeros() >= 9 {
                0x200
            } else {
                DEFAULT_ALIGNMENT
            }
        }

        let fat = self.fat()?;
        let arm9_overlays = self.arm9_overlays()?;
        let arm7_overlays = self.arm7_overlays()?;
        let arm9_overlay_files = get_overlay_files(arm9_overlays);
        let arm7_overlay_files = get_overlay_files(arm7_overlays);
        let header = self.header()?;

        let arm9 = get_alignment(header.arm9.offset);
        let arm9_overlay_table = get_alignment(header.arm9_overlays.offset);
        let arm9_overlay = arm9_overlays
            .iter()
            .map(|overlay| get_alignment(fat[overlay.file_id as usize].start))
            .min()
            .unwrap_or(DEFAULT_ALIGNMENT);
        let arm7 = get_alignment(header.arm7.offset);
        let arm7_overlay_table = get_alignment(header.arm7_overlays.offset);
        let arm7_overlay = arm7_overlays
            .iter()
            .map(|overlay| get_alignment(fat[overlay.file_id as usize].start))
            .min()
            .unwrap_or(DEFAULT_ALIGNMENT);
        let file_name_table = get_alignment(header.file_names.offset);
        let file_allocation_table = get_alignment(header.file_allocs.offset);
        let banner = get_alignment(header.banner_offset);

        let file_iter = fat
            .iter()
            .enumerate()
            .filter(|(i, _)| !arm9_overlay_files.contains(&(*i as u32)) && !arm7_overlay_files.contains(&(*i as u32)))
            .map(|(_, file)| file);

        let file_image_block = file_iter.clone().map(|file| file.start).min().map(get_alignment).unwrap_or(DEFAULT_ALIGNMENT);
        let file = file_iter.clone().map(|file| get_alignment(file.start)).min().unwrap_or(DEFAULT_ALIGNMENT);

        Ok(RomConfigAlignment {
            arm9,
            arm9_overlay_table,
            arm9_overlay,
            arm7,
            arm7_overlay_table,
            arm7_overlay,
            file_name_table,
            file_allocation_table,
            banner,
            file_image_block,
            file,
        })
    }
}
