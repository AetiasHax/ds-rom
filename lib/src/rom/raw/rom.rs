use std::{borrow::Cow, collections::BTreeSet, fmt::Display, io::Read, mem::size_of, path::Path};

use snafu::{Backtrace, Snafu};

use super::{
    Arm9Footer, Arm9FooterError, Banner, FileAlloc, Fnt, Header, NITROCODE_BYTES, Overlay, OverlayTable, RawBannerError,
    RawFatError, RawFntError, RawHeaderError, RawOverlayError,
};
use crate::{
    error::{DataOutOfBoundsError, OverflowError, slice_data, slice_data_mut},
    io::{FileError, open_file, write_file},
    rom::{
        Arm7, Arm7Offsets, Arm9, Arm9AutoloadError, Arm9Offsets, Arm9Options, DsiProgram, DsiProgramOffsets,
        RomConfigAlignment, RomConfigDsiAlignment, RomConfigDsiPaddingValues, RomConfigPaddingValues,
        raw::{MultibootSignature, ProgramOffset, RawMultibootSignatureError, TableOffset},
    },
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
    /// See [`Arm9AutoloadError`].
    #[snafu(transparent)]
    Arm9Autoload {
        /// Source error.
        source: Arm9AutoloadError,
    },
    /// Occurs when the ARM9 build info can be found neither in the header nor in an ARM9 footer.
    #[snafu(display("ROM header has no ARM9 build info offset and there is no ARM9 footer to take one from:\n{backtrace}"))]
    NoBuildInfo {
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// See [`OverflowError`].
    #[snafu(transparent)]
    Overflow {
        /// Source error.
        source: OverflowError,
    },
    /// See [`DataOutOfBoundsError`]
    #[snafu(transparent)]
    DataOutOfBounds {
        /// Source error.
        source: DataOutOfBoundsError,
    },
}

/// Errors related to [`Rom::arm7`].
#[derive(Debug, Snafu)]
pub enum RawArm7Error {
    /// See [`RawHeaderError`].
    #[snafu(transparent)]
    RawHeader {
        /// Source error.
        source: RawHeaderError,
    },
    /// See [`OverflowError`].
    #[snafu(transparent)]
    Overflow {
        /// Source error.
        source: OverflowError,
    },
    /// See [`DataOutOfBoundsError`]
    #[snafu(transparent)]
    DataOutOfBounds {
        /// Source error.
        source: DataOutOfBoundsError,
    },
}

/// Errors related to [`Rom::arm9i`] and [`Rom::arm7i`].
#[derive(Debug, Snafu)]
pub enum RawDsiProgramError {
    /// Occurs when the ROM has no DSi area.
    #[snafu(display("ROM does not have a DSi area"))]
    NoDsiArea {
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// See [`RawHeaderError`].
    #[snafu(transparent)]
    RawHeader {
        /// Source error.
        source: RawHeaderError,
    },
    /// See [`OverflowError`].
    #[snafu(transparent)]
    Overflow {
        /// Source error.
        source: OverflowError,
    },
    /// See [`DataOutOfBoundsError`]
    #[snafu(transparent)]
    DataOutOfBounds {
        /// Source error.
        source: DataOutOfBoundsError,
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
    /// See [`OverflowError`].
    #[snafu(transparent)]
    Overflow {
        /// Source error.
        source: OverflowError,
    },
    /// See [`DataOutOfBoundsError`]
    #[snafu(transparent)]
    DataOutOfBounds {
        /// Source error.
        source: DataOutOfBoundsError,
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
        let start = header.arm9.offset;
        let end = start.checked_add(header.arm9.size).ok_or_else(|| OverflowError::new("ARM9 end offset"))?;
        let data = slice_data(&self.data, start..end, || "ARM9")?;

        let footer = self.arm9_footer()?;
        let build_info_offset = if header.arm9_build_info_offset == 0 {
            let Some(footer) = footer else { return NoBuildInfoSnafu {}.fail() };
            footer.build_info_offset
        } else if header.arm9_build_info_offset > header.arm9.offset {
            header
                .arm9_build_info_offset
                .checked_sub(header.arm9.offset)
                .ok_or_else(|| OverflowError::new("ARM9 build info offset"))?
        } else {
            // `arm9_build_info_offset` is not an absolute ROM offset in DSi titles
            header.arm9_build_info_offset
        };

        let arm9 = Arm9::new(
            Cow::Borrowed(data),
            Arm9Offsets {
                base_address: header.arm9.base_addr,
                entry_function: header.arm9.entry,
                build_info: build_info_offset,
                autoload_callback: header.arm9_autoload_callback,
                overlay_signatures: footer.map_or(0, |footer| footer.overlay_signatures_offset),
            },
            Arm9Options { has_footer: footer.is_some() },
        )?;
        Ok(arm9)
    }

    /// Returns a reference to the ARM9 footer of this [`Rom`], or [`None`] if this ROM has no ARM9 footer. The footer is
    /// considered absent if it doesn't fit in the ROM or doesn't start with the nitrocode.
    ///
    /// # Errors
    ///
    /// See [`Self::header`] and [`Arm9Footer::borrow_from_slice`].
    pub fn arm9_footer(&self) -> Result<Option<&Arm9Footer>, RawArm9Error> {
        let header = self.header()?;
        let start =
            header.arm9.offset.checked_add(header.arm9.size).ok_or_else(|| OverflowError::new("ARM9 footer offset"))?;
        let end =
            start.checked_add(size_of::<Arm9Footer>() as u32).ok_or_else(|| OverflowError::new("ARM9 footer end address"))?;
        if end as usize > self.data.len() {
            return Ok(None);
        }
        let data = slice_data(&self.data, start..end, || "ARM9 footer")?;
        if !data.starts_with(&NITROCODE_BYTES) {
            return Ok(None);
        }
        Ok(Some(Arm9Footer::borrow_from_slice(data)?))
    }

    /// Returns a mutable reference to the ARM9 footer of this [`Rom`], or [`None`] if this ROM has no ARM9 footer. The footer
    /// is considered absent if it doesn't fit in the ROM or doesn't start with the nitrocode.
    ///
    /// # Errors
    ///
    /// See [`Self::header`] and [`Arm9Footer::borrow_from_slice_mut`].
    pub fn arm9_footer_mut(&mut self) -> Result<Option<&mut Arm9Footer>, Arm9FooterError> {
        let header = self.header()?;
        let start =
            header.arm9.offset.checked_add(header.arm9.size).ok_or_else(|| OverflowError::new("ARM9 footer offset"))?;
        let end =
            start.checked_add(size_of::<Arm9Footer>() as u32).ok_or_else(|| OverflowError::new("ARM9 footer end address"))?;
        if end as usize > self.data.len() {
            return Ok(None);
        }
        let data = slice_data_mut(self.data.to_mut(), start..end, || "ARM9 footer")?;
        if !data.starts_with(&NITROCODE_BYTES) {
            return Ok(None);
        }
        Ok(Some(Arm9Footer::borrow_from_slice_mut(data)?))
    }

    /// Returns the ARM9 overlays of this [`Rom`].
    ///
    /// # Errors
    ///
    /// See [`Self::header`] and [`Overlay::borrow_from_slice`].
    pub fn arm9_overlays(&self) -> Result<&[Overlay], RawOverlayError> {
        let header = self.header()?;
        let start = header.arm9_overlays.offset;
        let end =
            start.checked_add(header.arm9_overlays.size).ok_or_else(|| OverflowError::new("ARM9 overlay table end offset"))?;
        if start == 0 && end == 0 {
            Ok(&[])
        } else {
            let data = slice_data(&self.data, start..end, || "ARM9 overlay table")?;
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
        #[allow(clippy::arithmetic_side_effects)] // size_of::<Overlay>() is not zero
        Ok(header.arm9_overlays.size as usize / size_of::<Overlay>())
    }

    /// Returns the ARM7 program of this [`Rom`].
    ///
    /// # Errors
    ///
    /// See [`Self::header`].
    pub fn arm7(&self) -> Result<Arm7<'_>, RawArm7Error> {
        let header = self.header()?;
        let start = header.arm7.offset;
        let end = start.checked_add(header.arm7.size).ok_or_else(|| OverflowError::new("ARM7 offset"))?;
        let data = slice_data(&self.data, start..end, || "ARM7")?;

        let build_info_offset = if header.arm7_build_info_offset == 0 {
            0
        } else if header.arm7_build_info_offset > header.arm7.offset {
            header
                .arm7_build_info_offset
                .checked_sub(header.arm7.offset)
                .ok_or_else(|| OverflowError::new("ARM7 build info offset"))?
        } else {
            // `arm7_build_info_offset` is not an absolute ROM offset in DSi titles
            header.arm7_build_info_offset
        };

        Ok(Arm7::new(Cow::Borrowed(data), Arm7Offsets {
            base_address: header.arm7.base_addr,
            entry_function: header.arm7.entry,
            build_info: build_info_offset,
            autoload_callback: header.arm7_autoload_callback,
        }))
    }

    /// Returns the ARM7 overlay table of this [`Rom`].
    ///
    /// # Errors
    ///
    /// See [`Self::header`] and [`Overlay::borrow_from_slice`].
    pub fn arm7_overlays(&self) -> Result<&[Overlay], RawOverlayError> {
        let header = self.header()?;
        let start = header.arm7_overlays.offset;
        let end =
            start.checked_add(header.arm7_overlays.size).ok_or_else(|| OverflowError::new("ARM7 overlay table end offset"))?;
        if start == 0 && end == 0 {
            Ok(&[])
        } else {
            let data = slice_data(&self.data, start..end, || "ARM7 overlay table")?;
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
        #[allow(clippy::arithmetic_side_effects)] // size_of::<Overlay>() is not zero
        Ok((header.arm7_overlays.size as usize) / size_of::<Overlay>())
    }

    /// Returns the FNT of this [`Rom`].
    ///
    /// # Errors
    ///
    /// See [`Self::header`] and [`Fnt::borrow_from_slice`].
    pub fn fnt(&self) -> Result<Fnt<'_>, RawFntError> {
        let header = self.header()?;
        let start = header.file_names.offset;
        let end = start.checked_add(header.file_names.size).ok_or_else(|| OverflowError::new("FNT end offset"))?;
        let data = slice_data(&self.data, start..end, || "FNT")?;
        Fnt::borrow_from_slice(data)
    }

    /// Returns the FAT of this [`Rom`].
    ///
    /// # Errors
    ///
    /// See [`Self::header`] and [`FileAlloc::borrow_from_slice`].
    pub fn fat(&self) -> Result<&[FileAlloc], RawFatError> {
        let header = self.header()?;
        let start = header.file_allocs.offset;
        let end = start.checked_add(header.file_allocs.size).ok_or_else(|| OverflowError::new("FAT end offset"))?;
        let data = slice_data(&self.data, start..end, || "FAT")?;
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
        let data = slice_data(&self.data, header.banner_offset.., || "banner")?;
        Banner::borrow_from_slice(data)
    }

    /// Returns the multiboot signature of this [`Rom`].
    ///
    /// # Errors
    ///
    /// See [`Self::header`] and [`MultibootSignature::borrow_from_slice`].
    pub fn multiboot_signature(&self) -> Result<Option<MultibootSignature>, RawMultibootSignatureError> {
        let header = self.header()?;
        let data = slice_data(&self.data, header.rom_size_ds.., || "multiboot signature")?;
        match MultibootSignature::from_slice(data) {
            Ok(s) => Ok(Some(s)),
            Err(RawMultibootSignatureError::InvalidMagic { .. }) => Ok(None), // signature not found
            Err(RawMultibootSignatureError::DataTooSmall { .. }) => Ok(None), // signature truncated or absent at EOF
            Err(e) => Err(e),
        }
    }

    /// Returns the padding values between ROM sections.
    ///
    /// # Errors
    ///
    /// See [`Self::header`], [`Self::fat`], [`Self::arm9_overlays`], [`Self::arm7_overlays`] and
    /// [`Self::file_image_padding_value`].
    pub fn padding_values(&self) -> Result<RomConfigPaddingValues, RomAlignmentsError> {
        let header = self.header()?;
        let fat = self.fat()?;
        let arm9_overlays = self.arm9_overlays()?;
        let arm7_overlays = self.arm7_overlays()?;

        Ok(RomConfigPaddingValues {
            arm9: self.get_padding_value(header.arm9.offset, "ARM9")?,
            arm9_overlay_table: self.get_padding_value(header.arm9_overlays.offset, "ARM9 overlay table")?,
            arm9_overlays: self.get_overlays_padding(arm9_overlays, fat, "ARM9")?,
            arm7: self.get_padding_value(header.arm7.offset, "ARM7")?,
            arm7_overlay_table: self.get_padding_value(header.arm7_overlays.offset, "ARM7 overlay table")?,
            arm7_overlays: self.get_overlays_padding(arm7_overlays, fat, "ARM7")?,
            fnt: self.get_padding_value(header.file_names.offset, "FNT")?,
            fat: self.get_padding_value(header.file_allocs.offset, "FAT")?,
            banner: self.get_padding_value(header.banner_offset, "banner")?,
            file_image: self.file_image_padding_value()?,
            rom: *self.data.last().unwrap_or(&DEFAULT_PADDING_VALUE),
        })
    }

    fn get_padding_value(&self, offset: u32, what: impl Display) -> Result<u8, RomAlignmentsError> {
        if offset > 0 {
            #[allow(clippy::arithmetic_side_effects)] // offset is not zero
            let padding_offset = offset - 1;
            Ok(*self
                .data
                .get(padding_offset as usize)
                .ok_or_else(|| DataOutOfBoundsError::new(format!("{what} padding value"), padding_offset..offset))?)
        } else {
            Ok(DEFAULT_PADDING_VALUE)
        }
    }

    fn get_overlays_padding(
        &self,
        overlays: &[Overlay],
        fat: &[FileAlloc],
        processor: &'static str,
    ) -> Result<u8, RomAlignmentsError> {
        let mut overlay_files = overlays.iter().filter_map(|o| fat.get(o.id as usize)).collect::<Vec<_>>();
        overlay_files.sort_unstable_by_key(|o| o.start);
        let mut overlay_files = overlay_files.into_iter();
        if let Some(mut prev_overlay) = overlay_files.next() {
            for overlay in overlay_files {
                if prev_overlay.end != overlay.start {
                    return self.get_padding_value(overlay.start, format!("{processor} overlay"));
                }
                prev_overlay = overlay;
            }
        }
        Ok(DEFAULT_PADDING_VALUE)
    }

    /// Returns the padding values between DSi-specific ROM sections.
    pub fn dsi_padding_values(&self) -> Result<RomConfigDsiPaddingValues, RomAlignmentsError> {
        let header = self.header()?;
        let region_start = header.dsi_region_start()?;
        Ok(RomConfigDsiPaddingValues {
            digest_sector_hashtable: self
                .get_padding_value(header.digest_sector_hashtable.offset, "digest sector hashtable")?,
            digest_block_hashtable: self.get_padding_value(header.digest_block_hashtable.offset, "digest block hashtable")?,
            rom_size_ds: self.get_padding_value(header.rom_size_ds, "rom_size_ds")?,
            dsi_region: self.get_padding_value(region_start, "DSi region")?,
            arm7i: self.get_padding_value(header.arm7i.offset, "ARM7i")?,
            rom_size_dsi: self.get_padding_value(header.rom_size_dsi, "rom_size_dsi")?,
        })
    }

    /// Returns the padding value in the file image block of this [`Rom`].
    ///
    /// # Errors
    ///
    /// See [`Self::fat`], [`Self::arm9_overlays`] and [`Self::arm7_overlays`].
    fn file_image_padding_value(&self) -> Result<u8, RomAlignmentsError> {
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
        let Some(gap) = files.array_windows::<2>().find(|pair| pair[0].end != pair[1].start) else {
            return Ok(DEFAULT_PADDING_VALUE);
        };
        let offset = gap[0].end;
        Ok(*self
            .data
            .get(offset as usize)
            .ok_or_else(|| DataOutOfBoundsError::new("file image padding value", offset..offset.saturating_add(1)))?)
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
            .filter_map(|overlay| fat.get(overlay.file_id as usize))
            .map(|file| get_alignment(file.start))
            .min()
            .unwrap_or(DEFAULT_ALIGNMENT);
        let arm7 = get_alignment(header.arm7.offset);
        let arm7_overlay_table = get_alignment(header.arm7_overlays.offset);
        let arm7_overlay = arm7_overlays
            .iter()
            .filter_map(|overlay| fat.get(overlay.file_id as usize))
            .map(|file| get_alignment(file.start))
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

    /// Returns the alignment of DSi-specific ROM sections.
    pub fn dsi_alignments(&self) -> Result<RomConfigDsiAlignment, RomAlignmentsError> {
        // Guesses the section alignment from trailing zeros, clamped to 4-byte..4KB.
        // Not a duplicate, the DSi area lays out sections more coarsely than the DS area.
        fn detect_alignment(offset: u32) -> u32 {
            if offset == 0 {
                4
            } else {
                1 << offset.trailing_zeros().clamp(2, 12)
            }
        }

        let header = self.header()?;
        Ok(RomConfigDsiAlignment {
            digest_block_hashtable: detect_alignment(header.digest_block_hashtable.offset),
            rom_size_ds: detect_alignment(header.rom_size_ds),
            arm7i: detect_alignment(header.arm7i.offset),
        })
    }

    fn dsi_program(
        &'a self,
        header: &Header,
        program: &ProgramOffset,
        build_info_offset: u32,
        modcrypt_area: &TableOffset,
        name: &'static str,
    ) -> Result<DsiProgram<'a>, RawDsiProgramError> {
        debug_assert!(header.has_dsi_area());

        let modcrypt_size = if modcrypt_area.size == 0 || !header.dsi_flags.modcrypted() {
            0
        } else if modcrypt_area.offset == program.offset {
            modcrypt_area.size
        } else {
            log::warn!(
                "Modcrypt area at {:#x} does not start at the {name} program at {:#x}, leaving it encrypted",
                modcrypt_area.offset,
                program.offset
            );
            0
        };

        let start = program.offset;
        let end = start.checked_add(program.size).ok_or_else(|| OverflowError::new(format!("{name} end offset")))?;
        let data = slice_data(&self.data, start..end, || name)?;
        Ok(DsiProgram::new(data, DsiProgramOffsets {
            entry_function: program.entry,
            base_address: program.base_addr,
            build_info_offset,
            modcrypt_size,
        }))
    }

    /// Returns the ARM9i program of this [`Rom`].
    ///
    /// # Errors
    ///
    /// See [`Self::header`].
    pub fn arm9i(&'a self) -> Result<DsiProgram<'a>, RawDsiProgramError> {
        let header = self.header()?;
        if !header.has_dsi_area() {
            return NoDsiAreaSnafu.fail();
        }
        self.dsi_program(header, &header.arm9i, header.arm9i_build_info_offset, &header.modcrypt_area_1, "ARM9i")
    }

    /// Returns the ARM7i program of this [`Rom`].
    ///
    /// # Errors
    ///
    /// See [`Self::header`].
    pub fn arm7i(&'a self) -> Result<DsiProgram<'a>, RawDsiProgramError> {
        let header = self.header()?;
        if !header.has_dsi_area() {
            return NoDsiAreaSnafu.fail();
        }
        self.dsi_program(header, &header.arm7i, header.arm7i_build_info_offset, &header.modcrypt_area_2, "ARM7i")
    }

    /// Returns the DSi region padding of this [`Rom`].
    ///
    /// # Errors
    ///
    /// See [`Self::header`] and [`Header::dsi_region_start`].
    pub fn region_padding(&'a self) -> Result<&'a [u8], RawHeaderError> {
        let header = self.header()?;
        let region_start = header.dsi_region_start()?;
        Ok(slice_data(&self.data, region_start..header.arm9i.offset, || "DSi region padding")?)
    }
}

const DEFAULT_PADDING_VALUE: u8 = 0xff;
