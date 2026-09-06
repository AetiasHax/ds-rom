use std::{borrow::Cow, collections::BTreeSet, io::Read, mem::size_of, path::Path};

use snafu::Snafu;

use super::{
    Arm9Footer, Arm9FooterError, Banner, FileAlloc, Fnt, Header, NITROCODE_BYTES, Overlay, OverlayTable, RawBannerError,
    RawBuildInfoError, RawFatError, RawFntError, RawHeaderError, RawOverlayError,
};
use crate::{
    io::{FileError, open_file, write_file},
    rom::{
        Arm7, Arm7Offsets, Arm9, Arm9Offsets, RomConfigAlignment, RomConfigPaddingValues,
        raw::{MultibootSignature, RawMultibootSignatureError},
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
        let footer_offset = self.arm9_footer_offset()?;
        let start = header.arm9.offset as usize;
        // The footer normally follows the ARM9 program, but some ROMs report an ARM9 size that
        // includes the footer. In that case `footer_offset` lands inside the reported size, so
        // slicing up to it keeps the footer out of the ARM9 program data.
        let end = footer_offset.max(start);
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

        Ok(Arm9::new(Cow::Borrowed(data), Arm9Offsets {
            base_address: header.arm9.base_addr,
            entry_function: header.arm9.entry,
            build_info: build_info_offset,
            autoload_callback: header.arm9_autoload_callback,
            overlay_signatures: footer.overlay_signatures_offset,
        })?)
    }

    /// Returns the ROM offset of the ARM9 footer.
    ///
    /// The footer normally follows the ARM9 program at `arm9.offset + arm9.size`. However, some
    /// ROMs report an ARM9 size that includes the 12-byte footer, in which case the footer is
    /// located at `arm9.offset + arm9.size - size_of::<Arm9Footer>()`. This function detects the
    /// nitrocode to find the footer in either case, falling back to the standard location so that
    /// callers report the usual "missing nitrocode" error when no footer is present.
    ///
    /// # Errors
    ///
    /// See [`Self::header`].
    fn arm9_footer_offset(&self) -> Result<usize, Arm9FooterError> {
        let header = self.header()?;
        let after_arm9 = (header.arm9.offset + header.arm9.size) as usize;
        let footer_size = size_of::<Arm9Footer>();
        if self.has_nitrocode_at(after_arm9) {
            Ok(after_arm9)
        } else if after_arm9 >= footer_size && self.has_nitrocode_at(after_arm9 - footer_size) {
            Ok(after_arm9 - footer_size)
        } else {
            Ok(after_arm9)
        }
    }

    /// Returns whether the ARM9 footer nitrocode is present at the given ROM offset.
    fn has_nitrocode_at(&self, offset: usize) -> bool {
        self.data.get(offset..offset + NITROCODE_BYTES.len()).is_some_and(|bytes| bytes == NITROCODE_BYTES)
    }

    /// Returns a reference to the ARM9 footer of this [`Rom`].
    ///
    /// # Errors
    ///
    /// See [`Self::header`] and [`Arm9Footer::borrow_from_slice`].
    pub fn arm9_footer(&self) -> Result<&Arm9Footer, Arm9FooterError> {
        let start = self.arm9_footer_offset()?;
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
        let start = self.arm9_footer_offset()?;
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

        let build_info_offset = if header.arm7_build_info_offset == 0 {
            0
        } else {
            header.arm7_build_info_offset - header.arm7.offset
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

    /// Returns the multiboot signature of this [`Rom`].
    ///
    /// # Errors
    ///
    /// See [`Self::header`] and [`MultibootSignature::borrow_from_slice`].
    pub fn multiboot_signature(&self) -> Result<Option<MultibootSignature>, RawMultibootSignatureError> {
        let header = self.header()?;
        let start = header.rom_size_ds as usize;
        let data = &self.data[start..];
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
            arm9: self.data[header.arm9.offset as usize - 1],
            arm9_overlay_table: if header.arm9_overlays.offset > 0 {
                self.data[header.arm9_overlays.offset as usize - 1]
            } else {
                DEFAULT_PADDING_VALUE
            },
            arm9_overlays: self.get_overlays_padding(arm9_overlays, fat).unwrap_or(DEFAULT_PADDING_VALUE),
            arm7: self.data[header.arm7.offset as usize - 1],
            arm7_overlay_table: if header.arm7_overlays.offset > 0 {
                self.data[header.arm7_overlays.offset as usize - 1]
            } else {
                DEFAULT_PADDING_VALUE
            },
            arm7_overlays: self.get_overlays_padding(arm7_overlays, fat).unwrap_or(DEFAULT_PADDING_VALUE),
            fnt: self.data[header.file_names.offset as usize - 1],
            fat: self.data[header.file_allocs.offset as usize - 1],
            banner: self.data[header.banner_offset as usize - 1],
            file_image: self.file_image_padding_value()?,
            rom: *self.data.last().unwrap_or(&DEFAULT_PADDING_VALUE),
        })
    }

    fn get_overlays_padding(&self, overlays: &[Overlay], fat: &[FileAlloc]) -> Option<u8> {
        let mut overlay_files = overlays.iter().map(|o| &fat[o.id as usize]).collect::<Vec<_>>();
        overlay_files.sort_unstable_by_key(|o| o.start);
        let mut overlay_files = overlay_files.into_iter();
        if let Some(mut prev_overlay) = overlay_files.next() {
            for overlay in overlay_files {
                if prev_overlay.end != overlay.start {
                    return Some(self.data[overlay.start as usize - 1]);
                }
                prev_overlay = overlay;
            }
        }
        None
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
        let Some(gap) = files.windows(2).find(|pair| pair[0].end != pair[1].start) else {
            return Ok(DEFAULT_PADDING_VALUE);
        };
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

const DEFAULT_PADDING_VALUE: u8 = 0xff;
