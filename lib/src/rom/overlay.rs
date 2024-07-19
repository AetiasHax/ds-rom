use std::{borrow::Cow, io};

use serde::{Deserialize, Serialize};

use super::raw::{self, FileAlloc, HeaderVersion, OverlayCompressedSize, RawHeaderError};
use crate::compress::lz77::Lz77;

/// An overlay module for ARM9/ARM7.
#[derive(Clone)]
pub struct Overlay<'a> {
    header_version: HeaderVersion,
    info: OverlayInfo,
    data: Cow<'a, [u8]>,
}

const LZ77: Lz77 = Lz77 {};

impl<'a> Overlay<'a> {
    /// Creates a new [`Overlay`] from plain data.
    pub fn new<T: Into<Cow<'a, [u8]>>>(data: T, header_version: HeaderVersion, info: OverlayInfo) -> Self {
        Self { header_version, info, data: data.into() }
    }

    /// Parses an [`Overlay`] from a FAT and ROM.
    pub fn parse(overlay: &raw::Overlay, fat: &[FileAlloc], rom: &'a raw::Rom) -> Result<Self, RawHeaderError> {
        let alloc = fat[overlay.file_id as usize];
        let data = &rom.data()[alloc.range()];
        Ok(Self { header_version: rom.header()?.version(), info: OverlayInfo::new(overlay), data: Cow::Borrowed(data) })
    }

    /// Builds a raw overlay table entry.
    pub fn build(&self) -> raw::Overlay {
        raw::Overlay {
            id: self.id(),
            base_addr: self.base_address(),
            code_size: self.code_size(),
            bss_size: self.bss_size(),
            ctor_start: self.ctor_start(),
            ctor_end: self.ctor_end(),
            file_id: self.file_id(),
            compressed: if self.is_compressed() {
                OverlayCompressedSize::new().with_size(self.data.len()).with_is_compressed(1)
            } else {
                OverlayCompressedSize::new().with_size(0).with_is_compressed(0)
            },
        }
    }

    /// Returns the ID of this [`Overlay`].
    pub fn id(&self) -> u32 {
        self.info.id
    }

    /// Returns the base address of this [`Overlay`].
    pub fn base_address(&self) -> u32 {
        self.info.base_address
    }

    /// Returns the size of initialized data in this [`Overlay`].
    pub fn code_size(&self) -> u32 {
        self.info.code_size
    }

    /// Returns the size of uninitialized data in this [`Overlay`].
    pub fn bss_size(&self) -> u32 {
        self.info.bss_size
    }

    /// Returns the offset to the start of the .ctor section.
    pub fn ctor_start(&self) -> u32 {
        self.info.ctor_start
    }

    /// Returns the offset to the end of the .ctor section.
    pub fn ctor_end(&self) -> u32 {
        self.info.ctor_end
    }

    /// Returns the file ID of this [`Overlay`].
    pub fn file_id(&self) -> u32 {
        self.info.file_id
    }

    /// Returns whether this [`Overlay`] is compressed.
    pub fn is_compressed(&self) -> bool {
        self.info.compressed
    }

    /// Decompresses this [`Overlay`], but does nothing if already decompressed.
    pub fn decompress(&mut self) {
        if !self.is_compressed() {
            return;
        }
        self.data = LZ77.decompress(&self.data).into_vec().into();
        self.info.compressed = false;
    }

    /// Compresses this [`Overlay`], but does nothing if already compressed.
    ///
    /// # Errors
    ///
    /// This function will return an error if an I/O operation fails.
    pub fn compress(&mut self) -> Result<(), io::Error> {
        if self.is_compressed() {
            return Ok(());
        }
        self.data = LZ77.compress(self.header_version, &self.data, 0)?.into_vec().into();
        self.info.compressed = true;
        Ok(())
    }

    /// Returns a reference to the code of this [`Overlay`].
    pub fn code(&self) -> &[u8] {
        &self.data[..self.code_size() as usize]
    }

    /// Returns a reference to the full data of this [`Overlay`].
    pub fn full_data(&self) -> &[u8] {
        &self.data
    }

    /// Returns a reference to the info of this [`Overlay`].
    pub fn info(&self) -> &OverlayInfo {
        &self.info
    }
}

/// Info of an [`Overlay`], similar to an entry in the overlay table.
#[derive(Serialize, Deserialize, Clone)]
pub struct OverlayInfo {
    /// Overlay ID.
    pub id: u32,
    /// Base address.
    pub base_address: u32,
    /// Initialized size.
    pub code_size: u32,
    /// Uninitialized size.
    pub bss_size: u32,
    /// Offset to start of .ctor section.
    pub ctor_start: u32,
    /// Offset to end of .ctor section.
    pub ctor_end: u32,
    /// File ID for the FAT.
    pub file_id: u32,
    /// Whether the overlay is compressed.
    pub compressed: bool,
}

impl OverlayInfo {
    /// Creates a new [`OverlayInfo`] from raw data.
    pub fn new(overlay: &raw::Overlay) -> Self {
        Self {
            id: overlay.id,
            base_address: overlay.base_addr,
            code_size: overlay.code_size,
            bss_size: overlay.bss_size,
            ctor_start: overlay.ctor_start,
            ctor_end: overlay.ctor_end,
            file_id: overlay.file_id,
            compressed: overlay.compressed.is_compressed() != 0,
        }
    }
}
