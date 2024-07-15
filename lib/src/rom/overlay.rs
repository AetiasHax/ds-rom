use std::{borrow::Cow, io};

use serde::{Deserialize, Serialize};

use crate::compress::lz77::Lz77;

use super::raw::{self, FileAlloc, OverlayCompressedSize};

#[derive(Clone)]
pub struct Overlay<'a> {
    info: OverlayInfo,
    data: Cow<'a, [u8]>,
}

const LZ77: Lz77 = Lz77 {};

impl<'a> Overlay<'a> {
    pub fn parse(overlay: &raw::Overlay, fat: &[FileAlloc], rom: &'a raw::Rom) -> Self {
        let alloc = fat[overlay.file_id as usize];
        let data = &rom.data()[alloc.range()];
        Self { info: OverlayInfo::new(overlay), data: Cow::Borrowed(data) }
    }

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

    pub fn id(&self) -> u32 {
        self.info.id
    }

    pub fn base_address(&self) -> u32 {
        self.info.base_address
    }

    pub fn code_size(&self) -> u32 {
        self.info.code_size
    }

    pub fn bss_size(&self) -> u32 {
        self.info.bss_size
    }

    pub fn ctor_start(&self) -> u32 {
        self.info.ctor_start
    }

    pub fn ctor_end(&self) -> u32 {
        self.info.ctor_end
    }

    pub fn file_id(&self) -> u32 {
        self.info.file_id
    }

    pub fn is_compressed(&self) -> bool {
        self.info.compressed
    }

    pub fn decompress(&mut self) {
        if !self.is_compressed() {
            return;
        }
        self.data = LZ77.decompress(&self.data).into_vec().into();
        self.info.compressed = false;
    }

    pub fn compress(&mut self) -> Result<(), io::Error> {
        if self.is_compressed() {
            return Ok(());
        }
        self.data = LZ77.compress(&self.data, 0)?.into_vec().into();
        self.info.compressed = true;
        Ok(())
    }

    pub fn code(&self) -> &[u8] {
        &self.data[..self.code_size() as usize]
    }

    pub fn full_data(&self) -> &[u8] {
        &self.data
    }

    pub fn info(&self) -> &OverlayInfo {
        &self.info
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct OverlayInfo {
    id: u32,
    base_address: u32,
    code_size: u32,
    bss_size: u32,
    ctor_start: u32,
    ctor_end: u32,
    file_id: u32,
    compressed: bool,
}

impl OverlayInfo {
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
