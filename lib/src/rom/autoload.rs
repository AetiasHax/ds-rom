use std::borrow::Cow;

use super::raw::{AutoloadInfo, AutoloadKind};

/// An autoload block.
pub struct Autoload<'a> {
    data: Cow<'a, [u8]>,
    info: AutoloadInfo,
}

impl<'a> Autoload<'a> {
    /// Creates a new autoload block from raw data.
    pub fn new<T: Into<Cow<'a, [u8]>>>(data: T, info: AutoloadInfo) -> Self {
        Self { data: data.into(), info }
    }

    /// Returns a reference to the code of this [`Autoload`].
    pub fn code(&self) -> &[u8] {
        &self.data[..self.info.code_size() as usize]
    }

    /// Returns a reference to the full data of this [`Autoload`].
    pub fn full_data(&self) -> &[u8] {
        &self.data
    }

    /// Consumes this [`Autoload`] and returns the data.
    pub fn into_data(self) -> Box<[u8]> {
        self.data.into_owned().into_boxed_slice()
    }

    /// Returns the base address of this [`Autoload`].
    pub fn base_address(&self) -> u32 {
        self.info.base_address()
    }

    /// Returns the end address of this [`Autoload`].
    pub fn end_address(&self) -> u32 {
        self.info.base_address() + self.info.code_size() + self.info.bss_size()
    }

    /// Returns the kind of this [`Autoload`].
    pub fn kind(&self) -> AutoloadKind {
        self.info.kind()
    }

    /// Returns the size of the uninitialized data of this [`Autoload`].
    pub fn bss_size(&self) -> u32 {
        self.info.bss_size()
    }

    /// Returns a reference to the info of this [`Autoload`].
    pub fn info(&self) -> &AutoloadInfo {
        &self.info
    }
}
