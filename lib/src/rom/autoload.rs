use std::borrow::Cow;

use snafu::Snafu;

use super::raw::{AutoloadInfo, AutoloadKind};
use crate::error::{DataOutOfBoundsError, OverflowError};

/// An autoload block.
pub struct Autoload<'a> {
    data: Cow<'a, [u8]>,
    info: AutoloadInfo,
    end_address: u32,
}

/// Errors related to [`Autoload`].
#[derive(Debug, Snafu)]
pub enum AutoloadError {
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

impl<'a> Autoload<'a> {
    /// Creates a new autoload block from raw data.
    pub fn new<T: Into<Cow<'a, [u8]>>>(data: T, info: AutoloadInfo) -> Result<Self, AutoloadError> {
        let code_end = info
            .base_address()
            .checked_add(info.code_size())
            .ok_or_else(|| OverflowError::new("autoload code end address"))?;
        let end_address = code_end.checked_add(info.bss_size()).ok_or_else(|| OverflowError::new("autoload end address"))?;

        let data = data.into();

        if info.code_size() as usize > data.len() {
            Err(DataOutOfBoundsError::new("autoload data", info.base_address()..code_end))?;
        }

        Ok(Self { data, info, end_address })
    }

    /// Returns a reference to the code of this [`Autoload`].
    pub fn code(&self) -> &[u8] {
        #[allow(clippy::indexing_slicing)] // range was checked in Autoload::new()
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
        self.end_address
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
