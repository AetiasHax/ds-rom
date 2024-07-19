use std::borrow::Cow;

use serde::{Deserialize, Serialize};

/// ARM7 program.
pub struct Arm7<'a> {
    data: Cow<'a, [u8]>,
    offsets: Arm7Offsets,
}

/// Offsets in the ARM7 program.
#[derive(Serialize, Deserialize)]
pub struct Arm7Offsets {
    /// Base address.
    pub base_address: u32,
    /// Entrypoint function address.
    pub entry_function: u32,
    /// Build info offset.
    pub build_info: u32,
    /// Autoload callback address.
    pub autoload_callback: u32,
}

impl<'a> Arm7<'a> {
    /// Creates a new ARM7 program from raw data.
    pub fn new<T: Into<Cow<'a, [u8]>>>(data: T, offsets: Arm7Offsets) -> Self {
        Self { data: data.into(), offsets }
    }

    /// Returns a reference to the full data.
    pub fn full_data(&self) -> &[u8] {
        &self.data
    }

    /// Returns the base address of this.
    pub fn base_address(&self) -> u32 {
        self.offsets.base_address
    }

    /// Returns the entrypoint function address.
    pub fn entry_function(&self) -> u32 {
        self.offsets.entry_function
    }

    /// Returns the build info offset.
    pub fn build_info_offset(&self) -> u32 {
        self.offsets.build_info
    }

    /// Returns the autoload callback address.
    pub fn autoload_callback(&self) -> u32 {
        self.offsets.autoload_callback
    }

    /// Returns a reference to the ARM7 offsets.
    pub fn offsets(&self) -> &Arm7Offsets {
        &self.offsets
    }
}
