use std::borrow::Cow;

use serde::{Deserialize, Serialize};

pub struct Arm7<'a> {
    data: Cow<'a, [u8]>,
    offsets: Arm7Offsets,
}

#[derive(Serialize, Deserialize)]
pub struct Arm7Offsets {
    pub base_address: u32,
    pub entry_function: u32,
    pub build_info: u32,
    pub autoload_callback: u32,
}

impl<'a> Arm7<'a> {
    pub fn new<T: Into<Cow<'a, [u8]>>>(data: T, offsets: Arm7Offsets) -> Self {
        Self { data: data.into(), offsets }
    }

    pub fn full_data(&self) -> &[u8] {
        &self.data
    }

    pub fn base_address(&self) -> u32 {
        self.offsets.base_address
    }

    pub fn entry_function(&self) -> u32 {
        self.offsets.entry_function
    }

    pub fn build_info_offset(&self) -> u32 {
        self.offsets.build_info
    }

    pub fn autoload_callback(&self) -> u32 {
        self.offsets.autoload_callback
    }

    pub fn offsets(&self) -> &Arm7Offsets {
        &self.offsets
    }
}
