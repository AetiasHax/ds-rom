use std::borrow::Cow;

use super::raw::{AutoloadInfo, AutoloadKind};

pub struct Autoload<'a> {
    data: Cow<'a, [u8]>,
    info: AutoloadInfo,
}

impl<'a> Autoload<'a> {
    pub fn new<T: Into<Cow<'a, [u8]>>>(data: T, info: AutoloadInfo) -> Self {
        Self { data: data.into(), info }
    }

    pub fn code(&self) -> &[u8] {
        &self.data[..self.info.code_size as usize]
    }

    pub fn full_data(&self) -> &[u8] {
        &self.data
    }

    pub fn base_address(&self) -> u32 {
        self.info.base_address
    }

    pub fn kind(&self) -> AutoloadKind {
        self.info.kind()
    }

    pub fn bss_size(&self) -> u32 {
        self.info.bss_size
    }

    pub fn info(&self) -> &AutoloadInfo {
        &self.info
    }
}
