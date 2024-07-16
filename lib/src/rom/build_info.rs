use serde::{Deserialize, Serialize};

use super::raw;

#[derive(Serialize, Deserialize)]
pub struct BuildInfo {
    pub bss_start: u32,
    pub bss_end: u32,
    pub sdk_version: u32,
}

impl From<raw::BuildInfo> for BuildInfo {
    fn from(raw: raw::BuildInfo) -> Self {
        Self { bss_start: raw.bss_start, bss_end: raw.bss_end, sdk_version: raw.sdk_version }
    }
}

impl BuildInfo {
    pub fn assign_to_raw(&self, build_info: &mut raw::BuildInfo) {
        build_info.bss_start = self.bss_start;
        build_info.bss_end = self.bss_end;
        build_info.sdk_version = self.sdk_version;
    }
}
