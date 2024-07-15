use serde::{Deserialize, Serialize};

use super::raw;

#[derive(Serialize, Deserialize)]
pub struct BuildInfo {
    pub autoload_infos_start: u32,
    pub autoload_infos_end: u32,
    pub autoload_blocks: u32,
    pub bss_start: u32,
    pub bss_end: u32,
    pub sdk_version: u32,
}

impl From<raw::BuildInfo> for BuildInfo {
    fn from(raw: raw::BuildInfo) -> Self {
        Self {
            autoload_infos_start: raw.autoload_infos_start,
            autoload_infos_end: raw.autoload_infos_end,
            autoload_blocks: raw.autoload_blocks,
            bss_start: raw.bss_start,
            bss_end: raw.bss_end,
            sdk_version: raw.sdk_version,
        }
    }
}
