use serde::{Deserialize, Serialize};

use super::raw;

/// Build info for the ARM9 program.
#[derive(Serialize, Deserialize)]
pub struct BuildInfo {
    /// Start of the uninitialized section.
    pub bss_start: u32,
    /// End of the uninitialized section.
    pub bss_end: u32,
    /// SDK version? See [`super::raw::BuildInfo::sdk_version`].
    pub sdk_version: u32,
}

impl From<raw::BuildInfo> for BuildInfo {
    fn from(raw: raw::BuildInfo) -> Self {
        Self { bss_start: raw.bss_start, bss_end: raw.bss_end, sdk_version: raw.sdk_version }
    }
}

impl BuildInfo {
    /// Assigns values in this build info to a raw build info.
    pub fn assign_to_raw(&self, build_info: &mut raw::BuildInfo) {
        build_info.bss_start = self.bss_start;
        build_info.bss_end = self.bss_end;
        build_info.sdk_version = self.sdk_version;
    }
}
