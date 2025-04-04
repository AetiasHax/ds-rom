use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Config file mainly consisting of paths to extracted files.
#[derive(Serialize, Deserialize, Clone)]
pub struct RomConfig {
    /// Byte value to append between ROM sections
    pub padding_value: u8,

    /// Path to header YAML
    pub header: PathBuf,
    /// Path to header logo PNG
    pub header_logo: PathBuf,

    /// Path to ARM9 binary
    pub arm9_bin: PathBuf,
    /// Path to ARM9 YAML
    pub arm9_config: PathBuf,

    /// Path to ARM7 binary
    pub arm7_bin: PathBuf,
    /// Path to ARM7 YAML
    pub arm7_config: PathBuf,

    /// Path to ITCM files
    pub itcm: RomConfigAutoload,
    /// Path to DTCM files
    pub dtcm: RomConfigAutoload,
    /// Path to unknown autoloads
    #[serde(skip_serializing_if = "Vec::is_empty", default = "Vec::new")]
    pub unknown_autoloads: Vec<RomConfigAutoload>,

    /// Path to ARM9 overlays YAML
    pub arm9_overlays: Option<PathBuf>,
    /// Path to ARM7 overlays YAML
    pub arm7_overlays: Option<PathBuf>,

    /// Path to banner YAML
    pub banner: PathBuf,

    /// Path to asset files directory
    pub files_dir: PathBuf,
    /// Path to path order file
    pub path_order: PathBuf,

    /// Path to HMAC SHA1 key file for ARM9
    pub arm9_hmac_sha1_key: Option<PathBuf>,

    /// Alignment of ROM sections
    pub alignment: RomConfigAlignment,
}

/// Path to autoload files
#[derive(Serialize, Deserialize, Clone)]
pub struct RomConfigAutoload {
    /// Path to binary
    pub bin: PathBuf,
    /// Path to YAML
    pub config: PathBuf,
}

/// Alignment of ROM sections.
#[derive(Serialize, Deserialize, Clone)]
pub struct RomConfigAlignment {
    /// Alignment of the ARM9 program.
    pub arm9: u32,
    /// Alignment of the ARM9 overlay table.
    pub arm9_overlay_table: u32,
    /// Alignment of each ARM9 overlay file.
    pub arm9_overlay: u32,
    /// Alignment of the ARM7 program.
    pub arm7: u32,
    /// Alignment of the ARM7 overlay table.
    pub arm7_overlay_table: u32,
    /// Alignment of each ARM7 overlay file.
    pub arm7_overlay: u32,
    /// Alignment of the file name table.
    pub file_name_table: u32,
    /// Alignment of the file allocation table.
    pub file_allocation_table: u32,
    /// Alignment of the banner.
    pub banner: u32,
    /// Alignment of the file image block.
    pub file_image_block: u32,
    /// Alignment of each file.
    pub file: u32,
}
