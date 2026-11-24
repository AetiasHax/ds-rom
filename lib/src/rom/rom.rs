use std::{
    backtrace::Backtrace,
    borrow::Cow,
    io::{self, Write},
    mem::size_of,
    path::Path,
};

use serde::{Deserialize, Serialize};
use snafu::Snafu;

use super::{
    Arm7, Arm9, Arm9AutoloadError, Arm9Error, Arm9HmacSha1KeyError, Arm9Offsets, Arm9OverlaySignaturesError, Autoload, Banner,
    BannerError, BannerImageError, BuildInfo, Digest, DigestError, DsiProgram, FileBuildError, FileParseError, FileSystem,
    Header, HeaderBuildError, Logo, LogoError, LogoLoadError, LogoSaveError, Overlay, OverlayError, OverlayInfo,
    OverlayOptions, OverlayTable, RomConfigAutoload, RomConfigDsi, RomConfigUnknownAutoload,
    raw::{
        self, Arm9Footer, HmacSha1Signature, ProgramOffset, RawArm9Error, RawBannerError, RawBuildInfoError, RawFatError,
        RawFntError, RawHeaderError, RomAlignmentsError, TableOffset,
    },
};
use crate::{
    compress::lz77::{Lz77CompressError, Lz77DecompressError},
    crypto::{
        blowfish::BlowfishKey,
        dsprot::{DsProtDecryptOptions, DsProtEncryptOptions, DsProtState},
        hmac_sha1::{HmacSha1, HmacSha1FromBytesError},
        modcrypt::Modcrypt,
    },
    error::OverflowError,
    io::{FileError, create_dir_all, create_file, create_file_and_dirs, open_file, read_file, read_to_string},
    rom::{
        Arm9DsProtInfoError, Arm9WithTcmsOptions, AutoloadError, FileSystemLoadError, FileSystemPathOrderError,
        FileSystemTraverseError, HeaderPadding, OverlayDsProtError, RomConfig,
        raw::{
            DSI_REGION_UNIT, FileAlloc, MultibootSignature, RawArm7Error, RawDsiProgramError, RawMultibootSignatureError,
            RawOverlayError,
        },
    },
    writer::{ByteWriter, ByteWriterError, align_up},
};

/// A plain ROM.
pub struct Rom<'a> {
    header: Header,
    header_logo: Logo,
    header_padding: Option<HeaderPadding>,
    arm9: Arm9<'a>,
    arm9_overlay_table: OverlayTable<'a>,
    arm7: Arm7<'a>,
    arm7_overlay_table: OverlayTable<'a>,
    banner: Banner,
    files: FileSystem<'a>,
    multiboot_signature: Option<MultibootSignature>,
    dsi: Option<DsiArea<'a>>,
    /// SHA1-HMAC used for overlay signatures and, on DSi titles, for the digest tables and content hashes.
    hmac_sha1: Option<HmacSha1>,

    path_order: Vec<String>,
    config: RomConfig,
}

/// The area which holds the DSi-exclusive programs.
pub struct DsiArea<'a> {
    /// ARM9i program, stored decrypted.
    pub arm9i: DsiProgram<'a>,
    /// ARM7i program, stored decrypted.
    pub arm7i: DsiProgram<'a>,
    /// Filler between the DS and DSi areas, see [`RomConfigDsi::region_padding`].
    pub region_padding: Box<[u8]>,
}

/// Errors related to [`Rom::extract`].
#[derive(Debug, Snafu)]
pub enum RomExtractError {
    /// See [`RawHeaderError`].
    #[snafu(transparent)]
    RawHeader {
        /// Source error.
        source: RawHeaderError,
    },
    /// See [`LogoError`].
    #[snafu(transparent)]
    Logo {
        /// Source error.
        source: LogoError,
    },
    /// See [`RawOverlayError`].
    #[snafu(transparent)]
    RawOverlay {
        /// Source error.
        source: RawOverlayError,
    },
    /// See [`RawFntError`].
    #[snafu(transparent)]
    RawFnt {
        /// Source error.
        source: RawFntError,
    },
    /// See [`RawFatError`].
    #[snafu(transparent)]
    RawFat {
        /// Source error.
        source: RawFatError,
    },
    /// See [`RawBannerError`].
    #[snafu(transparent)]
    RawBanner {
        /// Source error.
        source: RawBannerError,
    },
    /// See [`FileParseError`].
    #[snafu(transparent)]
    FileParse {
        /// Source error.
        source: FileParseError,
    },
    /// See [`RawArm9Error`].
    #[snafu(transparent)]
    RawArm9 {
        /// Source error.
        source: RawArm9Error,
    },
    /// See [`Arm9AutoloadError`]
    #[snafu(transparent)]
    Arm9Autoload {
        /// Source error.
        source: Arm9AutoloadError,
    },
    /// See [`RawBuildInfoError`].
    #[snafu(transparent)]
    RawBuildInfo {
        /// Source error.
        source: RawBuildInfoError,
    },
    /// See [`Arm9Error`].
    #[snafu(transparent)]
    Arm9 {
        /// Source error.
        source: Arm9Error,
    },
    /// Occurs when a DSi ROM has no ARM9 SHA1-HMAC key, which is needed to decrypt and verify its DSi area.
    #[snafu(display("a DSi ROM needs an ARM9 SHA1-HMAC key but none was found:\n{backtrace}"))]
    NoDsiHmacSha1Key {
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// See [`RomAlignmentsError`].
    #[snafu(transparent)]
    RomAlignments {
        /// Source error.
        source: RomAlignmentsError,
    },
    /// See [`OverlayError`].
    #[snafu(transparent)]
    Overlay {
        /// Source error.
        source: OverlayError,
    },
    /// See [`Arm9HmacSha1KeyError`].
    #[snafu(transparent)]
    Arm9HmacSha1Key {
        /// Source error.
        source: Arm9HmacSha1KeyError,
    },
    /// See [`RawMultibootSignatureError`].
    #[snafu(transparent)]
    RawMultibootSignature {
        /// Source error.
        source: RawMultibootSignatureError,
    },
    /// See [`Arm9DsProtInfoError`].
    #[snafu(transparent)]
    Arm9DsProtInfo {
        /// Source error.
        source: Arm9DsProtInfoError,
    },
    /// See [`OverlayDsProtError`].
    #[snafu(transparent)]
    OverlayDsProt {
        /// Source error.
        source: OverlayDsProtError,
    },
    /// See [`Lz77DecompressError`].
    #[snafu(transparent)]
    Lz77Decompress {
        /// Source error.
        source: Lz77DecompressError,
    },
    /// See [`RawDsiProgramError`].
    #[snafu(transparent)]
    RawDsiProgram {
        /// Source error.
        source: RawDsiProgramError,
    },
    /// See [`RawArm7Error`].
    #[snafu(transparent)]
    RawArm7 {
        /// Source error.
        source: RawArm7Error,
    },
    /// See [`OverflowError`].
    #[snafu(transparent)]
    Overflow {
        /// Source error.
        source: OverflowError,
    },
    /// See [`FileSystemPathOrderError`].
    #[snafu(transparent)]
    FileSystemPathOrder {
        /// Source error.
        source: FileSystemPathOrderError,
    },
}

/// Errors related to [`Rom::build`].
#[derive(Snafu, Debug)]
pub enum RomBuildError {
    /// See [`io::Error`].
    #[snafu(transparent)]
    Io {
        /// Source error.
        source: io::Error,
    },
    /// See [`FileBuildError`].
    #[snafu(transparent)]
    FileBuild {
        /// Source error.
        source: FileBuildError,
    },
    /// See [`BannerError`].
    #[snafu(transparent)]
    Banner {
        /// Source error.
        source: BannerError,
    },
    /// See [`HeaderBuildError`].
    #[snafu(transparent)]
    HeaderBuild {
        /// Source error.
        source: HeaderBuildError,
    },
    /// See [`DigestError`].
    #[snafu(transparent)]
    Digest {
        /// Source error.
        source: DigestError,
    },
    /// See [`Arm9Error`].
    #[snafu(transparent)]
    Arm9 {
        /// Source error.
        source: Arm9Error,
    },
    /// See [`RawBuildInfoError`].
    #[snafu(transparent)]
    RawBuildInfo {
        /// Source error.
        source: RawBuildInfoError,
    },
    /// Occurs when the header has a DSi section but the ROM has no DSi area, or vice versa.
    #[snafu(display("a DSi ROM needs both a DSi header section and a DSi area, but only one is present:\n{backtrace}"))]
    DsiIncomplete {
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// Occurs when a DSi ROM is built without the SHA1-HMAC key needed for its digest tables and content hashes.
    #[snafu(display("a DSi ROM needs an ARM9 SHA1-HMAC key to compute its digest tables:\n{backtrace}"))]
    DsiHmacSha1KeyNeeded {
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// Occurs when a DSi ROM is built without the Blowfish key needed to encrypt its ARM9 secure area.
    #[snafu(display("a DSi ROM needs a blowfish key to hash its encrypted ARM9 secure area:\n{backtrace}"))]
    DsiBlowfishKeyNeeded {
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// See [`OverflowError`].
    #[snafu(transparent)]
    Overflow {
        /// Source error.
        source: OverflowError,
    },
    /// Occurs when writing the ROM fails, e.g. because it grows past 4 GiB or a config alignment is not a power of two.
    #[snafu(transparent)]
    ByteWriter {
        /// Source error.
        source: ByteWriterError,
    },
    /// Occurs when trying to access a part of the ROM that is already written, but the access goes
    /// out of bounds.
    #[snafu(display("could not access {what} because it is out of bounds:\n{backtrace}"))]
    OutOfBoundsAccess {
        /// The value being accessed.
        what: Cow<'static, str>,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// See [`FileSystemTraverseError`].
    #[snafu(transparent)]
    FileSystemTraverse {
        /// Source error.
        source: FileSystemTraverseError,
    },
    /// Occurs when an overlay's file ID is not a valid file ID. File IDs must be less than 0xf000, where directory IDs
    /// begin.
    #[snafu(display("overlay {overlay_id} has file ID {file_id:#x}, but file IDs must be less than 0xf000:\n{backtrace}"))]
    InvalidOverlayFileId {
        /// The overlay's ID.
        overlay_id: u16,
        /// The overlay's file ID.
        file_id: u32,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
}

/// Errors related to [`Rom::save`] and [`Rom::load`].
#[derive(Snafu, Debug)]
pub enum RomSaveError {
    /// Occurs when the ROM is encrypted but no Blowfish key was provided.
    #[snafu(display("blowfish key is required because ARM9 program is encrypted"))]
    BlowfishKeyNeeded,
    /// See [`io::Error`].
    #[snafu(transparent)]
    Io {
        /// Source error.
        source: io::Error,
    },
    /// See [`FileError`].
    #[snafu(transparent)]
    File {
        /// Source error.
        source: FileError,
    },
    /// See [`serde_saphyr::Error`].
    #[snafu(transparent)]
    SerdeSaphyrDeserialize {
        /// Source error.
        source: serde_saphyr::Error,
    },
    /// See [`serde_saphyr::ser_error::Error`].
    #[snafu(transparent)]
    SerdeSaphyrSerialize {
        /// Source error.
        source: serde_saphyr::ser_error::Error,
    },
    /// See [`LogoSaveError`].
    #[snafu(transparent)]
    LogoSave {
        /// Source error.
        source: LogoSaveError,
    },
    /// See [`LogoLoadError`].
    #[snafu(transparent)]
    LogoLoad {
        /// Source error.
        source: LogoLoadError,
    },
    /// See [`RawBuildInfoError`].
    #[snafu(transparent)]
    RawBuildInfo {
        /// Source error.
        source: RawBuildInfoError,
    },
    /// See [`Arm9Error`].
    #[snafu(transparent)]
    Arm9 {
        /// Source error.
        source: Arm9Error,
    },
    /// See [`Arm9AutoloadError`].
    #[snafu(transparent)]
    Arm9Autoload {
        /// Source error.
        source: Arm9AutoloadError,
    },
    /// See [`BannerImageError`].
    #[snafu(transparent)]
    BannerImage {
        /// Source error.
        source: BannerImageError,
    },
    /// See [`Lz77DecompressError`].
    #[snafu(transparent)]
    Lz77Decompress {
        /// Source error.
        source: Lz77DecompressError,
    },
    /// See [`Lz77CompressError`].
    #[snafu(transparent)]
    Lz77Compress {
        /// Source error.
        source: Lz77CompressError,
    },
    /// See [`OverlayError`].
    #[snafu(transparent)]
    Overlay {
        /// Source error.
        source: OverlayError,
    },
    /// See [`Arm9OverlaySignaturesError`].
    #[snafu(transparent)]
    HmacSha1FromBytes {
        /// Source error.
        source: HmacSha1FromBytesError,
    },
    /// See [`Arm9HmacSha1KeyError`].
    #[snafu(transparent)]
    Arm9HmacSha1Key {
        /// Source error.
        source: Arm9HmacSha1KeyError,
    },
    /// See [`Arm9OverlaySignaturesError`].
    #[snafu(transparent)]
    Arm9OverlaySignatures {
        /// Source error.
        source: Arm9OverlaySignaturesError,
    },
    /// Occurs when the HMAC-SHA1 key was not provided for a signed overlay.
    #[snafu(display("HMAC-SHA1 key was not provided for a signed overlay:\n{backtrace}"))]
    NoHmacSha1Key {
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// Occurs when an autoload was not found in the config.
    #[snafu(display("autoload index {index} not found in config:\n{backtrace}"))]
    AutoloadNotFound {
        /// The index of the autoload that was missing.
        index: u32,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// See [`Arm9DsProtInfoError`].
    #[snafu(transparent)]
    Arm9DsProtInfo {
        /// Source error.
        source: Arm9DsProtInfoError,
    },
    /// See [`OverlayDsProtError`].
    #[snafu(transparent)]
    OverlayDsProt {
        /// Source error.
        source: OverlayDsProtError,
    },
    /// Occurs when the provided config file path has no parent directory.
    #[snafu(display("{what} has no parent directory: {path}\n{backtrace}"))]
    NoPathParent {
        /// The kind of path causing the error.
        what: Cow<'static, str>,
        /// The config file path.
        path: String,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// See [`FileSystemLoadError`].
    #[snafu(transparent)]
    FileSystemLoad {
        /// Source error.
        source: FileSystemLoadError,
    },
    /// See [`FileSystemTraverseError`].
    #[snafu(transparent)]
    FileSystemTraverse {
        /// Source error.
        source: FileSystemTraverseError,
    },
    /// See [`AutoloadError`].
    #[snafu(transparent)]
    Autoload {
        /// Source error.
        source: AutoloadError,
    },
}

/// Config file for the ARM9 main module.
#[derive(Serialize, Deserialize)]
pub struct Arm9BuildConfig {
    /// Various offsets within the ARM9 module.
    #[serde(flatten)]
    pub offsets: Arm9Offsets,
    /// Whether this module is encrypted in the ROM.
    pub encrypted: bool,
    /// Whether this module is compressed in the ROM.
    pub compressed: bool,
    /// Whether this module is followed by an ARM9 footer in the ROM.
    #[serde(default = "default_true")]
    pub footer: bool,
    /// Build info for this module.
    #[serde(flatten)]
    pub build_info: BuildInfo,
    /// Information about DS Protect.
    #[serde(default, skip_serializing_if = "DsProtState::is_none")]
    pub dsprot_state: DsProtState,
}

/// Overlay configuration, extending [`OverlayInfo`] with more fields.
#[derive(Serialize, Deserialize)]
pub struct OverlayConfig {
    /// See [`OverlayInfo`].
    #[serde(flatten)]
    pub info: OverlayInfo,
    /// Whether this overlay is signed.
    pub signed: bool,
    /// Name of binary file.
    pub file_name: String,
    /// Stores information about DS Protect functions that were decrypted in this overlay.
    #[serde(default, skip_serializing_if = "DsProtState::is_none")]
    pub dsprot: DsProtState,
}

/// Configuration for the overlay table, used for both ARM9 and ARM7 overlays.
#[derive(Serialize, Deserialize)]
pub struct OverlayTableConfig {
    /// Whether the overlay table has an HMAC-SHA1 signature.
    pub table_signed: bool,
    /// Overlay table HMAC-SHA1 signature. NOTE: This field is temporary! A bug in the DS standard library causes this
    /// signature to be computed incorrectly, and we haven't replicated this bug in our code yet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub table_signature: Option<HmacSha1Signature>,
    /// List of overlays.
    pub overlays: Vec<OverlayConfig>,
}

impl<'a> Rom<'a> {
    /// Loads a ROM from a path generated by [`Self::save`].
    ///
    /// # Errors
    ///
    /// This function will return an error if there's a file missing or the file has an invalid format.
    pub fn load<P: AsRef<Path>>(config_path: P, options: RomLoadOptions) -> Result<Self, RomSaveError> {
        let config_path = config_path.as_ref();
        log::info!("Loading ROM from {}", config_path.display());

        let config: RomConfig = serde_saphyr::from_reader(open_file(config_path)?)?;
        let path = config_path
            .parent()
            .ok_or_else(|| NoPathParentSnafu { what: "config path", path: config_path.to_string_lossy() }.build())?;

        // --------------------- Load header ---------------------
        let (header, header_logo, header_padding) = if options.load_header {
            let header: Header = serde_saphyr::from_reader(open_file(path.join(&config.header))?)?;
            let header_logo = Logo::from_png(path.join(&config.header_logo))?;
            let header_padding = if let Some(header_padding_path) = &config.header_padding {
                Some(HeaderPadding::from_file(path.join(header_padding_path))?)
            } else {
                None
            };
            (header, header_logo, header_padding)
        } else {
            Default::default()
        };

        // --------------------- Load ARM9 program ---------------------
        let arm9_build_config: Arm9BuildConfig = serde_saphyr::from_reader(open_file(path.join(&config.arm9_config))?)?;
        let arm9 = read_file(path.join(&config.arm9_bin))?;

        // --------------------- Load autoloads ---------------------
        let mut autoloads = vec![];

        let itcm = read_file(path.join(&config.itcm.bin))?;
        let itcm_info = serde_saphyr::from_reader(open_file(path.join(&config.itcm.config))?)?;
        let itcm = Autoload::new(itcm, itcm_info)?;
        autoloads.push(itcm);

        let dtcm = read_file(path.join(&config.dtcm.bin))?;
        let dtcm_info = serde_saphyr::from_reader(open_file(path.join(&config.dtcm.config))?)?;
        let dtcm = Autoload::new(dtcm, dtcm_info)?;
        autoloads.push(dtcm);

        for unknown_autoload in &config.unknown_autoloads {
            let autoload = read_file(path.join(&unknown_autoload.files.bin))?;
            let autoload_info = serde_saphyr::from_reader(open_file(path.join(&unknown_autoload.files.config))?)?;
            let autoload = Autoload::new(autoload, autoload_info)?;
            autoloads.push(autoload);
        }

        autoloads.sort_by_key(|autoload| autoload.kind());

        // --------------------- Load HMAC SHA1 key ---------------------
        let arm9_hmac_sha1 = if let Some(hmac_sha1_key_file) = &config.arm9_hmac_sha1_key {
            let hmac_sha1_key = read_file(path.join(hmac_sha1_key_file))?;
            Some(HmacSha1::try_from(hmac_sha1_key.as_ref())?)
        } else {
            None
        };

        // --------------------- Load ARM9 overlays ---------------------
        let arm9_overlays = if let Some(arm9_overlays_config) = &config.arm9_overlays {
            Self::load_overlays(&path.join(arm9_overlays_config), "arm9", arm9_hmac_sha1.as_ref(), &options)?
        } else {
            Default::default()
        };

        // --------------------- Build ARM9 program ---------------------
        let mut arm9 = Arm9::with_autoloads(arm9, &autoloads, arm9_build_config.offsets, Arm9WithTcmsOptions {
            originally_compressed: arm9_build_config.compressed,
            originally_encrypted: arm9_build_config.encrypted,
            dsprot_state: arm9_build_config.dsprot_state,
            has_footer: arm9_build_config.footer,
        })?;
        arm9_build_config.build_info.assign_to_raw(arm9.build_info_mut()?);
        arm9.update_overlay_signatures(&arm9_overlays)?;
        if arm9.dsprot_state().is_unencrypted() && options.encrypt {
            log::info!("Encrypting DS Protect in ARM9 program");
            arm9.encrypt_dsprot(&DsProtEncryptOptions::default())?;
        }
        if arm9_build_config.compressed && options.compress {
            log::info!("Compressing ARM9 program");
            arm9.compress()?;
        }
        if arm9_build_config.encrypted && options.encrypt {
            let Some(key) = options.key else {
                return BlowfishKeyNeededSnafu {}.fail();
            };
            log::info!("Encrypting ARM9 program");
            arm9.encrypt(key, header.original.gamecode.to_le_u32())?;
        }

        // --------------------- Load ARM7 overlays ---------------------
        let arm7_overlays = if let Some(arm7_overlays_config) = &config.arm7_overlays {
            Self::load_overlays(&path.join(arm7_overlays_config), "arm7", None, &options)?
        } else {
            Default::default()
        };

        // --------------------- Load ARM7 program ---------------------
        let arm7 = read_file(path.join(&config.arm7_bin))?;
        let arm7_config = serde_saphyr::from_reader(open_file(path.join(&config.arm7_config))?)?;
        let arm7 = Arm7::new(arm7, arm7_config);

        // --------------------- Load banner ---------------------
        let banner = if options.load_banner {
            let banner_path = path.join(&config.banner);
            let banner_dir = banner_path
                .parent()
                .ok_or_else(|| NoPathParentSnafu { what: "banner path", path: banner_path.to_string_lossy() }.build())?;
            let mut banner: Banner = serde_saphyr::from_reader(open_file(&banner_path)?)?;
            banner.images.load(banner_dir)?;
            banner
        } else {
            Default::default()
        };

        // --------------------- Load files ---------------------
        #[allow(clippy::arithmetic_side_effects)] // overlay count is far from usize::MAX
        let num_overlays = arm9_overlays.overlays().len() + arm7_overlays.overlays().len();
        let (files, path_order) = if options.load_files {
            log::info!("Loading ROM assets");
            let files = FileSystem::load(path.join(&config.files_dir), num_overlays)?;
            let path_order =
                read_to_string(path.join(&config.path_order))?.trim().lines().map(|l| l.to_string()).collect::<Vec<_>>();
            (files, path_order)
        } else {
            (FileSystem::new(num_overlays), vec![])
        };

        // --------------------- Load DSi area ---------------------
        let dsi = if let Some(dsi_config) = &config.dsi {
            let arm9i = read_file(path.join(&dsi_config.arm9i_bin))?;
            let arm9i_offsets = serde_saphyr::from_reader(open_file(path.join(&dsi_config.arm9i_config))?)?;
            let arm7i = read_file(path.join(&dsi_config.arm7i_bin))?;
            let arm7i_offsets = serde_saphyr::from_reader(open_file(path.join(&dsi_config.arm7i_config))?)?;
            let region_padding = read_file(path.join(&dsi_config.region_padding))?;
            Some(DsiArea {
                arm9i: DsiProgram::new(arm9i, arm9i_offsets),
                arm7i: DsiProgram::new(arm7i, arm7i_offsets),
                region_padding: region_padding.into_boxed_slice(),
            })
        } else {
            None
        };

        // --------------------- Load multiboot signature ---------------------
        let multiboot_signature = if let Some(multiboot_signature) = config.multiboot_signature.as_ref() {
            serde_saphyr::from_reader(open_file(path.join(multiboot_signature))?)?
        } else {
            None
        };

        Ok(Self {
            header,
            header_logo,
            header_padding,
            arm9,
            arm9_overlay_table: arm9_overlays,
            arm7,
            arm7_overlay_table: arm7_overlays,
            banner,
            files,
            path_order,
            multiboot_signature,
            dsi,
            hmac_sha1: arm9_hmac_sha1,
            config,
        })
    }

    fn load_overlays(
        config_path: &Path,
        processor: &str,
        hmac_sha1: Option<&HmacSha1>,
        options: &RomLoadOptions,
    ) -> Result<OverlayTable<'a>, RomSaveError> {
        let path = config_path
            .parent()
            .ok_or_else(|| NoPathParentSnafu { what: "config path", path: config_path.to_string_lossy() }.build())?;
        let mut overlays = vec![];
        let overlay_table_config: OverlayTableConfig = serde_saphyr::from_reader(open_file(config_path)?)?;
        let num_overlays = overlay_table_config.overlays.len();
        for mut config in overlay_table_config.overlays.into_iter() {
            let data = read_file(path.join(config.file_name))?;
            let compressed = config.info.compressed;
            config.info.compressed = false;
            let mut overlay = Overlay::new(data, OverlayOptions {
                info: config.info,
                originally_compressed: compressed,
                originally_signed: config.signed,
                dsprot_state: config.dsprot,
            })?;

            if overlay.dsprot_state().is_unencrypted() && options.encrypt {
                log::info!("Encrypting DS Protect in {processor} overlay {}", overlay.id());
                overlay.encrypt_dsprot(&DsProtEncryptOptions::default())?;
            }

            if options.compress {
                if compressed {
                    log::info!("Compressing {processor} overlay {}/{}", overlay.id(), num_overlays.saturating_sub(1));
                    overlay.compress()?;
                }

                if config.signed {
                    let Some(hmac_sha1) = hmac_sha1 else {
                        return NoHmacSha1KeySnafu {}.fail();
                    };
                    overlay.sign(hmac_sha1)?;
                }
            }

            overlays.push(overlay);
        }

        let mut overlay_table = OverlayTable::new(overlays);
        if overlay_table_config.table_signed {
            if let Some(signature) = overlay_table_config.table_signature {
                overlay_table.set_signature(signature);
            } else {
                let Some(hmac_sha1) = hmac_sha1 else {
                    return NoHmacSha1KeySnafu {}.fail();
                };
                overlay_table.sign(hmac_sha1);
            }
        }

        Ok(overlay_table)
    }

    /// Saves this ROM to a path as separate files.
    ///
    /// # Errors
    ///
    /// This function will return an error if a file could not be created or the a component of the ROM has an invalid format.
    pub fn save<P: AsRef<Path>>(&self, path: P, key: Option<&BlowfishKey>) -> Result<(), RomSaveError> {
        let path = path.as_ref();
        create_dir_all(path)?;

        log::info!("Saving ROM to directory {}", path.display());

        // --------------------- Save config ---------------------
        serde_saphyr::to_io_writer(&mut create_file_and_dirs(path.join("config.yaml"))?, &self.config)?;

        // --------------------- Save header ---------------------
        serde_saphyr::to_io_writer(&mut create_file_and_dirs(path.join(&self.config.header))?, &self.header)?;
        self.header_logo.save_png(path.join(&self.config.header_logo))?;
        match (self.header_padding.as_ref(), self.config.header_padding.as_ref()) {
            (Some(header_padding), Some(header_padding_path)) => {
                header_padding.save(path.join(header_padding_path))?;
            }
            (None, Some(_)) => log::warn!("Header padding not found, but config requested it to be saved"),
            (Some(_), None) => log::warn!("Header padding found, but config has no place to save it"),
            (None, None) => {}
        }

        // --------------------- Save ARM9 program ---------------------
        let mut plain_arm9 = self.arm9.clone();
        if plain_arm9.is_encrypted() {
            let Some(key) = key else {
                return BlowfishKeyNeededSnafu {}.fail();
            };
            log::info!("Decrypting ARM9 program");
            plain_arm9.decrypt(key, self.header.original.gamecode.to_le_u32())?;
        }
        if plain_arm9.is_compressed()? {
            log::info!("Decompressing ARM9 program");
            plain_arm9.decompress()?;
        }
        if plain_arm9.dsprot_state().is_encrypted() {
            log::info!("Decrypting DS Protect in ARM9 program");
            plain_arm9.decrypt_dsprot(&DsProtDecryptOptions::default())?;
        }
        create_file_and_dirs(path.join(&self.config.arm9_bin))?.write_all(plain_arm9.code()?)?;
        let arm9_build_config = Arm9BuildConfig {
            offsets: *self.arm9.offsets(),
            encrypted: self.arm9.is_encrypted(),
            compressed: self.arm9.is_compressed()?,
            footer: self.arm9.has_footer(),
            build_info: (*self.arm9.build_info()?).into(),
            dsprot_state: plain_arm9.dsprot_state().clone(),
        };
        serde_saphyr::to_io_writer(&mut create_file_and_dirs(path.join(&self.config.arm9_config))?, &arm9_build_config)?;

        // --------------------- Save ARM9 HMAC-SHA1 key ---------------------
        if let Some(arm9_hmac_sha1_key) = plain_arm9.hmac_sha1_key()? {
            if let Some(key_file) = &self.config.arm9_hmac_sha1_key {
                create_file_and_dirs(path.join(key_file))?.write_all(arm9_hmac_sha1_key.as_ref())?;
            }
        } else if self.config.arm9_hmac_sha1_key.is_some() {
            log::warn!("ARM9 HMAC-SHA1 key not found, but config requested it to be saved");
        }

        // --------------------- Save autoloads ---------------------
        for autoload in plain_arm9.autoloads()?.iter() {
            let (bin_path, config_path) = match autoload.kind() {
                raw::AutoloadKind::Itcm => (path.join(&self.config.itcm.bin), path.join(&self.config.itcm.config)),
                raw::AutoloadKind::Dtcm => (path.join(&self.config.dtcm.bin), path.join(&self.config.dtcm.config)),
                raw::AutoloadKind::Unknown(index) => {
                    let unknown_autoload = self
                        .config
                        .unknown_autoloads
                        .iter()
                        .find(|autoload| autoload.index == index)
                        .ok_or_else(|| AutoloadNotFoundSnafu { index }.build())?;
                    (path.join(&unknown_autoload.files.bin), path.join(&unknown_autoload.files.config))
                }
            };
            create_file_and_dirs(bin_path)?.write_all(autoload.code())?;
            serde_saphyr::to_io_writer(&mut create_file_and_dirs(config_path)?, autoload.info())?;
        }

        // --------------------- Save ARM9 overlays ---------------------
        if let Some(arm9_overlays_config) = &self.config.arm9_overlays {
            Self::save_overlays(&path.join(arm9_overlays_config), &self.arm9_overlay_table, "arm9")?;
        }

        // --------------------- Save ARM7 program ---------------------
        create_file_and_dirs(path.join(&self.config.arm7_bin))?.write_all(self.arm7.full_data())?;
        serde_saphyr::to_io_writer(&mut create_file_and_dirs(path.join(&self.config.arm7_config))?, self.arm7.offsets())?;

        // --------------------- Save ARM7 overlays ---------------------
        if let Some(arm7_overlays_config) = &self.config.arm7_overlays {
            Self::save_overlays(&path.join(arm7_overlays_config), &self.arm7_overlay_table, "arm7")?;
        }

        // --------------------- Save banner ---------------------
        {
            let banner_path = path.join(&self.config.banner);
            let banner_dir = banner_path
                .parent()
                .ok_or_else(|| NoPathParentSnafu { what: "bitmap path", path: banner_path.to_string_lossy() }.build())?;
            serde_saphyr::to_io_writer(&mut create_file_and_dirs(&banner_path)?, &self.banner)?;
            self.banner.images.save_bitmap_file(banner_dir)?;
        }

        // --------------------- Save files ---------------------
        {
            log::info!("Saving ROM assets");
            let files_path = path.join(&self.config.files_dir);
            self.files.traverse_files(["/"], |file, path| -> Result<(), RomSaveError> {
                let path = files_path.join(path);
                create_dir_all(&path)?;
                create_file(path.join(file.name()))?.write_all(file.contents())?;
                Ok(())
            })?;
        }
        let mut path_order_file = create_file_and_dirs(path.join(&self.config.path_order))?;
        for path in &self.path_order {
            path_order_file.write_all(path.as_bytes())?;
            path_order_file.write_all("\n".as_bytes())?;
        }

        // --------------------- Save DSi area ---------------------
        match (&self.dsi, &self.config.dsi) {
            (Some(dsi), Some(config)) => {
                create_file_and_dirs(path.join(&config.arm9i_bin))?.write_all(dsi.arm9i.full_data())?;
                serde_saphyr::to_io_writer(&mut create_file_and_dirs(path.join(&config.arm9i_config))?, dsi.arm9i.offsets())?;
                create_file_and_dirs(path.join(&config.arm7i_bin))?.write_all(dsi.arm7i.full_data())?;
                serde_saphyr::to_io_writer(&mut create_file_and_dirs(path.join(&config.arm7i_config))?, dsi.arm7i.offsets())?;
                create_file_and_dirs(path.join(&config.region_padding))?.write_all(&dsi.region_padding)?;
            }
            (None, Some(_)) => log::warn!("DSi area not found, but config requested it to be saved"),
            (Some(_), None) => log::warn!("DSi area found, but config has no place to save it"),
            (None, None) => {}
        }

        // --------------------- Save multiboot signature ---------------------
        if let Some(multiboot_signature) = &self.multiboot_signature {
            if let Some(signature_file) = &self.config.multiboot_signature {
                let file_path = path.join(signature_file);
                serde_saphyr::to_io_writer(&mut create_file_and_dirs(&file_path)?, multiboot_signature)?;
            }
        } else if self.config.multiboot_signature.is_some() {
            log::warn!("Multiboot signature not found, but config requested it to be saved");
        }

        Ok(())
    }

    fn save_overlays(config_path: &Path, overlay_table: &OverlayTable, processor: &str) -> Result<(), RomSaveError> {
        let overlays = overlay_table.overlays();
        if !overlays.is_empty() {
            let overlays_path = config_path.parent().ok_or_else(|| {
                NoPathParentSnafu { what: format!("{processor} overlay config path"), path: config_path.to_string_lossy() }
                    .build()
            })?;
            create_dir_all(overlays_path)?;

            let mut configs = vec![];
            for overlay in overlays {
                let name = format!("ov{:03}", overlay.id());

                let mut plain_overlay = overlay.clone();
                if plain_overlay.is_compressed() {
                    log::info!("Decompressing {processor} overlay {}/{}", overlay.id(), overlays.len().saturating_sub(1));
                    plain_overlay.decompress()?;
                }
                if plain_overlay.dsprot_state().is_encrypted() {
                    log::info!("Decrypting DS Protect in {processor} overlay {}", overlay.id());
                    plain_overlay.decrypt_dsprot(&DsProtDecryptOptions { decode_relocations: false })?;
                }

                configs.push(OverlayConfig {
                    info: overlay.info().clone(),
                    file_name: format!("{name}.bin"),
                    signed: plain_overlay.is_signed(),
                    dsprot: plain_overlay.dsprot_state().clone(),
                });

                create_file(overlays_path.join(format!("{name}.bin")))?.write_all(plain_overlay.code()?)?;
            }

            let overlay_table_config = OverlayTableConfig {
                table_signed: overlay_table.is_signed(),
                table_signature: overlay_table.signature(),
                overlays: configs,
            };
            serde_saphyr::to_io_writer(&mut create_file(config_path)?, &overlay_table_config)?;
        }
        Ok(())
    }

    /// Extracts from a raw ROM.
    ///
    /// # Errors
    ///
    /// This function will return an error if a component is missing from the raw ROM.
    pub fn extract(rom: &'a raw::Rom) -> Result<Self, RomExtractError> {
        let header = rom.header()?;
        log::info!("Extracting from {}", header.title);

        let fnt = rom.fnt()?;
        let fat = rom.fat()?;
        let banner = rom.banner()?;
        let file_root = FileSystem::parse(&fnt, fat, rom)?;
        let path_order = file_root.compute_path_order()?;

        let mut arm9 = rom.arm9()?;
        let mut decompressed_arm9 = arm9.clone();
        decompressed_arm9.decompress()?;

        let arm9_overlays = rom.arm9_overlay_table_with(&decompressed_arm9)?;
        let mut arm9_overlays = OverlayTable::parse_arm9(arm9_overlays, rom, &decompressed_arm9)?;
        let arm7_overlays = rom.arm7_overlay_table()?;
        let arm7_overlays = OverlayTable::parse_arm7(arm7_overlays, rom)?;

        let autoloads = decompressed_arm9.autoloads()?;
        let unknown_autoloads = autoloads
            .iter()
            .filter_map(|autoload| {
                let raw::AutoloadKind::Unknown(index) = autoload.kind() else {
                    return None;
                };
                Some(RomConfigUnknownAutoload {
                    index,
                    files: RomConfigAutoload {
                        bin: format!("arm9/unk_autoload_{index}.bin").into(),
                        config: format!("arm9/unk_autoload_{index}.yaml").into(),
                    },
                })
            })
            .collect();

        let arm9_hmac_sha1_key = decompressed_arm9.hmac_sha1_key()?;
        let has_arm9_hmac_sha1 = arm9_hmac_sha1_key.is_some();
        let hmac_sha1 = arm9_hmac_sha1_key.map(HmacSha1::new);

        let multiboot_signature = rom.multiboot_signature()?;

        let (dsi, dsi_config) = if header.has_dsi_area() {
            if hmac_sha1.is_none() {
                return NoDsiHmacSha1KeySnafu {}.fail();
            }
            let (dsi, dsi_config) = Self::extract_dsi_area(rom, header)?;
            (Some(dsi), Some(dsi_config))
        } else {
            (None, None)
        };

        let alignment = rom.alignments()?;
        let padding = rom.padding_values()?;

        let dsprot_options = DsProtDecryptOptions::default();
        if let Some(result) = decompressed_arm9.decrypt_dsprot(&dsprot_options)? {
            arm9.set_dsprot_state(DsProtState::Encrypted(result.clone()));
        }
        for overlay in arm9_overlays.overlays_mut() {
            let mut decompressed_overlay = overlay.clone();
            decompressed_overlay.decompress()?;
            if let Some(result) = decompressed_overlay.decrypt_dsprot(&dsprot_options)? {
                overlay.set_dsprot_state(DsProtState::Encrypted(result.clone()));
            }
        }

        let header_padding = if header.padding.iter().any(|&x| x != 0) {
            Some(HeaderPadding(header.padding))
        } else {
            None
        };

        let config = RomConfig {
            header: "header.yaml".into(),
            header_logo: "header_logo.png".into(),
            header_padding: header_padding.is_some().then_some("header_padding.bin".into()),
            arm9_bin: "arm9/arm9.bin".into(),
            arm9_config: "arm9/arm9.yaml".into(),
            arm7_bin: "arm7/arm7.bin".into(),
            arm7_config: "arm7/arm7.yaml".into(),
            itcm: RomConfigAutoload { bin: "arm9/itcm.bin".into(), config: "arm9/itcm.yaml".into() },
            unknown_autoloads,
            dtcm: RomConfigAutoload { bin: "arm9/dtcm.bin".into(), config: "arm9/dtcm.yaml".into() },
            arm9_overlays: if arm9_overlays.is_empty() {
                None
            } else {
                Some("arm9_overlays/overlays.yaml".into())
            },
            arm7_overlays: if arm7_overlays.is_empty() {
                None
            } else {
                Some("arm7_overlays/overlays.yaml".into())
            },
            banner: "banner/banner.yaml".into(),
            files_dir: "files/".into(),
            path_order: "path_order.txt".into(),
            multiboot_signature: if multiboot_signature.is_none() {
                None
            } else {
                Some("multiboot_signature.yaml".into())
            },
            arm9_hmac_sha1_key: has_arm9_hmac_sha1.then_some("arm9/hmac_sha1_key.bin".into()),
            dsi: dsi_config,
            alignment,
            padding,
        };

        Ok(Self {
            header: Header::load_raw(header),
            header_logo: Logo::decompress(&header.logo)?,
            header_padding,
            arm9,
            arm9_overlay_table: arm9_overlays,
            arm7: rom.arm7()?,
            arm7_overlay_table: arm7_overlays,
            banner: Banner::load_raw(&banner),
            files: file_root,
            multiboot_signature,
            dsi,
            hmac_sha1,
            path_order,
            config,
        })
    }

    fn extract_dsi_area(rom: &'a raw::Rom, header: &raw::Header) -> Result<(DsiArea<'a>, RomConfigDsi), RomExtractError> {
        let mut arm9i = rom.arm9i()?;
        let mut arm7i = rom.arm7i()?;
        if let Some(modcrypt) = header.modcrypt() {
            arm9i.apply_modcrypt(&modcrypt, Modcrypt::counter(&header.sha1_hmac_arm9_with_secure_area));
            arm7i.apply_modcrypt(&modcrypt, Modcrypt::counter(&header.sha1_hmac_arm7));
        }

        // Everything between the end of the DS region and the ARM9i program is dummy data
        let region_padding = rom.region_padding()?.to_vec().into_boxed_slice();

        let config = RomConfigDsi {
            arm9i_bin: "dsi/arm9i.bin".into(),
            arm9i_config: "dsi/arm9i.yaml".into(),
            arm7i_bin: "dsi/arm7i.bin".into(),
            arm7i_config: "dsi/arm7i.yaml".into(),
            region_padding: "dsi/region_padding.bin".into(),
            alignment: rom.dsi_alignments()?,
            padding: rom.dsi_padding_values()?,
        };

        Ok((DsiArea { arm9i, arm7i, region_padding }, config))
    }

    /// Builds a raw ROM.
    ///
    /// # Errors
    ///
    /// This function will return an error if an I/O operation fails or a component fails to build.
    pub fn build(mut self, key: Option<&BlowfishKey>) -> Result<raw::Rom<'a>, RomBuildError> {
        let mut context = BuildContext { blowfish_key: key, ..Default::default() };

        let mut writer = ByteWriter::with_capacity(128 * 1024); // smallest possible ROM

        // --------------------- Write header placeholder ---------------------
        let header_offset = writer.position();
        context.header_offset = Some(header_offset);
        writer.fill(0, size_of::<raw::Header>())?;

        // --------------------- Write ARM9 program ---------------------
        writer.align(self.config.padding.arm9, self.config.alignment.arm9)?;
        let arm9_offset = writer.position();
        context.arm9_offset = Some(arm9_offset);
        context.arm9_autoload_callback = Some(self.arm9.autoload_callback());
        context.arm9_build_info_offset = Some(self.arm9.build_info_offset());
        writer.copy(self.arm9.full_data())?;
        if self.arm9.has_footer() {
            let footer = Arm9Footer::new(self.arm9.build_info_offset(), self.arm9.overlay_signatures_offset());
            writer.copy(bytemuck::bytes_of(&footer))?;
        }

        let overlay_file_ids = self
            .arm9_overlay_table
            .overlays()
            .iter()
            .chain(self.arm7_overlay_table.overlays())
            .map(|overlay| (overlay.id(), overlay.file_id()));
        let fat_entry_count = fat_entry_count(self.files.max_file_id(), overlay_file_ids)?;
        let mut file_allocs = vec![FileAlloc::default(); fat_entry_count];

        if !self.arm9_overlay_table.is_empty() {
            // --------------------- Write ARM9 overlay table ---------------------
            writer.align(self.config.padding.arm9_overlay_table, self.config.alignment.arm9_overlay_table)?;
            context.arm9_ovt_offset = Some(TableOffset {
                offset: writer.position(),
                size: (self.arm9_overlay_table.len() as u32)
                    .checked_mul(size_of::<raw::Overlay>() as u32)
                    .ok_or_else(|| OverflowError::new("ARM9 overlay table size"))?,
            });
            let raw_table = self.arm9_overlay_table.build();
            writer.copy(raw_table.as_bytes())?;

            // --------------------- Write ARM9 overlays ---------------------
            #[allow(clippy::indexing_slicing)] // file_allocs covers every overlay's file ID
            for overlay in self.arm9_overlay_table.overlays() {
                writer.align(self.config.padding.arm9_overlays, self.config.alignment.arm9_overlay)?;
                let start = writer.position();
                let end = start
                    .checked_add(overlay.full_data().len() as u32)
                    .ok_or_else(|| OverflowError::new(format!("end of ARM9 overlay {}", overlay.id())))?;
                file_allocs[overlay.file_id() as usize] = FileAlloc { start, end };

                writer.copy(overlay.full_data())?;
            }
        }

        // --------------------- Write ARM7 program ---------------------
        writer.align(self.config.padding.arm7, self.config.alignment.arm7)?;
        context.arm7_offset = Some(writer.position());
        context.arm7_autoload_callback = Some(self.arm7.autoload_callback());
        context.arm7_build_info_offset = Some(self.arm7.build_info_offset());
        writer.copy(self.arm7.full_data())?;

        if !self.arm7_overlay_table.is_empty() {
            // --------------------- Write ARM7 overlay table ---------------------
            writer.align(self.config.padding.arm7_overlay_table, self.config.alignment.arm7_overlay_table)?;
            context.arm7_ovt_offset = Some(TableOffset {
                offset: writer.position(),
                size: (self.arm7_overlay_table.len() as u32)
                    .checked_mul(size_of::<raw::Overlay>() as u32)
                    .ok_or_else(|| OverflowError::new("ARM7 overlay table size"))?,
            });
            let raw_table = self.arm7_overlay_table.build();
            writer.copy(raw_table.as_bytes())?;

            // --------------------- Write ARM7 overlays ---------------------
            #[allow(clippy::indexing_slicing)] // file_allocs covers every overlay's file ID
            for overlay in self.arm7_overlay_table.overlays() {
                writer.align(self.config.padding.arm7_overlays, self.config.alignment.arm7_overlay)?;
                let start = writer.position();
                let end = start
                    .checked_add(overlay.full_data().len() as u32)
                    .ok_or_else(|| OverflowError::new(format!("end of ARM7 overlay {}", overlay.id())))?;
                file_allocs[overlay.file_id() as usize] = FileAlloc { start, end };

                writer.copy(overlay.full_data())?;
            }
        }

        // --------------------- Write file name table (FNT) ---------------------
        writer.align(self.config.padding.fnt, self.config.alignment.file_name_table)?;
        self.files.sort_for_fnt()?;
        let fnt = self.files.build_fnt()?.build()?;
        context.fnt_offset = Some(TableOffset { offset: writer.position(), size: fnt.len() as u32 });
        writer.copy(&fnt)?;

        // --------------------- Write file allocation table (FAT) placeholder ---------------------
        writer.align(self.config.padding.fat, self.config.alignment.file_allocation_table)?;
        let fat_offset = writer.position();
        context.fat_offset = Some(TableOffset {
            offset: fat_offset,
            size: (file_allocs.len() as u32)
                .checked_mul(size_of::<FileAlloc>() as u32)
                .ok_or_else(|| OverflowError::new("FAT size"))?,
        });
        writer.copy(bytemuck::cast_slice(&file_allocs))?;

        // --------------------- Write banner ---------------------
        writer.align(self.config.padding.banner, self.config.alignment.banner)?;
        let banner = self.banner.build()?;
        context.banner_offset = Some(TableOffset { offset: writer.position(), size: banner.full_data().len() as u32 });
        writer.copy(banner.full_data())?;

        // --------------------- Write files ---------------------
        writer.align(self.config.padding.file_image, self.config.alignment.file_image_block)?;
        self.files.sort_for_rom()?;
        #[allow(clippy::indexing_slicing)] // file_allocs covers every file ID in the file system
        self.files.traverse_files(self.path_order.iter().map(|s| s.as_str()), |file, _| -> Result<(), RomBuildError> {
            writer.align(self.config.padding.file_image, self.config.alignment.file)?;

            let contents = file.contents();
            let length = u32::try_from(contents.len()).map_err(|_| OverflowError::new(format!("size of {}", file.name())))?;
            let start = writer.position();
            let end = start.checked_add(length).ok_or_else(|| OverflowError::new(format!("end offset of {}", file.name())))?;
            file_allocs[file.id() as usize] = FileAlloc { start, end };

            writer.copy(contents)?;
            Ok(())
        })?;

        // --------------------- Write multiboot signature ---------------------
        // Multiboot signature is placed "after" the ROM ends
        context.rom_size = Some(writer.position());
        if let Some(multiboot_signature) = &self.multiboot_signature {
            writer.copy(bytemuck::bytes_of(multiboot_signature))?;
        }

        // --------------------- Update FAT ---------------------
        // The FAT must be final before the digest tables are computed below
        let ntr_region_end = writer.position();
        writer.set_position(fat_offset)?;
        writer.copy(bytemuck::cast_slice(&file_allocs))?;

        // --------------------- Write DSi area ---------------------
        writer.set_position(ntr_region_end)?;
        context.dsi = self.build_dsi_area(&mut writer, &mut context, key, &banner, arm9_offset)?;

        // --------------------- Write padding ---------------------
        writer.align(self.config.padding.rom, padded_rom_size(writer.position())?)?;

        // --------------------- Update header ---------------------
        writer.set_position(header_offset)?;
        let header = self.header.build(&context, &self)?;
        writer.copy(bytemuck::bytes_of(&header))?;

        Ok(raw::Rom::new(writer.into_vec()))
    }

    fn build_dsi_area(
        &self,
        writer: &mut ByteWriter,
        context: &mut BuildContext,
        key: Option<&BlowfishKey>,
        banner: &raw::Banner<'_>,
        arm9_offset: u32,
    ) -> Result<Option<DsiBuildContext>, RomBuildError> {
        let (dsi, config, header_ds_post_dsi, header_dsi) =
            match (&self.dsi, &self.config.dsi, &self.header.ds_post_dsi, &self.header.dsi) {
                (Some(dsi), Some(config), Some(header_ds_post_dsi), Some(header_dsi)) => {
                    (dsi, config, header_ds_post_dsi, header_dsi)
                }
                (None, None, _, None) => return Ok(None),
                _ => return DsiIncompleteSnafu {}.fail(),
            };
        let Some(hmac_sha1) = &self.hmac_sha1 else {
            return DsiHmacSha1KeyNeededSnafu {}.fail();
        };
        let Some(key) = key else {
            return DsiBlowfishKeyNeededSnafu {}.fail();
        };

        let params = header_dsi.digest;
        Digest::check_params(&params)?;
        const HASH_SIZE: u32 = size_of::<HmacSha1Signature>() as u32;

        // --------------------- Align NTR region size ---------------------
        writer.align(config.padding.digest_sector_hashtable, params.sector_size)?;
        let sector_hashtable_offset = writer.position();
        let ntr_region_start = size_of::<raw::Header>() as u32;
        // sector hashtable is always after NTR region, and sector_size is not zero
        #[allow(clippy::arithmetic_side_effects)]
        let ntr_sectors = (sector_hashtable_offset - ntr_region_start) / params.sector_size;

        // Where the DSi area starts decides how many sectors it contributes, which decides how big the digest tables are,
        // which decides where the DS area ends. Start from the boundary the original ROM used and push it out if the DS area
        // no longer fits below it.
        let arm9i_len = dsi.arm9i.full_data().len() as u32;
        let arm7i_len = dsi.arm7i.full_data().len() as u32;
        let mut ds_rom_region_end = header_dsi.ds_rom_region_end;
        let layout: DsiLayout = loop {
            #[allow(clippy::arithmetic_side_effects)] // 16x20-bit multiplication fits in 64 bits
            let region_start: u32 = (ds_rom_region_end as u64 * DSI_REGION_UNIT as u64)
                .try_into()
                .map_err(|_| OverflowError::new("DSi region start"))?;
            let arm9i_offset =
                region_start.checked_add(dsi.region_padding.len() as u32).ok_or_else(|| OverflowError::new("ARM9i offset"))?;
            let arm9i_end = arm9i_offset.checked_add(arm9i_len).ok_or_else(|| OverflowError::new("ARM9i end"))?;
            let arm7i_offset = align_up(arm9i_end, config.alignment.arm7i, "ARM7i offset")?;
            let arm7i_end = arm7i_offset.checked_add(arm7i_len).ok_or_else(|| OverflowError::new("ARM7i end"))?;
            let rom_size_dsi = align_up(arm7i_end, params.sector_size, "DSi ROM size")?;
            // rom_size_dsi is always greater than arm9i_offset, and sector_size is not zero
            #[allow(clippy::arithmetic_side_effects)]
            let twl_sectors = (rom_size_dsi - arm9i_offset) / params.sector_size;

            let num_sectors = ntr_sectors.checked_add(twl_sectors).ok_or_else(|| OverflowError::new("hash sector count"))?;
            let num_blocks = num_sectors.div_ceil(params.block_sector_count);
            let block_hash_size =
                params.block_sector_count.checked_mul(HASH_SIZE).ok_or_else(|| OverflowError::new("digest block size"))?;
            let sector_hashtable_size =
                num_blocks.checked_mul(block_hash_size).ok_or_else(|| OverflowError::new("sector hashtable size"))?;
            let sector_hashtable_end = sector_hashtable_offset
                .checked_add(sector_hashtable_size)
                .ok_or_else(|| OverflowError::new("sector hashtable end"))?;
            let block_hashtable_offset =
                align_up(sector_hashtable_end, config.alignment.digest_block_hashtable, "block hashtable offset")?;
            let block_hashtable_size =
                num_blocks.checked_mul(HASH_SIZE).ok_or_else(|| OverflowError::new("block hashtable size"))?;
            let block_hashtable_end = block_hashtable_offset
                .checked_add(block_hashtable_size)
                .ok_or_else(|| OverflowError::new("block hashtable end"))?;
            let rom_size_ds = align_up(block_hashtable_end, config.alignment.rom_size_ds, "DS ROM size")?;

            if rom_size_ds <= region_start {
                break DsiLayout {
                    region_start,
                    arm9i_offset,
                    arm7i_offset,
                    rom_size_ds,
                    rom_size_dsi,
                    sector_hashtable_size,
                    block_hashtable_offset,
                    block_hashtable_size,
                };
            }
            let needed = rom_size_ds.div_ceil(DSI_REGION_UNIT) as u16;
            log::warn!(
                "DS area no longer fits below the DSi area, moving the region end from {ds_rom_region_end:#x} to {needed:#x}"
            );
            ds_rom_region_end = needed;
        };

        // --------------------- Reserve the digest tables ---------------------
        // Their contents cover the DSi area written below, so they get filled in afterwards.
        writer.fill(0, layout.sector_hashtable_size as usize)?;
        writer.align(config.padding.digest_block_hashtable, config.alignment.digest_block_hashtable)?;
        debug_assert_eq!(writer.position(), layout.block_hashtable_offset, "digest block hashtable landed off-layout");
        writer.fill(0, layout.block_hashtable_size as usize)?;
        writer.align(config.padding.rom_size_ds, config.alignment.rom_size_ds)?;
        debug_assert_eq!(writer.position(), layout.rom_size_ds, "DS area ended off-layout");
        context.rom_size = Some(layout.rom_size_ds);

        // --------------------- Write the DSi area ---------------------
        // The DSi-exclusive programs go in decrypted, so that the digest below sees them the way the DSi does. Modcrypt is
        // applied afterwards.
        #[allow(clippy::arithmetic_side_effects)] // region_start not reached yet
        let region_gap = layout.region_start - writer.position();
        writer.fill(config.padding.dsi_region, region_gap as usize)?;
        writer.copy(&dsi.region_padding)?;
        debug_assert_eq!(writer.position(), layout.arm9i_offset, "ARM9i landed off-layout");
        writer.copy(dsi.arm9i.full_data())?;
        writer.align(config.padding.arm7i, config.alignment.arm7i)?;
        debug_assert_eq!(writer.position(), layout.arm7i_offset, "ARM7i landed off-layout");
        writer.copy(dsi.arm7i.full_data())?;
        #[allow(clippy::arithmetic_side_effects)] // rom_size_dsi not reached yet
        let dsi_gap = layout.rom_size_dsi - writer.position();
        writer.fill(config.padding.rom_size_dsi, dsi_gap as usize)?;

        // --------------------- Content SHA1-HMACs ---------------------
        // The ARM9 hashes cover the secure area encrypted, which is not how every dump stores it.
        let gamecode = self.header.original.gamecode;
        let encrypted_secure_area = self.arm9.encrypted_secure_area(key, gamecode.to_le_u32())?;
        let secure_area_size = encrypted_secure_area.len();
        let mut arm9_with_secure_area = encrypted_secure_area.to_vec();
        #[allow(clippy::indexing_slicing)] // ARM9 always has a secure area
        arm9_with_secure_area.extend_from_slice(&self.arm9.full_data()[secure_area_size..]);

        let sha1_hmac_arm9_with_secure_area = hmac_sha1.compute(&arm9_with_secure_area);
        #[allow(clippy::indexing_slicing)] // ARM9 always has a secure area
        let sha1_hmac_arm9 = hmac_sha1.compute(&arm9_with_secure_area[secure_area_size..]);
        let sha1_hmac_arm7 = hmac_sha1.compute(self.arm7.full_data());
        let sha1_hmac_banner = hmac_sha1.compute(banner.full_data());
        let sha1_hmac_arm9i = hmac_sha1.compute(dsi.arm9i.full_data());
        let sha1_hmac_arm7i = hmac_sha1.compute(dsi.arm7i.full_data());

        // --------------------- Digest tables ---------------------
        // Swap the encrypted secure area in, hash the ROM as the DSi expects to see it, then put the ROM back.
        #[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)] // secure area is always written at this point
        let original_secure_area = writer.data()[arm9_offset as usize..arm9_offset as usize + secure_area_size].to_vec();
        writer.copy_to(&encrypted_secure_area, arm9_offset)?;
        let digest = Digest::compute(
            hmac_sha1,
            &params,
            writer.data(),
            ntr_region_start..sector_hashtable_offset,
            layout.arm9i_offset..layout.rom_size_dsi,
        )?;
        writer.copy_to(&original_secure_area, arm9_offset)?;

        // --------------------- Modcrypt ---------------------
        let mut modcrypt_area_1 = TableOffset::default();
        let mut modcrypt_area_2 = TableOffset::default();
        if dsi.arm9i.is_modcrypted() || dsi.arm7i.is_modcrypted() {
            let modcrypt = if header_dsi.dsi_flags.modcrypt_debug_key() || header_ds_post_dsi.dsi_flags_2.developer_app() {
                let key = self.header.build_modcrypt_debug_key()?;
                Modcrypt::debug(&key)
            } else {
                Modcrypt::retail(gamecode.0, &sha1_hmac_arm9i)
            };
            modcrypt_area_1 = encrypt_dsi_program(
                writer,
                &modcrypt,
                &dsi.arm9i,
                layout.arm9i_offset,
                &sha1_hmac_arm9_with_secure_area,
                "ARM9i",
            )?;
            modcrypt_area_2 =
                encrypt_dsi_program(writer, &modcrypt, &dsi.arm7i, layout.arm7i_offset, &sha1_hmac_arm7, "ARM7i")?;
        }

        // --------------------- Fill in the digest tables ---------------------
        let rom_end = writer.position();
        writer.set_position(sector_hashtable_offset)?;
        writer.copy(digest.sector_hashtable())?;
        writer.set_position(layout.block_hashtable_offset)?;
        writer.copy(digest.block_hashtable())?;
        writer.set_position(rom_end)?;

        #[allow(clippy::arithmetic_side_effects)] // always a non-negative result
        let region_end_delta = ds_rom_region_end - header_dsi.ds_rom_region_end;
        let dsi_rom_region_end = header_dsi
            .dsi_rom_region_end
            .checked_add(region_end_delta)
            .ok_or_else(|| OverflowError::new("DSi ROM region end"))?;
        Ok(Some(DsiBuildContext {
            arm9i: ProgramOffset {
                offset: layout.arm9i_offset,
                entry: dsi.arm9i.offsets().entry_function,
                base_addr: dsi.arm9i.offsets().base_address,
                size: arm9i_len,
            },
            arm7i: ProgramOffset {
                offset: layout.arm7i_offset,
                entry: dsi.arm7i.offsets().entry_function,
                base_addr: dsi.arm7i.offsets().base_address,
                size: arm7i_len,
            },
            arm9i_build_info_offset: dsi.arm9i.offsets().build_info_offset,
            arm7i_build_info_offset: dsi.arm7i.offsets().build_info_offset,
            modcrypt_area_1,
            modcrypt_area_2,
            #[allow(clippy::arithmetic_side_effects)] // always a non-negative result
            digest_ds_area: TableOffset { offset: ntr_region_start, size: sector_hashtable_offset - ntr_region_start },
            #[allow(clippy::arithmetic_side_effects)] // always a non-negative result
            digest_dsi_area: TableOffset { offset: layout.arm9i_offset, size: layout.rom_size_dsi - layout.arm9i_offset },
            digest_sector_hashtable: TableOffset { offset: sector_hashtable_offset, size: layout.sector_hashtable_size },
            digest_block_hashtable: TableOffset { offset: layout.block_hashtable_offset, size: layout.block_hashtable_size },
            rom_size_dsi: layout.rom_size_dsi,
            banner_size: banner.full_data().len() as u32,
            ds_rom_region_end,
            dsi_rom_region_end,
            sha1_hmac_arm9_with_secure_area,
            sha1_hmac_arm9,
            sha1_hmac_arm7,
            sha1_hmac_digest: digest.master().hash,
            sha1_hmac_banner,
            sha1_hmac_arm9i,
            sha1_hmac_arm7i,
        }))
    }

    /// Returns a reference to the header logo of this [`Rom`].
    pub fn header_logo(&self) -> &Logo {
        &self.header_logo
    }

    /// Returns a mutable reference to the header logo of this [`Rom`].
    pub fn header_logo_mut(&mut self) -> &mut Logo {
        &mut self.header_logo
    }

    /// Returns a reference to the ARM9 program of this [`Rom`].
    pub fn arm9(&self) -> &Arm9<'a> {
        &self.arm9
    }

    /// Returns a mutable reference to the ARM9 program of this [`Rom`].
    pub fn arm9_mut(&mut self) -> &mut Arm9<'a> {
        &mut self.arm9
    }

    /// Returns a reference to the ARM9 overlay table of this [`Rom`].
    pub fn arm9_overlay_table(&self) -> &OverlayTable<'a> {
        &self.arm9_overlay_table
    }

    /// Returns a mutable reference to the ARM9 overlay table of this [`Rom`].
    pub fn arm9_overlay_table_mut(&mut self) -> &mut OverlayTable<'a> {
        &mut self.arm9_overlay_table
    }

    /// Returns a reference to the ARM9 overlays of this [`Rom`].
    pub fn arm9_overlays(&self) -> &[Overlay<'a>] {
        self.arm9_overlay_table.overlays()
    }

    /// Returns a mutable reference to the ARM9 overlays of this [`Rom`].
    pub fn arm9_overlays_mut(&mut self) -> &mut [Overlay<'a>] {
        self.arm9_overlay_table.overlays_mut()
    }

    /// Returns a reference to the ARM7 program of this [`Rom`].
    pub fn arm7(&self) -> &Arm7<'a> {
        &self.arm7
    }

    /// Returns a mutable reference to the ARM7 program of this [`Rom`].
    pub fn arm7_mut(&mut self) -> &mut Arm7<'a> {
        &mut self.arm7
    }

    /// Returns a reference to the ARM7 overlay table of this [`Rom`].
    pub fn arm7_overlay_table(&self) -> &OverlayTable<'a> {
        &self.arm7_overlay_table
    }

    /// Returns a mutable reference to the ARM7 overlay table of this [`Rom`].
    pub fn arm7_overlay_table_mut(&mut self) -> &mut OverlayTable<'a> {
        &mut self.arm7_overlay_table
    }

    /// Returns a reference to the ARM7 overlays of this [`Rom`].
    pub fn arm7_overlays(&self) -> &[Overlay<'a>] {
        self.arm7_overlay_table.overlays()
    }

    /// Returns a mutable reference to the ARM7 overlays of this [`Rom`].
    pub fn arm7_overlays_mut(&mut self) -> &mut [Overlay<'a>] {
        self.arm7_overlay_table.overlays_mut()
    }

    /// Returns a reference to the header of this [`Rom`].
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// Returns a mutable reference to the header of this [`Rom`].
    pub fn header_mut(&mut self) -> &mut Header {
        &mut self.header
    }

    /// Returns the [`RomConfig`] consisting of paths to extracted files.
    pub fn config(&self) -> &RomConfig {
        &self.config
    }

    /// Returns the [`MultibootSignature`] of this [`Rom`].
    pub fn multiboot_signature(&self) -> Option<&MultibootSignature> {
        self.multiboot_signature.as_ref()
    }

    /// Returns the ARM9i program of this [`Rom`].
    pub fn arm9i(&'a self) -> Option<&'a DsiProgram<'a>> {
        self.dsi.as_ref().map(|dsi| &dsi.arm9i)
    }

    /// Returns the ARM9i program of this [`Rom`].
    pub fn arm7i(&'a self) -> Option<&'a DsiProgram<'a>> {
        self.dsi.as_ref().map(|dsi| &dsi.arm7i)
    }

    /// Returns the [`HeaderPadding`] of this [`Rom`].
    pub fn header_padding(&self) -> Option<&HeaderPadding> {
        self.header_padding.as_ref()
    }
}

/// Build context, generated during [`Rom::build`] and later passed to [`Header::build`] to fill in the header.
#[derive(Default)]
pub struct BuildContext<'a> {
    /// Header offset.
    pub header_offset: Option<u32>,
    /// ARM9 program offset.
    pub arm9_offset: Option<u32>,
    /// ARM7 program offset.
    pub arm7_offset: Option<u32>,
    /// FNT offset.
    pub fnt_offset: Option<TableOffset>,
    /// FAT offset.
    pub fat_offset: Option<TableOffset>,
    /// ARM9 overlay table offset.
    pub arm9_ovt_offset: Option<TableOffset>,
    /// ARM7 overlay table offset.
    pub arm7_ovt_offset: Option<TableOffset>,
    /// Banner offset.
    pub banner_offset: Option<TableOffset>,
    /// Blowfish key.
    pub blowfish_key: Option<&'a BlowfishKey>,
    /// ARM9 autoload callback.
    pub arm9_autoload_callback: Option<u32>,
    /// ARM7 autoload callback.
    pub arm7_autoload_callback: Option<u32>,
    /// ARM9 build info offset.
    pub arm9_build_info_offset: Option<u32>,
    /// ARM7 build info offset.
    pub arm7_build_info_offset: Option<u32>,
    /// Total ROM size.
    pub rom_size: Option<u32>,
    /// Values computed while building the DSi area, absent for DS-only ROMs.
    pub dsi: Option<DsiBuildContext>,
}

/// Everything in the ROM header that describes the DSi area.
#[derive(Default, Clone, Copy)]
pub struct DsiBuildContext {
    /// ARM9i program offset.
    pub arm9i: ProgramOffset,
    /// ARM7i program offset.
    pub arm7i: ProgramOffset,
    /// ARM9i build info offset.
    pub arm9i_build_info_offset: u32,
    /// ARM7i build info offset.
    pub arm7i_build_info_offset: u32,
    /// Modcrypt area 1, covering the start of the ARM9i program.
    pub modcrypt_area_1: TableOffset,
    /// Modcrypt area 2, covering the start of the ARM7i program.
    pub modcrypt_area_2: TableOffset,
    /// Digest NTR (DS) region.
    pub digest_ds_area: TableOffset,
    /// Digest TWL (DSi) region.
    pub digest_dsi_area: TableOffset,
    /// Digest sector hashtable.
    pub digest_sector_hashtable: TableOffset,
    /// Digest block hashtable.
    pub digest_block_hashtable: TableOffset,
    /// Total ROM size including the DSi area.
    pub rom_size_dsi: u32,
    /// Banner size.
    pub banner_size: u32,
    /// DS ROM region end in multiples of 0x80000.
    pub ds_rom_region_end: u16,
    /// DSi ROM region end in multiples of 0x80000.
    pub dsi_rom_region_end: u16,
    /// SHA1-HMAC of the ARM9 program including its encrypted secure area.
    pub sha1_hmac_arm9_with_secure_area: [u8; 0x14],
    /// SHA1-HMAC of the ARM9 program excluding its secure area.
    pub sha1_hmac_arm9: [u8; 0x14],
    /// SHA1-HMAC of the ARM7 program.
    pub sha1_hmac_arm7: [u8; 0x14],
    /// SHA1-HMAC of the digest block hashtable.
    pub sha1_hmac_digest: [u8; 0x14],
    /// SHA1-HMAC of the banner.
    pub sha1_hmac_banner: [u8; 0x14],
    /// SHA1-HMAC of the decrypted ARM9i program.
    pub sha1_hmac_arm9i: [u8; 0x14],
    /// SHA1-HMAC of the decrypted ARM7i program.
    pub sha1_hmac_arm7i: [u8; 0x14],
}

/// Options for [`Rom::load`].
pub struct RomLoadOptions<'a> {
    /// Blowfish encryption key.
    pub key: Option<&'a BlowfishKey>,
    /// If true (default), compress ARM9 and overlays if they are configured with `compressed: true`.
    pub compress: bool,
    /// If true (default), encrypt ARM9 if it's configured with `encrypted: true`, and ARM9/overlays
    /// if they contain DS Protect.
    pub encrypt: bool,
    /// If true (default), load asset files.
    pub load_files: bool,
    /// If true (default), load the header and the header logo.
    pub load_header: bool,
    /// If true (default), load the banner.
    pub load_banner: bool,
    /// If true (default), load the multiboot signature.
    pub load_multiboot_signature: bool,
}

impl Default for RomLoadOptions<'_> {
    fn default() -> Self {
        Self {
            key: None,
            compress: true,
            encrypt: true,
            load_files: true,
            load_header: true,
            load_banner: true,
            load_multiboot_signature: true,
        }
    }
}

/// Offsets worked out while laying out the DSi area, see [`Rom::build_dsi_area`].
struct DsiLayout {
    region_start: u32,
    arm9i_offset: u32,
    arm7i_offset: u32,
    rom_size_ds: u32,
    rom_size_dsi: u32,
    sector_hashtable_size: u32,
    block_hashtable_offset: u32,
    block_hashtable_size: u32,
}

fn encrypt_dsi_program(
    writer: &mut ByteWriter,
    modcrypt: &Modcrypt,
    program: &DsiProgram,
    offset: u32,
    counter: &[u8; 0x14],
    name: &str,
) -> Result<TableOffset, RomBuildError> {
    if !program.is_modcrypted() {
        return Ok(TableOffset::default());
    }
    let size = program.offsets().modcrypt_size;
    let start = offset as usize;
    let end = start.checked_add(size as usize).ok_or_else(|| OverflowError::new(format!("{name} modcrypt area end")))?;
    let modcrypt_area = writer
        .data_mut()
        .get_mut(start..end)
        .ok_or_else(|| OutOfBoundsAccessSnafu { what: format!("{name} modcrypt area") }.build())?;
    modcrypt.apply(Modcrypt::counter(counter), modcrypt_area);
    Ok(TableOffset { offset, size })
}

/// Returns the number of FAT entries needed to cover every file ID in the file system and every overlay's file ID, given
/// the max file ID of the file system and the `(overlay ID, file ID)` pair of each overlay.
fn fat_entry_count(max_file_id: u16, overlay_file_ids: impl IntoIterator<Item = (u16, u32)>) -> Result<usize, RomBuildError> {
    let mut max_file_id = max_file_id;
    for (overlay_id, file_id) in overlay_file_ids {
        let file_id = u16::try_from(file_id)
            .ok()
            .filter(|&id| FileSystem::is_file(id))
            .ok_or_else(|| InvalidOverlayFileIdSnafu { overlay_id, file_id }.build())?;
        max_file_id = max_file_id.max(file_id);
    }
    Ok(usize::from(max_file_id) + 1)
}

/// Returns the size of a ROM after padding it to a power of two, which is at least 128 kB.
fn padded_rom_size(rom_size: u32) -> Result<u32, OverflowError> {
    let padded_size = rom_size.checked_next_power_of_two().ok_or_else(|| OverflowError::new("padded ROM size"))?;
    Ok(padded_size.max(128 * 1024))
}

fn default_true() -> bool {
    true
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn fat_entry_count_values() {
        assert_eq!(fat_entry_count(0, []).unwrap(), 1);
        assert_eq!(fat_entry_count(5, []).unwrap(), 6);
        assert_eq!(fat_entry_count(5, [(0, 0), (1, 1)]).unwrap(), 6);
        // Overlays without regular files
        assert_eq!(fat_entry_count(0, [(0, 0), (1, 1), (2, 2)]).unwrap(), 3);
        // Overlay file ID above the file system's max file ID
        assert_eq!(fat_entry_count(5, [(0, 9)]).unwrap(), 10);
        assert_eq!(fat_entry_count(0, [(0, 0xefff)]).unwrap(), 0xf000);
    }

    #[test]
    fn fat_entry_count_invalid_file_id_is_error() {
        let result = fat_entry_count(0, [(0, 0), (1, 0xf000)]);
        assert!(matches!(result, Err(RomBuildError::InvalidOverlayFileId { overlay_id: 1, file_id: 0xf000, .. })));
        let result = fat_entry_count(0, [(3, 0x10000)]);
        assert!(matches!(result, Err(RomBuildError::InvalidOverlayFileId { overlay_id: 3, file_id: 0x10000, .. })));
        let result = fat_entry_count(0, [(4, u32::MAX)]);
        assert!(matches!(result, Err(RomBuildError::InvalidOverlayFileId { overlay_id: 4, file_id: u32::MAX, .. })));
    }

    #[test]
    fn padded_rom_size_values() {
        assert_eq!(padded_rom_size(0).unwrap(), 0x20000);
        assert_eq!(padded_rom_size(0x1234).unwrap(), 0x20000);
        assert_eq!(padded_rom_size(0x20001).unwrap(), 0x40000);
        assert_eq!(padded_rom_size(0x01000000).unwrap(), 0x01000000);
        assert_eq!(padded_rom_size(0x80000000).unwrap(), 0x80000000);
        assert!(padded_rom_size(0x80000001).is_err());
        assert!(padded_rom_size(u32::MAX).is_err());
    }
}
