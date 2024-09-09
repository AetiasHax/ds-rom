use std::{
    io::{self, Cursor, Write},
    mem::size_of,
    path::Path,
};

use serde::{Deserialize, Serialize};
use snafu::Snafu;

use super::{
    raw::{
        self, Arm9Footer, RawArm9Error, RawBannerError, RawBuildInfoError, RawFatError, RawFntError, RawHeaderError,
        RawOverlayError, TableOffset,
    },
    Arm7, Arm9, Arm9AutoloadError, Arm9Error, Arm9Offsets, Autoload, Banner, BannerError, BannerImageError, BuildInfo,
    FileBuildError, FileParseError, FileSystem, Header, HeaderBuildError, Logo, LogoError, LogoLoadError, LogoSaveError,
    Overlay, OverlayInfo,
};
use crate::{
    crypto::blowfish::BlowfishKey,
    io::{create_dir_all, create_file, open_file, read_file, read_to_string, FileError},
    rom::raw::FileAlloc,
};

/// Path from extract root to main ARM9 binary
pub const ARM9_BIN_PATH: &str = "arm9/arm9.bin"; // TODO: Move these to config file
/// Path from extract root to ITCM binary
pub const ITCM_BIN_PATH: &str = "arm9/itcm.bin";
/// Path from extract root to DTCM binary
pub const DTCM_BIN_PATH: &str = "arm9/dtcm.bin";

/// A plain ROM.
pub struct Rom<'a> {
    header: Header,
    header_logo: Logo,
    arm9: Arm9<'a>,
    arm9_overlays: Vec<Overlay<'a>>,
    arm7: Arm7<'a>,
    arm7_overlays: Vec<Overlay<'a>>,
    banner: Banner,
    files: FileSystem<'a>,
    path_order: Vec<String>,
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
    /// See [`serde_yml::Error`].
    #[snafu(transparent)]
    SerdeJson {
        /// Source error.
        source: serde_yml::Error,
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
    /// Build info for this module.
    #[serde(flatten)]
    pub build_info: BuildInfo,
}

/// Overlay configuration, extending [`OverlayInfo`] with more fields.
#[derive(Serialize, Deserialize)]
pub struct OverlayConfig {
    /// See [`OverlayInfo`].
    #[serde(flatten)]
    pub info: OverlayInfo,
    /// Name of binary file.
    pub file_name: String,
}

impl<'a> Rom<'a> {
    /// Loads a ROM from a path generated by [`Self::save`].
    ///
    /// # Errors
    ///
    /// This function will return an error if there's a file missing or the file has an invalid format.
    pub fn load<P: AsRef<Path>>(path: P, options: RomLoadOptions) -> Result<Self, RomSaveError> {
        let path = path.as_ref();
        log::info!("Loading ROM from path {}", path.display());

        // --------------------- Load header ---------------------
        let header: Header = serde_yml::from_reader(open_file(path.join("header.yaml"))?)?;
        let header_logo = Logo::from_png(path.join("header_logo.png"))?;

        // --------------------- Load ARM9 program ---------------------
        let arm9_path = path.join("arm9");
        let arm9_build_config: Arm9BuildConfig = serde_yml::from_reader(open_file(arm9_path.join("arm9.yaml"))?)?;
        let arm9 = read_file(path.join(ARM9_BIN_PATH))?;

        // --------------------- Load ITCM, DTCM ---------------------
        let itcm = read_file(path.join(ITCM_BIN_PATH))?;
        let itcm_info = serde_yml::from_reader(open_file(arm9_path.join("itcm.yaml"))?)?;
        let itcm = Autoload::new(itcm, itcm_info);

        let dtcm = read_file(path.join(DTCM_BIN_PATH))?;
        let dtcm_info = serde_yml::from_reader(open_file(arm9_path.join("dtcm.yaml"))?)?;
        let dtcm = Autoload::new(dtcm, dtcm_info);

        // --------------------- Build ARM9 program ---------------------
        let mut arm9 = Arm9::with_two_tcms(arm9, itcm, dtcm, header.version(), arm9_build_config.offsets)?;
        arm9_build_config.build_info.assign_to_raw(arm9.build_info_mut()?);
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

        // --------------------- Load ARM9 overlays ---------------------
        let arm9_overlays = Self::load_overlays(path, &header, "arm9", &options)?;

        // --------------------- Load ARM7 program ---------------------
        let arm7_path = path.join("arm7");
        let arm7 = read_file(arm7_path.join("arm7.bin"))?;
        let arm7_config = serde_yml::from_reader(open_file(arm7_path.join("arm7.yaml"))?)?;
        let arm7 = Arm7::new(arm7, arm7_config);

        // --------------------- Load ARM7 overlays ---------------------
        let arm7_overlays = Self::load_overlays(path, &header, "arm7", &options)?;

        // --------------------- Load banner ---------------------
        let banner_path = path.join("banner");
        let mut banner: Banner = serde_yml::from_reader(open_file(banner_path.join("banner.yaml"))?)?;
        banner.images.load_bitmap_file(banner_path.join("bitmap.png"), banner_path.join("palette.png"))?;

        // --------------------- Load files ---------------------
        log::info!("Loading ROM assets");
        let num_overlays = arm9_overlays.len() + arm7_overlays.len();
        let (files, path_order) = if options.load_files {
            let files = FileSystem::load(path.join("files"), num_overlays)?;
            let path_order =
                read_to_string(path.join("path_order.txt"))?.trim().lines().map(|l| l.to_string()).collect::<Vec<_>>();
            (files, path_order)
        } else {
            (FileSystem::new(num_overlays), vec![])
        };

        Ok(Self { header, header_logo, arm9, arm9_overlays, arm7, arm7_overlays, banner, files, path_order })
    }

    fn load_overlays(
        path: &Path,
        header: &Header,
        processor: &str,
        options: &RomLoadOptions,
    ) -> Result<Vec<Overlay<'a>>, RomSaveError> {
        let mut overlays = vec![];
        let overlays_path = path.join(format!("{processor}_overlays"));
        if overlays_path.exists() && overlays_path.is_dir() {
            let overlay_configs: Vec<OverlayConfig> = serde_yml::from_reader(open_file(overlays_path.join("overlays.yaml"))?)?;
            let num_overlays = overlay_configs.len();
            for mut config in overlay_configs.into_iter() {
                let data = read_file(overlays_path.join(config.file_name))?;
                let compressed = config.info.compressed;
                config.info.compressed = false;
                let mut overlay = Overlay::new(data, header.version(), config.info);
                if compressed && options.compress {
                    log::info!("Compressing {processor} overlay {}/{}", overlay.id(), num_overlays - 1);
                    overlay.compress()?;
                }
                overlays.push(overlay);
            }
        }
        Ok(overlays)
    }

    /// Saves this ROM to a path as separate files.
    ///
    /// # Errors
    ///
    /// This function will return an error if a file could not be created or the a component of the ROM has an invalid format.
    pub fn save<P: AsRef<Path>>(&self, path: P, key: Option<&BlowfishKey>) -> Result<(), RomSaveError> {
        let path = path.as_ref();
        create_dir_all(path)?;

        log::info!("Saving ROM to path {}", path.display());

        // --------------------- Save header ---------------------
        serde_yml::to_writer(create_file(path.join("header.yaml"))?, &self.header)?;
        self.header_logo.save_png(path.join("header_logo.png"))?;

        // --------------------- Save ARM9 program ---------------------
        let arm9_build_config = Arm9BuildConfig {
            offsets: *self.arm9.offsets(),
            encrypted: self.arm9.is_encrypted(),
            compressed: self.arm9.is_compressed()?,
            build_info: self.arm9.build_info()?.clone().into(),
        };
        let arm9_path = path.join("arm9");
        create_dir_all(&arm9_path)?;
        serde_yml::to_writer(create_file(arm9_path.join("arm9.yaml"))?, &arm9_build_config)?;
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
        create_file(path.join(ARM9_BIN_PATH))?.write(plain_arm9.code()?)?;

        // --------------------- Save ITCM, DTCM ---------------------
        for autoload in plain_arm9.autoloads()?.iter() {
            let name = match autoload.kind() {
                raw::AutoloadKind::Itcm => "itcm",
                raw::AutoloadKind::Dtcm => "dtcm",
                raw::AutoloadKind::Unknown => panic!("unknown autoload block"),
            };
            create_file(arm9_path.join(format!("{name}.bin")))?.write(autoload.code())?;
            serde_yml::to_writer(create_file(arm9_path.join(format!("{name}.yaml")))?, autoload.info())?;
        }

        // --------------------- Save ARM9 overlays ---------------------
        Self::save_overlays(path, &self.arm9_overlays, "arm9")?;

        // --------------------- Save ARM7 program ---------------------
        let arm7_path = path.join("arm7");
        create_dir_all(&arm7_path)?;
        create_file(arm7_path.join("arm7.bin"))?.write(self.arm7.full_data())?;
        serde_yml::to_writer(create_file(arm7_path.join("arm7.yaml"))?, self.arm7.offsets())?;

        // --------------------- Save ARM7 overlays ---------------------
        Self::save_overlays(path, &self.arm7_overlays, "arm7")?;

        // --------------------- Save banner ---------------------
        {
            let path = &path.join("banner");
            create_dir_all(path)?;

            serde_yml::to_writer(create_file(path.join("banner.yaml"))?, &self.banner)?;
            self.banner.images.save_bitmap_file(path)?;
        }

        // --------------------- Save files ---------------------
        {
            log::info!("Saving ROM assets");
            let files_path = path.join("files");
            self.files.traverse_files(["/"], |file, path| {
                let path = files_path.join(path);
                // TODO: Rewrite traverse_files as an iterator so these errors can be returned
                create_dir_all(&path).expect("failed to create file directory");
                create_file(&path.join(file.name()))
                    .expect("failed to create file")
                    .write(file.contents())
                    .expect("failed to write file");
            });
        }
        let mut path_order_file = create_file(path.join("path_order.txt"))?;
        for path in &self.path_order {
            path_order_file.write(path.as_bytes())?;
            path_order_file.write("\n".as_bytes())?;
        }

        Ok(())
    }

    fn save_overlays(path: &Path, overlays: &[Overlay], processor: &str) -> Result<(), RomSaveError> {
        if !overlays.is_empty() {
            let path = &path.join(format!("{processor}_overlays"));
            create_dir_all(path)?;

            let mut configs = vec![];
            for overlay in overlays {
                let name = format!("ov{:03}", overlay.id());

                let mut plain_overlay = overlay.clone();
                configs.push(OverlayConfig { info: plain_overlay.info().clone(), file_name: format!("{name}.bin") });

                if plain_overlay.is_compressed() {
                    log::info!("Decompressing {processor} overlay {}/{}", overlay.id(), overlays.len() - 1);
                    plain_overlay.decompress();
                }
                create_file(path.join(format!("{name}.bin")))?.write(plain_overlay.code())?;
            }
            serde_yml::to_writer(create_file(path.join("overlays.yaml"))?, &configs)?;
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
        let fnt = rom.fnt()?;
        let fat = rom.fat()?;
        let banner = rom.banner()?;
        let file_root = FileSystem::parse(&fnt, fat, rom)?;
        let path_order = file_root.compute_path_order();
        Ok(Self {
            header: Header::load_raw(&header, Some(rom.padding_value()?)),
            header_logo: Logo::decompress(&header.logo)?,
            arm9: rom.arm9()?,
            arm9_overlays: rom
                .arm9_overlay_table()?
                .iter()
                .map(|ov| Overlay::parse(ov, fat, rom))
                .collect::<Result<Vec<_>, _>>()?,
            arm7: rom.arm7()?,
            arm7_overlays: rom
                .arm7_overlay_table()?
                .iter()
                .map(|ov| Overlay::parse(ov, fat, rom))
                .collect::<Result<Vec<_>, _>>()?,
            banner: Banner::load_raw(&banner),
            files: file_root,
            path_order,
        })
    }

    /// Builds a raw ROM.
    ///
    /// # Errors
    ///
    /// This function will return an error if an I/O operation fails or a component fails to build.
    pub fn build(mut self, key: Option<&BlowfishKey>) -> Result<raw::Rom<'a>, RomBuildError> {
        let mut context = BuildContext::default();
        context.blowfish_key = key;

        let mut cursor = Cursor::new(Vec::with_capacity(128 * 1024)); // smallest possible ROM

        // --------------------- Write header placeholder ---------------------
        context.header_offset = Some(cursor.position() as u32);
        cursor.write(&[0u8; size_of::<raw::Header>()])?;
        self.align(&mut cursor)?;

        // --------------------- Write ARM9 program ---------------------
        context.arm9_offset = Some(cursor.position() as u32);
        context.arm9_autoload_callback = Some(self.arm9.autoload_callback());
        context.arm9_build_info_offset = Some(self.arm9.build_info_offset());
        cursor.write(self.arm9.full_data())?;
        let footer = Arm9Footer::new(self.arm9.build_info_offset());
        cursor.write(bytemuck::bytes_of(&footer))?;
        self.align(&mut cursor)?;

        let max_file_id = self.files.max_file_id();
        let mut file_allocs = vec![FileAlloc::default(); max_file_id as usize + 1];

        if !self.arm9_overlays.is_empty() {
            // --------------------- Write ARM9 overlay table ---------------------
            context.arm9_ovt_offset = Some(TableOffset {
                offset: cursor.position() as u32,
                size: (self.arm9_overlays.len() * size_of::<raw::Overlay>()) as u32,
            });
            for overlay in &self.arm9_overlays {
                let raw = overlay.build();
                cursor.write(bytemuck::bytes_of(&raw))?;
            }
            self.align(&mut cursor)?;

            // --------------------- Write ARM9 overlays ---------------------
            for overlay in &self.arm9_overlays {
                let start = cursor.position() as u32;
                let end = start + overlay.full_data().len() as u32;
                file_allocs[overlay.file_id() as usize] = FileAlloc { start, end };

                cursor.write(overlay.full_data())?;
                self.align(&mut cursor)?;
            }
        }

        // --------------------- Write ARM7 program ---------------------
        context.arm7_offset = Some(cursor.position() as u32);
        context.arm7_autoload_callback = Some(self.arm7.autoload_callback());
        context.arm7_build_info_offset = None;
        cursor.write(self.arm7.full_data())?;
        self.align(&mut cursor)?;

        if !self.arm7_overlays.is_empty() {
            // --------------------- Write ARM7 overlay table ---------------------
            context.arm7_ovt_offset = Some(TableOffset {
                offset: cursor.position() as u32,
                size: (self.arm7_overlays.len() * size_of::<raw::Overlay>()) as u32,
            });
            for overlay in &self.arm7_overlays {
                let raw = overlay.build();
                cursor.write(bytemuck::bytes_of(&raw))?;
            }
            self.align(&mut cursor)?;

            // --------------------- Write ARM7 overlays ---------------------
            for overlay in &self.arm7_overlays {
                let start = cursor.position() as u32;
                let end = start + overlay.full_data().len() as u32;
                file_allocs[overlay.file_id() as usize] = FileAlloc { start, end };

                cursor.write(overlay.full_data())?;
                self.align(&mut cursor)?;
            }
        }

        // --------------------- Write file name table (FNT) ---------------------
        self.files.sort_for_fnt();
        let fnt = self.files.build_fnt()?.build()?;
        context.fnt_offset = Some(TableOffset { offset: cursor.position() as u32, size: fnt.len() as u32 });
        cursor.write(&fnt)?;
        self.align(&mut cursor)?;

        // --------------------- Write file allocation table (FAT) placeholder ---------------------
        context.fat_offset =
            Some(TableOffset { offset: cursor.position() as u32, size: (file_allocs.len() * size_of::<FileAlloc>()) as u32 });
        cursor.write(bytemuck::cast_slice(&file_allocs))?;
        self.align(&mut cursor)?;

        // --------------------- Write banner ---------------------
        let banner = self.banner.build()?;
        context.banner_offset = Some(TableOffset { offset: cursor.position() as u32, size: banner.full_data().len() as u32 });
        cursor.write(banner.full_data())?;
        self.align(&mut cursor)?;

        // --------------------- Write files ---------------------
        self.files.sort_for_rom();
        self.files.traverse_files(self.path_order.iter().map(|s| s.as_str()), |file, _| {
            // TODO: Rewrite traverse_files as an iterator so these errors can be returned
            self.align(&mut cursor).expect("failed to align before file");

            let contents = file.contents();
            let start = cursor.position() as u32;
            let end = start + contents.len() as u32;
            file_allocs[file.id() as usize] = FileAlloc { start, end };

            cursor.write(contents).expect("failed to write file contents");
        });

        // --------------------- Write padding ---------------------
        context.rom_size = Some(cursor.position() as u32);
        while !cursor.position().is_power_of_two() && cursor.position() >= 128 * 1024 {
            cursor.write(&[self.header.padding_value])?;
        }

        // --------------------- Update FAT ---------------------
        cursor.set_position(context.fat_offset.unwrap().offset as u64);
        cursor.write(&bytemuck::cast_slice(&file_allocs))?;

        // --------------------- Update header ---------------------
        cursor.set_position(context.header_offset.unwrap() as u64);
        let header = self.header.build(&context, &self)?;
        cursor.write(bytemuck::bytes_of(&header))?;

        Ok(raw::Rom::new(cursor.into_inner()))
    }

    fn align(&self, cursor: &mut Cursor<Vec<u8>>) -> Result<(), RomBuildError> {
        let padding = (!cursor.position() + 1) & 0x1ff;
        for _ in 0..padding {
            cursor.write(&[self.header.padding_value])?;
        }
        Ok(())
    }

    /// Returns a reference to the header logo of this [`Rom`].
    pub fn header_logo(&self) -> &Logo {
        &self.header_logo
    }

    /// Returns a reference to the ARM9 program of this [`Rom`].
    pub fn arm9(&self) -> &Arm9 {
        &self.arm9
    }

    /// Returns a reference to the ARM9 overlays of this [`Rom`].
    pub fn arm9_overlays(&self) -> &[Overlay] {
        &self.arm9_overlays
    }

    /// Returns a reference to the ARM7 program of this [`Rom`].
    pub fn arm7(&self) -> &Arm7 {
        &self.arm7
    }

    /// Returns a reference to the ARM7 overlays of this [`Rom`].
    pub fn arm7_overlays(&self) -> &[Overlay] {
        &self.arm7_overlays
    }

    /// Returns a reference to the header of this [`Rom`].
    pub fn header(&self) -> &Header {
        &self.header
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
}

/// Options for [`Rom::load`].
pub struct RomLoadOptions<'a> {
    /// Blowfish encryption key.
    pub key: Option<&'a BlowfishKey>,
    /// If true (default), compress ARM9 and overlays if they are configured with `compressed: true`.
    pub compress: bool,
    /// If true (default), encrypt ARM9 if it's configured with `encrypted: true`.
    pub encrypt: bool,
    /// If true (default), load asset files.
    pub load_files: bool,
}

impl<'a> Default for RomLoadOptions<'a> {
    fn default() -> Self {
        Self { key: None, compress: true, encrypt: true, load_files: true }
    }
}
