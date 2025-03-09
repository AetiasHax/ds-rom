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
    Overlay, OverlayInfo, RomConfigAutoload,
};
use crate::{
    compress::lz77::Lz77DecompressError,
    crypto::blowfish::BlowfishKey,
    io::{create_dir_all, create_file, create_file_and_dirs, open_file, read_file, read_to_string, FileError},
    rom::{raw::FileAlloc, Arm9WithTcmsOptions, RomConfig},
};

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
    config: RomConfig,
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
    /// See [`Lz77DecompressError`].
    #[snafu(transparent)]
    Lz77Decompress {
        /// Source error.
        source: Lz77DecompressError,
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
    pub fn load<P: AsRef<Path>>(config_path: P, options: RomLoadOptions) -> Result<Self, RomSaveError> {
        let config_path = config_path.as_ref();
        log::info!("Loading ROM from {}", config_path.display());

        let config: RomConfig = serde_yml::from_reader(open_file(config_path)?)?;
        let path = config_path.parent().unwrap();

        // --------------------- Load header ---------------------
        let (header, header_logo) = if options.load_header {
            let header: Header = serde_yml::from_reader(open_file(path.join(&config.header))?)?;
            let header_logo = Logo::from_png(path.join(&config.header_logo))?;
            (header, header_logo)
        } else {
            Default::default()
        };

        // --------------------- Load ARM9 program ---------------------
        let arm9_build_config: Arm9BuildConfig = serde_yml::from_reader(open_file(path.join(&config.arm9_config))?)?;
        let arm9 = read_file(path.join(&config.arm9_bin))?;

        // --------------------- Load autoloads ---------------------
        let mut autoloads = vec![];

        let itcm = read_file(path.join(&config.itcm.bin))?;
        let itcm_info = serde_yml::from_reader(open_file(path.join(&config.itcm.config))?)?;
        let itcm = Autoload::new(itcm, itcm_info);
        autoloads.push(itcm);

        let dtcm = read_file(path.join(&config.dtcm.bin))?;
        let dtcm_info = serde_yml::from_reader(open_file(path.join(&config.dtcm.config))?)?;
        let dtcm = Autoload::new(dtcm, dtcm_info);
        autoloads.push(dtcm);

        for unknown_autoload in &config.unknown_autoloads {
            let autoload = read_file(path.join(&unknown_autoload.bin))?;
            let autoload_info = serde_yml::from_reader(open_file(path.join(&unknown_autoload.config))?)?;
            let autoload = Autoload::new(autoload, autoload_info);
            autoloads.push(autoload);
        }

        // --------------------- Build ARM9 program ---------------------
        let mut arm9 = Arm9::with_autoloads(
            arm9,
            &autoloads,
            arm9_build_config.offsets,
            Arm9WithTcmsOptions {
                originally_compressed: arm9_build_config.compressed,
                originally_encrypted: arm9_build_config.encrypted,
            },
        )?;
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
        let arm9_overlays = if let Some(arm9_overlays_config) = &config.arm9_overlays {
            Self::load_overlays(&path.join(arm9_overlays_config), "arm9", &options)?
        } else {
            vec![]
        };

        // --------------------- Load ARM7 program ---------------------
        let arm7 = read_file(path.join(&config.arm7_bin))?;
        let arm7_config = serde_yml::from_reader(open_file(path.join(&config.arm7_config))?)?;
        let arm7 = Arm7::new(arm7, arm7_config);

        // --------------------- Load ARM7 overlays ---------------------
        let arm7_overlays = if let Some(arm7_overlays_config) = &config.arm7_overlays {
            Self::load_overlays(&path.join(arm7_overlays_config), "arm7", &options)?
        } else {
            vec![]
        };

        // --------------------- Load banner ---------------------
        let banner = if options.load_banner {
            let banner_path = path.join(&config.banner);
            let banner_dir = banner_path.parent().unwrap();
            let mut banner: Banner = serde_yml::from_reader(open_file(&banner_path)?)?;
            banner.images.load(banner_dir)?;
            banner
        } else {
            Default::default()
        };

        // --------------------- Load files ---------------------
        let num_overlays = arm9_overlays.len() + arm7_overlays.len();
        let (files, path_order) = if options.load_files {
            log::info!("Loading ROM assets");
            let files = FileSystem::load(path.join(&config.files_dir), num_overlays)?;
            let path_order =
                read_to_string(path.join(&config.path_order))?.trim().lines().map(|l| l.to_string()).collect::<Vec<_>>();
            (files, path_order)
        } else {
            (FileSystem::new(num_overlays), vec![])
        };

        Ok(Self { header, header_logo, arm9, arm9_overlays, arm7, arm7_overlays, banner, files, path_order, config })
    }

    fn load_overlays(config_path: &Path, processor: &str, options: &RomLoadOptions) -> Result<Vec<Overlay<'a>>, RomSaveError> {
        let path = config_path.parent().unwrap();
        let mut overlays = vec![];
        let overlay_configs: Vec<OverlayConfig> = serde_yml::from_reader(open_file(config_path)?)?;
        let num_overlays = overlay_configs.len();
        for mut config in overlay_configs.into_iter() {
            let data = read_file(path.join(config.file_name))?;
            let compressed = config.info.compressed;
            config.info.compressed = false;
            let mut overlay = Overlay::new(data, config.info, compressed);
            if compressed && options.compress {
                log::info!("Compressing {processor} overlay {}/{}", overlay.id(), num_overlays - 1);
                overlay.compress()?;
            }
            overlays.push(overlay);
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

        log::info!("Saving ROM to directory {}", path.display());

        // --------------------- Save config ---------------------
        serde_yml::to_writer(create_file_and_dirs(path.join("config.yaml"))?, &self.config)?;

        // --------------------- Save header ---------------------
        serde_yml::to_writer(create_file_and_dirs(path.join(&self.config.header))?, &self.header)?;
        self.header_logo.save_png(path.join(&self.config.header_logo))?;

        // --------------------- Save ARM9 program ---------------------
        let arm9_build_config = self.arm9_build_config()?;
        serde_yml::to_writer(create_file_and_dirs(path.join(&self.config.arm9_config))?, &arm9_build_config)?;
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
        create_file_and_dirs(path.join(&self.config.arm9_bin))?.write_all(plain_arm9.code()?)?;

        // --------------------- Save autoloads ---------------------
        let mut unknown_autoloads = self.config.unknown_autoloads.iter();
        for autoload in plain_arm9.autoloads()?.iter() {
            let (bin_path, config_path) = match autoload.kind() {
                raw::AutoloadKind::Itcm => (path.join(&self.config.itcm.bin), path.join(&self.config.itcm.config)),
                raw::AutoloadKind::Dtcm => (path.join(&self.config.dtcm.bin), path.join(&self.config.dtcm.config)),
                raw::AutoloadKind::Unknown(_) => {
                    let unknown_autoload = unknown_autoloads.next().expect("no more autoloads in config, was it removed?");
                    (path.join(&unknown_autoload.bin), path.join(&unknown_autoload.config))
                }
            };
            create_file_and_dirs(bin_path)?.write_all(autoload.code())?;
            serde_yml::to_writer(create_file_and_dirs(config_path)?, autoload.info())?;
        }

        // --------------------- Save ARM9 overlays ---------------------
        if let Some(arm9_overlays_config) = &self.config.arm9_overlays {
            Self::save_overlays(&path.join(arm9_overlays_config), &self.arm9_overlays, "arm9")?;
        }

        // --------------------- Save ARM7 program ---------------------
        create_file_and_dirs(path.join(&self.config.arm7_bin))?.write_all(self.arm7.full_data())?;
        serde_yml::to_writer(create_file_and_dirs(path.join(&self.config.arm7_config))?, self.arm7.offsets())?;

        // --------------------- Save ARM7 overlays ---------------------
        if let Some(arm7_overlays_config) = &self.config.arm7_overlays {
            Self::save_overlays(&path.join(arm7_overlays_config), &self.arm7_overlays, "arm7")?;
        }

        // --------------------- Save banner ---------------------
        {
            let banner_path = path.join(&self.config.banner);
            let banner_dir = banner_path.parent().unwrap();
            serde_yml::to_writer(create_file_and_dirs(&banner_path)?, &self.banner)?;
            self.banner.images.save_bitmap_file(banner_dir)?;
        }

        // --------------------- Save files ---------------------
        {
            log::info!("Saving ROM assets");
            let files_path = path.join(&self.config.files_dir);
            self.files.traverse_files(["/"], |file, path| {
                let path = files_path.join(path);
                // TODO: Rewrite traverse_files as an iterator so these errors can be returned
                create_dir_all(&path).expect("failed to create file directory");
                create_file(path.join(file.name()))
                    .expect("failed to create file")
                    .write_all(file.contents())
                    .expect("failed to write file");
            });
        }
        let mut path_order_file = create_file_and_dirs(path.join(&self.config.path_order))?;
        for path in &self.path_order {
            path_order_file.write_all(path.as_bytes())?;
            path_order_file.write_all("\n".as_bytes())?;
        }

        Ok(())
    }

    /// Generates a build config for ARM9, which normally goes into arm9.yaml.
    pub fn arm9_build_config(&self) -> Result<Arm9BuildConfig, RomSaveError> {
        Ok(Arm9BuildConfig {
            offsets: *self.arm9.offsets(),
            encrypted: self.arm9.is_encrypted(),
            compressed: self.arm9.is_compressed()?,
            build_info: (*self.arm9.build_info()?).into(),
        })
    }

    fn save_overlays(config_path: &Path, overlays: &[Overlay], processor: &str) -> Result<(), RomSaveError> {
        if !overlays.is_empty() {
            let overlays_path = config_path.parent().unwrap();
            create_dir_all(overlays_path)?;

            let mut configs = vec![];
            for overlay in overlays {
                let name = format!("ov{:03}", overlay.id());

                let mut plain_overlay = overlay.clone();
                configs.push(OverlayConfig { info: plain_overlay.info().clone(), file_name: format!("{name}.bin") });

                if plain_overlay.is_compressed() {
                    log::info!("Decompressing {processor} overlay {}/{}", overlay.id(), overlays.len() - 1);
                    plain_overlay.decompress()?;
                }
                create_file(overlays_path.join(format!("{name}.bin")))?.write_all(plain_overlay.code())?;
            }
            serde_yml::to_writer(create_file(config_path)?, &configs)?;
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

        let arm9_overlays =
            rom.arm9_overlay_table()?.iter().map(|ov| Overlay::parse(ov, fat, rom)).collect::<Result<Vec<_>, _>>()?;
        let arm7_overlays =
            rom.arm7_overlay_table()?.iter().map(|ov| Overlay::parse(ov, fat, rom)).collect::<Result<Vec<_>, _>>()?;

        let arm9 = rom.arm9()?;

        let num_unknown_autoloads = if arm9.is_compressed()? {
            let mut decompressed_arm9 = arm9.clone();
            decompressed_arm9.decompress()?;
            decompressed_arm9.num_unknown_autoloads()?
        } else {
            arm9.num_unknown_autoloads()?
        };
        let unknown_autoloads = (0..num_unknown_autoloads)
            .map(|index| RomConfigAutoload {
                bin: format!("arm9/unk_autoload_{index}.bin").into(),
                config: format!("arm9/unk_autoload_{index}.yaml").into(),
            })
            .collect();

        let config = RomConfig {
            padding_value: rom.padding_value()?,
            header: "header.yaml".into(),
            header_logo: "header_logo.png".into(),
            arm9_bin: "arm9/arm9.bin".into(),
            arm9_config: "arm9/arm9.yaml".into(),
            arm7_bin: "arm7/arm7.bin".into(),
            arm7_config: "arm7/arm7.yaml".into(),
            itcm: RomConfigAutoload { bin: "arm9/itcm.bin".into(), config: "arm9/itcm.yaml".into() },
            unknown_autoloads,
            dtcm: RomConfigAutoload { bin: "arm9/dtcm.bin".into(), config: "arm9/dtcm.yaml".into() },
            arm9_overlays: if arm9_overlays.is_empty() { None } else { Some("arm9_overlays/overlays.yaml".into()) },
            arm7_overlays: if arm7_overlays.is_empty() { None } else { Some("arm7_overlays/overlays.yaml".into()) },
            banner: "banner/banner.yaml".into(),
            files_dir: "files/".into(),
            path_order: "path_order.txt".into(),
        };

        Ok(Self {
            header: Header::load_raw(header),
            header_logo: Logo::decompress(&header.logo)?,
            arm9,
            arm9_overlays,
            arm7: rom.arm7()?,
            arm7_overlays,
            banner: Banner::load_raw(&banner),
            files: file_root,
            path_order,
            config,
        })
    }

    /// Builds a raw ROM.
    ///
    /// # Errors
    ///
    /// This function will return an error if an I/O operation fails or a component fails to build.
    pub fn build(mut self, key: Option<&BlowfishKey>) -> Result<raw::Rom<'a>, RomBuildError> {
        let mut context = BuildContext { blowfish_key: key, ..Default::default() };

        let mut cursor = Cursor::new(Vec::with_capacity(128 * 1024)); // smallest possible ROM

        // --------------------- Write header placeholder ---------------------
        context.header_offset = Some(cursor.position() as u32);
        cursor.write_all(&[0u8; size_of::<raw::Header>()])?;
        self.align(&mut cursor)?;

        // --------------------- Write ARM9 program ---------------------
        context.arm9_offset = Some(cursor.position() as u32);
        context.arm9_autoload_callback = Some(self.arm9.autoload_callback());
        context.arm9_build_info_offset = Some(self.arm9.build_info_offset());
        cursor.write_all(self.arm9.full_data())?;
        let footer = Arm9Footer::new(self.arm9.build_info_offset());
        cursor.write_all(bytemuck::bytes_of(&footer))?;
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
                cursor.write_all(bytemuck::bytes_of(&raw))?;
            }
            self.align(&mut cursor)?;

            // --------------------- Write ARM9 overlays ---------------------
            for overlay in &self.arm9_overlays {
                let start = cursor.position() as u32;
                let end = start + overlay.full_data().len() as u32;
                file_allocs[overlay.file_id() as usize] = FileAlloc { start, end };

                cursor.write_all(overlay.full_data())?;
                self.align(&mut cursor)?;
            }
        }

        // --------------------- Write ARM7 program ---------------------
        context.arm7_offset = Some(cursor.position() as u32);
        context.arm7_autoload_callback = Some(self.arm7.autoload_callback());
        context.arm7_build_info_offset = None;
        cursor.write_all(self.arm7.full_data())?;
        self.align(&mut cursor)?;

        if !self.arm7_overlays.is_empty() {
            // --------------------- Write ARM7 overlay table ---------------------
            context.arm7_ovt_offset = Some(TableOffset {
                offset: cursor.position() as u32,
                size: (self.arm7_overlays.len() * size_of::<raw::Overlay>()) as u32,
            });
            for overlay in &self.arm7_overlays {
                let raw = overlay.build();
                cursor.write_all(bytemuck::bytes_of(&raw))?;
            }
            self.align(&mut cursor)?;

            // --------------------- Write ARM7 overlays ---------------------
            for overlay in &self.arm7_overlays {
                let start = cursor.position() as u32;
                let end = start + overlay.full_data().len() as u32;
                file_allocs[overlay.file_id() as usize] = FileAlloc { start, end };

                cursor.write_all(overlay.full_data())?;
                self.align(&mut cursor)?;
            }
        }

        // --------------------- Write file name table (FNT) ---------------------
        self.files.sort_for_fnt();
        let fnt = self.files.build_fnt()?.build()?;
        context.fnt_offset = Some(TableOffset { offset: cursor.position() as u32, size: fnt.len() as u32 });
        cursor.write_all(&fnt)?;
        self.align(&mut cursor)?;

        // --------------------- Write file allocation table (FAT) placeholder ---------------------
        context.fat_offset =
            Some(TableOffset { offset: cursor.position() as u32, size: (file_allocs.len() * size_of::<FileAlloc>()) as u32 });
        cursor.write_all(bytemuck::cast_slice(&file_allocs))?;
        self.align(&mut cursor)?;

        // --------------------- Write banner ---------------------
        let banner = self.banner.build()?;
        context.banner_offset = Some(TableOffset { offset: cursor.position() as u32, size: banner.full_data().len() as u32 });
        cursor.write_all(banner.full_data())?;
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

            cursor.write_all(contents).expect("failed to write file contents");
        });

        // --------------------- Write padding ---------------------
        context.rom_size = Some(cursor.position() as u32);
        while !cursor.position().is_power_of_two() && cursor.position() >= 128 * 1024 {
            cursor.write_all(&[self.config.padding_value])?;
        }

        // --------------------- Update FAT ---------------------
        cursor.set_position(context.fat_offset.unwrap().offset as u64);
        cursor.write_all(bytemuck::cast_slice(&file_allocs))?;

        // --------------------- Update header ---------------------
        cursor.set_position(context.header_offset.unwrap() as u64);
        let header = self.header.build(&context, &self)?;
        cursor.write_all(bytemuck::bytes_of(&header))?;

        Ok(raw::Rom::new(cursor.into_inner()))
    }

    fn align(&self, cursor: &mut Cursor<Vec<u8>>) -> Result<(), RomBuildError> {
        let padding = (!cursor.position() + 1) & 0x1ff;
        for _ in 0..padding {
            cursor.write_all(&[self.config.padding_value])?;
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

    /// Returns the [`RomConfig`] consisting of paths to extracted files.
    pub fn config(&self) -> &RomConfig {
        &self.config
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
    /// If true (default), load header and header logo.
    pub load_header: bool,
    /// If true (default), load banner.
    pub load_banner: bool,
}

impl<'a> Default for RomLoadOptions<'a> {
    fn default() -> Self {
        Self { key: None, compress: true, encrypt: true, load_files: true, load_header: true, load_banner: true }
    }
}
