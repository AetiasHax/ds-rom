use std::{
    fs::{self, create_dir_all, File},
    io::{self, Cursor, Write},
    mem::size_of,
    path::Path,
};

use serde::{Deserialize, Serialize};
use snafu::Snafu;

use crate::{crypto::blowfish::BlowfishKey, rom::raw::FileAlloc};

use super::{
    raw::{
        self, Arm9Footer, RawBannerError, RawBuildInfoError, RawFatError, RawFntError, RawHeaderError, RawOverlayError,
        TableOffset,
    },
    Arm7, Arm9, Arm9AutoloadError, Arm9Offsets, Autoload, Banner, BannerError, BannerImageError, BannerLoadError, BuildInfo,
    FileBuildError, FileParseError, Files, FilesLoadError, Header, HeaderBuildError, HeaderLoadError, Logo, LogoError,
    LogoLoadError, LogoSaveError, Overlay, OverlayInfo, RawArm9Error,
};

pub struct Rom<'a> {
    header: Header,
    header_logo: Logo,
    arm9: Arm9<'a>,
    arm9_overlays: Vec<Overlay<'a>>,
    arm7: Arm7<'a>,
    arm7_overlays: Vec<Overlay<'a>>,
    banner: Banner,
    files: Files<'a>,
    path_order: Vec<String>,
}

#[derive(Debug, Snafu)]
pub enum RomExtractError {
    #[snafu(transparent)]
    RawHeader { source: RawHeaderError },
    #[snafu(transparent)]
    HeaderLoad { source: HeaderLoadError },
    #[snafu(transparent)]
    Logo { source: LogoError },
    #[snafu(transparent)]
    RawOverlay { source: RawOverlayError },
    #[snafu(transparent)]
    RawFnt { source: RawFntError },
    #[snafu(transparent)]
    RawFat { source: RawFatError },
    #[snafu(transparent)]
    RawBanner { source: RawBannerError },
    #[snafu(transparent)]
    BannerLoad { source: BannerLoadError },
    #[snafu(transparent)]
    FileParse { source: FileParseError },
}

#[derive(Snafu, Debug)]
pub enum RomBuildError {
    #[snafu(transparent)]
    Io { source: io::Error },
    #[snafu(transparent)]
    FileBuild { source: FileBuildError },
    #[snafu(transparent)]
    Banner { source: BannerError },
    #[snafu(transparent)]
    HeaderBuild { source: HeaderBuildError },
}

#[derive(Snafu, Debug)]
pub enum RomSaveError {
    #[snafu(display("blowfish key is required because ARM9 program is encrypted"))]
    BlowfishKeyNeeded,
    #[snafu(transparent)]
    Io { source: io::Error },
    #[snafu(transparent)]
    SerdeJson { source: serde_yml::Error },
    #[snafu(transparent)]
    LogoSave { source: LogoSaveError },
    #[snafu(transparent)]
    LogoLoad { source: LogoLoadError },
    #[snafu(transparent)]
    RawBuildInfo { source: RawBuildInfoError },
    #[snafu(transparent)]
    RawArm9 { source: RawArm9Error },
    #[snafu(transparent)]
    Arm9Autoload { source: Arm9AutoloadError },
    #[snafu(transparent)]
    BannerImage { source: BannerImageError },
    #[snafu(transparent)]
    FilesLoad { source: FilesLoadError },
}

#[derive(Serialize, Deserialize)]
struct Arm9BuildConfig {
    #[serde(flatten)]
    offsets: Arm9Offsets,
    encrypted: bool,
    compressed: bool,
    #[serde(flatten)]
    build_info: BuildInfo,
}

#[derive(Serialize, Deserialize)]
struct OverlayConfig {
    #[serde(flatten)]
    info: OverlayInfo,
    file_name: String,
}

impl<'a> Rom<'a> {
    pub fn load<P: AsRef<Path>>(path: P, key: Option<&BlowfishKey>) -> Result<Self, RomSaveError> {
        let path = path.as_ref();

        // --------------------- Load header ---------------------
        let header: Header = serde_yml::from_reader(File::open(path.join("header.yaml"))?)?;
        let header_logo = Logo::from_png(path.join("header_logo.png"))?;

        // --------------------- Load ARM9 program ---------------------
        let arm9_build_config: Arm9BuildConfig = serde_yml::from_reader(File::open(path.join("arm9.yaml"))?)?;
        let arm9 = fs::read(path.join("arm9.bin"))?;

        // --------------------- Load ITCM, DTCM ---------------------
        let itcm = fs::read(path.join("itcm.bin"))?;
        let itcm_info = serde_yml::from_reader(File::open(path.join("itcm.yaml"))?)?;
        let itcm = Autoload::new(itcm, itcm_info);

        let dtcm = fs::read(path.join("dtcm.bin"))?;
        let dtcm_info = serde_yml::from_reader(File::open(path.join("dtcm.yaml"))?)?;
        let dtcm = Autoload::new(dtcm, dtcm_info);

        // --------------------- Build ARM9 program ---------------------
        let mut arm9 = Arm9::with_two_tcms(arm9, itcm, dtcm, arm9_build_config.offsets)?;
        arm9_build_config.build_info.assign_to_raw(arm9.build_info_mut()?);
        if arm9_build_config.compressed {
            arm9.compress()?;
        }
        if arm9_build_config.encrypted {
            let Some(key) = key else {
                return BlowfishKeyNeededSnafu {}.fail();
            };
            arm9.encrypt(key, header.gamecode.to_le_u32())?;
        }

        // --------------------- Load ARM9 overlays ---------------------
        let mut arm9_overlays = vec![];
        let overlays_path = path.join("arm9_overlays");
        if overlays_path.exists() && overlays_path.is_dir() {
            let overlay_configs: Vec<OverlayConfig> =
                serde_yml::from_reader(File::open(overlays_path.join("arm9_overlays.yaml"))?)?;
            for mut config in overlay_configs.into_iter() {
                let data = fs::read(overlays_path.join(config.file_name))?;
                let compressed = config.info.compressed;
                config.info.compressed = false;
                let mut overlay = Overlay::new(data, config.info);
                if compressed {
                    overlay.compress()?;
                }
                arm9_overlays.push(overlay);
            }
        }

        // --------------------- Load ARM7 program ---------------------
        let arm7 = fs::read(path.join("arm7.bin"))?;
        let arm7_config = serde_yml::from_reader(File::open(path.join("arm7.yaml"))?)?;
        let arm7 = Arm7::new(arm7, arm7_config);

        // --------------------- Load ARM7 overlays ---------------------
        let mut arm7_overlays = vec![];
        let overlays_path = path.join("arm7_overlays");
        if overlays_path.exists() && overlays_path.is_dir() {
            let overlay_configs: Vec<OverlayConfig> = serde_yml::from_reader(File::open(path.join("arm7_overlays.yaml"))?)?;
            for config in overlay_configs.into_iter() {
                let data = fs::read(overlays_path.join(config.file_name))?;
                arm7_overlays.push(Overlay::new(data, config.info));
            }
        }

        // --------------------- Load banner ---------------------
        let banner_path = path.join("banner");
        let mut banner: Banner = serde_yml::from_reader(File::open(banner_path.join("banner.yaml"))?)?;
        banner.images.load_bitmap_file(banner_path.join("bitmap.png"), banner_path.join("palette.png"))?;

        // --------------------- Load files ---------------------
        let files = Files::load(path.join("files"), arm9_overlays.len() + arm7_overlays.len())?;
        let path_order =
            fs::read_to_string(path.join("path_order.txt"))?.trim().lines().map(|l| l.to_string()).collect::<Vec<_>>();

        Ok(Self { header, header_logo, arm9, arm9_overlays, arm7, arm7_overlays, banner, files, path_order })
    }

    pub fn save<P: AsRef<Path>>(&self, path: P, key: Option<&BlowfishKey>) -> Result<(), RomSaveError> {
        let path = path.as_ref();
        create_dir_all(path)?;

        // --------------------- Save header ---------------------
        serde_yml::to_writer(File::create(path.join("header.yaml"))?, &self.header)?;
        self.header_logo.save_png(path.join("header_logo.png"))?;

        // --------------------- Save ARM9 program ---------------------
        let arm9_build_config = Arm9BuildConfig {
            offsets: *self.arm9.offsets(),
            encrypted: self.arm9.is_encrypted(),
            compressed: self.arm9.is_compressed()?,
            build_info: self.arm9.build_info()?.clone().into(),
        };
        serde_yml::to_writer(File::create(path.join("arm9.yaml"))?, &arm9_build_config)?;
        let mut plain_arm9 = self.arm9.clone();
        if plain_arm9.is_encrypted() {
            let Some(key) = key else {
                return BlowfishKeyNeededSnafu {}.fail();
            };
            plain_arm9.decrypt(key, self.header.gamecode.to_le_u32())?;
        }
        plain_arm9.decompress()?;
        File::create(path.join("arm9.bin"))?.write(plain_arm9.code()?)?;

        // --------------------- Save ITCM, DTCM ---------------------
        for autoload in plain_arm9.autoloads()?.iter() {
            let name = match autoload.kind() {
                raw::AutoloadKind::Itcm => "itcm",
                raw::AutoloadKind::Dtcm => "dtcm",
                raw::AutoloadKind::Unknown => panic!("unknown autoload block"),
            };
            File::create(path.join(format!("{name}.bin")))?.write(autoload.code())?;
            serde_yml::to_writer(File::create(path.join(format!("{name}.yaml")))?, autoload.info())?;
        }

        // --------------------- Save ARM9 overlays ---------------------
        if !self.arm9_overlays.is_empty() {
            let path = &path.join("arm9_overlays");
            create_dir_all(path)?;

            let mut configs = vec![];
            for overlay in &self.arm9_overlays {
                let name = format!("ov{:02}", overlay.id());

                let mut plain_overlay = overlay.clone();
                configs.push(OverlayConfig { info: plain_overlay.info().clone(), file_name: format!("{name}.bin") });

                plain_overlay.decompress();
                File::create(path.join(format!("{name}.bin")))?.write(plain_overlay.code())?;
            }
            serde_yml::to_writer(File::create(path.join(format!("arm9_overlays.yaml")))?, &configs)?;
        }

        // --------------------- Save ARM7 program ---------------------
        File::create(path.join("arm7.bin"))?.write(self.arm7.full_data())?;
        serde_yml::to_writer(File::create(path.join("arm7.yaml"))?, self.arm7.offsets())?;

        // --------------------- Save ARM7 overlays ---------------------
        if !self.arm7_overlays.is_empty() {
            let path = &path.join("arm7_overlays");
            create_dir_all(path)?;

            for overlay in &self.arm7_overlays {
                let name = format!("ov{:02}", overlay.id());

                let mut plain_overlay = overlay.clone();
                plain_overlay.decompress();

                File::create(path.join(format!("{name}.bin")))?.write(plain_overlay.code())?;
                serde_yml::to_writer(File::create(path.join(format!("{name}.yaml")))?, overlay.info())?;
            }
        }

        // --------------------- Save banner ---------------------
        {
            let path = &path.join("banner");
            create_dir_all(path)?;

            serde_yml::to_writer(File::create(path.join("banner.yaml"))?, &self.banner)?;
            self.banner.images.save_bitmap_file(path)?;
        }

        // --------------------- Save files ---------------------
        {
            let files_path = path.join("files");
            self.files.traverse_files(["/"], |file, path| {
                let path = files_path.join(path);
                // TODO: Rewrite traverse_files as an iterator so these errors can be returned
                create_dir_all(&path).expect("failed to create file directory");
                File::create(&path.join(file.name()))
                    .expect("failed to create file")
                    .write(file.contents())
                    .expect("failed to write file");
            });
        }
        let mut path_order_file = File::create(path.join("path_order.txt"))?;
        for path in &self.path_order {
            path_order_file.write(path.as_bytes())?;
            path_order_file.write("\n".as_bytes())?;
        }

        Ok(())
    }

    pub fn extract(rom: &'a raw::Rom) -> Result<Self, RomExtractError> {
        let header = rom.header()?;
        let fnt = rom.fnt()?;
        let fat = rom.fat()?;
        let banner = rom.banner()?;
        let file_root = Files::parse(&fnt, fat, rom)?;
        let path_order = file_root.compute_path_order();
        Ok(Self {
            header: Header::load_raw(&header)?,
            header_logo: Logo::decompress(&header.logo)?,
            arm9: rom.arm9()?,
            arm9_overlays: rom.arm9_overlay_table()?.iter().map(|ov| Overlay::parse(ov, fat, rom)).collect::<Vec<_>>(),
            arm7: rom.arm7()?,
            arm7_overlays: rom.arm7_overlay_table()?.iter().map(|ov| Overlay::parse(ov, fat, rom)).collect::<Vec<_>>(),
            banner: Banner::load_raw(&banner)?,
            files: file_root,
            path_order,
        })
    }

    pub fn build(mut self, key: Option<&BlowfishKey>) -> Result<raw::Rom<'a>, RomBuildError> {
        let mut context = BuildContext::default();
        context.blowfish_key = key;

        let mut cursor = Cursor::new(Vec::with_capacity(128 * 1024)); // smallest possible ROM

        // --------------------- Write header placeholder ---------------------
        context.header_offset = Some(cursor.position() as u32);
        cursor.write(&[0u8; size_of::<raw::Header>()])?;
        Self::align(&mut cursor)?;

        // --------------------- Write ARM9 program ---------------------
        context.arm9_offset = Some(cursor.position() as u32);
        context.arm9_autoload_callback = Some(self.arm9.autoload_callback());
        context.arm9_build_info_offset = Some(self.arm9.build_info_offset());
        cursor.write(self.arm9.full_data())?;
        let footer = Arm9Footer::new(self.arm9.build_info_offset());
        cursor.write(bytemuck::bytes_of(&footer))?;
        Self::align(&mut cursor)?;

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
            Self::align(&mut cursor)?;

            // --------------------- Write ARM9 overlays ---------------------
            for overlay in &self.arm9_overlays {
                let start = cursor.position() as u32;
                let end = start + overlay.full_data().len() as u32;
                file_allocs[overlay.file_id() as usize] = FileAlloc { start, end };

                cursor.write(overlay.full_data())?;
                Self::align(&mut cursor)?;
            }
        }

        // --------------------- Write ARM7 program ---------------------
        context.arm7_offset = Some(cursor.position() as u32);
        context.arm7_autoload_callback = Some(self.arm7.autoload_callback());
        context.arm7_build_info_offset = None;
        cursor.write(self.arm7.full_data())?;
        Self::align(&mut cursor)?;

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
            Self::align(&mut cursor)?;

            // --------------------- Write ARM7 overlays ---------------------
            for overlay in &self.arm7_overlays {
                let start = cursor.position() as u32;
                let end = start + overlay.full_data().len() as u32;
                file_allocs[overlay.file_id() as usize] = FileAlloc { start, end };

                cursor.write(overlay.full_data())?;
                Self::align(&mut cursor)?;
            }
        }

        // --------------------- Write file name table (FNT) ---------------------
        self.files.sort_for_fnt();
        let fnt = self.files.build_fnt()?.build()?;
        context.fnt_offset = Some(TableOffset { offset: cursor.position() as u32, size: fnt.len() as u32 });
        cursor.write(&fnt)?;
        Self::align(&mut cursor)?;

        // --------------------- Write file allocation table (FAT) placeholder ---------------------
        context.fat_offset =
            Some(TableOffset { offset: cursor.position() as u32, size: (file_allocs.len() * size_of::<FileAlloc>()) as u32 });
        cursor.write(bytemuck::cast_slice(&file_allocs))?;
        Self::align(&mut cursor)?;

        // --------------------- Write banner ---------------------
        let banner = self.banner.build()?;
        context.banner_offset = Some(TableOffset { offset: cursor.position() as u32, size: banner.full_data().len() as u32 });
        cursor.write(banner.full_data())?;
        Self::align(&mut cursor)?;

        // --------------------- Write files ---------------------
        self.files.sort_for_rom();
        self.files.traverse_files(self.path_order.iter().map(|s| s.as_str()), |file, path| {
            // TODO: Rewrite traverse_files as an iterator so these errors can be returned
            Self::align(&mut cursor).expect("failed to align before file");

            let contents = file.contents();
            let start = cursor.position() as u32;
            let end = start + contents.len() as u32;
            file_allocs[file.id() as usize] = FileAlloc { start, end };

            cursor.write(contents).expect("failed to write file contents");
        });

        // --------------------- Write padding ---------------------
        context.rom_size = Some(cursor.position() as u32);
        while !cursor.position().is_power_of_two() && cursor.position() >= 128 * 1024 {
            cursor.write(&[0xff])?;
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

    fn align(cursor: &mut Cursor<Vec<u8>>) -> Result<(), RomBuildError> {
        let padding = (!cursor.position() + 1) & 0x1ff;
        for _ in 0..padding {
            cursor.write(&[0xff])?;
        }
        Ok(())
    }

    pub fn header_logo(&self) -> &Logo {
        &self.header_logo
    }

    pub fn arm9(&self) -> &Arm9 {
        &self.arm9
    }

    pub fn arm9_overlays(&self) -> &[Overlay] {
        &self.arm9_overlays
    }

    pub fn arm7(&self) -> &Arm7 {
        &self.arm7
    }

    pub fn arm7_overlays(&self) -> &[Overlay] {
        &self.arm7_overlays
    }
}

#[derive(Default)]
pub struct BuildContext<'a> {
    pub header_offset: Option<u32>,
    pub arm9_offset: Option<u32>,
    pub arm7_offset: Option<u32>,
    pub fnt_offset: Option<TableOffset>,
    pub fat_offset: Option<TableOffset>,
    pub arm9_ovt_offset: Option<TableOffset>,
    pub arm7_ovt_offset: Option<TableOffset>,
    pub banner_offset: Option<TableOffset>,
    pub blowfish_key: Option<&'a BlowfishKey>,
    pub arm9_autoload_callback: Option<u32>,
    pub arm7_autoload_callback: Option<u32>,
    pub arm9_build_info_offset: Option<u32>,
    pub arm7_build_info_offset: Option<u32>,

    pub rom_size: Option<u32>,
}
