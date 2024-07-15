use std::{
    fs::{self, create_dir, create_dir_all, File},
    io::{self, Cursor, Write},
    mem::size_of,
    path::Path,
};

use serde::{Deserialize, Serialize};
use snafu::{Backtrace, Snafu};

use crate::{crypto::blowfish::BlowfishKey, rom::raw::FileAlloc};

use super::{
    raw::{self, RawBannerError, RawBuildInfoError, RawFatError, RawFntError, RawHeaderError, RawOverlayError, TableOffset},
    Arm7, Arm9, Arm9AutoloadError, Arm9Offsets, Banner, BannerError, BannerImageError, BannerLoadError, BuildInfo,
    FileBuildError, FileParseError, Files, Header, HeaderBuildError, HeaderLoadError, Logo, LogoError, LogoSaveError, Overlay,
    OverlayInfo, RawArm9Error,
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
    RawBuildInfo { source: RawBuildInfoError },
    #[snafu(transparent)]
    RawArm9 { source: RawArm9Error },
    #[snafu(transparent)]
    Arm9Autoload { source: Arm9AutoloadError },
    #[snafu(transparent)]
    BannerImage { source: BannerImageError },
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

impl<'a> Rom<'a> {
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
            plain_arm9.decrypt(key, u32::from_le_bytes(self.header.gamecode.0))?;
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

            for overlay in &self.arm9_overlays {
                let name = format!("ov{:02}", overlay.id());

                let mut plain_overlay = overlay.clone();
                plain_overlay.decompress();

                File::create(path.join(format!("{name}.bin")))?.write(plain_overlay.code())?;
                serde_yml::to_writer(File::create(path.join(format!("{name}.yaml")))?, plain_overlay.info())?;
            }
        }

        // --------------------- Save ARM7 program ---------------------
        File::create(path.join("arm7.bin"))?.write(self.arm7.full_data())?;

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
                // TODO: Rewrite traverse_files as an iterator so these errors can be returned
                let path = files_path.join(path);
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

    pub fn build(mut self) -> Result<raw::Rom<'a>, RomBuildError> {
        let mut context = BuildContext::default();

        let mut cursor = Cursor::new(Vec::with_capacity(128 * 1024)); // smallest possible ROM

        // --------------------- Write header placeholder ---------------------
        context.header_offset = Some(cursor.position() as u32);
        cursor.write(&[0u8; size_of::<raw::Header>()])?;
        Self::align(&mut cursor)?;

        // --------------------- Write ARM9 program ---------------------
        context.arm9_offset = Some(cursor.position() as u32);
        cursor.write(self.arm9.full_data())?;
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
        cursor.write(&fnt)?;
        Self::align(&mut cursor)?;

        // --------------------- Write file allocation table (FAT) placeholder ---------------------
        context.fat_offset =
            Some(TableOffset { offset: cursor.position() as u32, size: (file_allocs.len() * size_of::<FileAlloc>()) as u32 });
        cursor.write(bytemuck::cast_slice(&file_allocs))?;
        Self::align(&mut cursor)?;

        // --------------------- Write banner ---------------------
        let banner = self.banner.build()?;
        cursor.write(banner.full_data())?;
        Self::align(&mut cursor)?;

        // --------------------- Write files ---------------------
        self.files.sort_for_rom();
        self.files.traverse_files(self.path_order.iter().map(|s| s.as_str()), |file, _| {
            // TODO: Rewrite traverse_files as an iterator so these errors can be returned
            let contents = file.contents();

            let start = cursor.position() as u32;
            let end = start + contents.len() as u32;
            file_allocs[file.id() as usize] = FileAlloc { start, end };

            cursor.write(contents).expect("failed to write file contents");
            Self::align(&mut cursor).expect("failed to align after file");
        });

        // --------------------- Write padding ---------------------
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
        let padding = !cursor.position() & 0x1ff;
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
