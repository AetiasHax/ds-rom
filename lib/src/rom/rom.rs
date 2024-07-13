use std::{
    io::{self, Cursor, Write},
    mem::size_of,
};

use snafu::Snafu;

use crate::rom::raw::FileAlloc;

use super::{
    raw::{self, TableOffset},
    Arm7, Arm9, Banner, BannerError, File, FileBuildError, Header, HeaderBuildError, Logo, Overlay,
};

pub struct Rom<'a> {
    header: Header,
    header_logo: Logo,
    arm9: Arm9<'a>,
    arm9_overlays: Vec<Overlay<'a>>,
    arm7: Arm7<'a>,
    arm7_overlays: Vec<Overlay<'a>>,
    banner: Banner,
    file_root: File<'a>,
    path_order: Vec<String>,
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

impl<'a> Rom<'a> {
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

        let max_file_id = self.file_root.max_file_id();
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
        self.file_root.sort_for_fnt();
        let fnt = self.file_root.build_fnt()?.build()?;
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
        self.file_root.sort_for_rom();
        self.file_root.traverse_files(self.path_order.iter().map(|s| s.as_str()), |file| {
            // TODO: Rewrite traverse_files as an iterator so these errors can be returned
            let contents = file.contents().expect("file contents missing");

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
    pub blowfish_key: Option<&'a [u8]>,
    pub arm9_autoload_callback: Option<u32>,
    pub arm7_autoload_callback: Option<u32>,
    pub arm9_build_info_offset: Option<u32>,
    pub arm7_build_info_offset: Option<u32>,

    pub rom_size: Option<u32>,
}
