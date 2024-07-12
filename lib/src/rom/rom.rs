use std::{
    io::{self, Cursor, Write},
    mem::size_of,
};

use snafu::Snafu;

use super::{
    raw::{self, Banner, TableOffset},
    Arm7, Arm9, Autoload, File, Header, Logo, Overlay,
};

pub struct Rom<'a> {
    header: Header,
    header_logo: Logo,
    arm9: Arm9<'a>,
    arm9_overlays: Vec<Overlay<'a>>,
    arm7: Arm7<'a>,
    arm7_overlays: Vec<Overlay<'a>>,
    itcm: Autoload<'a>,
    dtcm: Autoload<'a>,
    banner: Banner<'a>,
    file_root: File<'a>,
}

#[derive(Snafu, Debug)]
pub enum RomBuildError {
    #[snafu(transparent)]
    Io { source: io::Error },
}

impl<'a> Rom<'a> {
    pub fn build(&self) -> Result<raw::Rom, RomBuildError> {
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

        todo!()
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
