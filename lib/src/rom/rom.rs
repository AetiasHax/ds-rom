use std::io::{self, Cursor, Write};

use snafu::Snafu;

use super::{raw, Arm9, Header};

pub struct Rom<'a> {
    header: Header,
    arm9: Arm9<'a>,
}

#[derive(Snafu, Debug)]
pub enum RomBuildError {
    #[snafu(transparent)]
    Io { source: io::Error },
}

impl<'a> Rom<'a> {
    pub fn build(&self) -> Result<raw::Rom, RomBuildError> {
        let mut cursor = Cursor::new(Vec::with_capacity(128 * 1024)); // smallest possible ROM

        // --------------------- Write initial header ---------------------
        let header = self.header.build();
        cursor.write(bytemuck::bytes_of(&header))?;
        Self::align(&mut cursor)?;

        // --------------------- Write ARM9 program ---------------------
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
}
