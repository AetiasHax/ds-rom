use std::{
    fmt::Display,
    mem::{align_of, size_of},
    usize,
};

use bytemuck::{Pod, PodCastError, Zeroable};
use snafu::{Backtrace, Snafu};

use super::RawHeaderError;

#[repr(C)]
#[derive(Clone, Copy, Zeroable, Pod)]
pub struct Overlay {
    pub id: u32,
    pub base_addr: u32,
    pub code_size: u32,
    pub bss_size: u32,
    pub ctor_start: u32,
    pub ctor_end: u32,
    pub file_id: u32,
    compressed_size: u32,
}

#[derive(Snafu, Debug)]
pub enum RawOverlayError {
    #[snafu(transparent)]
    RawHeader { source: RawHeaderError },
    #[snafu(display("the overlay table does not end with 0xFF values:\n{backtrace}"))]
    NoEnd { backtrace: Backtrace },
    #[snafu(display("expected {expected}-alignment for overlay table but got {actual}-alignment:\n{backtrace}"))]
    Misaligned { expected: usize, actual: usize, backtrace: Backtrace },
}

impl Overlay {
    pub fn borrow_from_slice(data: &'_ [u8]) -> Result<&'_ [Self], RawOverlayError> {
        let size = size_of::<Self>();
        let Some(num_overlays) = data.chunks_exact(size).position(|xs| xs.iter().all(|x| *x == 0xff)) else {
            return Err(NoEndSnafu {}.build());
        };
        let addr = data as *const [u8] as *const () as usize;
        match bytemuck::try_cast_slice(&data[..num_overlays * size]) {
            Ok(table) => Ok(table),
            Err(PodCastError::TargetAlignmentGreaterAndInputNotAligned) => {
                MisalignedSnafu { expected: align_of::<Self>(), actual: 1usize << addr.leading_zeros() }.fail()
            }
            Err(PodCastError::SizeMismatch) => panic!(),
            Err(PodCastError::OutputSliceWouldHaveSlop) => panic!(),
            Err(PodCastError::AlignmentMismatch) => unreachable!(),
        }
    }

    pub fn compressed_size(&self) -> u32 {
        self.compressed_size & 0xffffff
    }

    pub fn set_compressed_size(&mut self, value: u32) {
        self.compressed_size = (self.compressed_size & !0xffffff) | (value & 0xffffff);
    }

    pub fn is_compressed(&self) -> bool {
        (self.compressed_size >> 24) != 0
    }

    pub fn set_is_compressed(&mut self, value: bool) {
        self.compressed_size &= 0xffffff;
        if value {
            self.compressed_size |= 0x01000000;
        }
    }

    pub fn display(&self, indent: usize) -> DisplayOverlay {
        DisplayOverlay { overlay: self, indent }
    }
}

pub struct DisplayOverlay<'a> {
    overlay: &'a Overlay,
    indent: usize,
}

impl<'a> Display for DisplayOverlay<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let i = format!("{:indent$}", "", indent = self.indent);
        let overlay = &self.overlay;
        writeln!(f, "{i}ID ............... : {}", overlay.id)?;
        writeln!(f, "{i}File ID .......... : {}", overlay.file_id)?;
        writeln!(f, "{i}Base address ..... : {:#x}", overlay.base_addr)?;
        writeln!(f, "{i}Code size ........ : {:#x}", overlay.code_size)?;
        writeln!(f, "{i}.bss size ........ : {:#x}", overlay.bss_size)?;
        writeln!(f, "{i}.ctor start ...... : {:#x}", overlay.ctor_start)?;
        writeln!(f, "{i}.ctor end ........ : {:#x}", overlay.ctor_end)?;
        writeln!(f, "{i}Compressed size .. : {:#x}", overlay.compressed_size())?;
        writeln!(f, "{i}Is compressed .... : {}", overlay.is_compressed())?;
        Ok(())
    }
}
