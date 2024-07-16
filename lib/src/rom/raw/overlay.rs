use std::{
    fmt::Display,
    mem::{align_of, size_of},
    usize,
};

use bitfield_struct::bitfield;
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
    pub compressed: OverlayCompressedSize,
}

#[derive(Snafu, Debug)]
pub enum RawOverlayError {
    #[snafu(transparent)]
    RawHeader { source: RawHeaderError },
    #[snafu(display("the overlay table must be a multiple of {} bytes:\n{backtrace}", size_of::<Overlay>()))]
    InvalidSize { backtrace: Backtrace },
    #[snafu(display("expected {expected}-alignment for overlay table but got {actual}-alignment:\n{backtrace}"))]
    Misaligned { expected: usize, actual: usize, backtrace: Backtrace },
}

impl Overlay {
    fn check_size(data: &[u8]) -> Result<(), RawOverlayError> {
        let size = size_of::<Self>();
        if data.len() % size != 0 {
            InvalidSizeSnafu {}.fail()
        } else {
            Ok(())
        }
    }

    pub fn borrow_from_slice(data: &'_ [u8]) -> Result<&'_ [Self], RawOverlayError> {
        Self::check_size(data)?;
        let addr = data as *const [u8] as *const () as usize;
        match bytemuck::try_cast_slice(&data) {
            Ok(table) => Ok(table),
            Err(PodCastError::TargetAlignmentGreaterAndInputNotAligned) => {
                MisalignedSnafu { expected: align_of::<Self>(), actual: 1usize << addr.trailing_zeros() }.fail()
            }
            Err(PodCastError::SizeMismatch) => panic!(),
            Err(PodCastError::OutputSliceWouldHaveSlop) => panic!(),
            Err(PodCastError::AlignmentMismatch) => unreachable!(),
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
        writeln!(f, "{i}Compressed size .. : {:#x}", overlay.compressed.size())?;
        writeln!(f, "{i}Is compressed .... : {}", overlay.compressed.is_compressed() != 0)?;
        Ok(())
    }
}

#[bitfield(u32)]
pub struct OverlayCompressedSize {
    #[bits(24)]
    pub size: usize,
    pub is_compressed: u8,
}

unsafe impl Zeroable for OverlayCompressedSize {}
unsafe impl Pod for OverlayCompressedSize {}
