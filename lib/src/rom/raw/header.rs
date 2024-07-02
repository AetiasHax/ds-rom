use std::{
    fmt::Display,
    mem::{align_of, size_of},
};

use bytemuck::{Pod, PodCastError, Zeroable};
use snafu::{Backtrace, Snafu};

use crate::str::{write_blob_size, AsciiArray};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Header {
    pub title: AsciiArray<12>,
    pub gamecode: AsciiArray<4>,
    pub makercode: AsciiArray<2>,
    pub unitcode: u8,
    pub seed_select: u8,
    pub capacity: Capacity,
    pub reserved0: [u8; 8],
    pub ds_region: DsRegion,
    pub rom_version: u8,
    pub autostart: u8,
    pub arm9: ProgramOffset,
    pub arm7: ProgramOffset,
    pub file_names: TableOffset,
    pub file_allocs: TableOffset,
    pub arm9_overlays: TableOffset,
    pub arm7_overlays: TableOffset,
    pub normal_cmd_setting: u32,
    pub key1_cmd_setting: u32,
    pub banner_offset: u32,
    pub secure_area_crc: u16,
    pub secure_area_delay: Delay,
    pub arm9_autoload_callback: u32,
    pub arm7_autoload_callback: u32,
    pub secure_area_disable: u64,
    pub rom_size: u32,
    pub header_size: u32,
    pub autoload_block_infos_offset: u32,
    pub reserved1: [u8; 8],
    pub rom_end: u16,
    pub rw_end: u16,
    pub reserved2: [u8; 0x18],
    pub reserved3: [u8; 0x10],
    pub logo: [u8; 0x9c],
    pub logo_crc: u16,
    pub header_crc: u16,
    pub debug_rom_offset: u32,
    pub debug_size: u32,
    pub debug_ram_addr: u32,
    pub reserved4: [u8; 4],
    pub reserved5: [u8; 0x90],
    pub reserved6: [u8; 0xe00],
    pub reserved7: [u8; 0x3000],
}

unsafe impl Zeroable for Header {}
unsafe impl Pod for Header {}

#[derive(Debug, Snafu)]
pub enum RawHeaderError {
    #[snafu(display("expected {expected:#x} bytes for header but had only {actual:#x}:\n{backtrace}"))]
    DataTooSmall { expected: usize, actual: usize, backtrace: Backtrace },
    #[snafu(display("expected {expected}-alignment for header but got {actual}-alignment:\n{backtrace}"))]
    Misaligned { expected: usize, actual: usize, backtrace: Backtrace },
}

impl Header {
    pub fn borrow_from_slice(data: &'_ [u8]) -> Result<&'_ Self, RawHeaderError> {
        let size = size_of::<Self>();
        if data.len() < size {
            DataTooSmallSnafu { expected: size, actual: data.len() }.fail()
        } else {
            let addr = data as *const [u8] as *const () as usize;
            match bytemuck::try_from_bytes(&data[..size]) {
                Ok(header) => Ok(header),
                Err(PodCastError::TargetAlignmentGreaterAndInputNotAligned) => {
                    MisalignedSnafu { expected: align_of::<Self>(), actual: 1usize << addr.leading_zeros() }.fail()
                }
                Err(PodCastError::AlignmentMismatch) => panic!(),
                Err(PodCastError::OutputSliceWouldHaveSlop) => panic!(),
                Err(PodCastError::SizeMismatch) => unreachable!(),
            }
        }
    }

    pub fn borrow_from_slice_mut(data: &'_ mut [u8]) -> Result<&'_ mut Self, RawHeaderError> {
        let size = size_of::<Self>();
        if data.len() < size {
            DataTooSmallSnafu { expected: size, actual: data.len() }.fail()
        } else {
            let addr = data as *const [u8] as *const () as usize;
            match bytemuck::try_from_bytes_mut(&mut data[..size]) {
                Ok(header) => Ok(header),
                Err(PodCastError::TargetAlignmentGreaterAndInputNotAligned) => {
                    MisalignedSnafu { expected: align_of::<Self>(), actual: 1usize << addr.leading_zeros() }.fail()
                }
                Err(PodCastError::AlignmentMismatch) => panic!(),
                Err(PodCastError::OutputSliceWouldHaveSlop) => panic!(),
                Err(PodCastError::SizeMismatch) => unreachable!(),
            }
        }
    }

    pub fn display(&self, indent: usize) -> DisplayHeader {
        DisplayHeader { header: self, indent }
    }
}

pub struct DisplayHeader<'a> {
    header: &'a Header,
    indent: usize,
}

impl<'a> Display for DisplayHeader<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let i = format!("{:indent$}", "", indent = self.indent);
        let header = &self.header;
        writeln!(f, "{i}Title ................... : {}", header.title)?;
        writeln!(f, "{i}Gamecode ................ : {}", header.gamecode)?;
        writeln!(f, "{i}Makercode ............... : {}", header.makercode)?;
        writeln!(f, "{i}Unitcode ................ : {}", header.unitcode)?;
        writeln!(f, "{i}DS region ............... : {}", header.ds_region)?;
        writeln!(f, "{i}Capacity ................ : {}", header.capacity)?;
        write!(f, "{i}ROM size ................ : ")?;
        write_blob_size(f, header.rom_size)?;
        writeln!(f, " ({:#x})", header.rom_size)?;
        writeln!(f, "{i}ROM version ............. : {}", header.rom_version)?;
        write!(f, "{i}ARM9 program\n{}", header.arm9.display(self.indent + 2))?;
        writeln!(f, "{i}ARM9 autoload callback .. : {:#x}", header.arm9_autoload_callback)?;
        write!(f, "{i}ARM7 program\n{}", header.arm7.display(self.indent + 2))?;
        writeln!(f, "{i}ARM7 autoload callback .. : {:#x}", header.arm7_autoload_callback)?;
        write!(f, "{i}File name table\n{}", header.file_names.display(self.indent + 2))?;
        write!(f, "{i}File allocation table\n{}", header.file_allocs.display(self.indent + 2))?;
        writeln!(f, "{i}Banner\n{i}  Offset: {:#x}", header.banner_offset)?;
        writeln!(f, "{i}Normal cmd setting ...... : {:#x}", header.normal_cmd_setting)?;
        writeln!(f, "{i}KEY1 cmd setting ........ : {:#x}", header.key1_cmd_setting)?;
        writeln!(f, "{i}Autoload info offset .... : {:#x}", header.autoload_block_infos_offset)?;
        writeln!(f, "{i}Seed select ............. : {:#x}", header.seed_select)?;
        writeln!(f, "{i}Autostart ............... : {:#x}", header.autostart)?;
        writeln!(f, "{i}Secure area disable ..... : {:#x}", header.secure_area_disable)?;
        writeln!(f, "{i}Secure area delay ....... : {} ({:#x})", header.secure_area_delay, header.secure_area_delay.0)?;
        writeln!(f, "{i}Secure area CRC ......... : {:#x}", header.secure_area_crc)?;
        writeln!(f, "{i}Logo CRC ................ : {:#x}", header.logo_crc)?;
        writeln!(f, "{i}Header CRC .............. : {:#x}", header.header_crc)?;
        writeln!(f, "{i}ROM end ................. : {:#x}", header.rom_end)?;
        writeln!(f, "{i}RW end .................. : {:#x}", header.rw_end)?;
        writeln!(f, "{i}Debug ROM offset ........ : {:#x}", header.debug_rom_offset)?;
        writeln!(f, "{i}Debug size .............. : {:#x}", header.debug_size)?;
        writeln!(f, "{i}Debug RAM address ....... : {:#x}", header.debug_ram_addr)?;
        writeln!(f, "{i}Header size ............. : {:#x}", header.header_size)?;
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub struct Capacity(pub u8);

impl Display for Capacity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            0..=2 => write!(f, "{}kB", 128 << self.0),
            3.. => write!(f, "{}MB", 1 << (self.0 - 3)),
        }
    }
}

#[derive(Clone, Copy)]
pub struct DsRegion(pub u8);

impl Display for DsRegion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            0x00 => write!(f, "Normal"),
            0x80 => write!(f, "China"),
            0x40 => write!(f, "Korea"),
            _ => write!(f, "Unknown"),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Zeroable, Pod)]
pub struct ProgramOffset {
    pub offset: u32,
    pub entry: u32,
    pub base_addr: u32,
    pub size: u32,
}

impl ProgramOffset {
    pub fn display(&self, indent: usize) -> DisplayProgramOffset {
        DisplayProgramOffset { offset: self, indent }
    }
}

pub struct DisplayProgramOffset<'a> {
    offset: &'a ProgramOffset,
    indent: usize,
}

impl<'a> Display for DisplayProgramOffset<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let i = format!("{:indent$}", "", indent = self.indent);
        let offset = &self.offset;
        writeln!(f, "{i}Offset ........ : {:#x}", offset.offset)?;
        writeln!(f, "{i}Entrypoint .... : {:#x}", offset.entry)?;
        writeln!(f, "{i}Base address .. : {:#x}", offset.base_addr)?;
        writeln!(f, "{i}Size .......... : {:#x}", offset.size)?;
        Ok(())
    }
}

#[repr(C)]
#[derive(Clone, Copy, Zeroable, Pod)]
pub struct TableOffset {
    pub offset: u32,
    pub size: u32,
}

impl TableOffset {
    pub fn display(&self, indent: usize) -> DisplayTableOffset {
        DisplayTableOffset { offset: self, indent }
    }
}

pub struct DisplayTableOffset<'a> {
    offset: &'a TableOffset,
    indent: usize,
}

impl<'a> Display for DisplayTableOffset<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let i = format!("{:indent$}", "", indent = self.indent);
        let offset = &self.offset;
        writeln!(f, "{i}Offset .. : {:#x}", offset.offset)?;
        writeln!(f, "{i}Size .... : {:#x}", offset.size)?;
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub struct Delay(pub u16);

impl Display for Delay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:.1}ms", self.0 as f32 / 131.072)
    }
}
