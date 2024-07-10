use std::{
    mem::{align_of, size_of},
    str::from_utf8,
};

use bytemuck::{Pod, PodCastError, Zeroable};
use snafu::{Backtrace, Snafu};

use crate::str::print_hex;

use super::RawHeaderError;

pub struct Fnt<'a> {
    pub subtables: Box<[FntSubtable<'a>]>,
}

#[repr(C)]
#[derive(Clone, Copy, Zeroable, Pod)]
pub struct FntDirectory {
    pub subtable_offset: u32,
    pub first_file_id: u16,
    pub parent_id: u16,
}

pub struct FntSubtable<'a> {
    pub directory: &'a FntDirectory,
    pub data: &'a [u8],
}

#[derive(Debug, Snafu)]
pub enum RawFntError {
    #[snafu(transparent)]
    RawHeader { source: RawHeaderError },
    #[snafu(display("file name table must be at least {} bytes long:\n{backtrace}", size_of::<FntDirectory>()))]
    InvalidSize { backtrace: Backtrace },
    #[snafu(display("expected {expected}-alignment for {section} but got {actual}-alignment:\n{backtrace}"))]
    Misaligned { expected: usize, actual: usize, section: &'static str, backtrace: Backtrace },
    #[snafu(display("encountered an unterminated subtable in the file name table:\n{backtrace}"))]
    UnterminatedSubtable { backtrace: Backtrace },
}

impl<'a> Fnt<'a> {
    fn check_size(data: &'_ [u8]) -> Result<(), RawFntError> {
        let size = size_of::<FntDirectory>();
        if data.len() < size {
            InvalidSizeSnafu {}.fail()
        } else {
            Ok(())
        }
    }

    fn handle_pod_cast<T>(result: Result<T, PodCastError>, addr: usize, section: &'static str) -> Result<T, RawFntError> {
        match result {
            Ok(x) => Ok(x),
            Err(PodCastError::TargetAlignmentGreaterAndInputNotAligned) => {
                MisalignedSnafu { expected: align_of::<T>(), actual: 1usize << addr.leading_zeros(), section }.fail()
            }
            Err(PodCastError::AlignmentMismatch) => panic!(),
            Err(PodCastError::OutputSliceWouldHaveSlop) => panic!(),
            Err(PodCastError::SizeMismatch) => unreachable!(),
        }
    }

    pub fn borrow_from_slice(data: &'a [u8]) -> Result<Self, RawFntError> {
        Self::check_size(data)?;
        let addr = data as *const [u8] as *const () as usize;
        let size = size_of::<FntDirectory>();
        let root_dir: &FntDirectory = Self::handle_pod_cast(bytemuck::try_from_bytes(&data[..size]), addr, "root directory")?;

        // the root entry has no parent, so `parent_id` is instead the number of directories
        let num_dirs = root_dir.parent_id as usize;
        let directories: &[FntDirectory] =
            Self::handle_pod_cast(bytemuck::try_cast_slice(&data[..size * num_dirs]), addr, "directories")?;

        let mut subtables = Vec::with_capacity(directories.len());
        for directory in directories {
            let start = directory.subtable_offset as usize;
            let Some(length) = data[start..].iter().position(|b| *b == 0) else {
                return UnterminatedSubtableSnafu {}.fail();
            };
            subtables.push(FntSubtable { directory, data: &data[start..start + length] });
        }

        Ok(Self { subtables: subtables.into_boxed_slice() })
    }
}

impl<'a> FntSubtable<'a> {
    pub fn iter(&self) -> IterFntSubtable {
        IterFntSubtable { data: &self.data, id: self.directory.first_file_id }
    }
}

pub struct IterFntSubtable<'a> {
    data: &'a [u8],
    id: u16,
}

impl<'a> Iterator for IterFntSubtable<'a> {
    type Item = FntFile<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.data.is_empty() {
            return None;
        }

        let length = self.data[0] as usize & 0x7f;
        let subdir = self.data[0] & 0x80 != 0;
        self.data = &self.data[1..];

        let name = from_utf8(&self.data[..length]).expect("file name could not be parsed");
        self.data = &self.data[length..];

        let id = if subdir {
            let id = u16::from_le_bytes([self.data[0], self.data[1]]);
            self.data = &self.data[2..];
            id
        } else {
            let id = self.id;
            self.id += 1;
            id
        };

        Some(FntFile { id, name })
    }
}

pub struct FntFile<'a> {
    pub id: u16,
    pub name: &'a str,
}
