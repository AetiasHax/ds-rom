use std::{
    borrow::Cow,
    io::{self, Write},
    mem::{align_of, size_of},
    str::from_utf8,
};

use bytemuck::{Pod, PodCastError, Zeroable};
use snafu::{Backtrace, Snafu};

use super::RawHeaderError;

pub struct Fnt<'a> {
    /// Every directory has one subtable, indexed by `dir_id & 0xfff`
    pub subtables: Box<[FntSubtable<'a>]>,
}

#[repr(C)]
#[derive(Clone, Copy, Zeroable, Pod)]
pub struct FntDirectory {
    pub subtable_offset: u32,
    pub first_file_id: u16,
    pub parent_id: u16,
}

/// Contains a directory's immediate children (files and folders).
pub struct FntSubtable<'a> {
    pub directory: Cow<'a, FntDirectory>,
    pub data: Cow<'a, [u8]>,
}

#[derive(Debug, Snafu)]
pub enum RawFntError {
    #[snafu(transparent)]
    RawHeader { source: RawHeaderError },
    #[snafu(display("file name table must be at least {} bytes long:\n{backtrace}", size_of::<FntDirectory>()))]
    InvalidSize { backtrace: Backtrace },
    #[snafu(display("expected {expected}-alignment for {section} but got {actual}-alignment:\n{backtrace}"))]
    Misaligned { expected: usize, actual: usize, section: &'static str, backtrace: Backtrace },
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
            subtables.push(FntSubtable { directory: Cow::Borrowed(directory), data: Cow::Borrowed(&data[start..]) });
        }

        Ok(Self { subtables: subtables.into_boxed_slice() })
    }

    pub fn build(mut self) -> Result<Box<[u8]>, io::Error> {
        let mut bytes = vec![];
        let mut subtable_offset = 0;

        let num_directories = self.subtables.len() as u16;

        if let Some(root) = self.subtables.first_mut() {
            // the root entry has no parent, so `parent_id` is instead the number of directories
            root.directory.to_mut().parent_id = num_directories;
        }

        for subtable in self.subtables.iter_mut() {
            subtable.directory.to_mut().subtable_offset = subtable_offset;
            bytes.write(bytemuck::bytes_of(subtable.directory.as_ref()))?;
            subtable_offset += subtable.data.len() as u32 + 1; // +1 for 0-byte terminator, see loop below
        }

        for subtable in self.subtables.iter() {
            bytes.write(&subtable.data)?;
            bytes.push(0);
        }

        Ok(bytes.into_boxed_slice())
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
        if self.data.is_empty() || self.data[0] == 0 {
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
