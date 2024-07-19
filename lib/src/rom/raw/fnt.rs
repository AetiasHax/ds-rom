use std::{
    borrow::Cow,
    io::{self, Write},
    mem::size_of,
    str::from_utf8,
};

use bytemuck::{Pod, PodCastError, Zeroable};
use snafu::{Backtrace, Snafu};

use super::RawHeaderError;

/// File Name Table or FNT for short. Contains the names of every file and directory in the ROM. This is the raw struct, see
/// the plain one [here](super::super::Files).
pub struct Fnt<'a> {
    /// Every directory has one subtable, indexed by `dir_id & 0xfff`
    pub subtables: Box<[FntSubtable<'a>]>,
}

/// A directory entry in the FNT's directory list.
#[repr(C)]
#[derive(Clone, Copy, Zeroable, Pod)]
pub struct FntDirectory {
    /// Offset to this directory's subtable, which contains the names of immediate children (both files and directories).
    pub subtable_offset: u32,
    /// The first file ID.
    pub first_file_id: u16,
    /// The parent ID. If this is the root directory, this number is actually the total number of directories, as the root has
    /// no parent anyway.
    pub parent_id: u16,
}

/// Contains a directory's immediate children (files and folders).
pub struct FntSubtable<'a> {
    /// Reference to [`FntDirectory`].
    pub directory: Cow<'a, FntDirectory>,
    /// Raw subtable data.
    pub data: Cow<'a, [u8]>,
}

/// Errors related to [`Fnt`].
#[derive(Debug, Snafu)]
pub enum RawFntError {
    /// See [`RawHeaderError`].
    #[snafu(transparent)]
    RawHeader {
        /// Source error.
        source: RawHeaderError,
    },
    /// Occurs when the input it too small to fit an FNT.
    #[snafu(display("file name table must be at least {} bytes long:\n{backtrace}", size_of::<FntDirectory>()))]
    InvalidSize {
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// Occurs when the input is not aligned enough.
    #[snafu(display("expected {expected}-alignment but got {actual}-alignment:\n{backtrace}"))]
    Misaligned {
        /// Expected alignment.
        expected: usize,
        /// Actual input alignment.
        actual: usize,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
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

    fn handle_pod_cast<T>(result: Result<T, PodCastError>) -> T {
        match result {
            Ok(x) => x,
            Err(PodCastError::TargetAlignmentGreaterAndInputNotAligned) => unreachable!(),
            Err(PodCastError::AlignmentMismatch) => panic!(),
            Err(PodCastError::OutputSliceWouldHaveSlop) => panic!(),
            Err(PodCastError::SizeMismatch) => unreachable!(),
        }
    }

    /// Reinterprets a `&[u8]` as an [`Fnt`].
    ///
    /// # Errors
    ///
    /// This function will return an error if the input is too small or not aligned enough.
    pub fn borrow_from_slice(data: &'a [u8]) -> Result<Self, RawFntError> {
        Self::check_size(data)?;
        let addr = data as *const [u8] as *const () as usize;
        if addr % 4 != 0 {
            return MisalignedSnafu { expected: 4usize, actual: 1usize << addr.trailing_zeros() as usize }.fail();
        }

        let size = size_of::<FntDirectory>();
        let root_dir: &FntDirectory = Self::handle_pod_cast(bytemuck::try_from_bytes(&data[..size]));

        // the root entry has no parent, so `parent_id` is instead the number of directories
        let num_dirs = root_dir.parent_id as usize;
        let directories: &[FntDirectory] = Self::handle_pod_cast(bytemuck::try_cast_slice(&data[..size * num_dirs]));

        let mut subtables = Vec::with_capacity(directories.len());
        for directory in directories {
            let start = directory.subtable_offset as usize;
            subtables.push(FntSubtable { directory: Cow::Borrowed(directory), data: Cow::Borrowed(&data[start..]) });
        }

        Ok(Self { subtables: subtables.into_boxed_slice() })
    }

    /// Builds the FNT to be placed in a ROM.
    ///
    /// # Errors
    ///
    /// This function will return an error if an I/O operation fails.
    pub fn build(mut self) -> Result<Box<[u8]>, io::Error> {
        let mut bytes = vec![];
        let mut subtable_offset = (self.subtables.len() * size_of::<FntDirectory>()) as u32;

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
    /// Returns an iterator over all immediate children (files and directories) in this subtable.
    pub fn iter(&self) -> IterFntSubtable {
        IterFntSubtable { data: &self.data, id: self.directory.first_file_id }
    }
}

/// Iterates over immediate children (files and directories) in a subtable.
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

/// A file/directory inside an [`FntSubtable`].
pub struct FntFile<'a> {
    /// File ID if less than `0xf000`, otherwise it's a directory ID.
    pub id: u16,
    /// File/directory name.
    pub name: &'a str,
}
