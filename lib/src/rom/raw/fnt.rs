use std::{
    borrow::Cow,
    io::{self, Write},
    mem::size_of,
};

use bytemuck::{Pod, Zeroable};
use encoding_rs::SHIFT_JIS;
use snafu::{Backtrace, Snafu};

use super::RawHeaderError;
use crate::error::{DataOutOfBoundsError, OverflowError, SliceCastError, handle_pod_cast};

/// File Name Table or FNT for short. Contains the names of every file and directory in the ROM. This is the raw struct, see
/// the plain one [here](super::super::FileSystem).
pub struct Fnt<'a> {
    /// Every directory has one subtable, indexed by `dir_id & 0xfff`
    subtables: Box<[FntSubtable<'a>]>,
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
    #[snafu(display("file name table is too small:\n{backtrace}"))]
    InvalidSize {
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// See [`SliceCastError`].
    #[snafu(transparent)]
    SliceCast {
        /// Source error.
        source: SliceCastError,
    },
    /// Occurs when a subtable offset points outside the FNT.
    #[snafu(display("subtable at {offset} goes outside FNT of size {size}:\n{backtrace}"))]
    InvalidSubtableOffset {
        /// Subtable offset.
        offset: usize,
        /// FNT size.
        size: usize,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// Occurs when more than 4096 subtables were provided.
    #[snafu(display("FNT cannot have more than 4096 subtables, but {count} were provided:\n{backtrace}"))]
    TooManySubtables {
        /// Provided number of subtables.
        count: usize,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// See [`OverflowError`].
    #[snafu(transparent)]
    Overflow {
        /// Source error.
        source: OverflowError,
    },
    /// See [`DataOutOfBoundsError`]
    #[snafu(transparent)]
    DataOutOfBounds {
        /// Source error.
        source: DataOutOfBoundsError,
    },
}

/// Maximum number of subtables supported by the FNT.
pub const MAX_SUBTABLES: u16 = 0x1000;

impl<'a> Fnt<'a> {
    /// Reinterprets a `&[u8]` as an [`Fnt`].
    ///
    /// # Errors
    ///
    /// This function will return an error if the input is too small or not aligned enough.
    pub fn borrow_from_slice(data: &'a [u8]) -> Result<Self, RawFntError> {
        let addr = data as *const [u8] as *const () as usize;

        let dir_size = size_of::<FntDirectory>();
        let root_dir: &FntDirectory =
            handle_pod_cast(bytemuck::try_from_bytes(data.get(..dir_size).ok_or_else(|| InvalidSizeSnafu {}.build())?), addr)?;

        // the root entry has no parent, so `parent_id` is instead the number of directories
        let num_dirs = root_dir.parent_id;
        if num_dirs > MAX_SUBTABLES {
            return TooManySubtablesSnafu { count: num_dirs as usize }.fail();
        }

        #[allow(clippy::arithmetic_side_effects)] // 3x15-bit multiplication
        let size = dir_size * num_dirs as usize;
        let directories: &[FntDirectory] =
            handle_pod_cast(bytemuck::try_cast_slice(data.get(..size).ok_or_else(|| InvalidSizeSnafu {}.build())?), addr)?;

        let mut subtables = Vec::with_capacity(directories.len());
        for directory in directories {
            let start = directory.subtable_offset as usize;
            let data = data.get(start..).ok_or_else(|| InvalidSubtableOffsetSnafu { offset: start, size }.build())?;
            subtables.push(FntSubtable { directory: Cow::Borrowed(directory), data: Cow::Borrowed(data) });
        }

        Ok(Self { subtables: subtables.into_boxed_slice() })
    }

    /// Creates a new [`Fnt`].
    ///
    /// # Errors
    ///
    /// This function will return an error if there are more than [`MAX_SUBTABLES`] subtables.
    pub fn new(subtables: Vec<FntSubtable<'a>>) -> Result<Self, RawFntError> {
        if subtables.len() > MAX_SUBTABLES as usize {
            return TooManySubtablesSnafu { count: subtables.len() }.fail();
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
        #[allow(clippy::arithmetic_side_effects)] // 15x3-bit multiplication
        let mut subtable_offset = (self.subtables.len() * size_of::<FntDirectory>()) as u32;

        let num_directories = self.subtables.len() as u16;

        if let Some(root) = self.subtables.first_mut() {
            // the root entry has no parent, so `parent_id` is instead the number of directories
            root.directory.to_mut().parent_id = num_directories;
        }

        for subtable in self.subtables.iter_mut() {
            subtable.directory.to_mut().subtable_offset = subtable_offset;
            bytes.write_all(bytemuck::bytes_of(subtable.directory.as_ref()))?;
            #[allow(clippy::arithmetic_side_effects)] // small numbers
            {
                subtable_offset += subtable.data.len() as u32 + 1; // +1 for 0-byte terminator, see loop below
            }
        }

        for subtable in self.subtables.iter() {
            bytes.write_all(&subtable.data)?;
            bytes.push(0);
        }

        Ok(bytes.into_boxed_slice())
    }

    /// Returns a reference to the subtables of this [`Fnt`].
    pub fn subtables(&self) -> &[FntSubtable<'a>] {
        &self.subtables
    }
}

impl FntSubtable<'_> {
    /// Returns an iterator over all immediate children (files and directories) in this subtable.
    pub fn iter(&self) -> IterFntSubtable<'_> {
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

    #[allow(clippy::indexing_slicing)] // all checked
    fn next(&mut self) -> Option<Self::Item> {
        if self.data.is_empty() || self.data[0] == 0 {
            return None;
        }

        let length = self.data[0] as usize & 0x7f;
        let subdir = self.data[0] & 0x80 != 0;
        self.data = &self.data[1..];

        if length > self.data.len() {
            log::warn!("Name of file with ID {} goes outside FNT subtable", self.id);
            return None;
        }

        let (name, _, had_errors) = SHIFT_JIS.decode(&self.data[..length]);
        if had_errors {
            log::warn!("The file name '{name}' contains a malformed byte sequence");
        }

        self.data = &self.data[length..];

        let id = if subdir {
            if self.data.len() < 2 {
                log::warn!("Can't read ID of subdirectory '{name}' due to FNT subtable ending too soon");
                return None;
            }
            let id = u16::from_le_bytes([self.data[0], self.data[1]]);
            self.data = &self.data[2..];
            id
        } else if self.id < 0xf000 {
            let id = self.id;
            self.id = self.id.wrapping_add(1);
            id
        } else {
            // Ran out of file IDs
            return None;
        };

        Some(FntFile { id, name })
    }
}

/// A file/directory inside an [`FntSubtable`].
pub struct FntFile<'a> {
    /// File ID if less than `0xf000`, otherwise it's a directory ID.
    pub id: u16,
    /// File/directory name.
    pub name: Cow<'a, str>,
}
