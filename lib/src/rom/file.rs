use std::{
    borrow::Cow,
    cmp::Ordering,
    collections::{BinaryHeap, HashSet},
    fmt::Display,
    path::{Path, PathBuf},
};

use encoding_rs::SHIFT_JIS;
use snafu::{Backtrace, Snafu};

use super::raw::{self, FileAlloc, Fnt, FntDirectory, FntFile, FntSubtable, RawHeaderError};
use crate::{
    error::{DataOutOfBoundsError, OverflowError, slice_data},
    io::{FileError, read_dir, read_file},
    rom::raw::RawFntError,
    str::BlobSize,
};

/// Contains files and directories to be placed into a ROM.
pub struct FileSystem<'a> {
    num_overlays: usize,
    files: Vec<File<'a>>,
    dirs: Vec<Dir>,
    next_file_id: u16,
    next_dir_id: u16,
}

/// A file for the [`FileSystem`] struct.
#[derive(Clone)]
pub struct File<'a> {
    id: u16,
    name: String,
    original_offset: u32,
    contents: Cow<'a, [u8]>,
}

/// A directory for the [`FileSystem`] struct.
#[derive(Clone, Default)]
pub struct Dir {
    id: u16,
    name: String,
    parent_id: u16,
    children: Vec<u16>,
}

/// Errors related to [`FileSystem::parse`].
#[derive(Debug, Snafu)]
pub enum FileParseError {
    /// See [`ItemMissingError`].
    #[snafu(transparent)]
    ItemMissing {
        /// Source error.
        source: ItemMissingError,
    },
    /// See [`RawHeaderError`].
    #[snafu(transparent)]
    RawHeader {
        /// Source error.
        source: RawHeaderError,
    },
    /// Occurs when trying to access a subtable that doesn't exist.
    #[snafu(display("no subtable for directory with ID {id}:\n{backtrace}"))]
    SubtableMissing {
        /// The directory's ID.
        id: u16,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// Occurs when trying to access a FAT entry that doesn't exist.
    #[snafu(display("no FAT entry for file with ID {id}:\n{backtrace}"))]
    FatMissing {
        /// The file's ID.
        id: u16,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// See [`DataOutOfBoundsError`]
    #[snafu(transparent)]
    DataOutOfBounds {
        /// Source error.
        source: DataOutOfBoundsError,
    },
    /// Occurs when trying to write to a file entry that doesn't exist.
    #[snafu(display("no entry for file with ID {id}:\n{backtrace}"))]
    FileEntryMissing {
        /// The file's ID.
        id: u16,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// See [`OverflowError`].
    #[snafu(transparent)]
    Overflow {
        /// Source error.
        source: OverflowError,
    },
    /// Occurs when directories are nested deeper than [`MAX_DIR_DEPTH`].
    #[snafu(display("directory with ID {id:#x} is nested deeper than {MAX_DIR_DEPTH} levels:\n{backtrace}"))]
    DirectoryTooDeep {
        /// The directory's ID.
        id: u16,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// Occurs when a directory's subtable is reached more than once, i.e. the directory is listed twice or is its own
    /// ancestor.
    #[snafu(display("directory with ID {id:#x} is listed more than once in the FNT:\n{backtrace}"))]
    DirectoryRevisited {
        /// The directory's ID.
        id: u16,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
}

/// State for [`FileSystem::parse_subtable`].
struct FileSystemParseContext<'f, 'a> {
    fnt: &'f Fnt<'f>,
    fat: &'f [FileAlloc],
    rom: &'a raw::Rom<'a>,
    dirs: Vec<Option<Dir>>,
    files: Vec<Option<File<'a>>>,
    /// Which subtables have been parsed, indexed like [`Fnt::subtables`].
    visited: Vec<bool>,
}

/// Maximum number of nested directories below the root directory. Directory trees are traversed recursively, so this limit
/// prevents stack overflows on malformed FNTs and deeply nested file directories. Real ROMs only nest a few levels deep.
pub const MAX_DIR_DEPTH: usize = 128;

/// Occurs when trying to use a file or directory which doesn't exist.
#[derive(Debug, Snafu)]
#[snafu(display("file/directory with ID {id} is missing:\n{backtrace}"))]
pub struct ItemMissingError {
    /// The file/directory ID.
    id: u16,
    /// Backtrace to the source of the error.
    backtrace: Backtrace,
}

/// Errors related to [`FileSystem::load`].
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum FileSystemLoadError {
    /// Occurs when reading a file or directory fails.
    #[snafu(transparent)]
    File {
        /// Source error.
        source: FileError,
    },
    /// See [`std::io::Error`].
    #[snafu(transparent)]
    Io {
        /// Source error.
        source: std::io::Error,
    },
    /// See [`ItemMissingError`].
    #[snafu(transparent)]
    ItemMissing {
        /// Source error.
        source: ItemMissingError,
    },
    /// See [`OverflowError`].
    #[snafu(transparent)]
    Overflow {
        /// Source error.
        source: OverflowError,
    },
    /// Occurs when directories are nested deeper than [`MAX_DIR_DEPTH`].
    #[snafu(display("directory {path} is nested deeper than {MAX_DIR_DEPTH} levels:\n{backtrace}"))]
    DirectoryTooDeep {
        /// Path to the directory.
        path: String,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
}

/// Errors related to [`FileSystem::build_fnt`].
#[derive(Debug, Snafu)]
pub enum FileBuildError {
    /// Occurs when a file name contains unmappable characters that could not be encoded to SHIFT-JIS.
    #[snafu(display("the file name {name} contains unmappable character(s):\n{backtrace}"))]
    EncodingFailed {
        /// File name.
        name: String,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// See [`ItemMissingError`].
    #[snafu(transparent)]
    ItemMissing {
        /// Source error.
        source: ItemMissingError,
    },
    /// See [`RawFntError`].
    #[snafu(transparent)]
    RawFnt {
        /// Source error.
        source: RawFntError,
    },
}

/// Errors related to [`FileSystem::traverse_files`].
#[derive(Debug, Snafu)]
pub enum FileSystemTraverseError {
    /// See [`ItemMissingError`].
    #[snafu(transparent)]
    ItemMissing {
        /// Source error.
        source: ItemMissingError,
    },
}

/// Errors related to [`FileSystem::compute_path_order`].
#[derive(Debug, Snafu)]
pub enum FileSystemPathOrderError {
    /// See [`ItemMissingError`].
    #[snafu(transparent)]
    ItemMissing {
        /// Source error.
        source: ItemMissingError,
    },
}

const ROOT_DIR_ID: u16 = 0xf000;

impl<'a> FileSystem<'a> {
    /// Creates a new [`FileSystem`]. The number of overlays are used to determine the first file ID, since overlays are also
    /// located in the FAT but not the FNT.
    pub fn new(num_overlays: usize) -> Self {
        let root = Dir { id: ROOT_DIR_ID, name: "/".to_string(), parent_id: 0, children: vec![] };
        Self { num_overlays, files: vec![], dirs: vec![root], next_file_id: num_overlays as u16, next_dir_id: ROOT_DIR_ID + 1 }
    }

    fn load_in<P: AsRef<Path>>(&mut self, path: P, parent_id: u16, depth: usize) -> Result<(), FileSystemLoadError> {
        if depth > MAX_DIR_DEPTH {
            let path = path.as_ref().to_string_lossy().to_string();
            return file_system_load_error::DirectoryTooDeepSnafu { path }.fail();
        }

        // Sort children by FNT order so the file/dir IDs become correct
        let mut children = read_dir(&path)?
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(|entry| entry.path())
            .map(|child| {
                let as_string = child.to_string_lossy().to_string();
                let is_dir = child.is_dir();
                (child, as_string, is_dir)
            })
            .collect::<Vec<_>>();
        children.sort_unstable_by(|a, b| Self::compare_for_fnt(&a.1, a.2, &b.1, b.2));

        for (child, _, is_dir) in children.into_iter() {
            let Some(name) = child.file_name() else {
                continue; // never happens
            };
            let name = name.to_string_lossy().to_string();
            if is_dir {
                let child_id = self.next_dir_id;
                let child_path = path.as_ref().join(&name);
                self.make_child_dir(name, parent_id)?;
                #[allow(clippy::arithmetic_side_effects)] // depth <= MAX_DIR_DEPTH
                self.load_in(child_path, child_id, depth + 1)?;
            } else {
                let contents = read_file(child)?;
                self.make_child_file(name, parent_id, contents)?;
            }
        }
        Ok(())
    }

    /// Loads a file system from the given root directory. This will traverse and add all folders and files into the
    /// [`FileSystem`] struct.
    ///
    /// # Errors
    ///
    /// This function will return an error if an I/O operation fails, or if directories are nested deeper than
    /// [`MAX_DIR_DEPTH`].
    pub fn load<P: AsRef<Path>>(root: P, num_overlays: usize) -> Result<Self, FileSystemLoadError> {
        let mut files = Self::new(num_overlays);
        files.load_in(root, ROOT_DIR_ID, 0)?;
        Ok(files)
    }

    /// Returns whether the ID is a directory ID.
    pub fn is_dir(id: u16) -> bool {
        id >= ROOT_DIR_ID
    }

    /// Returns whether the ID is a file ID.
    pub fn is_file(id: u16) -> bool {
        !Self::is_dir(id)
    }

    /// Returns the name of a directory or file.
    pub fn name(&self, id: u16) -> Option<&str> {
        if Self::is_dir(id) {
            self.dir(id).map(|d| d.name.as_str())
        } else {
            self.file(id).map(|f| f.name.as_str())
        }
    }

    /// Returns the directory with the given ID, if it exists.
    pub fn dir(&self, id: u16) -> Option<&Dir> {
        self.dirs.get(id as usize & 0xfff)
    }

    fn dir_mut(&mut self, id: u16) -> Option<&mut Dir> {
        self.dirs.get_mut(id as usize & 0xfff)
    }

    /// Returns the file with the given ID, if it exists.
    pub fn file(&self, id: u16) -> Option<&File<'a>> {
        if (id as usize) < self.num_overlays {
            None
        } else {
            #[allow(clippy::arithmetic_side_effects)] // id is never less than num_overlays
            self.files.get(id as usize - self.num_overlays)
        }
    }

    /// Returns the file or directory with the given ID, if it exists.
    pub fn get(&'a self, id: u16) -> Option<FileOrDir<'a>> {
        if Self::is_dir(id) {
            Some(FileOrDir::Dir(self.dir(id)?))
        } else {
            Some(FileOrDir::File(self.file(id)?))
        }
    }

    fn parse_subtable(
        ctx: &mut FileSystemParseContext<'_, 'a>,
        parent: &mut Dir,
        depth: usize,
    ) -> Result<(u16, u16), FileParseError> {
        if depth > MAX_DIR_DEPTH {
            return DirectoryTooDeepSnafu { id: parent.id }.fail();
        }
        let subtable_index = parent.id as usize & 0xfff;
        let subtable: &FntSubtable =
            ctx.fnt.subtables().get(subtable_index).ok_or_else(|| SubtableMissingSnafu { id: parent.id }.build())?;

        // Prevents infinite recursion when a directory contains itself or one of its ancestors
        let is_visited = ctx.visited.get_mut(subtable_index).ok_or_else(|| SubtableMissingSnafu { id: parent.id }.build())?;
        if *is_visited {
            return DirectoryRevisitedSnafu { id: parent.id }.fail();
        }
        *is_visited = true;

        let mut max_file_id = 0;
        let mut max_dir_id = 0;
        for FntFile { id, name } in subtable.iter() {
            let name = name.to_string();

            if Self::is_dir(id) {
                max_dir_id = max_dir_id.max(id);
                let mut dir = Dir { id, name, parent_id: parent.id, children: vec![] };
                let (max_child_dir_id, max_child_file_id) = Self::parse_subtable(ctx, &mut dir, depth.saturating_add(1))?;
                max_dir_id = max_dir_id.max(max_child_dir_id);
                max_file_id = max_file_id.max(max_child_file_id);

                let dest_dir = ctx.dirs.get_mut(id as usize & 0xfff).ok_or_else(|| SubtableMissingSnafu { id }.build())?;
                *dest_dir = Some(dir);
                parent.children.push(id);
            } else {
                max_file_id = max_file_id.max(id);
                let alloc: &FileAlloc = ctx.fat.get(id as usize).ok_or_else(|| FatMissingSnafu { id }.build())?;
                let contents = slice_data(ctx.rom.data(), alloc.range(), || format!("contents of {}", name))?;
                let dest_file = ctx.files.get_mut(id as usize).ok_or_else(|| FileEntryMissingSnafu { id }.build())?;
                *dest_file = Some(File { id, name, original_offset: alloc.start, contents: Cow::Borrowed(contents) });
                parent.children.push(id);
            }
        }
        Ok((max_file_id, max_dir_id))
    }

    /// Parses an FNT, FAT and ROM to create a [`FileSystem`].
    ///
    /// # Errors
    ///
    /// This function will return an error if [`raw::Rom::num_arm9_overlays`] or [`raw::Rom::num_arm7_overlays`] fails, or if
    /// a file or directory ID is missing from the FNT.
    pub fn parse(fnt: &Fnt, fat: &[FileAlloc], rom: &'a raw::Rom) -> Result<Self, FileParseError> {
        let num_overlays = rom
            .num_arm9_overlays()?
            .checked_add(rom.num_arm7_overlays()?)
            .ok_or_else(|| OverflowError::new("number of overlays"))?;

        let mut root = Dir { id: ROOT_DIR_ID, name: "/".to_string(), parent_id: 0, children: vec![] };
        let mut ctx = FileSystemParseContext {
            fnt,
            fat,
            rom,
            dirs: vec![None; fnt.subtables().len().max(1)],
            files: vec![None; fat.len()],
            visited: vec![false; fnt.subtables().len()],
        };
        let (max_file_id, max_dir_id) = Self::parse_subtable(&mut ctx, &mut root, 0)?;
        let FileSystemParseContext { mut dirs, files, .. } = ctx;
        #[allow(clippy::indexing_slicing)] // size is at least 1
        {
            dirs[0] = Some(root);
        }

        let files = files
            .into_iter()
            .skip(num_overlays)
            .enumerate()
            .map(|(id, f)| f.ok_or(ItemMissingSnafu { id: id as u16 }.build()))
            .collect::<Result<Vec<_>, _>>()?;
        let dirs = dirs
            .into_iter()
            .enumerate()
            .map(|(id, d)| d.ok_or(ItemMissingSnafu { id: id as u16 | ROOT_DIR_ID }.build()))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(FileSystem {
            files,
            dirs,
            num_overlays,
            next_file_id: max_file_id.checked_add(1).ok_or_else(|| OverflowError::new("next file ID"))?,
            next_dir_id: max_dir_id.checked_add(1).ok_or_else(|| OverflowError::new("next directory ID"))?,
        })
    }

    fn find_first_file_id(&self, parent: &Dir) -> Option<u16> {
        let child = *parent.children.first()?;
        match self.get(child)? {
            FileOrDir::File(_) => Some(child),
            FileOrDir::Dir(dir) => self.find_first_file_id(dir),
        }
    }

    fn build_subtable(&self, parent: &Dir) -> Result<Option<FntSubtable<'a>>, FileBuildError> {
        let Some(first_file_id) = self.find_first_file_id(parent) else {
            return Ok(None);
        };

        let mut data = vec![];

        for &child in &parent.children {
            let item = self.get(child).ok_or_else(|| ItemMissingSnafu { id: child }.build())?;

            let is_dir = matches!(item, FileOrDir::Dir(_));
            let name = item.name();

            let (sjis_name, _, had_errors) = SHIFT_JIS.encode(name);
            if had_errors {
                return EncodingFailedSnafu { name }.fail();
            }

            let name_length = sjis_name.len() as u8 & 0x7f;
            let directory_bit = if is_dir { 0x80 } else { 0 };
            data.push(name_length | directory_bit);

            data.extend(sjis_name.iter().take(0x7f));
            if is_dir {
                data.extend_from_slice(&child.to_le_bytes());
            }
        }

        Ok(Some(FntSubtable {
            directory: Cow::Owned(FntDirectory { subtable_offset: 0, first_file_id, parent_id: parent.parent_id }),
            data: Cow::Owned(data),
        }))
    }

    fn build_fnt_recursive(&'a self, subtables: &mut Vec<FntSubtable<'a>>, parent_id: u16) -> Result<(), FileBuildError> {
        let parent = &self.dir(parent_id).ok_or_else(|| ItemMissingSnafu { id: parent_id }.build())?;
        let Some(subtable) = self.build_subtable(parent)? else {
            // Parent is empty
            return Ok(());
        };
        subtables.push(subtable);
        for child in &parent.children {
            if Self::is_dir(*child) {
                self.build_fnt_recursive(subtables, *child)?;
            }
        }
        Ok(())
    }

    /// Builds an FNT from this [`FileSystem`].
    ///
    /// # Errors
    ///
    /// This function will return an error if a file/directory name contains non-ASCII characters, or if there are more than
    /// [`MAX_SUBTABLES`](super::raw::MAX_SUBTABLES) directories.
    pub fn build_fnt(&self) -> Result<Fnt<'_>, FileBuildError> {
        let mut subtables = vec![];
        self.build_fnt_recursive(&mut subtables, ROOT_DIR_ID)?;
        Ok(Fnt::new(subtables)?)
    }

    fn compare_for_fnt(a: &str, a_dir: bool, b: &str, b_dir: bool) -> Ordering {
        let files_first = a_dir.cmp(&b_dir);
        if files_first.is_ne() {
            return files_first;
        }

        // Convert to Shift-JIS first, *then* convert to lowercase byte-by-byte
        // without accounting for multibyte characters like コ (83 52, but sorted
        // as if it was actually ビ / 83 72). This strcasecmp-like behavior was
        // observed in 999's Japanese file names.
        let (mut a_bytes, _, _) = SHIFT_JIS.encode(a);
        let (mut b_bytes, _, _) = SHIFT_JIS.encode(b);
        let a_vec = a_bytes.to_mut();
        let b_vec = b_bytes.to_mut();
        a_vec.make_ascii_lowercase();
        b_vec.make_ascii_lowercase();

        // Lexicographic, case-insensitive Shift-JIS order
        a_vec.cmp(&b_vec)
    }

    fn get_parent(&mut self, parent_id: u16) -> Result<&mut Dir, ItemMissingError> {
        self.dir_mut(parent_id).ok_or_else(|| ItemMissingSnafu { id: parent_id }.build())
    }

    fn sort_for_fnt_in(&mut self, parent_id: u16) -> Result<(), FileBuildError> {
        let mut parent = std::mem::take(self.get_parent(parent_id)?);
        parent.children.sort_by(|a, b| {
            Self::compare_for_fnt(
                self.name(*a).unwrap_or_default(),
                Self::is_dir(*a),
                self.name(*b).unwrap_or_default(),
                Self::is_dir(*b),
            )
        });

        for child in &mut parent.children {
            if Self::is_dir(*child) {
                self.sort_for_fnt_in(*child)?;
            }
        }

        *self.get_parent(parent_id)? = parent;
        Ok(())
    }

    /// Sorts the entire [`FileSystem`] so that it's laid out in the right order for the FNT.
    pub fn sort_for_fnt(&mut self) -> Result<(), FileBuildError> {
        self.sort_for_fnt_in(ROOT_DIR_ID)?;
        Ok(())
    }

    fn compare_for_rom(a: &str, b: &str) -> Ordering {
        // Lexicographic UTF-8 order
        a.cmp(b)
    }

    fn sort_for_rom_in(&mut self, parent_id: u16) -> Result<(), FileBuildError> {
        let mut parent = std::mem::take(self.get_parent(parent_id)?);
        parent
            .children
            .sort_by(|a, b| Self::compare_for_rom(self.name(*a).unwrap_or_default(), self.name(*b).unwrap_or_default()));

        for child in &mut parent.children {
            if Self::is_dir(*child) {
                self.sort_for_rom_in(*child)?;
            }
        }

        *self.get_parent(parent_id)? = parent;
        Ok(())
    }

    /// Sorts the entire [`FileSystem`] so that files laid out in the right order for appending to the ROM.
    pub fn sort_for_rom(&mut self) -> Result<(), FileBuildError> {
        self.sort_for_rom_in(ROOT_DIR_ID)?;
        Ok(())
    }

    fn find_path_in(&'_ self, path: &str, parent_id: u16) -> Result<Option<FileOrDir<'_>>, FileSystemTraverseError> {
        let parent = self.dir(parent_id).ok_or_else(|| ItemMissingSnafu { id: parent_id }.build())?;
        let (child_name, next) = path.split_once('/').map(|(c, n)| (c, Some(n))).unwrap_or((path, None));
        let Some(&child) = parent.children.iter().find(|&&id| self.name(id) == Some(child_name)) else {
            return Ok(None);
        };
        if let Some(next) = next {
            if Self::is_dir(child) {
                self.find_path_in(next, child)
            } else {
                Ok(None)
            }
        } else {
            Ok(self.get(child))
        }
    }

    fn find_path(&'_ self, path: &str) -> Result<Option<FileOrDir<'_>>, FileSystemTraverseError> {
        self.find_path_in(path, ROOT_DIR_ID)
    }

    fn make_child_dir(&mut self, name: String, parent_id: u16) -> Result<&Dir, FileSystemLoadError> {
        let id = self.next_dir_id;
        self.dirs.push(Dir { id, name, parent_id, children: vec![] });
        let parent = self.dir_mut(parent_id).ok_or_else(|| ItemMissingSnafu { id: parent_id }.build())?;
        parent.children.push(id);
        self.next_dir_id = self.next_dir_id.checked_add(1).ok_or_else(|| OverflowError::new("next directory ID"))?;
        #[allow(clippy::unwrap_used)] // dirs is not empty
        Ok(self.dirs.last().unwrap())
    }

    fn make_child_file(&mut self, name: String, parent_id: u16, contents: Vec<u8>) -> Result<&File<'a>, FileSystemLoadError> {
        let id = self.next_file_id;
        self.files.push(File { id, name, original_offset: 0, contents: contents.into() });
        let parent = self.dir_mut(parent_id).ok_or_else(|| ItemMissingSnafu { id: parent_id }.build())?;
        parent.children.push(id);
        self.next_file_id = self.next_file_id.checked_add(1).ok_or_else(|| OverflowError::new("next file ID"))?;
        #[allow(clippy::unwrap_used)] // files is not empty
        Ok(self.files.last().unwrap())
    }

    fn traverse_nonvisited_files<Cb, E>(
        &self,
        visited: &mut HashSet<u16>,
        callback: &mut Cb,
        subdir: &Dir,
        path: &Path,
    ) -> Result<(), E>
    where
        Cb: FnMut(&File, &Path) -> Result<(), E>,
        E: From<FileSystemTraverseError>,
    {
        if visited.contains(&subdir.id) {
            return Ok(());
        }
        for &child in &subdir.children {
            if visited.contains(&child) {
                continue;
            }

            let item = self.get(child).ok_or_else(|| FileSystemTraverseError::from(ItemMissingSnafu { id: child }.build()))?;
            match item {
                FileOrDir::Dir(dir) => {
                    let path = path.join(&dir.name);
                    self.traverse_nonvisited_files(visited, callback, dir, &path)?;
                }
                FileOrDir::File(file) => {
                    callback(file, path)?;
                    let first_time_visiting_file = visited.insert(child);
                    debug_assert!(first_time_visiting_file);
                }
            }
        }
        let first_time_visiting_file = visited.insert(subdir.id);
        debug_assert!(first_time_visiting_file);
        Ok(())
    }

    /// Traverses the [`FileSystem`] and calls `callback` for each file found. The directories will be prioritized according to
    /// the `path_order`.
    pub fn traverse_files<I, Cb, E>(&self, path_order: I, mut callback: Cb) -> Result<(), E>
    where
        I: IntoIterator<Item = &'a str>,
        Cb: FnMut(&File, &Path) -> Result<(), E>,
        E: From<FileSystemTraverseError>,
    {
        let mut visited = HashSet::<u16>::new();

        for path in path_order {
            let path = path.strip_prefix("/").unwrap_or(path);
            let path_buf = PathBuf::from(path);
            let subdir = if path.trim() == "" {
                self.dir(ROOT_DIR_ID)
                    .ok_or_else(|| FileSystemTraverseError::from(ItemMissingSnafu { id: ROOT_DIR_ID }.build()))?
            } else {
                let Some(child) = self.find_path(path)? else { continue };
                if visited.contains(&child.id()) {
                    continue;
                }

                match child {
                    FileOrDir::Dir(dir) => dir,
                    FileOrDir::File(file) => {
                        callback(file, &path_buf)?;
                        let first_time_visiting_file = visited.insert(file.id);
                        debug_assert!(first_time_visiting_file);
                        continue;
                    }
                }
            };
            self.traverse_nonvisited_files(&mut visited, &mut callback, subdir, &path_buf)?;
        }
        Ok(())
    }

    fn max_file_id_in(&self, parent_id: u16) -> u16 {
        let mut max_id = 0;
        if let Some(parent) = self.dir(parent_id) {
            for child in &parent.children {
                let id = if Self::is_dir(*child) {
                    self.max_file_id_in(*child)
                } else {
                    *child
                };
                if id > max_id {
                    max_id = id;
                }
            }
        }
        max_id
    }

    /// Returns the max file ID of this [`FileSystem`].
    pub fn max_file_id(&self) -> u16 {
        self.max_file_id_in(ROOT_DIR_ID)
    }

    /// Creates a [`DisplayFileSystem`] which implements [`Display`].
    pub fn display(&self, indent: usize) -> DisplayFileSystem<'_> {
        DisplayFileSystem { files: self, parent_id: ROOT_DIR_ID, indent }
    }

    fn traverse_and_compute_path_order(
        &self,
        path: &str,
        path_order: &mut BinaryHeap<PathOrder>,
        parent: &Dir,
    ) -> Result<(), FileSystemPathOrderError> {
        for &child in &parent.children {
            let item = self.get(child).ok_or_else(|| ItemMissingSnafu { id: child }.build())?;
            let path = format!("{}/{}", path, item.name());
            match item {
                FileOrDir::Dir(dir) => {
                    self.traverse_and_compute_path_order(path.as_str(), path_order, dir)?;
                }
                FileOrDir::File(file) => {
                    path_order.push(PathOrder {
                        id: child,
                        parent_id: parent.id,
                        path_name: path,
                        offset: file.original_offset,
                    });
                }
            }
        }
        Ok(())
    }

    fn are_paths_sorted(&self, paths: &[PathOrder]) -> bool {
        #[allow(clippy::indexing_slicing)] // window is always 2 items
        paths.windows(2).all(|w| {
            Self::compare_for_rom(self.name(w[0].id).unwrap_or_default(), self.name(w[1].id).unwrap_or_default()).is_lt()
        })
    }

    /// Computes the path order that the [`FileSystem`] is currently in. This can be saved and reused in
    /// [`Self::traverse_files`] to traverse in the same order later.
    pub fn compute_path_order(&self) -> Result<Vec<String>, FileSystemPathOrderError> {
        let mut path_order = BinaryHeap::new();
        let root = self.dir(ROOT_DIR_ID).ok_or_else(|| ItemMissingSnafu { id: ROOT_DIR_ID }.build())?;
        self.traverse_and_compute_path_order("", &mut path_order, root)?;
        let mut paths = path_order.into_sorted_vec();

        // Loop to simplify path order
        let mut children_start = 0;
        #[allow(clippy::indexing_slicing)] // children_start and children_end are always within paths vec
        #[allow(clippy::arithmetic_side_effects)] // result never overflows
        while children_start < paths.len() {
            let parent_id = paths[children_start].parent_id;
            if parent_id == 0 {
                children_start += 1;
                continue;
            }

            // Find all surrounding children with the same parent as the current child
            let children_end = paths[children_start..]
                .iter()
                .position(|c| c.parent_id != parent_id)
                .map(|pos| children_start + pos)
                .unwrap_or(paths.len());
            children_start = paths[..children_start]
                .iter()
                .enumerate()
                .rev()
                .find_map(|(index, child)| (child.parent_id != parent_id).then_some(index + 1))
                .unwrap_or(0);
            let num_children = children_end - children_start;

            let parent = self.dir(parent_id).ok_or_else(|| ItemMissingSnafu { id: parent_id }.build())?;
            let num_unvisited_children =
                parent.children.iter().filter(|c| !paths[..children_start].iter().any(|p| p.id == **c)).count();

            // Check if the child count matches the parent (excluding child paths which already exist in the path order)
            // Also check that the children are sorted, so that simplifying the path order doesn't affect the resulting order of files
            if num_children == num_unvisited_children && self.are_paths_sorted(&paths[children_start..children_end]) {
                let mut path_name =
                    paths[children_start].path_name.rsplit_once('/').map(|(parent, _)| parent).unwrap_or("/").to_string();
                if path_name.is_empty() {
                    path_name = "/".to_string();
                }

                // Replace the children with their parent
                let offset = paths[children_start].offset;
                paths.drain(children_start..children_end);
                paths.insert(children_start, PathOrder { id: parent_id, parent_id: parent.parent_id, path_name, offset });
            } else {
                children_start = children_end;
            }
        }

        Ok(paths.into_iter().map(|p| p.path_name).collect())
    }
}

impl File<'_> {
    /// Returns a reference to the name of this [`File`].
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the ID of this [`File`].
    pub fn id(&self) -> u16 {
        self.id
    }

    /// Returns a reference to the contents of this [`File`].
    pub fn contents(&self) -> &[u8] {
        &self.contents
    }
}

impl Dir {
    /// Returns whether this [`Dir`] is the root directory.
    pub fn is_root(&self) -> bool {
        self.id == ROOT_DIR_ID
    }
}

/// Contains a [`File`] or a [`Dir`].
pub enum FileOrDir<'a> {
    /// Contains a [`File`].
    File(&'a File<'a>),
    /// Contains a [`Dir`].
    Dir(&'a Dir),
}

impl FileOrDir<'_> {
    fn id(&self) -> u16 {
        match self {
            FileOrDir::File(file) => file.id,
            FileOrDir::Dir(dir) => dir.id,
        }
    }

    fn name(&self) -> &str {
        match self {
            FileOrDir::File(file) => &file.name,
            FileOrDir::Dir(dir) => &dir.name,
        }
    }
}

#[derive(PartialEq, Eq, Clone, Debug)]
struct PathOrder {
    id: u16,
    parent_id: u16,
    path_name: String,
    offset: u32,
}

impl PartialOrd for PathOrder {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PathOrder {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.offset.cmp(&other.offset)
    }
}

/// Can be used to display the file hierarchy of a [`FileSystem`].
pub struct DisplayFileSystem<'a> {
    files: &'a FileSystem<'a>,
    parent_id: u16,
    indent: usize,
}

impl Display for DisplayFileSystem<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let i = " ".repeat(self.indent);
        let Some(parent) = self.files.dir(self.parent_id) else {
            return Ok(());
        };
        let files = &self.files;
        for &child in &parent.children {
            let Some(item) = files.get(child) else {
                continue;
            };
            match item {
                FileOrDir::Dir(dir) => {
                    write!(f, "{i}0x{:04x}: {: <32}", child, dir.name)?;
                    writeln!(f)?;
                    write!(f, "{}", Self { files, parent_id: child, indent: self.indent.saturating_add(2) })?;
                }
                FileOrDir::File(file) => {
                    let size = BlobSize(file.contents.len()).to_string();
                    write!(f, "{i}0x{:04x}: {: <48}{size: >7}", file.id, file.name)?;
                    writeln!(f)?;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::unwrap_in_result, clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// Creates an FNT where `children[i]` lists the subdirectory IDs inside directory `0xf000 | i`.
    fn make_fnt(children: &[&[u16]]) -> Fnt<'static> {
        let subtables = children
            .iter()
            .map(|dir_children| {
                let mut data = vec![];
                for &id in dir_children.iter() {
                    data.extend([0x81, b'd']);
                    data.extend(id.to_le_bytes());
                }
                data.push(0);
                FntSubtable {
                    directory: Cow::Owned(FntDirectory { subtable_offset: 0, first_file_id: 0, parent_id: 0 }),
                    data: Cow::Owned(data),
                }
            })
            .collect();
        Fnt::new(subtables).unwrap()
    }

    fn parse(fnt: &Fnt) -> Result<(), FileParseError> {
        let header = vec![0u32; size_of::<raw::Header>() / 4];
        let rom = raw::Rom::new(bytemuck::cast_slice::<u32, u8>(&header));
        let file_system = FileSystem::parse(fnt, &[], &rom)?;
        file_system.compute_path_order().unwrap();
        Ok(())
    }

    /// Creates an FNT with `depth` directories nested inside each other below the root.
    fn make_nested_fnt(depth: u16) -> Fnt<'static> {
        let ids: Vec<u16> = (1..=depth).map(|i| 0xf000 | i).collect();
        let mut children: Vec<&[u16]> = ids.chunks(1).collect();
        children.push(&[]);
        make_fnt(&children)
    }

    /// Runs `f` in a thread with a small stack, as callers may not have much stack space to spare.
    fn with_small_stack<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
        std::thread::Builder::new().stack_size(1024 * 1024).spawn(f).unwrap().join().unwrap()
    }

    #[test]
    fn parse_valid_dirs() {
        parse(&make_fnt(&[&[0xf001, 0xf002], &[], &[]])).unwrap();
    }

    #[test]
    fn parse_dir_containing_ancestor_is_error() {
        let result = parse(&make_fnt(&[&[0xf001], &[0xf000]]));
        assert!(matches!(result, Err(FileParseError::DirectoryRevisited { id: 0xf000, .. })));
    }

    #[test]
    fn parse_dir_containing_itself_is_error() {
        let result = parse(&make_fnt(&[&[0xf001], &[0xf001]]));
        assert!(matches!(result, Err(FileParseError::DirectoryRevisited { id: 0xf001, .. })));
    }

    #[test]
    fn parse_dir_listed_twice_is_error() {
        let result = parse(&make_fnt(&[&[0xf001, 0xf001], &[]]));
        assert!(matches!(result, Err(FileParseError::DirectoryRevisited { id: 0xf001, .. })));
    }

    #[test]
    fn parse_max_depth_dirs() {
        with_small_stack(|| parse(&make_nested_fnt(MAX_DIR_DEPTH as u16)).unwrap());
    }

    #[test]
    fn parse_too_deep_dirs_is_error() {
        let result = with_small_stack(|| parse(&make_nested_fnt(MAX_DIR_DEPTH as u16 + 1)));
        assert!(matches!(result, Err(FileParseError::DirectoryTooDeep { .. })));
    }

    /// Creates an empty temporary directory that is removed when dropped.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!("ds-rom-test-{}-{name}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Creates `depth` nested directories in `root` with a file in the deepest one.
    fn make_nested_dirs(root: &Path, depth: usize) {
        let deepest = (0..depth).fold(root.to_path_buf(), |path, _| path.join("d"));
        std::fs::create_dir_all(&deepest).unwrap();
        std::fs::write(deepest.join("file.bin"), [1, 2, 3]).unwrap();
    }

    #[test]
    fn load_max_depth_dirs() {
        let dir = TempDir::new("load_max_depth_dirs");
        make_nested_dirs(&dir.0, MAX_DIR_DEPTH);
        let path = dir.0.clone();
        let files = with_small_stack(move || FileSystem::load(path, 0).unwrap());
        assert_eq!(files.max_file_id(), 0);
    }

    #[test]
    fn load_too_deep_dirs_is_error() {
        let dir = TempDir::new("load_too_deep_dirs_is_error");
        make_nested_dirs(&dir.0, MAX_DIR_DEPTH + 1);
        let path = dir.0.clone();
        let result = with_small_stack(move || FileSystem::load(path, 0).map(|_| ()));
        assert!(matches!(result, Err(FileSystemLoadError::DirectoryTooDeep { .. })));
    }

    #[test]
    fn parse_deepest_possible_dirs_is_error() {
        let result = with_small_stack(|| parse(&make_nested_fnt(raw::MAX_SUBTABLES - 1)));
        assert!(matches!(result, Err(FileParseError::DirectoryTooDeep { .. })));
    }
}
