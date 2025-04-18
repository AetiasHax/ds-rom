use std::{
    borrow::Cow,
    cmp::Ordering,
    collections::{BinaryHeap, HashSet},
    fmt::Display,
    io::Write,
    path::{Path, PathBuf},
    str::FromStr,
};

use encoding_rs::SHIFT_JIS;
use snafu::{Backtrace, Snafu};

use super::raw::{self, FileAlloc, Fnt, FntDirectory, FntFile, FntSubtable, RawHeaderError};
use crate::{
    io::{read_dir, read_file, FileError},
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
#[derive(Clone)]
pub struct Dir {
    id: u16,
    name: String,
    parent_id: u16,
    children: Vec<u16>,
}

/// Errors related to [`FileSystem::parse`].
#[derive(Debug, Snafu)]
pub enum FileParseError {
    /// Occurs when a file ID is missing from the raw FNT.
    #[snafu(display("the file ID {id} is missing from the FNT:\n{backtrace}"))]
    MissingFileId {
        /// File ID.
        id: u16,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// Occurs when a directory ID is missing from the faw FNT.
    #[snafu(display("the directory ID {id} is missing from the FNT:\n{backtrace}"))]
    MissingDirId {
        /// Directory ID.
        id: u16,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// See [`RawHeaderError`].
    #[snafu(transparent)]
    RawHeader {
        /// Source error.
        source: RawHeaderError,
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
}

const ROOT_DIR_ID: u16 = 0xf000;

impl<'a> FileSystem<'a> {
    /// Creates a new [`FileSystem`]. The number of overlays are used to determine the first file ID, since overlays are also
    /// located in the FAT but not the FNT.
    pub fn new(num_overlays: usize) -> Self {
        let root = Dir { id: ROOT_DIR_ID, name: "/".to_string(), parent_id: 0, children: vec![] };
        Self { num_overlays, files: vec![], dirs: vec![root], next_file_id: num_overlays as u16, next_dir_id: ROOT_DIR_ID + 1 }
    }

    fn load_in<P: AsRef<Path>>(&mut self, path: P, parent_id: u16) -> Result<(), FileError> {
        // Sort children by FNT order so the file/dir IDs become correct
        let mut children =
            read_dir(&path)?.collect::<Result<Vec<_>, _>>()?.into_iter().map(|entry| entry.path()).collect::<Vec<_>>();
        children.sort_unstable_by(|a, b| {
            Self::compare_for_fnt(a.to_string_lossy().as_ref(), a.is_dir(), b.to_string_lossy().as_ref(), b.is_dir())
        });

        for child in children.into_iter() {
            let name = child.file_name().unwrap().to_string_lossy().to_string();
            if child.is_dir() {
                let child_id = self.next_dir_id;
                let child_path = path.as_ref().join(&name);
                self.make_child_dir(name, parent_id);
                self.load_in(child_path, child_id)?;
            } else {
                let contents = read_file(child)?;
                self.make_child_file(name, parent_id, contents);
            }
        }
        Ok(())
    }

    /// Loads a file system from the given root directory. This will traverse and add all folders and files into the
    /// [`FileSystem`] struct.
    ///
    /// # Errors
    ///
    /// This function will return an error if an I/O operation fails.
    pub fn load<P: AsRef<Path>>(root: P, num_overlays: usize) -> Result<Self, FileError> {
        let mut files = Self::new(num_overlays);
        files.load_in(root, ROOT_DIR_ID)?;
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
    pub fn name(&self, id: u16) -> &str {
        if Self::is_dir(id) {
            &self.dir(id).name
        } else {
            &self.file(id).name
        }
    }

    /// Returns a directory.
    pub fn dir(&self, id: u16) -> &Dir {
        &self.dirs[id as usize & 0xfff]
    }

    fn dir_mut(&mut self, id: u16) -> &mut Dir {
        &mut self.dirs[id as usize & 0xfff]
    }

    /// Returns a file.
    pub fn file(&self, id: u16) -> &File {
        &self.files[id as usize - self.num_overlays]
    }

    fn parse_subtable(
        fnt: &Fnt,
        fat: &[FileAlloc],
        rom: &'a raw::Rom,
        parent: &mut Dir,
        dirs: &mut Vec<Option<Dir>>,
        files: &mut Vec<Option<File<'a>>>,
    ) -> (u16, u16) {
        let subtable_index = parent.id as usize & 0xfff;
        let subtable = &fnt.subtables[subtable_index];

        let mut max_file_id = 0;
        let mut max_dir_id = 0;
        for FntFile { id, name } in subtable.iter() {
            let name = name.to_string();

            if Self::is_dir(id) {
                max_dir_id = max_dir_id.max(id);
                let mut dir = Dir { id, name, parent_id: parent.id, children: vec![] };
                let (max_child_dir_id, max_child_file_id) = Self::parse_subtable(fnt, fat, rom, &mut dir, dirs, files);
                max_dir_id = max_dir_id.max(max_child_dir_id);
                max_file_id = max_file_id.max(max_child_file_id);

                dirs[id as usize & 0xfff] = Some(dir);
                parent.children.push(id);
            } else {
                max_file_id = max_file_id.max(id);
                let alloc = fat[id as usize];
                let contents = &rom.data()[alloc.range()];
                files[id as usize] = Some(File { id, name, original_offset: alloc.start, contents: Cow::Borrowed(contents) });
                parent.children.push(id);
            }
        }
        (max_file_id, max_dir_id)
    }

    /// Parses an FNT, FAT and ROM to create a [`FileSystem`].
    ///
    /// # Errors
    ///
    /// This function will return an error if [`raw::Rom::num_arm9_overlays`] or [`raw::Rom::num_arm7_overlays`] fails, or if
    /// a file or directory ID is missing from the FNT.
    pub fn parse(fnt: &Fnt, fat: &[FileAlloc], rom: &'a raw::Rom) -> Result<Self, FileParseError> {
        let num_overlays = rom.num_arm9_overlays()? + rom.num_arm7_overlays()?;

        let mut root = Dir { id: ROOT_DIR_ID, name: "/".to_string(), parent_id: 0, children: vec![] };
        let mut dirs = vec![None; fnt.subtables.len()];
        let mut files = vec![None; fat.len()];
        let (max_file_id, max_dir_id) = Self::parse_subtable(fnt, fat, rom, &mut root, &mut dirs, &mut files);
        dirs[0] = Some(root);

        let files = files
            .into_iter()
            .skip(num_overlays)
            .enumerate()
            .map(|(id, f)| f.ok_or(MissingFileIdSnafu { id: id as u16 }.build()))
            .collect::<Result<Vec<_>, _>>()?;
        let dirs = dirs
            .into_iter()
            .enumerate()
            .map(|(id, d)| d.ok_or(MissingDirIdSnafu { id: id as u16 + ROOT_DIR_ID }.build()))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(FileSystem { files, dirs, num_overlays, next_file_id: max_file_id + 1, next_dir_id: max_dir_id + 1 })
    }

    fn find_first_file_id(&self, parent: &Dir) -> u16 {
        let child = *parent.children.first().expect("No first file ID found, directory is empty");
        if Self::is_file(child) {
            child
        } else {
            self.find_first_file_id(self.dir(child))
        }
    }

    fn build_subtable(&self, parent: &Dir) -> Result<FntSubtable, FileBuildError> {
        let mut data = vec![];

        for child in &parent.children {
            let child = *child;

            let is_dir = Self::is_dir(child);
            let name = self.name(child);

            let (sjis_name, _, had_errors) = SHIFT_JIS.encode(name);
            if had_errors {
                return EncodingFailedSnafu { name }.fail();
            }

            let name_length = sjis_name.len() as u8 & 0x7f;
            let directory_bit = if is_dir { 0x80 } else { 0 };
            data.push(name_length | directory_bit);

            data.extend(sjis_name.iter().take(0x7f));
            if is_dir {
                data.write_all(&u16::to_le_bytes(child)).unwrap();
            }
        }

        Ok(FntSubtable {
            directory: Cow::Owned(FntDirectory {
                subtable_offset: 0,
                first_file_id: self.find_first_file_id(parent),
                parent_id: parent.parent_id,
            }),
            data: Cow::Owned(data),
        })
    }

    fn build_fnt_recursive(&'a self, subtables: &mut Vec<FntSubtable<'a>>, parent_id: u16) -> Result<(), FileBuildError> {
        let parent = &self.dir(parent_id);
        subtables.push(self.build_subtable(parent)?);
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
    /// This function will return an error if a file/directory name contains non-ASCII characters.
    pub fn build_fnt(&self) -> Result<Fnt, FileBuildError> {
        let mut subtables = vec![];
        self.build_fnt_recursive(&mut subtables, ROOT_DIR_ID)?;
        Ok(Fnt { subtables: subtables.into_boxed_slice() })
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

    fn sort_for_fnt_in(&mut self, parent_id: u16) {
        let mut parent = self.dir(parent_id).clone();
        parent
            .children
            .sort_by(|a, b| Self::compare_for_fnt(self.name(*a), Self::is_dir(*a), self.name(*b), Self::is_dir(*b)));

        for child in &mut parent.children {
            if Self::is_dir(*child) {
                self.sort_for_fnt_in(*child);
            }
        }

        *self.dir_mut(parent_id) = parent;
    }

    /// Sorts the entire [`FileSystem`] so that it's laid out in the right order for the FNT.
    pub fn sort_for_fnt(&mut self) {
        self.sort_for_fnt_in(ROOT_DIR_ID);
    }

    fn compare_for_rom(a: &str, b: &str) -> Ordering {
        // Lexicographic UTF-8 order
        a.cmp(b)
    }

    fn sort_for_rom_in(&mut self, parent_id: u16) {
        let mut parent = self.dir(parent_id).clone();
        parent.children.sort_by(|a, b| Self::compare_for_rom(self.name(*a), self.name(*b)));

        for child in &mut parent.children {
            if Self::is_dir(*child) {
                self.sort_for_rom_in(*child);
            }
        }

        *self.dir_mut(parent_id) = parent;
    }

    /// Sorts the entire [`FileSystem`] so that files laid out in the right order for appending to the ROM.
    pub fn sort_for_rom(&mut self) {
        self.sort_for_rom_in(ROOT_DIR_ID);
    }

    fn find_path_in(&self, path: &str, parent_id: u16) -> Option<u16> {
        let parent = &self.dir(parent_id);
        let (child_name, next) = path.split_once('/').map(|(c, n)| (c, Some(n))).unwrap_or((path, None));
        let child = parent.children.iter().find(|id| self.name(**id) == child_name)?;
        if let Some(next) = next {
            if Self::is_dir(*child) {
                self.find_path_in(next, *child)
            } else {
                None
            }
        } else {
            Some(*child)
        }
    }

    fn find_path(&self, path: &str) -> Option<u16> {
        self.find_path_in(path, ROOT_DIR_ID)
    }

    fn make_child_dir(&mut self, name: String, parent_id: u16) -> &Dir {
        let id = self.next_dir_id;
        self.dirs.push(Dir { id, name, parent_id, children: vec![] });
        let parent = self.dir_mut(parent_id);
        parent.children.push(id);
        self.next_dir_id += 1;
        self.dirs.last().unwrap()
    }

    fn make_child_file(&mut self, name: String, parent_id: u16, contents: Vec<u8>) -> &File {
        let id = self.next_file_id;
        self.files.push(File { id, name, original_offset: 0, contents: contents.into() });
        let parent = self.dir_mut(parent_id);
        parent.children.push(id);
        self.next_file_id += 1;
        self.files.last().unwrap()
    }

    fn traverse_nonvisited_files<Cb>(&self, visited: &mut HashSet<u16>, callback: &mut Cb, subdir: &Dir, path: &Path)
    where
        Cb: FnMut(&File, &Path),
    {
        if visited.contains(&subdir.id) {
            return;
        }
        for child in &subdir.children {
            if visited.contains(child) {
                continue;
            }

            if Self::is_dir(*child) {
                let path = path.join(self.name(*child));
                self.traverse_nonvisited_files(visited, callback, self.dir(*child), &path);
            } else {
                callback(self.file(*child), path);
                let first_time_visiting_file = visited.insert(*child);
                assert!(first_time_visiting_file);
            }
        }
        let first_time_visiting_file = visited.insert(subdir.id);
        assert!(first_time_visiting_file);
    }

    /// Traverses the [`FileSystem`] and calls `callback` for each file found. The directories will be prioritized according to
    /// the `path_order`.
    pub fn traverse_files<I, Cb>(&self, path_order: I, mut callback: Cb)
    where
        I: IntoIterator<Item = &'a str>,
        Cb: FnMut(&File, &Path),
    {
        let mut visited = HashSet::<u16>::new();

        for path in path_order {
            let path = path.strip_prefix("/").unwrap_or(path);
            let path_buf = &PathBuf::from_str(path).unwrap();
            let subdir = if path.trim() == "" {
                self.dir(ROOT_DIR_ID)
            } else {
                let Some(child) = self.find_path(path) else { continue };
                if visited.contains(&child) {
                    continue;
                }

                if Self::is_dir(child) {
                    self.dir(child)
                } else {
                    let file = self.file(child);
                    callback(file, path_buf);
                    let first_time_visiting_file = visited.insert(file.id);
                    assert!(first_time_visiting_file);
                    continue;
                }
            };
            self.traverse_nonvisited_files(&mut visited, &mut callback, subdir, path_buf);
        }
    }

    fn max_file_id_in(&self, parent_id: u16) -> u16 {
        let mut max_id = 0;
        let parent = self.dir(parent_id);
        for child in &parent.children {
            let id = if Self::is_dir(*child) { self.max_file_id_in(*child) } else { *child };
            if id > max_id {
                max_id = id;
            }
        }
        max_id
    }

    /// Returns the max file ID of this [`FileSystem`].
    pub fn max_file_id(&self) -> u16 {
        self.max_file_id_in(ROOT_DIR_ID)
    }

    /// Creates a [`DisplayFileSystem`] which implements [`Display`].
    pub fn display(&self, indent: usize) -> DisplayFileSystem {
        DisplayFileSystem { files: self, parent_id: ROOT_DIR_ID, indent }
    }

    fn traverse_and_compute_path_order(&self, path: &str, path_order: &mut BinaryHeap<PathOrder>, parent: &Dir) {
        for child in &parent.children {
            let path = format!("{}/{}", path, self.name(*child));
            if Self::is_dir(*child) {
                self.traverse_and_compute_path_order(path.as_str(), path_order, self.dir(*child));
            } else {
                path_order.push(PathOrder {
                    id: *child,
                    parent_id: parent.id,
                    path_name: path,
                    offset: self.file(*child).original_offset,
                });
            }
        }
    }

    fn are_paths_sorted(&self, paths: &[PathOrder]) -> bool {
        paths.windows(2).all(|w| Self::compare_for_rom(self.name(w[0].id), self.name(w[1].id)).is_lt())
    }

    /// Computes the path order that the [`FileSystem`] is currently in. This can be saved and reused in
    /// [`Self::traverse_files`] to traverse in the same order later.
    pub fn compute_path_order(&self) -> Vec<String> {
        let mut path_order = BinaryHeap::new();
        self.traverse_and_compute_path_order("", &mut path_order, self.dir(ROOT_DIR_ID));
        let mut paths = path_order.into_sorted_vec();

        // Loop to simplify path order
        let mut children_start = 0;
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

            let parent = self.dir(parent_id);
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

        paths.into_iter().map(|p| p.path_name).collect()
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
        let parent = self.files.dir(self.parent_id);
        let files = &self.files;
        for child in &parent.children {
            if FileSystem::is_dir(*child) {
                write!(f, "{i}0x{:04x}: {: <32}", *child, files.name(*child))?;
                writeln!(f)?;
                write!(f, "{}", Self { files, parent_id: *child, indent: self.indent + 2 })?;
            } else {
                let file = files.file(*child);
                let size = BlobSize(file.contents.len()).to_string();
                write!(f, "{i}0x{:04x}: {: <48}{size: >7}", file.id, file.name)?;
                writeln!(f)?;
            }
        }
        Ok(())
    }
}
