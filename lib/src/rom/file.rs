use std::{
    borrow::Cow,
    cmp::Ordering,
    collections::{BinaryHeap, HashSet},
    fmt::Display,
    io::Write,
    path::{Path, PathBuf},
};

use snafu::{Backtrace, Snafu};

use crate::str::BlobSize;

use super::raw::{self, FileAlloc, Fnt, FntDirectory, FntFile, FntSubtable, RawHeaderError};

pub struct Files<'a> {
    num_overlays: usize,
    files: Vec<File<'a>>,
    dirs: Vec<Dir>,
}

#[derive(Clone)]
pub struct File<'a> {
    id: u16,
    name: String,
    parent_id: u16,
    original_offset: u32,
    contents: Cow<'a, [u8]>,
}

#[derive(Clone)]
pub struct Dir {
    id: u16,
    name: String,
    parent_id: u16,
    children: Vec<u16>,
}

#[derive(Debug, Snafu)]
pub enum FileParseError {
    #[snafu(display("the file ID {id} is missing from the FNT:\n{backtrace}"))]
    MissingFileId { id: u16, backtrace: Backtrace },
    #[snafu(display("the directory ID {id} is missing from the FNT:\n{backtrace}"))]
    MissingDirId { id: u16, backtrace: Backtrace },
    #[snafu(transparent)]
    RawHeader { source: RawHeaderError },
}

#[derive(Debug, Snafu)]
pub enum FileBuildError {
    #[snafu(display("the file name {name} contains one or more non-ASCII characters:\n{backtrace}"))]
    NotAscii { name: String, backtrace: Backtrace },
}

const ROOT_DIR_ID: u16 = 0xf000;

impl<'a> Files<'a> {
    pub fn is_dir(id: u16) -> bool {
        id >= ROOT_DIR_ID
    }

    pub fn is_file(id: u16) -> bool {
        !Self::is_dir(id)
    }

    pub fn name(&self, id: u16) -> &str {
        if Self::is_dir(id) {
            &self.dir(id).name
        } else {
            &self.file(id).name
        }
    }

    pub fn dir(&self, id: u16) -> &Dir {
        &self.dirs[id as usize & 0xfff]
    }

    fn dir_mut(&mut self, id: u16) -> &mut Dir {
        &mut self.dirs[id as usize & 0xfff]
    }

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
    ) {
        let subtable_index = parent.id as usize & 0xfff;
        let subtable = &fnt.subtables[subtable_index];

        for FntFile { id, name } in subtable.iter() {
            let name = name.to_string();

            if id >= ROOT_DIR_ID {
                let mut dir = Dir { id, name, parent_id: parent.id, children: vec![] };
                Self::parse_subtable(fnt, fat, rom, &mut dir, dirs, files);
                dirs[id as usize & 0xfff] = Some(dir);
                parent.children.push(id);
            } else {
                let alloc = fat[id as usize];
                let contents = &rom.data()[alloc.range()];
                files[id as usize] = Some(File {
                    id,
                    name,
                    parent_id: parent.id,
                    original_offset: alloc.start,
                    contents: Cow::Borrowed(contents),
                });
                parent.children.push(id);
            }
        }
    }

    pub fn parse(fnt: &Fnt, fat: &[FileAlloc], rom: &'a raw::Rom) -> Result<Self, FileParseError> {
        let num_overlays = rom.num_arm9_overlays()? + rom.num_arm7_overlays()?;

        let mut root = Dir { id: ROOT_DIR_ID, name: "/".to_string(), parent_id: 0, children: vec![] };
        let mut dirs = vec![None; fnt.subtables.len()];
        let mut files = vec![None; fat.len()];
        Self::parse_subtable(fnt, fat, rom, &mut root, &mut dirs, &mut files);
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

        Ok(Files { files, dirs, num_overlays })
    }

    fn build_subtable(&self, parent: &Dir) -> Result<FntSubtable, FileBuildError> {
        let mut data = vec![];

        for child in &parent.children {
            let child = *child;

            let is_dir = Self::is_dir(child);
            let name = self.name(child);

            let name_length = name.len() as u8 & 0x7f;
            let directory_bit = if is_dir { 0x80 } else { 0 };
            data.push(name_length | directory_bit);
            for ch in name.chars().take(0x7f) {
                if !ch.is_ascii() {
                    return NotAsciiSnafu { name }.fail();
                }
                data.push(ch as u8);
            }
            if is_dir {
                data.write(&u16::to_le_bytes(child)).unwrap();
            }
        }

        Ok(FntSubtable {
            directory: Cow::Owned(FntDirectory {
                subtable_offset: 0,
                first_file_id: parent.children.first().map_or(0, |id| *id),
                parent_id: if parent.is_root() { self.dirs.len() as u16 } else { parent.id },
            }),
            data: Cow::Owned(data),
        })
    }

    fn build_fnt_recursive(&'a self, subtables: &mut Vec<FntSubtable<'a>>, parent_id: u16) -> Result<(), FileBuildError> {
        let parent = &self.dir(parent_id);
        subtables.push(self.build_subtable(parent)?);
        for child in &parent.children {
            if *child >= ROOT_DIR_ID {
                self.build_fnt_recursive(subtables, *child)?;
            }
        }
        Ok(())
    }

    pub fn build_fnt(&self) -> Result<Fnt, FileBuildError> {
        let mut subtables = vec![];
        self.build_fnt_recursive(&mut subtables, ROOT_DIR_ID)?;
        Ok(Fnt { subtables: subtables.into_boxed_slice() })
    }

    pub fn sort_for_fnt_in(&mut self, parent_id: u16) {
        let mut parent = self.dir(parent_id).clone();
        parent.children.sort_by(|a, b| {
            let dirs_first = Self::is_dir(*a).cmp(&Self::is_dir(*b));

            let a_name = self.name(*a);
            let b_name = self.name(*b);

            let len = a_name.len().min(b_name.len());
            let a_chars = a_name[..len].chars().map(|c| c.to_ascii_lowercase());
            let b_chars = b_name[..len].chars().map(|c| c.to_ascii_lowercase());
            let alphabetic_order = a_chars.cmp(b_chars);

            let shortest_first = a_name.len().cmp(&b_name.len());

            dirs_first.then(alphabetic_order).then(shortest_first)
        });

        for child in &mut parent.children {
            if Self::is_dir(*child) {
                self.sort_for_fnt_in(*child);
            }
        }

        *self.dir_mut(parent_id) = parent;
    }

    pub fn sort_for_fnt(&mut self) {
        self.sort_for_fnt_in(ROOT_DIR_ID);
    }

    pub fn compare_for_rom(&self, a: u16, b: u16) -> Ordering {
        let a_name = self.name(a);
        let b_name = self.name(b);

        let len = a_name.len().min(b_name.len());
        let a_chars = a_name[..len].chars();
        let b_chars = b_name[..len].chars();
        let ascii_order = a_chars.cmp(b_chars);

        let shortest_first = a_name.len().cmp(&b_name.len());

        ascii_order.then(shortest_first)
    }

    pub fn sort_for_rom_in(&mut self, parent_id: u16) {
        let mut parent = self.dir(parent_id).clone();
        parent.children.sort_by(|a, b| self.compare_for_rom(*a, *b));

        for child in &mut parent.children {
            if Self::is_dir(*child) {
                self.sort_for_rom_in(*child);
            }
        }

        *self.dir_mut(parent_id) = parent;
    }

    pub fn sort_for_rom(&mut self) {
        self.sort_for_fnt_in(ROOT_DIR_ID);
    }

    pub fn find_subdirectory(&self, path: &str, parent_id: u16) -> Option<&Dir> {
        let parent = &self.dir(parent_id);
        let (child_name, next) = path.split_once('/').map(|(c, n)| (c, Some(n))).unwrap_or((path, None));
        let child = parent.children.iter().find(|id| self.name(**id) == child_name)?;
        if let Some(next) = next {
            self.find_subdirectory(next, *child)
        } else {
            Some(self.dir(*child))
        }
    }

    fn traverse_nonvisited_files<Cb>(&self, visited: &mut HashSet<u16>, callback: &mut Cb, subdir: &Dir, path: &Path)
    where
        Cb: FnMut(&File, &Path) -> (),
    {
        if visited.contains(&subdir.id) {
            return;
        }
        for child in &subdir.children {
            if Self::is_dir(*child) {
                let path = path.join(self.name(*child));
                self.traverse_nonvisited_files(visited, callback, self.dir(*child), &path);
            } else {
                callback(self.file(*child), path);
            }
        }
        visited.insert(subdir.id);
    }

    pub fn traverse_files<I, Cb>(&self, path_order: I, mut callback: Cb)
    where
        I: IntoIterator<Item = &'a str>,
        Cb: FnMut(&File, &Path) -> (),
    {
        let mut visited = HashSet::<u16>::new();

        for path in path_order {
            let subdir = if path.trim() == "/" {
                self.dir(ROOT_DIR_ID)
            } else {
                let Some(subdir) = self.find_subdirectory(path, ROOT_DIR_ID) else { continue };
                subdir
            };
            self.traverse_nonvisited_files(&mut visited, &mut callback, subdir, &PathBuf::new());
        }
    }

    pub fn max_file_id_in(&self, parent_id: u16) -> u16 {
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

    pub fn max_file_id(&self) -> u16 {
        self.max_file_id_in(ROOT_DIR_ID)
    }

    pub fn display(&self, indent: usize) -> DisplayFiles {
        DisplayFiles { files: self, parent_id: ROOT_DIR_ID, indent }
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
        paths.windows(2).all(|w| self.compare_for_rom(w[0].id, w[1].id).is_lt())
    }

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

impl<'a> File<'a> {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn id(&self) -> u16 {
        self.id
    }

    pub fn contents(&self) -> &[u8] {
        &self.contents
    }
}

impl Dir {
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
        self.offset.partial_cmp(&other.offset)
    }
}

impl Ord for PathOrder {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.offset.cmp(&other.offset)
    }
}

pub struct DisplayFiles<'a> {
    files: &'a Files<'a>,
    parent_id: u16,
    indent: usize,
}

impl<'a> Display for DisplayFiles<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let i = format!("{:indent$}", "", indent = self.indent);
        let parent = self.files.dir(self.parent_id);
        let files = &self.files;
        for child in &parent.children {
            if Files::is_dir(*child) {
                write!(f, "{i}0x{:04x}: {: <32}", *child, files.name(*child))?;
                writeln!(f)?;
                write!(f, "{}", Self { files, parent_id: *child, indent: self.indent + 2 })?;
            } else {
                let file = files.file(*child);
                let size = BlobSize(file.contents.len()).to_string();
                write!(f, "{i}0x{:04x}: {: <32}{size: >7}", file.id, file.name)?;
                writeln!(f)?;
            }
        }
        Ok(())
    }
}
