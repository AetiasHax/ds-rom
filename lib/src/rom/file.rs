use std::{borrow::Cow, collections::HashSet, fmt::Display, io::Write};

use snafu::{Backtrace, Snafu};

use crate::str::BlobSize;

use super::raw::{Fnt, FntDirectory, FntFile, FntSubtable};

pub struct File<'a> {
    id: u16,
    name: String,
    parent_id: u16,
    children: Vec<File<'a>>,
    contents: Option<Cow<'a, [u8]>>,
}

#[derive(Debug, Snafu)]
pub enum FileBuildError {
    #[snafu(display("the file name {name} contains one or more non-ASCII characters:\n{backtrace}"))]
    NotAscii { name: String, backtrace: Backtrace },
}

const ROOT_DIR_ID: u16 = 0xf000;

impl<'a> File<'a> {
    fn parse_subtable(&mut self, fnt: &Fnt, fat: &'a [&[u8]], subtable: u16) {
        let subtable = &fnt.subtables[subtable as usize];
        for FntFile { id, name } in subtable.iter() {
            let name = name.to_string();
            let mut file = File { id, name, parent_id: self.id, children: vec![], contents: None };
            if file.is_dir() {
                file.parse_subtable(fnt, fat, file.id - ROOT_DIR_ID);
            } else {
                file.contents = Some(Cow::Borrowed(fat[id as usize]));
            }
            self.children.push(file);
        }
    }

    pub fn parse(fnt: &Fnt, fat: &'a [&[u8]]) -> Self {
        let mut root = Self { id: ROOT_DIR_ID, name: "/".to_string(), parent_id: 0, children: vec![], contents: None };
        root.parse_subtable(fnt, fat, 0);
        root
    }

    fn build_subtable(&self) -> Result<FntSubtable, FileBuildError> {
        let mut data = vec![];

        for child in &self.children {
            let name_length = child.name.len() as u8 & 0x7f;
            let directory_bit = if child.is_dir() { 0x80 } else { 0 };
            data.push(name_length | directory_bit);
            for ch in child.name.chars().take(0x7f) {
                if !ch.is_ascii() {
                    return NotAsciiSnafu { name: child.name.clone() }.fail();
                }
                data.push(ch as u8);
            }
            if child.is_dir() {
                data.write(&u16::to_le_bytes(child.id)).unwrap();
            }
        }

        Ok(FntSubtable {
            directory: Cow::Owned(FntDirectory {
                subtable_offset: 0,
                first_file_id: self.children.first().map_or(0, |c| c.id),
                parent_id: if self.is_root() { todo!() } else { self.parent_id },
            }),
            data: Cow::Owned(data),
        })
    }

    fn build_fnt_recursive(&'a self, subtables: &mut Vec<FntSubtable<'a>>) -> Result<(), FileBuildError> {
        subtables.push(self.build_subtable()?);
        for child in &self.children {
            if child.is_dir() {
                child.build_fnt_recursive(subtables)?;
            }
        }
        Ok(())
    }

    pub fn build_fnt(&self) -> Result<Fnt, FileBuildError> {
        let mut subtables = vec![];
        self.build_fnt_recursive(&mut subtables)?;
        Ok(Fnt { subtables: subtables.into_boxed_slice() })
    }

    pub fn sort_for_fnt(&mut self) {
        self.children.sort_by(|a, b| {
            let dirs_first = a.is_dir().cmp(&b.is_dir());

            let len = a.name.len().min(b.name.len());
            let a_chars = a.name[..len].chars().map(|c| c.to_ascii_lowercase());
            let b_chars = b.name[..len].chars().map(|c| c.to_ascii_lowercase());
            let alphabetic_order = a_chars.cmp(b_chars);

            let shortest_first = a.name.len().cmp(&b.name.len());

            dirs_first.then(alphabetic_order).then(shortest_first)
        });

        for child in &mut self.children {
            if child.is_dir() {
                child.sort_for_fnt();
            }
        }
    }

    pub fn sort_for_rom(&mut self) {
        self.children.sort_by(|a, b| {
            let len = a.name.len().min(b.name.len());
            let a_chars = a.name[..len].chars();
            let b_chars = b.name[..len].chars();
            let ascii_order = a_chars.cmp(b_chars);

            let shortest_first = a.name.len().cmp(&b.name.len());

            ascii_order.then(shortest_first)
        });

        for child in &mut self.children {
            if child.is_dir() {
                child.sort_for_rom();
            }
        }
    }

    pub fn find_subdirectory(&self, path: &str) -> Option<&File> {
        let (child_name, next) = path.split_once('/').map(|(c, n)| (c, Some(n))).unwrap_or((path, None));
        let child = self.children.iter().find(|c| c.name == child_name)?;
        if let Some(next) = next {
            child.find_subdirectory(next)
        } else {
            Some(child)
        }
    }

    fn nonvisited_traverse_files<Cb>(&self, visited: &mut HashSet<u16>, callback: &mut Cb)
    where
        Cb: FnMut(&File) -> (),
    {
        if visited.contains(&self.id) {
            return;
        }
        for child in &self.children {
            if child.is_dir() {
                child.nonvisited_traverse_files(visited, callback);
            } else {
                callback(child);
            }
        }
        visited.insert(self.id);
    }

    pub fn traverse_files<I, Cb>(&self, path_order: I, mut callback: Cb)
    where
        I: IntoIterator<Item = &'a str>,
        Cb: FnMut(&File) -> (),
    {
        let mut visited = HashSet::<u16>::new();

        for path in path_order {
            let Some(subdir) = self.find_subdirectory(path) else { continue };
            visited.insert(subdir.id);
            subdir.nonvisited_traverse_files(&mut visited, &mut callback);
        }
    }

    pub fn max_file_id(&self) -> u16 {
        let mut max_id = 0;
        for child in &self.children {
            let id = if child.is_dir() { child.max_file_id() } else { child.id };
            if id > max_id {
                max_id = id;
            }
        }
        max_id
    }

    pub fn id(&self) -> u16 {
        self.id
    }

    pub fn is_root(&self) -> bool {
        self.parent_id == 0
    }

    pub fn is_dir(&self) -> bool {
        self.id >= ROOT_DIR_ID
    }

    pub fn contents(&self) -> Option<&[u8]> {
        self.contents.as_deref()
    }

    pub fn display(&self, indent: usize) -> DisplayFile {
        DisplayFile { file: self, indent }
    }
}

pub struct DisplayFile<'a> {
    file: &'a File<'a>,
    indent: usize,
}

impl<'a> Display for DisplayFile<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let i = format!("{:indent$}", "", indent = self.indent);
        let file = &self.file;
        let size = if let Some(contents) = &file.contents { BlobSize(contents.len()).to_string() } else { "".to_string() };
        write!(f, "{i}0x{:04x}: {: <32}{size: >7}", file.id, file.name)?;
        writeln!(f)?;
        for child in &file.children {
            write!(f, "{}", child.display(self.indent + 2))?;
        }
        Ok(())
    }
}
