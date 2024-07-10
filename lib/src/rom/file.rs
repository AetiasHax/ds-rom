use std::{borrow::Cow, fmt::Display};

use crate::str::BlobSize;

use super::raw::{Fnt, FntFile};

pub struct File<'a> {
    pub id: u16,
    pub name: String,
    pub children: Vec<File<'a>>,
    pub contents: Option<Cow<'a, [u8]>>,
}

const ROOT_DIR_ID: u16 = 0xf000;

impl<'a> File<'a> {
    fn parse_subtable(&mut self, fnt: &Fnt, fat: &'a [&[u8]], subtable: u16) {
        let subtable = &fnt.subtables[subtable as usize];
        for FntFile { id, name } in subtable.iter() {
            let name = name.to_string();
            let mut file = File { id, name, children: vec![], contents: None };
            if file.is_dir() {
                file.parse_subtable(fnt, fat, file.id - ROOT_DIR_ID);
            } else {
                file.contents = Some(Cow::Borrowed(fat[id as usize]));
            }
            self.children.push(file);
        }
    }

    pub fn parse(fnt: &Fnt, fat: &'a [&[u8]]) -> Self {
        let mut root = Self { id: ROOT_DIR_ID, name: "/".to_string(), children: vec![], contents: None };
        root.parse_subtable(fnt, fat, 0);
        root
    }

    pub fn is_dir(&self) -> bool {
        self.id >= ROOT_DIR_ID
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
