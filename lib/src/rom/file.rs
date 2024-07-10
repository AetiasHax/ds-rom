use std::fmt::Display;

use super::raw::{Fnt, FntFile};

pub struct File {
    pub id: u16,
    pub name: String,
    pub children: Vec<File>,
}

const ROOT_DIR_ID: u16 = 0xf000;

impl File {
    fn parse_subtable(&mut self, fnt: &Fnt, index: u16) {
        let subtable = &fnt.subtables[index as usize];
        for FntFile { id, name } in subtable.iter() {
            let name = name.to_string();
            let mut file = File { id, name, children: vec![] };
            if file.is_dir() {
                file.parse_subtable(fnt, file.id - ROOT_DIR_ID);
            }
            self.children.push(file);
        }
    }

    pub fn parse(fnt: &Fnt) -> Self {
        let mut root = Self { id: ROOT_DIR_ID, name: "/".to_string(), children: vec![] };
        root.parse_subtable(fnt, 0);
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
    file: &'a File,
    indent: usize,
}

impl<'a> Display for DisplayFile<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let i = format!("{:indent$}", "", indent = self.indent);
        let file = &self.file;
        writeln!(f, "{i}0x{:04x}: {}", file.id, file.name)?;
        for child in &file.children {
            write!(f, "{}", child.display(self.indent + 2))?;
        }
        Ok(())
    }
}
