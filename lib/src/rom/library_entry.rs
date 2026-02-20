use std::fmt::Display;

/// A library version string entry after the build info of an ARM9 program.
pub struct LibraryEntry<'a> {
    address: u32,
    version_string: &'a str,
}

impl<'a> LibraryEntry<'a> {
    /// Creates a new [`LibraryEntry`].
    pub fn new(address: u32, version_string: &'a str) -> Self {
        Self { address, version_string }
    }

    /// Returns the address of this [`LibraryEntry`].
    pub fn address(&self) -> u32 {
        self.address
    }

    /// Returns the version string of this [`LibraryEntry`].
    pub fn version_string(&self) -> &'a str {
        self.version_string
    }

    /// Returns a [`DisplayLibraryEntry`] which implements [`Display`].
    pub fn display(&'a self, indent: usize) -> DisplayLibraryEntry<'a> {
        DisplayLibraryEntry { entry: self, indent }
    }
}

/// Can be used to display values inside [`LibraryEntry`].
pub struct DisplayLibraryEntry<'a> {
    entry: &'a LibraryEntry<'a>,
    indent: usize,
}

impl Display for DisplayLibraryEntry<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let i = " ".repeat(self.indent);
        writeln!(f, "{i}Address .......... : {:#010x}", self.entry.address)?;
        writeln!(f, "{i}Version string ... : {}", self.entry.version_string)?;
        Ok(())
    }
}
