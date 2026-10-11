use std::{cmp::Ordering, fmt::Display};

use serde::{Deserialize, Serialize};
use snafu::{Backtrace, Snafu};

use super::RawBuildInfoError;

/// Layout of the entries in the ARM9 autoload list.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Deserialize, Serialize)]
pub enum AutoloadInfoLayout {
    /// Base address, code size and .bss size.
    Basic,
    /// Base address, code size, .ctor address and .bss size.
    Extended,
}

impl AutoloadInfoLayout {
    /// All layouts, in the order they should be tried when parsing an autoload list.
    pub const ALL: [Self; 2] = [Self::Basic, Self::Extended];

    /// Size of one autoload list entry in this layout.
    pub fn entry_size(self) -> usize {
        match self {
            Self::Basic => 12,
            Self::Extended => 16,
        }
    }
}

impl Display for AutoloadInfoLayout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Basic => write!(f, "basic ({}-byte entries)", self.entry_size()),
            Self::Extended => write!(f, "extended ({}-byte entries)", self.entry_size()),
        }
    }
}

/// An entry in the autoload list.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Deserialize, Serialize)]
pub struct AutoloadInfoEntry {
    /// Base address of the autoload module.
    pub base_address: u32,
    /// Size of the module's initialized area.
    pub code_size: u32,
    /// Size of the module's uninitialized area.
    pub bss_size: u32,
    /// Address of the module's static initializer list, a list of function pointers terminated by a null pointer. Only exists
    /// in [`AutoloadInfoLayout::Extended`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ctor_start: Option<u32>,
}

/// Autoload kind.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub enum AutoloadKind {
    /// Instruction TCM (Tightly Coupled Memory). Mainly used to make functions have fast and predictable load times.
    Itcm,
    /// Data TCM (Tightly Coupled Memory). Mainly used to make data have fast and predictable access times.
    Dtcm,
    /// Other autoload block of unknown purpose.
    Unknown(u32),
}

impl PartialOrd for AutoloadKind {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AutoloadKind {
    fn cmp(&self, other: &Self) -> Ordering {
        // ITCM < DTCM < Unknown
        match (self, other) {
            (_, _) if self == other => Ordering::Equal,
            (AutoloadKind::Itcm, _) => Ordering::Less,
            (_, AutoloadKind::Itcm) => Ordering::Greater,
            (AutoloadKind::Dtcm, _) => Ordering::Less,
            (_, AutoloadKind::Dtcm) => Ordering::Greater,
            (AutoloadKind::Unknown(a), AutoloadKind::Unknown(b)) => a.cmp(b),
        }
    }
}

/// Info about an autoload block.
#[derive(Clone, Copy, Deserialize, Serialize, Debug, PartialEq, Eq)]
pub struct AutoloadInfo {
    #[serde(flatten)]
    /// Entry in the autoload list.
    pub list_entry: AutoloadInfoEntry,
    /// The kind of autoload block.
    pub kind: AutoloadKind,
}

/// Errors related to [`AutoloadInfo`].
#[derive(Debug, Snafu)]
pub enum RawAutoloadInfoError {
    /// See [`RawBuildInfoError`].
    #[snafu(transparent)]
    RawBuildInfo {
        /// Source error.
        source: RawBuildInfoError,
    },
    /// Occurs when the input cannot be divided into autoload list entries of any known layout.
    #[snafu(display(
        "autoload infos are {size} bytes, which is not a multiple of 12 (basic layout) or 16 (extended layout):\n{backtrace}"
    ))]
    InvalidSize {
        /// Size of the input.
        size: usize,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// Occurs when the autoload info entries' `code_size` values don't add up to the combined size of all autoload blocks.
    #[snafu(display(
        "none of the possible total code sizes {total:?} match with the expected total autoload blocks size of {expected}:\n{backtrace}"
    ))]
    TotalSizeMismatch {
        /// The sum of `code_size` values.
        total: Vec<u64>,
        /// The combined size of all autoload blocks.
        expected: u32,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
}

impl AutoloadInfoEntry {
    /// Parses `data` as an autoload list. `blocks_size` is the combined size of the autoload blocks, which the code sizes of
    /// the parsed entries should add up to. It is used to tell the layouts apart, as a list of
    /// [`AutoloadInfoLayout::Extended`] entries can otherwise be silently misparsed as [`AutoloadInfoLayout::Basic`] entries
    /// and vice versa.
    ///
    /// # Errors
    ///
    /// This function will return an error if `data` doesn't parse as an autoload list in any known layout.
    pub fn parse_list(data: &'_ [u8], blocks_size: u32) -> Result<Vec<Self>, RawAutoloadInfoError> {
        let candidates = AutoloadInfoLayout::ALL
            .into_iter()
            .filter(|layout| data.len().is_multiple_of(layout.entry_size()))
            .map(|layout| (layout, Self::parse_list_with_layout(data, layout)))
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            return InvalidSizeSnafu { size: data.len() }.fail();
        }

        // The code sizes adding up to the size of the autoload blocks is a strong signal that the layout is correct.
        if let Some((_, entries)) = candidates
            .iter()
            .find(|(_, entries)| entries.iter().map(|entry| entry.code_size as u64).sum::<u64>() == blocks_size as u64)
        {
            return Ok(entries.clone());
        }

        TotalSizeMismatchSnafu {
            total: candidates
                .iter()
                .map(|(_, entries)| entries.iter().map(|entry| entry.code_size as u64).sum::<u64>())
                .collect::<Vec<_>>(),
            expected: blocks_size,
        }
        .fail()
    }

    fn parse_list_with_layout(data: &'_ [u8], layout: AutoloadInfoLayout) -> Vec<Self> {
        data.chunks_exact(layout.entry_size()).map(|chunk| Self::parse_entry(chunk, layout)).collect()
    }

    fn parse_entry(data: &'_ [u8], layout: AutoloadInfoLayout) -> Self {
        let word = |index: usize| u32::from_le_bytes(data[index * 4..index * 4 + 4].try_into().unwrap());
        match layout {
            AutoloadInfoLayout::Basic => {
                Self { base_address: word(0), code_size: word(1), bss_size: word(2), ctor_start: None }
            }
            AutoloadInfoLayout::Extended => {
                Self { base_address: word(0), code_size: word(1), bss_size: word(3), ctor_start: Some(word(2)) }
            }
        }
    }

    /// Returns the layout this entry is written back in.
    pub fn layout(&self) -> AutoloadInfoLayout {
        if self.ctor_start.is_some() {
            AutoloadInfoLayout::Extended
        } else {
            AutoloadInfoLayout::Basic
        }
    }

    /// Serializes this entry to the layout returned by [`Self::layout`].
    pub fn to_bytes(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.layout().entry_size());
        bytes.extend(self.base_address.to_le_bytes());
        bytes.extend(self.code_size.to_le_bytes());
        if let Some(ctor_start) = self.ctor_start {
            bytes.extend(ctor_start.to_le_bytes());
        }
        bytes.extend(self.bss_size.to_le_bytes());
        bytes
    }
}

impl AutoloadInfo {
    /// Creates a new [`AutoloadInfo`] from an [`AutoloadInfoEntry`].
    pub fn new(list_entry: AutoloadInfoEntry, index: u32) -> Self {
        let kind = match list_entry.base_address {
            0x1ff8000 => AutoloadKind::Itcm,
            0x27e0000 | 0x27c0000 | 0x23c0000 | 0x2fe0000 => AutoloadKind::Dtcm,
            _ => AutoloadKind::Unknown(index),
        };

        Self { list_entry, kind }
    }

    /// Returns the index of this [`AutoloadInfo`].
    pub fn base_address(&self) -> u32 {
        self.list_entry.base_address
    }

    /// Returns the code size of this [`AutoloadInfo`].
    pub fn code_size(&self) -> u32 {
        self.list_entry.code_size
    }

    /// Returns the size of the uninitialized data of this [`AutoloadInfo`].
    pub fn bss_size(&self) -> u32 {
        self.list_entry.bss_size
    }

    /// Returns the address of the static initializer list of this [`AutoloadInfo`], if it has one. See
    /// [`AutoloadInfoEntry::ctor_start`].
    pub fn ctor_start(&self) -> Option<u32> {
        self.list_entry.ctor_start
    }

    /// Returns the kind of this [`AutoloadInfo`].
    pub fn kind(&self) -> AutoloadKind {
        self.kind
    }

    /// Returns the entry of this [`AutoloadInfo`].
    pub fn entry(&self) -> &AutoloadInfoEntry {
        &self.list_entry
    }

    /// Creates a [`DisplayAutoloadInfo`] which implements [`Display`].
    pub fn display(&self, indent: usize) -> DisplayAutoloadInfo<'_> {
        DisplayAutoloadInfo { info: self, indent }
    }
}

/// Can be used to display values inside [`AutoloadInfo`].
pub struct DisplayAutoloadInfo<'a> {
    info: &'a AutoloadInfo,
    indent: usize,
}

impl Display for DisplayAutoloadInfo<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let i = " ".repeat(self.indent);
        let info = &self.info;
        writeln!(f, "{i}Type .......... : {}", info.kind)?;
        writeln!(f, "{i}Base address .. : {:#x}", info.list_entry.base_address)?;
        writeln!(f, "{i}Code size ..... : {:#x}", info.list_entry.code_size)?;
        writeln!(f, "{i}.bss size ..... : {:#x}", info.list_entry.bss_size)?;
        if let Some(ctor_start) = info.list_entry.ctor_start {
            writeln!(f, "{i}.ctor start ... : {ctor_start:#x}")?;
        }
        Ok(())
    }
}

impl Display for AutoloadKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AutoloadKind::Itcm => write!(f, "ITCM"),
            AutoloadKind::Dtcm => write!(f, "DTCM"),
            AutoloadKind::Unknown(index) => write!(f, "Unknown({index})"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXTENDED: [u8; 64] = [
        0x00, 0x80, 0xff, 0x01, 0xa0, 0x13, 0x00, 0x00, 0x00, 0x80, 0xff, 0x01, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0xfe, 0x02, 0xa0, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x02, 0x20, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x40, 0x02, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x02, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x80, 0x89, 0x06, 0x20, 0x00, 0x00, 0x00, 0x00, 0x80, 0x89, 0x06, 0x00, 0x00, 0x00, 0x00,
    ];

    const BASIC: [u8; 24] = [
        0x00, 0x80, 0xff, 0x01, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x7e, 0x02, 0x00, 0x10, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00,
    ];

    #[test]
    fn parses_extended_layout() {
        let entries = AutoloadInfoEntry::parse_list(&EXTENDED, 0x1480).unwrap();
        assert_eq!(entries.len(), 4);
        assert_eq!(entries[0], AutoloadInfoEntry {
            base_address: 0x01ff8000,
            code_size: 0x13a0,
            bss_size: 0,
            ctor_start: Some(0x01ff8000),
        });
        assert_eq!(entries[1].base_address, 0x02fe0000);
        assert_eq!(entries[1].bss_size, 0x20);
        assert_eq!(entries[3].base_address, 0x06898000);
        assert_eq!(entries.iter().map(|entry| entry.code_size).sum::<u32>(), 0x1480);
    }

    #[test]
    fn parses_basic_layout() {
        let entries = AutoloadInfoEntry::parse_list(&BASIC, 0x3000).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0], AutoloadInfoEntry {
            base_address: 0x01ff8000,
            code_size: 0x2000,
            bss_size: 0,
            ctor_start: None
        });
        assert_eq!(entries[1], AutoloadInfoEntry {
            base_address: 0x027e0000,
            code_size: 0x1000,
            bss_size: 0x400,
            ctor_start: None
        });
    }

    #[test]
    fn tells_ambiguous_sizes_apart() {
        let data = &EXTENDED[..48];
        let entries = AutoloadInfoEntry::parse_list(data, 0x1460).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[2].base_address, 0x02400000);
        assert!(entries.iter().all(|entry| entry.ctor_start.is_some()));
    }

    #[test]
    fn round_trips_both_layouts() {
        for (data, blocks_size) in [(&EXTENDED[..], 0x1480), (&BASIC[..], 0x3000)] {
            let entries = AutoloadInfoEntry::parse_list(data, blocks_size).unwrap();
            let bytes = entries.iter().flat_map(|entry| entry.to_bytes()).collect::<Vec<_>>();
            assert_eq!(bytes, data);
        }
    }

    #[test]
    fn rejects_sizes_that_are_no_layout() {
        let error = AutoloadInfoEntry::parse_list(&EXTENDED[..20], 0x1480).unwrap_err();
        assert!(matches!(error, RawAutoloadInfoError::InvalidSize { .. }));
    }
}
