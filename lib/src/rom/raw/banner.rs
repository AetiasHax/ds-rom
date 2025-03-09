use std::{borrow::Cow, fmt::Display, ops::Range};

use bitfield_struct::bitfield;
use bytemuck::{Pod, PodCastError, Zeroable};
use serde::{Deserialize, Serialize};
use snafu::{Backtrace, Snafu};

use super::RawHeaderError;
use crate::str::Unicode16Array;

/// Banner for displaying an icon and title on the home menu. This is the raw struct, see the plain one [here](super::super::Banner).
pub struct Banner<'a> {
    version: BannerVersion,
    data: Cow<'a, [u8]>,
}

/// Errors related to [`Banner`].
#[derive(Debug, Snafu)]
pub enum RawBannerError {
    /// See [`RawHeaderError`].
    #[snafu(transparent)]
    RawHeader {
        /// Source error.
        source: RawHeaderError,
    },
    /// Occurs when the input banner has an unknown version. Should not occur unless there's an undocumented banner version
    /// we're unaware of.
    #[snafu(display("unknown banner version {version}:\n{backtrace}"))]
    UnknownVersion {
        /// Input banner version.
        version: u16,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// Occurs when the input is not the right size according to its version number.
    #[snafu(display("banner version {version:x} must be {expected} bytes but got {actual} bytes"))]
    InvalidSize {
        /// Version number.
        version: u16,
        /// Expected size for this version.
        expected: usize,
        /// Actual input size.
        actual: usize,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// Occurs when the input is less aligned than the banner
    #[snafu(display("expected {expected}-alignment but got {actual}-alignment:\n{backtrace}"))]
    Misaligned {
        /// Expected alignment.
        expected: usize,
        /// Actual alignment.
        actual: usize,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
}

impl<'a> Banner<'a> {
    /// Creates a new [`Banner`].
    pub fn new(version: BannerVersion) -> Self {
        let size = version.banner_size();
        let mut data = vec![0u8; size];
        data[0..2].copy_from_slice(&(version as u16).to_le_bytes());
        Self { version, data: data.into() }
    }

    fn handle_pod_cast<T>(result: Result<T, PodCastError>) -> T {
        match result {
            Ok(build_info) => build_info,
            Err(PodCastError::TargetAlignmentGreaterAndInputNotAligned) => unreachable!(),
            Err(PodCastError::AlignmentMismatch) => panic!(),
            Err(PodCastError::OutputSliceWouldHaveSlop) => panic!(),
            Err(PodCastError::SizeMismatch) => unreachable!(),
        }
    }

    /// Reinterprets a `&[u8]` as a reference to [`Banner`].
    ///
    /// # Errors
    ///
    /// This function will return an error if the input has an unknown banner version, or has the wrong size for its version,
    /// or is not aligned enough.
    pub fn borrow_from_slice(data: &'a [u8]) -> Result<Self, RawBannerError> {
        let addr = data as *const [u8] as *const () as usize;
        if addr % 2 != 0 {
            return MisalignedSnafu { expected: 2usize, actual: 1usize << addr.trailing_zeros() as usize }.fail();
        }

        let version_value = u16::from_le_bytes([data[0], data[1]]);
        let Some(version) = BannerVersion::from_u16(version_value) else {
            return UnknownVersionSnafu { version: version_value }.fail();
        };
        let size = version.banner_size();
        if data.len() < size {
            return InvalidSizeSnafu { version: version_value, expected: size, actual: data.len() }.fail();
        }
        let data = &data[..size];

        let mut bitmap = [0u8; 0x200];
        bitmap.copy_from_slice(&data[0x20..0x220]);

        let mut palette = [0u16; 16];
        for i in 0..16 {
            palette[i] = u16::from_le_bytes([data[0x220 + i * 2], data[0x221 + i * 2]]);
        }

        Ok(Self { version, data: Cow::Borrowed(data) })
    }

    /// Returns the version of this [`Banner`].
    pub fn version(&self) -> BannerVersion {
        self.version
    }

    /// Returns the CRC checksum at the given index.
    pub fn crc(&self, index: usize) -> u16 {
        u16::from_le_bytes([self.data[2 + index * 2], self.data[3 + index * 2]])
    }

    /// Returns a mutable CRC checksum at the given index.
    pub fn crc_mut(&mut self, index: usize) -> &mut u16 {
        let start = 2 + index * 2;
        let end = start + 2;
        let data = &mut self.data.to_mut()[start..end];
        Self::handle_pod_cast(bytemuck::try_from_bytes_mut(data))
    }

    /// Returns a reference to the bitmap of this [`Banner`].
    pub fn bitmap(&self) -> &BannerBitmap {
        let data = &self.data[0x20..0x220];
        Self::handle_pod_cast(bytemuck::try_from_bytes(data))
    }

    /// Returns a mutable reference to the bitmap of this [`Banner`].
    pub fn bitmap_mut(&mut self) -> &mut BannerBitmap {
        let data = &mut self.data.to_mut()[0x20..0x220];
        Self::handle_pod_cast(bytemuck::try_from_bytes_mut(data))
    }

    /// Returns a reference to the palette of this [`Banner`].
    pub fn palette(&self) -> &BannerPalette {
        let data = &self.data[0x220..0x240];
        Self::handle_pod_cast(bytemuck::try_from_bytes(data))
    }

    /// Returns a mutable reference to the palette of this [`Banner`].
    pub fn palette_mut(&mut self) -> &mut BannerPalette {
        let data = &mut self.data.to_mut()[0x220..0x240];
        Self::handle_pod_cast(bytemuck::try_from_bytes_mut(data))
    }

    /// Returns a title for the given language, or `None` the language is not supported by this banner version.
    pub fn title(&self, language: Language) -> Option<&Unicode16Array<0x80>> {
        if !self.version.supports_language(language) {
            None
        } else {
            let start = 0x240 + language as usize * 0x100;
            let end = start + 0x100;
            let data = &self.data[start..end];
            Some(Self::handle_pod_cast(bytemuck::try_from_bytes(data)))
        }
    }

    /// Returns a mutable title for the given language, or `None` the language is not supported by this banner version.
    pub fn title_mut(&mut self, language: Language) -> Option<&mut Unicode16Array<0x80>> {
        if !self.version.supports_language(language) {
            None
        } else {
            let start = 0x240 + language as usize * 0x100;
            let end = start + 0x100;
            let data = &mut self.data.to_mut()[start..end];
            Some(Self::handle_pod_cast(bytemuck::try_from_bytes_mut(data)))
        }
    }

    /// Returns a reference to the animation of this [`Banner`], if it exists in this banner version.
    pub fn animation(&self) -> Option<&BannerAnimation> {
        if !self.version.has_animation() {
            None
        } else {
            let data = &self.data[0x1240..0x23c0];
            Some(Self::handle_pod_cast(bytemuck::try_from_bytes(data)))
        }
    }

    /// Returns a mutable reference to the animation of this [`Banner`], if it exists in this banner version.
    pub fn animation_mut(&mut self) -> Option<&mut BannerAnimation> {
        if !self.version.has_animation() {
            None
        } else {
            let data = &mut self.data.to_mut()[0x1240..0x23c0];
            Some(Self::handle_pod_cast(bytemuck::try_from_bytes_mut(data)))
        }
    }

    /// Returns a reference to the full data of this [`Banner`].
    pub fn full_data(&self) -> &[u8] {
        &self.data
    }

    /// Creates a [`DisplayBanner`] which implements [`Display`].
    pub fn display(&self, indent: usize) -> DisplayBanner {
        DisplayBanner { banner: self, indent }
    }
}

/// Can be used to display values inside [`Banner`].
pub struct DisplayBanner<'a> {
    banner: &'a Banner<'a>,
    indent: usize,
}

macro_rules! write_title {
    ($f:ident, $fmt:literal, $banner:ident, $language:expr) => {
        if let Some(title) = $banner.title($language) {
            writeln!($f, $fmt, '\n', title, '\n')
        } else {
            Ok(())
        }
    };
}

impl Display for DisplayBanner<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let i = format!("{:indent$}", "", indent = self.indent);
        let banner = &self.banner;
        writeln!(f, "{i}Version ......... : {}", banner.version)?;
        writeln!(f, "{i}Original CRC .... : {:#x}", banner.crc(BannerVersion::Original.crc_index()))?;
        write_title!(f, "{i}Japanese Title .. : {}{}{}", banner, Language::Japanese)?;
        write_title!(f, "{i}English Title ... : {}{}{}", banner, Language::English)?;
        write_title!(f, "{i}French Title .... : {}{}{}", banner, Language::French)?;
        write_title!(f, "{i}German Title .... : {}{}{}", banner, Language::German)?;
        write_title!(f, "{i}Italian Title ... : {}{}{}", banner, Language::Italian)?;
        write_title!(f, "{i}Spanish Title ... : {}{}{}", banner, Language::Spanish)?;
        if banner.version >= BannerVersion::China {
            writeln!(f, "{i}China CRC ....... : {:#x}", banner.crc(BannerVersion::China.crc_index()))?;
            write_title!(f, "{i}Chinese Title ... : {}{}{}", banner, Language::Chinese)?;
        }
        if banner.version >= BannerVersion::Korea {
            writeln!(f, "{i}Korea CRC ....... : {:#x}", banner.crc(BannerVersion::Korea.crc_index()))?;
            write_title!(f, "{i}Korean Title .... : {}{}{}", banner, Language::Korean)?;
        }
        if banner.version >= BannerVersion::Animated {
            writeln!(f, "{i}Animation CRC ... : {:#x}", banner.crc(BannerVersion::Animated.crc_index()))?;
        }
        writeln!(f, "{i}Bitmap .......... :\n{}", banner.bitmap().display(banner.palette()))?;
        Ok(())
    }
}

/// Known banner versions.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize, Deserialize, Default)]
pub enum BannerVersion {
    /// Original version with titles in Japanese, English, French, German, Italian and Spanish.
    #[default]
    Original = 1,
    /// Inherits from [`BannerVersion::Original`] and adds Chinese.
    China = 2,
    /// Inherits from [`BannerVersion::China`] and adds Korean.
    Korea = 3,
    /// Inherits from [`BannerVersion::Korea`] and adds an animated icon.
    Animated = 0x103,
}

impl BannerVersion {
    fn from_u16(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::Original),
            2 => Some(Self::China),
            3 => Some(Self::Korea),
            0x103 => Some(Self::Animated),
            _ => None,
        }
    }

    /// Returns whether this version has a Chinese title.
    pub fn has_chinese(self) -> bool {
        self >= Self::China
    }

    /// Returns whether this version has a Korean title.
    pub fn has_korean(self) -> bool {
        self >= Self::Korea
    }

    /// Returns whether this version has an animated icon.
    pub fn has_animation(self) -> bool {
        self >= Self::Animated
    }

    /// Returns whether this version supports the given language.
    pub fn supports_language(self, language: Language) -> bool {
        match language {
            Language::Japanese => true,
            Language::English => true,
            Language::French => true,
            Language::German => true,
            Language::Italian => true,
            Language::Spanish => true,
            Language::Chinese => self.has_chinese(),
            Language::Korean => self.has_korean(),
        }
    }

    /// Returns the CRC index of this version.
    pub fn crc_index(self) -> usize {
        match self {
            BannerVersion::Original => 0,
            BannerVersion::China => 1,
            BannerVersion::Korea => 2,
            BannerVersion::Animated => 3,
        }
    }

    /// Returns the CRC checksum range of this version.
    pub fn crc_range(self) -> Range<usize> {
        match self {
            BannerVersion::Original => 0x20..0x840,
            BannerVersion::China => 0x20..0x940,
            BannerVersion::Korea => 0x20..0xa40,
            BannerVersion::Animated => 0x1240..0x23c0,
        }
    }

    /// Returns the banner size of this version.
    pub fn banner_size(self) -> usize {
        match self {
            BannerVersion::Original => 0x840,
            BannerVersion::China => 0x940,
            BannerVersion::Korea => 0x1240,
            BannerVersion::Animated => 0x23c0,
        }
    }
}

impl Display for BannerVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BannerVersion::Original => write!(f, "Original"),
            BannerVersion::China => write!(f, "China"),
            BannerVersion::Korea => write!(f, "Korea"),
            BannerVersion::Animated => write!(f, "DSi Animated"),
        }
    }
}

/// Languages present in the banner.
#[derive(Clone, Copy, Debug)]
pub enum Language {
    /// Japanese.
    Japanese = 0,
    /// English.
    English = 1,
    /// French.
    French = 2,
    /// German.
    German = 3,
    /// Italian.
    Italian = 4,
    /// Spanish.
    Spanish = 5,
    /// Chinese.
    Chinese = 6,
    /// Korean.
    Korean = 7,
}

impl Display for Language {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Language::Japanese => write!(f, "Japanese"),
            Language::English => write!(f, "English"),
            Language::French => write!(f, "French"),
            Language::German => write!(f, "German"),
            Language::Italian => write!(f, "Italian"),
            Language::Spanish => write!(f, "Spanish"),
            Language::Chinese => write!(f, "Chinese"),
            Language::Korean => write!(f, "Korean"),
        }
    }
}

/// Contains a palette for a banner bitmap, where each color is 15-bit BGR.
#[repr(C)]
#[derive(Clone, Copy, Zeroable, Pod, Default)]
pub struct BannerPalette(pub [u16; 16]);

impl BannerPalette {
    /// Returns the color from 24-bit `(r, g, b)` at the given index.
    pub fn get_color(&self, index: usize) -> (u8, u8, u8) {
        if index < self.0.len() {
            let color = self.0[index];
            let b = (((color >> 10) & 31) << 3) as u8;
            let g = (((color >> 5) & 31) << 3) as u8;
            let r = ((color & 31) << 3) as u8;
            (r, g, b)
        } else {
            (0, 0, 0)
        }
    }

    /// Sets the color from 24-bit `(r, g, b)` at the given index.
    pub fn set_color(&mut self, index: usize, r: u8, g: u8, b: u8) {
        let r = r as u16 >> 3;
        let g = g as u16 >> 3;
        let b = b as u16 >> 3;
        let color = r | (g << 5) | (b << 10);
        self.0[index] = color;
    }
}

impl Display for BannerPalette {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for i in 0..16 {
            let (r, g, b) = self.get_color(i);
            write!(f, "\x1b[38;2;{r};{g};{b}m█")?;
        }
        write!(f, "\x1b[0m")
    }
}

/// A bitmap in the banner.
#[repr(C)]
#[derive(Clone, Copy, Zeroable, Pod)]
pub struct BannerBitmap(pub [u8; 0x200]);

impl BannerBitmap {
    /// Creates a [`DisplayBannerBitmap`] which implements [`Display`].
    pub fn display<'a>(&'a self, palette: &'a BannerPalette) -> DisplayBannerBitmap<'a> {
        DisplayBannerBitmap { bitmap: self, palette }
    }

    fn get_index(x: usize, y: usize) -> (usize, usize) {
        // 8x8 pixel tiles in a 4x4 grid
        let index = (y / 8 * 0x80) + (x / 8 * 0x20) + (y % 8 * 4) + (x / 2 % 4);
        // 4 bits per pixel
        let offset = (x % 2) * 4;
        (index, offset)
    }

    /// Gets a palette index at the given coordinates.
    pub fn get_pixel(&self, x: usize, y: usize) -> usize {
        let (index, offset) = Self::get_index(x, y);
        if index < self.0.len() {
            (self.0[index] as usize >> offset) & 0xf
        } else {
            0
        }
    }

    /// Sets a palette index at the given coordinates.
    pub fn set_pixel(&mut self, x: usize, y: usize, value: u8) {
        let (index, offset) = Self::get_index(x, y);
        if index < self.0.len() {
            self.0[index] = (self.0[index] & !(0xf << offset)) | (value << offset);
        }
    }
}

impl Default for BannerBitmap {
    fn default() -> Self {
        Self([0; 0x200])
    }
}

/// Can be used to display a [`BannerBitmap`].
pub struct DisplayBannerBitmap<'a> {
    bitmap: &'a BannerBitmap,
    palette: &'a BannerPalette,
}

impl Display for DisplayBannerBitmap<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for y in (0..32).step_by(2) {
            for x in 0..32 {
                let (tr, tg, tb) = self.palette.get_color(self.bitmap.get_pixel(x, y));
                let (br, bg, bb) = self.palette.get_color(self.bitmap.get_pixel(x, y + 1));

                write!(f, "\x1b[38;2;{tr};{tg};{tb}m\x1b[48;2;{br};{bg};{bb}m▀")?;
            }
            writeln!(f, "\x1b[0m")?;
        }
        Ok(())
    }
}

/// An animated banner icon.
#[repr(C)]
#[derive(Clone, Copy, Zeroable, Pod)]
pub struct BannerAnimation {
    /// Up to 8 bitmaps.
    pub bitmaps: [BannerBitmap; 8],
    /// Up to 8 palettes.
    pub palettes: [BannerPalette; 8],
    /// Up to 64 keyframes.
    pub keyframes: [BannerKeyframe; 64],
}

/// A keyframe for [`BannerAnimation`].
#[bitfield(u16)]
pub struct BannerKeyframe {
    /// How long to show this keyframe for, in frames.
    pub frame_duration: u8,
    /// Which of the 8 bitmaps to show.
    #[bits(3)]
    pub bitmap_index: u8,
    /// Which of the 8 palettes to use.
    #[bits(3)]
    pub palette_index: u8,
    /// Flips the bitmap horizontally.
    pub flip_horizontally: bool,
    /// Flips the bitmap vertically.
    pub flip_vertically: bool,
}

unsafe impl Zeroable for BannerKeyframe {}
unsafe impl Pod for BannerKeyframe {}
