use std::{borrow::Cow, fmt::Display, mem::align_of};

use bytemuck::{Pod, PodCastError, Zeroable};
use snafu::{Backtrace, Snafu};

use crate::str::Unicode16Array;

use super::RawHeaderError;

pub struct Banner<'a> {
    version: BannerVersion,
    data: Cow<'a, [u8]>,
}

#[derive(Debug, Snafu)]
pub enum RawBannerError {
    #[snafu(transparent)]
    RawHeader { source: RawHeaderError },
    #[snafu(display("unknown banner version {version}:\n{backtrace}"))]
    UnknownVersion { version: u16, backtrace: Backtrace },
    #[snafu(display("banner version {version:x} must be {expected} bytes but got {actual} bytes"))]
    InvalidSize { version: u16, expected: usize, actual: usize, backtrace: Backtrace },
    #[snafu(display("expected {expected}-alignment for {section} but got {actual}-alignment:\n{backtrace}"))]
    Misaligned { expected: usize, actual: usize, section: &'static str, backtrace: Backtrace },
    #[snafu(display("not supported in banner version {actual:x}, must be version {expected:x} or higher:\n{backtrace}"))]
    NotSupported { expected: u16, actual: u16, backtrace: Backtrace },
}

impl<'a> Banner<'a> {
    pub fn new(version: BannerVersion) -> Self {
        let size = version.banner_size();
        let mut data = vec![0u8; size];
        data[0..2].copy_from_slice(&(version as u16).to_le_bytes());
        Self { version, data: data.into() }
    }

    fn handle_pod_cast<T>(result: Result<T, PodCastError>, addr: usize, section: &'static str) -> Result<T, RawBannerError> {
        match result {
            Ok(build_info) => Ok(build_info),
            Err(PodCastError::TargetAlignmentGreaterAndInputNotAligned) => {
                MisalignedSnafu { expected: align_of::<T>(), actual: 1usize << addr.leading_zeros(), section }.fail()
            }
            Err(PodCastError::AlignmentMismatch) => panic!(),
            Err(PodCastError::OutputSliceWouldHaveSlop) => panic!(),
            Err(PodCastError::SizeMismatch) => unreachable!(),
        }
    }

    pub fn borrow_from_slice(data: &'a [u8]) -> Result<Self, RawBannerError> {
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

    pub fn version(&self) -> BannerVersion {
        self.version
    }

    pub fn crc(&self, index: usize) -> u16 {
        u16::from_le_bytes([self.data[2 + index * 2], self.data[3 + index * 2]])
    }

    pub fn crc_mut(&mut self, index: usize) -> Result<&mut u16, RawBannerError> {
        let start = 2 + index * 2;
        let end = start + 2;
        let data = &mut self.data.to_mut()[start..end];
        let addr = data as *const [u8] as *const () as usize;
        Self::handle_pod_cast(bytemuck::try_from_bytes_mut(data), addr, "banner CRC")
    }

    pub fn bitmap(&self) -> Result<&BannerBitmap, RawBannerError> {
        let data = &self.data[0x20..0x220];
        let addr = data as *const [u8] as *const () as usize;
        Self::handle_pod_cast(bytemuck::try_from_bytes(data), addr, "banner bitmap")
    }

    pub fn bitmap_mut(&mut self) -> Result<&mut BannerBitmap, RawBannerError> {
        let data = &mut self.data.to_mut()[0x20..0x220];
        let addr = data as *const [u8] as *const () as usize;
        Self::handle_pod_cast(bytemuck::try_from_bytes_mut(data), addr, "banner bitmap")
    }

    pub fn palette(&self) -> Result<&BannerPalette, RawBannerError> {
        let data = &self.data[0x220..0x240];
        let addr = data as *const [u8] as *const () as usize;
        Self::handle_pod_cast(bytemuck::try_from_bytes(data), addr, "banner palette")
    }

    pub fn palette_mut(&mut self) -> Result<&mut BannerPalette, RawBannerError> {
        let data = &mut self.data.to_mut()[0x220..0x240];
        let addr = data as *const [u8] as *const () as usize;
        Self::handle_pod_cast(bytemuck::try_from_bytes_mut(data), addr, "banner palette")
    }

    pub fn title(&self, language: Language) -> Option<Result<&Unicode16Array<0x80>, RawBannerError>> {
        if !self.version.supports_language(language) {
            None
        } else {
            let start = 0x240 + language as usize * 0x100;
            let end = start + 0x100;
            let data = &self.data[start..end];
            let addr = data as *const [u8] as *const () as usize;
            Some(Self::handle_pod_cast(bytemuck::try_from_bytes(data), addr, "banner title"))
        }
    }

    pub fn title_mut(&mut self, language: Language) -> Option<Result<&mut Unicode16Array<0x80>, RawBannerError>> {
        if !self.version.supports_language(language) {
            None
        } else {
            let start = 0x240 + language as usize * 0x100;
            let end = start + 0x100;
            let data = &mut self.data.to_mut()[start..end];
            let addr = data as *const [u8] as *const () as usize;
            Some(Self::handle_pod_cast(bytemuck::try_from_bytes_mut(data), addr, "banner title"))
        }
    }

    pub fn animation(&self) -> Result<&BannerAnimation, RawBannerError> {
        if !self.version.has_animation() {
            NotSupportedSnafu { expected: BannerVersion::Animated as u16, actual: self.version as u16 }.fail()
        } else {
            let data = &self.data[0x1240..0x23c0];
            let addr = data as *const [u8] as *const () as usize;
            Self::handle_pod_cast(bytemuck::try_from_bytes(data), addr, "banner animation")
        }
    }

    pub fn animation_mut(&mut self) -> Result<&mut BannerAnimation, RawBannerError> {
        if !self.version.has_animation() {
            NotSupportedSnafu { expected: BannerVersion::Animated as u16, actual: self.version as u16 }.fail()
        } else {
            let data = &mut self.data.to_mut()[0x1240..0x23c0];
            let addr = data as *const [u8] as *const () as usize;
            Self::handle_pod_cast(bytemuck::try_from_bytes_mut(data), addr, "banner animation")
        }
    }

    pub fn full_data(&self) -> &[u8] {
        &self.data
    }

    pub fn display(&self, indent: usize) -> DisplayBanner {
        DisplayBanner { banner: self, indent }
    }
}

pub struct DisplayBanner<'a> {
    banner: &'a Banner<'a>,
    indent: usize,
}

macro_rules! write_title {
    ($f:ident, $fmt:literal, $banner:ident, $language:expr) => {
        if let Some(title) = $banner.title($language) {
            if let Ok(title) = title {
                writeln!($f, $fmt, '\n', title, '\n')
            } else {
                writeln!($f, $fmt, "", "Failed to load", "")
            }
        } else {
            Ok(())
        }
    };
}

impl<'a> Display for DisplayBanner<'a> {
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
        if let Ok(palette) = banner.palette() {
            if let Ok(bitmap) = banner.bitmap() {
                writeln!(f, "{i}Bitmap .......... :\n{}", bitmap.display(palette))?;
            } else {
                writeln!(f, "{i}Bitmap .......... :\nFailed to load bitmap")?;
            }
            writeln!(f, "{i}Palette ......... : {}", palette)?;
        } else {
            writeln!(f, "{i}Bitmap .......... :\nFailed to load palette")?;
            writeln!(f, "{i}Palette ......... :\nFailed to load palette")?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BannerVersion {
    Original = 1,
    China = 2,
    Korea = 3,
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

    pub fn has_chinese(self) -> bool {
        self >= Self::China
    }

    pub fn has_korean(self) -> bool {
        self >= Self::Korea
    }

    pub fn has_animation(self) -> bool {
        self >= Self::Animated
    }

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

    pub fn crc_index(self) -> usize {
        match self {
            BannerVersion::Original => 0,
            BannerVersion::China => 1,
            BannerVersion::Korea => 2,
            BannerVersion::Animated => 3,
        }
    }

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

#[derive(Clone, Copy)]
pub enum Language {
    Japanese = 0,
    English = 1,
    French = 2,
    German = 3,
    Italian = 4,
    Spanish = 5,
    Chinese = 6,
    Korean = 7,
}

#[repr(C)]
#[derive(Clone, Copy, Zeroable, Pod)]
pub struct BannerPalette([u16; 16]);

impl BannerPalette {
    pub fn get_color(&self, index: usize) -> (u8, u8, u8) {
        if index < self.0.len() {
            let color = self.0[index];
            let b = (((color >> 10) & 31) * 255 / 31) as u8;
            let g = (((color >> 5) & 31) * 255 / 31) as u8;
            let r = ((color & 31) * 255 / 31) as u8;
            (r, g, b)
        } else {
            (0, 0, 0)
        }
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

#[repr(C)]
#[derive(Clone, Copy, Zeroable, Pod)]
pub struct BannerBitmap([u8; 0x200]);

impl BannerBitmap {
    pub fn display<'a>(&'a self, palette: &'a BannerPalette) -> DisplayBannerBitmap<'a> {
        DisplayBannerBitmap { bitmap: self, palette }
    }

    pub fn get_pixel(&self, x: usize, y: usize) -> usize {
        // 8x8 pixel tiles in a 4x4 grid
        let index = (y / 8 * 0x80) + (x / 8 * 0x20) + (y % 8 * 4) + (x / 2 % 4);
        // 4 bits per pixel
        let offset = (x % 2) * 4;
        if index < self.0.len() {
            (self.0[index] as usize >> offset) & 0xf
        } else {
            0
        }
    }
}

pub struct DisplayBannerBitmap<'a> {
    bitmap: &'a BannerBitmap,
    palette: &'a BannerPalette,
}

impl<'a> Display for DisplayBannerBitmap<'a> {
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

#[repr(C)]
#[derive(Clone, Copy, Zeroable, Pod)]
pub struct BannerAnimation {
    pub bitmaps: [BannerBitmap; 8],
    pub palettes: [BannerPalette; 8],
    pub keyframes: [BannerKeyframe; 64],
}

#[repr(C)]
#[derive(Clone, Copy, Zeroable, Pod)]
pub struct BannerKeyframe(u16);

impl BannerKeyframe {
    pub fn flip_vertically(self) -> bool {
        self.0 & 0x8000 != 0
    }

    pub fn flip_horizontally(self) -> bool {
        self.0 & 0x4000 != 0
    }

    pub fn palette_index(self) -> usize {
        (self.0 as usize >> 11) & 7
    }

    pub fn bitmap_index(self) -> usize {
        (self.0 as usize >> 8) & 7
    }

    pub fn frame_duration(self) -> usize {
        self.0 as usize & 0xff
    }
}
