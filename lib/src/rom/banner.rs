use std::{io, path::PathBuf};

use image::{io::Reader, GenericImageView, ImageError};
use snafu::{Backtrace, Snafu};

use crate::{str::Unicode16Array, CRC_16_MODBUS};

use super::{
    raw::{self, BannerBitmap, BannerPalette, BannerVersion, Language, RawBannerError},
    ImageSize,
};

pub struct Banner {
    version: BannerVersion,
    title: BannerTitle,
    files: BannerFiles,
    keyframes: Option<Box<[BannerKeyframe]>>,
}

#[derive(Debug, Snafu)]
pub enum BannerLoadError {
    #[snafu(transparent)]
    RawBanner { source: RawBannerError },
}

#[derive(Debug, Snafu)]
pub enum BannerError {
    #[snafu(transparent)]
    RawBanner { source: RawBannerError },
    #[snafu(transparent)]
    BannerFile { source: BannerFileError },
    #[snafu(display("maximum keyframe count is {max} but got {actual}:\n{backtrace}"))]
    TooManyKeyframes { max: usize, actual: usize, backtrace: Backtrace },
    #[snafu(display("maximum supported banner version is currently {max} but got {actual}:\n{backtrace}"))]
    VersionNotSupported { max: BannerVersion, actual: BannerVersion, backtrace: Backtrace },
}

impl Banner {
    fn load_title(
        banner: &raw::Banner,
        version: BannerVersion,
        language: Language,
    ) -> Result<Option<String>, BannerLoadError> {
        if version.supports_language(language) {
            if let Some(title) = banner.title(language) {
                Ok(Some(title?.to_string()))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    pub fn load_raw(banner: &raw::Banner) -> Result<Self, BannerLoadError> {
        let version = banner.version();
        Ok(Self {
            version,
            title: BannerTitle {
                japanese: Self::load_title(banner, version, Language::Japanese)?.unwrap(),
                english: Self::load_title(banner, version, Language::English)?.unwrap(),
                french: Self::load_title(banner, version, Language::French)?.unwrap(),
                german: Self::load_title(banner, version, Language::German)?.unwrap(),
                italian: Self::load_title(banner, version, Language::Italian)?.unwrap(),
                spanish: Self::load_title(banner, version, Language::Spanish)?.unwrap(),
                chinese: Self::load_title(banner, version, Language::Chinese)?,
                korean: Self::load_title(banner, version, Language::Korean)?,
            },
            files: BannerFiles {
                bitmap_path: PathBuf::from("banner/bitmap.png"),
                palette_path: PathBuf::from("banner/palette.png"),
                animation_bitmap_paths: None,
                animation_palette_paths: None,
            },
            keyframes: None,
        })
    }

    fn crc(&self, banner: &mut raw::Banner, version: BannerVersion) -> Result<(), BannerError> {
        if self.version < version {
            return Ok(());
        }
        *banner.crc_mut(version.crc_index())? = CRC_16_MODBUS.checksum(&banner.full_data()[version.crc_range()]);
        Ok(())
    }

    pub fn build(&self) -> Result<raw::Banner, BannerError> {
        // TODO: Increase max version to Animated
        // The challenge is to convert the animated icon to indexed bitmaps. Each bitmap can use any of the 8 palettes at any
        // given time according to the keyframes. This means that to convert the PNG animation frames to indexed bitmaps, we
        // may need more than 8 PNG files if a palette is reused on multiple bitmaps. Then we have to deduplicate indexed
        // bitmaps with precisely the same indexes. Not very efficient, but it may be our only option for modern image formats.
        if self.version > BannerVersion::Korea {
            return VersionNotSupportedSnafu { max: BannerVersion::Korea, actual: self.version }.fail();
        }

        let mut banner = raw::Banner::new(self.version);
        self.title.copy_to_banner(&mut banner)?;

        let (bitmap, palette) = self.files.build_icon()?;
        *banner.bitmap_mut()? = bitmap;
        *banner.palette_mut()? = palette;

        if let Some(keyframes) = &self.keyframes {
            if keyframes.len() > 64 {
                TooManyKeyframesSnafu { max: 64usize, actual: keyframes.len() }.fail()?;
            }

            let animation = banner.animation_mut()?;
            for i in 0..keyframes.len() {
                animation.keyframes[i] = keyframes[i].build();
            }
            for i in keyframes.len()..64 {
                animation.keyframes[i] = raw::BannerKeyframe::new();
            }
        }

        self.crc(&mut banner, BannerVersion::Original)?;
        self.crc(&mut banner, BannerVersion::China)?;
        self.crc(&mut banner, BannerVersion::Korea)?;
        self.crc(&mut banner, BannerVersion::Animated)?;

        Ok(banner)
    }
}

pub struct BannerFiles {
    bitmap_path: PathBuf,
    palette_path: PathBuf,
    animation_bitmap_paths: Option<Box<[PathBuf]>>,
    animation_palette_paths: Option<Box<[PathBuf]>>,
}

#[derive(Debug, Snafu)]
pub enum BannerFileError {
    #[snafu(transparent)]
    Io { source: io::Error },
    #[snafu(transparent)]
    Image { source: ImageError },
    #[snafu(display("banner icon must be {expected} pixels but got {actual} pixels:\n{backtrace}"))]
    WrongSize { expected: ImageSize, actual: ImageSize, backtrace: Backtrace },
    #[snafu(display("banner icon {bitmap:?} contains a pixel at {x},{y} which is not present in the palette:\n{backtrace}"))]
    InvalidPixel { bitmap: PathBuf, x: u32, y: u32, backtrace: Backtrace },
}

impl BannerFiles {
    pub fn build_icon(&self) -> Result<(BannerBitmap, BannerPalette), BannerFileError> {
        let bitmap = Reader::open(self.bitmap_path.clone())?.decode()?;
        if bitmap.width() != 32 || bitmap.height() != 32 {
            return WrongSizeSnafu {
                expected: ImageSize { width: 32, height: 32 },
                actual: ImageSize { width: bitmap.width(), height: bitmap.height() },
            }
            .fail();
        }

        let palette = Reader::open(self.palette_path.clone())?.decode()?;
        if palette.width() != 16 || palette.height() != 1 {
            return WrongSizeSnafu {
                expected: ImageSize { width: 16, height: 1 },
                actual: ImageSize { width: bitmap.width(), height: bitmap.height() },
            }
            .fail();
        }

        let mut banner_bitmap = BannerBitmap([0u8; 0x200]);

        for (x, y, color) in bitmap.pixels() {
            let index = palette.pixels().find_map(|(i, _, c)| (color == c).then_some(i));
            let Some(index) = index else {
                return InvalidPixelSnafu { bitmap: self.bitmap_path.clone(), x, y }.fail();
            };
            banner_bitmap.set_pixel(x as usize, y as usize, index as u8);
        }

        let mut banner_palette = BannerPalette([0u16; 16]);
        for (i, _, color) in palette.pixels() {
            let [r, g, b, _] = color.0;
            banner_palette.set_color(i as usize, r, g, b);
        }

        Ok((banner_bitmap, banner_palette))
    }
}

pub struct BannerTitle {
    japanese: String,
    english: String,
    french: String,
    german: String,
    italian: String,
    spanish: String,
    chinese: Option<String>,
    korean: Option<String>,
}

macro_rules! copy_title {
    ($banner:ident, $title:expr) => {
        if let Some(title) = $banner.title_mut(Language::Japanese) {
            let title = title?;
            *title = Unicode16Array::from_str($title);
        }
    };
}

impl BannerTitle {
    fn copy_to_banner(&self, banner: &mut raw::Banner) -> Result<(), BannerError> {
        copy_title!(banner, &self.japanese);
        copy_title!(banner, &self.english);
        copy_title!(banner, &self.french);
        copy_title!(banner, &self.german);
        copy_title!(banner, &self.italian);
        copy_title!(banner, &self.spanish);
        if let Some(chinese) = &self.chinese {
            copy_title!(banner, chinese);
        }
        if let Some(korean) = &self.korean {
            copy_title!(banner, korean);
        }
        Ok(())
    }
}

pub struct BannerKeyframe {
    flip_vertically: bool,
    flip_horizontally: bool,
    palette: usize,
    bitmap: usize,
    frame_duration: usize,
}

impl BannerKeyframe {
    pub fn build(&self) -> raw::BannerKeyframe {
        raw::BannerKeyframe::new()
            .with_frame_duration(self.frame_duration.try_into().unwrap())
            .with_bitmap_index(self.bitmap.try_into().unwrap())
            .with_palette_index(self.palette.try_into().unwrap())
            .with_flip_horizontally(self.flip_horizontally)
            .with_flip_vertically(self.flip_vertically)
    }
}
