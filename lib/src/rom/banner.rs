use std::{
    io,
    path::{Path, PathBuf},
};

use image::{io::Reader, GenericImageView, ImageError, Rgb, RgbImage};
use serde::{Deserialize, Serialize};
use snafu::{Backtrace, Snafu};

use crate::{str::Unicode16Array, CRC_16_MODBUS};

use super::{
    raw::{self, BannerBitmap, BannerPalette, BannerVersion, Language, RawBannerError},
    ImageSize,
};

#[derive(Serialize, Deserialize)]
pub struct Banner {
    version: BannerVersion,
    pub title: BannerTitle,
    #[serde(skip)]
    pub images: BannerImages,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keyframes: Option<Vec<BannerKeyframe>>,
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
    BannerFile { source: BannerImageError },
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
            images: BannerImages::from_bitmap(*banner.bitmap()?, *banner.palette()?),
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

        *banner.bitmap_mut()? = self.images.bitmap;
        *banner.palette_mut()? = self.images.palette;

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

    pub fn save_images(&self) {}
}

#[derive(Default)]
pub struct BannerImages {
    pub bitmap: BannerBitmap,
    pub palette: BannerPalette,
    pub animation_bitmap_paths: Option<Box<[BannerBitmap]>>,
    pub animation_palette_paths: Option<Box<[BannerPalette]>>,
}

#[derive(Debug, Snafu)]
pub enum BannerImageError {
    #[snafu(transparent)]
    Io { source: io::Error },
    #[snafu(transparent)]
    Image { source: ImageError },
    #[snafu(display("banner icon must be {expected} pixels but got {actual} pixels:\n{backtrace}"))]
    WrongSize { expected: ImageSize, actual: ImageSize, backtrace: Backtrace },
    #[snafu(display("banner icon {bitmap:?} contains a pixel at {x},{y} which is not present in the palette:\n{backtrace}"))]
    InvalidPixel { bitmap: PathBuf, x: u32, y: u32, backtrace: Backtrace },
}

impl BannerImages {
    pub fn from_bitmap(bitmap: BannerBitmap, palette: BannerPalette) -> Self {
        Self { bitmap, palette, animation_bitmap_paths: None, animation_palette_paths: None }
    }

    pub fn load_bitmap_file<P: AsRef<Path> + Into<PathBuf>>(
        &mut self,
        bitmap_path: P,
        palette_path: P,
    ) -> Result<(), BannerImageError> {
        let bitmap_image = Reader::open(&bitmap_path)?.decode()?;
        if bitmap_image.width() != 32 || bitmap_image.height() != 32 {
            return WrongSizeSnafu {
                expected: ImageSize { width: 32, height: 32 },
                actual: ImageSize { width: bitmap_image.width(), height: bitmap_image.height() },
            }
            .fail();
        }

        let palette_image = Reader::open(palette_path)?.decode()?;
        if palette_image.width() != 16 || palette_image.height() != 1 {
            return WrongSizeSnafu {
                expected: ImageSize { width: 16, height: 1 },
                actual: ImageSize { width: palette_image.width(), height: palette_image.height() },
            }
            .fail();
        }

        let mut bitmap = BannerBitmap([0u8; 0x200]);
        for (x, y, color) in bitmap_image.pixels() {
            let index = palette_image.pixels().find_map(|(i, _, c)| (color == c).then_some(i));
            let Some(index) = index else {
                return InvalidPixelSnafu { bitmap: bitmap_path, x, y }.fail();
            };
            bitmap.set_pixel(x as usize, y as usize, index as u8);
        }

        let mut palette = BannerPalette([0u16; 16]);
        for (i, _, color) in palette_image.pixels() {
            let [r, g, b, _] = color.0;
            palette.set_color(i as usize, r, g, b);
        }

        self.bitmap = bitmap;
        self.palette = palette;
        Ok(())
    }

    pub fn save_bitmap_file(&self, path: &Path) -> Result<(), BannerImageError> {
        let mut bitmap_image = RgbImage::new(32, 32);
        for y in 0..32 {
            for x in 0..32 {
                let index = self.bitmap.get_pixel(x, y);
                let (r, g, b) = self.palette.get_color(index);
                bitmap_image.put_pixel(x as u32, y as u32, Rgb([r, g, b]));
            }
        }

        let mut palette_image = RgbImage::new(16, 1);
        for index in 0..16 {
            let (r, g, b) = self.palette.get_color(index);
            palette_image.put_pixel(index as u32, 0, Rgb([r, g, b]));
        }

        bitmap_image.save(path.join("bitmap.png"))?;
        palette_image.save(path.join("palette.png"))?;
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
pub struct BannerTitle {
    pub japanese: String,
    pub english: String,
    pub french: String,
    pub german: String,
    pub italian: String,
    pub spanish: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chinese: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub korean: Option<String>,
}

macro_rules! copy_title {
    ($banner:ident, $language:expr, $title:expr) => {
        if let Some(title) = $banner.title_mut($language) {
            let title = title?;
            *title = Unicode16Array::from_str($title);
        }
    };
}

impl BannerTitle {
    fn copy_to_banner(&self, banner: &mut raw::Banner) -> Result<(), BannerError> {
        copy_title!(banner, Language::Japanese, &self.japanese);
        copy_title!(banner, Language::English, &self.english);
        copy_title!(banner, Language::French, &self.french);
        copy_title!(banner, Language::German, &self.german);
        copy_title!(banner, Language::Italian, &self.italian);
        copy_title!(banner, Language::Spanish, &self.spanish);
        if let Some(chinese) = &self.chinese {
            copy_title!(banner, Language::Chinese, chinese);
        }
        if let Some(korean) = &self.korean {
            copy_title!(banner, Language::Korean, korean);
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
pub struct BannerKeyframe {
    pub flip_vertically: bool,
    pub flip_horizontally: bool,
    pub palette: usize,
    pub bitmap: usize,
    pub frame_duration: usize,
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
