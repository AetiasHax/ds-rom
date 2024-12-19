use std::{
    io,
    path::{Path, PathBuf},
};

use image::{io::Reader, GenericImageView, ImageError, Rgb, RgbImage};
use serde::{Deserialize, Serialize};
use snafu::{Backtrace, Snafu};

use super::{
    raw::{self, BannerBitmap, BannerPalette, BannerVersion, Language},
    ImageSize,
};
use crate::{crc::CRC_16_MODBUS, str::Unicode16Array};

/// ROM banner.
#[derive(Serialize, Deserialize)]
pub struct Banner {
    version: BannerVersion,
    /// Game title in different languages.
    pub title: BannerTitle,
    /// Icon to show on the home screen.
    pub images: BannerImages,
    /// Keyframes for animated icons.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keyframes: Option<Vec<BannerKeyframe>>,
}

/// Errors related to [`Banner`].
#[derive(Debug, Snafu)]
pub enum BannerError {
    /// See [`BannerImageError`].
    #[snafu(transparent)]
    BannerFile {
        /// Source error.
        source: BannerImageError,
    },
    /// Occurs when trying to build a banner to place in the ROM, but there were too many keyframes.
    #[snafu(display("maximum keyframe count is {max} but got {actual}:\n{backtrace}"))]
    TooManyKeyframes {
        /// Max allowed amount.
        max: usize,
        /// Actual amount.
        actual: usize,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// Occurs when trying to build a banner to place in the ROM, but the version is not yet supported by this library.
    #[snafu(display("maximum supported banner version is currently {max} but got {actual}:\n{backtrace}"))]
    VersionNotSupported {
        /// Max supported version.
        max: BannerVersion,
        /// Actual version.
        actual: BannerVersion,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
}

impl Banner {
    fn load_title(banner: &raw::Banner, version: BannerVersion, language: Language) -> Option<String> {
        if version.supports_language(language) {
            banner.title(language).map(|title| title.to_string())
        } else {
            None
        }
    }

    /// Loads from a raw banner.
    pub fn load_raw(banner: &raw::Banner) -> Self {
        let version = banner.version();
        Self {
            version,
            title: BannerTitle {
                japanese: Self::load_title(banner, version, Language::Japanese).unwrap(),
                english: Self::load_title(banner, version, Language::English).unwrap(),
                french: Self::load_title(banner, version, Language::French).unwrap(),
                german: Self::load_title(banner, version, Language::German).unwrap(),
                italian: Self::load_title(banner, version, Language::Italian).unwrap(),
                spanish: Self::load_title(banner, version, Language::Spanish).unwrap(),
                chinese: Self::load_title(banner, version, Language::Chinese),
                korean: Self::load_title(banner, version, Language::Korean),
            },
            images: BannerImages::from_bitmap(*banner.bitmap(), *banner.palette()),
            keyframes: None,
        }
    }

    fn crc(&self, banner: &mut raw::Banner, version: BannerVersion) {
        if self.version >= version {
            *banner.crc_mut(version.crc_index()) = CRC_16_MODBUS.checksum(&banner.full_data()[version.crc_range()]);
        }
    }

    /// Builds a raw banner to place in a ROM.
    ///
    /// # Errors
    ///
    /// This function will return an error if the banner version is not yet supported by this library, or there are too many
    /// keyframes.
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
        self.title.copy_to_banner(&mut banner);

        *banner.bitmap_mut() = self.images.bitmap;
        *banner.palette_mut() = self.images.palette;

        if let Some(keyframes) = &self.keyframes {
            if keyframes.len() > 64 {
                TooManyKeyframesSnafu { max: 64usize, actual: keyframes.len() }.fail()?;
            }

            let animation = banner.animation_mut().unwrap();
            for i in 0..keyframes.len() {
                animation.keyframes[i] = keyframes[i].build();
            }
            for i in keyframes.len()..64 {
                animation.keyframes[i] = raw::BannerKeyframe::new();
            }
        }

        self.crc(&mut banner, BannerVersion::Original);
        self.crc(&mut banner, BannerVersion::China);
        self.crc(&mut banner, BannerVersion::Korea);
        self.crc(&mut banner, BannerVersion::Animated);

        Ok(banner)
    }
}

/// Icon for the [`Banner`].
#[derive(Default, Serialize, Deserialize)]
pub struct BannerImages {
    /// Main bitmap.
    #[serde(skip)]
    pub bitmap: BannerBitmap,
    /// Main palette.
    #[serde(skip)]
    pub palette: BannerPalette,
    /// Bitmaps for animated icon.
    #[serde(skip)]
    pub animation_bitmaps: Option<Box<[BannerBitmap]>>,
    /// Palettes for animated icon
    #[serde(skip)]
    pub animation_palettes: Option<Box<[BannerPalette]>>,

    /// Path to bitmap PNG.
    pub bitmap_path: PathBuf,
    /// Path to palette PNG.
    pub palette_path: PathBuf,
}

/// Errors related to [`BannerImages`].
#[derive(Debug, Snafu)]
pub enum BannerImageError {
    /// See [`io::Error`].
    #[snafu(transparent)]
    Io {
        /// Error source.
        source: io::Error,
    },
    /// See [`ImageError`].
    #[snafu(transparent)]
    Image {
        /// Source error.
        source: ImageError,
    },
    /// Occurs when loading a banner image with the wrong size.
    #[snafu(display("banner icon must be {expected} pixels but got {actual} pixels:\n{backtrace}"))]
    WrongSize {
        /// Expected size.
        expected: ImageSize,
        /// Actual input size.
        actual: ImageSize,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// Occurs when the bitmap has a pixel not present in the palette.
    #[snafu(display("banner icon {bitmap:?} contains a pixel at {x},{y} which is not present in the palette:\n{backtrace}"))]
    InvalidPixel {
        /// Path to the bitmap.
        bitmap: PathBuf,
        /// X coordinate.
        x: u32,
        /// Y coordinate.
        y: u32,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
}

impl BannerImages {
    /// Creates a new [`BannerImages`] from a bitmap and palette.
    pub fn from_bitmap(bitmap: BannerBitmap, palette: BannerPalette) -> Self {
        Self {
            bitmap,
            palette,
            animation_bitmaps: None,
            animation_palettes: None,
            bitmap_path: "bitmap.png".into(),
            palette_path: "palette.png".into(),
        }
    }

    /// Loads the bitmap and palette
    ///
    /// # Errors
    ///
    /// This function will return an error if [`Reader::open`] or [`Reader::decode`] fails, or if the images are the wrong
    /// size, or the bitmap has a color not present in the palette.
    pub fn load(&mut self, path: &Path) -> Result<(), BannerImageError> {
        let bitmap_image = Reader::open(path.join(&self.bitmap_path))?.decode()?;
        if bitmap_image.width() != 32 || bitmap_image.height() != 32 {
            return WrongSizeSnafu {
                expected: ImageSize { width: 32, height: 32 },
                actual: ImageSize { width: bitmap_image.width(), height: bitmap_image.height() },
            }
            .fail();
        }

        let palette_image = Reader::open(path.join(&self.palette_path))?.decode()?;
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
                return InvalidPixelSnafu { bitmap: path.join(&self.bitmap_path), x, y }.fail();
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

    /// Saves to a bitmap and palette file in the given path.
    ///
    /// # Errors
    ///
    /// See [`RgbImage::save`].
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

        bitmap_image.save(path.join(&self.bitmap_path))?;
        palette_image.save(path.join(&self.palette_path))?;
        Ok(())
    }
}

/// Game title in different languages.
#[derive(Serialize, Deserialize)]
pub struct BannerTitle {
    /// Japanese.
    pub japanese: String,
    /// English.
    pub english: String,
    /// French.
    pub french: String,
    /// German.
    pub german: String,
    /// Italian.
    pub italian: String,
    /// Spanish.
    pub spanish: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Chinese.
    pub chinese: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Korean.
    pub korean: Option<String>,
}

macro_rules! copy_title {
    ($banner:ident, $language:expr, $title:expr) => {
        if let Some(title) = $banner.title_mut($language) {
            *title = Unicode16Array::from($title.as_str());
        }
    };
}

impl BannerTitle {
    fn copy_to_banner(&self, banner: &mut raw::Banner) {
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
    }
}

/// Keyframe for animated icon.
#[derive(Serialize, Deserialize)]
pub struct BannerKeyframe {
    /// Flips the bitmap vertically.
    pub flip_vertically: bool,
    /// Flips the bitmap horizontally.
    pub flip_horizontally: bool,
    /// Palette index.
    pub palette: usize,
    /// Bitmap index.
    pub bitmap: usize,
    /// Duration in frames.
    pub frame_duration: usize,
}

impl BannerKeyframe {
    /// Builds a raw keyframe.
    ///
    /// # Panics
    ///
    /// Panics if the frame duration, bitmap index or palette do not fit in the raw keyframe.
    pub fn build(&self) -> raw::BannerKeyframe {
        raw::BannerKeyframe::new()
            .with_frame_duration(self.frame_duration.try_into().unwrap())
            .with_bitmap_index(self.bitmap.try_into().unwrap())
            .with_palette_index(self.palette.try_into().unwrap())
            .with_flip_horizontally(self.flip_horizontally)
            .with_flip_vertically(self.flip_vertically)
    }
}
