use std::{
    io,
    path::{Path, PathBuf},
};

use image::{DynamicImage, GenericImageView, ImageError, ImageReader, Rgba, RgbaImage};
use serde::{Deserialize, Serialize};
use snafu::{Backtrace, Snafu};

use super::{
    ImageSize,
    raw::{self, BannerBitmap, BannerPalette, BannerVersion, Language},
};
use crate::{crc::CRC_16_MODBUS, str::Unicode16Array};

/// ROM banner.
#[derive(Serialize, Deserialize, Default)]
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
        let mut images = BannerImages::from_bitmap(*banner.bitmap(), *banner.palette());
        let keyframes = banner.animation().map(|animation| {
            images.set_animation(animation);
            // A keyframe with no duration ends the animation, so the trailing empty ones are left out and zero-filled again
            // when building.
            let used = animation.keyframes.iter().rposition(|keyframe| keyframe.frame_duration() > 0);
            animation.keyframes[..used.map_or(0, |i| i + 1)].iter().map(BannerKeyframe::load_raw).collect()
        });
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
            images,
            keyframes,
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
    pub fn build(&self) -> Result<raw::Banner<'_>, BannerError> {
        if let Some(keyframes) = &self.keyframes
            && keyframes.len() > 64
        {
            TooManyKeyframesSnafu { max: 64usize, actual: keyframes.len() }.fail()?;
        }

        let mut banner = raw::Banner::new(self.version);
        self.title.copy_to_banner(&mut banner);

        *banner.bitmap_mut() = self.images.bitmap;
        *banner.palette_mut() = self.images.palette;

        if let Some(animation) = banner.animation_mut() {
            if let Some(bitmaps) = &self.images.animation_bitmaps {
                for (slot, bitmap) in animation.bitmaps.iter_mut().zip(bitmaps.iter()) {
                    *slot = *bitmap;
                }
            }
            if let Some(palettes) = &self.images.animation_palettes {
                for (slot, palette) in animation.palettes.iter_mut().zip(palettes.iter()) {
                    *slot = *palette;
                }
            }
            let keyframes = self.keyframes.as_deref().unwrap_or_default();
            for (slot, keyframe) in animation.keyframes.iter_mut().zip(keyframes.iter()) {
                *slot = keyframe.build();
            }
            for slot in animation.keyframes.iter_mut().skip(keyframes.len()) {
                *slot = raw::BannerKeyframe::new();
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
    /// Paths to the images of the animated icon, if this banner has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub animation_paths: Option<BannerAnimationPaths>,
}

/// Paths to the images of an animated banner icon.
#[derive(Clone, Serialize, Deserialize)]
pub struct BannerAnimationPaths {
    /// One entry per bitmap in the animation.
    pub bitmaps: Vec<BannerAnimationBitmapPath>,
    /// Paths to the palette PNGs, one per palette in the animation.
    pub palettes: Vec<PathBuf>,
}

/// Path to the PNG of one bitmap in an animated banner icon.
#[derive(Clone, Serialize, Deserialize)]
pub struct BannerAnimationBitmapPath {
    /// Path to the bitmap PNG.
    pub path: PathBuf,
    /// Index of the palette the PNG is rendered with. A keyframe can pair a bitmap with any of the animation's palettes, so
    /// this records which one the bitmap's colors have to be mapped back through to recover its palette indices.
    pub palette: usize,
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
            animation_paths: None,
        }
    }

    /// Adds the bitmaps and palettes of an animated icon to this [`BannerImages`]. Every bitmap is rendered with the palette
    /// that the first keyframe showing it uses, so that its colors can be mapped back to palette indices when loading.
    pub fn set_animation(&mut self, animation: &raw::BannerAnimation) {
        let palette_of = |bitmap_index: usize| {
            animation
                .keyframes
                .iter()
                .find(|keyframe| keyframe.frame_duration() > 0 && keyframe.bitmap_index() as usize == bitmap_index)
                .map_or(0, |keyframe| keyframe.palette_index() as usize)
        };

        self.animation_paths = Some(BannerAnimationPaths {
            bitmaps: (0..animation.bitmaps.len())
                .map(|i| BannerAnimationBitmapPath { path: format!("anim_bitmap_{i}.png").into(), palette: palette_of(i) })
                .collect(),
            palettes: (0..animation.palettes.len()).map(|i| format!("anim_palette_{i}.png").into()).collect(),
        });
        self.animation_bitmaps = Some(animation.bitmaps.into());
        self.animation_palettes = Some(animation.palettes.into());
    }

    fn load_palette(path: &Path) -> Result<(BannerPalette, DynamicImage), BannerImageError> {
        let palette_image = ImageReader::open(path)?.decode()?;
        if palette_image.width() != 16 || palette_image.height() != 1 {
            return WrongSizeSnafu {
                expected: ImageSize { width: 16, height: 1 },
                actual: ImageSize { width: palette_image.width(), height: palette_image.height() },
            }
            .fail();
        }

        let mut palette = BannerPalette([0u16; 16]);
        for (i, _, color) in palette_image.pixels() {
            let [r, g, b, _] = color.0;
            palette.set_color(i as usize, r, g, b);
        }
        Ok((palette, palette_image))
    }

    fn load_bitmap(path: &Path, palette_image: &DynamicImage) -> Result<BannerBitmap, BannerImageError> {
        let bitmap_image = ImageReader::open(path)?.decode()?;
        if bitmap_image.width() != 32 || bitmap_image.height() != 32 {
            return WrongSizeSnafu {
                expected: ImageSize { width: 32, height: 32 },
                actual: ImageSize { width: bitmap_image.width(), height: bitmap_image.height() },
            }
            .fail();
        }

        let mut bitmap = BannerBitmap([0u8; 0x200]);
        for (x, y, color) in bitmap_image.pixels() {
            let alpha = color.0[3];
            let index = if alpha == 0 {
                0
            } else {
                let Some(index) = palette_image.pixels().find_map(|(i, _, c)| (color == c).then_some(i)) else {
                    return InvalidPixelSnafu { bitmap: path.to_path_buf(), x, y }.fail();
                };
                index
            };
            bitmap.set_pixel(x as usize, y as usize, index as u8);
        }
        Ok(bitmap)
    }

    /// Loads the bitmap and palette, and the images of the animated icon if this banner has one.
    ///
    /// # Errors
    ///
    /// This function will return an error if [`Reader::open`] or [`Reader::decode`] fails, or if the images are the wrong
    /// size, or a bitmap has a color not present in its palette.
    pub fn load(&mut self, path: &Path) -> Result<(), BannerImageError> {
        let (palette, palette_image) = Self::load_palette(&path.join(&self.palette_path))?;
        self.bitmap = Self::load_bitmap(&path.join(&self.bitmap_path), &palette_image)?;
        self.palette = palette;

        if let Some(animation_paths) = &self.animation_paths {
            let mut palettes = Vec::with_capacity(animation_paths.palettes.len());
            let mut palette_images = Vec::with_capacity(animation_paths.palettes.len());
            for palette_path in &animation_paths.palettes {
                let (palette, palette_image) = Self::load_palette(&path.join(palette_path))?;
                palettes.push(palette);
                palette_images.push(palette_image);
            }

            let mut bitmaps = Vec::with_capacity(animation_paths.bitmaps.len());
            for bitmap in &animation_paths.bitmaps {
                let palette_image = palette_images.get(bitmap.palette).unwrap_or(&palette_image);
                bitmaps.push(Self::load_bitmap(&path.join(&bitmap.path), palette_image)?);
            }

            self.animation_bitmaps = Some(bitmaps.into());
            self.animation_palettes = Some(palettes.into());
        }

        Ok(())
    }

    fn save_bitmap(bitmap: &BannerBitmap, palette: &BannerPalette, path: &Path) -> Result<(), BannerImageError> {
        let mut bitmap_image = RgbaImage::new(32, 32);
        for y in 0..32 {
            for x in 0..32 {
                let index = bitmap.get_pixel(x, y);
                let color = palette.get_color(index);
                bitmap_image.put_pixel(x as u32, y as u32, Rgba(color));
            }
        }
        bitmap_image.save(path)?;
        Ok(())
    }

    fn save_palette(palette: &BannerPalette, path: &Path) -> Result<(), BannerImageError> {
        let mut palette_image = RgbaImage::new(16, 1);
        for index in 0..16 {
            palette_image.put_pixel(index as u32, 0, Rgba(palette.get_color(index)));
        }
        palette_image.save(path)?;
        Ok(())
    }

    /// Saves the bitmap and palette, and the images of the animated icon if this banner has one, to the given path.
    ///
    /// # Errors
    ///
    /// See [`RgbImage::save`].
    pub fn save_bitmap_file(&self, path: &Path) -> Result<(), BannerImageError> {
        Self::save_bitmap(&self.bitmap, &self.palette, &path.join(&self.bitmap_path))?;
        Self::save_palette(&self.palette, &path.join(&self.palette_path))?;

        if let Some(animation_paths) = &self.animation_paths {
            let palettes = self.animation_palettes.as_deref().unwrap_or_default();
            for (palette, palette_path) in palettes.iter().zip(animation_paths.palettes.iter()) {
                Self::save_palette(palette, &path.join(palette_path))?;
            }

            let bitmaps = self.animation_bitmaps.as_deref().unwrap_or_default();
            for (bitmap, bitmap_path) in bitmaps.iter().zip(animation_paths.bitmaps.iter()) {
                let palette = palettes.get(bitmap_path.palette).unwrap_or(&self.palette);
                Self::save_bitmap(bitmap, palette, &path.join(&bitmap_path.path))?;
            }
        }

        Ok(())
    }
}

/// Game title in different languages.
#[derive(Serialize, Deserialize, Default)]
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
    /// Loads from a raw keyframe.
    pub fn load_raw(keyframe: &raw::BannerKeyframe) -> Self {
        Self {
            flip_vertically: keyframe.flip_vertically(),
            flip_horizontally: keyframe.flip_horizontally(),
            palette: keyframe.palette_index() as usize,
            bitmap: keyframe.bitmap_index() as usize,
            frame_duration: keyframe.frame_duration() as usize,
        }
    }

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
