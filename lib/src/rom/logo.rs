use std::{fmt::Display, io, path::Path};

use image::{io::Reader, GenericImageView, GrayImage, ImageError, Luma};
use snafu::{Backtrace, Snafu};

use crate::compress::huffman::{NibbleHuffman, NibbleHuffmanCode};

/// Huffman codes for every combination of 4 pixels
const HUFFMAN: NibbleHuffman = NibbleHuffman {
    codes: [
        /* 0000 */ NibbleHuffmanCode { length: 1, bits: 0b1 },
        /* 0001 */ NibbleHuffmanCode { length: 4, bits: 0b0110 },
        /* 0010 */ NibbleHuffmanCode { length: 5, bits: 0b01010 },
        /* 0011 */ NibbleHuffmanCode { length: 4, bits: 0b0100 },
        /* 0100 */ NibbleHuffmanCode { length: 5, bits: 0b00010 },
        /* 0101 */ NibbleHuffmanCode { length: 6, bits: 0b011110 },
        /* 0110 */ NibbleHuffmanCode { length: 6, bits: 0b010110 },
        /* 0111 */ NibbleHuffmanCode { length: 6, bits: 0b000110 },
        /* 1000 */ NibbleHuffmanCode { length: 5, bits: 0b00110 },
        /* 1001 */ NibbleHuffmanCode { length: 6, bits: 0b011111 },
        /* 1010 */ NibbleHuffmanCode { length: 6, bits: 0b010111 },
        /* 1011 */ NibbleHuffmanCode { length: 6, bits: 0b000111 },
        /* 1100 */ NibbleHuffmanCode { length: 4, bits: 0b0010 },
        /* 1101 */ NibbleHuffmanCode { length: 5, bits: 0b01110 },
        /* 1110 */ NibbleHuffmanCode { length: 5, bits: 0b00111 },
        /* 1111 */ NibbleHuffmanCode { length: 4, bits: 0b0000 },
    ],
};

const WIDTH: usize = 104;
const HEIGHT: usize = 16;
const SIZE: usize = WIDTH * HEIGHT / 8;

const LOGO_HEADER: u32 = 0x0000d082;
const LOGO_FOOTER: u32 = 0xfff4c307;

/// Header logo.
pub struct Logo {
    pixels: [u8; SIZE],
}

impl Default for Logo {
    fn default() -> Self {
        Self { pixels: [0u8; SIZE] }
    }
}

/// Errors related to [`Logo`].
#[derive(Snafu, Debug)]
pub enum LogoError {
    /// Occurs when decompressing a logo with an invalid header.
    #[snafu(display("invalid logo header, expected {expected:08x} but got {actual:08x}:\n{backtrace}"))]
    InvalidHeader {
        /// Expected header.
        expected: u32,
        /// Actual input header.
        actual: u32,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// Occurs when decompressing a logo with an invalid footer.
    #[snafu(display("invalid logo footer, expected {expected:08x} but got {actual:08x}:\n{backtrace}"))]
    InvalidFooter {
        /// Expected footer.
        expected: u32,
        /// Actual input footer.
        actual: u32,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// Occurs when decompressing a logo which doesn't yield the correct bitmap size.
    #[snafu(display("wrong logo size, expected {expected} bytes but got {actual} bytes:\n{backtrace}"))]
    WrongSize {
        /// Expected size.
        expected: usize,
        /// Actual input size.
        actual: usize,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
}

/// Errors when loading a [`Logo`].
#[derive(Snafu, Debug)]
pub enum LogoLoadError {
    /// See [`io::Error`].
    #[snafu(transparent)]
    Io {
        /// Source error.
        source: io::Error,
    },
    /// See [`ImageError`].
    #[snafu(transparent)]
    Image {
        /// Source error.
        source: ImageError,
    },
    /// Occurs when the input image has a pixel which isn't white or black.
    #[snafu(display("logo image contains a pixel at {x},{y} which isn't white or black:\n{backtrace}"))]
    InvalidColor {
        /// X coordinate.
        x: u32,
        /// Y coordinate.
        y: u32,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// Occurs when the input image has the wrong size.
    #[snafu(display("logo image must be {expected} pixels but got {actual} pixels:\n{backtrace}"))]
    ImageSize {
        /// Expected size.
        expected: ImageSize,
        /// Actual input size.
        actual: ImageSize,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
}

/// Errors when saving a [`Logo`].
#[derive(Snafu, Debug)]
pub enum LogoSaveError {
    /// See [`ImageError`].
    #[snafu(transparent)]
    Image {
        /// Source error.
        source: ImageError,
    },
}

/// Size of an image.
#[derive(Debug)]
pub struct ImageSize {
    /// Image width.
    pub width: u32,
    /// Image height.
    pub height: u32,
}

impl Display for ImageSize {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}x{}", self.width, self.height)
    }
}

fn reverse32(data: &mut [u8]) {
    for i in (0..data.len() & !3).step_by(4) {
        let value = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        let swapped = value.swap_bytes().to_le_bytes();
        data[i..i + 4].copy_from_slice(&swapped);
    }
}

impl Logo {
    /// Saves this [`Logo`] to a PNG image.
    ///
    /// # Errors
    ///
    /// This function will return an error if [`GrayImage::save`] fails.
    pub fn save_png<P: AsRef<Path>>(&self, path: P) -> Result<(), LogoSaveError> {
        let mut image = GrayImage::new(WIDTH as u32, HEIGHT as u32);
        for y in 0..HEIGHT {
            for x in 0..WIDTH {
                let luma = if self.get_pixel(x, y) { 0x00 } else { 0xff };
                image.put_pixel(x as u32, y as u32, Luma([luma]));
            }
        }
        image.save(path)?;
        Ok(())
    }

    /// Loads a [`Logo`] from a PNG image.
    ///
    /// # Errors
    ///
    /// This function will return an error if it failed to open or decode the image, or the image has the wrong size or colors.
    pub fn from_png<P: AsRef<Path>>(path: P) -> Result<Self, LogoLoadError> {
        let image = Reader::open(path)?.decode()?;
        if image.width() != WIDTH as u32 || image.height() != HEIGHT as u32 {
            ImageSizeSnafu {
                expected: ImageSize { width: WIDTH as u32, height: HEIGHT as u32 },
                actual: ImageSize { width: image.width(), height: image.height() },
            }
            .fail()?;
        }

        let mut logo = Logo { pixels: [0; SIZE] };
        for (x, y, color) in image.pixels() {
            let [r, g, b, _] = color.0;
            if (r != 0xff && r != 0x00) || g != r || b != r {
                return InvalidColorSnafu { x, y }.fail();
            }
            logo.set_pixel(x as usize, y as usize, r == 0x00);
        }
        Ok(logo)
    }

    /// Decompresses a [`Logo`] from a compressed logo in the ROM header.
    ///
    /// # Errors
    ///
    /// This function will return an error if the compressed logo yields an invalid header, footer or bitmap size.
    pub fn decompress(data: &[u8]) -> Result<Self, LogoError> {
        let data = {
            let mut swapped_data = data.to_owned();
            reverse32(&mut swapped_data);
            swapped_data.into_boxed_slice()
        };

        let mut bytes = [0u8; SIZE + 8];
        HUFFMAN.decompress_to_slice(&data, &mut bytes);

        let header = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if header != LOGO_HEADER {
            InvalidHeaderSnafu { expected: LOGO_HEADER, actual: header }.fail()?;
        }

        let footer = u32::from_le_bytes([
            bytes[bytes.len() - 4],
            bytes[bytes.len() - 3],
            bytes[bytes.len() - 2],
            bytes[bytes.len() - 1],
        ]);
        if footer != LOGO_FOOTER {
            InvalidFooterSnafu { expected: LOGO_FOOTER, actual: footer }.fail()?;
        }

        let len = bytes.len();
        let mut diff = &mut bytes[4..len - 4];
        if diff.len() != SIZE {
            WrongSizeSnafu { expected: SIZE, actual: diff.len() }.fail()?;
        }
        HUFFMAN.diff16_to_data(&mut diff);

        let mut logo = Logo::default();
        logo.load_tiles(diff);
        Ok(logo)
    }

    /// Compresses this [`Logo`] to put into a ROM header.
    pub fn compress(&self) -> [u8; 0x9c] {
        let mut diff = [0u8; SIZE + 8];
        self.store_tiles(&mut diff[4..SIZE + 4]);
        HUFFMAN.data_to_diff16(&mut diff[4..SIZE + 4]);

        diff[0..4].copy_from_slice(&LOGO_HEADER.to_le_bytes());
        diff[SIZE + 4..SIZE + 8].copy_from_slice(&LOGO_FOOTER.to_le_bytes());

        let mut bytes = [0u8; 0x9c];
        HUFFMAN.compress_to_slice(&diff, &mut bytes);
        reverse32(&mut bytes);
        bytes
    }

    fn load_tiles(&mut self, data: &[u8]) {
        for y in 0..HEIGHT {
            for x in 0..WIDTH {
                let index = (y / 8) * WIDTH + (x / 8) * 8 + y % 8;
                let value = if index >= data.len() {
                    false
                } else {
                    let offset = x & 7;
                    (data[index] & (1 << offset)) != 0
                };
                self.set_pixel(x, y, value);
            }
        }
    }

    fn store_tiles(&self, data: &mut [u8]) {
        for y in 0..HEIGHT {
            for x in 0..WIDTH {
                let bit = 1 << (x & 7);
                let value = self.get_pixel_value(x, y, bit);
                let index = (y / 8) * WIDTH + (x / 8) * 8 + y % 8;
                if index < data.len() {
                    data[index] = (data[index] & !bit) | value
                };
            }
        }
    }

    /// Returns the pixel value at the given coordinates.
    pub fn get_pixel(&self, x: usize, y: usize) -> bool {
        let index = (y * WIDTH + x) / 8;
        if index >= self.pixels.len() {
            false
        } else {
            let offset = !x & 7;
            (self.pixels[index] & (1 << offset)) != 0
        }
    }

    /// Sets the pixel value at the given coordinates.
    pub fn set_pixel(&mut self, x: usize, y: usize, value: bool) {
        let index = (y * WIDTH + x) / 8;
        if index < self.pixels.len() {
            let bit = 1 << (!x & 7);
            let value = if value { bit } else { 0 };
            self.pixels[index] = (self.pixels[index] & !bit) | value;
        }
    }

    fn get_pixel_value(&self, x: usize, y: usize, value: u8) -> u8 {
        if self.get_pixel(x, y) {
            value
        } else {
            0
        }
    }

    fn get_braille_index(&self, x: usize, y: usize) -> u8 {
        let value = self.get_pixel_value(x, y, 0x80)
            | self.get_pixel_value(x + 1, y, 0x40)
            | self.get_pixel_value(x, y + 1, 0x20)
            | self.get_pixel_value(x + 1, y + 1, 0x10)
            | self.get_pixel_value(x, y + 2, 0x8)
            | self.get_pixel_value(x + 1, y + 2, 0x4)
            | self.get_pixel_value(x, y + 3, 0x2)
            | self.get_pixel_value(x + 1, y + 3, 0x1);
        !value
    }
}

/// Braille patterns indexed as binary representations of 0-255. Bit positions:  
/// 6 7  
/// 4 5  
/// 3 2  
/// 1 0
const BRAILLE: &[char; 256] = &[
    '⠀', '⢀', '⡀', '⣀', '⠠', '⢠', '⡠', '⣠', '⠄', '⢄', '⡄', '⣄', '⠤', '⢤', '⡤', '⣤', '⠐', '⢐', '⡐', '⣐', '⠰', '⢰', '⡰', '⣰',
    '⠔', '⢔', '⡔', '⣔', '⠴', '⢴', '⡴', '⣴', '⠂', '⢂', '⡂', '⣂', '⠢', '⢢', '⡢', '⣢', '⠆', '⢆', '⡆', '⣆', '⠦', '⢦', '⡦', '⣦',
    '⠒', '⢒', '⡒', '⣒', '⠲', '⢲', '⡲', '⣲', '⠖', '⢖', '⡖', '⣖', '⠶', '⢶', '⡶', '⣶', '⠈', '⢈', '⡈', '⣈', '⠨', '⢨', '⡨', '⣨',
    '⠌', '⢌', '⡌', '⣌', '⠬', '⢬', '⡬', '⣬', '⠘', '⢘', '⡘', '⣘', '⠸', '⢸', '⡸', '⣸', '⠜', '⢜', '⡜', '⣜', '⠼', '⢼', '⡼', '⣼',
    '⠊', '⢊', '⡊', '⣊', '⠪', '⢪', '⡪', '⣪', '⠎', '⢎', '⡎', '⣎', '⠮', '⢮', '⡮', '⣮', '⠚', '⢚', '⡚', '⣚', '⠺', '⢺', '⡺', '⣺',
    '⠞', '⢞', '⡞', '⣞', '⠾', '⢾', '⡾', '⣾', '⠁', '⢁', '⡁', '⣁', '⠡', '⢡', '⡡', '⣡', '⠅', '⢅', '⡅', '⣅', '⠥', '⢥', '⡥', '⣥',
    '⠑', '⢑', '⡑', '⣑', '⠱', '⢱', '⡱', '⣱', '⠕', '⢕', '⡕', '⣕', '⠵', '⢵', '⡵', '⣵', '⠃', '⢃', '⡃', '⣃', '⠣', '⢣', '⡣', '⣣',
    '⠇', '⢇', '⡇', '⣇', '⠧', '⢧', '⡧', '⣧', '⠓', '⢓', '⡓', '⣓', '⠳', '⢳', '⡳', '⣳', '⠗', '⢗', '⡗', '⣗', '⠷', '⢷', '⡷', '⣷',
    '⠉', '⢉', '⡉', '⣉', '⠩', '⢩', '⡩', '⣩', '⠍', '⢍', '⡍', '⣍', '⠭', '⢭', '⡭', '⣭', '⠙', '⢙', '⡙', '⣙', '⠹', '⢹', '⡹', '⣹',
    '⠝', '⢝', '⡝', '⣝', '⠽', '⢽', '⡽', '⣽', '⠋', '⢋', '⡋', '⣋', '⠫', '⢫', '⡫', '⣫', '⠏', '⢏', '⡏', '⣏', '⠯', '⢯', '⡯', '⣯',
    '⠛', '⢛', '⡛', '⣛', '⠻', '⢻', '⡻', '⣻', '⠟', '⢟', '⡟', '⣟', '⠿', '⢿', '⡿', '⣿',
];

impl Display for Logo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for y in (0..HEIGHT).step_by(4) {
            if y > 0 {
                writeln!(f)?;
            }
            for x in (0..WIDTH).step_by(2) {
                let index = self.get_braille_index(x, y) as usize;
                let ch = BRAILLE.get(index).unwrap_or(&' ');
                write!(f, "{ch}")?;
            }
        }

        Ok(())
    }
}
