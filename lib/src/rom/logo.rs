use std::{fmt::Display, fs::File, io, path::Path};

use snafu::{Backtrace, Snafu};

use crate::compress::huffman::{NibbleHuffman, NibbleHuffmanCode};

/// Huffman codes for every combination of 4 pixels
const HUFFMAN: NibbleHuffman = NibbleHuffman {
    codes: [
        NibbleHuffmanCode { value: 0b0000, length: 1, bits: 0b1 },
        NibbleHuffmanCode { value: 0b0001, length: 4, bits: 0b0110 },
        NibbleHuffmanCode { value: 0b0010, length: 5, bits: 0b01010 },
        NibbleHuffmanCode { value: 0b0011, length: 4, bits: 0b0100 },
        NibbleHuffmanCode { value: 0b0100, length: 5, bits: 0b00010 },
        NibbleHuffmanCode { value: 0b0101, length: 6, bits: 0b011110 },
        NibbleHuffmanCode { value: 0b0110, length: 6, bits: 0b010110 },
        NibbleHuffmanCode { value: 0b0111, length: 6, bits: 0b000110 },
        NibbleHuffmanCode { value: 0b1000, length: 5, bits: 0b00110 },
        NibbleHuffmanCode { value: 0b1001, length: 6, bits: 0b011111 },
        NibbleHuffmanCode { value: 0b1010, length: 6, bits: 0b010111 },
        NibbleHuffmanCode { value: 0b1011, length: 6, bits: 0b000111 },
        NibbleHuffmanCode { value: 0b1100, length: 4, bits: 0b0010 },
        NibbleHuffmanCode { value: 0b1101, length: 5, bits: 0b01110 },
        NibbleHuffmanCode { value: 0b1110, length: 5, bits: 0b00111 },
        NibbleHuffmanCode { value: 0b1111, length: 4, bits: 0b0000 },
    ],
};

const WIDTH: usize = 104;
const HEIGHT: usize = 16;
const SIZE: usize = WIDTH * HEIGHT / 8;

const LOGO_HEADER: u32 = 0x0000d082;
const LOGO_FOOTER: u32 = 0xfff4c307;

pub struct Logo {
    pixels: [u8; SIZE],
}

impl Default for Logo {
    fn default() -> Self {
        Self { pixels: [0u8; SIZE] }
    }
}

#[derive(Snafu, Debug)]
pub enum LogoError {
    #[snafu(display("invalid logo header, expected {expected:08x} but got {actual:08x}:\n{backtrace}"))]
    InvalidHeader { expected: u32, actual: u32, backtrace: Backtrace },
    #[snafu(display("invalid logo footer, expected {expected:08x} but got {actual:08x}:\n{backtrace}"))]
    InvalidFooter { expected: u32, actual: u32, backtrace: Backtrace },
    #[snafu(display("wrong logo size, expected {expected} bytes but got {actual} bytes:\n{backtrace}"))]
    WrongSize { expected: usize, actual: usize, backtrace: Backtrace },
}

#[derive(Snafu, Debug)]
pub enum LogoLoadError {
    #[snafu(transparent)]
    Io { source: io::Error },
    #[snafu(transparent)]
    Decoding { source: png::DecodingError },
    #[snafu(display("logo image must have {expected}-bit color depth but got {actual}-bit:\n{backtrace}"))]
    ColorDepth { expected: u8, actual: u8, backtrace: Backtrace },
    #[snafu(display("logo image must be {expected} pixels but got {actual} pixels:\n{backtrace}"))]
    ImageSize { expected: ImageSize, actual: ImageSize, backtrace: Backtrace },
    #[snafu(display("logo buffer must be {expected} bytes but got {actual} bytes:\n{backtrace}"))]
    BufferSize { expected: usize, actual: usize, backtrace: Backtrace },
}

#[derive(Debug)]
pub struct ImageSize {
    pub width: usize,
    pub height: usize,
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
    pub fn from_png<P: AsRef<Path>>(path: P) -> Result<Self, LogoLoadError> {
        let decoder = png::Decoder::new(File::open(path)?);
        let mut reader = decoder.read_info()?;
        let bit_depth = reader.output_color_type().1;
        match bit_depth {
            png::BitDepth::One => {}
            _ => {
                ColorDepthSnafu { expected: 1, actual: bit_depth as u8 }.fail()?;
            }
        };

        let mut buf = vec![0; reader.output_buffer_size()];
        let info = reader.next_frame(&mut buf)?;
        if info.width != WIDTH as u32 || info.height != HEIGHT as u32 {
            ImageSizeSnafu {
                expected: ImageSize { width: WIDTH, height: HEIGHT },
                actual: ImageSize { width: info.width as usize, height: info.height as usize },
            }
            .fail()?;
        }

        let bytes = buf.into_boxed_slice();
        let mut pixels = [0u8; SIZE];
        pixels.copy_from_slice(&bytes);
        Ok(Logo { pixels })
    }

    pub fn decompress(data: &[u8]) -> Result<Self, LogoError> {
        let data = {
            let mut swapped_data = data.to_owned();
            reverse32(&mut swapped_data);
            swapped_data.into_boxed_slice()
        };

        let mut bytes = [0u8; SIZE + 8];
        HUFFMAN.decompress(&data, &mut bytes);

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

    pub fn compress(&self) -> Box<[u8]> {
        let mut diff = [0u8; SIZE + 8];
        self.store_tiles(&mut diff[4..SIZE + 4]);
        HUFFMAN.data_to_diff16(&mut diff[4..SIZE + 4]);

        diff[0..4].copy_from_slice(&LOGO_HEADER.to_le_bytes());
        diff[SIZE + 4..SIZE + 8].copy_from_slice(&LOGO_FOOTER.to_le_bytes());

        let mut bytes = vec![0u8; 0x9c];
        HUFFMAN.compress(&diff, &mut bytes);
        reverse32(&mut bytes);
        bytes.into_boxed_slice()
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

    pub fn get_pixel(&self, x: usize, y: usize) -> bool {
        let index = (y * WIDTH + x) / 8;
        if index >= self.pixels.len() {
            false
        } else {
            let offset = !x & 7;
            (self.pixels[index] & (1 << offset)) != 0
        }
    }

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
        self.get_pixel_value(x, y, 0x80)
            | self.get_pixel_value(x + 1, y, 0x40)
            | self.get_pixel_value(x, y + 1, 0x20)
            | self.get_pixel_value(x + 1, y + 1, 0x10)
            | self.get_pixel_value(x, y + 2, 0x8)
            | self.get_pixel_value(x + 1, y + 2, 0x4)
            | self.get_pixel_value(x, y + 3, 0x2)
            | self.get_pixel_value(x + 1, y + 3, 0x1)
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
