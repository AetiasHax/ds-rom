use bitreader::BitReader;
use rust_bitwriter::BitWriter;

/// De/compresses data with [Huffman coding](https://en.wikipedia.org/wiki/Huffman_coding), one nibble at a time. This struct
/// is not represented as a tree (like it is formally) but instead the Huffman codes are found in an array of length 16, one
/// for each possible nibble value (2^4).
pub struct NibbleHuffman {
    /// Huffman codes for each nibble value, i.e. `codes[n]` encodes the value `n`. The codes must not be prefixed by any other
    /// code in the array.
    pub codes: [NibbleHuffmanCode; 16],
}

/// A huffman code for [NibbleHuffman].
pub struct NibbleHuffmanCode {
    /// The number of bits in [`Self::bits`].
    pub length: u8,
    /// The code for the corresponding nibble.
    pub bits: u8,
}

impl NibbleHuffman {
    fn decompress_nibble(&self, reader: &mut BitReader) -> u8 {
        let (bits_read, value) = self
            .codes
            .iter()
            .enumerate()
            .find_map(|(index, code)| {
                let (bits_read, value) = if code.length as u64 > reader.remaining() {
                    let rem = reader.remaining() as u8;
                    (rem, reader.peek_u8(rem).unwrap() << (code.length - rem))
                } else {
                    (code.length, reader.peek_u8(code.length).unwrap())
                };
                (value == code.bits).then_some((bits_read, index as u8))
            })
            .unwrap();
        reader.skip(bits_read as u64).unwrap();
        value
    }

    /// Decompresses `data` into the `out` slice. It will decompress until `out` is filled, padding zeros past the end of
    /// `data`.
    pub fn decompress_to_slice(&self, data: &[u8], out: &mut [u8]) {
        let mut reader = BitReader::new(data);

        for i in 0..out.len() {
            let low = self.decompress_nibble(&mut reader);
            let high = self.decompress_nibble(&mut reader);
            out[i] = high << 4 | low;
        }
    }

    fn compress_nibble(&self, writer: &mut BitWriter, data: u8) {
        assert!(data < 16);
        let (_, code) = &self.codes.iter().enumerate().find(|(value, _)| *value as u8 == data).unwrap();
        writer.write_u8(code.bits, code.length).unwrap();
    }

    /// Compresses `bytes` into the `out` slice. It will truncate the compressed result to fit into `out`.
    pub fn compress_to_slice(&self, bytes: &[u8], out: &mut [u8]) {
        let mut writer = BitWriter::new();

        for byte in bytes.iter() {
            let low = byte & 0xf;
            let high = byte >> 4;
            self.compress_nibble(&mut writer, low);
            self.compress_nibble(&mut writer, high);
        }

        let _ = writer.close();
        let data = writer.data();
        let len = out.len().min(data.len());
        out[..len].copy_from_slice(&data[..len]);
    }

    /// Does the opposite of [Self::data_to_diff16]. If `data` consists of 16-bit integers that look like A, B-A, C-B and so
    /// on, this function will recover the original data A, B, C.
    ///
    /// # Panics
    ///
    /// Panics if `data.len()` is not a multiple of 2.
    pub fn diff16_to_data(&self, data: &mut [u8]) {
        assert!(data.len() % 2 == 0);
        let mut prev = 0;
        for i in (0..data.len()).step_by(2) {
            let curr = u16::from_le_bytes([data[i], data[i + 1]]);
            let value = curr.wrapping_add(prev);
            data[i..i + 2].copy_from_slice(&value.to_le_bytes());
            prev = value;
        }
    }

    /// Differentiates every 16-bit integer in `data`. For example, if the 16-bit integers are called A, B, C and so on, then
    /// they will be differentiated to A, B-A, C-B and so on.
    ///
    /// If `data` has a lot of repeating values, this will result in plenty of zeros. This benefits Huffman compression, as it
    /// compresses better if some values occur more often than others.
    ///
    /// # Panics
    ///
    /// Panics if `data.len()` is not a multiple of 2.
    pub fn data_to_diff16(&self, data: &mut [u8]) {
        assert!(data.len() % 2 == 0);
        let mut prev = 0;
        for i in (0..data.len()).step_by(2) {
            let curr = u16::from_le_bytes([data[i], data[i + 1]]);
            let value = curr.wrapping_sub(prev);
            data[i..i + 2].copy_from_slice(&value.to_le_bytes());
            prev = curr;
        }
    }
}
