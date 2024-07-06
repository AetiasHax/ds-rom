use bitreader::BitReader;
use rust_bitwriter::BitWriter;

pub struct NibbleHuffman {
    pub codes: [NibbleHuffmanCode; 16],
}

pub struct NibbleHuffmanCode {
    pub value: u8,
    pub length: u8,
    pub bits: u8,
}

impl NibbleHuffman {
    fn decompress_nibble(&self, reader: &mut BitReader) -> u8 {
        let (bits_read, code) = self
            .codes
            .iter()
            .find_map(|code| {
                let (bits_read, value) = if code.length as u64 > reader.remaining() {
                    let rem = reader.remaining() as u8;
                    (rem, reader.peek_u8(rem).unwrap() << (code.length - rem))
                } else {
                    (code.length, reader.peek_u8(code.length).unwrap())
                };
                (value == code.bits).then_some((bits_read, code))
            })
            .unwrap();
        reader.skip(bits_read as u64).unwrap();
        code.value
    }

    pub fn decompress(&self, data: &[u8], out: &mut [u8]) {
        let mut reader = BitReader::new(data);

        for i in 0..out.len() {
            let low = self.decompress_nibble(&mut reader);
            let high = self.decompress_nibble(&mut reader);
            out[i] = high << 4 | low;
        }
    }

    fn compress_nibble(&self, writer: &mut BitWriter, data: u8) {
        assert!(data < 16);
        let code = &self.codes.iter().find(|c| c.value == data).unwrap();
        writer.write_u8(code.bits, code.length).unwrap();
    }

    pub fn compress(&self, bytes: &[u8], out: &mut [u8]) {
        let mut writer = BitWriter::new();

        for byte in bytes.iter() {
            let low = byte & 0xf;
            let high = byte >> 4;
            self.compress_nibble(&mut writer, low);
            self.compress_nibble(&mut writer, high);
        }

        writer.close().unwrap();
        let data = writer.data();
        let len = out.len().min(data.len());
        out[..len].copy_from_slice(&data[..len]);
    }

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
