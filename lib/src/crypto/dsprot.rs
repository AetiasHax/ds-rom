// Credits to taxicat1 aka Mow:
// https://github.com/taxicat1/dsprot
// https://github.com/taxicat1/dsdetect

use std::{backtrace::Backtrace, borrow::Cow, fmt::Display};

use serde::{Deserialize, Serialize};
use snafu::Snafu;

use crate::{crypto::rc4::Rc4, error::OverflowError, util::slice::SliceExt as _};

struct DsProtVersion {
    number: DsProtVersionNumber,
    detect_signature: [u32; 6],
    algo: &'static dyn DsProtAlgo,
}

/// Represents all known versions of DS Protect
#[derive(Serialize, Deserialize, Clone, Copy, derive_more::Display, PartialEq, Eq, Debug)]
pub enum DsProtVersionNumber {
    /// 1.00 or 1.02
    #[serde(rename = "1.00")]
    #[display("1.00")]
    V1_00,
    /// 1.05
    #[serde(rename = "1.05")]
    #[display("1.05")]
    V1_05,
    /// 1.06
    #[serde(rename = "1.06")]
    #[display("1.06")]
    V1_06,
    /// 1.08
    #[serde(rename = "1.08")]
    #[display("1.08")]
    V1_08,
    /// 1.10
    #[serde(rename = "1.10")]
    #[display("1.10")]
    V1_10,
    /// 1.20
    #[serde(rename = "1.20")]
    #[display("1.20")]
    V1_20,
    /// 1.22
    #[serde(rename = "1.22")]
    #[display("1.22")]
    V1_22,
    /// 1.23
    #[serde(rename = "1.23")]
    #[display("1.23")]
    V1_23,
    /// 1.23z
    #[serde(rename = "1.23z")]
    #[display("1.23z")]
    V1_23Z,
    /// 1.25
    #[serde(rename = "1.25")]
    #[display("1.25")]
    V1_25,
    /// 1.26
    #[serde(rename = "1.26")]
    #[display("1.26")]
    V1_26,
    /// 1.27
    #[serde(rename = "1.27")]
    #[display("1.27")]
    V1_27,
    /// 1.28
    #[serde(rename = "1.28")]
    #[display("1.28")]
    V1_28,
    /// 2.00
    #[serde(rename = "2.00")]
    #[display("2.00")]
    V2_00,
    /// 2.00 Instant
    #[serde(rename = "2.00 Instant")]
    #[display("2.00 Instant")]
    V2_00Instant,
    /// 2.01
    #[serde(rename = "2.01")]
    #[display("2.01")]
    V2_01,
    /// 2.01 Instant
    #[serde(rename = "2.01 Instant")]
    #[display("2.01 Instant")]
    V2_01Instant,
    /// 2.03
    #[serde(rename = "2.03")]
    #[display("2.03")]
    V2_03,
    /// 2.03 Instant
    #[serde(rename = "2.03 Instant")]
    #[display("2.03 Instant")]
    V2_03Instant,
    /// 2.05
    #[serde(rename = "2.05")]
    #[display("2.05")]
    V2_05,
    /// 2.05 Instant
    #[serde(rename = "2.05 Instant")]
    #[display("2.05 Instant")]
    V2_05Instant,
}

const DSPROT_VERSIONS: &[DsProtVersion] = &[
    DsProtVersion {
        number: DsProtVersionNumber::V1_00,
        detect_signature: [0xe3527270, 0xbafe77fc, 0xe59e0989, 0xe1c2f9af, 0xea018a51, 0xeb004ae2],
        algo: &DsProtAlgoV1 { encrypted_range_start_signature: [0xe92d0001, 0xe1a0000f, 0xe2800010, 0xe8bd0001, 0xea000000] },
    },
    DsProtVersion {
        number: DsProtVersionNumber::V1_05,
        detect_signature: [0xbafe0f18, 0xe59caf7a, 0xe2861884, 0xe1c5da54, 0xea018a6b, 0xeb0070c2],
        algo: &DsProtAlgoV1 { encrypted_range_start_signature: [0xe92d0001, 0xe3a0000c, 0xe080000f, 0xe8bd0001, 0xea000000] },
    },
    DsProtVersion {
        number: DsProtVersionNumber::V1_06,
        detect_signature: [0xbafe9b10, 0xe59cfa77, 0xe2862a71, 0xe1c54e3d, 0xea01879d, 0xeb005fdf],
        algo: &DsProtAlgoV1 { encrypted_range_start_signature: [0xe92d000f, 0xe3a0100c, 0xe081000f, 0xe8bd000f, 0xea000000] },
    },
    DsProtVersion {
        number: DsProtVersionNumber::V1_08,
        detect_signature: [0xbafe4040, 0xe59c2300, 0xe2852226, 0xe1c5cbe8, 0xea01612f, 0xeb004979],
        algo: &DsProtAlgoV1 { encrypted_range_start_signature: [0xe92d00ff, 0xe1a0000f, 0xe2800010, 0xe8bd00ff, 0xea000000] },
    },
    DsProtVersion {
        number: DsProtVersionNumber::V1_10,
        detect_signature: [0xbafe29a2, 0xe59cc95b, 0xe285d70a, 0xe1c5442c, 0xea01fd7e, 0xeb001cfc],
        algo: &DsProtAlgoV1 { encrypted_range_start_signature: [0xe92d00ff, 0xe3a00006, 0xe08f0080, 0xe8bd00ff, 0xea000000] },
    },
    DsProtVersion {
        number: DsProtVersionNumber::V1_20,
        detect_signature: [0xe3580f00, 0xbafe7df8, 0xe284dff9, 0xe1c2059d, 0xea014de4, 0xeb002f0c],
        algo: &DsProtAlgoV1 { encrypted_range_start_signature: [0xe92d03ff, 0xe3a00006, 0xe08f0080, 0xe8bd03ff, 0xea000000] },
    },
    DsProtVersion {
        number: DsProtVersionNumber::V1_22,
        detect_signature: [0xe3581567, 0xbafee339, 0xe284dad2, 0xe1c27622, 0xea017231, 0xeb0037ee],
        algo: &DsProtAlgoV1 { encrypted_range_start_signature: [0xe92d03ff, 0xe3a00003, 0xe08f0100, 0xe8bd03ff, 0xea000000] },
    },
    DsProtVersion {
        number: DsProtVersionNumber::V1_23,
        detect_signature: [0xebaa0113, 0xe4064ec7, 0xef013596, 0xe5212f83, 0xe7ee335b, 0xe83b197c],
        algo: &DsProtAlgoV2 { reference_offset: 0x1300, unkeyed_encryption_xor: 0xf0566556 },
    },
    DsProtVersion {
        number: DsProtVersionNumber::V1_23Z,
        detect_signature: [0xebaa0114, 0x40064eb7, 0x5f013696, 0xe5211f83, 0xe7ef335b, 0xe84b197c],
        algo: &DsProtAlgoV2 { reference_offset: 0x1400, unkeyed_encryption_xor: 0xd0685665 },
    },
    DsProtVersion {
        number: DsProtVersionNumber::V1_25,
        detect_signature: [0xebb6df66, 0xe42f6211, 0xef56b5aa, 0xe5b903fd, 0xe7d29154, 0xe859697c],
        algo: &DsProtAlgoV3 { reference_offset: 0x1500, unkeyed_encryption_xor: 0xf0556655 },
    },
    DsProtVersion {
        number: DsProtVersionNumber::V1_26,
        detect_signature: [0xeb8fbc31, 0xe4ec10cf, 0xef73e592, 0xe59a0b7e, 0xe78cb309, 0xe87f3ed1],
        algo: &DsProtAlgoV4 { reference_offset: 0x1200, unkeyed_encryption_xor: 0xf03852cb },
    },
    DsProtVersion {
        number: DsProtVersionNumber::V1_27,
        detect_signature: [0xe8dffe17, 0xe43df0de, 0x2ae8335c, 0x0ac09826, 0xe7a838dc, 0xe891a6fc],
        algo: &DsProtAlgoV4 { reference_offset: 0x1600, unkeyed_encryption_xor: 0xf0618c46 },
    },
    DsProtVersion {
        number: DsProtVersionNumber::V1_28,
        detect_signature: [0xe2ed720b, 0xef69d1b1, 0x2ec32a41, 0x1aa3e665, 0xe9e1c153, 0xe49e8d9c],
        algo: &DsProtAlgoV4 { reference_offset: 0x1000, unkeyed_encryption_xor: 0xf0b9a2ea },
    },
    DsProtVersion {
        number: DsProtVersionNumber::V2_00,
        detect_signature: [0x0819ff33, 0xe4a1ef1c, 0x5a85a2b3, 0xea0d2a0f, 0xe0d6bd78, 0xe29d9377],
        algo: &DsProtAlgoV5 { reference_offset: 0x1700, unkeyed_encryption_xor: 0xa5ca49b3 },
    },
    DsProtVersion {
        number: DsProtVersionNumber::V2_00Instant,
        detect_signature: [0x0849ea8b, 0xe33b6243, 0x53b2d501, 0xe6847168, 0xebd886d7, 0xee3c09c0],
        algo: &DsProtAlgoV5 { reference_offset: 0x1700, unkeyed_encryption_xor: 0xa5ca49b3 },
    },
    DsProtVersion {
        number: DsProtVersionNumber::V2_01,
        detect_signature: [0x08d5310e, 0xe41bdb46, 0x5a3d9627, 0xeaf8fc79, 0xe016c9e7, 0xe2eb8130],
        algo: &DsProtAlgoV5 { reference_offset: 0x2100, unkeyed_encryption_xor: 0x7fec9df1 },
    },
    DsProtVersion {
        number: DsProtVersionNumber::V2_01Instant,
        detect_signature: [0x08637dd1, 0xe3618cb3, 0x5356f520, 0xe6b110ca, 0xeb4c1e5c, 0xeed91028],
        algo: &DsProtAlgoV5 { reference_offset: 0x2100, unkeyed_encryption_xor: 0x7fec9df1 },
    },
    DsProtVersion {
        number: DsProtVersionNumber::V2_03,
        detect_signature: [0x08b76046, 0xe4177f2f, 0x5ab21c99, 0xea2af4b1, 0xe0fe885a, 0xe202fc9e],
        algo: &DsProtAlgoV6 {
            reference_offset: 0x3200,
            unkeyed_encryption_xor: 0x0976afcc,
            precalculated_seed_key: 0xfa8fd0ea,
            decrypt_opcode: |curr, prev| curr ^ prev,
            encrypt_opcode: |curr, prev| curr ^ prev,
        },
    },
    DsProtVersion {
        number: DsProtVersionNumber::V2_03Instant,
        detect_signature: [0x08b76046, 0xe4177f2f, 0x5ab21c99, 0xea2af4b1, 0xe0fe885a, 0xe2029efc],
        algo: &DsProtAlgoV6 {
            reference_offset: 0x3200,
            unkeyed_encryption_xor: 0x0976afcc,
            precalculated_seed_key: 0xfa8fd0ea,
            decrypt_opcode: |curr, prev| curr ^ prev,
            encrypt_opcode: |curr, prev| curr ^ prev,
        },
    },
    DsProtVersion {
        number: DsProtVersionNumber::V2_05,
        detect_signature: [0x08a27510, 0xe47ab3c3, 0x5a289302, 0xeaa6cac8, 0xe00d75d5, 0xe2d2fe01],
        algo: &DsProtAlgoV6 {
            reference_offset: 0x2200,
            unkeyed_encryption_xor: 0x0a471abb,
            precalculated_seed_key: 0x89ede4ea,
            decrypt_opcode: |curr, prev| curr.wrapping_sub(prev),
            encrypt_opcode: |curr, prev| curr.wrapping_add(prev),
        },
    },
    DsProtVersion {
        number: DsProtVersionNumber::V2_05Instant,
        detect_signature: [0x08a27510, 0xe47ab3c3, 0x5a289302, 0xeaa6cac8, 0xe00d75d5, 0xe2d2fe00],
        algo: &DsProtAlgoV6 {
            reference_offset: 0x2200,
            unkeyed_encryption_xor: 0x0a471abb,
            precalculated_seed_key: 0x89ede4ea,
            decrypt_opcode: |curr, prev| curr.wrapping_sub(prev),
            encrypt_opcode: |curr, prev| curr.wrapping_add(prev),
        },
    },
];

/// Contains information about DS Protect usage.
pub struct DsProtInfo {
    version: &'static DsProtVersion,
}

/// Errors related to [`DsProtInfo`].
#[derive(Debug, Snafu)]
pub enum DsProtError {
    /// Occurs when trying to access data outside the given module's code.
    #[snafu(display("{what} {address:#010x} is out of bounds {base_address:#010x}..{end_address:#010x}:\n{backtrace}"))]
    OutOfBounds {
        /// What is being accessed.
        what: &'static str,
        /// The address being accessed.
        address: u32,
        /// The module's base address.
        base_address: u32,
        /// The module's end address.
        end_address: u32,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// Occurs when trying to access data outside the given module's code.
    #[snafu(display(
        "{what} {start:#010x}..{end:#010x} is out of bounds {base_address:#010x}..{end_address:#010x}:\n{backtrace}"
    ))]
    RangeOutOfBounds {
        /// What is being accessed.
        what: &'static str,
        /// The start of the address range being accessed.
        start: u32,
        /// The end of the address range being accessed.
        end: u32,
        /// The module's base address.
        base_address: u32,
        /// The module's end address.
        end_address: u32,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// Occurs when the DS Protect .bss variable address was not found.
    #[snafu(display("failed to find .bss variable address for DS Protect"))]
    BssNotFound {
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// Occurs when failing to find the start of a function table decoder with children.
    #[snafu(display("failed to find start of parent function table decoder near {near_address:#010x}"))]
    TableDecoderStartNotFound {
        /// The approximate location of the table decoder.
        near_address: u32,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// Occurs when failing to find the end of a decoder's function table.
    #[snafu(display("failed to find end of function table for decoder at {decoder_address:#010x}"))]
    DecoderTableEndNotFound {
        /// The address of the decoder function.
        decoder_address: u32,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// Occurs when failing to find the instruction overwrite address for a primary decoder funciton.
    #[snafu(display("failed to find the instruction overwrite address for primary decoder at {decoder_address:#010x}"))]
    DecoderOverwriteAddressNotFound {
        /// The address of the decoder function.
        decoder_address: u32,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// See [`OverflowError`].
    #[snafu(transparent)]
    Overflow {
        /// Source error.
        source: OverflowError,
    },
}

/// Options for [`DsProtInfo::decrypt`].
#[derive(Clone, Default)]
pub struct DsProtDecryptOptions {
    /// If true, pointers and constants will be decoded. This applies to constant pools and global
    /// variables managed by DS Protect.
    pub decode_relocations: bool,
}

/// Options for [`DsProtDecryptResult::encrypt`].
#[derive(Clone, Default)]
pub struct DsProtEncryptOptions {
    /// If true, pointers and constants will be decoded. This applies to constant pools and global
    /// variables managed by DS Protect.
    pub encode_relocations: bool,
}

impl DsProtInfo {
    /// Searches for DS Protect usage in the provided module.
    pub fn detect(data: &[u8]) -> Option<Self> {
        // Make 32-bit chunks
        let (chunks, _) = data.as_chunks::<4>();
        let words: Cow<[u32]> = match bytemuck::try_cast_slice(chunks) {
            Ok(words) => Cow::Borrowed(words),
            Err(_) => Cow::Owned(chunks.iter().map(|chunk| u32::from_ne_bytes(*chunk)).collect()),
        };

        for version in DSPROT_VERSIONS {
            // Identify if DS Protect might exist
            if !words.array_windows::<6>().any(|window| window == &version.detect_signature) {
                continue;
            }

            return Some(Self { version });
        }
        None
    }

    /// Decrypts the given module's code.
    ///
    /// # Errors
    ///
    /// This function will return an error if it accesses data out of bounds. This happens if the
    /// wrong data is passed, or due to a bug in this function.
    pub(crate) fn decrypt(
        &self,
        data: &mut [u8],
        base_address: u32,
        options: &DsProtDecryptOptions,
    ) -> Result<DsProtDecryptResult, DsProtError> {
        with_words_mut(data, |words| {
            let end_address = module_end_address(base_address, words)?;
            let DsProtDecryptOptions { decode_relocations } = options.clone();
            self.version.algo.decrypt(words, &AlgoDecryptOptions {
                base_address,
                end_address,
                version: self.version.number,
                decode_relocations,
            })
        })
    }

    /// Creates a [`DisplayDsProtInfo`] which implements [`Display`].
    pub fn display(&self, indent: usize) -> DisplayDsProtInfo<'_> {
        DisplayDsProtInfo { info: self, indent }
    }
}

#[derive(PartialEq, Eq)]
enum InstructionCategory {
    Other,
    BlxImm,
    Bl,
    B,
}

impl InstructionCategory {
    fn new(instruction: u32) -> Self {
        let opcode = instruction >> 24;
        if (opcode & 0x0e) != 0x0a {
            Self::Other
        } else if (opcode & 0xf0) == 0xf0 {
            Self::BlxImm
        } else if (opcode & 0x01) != 0 {
            Self::Bl
        } else {
            Self::B
        }
    }
}

/// Can be used to display values inside [`DsProtInfo`].
pub struct DisplayDsProtInfo<'a> {
    info: &'a DsProtInfo,
    indent: usize,
}

impl Display for DisplayDsProtInfo<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let i = " ".repeat(self.indent);
        let info = &self.info;
        writeln!(f, "{i}Version number .......... : {}", info.version.number)?;
        Ok(())
    }
}

struct AlgoDecryptOptions {
    base_address: u32,
    end_address: u32,
    version: DsProtVersionNumber,
    decode_relocations: bool,
}

struct AlgoEncryptOptions {
    base_address: u32,
    end_address: u32,
    encode_relocations: bool,
}

const DECRYPTION_WRAPPER_SIGNATURE_1: [u32; 3] = [0xe92d00f0, 0xe92d000f, 0xe8bd00f0];
const DECRYPTION_WRAPPER_SIGNATURE_2: [u32; 4] = [0xe18fc00f, 0xe01cc00c, 0x03a0c000, 0x128cc01c];
const DECRYPTION_WRAPPER_SIGNATURE_3: [u32; 4] = [0xe18fc00f, 0xe01cc00c, 0x03a0c000, 0x128cc068];
const DECRYPTION_WRAPPER_SIGNATURE_4: [u32; 4] = [0xe18fc00f, 0xe01cc00c, 0x03a0c000, 0x128cc08c];

trait DsProtAlgo {
    fn reference_offset(&self) -> u32;
    fn unkeyed_encryption_xor(&self) -> u32;
    fn unkeyed_encrypt_instruction(&self, ins: u32, xor: u32) -> (u32, u32);
    fn unkeyed_decrypt_instruction(&self, ins: u32, xor: u32) -> (u32, u32);
    fn decrypt_instruction(&self, rc4: &mut Rc4, ins: u32, prev_ins: u32) -> u32;
    fn encrypt_instruction(&self, rc4: &mut Rc4, ins: u32, prev_ins: u32) -> u32;
    fn precalculated_seed_key(&self) -> Option<u32> {
        None
    }
    fn init_rc4(&self, seed_key: u32, func_size: u32) -> Rc4;

    // The below default implementations are for version 1.23 onwards (DsProtAlgoV2 and up), as
    // the de/encryption procedure for those versions are essentially identical aside from the bit
    // twiddling.

    fn decrypt(&self, words: &mut [u32], options: &AlgoDecryptOptions) -> Result<DsProtDecryptResult, DsProtError> {
        let dsprot_bss = self.find_bss_variable(words, options)?;
        let mut functions = self.find_obfuscated_function_tables(options, words)?;
        let mut relocations = Vec::new();
        let mut unkeyed_encrypted_functions =
            self.decode_function_tables(options, words, dsprot_bss, &functions, &mut relocations)?;
        let mut keyed_encrypted_functions =
            self.unkeyed_decrypt_functions(options, words, dsprot_bss, &mut unkeyed_encrypted_functions, &mut relocations)?;
        self.decrypt_wrappers(options, words, &mut keyed_encrypted_functions, &mut relocations)?;

        relocations.sort_unstable_by_key(|r| r.from_address);
        relocations.dedup_by_key(|r| r.from_address);

        if options.decode_relocations {
            self.decode_relocations(options, words, &relocations)?;
        }

        functions.append(&mut unkeyed_encrypted_functions);
        functions.append(&mut keyed_encrypted_functions);
        functions.sort_unstable_by_key(|f| f.address);

        Ok(DsProtDecryptResult {
            version: options.version,
            encrypted_ranges: Vec::new(),
            bss_variable: Some(dsprot_bss),
            functions,
            relocations,
        })
    }

    fn encrypt(
        &self,
        words: &mut [u32],
        decrypt_result: &DsProtDecryptResult,
        options: &AlgoEncryptOptions,
    ) -> Result<(), DsProtError> {
        // Encrypt whole functions
        for function in &decrypt_result.functions {
            let start_offset = function.offset(options.base_address)? / 4;
            let end_offset = function.end_offset(options.base_address)? / 4;
            let function_end_address = function.end_address()?;
            let instructions = words.get_mut(start_offset..end_offset).ok_or_else(|| {
                RangeOutOfBoundsSnafu {
                    what: "function to encrypt",
                    start: function.address,
                    end: function_end_address,
                    base_address: options.base_address,
                    end_address: options.end_address,
                }
                .build()
            })?;
            match function.encryption {
                EncryptionType::None => continue,
                EncryptionType::Unkeyed => {
                    let mut xor = self.unkeyed_encryption_xor();
                    for ins in instructions {
                        let (new_ins, new_xor) = self.unkeyed_encrypt_instruction(*ins, xor);
                        *ins = new_ins;
                        xor = new_xor;
                    }
                }
                EncryptionType::Keyed(seed_key) => {
                    let mut rc4 = self.init_rc4(seed_key, function.size);
                    let mut prev_ins = 0;
                    for ins in instructions {
                        *ins = self.encrypt_instruction(&mut rc4, *ins, prev_ins);
                        prev_ins = *ins;
                    }
                }
            }
        }

        // Encrypt function ranges
        for range in &decrypt_result.encrypted_ranges {
            let start_offset = range.start_offset(options.base_address)? / 4;
            let end_offset = range.end_offset(options.base_address)? / 4;
            let instructions = words.get_mut(start_offset..end_offset).ok_or_else(|| {
                RangeOutOfBoundsSnafu {
                    what: "range to encrypt",
                    start: range.start_address,
                    end: range.end_address,
                    base_address: options.base_address,
                    end_address: options.end_address,
                }
                .build()
            })?;
            let mut rc4 = self.init_rc4(range.seed_key, range.size()?);
            let mut prev_ins = 0;
            for ins in instructions {
                *ins = self.encrypt_instruction(&mut rc4, *ins, prev_ins);
                prev_ins = *ins;
            }
        }

        // Encode relocations
        if options.encode_relocations {
            for relocation in &decrypt_result.relocations {
                let Some(relocated_value) = words.get_mut(relocation.from_offset(options.base_address)? / 4) else {
                    return OutOfBoundsSnafu {
                        what: "relocation",
                        address: relocation.from_address,
                        base_address: options.base_address,
                        end_address: options.end_address,
                    }
                    .fail();
                };
                *relocated_value = relocated_value.wrapping_add(relocation.addend);
            }
        }

        Ok(())
    }

    fn find_bss_variable(&self, words: &[u32], options: &AlgoDecryptOptions) -> Result<u32, DsProtError> {
        let AlgoDecryptOptions { base_address, .. } = *options;

        let mut signature_1 = DECRYPTION_WRAPPER_SIGNATURE_1;
        let mut signature_2 = DECRYPTION_WRAPPER_SIGNATURE_2;
        let mut signature_3 = DECRYPTION_WRAPPER_SIGNATURE_3;
        let mut signature_4 = DECRYPTION_WRAPPER_SIGNATURE_4;
        let signature_1 = self.unkeyed_encrypt_decryption_wrapper(&mut signature_1);
        let signature_2 = self.unkeyed_encrypt_decryption_wrapper(&mut signature_2);
        let signature_3 = self.unkeyed_encrypt_decryption_wrapper(&mut signature_3);
        let signature_4 = self.unkeyed_encrypt_decryption_wrapper(&mut signature_4);

        for (i, window) in words.array_windows::<4>().enumerate() {
            let func_size = if &window[0..3] == signature_1 {
                0x68
            } else if window == signature_2 {
                0x24
            } else if window == signature_3 {
                0x70
            } else if window == signature_4 {
                0x94
            } else {
                continue;
            };
            let Some(offset) = (i as u32).checked_mul(4) else {
                break;
            };
            let Some(decryption_wrapper_address) = base_address.checked_add(offset) else {
                break;
            };
            let Some(pool_address) = decryption_wrapper_address.checked_add(func_size) else {
                continue;
            };

            #[allow(clippy::arithmetic_side_effects)] // pool_address is always greater than base_address
            let pool_offset = (pool_address - base_address) as usize / 4;
            let Some(bss) = words.get(pool_offset).and_then(|word| word.checked_sub(1)) else {
                continue;
            };
            log::debug!(
                "Found BSS variable address at {:#010x} from decryption wrapper at {:#010x}",
                bss,
                decryption_wrapper_address
            );

            return Ok(bss);
        }

        BssNotFoundSnafu.fail()
    }

    fn unkeyed_encrypt_decryption_wrapper<'a>(&self, signature: &'a mut [u32]) -> &'a [u32] {
        let mut xor = self.unkeyed_encryption_xor();
        for ins in signature.iter_mut() {
            let (new_ins, new_xor) = self.unkeyed_encrypt_instruction(*ins, xor);
            *ins = new_ins;
            xor = new_xor;
        }
        signature
    }

    fn find_obfuscated_function_tables(
        &self,
        options: &AlgoDecryptOptions,
        words: &[u32],
    ) -> Result<Vec<DsProtFunction>, DsProtError> {
        let AlgoDecryptOptions { base_address, .. } = *options;

        let mut function_tables = Vec::new();
        for (i, window) in words.array_windows::<4>().enumerate() {
            let Some(offset) = (i as u32).checked_mul(4) else {
                break;
            };
            let Some(address) = base_address.checked_add(offset) else {
                break;
            };
            let (pool_offset, fn_offset, primary_decoder) =
                if window[0..2] == [0xe38f0000, 0xe2900004] && window[2] >> 24 == 0x1a {
                    #[allow(clippy::indexing_slicing)] // i is always less than words.len()
                    #[allow(clippy::arithmetic_side_effects)] // i is always at least 1
                    let (fn_offset, primary_decoder) = if i >= 1 && words[i - 1] == 0xe8a007fe {
                        let fn_offset = words[..=i]
                            .iter()
                            .rev()
                            .position(|&word| word == 0xe92d4000)
                            .ok_or_else(|| TableDecoderStartNotFoundSnafu { near_address: address }.build())?
                            as u32;
                        (fn_offset * 4, true)
                    } else {
                        (0, false)
                    };
                    (0xc, fn_offset, primary_decoder)
                } else if window[0..2] == [0xe92d4000, 0xe28f0004] && window[2] >> 24 == 0xeb && window[3] == 0xe8bd8000 {
                    (0x10, 0, false)
                } else {
                    continue;
                };

            let Some(fn_address) = address.checked_sub(fn_offset) else {
                continue;
            };
            let Some(fn_size) = fn_offset.checked_add(pool_offset) else {
                continue;
            };

            let Some(pool_address) = address.checked_add(pool_offset) else {
                continue;
            };
            #[allow(clippy::arithmetic_side_effects)] // pool_address is always greater than base_address
            let pool_position = (pool_address - base_address) as usize / 4;
            let Some(pool_words) = words.get(pool_position..) else {
                continue;
            };
            let mut pool_iter = pool_words.iter().copied().enumerate();
            let pool_end_offset = loop {
                let Some((j, word)) = pool_iter.next() else {
                    return DecoderTableEndNotFoundSnafu { decoder_address: fn_address }.fail();
                };
                if word == 0
                    && let Some((_, 0)) = pool_iter.next()
                {
                    let Some(pool_offset) = (j as u32).checked_mul(4) else {
                        continue;
                    };
                    break pool_offset;
                }
            };
            let Some(table_end_address) = pool_address.checked_add(pool_end_offset).and_then(|x| x.checked_add(8)) else {
                continue;
            };

            #[allow(clippy::arithmetic_side_effects)] // table_end_address is always greater than base_address
            let table_end_offset = (table_end_address - base_address) as usize / 4;

            // Get up to 2 trailing addresses after the decoded function table
            let trailing_address_1 = words.get(table_end_offset).copied().filter(|&addr| addr >> 24 == 0x02);
            let trailing_address_2 = if trailing_address_1.is_some()
                && let Some(second_offset) = table_end_offset.checked_add(4)
            {
                words.get(second_offset).copied().filter(|&addr| addr >> 24 == 0x02)
            } else {
                None
            };

            let (garbage_address, overwrite_address) = match (primary_decoder, trailing_address_1, trailing_address_2) {
                // No trailing addresses
                (_, None, None) => (None, None),
                // Unreachable, second trailing address is always None if first trailing address is None
                (_, None, Some(_)) => (None, None),
                // Not primary but has a garbage address
                (false, Some(garbage_address), _) => {
                    if garbage_address.saturating_sub(self.reference_offset()) > address {
                        // Points to .data which is always after .text
                        (Some(garbage_address), None)
                    } else {
                        // Points to .text, so this must be a different unrelated pointer
                        (None, None)
                    }
                }
                // Primary without garbage address
                (true, Some(overwrite_address), None) => (None, Some(overwrite_address)),
                // Primary with garbage address
                (true, Some(garbage_address), Some(overwrite_address)) => {
                    if garbage_address.saturating_sub(self.reference_offset()) > address {
                        // Points to .data which is always after .text
                        (Some(garbage_address), Some(overwrite_address))
                    } else {
                        // Points to .text, so this must be a different unrelated pointer
                        (None, None)
                    }
                }
            };

            // Primary decoder always overwrites itself after it runs
            if primary_decoder && overwrite_address.is_none() {
                return DecoderOverwriteAddressNotFoundSnafu { decoder_address: fn_address }.fail();
            }

            #[allow(clippy::arithmetic_side_effects)] // table_end_address is always greater than pool_address
            let length = (table_end_address - pool_address) / 8;
            let has_garbage = garbage_address.is_some();
            let has_overwrite = overwrite_address.is_some();

            function_tables.push(DsProtFunction {
                address: fn_address,
                size: fn_size,
                // has_overwrite is 8 bytes because 4 bytes for overwrite address and 4 bytes for
                // return instruction literal (0xe12fff1e <bx lr>)
                #[allow(clippy::arithmetic_side_effects)] // small number
                pool_size: Some(length * 8 + has_garbage as u32 * 4 + has_overwrite as u32 * 8),
                encryption: EncryptionType::None,
                function_table: Some(FunctionTable { length, has_garbage, has_overwrite }),
            });
        }

        Ok(function_tables)
    }

    fn unkeyed_decrypt_functions(
        &self,
        options: &AlgoDecryptOptions,
        words: &mut [u32],
        dsprot_bss: u32,
        unkeyed_encrypted_functions: &mut [DsProtFunction],
        relocations: &mut Vec<DsProtRelocation>,
    ) -> Result<Vec<DsProtFunction>, DsProtError> {
        let AlgoDecryptOptions { base_address, end_address, .. } = *options;

        let mut decryption_wrappers = Vec::new();
        for function in unkeyed_encrypted_functions {
            let EncryptionType::Unkeyed = function.encryption else { continue };

            let func_offset = function.offset(options.base_address)? / 4;
            let func_end_offset = function.end_offset(options.base_address)? / 4;
            let function_end_address = function.end_address()?;

            let Some(func_words) = words.get_mut(func_offset..func_end_offset) else {
                return RangeOutOfBoundsSnafu {
                    what: "unkeyed encrypted function",
                    start: function.address,
                    end: function_end_address,
                    base_address,
                    end_address,
                }
                .fail();
            };
            let func_words: &mut [u32] = func_words;

            let mut xor_value = self.unkeyed_encryption_xor();

            log::debug!("Decrypting function at {:#010x} with size {:#x}", function.address, function.size);

            for instruction in func_words.iter_mut() {
                let (new_instruction, new_xor_value) = self.unkeyed_decrypt_instruction(*instruction, xor_value);
                *instruction = new_instruction;
                xor_value = new_xor_value;
            }

            let reference_offset = self.reference_offset();

            if func_words.starts_with(&DECRYPTION_WRAPPER_SIGNATURE_1) {
                let pool_words = get_constant_pool::<5>(base_address, end_address, words, function)?;

                let bss = pool_words[0].wrapping_sub(1);
                debug_assert_eq!(bss, dsprot_bss);
                let dest_func_size = pool_words[1].wrapping_sub(dsprot_bss).wrapping_sub(reference_offset);
                let seed_key = pool_words[2].wrapping_sub(dsprot_bss).wrapping_sub(reference_offset);
                let dest_func_address = pool_words[3].wrapping_sub(reference_offset);
                let garbage_address = pool_words[4].wrapping_sub(reference_offset);

                // Check that this looks like a RAM address
                let has_garbage = garbage_address >> 24 == 0x02;

                // BSS + 1
                relocations.push(DsProtRelocation { from_address: function_end_address, to_address: dsprot_bss, addend: 1 });
                // Destination function size
                relocations.push(DsProtRelocation {
                    from_address: function_end_address.wrapping_add(0x4),
                    to_address: dsprot_bss,
                    addend: dest_func_size.wrapping_add(reference_offset),
                });
                // Seed key
                relocations.push(DsProtRelocation {
                    from_address: function_end_address.wrapping_add(0x8),
                    to_address: dsprot_bss,
                    addend: seed_key.wrapping_add(reference_offset),
                });
                // Destination function address
                relocations.push(DsProtRelocation {
                    from_address: function_end_address.wrapping_add(0xc),
                    to_address: dest_func_address,
                    addend: reference_offset,
                });
                if has_garbage {
                    // Pointer to garbage code
                    relocations.push(DsProtRelocation {
                        from_address: function_end_address.wrapping_add(0x10),
                        to_address: garbage_address,
                        addend: reference_offset,
                    });
                }
                #[allow(clippy::arithmetic_side_effects)] // small number
                {
                    function.pool_size = Some(0x10 + has_garbage as u32 * 4);
                }

                log::debug!(
                    "Found decryption wrapper (type 1) at {:#010x} which targets {:#010x}",
                    function.address,
                    dest_func_address
                );
                decryption_wrappers.push(DsProtFunction {
                    address: dest_func_address,
                    size: dest_func_size,
                    pool_size: None,
                    encryption: EncryptionType::Keyed(seed_key),
                    function_table: None,
                });
            } else if func_words.starts_with(&DECRYPTION_WRAPPER_SIGNATURE_2) {
                let pool_words = get_constant_pool::<7>(base_address, end_address, words, function)?;

                let bss = pool_words[0].wrapping_sub(1);
                debug_assert_eq!(bss, dsprot_bss);
                let seed_key = pool_words[1].wrapping_sub(dsprot_bss).wrapping_sub(reference_offset);
                let dest_func_address = pool_words[2].wrapping_sub(reference_offset);
                let dest_func_size = pool_words[3].wrapping_sub(dsprot_bss).wrapping_sub(reference_offset);
                let wrapper_fragment = pool_words[5].wrapping_sub(reference_offset);
                let garbage_address = pool_words[6].wrapping_sub(reference_offset);

                // Check that this looks like a RAM address
                let has_garbage = garbage_address >> 24 == 0x02;

                // BSS + 1
                relocations.push(DsProtRelocation { from_address: function_end_address, to_address: dsprot_bss, addend: 1 });
                // Seed key
                relocations.push(DsProtRelocation {
                    from_address: function_end_address.wrapping_add(0x4),
                    to_address: dsprot_bss,
                    addend: seed_key.wrapping_add(reference_offset),
                });
                // Destination function address
                relocations.push(DsProtRelocation {
                    from_address: function_end_address.wrapping_add(0x8),
                    to_address: dest_func_address,
                    addend: reference_offset,
                });
                // Destination function size
                relocations.push(DsProtRelocation {
                    from_address: function_end_address.wrapping_add(0xc),
                    to_address: dsprot_bss,
                    addend: dest_func_size.wrapping_add(reference_offset),
                });
                // Decryption wrapper fragment address
                relocations.push(DsProtRelocation {
                    from_address: function_end_address.wrapping_add(0x14),
                    to_address: wrapper_fragment,
                    addend: reference_offset,
                });
                if has_garbage {
                    // Pointer to garbage code
                    relocations.push(DsProtRelocation {
                        from_address: function_end_address.wrapping_add(0x18),
                        to_address: garbage_address,
                        addend: reference_offset,
                    });
                }
                #[allow(clippy::arithmetic_side_effects)] // small number
                {
                    function.pool_size = Some(0x18 + has_garbage as u32 * 4);
                }

                log::debug!(
                    "Found decryption wrapper (type 2) at {:#010x} which targets {:#010x}",
                    function.address,
                    dest_func_address
                );
                decryption_wrappers.push(DsProtFunction {
                    address: dest_func_address,
                    size: dest_func_size,
                    pool_size: None,
                    encryption: EncryptionType::Keyed(seed_key),
                    function_table: None,
                });
            } else if func_words.starts_with(&DECRYPTION_WRAPPER_SIGNATURE_3)
                || func_words.starts_with(&DECRYPTION_WRAPPER_SIGNATURE_4)
            {
                let pool_words = get_constant_pool::<7>(base_address, end_address, words, function)?;

                let bss = pool_words[0].wrapping_sub(1);
                debug_assert_eq!(bss, dsprot_bss);
                let dest_func_address = pool_words[2].wrapping_sub(reference_offset);
                let dest_func_size = pool_words[3].wrapping_sub(dsprot_bss).wrapping_sub(reference_offset);
                let wrapper_fragment = pool_words[5] & 0x03ffffff;
                let garbage_address = pool_words[6].wrapping_sub(reference_offset);

                #[allow(clippy::arithmetic_side_effects)] // small number
                let wrapper_fragment_size = (pool_words[5] >> 26) * 4;

                // Check that this looks like a RAM address
                let has_garbage = garbage_address >> 24 == 0x02;

                // BSS + 1
                relocations.push(DsProtRelocation { from_address: function_end_address, to_address: dsprot_bss, addend: 1 });
                // Seed key placeholder (BSS + 3 initially)
                relocations.push(DsProtRelocation {
                    from_address: function_end_address.wrapping_add(0x4),
                    to_address: dsprot_bss,
                    addend: 3,
                });
                // Destination function address
                relocations.push(DsProtRelocation {
                    from_address: function_end_address.wrapping_add(0x8),
                    to_address: dest_func_address,
                    addend: reference_offset,
                });
                // Destination function size
                relocations.push(DsProtRelocation {
                    from_address: function_end_address.wrapping_add(0xc),
                    to_address: dsprot_bss,
                    addend: dest_func_size.wrapping_add(reference_offset),
                });
                // Decryption wrapper fragment address
                relocations.push(DsProtRelocation {
                    from_address: function_end_address.wrapping_add(0x14),
                    to_address: wrapper_fragment,
                    addend: pool_words[5] & 0xfc000000,
                });
                if has_garbage {
                    // Pointer to garbage code
                    relocations.push(DsProtRelocation {
                        from_address: function_end_address.wrapping_add(0x18),
                        to_address: garbage_address,
                        addend: reference_offset,
                    });
                }
                #[allow(clippy::arithmetic_side_effects)] // small number
                {
                    function.pool_size = Some(0x18 + has_garbage as u32 * 4);
                }

                let seed_key = self.precalculated_seed_key().unwrap_or(0);

                log::debug!(
                    "Found decryption wrapper (type 3) at {:#010x} which targets {:#010x}. \
                    Seed key {:#010x} was derived from function at {:#010x} with size {:#x}",
                    function.address,
                    dest_func_address,
                    seed_key,
                    wrapper_fragment,
                    wrapper_fragment_size,
                );
                decryption_wrappers.push(DsProtFunction {
                    address: dest_func_address,
                    size: dest_func_size,
                    pool_size: None,
                    encryption: EncryptionType::Keyed(seed_key),
                    function_table: None,
                });
            } else if func_words.starts_with(&[0xe92d4070, 0xe24dd010, 0xe59f40ac, 0xe59fc0ac]) {
                // Decryption proxy
                let pool_words = get_constant_pool::<2>(base_address, end_address, words, function)?;
                relocations.push(proxy_relocation(pool_words[1], words, base_address, end_address, reference_offset)?);
                log::debug!("Decrypted decryption proxy function");
            } else if func_words.starts_with(&[0xe92d41f0, 0xe24dd010, 0xe1a05000, 0xe59f00c0]) {
                // Encryption proxy
                let pool_words = get_constant_pool::<1>(base_address, end_address, words, function)?;
                relocations.push(proxy_relocation(pool_words[0], words, base_address, end_address, reference_offset)?);
                log::debug!("Decrypted encryption proxy function");
            } else if func_words.starts_with(&[0xe92d000f, 0xe58ca010, 0xe1a0a00c, 0xe59fc054]) {
                // Decryption wrapper proxy
                let pool_words = get_constant_pool::<2>(base_address, end_address, words, function)?;
                relocations.push(proxy_relocation(pool_words[0], words, base_address, end_address, reference_offset)?);
                relocations.push(proxy_relocation(pool_words[1], words, base_address, end_address, reference_offset)?);
                log::debug!("Decrypted decryption wrapper proxy function");
            } else if func_words.starts_with(&[0xe92d4ff8, 0xe24dd008, 0xe1a0b003, 0xe1a0a000])
                || func_words.starts_with(&[0xe92d4ff8, 0xe24dd010, 0xe1a0a000, 0xe1a00003])
            {
                // RC4 encryptor/decryptor
                let pool_words = get_constant_pool::<1>(base_address, end_address, words, function)?;
                relocations.push(proxy_relocation(pool_words[0], words, base_address, end_address, reference_offset)?);
                relocations.push(proxy_relocation(
                    pool_words[0].wrapping_add(0xc),
                    words,
                    base_address,
                    end_address,
                    reference_offset,
                )?);
                log::debug!("Found RC4 encryptor/decryptor");
            } else if func_words.starts_with(&[0xe92d43f0, 0xe24ddf43, 0xe59f7064, 0xe28d8000]) {
                // RC4 encrypt/decrypt function
                let pool_words = get_constant_pool::<1>(base_address, end_address, words, function)?;
                relocations.push(proxy_relocation(pool_words[0], words, base_address, end_address, reference_offset)?);
                relocations.push(proxy_relocation(
                    pool_words[0].wrapping_add(0x4),
                    words,
                    base_address,
                    end_address,
                    reference_offset,
                )?);
                relocations.push(proxy_relocation(
                    pool_words[0].wrapping_add(0x8),
                    words,
                    base_address,
                    end_address,
                    reference_offset,
                )?);
                relocations.push(proxy_relocation(
                    pool_words[0].wrapping_add(0x10),
                    words,
                    base_address,
                    end_address,
                    reference_offset,
                )?);
                log::debug!("Found RC4 encrypt/decrypt function");
            }
        }
        Ok(decryption_wrappers)
    }

    fn decode_function_tables(
        &self,
        options: &AlgoDecryptOptions,
        words: &mut [u32],
        dsprot_bss: u32,
        function_tables: &[DsProtFunction],
        relocations: &mut Vec<DsProtRelocation>,
    ) -> Result<Vec<DsProtFunction>, DsProtError> {
        let AlgoDecryptOptions { base_address, end_address, .. } = *options;

        let mut functions = Vec::new();
        for function in function_tables {
            let Some(FunctionTable { length, has_garbage, has_overwrite }) = function.function_table else {
                continue;
            };

            let function_table_address = function.end_address()?;

            log::debug!("Obfuscated function table found at {:#010x}", function_table_address);

            let pool_offset = function.end_offset(base_address)? / 4;
            let Some(pool_words) = words.get_mut(pool_offset..) else {
                return OutOfBoundsSnafu {
                    what: "function table",
                    address: function_table_address,
                    base_address,
                    end_address,
                }
                .fail();
            };

            let mut pool_iter = pool_words.iter();
            for i in 0..length {
                let Some(first) = pool_iter.next() else {
                    break;
                };
                let Some(second) = pool_iter.next() else {
                    break;
                };
                if *first == 0 && *second == 0 {
                    break;
                }

                let func_address = (*first).wrapping_sub(self.reference_offset());
                let func_size = (*second).wrapping_sub(dsprot_bss).wrapping_sub(self.reference_offset());
                log::debug!("Found unkeyed encrypted function at {:#010x}, size {:#x}", func_address, func_size);

                // Function address
                #[allow(clippy::arithmetic_side_effects)] // the pool words were found within the module's address range
                relocations.push(DsProtRelocation {
                    from_address: function_table_address + i * 8,
                    to_address: func_address,
                    addend: self.reference_offset(),
                });
                // Function size
                #[allow(clippy::arithmetic_side_effects)] // the pool words were found within the module's address range
                relocations.push(DsProtRelocation {
                    from_address: function_table_address + i * 8 + 4,
                    to_address: dsprot_bss,
                    addend: func_size.wrapping_add(self.reference_offset()),
                });

                functions.push(DsProtFunction {
                    address: func_address,
                    size: func_size,
                    pool_size: None,
                    encryption: EncryptionType::Unkeyed,
                    function_table: None,
                });
            }

            #[allow(clippy::arithmetic_side_effects)] // small number
            let mut current_address = function_table_address + length * 8;
            if has_garbage && let Some(pool_word) = pool_iter.next() {
                let garbage_address = pool_word.wrapping_sub(self.reference_offset());
                relocations.push(DsProtRelocation {
                    from_address: current_address,
                    to_address: garbage_address,
                    addend: self.reference_offset(),
                });
                #[allow(clippy::arithmetic_side_effects)] // small number
                {
                    current_address += 4;
                }
            }
            if has_overwrite && let Some(pool_word) = pool_iter.next() {
                let overwrite_address = pool_word.wrapping_sub(self.reference_offset());
                relocations.push(DsProtRelocation {
                    from_address: current_address,
                    to_address: overwrite_address,
                    addend: self.reference_offset(),
                });
            }
        }
        Ok(functions)
    }

    fn decrypt_wrappers(
        &self,
        options: &AlgoDecryptOptions,
        words: &mut [u32],
        decryption_wrappers: &mut [DsProtFunction],
        relocations: &mut Vec<DsProtRelocation>,
    ) -> Result<(), DsProtError> {
        let AlgoDecryptOptions { base_address, end_address, .. } = *options;

        for function in decryption_wrappers {
            let EncryptionType::Keyed(seed_key) = function.encryption else {
                continue;
            };

            log::debug!(
                "Decrypting function at {:#010x} with size {:#x} using seed key {:#06x}",
                function.address,
                function.size,
                seed_key
            );

            let mut rc4 = self.init_rc4(seed_key, function.size);

            // Decrypt instructions
            let func_offset = function.offset(base_address)? / 4;
            let func_end_offset = function.end_offset(base_address)? / 4;
            let function_end_address = function.end_address()?;
            let Some(func_words) = words.get_mut(func_offset..func_end_offset) else {
                return RangeOutOfBoundsSnafu {
                    what: "encrypted function",
                    start: function.address,
                    end: function_end_address,
                    base_address,
                    end_address,
                }
                .fail();
            };
            let mut prev_ins = 0;
            for instruction in func_words.iter_mut() {
                let ins = *instruction;
                *instruction = self.decrypt_instruction(&mut rc4, ins, prev_ins);
                prev_ins = ins;
            }

            // Decrypt constant pools based on function signature
            let mut func_start = [0; 7];
            let limit = func_start.len().min(func_words.len());
            #[allow(clippy::indexing_slicing)] // limit is not more than both slice's lengths
            func_start[0..limit].copy_from_slice(&func_words[0..limit]);

            let Some(pool_words) = words.get(func_end_offset..) else {
                return OutOfBoundsSnafu {
                    what: "encrypted function constant pool",
                    address: function_end_address,
                    base_address,
                    end_address,
                }
                .fail();
            };

            let reference_offset = self.reference_offset();

            if (func_start.starts_with(&[0xe92d4ff8, 0xe24dd080, 0xe59f209c, 0xe59f109c])
                || func_start.starts_with(&[0xe92d41f0, 0xe24dd080, 0xe59f3080, 0xe59f2080])
                || func_start.starts_with(&[0xe92d41f0, 0xe24dd080, 0xe59f308c, 0xe59f208c])
                || func_start.starts_with(&[0xe92d41f0, 0xe24dd080, 0xe59f307c, 0xe59f207c]))
                && let Some(pool_words) = pool_words.head_array::<2>()
            {
                log::debug!("Decrypted flashcart/emulator detector (type 1)");

                let test_fn_addr = pool_words[0].wrapping_sub(reference_offset);
                relocations.push(DsProtRelocation {
                    from_address: function_end_address,
                    to_address: test_fn_addr,
                    addend: reference_offset,
                });

                let integrity_fn_addr = pool_words[1].wrapping_sub(reference_offset);
                relocations.push(DsProtRelocation {
                    from_address: function_end_address.wrapping_add(0x4),
                    to_address: integrity_fn_addr,
                    addend: reference_offset,
                });
            } else if (func_start.starts_with(&[0xe92d4ff8, 0xe24dd098, 0xe59f2170, 0xe59f4170])
                || func_start.starts_with(&[0xe92d4ff8, 0xe24dd098, 0xe59f2174, 0xe59f4174]))
                && let Some(pool_words) = pool_words.head_array::<4>()
            {
                log::debug!("Decrypted flashcart/emulator detector (type 2)");

                let callback_index_addr = pool_words[0].wrapping_sub(reference_offset);
                relocations.push(DsProtRelocation {
                    from_address: function_end_address,
                    to_address: callback_index_addr,
                    addend: reference_offset,
                });

                let callback_table_addr = pool_words[1].wrapping_sub(reference_offset);
                relocations.push(DsProtRelocation {
                    from_address: function_end_address.wrapping_add(0x4),
                    to_address: callback_table_addr,
                    addend: reference_offset,
                });

                let test_fn_addr = pool_words[2].wrapping_sub(reference_offset);
                relocations.push(DsProtRelocation {
                    from_address: function_end_address.wrapping_add(0x8),
                    to_address: test_fn_addr,
                    addend: reference_offset,
                });

                let integrity_fn_addr = pool_words[3].wrapping_sub(reference_offset);
                relocations.push(DsProtRelocation {
                    from_address: function_end_address.wrapping_add(0xc),
                    to_address: integrity_fn_addr,
                    addend: reference_offset,
                });
            } else if (func_start.starts_with(&[0xe92d41f0, 0xe24dd080, 0xe59f3070, 0xe3a02000])
                || func_start.starts_with(&[0xe92d41f0, 0xe24dd080, 0xe59f3074, 0xe3a02000])
                || func_start.starts_with(&[0xe92d41f0, 0xe24dd080, 0xe59f3080, 0xe3a02000]))
                && let Some(pool_words) = pool_words.head_array::<1>()
            {
                log::debug!("Decrypted dummy detector");

                let test_fn_addr = pool_words[0].wrapping_sub(reference_offset);
                relocations.push(DsProtRelocation {
                    from_address: function_end_address,
                    to_address: test_fn_addr,
                    addend: reference_offset,
                });
            } else if func_start.starts_with(&[0xe92d4ff8, 0xe24dd018, 0xe59fa100, 0xe59f6100])
                && let Some(pool_words) = pool_words.head_array::<4>()
            {
                log::debug!("Decrypted MAC and ROM integrity checkers");

                let mac_integrity_fn_addr = pool_words[0].wrapping_sub(reference_offset);
                relocations.push(DsProtRelocation {
                    from_address: function_end_address,
                    to_address: mac_integrity_fn_addr,
                    addend: reference_offset,
                });
                let mac_test_fn_addr = pool_words[1].wrapping_sub(reference_offset);
                relocations.push(DsProtRelocation {
                    from_address: function_end_address.wrapping_add(0x4),
                    to_address: mac_test_fn_addr,
                    addend: reference_offset,
                });
                let rom_integrity_fn_addr = pool_words[2].wrapping_sub(reference_offset);
                relocations.push(DsProtRelocation {
                    from_address: function_end_address.wrapping_add(0x8),
                    to_address: rom_integrity_fn_addr,
                    addend: reference_offset,
                });
                let rom_test_fn_addr = pool_words[3].wrapping_sub(reference_offset);
                relocations.push(DsProtRelocation {
                    from_address: function_end_address.wrapping_add(0xc),
                    to_address: rom_test_fn_addr,
                    addend: reference_offset,
                });
            } else if func_start[6] == 0x112fff1e
                && let Some(pool_words) = pool_words.head_array::<1>()
            {
                let checked_fn_addr = pool_words[0].wrapping_sub(reference_offset);
                log::debug!("Decrypted integrity checker for {:#010x}", checked_fn_addr);

                relocations.push(DsProtRelocation {
                    from_address: function_end_address,
                    to_address: checked_fn_addr,
                    addend: reference_offset,
                });
            } else if func_start.starts_with(&[0xe1a0a00f, 0xe19aa00a, 0x102ee00e, 0xe25aa008])
                && let Some(pool_words) = pool_words.head_array::<2>()
            {
                log::debug!("Decrypted crash function");

                let clear_fn_addr = pool_words[0].wrapping_sub(reference_offset);
                relocations.push(DsProtRelocation {
                    from_address: function_end_address,
                    to_address: clear_fn_addr,
                    addend: reference_offset,
                });
                let terminate_fn_addr = pool_words[1].wrapping_sub(reference_offset);
                relocations.push(DsProtRelocation {
                    from_address: function_end_address.wrapping_add(0x4),
                    to_address: terminate_fn_addr,
                    addend: reference_offset,
                });
            }
            // The other function types don't have any encrypted constant pools
        }
        Ok(())
    }

    fn decode_relocations(
        &self,
        options: &AlgoDecryptOptions,
        words: &mut [u32],
        relocations: &[DsProtRelocation],
    ) -> Result<(), DsProtError> {
        let &AlgoDecryptOptions { base_address, end_address, .. } = options;
        for relocation in relocations.iter() {
            let Some(relocated_value) = words.get_mut(relocation.from_offset(base_address)? / 4) else {
                return OutOfBoundsSnafu { what: "relocation", address: relocation.from_address, base_address, end_address }
                    .fail();
            };
            *relocated_value = (*relocated_value).wrapping_sub(relocation.addend);
        }
        Ok(())
    }
}

fn get_constant_pool<'a, const N: usize>(
    base_address: u32,
    end_address: u32,
    words: &'a [u32],
    function: &DsProtFunction,
) -> Result<&'a [u32; N], DsProtError> {
    let pool_offset = function.end_offset(base_address)? / 4;
    let wrapper_end_offset = pool_offset.checked_add(N).ok_or_else(|| OverflowError::new("decryption wrapper end offset"))?;
    let function_end_address = function.end_address()?;
    let Some(pool_words) = words.get(pool_offset..wrapper_end_offset) else {
        return RangeOutOfBoundsSnafu {
            what: "decryption wrapper constant pool",
            start: function_end_address,
            end: function_end_address.wrapping_add((N as u32).saturating_mul(4)),
            base_address,
            end_address,
        }
        .fail();
    };
    #[allow(clippy::unwrap_used)] // pool_words is always N elements
    Ok(pool_words.as_array::<N>().unwrap())
}

fn proxy_relocation(
    proxy_ptr_address: u32,
    words: &[u32],
    base_address: u32,
    end_address: u32,
    reference_offset: u32,
) -> Result<DsProtRelocation, DsProtError> {
    let offset =
        proxy_ptr_address.checked_sub(base_address).ok_or_else(|| OverflowError::new("proxy function pointer offset"))?;
    let offset = offset as usize / 4;
    let Some(proxy_fn) = words.get(offset) else {
        return OutOfBoundsSnafu { what: "proxy function pointer", address: proxy_ptr_address, base_address, end_address }
            .fail();
    };
    let to_address = proxy_fn.wrapping_sub(reference_offset);
    Ok(DsProtRelocation { from_address: proxy_ptr_address, to_address, addend: reference_offset })
}

fn encrypt_branch_1(reference_offset: u32, ins: u32) -> u32 {
    // Flip link bit and add branch destination
    let opcode = (ins & 0xff000000) ^ 0x01000000;
    let operands = (ins & 0x00ffffff).wrapping_add(reference_offset) & 0x00ffffff;
    opcode | operands
}

fn encrypt_branch_2(reference_offset: u32, ins: u32) -> u32 {
    // Flip link bit and add branch destination
    let opcode = (ins & 0xff000000) ^ 0x01000000;
    let offset = reference_offset.wrapping_add(8) >> 2;
    let operands = (ins & 0x00ffffff).wrapping_add(offset) & 0x00ffffff;
    opcode | operands
}

fn decrypt_branch_1(reference_offset: u32, ins: u32) -> u32 {
    // Flip link bit and subtract branch destination
    let opcode = (ins & 0xff000000) ^ 0x01000000;
    let operands = (ins & 0x00ffffff).wrapping_sub(reference_offset) & 0x00ffffff;
    opcode | operands
}

fn decrypt_branch_2(reference_offset: u32, ins: u32) -> u32 {
    // Flip link bit and subtract branch destination
    let opcode = (ins & 0xff000000) ^ 0x01000000;
    let offset = reference_offset.wrapping_add(8) >> 2;
    let operands = (ins & 0x00ffffff).wrapping_sub(offset) & 0x00ffffff;
    opcode | operands
}

fn expand_seed_key_old(seed_key: u32) -> [u8; 16] {
    assert_eq!(seed_key & 0xff000000, 0xeb000000);
    let bytes = seed_key.to_le_bytes();
    [
        bytes[0] ^ 0xff,
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3] ^ 0xff,
    ]
}

fn expand_seed_key(seed_key: u32, func_size: u32) -> [u32; 4] {
    [
        seed_key ^ func_size,
        seed_key.rotate_left(8) ^ func_size,
        seed_key.rotate_left(16) ^ func_size,
        seed_key.rotate_left(24) ^ func_size,
    ]
}

/// Before 1.23
#[derive(Clone, Copy)]
pub struct DsProtAlgoV1 {
    encrypted_range_start_signature: [u32; 5],
}

/// Before 1.25
#[derive(Clone, Copy)]
pub struct DsProtAlgoV2 {
    reference_offset: u32,
    unkeyed_encryption_xor: u32,
}

/// 1.25 only
#[derive(Clone, Copy)]
pub struct DsProtAlgoV3 {
    reference_offset: u32,
    unkeyed_encryption_xor: u32,
}

/// Before 2.00
#[derive(Clone, Copy)]
pub struct DsProtAlgoV4 {
    reference_offset: u32,
    unkeyed_encryption_xor: u32,
}

/// Before 2.03
#[derive(Clone, Copy)]
pub struct DsProtAlgoV5 {
    reference_offset: u32,
    unkeyed_encryption_xor: u32,
}

/// 2.03 onwards
#[derive(Clone, Copy)]
pub struct DsProtAlgoV6 {
    reference_offset: u32,
    unkeyed_encryption_xor: u32,
    precalculated_seed_key: u32,
    decrypt_opcode: fn(curr: u8, prev: u8) -> u8,
    encrypt_opcode: fn(curr: u8, prev: u8) -> u8,
}

impl DsProtAlgo for DsProtAlgoV1 {
    fn reference_offset(&self) -> u32 {
        0 // unused
    }

    fn unkeyed_encryption_xor(&self) -> u32 {
        0 // unused
    }

    fn unkeyed_encrypt_instruction(&self, ins: u32, xor: u32) -> (u32, u32) {
        (ins, xor) // unused
    }

    fn unkeyed_decrypt_instruction(&self, ins: u32, xor: u32) -> (u32, u32) {
        (ins, xor) // unused
    }

    fn decrypt_instruction(&self, rc4: &mut Rc4, ins: u32, _prev_ins: u32) -> u32 {
        let bytes = ins.to_le_bytes();
        u32::from_le_bytes([rc4.decrypt_byte(bytes[0]), rc4.decrypt_byte(bytes[1]), bytes[2] ^ 0x01, bytes[3]])
    }

    fn encrypt_instruction(&self, rc4: &mut Rc4, ins: u32, _prev_ins: u32) -> u32 {
        let bytes = ins.to_le_bytes();
        u32::from_le_bytes([rc4.encrypt_byte(bytes[0]), rc4.encrypt_byte(bytes[1]), bytes[2] ^ 0x01, bytes[3]])
    }

    fn init_rc4(&self, seed_key: u32, _func_size: u32) -> Rc4 {
        let expanded_key = expand_seed_key_old(seed_key);
        Rc4::new(&expanded_key, None)
    }

    fn decrypt(&self, words: &mut [u32], options: &AlgoDecryptOptions) -> Result<DsProtDecryptResult, DsProtError> {
        let AlgoDecryptOptions { base_address, version, .. } = *options;

        // Find the starts and keys of all encrypted code ranges
        let encrypted_range_starts = words
            .array_windows::<7>()
            .enumerate()
            .filter(|(_i, word)| [word[0], word[1], word[2], word[4], word[5]] == self.encrypted_range_start_signature)
            .map(|(i, word)| -> Result<_, DsProtError> {
                #[allow(clippy::arithmetic_side_effects)] // small number
                let start_address = base_address
                    .checked_add(i as u32 * 4 + 0x1c)
                    .ok_or_else(|| OverflowError::new("encrypted range start address"))?;
                let seed_key = word[6];
                Ok((start_address, seed_key))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let mut encrypted_ranges = Vec::new();
        for (start_address, seed_key) in encrypted_range_starts {
            log::debug!("Found encrypted range starting at {:#010x} with key {:#010x}", start_address, seed_key);

            let mut rc4 = self.init_rc4(seed_key, 0); // function size not needed

            for address in (start_address..).step_by(4) {
                #[allow(clippy::arithmetic_side_effects)] // address is always greater than base_address
                let offset = ((address - base_address) / 4) as usize;
                let instruction = words.get_mut(offset).ok_or_else(|| {
                    OutOfBoundsSnafu {
                        what: "encrypted range start instruction",
                        address,
                        base_address,
                        end_address: options.end_address,
                    }
                    .build()
                })?;
                if *instruction == seed_key {
                    encrypted_ranges.push(EncryptedRange { start_address, end_address: address, seed_key });
                    break;
                }
                let prev_ins = 0; // unused
                *instruction = self.decrypt_instruction(&mut rc4, *instruction, prev_ins);
            }
        }
        encrypted_ranges.sort_unstable_by_key(|r| r.start_address);

        Ok(DsProtDecryptResult {
            version,
            encrypted_ranges,
            bss_variable: None,
            functions: Vec::new(),
            relocations: Vec::new(),
        })
    }
}

impl DsProtAlgo for DsProtAlgoV2 {
    fn reference_offset(&self) -> u32 {
        self.reference_offset
    }

    fn unkeyed_encryption_xor(&self) -> u32 {
        self.unkeyed_encryption_xor
    }

    fn unkeyed_encrypt_instruction(&self, ins: u32, xor: u32) -> (u32, u32) {
        let new_ins = match InstructionCategory::new(ins) {
            InstructionCategory::BlxImm | InstructionCategory::Bl => encrypt_branch_2(self.reference_offset, ins),
            InstructionCategory::B => encrypt_branch_1(self.reference_offset, ins),
            InstructionCategory::Other => ins ^ xor,
        };
        (new_ins, xor)
    }

    fn unkeyed_decrypt_instruction(&self, ins: u32, xor: u32) -> (u32, u32) {
        let new_ins = match InstructionCategory::new(ins) {
            InstructionCategory::BlxImm | InstructionCategory::Bl => decrypt_branch_1(self.reference_offset, ins),
            InstructionCategory::B => decrypt_branch_2(self.reference_offset, ins),
            InstructionCategory::Other => ins ^ xor,
        };
        (new_ins, xor)
    }

    fn decrypt_instruction(&self, rc4: &mut Rc4, ins: u32, _prev_ins: u32) -> u32 {
        match InstructionCategory::new(ins) {
            InstructionCategory::BlxImm | InstructionCategory::Bl => decrypt_branch_1(self.reference_offset, ins),
            InstructionCategory::B => decrypt_branch_2(self.reference_offset, ins),
            InstructionCategory::Other => {
                let bytes = ins.to_le_bytes();
                u32::from_le_bytes([rc4.decrypt_byte(bytes[0]), rc4.decrypt_byte(bytes[1]), bytes[2] ^ 1, bytes[3]])
            }
        }
    }

    fn encrypt_instruction(&self, rc4: &mut Rc4, ins: u32, _prev_ins: u32) -> u32 {
        match InstructionCategory::new(ins) {
            InstructionCategory::BlxImm | InstructionCategory::Bl => encrypt_branch_2(self.reference_offset, ins),
            InstructionCategory::B => encrypt_branch_1(self.reference_offset, ins),
            InstructionCategory::Other => {
                let bytes = ins.to_le_bytes();
                u32::from_le_bytes([rc4.encrypt_byte(bytes[0]), rc4.encrypt_byte(bytes[1]), bytes[2] ^ 1, bytes[3]])
            }
        }
    }

    fn init_rc4(&self, seed_key: u32, func_size: u32) -> Rc4 {
        let expanded_key = expand_seed_key(seed_key, func_size);
        Rc4::new(bytemuck::cast_slice(&expanded_key), None)
    }
}

impl DsProtAlgo for DsProtAlgoV3 {
    fn reference_offset(&self) -> u32 {
        self.reference_offset
    }

    fn unkeyed_encryption_xor(&self) -> u32 {
        self.unkeyed_encryption_xor
    }

    fn unkeyed_encrypt_instruction(&self, ins: u32, xor: u32) -> (u32, u32) {
        match InstructionCategory::new(ins) {
            InstructionCategory::BlxImm | InstructionCategory::Bl => {
                let new_ins = encrypt_branch_2(self.reference_offset, ins);
                (new_ins, xor)
            }
            InstructionCategory::B => {
                let new_ins = ins ^ xor ^ 0x01000000; // flip link bit
                (new_ins, (xor << 1).wrapping_add(ins) & 0xffffff)
            }
            InstructionCategory::Other => {
                let new_ins = ins ^ xor;
                (new_ins, (xor << 1).wrapping_add(ins) & 0xffffff)
            }
        }
    }

    fn unkeyed_decrypt_instruction(&self, ins: u32, xor: u32) -> (u32, u32) {
        match InstructionCategory::new(ins) {
            InstructionCategory::BlxImm | InstructionCategory::B => {
                let new_ins = decrypt_branch_2(self.reference_offset, ins);
                (new_ins, xor)
            }
            InstructionCategory::Bl => {
                let new_ins = ins ^ xor ^ 0x01000000; // flip link bit
                (new_ins, (xor << 1).wrapping_add(new_ins) & 0xffffff)
            }
            InstructionCategory::Other => {
                let new_ins = ins ^ xor;
                (new_ins, (xor << 1).wrapping_add(new_ins) & 0xffffff)
            }
        }
    }

    fn decrypt_instruction(&self, rc4: &mut Rc4, ins: u32, _prev_ins: u32) -> u32 {
        match InstructionCategory::new(ins) {
            InstructionCategory::BlxImm | InstructionCategory::B => decrypt_branch_2(self.reference_offset, ins),
            category => {
                let bytes = ins.to_le_bytes();
                u32::from_le_bytes([
                    rc4.decrypt_byte(bytes[0]),
                    rc4.decrypt_byte(bytes[1]),
                    bytes[2] ^ 0x3f,
                    if category == InstructionCategory::Bl {
                        bytes[3] ^ 0x01 // flip link bit
                    } else {
                        bytes[3]
                    },
                ])
            }
        }
    }

    fn encrypt_instruction(&self, rc4: &mut Rc4, ins: u32, _prev_ins: u32) -> u32 {
        match InstructionCategory::new(ins) {
            InstructionCategory::BlxImm | InstructionCategory::Bl => encrypt_branch_2(self.reference_offset, ins),
            category => {
                let bytes = ins.to_le_bytes();
                u32::from_le_bytes([
                    rc4.encrypt_byte(bytes[0]),
                    rc4.encrypt_byte(bytes[1]),
                    bytes[2] ^ 0x3f,
                    if category == InstructionCategory::B {
                        bytes[3] ^ 0x01 // flip link bit
                    } else {
                        bytes[3]
                    },
                ])
            }
        }
    }

    fn init_rc4(&self, seed_key: u32, func_size: u32) -> Rc4 {
        let expanded_key = expand_seed_key(seed_key, func_size);
        Rc4::new(bytemuck::cast_slice(&expanded_key), Some(0xaa))
    }
}

impl DsProtAlgo for DsProtAlgoV4 {
    fn reference_offset(&self) -> u32 {
        self.reference_offset
    }

    fn unkeyed_encryption_xor(&self) -> u32 {
        self.unkeyed_encryption_xor
    }

    fn unkeyed_encrypt_instruction(&self, ins: u32, xor: u32) -> (u32, u32) {
        match InstructionCategory::new(ins) {
            InstructionCategory::BlxImm | InstructionCategory::Bl => {
                let new_ins = encrypt_branch_2(self.reference_offset, ins);
                (new_ins, (xor ^ (ins >> 24)) & 0xffffff)
            }
            InstructionCategory::B => {
                let new_ins = ins ^ xor ^ 0x01000000; // flip link bit
                (new_ins, (xor ^ ins ^ (ins >> 8)) & 0xffffff)
            }
            InstructionCategory::Other => {
                let new_ins = ins ^ xor;
                (new_ins, (xor ^ ins ^ (ins >> 8)) & 0xffffff)
            }
        }
    }

    fn unkeyed_decrypt_instruction(&self, ins: u32, xor: u32) -> (u32, u32) {
        match InstructionCategory::new(ins) {
            InstructionCategory::BlxImm | InstructionCategory::B => {
                let new_ins = decrypt_branch_2(self.reference_offset, ins);
                (new_ins, (xor ^ (new_ins >> 24)) & 0xffffff)
            }
            InstructionCategory::Bl => {
                let new_ins = ins ^ xor ^ 0x01000000; // flip link bit
                (new_ins, (xor ^ new_ins ^ (new_ins >> 8)) & 0xffffff)
            }
            InstructionCategory::Other => {
                let new_ins = ins ^ xor;
                (new_ins, (xor ^ new_ins ^ (new_ins >> 8)) & 0xffffff)
            }
        }
    }

    fn decrypt_instruction(&self, rc4: &mut Rc4, ins: u32, _prev_ins: u32) -> u32 {
        match InstructionCategory::new(ins) {
            InstructionCategory::BlxImm | InstructionCategory::B => {
                rc4.update_x(|x| x.wrapping_add((ins >> 24) as u8));
                decrypt_branch_2(self.reference_offset, ins)
            }
            category => {
                let bytes = ins.to_le_bytes();
                let result = u32::from_le_bytes([
                    rc4.decrypt_byte(bytes[0]),
                    rc4.decrypt_byte(bytes[1]),
                    bytes[2] ^ 0xff,
                    if category == InstructionCategory::Bl {
                        bytes[3] ^ 0x01 // flip link bit
                    } else {
                        bytes[3]
                    },
                ]);
                rc4.update_x(|x| bytes[2].wrapping_mul(x).wrapping_sub(bytes[3]));
                result
            }
        }
    }

    fn encrypt_instruction(&self, rc4: &mut Rc4, ins: u32, _prev_ins: u32) -> u32 {
        match InstructionCategory::new(ins) {
            InstructionCategory::BlxImm | InstructionCategory::Bl => {
                let new_ins = encrypt_branch_2(self.reference_offset, ins);
                rc4.update_x(|x| x.wrapping_add((new_ins >> 24) as u8));
                new_ins
            }
            category => {
                let bytes = ins.to_le_bytes();
                let new_bytes = [
                    rc4.encrypt_byte(bytes[0]),
                    rc4.encrypt_byte(bytes[1]),
                    bytes[2] ^ 0xff,
                    if category == InstructionCategory::B {
                        bytes[3] ^ 0x01 // flip link bit
                    } else {
                        bytes[3]
                    },
                ];
                let result = u32::from_le_bytes(new_bytes);
                rc4.update_x(|x| new_bytes[2].wrapping_mul(x).wrapping_sub(new_bytes[3]));
                result
            }
        }
    }

    fn init_rc4(&self, seed_key: u32, func_size: u32) -> Rc4 {
        let expanded_key = expand_seed_key(seed_key, func_size);
        Rc4::new(bytemuck::cast_slice(&expanded_key), Some(0xaa))
    }
}

impl DsProtAlgo for DsProtAlgoV5 {
    fn reference_offset(&self) -> u32 {
        self.reference_offset
    }

    fn unkeyed_encryption_xor(&self) -> u32 {
        self.unkeyed_encryption_xor
    }

    fn unkeyed_encrypt_instruction(&self, ins: u32, xor: u32) -> (u32, u32) {
        let new_ins = ins ^ xor;
        let new_xor = xor ^ ins.wrapping_sub(ins >> 8);
        (new_ins, new_xor)
    }

    fn unkeyed_decrypt_instruction(&self, ins: u32, xor: u32) -> (u32, u32) {
        let new_ins = ins ^ xor;
        let new_xor = xor ^ new_ins.wrapping_sub(new_ins >> 8);
        (new_ins, new_xor)
    }

    fn decrypt_instruction(&self, rc4: &mut Rc4, ins: u32, _prev_ins: u32) -> u32 {
        match InstructionCategory::new(ins) {
            InstructionCategory::BlxImm | InstructionCategory::B => {
                rc4.update_x(|x| x.wrapping_add((ins >> 24) as u8));
                decrypt_branch_2(self.reference_offset, ins)
            }
            category => {
                let bytes = ins.to_le_bytes();
                let result = u32::from_le_bytes([
                    rc4.decrypt_byte(bytes[0]),
                    rc4.decrypt_byte(bytes[1]),
                    rc4.decrypt_byte(bytes[2]),
                    if category == InstructionCategory::Bl {
                        bytes[3] ^ 0x01 // flip link bit
                    } else {
                        bytes[3]
                    },
                ]);
                rc4.update_x(|x| x.wrapping_sub(bytes[3]));
                result
            }
        }
    }

    fn encrypt_instruction(&self, rc4: &mut Rc4, ins: u32, _prev_ins: u32) -> u32 {
        match InstructionCategory::new(ins) {
            InstructionCategory::BlxImm | InstructionCategory::Bl => {
                let new_ins = encrypt_branch_2(self.reference_offset, ins);
                rc4.update_x(|x| x.wrapping_add((new_ins >> 24) as u8));
                new_ins
            }
            category => {
                let bytes = ins.to_le_bytes();
                let new_bytes = [
                    rc4.encrypt_byte(bytes[0]),
                    rc4.encrypt_byte(bytes[1]),
                    rc4.encrypt_byte(bytes[2]),
                    if category == InstructionCategory::B {
                        bytes[3] ^ 0x01 // flip link bit
                    } else {
                        bytes[3]
                    },
                ];
                let result = u32::from_le_bytes(new_bytes);
                rc4.update_x(|x| x.wrapping_sub(new_bytes[3]));
                result
            }
        }
    }

    fn init_rc4(&self, seed_key: u32, func_size: u32) -> Rc4 {
        let expanded_key = expand_seed_key(seed_key, func_size);
        Rc4::new(bytemuck::cast_slice(&expanded_key), Some(0xaa))
    }
}

impl DsProtAlgo for DsProtAlgoV6 {
    fn reference_offset(&self) -> u32 {
        self.reference_offset
    }

    fn unkeyed_encryption_xor(&self) -> u32 {
        self.unkeyed_encryption_xor
    }

    fn unkeyed_encrypt_instruction(&self, ins: u32, xor: u32) -> (u32, u32) {
        let new_ins = ins ^ xor;
        let new_xor = xor ^ ins.wrapping_sub(ins >> 8);
        (new_ins, new_xor)
    }

    fn unkeyed_decrypt_instruction(&self, ins: u32, xor: u32) -> (u32, u32) {
        let new_ins = ins ^ xor;
        let new_xor = xor ^ new_ins.wrapping_sub(new_ins >> 8);
        (new_ins, new_xor)
    }

    fn decrypt_instruction(&self, rc4: &mut Rc4, ins: u32, prev_ins: u32) -> u32 {
        let opcode = (ins >> 24) as u8;
        let prev_opcode = (prev_ins >> 24) as u8;
        let new_opcode = (self.decrypt_opcode)(opcode, prev_opcode);
        let ins = (ins & 0xffffff) | ((new_opcode as u32) << 24);
        let category = InstructionCategory::new(ins);
        let new_ins = match category {
            InstructionCategory::BlxImm | InstructionCategory::B => decrypt_branch_2(self.reference_offset, ins),
            InstructionCategory::Bl | InstructionCategory::Other => {
                let bytes = ins.to_le_bytes();
                u32::from_le_bytes([
                    rc4.decrypt_byte(bytes[0]),
                    rc4.decrypt_byte(bytes[1]),
                    rc4.decrypt_byte(bytes[2]),
                    bytes[3],
                ])
            }
        };
        rc4.update_x(|x| x.wrapping_sub(opcode));
        match category {
            // flip link bit
            InstructionCategory::Bl | InstructionCategory::BlxImm => new_ins ^ 0x01000000,
            InstructionCategory::B | InstructionCategory::Other => new_ins,
        }
    }

    fn encrypt_instruction(&self, rc4: &mut Rc4, ins: u32, prev_ins: u32) -> u32 {
        let category = InstructionCategory::new(ins);
        let new_ins = match category {
            InstructionCategory::BlxImm | InstructionCategory::Bl => encrypt_branch_2(self.reference_offset, ins),
            InstructionCategory::B | InstructionCategory::Other => {
                let bytes = ins.to_le_bytes();
                u32::from_le_bytes([
                    rc4.encrypt_byte(bytes[0]),
                    rc4.encrypt_byte(bytes[1]),
                    rc4.encrypt_byte(bytes[2]),
                    bytes[3],
                ])
            }
        };
        let new_ins = match category {
            // flip link bit
            InstructionCategory::BlxImm | InstructionCategory::B => new_ins ^ 0x01000000,
            InstructionCategory::Bl | InstructionCategory::Other => new_ins,
        };
        let opcode = (new_ins >> 24) as u8;
        let prev_opcode = (prev_ins >> 24) as u8;
        let new_opcode = (self.encrypt_opcode)(opcode, prev_opcode);
        let new_ins = (new_ins & 0xffffff) | ((new_opcode as u32) << 24);
        rc4.update_x(|x| x.wrapping_sub(new_opcode));
        new_ins
    }

    fn precalculated_seed_key(&self) -> Option<u32> {
        Some(self.precalculated_seed_key)
    }

    fn init_rc4(&self, seed_key: u32, func_size: u32) -> Rc4 {
        let expanded_key = expand_seed_key(seed_key, func_size);
        Rc4::new(bytemuck::cast_slice(&expanded_key), Some(0xaa))
    }
}

/// Contains the result of decrypting DS Protect code.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct DsProtDecryptResult {
    /// The version of DS Protect that was used.
    pub version: DsProtVersionNumber,
    /// List of encrypted ranges of instructions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub encrypted_ranges: Vec<EncryptedRange>,
    /// Address of the DS Protect BSS variable. Used for offsetting constants.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bss_variable: Option<u32>,
    /// List of functions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub functions: Vec<DsProtFunction>,
    /// List of relocations.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relocations: Vec<DsProtRelocation>,
}

impl DsProtDecryptResult {
    /// Returns a [`DisplayDsProtDecryptResult`] which implements [`Display`].
    pub fn display(&self, indent: usize) -> DisplayDsProtDecryptResult<'_> {
        DisplayDsProtDecryptResult { inner: self, indent }
    }

    pub(crate) fn encrypt(
        &self,
        data: &mut [u8],
        base_address: u32,
        options: &DsProtEncryptOptions,
    ) -> Result<(), DsProtError> {
        let Some(dsprot_version) = DSPROT_VERSIONS.iter().find(|v| v.number == self.version) else {
            return Ok(());
        };

        with_words_mut(data, |words| {
            let end_address = module_end_address(base_address, words)?;
            dsprot_version.algo.encrypt(words, self, &AlgoEncryptOptions {
                base_address,
                end_address,
                encode_relocations: options.encode_relocations,
            })
        })
    }
}

/// Runs `f` on `data` as 32-bit words, ignoring trailing bytes that don't fill a whole word. If `data` is not 4-aligned, the
/// words are copied to a temporary buffer and written back to `data` afterwards.
fn with_words_mut<R>(data: &mut [u8], f: impl FnOnce(&mut [u32]) -> R) -> R {
    let (chunks, _) = data.as_chunks_mut::<4>();
    if let Ok(words) = bytemuck::try_cast_slice_mut(chunks) {
        return f(words);
    }
    let mut words: Vec<u32> = chunks.iter().map(|chunk| u32::from_ne_bytes(*chunk)).collect();
    let result = f(&mut words);
    for (chunk, word) in chunks.iter_mut().zip(words) {
        *chunk = word.to_ne_bytes();
    }
    result
}

fn module_end_address(base_address: u32, words: &[u32]) -> Result<u32, OverflowError> {
    u32::try_from(size_of_val(words))
        .ok()
        .and_then(|size| base_address.checked_add(size))
        .ok_or_else(|| OverflowError::new("module end address"))
}

/// Can be used to display values inside [`DsProtDecryptResult`].
pub struct DisplayDsProtDecryptResult<'a> {
    inner: &'a DsProtDecryptResult,
    indent: usize,
}

impl Display for DisplayDsProtDecryptResult<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let i = " ".repeat(self.indent);
        let inner = self.inner;
        writeln!(f, "{i}Version .................... : {}", inner.version)?;
        if !inner.encrypted_ranges.is_empty() {
            writeln!(f, "{i}Encrypted ranges ........... :")?;
            for range in &inner.encrypted_ranges {
                writeln!(f, "{i}  {:#010x}..{:#010x}", range.start_address, range.end_address)?;
            }
        }
        if let Some(bss_variable) = inner.bss_variable {
            writeln!(f, "{i}BSS variable ............... : {:#010x}", bss_variable)?;
        }
        if !inner.functions.is_empty() {
            writeln!(f, "{i}Functions .................. :")?;
            for function in &inner.functions {
                writeln!(f, "{i}  Address ......... : {:#010x}", function.address)?;
                writeln!(f, "{i}  Size ............ : {:#x}", function.size)?;
                write!(f, "{i}  Encryption ...... : ")?;
                match function.encryption {
                    EncryptionType::None => {
                        writeln!(f, "None")?;
                    }
                    EncryptionType::Unkeyed => {
                        writeln!(f, "Unkeyed")?;
                    }
                    EncryptionType::Keyed(seed_key) => {
                        writeln!(f, "Keyed ({:#x})", seed_key)?;
                    }
                }
                write!(f, "{i}  Function table .. : ")?;
                if let Some(function_table) = &function.function_table {
                    writeln!(f)?;
                    writeln!(f, "{i}    Length ......... : {}", function_table.length)?;
                    writeln!(f, "{i}    Has garbage .... : {}", function_table.has_garbage)?;
                    writeln!(f, "{i}    Has overwrite .. : {}", function_table.has_overwrite)?;
                } else {
                    writeln!(f, "None")?;
                }
                writeln!(f)?;
            }
        }
        if !inner.relocations.is_empty() {
            writeln!(f, "{i}Relocations ................ :")?;
            for fn_ptr in &inner.relocations {
                writeln!(f, "{i}  Address .. : {:#010x}", fn_ptr.from_address)?;
                writeln!(f, "{i}  Offset ... : {:#x}\n", fn_ptr.addend)?;
            }
        }
        Ok(())
    }
}

/// Represents an address range of encrypted instructions.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct EncryptedRange {
    /// Start of range, inclusive.
    pub start_address: u32,
    /// End of range, exclusive.
    pub end_address: u32,
    /// Seed key for RC4 keystream.
    pub seed_key: u32,
}

impl EncryptedRange {
    /// Returns the start address of this [`EncryptedRange`].
    pub fn start_address(&self) -> u32 {
        self.start_address
    }

    /// Returns the end address of this [`EncryptedRange`].
    pub fn end_address(&self) -> u32 {
        self.end_address
    }

    /// Returns the size of this [`EncryptedRange`].
    pub fn size(&self) -> Result<u32, OverflowError> {
        self.end_address.checked_sub(self.start_address).ok_or_else(|| OverflowError::new("encrypted range size"))
    }

    #[inline(always)]
    fn start_offset(&self, base_address: u32) -> Result<usize, OverflowError> {
        Ok(self.start_address.checked_sub(base_address).ok_or_else(|| OverflowError::new("encrypted range start offset"))?
            as usize)
    }

    #[inline(always)]
    fn end_offset(&self, base_address: u32) -> Result<usize, OverflowError> {
        Ok(self.end_address.checked_sub(base_address).ok_or_else(|| OverflowError::new("encrypted range end offset"))?
            as usize)
    }
}

/// Contains information about a DS Protect function.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct DsProtFunction {
    /// This function's address.
    pub address: u32,
    /// This function's size, excluding constant pool.
    pub size: u32,
    /// The size in bytes of this function's constant pool, if known.
    pub pool_size: Option<u32>,
    /// The type of encryption applied to this function.
    pub encryption: EncryptionType,
    /// If this function is a decoder which performs unkeyed decryption on a list of functions, then
    /// `function_table` will be `Some`.
    pub function_table: Option<FunctionTable>,
}

impl DsProtFunction {
    #[inline(always)]
    fn end_address(&self) -> Result<u32, OverflowError> {
        self.address.checked_add(self.size).ok_or_else(|| OverflowError::new("dsprot function end address"))
    }

    #[inline(always)]
    fn offset(&self, base_address: u32) -> Result<usize, OverflowError> {
        Ok(self.address.checked_sub(base_address).ok_or_else(|| OverflowError::new("dsprot function offset"))? as usize)
    }

    #[inline(always)]
    fn end_offset(&self, base_address: u32) -> Result<usize, OverflowError> {
        Ok(self.end_address()?.checked_sub(base_address).ok_or_else(|| OverflowError::new("dsprot function end offset"))?
            as usize)
    }
}

/// The type of encryption used on a [`DsProtFunction`].
#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Debug)]
pub enum EncryptionType {
    /// No encryption, only encoded constant pool.
    #[serde(rename = "none")]
    None,
    /// Unkeyed encryption using an XOR cipher.
    #[serde(rename = "unkeyed")]
    Unkeyed,
    /// Keyed encryption using modified [`Rc4`].
    #[serde(rename = "keyed")]
    Keyed(u32),
}

/// Represents the size of the function table in the constant pool of a decoder function.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct FunctionTable {
    /// The number of (function address, function size) entries.
    pub length: u32,
    /// If true, a pointer to DS Protect's garbage data was appended to the end of the constant pool.
    pub has_garbage: bool,
    /// If true, a pointer to this decoder function was appended to the end of the constant pool.
    pub has_overwrite: bool,
}

/// Represents a pointer or constant in DS Protect's code which was encoded by adding an offset
/// value to it.
#[derive(PartialEq, Eq, Clone, Copy, Serialize, Deserialize, Debug)]
pub struct DsProtRelocation {
    /// The location of the relocated value.
    pub from_address: u32,
    /// The resolved address.
    pub to_address: u32,
    /// Offset to add to the resolved address.
    pub addend: u32,
}

impl DsProtRelocation {
    #[allow(clippy::wrong_self_convention)]
    fn from_offset(&self, base_address: u32) -> Result<usize, OverflowError> {
        Ok(self.from_address.checked_sub(base_address).ok_or_else(|| OverflowError::new("relocation from offset"))? as usize)
    }
}

/// Defines whether DS Protect is present in the ARM9 program or an ARM9 overlay, and whether it
/// is currently encrypted.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, Default)]
pub enum DsProtState {
    /// Not present.
    #[default]
    None,
    /// Present and unencrypted.
    #[serde(rename = "unencrypted")]
    Unencrypted(DsProtDecryptResult),
    /// Present and encrypted.
    #[serde(rename = "encrypted")]
    Encrypted(DsProtDecryptResult),
}

impl DsProtState {
    /// Returns `true` if DS Protect is not present. Opposite of [`DsProtState::is_present`].
    pub fn is_none(&self) -> bool {
        match self {
            DsProtState::None => true,
            DsProtState::Unencrypted(_) | DsProtState::Encrypted(_) => false,
        }
    }

    /// Returns `true` if DS Protect is present. Opposite of [`DsProtState::is_none`].
    pub fn is_present(&self) -> bool {
        !self.is_none()
    }

    /// Returns `true` if DS Protect is present and encrypted.
    pub fn is_encrypted(&self) -> bool {
        match self {
            DsProtState::Encrypted(_) => true,
            DsProtState::None | DsProtState::Unencrypted(_) => false,
        }
    }

    /// Returns `true` if DS Protect is present and unencrypted.
    pub fn is_unencrypted(&self) -> bool {
        match self {
            DsProtState::Unencrypted(_) => true,
            DsProtState::None | DsProtState::Encrypted(_) => false,
        }
    }

    /// Returns `Some` containing a [`DsProtDecryptResult`] if DS Protect is present.
    pub fn as_option(&self) -> Option<&DsProtDecryptResult> {
        match self {
            DsProtState::None => None,
            DsProtState::Unencrypted(result) | DsProtState::Encrypted(result) => Some(result),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[repr(C, align(4))]
    struct Aligned([u8; 16]);

    fn increment_words(data: &mut [u8]) -> usize {
        with_words_mut(data, |words| {
            words.iter_mut().for_each(|word| *word = word.wrapping_add(1));
            words.len()
        })
    }

    #[test]
    fn with_words_mut_aligned() {
        let mut buf = Aligned([0; 16]);
        let num_words = increment_words(&mut buf.0[..11]);
        assert_eq!(num_words, 2);
        let one = 1u32.to_ne_bytes();
        assert_eq!(&buf.0[0..4], &one);
        assert_eq!(&buf.0[4..8], &one);
        assert_eq!(&buf.0[8..], &[0; 8], "trailing bytes must be untouched");
    }

    #[test]
    fn with_words_mut_misaligned() {
        let mut buf = Aligned([0; 16]);
        let num_words = increment_words(&mut buf.0[1..12]);
        assert_eq!(num_words, 2);
        let one = 1u32.to_ne_bytes();
        assert_eq!(buf.0[0], 0);
        assert_eq!(&buf.0[1..5], &one);
        assert_eq!(&buf.0[5..9], &one);
        assert_eq!(&buf.0[9..], &[0; 7], "trailing bytes must be untouched");
    }

    #[test]
    fn find_bss_variable_pool_out_of_bounds() {
        for version in DSPROT_VERSIONS {
            // Decryption wrapper signature at the very end, so its constant pool is out of bounds
            let mut signature = DECRYPTION_WRAPPER_SIGNATURE_2;
            let signature = version.algo.unkeyed_encrypt_decryption_wrapper(&mut signature);
            let mut words = vec![0u32; 8];
            words.extend_from_slice(signature);

            let options = AlgoDecryptOptions {
                base_address: 0x02000000,
                end_address: 0x02000000 + words.len() as u32 * 4,
                version: version.number,
                decode_relocations: false,
            };
            let result = version.algo.find_bss_variable(&words, &options);
            assert!(matches!(result, Err(DsProtError::BssNotFound { .. })));
        }
    }

    #[test]
    fn decode_function_tables_size_addend_wraps() {
        const BASE_ADDRESS: u32 = 0x02000000;
        const DSPROT_BSS: u32 = 0x02100000;
        for version in DSPROT_VERSIONS {
            // Function table with one entry whose size word is less than `DSPROT_BSS + reference_offset`, so `func_size`
            // wraps around
            let mut words = vec![0u32; 4];
            words[0] = 0x02000100; // function address
            words[1] = DSPROT_BSS; // function size

            let decoder = DsProtFunction {
                address: BASE_ADDRESS,
                size: 0,
                pool_size: None,
                encryption: EncryptionType::None,
                function_table: Some(FunctionTable { length: 1, has_garbage: false, has_overwrite: false }),
            };
            let options = AlgoDecryptOptions {
                base_address: BASE_ADDRESS,
                end_address: BASE_ADDRESS + words.len() as u32 * 4,
                version: version.number,
                decode_relocations: false,
            };
            let mut relocations = vec![];
            let functions =
                version.algo.decode_function_tables(&options, &mut words, DSPROT_BSS, &[decoder], &mut relocations).unwrap();
            assert_eq!(functions.len(), 1);
            assert_eq!(functions[0].size, 0u32.wrapping_sub(version.algo.reference_offset()));
            let size_relocation = relocations.iter().find(|r| r.from_address == BASE_ADDRESS + 4).unwrap();
            assert_eq!(size_relocation.to_address, DSPROT_BSS);
            assert_eq!(size_relocation.addend, 0);
        }
    }

    #[test]
    fn detect_misaligned() {
        let version = &DSPROT_VERSIONS[0];
        let signature: &[u8] = bytemuck::cast_slice(&version.detect_signature);
        let mut buf = vec![0u32; 16];
        let bytes: &mut [u8] = bytemuck::cast_slice_mut(&mut buf);
        bytes[5..5 + signature.len()].copy_from_slice(signature);

        let misaligned = &bytes[1..bytes.len() - 2];
        let info = DsProtInfo::detect(misaligned).unwrap();
        assert_eq!(info.version.number, version.number);
        assert!(DsProtInfo::detect(&bytes[2..]).is_none(), "signature is not word-aligned within the module");
    }
}
