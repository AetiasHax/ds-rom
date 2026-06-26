// Credits to taxicat1 aka Mow:
// https://github.com/taxicat1/dsprot
// https://github.com/taxicat1/dsdetect

use std::{backtrace::Backtrace, fmt::Display};

use serde::{Deserialize, Serialize};
use snafu::Snafu;

use crate::crypto::rc4::Rc4;

struct DsProtVersion {
    number: &'static str,
    detect_signature: [u32; 6],
    algo: &'static dyn DsProtAlgo,
}

const DSPROT_VERSIONS: &[DsProtVersion] = &[
    DsProtVersion {
        number: "1.00",
        detect_signature: [0xe3527270, 0xbafe77fc, 0xe59e0989, 0xe1c2f9af, 0xea018a51, 0xeb004ae2],
        algo: &DsProtAlgoV1 { encrypted_range_start_signature: [0xe92d0001, 0xe1a0000f, 0xe2800010, 0xe8bd0001, 0xea000000] },
    },
    DsProtVersion {
        number: "1.05",
        detect_signature: [0xbafe0f18, 0xe59caf7a, 0xe2861884, 0xe1c5da54, 0xea018a6b, 0xeb0070c2],
        algo: &DsProtAlgoV1 { encrypted_range_start_signature: [0xe92d0001, 0xe3a0000c, 0xe080000f, 0xe8bd0001, 0xea000000] },
    },
    DsProtVersion {
        number: "1.06",
        detect_signature: [0xbafe9b10, 0xe59cfa77, 0xe2862a71, 0xe1c54e3d, 0xea01879d, 0xeb005fdf],
        algo: &DsProtAlgoV1 { encrypted_range_start_signature: [0xe92d000f, 0xe3a0100c, 0xe081000f, 0xe8bd000f, 0xea000000] },
    },
    DsProtVersion {
        number: "1.08",
        detect_signature: [0xbafe4040, 0xe59c2300, 0xe2852226, 0xe1c5cbe8, 0xea01612f, 0xeb004979],
        algo: &DsProtAlgoV1 { encrypted_range_start_signature: [0xe92d00ff, 0xe1a0000f, 0xe2800010, 0xe8bd00ff, 0xea000000] },
    },
    DsProtVersion {
        number: "1.10",
        detect_signature: [0xbafe29a2, 0xe59cc95b, 0xe285d70a, 0xe1c5442c, 0xea01fd7e, 0xeb001cfc],
        algo: &DsProtAlgoV1 { encrypted_range_start_signature: [0xe92d00ff, 0xe3a00006, 0xe08f0080, 0xe8bd00ff, 0xea000000] },
    },
    DsProtVersion {
        number: "1.20",
        detect_signature: [0xe3580f00, 0xbafe7df8, 0xe284dff9, 0xe1c2059d, 0xea014de4, 0xeb002f0c],
        algo: &DsProtAlgoV1 { encrypted_range_start_signature: [0xe92d03ff, 0xe3a00006, 0xe08f0080, 0xe8bd03ff, 0xea000000] },
    },
    DsProtVersion {
        number: "1.22",
        detect_signature: [0xe3581567, 0xbafee339, 0xe284dad2, 0xe1c27622, 0xea017231, 0xeb0037ee],
        algo: &DsProtAlgoV1 { encrypted_range_start_signature: [0xe92d03ff, 0xe3a00003, 0xe08f0100, 0xe8bd03ff, 0xea000000] },
    },
    DsProtVersion {
        number: "1.23",
        detect_signature: [0xebaa0113, 0xe4064ec7, 0xef013596, 0xe5212f83, 0xe7ee335b, 0xe83b197c],
        algo: &DsProtAlgoV2 { reference_offset: 0x1300, unkeyed_encryption_xor: 0xf0566556 },
    },
    DsProtVersion {
        number: "1.23z",
        detect_signature: [0xebaa0114, 0x40064eb7, 0x5f013696, 0xe5211f83, 0xe7ef335b, 0xe84b197c],
        algo: &DsProtAlgoV2 { reference_offset: 0x1400, unkeyed_encryption_xor: 0xd0685665 },
    },
    DsProtVersion {
        number: "1.25",
        detect_signature: [0xebb6df66, 0xe42f6211, 0xef56b5aa, 0xe5b903fd, 0xe7d29154, 0xe859697c],
        algo: &DsProtAlgoV3 { reference_offset: 0x1500, unkeyed_encryption_xor: 0xf0556655 },
    },
    DsProtVersion {
        number: "1.26",
        detect_signature: [0xeb8fbc31, 0xe4ec10cf, 0xef73e592, 0xe59a0b7e, 0xe78cb309, 0xe87f3ed1],
        algo: &DsProtAlgoV4 { reference_offset: 0x1200, unkeyed_encryption_xor: 0xf03852cb },
    },
    DsProtVersion {
        number: "1.27",
        detect_signature: [0xe8dffe17, 0xe43df0de, 0x2ae8335c, 0x0ac09826, 0xe7a838dc, 0xe891a6fc],
        algo: &DsProtAlgoV4 { reference_offset: 0x1600, unkeyed_encryption_xor: 0xf0618c46 },
    },
    DsProtVersion {
        number: "1.28",
        detect_signature: [0xe2ed720b, 0xef69d1b1, 0x2ec32a41, 0x1aa3e665, 0xe9e1c153, 0xe49e8d9c],
        algo: &DsProtAlgoV4 { reference_offset: 0x1000, unkeyed_encryption_xor: 0xf0b9a2ea },
    },
    DsProtVersion {
        number: "2.00",
        detect_signature: [0x0819ff33, 0xe4a1ef1c, 0x5a85a2b3, 0xea0d2a0f, 0xe0d6bd78, 0xe29d9377],
        algo: &DsProtAlgoV5 { reference_offset: 0x1700, unkeyed_encryption_xor: 0xa5ca49b3 },
    },
    DsProtVersion {
        number: "2.00 Instant",
        detect_signature: [0x0849ea8b, 0xe33b6243, 0x53b2d501, 0xe6847168, 0xebd886d7, 0xee3c09c0],
        algo: &DsProtAlgoV5 { reference_offset: 0x1700, unkeyed_encryption_xor: 0xa5ca49b3 },
    },
    DsProtVersion {
        number: "2.01",
        detect_signature: [0x08d5310e, 0xe41bdb46, 0x5a3d9627, 0xeaf8fc79, 0xe016c9e7, 0xe2eb8130],
        algo: &DsProtAlgoV5 { reference_offset: 0x2100, unkeyed_encryption_xor: 0x7fec9df1 },
    },
    DsProtVersion {
        number: "2.01 Instant",
        detect_signature: [0x08637dd1, 0xe3618cb3, 0x5356f520, 0xe6b110ca, 0xeb4c1e5c, 0xeed91028],
        algo: &DsProtAlgoV5 { reference_offset: 0x2100, unkeyed_encryption_xor: 0x7fec9df1 },
    },
    DsProtVersion {
        number: "2.03",
        detect_signature: [0x08b76046, 0xe4177f2f, 0x5ab21c99, 0xea2af4b1, 0xe0fe885a, 0xe202fc9e],
        algo: &DsProtAlgoV6 {
            reference_offset: 0x3200,
            unkeyed_encryption_xor: 0x0976afcc,
            precalculated_seed_key: 0xfa8fd0ea,
            encrypt_opcode: |curr, prev| curr ^ prev,
        },
    },
    DsProtVersion {
        number: "2.03 Instant",
        detect_signature: [0x08b76046, 0xe4177f2f, 0x5ab21c99, 0xea2af4b1, 0xe0fe885a, 0xe2029efc],
        algo: &DsProtAlgoV6 {
            reference_offset: 0x3200,
            unkeyed_encryption_xor: 0x0976afcc,
            precalculated_seed_key: 0xfa8fd0ea,
            encrypt_opcode: |curr, prev| curr ^ prev,
        },
    },
    DsProtVersion {
        number: "2.05",
        detect_signature: [0x08a27510, 0xe47ab3c3, 0x5a289302, 0xeaa6cac8, 0xe00d75d5, 0xe2d2fe01],
        algo: &DsProtAlgoV6 {
            reference_offset: 0x2200,
            unkeyed_encryption_xor: 0x0a471abb,
            precalculated_seed_key: 0x89ede4ea,
            encrypt_opcode: |curr, prev| curr.wrapping_sub(prev),
        },
    },
    DsProtVersion {
        number: "2.05 Instant",
        detect_signature: [0x08a27510, 0xe47ab3c3, 0x5a289302, 0xeaa6cac8, 0xe00d75d5, 0xe2d2fe00],
        algo: &DsProtAlgoV6 {
            reference_offset: 0x2200,
            unkeyed_encryption_xor: 0x0a471abb,
            precalculated_seed_key: 0x89ede4ea,
            encrypt_opcode: |curr, prev| curr.wrapping_sub(prev),
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
}

impl DsProtInfo {
    /// Searches for DS Protect usage in the provided module.
    pub fn detect(data: &[u8]) -> Option<Self> {
        // Make 32-bit chunks
        let words: &[u32] = bytemuck::cast_slice(&data[..data.len() & !3]);

        for version in DSPROT_VERSIONS {
            // Identify if DS Protect might exist
            if !words.windows(6).any(|window| window == version.detect_signature) {
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
    pub fn decrypt(&self, data: &mut [u8], base_address: u32) -> Result<DsProtDecryptDetails, DsProtError> {
        let end_address = base_address + data.len() as u32;

        // Make 32-bit chunks
        let words: &mut [u32] = bytemuck::cast_slice_mut(data);

        self.version.algo.decrypt(words, &AlgoDecryptOptions { base_address, end_address, version: self.version.number })
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
    version: &'static str,
}

const DECRYPTION_WRAPPER_SIGNATURE_1: [u32; 3] = [0xe92d00f0, 0xe92d000f, 0xe8bd00f0];
const DECRYPTION_WRAPPER_SIGNATURE_2: [u32; 4] = [0xe18fc00f, 0xe01cc00c, 0x03a0c000, 0x128cc01c];
const DECRYPTION_WRAPPER_SIGNATURE_3: [u32; 4] = [0xe18fc00f, 0xe01cc00c, 0x03a0c000, 0x128cc068];
const DECRYPTION_WRAPPER_SIGNATURE_4: [u32; 4] = [0xe18fc00f, 0xe01cc00c, 0x03a0c000, 0x128cc08c];

trait DsProtAlgo {
    fn reference_offset(&self) -> u32;
    fn integrity_check_offset(&self) -> u32;
    fn unkeyed_encryption_xor(&self) -> u32;
    fn unkeyed_encrypt_instruction(&self, ins: u32, xor: u32) -> (u32, u32);
    fn unkeyed_decrypt_instruction(&self, ins: u32, xor: u32) -> (u32, u32);
    fn decrypt_instruction(&self, rc4: &mut Rc4, ins: u32, prev_ins: u32) -> u32;
    fn precalculated_seed_key(&self) -> Option<u32>;
    fn init_rc4(&self, seed_key: u32, func_size: u32) -> Rc4;

    // The below default implementations are for version 1.23 onwards (DsProtAlgoV2, V3 and V4), as
    // the de/encryption procedure for those versions are essentially identical aside from the bit
    // the de/encryption procedure for those versions are essentially identical aside from the bit
    // twiddling.

    fn decrypt(&self, words: &mut [u32], options: &AlgoDecryptOptions) -> Result<DsProtDecryptDetails, DsProtError> {
        let dsprot_bss = self.find_bss_variable(words, options)?;
        let obfuscated_function_tables = self.find_obfuscated_function_tables(options, words)?;
        let mut unkeyed_encrypted_functions =
            self.decode_function_tables(options, words, dsprot_bss, &obfuscated_function_tables)?;
        let (mut keyed_encrypted_functions, mut encoded_function_pointers) =
            self.unkeyed_decrypt_functions(options, words, dsprot_bss, &mut unkeyed_encrypted_functions)?;
        self.decrypt_wrappers(options, words, &mut keyed_encrypted_functions)?;

        encoded_function_pointers.sort_unstable_by_key(|fp| fp.0);
        encoded_function_pointers.dedup();
        self.decode_function_pointers(options, words, &encoded_function_pointers)?;

        let mut encrypted_functions = obfuscated_function_tables;
        encrypted_functions.append(&mut unkeyed_encrypted_functions);
        encrypted_functions.append(&mut keyed_encrypted_functions);
        encrypted_functions.sort_unstable_by_key(|f| f.address);

        Ok(DsProtDecryptDetails::Post1_23 {
            version: options.version,
            dsprot_bss,
            encrypted_functions,
            encoded_function_pointers,
        })
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

        for (i, window) in words.windows(4).enumerate() {
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
            let decryption_wrapper_address = base_address + i as u32 * 4;
            let pool_address = decryption_wrapper_address + func_size;

            let pool_offset = (pool_address - base_address) as usize / 4;
            let bss = words[pool_offset] - 1;
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
        words: &mut [u32],
    ) -> Result<Vec<EncryptedFunction>, DsProtError> {
        let AlgoDecryptOptions { base_address, .. } = *options;

        let mut encrypted_functions = Vec::new();
        for (i, window) in words.windows(4).enumerate() {
            let address = base_address + i as u32 * 4;
            let (pool_offset, fn_offset, primary_decoder) =
                if window[0..2] == [0xe38f0000, 0xe2900004] && window[2] >> 24 == 0x1a {
                    let (fn_offset, primary_decoder) = if words[i - 1] == 0xe8a007fe {
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

            let pool_address = address + pool_offset;
            let pool_position = (pool_address - base_address) as usize / 4;
            let mut pool_iter = words[pool_position..].iter().copied().enumerate();
            let table_end_address = loop {
                let Some((i, word)) = pool_iter.next() else {
                    return DecoderTableEndNotFoundSnafu { decoder_address: address - fn_offset }.fail();
                };
                if word == 0
                    && let Some((_, 0)) = pool_iter.next()
                {
                    break pool_address + i as u32 * 4 + 8;
                }
            };

            // Get up to 2 trailing addresses after the decoded function table
            let trailing_address_1 =
                words.get((table_end_address - base_address) as usize / 4).copied().filter(|&addr| addr >> 24 == 0x02);
            let trailing_address_2 = if trailing_address_1.is_some() {
                words.get((table_end_address + 4 - base_address) as usize / 4).copied().filter(|&addr| addr >> 24 == 0x02)
            } else {
                None
            };

            let (garbage_address, overwrite_address) = match (primary_decoder, trailing_address_1, trailing_address_2) {
                // No trailing addresses
                (_, None, None) => (None, None),
                // Second trailing address is always None if first trailing address is None
                (_, None, Some(_)) => unreachable!(),
                // Not primary but has a garbage address
                (false, Some(garbage_address), _) => {
                    if garbage_address - self.reference_offset() > address {
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
                    if garbage_address - self.reference_offset() > address {
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
                return DecoderOverwriteAddressNotFoundSnafu { decoder_address: address - fn_offset }.fail();
            }

            encrypted_functions.push(EncryptedFunction {
                address: address - fn_offset,
                size: pool_offset + fn_offset,
                encryption: EncryptionType::None,
                constant_pool: EncodedConstantPool::ObfuscatedFunctionTable {
                    with_garbage: garbage_address.is_some(),
                    with_overwrite: overwrite_address.is_some(),
                },
            });
        }

        Ok(encrypted_functions)
    }

    fn unkeyed_decrypt_functions(
        &self,
        options: &AlgoDecryptOptions,
        words: &mut [u32],
        dsprot_bss: u32,
        unkeyed_encrypted_functions: &mut [EncryptedFunction],
    ) -> Result<(Vec<EncryptedFunction>, Vec<EncodedFunctionPointer>), DsProtError> {
        let AlgoDecryptOptions { base_address, end_address, .. } = *options;

        let mut decryption_wrappers = Vec::new();
        let mut encoded_function_pointers = Vec::new();
        for function in unkeyed_encrypted_functions {
            let EncryptionType::Unkeyed = function.encryption else { continue };

            let func_offset = ((function.address - base_address) / 4) as usize;
            let instruction_count = (function.size / 4) as usize;

            let Some(func_words) = words.get_mut(func_offset..func_offset + instruction_count) else {
                return RangeOutOfBoundsSnafu {
                    what: "unkeyed encrypted function",
                    start: function.address,
                    end: function.address + function.size,
                    base_address,
                    end_address,
                }
                .fail();
            };

            let mut xor_value = self.unkeyed_encryption_xor();

            log::debug!("Decrypting function at {:#010x} with size {:#x}", function.address, function.size);

            for instruction in func_words.iter_mut() {
                let (new_instruction, new_xor_value) = self.unkeyed_decrypt_instruction(*instruction, xor_value);
                *instruction = new_instruction;
                xor_value = new_xor_value;
            }

            let reference_offset = self.reference_offset();

            if func_words.len() >= 3 && func_words[0..3] == DECRYPTION_WRAPPER_SIGNATURE_1 {
                let pool_words = get_constant_pool(base_address, end_address, words, function.address, function.size, 5)?;

                let bss = pool_words[0] - 1;
                debug_assert_eq!(bss, dsprot_bss);
                let dest_func_size = pool_words[1] - dsprot_bss - reference_offset;
                let seed_key = pool_words[2] - dsprot_bss - reference_offset;
                let dest_func_address = pool_words[3] - reference_offset;
                let garbage_address = pool_words[4] - reference_offset;

                pool_words[0] = bss;
                pool_words[1] = dest_func_size;
                pool_words[2] = seed_key;
                pool_words[3] = dest_func_address;
                // sanity check that this looks like a RAM address
                let with_garbage = garbage_address >> 24 == 0x02;
                if with_garbage {
                    pool_words[4] = garbage_address;
                }

                function.constant_pool = EncodedConstantPool::DecryptionWrapperType1 { with_garbage };
                log::debug!(
                    "Found decryption wrapper (type 1) at {:#010x} which targets {:#010x}",
                    function.address,
                    dest_func_address
                );
                decryption_wrappers.push(EncryptedFunction {
                    address: dest_func_address,
                    size: dest_func_size,
                    encryption: EncryptionType::Keyed(seed_key),
                    constant_pool: EncodedConstantPool::None,
                });
            } else if func_words.len() >= 4 && func_words[0..4] == DECRYPTION_WRAPPER_SIGNATURE_2 {
                let pool_words = get_constant_pool(base_address, end_address, words, function.address, function.size, 7)?;

                let bss = pool_words[0] - 1;
                debug_assert_eq!(bss, dsprot_bss);
                let seed_key = pool_words[1] - dsprot_bss - reference_offset;
                let dest_func_address = pool_words[2] - reference_offset;
                let dest_func_size = pool_words[3] - dsprot_bss - reference_offset;
                let wrapper_fragment = pool_words[5] - reference_offset;
                let garbage_address = pool_words[6] - reference_offset;

                pool_words[0] = bss;
                pool_words[1] = seed_key;
                pool_words[2] = dest_func_address;
                pool_words[3] = dest_func_size;
                pool_words[5] = wrapper_fragment;
                // sanity check that this looks like a RAM address
                let with_garbage = garbage_address >> 24 == 0x02;
                if with_garbage {
                    pool_words[6] = garbage_address;
                }

                function.constant_pool = EncodedConstantPool::DecryptionWrapperType2 { with_garbage };
                log::debug!(
                    "Found decryption wrapper (type 2) at {:#010x} which targets {:#010x}",
                    function.address,
                    dest_func_address
                );
                decryption_wrappers.push(EncryptedFunction {
                    address: dest_func_address,
                    size: dest_func_size,
                    encryption: EncryptionType::Keyed(seed_key),
                    constant_pool: EncodedConstantPool::None,
                });
            } else if func_words.len() >= 4
                && (func_words[0..4] == DECRYPTION_WRAPPER_SIGNATURE_3 || func_words[0..4] == DECRYPTION_WRAPPER_SIGNATURE_4)
            {
                let pool_words = get_constant_pool(base_address, end_address, words, function.address, function.size, 7)?;

                let bss = pool_words[0] - 1;
                debug_assert_eq!(bss, dsprot_bss);
                let seed_key_placeholder = pool_words[1] - 3;
                let dest_func_address = pool_words[2] - reference_offset;
                let dest_func_size = pool_words[3] - dsprot_bss - reference_offset;
                let wrapper_fragment = pool_words[5] & 0x03ffffff;
                let garbage_address = pool_words[6] - reference_offset;

                let wrapper_fragment_size = pool_words[5] >> 26;

                pool_words[0] = bss;
                pool_words[1] = seed_key_placeholder;
                pool_words[2] = dest_func_address;
                pool_words[3] = dest_func_size;
                pool_words[5] = wrapper_fragment;
                // sanity check that this looks like a RAM address
                let with_garbage = garbage_address >> 24 == 0x02;
                if with_garbage {
                    pool_words[6] = garbage_address;
                }

                let seed_key = self.precalculated_seed_key().unwrap();

                function.constant_pool = EncodedConstantPool::DecryptionWrapperType3 { with_garbage };
                log::debug!(
                    "Found decryption wrapper (type 3) at {:#010x} which targets {:#010x}. \
                    Seed key {:#010x} was derived from function at {:#010x} with size {:#x}",
                    function.address,
                    dest_func_address,
                    seed_key,
                    wrapper_fragment,
                    wrapper_fragment_size * 4,
                );
                decryption_wrappers.push(EncryptedFunction {
                    address: dest_func_address,
                    size: dest_func_size,
                    encryption: EncryptionType::Keyed(seed_key),
                    constant_pool: EncodedConstantPool::None,
                });
            } else if func_words[0..4] == [0xe92d4070, 0xe24dd010, 0xe59f40ac, 0xe59fc0ac] {
                // Decryption proxy
                let pool_words = get_constant_pool(base_address, end_address, words, function.address, function.size, 2)?;
                encoded_function_pointers.push(EncodedFunctionPointer(pool_words[1]));
                log::debug!("Decrypted decryption proxy function");
            } else if func_words[0..4] == [0xe92d41f0, 0xe24dd010, 0xe1a05000, 0xe59f00c0] {
                // Encryption proxy
                let pool_words = get_constant_pool(base_address, end_address, words, function.address, function.size, 1)?;
                encoded_function_pointers.push(EncodedFunctionPointer(pool_words[0]));
                log::debug!("Decrypted encryption proxy function");
            } else if func_words[0..4] == [0xe92d000f, 0xe58ca010, 0xe1a0a00c, 0xe59fc054] {
                // Decryption wrapper proxy
                let pool_words = get_constant_pool(base_address, end_address, words, function.address, function.size, 2)?;
                encoded_function_pointers.push(EncodedFunctionPointer(pool_words[0]));
                encoded_function_pointers.push(EncodedFunctionPointer(pool_words[1]));
                log::debug!("Decrypted decryption wrapper proxy function");
            } else if func_words[0..4] == [0xe92d4ff8, 0xe24dd008, 0xe1a0b003, 0xe1a0a000]
                || func_words[0..4] == [0xe92d4ff8, 0xe24dd010, 0xe1a0a000, 0xe1a00003]
            {
                // RC4 encryptor/decryptor
                let pool_words = get_constant_pool(base_address, end_address, words, function.address, function.size, 1)?;
                encoded_function_pointers.push(EncodedFunctionPointer(pool_words[0]));
                encoded_function_pointers.push(EncodedFunctionPointer(pool_words[0] + 0xc));
                log::debug!("Found RC4 encryptor/decryptor");
            } else if func_words[0..4] == [0xe92d43f0, 0xe24ddf43, 0xe59f7064, 0xe28d8000] {
                // RC4 encrypt/decrypt function
                let pool_words = get_constant_pool(base_address, end_address, words, function.address, function.size, 1)?;
                encoded_function_pointers.push(EncodedFunctionPointer(pool_words[0]));
                encoded_function_pointers.push(EncodedFunctionPointer(pool_words[0] + 0x4));
                encoded_function_pointers.push(EncodedFunctionPointer(pool_words[0] + 0x8));
                encoded_function_pointers.push(EncodedFunctionPointer(pool_words[0] + 0x10));
                log::debug!("Found RC4 encrypt/decrypt function");
            }
        }
        Ok((decryption_wrappers, encoded_function_pointers))
    }

    fn decode_function_tables(
        &self,
        options: &AlgoDecryptOptions,
        words: &mut [u32],
        dsprot_bss: u32,
        obfuscated_function_tables: &[EncryptedFunction],
    ) -> Result<Vec<EncryptedFunction>, DsProtError> {
        let AlgoDecryptOptions { base_address, end_address, .. } = *options;

        let mut encrypted_functions = Vec::new();
        for &EncryptedFunction { address: func_address, size: func_size, encryption: _, constant_pool } in
            obfuscated_function_tables
        {
            let EncodedConstantPool::ObfuscatedFunctionTable { with_garbage, with_overwrite } = constant_pool else {
                continue;
            };

            let function_table_address = func_address + func_size;

            log::debug!("Obfuscated function table found at {:#010x}", function_table_address);

            let pool_offset = ((function_table_address - base_address) / 4) as usize;
            let Some(pool_words) = words.get_mut(pool_offset..) else {
                return OutOfBoundsSnafu {
                    what: "function table",
                    address: function_table_address,
                    base_address,
                    end_address,
                }
                .fail();
            };

            let mut pool_iter = pool_words.iter_mut();
            while let Some(first) = pool_iter.next()
                && let Some(second) = pool_iter.next()
            {
                if *first == 0 {
                    // End of list
                    break;
                }

                let func_address = *first - self.reference_offset();
                let func_size = *second - dsprot_bss - self.reference_offset();
                log::debug!("Found unkeyed encrypted function at {:#010x}, size {:#x}", func_address, func_size);

                *first = func_address;
                *second = func_size;

                encrypted_functions.push(EncryptedFunction {
                    address: func_address,
                    size: func_size,
                    encryption: EncryptionType::Unkeyed,
                    constant_pool: EncodedConstantPool::None,
                });
            }

            // Decode pointer to garbage data
            if with_garbage && let Some(next_chunk) = pool_iter.next() {
                *next_chunk -= self.reference_offset();
                log::debug!("Decoded garbage pointer after decoder function at {:#010x}", func_address);
            }
            // Decode pointer to this decoder function
            if with_overwrite && let Some(next_chunk) = pool_iter.next() {
                *next_chunk -= self.reference_offset();
                log::debug!("Decoded overwrite pointer after decoder function at {:#010x}", func_address);
            }
        }
        Ok(encrypted_functions)
    }

    fn decrypt_wrappers(
        &self,
        options: &AlgoDecryptOptions,
        words: &mut [u32],
        decryption_wrappers: &mut [EncryptedFunction],
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
            let func_offset = ((function.address - base_address) / 4) as usize;
            let func_end_offset = func_offset + (function.size / 4) as usize;
            let Some(func_words) = words.get_mut(func_offset..func_end_offset) else {
                return RangeOutOfBoundsSnafu {
                    what: "encrypted function",
                    start: function.address,
                    end: function.address + function.size,
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
            func_start[0..limit].copy_from_slice(&func_words[0..limit]);

            let Some(pool_words) = words.get_mut(func_end_offset..) else {
                return OutOfBoundsSnafu {
                    what: "encrypted function constant pool",
                    address: function.address + function.size,
                    base_address,
                    end_address,
                }
                .fail();
            };

            let reference_offset = self.reference_offset();

            if func_start[0..4] == [0xe92d4ff8, 0xe24dd080, 0xe59f209c, 0xe59f109c]
                || func_start[0..4] == [0xe92d41f0, 0xe24dd080, 0xe59f3080, 0xe59f2080]
                || func_start[0..4] == [0xe92d41f0, 0xe24dd080, 0xe59f308c, 0xe59f208c]
                || func_start[0..4] == [0xe92d41f0, 0xe24dd080, 0xe59f307c, 0xe59f207c]
            {
                // Flashcart/Emulator detector
                let test_fn_addr = pool_words[0] - reference_offset;
                let integrity_fn_addr = pool_words[1] - reference_offset;
                pool_words[0] = test_fn_addr;
                pool_words[1] = integrity_fn_addr;
                function.constant_pool = EncodedConstantPool::FlashcartEmulatorDetectorType1;
                log::debug!("Decrypted flashcart/emulator detector (type 1)");
            } else if func_start[0..4] == [0xe92d4ff8, 0xe24dd098, 0xe59f2170, 0xe59f4170]
                || func_start[0..4] == [0xe92d4ff8, 0xe24dd098, 0xe59f2174, 0xe59f4174]
            {
                // Flashcart/Emulator detector
                let callback_index_addr = pool_words[0] - reference_offset;
                let callback_table_addr = pool_words[1] - reference_offset;
                let test_fn_addr = pool_words[2] - reference_offset;
                let integrity_fn_addr = pool_words[3] - reference_offset;
                pool_words[0] = callback_index_addr;
                pool_words[1] = callback_table_addr;
                pool_words[2] = test_fn_addr;
                pool_words[3] = integrity_fn_addr;
                function.constant_pool = EncodedConstantPool::FlashcartEmulatorDetectorType2;
                log::debug!("Decrypted flashcart/emulator detector (type 2)");
            } else if func_start[0..4] == [0xe92d41f0, 0xe24dd080, 0xe59f3070, 0xe3a02000]
                || func_start[0..4] == [0xe92d41f0, 0xe24dd080, 0xe59f3074, 0xe3a02000]
                || func_start[0..4] == [0xe92d41f0, 0xe24dd080, 0xe59f3080, 0xe3a02000]
            {
                // Dummy detector
                let test_fn_addr = pool_words[0] - reference_offset;
                pool_words[0] = test_fn_addr;
                function.constant_pool = EncodedConstantPool::DummyDetector;
                log::debug!("Decrypted dummy detector");
            } else if func_start[0..4] == [0xe92d4ff8, 0xe24dd018, 0xe59fa100, 0xe59f6100] {
                // MAC and ROM integrity checkers
                let mac_integrity_fn_addr = pool_words[0] - reference_offset;
                let mac_test_fn_addr = pool_words[1] - reference_offset;
                let rom_integrity_fn_addr = pool_words[2] - reference_offset;
                let rom_test_fn_addr = pool_words[3] - reference_offset;
                pool_words[0] = mac_integrity_fn_addr;
                pool_words[1] = mac_test_fn_addr;
                pool_words[2] = rom_integrity_fn_addr;
                pool_words[3] = rom_test_fn_addr;
                function.constant_pool = EncodedConstantPool::MacRomIntegrityChecker;
                log::debug!("Decrypted MAC and ROM integrity checkers");
            } else if func_start[6] == 0x112fff1e {
                // Integrity checkers
                let checked_fn_addr = pool_words[0] - self.integrity_check_offset();
                pool_words[0] = checked_fn_addr;
                function.constant_pool = EncodedConstantPool::IntegrityChecker;
                log::debug!("Decrypted integrity checker");
            } else if func_start[0..4] == [0xe1a0a00f, 0xe19aa00a, 0x102ee00e, 0xe25aa008] {
                // Crash
                let clear_fn_addr = pool_words[0] - reference_offset;
                let terminate_fn_addr = pool_words[1] - reference_offset;
                pool_words[0] = clear_fn_addr;
                pool_words[1] = terminate_fn_addr;
                function.constant_pool = EncodedConstantPool::Crash;
                log::debug!("Decrypted crash function");
            }
            // The other function types don't have any encrypted constant pools
        }
        Ok(())
    }

    fn decode_function_pointers(
        &self,
        options: &AlgoDecryptOptions,
        words: &mut [u32],
        encoded_function_pointers: &[EncodedFunctionPointer],
    ) -> Result<(), DsProtError> {
        let &AlgoDecryptOptions { base_address, end_address, .. } = options;
        for &encoded_fn_ptr in encoded_function_pointers.iter() {
            let Some(encoded_fn) = words.get_mut((encoded_fn_ptr.0 - base_address) as usize / 4) else {
                return OutOfBoundsSnafu {
                    what: "encoded function pointer",
                    address: encoded_fn_ptr.0,
                    base_address,
                    end_address,
                }
                .fail();
            };
            *encoded_fn -= self.reference_offset();
        }
        Ok(())
    }
}

fn get_constant_pool(
    base_address: u32,
    end_address: u32,
    words: &mut [u32],
    func_address: u32,
    func_size: u32,
    pool_size: u32,
) -> Result<&mut [u32], DsProtError> {
    let pool_offset = ((func_address + func_size - base_address) / 4) as usize;
    let wrapper_end_offset = pool_offset + pool_size as usize;
    let Some(pool_words) = words.get_mut(pool_offset..wrapper_end_offset) else {
        return RangeOutOfBoundsSnafu {
            what: "decryption wrapper constant pool",
            start: func_address + func_size,
            end: func_address + pool_size * 4,
            base_address,
            end_address,
        }
        .fail();
    };
    Ok(pool_words)
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
    let offset = (reference_offset + 8) >> 2;
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
    let offset = (reference_offset + 8) >> 2;
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
    encrypt_opcode: fn(curr: u8, prev: u8) -> u8,
}

impl DsProtAlgo for DsProtAlgoV1 {
    fn reference_offset(&self) -> u32 {
        0 // unused
    }

    fn integrity_check_offset(&self) -> u32 {
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

    fn precalculated_seed_key(&self) -> Option<u32> {
        None
    }

    fn init_rc4(&self, seed_key: u32, _func_size: u32) -> Rc4 {
        let expanded_key = expand_seed_key_old(seed_key);
        Rc4::new(&expanded_key, None)
    }

    fn decrypt(&self, words: &mut [u32], options: &AlgoDecryptOptions) -> Result<DsProtDecryptDetails, DsProtError> {
        let AlgoDecryptOptions { base_address, version, .. } = *options;

        // Find the starts and keys of all encrypted code ranges
        let encrypted_range_starts: Vec<(u32, u32)> = words
            .windows(7)
            .enumerate()
            .filter(|(_i, word)| [word[0], word[1], word[2], word[4], word[5]] == self.encrypted_range_start_signature)
            .map(|(i, word)| {
                let start_address = base_address + i as u32 * 4 + 0x1c;
                let key = word[6];
                (start_address, key)
            })
            .collect();

        let mut encrypted_ranges = Vec::new();
        for (start_address, key) in encrypted_range_starts {
            log::debug!("Found encrypted range starting at {:#010x} with key {:#010x}", start_address, key);

            let mut rc4 = self.init_rc4(key, 0); // function size not needed

            for address in (start_address..).step_by(4) {
                let offset = ((address - base_address) / 4) as usize;
                let instruction = words[offset];
                if instruction == key {
                    encrypted_ranges.push(EncryptedRange { start_address, end_address: address });
                    break;
                }
                let prev_ins = 0; // unused
                words[offset] = self.decrypt_instruction(&mut rc4, instruction, prev_ins);
            }
        }
        encrypted_ranges.sort_unstable_by_key(|r| r.start_address);

        Ok(DsProtDecryptDetails::Pre1_23 { version, encrypted_ranges })
    }
}

impl DsProtAlgo for DsProtAlgoV2 {
    fn reference_offset(&self) -> u32 {
        self.reference_offset
    }

    fn integrity_check_offset(&self) -> u32 {
        self.reference_offset * 2
    }

    fn unkeyed_encryption_xor(&self) -> u32 {
        self.unkeyed_encryption_xor
    }

    fn unkeyed_encrypt_instruction(&self, ins: u32, xor: u32) -> (u32, u32) {
        let new_ins = match InstructionCategory::new(ins) {
            InstructionCategory::BlxImm | InstructionCategory::Bl => encrypt_branch_1(self.reference_offset, ins),
            InstructionCategory::B => encrypt_branch_2(self.reference_offset, ins),
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

    fn precalculated_seed_key(&self) -> Option<u32> {
        None
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

    fn integrity_check_offset(&self) -> u32 {
        self.reference_offset * 2
    }

    fn unkeyed_encryption_xor(&self) -> u32 {
        self.unkeyed_encryption_xor
    }

    fn unkeyed_encrypt_instruction(&self, ins: u32, xor: u32) -> (u32, u32) {
        match InstructionCategory::new(ins) {
            InstructionCategory::BlxImm | InstructionCategory::B => {
                let new_ins = decrypt_branch_2(self.reference_offset, ins);
                (new_ins, xor)
            }
            InstructionCategory::Bl => {
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

    fn precalculated_seed_key(&self) -> Option<u32> {
        None
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

    fn integrity_check_offset(&self) -> u32 {
        self.reference_offset * 2
    }

    fn unkeyed_encryption_xor(&self) -> u32 {
        self.unkeyed_encryption_xor
    }

    fn unkeyed_encrypt_instruction(&self, ins: u32, xor: u32) -> (u32, u32) {
        match InstructionCategory::new(ins) {
            InstructionCategory::BlxImm | InstructionCategory::B => {
                let new_ins = decrypt_branch_2(self.reference_offset, ins);
                (new_ins, (xor ^ (ins >> 24)) & 0xffffff)
            }
            InstructionCategory::Bl => {
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

    fn precalculated_seed_key(&self) -> Option<u32> {
        None
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

    fn integrity_check_offset(&self) -> u32 {
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

    fn precalculated_seed_key(&self) -> Option<u32> {
        None
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

    fn integrity_check_offset(&self) -> u32 {
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
        let new_opcode = (self.encrypt_opcode)(opcode, prev_opcode);
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

    fn precalculated_seed_key(&self) -> Option<u32> {
        Some(self.precalculated_seed_key)
    }

    fn init_rc4(&self, seed_key: u32, func_size: u32) -> Rc4 {
        let expanded_key = expand_seed_key(seed_key, func_size);
        Rc4::new(bytemuck::cast_slice(&expanded_key), Some(0xaa))
    }
}

/// Contains complete information about how DS Protect's encrypted code was decrypted.
#[derive(Serialize, Deserialize)]
pub enum DsProtDecryptDetails {
    /// Before DS Protect version 1.23
    Pre1_23 {
        /// The DS Protect version number.
        version: &'static str,
        /// List of encrypted ranges of instructions.
        encrypted_ranges: Vec<EncryptedRange>,
    },
    /// DS Protect version 1.23 and onwards
    Post1_23 {
        /// The DS Protect version number.
        version: &'static str,
        /// Address of the DS Protect BSS variable. Used for offsetting constants.
        dsprot_bss: u32,
        /// List of encrypted functions.
        encrypted_functions: Vec<EncryptedFunction>,
        /// List of encoded function pointers.
        encoded_function_pointers: Vec<EncodedFunctionPointer>,
    },
}

impl DsProtDecryptDetails {
    /// Returns a [`DisplayDsProtDecryptDetails`] which implements [`Display`].
    pub fn display(&self, indent: usize) -> DisplayDsProtDecryptDetails<'_> {
        DisplayDsProtDecryptDetails { inner: self, indent }
    }
}

/// Can be used to display values inside [`DsProtDecryptDetails`].
pub struct DisplayDsProtDecryptDetails<'a> {
    inner: &'a DsProtDecryptDetails,
    indent: usize,
}

impl Display for DisplayDsProtDecryptDetails<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let i = " ".repeat(self.indent);
        let inner = self.inner;
        match inner {
            DsProtDecryptDetails::Pre1_23 { version, encrypted_ranges } => {
                writeln!(f, "{i}Version ........... : {}", version)?;
                writeln!(f, "{i}Encrypted ranges .. :")?;
                for range in encrypted_ranges {
                    writeln!(f, "{i}  {:#010x}..{:#010x}", range.start_address, range.end_address)?;
                }
            }
            DsProtDecryptDetails::Post1_23 { version, dsprot_bss, encrypted_functions, encoded_function_pointers } => {
                writeln!(f, "{i}Version .................... : {}", version)?;
                writeln!(f, "{i}BSS variable ............... : {:#010x}", dsprot_bss)?;
                writeln!(f, "{i}Encrypted functions ........ :")?;
                for function in encrypted_functions {
                    writeln!(f, "{i}  Address ................ : {:#010x}", function.address)?;
                    writeln!(f, "{i}  Size ................... : {:#x}", function.size)?;
                    write!(f, "{i}  Encryption ............. : ")?;
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
                    writeln!(f, "{i}  Encoded constant pool .. : {:?}\n", function.constant_pool)?;
                }
                writeln!(f, "{i}Encoded function pointers .. :")?;
                for fn_ptr in encoded_function_pointers {
                    writeln!(f, "{i}  Address .. : {:#010x}", fn_ptr.0)?;
                }
            }
        }
        Ok(())
    }
}

/// Represents an address range of encrypted instructions.
#[derive(Serialize, Deserialize)]
pub struct EncryptedRange {
    start_address: u32,
    end_address: u32,
}

/// Contains information about an encrypted function.
#[derive(Serialize, Deserialize)]
pub struct EncryptedFunction {
    address: u32,
    size: u32,
    encryption: EncryptionType,
    constant_pool: EncodedConstantPool,
}

/// The type of encryption used on an [`EncryptedFunction`].
#[derive(Clone, Copy, Serialize, Deserialize)]
pub enum EncryptionType {
    /// No encryption, only encoded constant pool.
    None,
    /// Unkeyed encryption using an XOR cipher.
    Unkeyed,
    /// Keyed encryption using modified [`Rc4`].
    Keyed(u32),
}

/// Represents a type of DS Protect function whose constant pool contains encoded values.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone, Copy)]
pub enum EncodedConstantPool {
    /// No encoding, only encryption.
    None,
    /// Encodes an array of (function address, function size).
    ObfuscatedFunctionTable {
        /// If true, a pointer to DS Protect's garbage data was appended to the end of the constant pool.
        with_garbage: bool,
        /// If true, a pointer to this decoder function was appended to the end of the constant pool.
        with_overwrite: bool,
    },
    /// Encodes BSS var address, dest function size, seed key, dest function address, optionally pointer to garbage.
    DecryptionWrapperType1 {
        /// If true, a pointer to DS Protect's garbage data was appended to the end of the constant pool.
        with_garbage: bool,
    },
    /// Encodes BSS var address, seed key, dest function address, dest function size, wrapper fragment address.
    DecryptionWrapperType2 {
        /// If true, a pointer to DS Protect's garbage data was appended to the end of the constant pool.
        with_garbage: bool,
    },
    /// Encodes BSS var address, seed key placeholder, dest function address, dest function size, wrapper fragment address.
    DecryptionWrapperType3 {
        /// If true, a pointer to DS Protect's garbage data was appended to the end of the constant pool.
        with_garbage: bool,
    },
    /// Encodes test function address, integrity checker address.
    FlashcartEmulatorDetectorType1,
    /// Encodes callback index address, callback table address, test function address, integrity checker address.
    FlashcartEmulatorDetectorType2,
    /// Encodes test function address.
    DummyDetector,
    /// Encodes checked function address.
    IntegrityChecker,
    /// Encodes two sets of checked function address, test function address.
    MacRomIntegrityChecker,
    /// Encodes memory clear function address, terminate function address.
    Crash,
}

/// Represents a function pointer in a data section, which was encoded by adding the reference
/// offset value.
#[derive(PartialEq, Eq, Clone, Copy, Serialize, Deserialize)]
pub struct EncodedFunctionPointer(u32);
