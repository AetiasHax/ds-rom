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
        number: "1.00/2",
        detect_signature: [0xe3527270, 0xbafe77fc, 0xe59e0989, 0xe1c2f9af, 0xea018a51, 0xeb004ae2],
        algo: &DsProtAlgoV1,
    },
    DsProtVersion {
        number: "1.05",
        detect_signature: [0xbafe0f18, 0xe59caf7a, 0xe2861884, 0xe1c5da54, 0xea018a6b, 0xeb0070c2],
        algo: &DsProtAlgoV1,
    },
    DsProtVersion {
        number: "1.06",
        detect_signature: [0xbafe9b10, 0xe59cfa77, 0xe2862a71, 0xe1c54e3d, 0xea01879d, 0xeb005fdf],
        algo: &DsProtAlgoV1,
    },
    DsProtVersion {
        number: "1.08",
        detect_signature: [0xbafe4040, 0xe59c2300, 0xe2852226, 0xe1c5cbe8, 0xea01612f, 0xeb004979],
        algo: &DsProtAlgoV1,
    },
    DsProtVersion {
        number: "1.10",
        detect_signature: [0xbafe29a2, 0xe59cc95b, 0xe285d70a, 0xe1c5442c, 0xea01fd7e, 0xeb001cfc],
        algo: &DsProtAlgoV1,
    },
    DsProtVersion {
        number: "1.20",
        detect_signature: [0xe3580f00, 0xbafe7df8, 0xe284dff9, 0xe1c2059d, 0xea014de4, 0xeb002f0c],
        algo: &DsProtAlgoV1,
    },
    DsProtVersion {
        number: "1.22",
        detect_signature: [0xe3581567, 0xbafee339, 0xe284dad2, 0xe1c27622, 0xea017231, 0xeb0037ee],
        algo: &DsProtAlgoV1,
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
        algo: &DsProtAlgoV3 { reference_offset: 0x1200, unkeyed_encryption_xor: 0xf03852cb },
    },
    DsProtVersion {
        number: "1.27",
        detect_signature: [0xe8dffe17, 0xe43df0de, 0x2ae8335c, 0x0ac09826, 0xe7a838dc, 0xe891a6fc],
        algo: &DsProtAlgoV3 { reference_offset: 0x1600, unkeyed_encryption_xor: 0xf0618c46 },
    },
    DsProtVersion {
        number: "1.28",
        detect_signature: [0xe2ed720b, 0xef69d1b1, 0x2ec32a41, 0x1aa3e665, 0xe9e1c153, 0xe49e8d9c],
        algo: &DsProtAlgoV3 { reference_offset: 0x1000, unkeyed_encryption_xor: 0xf0b9a2ea },
    },
    DsProtVersion {
        number: "2.00",
        detect_signature: [0x0819ff33, 0xe4a1ef1c, 0x5a85a2b3, 0xea0d2a0f, 0xe0d6bd78, 0xe29d9377],
        algo: &DsProtAlgoV4 { reference_offset: 0x1700, unkeyed_encryption_xor: 0xa5ca49b3 },
    },
    DsProtVersion {
        number: "2.00 Instant",
        detect_signature: [0x0849ea8b, 0xe33b6243, 0x53b2d501, 0xe6847168, 0xebd886d7, 0xee3c09c0],
        algo: &DsProtAlgoV4 { reference_offset: 0x1700, unkeyed_encryption_xor: 0xa5ca49b3 },
    },
    DsProtVersion {
        number: "2.01",
        detect_signature: [0x08d5310e, 0xe41bdb46, 0x5a3d9627, 0xeaf8fc79, 0xe016c9e7, 0xe2eb8130],
        algo: &DsProtAlgoV4 { reference_offset: 0x2100, unkeyed_encryption_xor: 0x7fec9df1 },
    },
    DsProtVersion {
        number: "2.01 Instant",
        detect_signature: [0x08637dd1, 0xe3618cb3, 0x5356f520, 0xe6b110ca, 0xeb4c1e5c, 0xeed91028],
        algo: &DsProtAlgoV4 { reference_offset: 0x2100, unkeyed_encryption_xor: 0x7fec9df1 },
    },
    DsProtVersion {
        number: "2.03",
        detect_signature: [0x08b76046, 0xe4177f2f, 0x5ab21c99, 0xea2af4b1, 0xe0fe885a, 0xe202fc9e],
        algo: &DsProtAlgoV4 { reference_offset: 0x3200, unkeyed_encryption_xor: 0x7fec9df1 },
    },
    DsProtVersion {
        number: "2.03 Instant",
        detect_signature: [0x08b76046, 0xe4177f2f, 0x5ab21c99, 0xea2af4b1, 0xe0fe885a, 0xe2029efc],
        algo: &DsProtAlgoV4 { reference_offset: 0x3200, unkeyed_encryption_xor: 0x7fec9df1 },
    },
    DsProtVersion {
        number: "2.05",
        detect_signature: [0x08a27510, 0xe47ab3c3, 0x5a289302, 0xeaa6cac8, 0xe00d75d5, 0xe2d2fe01],
        algo: &DsProtAlgoV4 { reference_offset: 0x2200, unkeyed_encryption_xor: 0x7fec9df1 },
    },
    DsProtVersion {
        number: "2.05 Instant",
        detect_signature: [0x08a27510, 0xe47ab3c3, 0x5a289302, 0xeaa6cac8, 0xe00d75d5, 0xe2d2fe00],
        algo: &DsProtAlgoV4 { reference_offset: 0x2200, unkeyed_encryption_xor: 0x7fec9df1 },
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

        self.version.algo.decrypt(words, &AlgoDecryptOptions { base_address, end_address })
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
}

const DECRYPTION_WRAPPER_SIGNATURE_1: [u32; 3] = [0xe92d00f0, 0xe92d000f, 0xe8bd00f0];
const DECRYPTION_WRAPPER_SIGNATURE_2: [u32; 3] = [0xe18fc00f, 0xe01cc00c, 0x03a0c000];

trait DsProtAlgo {
    fn algorithm(&self) -> DsProtAlgoVersion;
    fn reference_offset(&self) -> u32;
    fn integrity_check_offset(&self) -> u32;
    fn unkeyed_encryption_xor(&self) -> u32;
    fn unkeyed_encrypt_instruction(&self, ins: u32, xor: u32) -> (u32, u32);
    fn unkeyed_decrypt_instruction(&self, ins: u32, xor: u32) -> (u32, u32);
    fn decrypt_instruction(&self, rc4: &mut Rc4, ins: u32) -> u32;
    fn init_rc4(&self, seed_key: u32, func_size: u32) -> Rc4;

    // The below default implementations are for version 1.23 onwards (DsProtAlgoV2, V3 and V4), as
    // the de/encryption procedure for those versions are essentially identical aside from the bit
    // twiddling.

    fn decrypt(&self, words: &mut [u32], options: &AlgoDecryptOptions) -> Result<DsProtDecryptDetails, DsProtError> {
        let dsprot_bss = self.find_bss_variable(words, options)?;
        let obfuscated_function_tables = find_obfuscated_function_tables(options, words)?;
        let mut unkeyed_encrypted_functions =
            self.decode_function_tables(options, words, dsprot_bss, &obfuscated_function_tables)?;
        let mut keyed_encrypted_functions =
            self.unkeyed_decrypt_functions(options, words, dsprot_bss, &unkeyed_encrypted_functions)?;
        self.decrypt_wrappers(options, words, &mut keyed_encrypted_functions)?;

        let mut encrypted_functions = obfuscated_function_tables;
        encrypted_functions.append(&mut unkeyed_encrypted_functions);
        encrypted_functions.append(&mut keyed_encrypted_functions);

        Ok(DsProtDecryptDetails::Post1_23 { algorithm: self.algorithm(), dsprot_bss, encrypted_functions })
    }

    fn find_bss_variable(&self, words: &[u32], options: &AlgoDecryptOptions) -> Result<u32, DsProtError> {
        let AlgoDecryptOptions { base_address, .. } = *options;

        let signature_1 = self.unkeyed_encrypt_decryption_wrapper(DECRYPTION_WRAPPER_SIGNATURE_1);
        let signature_2 = self.unkeyed_encrypt_decryption_wrapper(DECRYPTION_WRAPPER_SIGNATURE_2);

        for (i, window) in words.windows(3).enumerate() {
            let func_size = if window == signature_1 {
                0x68
            } else if window == signature_2 {
                0x24
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

    fn unkeyed_encrypt_decryption_wrapper(&self, signature: [u32; 3]) -> [u32; 3] {
        let mut encrypted_signature = [0u32; 3];
        let mut xor = self.unkeyed_encryption_xor();
        for (i, ins) in signature.iter().enumerate() {
            let (new_ins, new_xor) = self.unkeyed_encrypt_instruction(*ins, xor);
            encrypted_signature[i] = new_ins;
            xor = new_xor;
        }
        encrypted_signature
    }

    fn unkeyed_decrypt_functions(
        &self,
        options: &AlgoDecryptOptions,
        words: &mut [u32],
        dsprot_bss: u32,
        unkeyed_encrypted_functions: &[EncryptedFunction],
    ) -> Result<Vec<EncryptedFunction>, DsProtError> {
        let AlgoDecryptOptions { base_address, end_address, .. } = *options;

        let mut decryption_wrappers = Vec::new();
        for &EncryptedFunction { address: func_address, size: func_size, encryption, constant_pool: _ } in
            unkeyed_encrypted_functions
        {
            let EncryptionType::Unkeyed = encryption else { continue };

            let func_offset = ((func_address - base_address) / 4) as usize;
            let instruction_count = (func_size / 4) as usize;

            let Some(func_words) = words.get_mut(func_offset..func_offset + instruction_count) else {
                return RangeOutOfBoundsSnafu {
                    what: "unkeyed encrypted function",
                    start: func_address,
                    end: func_address + func_size,
                    base_address,
                    end_address,
                }
                .fail();
            };

            let mut xor_value = self.unkeyed_encryption_xor();

            log::debug!("Decrypting function at {:#010x} with size {:#x}", func_address, func_size);

            for instruction in func_words.iter_mut() {
                let (new_instruction, new_xor_value) = self.unkeyed_decrypt_instruction(*instruction, xor_value);
                *instruction = new_instruction;
                xor_value = new_xor_value;
            }

            let reference_offset = self.reference_offset();

            if func_words.len() >= 3 && func_words[0..3] == DECRYPTION_WRAPPER_SIGNATURE_1 {
                let pool_words = get_constant_pool(base_address, end_address, words, func_address, func_size, 4)?;

                let bss = pool_words[0] - 1;
                debug_assert_eq!(bss, dsprot_bss);
                let dest_func_size = pool_words[1] - dsprot_bss - reference_offset;
                let seed_key = pool_words[2] - dsprot_bss - reference_offset;
                let dest_func_address = pool_words[3] - reference_offset;

                pool_words[0] = bss;
                pool_words[1] = dest_func_size;
                pool_words[2] = seed_key;
                pool_words[3] = dest_func_address;

                log::debug!(
                    "Found decryption wrapper (type 1) at {:#010x} which targets {:#010x}",
                    func_address,
                    dest_func_address
                );
                decryption_wrappers.push(EncryptedFunction {
                    address: dest_func_address,
                    size: dest_func_size,
                    encryption: EncryptionType::Keyed(seed_key),
                    constant_pool: EncodedConstantPool::DecryptionWrapperType1,
                });
            } else if func_words.len() >= 3 && func_words[0..3] == DECRYPTION_WRAPPER_SIGNATURE_2 {
                let pool_words = get_constant_pool(base_address, end_address, words, func_address, func_size, 6)?;

                let bss = pool_words[0] - 1;
                debug_assert_eq!(bss, dsprot_bss);
                let seed_key = pool_words[1] - dsprot_bss - reference_offset;
                let dest_func_address = pool_words[2] - reference_offset;
                let dest_func_size = pool_words[3] - dsprot_bss - reference_offset;
                let wrapper_fragment = pool_words[5] - reference_offset;

                pool_words[0] = bss;
                pool_words[1] = seed_key;
                pool_words[2] = dest_func_address;
                pool_words[3] = dest_func_size;
                pool_words[5] = wrapper_fragment;

                log::debug!(
                    "Found decryption wrapper (type 2) at {:#010x} which targets {:#010x}",
                    func_address,
                    dest_func_address
                );
                decryption_wrappers.push(EncryptedFunction {
                    address: dest_func_address,
                    size: dest_func_size,
                    encryption: EncryptionType::Keyed(seed_key),
                    constant_pool: EncodedConstantPool::DecryptionWrapperType2,
                });
            }
        }
        Ok(decryption_wrappers)
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
        for &EncryptedFunction { address: func_address, size: func_size, encryption: _, constant_pool: _ } in
            obfuscated_function_tables
        {
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

            for chunk in pool_words.chunks_exact_mut(2) {
                if chunk[0] == 0 {
                    // End of list
                    break;
                }

                let func_address = chunk[0] - self.reference_offset();
                let func_size = chunk[1] - dsprot_bss - self.reference_offset();
                log::debug!("Found unkeyed encrypted function at {:#010x}, size {:#x}", func_address, func_size);

                chunk[0] = func_address;
                chunk[1] = func_size;

                encrypted_functions.push(EncryptedFunction {
                    address: func_address,
                    size: func_size,
                    encryption: EncryptionType::Unkeyed,
                    constant_pool: EncodedConstantPool::None,
                });
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
            for instruction in func_words.iter_mut() {
                *instruction = self.decrypt_instruction(&mut rc4, *instruction);
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
                || func_start[0..4] == [0xe92d41f0, 0xe24dd080, 0xe59f307c, 0xe59f207c]
            {
                // Flashcart/Emulator detector
                let test_fn_addr = pool_words[0] - reference_offset;
                let integrity_fn_addr = pool_words[1] - reference_offset;
                pool_words[0] = test_fn_addr;
                pool_words[1] = integrity_fn_addr;
                function.constant_pool = EncodedConstantPool::FlashcartEmulatorDetectorType1;
                log::debug!("Decrypted flashcart/emulator detector (type 1)");
            } else if func_start[0..4] == [0xe92d4ff8, 0xe24dd098, 0xe59f2170, 0xe59f4170] {
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
            } else if func_start[0..4] == [0xe92d41f0, 0xe24dd080, 0xe59f3070, 0xe3a02000] {
                // Dummy detector
                let test_fn_addr = pool_words[0] - reference_offset;
                pool_words[0] = test_fn_addr;
                function.constant_pool = EncodedConstantPool::DummyDetector;
                log::debug!("Decrypted dummy detector");
            } else if func_start[6] == 0x112fff1e {
                // Integrity checkers
                let checked_fn_addr = pool_words[0] - self.integrity_check_offset();
                pool_words[0] = checked_fn_addr;
                function.constant_pool = EncodedConstantPool::IntegrityChecker;
                log::debug!("Decrypted integrity checker");
            }
            // The other function types don't have any encrypted constant pools
        }
        Ok(())
    }
}

fn find_obfuscated_function_tables(
    options: &AlgoDecryptOptions,
    words: &mut [u32],
) -> Result<Vec<EncryptedFunction>, DsProtError> {
    let AlgoDecryptOptions { base_address, .. } = *options;

    let mut encrypted_functions = Vec::new();
    for (i, window) in words.windows(4).enumerate() {
        let address = base_address + i as u32 * 4;
        let pool_offset = if window[0..2] == [0xe38f0000, 0xe2900004] && window[2] >> 24 == 0x1a {
            0xc
        } else if window[0..2] == [0xe92d4000, 0xe28f0004] && window[2] >> 24 == 0xeb && window[3] == 0xe8bd8000 {
            0x10
        } else {
            continue;
        };
        encrypted_functions.push(EncryptedFunction {
            address,
            size: pool_offset,
            encryption: EncryptionType::None,
            constant_pool: EncodedConstantPool::ObfuscatedFunctionTable,
        });
    }

    Ok(encrypted_functions)
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

/// Defines each version of the de/encryption algorithm.
#[derive(Serialize, Deserialize)]
pub enum DsProtAlgoVersion {
    /// Before 1.23
    V1(DsProtAlgoV1),
    /// Before 1.25
    V2(DsProtAlgoV2),
    /// Before 2.00
    V3(DsProtAlgoV3),
    /// 2.00 onwards
    V4(DsProtAlgoV4),
}

/// Before 1.23
#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct DsProtAlgoV1;

/// Before 1.25
#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct DsProtAlgoV2 {
    reference_offset: u32,
    unkeyed_encryption_xor: u32,
}

/// Before 2.00
#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct DsProtAlgoV3 {
    reference_offset: u32,
    unkeyed_encryption_xor: u32,
}

/// 2.00 onwards
#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct DsProtAlgoV4 {
    reference_offset: u32,
    unkeyed_encryption_xor: u32,
}

impl DsProtAlgo for DsProtAlgoV1 {
    fn algorithm(&self) -> DsProtAlgoVersion {
        DsProtAlgoVersion::V1(*self)
    }

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

    fn decrypt_instruction(&self, rc4: &mut Rc4, ins: u32) -> u32 {
        let bytes = ins.to_le_bytes();
        u32::from_le_bytes([rc4.decrypt_byte(bytes[0]), rc4.decrypt_byte(bytes[1]), bytes[2] ^ 0x01, bytes[3]])
    }

    fn init_rc4(&self, seed_key: u32, _func_size: u32) -> Rc4 {
        let expanded_key = expand_seed_key_old(seed_key);
        Rc4::new(&expanded_key, None)
    }

    fn decrypt(&self, words: &mut [u32], options: &AlgoDecryptOptions) -> Result<DsProtDecryptDetails, DsProtError> {
        let AlgoDecryptOptions { base_address, .. } = *options;

        // Find the starts and keys of all encrypted code ranges
        let encrypted_range_starts: Vec<(u32, u32)> = words
            .windows(7)
            .enumerate()
            .filter(|(_i, word)| {
                word[0] == 0xe92d03ff
                    && word[1] == 0xe3a00006
                    && word[2] == 0xe08f0080
                    && word[4] == 0xe8bd03ff
                    && word[5] == 0xea000000
            })
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
                words[offset] = self.decrypt_instruction(&mut rc4, instruction);
            }
        }

        Ok(DsProtDecryptDetails::Pre1_23 { encrypted_ranges })
    }
}

impl DsProtAlgo for DsProtAlgoV2 {
    fn algorithm(&self) -> DsProtAlgoVersion {
        DsProtAlgoVersion::V2(*self)
    }

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

    fn decrypt_instruction(&self, rc4: &mut Rc4, ins: u32) -> u32 {
        match InstructionCategory::new(ins) {
            InstructionCategory::BlxImm | InstructionCategory::Bl => decrypt_branch_1(self.reference_offset, ins),
            InstructionCategory::B => decrypt_branch_2(self.reference_offset, ins),
            InstructionCategory::Other => {
                let bytes = ins.to_le_bytes();
                u32::from_le_bytes([rc4.decrypt_byte(bytes[0]), rc4.decrypt_byte(bytes[1]), bytes[2] ^ 1, bytes[3]])
            }
        }
    }

    fn init_rc4(&self, seed_key: u32, func_size: u32) -> Rc4 {
        let expanded_key = expand_seed_key(seed_key, func_size);
        Rc4::new(bytemuck::cast_slice(&expanded_key), None)
    }
}

impl DsProtAlgo for DsProtAlgoV3 {
    fn algorithm(&self) -> DsProtAlgoVersion {
        DsProtAlgoVersion::V3(*self)
    }

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

    fn decrypt_instruction(&self, rc4: &mut Rc4, ins: u32) -> u32 {
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

    fn init_rc4(&self, seed_key: u32, func_size: u32) -> Rc4 {
        let expanded_key = expand_seed_key(seed_key, func_size);
        Rc4::new(bytemuck::cast_slice(&expanded_key), Some(0xaa))
    }
}

impl DsProtAlgo for DsProtAlgoV4 {
    fn algorithm(&self) -> DsProtAlgoVersion {
        DsProtAlgoVersion::V4(*self)
    }

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

    fn decrypt_instruction(&self, rc4: &mut Rc4, ins: u32) -> u32 {
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

    fn init_rc4(&self, seed_key: u32, func_size: u32) -> Rc4 {
        let expanded_key = expand_seed_key(seed_key, func_size);
        Rc4::new(bytemuck::cast_slice(&expanded_key), Some(0xaa))
    }
}

/// Contains complete information about how DS Protect's encrypted code was decrypted. This is used
/// when building a ROM so the decrypted code can be re-encrypted so it matches the original ROM.
#[derive(Serialize, Deserialize)]
pub enum DsProtDecryptDetails {
    /// Before DS Protect version 1.23
    Pre1_23 {
        /// List of encrypted ranges of instructions.
        encrypted_ranges: Vec<EncryptedRange>,
    },
    /// DS Protect version 1.23 and onwards
    Post1_23 {
        /// Which decryption algorithm was used.
        algorithm: DsProtAlgoVersion,
        /// Address of the DS Protect BSS variable. Used for offsetting constants.
        dsprot_bss: u32,
        /// List of encrypted functions.
        encrypted_functions: Vec<EncryptedFunction>,
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
            DsProtDecryptDetails::Pre1_23 { encrypted_ranges } => {
                writeln!(f, "{i}Encrypted ranges .. :")?;
                for range in encrypted_ranges {
                    writeln!(f, "{i}  {:#010x}..{:#010x}", range.start_address, range.end_address)?;
                }
            }
            DsProtDecryptDetails::Post1_23 { algorithm, dsprot_bss, encrypted_functions } => {
                writeln!(f, "{i}BSS variable ......... : {:#010x}", dsprot_bss)?;
                write!(f, "{i}Algorithm ............ : ")?;
                match algorithm {
                    DsProtAlgoVersion::V1(_algo) => {
                        writeln!(f, "v1")?;
                    }
                    DsProtAlgoVersion::V2(algo) => {
                        writeln!(
                            f,
                            "v2 (reference offset = {:#x}, xor = {:#x})",
                            algo.reference_offset, algo.unkeyed_encryption_xor
                        )?;
                    }
                    DsProtAlgoVersion::V3(algo) => {
                        writeln!(
                            f,
                            "v3 (reference offset = {:#x}, xor = {:#x})",
                            algo.reference_offset, algo.unkeyed_encryption_xor
                        )?;
                    }
                    DsProtAlgoVersion::V4(algo) => {
                        writeln!(
                            f,
                            "v4 (reference offset = {:#x}, xor = {:#x})",
                            algo.reference_offset, algo.unkeyed_encryption_xor
                        )?;
                    }
                }
                writeln!(f, "{i}Encrypted functions .. :")?;
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
#[derive(Debug, Serialize, Deserialize)]
pub enum EncodedConstantPool {
    /// No encoding, only encryption.
    None,
    /// Encodes an array of (function address, function size).
    ObfuscatedFunctionTable,
    /// Encodes BSS var address, dest function size, seed key, dest function address.
    DecryptionWrapperType1,
    /// Encodes BSS var address, seed key, dest function address, dest function size, wrapper fragment address.
    DecryptionWrapperType2,
    /// Encodes test function address, integrity checker address.
    FlashcartEmulatorDetectorType1,
    /// Encodes callback index address, callback table address, test function address, integrity checker address.
    FlashcartEmulatorDetectorType2,
    /// Encodes test function address.
    DummyDetector,
    /// Encodes checked function address.
    IntegrityChecker,
}
