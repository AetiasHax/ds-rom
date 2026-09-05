use std::{mem::size_of, ops::Range};

use serde::{Deserialize, Serialize};
use snafu::{Backtrace, Snafu};

use super::raw::HmacSha1Signature;
use crate::crypto::hmac_sha1::HmacSha1;

/// Shape of the digest tables. The sector and block sizes come from the ROM header and are the only parts a rebuild cannot
/// derive from the ROM layout.
#[derive(Serialize, Deserialize, Clone, Copy)]
pub struct DigestParams {
    /// Number of bytes covered by one sector hash, normally 0x400.
    pub sector_size: u32,
    /// Number of sector hashes covered by one block hash, normally 0x20.
    pub block_sector_count: u32,
}

impl Default for DigestParams {
    fn default() -> Self {
        Self { sector_size: 0x400, block_sector_count: 0x20 }
    }
}

/// Errors related to [`Digest::compute`].
#[derive(Debug, Snafu)]
pub enum DigestError {
    /// Occurs when a digest region is not a whole number of sectors.
    #[snafu(display(
        "digest region {start:#x}..{end:#x} is not a multiple of the sector size {sector_size:#x}:\n{backtrace}"
    ))]
    UnalignedRegion {
        /// Start of the region.
        start: u32,
        /// End of the region.
        end: u32,
        /// Sector size.
        sector_size: u32,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// Occurs when a digest region lies outside the ROM.
    #[snafu(display("digest region {start:#x}..{end:#x} exceeds the ROM size {rom_size:#x}:\n{backtrace}"))]
    RegionOutOfBounds {
        /// Start of the region.
        start: u32,
        /// End of the region.
        end: u32,
        /// Size of the ROM.
        rom_size: usize,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// Occurs when [`DigestParams`] has a zero sector size or block sector count.
    #[snafu(display("digest sector size and block sector count must both be nonzero:\n{backtrace}"))]
    ZeroSized {
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
}

/// The digest tables of a DSi title. Every sector of the NTR and TWL regions gets a SHA1-HMAC in the sector hashtable, every
/// [`DigestParams::block_sector_count`] entries of that table get one in the block hashtable, and the whole block hashtable
/// gets one master hash which lives in the ROM header.
pub struct Digest {
    sector_hashtable: Vec<u8>,
    block_hashtable: Vec<u8>,
    master: HmacSha1Signature,
}

impl Digest {
    /// Computes the digest tables over the NTR and TWL regions of `rom`.
    ///
    /// `rom` must be in *digest form*, which is not the same as the ROM that gets written: the ARM9 secure area must be
    /// encrypted and the Modcrypt areas must be decrypted. See [`Rom::build`](super::Rom::build).
    ///
    /// # Errors
    ///
    /// This function will return an error if a region is out of bounds or not a whole number of sectors.
    pub fn compute(
        hmac_sha1: &HmacSha1,
        params: &DigestParams,
        rom: &[u8],
        ntr_region: Range<u32>,
        twl_region: Range<u32>,
    ) -> Result<Self, DigestError> {
        if params.sector_size == 0 || params.block_sector_count == 0 {
            return ZeroSizedSnafu {}.fail();
        }
        let hash_size = size_of::<HmacSha1Signature>();

        // --------------------- Sector hashtable ---------------------
        let mut sector_hashtable = Vec::new();
        for region in [&ntr_region, &twl_region] {
            if region.is_empty() {
                continue;
            }
            if region.end as usize > rom.len() {
                return RegionOutOfBoundsSnafu { start: region.start, end: region.end, rom_size: rom.len() }.fail();
            }
            if !(region.end - region.start).is_multiple_of(params.sector_size) {
                return UnalignedRegionSnafu { start: region.start, end: region.end, sector_size: params.sector_size }.fail();
            }
            for sector in rom[region.start as usize..region.end as usize].chunks(params.sector_size as usize) {
                sector_hashtable.extend_from_slice(&hmac_sha1.compute(sector));
            }
        }

        // The sector hashtable is padded with zeroed entries up to a whole number of blocks, and the last block hash covers
        // that padding.
        let num_sectors = sector_hashtable.len() / hash_size;
        let num_blocks = num_sectors.div_ceil(params.block_sector_count as usize);
        sector_hashtable.resize(num_blocks * params.block_sector_count as usize * hash_size, 0);

        // --------------------- Block hashtable ---------------------
        let block_size = params.block_sector_count as usize * hash_size;
        let mut block_hashtable = Vec::with_capacity(num_blocks * hash_size);
        for block in sector_hashtable.chunks(block_size) {
            block_hashtable.extend_from_slice(&hmac_sha1.compute(block));
        }

        // --------------------- Master hash ---------------------
        let master = HmacSha1Signature::from_hmac_sha1(hmac_sha1, &block_hashtable);

        Ok(Self { sector_hashtable, block_hashtable, master })
    }

    /// Returns the sector hashtable, one SHA1-HMAC per sector.
    pub fn sector_hashtable(&self) -> &[u8] {
        &self.sector_hashtable
    }

    /// Returns the block hashtable, one SHA1-HMAC per block of sector hashes.
    pub fn block_hashtable(&self) -> &[u8] {
        &self.block_hashtable
    }

    /// Returns the master hash, a SHA1-HMAC of the whole block hashtable.
    pub fn master(&self) -> &HmacSha1Signature {
        &self.master
    }
}
