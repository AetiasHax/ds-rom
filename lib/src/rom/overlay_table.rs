use super::{
    raw::{self, HmacSha1Signature},
    Arm9, Overlay, OverlayError,
};
use crate::crypto::hmac_sha1::HmacSha1;

/// An overlay table, used for both ARM9 and ARM7 overlays. This is the plain struct, see the raw one [here](super::raw::OverlayTable).
#[derive(Clone, Default)]
pub struct OverlayTable<'a> {
    overlays: Vec<Overlay<'a>>,
    signature: Option<HmacSha1Signature>,
}

impl<'a> OverlayTable<'a> {
    /// Creates a new [`OverlayTable`].
    pub fn new(overlays: Vec<Overlay<'a>>) -> Self {
        Self { overlays, signature: None }
    }

    /// Returns a reference to the overlays of this [`OverlayTable`].
    pub fn overlays(&self) -> &[Overlay<'a>] {
        &self.overlays
    }

    /// Returns a mutable reference to the overlays of this [`OverlayTable`].
    pub fn overlays_mut(&mut self) -> &mut [Overlay<'a>] {
        &mut self.overlays
    }

    /// Returns the length of this [`OverlayTable`].
    pub fn len(&self) -> usize {
        self.overlays.len()
    }

    /// Returns `true` if this [`OverlayTable`] is empty.
    pub fn is_empty(&self) -> bool {
        self.overlays.is_empty()
    }

    /// Parses an [`OverlayTable`] from the given raw ARM9 overlay table.
    ///
    /// # Errors
    ///
    /// See [`Overlay::parse_arm9`].
    pub fn parse_arm9(raw: raw::OverlayTable, rom: &'a raw::Rom, arm9: &Arm9) -> Result<Self, OverlayError> {
        let overlays =
            raw.overlays().iter().map(|overlay| Overlay::parse_arm9(overlay, rom, arm9)).collect::<Result<Vec<_>, _>>()?;
        let signature = raw.signature();
        Ok(Self { overlays, signature })
    }

    /// Parses an [`OverlayTable`] from the given raw ARM7 overlay table.
    ///
    /// # Errors
    ///
    /// See [`Overlay::parse_arm7`].
    pub fn parse_arm7(raw: raw::OverlayTable, rom: &'a raw::Rom) -> Result<Self, OverlayError> {
        let overlays =
            raw.overlays().iter().map(|overlay| Overlay::parse_arm7(overlay, rom)).collect::<Result<Vec<_>, _>>()?;
        let signature = raw.signature();
        Ok(Self { overlays, signature })
    }

    /// Builds a raw overlay table.
    pub fn build(&self) -> raw::OverlayTable<'a> {
        let overlays: Vec<raw::Overlay> = self.overlays.iter().map(|overlay| overlay.build()).collect();
        let signature = self.signature;
        raw::OverlayTable::new(overlays, signature)
    }

    /// Computes the HMAC-SHA1 signature of this overlay table using the given HMAC-SHA1 instance.
    pub fn compute_signature(&self, hmac_sha1: &HmacSha1) -> HmacSha1Signature {
        self.build().compute_signature(hmac_sha1)
    }

    /// Verifies the HMAC-SHA1 signature of this overlay table using the given HMAC-SHA1 instance.
    pub fn verify_signature(&self, hmac_sha1: &HmacSha1) -> bool {
        self.build().verify_signature(hmac_sha1)
    }

    /// Returns the HMAC-SHA1 signature of this overlay table, if it exists.
    pub fn signature(&self) -> Option<HmacSha1Signature> {
        self.signature
    }

    /// Computes and sets the HMAC-SHA1 signature of this overlay table.
    pub fn sign(&mut self, hmac_sha1: &HmacSha1) {
        self.signature = Some(self.compute_signature(hmac_sha1));
    }

    /// Returns `true` if this overlay table has an HMAC-SHA1 signature.
    pub fn is_signed(&self) -> bool {
        self.signature.is_some()
    }

    /// Sets the signature of this overlay table.
    pub fn set_signature(&mut self, signature: HmacSha1Signature) {
        self.signature = Some(signature);
    }
}
