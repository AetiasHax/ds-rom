use std::{borrow::Cow, fmt::Display};

use super::{HmacSha1Signature, Overlay};
use crate::crypto::hmac_sha1::HmacSha1;

/// An overlay table, used for both ARM9 and ARM7 overlays. This is the raw struct, see the plain one [here](crate::rom::OverlayTable).
pub struct OverlayTable<'a> {
    overlays: Cow<'a, [Overlay]>,
    signature: Option<HmacSha1Signature>,
}

impl<'a> OverlayTable<'a> {
    /// Creates a new overlay table.
    pub fn new<O>(overlays: O, signature: Option<HmacSha1Signature>) -> Self
    where
        O: Into<Cow<'a, [Overlay]>>,
    {
        Self { overlays: overlays.into(), signature }
    }

    /// Returns the overlays in the table.
    pub fn overlays(&'a self) -> &'a [Overlay] {
        self.overlays.as_ref()
    }

    /// Computes the HMAC-SHA1 signature of this overlay table using the given HMAC-SHA1 instance.
    pub fn compute_signature(&self, hmac_sha1: &HmacSha1) -> HmacSha1Signature {
        let bytes = bytemuck::cast_slice(&self.overlays);
        HmacSha1Signature::from_hmac_sha1(hmac_sha1, bytes)
    }

    /// Verifies the HMAC-SHA1 signature of this overlay table using the given HMAC-SHA1 instance.
    pub fn verify_signature(&self, hmac_sha1: &HmacSha1) -> bool {
        let Some(signature) = self.signature() else {
            return true;
        };

        let computed_signature = self.compute_signature(hmac_sha1);
        computed_signature == signature
    }

    /// Returns the HMAC-SHA1 signature of the overlay table, if it exists.
    pub fn signature(&self) -> Option<HmacSha1Signature> {
        self.signature
    }

    /// Returns `true` if this overlay table has an HMAC-SHA1 signature.
    pub fn is_signed(&self) -> bool {
        self.signature.is_some()
    }

    /// Returns the raw bytes of the overlay table.
    pub fn as_bytes(&self) -> &[u8] {
        bytemuck::cast_slice(self.overlays.as_ref())
    }

    /// Returns a [`DisplayOverlayTable`] which implements [`Display`].
    pub fn display(&'a self, indent: usize) -> DisplayOverlayTable<'a> {
        DisplayOverlayTable { overlay_table: self, indent }
    }
}

/// Can be used to display values in [`OverlayTable`].
pub struct DisplayOverlayTable<'a> {
    overlay_table: &'a OverlayTable<'a>,
    indent: usize,
}

impl Display for DisplayOverlayTable<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let i = " ".repeat(self.indent);
        let overlay_table = &self.overlay_table;
        let overlays = overlay_table.overlays();
        let signature = overlay_table.signature().map_or("None".to_string(), |s| s.to_string());

        writeln!(f, "{i}Overlay Table:")?;
        writeln!(f, "{i}Signature: {}", signature)?;
        writeln!(f, "{i}Overlays:")?;

        for overlay in overlays {
            writeln!(f, "{}", overlay.display(self.indent + 2))?;
        }

        Ok(())
    }
}
