use std::fmt::Display;

use bytemuck::{Pod, Zeroable};
use serde::{de::Visitor, Deserialize, Serialize};

/// Represents an RSA signature.
#[repr(C)]
#[derive(Zeroable, Pod, Clone, Copy)]
pub struct RsaSignature(pub [u8; 0x80]);

impl Serialize for RsaSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for RsaSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_bytes(RsaSignatureBytesVisitor)
    }
}

struct RsaSignatureBytesVisitor;

impl<'de> Visitor<'de> for RsaSignatureBytesVisitor {
    type Value = RsaSignature;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("an array of 128 (0x80) bytes")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if v.len() != 0x80 {
            Err(serde::de::Error::custom("RSA signature must be 128 bytes"))
        } else {
            let mut buf = [0u8; 0x80];
            buf.copy_from_slice(v);
            Ok(RsaSignature(buf))
        }
    }
}

impl RsaSignature {
    /// Returns a [`DisplayRsaSignature`] which implements [`Display`].
    pub fn display(&self, indent: usize) -> DisplayRsaSignature<'_> {
        DisplayRsaSignature { rsa_signature: self, indent }
    }
}

/// Can be used to display values inside [`RsaSignature`].
pub struct DisplayRsaSignature<'a> {
    rsa_signature: &'a RsaSignature,
    indent: usize,
}

impl Display for DisplayRsaSignature<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let i = " ".repeat(self.indent);
        let bytes = &self.rsa_signature.0;
        for row in 0..8 {
            write!(f, "{i}")?;
            for col in 0..16 {
                write!(f, "{:02x} ", bytes[row * 16 + col])?;
            }
            writeln!(f)?;
        }
        Ok(())
    }
}
