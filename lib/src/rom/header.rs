use snafu::Snafu;

use super::{raw, Logo, LogoError};

pub struct Header {
    logo: Logo,
}

#[derive(Snafu, Debug)]
pub enum HeaderLoadError {
    #[snafu(transparent)]
    Logo { source: LogoError },
}

impl TryFrom<raw::Header> for Header {
    type Error = HeaderLoadError;

    fn try_from(value: raw::Header) -> Result<Self, Self::Error> {
        let logo = Logo::decompress(&value.logo)?;
        Ok(Self { logo })
    }
}
