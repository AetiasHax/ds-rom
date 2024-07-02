use std::io;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ReadError {
    #[error("expected {expected:#x} bytes for {section} but had only {actual:#x}")]
    DataTooSmall { section: &'static str, expected: usize, actual: usize },
    #[error("io error")]
    Io(io::Error),
}

impl From<io::Error> for ReadError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}
