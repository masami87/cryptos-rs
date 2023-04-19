use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptosError {
    #[error("network failed: {0}")]
    Network(#[from] reqwest::Error),
    #[error("file error: {0}")]
    File(#[from] std::io::Error),
    #[error("key error: {0}")]
    Key(String),
    #[error("Hex error: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("internal error: {0}")]
    Internal(String),
    #[error("unknown error")]
    Unknown,
}

pub type Result<T> = std::result::Result<T, CryptosError>;
