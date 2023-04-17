use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptosError {
    #[error("network failed: {0}")]
    Network(#[from] std::io::Error),
    #[error("key error: {0}")]
    Key(String),
    #[error("internal error: {0}")]
    Internal(String),
    #[error("unknown error")]
    Unknown,
}

pub type Result<T> = std::result::Result<T, CryptosError>;
