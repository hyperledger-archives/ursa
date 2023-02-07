use string_error::*;
use thiserror::Error as ThisError;

/// The common errors that can occur in Ursa
#[derive(ThisError, Debug)]
#[non_exhaustive]
pub enum UrsaError {
    /// Convert IO errors
    #[error("io error")]
    IoError(#[from] core2::io::Error),
    /// Convert format errors
    #[error("fmt error")]
    FmtError(#[from] std::fmt::Error),
    /// Convert parse bool from string errors
    #[error("parse bool error")]
    ParseBoolError(#[from] std::str::ParseBoolError),
    #[error("environment variable error")]
    /// Convert environment variable errors
    EnvVarError(#[from] std::env::VarError),
    /// Convert json errors
    #[error("json error")]
    JsonError(#[from] serde_json::Error),
    /// Convert cbor errors
    #[error("cbor error")]
    CborError(#[from] serde_cbor::Error),
    /// Convert bare errors
    #[error("bare error")]
    BareError(#[from] serde_bare::error::Error),
    /// Convert thread access errors
    #[error("thread access error")]
    ThreadAccessError(#[from] std::thread::AccessError),
    /// Generic errors to handle anything that implements the std::error::Error trait
    #[error("error: {0}")]
    Kind(Box<dyn std::error::Error>),
}

impl From<String> for UrsaError {
    fn from(value: String) -> Self {
        Self::Kind(into_err(value))
    }
}

impl From<&String> for UrsaError {
    fn from(value: &String) -> Self {
        Self::Kind(into_err(value.clone()))
    }
}

impl From<&str> for UrsaError {
    fn from(value: &str) -> Self {
        Self::Kind(new_err(value))
    }
}

/// Results returned from ursa components
pub type UrsaResult<T> = anyhow::Result<T, UrsaError>;
