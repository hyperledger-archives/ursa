extern crate log;

#[cfg(feature = "ffi")]
use crate::ffi::ErrorCode;

use core::fmt::Display;
use std::cell::RefCell;
use std::ffi::CString;
use std::fmt;
#[cfg(feature = "ffi")]
use std::os::raw::c_char;
#[cfg(feature = "ffi")]
use std::ptr;

#[cfg(feature = "ffi")]
use crate::utils::ctypes;

#[cfg(feature = "ffi")]
pub mod prelude {
    pub use super::{
        err_msg, get_current_error_c_json, set_current_error, UrsaCryptoError, UrsaCryptoErrorExt,
        UrsaCryptoErrorKind, UrsaCryptoResult,
    };
}

#[cfg(not(feature = "ffi"))]
pub mod prelude {
    pub use super::{
        err_msg, UrsaCryptoError, UrsaCryptoErrorExt, UrsaCryptoErrorKind, UrsaCryptoResult,
    };
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, thiserror::Error)]
pub enum UrsaCryptoErrorKind {
    // Common errors
    #[error("Invalid library state")]
    InvalidState,
    #[error("Invalid structure")]
    InvalidStructure,
    #[error("Invalid parameter {_0}")]
    InvalidParam(u32),
    #[error("IO error")]
    IOError,
    // CL errors
    #[error("Proof rejected")]
    ProofRejected,
    #[error("Revocation accumulator is full")]
    RevocationAccumulatorIsFull,
    #[error("Invalid revocation id")]
    InvalidRevocationAccumulatorIndex,
    #[error("Credential revoked")]
    CredentialRevoked,
}

#[derive(Debug)]
pub struct UrsaCryptoError {
    inner: Context<UrsaCryptoErrorKind>,
}

pub struct Context<T> {
    error: T,
    context: String,
    backtrace: &'static str,
}

impl<T: core::fmt::Debug> core::fmt::Debug for Context<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Context")
            .field("error", &self.error)
            .field("context", &self.context)
            .finish()
    }
}

impl<T: Display> Display for Context<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl UrsaCryptoError {
    pub fn from_msg<D>(kind: UrsaCryptoErrorKind, msg: D) -> UrsaCryptoError
    where
        D: fmt::Display + fmt::Debug + Send + Sync + 'static,
    {
        UrsaCryptoError {
            inner: Context {
                error: kind,
                context: msg.to_string(),
                backtrace: "",
            },
        }
    }

    pub fn kind(&self) -> UrsaCryptoErrorKind {
        self.inner.error
    }
}

impl fmt::Display for UrsaCryptoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        todo!()
    }
}

pub fn err_msg<D>(kind: UrsaCryptoErrorKind, msg: D) -> UrsaCryptoError
where
    D: fmt::Display + fmt::Debug + Send + Sync + 'static,
{
    UrsaCryptoError::from_msg(kind, msg)
}

impl From<Context<UrsaCryptoErrorKind>> for UrsaCryptoError {
    fn from(inner: Context<UrsaCryptoErrorKind>) -> UrsaCryptoError {
        UrsaCryptoError { inner }
    }
}

#[cfg(feature = "logger")]
impl From<log::SetLoggerError> for UrsaCryptoError {
    fn from(err: log::SetLoggerError) -> UrsaCryptoError {
        UrsaCryptoError {
            inner: Context {
                error: UrsaCryptoErrorKind::InvalidState,
                context: "Setting logger failed".to_owned(),
                backtrace: "",
            },
        }
    }
}

#[cfg(feature = "ffi")]
impl From<UrsaCryptoErrorKind> for ErrorCode {
    fn from(code: UrsaCryptoErrorKind) -> ErrorCode {
        match code {
            UrsaCryptoErrorKind::InvalidState => ErrorCode::CommonInvalidState,
            UrsaCryptoErrorKind::InvalidStructure => ErrorCode::CommonInvalidStructure,
            UrsaCryptoErrorKind::InvalidParam(num) => match num {
                1 => ErrorCode::CommonInvalidParam1,
                2 => ErrorCode::CommonInvalidParam2,
                3 => ErrorCode::CommonInvalidParam3,
                4 => ErrorCode::CommonInvalidParam4,
                5 => ErrorCode::CommonInvalidParam5,
                6 => ErrorCode::CommonInvalidParam6,
                7 => ErrorCode::CommonInvalidParam7,
                8 => ErrorCode::CommonInvalidParam8,
                9 => ErrorCode::CommonInvalidParam9,
                10 => ErrorCode::CommonInvalidParam10,
                11 => ErrorCode::CommonInvalidParam11,
                12 => ErrorCode::CommonInvalidParam12,
                _ => ErrorCode::CommonInvalidState,
            },
            UrsaCryptoErrorKind::IOError => ErrorCode::CommonIOError,
            UrsaCryptoErrorKind::ProofRejected => ErrorCode::AnoncredsProofRejected,
            UrsaCryptoErrorKind::RevocationAccumulatorIsFull => {
                ErrorCode::AnoncredsRevocationAccumulatorIsFull
            }
            UrsaCryptoErrorKind::InvalidRevocationAccumulatorIndex => {
                ErrorCode::AnoncredsInvalidRevocationAccumulatorIndex
            }
            UrsaCryptoErrorKind::CredentialRevoked => ErrorCode::AnoncredsCredentialRevoked,
        }
    }
}

#[cfg(feature = "ffi")]
impl From<ErrorCode> for UrsaCryptoErrorKind {
    fn from(err: ErrorCode) -> UrsaCryptoErrorKind {
        match err {
            ErrorCode::CommonInvalidState => UrsaCryptoErrorKind::InvalidState,
            ErrorCode::CommonInvalidStructure => UrsaCryptoErrorKind::InvalidStructure,
            ErrorCode::CommonInvalidParam1 => UrsaCryptoErrorKind::InvalidParam(1),
            ErrorCode::CommonInvalidParam2 => UrsaCryptoErrorKind::InvalidParam(2),
            ErrorCode::CommonInvalidParam3 => UrsaCryptoErrorKind::InvalidParam(3),
            ErrorCode::CommonInvalidParam4 => UrsaCryptoErrorKind::InvalidParam(4),
            ErrorCode::CommonInvalidParam5 => UrsaCryptoErrorKind::InvalidParam(5),
            ErrorCode::CommonInvalidParam6 => UrsaCryptoErrorKind::InvalidParam(6),
            ErrorCode::CommonInvalidParam7 => UrsaCryptoErrorKind::InvalidParam(7),
            ErrorCode::CommonInvalidParam8 => UrsaCryptoErrorKind::InvalidParam(8),
            ErrorCode::CommonInvalidParam9 => UrsaCryptoErrorKind::InvalidParam(9),
            ErrorCode::CommonInvalidParam10 => UrsaCryptoErrorKind::InvalidParam(10),
            ErrorCode::CommonInvalidParam11 => UrsaCryptoErrorKind::InvalidParam(11),
            ErrorCode::CommonInvalidParam12 => UrsaCryptoErrorKind::InvalidParam(12),
            ErrorCode::CommonIOError => UrsaCryptoErrorKind::IOError,
            ErrorCode::AnoncredsProofRejected => UrsaCryptoErrorKind::ProofRejected,
            ErrorCode::AnoncredsRevocationAccumulatorIsFull => {
                UrsaCryptoErrorKind::RevocationAccumulatorIsFull
            }
            ErrorCode::AnoncredsInvalidRevocationAccumulatorIndex => {
                UrsaCryptoErrorKind::InvalidRevocationAccumulatorIndex
            }
            ErrorCode::AnoncredsCredentialRevoked => UrsaCryptoErrorKind::CredentialRevoked,
            _code => UrsaCryptoErrorKind::InvalidState,
        }
    }
}

#[cfg(feature = "ffi")]
impl From<UrsaCryptoError> for ErrorCode {
    fn from(err: UrsaCryptoError) -> ErrorCode {
        set_current_error(&err);
        err.kind().into()
    }
}

pub type UrsaCryptoResult<T> = Result<T, UrsaCryptoError>;

/// Extension methods for `Error`.
pub trait UrsaCryptoErrorExt {
    fn to_ursa<D>(self, kind: UrsaCryptoErrorKind, msg: D) -> UrsaCryptoError
    where
        D: fmt::Display + Send + Sync + 'static;
}

impl UrsaCryptoErrorExt for openssl::error::ErrorStack {
    fn to_ursa<D>(self, kind: UrsaCryptoErrorKind, msg: D) -> UrsaCryptoError
    where
        D: fmt::Display + Send + Sync + 'static,
    {
        todo!()
    }
}

thread_local! {
    pub static CURRENT_ERROR_C_JSON: RefCell<Option<CString>> = RefCell::new(None);
}

#[cfg(feature = "ffi")]
pub fn set_current_error(err: &UrsaCryptoError) {
    use serde_json::json;

    CURRENT_ERROR_C_JSON.with(|error| {
        let error_json = json!({
            "message": err.to_string(),
            "backtrace": err.backtrace().map(|bt| bt.to_string())
        })
        .to_string();
        error.replace(Some(ctypes::string_to_cstring(error_json)));
    });
}

#[cfg(feature = "ffi")]
pub fn get_current_error_c_json() -> *const c_char {
    let mut value = ptr::null();

    CURRENT_ERROR_C_JSON.with(|err| err.borrow().as_ref().map(|err| value = err.as_ptr()));

    value
}
