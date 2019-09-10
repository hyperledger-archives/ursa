extern crate log;
#[cfg(feature = "serialization")]
extern crate serde_json;

#[cfg(feature = "ffi")]
use ffi::ErrorCode;

use std::cell::RefCell;
use std::ffi::CString;
use std::fmt;
#[cfg(feature = "ffi")]
use std::os::raw::c_char;
#[cfg(feature = "ffi")]
use std::ptr;

use failure::{Backtrace, Context, Fail};

#[cfg(feature = "ffi")]
use utils::ctypes;

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

#[derive(Copy, Clone, Eq, PartialEq, Debug, Fail)]
pub enum UrsaCryptoErrorKind {
    // Common errors
    #[fail(display = "Invalid library state")]
    InvalidState,
    #[fail(display = "Invalid structure")]
    InvalidStructure,
    #[fail(display = "Invalid parameter {}", 0)]
    InvalidParam(u32),
    #[fail(display = "IO error")]
    IOError,
    // CL errors
    #[fail(display = "Proof rejected")]
    ProofRejected,
    #[fail(display = "Revocation accumulator is full")]
    RevocationAccumulatorIsFull,
    #[fail(display = "Invalid revocation id")]
    InvalidRevocationAccumulatorIndex,
    #[fail(display = "Credential revoked")]
    CredentialRevoked,
}

#[derive(Debug)]
pub struct UrsaCryptoError {
    inner: Context<UrsaCryptoErrorKind>,
}

impl Fail for UrsaCryptoError {
    fn cause(&self) -> Option<&dyn Fail> {
        self.inner.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.inner.backtrace()
    }
}

impl UrsaCryptoError {
    pub fn from_msg<D>(kind: UrsaCryptoErrorKind, msg: D) -> UrsaCryptoError
    where
        D: fmt::Display + fmt::Debug + Send + Sync + 'static,
    {
        UrsaCryptoError {
            inner: Context::new(msg).context(kind),
        }
    }

    pub fn kind(&self) -> UrsaCryptoErrorKind {
        *self.inner.get_context()
    }
}

impl fmt::Display for UrsaCryptoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut first = true;

        for cause in Fail::iter_chain(&self.inner) {
            if first {
                first = false;
                writeln!(f, "Error: {}", cause)?;
            } else {
                writeln!(f, "Caused by: {}", cause)?;
            }
        }

        Ok(())
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

impl From<log::SetLoggerError> for UrsaCryptoError {
    fn from(err: log::SetLoggerError) -> UrsaCryptoError {
        err.context(UrsaCryptoErrorKind::InvalidState).into()
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

impl<E> UrsaCryptoErrorExt for E
where
    E: Fail,
{
    fn to_ursa<D>(self, kind: UrsaCryptoErrorKind, msg: D) -> UrsaCryptoError
    where
        D: fmt::Display + Send + Sync + 'static,
    {
        self.context(msg).context(kind).into()
    }
}

thread_local! {
    pub static CURRENT_ERROR_C_JSON: RefCell<Option<CString>> = RefCell::new(None);
}

#[cfg(feature = "ffi")]
pub fn set_current_error(err: &UrsaCryptoError) {
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
