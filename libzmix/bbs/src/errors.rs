use crate::pok_sig::PoKOfSignatureProofStatus;
use crate::pok_vc::PoKVCError;
use failure::{Backtrace, Context, Fail};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

/// Convenience importing module
pub mod prelude {
    pub use super::{BBSError, BBSErrorExt, BBSErrorKind};
}

/// The kinds of errors that can be generated
#[derive(Debug, Fail, Clone)]
pub enum BBSErrorKind {
    /// Error during key generation
    #[fail(display = "Key Generation Error")]
    KeyGenError,
    /// When there are more messages than public key generators
    #[fail(
        display = "Public key to message mismatch. Expected {}, found {}",
        0, 0
    )]
    PublicKeyGeneratorMessageCountMismatch(usize, usize),
    /// When the signature is the incorrect size when calling from_bytes
    #[fail(display = "Signature incorrect size. Expected 193, found {}", 0)]
    SignatureIncorrectSize(usize),
    /// When the signature bytes are not a valid curve point
    #[fail(display = "Signature cannot be loaded due to a bad value")]
    SignatureValueIncorrectSize,
    /// When a signature contains a zero or a point at infinity
    #[fail(display = "Malformed signature")]
    MalformedSignature,
    /// When a secret key is all zeros
    #[fail(display = "Malformed secret key")]
    MalformedSecretKey,
    /// When the public key bytes are not valid curve points
    #[fail(display = "Malformed public key")]
    MalformedPublicKey,
    /// Error during proof of knowledge generation
    #[fail(display = "Error from PoKVC module {:?}", msg)]
    PoKVCError {
        /// The error message
        msg: String,
    },
    /// Incorrect number of bytes passed to from_bytes methods
    #[fail(display = "Invalid number of bytes. Expected {}, found {}", 0, 0)]
    InvalidNumberOfBytes(usize, usize),
    /// Failed signature poof of knowledge
    #[fail(display = "The proof failed due to {}", status)]
    InvalidProof {
        /// The status of the invalid proof
        status: PoKOfSignatureProofStatus,
    },
    /// A Generic error
    #[fail(display = "{:?}", msg)]
    GeneralError {
        /// The error message
        msg: String,
    },
}

/// Wrapper to hold the kind of error and a backtrace
#[derive(Debug)]
pub struct BBSError {
    inner: Context<BBSErrorKind>,
}

impl Fail for BBSError {
    fn cause(&self) -> Option<&dyn Fail> {
        self.inner.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.inner.backtrace()
    }
}

impl BBSError {
    /// Convert from a kind and a static string
    pub fn from_msg<D>(kind: BBSErrorKind, msg: D) -> Self
    where
        D: std::fmt::Display + std::fmt::Debug + Send + Sync + 'static,
    {
        BBSError {
            inner: Context::new(msg).context(kind),
        }
    }

    /// Get the inner error kind
    pub fn from_kind(kind: BBSErrorKind) -> Self {
        BBSError {
            inner: Context::new("").context(kind),
        }
    }

    /// Get the inner error kind
    pub fn kind(&self) -> BBSErrorKind {
        self.inner.get_context().clone()
    }
}

impl From<BBSErrorKind> for BBSError {
    fn from(error: BBSErrorKind) -> Self {
        BBSError::from_kind(error)
    }
}

impl From<std::io::Error> for BBSError {
    fn from(err: std::io::Error) -> BBSError {
        BBSError::from_kind(BBSErrorKind::GeneralError {
            msg: format!("{:?}", err),
        })
    }
}

impl std::fmt::Display for BBSError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
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

#[cfg(feature = "wasm")]
impl From<BBSError> for JsValue {
    fn from(error: BBSError) -> Self {
        JsValue::from_str(&format!("{}", error))
    }
}

#[cfg(feature = "wasm")]
impl From<JsValue> for BBSError {
    fn from(js: JsValue) -> Self {
        if js.is_string() {
            BBSError::from(BBSErrorKind::GeneralError {
                msg: js.as_string().unwrap(),
            })
        } else {
            BBSError::from(BBSErrorKind::GeneralError {
                msg: "".to_string(),
            })
        }
    }
}

#[cfg(feature = "wasm")]
impl From<serde_wasm_bindgen::Error> for BBSError {
    fn from(err: serde_wasm_bindgen::Error) -> Self {
        BBSError::from(BBSErrorKind::GeneralError {
            msg: format!("{:?}", err),
        })
    }
}

#[cfg(feature = "wasm")]
impl From<BBSError> for serde_wasm_bindgen::Error {
    fn from(err: BBSError) -> Self {
        serde_wasm_bindgen::Error::new(err)
    }
}

/// Generate an error from a kind and static string
pub fn err_msg<D>(kind: BBSErrorKind, msg: D) -> BBSError
where
    D: std::fmt::Display + std::fmt::Debug + Send + Sync + 'static,
{
    BBSError::from_msg(kind, msg)
}

impl From<Context<BBSErrorKind>> for BBSError {
    fn from(inner: Context<BBSErrorKind>) -> BBSError {
        BBSError { inner }
    }
}

/// Extension methods for `Error`.
pub trait BBSErrorExt {
    /// convert self with kind and static string into an error
    fn to_bbs<D>(self, kind: BBSErrorKind, msg: D) -> BBSError
    where
        D: std::fmt::Display + Send + Sync + 'static;
}

impl<E> BBSErrorExt for E
where
    E: Fail,
{
    fn to_bbs<D>(self, kind: BBSErrorKind, msg: D) -> BBSError
    where
        D: std::fmt::Display + Send + Sync + 'static,
    {
        self.context(msg).context(kind).into()
    }
}

impl From<PoKVCError> for BBSError {
    fn from(err: PoKVCError) -> Self {
        let message = format!(
            "PoKVCError: {}",
            Fail::iter_causes(&err)
                .map(|e| e.to_string())
                .collect::<String>()
        );

        BBSError::from_kind(BBSErrorKind::PoKVCError { msg: message })
    }
}
