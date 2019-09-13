use commitments::pok_vc::PoKVCError;
use failure::{Backtrace, Context, Fail};

pub mod prelude {
    pub use super::{BBSError, BBSErrorExt, BBSErrorKind};
}

#[derive(Debug, Fail, Clone)]
pub enum BBSErrorKind {
    #[fail(display = "Key Generation Error")]
    KeyGenError,
    #[fail(display = "Signing Error. Expected {}, found {}", 0, 0)]
    SigningErrorMessageCountMismatch(usize, usize),
    #[fail(display = "Signature incorrect size. Expected 193, found {}", 0)]
    SignatureIncorrectSize(usize),
    #[fail(display = "Signature cannot be loaded due to a bad value")]
    SignatureValueIncorrectSize,
    #[fail(display = "Malformed public key")]
    MalformedPublicKey,
    #[fail(display = "Error from PoKVC module {:?}", msg)]
    PoKVCError { msg: String },
    #[fail(display = "{:?}", msg)]
    GeneralError { msg: String },
}

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
    pub fn from_msg<D>(kind: BBSErrorKind, msg: D) -> BBSError
    where
        D: std::fmt::Display + std::fmt::Debug + Send + Sync + 'static,
    {
        BBSError {
            inner: Context::new(msg).context(kind),
        }
    }

    pub fn from_kind(kind: BBSErrorKind) -> BBSError {
        BBSError {
            inner: Context::new("").context(kind),
        }
    }

    pub fn kind(&self) -> BBSErrorKind {
        self.inner.get_context().clone()
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

        match err.kind() {
            _ => BBSError::from_kind(BBSErrorKind::PoKVCError { msg: message }),
        }
    }
}
