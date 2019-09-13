use crate::commitments::pok_vc::PoKVCError;
use failure::{Backtrace, Context, Fail};
use std::fmt;

#[derive(Clone, Eq, PartialEq, Debug, Fail)]
pub enum PSErrorKind {
    #[fail(
        display = "Verkey has unequal number of Y and Y_tilde elements. Y={} and Y_tilde={}",
        y, y_tilde
    )]
    InvalidVerkey { y: usize, y_tilde: usize },

    #[fail(
        display = "Verkey valid for {} messages but given {} messages",
        expected, given
    )]
    UnsupportedNoOfMessages { expected: usize, given: usize },

    #[fail(
        display = "Same no of bases and exponents required. {} bases and {} exponents",
        bases, exponents
    )]
    UnequalNoOfBasesExponents { bases: usize, exponents: usize },

    #[fail(display = "Error from PoKVC module {:?}", msg)]
    PoKVCError { msg: String },

    #[fail(display = "Error with message {:?}", msg)]
    GeneralError { msg: String },
}

#[derive(Debug)]
pub struct PSError {
    inner: Context<PSErrorKind>,
}

impl PSError {
    pub fn kind(&self) -> PSErrorKind {
        self.inner.get_context().clone()
    }

    pub fn from_kind(kind: PSErrorKind) -> Self {
        Self {
            inner: Context::new("").context(kind),
        }
    }
}

impl From<PSErrorKind> for PSError {
    fn from(kind: PSErrorKind) -> Self {
        Self {
            inner: Context::new(kind),
        }
    }
}

impl From<Context<PSErrorKind>> for PSError {
    fn from(inner: Context<PSErrorKind>) -> Self {
        Self { inner }
    }
}

impl Fail for PSError {
    fn cause(&self) -> Option<&dyn Fail> {
        self.inner.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.inner.backtrace()
    }
}

impl fmt::Display for PSError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.inner, f)
    }
}

impl From<PoKVCError> for PSError {
    fn from(err: PoKVCError) -> Self {
        let message = format!(
            "PoKVCError: {}",
            Fail::iter_causes(&err)
                .map(|e| e.to_string())
                .collect::<String>()
        );

        match err.kind() {
            _ => PSErrorKind::PoKVCError { msg: message }.into(),
        }
    }
}
