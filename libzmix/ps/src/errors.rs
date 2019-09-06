use failure::{Backtrace, Context, Fail, Error};
use zmix::commitments::pok_vc::{PoKVCErrorKind, PoKVCError};

#[derive(Debug, Fail)]
pub enum PSError {
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

impl From<PoKVCError> for PSError {
    fn from(err: PoKVCError) -> Self {
        let message = format!("PoKVCError: {}", Fail::iter_causes(&err).map(|e| e.to_string()).collect::<String>());

        match err.kind() {
            _ => PSError::PoKVCError {msg: message}
        }
    }
}
