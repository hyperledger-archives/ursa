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

impl_Errors!(PSErrorKind, PSError);
impl_PoKVCError_conversion!(PSErrorKind, PSError);
