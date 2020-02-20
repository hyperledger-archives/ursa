use crate::commitments::pok_vc::PoKVCError;
use failure::{Backtrace, Context, Fail};
use std::fmt;

#[derive(Clone, Eq, PartialEq, Debug, Fail)]
pub enum DelgCredCDDErrorKind {
    #[fail(
        display = "Setup parameters valid for {} messages but given {} messages",
        expected, given
    )]
    UnsupportedNoOfMessages { expected: usize, given: usize },

    #[fail(display = "Expected even level but odd given {}", given)]
    ExpectedEvenLevel { given: usize },

    #[fail(display = "Expected odd level but even given {}", given)]
    ExpectedOddLevel { given: usize },

    #[fail(display = "Expected level {} but given {}", expected, given)]
    UnexpectedLevel { expected: usize, given: usize },

    #[fail(
        display = "Number of attributes should be less than {} but given {}",
        expected, given
    )]
    MoreAttributesThanExpected { expected: usize, given: usize },

    #[fail(display = "Delegatee verkey not found in delegation link")]
    VerkeyNotFoundInDelegationLink {},

    #[fail(display = "No links in the delegation chain")]
    ChainEmpty {},

    #[fail(display = "No odd delegation links in the delegation chain")]
    NoOddLinksInChain {},

    #[fail(display = "No even delegation links in the delegation chain")]
    NoEvenLinksInChain {},

    #[fail(
        display = "Requested odd link at index {} but only {} odd links present",
        given_index, size
    )]
    NoOddLinkInChainAtGivenIndex { given_index: usize, size: usize },

    #[fail(
        display = "Requested even link at index {} but only {} even links present",
        given_index, size
    )]
    NoEvenLinkInChainAtGivenIndex { given_index: usize, size: usize },

    #[fail(display = "Expected {} verkeys but found {}", expected, given)]
    IncorrectNumberOfVerkeys { expected: usize, given: usize },

    #[fail(
        display = "Expected {} odd level verkeys but found {}",
        expected, given
    )]
    IncorrectNumberOfOddLevelVerkeys { expected: usize, given: usize },

    #[fail(
        display = "Expected {} even level verkeys but found {}",
        expected, given
    )]
    IncorrectNumberOfEvenLevelVerkeys { expected: usize, given: usize },

    #[fail(
        display = "Same no of bases and exponents required. {} bases and {} exponents",
        bases, exponents
    )]
    UnequalNoOfBasesExponents { bases: usize, exponents: usize },

    #[fail(
        display = "Chain size is {} but expected size at least {}",
        actual_size, expected_size
    )]
    ChainIsShorterThanExpected {
        actual_size: usize,
        expected_size: usize,
    },

    #[fail(display = "Expected {} `s` commitments but found {}", expected, given)]
    IncorrectNumberOfSCommitments { expected: usize, given: usize },

    #[fail(display = "Expected {} `t` commitments but found {}", expected, given)]
    IncorrectNumberOfTCommitments { expected: usize, given: usize },

    #[fail(display = "Expected {} blinded `r` but found {}", expected, given)]
    IncorrectNumberOfBlindedR { expected: usize, given: usize },

    #[fail(
        display = "Expected {} sets of revealed attributes but found {}",
        expected, given
    )]
    IncorrectNumberOfRevealedAttributeSets { expected: usize, given: usize },

    #[fail(
        display = "Number of unrevealed attributes should be less than {} but given {}",
        expected, given
    )]
    MoreUnrevealedAttributesThanExpected { expected: usize, given: usize },

    #[fail(
        display = "Unequal number of commitments and responses for {:?}. {} commitments, {} responses",
        entity_type, count_commitments, count_responses
    )]
    UnequalNoOfCommitmentAndResponses {
        count_commitments: usize,
        count_responses: usize,
        entity_type: String,
    },

    #[fail(
        display = "Expected {} odd values but found {} for {:?}",
        expected, given, entity_type
    )]
    IncorrectNumberOfOddValues {
        expected: usize,
        given: usize,
        entity_type: String,
    },

    #[fail(
        display = "Expected {} even values but found {} for {:?}",
        expected, given, entity_type
    )]
    IncorrectNumberOfEvenValues {
        expected: usize,
        given: usize,
        entity_type: String,
    },

    #[fail(display = "Error from PoKVC module {:?}", msg)]
    PoKVCError { msg: String },

    #[fail(display = "Error with message {:?}", msg)]
    GeneralError { msg: String },
}

impl_Errors!(DelgCredCDDErrorKind, DelgCredCDDError);
impl_PoKVCError_conversion!(DelgCredCDDErrorKind, DelgCredCDDError);

pub type DelgCredCDDResult<T> = Result<T, DelgCredCDDError>;
