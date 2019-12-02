/*
    SPDX-License-Identifier: Apache-2.0 OR MIT
*/

use failure::{Backtrace, Context, Fail};
use std::fmt;

#[derive(Clone, Eq, PartialEq, Debug, Fail)]
pub enum BulletproofErrorKind {
    #[fail(display = "Occurs when verification of an Inner product proof fails.")]
    IPPVerificationError,

    /// Occurs when there are insufficient generators for the proof.
    #[fail(
        display = "Expected at least {} generators but found {}. Number of generators should be >= {} and a power of 2",
        expected, length, expected
    )]
    InvalidGeneratorsLength { length: usize, expected: usize },

    /// Occurs when the hash is not found in the database. Relevant to databases implementing `HashDb`
    /// trait. The hash is usually the merkle tree hash
    #[fail(display = "Expected to find hash {:?} in the database.", hash)]
    HashNotFoundInDB { hash: Vec<u8> },

    /// Occurs when an incorrect width is passed to for Poseidon hash.
    #[fail(display = "Expected width {} but found {}", expected, width)]
    IncorrectWidthForPoseidon { width: usize, expected: usize },

    /// Occurs when an unacceptable width is passed to for Poseidon hash. Only `acceptable` widths
    /// are supported
    #[fail(display = "Acceptable widths are {:?} but given {}", acceptable, width)]
    UnacceptableWidthForPoseidon {
        width: usize,
        acceptable: Vec<usize>,
    },

    /// Occurs when expected number of Poseidon round constant are not found in the file being read.
    #[fail(display = "Expected {} round constants but found {}", expected, found)]
    IncorrectRoundConstantsForPoseidon { found: usize, expected: usize },

    /// Occurs when no of rows of MDS matrix for Poseidon is not same as width.
    #[fail(display = "Expected {} rows but found {}", expected, found)]
    IncorrectMSDRowCountForPoseidon { found: usize, expected: usize },

    /// Occurs when no of columns of MDS matrix for Poseidon is not same as width.
    #[fail(display = "Expected {} columns but found {}", expected, found)]
    IncorrectMSDColCountForPoseidon { found: usize, expected: usize },

    /// Occurs when Poseidon constants are being read and parsed
    #[fail(
        display = "While parsing Poseidon constant {:?}, got error {:?}",
        constant, error_msg
    )]
    ParseErrorForPoseidonConstant { constant: String, error_msg: String },

    /// Occurs when Merkle tree hash is called with incorrect number of inputs
    #[fail(
        display = "Merkle tree hash is called with incorrect number of inputs. Expected {} inputs but found {}",
        expected, found
    )]
    IncorrectNoOfInputsForMerkleTreeHash { found: usize, expected: usize },

    /// Occurs when a error from Constraint system or gadget is returned.
    #[fail(display = "R1CS Error: {:?}", msg)]
    R1CSError { msg: String },
}

#[derive(Debug)]
pub struct BulletproofError {
    inner: Context<BulletproofErrorKind>,
}

impl BulletproofError {
    pub fn kind(&self) -> BulletproofErrorKind {
        self.inner.get_context().clone()
    }

    pub fn from_kind(kind: BulletproofErrorKind) -> Self {
        Self {
            inner: Context::new("").context(kind),
        }
    }
}

impl From<BulletproofErrorKind> for BulletproofError {
    fn from(kind: BulletproofErrorKind) -> Self {
        Self {
            inner: Context::new(kind),
        }
    }
}

impl From<Context<BulletproofErrorKind>> for BulletproofError {
    fn from(inner: Context<BulletproofErrorKind>) -> Self {
        Self { inner }
    }
}

impl Fail for BulletproofError {
    fn cause(&self) -> Option<&dyn Fail> {
        self.inner.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.inner.backtrace()
    }
}

impl fmt::Display for BulletproofError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.inner, f)
    }
}

/// Represents an error during the proving or verifying of a constraint system.
#[derive(Clone, Debug, Eq, PartialEq, Fail)]
pub enum R1CSErrorKind {
    /// Occurs when there are insufficient generators for the proof.
    #[fail(
        display = "Expected at least {} generators but found {}. Number of generators should be >= {} and a power of 2",
        expected, length, expected
    )]
    InvalidGeneratorsLength { length: usize, expected: usize },

    #[fail(display = "Occurs when verification of an R1CSProof fails.")]
    VerificationError,

    #[fail(display = "This error occurs when the proof encoding is malformed.")]
    FormatError,

    #[fail(
        display = "Occurs when trying to use a missing variable assignment. Used by gadgets that build the constraint system to signal that  a variable assignment is not provided when the prover needs it"
    )]
    MissingAssignment,

    #[fail(display = "Occurs when a gadget receives an inconsistent input")]
    GadgetError {
        /// The description of the reasons for the error.
        description: String,
    },
}

#[derive(Debug)]
pub struct R1CSError {
    inner: Context<R1CSErrorKind>,
}

impl R1CSError {
    pub fn kind(&self) -> R1CSErrorKind {
        self.inner.get_context().clone()
    }

    pub fn from_kind(kind: R1CSErrorKind) -> Self {
        Self {
            inner: Context::new("").context(kind),
        }
    }
}

impl From<R1CSErrorKind> for R1CSError {
    fn from(kind: R1CSErrorKind) -> Self {
        Self {
            inner: Context::new(kind),
        }
    }
}

impl From<Context<R1CSErrorKind>> for R1CSError {
    fn from(inner: Context<R1CSErrorKind>) -> Self {
        Self { inner }
    }
}

impl Fail for R1CSError {
    fn cause(&self) -> Option<&dyn Fail> {
        self.inner.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.inner.backtrace()
    }
}

impl fmt::Display for R1CSError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.inner, f)
    }
}

impl From<R1CSError> for BulletproofError {
    fn from(err: R1CSError) -> BulletproofError {
        let message = Fail::iter_causes(&err)
            .map(|e| e.to_string())
            .collect::<String>();

        match err.kind() {
            _ => BulletproofErrorKind::R1CSError { msg: message }.into(),
        }
    }
}

/// Check if either blinding is provided or random number generator that will be used to generate
/// the blinding is provided. Works like a boolean OR on Option
#[macro_export]
macro_rules! check_for_blindings_or_rng {
    ( $blindings:expr, $rng:expr ) => {{
        if $blindings.is_none() && $rng.is_none() {
            Err(R1CSError::from(R1CSErrorKind::GadgetError {
                description: String::from("Since blindings is None, provide"),
            }))
        } else {
            Ok(())
        }
    }};
}

#[macro_export]
macro_rules! check_for_input_and_blindings_length {
    ( $input:expr, $blindings:expr, $expected_length:expr ) => {{
        if ($input.len() != $expected_length) || ($blindings.len() != $expected_length) {
            Err(R1CSError::from(R1CSErrorKind::GadgetError {
                description: format!("Both input and blindings should be of the same size {} but input size is {} and blindings size is {}", $expected_length, $input.len(), $blindings.len()),
            }))
        } else {
            Ok(())
        }
    }};
}
