/*
    SPDX-License-Identifier: Apache-2.0 OR MIT
*/

/// Represents an error during the proving or verifying of a constraint system.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum R1CSError {
    /// Occurs when there are insufficient generators for the proof.
    InvalidGeneratorsLength,
    /// Occurs when verification of an R1CSProof fails.
    VerificationError,
    /// This error occurs when the proof encoding is malformed.
    FormatError,
    /// Occurs when trying to use a missing variable assignment.
    /// Used by gadgets that build the constraint system to signal that
    /// a variable assignment is not provided when the prover needs it.
    MissingAssignment,

    /// Occurs when a gadget receives an inconsistent input.
    GadgetError {
        /// The description of the reasons for the error.
        description: String,
    },

    HashNotFoundInDB {
        hash: Vec<u8>,
    },
}

/// Check if either randomness was provided or random number generator was provided. Works like a boolean OR on Option
#[macro_export]
macro_rules! check_for_randomness_or_rng {
    ( $randomness:expr, $rng:expr ) => {{
        if $randomness.is_none() && $rng.is_none() {
            Err(R1CSError::GadgetError {
                description: String::from("Since randomness is None, provide"),
            })
        } else {
            Ok(())
        }
    }};
}

#[macro_export]
macro_rules! check_for_input_and_randomness_length {
    ( $input:expr, $randomness:expr, $expected_length:expr ) => {{
        if ($input.len() != $expected_length) || ($randomness.len() != $expected_length) {
            Err(R1CSError::GadgetError {
                description: format!("Both input and randomness should be of the same size {} but input size is {} and randomness size is {}", $expected_length, $input.len(), $randomness.len()),
            })
        } else {
            Ok(())
        }
    }};
}
