/*
    SPDX-License-Identifier: Apache-2.0 OR MIT
*/

//! Definition of the proof struct.

use crate::ipp::InnerProductArgumentProof;
use amcl_wrapper::field_elem::FieldElement;
use amcl_wrapper::group_elem_g1::G1;

/// A proof of some statement specified by a `ConstraintSystem`
///
/// Statements are specified by writing gadget functions which add
/// constraints to a `ConstraintSystem`
/// implementation.  To construct an `R1CSProof`, a prover constructs
/// a `Prover`, then passes it to gadget
/// functions to build the constraint system, then consumes the
/// constraint system using `Prover::prove` to produce an
/// `R1CSProof`.  To verify an `R1CSProof`, a verifier constructs a
/// `Verifier`, then passes it to the same
/// gadget functions to (re)build the constraint system, then consumes
/// the constraint system using `Verifier::verify`
/// to verify the proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct R1CSProof {
    /// Commitment to the values of input wires in the first phase.
    pub(super) A_I1: G1,
    /// Commitment to the values of output wires in the first phase.
    pub(super) A_O1: G1,
    /// Commitment to the blinding factors in the first phase.
    pub(super) S1: G1,
    /// Commitment to the values of input wires in the second phase.
    pub(super) A_I2: G1,
    /// Commitment to the values of output wires in the second phase.
    pub(super) A_O2: G1,
    /// Commitment to the blinding factors in the second phase.
    pub(super) S2: G1,
    /// Commitment to the degree 1 coefficient of `t(x)`
    pub(super) T_1: G1,
    /// Commitment to the degree 3 coefficient of `t(x)`
    pub(super) T_3: G1,
    /// Commitment to the degree 4 coefficient of `t(x)`
    pub(super) T_4: G1,
    /// Commitment to the degree 5 coefficient of `t(x)`
    pub(super) T_5: G1,
    /// Commitment to the degree 6 coefficient of `t(x)`
    pub(super) T_6: G1,
    /// Evaluation of the polynomial `t(x)` at the challenge point `x`
    pub(super) t_x: FieldElement,
    /// Blinding factor for the synthetic commitment to `t(x)`
    pub(super) t_x_blinding: FieldElement,
    /// Blinding factor for the synthetic commitment to the
    /// inner-product arguments
    pub(super) e_blinding: FieldElement,
    /// Proof data for the inner-product argument.
    pub(super) ipp_proof: InnerProductArgumentProof,
}
