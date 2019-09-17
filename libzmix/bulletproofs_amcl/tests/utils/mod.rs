extern crate merlin;
extern crate rand;

use amcl_wrapper::field_elem::FieldElement;
use bulletproofs::r1cs::{ConstraintSystem, LinearCombination, Variable};
use bulletproofs_amcl as bulletproofs;

/// Constrain a linear combination to be equal to a scalar
pub fn constrain_lc_with_scalar<CS: ConstraintSystem>(
    cs: &mut CS,
    lc: LinearCombination,
    scalar: &FieldElement,
) {
    cs.constrain(lc - LinearCombination::from(*scalar));
}
