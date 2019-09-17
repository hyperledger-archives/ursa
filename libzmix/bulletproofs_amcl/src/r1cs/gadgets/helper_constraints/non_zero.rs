use crate::errors::R1CSError;
use crate::r1cs::{ConstraintSystem, LinearCombination, Variable};
use amcl_wrapper::field_elem::FieldElement;

/// if x == 0 then y = 0 else y = 1
/// if x != 0 then inv = x^-1 else inv = 0
/// x*(1-y) = 0
/// x*inv = y
/// The idea is described in the Pinocchio paper and i first saw it in https://github.com/HarryR/ethsnarks/blob/master/src/gadgets/isnonzero.cpp

/// Enforces that x is not 0.
pub fn is_nonzero_gadget<CS: ConstraintSystem>(
    cs: &mut CS,
    x: Variable,
    x_inv: Variable,
) -> Result<(), R1CSError> {
    let x_lc = LinearCombination::from(x);
    let y_lc = LinearCombination::from(FieldElement::one());
    let one_minus_y_lc = LinearCombination::from(Variable::One()) - y_lc.clone();

    // x * (1-y) = 0
    let (_, _, o1) = cs.multiply(x_lc.clone(), one_minus_y_lc);
    cs.constrain(o1.into());

    // x * x_inv = y
    let inv_lc: LinearCombination = vec![(x_inv, FieldElement::one())].iter().collect();
    let (_, _, o2) = cs.multiply(x_lc.clone(), inv_lc.clone());
    // Output wire should have value `y`
    cs.constrain(o2 - y_lc);

    Ok(())
}
