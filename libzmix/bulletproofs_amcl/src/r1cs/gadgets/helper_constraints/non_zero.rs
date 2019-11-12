use crate::errors::R1CSError;
use crate::r1cs::{ConstraintSystem, LinearCombination, Variable};
use amcl_wrapper::field_elem::FieldElement;

/// Enforces that x is not 0.
/// Takes x and x_inv as input.
/// The idea is described in the Pinocchio paper in section 3.2, "Zero-Equality Gate". Quoting the paper,
/// "Y = (X! = 0)?1 : 0 is is equivalent to satisfying the following two constraints: X · M −Y = 0 and
/// (1 −Y)· X = 0 for some value M". The constraint is satisfied when M is taken as inverse of x.
/// I first saw it in https://github.com/HarryR/ethsnarks/blob/master/src/gadgets/isnonzero.cpp
pub fn is_nonzero_gadget<CS: ConstraintSystem>(
    cs: &mut CS,
    x: Variable,
    x_inv: Variable,
) -> Result<(), R1CSError> {
    let x_lc = LinearCombination::from(x);
    let y_lc = LinearCombination::from(FieldElement::one());
    let one_minus_y_lc = LinearCombination::from(Variable::One()) - y_lc.clone();

    // Question: Maybe the multiplication constraint is not needed, linear constraint might be ok.
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
