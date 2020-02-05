use crate::errors::R1CSError;
use crate::r1cs::{ConstraintSystem, LinearCombination, Variable};
use amcl_wrapper::field_elem::FieldElement;

use crate::r1cs::gadgets::helper_constraints::constrain_lc_with_scalar;

/// Taken from https://eprint.iacr.org/2016/492, section 2.1, MiMC-2n/n (Feistel).
/// For each round: xl = (xl + constants[i])^3 + xr, xr = xl. Output is xl of last round.
pub fn mimc(xl: &FieldElement, xr: &FieldElement, constants: &[FieldElement]) -> FieldElement {
    let mut xl = xl.clone();
    let mut xr = xr.clone();

    for i in 0..constants.len() {
        let tmp1 = &xl + &constants[i];
        let mut tmp2 = tmp1.square() * &tmp1;
        tmp2 += &xr;
        xr = xl;
        xl = tmp2;
    }
    xl
}

/// Enforces the constraints of MiMC and check that the output equals `image`
pub fn mimc_gadget<CS: ConstraintSystem>(
    cs: &mut CS,
    left: LinearCombination,
    right: LinearCombination,
    mimc_constants: &[FieldElement],
    image: &FieldElement,
) -> Result<(), R1CSError> {
    let res_v = enforce_mimc_2_inputs::<CS>(cs, left, right, mimc_constants)?;
    constrain_lc_with_scalar::<CS>(cs, res_v, image);
    Ok(())
}

/// Constraints for MiMC
pub fn enforce_mimc_2_inputs<CS: ConstraintSystem>(
    cs: &mut CS,
    left: LinearCombination,
    right: LinearCombination,
    mimc_constants: &[FieldElement],
) -> Result<LinearCombination, R1CSError> {
    let mut left_v = left;
    let mut right_v = right;

    for j in 0..mimc_constants.len() {
        // xL, xR := xR + (xL + Ci)^3, xL

        let const_lc: LinearCombination = vec![(Variable::One(), mimc_constants[j].clone())]
            .iter()
            .collect();

        let left_plus_const: LinearCombination = left_v.clone() + const_lc;

        let (l, _, l_sqr) = cs.multiply(left_plus_const.clone(), left_plus_const);
        let (_, _, l_cube) = cs.multiply(l_sqr.into(), l.into());

        let tmp = l_cube + right_v;
        right_v = left_v;
        left_v = tmp;
    }
    Ok(left_v)
}
