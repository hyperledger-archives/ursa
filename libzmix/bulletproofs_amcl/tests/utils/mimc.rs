use amcl_wrapper::field_elem::FieldElement;
use bulletproofs::errors::R1CSError;
use bulletproofs::r1cs::{
    ConstraintSystem, LinearCombination, Prover, R1CSProof, Variable, Verifier,
};
use bulletproofs_amcl as bulletproofs;

use bulletproofs::r1cs::linear_combination::AllocatedQuantity;
use merlin::Transcript;

use crate::utils::constrain_lc_with_scalar;

//pub const MIMC_ROUNDS: usize = 322;
pub const MIMC_ROUNDS: usize = 10;

pub fn mimc(xl: &FieldElement, xr: &FieldElement, constants: &[FieldElement]) -> FieldElement {
    assert_eq!(constants.len(), MIMC_ROUNDS);

    let mut xl = xl.clone();
    let mut xr = xr.clone();

    for i in 0..MIMC_ROUNDS {
        let tmp1 = xl + constants[i];
        let mut tmp2 = (tmp1 * tmp1) * tmp1;
        tmp2 += xr;
        xr = xl;
        xl = tmp2;
    }

    xl
}

pub fn mimc_gadget<CS: ConstraintSystem>(
    cs: &mut CS,
    left: AllocatedQuantity,
    right: AllocatedQuantity,
    mimc_rounds: usize,
    mimc_constants: &[FieldElement],
    image: &FieldElement,
) -> Result<(), R1CSError> {
    let res_v = enforce_mimc_2_inputs::<CS>(
        cs,
        left.variable.into(),
        right.variable.into(),
        mimc_rounds,
        mimc_constants,
    )?;
    constrain_lc_with_scalar::<CS>(cs, res_v, image);
    Ok(())
}

pub fn enforce_mimc_2_inputs<CS: ConstraintSystem>(
    cs: &mut CS,
    left: LinearCombination,
    right: LinearCombination,
    mimc_rounds: usize,
    mimc_constants: &[FieldElement],
) -> Result<LinearCombination, R1CSError> {
    let mut left_v = left;
    let mut right_v = right;

    for j in 0..mimc_rounds {
        // xL, xR := xR + (xL + Ci)^3, xL
        //let cs = &mut cs.namespace(|| format!("mimc round {}", j));

        let const_lc: LinearCombination =
            vec![(Variable::One(), mimc_constants[j])].iter().collect();

        let left_plus_const: LinearCombination = left_v.clone() + const_lc;

        let (l, _, l_sqr) = cs.multiply(left_plus_const.clone(), left_plus_const);
        let (_, _, l_cube) = cs.multiply(l_sqr.into(), l.into());

        let tmp = LinearCombination::from(l_cube) + right_v;
        right_v = left_v;
        left_v = tmp;
    }
    Ok(left_v)
}
