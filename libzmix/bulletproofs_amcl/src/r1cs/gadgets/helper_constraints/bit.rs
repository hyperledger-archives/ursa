use crate::errors::R1CSError;
use crate::r1cs::linear_combination::AllocatedQuantity;
use crate::r1cs::{ConstraintSystem, LinearCombination};
use amcl_wrapper::field_elem::FieldElement;

// Ensure `v` is a bit, hence 0 or 1
pub fn bit_gadget<CS: ConstraintSystem>(
    cs: &mut CS,
    v: &AllocatedQuantity,
) -> Result<(), R1CSError> {
    // TODO: Possible to save reallocation of `v` in `bit`?
    let (a, b, o) = cs.allocate_multiplier(
        v.assignment
            .as_ref()
            .map(|bit| ((FieldElement::one() - bit), bit.clone())),
    )?;

    // Might not be necessary if above TODO is addressed
    // Variable b is same as v so b + (-v) = 0
    let neg_v: LinearCombination = vec![(v.variable, FieldElement::minus_one())]
        .iter()
        .collect();
    cs.constrain(b + neg_v);

    // Enforce a * b = 0, so one of (a,b) is zero
    cs.constrain(o.into());

    // Might not be necessary if above TODO is addressed
    // Enforce that a = 1 - b, so they both are either 1 or 0 and their sum is 1.
    cs.constrain(a + (b - FieldElement::one()));

    Ok(())
}
