use crate::errors::R1CSError;
use crate::r1cs::{ConstraintSystem, LinearCombination, Variable};
use amcl_wrapper::field_elem::FieldElement;

// Ensure sum of items of `vector` is `sum`
pub fn vector_sum_constraints<CS: ConstraintSystem>(
    cs: &mut CS,
    vector: Vec<Variable>,
    sum: u64,
) -> Result<(), R1CSError> {
    let mut constraints = vec![(Variable::One(), FieldElement::from(sum).negation())];
    for i in vector {
        constraints.push((i, FieldElement::one()));
    }

    cs.constrain(constraints.iter().collect());

    Ok(())
}
