use crate::r1cs::{ConstraintSystem, Variable};
use amcl_wrapper::field_elem::FieldElement;

// Ensure sum of items of `vector` is `sum`
pub fn vector_sum_constraints<CS: ConstraintSystem>(cs: &mut CS, vector: Vec<Variable>, sum: u64) {
    let mut constraints = vec![(Variable::One(), FieldElement::from(sum).negation())];
    for i in vector {
        constraints.push((i, FieldElement::one()));
    }
    cs.constrain(constraints.iter().collect());
}
