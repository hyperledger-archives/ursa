extern crate merlin;
extern crate rand;

use crate::r1cs::{ConstraintSystem, LinearCombination, Variable};
use amcl_wrapper::field_elem::FieldElement;

/// Constrain a linear combination to be equal to a scalar
pub fn constrain_lc_with_scalar<CS: ConstraintSystem>(
    cs: &mut CS,
    lc: LinearCombination,
    scalar: &FieldElement,
) {
    cs.constrain(lc - LinearCombination::from(*scalar));
}

fn get_byte_size(num_digits: usize, base: usize) -> usize {
    assert!(base.is_power_of_two());
    let num_bits_per_digit = base.checked_next_power_of_two().unwrap();
    let num_bits = num_digits * num_bits_per_digit;
    num_bits / 8 + {
        if num_bits % 8 == 0 {
            0
        } else {
            1
        }
    }
}

pub mod bit;
pub mod mimc;
pub mod non_zero;
pub mod poseidon;
pub mod positive_no;
pub mod sparse_merkle_tree_4_ary;
pub mod sparse_merkle_tree_8_ary;
pub mod vector_sum;
