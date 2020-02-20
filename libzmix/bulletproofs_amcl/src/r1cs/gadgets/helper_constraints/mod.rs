use crate::errors::{R1CSError, R1CSErrorKind};
use crate::r1cs::linear_combination::AllocatedQuantity;
use crate::r1cs::{ConstraintSystem, LinearCombination, Variable};
use amcl_wrapper::constants::MODBYTES;
use amcl_wrapper::field_elem::FieldElement;

use rand::{CryptoRng, Rng};

pub mod bit;
pub mod mimc;
pub mod non_zero;
pub mod poseidon;
pub mod positive_no;
pub mod sparse_merkle_tree_4_ary;
pub mod sparse_merkle_tree_8_ary;
pub mod vector_sum;

/// Constrain a linear combination to be equal to a scalar
pub fn constrain_lc_with_scalar<CS: ConstraintSystem>(
    cs: &mut CS,
    lc: LinearCombination,
    scalar: &FieldElement,
) {
    cs.constrain(lc - LinearCombination::from(scalar.clone()));
}

/// Get byte size of number in given `base` with `num_digits` digits in that base
fn get_byte_size(num_digits: usize, base: u8) -> usize {
    let num_bits = get_bit_count(num_digits, base);
    num_bits / 8 + {
        if num_bits % 8 == 0 {
            0
        } else {
            1
        }
    }
}

/// Get max number of bits in given `base` with `num_digits` digits in that base
fn get_bit_count(num_digits: usize, base: u8) -> usize {
    assert!(base.is_power_of_two());
    let num_bits_per_digit = base.trailing_zeros() as usize;
    num_digits * num_bits_per_digit
}

/// Get representation in a base that is a `n`th power of 2 of the given `scalar`. Assumes n <= 8 as
/// n > 8 is not needed anyway where this is being used. Only return `num_digits` of the representation
pub fn get_repr_in_power_2_base(n: u8, scalar: &FieldElement, num_digits: usize) -> Vec<u8> {
    assert!(n <= 8);
    let mut s = scalar.to_bignum();
    s.norm();

    let mut base_n = vec![];
    while (base_n.len() != num_digits) && (!s.iszilch()) {
        base_n.push(s.lastbits(n as usize) as u8);
        s.fshr(n as usize);
    }
    while base_n.len() != num_digits {
        base_n.push(0);
    }

    base_n.reverse();
    base_n
}

fn allocated_leaf_index_to_bytes(leaf_index: AllocatedQuantity) -> Option<[u8; MODBYTES]> {
    leaf_index.assignment.map(|l| {
        let mut b: [u8; MODBYTES] = [0u8; MODBYTES];
        let mut m = l.to_bignum();
        m.tobytes(&mut b);
        b.reverse();
        b
    })
}

/// When doing merkle proofs, the prover might want to hide the leaf index and leaf value both or
/// might only want to hide lead index but reveal leaf value. The following enum is used to indicate
/// whether the prover is hiding the leaf value or (`LeafValueType::Hidden`) or not (`LeafValueType::Known`).
/// Hence the leaf value type being passed to the gadget must be of the required type.
pub enum LeafValueType {
    Hidden(Variable),
    Known(FieldElement),
}

impl From<LeafValueType> for LinearCombination {
    fn from(v: LeafValueType) -> LinearCombination {
        match v {
            LeafValueType::Hidden(v) => LinearCombination::from(v),
            LeafValueType::Known(v) => LinearCombination::from(v),
        }
    }
}

/// Either get the blindings from the given Option or generate by using the given random number
/// generator. It returns 1 or 2 blindings depending on whether the leaf value is hidden from the
/// verifier or not
pub(crate) fn get_blinding_for_merkle_tree_prover<R: Rng + CryptoRng>(
    hide_leaf: bool,
    blindings: Option<Vec<FieldElement>>,
    rng: Option<&mut R>,
) -> Result<Vec<FieldElement>, R1CSError> {
    if hide_leaf {
        // Randomness is only provided for leaf value and leaf index
        let blindings = blindings.unwrap_or_else(|| {
            let r = rng.unwrap();
            vec![
                FieldElement::random_using_rng(r),
                FieldElement::random_using_rng(r),
            ]
        });

        if blindings.len() != 2 {
            return Err(R1CSErrorKind::GadgetError {
                description: String::from("Provided randomness should have size 2"),
            }
            .into());
        }
        Ok(blindings)
    } else {
        // Randomness is only provided for the leaf index
        let blindings = blindings.unwrap_or_else(|| {
            let r = rng.unwrap();
            vec![FieldElement::random_using_rng(r)]
        });

        if blindings.len() != 1 {
            return Err(R1CSErrorKind::GadgetError {
                description: String::from("Provided randomness should have size 1"),
            }
            .into());
        }
        Ok(blindings)
    }
}
