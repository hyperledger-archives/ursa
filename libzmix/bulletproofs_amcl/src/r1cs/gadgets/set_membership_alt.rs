use super::helper_constraints::bit::bit_gadget;
use super::helper_constraints::constrain_lc_with_scalar;
use super::helper_constraints::vector_sum::vector_sum_constraints;
use crate::errors::R1CSError;
use crate::r1cs::linear_combination::AllocatedQuantity;
use crate::r1cs::{ConstraintSystem, LinearCombination, Prover, R1CSProof, Variable, Verifier};
use amcl_wrapper::field_elem::FieldElement;
use amcl_wrapper::group_elem_g1::{G1Vector, G1};
use merlin::Transcript;
use rand::{CryptoRng, RngCore};

/*// Ensure `v` is a bit, hence 0 or 1
pub fn bit_gadget<CS: ConstraintSystem>(
    cs: &mut CS,
    v: AllocatedQuantity,
) -> Result<(), R1CSError> {
    // TODO: Possible to save reallocation of `v` in `bit`?
    let (a, b, o) =
        cs.allocate_multiplier(v.assignment.map(|bit| ((FieldElement::one() - bit), bit)))?;

    // Might not be necessary if above TODO is addressed
    // Variable b is same as v so b + (-v) = 0
    let neg_v: LinearCombination = vec![(v.variable, FieldElement::minus_one())]
        .iter()
        .collect();
    cs.constrain(b + neg_v);

    // Enforce a * b = 0, so one of (a,b) is zero
    cs.constrain(o.into());

    // Might not be necessary if above TODO is addressed
    // Enforce that a = 1 - b, so they both are 1 or 0.
    cs.constrain(a + (b - FieldElement::one()));

    Ok(())
}

// Ensure sum of items of `vector` is `sum`
pub fn vector_sum_gadget<CS: ConstraintSystem>(
    cs: &mut CS,
    vector: &[AllocatedQuantity],
    sum: u64,
) -> Result<(), R1CSError> {
    let mut constraints = vec![(Variable::One(), FieldElement::from(sum).negation())];
    for i in vector {
        constraints.push((i.variable, FieldElement::one()));
    }

    cs.constrain(constraints.iter().collect());

    Ok(())
}*/

// TODO: Find better name
// Ensure items[i] * vector[i] = vector[i] * value
pub fn vector_product_gadget<CS: ConstraintSystem>(
    cs: &mut CS,
    items: &[u64],
    vector: &[AllocatedQuantity],
    value: &AllocatedQuantity,
) -> Result<(), R1CSError> {
    let mut constraints = vec![(value.variable, FieldElement::minus_one())];

    for i in 0..items.len() {
        // TODO: Possible to save reallocation of elements of `vector` in `bit`? If circuit variables for vector are passed, then yes.
        let (bit_var, item_var, o1) = cs.allocate_multiplier(
            vector[i]
                .assignment
                .as_ref()
                .map(|bit| (bit.clone(), items[i].into())),
        )?;
        constrain_lc_with_scalar::<CS>(cs, item_var.into(), &items[i].into());

        let (_, _, o2) = cs.multiply(bit_var.into(), value.variable.into());

        cs.constrain(o1 - o2);

        constraints.push((o1, FieldElement::one()));
    }

    // Constrain the sum of output variables to be equal to the value of committed variable
    cs.constrain(constraints.iter().collect());

    Ok(())
}

/// Allocate a bitmap for the `set` with 1 as the index of `value`, 0 otherwise. Then commit to values of bitmap
/// and prove that each element is either 0 or 1, sum of elements of this bitmap is 1 (as there is only 1 element)
/// and the relation set[i] * bitmap[i] = bitmap[i] * value.
/// Taken from https://github.com/HarryR/ethsnarks/blob/master/src/gadgets/one_of_n.hpp
pub fn prove_set_membership_alt<R: RngCore + CryptoRng>(
    value: u64,
    randomness: Option<FieldElement>,
    set: &[u64],
    rng: Option<&mut R>,
    prover: &mut Prover,
) -> Result<Vec<G1>, R1CSError> {
    check_for_randomness_or_rng!(randomness, rng)?;

    // Set all indices to 0 except the one where `value` is
    let bit_map: Vec<u64> = set
        .iter()
        .map(|elem| if *elem == value { 1 } else { 0 })
        .collect();

    let mut comms = vec![];

    let mut bit_vars = vec![];
    let mut bit_allocs = vec![];
    for b in bit_map {
        let _b = FieldElement::from(b);
        let (com, var) = prover.commit(_b.clone(), FieldElement::random());
        bit_vars.push(var.clone());
        let quantity = AllocatedQuantity {
            variable: var,
            assignment: Some(_b),
        };
        bit_gadget(prover, &quantity)?;
        comms.push(com);
        bit_allocs.push(quantity);
    }

    // The bit vector sum should be 1
    vector_sum_constraints(prover, bit_vars, 1)?;

    let _value = FieldElement::from(value);
    let (com_value, var_value) = prover.commit(
        _value.clone(),
        randomness.unwrap_or_else(|| FieldElement::random_using_rng(rng.unwrap())),
    );
    let quantity_value = AllocatedQuantity {
        variable: var_value,
        assignment: Some(_value),
    };
    vector_product_gadget(prover, &set, &bit_allocs, &quantity_value)?;
    comms.push(com_value);

    Ok(comms)
}

pub fn verify_set_membership_alt(
    set: &[u64],
    mut commitments: Vec<G1>,
    verifier: &mut Verifier,
) -> Result<(), R1CSError> {
    let set_length = set.len();

    let mut bit_vars = vec![];
    let mut bit_allocs = vec![];

    for _ in 0..set_length {
        let var = verifier.commit(commitments.remove(0));
        bit_vars.push(var.clone());
        let quantity = AllocatedQuantity {
            variable: var,
            assignment: None,
        };
        bit_gadget(verifier, &quantity)?;
        bit_allocs.push(quantity);
    }

    vector_sum_constraints(verifier, bit_vars, 1)?;

    let var_val = verifier.commit(commitments.remove(0));
    let quantity_value = AllocatedQuantity {
        variable: var_val,
        assignment: None,
    };

    vector_product_gadget(verifier, &set, &bit_allocs, &quantity_value)?;

    Ok(())
}

pub fn gen_proof_of_set_membership_alt<R: RngCore + CryptoRng>(
    value: u64,
    randomness: Option<FieldElement>,
    set: &[u64],
    rng: Option<&mut R>,
    transcript_label: &'static [u8],
    g: &G1,
    h: &G1,
    G: &G1Vector,
    H: &G1Vector,
) -> Result<(R1CSProof, Vec<G1>), R1CSError> {
    let mut prover_transcript = Transcript::new(transcript_label);
    let mut prover = Prover::new(g, h, &mut prover_transcript);

    let set_length = set.len();

    let comms = prove_set_membership_alt(value, randomness, set, rng, &mut prover)?;

    println!(
        "For set size {}, no of constraints is {}",
        &set_length,
        &prover.num_constraints()
    );
    let proof = prover.prove(G, H)?;

    Ok((proof, comms))
}

pub fn verify_proof_of_set_membership_alt(
    set: &[u64],
    proof: R1CSProof,
    commitments: Vec<G1>,
    transcript_label: &'static [u8],
    g: &G1,
    h: &G1,
    G: &G1Vector,
    H: &G1Vector,
) -> Result<(), R1CSError> {
    let mut verifier_transcript = Transcript::new(transcript_label);
    let mut verifier = Verifier::new(&mut verifier_transcript);

    verify_set_membership_alt(set, commitments, &mut verifier)?;

    verifier.verify(&proof, g, h, G, H)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::get_generators;
    use amcl_wrapper::group_elem::GroupElement;

    #[test]
    fn test_set_membership_alt() {
        use rand::rngs::OsRng;
        use rand::Rng;

        let mut rng = rand::thread_rng();

        let set: Vec<u64> = vec![2, 3, 5, 6, 8, 20, 25];
        let value = 3u64;

        let G: G1Vector = get_generators("G", 64).into();
        let H: G1Vector = get_generators("H", 64).into();
        let g = G1::from_msg_hash("g".as_bytes());
        let h = G1::from_msg_hash("h".as_bytes());

        let label = b"SetMembershipAlternate";
        let (proof, commitments) = gen_proof_of_set_membership_alt(
            value,
            None,
            &set,
            Some(&mut rng),
            label,
            &g,
            &h,
            &G,
            &H,
        )
        .unwrap();

        verify_proof_of_set_membership_alt(&set, proof, commitments, label, &g, &h, &G, &H)
            .unwrap();
    }
}
