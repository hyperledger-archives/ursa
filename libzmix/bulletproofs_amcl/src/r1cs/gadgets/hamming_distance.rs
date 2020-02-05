use std::time::{Duration, Instant};

use amcl_wrapper::field_elem::FieldElement;
use amcl_wrapper::group_elem_g1::{G1Vector, G1};
use merlin::Transcript;
use rand::{CryptoRng, Rng};

/// Check in how many elements are 2 ordered sets different.
/// Checks that Hamming distance is equal to some public value.
use crate::errors::R1CSError;
use crate::r1cs::linear_combination::AllocatedQuantity;
use crate::r1cs::{ConstraintSystem, LinearCombination, Prover, R1CSProof, Variable, Verifier};

use super::helper_constraints::constrain_lc_with_scalar;
use super::helper_constraints::vector_sum::vector_sum_constraints;

pub fn hamming_distance_gadget<CS: ConstraintSystem>(
    cs: &mut CS,
    original: Vec<AllocatedQuantity>,
    new: &[FieldElement],
    count_different: u64,
) -> Result<(), R1CSError> {
    if original.len() != new.len() {
        return Err(R1CSError::GadgetError {
            description: String::from("Original and new are of different lengths"),
        });
    }
    let mut result = Vec::<Variable>::new();
    for i in 0..new.len() {
        let diff = original[i].variable - new[i].clone();
        let val_diff = cs.evaluate_lc(&diff);
        let (val_diff, val_diff_inv) = match val_diff {
            Some(l) => {
                let inv = l.inverse();
                (Some(l), Some(inv))
            }
            None => (None, None),
        };

        // diff * diff_inv = 1_or_0 depending on diff being non-zero or zero
        let (var_diff, _) = cs.allocate_single(val_diff)?;
        let (_, var_o) = cs.allocate_single(val_diff_inv)?;
        let var_1_or_0 = var_o.unwrap();

        // diff * (1 - 1_or_0) = 0
        let one_minus_var_1_or_0 = Variable::One() - var_1_or_0;
        let (_, _, o) = cs.multiply(var_diff.into(), one_minus_var_1_or_0);
        cs.constrain(o.into());

        result.push(var_1_or_0);
    }

    vector_sum_constraints::<CS>(cs, result, count_different);

    Ok(())
}

pub fn prove_hamming_distance(
    original_vals: &[FieldElement],
    new_vals: &[FieldElement],
    count_different: u64,
    prover: &mut Prover,
) -> Result<Vec<G1>, R1CSError> {
    if original_vals.len() != new_vals.len() {
        return Err(R1CSError::GadgetError {
            description: String::from("Original and new are of different lengths"),
        });
    }
    let mut comms = vec![];
    let mut allocs = vec![];

    for i in 0..original_vals.len() {
        let (com, var) = prover.commit(original_vals[i].clone(), FieldElement::random());
        comms.push(com);
        allocs.push(AllocatedQuantity {
            variable: var,
            assignment: Some(original_vals[i].clone()),
        });
    }

    hamming_distance_gadget(prover, allocs, new_vals, count_different)?;

    Ok(comms)
}

pub fn verify_hamming_distance(
    new_vals: &[FieldElement],
    count_different: u64,
    mut commitments: Vec<G1>,
    verifier: &mut Verifier,
) -> Result<(), R1CSError> {
    let mut allocs = vec![];

    for com in commitments.drain(0..) {
        let var = verifier.commit(com);
        let alloc = AllocatedQuantity {
            variable: var,
            assignment: None,
        };
        allocs.push(alloc);
    }

    hamming_distance_gadget(verifier, allocs, new_vals, count_different)?;

    Ok(())
}

pub fn gen_proof_for_hamming_distance(
    original_vals: &[FieldElement],
    new_vals: &[FieldElement],
    count_different: u64,
    transcript_label: &'static [u8],
    g: &G1,
    h: &G1,
    G: &G1Vector,
    H: &G1Vector,
) -> Result<(R1CSProof, Vec<G1>), R1CSError> {
    let mut prover_transcript = Transcript::new(transcript_label);
    let mut prover = Prover::new(&g, &h, &mut prover_transcript);

    let start = Instant::now();
    let comms = prove_hamming_distance(original_vals, new_vals, count_different, &mut prover)?;
    println!(
        "No of multipliers is {} and constraints is {}",
        &prover.num_multipliers(),
        &prover.num_constraints()
    );
    let proof = prover.prove(G, H).unwrap();
    println!("Proving time is {:?}", start.elapsed());
    Ok((proof, comms))
}

pub fn verify_proof_for_hamming_distance(
    new_vals: &[FieldElement],
    count_different: u64,
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

    let start = Instant::now();
    verify_hamming_distance(new_vals, count_different, commitments, &mut verifier)?;
    verifier.verify(&proof, g, h, G, H)?;

    println!("Verification time is {:?}", start.elapsed());
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::r1cs::gadgets::randomizer::{get_indices_to_modify, get_randomized_data};
    use crate::utils::get_generators;
    use amcl_wrapper::field_elem::FieldElementVector;
    use amcl_wrapper::group_elem::GroupElement;

    use super::*;

    #[test]
    fn test_hamming_distance() {
        let data_size = 150;
        let count_modified = 5;
        let original_data = FieldElementVector::random(data_size);
        let nonce = FieldElement::random();
        let indices = get_indices_to_modify(&nonce, data_size, count_modified);

        println!(
            "Total entries {}. Trying to modify {} entries.",
            data_size, count_modified
        );
        if count_modified != indices.len() {
            println!("Will modify {} entries", indices.len());
        }

        let (_, new_data) = get_randomized_data(&original_data, &indices);

        let G: G1Vector = get_generators("G", 8192).into();
        let H: G1Vector = get_generators("H", 8192).into();

        let g = G1::from_msg_hash("g".as_bytes());
        let h = G1::from_msg_hash("h".as_bytes());

        let label = b"Difference";

        let (proof, commitments) = {
            gen_proof_for_hamming_distance(
                &original_data.as_slice(),
                &new_data.as_slice(),
                count_modified as u64,
                label,
                &g,
                &h,
                &G,
                &H,
            )
            .unwrap()
        };

        verify_proof_for_hamming_distance(
            &new_data.as_slice(),
            count_modified as u64,
            proof,
            commitments,
            label,
            &g,
            &h,
            &G,
            &H,
        )
        .unwrap();
    }
}
