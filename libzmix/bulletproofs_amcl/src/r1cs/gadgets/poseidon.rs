use super::helper_constraints::constrain_lc_with_scalar;
use crate::errors::R1CSError;
use crate::r1cs::linear_combination::AllocatedQuantity;
use crate::r1cs::{ConstraintSystem, LinearCombination, Prover, R1CSProof, Variable, Verifier};
use amcl_wrapper::field_elem::FieldElement;
use amcl_wrapper::group_elem::GroupElement;
use amcl_wrapper::group_elem_g1::{G1Vector, G1};
use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use std::time::{Duration, Instant};

use super::helper_constraints::poseidon::{
    PoseidonParams, Poseidon_hash_2, Poseidon_hash_2_gadget, Poseidon_hash_4,
    Poseidon_hash_4_gadget, SboxType, PADDING_CONST, ZERO_CONST,
};
use amcl_wrapper::commitment::commit_to_field_element;

/// Statics are needed to use permutation as a hash function
///
/// Allocate padding constant and zeroes for Prover
pub fn allocate_statics_for_prover(
    prover: &mut Prover,
    num_statics: usize,
) -> Vec<AllocatedQuantity> {
    let mut statics = vec![];
    let (_, var) = prover.commit(FieldElement::from(ZERO_CONST), FieldElement::zero());
    statics.push(AllocatedQuantity {
        variable: var,
        assignment: Some(FieldElement::from(ZERO_CONST)),
    });

    // Commitment to PADDING_CONST with blinding as 0
    let (_, var) = prover.commit(FieldElement::from(PADDING_CONST), FieldElement::zero());
    statics.push(AllocatedQuantity {
        variable: var,
        assignment: Some(FieldElement::from(PADDING_CONST)),
    });

    // Commit to 0 with randomness 0 for the rest of the elements of width
    for _ in 2..num_statics {
        let (_, var) = prover.commit(FieldElement::from(ZERO_CONST), FieldElement::zero());
        statics.push(AllocatedQuantity {
            variable: var,
            assignment: Some(FieldElement::from(ZERO_CONST)),
        });
    }
    statics
}

/// Allocate padding constant and zeroes for Verifier
pub fn allocate_statics_for_verifier(
    verifier: &mut Verifier,
    num_statics: usize,
    g: &G1,
    h: &G1,
) -> Vec<AllocatedQuantity> {
    let mut statics = vec![];
    // Commitment to PADDING_CONST with blinding as 0
    let pad_comm = commit_to_field_element(
        g,
        h,
        &FieldElement::from(PADDING_CONST),
        &FieldElement::zero(),
    );

    // Commitment to 0 with blinding as 0
    let zero_comm =
        commit_to_field_element(g, h, &FieldElement::from(ZERO_CONST), &FieldElement::zero());

    let v = verifier.commit(zero_comm.clone());
    statics.push(AllocatedQuantity {
        variable: v,
        assignment: None,
    });

    let v = verifier.commit(pad_comm);
    statics.push(AllocatedQuantity {
        variable: v,
        assignment: None,
    });
    for _ in 2..num_statics {
        let v = verifier.commit(zero_comm.clone());
        statics.push(AllocatedQuantity {
            variable: v,
            assignment: None,
        });
    }
    statics
}

pub fn gen_proof_of_knowledge_of_preimage_of_Poseidon_2<R: RngCore + CryptoRng>(
    inputs: [FieldElement; 2],
    randomness: Option<[FieldElement; 2]>,
    expected_output: &FieldElement,
    hash_params: &PoseidonParams,
    sbox_type: &SboxType,
    rng: Option<&mut R>,
    transcript_label: &'static [u8],
    g: &G1,
    h: &G1,
    G: &G1Vector,
    H: &G1Vector,
) -> Result<(R1CSProof, Vec<G1>), R1CSError> {
    check_for_randomness_or_rng!(randomness, rng)?;

    let width = hash_params.width;
    let total_rounds = hash_params.full_rounds_beginning
        + hash_params.partial_rounds
        + hash_params.full_rounds_end;

    let mut prover_transcript = Transcript::new(transcript_label);
    let mut prover = Prover::new(&g, &h, &mut prover_transcript);

    let mut comms = vec![];
    let mut statics = vec![];

    let rands: [FieldElement; 2] = randomness.unwrap_or_else(|| {
        let r = rng.unwrap();
        [
            FieldElement::random_using_rng(r),
            FieldElement::random_using_rng(r),
        ]
    });
    let (com_l, var_l) = prover.commit(inputs[0].clone(), rands[0]);
    comms.push(com_l);
    let l_alloc = AllocatedQuantity {
        variable: var_l,
        assignment: Some(inputs[0]),
    };

    let (com_r, var_r) = prover.commit(inputs[1].clone(), rands[1]);
    comms.push(com_r);
    let r_alloc = AllocatedQuantity {
        variable: var_r,
        assignment: Some(inputs[1]),
    };

    // Commitment to PADDING_CONST with blinding as 0
    let (_, var) = prover.commit(FieldElement::from(PADDING_CONST), FieldElement::zero());
    statics.push(AllocatedQuantity {
        variable: var,
        assignment: Some(FieldElement::from(PADDING_CONST)),
    });

    // Commit to 0 with randomness 0 for the rest of the elements of width
    for _ in 3..width {
        let (_, var) = prover.commit(FieldElement::zero(), FieldElement::zero());
        statics.push(AllocatedQuantity {
            variable: var,
            assignment: Some(FieldElement::zero()),
        });
    }

    let start = Instant::now();
    Poseidon_hash_2_gadget(
        &mut prover,
        l_alloc,
        r_alloc,
        statics,
        &hash_params,
        sbox_type,
        &expected_output,
    )?;

    println!(
        "For Poseidon hash rounds {}, no of constraints is {}",
        total_rounds,
        &prover.num_constraints()
    );
    println!("Proving time is: {:?}", start.elapsed());

    let proof = prover.prove(&G, &H).unwrap();
    Ok((proof, comms))
}

pub fn verify_knowledge_of_preimage_of_Poseidon_2(
    expected_output: &FieldElement,
    hash_params: &PoseidonParams,
    sbox_type: &SboxType,
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
    let mut statics = vec![];
    let lv = verifier.commit(commitments[0]);
    let rv = verifier.commit(commitments[1]);
    let l_alloc = AllocatedQuantity {
        variable: lv,
        assignment: None,
    };
    let r_alloc = AllocatedQuantity {
        variable: rv,
        assignment: None,
    };

    let width = hash_params.width;

    // Commitment to PADDING_CONST with blinding as 0
    let pad_comm = commit_to_field_element(
        &g,
        &h,
        &FieldElement::from(PADDING_CONST),
        &FieldElement::zero(),
    );
    let v = verifier.commit(pad_comm);
    statics.push(AllocatedQuantity {
        variable: v,
        assignment: None,
    });

    // Commitment to 0 with blinding as 0
    let zero_comm = commit_to_field_element(&g, &h, &FieldElement::zero(), &FieldElement::zero());

    for i in 3..width {
        let v = verifier.commit(zero_comm.clone());
        statics.push(AllocatedQuantity {
            variable: v,
            assignment: None,
        });
    }

    let start = Instant::now();
    Poseidon_hash_2_gadget(
        &mut verifier,
        l_alloc,
        r_alloc,
        statics,
        &hash_params,
        sbox_type,
        &expected_output,
    )?;

    verifier.verify(&proof, &g, &h, &G, &H)?;
    println!("Verification time is: {:?}", start.elapsed());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::get_generators;
    use rand::rngs::OsRng;
    use rand::Rng;

    fn check_hash_2(hash_params: &PoseidonParams, sbox_type: &SboxType) {
        let mut rng = rand::thread_rng();
        let xl = FieldElement::random();
        let xr = FieldElement::random();
        let expected_output = Poseidon_hash_2(xl, xr, &hash_params, sbox_type);

        let G: G1Vector = get_generators("G", 2048).into();
        let H: G1Vector = get_generators("H", 2048).into();
        let g = G1::from_msg_hash("g".as_bytes());
        let h = G1::from_msg_hash("h".as_bytes());

        let label = b"PoseidonHash2:1";

        let (proof, commitments) = gen_proof_of_knowledge_of_preimage_of_Poseidon_2(
            [xl, xr],
            None,
            &expected_output,
            &hash_params,
            sbox_type,
            Some(&mut rng),
            label,
            &g,
            &h,
            &G,
            &H,
        )
        .unwrap();

        verify_knowledge_of_preimage_of_Poseidon_2(
            &expected_output,
            &hash_params,
            sbox_type,
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

    #[test]
    fn test_poseidon_hash_2() {
        let width = 6;
        let (full_b, full_e) = (4, 4);
        let partial_rounds = 140;
        let hash_params = PoseidonParams::new(width, full_b, full_e, partial_rounds);

        check_hash_2(&hash_params, &SboxType::Cube);
        check_hash_2(&hash_params, &SboxType::Inverse);
        check_hash_2(&hash_params, &SboxType::Quint);
    }
}
