use super::helper_constraints::constrain_lc_with_scalar;
use crate::errors::R1CSError;
use crate::r1cs::linear_combination::AllocatedQuantity;
use crate::r1cs::{ConstraintSystem, LinearCombination, Prover, R1CSProof, Variable, Verifier};
use amcl_wrapper::field_elem::FieldElement;
use amcl_wrapper::group_elem_g1::{G1Vector, G1};
use merlin::Transcript;
use rand::{CryptoRng, RngCore};

use super::helper_constraints::mimc::{mimc, mimc_gadget};

pub fn prove_mimc_preimage<R: RngCore + CryptoRng>(
    mut inputs: Vec<FieldElement>,
    randomness: Option<Vec<FieldElement>>,
    expected_output: &FieldElement,
    constants: &[FieldElement],
    mimc_rounds: usize,
    rng: Option<&mut R>,
    prover: &mut Prover,
) -> Result<Vec<G1>, R1CSError> {
    check_for_randomness_or_rng!(randomness, rng)?;

    let mut rands = randomness.unwrap_or_else(|| {
        let r = rng.unwrap();
        vec![
            FieldElement::random_using_rng(r),
            FieldElement::random_using_rng(r),
        ]
    });

    check_for_input_and_randomness_length!(inputs, rands, 2)?;

    let (com_l, var_l) = prover.commit(inputs[0].clone(), rands.remove(0));
    let (com_r, var_r) = prover.commit(inputs[1].clone(), rands.remove(0));

    let left_alloc_scalar = AllocatedQuantity {
        variable: var_l,
        assignment: Some(inputs.remove(0)),
    };

    let right_alloc_scalar = AllocatedQuantity {
        variable: var_r,
        assignment: Some(inputs.remove(0)),
    };

    mimc_gadget(
        prover,
        left_alloc_scalar,
        right_alloc_scalar,
        mimc_rounds,
        &constants,
        &expected_output,
    )?;

    Ok(vec![com_l, com_r])
}

pub fn verify_mimc_preimage(
    expected_output: &FieldElement,
    constants: &[FieldElement],
    mimc_rounds: usize,
    mut commitments: Vec<G1>,
    verifier: &mut Verifier,
) -> Result<(), R1CSError> {
    let var_l = verifier.commit(commitments.remove(0));
    let var_r = verifier.commit(commitments.remove(0));

    let left_alloc_scalar = AllocatedQuantity {
        variable: var_l,
        assignment: None,
    };

    let right_alloc_scalar = AllocatedQuantity {
        variable: var_r,
        assignment: None,
    };

    mimc_gadget(
        verifier,
        left_alloc_scalar,
        right_alloc_scalar,
        mimc_rounds,
        &constants,
        &expected_output,
    )?;

    Ok(())
}

pub fn gen_proof_of_knowledge_of_preimage_of_mimc<R: RngCore + CryptoRng>(
    inputs: Vec<FieldElement>,
    randomness: Option<Vec<FieldElement>>,
    expected_output: &FieldElement,
    constants: &[FieldElement],
    mimc_rounds: usize,
    rng: Option<&mut R>,
    transcript_label: &'static [u8],
    g: &G1,
    h: &G1,
    G: &G1Vector,
    H: &G1Vector,
) -> Result<(R1CSProof, Vec<G1>), R1CSError> {
    let mut prover_transcript = Transcript::new(transcript_label);
    let mut prover = Prover::new(&g, &h, &mut prover_transcript);

    let comms = prove_mimc_preimage(
        inputs,
        randomness,
        expected_output,
        constants,
        mimc_rounds,
        rng,
        &mut prover,
    )?;

    println!(
        "For MiMC rounds {}, no of multipliers is {}, no of constraints is {}",
        &mimc_rounds,
        &prover.num_multipliers(),
        &prover.num_constraints()
    );
    let proof = prover.prove(G, H)?;

    Ok((proof, comms))
}

pub fn verify_knowledge_of_preimage_of_mimc(
    expected_output: &FieldElement,
    constants: &[FieldElement],
    mimc_rounds: usize,
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

    verify_mimc_preimage(
        expected_output,
        constants,
        mimc_rounds,
        commitments,
        &mut verifier,
    )?;
    verifier.verify(&proof, g, h, G, H)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::get_generators;
    use amcl_wrapper::group_elem::GroupElement;
    use rand::rngs::OsRng;
    use rand::Rng;
    use std::time::{Duration, Instant};

    #[test]
    fn test_mimc() {
        let mimc_rounds = 322;
        let constants = (0..mimc_rounds)
            .map(|_| FieldElement::random())
            .collect::<Vec<_>>();

        let mut rng = rand::thread_rng();
        let xl = FieldElement::random();
        let xr = FieldElement::random();

        let expected_output = mimc(&xl, &xr, &constants, mimc_rounds);

        let G: G1Vector = get_generators("G", 2048).into();
        let H: G1Vector = get_generators("H", 2048).into();
        let g = G1::from_msg_hash("g".as_bytes());
        let h = G1::from_msg_hash("h".as_bytes());

        let label = b"MiMC";

        let start = Instant::now();
        let (proof, commitments) = gen_proof_of_knowledge_of_preimage_of_mimc(
            vec![xl, xr],
            None,
            &expected_output,
            &constants,
            mimc_rounds,
            Some(&mut rng),
            label,
            &g,
            &h,
            &G,
            &H,
        )
        .unwrap();
        println!("Proving time is: {:?}", start.elapsed());

        let start = Instant::now();
        verify_knowledge_of_preimage_of_mimc(
            &expected_output,
            &constants,
            mimc_rounds,
            proof,
            commitments,
            label,
            &g,
            &h,
            &G,
            &H,
        )
        .unwrap();
        println!("Verification time is: {:?}", start.elapsed());
    }
}
