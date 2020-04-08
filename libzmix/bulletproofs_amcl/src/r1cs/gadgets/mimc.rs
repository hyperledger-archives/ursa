use crate::errors::{R1CSError, R1CSErrorKind};
use crate::r1cs::{Prover, R1CSProof, Verifier};
use amcl_wrapper::field_elem::FieldElement;
use amcl_wrapper::group_elem_g1::{G1Vector, G1};
use merlin::Transcript;
use rand::{CryptoRng, Rng};

use super::helper_constraints::mimc::mimc_gadget;

/// Takes a Prover and enforces the constraints of MiMC hash with 2 inputs and 1 output
pub fn prove_mimc_preimage<R: Rng + CryptoRng>(
    mut preimage: Vec<FieldElement>,
    blindings: Option<Vec<FieldElement>>,
    image: &FieldElement,
    constants: &[FieldElement],
    rng: Option<&mut R>,
    prover: &mut Prover,
) -> Result<Vec<G1>, R1CSError> {
    check_for_blindings_or_rng!(blindings, rng)?;

    let mut rands = blindings.unwrap_or_else(|| {
        let r = rng.unwrap();
        vec![
            FieldElement::random_using_rng(r),
            FieldElement::random_using_rng(r),
        ]
    });

    check_for_input_and_blindings_length!(preimage, rands, 2)?;

    let (com_l, var_l) = prover.commit(preimage.remove(0), rands.remove(0));
    let (com_r, var_r) = prover.commit(preimage.remove(0), rands.remove(0));

    mimc_gadget(prover, var_l.into(), var_r.into(), &constants, &image)?;

    Ok(vec![com_l, com_r])
}

/// Takes a Verifier and enforces the constraints of MiMC hash with 2 inputs and 1 output
pub fn verify_mimc_preimage(
    image: &FieldElement,
    constants: &[FieldElement],
    mut commitments: Vec<G1>,
    verifier: &mut Verifier,
) -> Result<(), R1CSError> {
    let var_l = verifier.commit(commitments.remove(0));
    let var_r = verifier.commit(commitments.remove(0));

    mimc_gadget(verifier, var_l.into(), var_r.into(), &constants, &image)?;

    Ok(())
}

/// Initializes a Prover and creates proof of knowledge of preimage of MiMC hash with 2 inputs and 1 output.
pub fn gen_proof_of_knowledge_of_preimage_of_mimc<R: Rng + CryptoRng>(
    preimage: Vec<FieldElement>,
    randomness: Option<Vec<FieldElement>>,
    image: &FieldElement,
    constants: &[FieldElement],
    rng: Option<&mut R>,
    transcript_label: &'static [u8],
    g: &G1,
    h: &G1,
    G: &G1Vector,
    H: &G1Vector,
) -> Result<(R1CSProof, Vec<G1>), R1CSError> {
    let mut prover_transcript = Transcript::new(transcript_label);
    let mut prover = Prover::new(&g, &h, &mut prover_transcript);

    let comms = prove_mimc_preimage(preimage, randomness, image, constants, rng, &mut prover)?;

    println!(
        "For MiMC rounds {}, no of multipliers is {}, no of constraints is {}",
        &constants.len(),
        &prover.num_multipliers(),
        &prover.num_constraints()
    );
    let proof = prover.prove(G, H)?;

    Ok((proof, comms))
}

/// Initializes a Verifier and verifies proof of knowledge of preimage of MiMC hash with 2 inputs and 1 output
pub fn verify_knowledge_of_preimage_of_mimc(
    image: &FieldElement,
    constants: &[FieldElement],
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

    verify_mimc_preimage(image, constants, commitments, &mut verifier)?;
    verifier.verify(&proof, g, h, G, H)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::r1cs::gadgets::helper_constraints::mimc::mimc;
    use crate::utils::get_generators;
    use amcl_wrapper::group_elem::GroupElement;
    use std::time::Instant;

    #[test]
    fn test_mimc() {
        let mimc_rounds = 322;
        let constants = (0..mimc_rounds)
            .map(|_| FieldElement::random())
            .collect::<Vec<_>>();

        let mut rng = rand::thread_rng();
        let xl = FieldElement::random();
        let xr = FieldElement::random();

        let image = mimc(&xl, &xr, &constants);

        let G: G1Vector = get_generators("G", 2048).into();
        let H: G1Vector = get_generators("H", 2048).into();
        let g = G1::from_msg_hash("g".as_bytes());
        let h = G1::from_msg_hash("h".as_bytes());

        let label = b"MiMC";

        let start = Instant::now();
        let (proof, commitments) = gen_proof_of_knowledge_of_preimage_of_mimc(
            vec![xl, xr],
            None,
            &image,
            &constants,
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
            &image,
            &constants,
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
