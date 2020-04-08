use crate::errors::{R1CSError, R1CSErrorKind};
use crate::r1cs::{Prover, R1CSProof, Variable, Verifier};
use amcl_wrapper::field_elem::FieldElement;
use amcl_wrapper::group_elem_g1::{G1Vector, G1};
use merlin::Transcript;
use rand::{CryptoRng, Rng};

use super::helper_constraints::poseidon::{
    PoseidonParams, Poseidon_hash_2_gadget, Poseidon_hash_4_gadget, Poseidon_hash_8_gadget,
    SboxType, CAP_CONST_W_3, CAP_CONST_W_5, CAP_CONST_W_9,
};
use amcl_wrapper::commitment::commit_to_field_element;

// TODO: Comment on the distinction between wrapper and non-wrapper code.

/// Allocate capacity constant for Prover. Blinding is kept 0
pub fn allocate_capacity_const_for_prover(prover: &mut Prover, capacity_const: u64) -> Variable {
    let (_, var) = prover.commit(FieldElement::from(capacity_const), FieldElement::zero());
    var
}

/// Allocate capacity constant for Verifier. Blinding is kept 0
pub fn allocate_capacity_const_for_verifier(
    verifier: &mut Verifier,
    capacity_const: u64,
    g: &G1,
    h: &G1,
) -> Variable {
    // Commitment to capacity_const with blinding as 0
    let comm = commit_to_field_element(
        g,
        h,
        &FieldElement::from(capacity_const),
        &FieldElement::zero(),
    );

    verifier.commit(comm)
}

/// Takes a Prover and enforces the constraints of Poseidon hash with 2 inputs and 1 output
pub fn prove_knowledge_of_preimage_of_Poseidon_2<R: Rng + CryptoRng>(
    mut preimage: Vec<FieldElement>,
    blindings: Option<Vec<FieldElement>>,
    image: &FieldElement,
    hash_params: &PoseidonParams,
    sbox_type: &SboxType,
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

    let mut comms = vec![];

    let input1 = preimage.remove(0);
    let input2 = preimage.remove(0);

    let (com_l, var_l) = prover.commit(input1, rands.remove(0));
    comms.push(com_l);

    let (com_r, var_r) = prover.commit(input2, rands.remove(0));
    comms.push(com_r);

    let capacity_const = allocate_capacity_const_for_prover(prover, CAP_CONST_W_3);

    Poseidon_hash_2_gadget(
        prover,
        vec![var_l, var_r],
        capacity_const,
        &hash_params,
        sbox_type,
        &image,
    )?;

    Ok(comms)
}

/// Takes a Verifier and enforces the constraints of Poseidon hash with 2 inputs and 1 output
pub fn verify_knowledge_of_preimage_of_Poseidon_2(
    image: &FieldElement,
    hash_params: &PoseidonParams,
    sbox_type: &SboxType,
    mut commitments: Vec<G1>,
    g: &G1,
    h: &G1,
    verifier: &mut Verifier,
) -> Result<(), R1CSError> {
    let lv = verifier.commit(commitments.remove(0));
    let rv = verifier.commit(commitments.remove(0));

    let statics = allocate_capacity_const_for_verifier(verifier, CAP_CONST_W_3, g, h);

    Poseidon_hash_2_gadget(
        verifier,
        vec![lv, rv],
        statics,
        &hash_params,
        sbox_type,
        &image,
    )?;
    Ok(())
}

/// Initializes a Prover and creates proof of knowledge of preimage of Poseidon hash with 2 inputs and 1 output.
pub fn gen_proof_of_knowledge_of_preimage_of_Poseidon_2<R: Rng + CryptoRng>(
    preimage: Vec<FieldElement>,
    blindings: Option<Vec<FieldElement>>,
    image: &FieldElement,
    hash_params: &PoseidonParams,
    sbox_type: &SboxType,
    rng: Option<&mut R>,
    transcript_label: &'static [u8],
    g: &G1,
    h: &G1,
    G: &G1Vector,
    H: &G1Vector,
) -> Result<(R1CSProof, Vec<G1>), R1CSError> {
    let mut prover_transcript = Transcript::new(transcript_label);
    let mut prover = Prover::new(&g, &h, &mut prover_transcript);

    let total_rounds = hash_params.full_rounds_beginning
        + hash_params.partial_rounds
        + hash_params.full_rounds_end;

    let comms = prove_knowledge_of_preimage_of_Poseidon_2(
        preimage,
        blindings,
        image,
        hash_params,
        sbox_type,
        rng,
        &mut prover,
    )?;
    println!(
        "For Poseidon hash rounds {}, sbox type {:?}, no of multipliers is {}, no of constraints is {}",
        total_rounds,
        sbox_type,
        &prover.num_multipliers(),
        &prover.num_constraints()
    );

    let proof = prover.prove(G, H)?;
    Ok((proof, comms))
}

/// Initializes a Verifier and verifies proof of knowledge of preimage of Poseidon hash with 2 inputs and 1 output
pub fn verify_proof_of_knowledge_of_preimage_of_Poseidon_2(
    image: &FieldElement,
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

    verify_knowledge_of_preimage_of_Poseidon_2(
        image,
        hash_params,
        sbox_type,
        commitments,
        g,
        h,
        &mut verifier,
    )?;
    verifier.verify(&proof, g, h, G, H)
}

/// Takes a Prover and enforces the constraints of Poseidon hash with 4 inputs and 1 output
pub fn prove_knowledge_of_preimage_of_Poseidon_4<R: Rng + CryptoRng>(
    mut preimage: Vec<FieldElement>,
    blindings: Option<Vec<FieldElement>>,
    image: &FieldElement,
    hash_params: &PoseidonParams,
    sbox_type: &SboxType,
    rng: Option<&mut R>,
    prover: &mut Prover,
) -> Result<Vec<G1>, R1CSError> {
    check_for_blindings_or_rng!(blindings, rng)?;

    let mut comms = vec![];
    let mut vars = vec![];

    let mut rands = blindings.unwrap_or_else(|| {
        let r = rng.unwrap();
        vec![
            FieldElement::random_using_rng(r),
            FieldElement::random_using_rng(r),
            FieldElement::random_using_rng(r),
            FieldElement::random_using_rng(r),
        ]
    });

    check_for_input_and_blindings_length!(preimage, rands, 4)?;

    for _ in 0..4 {
        let (com, var) = prover.commit(preimage.remove(0), rands.remove(0));
        comms.push(com);
        vars.push(var);
    }

    let capacity_const = allocate_capacity_const_for_prover(prover, CAP_CONST_W_5);

    Poseidon_hash_4_gadget(
        prover,
        vars,
        capacity_const,
        &hash_params,
        sbox_type,
        &image,
    )?;

    Ok(comms)
}

/// Takes a Verifier and enforces the constraints of Poseidon hash with 4 inputs and 1 output
pub fn verify_knowledge_of_preimage_of_Poseidon_4(
    image: &FieldElement,
    hash_params: &PoseidonParams,
    sbox_type: &SboxType,
    mut commitments: Vec<G1>,
    g: &G1,
    h: &G1,
    verifier: &mut Verifier,
) -> Result<(), R1CSError> {
    let mut allocs = vec![];

    for _ in 0..4 {
        let var = verifier.commit(commitments.remove(0));
        allocs.push(var);
    }

    let capacity_const = allocate_capacity_const_for_verifier(verifier, CAP_CONST_W_5, g, h);

    Poseidon_hash_4_gadget(
        verifier,
        allocs,
        capacity_const,
        &hash_params,
        sbox_type,
        &image,
    )?;

    Ok(())
}

/// Initializes a Prover and creates proof of knowledge of preimage of Poseidon hash with 4 inputs and 1 output
pub fn gen_proof_of_knowledge_of_preimage_of_Poseidon_4<R: Rng + CryptoRng>(
    preimage: Vec<FieldElement>,
    blindings: Option<Vec<FieldElement>>,
    image: &FieldElement,
    hash_params: &PoseidonParams,
    sbox_type: &SboxType,
    rng: Option<&mut R>,
    transcript_label: &'static [u8],
    g: &G1,
    h: &G1,
    G: &G1Vector,
    H: &G1Vector,
) -> Result<(R1CSProof, Vec<G1>), R1CSError> {
    let total_rounds = hash_params.full_rounds_beginning
        + hash_params.partial_rounds
        + hash_params.full_rounds_end;

    let mut prover_transcript = Transcript::new(transcript_label);
    let mut prover = Prover::new(&g, &h, &mut prover_transcript);

    let comms = prove_knowledge_of_preimage_of_Poseidon_4(
        preimage,
        blindings,
        image,
        hash_params,
        sbox_type,
        rng,
        &mut prover,
    )?;

    println!(
        "For Poseidon hash rounds {}, sbox type {:?}, no of multipliers is {}, no of constraints is {}",
        total_rounds,
        sbox_type,
        &prover.num_multipliers(),
        &prover.num_constraints()
    );

    let proof = prover.prove(G, H)?;
    Ok((proof, comms))
}

/// Initializes a Verifier and verifies proof of knowledge of preimage of Poseidon hash with 4 inputs and 1 output
pub fn verify_proof_of_knowledge_of_preimage_of_Poseidon_4(
    image: &FieldElement,
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

    verify_knowledge_of_preimage_of_Poseidon_4(
        image,
        hash_params,
        sbox_type,
        commitments,
        g,
        h,
        &mut verifier,
    )?;

    verifier.verify(&proof, g, h, G, H)
}

/// Takes a Prover and enforces the constraints of Poseidon hash with 8 inputs and 1 output
pub fn prove_knowledge_of_preimage_of_Poseidon_8<R: Rng + CryptoRng>(
    mut preimage: Vec<FieldElement>,
    blindings: Option<Vec<FieldElement>>,
    image: &FieldElement,
    hash_params: &PoseidonParams,
    sbox_type: &SboxType,
    rng: Option<&mut R>,
    prover: &mut Prover,
) -> Result<Vec<G1>, R1CSError> {
    check_for_blindings_or_rng!(blindings, rng)?;

    let mut comms = vec![];
    let mut vars = vec![];

    let mut rands = blindings.unwrap_or_else(|| {
        let r = rng.unwrap();
        vec![
            FieldElement::random_using_rng(r),
            FieldElement::random_using_rng(r),
            FieldElement::random_using_rng(r),
            FieldElement::random_using_rng(r),
            FieldElement::random_using_rng(r),
            FieldElement::random_using_rng(r),
            FieldElement::random_using_rng(r),
            FieldElement::random_using_rng(r),
        ]
    });

    check_for_input_and_blindings_length!(preimage, rands, 8)?;

    for _ in 0..8 {
        let (com, var) = prover.commit(preimage.remove(0), rands.remove(0));
        comms.push(com);
        vars.push(var);
    }

    let capacity_const = allocate_capacity_const_for_prover(prover, CAP_CONST_W_9);
    Poseidon_hash_8_gadget(
        prover,
        vars,
        capacity_const,
        &hash_params,
        sbox_type,
        &image,
    )?;

    Ok(comms)
}

/// Takes a Verifier and enforces the constraints of Poseidon hash with 8 inputs and 1 output
pub fn verify_knowledge_of_preimage_of_Poseidon_8(
    image: &FieldElement,
    hash_params: &PoseidonParams,
    sbox_type: &SboxType,
    mut commitments: Vec<G1>,
    g: &G1,
    h: &G1,
    verifier: &mut Verifier,
) -> Result<(), R1CSError> {
    let mut vars = vec![];

    for _ in 0..8 {
        let var = verifier.commit(commitments.remove(0));
        vars.push(var);
    }

    let capacity_const = allocate_capacity_const_for_verifier(verifier, CAP_CONST_W_9, g, h);

    Poseidon_hash_8_gadget(
        verifier,
        vars,
        capacity_const,
        &hash_params,
        sbox_type,
        &image,
    )?;
    Ok(())
}

/// Initializes a Prover and creates proof of knowledge of preimage of Poseidon hash with 8 inputs and 1 output
pub fn gen_proof_of_knowledge_of_preimage_of_Poseidon_8<R: Rng + CryptoRng>(
    preimage: Vec<FieldElement>,
    blindings: Option<Vec<FieldElement>>,
    image: &FieldElement,
    hash_params: &PoseidonParams,
    sbox_type: &SboxType,
    rng: Option<&mut R>,
    transcript_label: &'static [u8],
    g: &G1,
    h: &G1,
    G: &G1Vector,
    H: &G1Vector,
) -> Result<(R1CSProof, Vec<G1>), R1CSError> {
    let total_rounds = hash_params.full_rounds_beginning
        + hash_params.partial_rounds
        + hash_params.full_rounds_end;

    let mut prover_transcript = Transcript::new(transcript_label);
    let mut prover = Prover::new(&g, &h, &mut prover_transcript);

    let comms = prove_knowledge_of_preimage_of_Poseidon_8(
        preimage,
        blindings,
        image,
        hash_params,
        sbox_type,
        rng,
        &mut prover,
    )?;

    println!(
        "For Poseidon hash rounds {}, sbox type {:?}, no of multipliers is {}, no of constraints is {}",
        total_rounds,
        sbox_type,
        &prover.num_multipliers(),
        &prover.num_constraints()
    );

    let proof = prover.prove(G, H)?;
    Ok((proof, comms))
}

/// Initializes a Verifier and verifies proof of knowledge of preimage of Poseidon hash with 8 inputs and 1 output
pub fn verify_proof_of_knowledge_of_preimage_of_Poseidon_8(
    image: &FieldElement,
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

    verify_knowledge_of_preimage_of_Poseidon_8(
        image,
        hash_params,
        sbox_type,
        commitments,
        g,
        h,
        &mut verifier,
    )?;

    verifier.verify(&proof, g, h, G, H)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::r1cs::gadgets::helper_constraints::poseidon::{
        Poseidon_hash_2, Poseidon_hash_4, Poseidon_hash_8,
    };
    use crate::utils::get_generators;
    use amcl_wrapper::group_elem::GroupElement;
    use std::time::Instant;

    fn check_hash_2(hash_params: &PoseidonParams, sbox_type: &SboxType) {
        let mut rng = rand::thread_rng();

        let G: G1Vector = get_generators("G", 1024).into();
        let H: G1Vector = get_generators("H", 1024).into();
        let g = G1::from_msg_hash("g".as_bytes());
        let h = G1::from_msg_hash("h".as_bytes());

        let xl = FieldElement::random();
        let xr = FieldElement::random();
        let inputs = vec![xl, xr];
        let expected_output = Poseidon_hash_2(inputs.clone(), &hash_params, sbox_type).unwrap();

        let label = b"PoseidonHash2:1";

        let start = Instant::now();
        let (proof, commitments) = gen_proof_of_knowledge_of_preimage_of_Poseidon_2(
            inputs,
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
        println!(
            "Proving time for Poseidon 2:1 with sbox {:?} is: {:?}",
            sbox_type,
            start.elapsed()
        );

        let start = Instant::now();
        verify_proof_of_knowledge_of_preimage_of_Poseidon_2(
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
        println!("Verification time is: {:?}", start.elapsed());
    }

    fn check_hash_4(hash_params: &PoseidonParams, sbox_type: &SboxType) {
        let mut rng = rand::thread_rng();

        let G: G1Vector = get_generators("G", 2048).into();
        let H: G1Vector = get_generators("H", 2048).into();
        let g = G1::from_msg_hash("g".as_bytes());
        let h = G1::from_msg_hash("h".as_bytes());

        let inputs = vec![
            FieldElement::random(),
            FieldElement::random(),
            FieldElement::random(),
            FieldElement::random(),
        ];
        let image = Poseidon_hash_4(inputs.clone(), &hash_params, sbox_type).unwrap();

        let label = b"PoseidonHash4:1";

        let start = Instant::now();
        let (proof, commitments) = gen_proof_of_knowledge_of_preimage_of_Poseidon_4(
            inputs,
            None,
            &image,
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
        println!(
            "Proving time for Poseidon 4:1 with sbox {:?} is: {:?}",
            sbox_type,
            start.elapsed()
        );

        let start = Instant::now();
        verify_proof_of_knowledge_of_preimage_of_Poseidon_4(
            &image,
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
        println!("Verification time is: {:?}", start.elapsed());
    }

    fn check_hash_8(hash_params: &PoseidonParams, sbox_type: &SboxType) {
        let mut rng = rand::thread_rng();

        let G: G1Vector = get_generators("G", 2048).into();
        let H: G1Vector = get_generators("H", 2048).into();
        let g = G1::from_msg_hash("g".as_bytes());
        let h = G1::from_msg_hash("h".as_bytes());

        let inputs = vec![
            FieldElement::random(),
            FieldElement::random(),
            FieldElement::random(),
            FieldElement::random(),
            FieldElement::random(),
            FieldElement::random(),
            FieldElement::random(),
            FieldElement::random(),
        ];
        let expected_output = Poseidon_hash_8(inputs.clone(), &hash_params, sbox_type).unwrap();

        let label = b"PoseidonHash8:1";

        let start = Instant::now();
        let (proof, commitments) = gen_proof_of_knowledge_of_preimage_of_Poseidon_8(
            inputs,
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
        println!(
            "Proving time for Poseidon 8:1 with sbox {:?} is: {:?}",
            sbox_type,
            start.elapsed()
        );

        let start = Instant::now();
        verify_proof_of_knowledge_of_preimage_of_Poseidon_8(
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
        println!("Verification time is: {:?}", start.elapsed());
    }

    #[test]
    fn test_poseidon_hash_2() {
        let width = 3;

        #[cfg(feature = "bls381")]
        let (full_b, full_e, partial_rounds) = (4, 4, 55);

        #[cfg(feature = "bn254")]
        let (full_b, full_e, partial_rounds) = (4, 4, 55);

        #[cfg(feature = "secp256k1")]
        let (full_b, full_e, partial_rounds) = (4, 4, 55);

        #[cfg(feature = "ed25519")]
        let (full_b, full_e, partial_rounds) = (4, 4, 55);

        let hash_params = PoseidonParams::new(width, full_b, full_e, partial_rounds).unwrap();

        check_hash_2(&hash_params, &SboxType::Cube);
        check_hash_2(&hash_params, &SboxType::Inverse);
        check_hash_2(&hash_params, &SboxType::Quint);
    }

    #[test]
    fn test_poseidon_hash_4() {
        let width = 5;

        #[cfg(feature = "bls381")]
        let (full_b, full_e, partial_rounds) = (4, 4, 56);

        #[cfg(feature = "bn254")]
        let (full_b, full_e, partial_rounds) = (4, 4, 56);

        #[cfg(feature = "secp256k1")]
        let (full_b, full_e, partial_rounds) = (4, 4, 56);

        #[cfg(feature = "ed25519")]
        let (full_b, full_e, partial_rounds) = (4, 4, 56);

        let hash_params = PoseidonParams::new(width, full_b, full_e, partial_rounds).unwrap();

        check_hash_4(&hash_params, &SboxType::Cube);
        check_hash_4(&hash_params, &SboxType::Inverse);
        check_hash_4(&hash_params, &SboxType::Quint);
    }

    #[test]
    fn test_poseidon_hash_8() {
        let width = 9;

        #[cfg(feature = "bls381")]
        let (full_b, full_e, partial_rounds) = (4, 4, 57);

        #[cfg(feature = "bn254")]
        let (full_b, full_e, partial_rounds) = (4, 4, 57);

        #[cfg(feature = "secp256k1")]
        let (full_b, full_e, partial_rounds) = (4, 4, 57);

        #[cfg(feature = "ed25519")]
        let (full_b, full_e, partial_rounds) = (4, 4, 57);

        let hash_params = PoseidonParams::new(width, full_b, full_e, partial_rounds).unwrap();

        check_hash_8(&hash_params, &SboxType::Cube);
        check_hash_8(&hash_params, &SboxType::Inverse);
        check_hash_8(&hash_params, &SboxType::Quint);
    }
}
