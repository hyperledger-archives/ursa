use super::helper_constraints::constrain_lc_with_scalar;
use crate::errors::R1CSError;
use crate::r1cs::linear_combination::AllocatedQuantity;
use crate::r1cs::{ConstraintSystem, LinearCombination, Prover, R1CSProof, Variable, Verifier};
use amcl_wrapper::field_elem::FieldElement;
use amcl_wrapper::group_elem_g1::{G1Vector, G1};
use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use std::time::{Duration, Instant};

use super::helper_constraints::poseidon::{
    PoseidonParams, Poseidon_hash_2, Poseidon_hash_2_gadget, Poseidon_hash_4,
    Poseidon_hash_4_gadget, Poseidon_hash_8, Poseidon_hash_8_gadget, SboxType, PADDING_CONST,
    ZERO_CONST,
};
use amcl_wrapper::commitment::commit_to_field_element;

/// Statics are needed to use permutation as a hash function
/// Allocate padding constant and zeroes for Prover
pub fn allocate_statics_for_prover(prover: &mut Prover, num_statics: usize) -> Vec<Variable> {
    let mut statics = vec![];
    let (_, var) = prover.commit(FieldElement::from(ZERO_CONST), FieldElement::zero());
    statics.push(var);

    if num_statics > statics.len() {
        // Commitment to PADDING_CONST with blinding as 0
        let (_, var) = prover.commit(FieldElement::from(PADDING_CONST), FieldElement::zero());
        statics.push(var);
    }

    // Commit to 0 with randomness 0 for the rest of the elements of width
    for _ in statics.len()..num_statics {
        let (_, var) = prover.commit(FieldElement::from(ZERO_CONST), FieldElement::zero());
        statics.push(var);
    }
    statics
}

/// Allocate padding constant and zeroes for Verifier
pub fn allocate_statics_for_verifier(
    verifier: &mut Verifier,
    num_statics: usize,
    g: &G1,
    h: &G1,
) -> Vec<Variable> {
    let mut statics = vec![];

    // Commitment to 0 with blinding as 0
    let zero_comm =
        commit_to_field_element(g, h, &FieldElement::from(ZERO_CONST), &FieldElement::zero());

    let v = verifier.commit(zero_comm.clone());
    statics.push(v);

    if num_statics > statics.len() {
        // Commitment to PADDING_CONST with blinding as 0
        let pad_comm = commit_to_field_element(
            g,
            h,
            &FieldElement::from(PADDING_CONST),
            &FieldElement::zero(),
        );
        let v = verifier.commit(pad_comm);
        statics.push(v);
    }

    for _ in statics.len()..num_statics {
        let v = verifier.commit(zero_comm.clone());
        statics.push(v);
    }
    statics
}

pub fn prove_knowledge_of_preimage_of_Poseidon_2<R: RngCore + CryptoRng>(
    mut inputs: Vec<FieldElement>,
    randomness: Option<Vec<FieldElement>>,
    expected_output: &FieldElement,
    hash_params: &PoseidonParams,
    sbox_type: &SboxType,
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

    let mut comms = vec![];

    let input1 = inputs.remove(0);
    let input2 = inputs.remove(0);

    let (com_l, var_l) = prover.commit(input1, rands.remove(0));
    comms.push(com_l);

    let (com_r, var_r) = prover.commit(input2, rands.remove(0));
    comms.push(com_r);

    let statics = allocate_statics_for_prover(prover, 1);

    Poseidon_hash_2_gadget(
        prover,
        var_l,
        var_r,
        statics,
        &hash_params,
        sbox_type,
        &expected_output,
    )?;

    Ok(comms)
}

pub fn verify_knowledge_of_preimage_of_Poseidon_2(
    expected_output: &FieldElement,
    hash_params: &PoseidonParams,
    sbox_type: &SboxType,
    mut commitments: Vec<G1>,
    g: &G1,
    h: &G1,
    verifier: &mut Verifier,
) -> Result<(), R1CSError> {
    let lv = verifier.commit(commitments.remove(0));
    let rv = verifier.commit(commitments.remove(0));

    let width = hash_params.width;

    let statics = allocate_statics_for_verifier(verifier, 1, g, h);

    Poseidon_hash_2_gadget(
        verifier,
        lv,
        rv,
        statics,
        &hash_params,
        sbox_type,
        &expected_output,
    )?;
    Ok(())
}

pub fn gen_proof_of_knowledge_of_preimage_of_Poseidon_2<R: RngCore + CryptoRng>(
    inputs: Vec<FieldElement>,
    randomness: Option<Vec<FieldElement>>,
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
    let mut prover_transcript = Transcript::new(transcript_label);
    let mut prover = Prover::new(&g, &h, &mut prover_transcript);

    let width = hash_params.width;
    let total_rounds = hash_params.full_rounds_beginning
        + hash_params.partial_rounds
        + hash_params.full_rounds_end;

    let comms = prove_knowledge_of_preimage_of_Poseidon_2(
        inputs,
        randomness,
        expected_output,
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

pub fn verify_proof_of_knowledge_of_preimage_of_Poseidon_2(
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

    verify_knowledge_of_preimage_of_Poseidon_2(
        expected_output,
        hash_params,
        sbox_type,
        commitments,
        g,
        h,
        &mut verifier,
    )?;
    verifier.verify(&proof, g, h, G, H)
}

pub fn prove_knowledge_of_preimage_of_Poseidon_4<R: RngCore + CryptoRng>(
    mut inputs: Vec<FieldElement>,
    randomness: Option<Vec<FieldElement>>,
    expected_output: &FieldElement,
    hash_params: &PoseidonParams,
    sbox_type: &SboxType,
    rng: Option<&mut R>,
    prover: &mut Prover,
) -> Result<Vec<G1>, R1CSError> {
    check_for_randomness_or_rng!(randomness, rng)?;

    let mut comms = vec![];
    let mut vars = vec![];

    let mut rands = randomness.unwrap_or_else(|| {
        let r = rng.unwrap();
        vec![
            FieldElement::random_using_rng(r),
            FieldElement::random_using_rng(r),
            FieldElement::random_using_rng(r),
            FieldElement::random_using_rng(r),
        ]
    });

    check_for_input_and_randomness_length!(inputs, rands, 4)?;

    for _ in 0..4 {
        let (com, var) = prover.commit(inputs.remove(0), rands.remove(0));
        comms.push(com);
        vars.push(var);
    }

    let num_statics = 1;
    let statics = allocate_statics_for_prover(prover, num_statics);

    Poseidon_hash_4_gadget(
        prover,
        vars,
        statics,
        &hash_params,
        sbox_type,
        &expected_output,
    )?;

    Ok(comms)
}

pub fn verify_knowledge_of_preimage_of_Poseidon_4(
    expected_output: &FieldElement,
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

    let num_statics = 1;
    let statics = allocate_statics_for_verifier(verifier, num_statics, g, h);

    Poseidon_hash_4_gadget(
        verifier,
        allocs,
        statics,
        &hash_params,
        sbox_type,
        &expected_output,
    )?;

    Ok(())
}

pub fn gen_proof_of_knowledge_of_preimage_of_Poseidon_4<R: RngCore + CryptoRng>(
    inputs: Vec<FieldElement>,
    randomness: Option<Vec<FieldElement>>,
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
    let total_rounds = hash_params.full_rounds_beginning
        + hash_params.partial_rounds
        + hash_params.full_rounds_end;

    let mut prover_transcript = Transcript::new(transcript_label);
    let mut prover = Prover::new(&g, &h, &mut prover_transcript);

    let comms = prove_knowledge_of_preimage_of_Poseidon_4(
        inputs,
        randomness,
        expected_output,
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

pub fn verify_proof_of_knowledge_of_preimage_of_Poseidon_4(
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

    verify_knowledge_of_preimage_of_Poseidon_4(
        expected_output,
        hash_params,
        sbox_type,
        commitments,
        g,
        h,
        &mut verifier,
    )?;

    verifier.verify(&proof, g, h, G, H)
}

pub fn prove_knowledge_of_preimage_of_Poseidon_8<R: RngCore + CryptoRng>(
    mut inputs: Vec<FieldElement>,
    randomness: Option<Vec<FieldElement>>,
    expected_output: &FieldElement,
    hash_params: &PoseidonParams,
    sbox_type: &SboxType,
    rng: Option<&mut R>,
    prover: &mut Prover,
) -> Result<Vec<G1>, R1CSError> {
    check_for_randomness_or_rng!(randomness, rng)?;

    let mut comms = vec![];
    let mut vars = vec![];

    let mut rands = randomness.unwrap_or_else(|| {
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

    check_for_input_and_randomness_length!(inputs, rands, 8)?;

    for _ in 0..8 {
        let (com, var) = prover.commit(inputs.remove(0), rands.remove(0));
        comms.push(com);
        vars.push(var);
    }

    let (_, var) = prover.commit(FieldElement::from(ZERO_CONST), FieldElement::zero());
    Poseidon_hash_8_gadget(prover, vars, var, &hash_params, sbox_type, &expected_output)?;

    Ok(comms)
}

pub fn verify_knowledge_of_preimage_of_Poseidon_8(
    expected_output: &FieldElement,
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

    let zero_comm =
        commit_to_field_element(g, h, &FieldElement::from(ZERO_CONST), &FieldElement::zero());
    let v = verifier.commit(zero_comm.clone());

    Poseidon_hash_8_gadget(verifier, vars, v, &hash_params, sbox_type, &expected_output)?;
    Ok(())
}

pub fn gen_proof_of_knowledge_of_preimage_of_Poseidon_8<R: RngCore + CryptoRng>(
    inputs: Vec<FieldElement>,
    randomness: Option<Vec<FieldElement>>,
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
    let total_rounds = hash_params.full_rounds_beginning
        + hash_params.partial_rounds
        + hash_params.full_rounds_end;

    let mut prover_transcript = Transcript::new(transcript_label);
    let mut prover = Prover::new(&g, &h, &mut prover_transcript);

    let comms = prove_knowledge_of_preimage_of_Poseidon_8(
        inputs,
        randomness,
        expected_output,
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

pub fn verify_proof_of_knowledge_of_preimage_of_Poseidon_8(
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

    verify_knowledge_of_preimage_of_Poseidon_8(
        expected_output,
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
    use crate::utils::get_generators;
    use amcl_wrapper::group_elem::GroupElement;
    use rand::rngs::OsRng;
    use rand::Rng;

    fn check_hash_2(hash_params: &PoseidonParams, sbox_type: &SboxType) {
        let mut rng = rand::thread_rng();

        let G: G1Vector = get_generators("G", 1024).into();
        let H: G1Vector = get_generators("H", 1024).into();
        let g = G1::from_msg_hash("g".as_bytes());
        let h = G1::from_msg_hash("h".as_bytes());

        let xl = FieldElement::random();
        let xr = FieldElement::random();
        let expected_output = Poseidon_hash_2(xl.clone(), xr.clone(), &hash_params, sbox_type);

        let label = b"PoseidonHash2:1";

        let start = Instant::now();
        let (proof, commitments) = gen_proof_of_knowledge_of_preimage_of_Poseidon_2(
            vec![xl, xr],
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
        let expected_output = Poseidon_hash_4(inputs.clone(), &hash_params, sbox_type);

        let label = b"PoseidonHash4:1";

        let start = Instant::now();
        let (proof, commitments) = gen_proof_of_knowledge_of_preimage_of_Poseidon_4(
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
            "Proving time for Poseidon 4:1 with sbox {:?} is: {:?}",
            sbox_type,
            start.elapsed()
        );

        let start = Instant::now();
        verify_proof_of_knowledge_of_preimage_of_Poseidon_4(
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
        let expected_output = Poseidon_hash_8(inputs.clone(), &hash_params, sbox_type);

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

        let hash_params = PoseidonParams::new(width, full_b, full_e, partial_rounds);

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

        let hash_params = PoseidonParams::new(width, full_b, full_e, partial_rounds);

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

        let hash_params = PoseidonParams::new(width, full_b, full_e, partial_rounds);

        check_hash_8(&hash_params, &SboxType::Cube);
        check_hash_8(&hash_params, &SboxType::Inverse);
        check_hash_8(&hash_params, &SboxType::Quint);
    }
}
