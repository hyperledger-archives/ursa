use super::helper_constraints::constrain_lc_with_scalar;
use crate::errors::R1CSError;
use crate::r1cs::linear_combination::AllocatedQuantity;
use crate::r1cs::{ConstraintSystem, LinearCombination, Prover, R1CSProof, Variable, Verifier};
use amcl_wrapper::field_elem::FieldElement;
use amcl_wrapper::group_elem::GroupElement;
use amcl_wrapper::group_elem_g1::{G1Vector, G1};
use merlin::Transcript;
use std::time::{Duration, Instant};

use rand::{CryptoRng, RngCore};

use crate::r1cs::gadgets::poseidon_hash::{
    allocate_statics_for_prover, allocate_statics_for_verifier,
};

use super::helper_constraints::poseidon::{PoseidonParams, SboxType};
use super::helper_constraints::sparse_merkle_tree_4_ary::{
    vanilla_merkle_merkle_tree_4_verif_gadget, DBVal, ProofNode, VanillaSparseMerkleTree_4,
};

pub fn gen_proof_of_leaf_inclusion_4_ary_merkle_tree<R: RngCore + CryptoRng>(
    leaf: FieldElement,
    leaf_index: FieldElement,
    randomness: Option<[FieldElement; 2]>,
    merkle_proof: Vec<ProofNode>,
    root: &FieldElement,
    tree_depth: usize,
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

    let mut prover_transcript = Transcript::new(transcript_label);
    let mut prover = Prover::new(&g, &h, &mut prover_transcript);

    // Randomness is only provided for leaf value and leaf index
    let rands: [FieldElement; 2] = randomness.unwrap_or_else(|| {
        let r = rng.unwrap();
        [
            FieldElement::random_using_rng(r),
            FieldElement::random_using_rng(r),
        ]
    });

    let mut comms = vec![];

    let (com_leaf, var_leaf) = prover.commit(leaf.clone(), rands[0]);
    let leaf_alloc_scalar = AllocatedQuantity {
        variable: var_leaf,
        assignment: Some(leaf),
    };
    comms.push(com_leaf);

    let (com_leaf_idx, var_leaf_idx) = prover.commit(leaf_index.clone(), rands[1]);
    let leaf_idx_alloc_scalar = AllocatedQuantity {
        variable: var_leaf_idx,
        assignment: Some(leaf_index),
    };
    comms.push(com_leaf_idx);

    let mut proof_alloc_scalars = vec![];
    for p in merkle_proof.iter() {
        for i in p {
            let (c, v) = prover.commit(*i, FieldElement::random());
            comms.push(c);
            proof_alloc_scalars.push(AllocatedQuantity {
                variable: v,
                assignment: Some(*i),
            });
        }
    }

    let num_statics = 2;
    let statics = allocate_statics_for_prover(&mut prover, num_statics);

    let start = Instant::now();
    vanilla_merkle_merkle_tree_4_verif_gadget(
        &mut prover,
        tree_depth,
        root,
        leaf_alloc_scalar,
        leaf_idx_alloc_scalar,
        proof_alloc_scalars,
        statics,
        &hash_params,
        sbox_type,
    )?;

    let total_rounds = hash_params.full_rounds_beginning
        + hash_params.partial_rounds
        + hash_params.full_rounds_end;
    println!("For 4-ary tree of height {} (has 2^{} leaves) and Poseidon rounds {}, no of multipliers is {} and constraints is {}", tree_depth, tree_depth*2, total_rounds, &prover.num_multipliers(), &prover.num_constraints());

    let proof = prover.prove(G, H).unwrap();
    let end = start.elapsed();

    println!("Proving time is {:?}", end);

    Ok((proof, comms))
}

pub fn verify_leaf_inclusion_4_ary_merkle_tree(
    root: &FieldElement,
    tree_depth: usize,
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

    let var_leaf = verifier.commit(commitments[0]);
    let leaf_alloc_scalar = AllocatedQuantity {
        variable: var_leaf,
        assignment: None,
    };

    let var_leaf_idx = verifier.commit(commitments[1]);
    let leaf_idx_alloc_scalar = AllocatedQuantity {
        variable: var_leaf_idx,
        assignment: None,
    };

    let mut proof_alloc_scalars = vec![];
    for c in commitments[2..].iter() {
        let v = verifier.commit(*c);
        proof_alloc_scalars.push(AllocatedQuantity {
            variable: v,
            assignment: None,
        });
    }

    let num_statics = 2;
    let statics = allocate_statics_for_verifier(&mut verifier, num_statics, g, h);

    let start = Instant::now();
    vanilla_merkle_merkle_tree_4_verif_gadget(
        &mut verifier,
        tree_depth,
        root,
        leaf_alloc_scalar,
        leaf_idx_alloc_scalar,
        proof_alloc_scalars,
        statics,
        hash_params,
        sbox_type,
    )?;

    verifier.verify(&proof, &g, &h, &G, &H)?;
    let end = start.elapsed();

    println!("Verification time is {:?}", end);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::get_generators;

    #[test]
    fn test_VSMT_4_Verif() {
        let width = 6;
        let (full_b, full_e) = (4, 4);
        let partial_rounds = 57;
        let total_rounds = full_b + partial_rounds + full_e;
        let hash_params = PoseidonParams::new(width, full_b, full_e, partial_rounds);
        let tree_depth = 6;
        let mut tree = VanillaSparseMerkleTree_4::new(&hash_params, tree_depth);

        for i in 1..=10 {
            let s = FieldElement::from(i as u32);
            tree.update(s, s);
        }

        let mut merkle_proof_vec = Vec::<ProofNode>::new();
        let mut merkle_proof = Some(merkle_proof_vec);
        let k = FieldElement::from(7u32);
        assert_eq!(k, tree.get(k, &mut merkle_proof));
        merkle_proof_vec = merkle_proof.unwrap();
        assert!(tree.verify_proof(k, k, &merkle_proof_vec, None));
        assert!(tree.verify_proof(k, k, &merkle_proof_vec, Some(&tree.root)));

        let mut rng = rand::thread_rng();

        let sbox_type = &SboxType::Quint;

        // TODO: Use iterators. Generating so many generators at once is very slow. In practice, generators will be persisted.
        let G: G1Vector = get_generators("G", 8192).into();
        let H: G1Vector = get_generators("H", 8192).into();

        let g = G1::from_msg_hash("g".as_bytes());
        let h = G1::from_msg_hash("h".as_bytes());

        let label = b"4-aryMerkleTree";

        let (proof, commitments) = gen_proof_of_leaf_inclusion_4_ary_merkle_tree(
            k.clone(),
            k.clone(),
            None,
            merkle_proof_vec,
            &tree.root,
            tree.depth,
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

        verify_leaf_inclusion_4_ary_merkle_tree(
            &tree.root,
            tree.depth,
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
}
