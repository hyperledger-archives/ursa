use crate::errors::{R1CSError, R1CSErrorKind};
use crate::r1cs::linear_combination::AllocatedQuantity;
use crate::r1cs::{Prover, R1CSProof, Verifier};
use amcl_wrapper::field_elem::FieldElement;
use amcl_wrapper::group_elem_g1::{G1Vector, G1};
use merlin::Transcript;
use std::time::Instant;

use rand::{CryptoRng, Rng};

use super::helper_constraints::sparse_merkle_tree_4_ary::{
    vanilla_merkle_merkle_tree_4_verif_gadget, ProofNode4ary,
};
use crate::r1cs::gadgets::helper_constraints::{
    get_blinding_for_merkle_tree_prover, LeafValueType,
};
use crate::r1cs::gadgets::merkle_tree_hash::Arity4MerkleTreeHashConstraints;

// If the leaf value (`leaf`) is not hidden from the verifier, then it will not be committed to
pub fn prove_leaf_inclusion_4_ary_merkle_tree<
    R: Rng + CryptoRng,
    MTHC: Arity4MerkleTreeHashConstraints,
>(
    leaf: FieldElement,
    leaf_index: FieldElement,
    hide_leaf: bool, // Indicates whether the leaf value is hidden from the verifier or not
    blindings: Option<Vec<FieldElement>>,
    mut merkle_proof: Vec<ProofNode4ary>,
    root: &FieldElement,
    tree_depth: usize,
    hash_func: &mut MTHC,
    rng: Option<&mut R>,
    prover: &mut Prover,
) -> Result<Vec<G1>, R1CSError> {
    check_for_blindings_or_rng!(blindings, rng)?;

    let mut blindings = get_blinding_for_merkle_tree_prover(hide_leaf, blindings, rng)?;

    let mut comms = vec![];

    let (com_leaf_idx, var_leaf_idx) = prover.commit(leaf_index.clone(), blindings.remove(0));
    let leaf_idx_alloc_scalar = AllocatedQuantity {
        variable: var_leaf_idx,
        assignment: Some(leaf_index),
    };
    comms.push(com_leaf_idx);

    let leaf = if hide_leaf {
        let (com_leaf, var_leaf) = prover.commit(leaf, blindings.remove(0));
        comms.push(com_leaf);
        LeafValueType::Hidden(var_leaf)
    } else {
        LeafValueType::Known(leaf)
    };

    let mut proof_vars = vec![];
    for p in merkle_proof.drain(0..) {
        for i in p.iter() {
            let (c, v) = prover.commit(i.clone(), FieldElement::random());
            comms.push(c);
            proof_vars.push(v);
        }
    }

    hash_func.prover_setup(prover)?;
    vanilla_merkle_merkle_tree_4_verif_gadget(
        prover,
        tree_depth,
        root,
        leaf,
        leaf_idx_alloc_scalar,
        proof_vars,
        hash_func,
    )?;

    Ok(comms)
}

pub fn verify_leaf_inclusion_4_ary_merkle_tree<MTHC: Arity4MerkleTreeHashConstraints>(
    root: &FieldElement,
    tree_depth: usize,
    hash_func: &mut MTHC,
    leaf_val: Option<FieldElement>, // If the leaf value is hidden from the verifier, `leaf_val` will be None else it will have the value of the leaf
    mut commitments: Vec<G1>,
    g: &G1,
    h: &G1,
    verifier: &mut Verifier,
) -> Result<(), R1CSError> {
    let var_leaf_idx = verifier.commit(commitments.remove(0));
    let leaf_idx_alloc_scalar = AllocatedQuantity {
        variable: var_leaf_idx,
        assignment: None,
    };

    let leaf = match leaf_val {
        Some(v) => LeafValueType::Known(v),
        None => LeafValueType::Hidden(verifier.commit(commitments.remove(0))),
    };

    let mut proof_vars = vec![];
    for c in commitments.drain(0..) {
        let v = verifier.commit(c);
        proof_vars.push(v);
    }

    hash_func.verifier_setup(verifier, Some(g), Some(h))?;
    vanilla_merkle_merkle_tree_4_verif_gadget(
        verifier,
        tree_depth,
        root,
        leaf,
        leaf_idx_alloc_scalar,
        proof_vars,
        hash_func,
    )?;

    Ok(())
}

pub fn gen_proof_of_leaf_inclusion_4_ary_merkle_tree<
    R: Rng + CryptoRng,
    MTHC: Arity4MerkleTreeHashConstraints,
>(
    leaf: FieldElement,
    leaf_index: FieldElement,
    hide_leaf: bool, // Indicates whether the leaf value is hidden from the verifier or not
    blindings: Option<Vec<FieldElement>>,
    merkle_proof: Vec<ProofNode4ary>,
    root: &FieldElement,
    tree_depth: usize,
    hash_func: &mut MTHC,
    rng: Option<&mut R>,
    transcript_label: &'static [u8],
    g: &G1,
    h: &G1,
    G: &G1Vector,
    H: &G1Vector,
) -> Result<(R1CSProof, Vec<G1>), R1CSError> {
    let mut prover_transcript = Transcript::new(transcript_label);
    let mut prover = Prover::new(&g, &h, &mut prover_transcript);

    let start = Instant::now();

    let comms = prove_leaf_inclusion_4_ary_merkle_tree(
        leaf,
        leaf_index,
        hide_leaf,
        blindings,
        merkle_proof,
        root,
        tree_depth,
        hash_func,
        rng,
        &mut prover,
    )?;

    /*let total_rounds = hash_params.full_rounds_beginning
        + hash_params.partial_rounds
        + hash_params.full_rounds_end;
    println!("For 4-ary tree of height {} (has 2^{} leaves) and Poseidon rounds {}, no of multipliers is {} and constraints is {}", tree_depth, tree_depth*2, total_rounds, &prover.num_multipliers(), &prover.num_constraints());*/

    let proof = prover.prove(G, H).unwrap();
    let end = start.elapsed();

    println!("Proving time is {:?}", end);

    Ok((proof, comms))
}

pub fn verify_proof_of_leaf_inclusion_4_ary_merkle_tree<MTHC: Arity4MerkleTreeHashConstraints>(
    root: &FieldElement,
    tree_depth: usize,
    hash_func: &mut MTHC,
    proof: R1CSProof,
    leaf_val: Option<FieldElement>, // If the leaf value is hidden from the verifier, `leaf_val` will be None else it will have the value of the leaf
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

    verify_leaf_inclusion_4_ary_merkle_tree(
        root,
        tree_depth,
        hash_func,
        leaf_val,
        commitments,
        g,
        h,
        &mut verifier,
    )?;

    verifier.verify(&proof, g, h, G, H)?;
    let end = start.elapsed();

    println!("Verification time is {:?}", end);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::r1cs::gadgets::helper_constraints::poseidon::{PoseidonParams, SboxType};
    use crate::r1cs::gadgets::helper_constraints::sparse_merkle_tree_4_ary::{
        DbVal4ary, VanillaSparseMerkleTree4,
    };
    use crate::r1cs::gadgets::merkle_tree_hash::{PoseidonHash4, PoseidonHashConstraints};
    use crate::utils::get_generators;
    use crate::utils::hash_db::InMemoryHashDb;
    use amcl_wrapper::group_elem::GroupElement;

    #[test]
    fn test_VSMT_4_Verif() {
        use crate::r1cs::gadgets::helper_constraints::poseidon::CAP_CONST_W_5;

        let width = 5;

        let mut db = InMemoryHashDb::<DbVal4ary>::new();

        #[cfg(feature = "bls381")]
        let (full_b, full_e, partial_rounds) = (4, 4, 56);

        #[cfg(feature = "bn254")]
        let (full_b, full_e, partial_rounds) = (4, 4, 56);

        #[cfg(feature = "secp256k1")]
        let (full_b, full_e, partial_rounds) = (4, 4, 56);

        #[cfg(feature = "ed25519")]
        let (full_b, full_e, partial_rounds) = (4, 4, 56);

        // let total_rounds = full_b + partial_rounds + full_e;
        let hash_params = PoseidonParams::new(width, full_b, full_e, partial_rounds).unwrap();
        let tree_depth = 12;
        let sbox = &SboxType::Quint;

        let hash_func = PoseidonHash4 {
            params: &hash_params,
            sbox,
        };
        let mut tree = VanillaSparseMerkleTree4::new(&hash_func, tree_depth, &mut db).unwrap();

        for i in 1..=10 {
            let s = FieldElement::from(i as u32);
            tree.update(&s, s.clone(), &mut db).unwrap();
        }

        // TODO: Use iterators. Generating so many generators at once is very slow. In practice, generators will be persisted.
        let G: G1Vector = get_generators("G", 8192).into();
        let H: G1Vector = get_generators("H", 8192).into();

        let g = G1::from_msg_hash("g".as_bytes());
        let h = G1::from_msg_hash("h".as_bytes());

        for i in vec![3u32, 4u32, 7u32, 8u32, 9u32] {
            let mut merkle_proof_vec = Vec::<ProofNode4ary>::new();
            let mut merkle_proof = Some(merkle_proof_vec);
            let k = FieldElement::from(i);
            assert_eq!(k, tree.get(&k, &mut merkle_proof, &db).unwrap());
            merkle_proof_vec = merkle_proof.unwrap();
            assert!(tree
                .verify_proof(&k, &k, &merkle_proof_vec, Some(&tree.root))
                .unwrap());

            let mut rng = rand::thread_rng();

            let label = b"4-aryMerkleTree";

            // Test with leaf value hidden from verifier
            let mut hash_func = PoseidonHashConstraints::new(&hash_params, sbox, CAP_CONST_W_5);
            let (proof, commitments) = gen_proof_of_leaf_inclusion_4_ary_merkle_tree(
                k.clone(),
                k.clone(),
                true,
                None,
                merkle_proof_vec.clone(),
                &tree.root,
                tree.depth,
                &mut hash_func,
                Some(&mut rng),
                label,
                &g,
                &h,
                &G,
                &H,
            )
            .unwrap();

            let mut hash_func = PoseidonHashConstraints::new(&hash_params, sbox, CAP_CONST_W_5);
            verify_proof_of_leaf_inclusion_4_ary_merkle_tree(
                &tree.root,
                tree.depth,
                &mut hash_func,
                proof,
                None,
                commitments,
                label,
                &g,
                &h,
                &G,
                &H,
            )
            .unwrap();

            // Test with leaf value known to verifier
            let mut hash_func = PoseidonHashConstraints::new(&hash_params, sbox, CAP_CONST_W_5);
            let (proof, commitments) = gen_proof_of_leaf_inclusion_4_ary_merkle_tree(
                k.clone(),
                k.clone(),
                false,
                None,
                merkle_proof_vec,
                &tree.root,
                tree.depth,
                &mut hash_func,
                Some(&mut rng),
                label,
                &g,
                &h,
                &G,
                &H,
            )
            .unwrap();

            let mut hash_func = PoseidonHashConstraints::new(&hash_params, sbox, CAP_CONST_W_5);
            verify_proof_of_leaf_inclusion_4_ary_merkle_tree(
                &tree.root,
                tree.depth,
                &mut hash_func,
                proof,
                Some(k.clone()), // The verifier knows the value of the leaf
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
}
