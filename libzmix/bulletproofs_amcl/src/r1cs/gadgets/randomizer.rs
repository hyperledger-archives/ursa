use rand::{CryptoRng, Rng};
/// Gadget to prove that 2 merkle trees have only few leaves different.
/// The leaves that are chosen different is based on value of the nonce
/// It is known to verifier which leaves are distorted.
/// The circuit should take the original data root, distorted data and the original data points which were distorted.
/// The idea is that the circuit will take call update as many times as the number of distorted leaves and eventually the root should match
/// Note that this is very slow.
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use amcl_wrapper::amcl::sha3::{SHA3, SHAKE256};
use amcl_wrapper::constants::MODBYTES;
use amcl_wrapper::field_elem::{FieldElement, FieldElementVector};
use amcl_wrapper::group_elem::GroupElement;
use amcl_wrapper::group_elem_g1::{G1Vector, G1};
use merlin::Transcript;

use super::helper_constraints::poseidon::{
    PoseidonParams, Poseidon_hash_4, Poseidon_hash_4_constraints, SboxType,
};
use super::helper_constraints::sparse_merkle_tree_4_ary::{
    vanilla_merkle_merkle_tree_4_verif_gadget, DbVal4ary, ProofNode4ary,
    VanillaSparseMerkleTree4,
};

use crate::errors::R1CSError;
use crate::r1cs::gadgets::helper_constraints::poseidon::CAP_CONST_W_5;
use crate::r1cs::gadgets::poseidon_hash::{
    allocate_capacity_const_for_prover, allocate_capacity_const_for_verifier,
};
use crate::r1cs::linear_combination::AllocatedQuantity;
use crate::r1cs::{ConstraintSystem, LinearCombination, Prover, R1CSProof, Variable, Verifier};
use crate::utils::hash_db::HashDb;

/// Hash to get a new number. For other variations a keyed permutation should be used.
pub fn randomize(x: &FieldElement) -> FieldElement {
    FieldElement::from_msg_hash(&x.to_bytes())
}

/// Generate `count_modified` numbers in range [0, data_size) using `nonce`. Uses SHAKE.
pub fn get_indices_to_modify(
    nonce: &FieldElement,
    data_size: usize,
    count_modified: usize,
) -> HashSet<FieldElement> {
    let mut hasher = SHA3::new(SHAKE256);
    for b in nonce.to_bytes() {
        hasher.process(b);
    }
    // Generate twice the number of bytes needed for random numbers as there might be some duplicates when taking modulo data_size_as_big
    let target_byte_size = 2 * count_modified * MODBYTES;
    let mut target = vec![0u8; target_byte_size];
    hasher.shake(&mut target.as_mut_slice(), target_byte_size);
    let data_size_as_big = FieldElement::from(data_size as u64).to_bignum();
    let mut indices = HashSet::<FieldElement>::new();
    //for _ in 0..count_modified {
    while (indices.len() < count_modified) && (target.len() >= MODBYTES) {
        let b: Vec<_> = target.drain(0..MODBYTES).collect();
        let mut n = FieldElement::from_bytes(&b).unwrap().to_bignum();
        // TODO: Somewhat probable that modulo data_size leads to repetition.
        // If that is the case, generate use a bigger target_size with shake.
        n.rmod(&data_size_as_big);
        indices.insert(n.into());
    }
    indices
}

pub fn get_randomized_data(
    original_data: &FieldElementVector,
    indices: &HashSet<FieldElement>,
) -> (HashMap<FieldElement, FieldElement>, FieldElementVector) {
    // Keeps original values of the modified indices.
    let mut modified_indices = HashMap::<FieldElement, FieldElement>::new();
    let mut new_data = original_data.clone();
    for _i in indices {
        // Next line is a temporary workaround
        let i = _i.to_bignum().w[0] as usize;
        let randomized = randomize(&new_data[i]);
        modified_indices.insert(_i.clone(), new_data[i].clone());
        new_data[i] = randomized;
    }

    (modified_indices, new_data)
}

/// Proves the presence of `orig_vals` in the tree with root `orig_root`.
/// Also proves that if `new_tree` is updated with `orig_vals`, its root becomes same `orig_root`
pub fn randomizer_gadget<CS: ConstraintSystem>(
    cs: &mut CS,
    depth: usize,
    orig_root: Variable, // original root is hidden since its correlating across several proofs
    new_tree: &mut VanillaSparseMerkleTree4,
    new_db: &mut HashDb<DbVal4ary>,
    indices: Vec<FieldElement>, // For future: `indices` can be made hidden too
    orig_vals: Vec<Variable>,   // values of the original tree
    mut orig_vals_proofs: Vec<Vec<Variable>>, // merkle proofs for values of the original tree
    capacity_const: Variable,
    poseidon_params: &PoseidonParams,
    sbox_type: &SboxType,
) -> Result<(), R1CSError> {
    assert_eq!(new_tree.depth, depth);
    assert_eq!(indices.len(), orig_vals.len());

    // Keep a map of path -> LinearCombination for the new_tree for all nodes in paths of modified indices
    let mut new_tree_modified_nodes = HashMap::<Vec<u8>, LinearCombination>::new();
    let root_key = vec![];
    new_tree_modified_nodes.insert(root_key.clone(), new_tree.root.clone().into());

    for i in 0..indices.len() {
        let idx = &indices[i];
        let orig_vals_proof = &mut orig_vals_proofs[i];

        let mut path_for_update = VanillaSparseMerkleTree4::leaf_index_to_path(idx, depth);
        let path_for_get = path_for_update.clone(); // Path from root to leaf
        path_for_update.reverse(); // Path from leaf to root

        // Prove index `idx` has value `orig_val` in tree with root `orig_root`.
        let mut cur_hash_in_orig_tree = orig_vals[i].into();
        for pos in path_for_update {
            let mut proof: Vec<LinearCombination> = vec![];
            proof.push(orig_vals_proof.pop().unwrap().into());
            proof.push(orig_vals_proof.pop().unwrap().into());
            proof.push(orig_vals_proof.pop().unwrap().into());
            proof.reverse();
            proof.insert(pos as usize, cur_hash_in_orig_tree);
            cur_hash_in_orig_tree = Poseidon_hash_4_constraints::<CS>(
                cs,
                proof,
                capacity_const.into(),
                poseidon_params,
                sbox_type,
            )?;
        }

        cs.constrain(cur_hash_in_orig_tree - orig_root);

        // Get all nodes on the path and its neighbors for idx in the new tree. Thus we end up with 4*depth node for each index
        let mut cur_node = new_tree.root.clone();
        let mut cur_prefix: Vec<u8> = vec![];

        for pos in path_for_get.iter() {
            let children = new_db.get(&cur_node.to_bytes()).unwrap().to_vec();
            cur_node = children[*pos as usize].clone();
            for (k, c) in children.iter().enumerate() {
                let mut key = cur_prefix.clone();
                key.push(k as u8);

                if !new_tree_modified_nodes.contains_key(&key) {
                    // As tree does not change during "get"s, only update `new_tree_modified_nodes` when key is absent
                    new_tree_modified_nodes.insert(key, LinearCombination::from(c.clone()));
                }
            }
            cur_prefix.push(*pos);
        }
    }

    // Update new_tree with orig_val
    for i in 0..indices.len() {
        let idx = &indices[i];
        let orig_val = orig_vals[i];

        let mut path = VanillaSparseMerkleTree4::leaf_index_to_path(idx, depth);

        let mut orig_val_lc = LinearCombination::from(orig_val);
        // Move in reverse order in path, i.e. leaf to root, updating `new_tree_modified_nodes` on nodes from leaf leading to root.
        for j in (0..depth).rev() {
            let mut nodes_at_level_j = vec![];
            for k in 0..4 {
                if path[j] != k {
                    let mut key = path.clone();
                    key[j] = k;
                    nodes_at_level_j.push(new_tree_modified_nodes[&key].clone());
                }
            }
            nodes_at_level_j.insert(path[j] as usize, orig_val_lc.clone());

            if j == (depth - 1) {
                // Since the leaf is updated, update the corresponding linear combination.
                new_tree_modified_nodes.insert(path.clone(), orig_val_lc);
            }

            orig_val_lc = Poseidon_hash_4_constraints::<CS>(
                cs,
                nodes_at_level_j,
                capacity_const.into(),
                poseidon_params,
                sbox_type,
            )?;
            path.remove(j);
            new_tree_modified_nodes.insert(path.clone(), orig_val_lc.clone());
        }
    }

    cs.constrain(new_tree_modified_nodes[&root_key].clone() - orig_root);

    Ok(())
}

/// XXX ORIGINAL TREE AS ARGUMENT SEEMS ODD. BETTER PASS THE PROOF.
pub fn gen_proof_for_randomizer(
    orig_tree: &VanillaSparseMerkleTree4,
    orig_db: &HashDb<DbVal4ary>,
    new_tree: &mut VanillaSparseMerkleTree4,
    new_db: &mut HashDb<DbVal4ary>,
    modified_indices: &[FieldElement],
    orig_vals: &[FieldElement],
    tree_depth: usize,
    hash_params: &PoseidonParams,
    sbox_type: &SboxType,
    transcript_label: &'static [u8],
    g: &G1,
    h: &G1,
    G: &G1Vector,
    H: &G1Vector,
) -> Result<(R1CSProof, Vec<G1>), R1CSError> {
    let orig_root = &orig_tree.root;

    let mut prover_transcript = Transcript::new(transcript_label);
    let mut prover = Prover::new(&g, &h, &mut prover_transcript);

    let mut comms = vec![];

    let (com_orig_root, var_orig_root) = prover.commit(orig_root.clone(), FieldElement::random());
    comms.push(com_orig_root);

    let mut orig_val_vars = vec![];
    let mut proof_vars = vec![];

    //for (i, v) in modified_indices {
    for i in 0..modified_indices.len() {
        let mut merkle_proof_vec = Vec::<ProofNode4ary>::new();
        let mut merkle_proof = Some(merkle_proof_vec);
        let _v = orig_tree.get(&modified_indices[i], &mut merkle_proof, orig_db)?;
        assert_eq!(_v, orig_vals[i]);
        let (com_orig_val, var_orig_val) = prover.commit(_v, FieldElement::random());
        comms.push(com_orig_val);
        orig_val_vars.push(var_orig_val);

        merkle_proof_vec = merkle_proof.unwrap();
        //println!("merkle_proof_vec len {}", &merkle_proof_vec.len());
        let mut ps = vec![];
        for p in merkle_proof_vec.iter() {
            for j in p {
                let (c, v) = prover.commit(j.clone(), FieldElement::random());
                comms.push(c);
                ps.push(v);
            }
        }
        proof_vars.push(ps);
    }

    let capacity_const = allocate_capacity_const_for_prover(&mut prover, CAP_CONST_W_5);

    let start = Instant::now();
    randomizer_gadget(
        &mut prover,
        tree_depth,
        var_orig_root,
        new_tree,
        new_db,
        modified_indices.to_vec(),
        orig_val_vars,
        proof_vars,
        capacity_const,
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

pub fn verify_proof_for_randomizer(
    new_tree: &mut VanillaSparseMerkleTree4,
    new_db: &mut HashDb<DbVal4ary>,
    modified_indices: &[FieldElement], // For future: `modified_indices` can be made hidden too
    tree_depth: usize,
    hash_params: &PoseidonParams,
    sbox_type: &SboxType,
    proof: R1CSProof,
    mut commitments: Vec<G1>,
    transcript_label: &'static [u8],
    g: &G1,
    h: &G1,
    G: &G1Vector,
    H: &G1Vector,
) -> Result<(), R1CSError> {
    let mut verifier_transcript = Transcript::new(transcript_label);
    let mut verifier = Verifier::new(&mut verifier_transcript);

    let var_orig_root = verifier.commit(commitments.remove(0));

    let mut orig_val_vars = vec![];
    let mut proof_vars = vec![];

    for _ in 0..modified_indices.len() {
        let var_orig_val = verifier.commit(commitments.remove(0));
        orig_val_vars.push(var_orig_val);

        let mut ps = vec![];
        for _ in 0..tree_depth * 3 {
            // Proof length = tree depth * 3
            let var = verifier.commit(commitments.remove(0));
            ps.push(var);
        }
        proof_vars.push(ps);
    }

    let capacity_const = allocate_capacity_const_for_verifier(&mut verifier, CAP_CONST_W_5, g, h);

    let start = Instant::now();
    randomizer_gadget(
        &mut verifier,
        tree_depth,
        var_orig_root,
        new_tree,
        new_db,
        modified_indices.to_vec(),
        orig_val_vars,
        proof_vars,
        capacity_const,
        hash_params,
        sbox_type,
    )?;

    verifier.verify(&proof, g, h, G, H)?;
    let end = start.elapsed();

    println!("Verification time is {:?}", end);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::get_generators;
    use crate::utils::hash_db::InMemoryHashDb;

    #[test]
    fn test_randomizer() {
        let width = 5;

        let mut orig_db = InMemoryHashDb::<DbVal4ary>::new();

        #[cfg(feature = "bls381")]
        let (full_b, full_e, partial_rounds) = (4, 4, 56);

        #[cfg(feature = "bn254")]
        let (full_b, full_e, partial_rounds) = (4, 4, 56);

        #[cfg(feature = "secp256k1")]
        let (full_b, full_e, partial_rounds) = (4, 4, 56);

        #[cfg(feature = "ed25519")]
        let (full_b, full_e, partial_rounds) = (4, 4, 56);

        let hash_params = PoseidonParams::new(width, full_b, full_e, partial_rounds);

        let tree_depth = 8;
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

        let mut orig_tree = VanillaSparseMerkleTree4::new(&hash_params, tree_depth, &mut orig_db);
        for i in 0..data_size {
            // Next line is a temporary workaround
            let idx = FieldElement::from(i as u64);
            orig_tree
                .update(&idx, original_data[i].clone(), &mut orig_db)
                .unwrap();
        }
        let orig_root = orig_tree.root.clone();

        let (modified_indices, new_data) = get_randomized_data(&original_data, &indices);
        // `new_data` is different from `original_data` only in `count_modified` values.
        // Check by creating sets over `new_data` and `original_data` and then intersecting them.
        // The intersection should have `data_size - count_modified` values.
        let orig_data_set: HashSet<&FieldElement> = original_data.iter().collect();
        let new_data_set: HashSet<&FieldElement> = new_data.iter().collect();
        let intersection: HashSet<_> = orig_data_set.intersection(&new_data_set).collect();
        assert_eq!(intersection.len(), data_size - count_modified);

        // Create new tree different from original tree
        let mut new_tree = orig_tree.clone();
        let mut new_db = orig_db.clone();
        for (i, v) in &modified_indices {
            new_tree.update(i, randomize(v), &mut new_db).unwrap();
        }
        assert_ne!(orig_root, new_tree.root);

        // Update new_tree back to old tree
        for (i, v) in &modified_indices {
            new_tree.update(i, v.clone(), &mut new_db).unwrap();
        }
        assert_eq!(orig_root, new_tree.root);

        // Create new tree different from original tree
        let mut new_tree_again = orig_tree.clone();
        let mut new_db_again = orig_db.clone();
        for (i, v) in &modified_indices {
            new_tree_again
                .update(i, randomize(v), &mut new_db_again)
                .unwrap();
        }
        assert_ne!(orig_root, new_tree_again.root);

        let sbox_type = &SboxType::Quint;

        // TODO: Use iterators. Generating so many generators at once is very slow. In practice, generators will be persisted.
        let G: G1Vector = get_generators("G", 65536).into();
        let H: G1Vector = get_generators("H", 65536).into();

        let g = G1::from_msg_hash("g".as_bytes());
        let h = G1::from_msg_hash("h".as_bytes());

        let label = b"Randomizer";

        let mut idxs = vec![];
        let mut orig_vals = vec![];
        for (i, v) in modified_indices {
            idxs.push(i);
            orig_vals.push(v);
        }

        let (proof, commitments) = {
            let mut new_tree_clone = new_tree_again.clone();
            let mut new_db_clone = new_db_again.clone();
            gen_proof_for_randomizer(
                &orig_tree,
                &orig_db,
                &mut new_tree_clone,
                &mut new_db_clone,
                &idxs,
                &orig_vals,
                tree_depth,
                &hash_params,
                sbox_type,
                label,
                &g,
                &h,
                &G,
                &H,
            )
            .unwrap()
        };

        {
            let mut new_tree_clone = new_tree_again.clone();
            let mut new_db_clone = new_db_again.clone();
            verify_proof_for_randomizer(
                &mut new_tree_clone,
                &mut new_db_clone,
                &idxs,
                tree_depth,
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
}
