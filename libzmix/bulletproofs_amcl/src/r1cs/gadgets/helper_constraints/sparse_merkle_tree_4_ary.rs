use crate::errors::{BulletproofError, R1CSError};
use crate::r1cs::linear_combination::AllocatedQuantity;
use crate::r1cs::{ConstraintSystem, LinearCombination, Variable};
use amcl_wrapper::field_elem::FieldElement;

use super::{constrain_lc_with_scalar, get_byte_size};
use crate::r1cs::gadgets::helper_constraints::{
    allocated_leaf_index_to_bytes, get_repr_in_power_2_base, LeafValueType,
};
use crate::r1cs::gadgets::merkle_tree_hash::{
    Arity4MerkleTreeHash, Arity4MerkleTreeHashConstraints,
};
use crate::utils::hash_db::HashDb;

pub type DbVal4ary = [FieldElement; 4];
pub type ProofNode4ary = [FieldElement; 3];

// Consider usage of SHA-2/3 as a hash function as well for testing. Testing constraint system will
// be hard with SHA as don't have constraints for now.
/// Sparse merkle tree with arity 4, .i.e each node has 4 children.
#[derive(Clone, Debug)]
pub struct VanillaSparseMerkleTree4<'a, MTH: Arity4MerkleTreeHash> {
    pub depth: usize,
    hash_func: &'a MTH,
    pub root: FieldElement,
}

/// For details here of sparse merkle trees, check here https://ethresear.ch/t/optimizing-sparse-merkle-trees/3751

// The logic of `VanillaSparseMerkleTree4` and `VanillaSparseMerkleTree8` is same. Only the arity
// and hence the hash function differs. The code is still kept separate for clarity. If code is to be
// combined then a generic implementation will take the hash and database as type parameters.

impl<'a, MTH> VanillaSparseMerkleTree4<'a, MTH>
where
    MTH: Arity4MerkleTreeHash,
{
    /// Create a new tree
    /// Requires a database to hold leaves and nodes. The db should implement the `HashDb` trait
    pub fn new(
        hash_func: &'a MTH,
        depth: usize,
        hash_db: &mut dyn HashDb<DbVal4ary>,
    ) -> Result<VanillaSparseMerkleTree4<'a, MTH>, BulletproofError> {
        // Hash for the each level of the tree when all leaves are same (choosing zero here arbitrarily).
        // Since all leaves are same, all nodes at the same level will have the same value.
        let mut empty_tree_hashes: Vec<FieldElement> = vec![];
        empty_tree_hashes.push(FieldElement::zero());
        for i in 1..=depth {
            let prev = &empty_tree_hashes[i - 1];
            let input: Vec<FieldElement> = (0..4).map(|_| prev.clone()).collect();
            // Hash all 4 children at once
            let mut val: DbVal4ary = [
                FieldElement::zero(),
                FieldElement::zero(),
                FieldElement::zero(),
                FieldElement::zero(),
            ];
            val.clone_from_slice(input.as_slice());
            let new = hash_func.hash(input)?;
            let key = new.to_bytes();

            hash_db.insert(key, val);
            empty_tree_hashes.push(new);
        }

        let root = empty_tree_hashes[depth].clone();

        Ok(VanillaSparseMerkleTree4 {
            depth,
            hash_func,
            root,
        })
    }

    /// Set the given `val` at the given leaf index `idx`
    pub fn update(
        &mut self,
        idx: &FieldElement,
        val: FieldElement,
        hash_db: &mut dyn HashDb<DbVal4ary>,
    ) -> Result<FieldElement, BulletproofError> {
        // Find path to insert the new key. siblings are the the sibling nodes at each level from
        // the root to the leaf for the `idx`
        let mut siblings_wrap = Some(Vec::<ProofNode4ary>::new());
        self.get(&idx, &mut siblings_wrap, hash_db)?;
        let mut siblings = siblings_wrap.unwrap();

        // Convert leaf index to base 4
        let mut path = Self::leaf_index_to_path(&idx, self.depth);
        // Reverse since path was from root to leaf but i am going leaf to root
        path.reverse();
        let mut cur_val = val;

        // Iterate over the base 4 digits
        for d in path {
            let mut sibling_elem = siblings.pop().unwrap().to_vec();
            // Insert the value at the position determined by the base 4 digit
            sibling_elem.insert(d as usize, cur_val);

            let mut db_val: DbVal4ary = [
                FieldElement::zero(),
                FieldElement::zero(),
                FieldElement::zero(),
                FieldElement::zero(),
            ];
            db_val.clone_from_slice(sibling_elem.as_slice());
            let h = self.hash_func.hash(sibling_elem)?;
            Self::update_db_with_key_val(&h, db_val, hash_db);
            cur_val = h;
        }

        self.root = cur_val.clone();

        Ok(cur_val)
    }

    /// Get a value from tree, if `proof` is not None, populate `proof` with the merkle proof
    pub fn get(
        &self,
        idx: &FieldElement,
        proof: &mut Option<Vec<ProofNode4ary>>,
        hash_db: &dyn HashDb<DbVal4ary>,
    ) -> Result<FieldElement, BulletproofError> {
        let path = Self::leaf_index_to_path(idx, self.depth);
        let mut cur_node = &self.root;
        // TODO: more comments
        let need_proof = proof.is_some();
        let mut proof_vec = Vec::<ProofNode4ary>::new();

        let mut children;
        for d in path {
            let k = cur_node.to_bytes();
            children = hash_db.get(&k)?;
            cur_node = &children[d as usize];
            if need_proof {
                let mut proof_node: ProofNode4ary = [
                    FieldElement::zero(),
                    FieldElement::zero(),
                    FieldElement::zero(),
                ];
                let mut j = 0;
                for (i, c) in children.to_vec().iter().enumerate() {
                    if i != (d as usize) {
                        proof_node[j] = c.clone();
                        j += 1;
                    }
                }
                proof_vec.push(proof_node);
            }
        }

        match proof {
            Some(v) => {
                v.extend_from_slice(&proof_vec);
            }
            None => (),
        }

        Ok(cur_node.clone())
    }

    /// Verify a merkle proof, if `root` is None, use the current root else use given root
    pub fn verify_proof(
        &self,
        idx: &FieldElement,
        val: &FieldElement,
        proof: &[ProofNode4ary],
        root: Option<&FieldElement>,
    ) -> Result<bool, BulletproofError> {
        let mut path = Self::leaf_index_to_path(&idx, self.depth);
        path.reverse();
        let mut cur_val = val.clone();

        for (i, d) in path.iter().enumerate() {
            let mut p = proof[self.depth - 1 - i].clone().to_vec();
            p.insert(*d as usize, cur_val);
            cur_val = self.hash_func.hash(p)?;
        }

        // Check if root is equal to cur_val
        match root {
            Some(r) => Ok(cur_val == *r),
            None => Ok(cur_val == self.root),
        }
    }

    /// Get path from root to leaf given a leaf index
    /// Convert leaf index to base 4
    pub fn leaf_index_to_path(idx: &FieldElement, depth: usize) -> Vec<u8> {
        get_repr_in_power_2_base(2, idx, depth).to_vec()
    }

    fn update_db_with_key_val(
        key: &FieldElement,
        val: DbVal4ary,
        hash_db: &mut dyn HashDb<DbVal4ary>,
    ) {
        hash_db.insert(key.to_bytes(), val);
    }
}

/*
    Constraints for 4-ary tree

    Hash all 4 children including the node on the path to leaf.
    But the prover cannot disclose at what index the node is in the children.
    So he expresses each child arithmetically. An example below for a single level of the tree.

    Proof elements = [N1, N2, N3]
    Hidden Node (node in path to leaf) = N

    Proof elements with placeholder (_p0, _p1, _p2, _p3) where hidden node can go
    [_p0, N1, _p1, N2, _p2, N3, _p3]

    p = position of hidden node, p =(b1, b0) where b0 and b1 are bits at index 0 and 1
    c0, c1, c2, c3 are children of one level of one subtree

    [c0, c1, c2, c3]

    Different arrangements of node for values of p => (b1b0)
    p=0 => [N, N1, N2, N3]
    p=1 => [N1, N, N2, N3]
    p=2 => [N1, N2, N, N3]
    p=3 => [N1, N2, N3, N]

    Another way of looking at it

    | node   | p=0(0)   | p=1(1)   | p=2(10)   | p=3(11)   |
    |--------|----------|----------|-----------|-----------|
    | c0     | N        | N1       | N1        | N1        |
    | c1     | N1       | N        | N2        | N2        |
    | c2     | N2       | N2       | N         | N3        |
    | c3     | N3       | N3       | N3        | N         |

    // TODO: Think about it. Don't need bits.
    c_k = c_{k-1} || c_k || c_{k+1}.
    c_k = N_k || N || N_{k+1}

    Arithmetic relations for c0, c1, c2 and c3

    c0 = (1-b0)*(1-b1)*N + (1 - (1-b0)*(1-b1))*N1

    c1 = (1-b0)*(1-b1)*N1 + (1-b1)*b0*N + b1*N2

    c2 = (1-b1)*N2 + (1-b0)*b1*N + b0*b1*N3

    c3 = (1-b1*b0)*N3 + b1*b0*N
*/
pub fn vanilla_merkle_merkle_tree_4_verif_gadget<
    CS: ConstraintSystem,
    MTHC: Arity4MerkleTreeHashConstraints,
>(
    cs: &mut CS,
    depth: usize,
    expected_root: &FieldElement,
    leaf_val: LeafValueType,
    leaf_index: AllocatedQuantity,
    mut proof_nodes: Vec<Variable>,
    hash_func: &mut MTHC,
) -> Result<(), R1CSError> {
    let mut prev_hash = LinearCombination::from(leaf_val);

    // Initialize  constraint_leaf_index with -leaf_index.
    let mut constraint_leaf_index = vec![(leaf_index.variable, FieldElement::minus_one())];
    let mut exp_4 = FieldElement::one();
    let two = FieldElement::from(2u64);
    let four = FieldElement::from(4u64);

    let leaf_index_bytes = allocated_leaf_index_to_bytes(leaf_index);

    let leaf_index_byte_size = get_byte_size(depth, 4);
    // Each leaf index can take upto leaf_index_byte_size bytes so for each byte
    for i in 0..leaf_index_byte_size {
        // Decompose each byte into 4 parts of 2 bits each. For each 2 bits
        for j in 0..4 {
            // The depth might not be a multiple of 4 so there might not be 4 base 4 digits
            if proof_nodes.is_empty() {
                break;
            }

            // Check that both 2 bits are actually bits, .i.e. they both are 0 or 1
            let (b0, b0_1, o) = cs.allocate_multiplier(leaf_index_bytes.map(|l| {
                let bit = (l[i] >> 2 * j) & 1;
                (bit.into(), (1 - bit).into())
            }))?;
            cs.constrain(o.into());
            cs.constrain(b0 + (b0_1 - FieldElement::one()));

            let (b1, b1_1, o) = cs.allocate_multiplier(leaf_index_bytes.map(|l| {
                let bit = (l[i] >> (2 * j + 1)) & 1;
                (bit.into(), (1 - bit).into())
            }))?;
            cs.constrain(o.into());
            cs.constrain(b1 + (b1_1 - FieldElement::one()));

            // The 2 bits should represent the base 4 digit for the node in path to leaf
            // Add (2*b1 + b0)*4^(4*i+j) to constraint_leaf_index.
            // (2*b1 + b0)*4^(4*i+j) = 2*4^(4*i+j)*b1 + 4^(4*i+j)*b0
            constraint_leaf_index.push((b1, &two * &exp_4));
            constraint_leaf_index.push((b0, exp_4.clone()));

            let N3: LinearCombination = proof_nodes.pop().unwrap().into();
            let N2: LinearCombination = proof_nodes.pop().unwrap().into();
            let N1: LinearCombination = proof_nodes.pop().unwrap().into();

            // Notation: b0_1 = 1 - b0 and b1_1 = 1 - b1 and prev_hash = N

            // Pre-compute various products of both bits
            // (1 - b0)*(1 - b1)
            let (_, _, b0_1_b1_1) = cs.multiply(b0_1.into(), b1_1.into());
            // (1 - b0)*b1
            let (_, _, b0_1_b1) = cs.multiply(b0_1.into(), b1.into());
            // b0*(1 - b1)
            let (_, _, b0_b1_1) = cs.multiply(b0.into(), b1_1.into());
            // b0*b1
            let (_, _, b0_b1) = cs.multiply(b0.into(), b1.into());

            // TODO: Look at the changes done in 8-ary tree, some constraints can be eliminated.

            // (1-b0)*(1-b1)*N
            let (_, _, c0_1) = cs.multiply(b0_1_b1_1.into(), prev_hash.clone());
            // (1 - (1-b0)*(1-b1))*N1
            let (_, _, c0_2) = cs.multiply((Variable::One() - b0_1_b1_1).into(), N1.clone());
            // c0 = (1-b0)*(1-b1)*N + (1 - (1-b0)*(1-b1))*N1
            let c0 = c0_1 + c0_2;

            // (1-b0)*(1-b1)*N1
            //let (_, _, c1_1) = cs.multiply(b0_1_b1_1.into(), N1.clone());
            let c1_1 = N1 - c0_2;
            // (1-b1)*b0*N
            let (_, _, c1_2) = cs.multiply(b0_b1_1.into(), prev_hash.clone());
            // b1*N2
            let (_, _, c1_3) = cs.multiply(b1.into(), N2.clone());
            // c1 = (1-b0)*(1-b1)*N1 + (1-b1)*b0*N + b1*N2
            let c1 = c1_1 + c1_2 + c1_3;

            // (1-b1)*N2
            //let (_, _, c2_1) = cs.multiply(b1_1.into(), N2.clone());
            let c2_1 = N2 - c1_3;
            // (1-b0)*b1*N
            let (_, _, c2_2) = cs.multiply(b0_1_b1.into(), prev_hash.clone());
            // b0*b1*N3
            let (_, _, c2_3) = cs.multiply(b0_b1.into(), N3.clone());
            // c2 = (1-b1)*N2 + (1-b0)*b1*N + b0*b1*N3
            let c2 = c2_1 + c2_2 + c2_3;

            // b1*b0*N
            let (_, _, c3_1) = cs.multiply(b0_b1.into(), prev_hash.clone());
            // (1 - b1*b0)*N3
            //let (_, _, c3_2) = cs.multiply((Variable::One() - b0_b1), N3.clone());
            let c3_2 = N3 - c2_3;
            // c3 = b1*b0*N + (1 - b1*b0)*N3
            let c3 = c3_1 + c3_2;

            let input = vec![c0, c1, c2, c3];

            prev_hash = hash_func.hash(cs, input)?;

            prev_hash = prev_hash.simplify();

            exp_4 = &exp_4 * &four;
        }
    }

    cs.constrain(constraint_leaf_index.iter().collect());

    constrain_lc_with_scalar::<CS>(cs, prev_hash, expected_root);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::r1cs::gadgets::helper_constraints::poseidon::{PoseidonParams, SboxType};
    use crate::r1cs::gadgets::merkle_tree_hash::PoseidonHash4;
    use crate::utils::hash_db::InMemoryHashDb;

    #[test]
    fn test_vanilla_sparse_merkle_tree_4() {
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

        let hash_params = PoseidonParams::new(width, full_b, full_e, partial_rounds).unwrap();

        let tree_depth = 17;
        let hash_func = PoseidonHash4 {
            params: &hash_params,
            sbox: &SboxType::Quint,
        };
        let mut tree = VanillaSparseMerkleTree4::new(&hash_func, tree_depth, &mut db).unwrap();

        for i in 1..10 {
            let s = FieldElement::from(i as u64);
            tree.update(&s, s.clone(), &mut db).unwrap();
        }

        for i in 1..10 {
            let s = FieldElement::from(i as u32);
            assert_eq!(s, tree.get(&s, &mut None, &db).unwrap());
            let mut proof_vec = Vec::<ProofNode4ary>::new();
            let mut proof = Some(proof_vec);
            assert_eq!(s, tree.get(&s, &mut proof, &db).unwrap());
            proof_vec = proof.unwrap();
            assert!(tree.verify_proof(&s, &s, &proof_vec, None).unwrap());
            assert!(tree
                .verify_proof(&s, &s, &proof_vec, Some(&tree.root))
                .unwrap());
        }

        let kvs: Vec<(FieldElement, FieldElement)> = (0..10)
            .map(|_| (FieldElement::random(), FieldElement::random()))
            .collect();

        for i in 0..kvs.len() {
            tree.update(&kvs[i].0, kvs[i].1.clone(), &mut db).unwrap();
        }
        for i in 0..kvs.len() {
            assert_eq!(kvs[i].1, tree.get(&kvs[i].0, &mut None, &db).unwrap());
        }
    }
}
