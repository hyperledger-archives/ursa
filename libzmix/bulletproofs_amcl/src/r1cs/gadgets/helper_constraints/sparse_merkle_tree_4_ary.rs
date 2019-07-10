use std::collections::HashMap;

use amcl_wrapper::constants::{MODBYTES, NLEN};

use crate::errors::R1CSError;
use crate::r1cs::linear_combination::AllocatedQuantity;
use crate::r1cs::{ConstraintSystem, LinearCombination, Prover, R1CSProof, Variable, Verifier};
use amcl_wrapper::field_elem::FieldElement;
use amcl_wrapper::group_elem::GroupElement;
use amcl_wrapper::group_elem_g1::G1;

use super::poseidon::{
    PoseidonParams, Poseidon_hash_4, Poseidon_hash_4_constraints, SboxType, PADDING_CONST,
};
use super::{constrain_lc_with_scalar, get_byte_size};

pub type DBVal = [FieldElement; 4];
pub type ProofNode = [FieldElement; 3];

/// Get a base 4 representation of the given `scalar`. Only return `num_digits` of the representation
pub fn get_base_4_repr(scalar: &FieldElement, num_digits: usize) -> Vec<u8> {
    let byte_size = get_byte_size(num_digits, 4);
    if byte_size > MODBYTES {
        panic!(
            "limit_bytes cannot be more than {} but found {}",
            MODBYTES, byte_size
        )
    }
    let mut s = scalar.to_bignum();
    s.norm();

    let mut base_4 = vec![];
    while (base_4.len() != num_digits) && (!s.iszilch()) {
        base_4.push(s.lastbits(2) as u8);
        s.fshr(2);
    }
    while base_4.len() != num_digits {
        base_4.push(0);
    }

    base_4.reverse();
    base_4
}

// TODO: ABSTRACT HASH FUNCTION BETTER
/// Sparse merkle tree with arity 4, .i.e each node has 4 children.
#[derive(Clone, Debug)]
pub struct VanillaSparseMerkleTree_4<'a> {
    pub depth: usize,
    empty_tree_hashes: Vec<FieldElement>,
    pub db: HashMap<Vec<u8>, DBVal>,
    hash_params: &'a PoseidonParams,
    pub root: FieldElement,
}

impl<'a> VanillaSparseMerkleTree_4<'a> {
    pub fn new(hash_params: &'a PoseidonParams, depth: usize) -> VanillaSparseMerkleTree_4<'a> {
        let mut db = HashMap::new();
        let mut empty_tree_hashes: Vec<FieldElement> = vec![];
        empty_tree_hashes.push(FieldElement::zero());
        for i in 1..=depth {
            let prev = empty_tree_hashes[i - 1];
            let input: [FieldElement; 4] = [prev.clone(); 4];
            // Hash all 4 children at once
            let new = Poseidon_hash_4(input.clone(), hash_params, &SboxType::Quint);
            let key = new.to_bytes();

            db.insert(key, input);
            empty_tree_hashes.push(new);
        }

        let root = empty_tree_hashes[depth].clone();

        VanillaSparseMerkleTree_4 {
            depth,
            empty_tree_hashes,
            db,
            hash_params,
            root,
        }
    }

    pub fn update(&mut self, idx: FieldElement, val: FieldElement) -> FieldElement {
        // Find path to insert the new key
        let mut sidenodes_wrap = Some(Vec::<ProofNode>::new());
        self.get(idx, &mut sidenodes_wrap);
        let mut sidenodes = sidenodes_wrap.unwrap();

        // Convert leaf index to base 4
        let mut path = Self::leaf_index_to_path(&idx, self.depth);
        path.reverse();
        let mut cur_val = val.clone();

        // Iterate over the base 4 digits
        for d in path {
            let mut side_elem = sidenodes.pop().unwrap().to_vec();
            // Insert the value at the position determined by the base 4 digit
            side_elem.insert(d as usize, cur_val);

            let mut input: DBVal = [FieldElement::zero(); 4];
            input.copy_from_slice(side_elem.as_slice());
            let h = Poseidon_hash_4(input.clone(), self.hash_params, &SboxType::Quint);
            self.update_db_with_key_val(&h, input);
            cur_val = h;
        }

        self.root = cur_val;

        cur_val
    }

    /// Get a value from tree, if `proof` is not None, populate `proof` with the merkle proof
    pub fn get(&self, idx: FieldElement, proof: &mut Option<Vec<ProofNode>>) -> FieldElement {
        let path = Self::leaf_index_to_path(&idx, self.depth);
        let mut cur_node = self.root.clone();

        let need_proof = proof.is_some();
        let mut proof_vec = Vec::<ProofNode>::new();

        for d in path {
            let k = cur_node.to_bytes();
            let children = self.db.get(&k).unwrap();
            cur_node = children[d as usize];
            if need_proof {
                let mut proof_node: ProofNode = [FieldElement::zero(); 3];
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

        cur_node
    }

    /// Verify a merkle proof, if `root` is None, use the current root else use given root
    pub fn verify_proof(
        &self,
        idx: FieldElement,
        val: FieldElement,
        proof: &[ProofNode],
        root: Option<&FieldElement>,
    ) -> bool {
        let mut path = Self::leaf_index_to_path(&idx, self.depth);
        path.reverse();
        let mut cur_val = val.clone();

        for (i, d) in path.iter().enumerate() {
            let mut p = proof[self.depth - 1 - i].clone().to_vec();
            p.insert(*d as usize, cur_val);
            let mut input: DBVal = [FieldElement::zero(); 4];
            input.copy_from_slice(p.as_slice());
            cur_val = Poseidon_hash_4(input.clone(), self.hash_params, &SboxType::Quint);
        }

        // Check if root is equal to cur_val
        match root {
            Some(r) => cur_val == *r,
            None => cur_val == self.root,
        }
    }

    pub fn leaf_index_to_path(idx: &FieldElement, depth: usize) -> Vec<u8> {
        get_base_4_repr(idx, depth).to_vec()
    }

    fn update_db_with_key_val(&mut self, key: &FieldElement, val: DBVal) {
        self.db.insert(key.to_bytes(), val);
    }
}

/// Constraints for 4-ary tree
///
///                Hash all 4 children including the node on the path to leaf.
///                But the prover cannot disclose at what index the node is in the children.
///                So he expresses each child arithmetically. An example below for a single level of the tree.
///
///                Proof elements = [N1, N2, N3]
///                Hidden Node (node in path to leaf) = N
///
///                Proof elements with placeholder (_p0, _p1, _p2, _p3) where hidden node can go
///                [_p0, N1, _p1, N2, _p2, N3, _p3]
///
///                p = position of hidden node, p =(b1, b0) where b0 and b1 are bits at index 0 and 1
///                c0, c1, c2, c3 are children of one level of one subtree
///
///                [c0, c1, c2, c3]
///
///                Different arrangements of node for values of p => (b1b0)
///                p=0 => [N, N1, N2, N3]
///                p=1 => [N1, N, N2, N3]
///                p=2 => [N1, N2, N, N3]
///                p=3 => [N1, N2, N3, N]
///
///                Arithmetic relations for c0, c1, c2 and c3
///
///                c0 = (1-b0)*(1-b1)*N + b0*N1 + (1-b0)*b1*N1
///
///                c1 = (1-b0)*(1-b1)*N1 + (1-b1)*b0*N + (1-b0)*b1*N2 + b0*b1*N2
///
///                c2 = (1-b1)*N2 + (1-b0)*b1*N + b0*b1*N3
///
///                c3 = (1-b1)*N3 + (1-b0)*b1*N3 + b1*b0*N
///
pub fn vanilla_merkle_merkle_tree_4_verif_gadget<CS: ConstraintSystem>(
    cs: &mut CS,
    depth: usize,
    expected_root: &FieldElement,
    leaf_val: AllocatedQuantity,
    leaf_index: AllocatedQuantity,
    mut proof_nodes: Vec<AllocatedQuantity>,
    statics: Vec<AllocatedQuantity>,
    poseidon_params: &PoseidonParams,
    sbox_type: &SboxType,
) -> Result<(), R1CSError> {
    let mut prev_hash = LinearCombination::from(leaf_val.variable);

    let statics: Vec<LinearCombination> = statics.iter().map(|s| s.variable.into()).collect();

    // Initialize  constraint_leaf_index with -leaf_index.
    let mut constraint_leaf_index = vec![(leaf_index.variable, FieldElement::minus_one())];
    let mut exp_4 = FieldElement::one();
    let two = FieldElement::from(2u64);
    let four = FieldElement::from(4u64);

    let leaf_index_bytes = leaf_index.assignment.map(|l| {
        let mut b: [u8; MODBYTES] = [0u8; MODBYTES];
        let mut m = l.to_bignum();
        m.tobytes(&mut b);
        b.reverse();
        b
    });

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
            constraint_leaf_index.push((b1, two * exp_4));
            constraint_leaf_index.push((b0, exp_4));

            let N3: LinearCombination = proof_nodes.pop().unwrap().variable.into();
            let N2: LinearCombination = proof_nodes.pop().unwrap().variable.into();
            let N1: LinearCombination = proof_nodes.pop().unwrap().variable.into();

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

            // (1-b0)*(1-b1)*N
            let (_, _, c0_1) = cs.multiply(b0_1_b1_1.into(), prev_hash.clone());
            // b0*N1
            let (_, _, c0_2) = cs.multiply(b0.into(), N1.clone());
            // (1-b0)*b1*N1
            let (_, _, c0_3) = cs.multiply(b0_1_b1.into(), N1.clone());
            // c0 = (1-b0)*(1-b1)*N + b0*N1 + (1-b0)*b1*N1
            let c0 = c0_1 + c0_2 + c0_3;

            // (1-b0)*(1-b1)*N1
            let (_, _, c1_1) = cs.multiply(b0_1_b1_1.into(), N1.clone());
            // (1-b1)*b0*N
            let (_, _, c1_2) = cs.multiply(b0_b1_1.into(), prev_hash.clone());
            // (1-b0)*b1*N2
            let (_, _, c1_3) = cs.multiply(b0_1_b1.into(), N2.clone());
            // b0*b1*N2
            let (_, _, c1_4) = cs.multiply(b0_b1.into(), N2.clone());
            // c1 = (1-b0)*(1-b1)*N1 + (1-b1)*b0*N + (1-b0)*b1*N2 + b0*b1*N2
            let c1 = c1_1 + c1_2 + c1_3 + c1_4;

            // (1-b1)*N2
            let (_, _, c2_1) = cs.multiply(b1_1.into(), N2.clone());
            // (1-b0)*b1*N
            let (_, _, c2_2) = cs.multiply(b0_1_b1.into(), prev_hash.clone());
            // b0*b1*N3
            let (_, _, c2_3) = cs.multiply(b0_b1.into(), N3.clone());
            // c2 = (1-b1)*N2 + (1-b0)*b1*N + b0*b1*N3
            let c2 = c2_1 + c2_2 + c2_3;

            // (1-b1)*N3
            let (_, _, c3_1) = cs.multiply(b1_1.into(), N3.clone());
            // (1-b0)*b1*N3
            let (_, _, c3_2) = cs.multiply(b0_1_b1.into(), N3.clone());
            // b1*b0*N
            let (_, _, c3_3) = cs.multiply(b0_b1.into(), prev_hash.clone());
            // c3 = (1-b1)*N3 + (1-b0)*b1*N3 + b1*b0*N
            let c3 = c3_1 + c3_2 + c3_3;

            let input: [LinearCombination; 4] = [c0, c1, c2, c3];
            prev_hash = Poseidon_hash_4_constraints::<CS>(
                cs,
                input,
                statics.clone(),
                poseidon_params,
                sbox_type,
            )?;

            exp_4 = exp_4 * four;
        }
    }

    cs.constrain(constraint_leaf_index.iter().collect());

    constrain_lc_with_scalar::<CS>(cs, prev_hash, expected_root);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vanilla_sparse_merkle_tree_4() {
        let width = 6;
        let (full_b, full_e) = (4, 4);
        let partial_rounds = 57;
        let hash_params = PoseidonParams::new(width, full_b, full_e, partial_rounds);

        let tree_depth = 17;
        let mut tree = VanillaSparseMerkleTree_4::new(&hash_params, tree_depth);

        for i in 1..10 {
            let s = FieldElement::from(i as u64);
            tree.update(s, s);
        }

        for i in 1..10 {
            let s = FieldElement::from(i as u32);
            assert_eq!(s, tree.get(s, &mut None));
            let mut proof_vec = Vec::<ProofNode>::new();
            let mut proof = Some(proof_vec);
            assert_eq!(s, tree.get(s, &mut proof));
            proof_vec = proof.unwrap();
            assert!(tree.verify_proof(s, s, &proof_vec, None));
            assert!(tree.verify_proof(s, s, &proof_vec, Some(&tree.root)));
        }

        let kvs: Vec<(FieldElement, FieldElement)> = (0..10)
            .map(|_| (FieldElement::random(), FieldElement::random()))
            .collect();
        for i in 0..kvs.len() {
            tree.update(kvs[i].0, kvs[i].1);
        }

        for i in 0..kvs.len() {
            assert_eq!(kvs[i].1, tree.get(kvs[i].0, &mut None));
        }
    }
}
