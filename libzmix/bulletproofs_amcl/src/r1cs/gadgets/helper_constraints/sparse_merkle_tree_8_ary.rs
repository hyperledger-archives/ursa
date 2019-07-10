use std::collections::HashMap;

use amcl_wrapper::constants::{MODBYTES, NLEN};

use crate::errors::R1CSError;
use crate::r1cs::linear_combination::AllocatedQuantity;
use crate::r1cs::{ConstraintSystem, LinearCombination, Prover, R1CSProof, Variable, Verifier};
use amcl_wrapper::field_elem::FieldElement;
use amcl_wrapper::group_elem::GroupElement;
use amcl_wrapper::group_elem_g1::G1;

use super::poseidon::{
    PoseidonParams, Poseidon_hash_8, Poseidon_hash_8_constraints, SboxType, PADDING_CONST,
};
use super::{constrain_lc_with_scalar, get_byte_size};
use crate::r1cs::gadgets::helper_constraints::poseidon::ZERO_CONST;

const ARITY: usize = 8;

pub type DBVal = [FieldElement; ARITY];
pub type ProofNode = [FieldElement; ARITY - 1];

/// Get a base 8 representation of the given `scalar`. Only return `num_digits` of the representation
pub fn get_base_8_repr(scalar: &FieldElement, num_digits: usize) -> Vec<u8> {
    let byte_size = get_byte_size(num_digits, 8);
    if byte_size > MODBYTES {
        panic!(
            "limit_bytes cannot be more than {} but found {}",
            MODBYTES, byte_size
        )
    }
    let mut s = scalar.to_bignum();
    s.norm();

    let mut base_8 = vec![];
    while (base_8.len() != num_digits) && (!s.iszilch()) {
        base_8.push(s.lastbits(3) as u8);
        s.fshr(3);
    }
    while base_8.len() != num_digits {
        base_8.push(0);
    }

    base_8.reverse();
    base_8
}

// TODO: ABSTRACT HASH FUNCTION BETTER
/// Sparse merkle tree with arity 8, .i.e each node has 4 children.
#[derive(Clone, Debug)]
pub struct VanillaSparseMerkleTree_8<'a> {
    pub depth: usize,
    empty_tree_hashes: Vec<FieldElement>,
    pub db: HashMap<Vec<u8>, DBVal>,
    hash_params: &'a PoseidonParams,
    pub root: FieldElement,
}

impl<'a> VanillaSparseMerkleTree_8<'a> {
    pub fn new(hash_params: &'a PoseidonParams, depth: usize) -> VanillaSparseMerkleTree_8<'a> {
        let mut db = HashMap::new();
        let mut empty_tree_hashes: Vec<FieldElement> = vec![];
        empty_tree_hashes.push(FieldElement::zero());
        for i in 1..=depth {
            let prev = empty_tree_hashes[i - 1];
            let input: [FieldElement; ARITY] = [prev.clone(); ARITY];
            // Hash all 8 children at once
            let new = Poseidon_hash_8(input.clone(), hash_params, &SboxType::Quint);
            let key = new.to_bytes();

            db.insert(key, input);
            empty_tree_hashes.push(new);
        }

        let root = empty_tree_hashes[depth].clone();

        VanillaSparseMerkleTree_8 {
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

        let mut path = Self::leaf_index_to_path(&idx, self.depth);
        path.reverse();
        let mut cur_val = val.clone();

        // Iterate over the base 8 digits
        for d in path {
            let mut side_elem = sidenodes.pop().unwrap().to_vec();
            // Insert the value at the position determined by the base 4 digit
            side_elem.insert(d as usize, cur_val);

            let mut input: DBVal = [FieldElement::zero(); ARITY];
            input.copy_from_slice(side_elem.as_slice());
            let h = Poseidon_hash_8(input.clone(), self.hash_params, &SboxType::Quint);
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
                let mut proof_node: ProofNode = [FieldElement::zero(); ARITY - 1];
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
            let mut input: DBVal = [FieldElement::zero(); ARITY];
            input.copy_from_slice(p.as_slice());
            cur_val = Poseidon_hash_8(input.clone(), self.hash_params, &SboxType::Quint);
        }

        // Check if root is equal to cur_val
        match root {
            Some(r) => cur_val == *r,
            None => cur_val == self.root,
        }
    }

    /// Convert leaf index to base 8
    pub fn leaf_index_to_path(idx: &FieldElement, depth: usize) -> Vec<u8> {
        get_base_8_repr(idx, depth).to_vec()
    }

    fn update_db_with_key_val(&mut self, key: &FieldElement, val: DBVal) {
        self.db.insert(key.to_bytes(), val);
    }
}

/// Constraints for 8-ary tree
///
///                Hash all 8 children including the node on the path to leaf.
///                But the prover cannot disclose at what index the node is in the children.
///                So he expresses each child arithmetically. An example below for a single level of the tree.
///
///                Proof elements = [N1, N2, N3, N4, N5, N6, N7]
///                Hidden Node (node in path to leaf) = N
///
///                Proof elements with placeholder (_p0, _p1, _p2, _p3, _p4, _p5, _p6) where hidden node can go
///                [_p0, N1, _p1, N2, _p2, N3, _p3, N4, _p4, N5, _p5, N6, _p6, N7]
///
///                p = position of hidden node, p =(b2, b1, b0) where b0, b1 and b2 are bits at index 0, 1 and 2
///                c0, c1, c2, c3, c4, c5, c6, c7 are children of one level of one subtree
///
///                [c0, c1, c2, c3, c4, c5, c6, c7]
///
///                Different arrangements of node for values of p => (b2b1b0)
///                p=0 => [N, N1, N2, N3, N4, N5, N6, N7]
///                p=1 => [N1, N, N2, N3, N4, N5, N6, N7]
///                p=2 => [N1, N2, N, N3, N4, N5, N6, N7]
///                p=3 => [N1, N2, N3, N, N4, N5, N6, N7]
///                p=4 => [N1, N2, N3, N4, N, N5, N6, N7]
///                p=5 => [N1, N2, N3, N4, N5, N, N6, N7]
///                p=6 => [N1, N2, N3, N4, N5, N6, N, N7]
///                p=7 => [N1, N2, N3, N4, N5, N6, N7, N]
///
///                Arithmetic relations for c0, c1, c2, c3, c4, c5, c6, c7
///
///                TODO: add constraints
///
pub fn vanilla_merkle_merkle_tree_8_verif_gadget<CS: ConstraintSystem>(
    cs: &mut CS,
    depth: usize,
    expected_root: &FieldElement,
    leaf_val: AllocatedQuantity,
    leaf_index: AllocatedQuantity,
    mut proof_nodes: Vec<AllocatedQuantity>,
    zero: AllocatedQuantity,
    poseidon_params: &PoseidonParams,
    sbox_type: &SboxType,
) -> Result<(), R1CSError> {
    let mut prev_hash = LinearCombination::from(leaf_val.variable);

    let zero: LinearCombination = zero.variable.into();

    // Initialize  constraint_leaf_index with -leaf_index.
    let mut constraint_leaf_index = vec![(leaf_index.variable, FieldElement::minus_one())];
    let mut exp_8 = FieldElement::one();
    let two = FieldElement::from(2u64);
    let four = FieldElement::from(4u64);
    let eight = FieldElement::from(8u64);

    let leaf_index_bytes = leaf_index.assignment.map(|l| {
        let mut b: [u8; MODBYTES] = [0u8; MODBYTES];
        let mut m = l.to_bignum();
        m.tobytes(&mut b);
        b.reverse();
        b
    });

    let leaf_index_byte_size = get_byte_size(depth, 8);
    // Each leaf index can take upto leaf_index_byte_size bytes so for each byte
    for i in 0..leaf_index_byte_size {
        // Decompose each byte into 3 parts, 2 parts of 3 bits and 1 part of 2 bits. For each parts
        for j in 0..3 {
            // The depth might not be a multiple of 8 so there might not be 3 base 8 digits
            if proof_nodes.is_empty() {
                break;
            }

            // Check each bit is actually a bit, .i.e. 0 or 1
            let (b0, b0_1, o) = cs.allocate_multiplier(leaf_index_bytes.map(|l| {
                let bit = (l[i] >> 3 * j) & 1;
                (bit.into(), (1 - bit).into())
            }))?;
            cs.constrain(o.into());
            cs.constrain(b0 + (b0_1 - FieldElement::one()));

            let (b1, b1_1, o) = cs.allocate_multiplier(leaf_index_bytes.map(|l| {
                let bit = (l[i] >> (3 * j + 1)) & 1;
                (bit.into(), (1 - bit).into())
            }))?;
            cs.constrain(o.into());
            cs.constrain(b1 + (b1_1 - FieldElement::one()));

            // The 3 bits should represent the base 8 digit for the node in path to leaf
            // Add (4*b2 + 2*b1 + b0)*8^(3*i+j) to constraint_leaf_index.
            // (4*b2 + 2*b1 + b0)*8^(3*i+j) = 4*8^(3*i+j)*b2 + 2*8^(3*i+j)*b1 + 8^(3*i+j)*b0
            constraint_leaf_index.push((b1, two * exp_8));
            constraint_leaf_index.push((b0, exp_8));

            if j != 2 {
                let (b2, b2_1, o) = cs.allocate_multiplier(leaf_index_bytes.map(|l| {
                    let bit = (l[i] >> (3 * j + 2)) & 1;
                    (bit.into(), (1 - bit).into())
                }))?;
                cs.constrain(o.into());
                cs.constrain(b2 + (b2_1 - FieldElement::one()));

                constraint_leaf_index.push((b2, four * exp_8));
            }

            // TODO: Add constraints for hashing proof nodes

            exp_8 = exp_8 * eight;
        }
    }

    cs.constrain(constraint_leaf_index.iter().collect());

    // TODO: Check for root equality

    unimplemented!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::get_generators;

    #[test]
    fn test_vanilla_sparse_merkle_tree_8() {
        let width = 9;
        let (full_b, full_e) = (4, 4);
        let partial_rounds = 57;
        let hash_params = PoseidonParams::new(width, full_b, full_e, partial_rounds);

        let tree_depth = 10;
        let mut tree = VanillaSparseMerkleTree_8::new(&hash_params, tree_depth);

        for i in 1..20 {
            let s = FieldElement::from(i as u64);
            tree.update(s, s);
        }

        for i in 1..20 {
            let s = FieldElement::from(i as u32);
            assert_eq!(s, tree.get(s, &mut None));
            let mut proof_vec = Vec::<ProofNode>::new();
            let mut proof = Some(proof_vec);
            assert_eq!(s, tree.get(s, &mut proof));
            proof_vec = proof.unwrap();
            assert!(tree.verify_proof(s, s, &proof_vec, None));
            assert!(tree.verify_proof(s, s, &proof_vec, Some(&tree.root)));
        }

        let kvs: Vec<(FieldElement, FieldElement)> = (0..20)
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
