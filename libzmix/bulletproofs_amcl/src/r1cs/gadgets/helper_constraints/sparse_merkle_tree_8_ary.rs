use crate::errors::{BulletproofError, R1CSError};
use crate::r1cs::linear_combination::AllocatedQuantity;
use crate::r1cs::{ConstraintSystem, LinearCombination, Variable};
use amcl_wrapper::field_elem::FieldElement;

use super::{constrain_lc_with_scalar, get_bit_count};
use crate::r1cs::gadgets::helper_constraints::{get_repr_in_power_2_base, LeafValueType};
use crate::r1cs::gadgets::merkle_tree_hash::{
    Arity8MerkleTreeHash, Arity8MerkleTreeHashConstraints,
};
use crate::utils::hash_db::HashDb;

const ARITY: usize = 8;

pub type DbVal8ary = [FieldElement; ARITY];
pub type ProofNode8ary = [FieldElement; ARITY - 1];

// The logic of `VanillaSparseMerkleTree4` and `VanillaSparseMerkleTree8` is same. Only the arity
// and hence the hash function differs. The code is still kept separate for clarity. If code is to be
// combined then a generic implementation will take the hash and database as type parameters.

/// Sparse merkle tree with arity 8, .i.e each node has 8 children.
#[derive(Clone, Debug)]
pub struct VanillaSparseMerkleTree8<'a, MTH: Arity8MerkleTreeHash> {
    pub depth: usize,
    hash_func: &'a MTH,
    pub root: FieldElement,
}

impl<'a, MTH> VanillaSparseMerkleTree8<'a, MTH>
where
    MTH: Arity8MerkleTreeHash,
{
    /// Create a new tree
    pub fn new(
        hash_func: &'a MTH,
        depth: usize,
        hash_db: &mut dyn HashDb<DbVal8ary>,
    ) -> Result<VanillaSparseMerkleTree8<'a, MTH>, BulletproofError> {
        let mut empty_tree_hashes: Vec<FieldElement> = vec![];
        empty_tree_hashes.push(FieldElement::zero());
        for i in 1..=depth {
            let prev = &empty_tree_hashes[i - 1];
            let inp: Vec<FieldElement> = (0..ARITY).map(|_| prev.clone()).collect();
            let mut input: DbVal8ary = [
                FieldElement::zero(),
                FieldElement::zero(),
                FieldElement::zero(),
                FieldElement::zero(),
                FieldElement::zero(),
                FieldElement::zero(),
                FieldElement::zero(),
                FieldElement::zero(),
            ];
            input.clone_from_slice(inp.as_slice());
            // Hash all 8 children at once
            let new = hash_func.hash(inp)?;
            let key = new.to_bytes();

            hash_db.insert(key, input);
            empty_tree_hashes.push(new);
        }

        let root = empty_tree_hashes[depth].clone();

        Ok(VanillaSparseMerkleTree8 {
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
        hash_db: &mut dyn HashDb<DbVal8ary>,
    ) -> Result<FieldElement, BulletproofError> {
        // Find path to insert the new key
        let mut siblings_wrap = Some(Vec::<ProofNode8ary>::new());
        self.get(idx, &mut siblings_wrap, hash_db)?;
        let mut siblings = siblings_wrap.unwrap();

        let mut path = Self::leaf_index_to_path(&idx, self.depth);
        // Reverse since path was from root to leaf but i am going leaf to root
        path.reverse();
        let mut cur_val = val.clone();

        // Iterate over the base 8 digits
        for d in path {
            let mut sibling = siblings.pop().unwrap().to_vec();
            // Insert the value at the position determined by the base 4 digit
            sibling.insert(d as usize, cur_val);
            let mut input: DbVal8ary = [
                FieldElement::zero(),
                FieldElement::zero(),
                FieldElement::zero(),
                FieldElement::zero(),
                FieldElement::zero(),
                FieldElement::zero(),
                FieldElement::zero(),
                FieldElement::zero(),
            ];
            input.clone_from_slice(sibling.as_slice());
            let h = self.hash_func.hash(sibling)?;
            Self::update_db_with_key_val(&h, input, hash_db);
            cur_val = h;
        }

        self.root = cur_val.clone();

        Ok(cur_val)
    }

    /// Get a value from tree, if `proof` is not None, populate `proof` with the merkle proof
    pub fn get(
        &self,
        idx: &FieldElement,
        proof: &mut Option<Vec<ProofNode8ary>>,
        hash_db: &dyn HashDb<DbVal8ary>,
    ) -> Result<FieldElement, BulletproofError> {
        let path = Self::leaf_index_to_path(idx, self.depth);
        let mut cur_node = &self.root;

        let need_proof = proof.is_some();
        let mut proof_vec = Vec::<ProofNode8ary>::new();

        let mut children;
        for d in path {
            let k = cur_node.to_bytes();
            children = hash_db.get(&k)?;
            cur_node = &children[d as usize];
            if need_proof {
                let mut pn: Vec<FieldElement> =
                    (0..ARITY - 1).map(|_| FieldElement::zero()).collect();
                let mut j = 0;
                for (i, c) in children.to_vec().iter().enumerate() {
                    if i != (d as usize) {
                        pn[j] = c.clone();
                        j += 1;
                    }
                }
                let mut proof_nodes: ProofNode8ary = [
                    FieldElement::zero(),
                    FieldElement::zero(),
                    FieldElement::zero(),
                    FieldElement::zero(),
                    FieldElement::zero(),
                    FieldElement::zero(),
                    FieldElement::zero(),
                ];
                proof_nodes.clone_from_slice(pn.as_slice());
                proof_vec.push(proof_nodes);
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
        proof: &[ProofNode8ary],
        root: Option<&FieldElement>,
    ) -> Result<bool, BulletproofError> {
        let mut path = Self::leaf_index_to_path(idx, self.depth);
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
    /// Convert leaf index to base 8
    pub fn leaf_index_to_path(idx: &FieldElement, depth: usize) -> Vec<u8> {
        get_repr_in_power_2_base(3, idx, depth).to_vec()
    }

    fn update_db_with_key_val(
        key: &FieldElement,
        val: DbVal8ary,
        hash_db: &mut dyn HashDb<DbVal8ary>,
    ) {
        hash_db.insert(key.to_bytes(), val);
    }
}

/*
    Constraints for 8-ary tree

    Hash all 8 children including the node on the path to leaf.
    But the prover cannot disclose at what index the node is in the children.
    So he expresses each child arithmetically. An example below for a single level of the tree.

    Proof elements = [N1, N2, N3, N4, N5, N6, N7]
    Hidden Node (node in path to leaf) = N

    Proof elements with placeholder (_p0, _p1, _p2, _p3, _p4, _p5, _p6) where hidden node can go
    [_p0, N1, _p1, N2, _p2, N3, _p3, N4, _p4, N5, _p5, N6, _p6, N7]

    p = position of hidden node, p =(b2, b1, b0) where b0, b1 and b2 are bits at index 0, 1 and 2
    c0, c1, c2, c3, c4, c5, c6, c7 are children of one level of one subtree

    [c0, c1, c2, c3, c4, c5, c6, c7]

    Different arrangements of node for values of p => (b2b1b0)
    p=0 => [N, N1, N2, N3, N4, N5, N6, N7]
    p=1 => [N1, N, N2, N3, N4, N5, N6, N7]
    p=2 => [N1, N2, N, N3, N4, N5, N6, N7]
    p=3 => [N1, N2, N3, N, N4, N5, N6, N7]
    p=4 => [N1, N2, N3, N4, N, N5, N6, N7]
    p=5 => [N1, N2, N3, N4, N5, N, N6, N7]
    p=6 => [N1, N2, N3, N4, N5, N6, N, N7]
    p=7 => [N1, N2, N3, N4, N5, N6, N7, N]

    Another way of looking at it
    | node   | p=0(0)   | p=1(1)   | p=2(10)   | p=3(11)   | p=4(100)   | p=5(101)   | p=6(110)   | p=7(111)   |
    |--------|----------|----------|-----------|-----------|------------|------------|------------|------------|
    | c0     | N        | N1       | N1        | N1        | N1         | N1         | N1         | N1         |
    | c1     | N1       | N        | N2        | N2        | N2         | N2         | N2         | N2         |
    | c2     | N2       | N2       | N         | N3        | N3         | N3         | N3         | N3         |
    | c3     | N3       | N3       | N3        | N         | N4         | N4         | N4         | N4         |
    | c4     | N4       | N4       | N4        | N4        | N          | N5         | N5         | N5         |
    | c5     | N5       | N5       | N5        | N5        | N5         | N          | N6         | N6         |
    | c6     | N6       | N6       | N6        | N6        | N6         | N6         | N          | N7         |
    | c7     | N7       | N7       | N7        | N7        | N7         | N7         | N7         | N          |

    Arithmetic relations for c0, c1, c2, c3, c4, c5, c6, c7

    c0 = (1-b0)*(1-b1)*(1-b2)*N + (1-(1-b0)*(1-b1)*(1-b2))*N1
    c1 = (1 - (1-b1)*(1-b2))*N2 + (1-b1)*(1-b2)*b0*N + (1-b1)*(1-b2)*(1-b0)*N1
    c2 = (1-b1)*(1-b2)*N2 + (1-b0)*(1-b2)*b1*N + (1-(1-b0*b1)*(1-b2))*N3
    c3 = (1-b2)*(1-b0*b1)*N3 + (1-b2)*b0*b1*N + b2*N4
    c4 = (1-b2)*N4 + b2*(1-b0)*(1-b1)*N + b2*(1-(1-b1)*(1-b0))*N5
    c5 = (1 - b2 * (1 - (1 - b0) * (1 - b1))) * N5 + b2 * b1 * N6 + b2 * (1 - b1) * b0 * N
    c6 = b0*b1*b2*N7 + b2*(1-b0)*b1*N + (1-b1*b2)*N6
    c7 = b0*b1*b2*N + (1-b0*b1*b2)*N7

    // TODO: Consider the trick from 4-ary tree here as well.
*/
pub fn vanilla_merkle_merkle_tree_8_verif_gadget<
    CS: ConstraintSystem,
    MTHC: Arity8MerkleTreeHashConstraints,
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
    let mut exp_8 = FieldElement::one();
    let two = FieldElement::from(2u64);
    let four = FieldElement::from(4u64);
    let eight = FieldElement::from(8u64);

    let leaf_index_octets = leaf_index.assignment.map(|l| {
        let mut b = get_repr_in_power_2_base(3, &l, depth);
        b.reverse();
        b
    });

    let leaf_index_bit_count = get_bit_count(depth, 8);
    for i in (0..leaf_index_bit_count).step_by(3) {
        if proof_nodes.is_empty() {
            break;
        }

        // Check each bit is actually a bit, .i.e. 0 or 1
        let (bit0, bit1, bit2) = match &leaf_index_octets {
            Some(l) => {
                let octet = l[i / 3];
                let b0 = (octet >> 0) & 1;
                let b0_1 = 1 - b0;
                let b1 = (octet >> 1) & 1;
                let b1_1 = 1 - b1;
                let b2 = (octet >> 2) & 1;
                let b2_1 = 1 - b2;
                (
                    Some((FieldElement::from(b0), FieldElement::from(b0_1))),
                    Some((FieldElement::from(b1), FieldElement::from(b1_1))),
                    Some((FieldElement::from(b2), FieldElement::from(b2_1))),
                )
            }
            None => (None, None, None),
        };

        let (b0, b0_1, o) = cs.allocate_multiplier(bit0)?;
        cs.constrain(o.into());
        cs.constrain(b0 + (b0_1 - FieldElement::one()));

        let (b1, b1_1, o) = cs.allocate_multiplier(bit1)?;
        cs.constrain(o.into());
        cs.constrain(b1 + (b1_1 - FieldElement::one()));

        let (b2, b2_1, o) = cs.allocate_multiplier(bit2)?;
        cs.constrain(o.into());
        cs.constrain(b2 + (b2_1 - FieldElement::one()));

        // The 3 bits should represent the base 8 digit for the node in path to leaf
        // Add (4*b2 + 2*b1 + b0)*8^(i/3) to constraint_leaf_index.
        // (4*b2 + 2*b1 + b0)*8^(i/3) = 4*8^(i/3)*b2 + 2*8^(i/3)*b1 + 8^(i/3)*b0
        constraint_leaf_index.push((b0, exp_8.clone()));
        constraint_leaf_index.push((b1, &two * &exp_8));
        constraint_leaf_index.push((b2, &four * &exp_8));

        let N7: LinearCombination = proof_nodes.pop().unwrap().into();
        let N6: LinearCombination = proof_nodes.pop().unwrap().into();
        let N5: LinearCombination = proof_nodes.pop().unwrap().into();
        let N4: LinearCombination = proof_nodes.pop().unwrap().into();
        let N3: LinearCombination = proof_nodes.pop().unwrap().into();
        let N2: LinearCombination = proof_nodes.pop().unwrap().into();
        let N1: LinearCombination = proof_nodes.pop().unwrap().into();

        // Notation: b0_1 = 1 - b0, b1_1 = 1 - b1 and b2_1 = 1 - b2 and prev_hash = N
        // Pre-compute various products of all bits
        // (1 - b0)*(1 - b1)
        let (_, _, b0_1_b1_1) = cs.multiply(b0_1.into(), b1_1.into());
        // (1 - b1)*(1 - b2)
        let (_, _, b1_1_b2_1) = cs.multiply(b1_1.into(), b2_1.into());
        // b0*b1
        let (_, _, b0_b1) = cs.multiply(b0.into(), b1.into());
        // b1*b2
        let (_, _, b1_b2) = cs.multiply(b1.into(), b2.into());
        // b0*b1*b2
        let (_, _, b0_b1_b2) = cs.multiply(b0_b1.into(), b2.into());
        // (1 - b0)*(1 - b1)*(1-b2)
        let (_, _, b0_1_b1_1_b2_1) = cs.multiply(b0_1_b1_1.into(), b2_1.into());
        // (1-b0*b1)*(1-b2)
        let (_, _, b01_1_b2_1) = cs.multiply((Variable::One() - b0_b1).into(), b2_1.into());

        // Constraints for nodes
        // (1 - b0)*(1 - b1)*(1-b2)*N
        let (_, _, c0_1) = cs.multiply(b0_1_b1_1_b2_1.into(), prev_hash.clone());
        // (1 - (1 - b0)*(1 - b1)*(1-b2))*N1
        let (_, _, c0_2) = cs.multiply((Variable::One() - b0_1_b1_1_b2_1).into(), N1.clone());
        // c0 = (1 - b0)*(1 - b1)*(1-b2)*N + (1 - (1 - b0)*(1 - b1)*(1-b2))*N1
        let c0 = c0_1 + c0_2;

        // (1-(1-b1)*(1-b2))*N2
        let (_, _, c1_1) = cs.multiply((Variable::One() - b1_1_b2_1).into(), N2.clone());
        // (1-b1)*(1-b2)*b0
        let (_, _, c1_2) = cs.multiply(b1_1_b2_1.into(), b0.into());
        // (1-b1)*(1-b2)*b0*N
        let (_, _, c1_3) = cs.multiply(c1_2.into(), prev_hash.clone());
        // (1-b1)*(1-b2)*(1-b0)*N1
        //let (_, _, c1_4) = cs.multiply(b0_1_b1_1_b2_1.into(), N1.clone());
        let c1_4 = N1 - c0_2;
        // c1 = (1 - (1-b1)*(1-b2))*N2 + (1-b1)*(1-b2)*b0*N + (1-b1)*(1-b2)*(1-b0)*N1
        let c1 = c1_1 + c1_3 + c1_4;

        // (1-b1)*(1-b2)*N2
        // let (_, _, c2_1) = cs.multiply(b1_1_b2_1.into(), N2.clone());
        let c2_1 = N2 - c1_1;
        // (1-b0)*(1-b2)
        let (_, _, c2_2) = cs.multiply(b0_1.into(), b2_1.into());
        // (1-b0)*(1-b2)*b1
        let (_, _, c2_3) = cs.multiply(c2_2.into(), b1.into());
        // (1-b0)*(1-b2)*b1*N
        let (_, _, c2_4) = cs.multiply(c2_3.into(), prev_hash.clone());
        // (1-(1-b0*b1)*(1-b2))*N3
        let (_, _, c2_5) = cs.multiply((Variable::One() - b01_1_b2_1).into(), N3.clone());
        // c2 = (1-b1)*(1-b2)*N2 + (1-b0)*(1-b2)*b1*N + (1-(1-b0*b1)*(1-b2))*N3
        let c2 = c2_1 + c2_4 + c2_5;

        // (1-b2)*(1-b0*b1)*N3
        //let (_, _, c3_1) = cs.multiply(b01_1_b2_1.into(), N3.clone());
        // XXX: Cant c3_1 be N3 - c2_5? There seem to be several such cases.
        let c3_1 = N3 - c2_5;

        // (1-b2)*b0*b1
        let (_, _, c3_2) = cs.multiply(b2_1.into(), b0_b1.into());
        // (1-b2)*b0*b1*N
        let (_, _, c3_3) = cs.multiply(c3_2.into(), prev_hash.clone());
        // b2*N4
        let (_, _, c3_4) = cs.multiply(b2.into(), N4.clone());
        // c3 = (1-b2)*(1-b0*b1)*N3 + (1-b2)*b0*b1*N + b2*N4
        let c3 = c3_1 + c3_3 + c3_4;

        // (1-b2)*N4
        //        let (_, _, c4_1) = cs.multiply(b2_1.into(), N4.clone());
        // XXX: Cant c4_1 be N4 - c3_4?
        let c4_1 = N4 - c3_4;

        // b2*(1-b0)*(1-b1)
        let (_, _, c4_2) = cs.multiply(b2.into(), b0_1_b1_1.into());
        // b2*(1-b0)*(1-b1)*N
        let (_, _, c4_3) = cs.multiply(c4_2.into(), prev_hash.clone());
        // b2*(1-(1-b1)*(1-b0))
        let (_, _, c4_4) = cs.multiply(b2.into(), (Variable::One() - b0_1_b1_1).into());
        // b2*(1-(1-b1)*(1-b0))*N5
        let (_, _, c4_5) = cs.multiply(c4_4.into(), N5.clone());
        // c4 = (1-b2)*N4 + b2*(1-b0)*(1-b1)*N + b2*(1-(1-b1)*(1-b0))*N5
        let c4 = c4_1 + c4_3 + c4_5;

        // (1-b2*(1-(1-b0)*(1-b1)))*N5
        //let (_, _, c5_1) = cs.multiply((Variable::One() - c4_4).into(), N5.clone());
        let c5_1 = N5 - c4_5;

        // b2*b1*N6
        let (_, _, c5_2) = cs.multiply(b1_b2.into(), N6.clone());
        // b2*(1 - b1)
        let (_, _, c5_3) = cs.multiply(b2.into(), b1_1.into());
        // b2*(1 - b1)*b0
        let (_, _, c5_4) = cs.multiply(c5_3.into(), b0.into());
        // b2*(1 - b1)*b0*N
        let (_, _, c5_5) = cs.multiply(c5_4.into(), prev_hash.clone());
        // c5 = (1-b2*(1-(1-b0)*(1-b1)))*N5 + b2*b1*N6 + b2*(1 - b1)*b0*N
        let c5 = c5_1 + c5_2 + c5_5;

        // b0*b1*b2*N7
        let (_, _, c6_1) = cs.multiply(b0_b1_b2.into(), N7.clone());
        // b2*(1-b0)*b1
        let (_, _, c6_2) = cs.multiply(b1_b2.into(), b0_1.into());
        // b2*(1-b0)*b1*N
        let (_, _, c6_3) = cs.multiply(c6_2.into(), prev_hash.clone());
        // (1-b1*b2)*N6
        //let (_, _, c6_4) = cs.multiply((Variable::One() - b1_b2).into(), N6.clone());
        let c6_4 = N6 - c5_2;
        // c6 = b0*b1*b2*N7 + b2*(1-b0)*b1*N + (1-b1*b2)*N6
        let c6 = c6_1 + c6_3 + c6_4;

        // b0*b1*b2*N
        let (_, _, c7_1) = cs.multiply(b0_b1_b2.into(), prev_hash.clone());
        // (1-b0*b1*b2)*N7
        //let (_, _, c7_2) = cs.multiply((Variable::One() - b0_b1_b2).into(), N7.clone());
        let c7_2 = N7 - c6_1;
        // c7 = b0*b1*b2*N + (1-b0*b1*b2)*N7
        let c7 = c7_1 + c7_2;

        let input = vec![c0, c1, c2, c3, c4, c5, c6, c7];

        prev_hash = hash_func.hash(cs, input)?;

        prev_hash = prev_hash.simplify();

        exp_8 = &exp_8 * &eight;
    }

    cs.constrain(constraint_leaf_index.iter().collect());

    constrain_lc_with_scalar::<CS>(cs, prev_hash, expected_root);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::r1cs::gadgets::helper_constraints::poseidon::{PoseidonParams, SboxType};
    use crate::r1cs::gadgets::merkle_tree_hash::PoseidonHash8;
    use crate::utils::hash_db::InMemoryHashDb;

    #[test]
    fn test_vanilla_sparse_merkle_tree_8() {
        let width = 9;

        let mut db = InMemoryHashDb::<DbVal8ary>::new();

        #[cfg(feature = "bls381")]
        let (full_b, full_e, partial_rounds) = (4, 4, 56);

        #[cfg(feature = "bn254")]
        let (full_b, full_e, partial_rounds) = (4, 4, 56);

        #[cfg(feature = "secp256k1")]
        let (full_b, full_e, partial_rounds) = (4, 4, 56);

        #[cfg(feature = "ed25519")]
        let (full_b, full_e, partial_rounds) = (4, 4, 56);

        let hash_params = PoseidonParams::new(width, full_b, full_e, partial_rounds).unwrap();

        let tree_depth = 12;
        let hash_func = PoseidonHash8 {
            params: &hash_params,
            sbox: &SboxType::Quint,
        };
        let mut tree = VanillaSparseMerkleTree8::new(&hash_func, tree_depth, &mut db).unwrap();

        for i in 1..20 {
            let s = FieldElement::from(i as u64);
            tree.update(&s, s.clone(), &mut db).unwrap();
        }

        for i in 1..20 {
            let s = FieldElement::from(i as u32);
            assert_eq!(s, tree.get(&s, &mut None, &db).unwrap());
            let mut proof_vec = Vec::<ProofNode8ary>::new();
            let mut proof = Some(proof_vec);
            assert_eq!(s, tree.get(&s, &mut proof, &db).unwrap());
            proof_vec = proof.unwrap();
            assert!(tree.verify_proof(&s, &s, &proof_vec, None).unwrap());
            assert!(tree
                .verify_proof(&s, &s, &proof_vec, Some(&tree.root))
                .unwrap());
        }

        let kvs: Vec<(FieldElement, FieldElement)> = (0..20)
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
