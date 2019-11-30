use crate::errors::{BulletproofError, R1CSError};
use crate::r1cs::gadgets::helper_constraints::mimc::mimc;
use crate::r1cs::gadgets::helper_constraints::poseidon::{
    PoseidonParams, Poseidon_hash_2, Poseidon_hash_4, Poseidon_hash_8, SboxType,
};
use crate::r1cs::LinearCombination;
use amcl_wrapper::field_elem::FieldElement;

pub trait MerkleTreeHash {
    fn hash(&self, inputs: Vec<FieldElement>) -> Result<FieldElement, BulletproofError>;
}

pub trait MerkleTreeHashConstraints {
    fn hash(&self, inputs: Vec<LinearCombination>) -> Result<LinearCombination, R1CSError>;
}

pub struct MiMC_2<'a> {
    pub constants: &'a [FieldElement],
}

pub struct PoseidonHash_2<'a> {
    pub params: &'a PoseidonParams,
    pub sbox: &'a SboxType,
}

pub struct PoseidonHash_4<'a> {
    pub params: &'a PoseidonParams,
    pub sbox: &'a SboxType,
}

pub struct PoseidonHash_8<'a> {
    pub params: &'a PoseidonParams,
    pub sbox: &'a SboxType,
}

impl<'a> MerkleTreeHash for MiMC_2<'a> {
    fn hash(&self, inputs: Vec<FieldElement>) -> Result<FieldElement, BulletproofError> {
        Ok(mimc(&inputs[0], &inputs[1], self.constants))
    }
}

impl<'a> MerkleTreeHash for PoseidonHash_2<'a> {
    fn hash(&self, inputs: Vec<FieldElement>) -> Result<FieldElement, BulletproofError> {
        Poseidon_hash_2(inputs, &self.params, &self.sbox)
    }
}

impl<'a> MerkleTreeHash for PoseidonHash_4<'a> {
    fn hash(&self, inputs: Vec<FieldElement>) -> Result<FieldElement, BulletproofError> {
        Poseidon_hash_4(inputs, &self.params, &self.sbox)
    }
}

impl<'a> MerkleTreeHash for PoseidonHash_8<'a> {
    fn hash(&self, inputs: Vec<FieldElement>) -> Result<FieldElement, BulletproofError> {
        Poseidon_hash_8(inputs, &self.params, &self.sbox)
    }
}
