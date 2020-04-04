use crate::errors::{BulletproofError, BulletproofErrorKind, R1CSError, R1CSErrorKind};
use crate::r1cs::gadgets::helper_constraints::mimc::mimc;
use crate::r1cs::gadgets::helper_constraints::poseidon::{
    PoseidonParams, Poseidon_hash_2, Poseidon_hash_4, Poseidon_hash_4_constraints, Poseidon_hash_8,
    Poseidon_hash_8_constraints, SboxType,
};
use crate::r1cs::{ConstraintSystem, LinearCombination, Prover, Variable, Verifier};
use amcl_wrapper::commitment::commit_to_field_element;
use amcl_wrapper::field_elem::FieldElement;
use amcl_wrapper::group_elem_g1::G1;

// The interfaced defined here are expected to change as we add more Bulletproof
// friendly hash functions.

pub trait Arity2MerkleTreeHash {
    fn is_num_inputs_correct(inputs: &[FieldElement]) -> Result<(), BulletproofError> {
        if inputs.len() != 2 {
            Err(BulletproofErrorKind::IncorrectNoOfInputsForMerkleTreeHash {
                found: inputs.len(),
                expected: 2,
            }
            .into())
        } else {
            Ok(())
        }
    }

    fn hash(&self, inputs: Vec<FieldElement>) -> Result<FieldElement, BulletproofError>;
}

pub trait Arity4MerkleTreeHash {
    fn is_num_inputs_correct(inputs: &[FieldElement]) -> Result<(), BulletproofError> {
        if inputs.len() != 4 {
            Err(BulletproofErrorKind::IncorrectNoOfInputsForMerkleTreeHash {
                found: inputs.len(),
                expected: 4,
            }
            .into())
        } else {
            Ok(())
        }
    }

    fn hash(&self, inputs: Vec<FieldElement>) -> Result<FieldElement, BulletproofError>;
}

pub trait Arity8MerkleTreeHash {
    fn is_num_inputs_correct(inputs: &[FieldElement]) -> Result<(), BulletproofError> {
        if inputs.len() != 8 {
            Err(BulletproofErrorKind::IncorrectNoOfInputsForMerkleTreeHash {
                found: inputs.len(),
                expected: 8,
            }
            .into())
        } else {
            Ok(())
        }
    }

    fn hash(&self, inputs: Vec<FieldElement>) -> Result<FieldElement, BulletproofError>;
}

pub trait Arity4MerkleTreeHashConstraints {
    /// This is for hash function specific setup. Like Poseidon needs a variable allocated for
    /// capacity constant. Done for the prover and must be done once and only once
    fn prover_setup(&mut self, prover: &mut Prover) -> Result<(), R1CSError>;
    /// This is for hash function specific setup. Like Poseidon needs a variable allocated for
    /// capacity constant. Done for the verifier and must be done once and only once.
    /// The `g` and `h` are needed to commit to capacity constant in case of Poseidon. If the
    /// specific hash function does not need it, they should be `None`.
    fn verifier_setup(
        &mut self,
        verifier: &mut Verifier,
        g: Option<&G1>,
        h: Option<&G1>,
    ) -> Result<(), R1CSError>;
    // TODO: It would be better to make inputs an array of size 4
    fn hash<CS: ConstraintSystem>(
        &self,
        cs: &mut CS,
        inputs: Vec<LinearCombination>,
    ) -> Result<LinearCombination, R1CSError>;
}

pub trait Arity8MerkleTreeHashConstraints {
    /// This is for hash function specific setup. Like Poseidon needs a variable allocated for
    /// capacity constant. Done for the prover and must be done once and only once
    fn prover_setup(&mut self, prover: &mut Prover) -> Result<(), R1CSError>;
    /// This is for hash function specific setup. Like Poseidon needs a variable allocated for
    /// capacity constant. Done for the verifier and must be done once and only once.
    /// The `g` and `h` are needed to commit to capacity constant in case of Poseidon. If the
    /// specific hash function does not need it, they should be `None`.
    fn verifier_setup(
        &mut self,
        verifier: &mut Verifier,
        g: Option<&G1>,
        h: Option<&G1>,
    ) -> Result<(), R1CSError>;
    // TODO: It would be better to make inputs an array of size 8
    fn hash<CS: ConstraintSystem>(
        &self,
        cs: &mut CS,
        inputs: Vec<LinearCombination>,
    ) -> Result<LinearCombination, R1CSError>;
}

pub struct Mimc2<'a> {
    pub constants: &'a [FieldElement],
}

pub struct PoseidonHash2<'a> {
    pub params: &'a PoseidonParams,
    pub sbox: &'a SboxType,
}

pub struct PoseidonHash4<'a> {
    pub params: &'a PoseidonParams,
    pub sbox: &'a SboxType,
}

pub struct PoseidonHash8<'a> {
    pub params: &'a PoseidonParams,
    pub sbox: &'a SboxType,
}

pub struct PoseidonHashConstraints<'a> {
    pub params: &'a PoseidonParams,
    pub sbox: &'a SboxType,
    pub capacity_const: u64,
    capacity_const_var: Option<Variable>,
}

impl<'a> Arity2MerkleTreeHash for Mimc2<'a> {
    fn hash(&self, inputs: Vec<FieldElement>) -> Result<FieldElement, BulletproofError> {
        Ok(mimc(&inputs[0], &inputs[1], self.constants))
    }
}

impl<'a> Arity2MerkleTreeHash for PoseidonHash2<'a> {
    fn hash(&self, inputs: Vec<FieldElement>) -> Result<FieldElement, BulletproofError> {
        Self::is_num_inputs_correct(&inputs)?;
        Poseidon_hash_2(inputs, &self.params, &self.sbox)
    }
}

impl<'a> Arity4MerkleTreeHash for PoseidonHash4<'a> {
    fn hash(&self, inputs: Vec<FieldElement>) -> Result<FieldElement, BulletproofError> {
        Self::is_num_inputs_correct(&inputs)?;
        Poseidon_hash_4(inputs, &self.params, &self.sbox)
    }
}

impl<'a> Arity8MerkleTreeHash for PoseidonHash8<'a> {
    fn hash(&self, inputs: Vec<FieldElement>) -> Result<FieldElement, BulletproofError> {
        Self::is_num_inputs_correct(&inputs)?;
        Poseidon_hash_8(inputs, &self.params, &self.sbox)
    }
}

impl<'a> PoseidonHashConstraints<'a> {
    pub fn new(params: &'a PoseidonParams, sbox: &'a SboxType, capacity_const: u64) -> Self {
        Self {
            params,
            sbox,
            capacity_const,
            capacity_const_var: None,
        }
    }

    fn prover_commit_to_capacity_const(&mut self, prover: &mut Prover) -> Result<(), R1CSError> {
        if self.capacity_const_var.is_some() {
            return Err(R1CSErrorKind::GadgetError {description: String::from("Poseidon: capacity_const_var should be None but is Some. Setup has already been called once.")}.into());
        }
        let (_, var) = prover.commit(
            FieldElement::from(self.capacity_const),
            FieldElement::zero(),
        );
        self.capacity_const_var = Some(var);
        Ok(())
    }

    fn verifier_commit_to_capacity_const(
        &mut self,
        verifier: &mut Verifier,
        g: Option<&G1>,
        h: Option<&G1>,
    ) -> Result<(), R1CSError> {
        if self.capacity_const_var.is_some() {
            return Err(R1CSErrorKind::GadgetError {description: String::from("Poseidon: capacity_const_var should be None but is Some. Setup has already been called once.")}.into());
        }
        if g.is_none() || h.is_none() {
            return Err(R1CSErrorKind::GadgetError {
                description: String::from("Poseidon: Neither g or h should be None"),
            }
            .into());
        }
        let comm = commit_to_field_element(
            g.unwrap(),
            h.unwrap(),
            &FieldElement::from(self.capacity_const),
            &FieldElement::zero(),
        );

        let var = verifier.commit(comm);
        self.capacity_const_var = Some(var);
        Ok(())
    }

    fn get_capacity_constant_lc(&self) -> Result<LinearCombination, R1CSError> {
        if self.capacity_const_var.is_none() {
            return Err(R1CSErrorKind::GadgetError {description: String::from("Poseidon: capacity_const_var should be Some but is None. Setup not called yet.")}.into());
        }
        let cap_const_lc = self
            .capacity_const_var
            .as_ref()
            .map(|c| LinearCombination::from(*c))
            .unwrap();
        Ok(cap_const_lc)
    }
}

impl<'a> Arity4MerkleTreeHashConstraints for PoseidonHashConstraints<'a> {
    fn prover_setup(&mut self, prover: &mut Prover) -> Result<(), R1CSError> {
        self.prover_commit_to_capacity_const(prover)
    }

    fn verifier_setup(
        &mut self,
        verifier: &mut Verifier,
        g: Option<&G1>,
        h: Option<&G1>,
    ) -> Result<(), R1CSError> {
        self.verifier_commit_to_capacity_const(verifier, g, h)
    }

    fn hash<CS: ConstraintSystem>(
        &self,
        cs: &mut CS,
        inputs: Vec<LinearCombination>,
    ) -> Result<LinearCombination, R1CSError> {
        Poseidon_hash_4_constraints::<CS>(
            cs,
            inputs,
            self.get_capacity_constant_lc()?,
            self.params,
            self.sbox,
        )
    }
}

impl<'a> Arity8MerkleTreeHashConstraints for PoseidonHashConstraints<'a> {
    fn prover_setup(&mut self, prover: &mut Prover) -> Result<(), R1CSError> {
        self.prover_commit_to_capacity_const(prover)
    }

    fn verifier_setup(
        &mut self,
        verifier: &mut Verifier,
        g: Option<&G1>,
        h: Option<&G1>,
    ) -> Result<(), R1CSError> {
        self.verifier_commit_to_capacity_const(verifier, g, h)
    }

    fn hash<CS: ConstraintSystem>(
        &self,
        cs: &mut CS,
        inputs: Vec<LinearCombination>,
    ) -> Result<LinearCombination, R1CSError> {
        Poseidon_hash_8_constraints::<CS>(
            cs,
            inputs,
            self.get_capacity_constant_lc()?,
            self.params,
            self.sbox,
        )
    }
}
