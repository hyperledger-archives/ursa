use crate::WrappedCircuit;
use bulletproofs::r1cs::ConstraintSystem;
use bulletproofs::{
    r1cs::{LinearCombination, Prover, R1CSError, R1CSProof, Variable, Verifier},
    BulletproofGens, PedersenGens,
};
use curve25519_dalek_ng::ristretto::CompressedRistretto;
use curve25519_dalek_ng::scalar::Scalar;
use merlin::Transcript;
use r1cs::{
    num::{BigUint, Num},
    Wire,
};
use r1cs::{Element, Expression, Field};
use std::collections::{HashMap, HashSet};
use std::iter::FromIterator;

pub struct Curve25519;

impl Field for Curve25519 {
    fn order() -> BigUint {
        BigUint::from_str_radix(
            "1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED",
            16,
        )
        .unwrap()
    }
}

pub fn prove<F: Field>(
    circuit: &WrappedCircuit<F>,
    transcript: &mut Transcript,
) -> Result<
    (
        R1CSProof,
        HashMap<u32, CompressedRistretto>,
        HashMap<u32, CompressedRistretto>,
    ),
    R1CSError,
> {
    let pc_gens = PedersenGens::default();
    let mut capacity = 128;
    while capacity < circuit.wires.len() {
        capacity <<= 1;
    }
    let bp_gens = BulletproofGens::new(capacity, 1);

    let mut prover = Prover::new(&pc_gens, transcript);

    let mut input_commitments = HashMap::new();
    let mut output_commitments = HashMap::new();

    let mut id_to_var = HashMap::<u32, Variable>::new();
    let mut id_to_val = HashMap::new();

    id_to_var.insert(0u32, Variable::One());
    id_to_val.insert(0u32, Scalar::one());

    let witnesses = circuit.witnesses.as_map();
    for id in &circuit.wires {
        let value = witnesses
            .get(id)
            .map(convert_25519)
            .ok_or(R1CSError::FormatError)?;

        if circuit.public_wires.contains(id) {
            let (comm, var) =
                prover.commit(value, Scalar::random(&mut rand::rngs::OsRng::default()));
            output_commitments.insert(id.index, comm);
            id_to_var.insert(id.index, var);
            id_to_val.insert(id.index, value);
        } else {
            let (comm, var) =
                prover.commit(value, Scalar::random(&mut rand::rngs::OsRng::default()));
            input_commitments.insert(id.index, comm);
            id_to_var.insert(id.index, var);
            id_to_val.insert(id.index, value);
        }
    }

    for constraint in circuit.gadget.constraints.iter() {
        let (_, _, o) = prover.multiply(
            convert_lc(&id_to_var, &constraint.a),
            convert_lc(&id_to_var, &constraint.b),
        );
        if is_public(&circuit.public_wires, &constraint.c) {
            let c = convert_lc(&id_to_var, &constraint.c);
            prover.constrain(o - c);
        }
    }

    Ok((
        prover.prove(&bp_gens)?,
        input_commitments,
        output_commitments,
    ))
}

pub fn verify<F: Field>(
    proof: &R1CSProof,
    circuit: &WrappedCircuit<F>,
    inputs: &HashMap<u32, CompressedRistretto>,
    outputs: &HashMap<u32, CompressedRistretto>,
    transcript: &mut Transcript,
) -> Result<(), R1CSError> {
    let pc_gens = PedersenGens::default();
    let mut capacity = 128;
    while capacity < circuit.wires.len() {
        capacity <<= 1;
    }
    let bp_gens = BulletproofGens::new(capacity, 1);

    let mut id_to_var = HashMap::<u32, Variable>::new();
    let mut verifier = Verifier::new(transcript);

    for id in &circuit.wires {
        if circuit.public_wires.contains(id) {
            match outputs.get(&id.index) {
                None => panic!(),
                Some(p) => {
                    let var = verifier.commit(*p);
                    id_to_var.insert(id.index, var);
                }
            };
        } else {
            match inputs.get(&id.index) {
                None => panic!(),
                Some(p) => {
                    let var = verifier.commit(*p);
                    id_to_var.insert(id.index, var);
                }
            };
        }
    }

    for constraint in circuit.gadget.constraints.iter() {
        let (_, _, o) = verifier.multiply(
            convert_lc(&id_to_var, &constraint.a),
            convert_lc(&id_to_var, &constraint.b),
        );
        if is_public(&circuit.public_wires, &constraint.c) {
            let c = convert_lc(&id_to_var, &constraint.c);
            verifier.constrain(o - c);
        }
    }

    verifier.verify(proof, &pc_gens, &bp_gens)
}

fn is_public<F: Field>(public_wires: &HashSet<Wire>, exp: &Expression<F>) -> bool {
    exp.coefficients()
        .iter()
        .any(|(w, _)| public_wires.contains(w))
}

fn convert_lc<F: Field>(
    id_to_var: &HashMap<u32, Variable>,
    exp: &Expression<F>,
) -> LinearCombination {
    let mut sum = LinearCombination::default();
    for (wire, coeff) in exp.coefficients() {
        let fr = convert_25519(coeff);
        let index = id_to_var.get(&wire.index).unwrap();
        let t = LinearCombination::from_iter(&[(*index, fr)]);
        sum = sum + t;
    }
    sum
}

fn convert_25519<F: Field>(n: &Element<F>) -> Scalar {
    let n = n.to_biguint();
    let mut b = [0u8; 32];
    let n_bytes = n.to_bytes_le();
    b[..n_bytes.len()].copy_from_slice(n_bytes.as_slice());
    Scalar::from_bits(b)
}
