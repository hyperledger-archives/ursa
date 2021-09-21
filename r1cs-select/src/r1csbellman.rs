use crate::WrappedCircuit;
use bellman::gadgets::num::AllocatedNum;
use bellman::{Circuit, ConstraintSystem, LinearCombination, SynthesisError, Variable};
use bls12_381::Scalar;
use r1cs::num::{Integer, One, ToPrimitive};
use r1cs::{num::BigUint, Constraint, Element, Expression, Field};
use std::collections::HashMap;

pub struct BellmanCircuit<F: Field> {
    pub circuit: WrappedCircuit<F>,
}

impl<F: Field> Circuit<Scalar> for BellmanCircuit<F> {
    fn synthesize<CS: ConstraintSystem<Scalar>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let mut id_to_var = HashMap::new();
        id_to_var.insert(0u32, CS::one());
        let witnesses = self.circuit.witnesses.as_map();

        for id in &self.circuit.wires {
            let val = witnesses
                .get(id)
                .map(|w| convert_bls12_381(w))
                .ok_or(SynthesisError::Unsatisfiable)?;
            if self.circuit.public_wires.contains(id) {
                let mut cs = cs.namespace(|| format!("public_{}", id.index));
                let num = AllocatedNum::alloc(&mut cs, || Ok(val))?;
                num.inputize(&mut cs)?;
                id_to_var.insert(id.index, num.get_variable());
            } else {
                let num =
                    AllocatedNum::alloc(cs.namespace(|| format!("private_{}", id.index)), || {
                        Ok(val)
                    })?;
                id_to_var.insert(id.index, num.get_variable());
            }
        }

        for (i, constraint) in self.circuit.gadget.constraints.iter().enumerate() {
            enforce(
                &mut cs.namespace(|| format!("constraint_{}", i)),
                &id_to_var,
                &constraint,
            );
        }

        Ok(())
    }
}

pub fn enforce<CS, F>(cs: &mut CS, id_to_var: &HashMap<u32, Variable>, constraint: &Constraint<F>)
where
    CS: ConstraintSystem<Scalar>,
    F: Field,
{
    cs.enforce(
        || "",
        |_| convert_lc(id_to_var, &constraint.a),
        |_| convert_lc(id_to_var, &constraint.b),
        |_| convert_lc(id_to_var, &constraint.c),
    );
}

fn convert_lc<F: Field>(
    id_to_var: &HashMap<u32, Variable>,
    exp: &Expression<F>,
) -> LinearCombination<bls12_381::Scalar> {
    // This is inefficient, but bellman doesn't expose a LinearCombination constructor taking an
    // entire variable/coefficient map, so we have to build one up with repeated addition.
    let mut sum = LinearCombination::zero();
    for (wire, coeff) in exp.coefficients() {
        let fr = convert_bls12_381(coeff);
        let index = id_to_var.get(&wire.index).unwrap();
        sum = sum + (fr, *index);
    }
    sum
}

pub fn convert_bls12_381<F: Field>(n: &Element<F>) -> bls12_381::Scalar {
    let n = n.to_biguint();
    let u64_size = BigUint::one() << 64;
    let chunks = [
        n.mod_floor(&u64_size).to_u64().unwrap(),
        (n >> 64).mod_floor(&u64_size).to_u64().unwrap(),
        (n >> 64 * 2).mod_floor(&u64_size).to_u64().unwrap(),
        (n >> 64 * 3).mod_floor(&u64_size).to_u64().unwrap(),
    ];
    bls12_381::Scalar::from_raw(chunks)
}
