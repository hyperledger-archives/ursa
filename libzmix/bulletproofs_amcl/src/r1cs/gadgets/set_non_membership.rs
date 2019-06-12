use super::helper_constraints::constrain_lc_with_scalar;
use super::helper_constraints::non_zero::is_nonzero_gadget;
use crate::errors::R1CSError;
use crate::r1cs::linear_combination::AllocatedQuantity;
use crate::r1cs::{ConstraintSystem, LinearCombination, Prover, R1CSProof, Variable, Verifier};
use amcl_wrapper::field_elem::FieldElement;
use amcl_wrapper::group_elem::GroupElement;
use amcl_wrapper::group_elem_g1::{G1Vector, G1};
use merlin::Transcript;
use rand::{CryptoRng, RngCore};

/// Constraints for checking set membership check
/// Create a new set with values being difference between the set value at that index and the value being proved a member.
/// Now ensure that the product of members of this new set is not 0
/// eg. Original set is (a, b, c, d, e). It is to be proved that x is not a member of set.
/// Create new set (a-x, b-x, c-x, d-x, e-x). Now ensure product (a-x).(b-x).(c-x).(d-x).(e-x) != 0
pub fn set_non_membership_gadget<CS: ConstraintSystem>(
    cs: &mut CS,
    v: AllocatedQuantity,
    diff_vars: Vec<AllocatedQuantity>,
    diff_inv_vars: Vec<AllocatedQuantity>,
    set: &[FieldElement],
) -> Result<(), R1CSError> {
    let set_length = set.len();

    for i in 0..set_length {
        // Since `diff_vars[i]` is `set[i] - v`, `diff_vars[i]` + `v` should be `set[i]`
        constrain_lc_with_scalar::<CS>(cs, diff_vars[i].variable + v.variable, &set[i]);
        // Ensure `set[i] - v` is non-zero
        is_nonzero_gadget(cs, diff_vars[i], diff_inv_vars[i])?;
    }

    Ok(())
}

/// Prove that difference between each set element and value is non-zero, hence value does not equal any set element.
pub fn gen_proof_of_set_non_membership<R: RngCore + CryptoRng>(
    value: FieldElement,
    randomness: Option<FieldElement>,
    set: &[FieldElement],
    rng: Option<&mut R>,
    transcript_label: &'static [u8],
    g: &G1,
    h: &G1,
    G: &G1Vector,
    H: &G1Vector,
) -> Result<(R1CSProof, Vec<G1>), R1CSError> {
    check_for_randomness_or_rng!(randomness, rng)?;

    let set_length = set.len();

    let mut prover_transcript = Transcript::new(transcript_label);

    let mut prover = Prover::new(&g, &h, &mut prover_transcript);

    let mut comms = vec![];
    let mut diff_vars: Vec<AllocatedQuantity> = vec![];
    let mut diff_inv_vars: Vec<AllocatedQuantity> = vec![];

    let value = FieldElement::from(value);
    let (com_value, var_value) = prover.commit(
        value.clone(),
        randomness.unwrap_or_else(|| FieldElement::random_using_rng(rng.unwrap())),
    );
    let alloc_scal = AllocatedQuantity {
        variable: var_value,
        assignment: Some(value),
    };
    comms.push(com_value);

    for i in 0..set_length {
        let elem = FieldElement::from(set[i]);
        let diff = elem - value;
        let diff_inv = diff.inverse();

        // Take difference of set element and value, `set[i] - value`
        let (com_diff, var_diff) = prover.commit(diff.clone(), FieldElement::random());
        let alloc_scal_diff = AllocatedQuantity {
            variable: var_diff,
            assignment: Some(diff),
        };
        diff_vars.push(alloc_scal_diff);
        comms.push(com_diff);

        // Inverse needed to prove that difference `set[i] - value` is non-zero
        let (com_diff_inv, var_diff_inv) = prover.commit(diff_inv.clone(), FieldElement::random());
        let alloc_scal_diff_inv = AllocatedQuantity {
            variable: var_diff_inv,
            assignment: Some(diff_inv),
        };
        diff_inv_vars.push(alloc_scal_diff_inv);
        comms.push(com_diff_inv);
    }

    set_non_membership_gadget(&mut prover, alloc_scal, diff_vars, diff_inv_vars, &set)?;

    let proof = prover.prove(&G, &H)?;

    Ok((proof, comms))
}

pub fn verify_proof_of_set_non_membership(
    set: &[FieldElement],
    proof: R1CSProof,
    commitments: Vec<G1>,
    transcript_label: &'static [u8],
    g: &G1,
    h: &G1,
    G: &G1Vector,
    H: &G1Vector,
) -> Result<(), R1CSError> {
    let mut verifier_transcript = Transcript::new(transcript_label);
    let mut verifier = Verifier::new(&mut verifier_transcript);

    let set_length = set.len();

    let mut diff_vars: Vec<AllocatedQuantity> = vec![];
    let mut diff_inv_vars: Vec<AllocatedQuantity> = vec![];

    let var_val = verifier.commit(commitments[0]);
    let alloc_scal = AllocatedQuantity {
        variable: var_val,
        assignment: None,
    };

    for i in 1..set_length + 1 {
        let var_diff = verifier.commit(commitments[2 * i - 1]);
        let alloc_scal_diff = AllocatedQuantity {
            variable: var_diff,
            assignment: None,
        };
        diff_vars.push(alloc_scal_diff);

        let var_diff_inv = verifier.commit(commitments[2 * i]);
        let alloc_scal_diff_inv = AllocatedQuantity {
            variable: var_diff_inv,
            assignment: None,
        };
        diff_inv_vars.push(alloc_scal_diff_inv);
    }

    set_non_membership_gadget(&mut verifier, alloc_scal, diff_vars, diff_inv_vars, &set)?;

    verifier.verify(&proof, &g, &h, &G, &H)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::get_generators;

    #[test]
    fn test_set_non_membership() {
        use rand::rngs::OsRng;
        use rand::Rng;

        let mut rng = rand::thread_rng();

        let set = vec![
            FieldElement::from(2),
            FieldElement::from(3),
            FieldElement::from(5),
            FieldElement::from(6),
            FieldElement::from(8),
            FieldElement::from(20),
            FieldElement::from(25),
        ];
        let value = FieldElement::from(101);

        let G: G1Vector = get_generators("G", 64).into();
        let H: G1Vector = get_generators("H", 64).into();
        let g = G1::from_msg_hash("g".as_bytes());
        let h = G1::from_msg_hash("h".as_bytes());

        let label = b"SetMembership";
        let (proof, commitments) = gen_proof_of_set_non_membership(
            value,
            None,
            &set,
            Some(&mut rng),
            label,
            &g,
            &h,
            &G,
            &H,
        )
        .unwrap();

        verify_proof_of_set_non_membership(&set, proof, commitments, label, &g, &h, &G, &H)
            .unwrap();
    }
}
