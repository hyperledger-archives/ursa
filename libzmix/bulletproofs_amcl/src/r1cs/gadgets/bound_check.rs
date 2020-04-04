use super::helper_constraints::constrain_lc_with_scalar;
use super::helper_constraints::positive_no::positive_no_gadget;
use crate::errors::{R1CSError, R1CSErrorKind};
use crate::r1cs::linear_combination::AllocatedQuantity;
use crate::r1cs::{ConstraintSystem, LinearCombination, Prover, R1CSProof, Verifier};
use amcl_wrapper::field_elem::FieldElement;
use amcl_wrapper::group_elem_g1::{G1Vector, G1};
use merlin::Transcript;
use rand::{CryptoRng, Rng};

/// Constraints for proving v lies in [min, max].
/// Ensure v - min and max - v are positive numbers and don't overflow.
/// This would work when since v, min and max are u64 and less than half
/// of the curve order/field size.
pub fn bound_check_gadget<CS: ConstraintSystem>(
    cs: &mut CS,
    v: AllocatedQuantity,
    a: AllocatedQuantity,
    b: AllocatedQuantity,
    max: u64,
    min: u64,
    n: usize,
) -> Result<(), R1CSError> {
    // a = v - min
    // b = max - v
    // a + b = max - min

    cs.constrain(v.variable - LinearCombination::from(FieldElement::from(min)) - a.variable);

    cs.constrain(LinearCombination::from(FieldElement::from(max)) - v.variable - b.variable);

    // Constrain a + b to be same as max - min.
    constrain_lc_with_scalar::<CS>(cs, a.variable + b.variable, &FieldElement::from(max - min));

    // Constrain a in [0, 2^n)
    positive_no_gadget(cs, a, n)?;
    // Constrain b in [0, 2^n)
    positive_no_gadget(cs, b, n)?;

    Ok(())
}

pub fn prove_bounded_num<R: Rng + CryptoRng>(
    val: u64,
    blinding: Option<FieldElement>,
    lower: u64,
    upper: u64,
    max_bits_in_val: usize,
    rng: Option<&mut R>,
    prover: &mut Prover,
) -> Result<Vec<G1>, R1CSError> {
    check_for_blindings_or_rng!(blinding, rng)?;

    let a = val - lower;
    let b = upper - val;

    let mut comms = vec![];

    let (com_v, var_v) = prover.commit(
        val.into(),
        blinding.unwrap_or_else(|| FieldElement::random_using_rng(rng.unwrap())),
    );
    let quantity_v = AllocatedQuantity {
        variable: var_v,
        assignment: Some(val.into()),
    };
    comms.push(com_v);

    let (com_a, var_a) = prover.commit(a.into(), FieldElement::random());
    let quantity_a = AllocatedQuantity {
        variable: var_a,
        assignment: Some(a.into()),
    };
    comms.push(com_a);

    let (com_b, var_b) = prover.commit(b.into(), FieldElement::random());
    let quantity_b = AllocatedQuantity {
        variable: var_b,
        assignment: Some(b.into()),
    };
    comms.push(com_b);

    bound_check_gadget(
        prover,
        quantity_v,
        quantity_a,
        quantity_b,
        upper,
        lower,
        max_bits_in_val,
    )?;

    Ok(comms)
}

pub fn verify_bounded_num(
    lower: u64,
    upper: u64,
    max_bits_in_val: usize,
    mut commitments: Vec<G1>,
    verifier: &mut Verifier,
) -> Result<(), R1CSError> {
    let var_v = verifier.commit(commitments.remove(0));
    let quantity_v = AllocatedQuantity {
        variable: var_v,
        assignment: None,
    };

    let var_a = verifier.commit(commitments.remove(0));
    let quantity_a = AllocatedQuantity {
        variable: var_a,
        assignment: None,
    };

    let var_b = verifier.commit(commitments.remove(0));
    let quantity_b = AllocatedQuantity {
        variable: var_b,
        assignment: None,
    };

    bound_check_gadget(
        verifier,
        quantity_v,
        quantity_a,
        quantity_b,
        upper,
        lower,
        max_bits_in_val,
    )?;
    Ok(())
}

/// Accepts the num for which the bounds have to proved and optionally the randomness used in committing to that number.
/// This randomness argument is accepted so that this can be used as a sub-protocol where the protocol on upper layer will create the commitment.
pub fn gen_proof_of_bounded_num<R: Rng + CryptoRng>(
    val: u64,
    blinding: Option<FieldElement>,
    lower: u64,
    upper: u64,
    max_bits_in_val: usize,
    rng: Option<&mut R>,
    transcript_label: &'static [u8],
    g: &G1,
    h: &G1,
    G: &G1Vector,
    H: &G1Vector,
) -> Result<(R1CSProof, Vec<G1>), R1CSError> {
    let mut prover_transcript = Transcript::new(transcript_label);
    let mut prover = Prover::new(g, h, &mut prover_transcript);

    let comms = prove_bounded_num(
        val,
        blinding,
        lower,
        upper,
        max_bits_in_val,
        rng,
        &mut prover,
    )?;
    let proof = prover.prove(G, H)?;

    Ok((proof, comms))
}

pub fn verify_proof_of_bounded_num(
    lower: u64,
    upper: u64,
    max_bits_in_val: usize,
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
    verify_bounded_num(lower, upper, max_bits_in_val, commitments, &mut verifier)?;
    verifier.verify(&proof, g, h, G, H)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::get_generators;
    use amcl_wrapper::group_elem::GroupElement;

    #[test]
    fn test_bound_check_gadget() {
        use rand::Rng;

        let mut rng = rand::thread_rng();
        let min = 10;
        let max = 100;

        let v = rng.gen_range(min, max);
        println!("v is {}", &v);
        let randomness = Some(FieldElement::random());

        let G: G1Vector = get_generators("G", 128).into();
        let H: G1Vector = get_generators("H", 128).into();
        let g = G1::from_msg_hash("g".as_bytes());
        let h = G1::from_msg_hash("h".as_bytes());

        let n = 32;

        let label = b"BoundsTest";
        let (proof, commitments) = gen_proof_of_bounded_num(
            v,
            randomness,
            min,
            max,
            n,
            Some(&mut rng),
            label,
            &g,
            &h,
            &G,
            &H,
        )
        .unwrap();

        verify_proof_of_bounded_num(min, max, n, proof, commitments, label, &g, &h, &G, &H)
            .unwrap();
    }
}
