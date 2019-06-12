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

/// Accepts the num which is to be proved non-zero and optionally the randomness used in committing to that number.
/// This randomness argument is accepted so that this can be used as a sub-protocol where the protocol on upper layer will create the commitment.
pub fn gen_proof_of_non_zero_val<R: RngCore + CryptoRng>(
    value: FieldElement,
    randomness: Option<FieldElement>,
    rng: Option<&mut R>,
    transcript_label: &'static [u8],
    g: &G1,
    h: &G1,
    G: &G1Vector,
    H: &G1Vector,
) -> Result<(R1CSProof, Vec<G1>), R1CSError> {
    check_for_randomness_or_rng!(randomness, rng)?;

    let inv = value.inverse();
    let mut comms = vec![];

    let mut prover_transcript = Transcript::new(transcript_label);
    let mut prover = Prover::new(g, h, &mut prover_transcript);

    let (com_val, var_val) = prover.commit(
        value.clone(),
        randomness.unwrap_or_else(|| FieldElement::random_using_rng(rng.unwrap())),
    );
    let alloc_scal = AllocatedQuantity {
        variable: var_val,
        assignment: Some(value),
    };
    comms.push(com_val);

    let (com_val_inv, var_val_inv) = prover.commit(inv.clone(), FieldElement::random());
    let alloc_scal_inv = AllocatedQuantity {
        variable: var_val_inv,
        assignment: Some(inv),
    };
    comms.push(com_val_inv);

    is_nonzero_gadget(&mut prover, alloc_scal, alloc_scal_inv)?;

    let proof = prover.prove(G, H)?;

    Ok((proof, comms))
}

pub fn verify_proof_of_non_zero_val(
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

    let var_val = verifier.commit(commitments[0]);
    let alloc_scal = AllocatedQuantity {
        variable: var_val,
        assignment: None,
    };

    let var_val_inv = verifier.commit(commitments[1]);
    let alloc_scal_inv = AllocatedQuantity {
        variable: var_val_inv,
        assignment: None,
    };

    is_nonzero_gadget(&mut verifier, alloc_scal, alloc_scal_inv)?;

    verifier.verify(&proof, &g, &h, &G, &H)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::get_generators;

    #[test]
    fn test_non_zero_gadget() {
        use rand::rngs::OsRng;
        use rand::Rng;

        let mut rng = rand::thread_rng();

        let value = FieldElement::random();

        let G: G1Vector = get_generators("G", 32).into();
        let H: G1Vector = get_generators("H", 32).into();
        let g = G1::from_msg_hash("g".as_bytes());
        let h = G1::from_msg_hash("h".as_bytes());

        let label = b"NonZero";
        let (proof, commitments) =
            gen_proof_of_non_zero_val(value, None, Some(&mut rng), label, &g, &h, &G, &H).unwrap();

        verify_proof_of_non_zero_val(proof, commitments, label, &g, &h, &G, &H).unwrap();
    }
}
