use super::helper_constraints::non_zero::is_nonzero_gadget;
use crate::errors::{R1CSError, R1CSErrorKind};
use crate::r1cs::{Prover, R1CSProof, Verifier};
use amcl_wrapper::field_elem::FieldElement;
use amcl_wrapper::group_elem_g1::{G1Vector, G1};
use merlin::Transcript;
use rand::{CryptoRng, Rng};

pub fn prove_non_zero_val<R: Rng + CryptoRng>(
    value: FieldElement,
    blinding: Option<FieldElement>,
    rng: Option<&mut R>,
    prover: &mut Prover,
) -> Result<Vec<G1>, R1CSError> {
    check_for_blindings_or_rng!(blinding, rng)?;

    let inv = value.inverse();
    let mut comms = vec![];

    let (com_val, var_val) = prover.commit(
        value,
        blinding.unwrap_or_else(|| FieldElement::random_using_rng(rng.unwrap())),
    );

    comms.push(com_val);

    let (com_val_inv, var_val_inv) = prover.commit(inv, FieldElement::random());

    comms.push(com_val_inv);

    is_nonzero_gadget(prover, var_val, var_val_inv)?;

    Ok(comms)
}

pub fn verify_non_zero_val(
    mut commitments: Vec<G1>,
    verifier: &mut Verifier,
) -> Result<(), R1CSError> {
    let var_val = verifier.commit(commitments.remove(0));

    let var_val_inv = verifier.commit(commitments.remove(0));

    is_nonzero_gadget(verifier, var_val, var_val_inv)?;

    Ok(())
}

/// Accepts the num which is to be proved non-zero and optionally the randomness used in committing to that number.
/// This randomness argument is accepted so that this can be used as a sub-protocol where the protocol on upper layer will create the commitment.
pub fn gen_proof_of_non_zero_val<R: Rng + CryptoRng>(
    value: FieldElement,
    blinding: Option<FieldElement>,
    rng: Option<&mut R>,
    transcript_label: &'static [u8],
    g: &G1,
    h: &G1,
    G: &G1Vector,
    H: &G1Vector,
) -> Result<(R1CSProof, Vec<G1>), R1CSError> {
    let mut prover_transcript = Transcript::new(transcript_label);
    let mut prover = Prover::new(g, h, &mut prover_transcript);

    let comms = prove_non_zero_val(value, blinding, rng, &mut prover)?;
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

    verify_non_zero_val(commitments, &mut verifier)?;
    verifier.verify(&proof, g, h, G, H)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::get_generators;
    use amcl_wrapper::group_elem::GroupElement;

    #[test]
    fn test_non_zero_gadget() {
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
