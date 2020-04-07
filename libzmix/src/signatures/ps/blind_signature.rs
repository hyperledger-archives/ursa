// Scheme defined in section 6.1 supporting blind signatures

use super::errors::{PSError, PSErrorKind};
use super::keys::{Params, Sigkey};
use super::signature::Signature;
use super::{SignatureGroup, SignatureGroupVec};
use crate::commitments::pok_vc::{PoKVCError, PoKVCErrorKind};
use amcl_wrapper::field_elem::{FieldElement, FieldElementVector};
use amcl_wrapper::group_elem::{GroupElement, GroupElementVector};
use signatures::ps::SIGNATURE_GROUP_SIZE;

// The public key described in the paper is split into `BlindingKey` and `Verkey`. Only `Verkey` is
// needed by the verifier. `BlindingKey` is used by the user to request a blind signature.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlindingKey {
    pub X: SignatureGroup,
    pub Y: Vec<SignatureGroup>,
}

impl BlindingKey {
    pub fn new(sig_key: &Sigkey, params: &Params) -> Self {
        let X = &params.g * &sig_key.x;
        let mut Y = vec![];
        for i in 0..sig_key.y.len() {
            Y.push(&params.g * &sig_key.y[i]);
        }
        Self { X, Y }
    }

    pub fn msg_count(&self) -> usize {
        self.Y.len()
    }
}

// Implement proof of knowledge of committed values in a vector commitment for `SignatureGroup`
impl_PoK_VC!(
    ProverCommittingSignatureGroup,
    ProverCommittedSignatureGroup,
    ProofSignatureGroup,
    SignatureGroup,
    SignatureGroupVec,
    SIGNATURE_GROUP_SIZE
);

pub struct BlindSignature {}

impl BlindSignature {
    /// 1 or more messages are captured in a commitment `commitment`. The remaining known messages are in `messages`.
    /// The signing key `sigkey` differs from paper, it does not contain one group element but is the same as
    /// signing key described in the scheme from section 4.2
    /// The signing process differs slightly from the paper but results in the same signature. An example to illustrate the difference:
    /// Lets say the signer wants to sign a multi-message of 10 messages where only 1 message is blinded.
    /// If we go by the paper where signer does not have y_1, y_2, .. y_10, signer will pick a random u and compute signature as
    /// (g^u, (XC)^u.Y_2^u.m_2.Y_3^u.m_3...Y_10^u.m_10), Y_1 is omitted as the first message was blinded. Of course the term
    /// (XC)^u.Y_2^u.Y_3^u...Y_10^u can be computed using efficient multi-exponentiation techniques but it would be more efficient
    /// if the signer could instead compute (g^u, C^u.g^{(x+y_2.m_2+y_3.m_3+...y_10.m_10).u}). The resulting signature will have the same form
    /// and can be unblinded in the same way as described in the paper.
    pub fn new(
        commitment: &SignatureGroup,
        messages: &[FieldElement],
        sigkey: &Sigkey,
        blinding_key: &BlindingKey,
        params: &Params,
    ) -> Result<Signature, PSError> {
        // There should be commitment to at least one message
        Self::check_blinding_key_and_messages_compat(messages, blinding_key)?;

        let u = FieldElement::random();
        let offset = blinding_key.Y.len() - messages.len();
        let (sigma_1, mut sigma_2) = Signature::sign_with_sigma_1_generated_from_given_exp(
            messages, sigkey, &u, offset, &params.g,
        )?;
        sigma_2 += commitment * &u;
        Ok(Signature { sigma_1, sigma_2 })
    }

    /// Scheme as described in the paper
    pub fn new_from_paper(
        commitment: &SignatureGroup,
        messages: &[FieldElement],
        sigkey_X: &SignatureGroup, // The signing key consists of a single group element
        blinding_key: &BlindingKey,
        params: &Params,
    ) -> Result<Signature, PSError> {
        // There should be commitment to at least one message
        Self::check_blinding_key_and_messages_compat(messages, blinding_key)?;

        let u = FieldElement::random();

        // sigma_1 = g^u
        let sigma_1 = &params.g * &u;

        // sigma_2 = {X + Y_i^{m_i} + commitment}^u
        let mut points = SignatureGroupVec::with_capacity(messages.len());
        let mut scalars = FieldElementVector::with_capacity(messages.len());
        let offset = blinding_key.Y.len() - messages.len();
        for i in 0..messages.len() {
            scalars.push(messages[i].clone());
            points.push(blinding_key.Y[offset + i].clone());
        }

        let mut sigma_2 = sigkey_X
            + &points
                .multi_scalar_mul_const_time(scalars.as_slice())
                .unwrap();
        sigma_2 += commitment;
        sigma_2 = &sigma_2 * &u;
        Ok(Signature { sigma_1, sigma_2 })
    }

    /// Once signature on committed attributes (blind signature) is received, the signature needs to be unblinded.
    /// Takes the blinding used in the commitment.
    pub fn unblind(sig: &Signature, blinding: &FieldElement) -> Signature {
        let sigma_1 = sig.sigma_1.clone();
        let sigma_1_t = &sigma_1 * blinding;
        let sigma_2 = &sig.sigma_2 - sigma_1_t;
        Signature { sigma_1, sigma_2 }
    }

    pub fn check_blinding_key_and_messages_compat(
        messages: &[FieldElement],
        blinding_key: &BlindingKey,
    ) -> Result<(), PSError> {
        if messages.len() >= blinding_key.Y.len() {
            return Err(PSErrorKind::UnsupportedNoOfMessages {
                expected: messages.len(),
                given: blinding_key.Y.len(),
            }
            .into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::keys::keygen;
    use super::*;
    use amcl_wrapper::field_elem::FieldElementVector;
    use amcl_wrapper::group_elem::GroupElement;
    // For benchmarking
    use std::time::{Duration, Instant};

    #[test]
    fn test_blinding_key() {
        let count_msgs = 5;
        let params = Params::new("test".as_bytes());
        let (_, sk) = keygen(count_msgs, &params);
        let blinding_key = BlindingKey::new(&sk, &params);
        assert_eq!(blinding_key.Y.len(), count_msgs);
    }

    #[test]
    fn test_PoK_VC_SignatureGroup() {
        let n = 5;

        test_PoK_VC!(
            n,
            ProverCommittingSignatureGroup,
            ProverCommittedSignatureGroup,
            ProofSignatureGroup,
            SignatureGroup,
            SignatureGroupVec
        );
    }

    #[test]
    fn test_signature_single_blinded_message() {
        // Only 1 blinded message, no message known to signer
        let params = Params::new("test".as_bytes());
        for _ in 0..10 {
            let count_msgs = 1;
            let (vk, sk) = keygen(count_msgs, &params);

            let blinding_key = BlindingKey::new(&sk, &params);
            let msg = FieldElement::random();
            let blinding = FieldElement::random();

            // commitment = Y[0]^msg * g^blinding
            let comm = (&blinding_key.Y[0] * &msg) + (&params.g * &blinding);

            let sig_blinded = BlindSignature::new(&comm, &[], &sk, &blinding_key, &params).unwrap();
            let sig_unblinded = BlindSignature::unblind(&sig_blinded, &blinding);
            assert!(sig_unblinded.verify(&[msg], &vk, &params).unwrap());
        }
    }

    #[test]
    fn test_signature_many_blinded_messages() {
        let params = Params::new("test".as_bytes());
        for i in 0..10 {
            let count_msgs = (i % 5) + 1;
            let (vk, sk) = keygen(count_msgs, &params);

            let blinding_key = BlindingKey::new(&sk, &params);
            let msgs = FieldElementVector::random(count_msgs);
            let blinding = FieldElement::random();

            // XXX: In production always use multi-scalar multiplication
            let mut comm = SignatureGroup::new();
            for i in 0..count_msgs {
                comm += &blinding_key.Y[i] * &msgs[i];
            }
            comm += &params.g * &blinding;
            let sig_blinded = BlindSignature::new(&comm, &[], &sk, &blinding_key, &params).unwrap();
            let sig_unblinded = BlindSignature::unblind(&sig_blinded, &blinding);
            assert!(sig_unblinded.verify(msgs.as_slice(), &vk, &params).unwrap());
        }
    }

    #[test]
    fn test_signature_known_and_blinded_messages() {
        let params = Params::new("test".as_bytes());
        for i in 0..10 {
            let count_msgs = (i % 6) + 1;
            let count_blinded_msgs = (i % count_msgs) + 1;
            let (vk, sk) = keygen(count_msgs, &params);

            let blinding_key = BlindingKey::new(&sk, &params);
            let msgs = FieldElementVector::random(count_msgs);
            let blinding = FieldElement::random();

            // XXX: In production always use multi-scalar multiplication
            let mut comm = SignatureGroup::new();
            for i in 0..count_blinded_msgs {
                comm += &blinding_key.Y[i] * &msgs[i];
            }
            comm += &params.g * &blinding;

            let sig_blinded = BlindSignature::new(
                &comm,
                &msgs.as_slice()[count_blinded_msgs..count_msgs],
                &sk,
                &blinding_key,
                &params,
            )
            .unwrap();
            let sig_unblinded = BlindSignature::unblind(&sig_blinded, &blinding);
            assert!(sig_unblinded.verify(msgs.as_slice(), &vk, &params).unwrap());
        }
    }

    #[test]
    fn test_signature_blinded_messages() {
        let count_msgs = 5;
        let count_blinded_msgs = 2;
        let params = Params::new("test".as_bytes());
        let (vk, sk) = keygen(count_msgs, &params);
        let sk_X = &params.g * &sk.x;

        let blinding_key = BlindingKey::new(&sk, &params);
        let msgs = FieldElementVector::random(count_msgs);
        let blinding = FieldElement::random();

        // User commits to messages
        // XXX: In production always use multi-scalar multiplication
        let mut comm = SignatureGroup::new();
        for i in 0..count_blinded_msgs {
            comm += &blinding_key.Y[i] * &msgs[i];
        }
        comm += &params.g * &blinding;

        // User and signer engage in a proof of knowledge for the above commitment `comm`
        let mut bases = Vec::<SignatureGroup>::new();
        let mut hidden_msgs = Vec::<FieldElement>::new();
        for i in 0..count_blinded_msgs {
            bases.push(blinding_key.Y[i].clone());
            hidden_msgs.push(msgs[i].clone());
        }
        bases.push(params.g.clone());
        hidden_msgs.push(blinding.clone());

        // User creates a random commitment, computes challenge and response. The proof of knowledge consists of commitment and responses
        let mut committing = ProverCommittingSignatureGroup::new();
        for b in &bases {
            committing.commit(b, None);
        }
        let committed = committing.finish();

        // Note: The challenge may come from the main protocol
        let chal = committed.gen_challenge(comm.to_bytes());

        let proof = committed.gen_proof(&chal, hidden_msgs.as_slice()).unwrap();

        // Signer verifies the proof of knowledge.
        assert!(proof.verify(bases.as_slice(), &comm, &chal).unwrap());

        let sig_blinded = BlindSignature::new(
            &comm,
            &msgs.as_slice()[count_blinded_msgs..count_msgs],
            &sk,
            &blinding_key,
            &params,
        )
        .unwrap();
        let sig_unblinded = BlindSignature::unblind(&sig_blinded, &blinding);
        assert!(sig_unblinded.verify(msgs.as_slice(), &vk, &params).unwrap());

        let sig_blinded_paper = BlindSignature::new_from_paper(
            &comm,
            &msgs.as_slice()[count_blinded_msgs..count_msgs],
            &sk_X,
            &blinding_key,
            &params,
        )
        .unwrap();
        let sig_unblinded_paper = BlindSignature::unblind(&sig_blinded_paper, &blinding);
        assert!(sig_unblinded_paper
            .verify(msgs.as_slice(), &vk, &params)
            .unwrap());
    }

    #[test]
    fn test_blinded_sig_with_incorrect_no_of_messages_and_verkey_elements() {
        let params = Params::new("test".as_bytes());
        let (_, sk) = keygen(5, &params);
        let blinding_key = BlindingKey::new(&sk, &params);

        let msgs_1 = FieldElementVector::random(5);
        let blinding = FieldElement::random();

        // No of messages should be at least one less than size of blinding_key.Y
        assert!(BlindSignature::new(
            &SignatureGroup::random(),
            &msgs_1.as_slice(),
            &sk,
            &blinding_key,
            &params
        )
        .is_err());

        // More messages than supported by blinding_key
        let mut comm = SignatureGroup::new();
        for i in 0..5 {
            comm += &blinding_key.Y[i] * &msgs_1[i];
        }
        comm += &params.g * &blinding;
        let msgs_2 = FieldElementVector::random(6);
        assert!(
            BlindSignature::new(&comm, &msgs_2.as_slice(), &sk, &blinding_key, &params).is_err()
        );
    }

    #[test]
    fn timing_signature_over_known_and_committed_messages() {
        // Measure time to create and verify signatures. Verifying time will include time to unblind the signature as well.
        let iterations = 100;
        let count_msgs = 10;
        let count_blinded_msgs = 3;
        let params = Params::new("test".as_bytes());

        let (vk, sk) = keygen(count_msgs, &params);

        let blinding_key = BlindingKey::new(&sk, &params);

        let mut total_signing = Duration::new(0, 0);
        let mut total_verifying = Duration::new(0, 0);
        for _ in 0..iterations {
            let msgs = FieldElementVector::random(count_msgs);
            let blinding = FieldElement::random();
            // XXX: In production always use multi-scalar multiplication
            let mut comm = SignatureGroup::new();
            for i in 0..count_blinded_msgs {
                comm += &blinding_key.Y[i] * &msgs[i];
            }
            comm += &params.g * &blinding;

            let start = Instant::now();
            let sig_blinded = BlindSignature::new(
                &comm,
                &msgs.as_slice()[count_blinded_msgs..count_msgs],
                &sk,
                &blinding_key,
                &params,
            )
            .unwrap();
            total_signing += start.elapsed();

            let start = Instant::now();
            let sig_unblinded = BlindSignature::unblind(&sig_blinded, &blinding);
            assert!(sig_unblinded.verify(msgs.as_slice(), &vk, &params).unwrap());
            total_verifying += start.elapsed();
        }

        println!(
            "Time to create {} signatures is {:?}",
            iterations, total_signing
        );
        println!(
            "Time to verify {} signatures is {:?}",
            iterations, total_verifying
        );
    }

    #[test]
    fn timing_comparison_for_both_blind_signature_schemes() {
        let iterations = 100;
        let count_msgs = 10;
        let count_blinded_msgs = 3;
        let params = Params::new("test".as_bytes());

        let (vk, sk) = keygen(count_msgs, &params);
        let sk_X = &params.g * &sk.x;

        let blinding_key = BlindingKey::new(&sk, &params);

        let mut total_signing_modified = Duration::new(0, 0);
        let mut total_signing_paper = Duration::new(0, 0);
        let mut total_verifying = Duration::new(0, 0);
        for _ in 0..iterations {
            let msgs = FieldElementVector::random(count_msgs);
            let blinding = FieldElement::random();
            // XXX: In production always use multi-scalar multiplication
            let mut comm = SignatureGroup::new();
            for i in 0..count_blinded_msgs {
                comm += &blinding_key.Y[i] * &msgs[i];
            }
            comm += &params.g * &blinding;

            let start = Instant::now();
            let sig_blinded = BlindSignature::new(
                &comm,
                &msgs.as_slice()[count_blinded_msgs..count_msgs],
                &sk,
                &blinding_key,
                &params,
            )
            .unwrap();
            total_signing_modified += start.elapsed();

            let start = Instant::now();
            let sig_blinded_paper = BlindSignature::new_from_paper(
                &comm,
                &msgs.as_slice()[count_blinded_msgs..count_msgs],
                &sk_X,
                &blinding_key,
                &params,
            )
            .unwrap();
            total_signing_paper += start.elapsed();

            let start = Instant::now();
            let sig_unblinded = BlindSignature::unblind(&sig_blinded, &blinding);
            assert!(sig_unblinded.verify(msgs.as_slice(), &vk, &params).unwrap());
            total_verifying += start.elapsed();

            let sig_unblinded_paper = BlindSignature::unblind(&sig_blinded_paper, &blinding);
            assert!(sig_unblinded_paper
                .verify(msgs.as_slice(), &vk, &params)
                .unwrap());
        }

        println!(
            "Time to create {} signatures with modified scheme is {:?}",
            iterations, total_signing_modified
        );
        println!(
            "Time to create {} signatures with scheme as in the paper is {:?}",
            iterations, total_signing_paper
        );
        println!(
            "Time to verify {} signatures is {:?}",
            iterations, total_verifying
        );
    }
}
