// Proof of knowledge of signature

use crate::errors::PSError;
use crate::keys::Verkey;
use crate::signature::Signature;
use crate::{ate_2_pairing, OtherGroup, OtherGroupVec, SignatureGroup, SignatureGroupVec};
use amcl_wrapper::field_elem::{FieldElement, FieldElementVector};
use amcl_wrapper::group_elem::{GroupElement, GroupElementVector};
use amcl_wrapper::group_elem_g1::{G1Vector, G1};
use amcl_wrapper::group_elem_g2::{G2Vector, G2};
use std::collections::{HashMap, HashSet};

// Implement proof of knowledge of committed values in a vector commitment for `SignatureGroup` and `OtherGroup`

impl_PoK_VC!(
    ProverCommittingSignatureGroup,
    ProverCommittedSignatureGroup,
    ProofSignatureGroup,
    SignatureGroup,
    SignatureGroupVec
);
impl_PoK_VC!(
    ProverCommittingOtherGroup,
    ProverCommittedOtherGroup,
    ProofOtherGroup,
    OtherGroup,
    OtherGroupVec
);

/*
As section 6.2 describes, for proving knowledge of a signature, the signature sigma is first randomized and also
transformed into a sequential aggregate signature with extra message t for public key g_tilde (and secret key 1).
1. Say the signature sigma is transformed to sigma_prime = (sigma_prime_1, sigma_prime_2) like step 1 in 6.2
1. The prover then sends sigma_prime and the value J = X_tilde * Y_tilde_1^m1 * Y_tilde_2^m2 * ..... * g_tilde^t and the proof J is formed correctly.
The verifier now checks whether e(sigma_prime_1, J) == e(sigma_prime_2, g_tilde)

To reveal some of the messages from the signature but not all, in above protocol, construct J to be of the hidden values only, the verifier will
then add the revealed values (raised to the respective generators) to get a final J which will then be used in the pairing check.
*/
pub struct PoKOfSignature {
    pub secrets: FieldElementVector,
    pub sig: Signature,
    pub J: OtherGroup,
    pub pok_vc: ProverCommittedOtherGroup,
}

pub struct PoKOfSignatureProof {
    pub sig: Signature,
    pub J: OtherGroup,
    pub proof_vc: ProofOtherGroup,
}

impl PoKOfSignature {
    /// Section 6.2 of paper
    pub fn init(
        sig: &Signature,
        vk: &Verkey,
        messages: &[FieldElement],
        revealed_msg_indices: HashSet<usize>,
    ) -> Result<Self, PSError> {
        for idx in &revealed_msg_indices {
            if *idx >= messages.len() {
                return Err(PSError::GeneralError {
                    msg: format!("Index {} should be less than {}", idx, messages.len()),
                });
            }
        }
        Signature::check_verkey_and_messages_compat(messages, vk)?;
        let r = FieldElement::random();
        let t = FieldElement::random();

        // Transform signature to an aggregate signature on (messages, t)
        let sigma_prime_1 = &sig.sigma_1 * &r;
        let sigma_prime_2 = (&sig.sigma_2 + (&sig.sigma_1 * &t)) * &r;

        let mut bases = OtherGroupVec::with_capacity(vk.Y_tilde.len() + 2);
        let mut exponents = FieldElementVector::with_capacity(vk.Y_tilde.len() + 2);
        bases.push(vk.X_tilde.clone());
        exponents.push(FieldElement::one());
        bases.push(vk.g_tilde.clone());
        exponents.push(t.clone());
        for i in 0..vk.Y_tilde.len() {
            if revealed_msg_indices.contains(&i) {
                continue;
            }
            bases.push(vk.Y_tilde[i].clone());
            exponents.push(messages[i].clone());
        }
        // J = X_tilde * Y_tilde_1^m1 * Y_tilde_2^m2 * ..... * g_tilde^t
        let J = bases.multi_scalar_mul_const_time(&exponents).unwrap();

        // For proving knowledge of messages in J.
        let mut committing = ProverCommittingOtherGroup::new();
        for b in bases.as_slice() {
            committing.commit(b, None);
        }
        let committed = committing.finish();

        let sigma_prime = Signature {
            sigma_1: sigma_prime_1,
            sigma_2: sigma_prime_2,
        };
        Ok(Self {
            secrets: exponents,
            sig: sigma_prime,
            J,
            pok_vc: committed,
        })
    }

    pub fn gen_proof(self, challenge: &FieldElement) -> Result<PoKOfSignatureProof, PSError> {
        let proof_vc = self.pok_vc.gen_proof(challenge, self.secrets.as_slice())?;
        Ok(PoKOfSignatureProof {
            sig: self.sig,
            J: self.J,
            proof_vc,
        })
    }
}

impl PoKOfSignatureProof {
    pub fn verify(
        &self,
        vk: &Verkey,
        revealed_msgs: HashMap<usize, FieldElement>,
        challenge: &FieldElement,
    ) -> Result<bool, PSError> {
        vk.validate()?;
        let mut bases = OtherGroupVec::with_capacity(vk.Y_tilde.len() + 2);
        bases.push(vk.X_tilde.clone());
        bases.push(vk.g_tilde.clone());
        for i in 0..vk.Y_tilde.len() {
            if revealed_msgs.contains_key(&i) {
                continue;
            }
            bases.push(vk.Y_tilde[i].clone());
        }
        if !self.proof_vc.verify(bases.as_slice(), &self.J, challenge)? {
            return Ok(false);
        }
        // e(sigma_prime_1, J) == e(sigma_prime_2, g_tilde) => e(sigma_prime_1, J) * e(sigma_prime_2, g_tilde^-1) == 1
        let neg_g_tilde = vk.g_tilde.negation();
        let mut j = OtherGroup::new();
        let J = if revealed_msgs.is_empty() {
            &self.J
        } else {
            j = self.J.clone();
            let mut b = OtherGroupVec::with_capacity(revealed_msgs.len());
            let mut e = FieldElementVector::with_capacity(revealed_msgs.len());
            for (i, m) in revealed_msgs {
                b.push(vk.Y_tilde[i].clone());
                e.push(m.clone());
            }
            j += b.multi_scalar_mul_var_time(&e).unwrap();
            &j
        };
        let res = ate_2_pairing(&self.sig.sigma_1, J, &self.sig.sigma_2, &neg_g_tilde);
        Ok(res.is_one())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // For benchmarking
    use crate::keys::keygen;
    use std::time::{Duration, Instant};

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
    fn test_PoK_VC_OtherGroup() {
        let n = 5;

        test_PoK_VC!(
            n,
            ProverCommittingOtherGroup,
            ProverCommittedOtherGroup,
            ProofOtherGroup,
            OtherGroup,
            OtherGroupVec
        );
    }

    #[test]
    fn test_sig_committed_messages() {
        let count_msgs = 5;
        let committed_msgs = 2;
        let (sk, vk) = keygen(count_msgs, "test".as_bytes());
        let msgs = FieldElementVector::random(count_msgs);
        let blinding = FieldElement::random();

        // User commits to messages
        // XXX: In production always use multi-scalar multiplication
        let mut comm = SignatureGroup::new();
        for i in 0..committed_msgs {
            comm += (&vk.Y[i] * &msgs[i]);
        }
        comm += (&vk.g * &blinding);

        // User and signer engage in a proof of knowledge for the above commitment `comm`
        let mut bases = Vec::<SignatureGroup>::new();
        let mut hidden_msgs = Vec::<FieldElement>::new();
        for i in 0..committed_msgs {
            bases.push(vk.Y[i].clone());
            hidden_msgs.push(msgs[i].clone());
        }
        bases.push(vk.g.clone());
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

        let sig_blinded = Signature::new_with_committed_attributes(
            &comm,
            &msgs.as_slice()[committed_msgs..count_msgs],
            &sk,
            &vk,
        )
        .unwrap();
        let sig_unblinded = sig_blinded.get_unblinded_signature(&blinding);
        assert!(sig_unblinded.verify(msgs.as_slice(), &vk).unwrap());
    }

    #[test]
    fn test_PoK_sig() {
        let count_msgs = 5;
        let (sk, vk) = keygen(count_msgs, "test".as_bytes());
        let msgs = FieldElementVector::random(count_msgs);
        let sig = Signature::new(msgs.as_slice(), &sk, &vk).unwrap();
        assert!(sig.verify(msgs.as_slice(), &vk).unwrap());

        let mut bases = OtherGroupVec::with_capacity(vk.Y_tilde.len() + 2);
        bases.push(vk.X_tilde.clone());
        bases.push(vk.g_tilde.clone());
        for i in 0..vk.Y_tilde.len() {
            bases.push(vk.Y_tilde[i].clone());
        }

        let pok = PoKOfSignature::init(&sig, &vk, msgs.as_slice(), HashSet::new()).unwrap();

        let chal = pok.pok_vc.gen_challenge(pok.J.to_bytes());

        let proof = pok.gen_proof(&chal).unwrap();

        assert!(proof.verify(&vk, HashMap::new(), &chal).unwrap());
    }

    #[test]
    fn test_PoK_sig_reveal_messages() {
        let count_msgs = 10;
        let (sk, vk) = keygen(count_msgs, "test".as_bytes());
        let msgs = FieldElementVector::random(count_msgs);
        let sig = Signature::new(msgs.as_slice(), &sk, &vk).unwrap();
        assert!(sig.verify(msgs.as_slice(), &vk).unwrap());

        let mut revealed_msg_indices = HashSet::new();
        revealed_msg_indices.insert(2);
        revealed_msg_indices.insert(4);
        revealed_msg_indices.insert(9);

        let mut bases = OtherGroupVec::with_capacity(vk.Y_tilde.len() + 2);
        bases.push(vk.X_tilde.clone());
        bases.push(vk.g_tilde.clone());
        for i in 0..vk.Y_tilde.len() {
            if revealed_msg_indices.contains(&i) {
                continue;
            }
            bases.push(vk.Y_tilde[i].clone());
        }

        let pok =
            PoKOfSignature::init(&sig, &vk, msgs.as_slice(), revealed_msg_indices.clone()).unwrap();

        let chal = pok.pok_vc.gen_challenge(pok.J.to_bytes());

        let proof = pok.gen_proof(&chal).unwrap();

        let mut revealed_msgs = HashMap::new();
        for i in &revealed_msg_indices {
            revealed_msgs.insert(i.clone(), msgs[*i].clone());
        }
        assert!(proof.verify(&vk, revealed_msgs.clone(), &chal).unwrap());

        // Reveal wrong message
        let mut revealed_msgs_1 = revealed_msgs.clone();
        revealed_msgs_1.insert(2, FieldElement::random());
        assert!(!proof.verify(&vk, revealed_msgs_1.clone(), &chal).unwrap());
    }
}
