// Proof of knowledge of signature

use super::errors::{PSError, PSErrorKind};
use super::keys::Verkey;
use super::signature::Signature;
use super::{ate_2_pairing, OtherGroup, OtherGroupVec};
use crate::commitments::pok_vc::{PoKVCError, PoKVCErrorKind};
use amcl_wrapper::field_elem::{FieldElement, FieldElementVector};
use amcl_wrapper::group_elem::{GroupElement, GroupElementVector};
use signatures::ps::{keys::Params, SIGNATURE_GROUP_SIZE};
use std::collections::{HashMap, HashSet};

// Implement proof of knowledge of committed values in a vector commitment for `SignatureGroup`

impl_PoK_VC!(
    ProverCommittingOtherGroup,
    ProverCommittedOtherGroup,
    ProofOtherGroup,
    OtherGroup,
    OtherGroupVec,
    SIGNATURE_GROUP_SIZE
);

/*
As section 6.2 describes, for proving knowledge of a signature, the signature sigma is first randomized and also
transformed into a sequential aggregate signature with extra message t for public key g_tilde (and secret key 1).
1. Say the signature sigma is transformed to sigma_prime = (sigma_prime_1, sigma_prime_2) like step 1 in 6.2
1. The prover then sends sigma_prime and the value J = X_tilde * Y_tilde_1^m1 * Y_tilde_2^m2 * ..... * g_tilde^t and the proof J is formed correctly.
The verifier now checks whether e(sigma_prime_1, J) == e(sigma_prime_2, g_tilde). Since X_tilde is known,
the verifier can send following a modified value J' where J' = Y_tilde_1^m_1 * Y_tilde_2^m_2 * ..... * g_tilde^t with the proof of knowledge of elements of J'.
The verifier will then check the pairing e(sigma_prime_1, J'*X_tilde) == e(sigma_prime_2, g_tilde).

To reveal some of the messages from the signature but not all, in above protocol, construct J to be of the hidden values only, the verifier will
then add the revealed values (raised to the respective generators) to get a final J which will then be used in the pairing check.
*/
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PoKOfSignature {
    pub secrets: FieldElementVector,
    pub sig: Signature,
    pub J: OtherGroup,
    pub pok_vc: ProverCommittedOtherGroup,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PoKOfSignatureProof {
    // This is the randomized signature.
    pub sig: Signature,
    pub J: OtherGroup,
    pub proof_vc: ProofOtherGroup,
}

impl PoKOfSignature {
    /// Section 6.2 of paper
    pub fn init(
        sig: &Signature,
        vk: &Verkey,
        params: &Params,
        messages: &[FieldElement],
        blindings: Option<&[FieldElement]>,
        revealed_msg_indices: HashSet<usize>,
    ) -> Result<Self, PSError> {
        for idx in &revealed_msg_indices {
            if *idx >= messages.len() {
                return Err(PSErrorKind::GeneralError {
                    msg: format!("Index {} should be less than {}", idx, messages.len()),
                }
                .into());
            }
        }
        Signature::check_verkey_and_messages_compat(messages, vk)?;
        let mut blindings: Vec<Option<&FieldElement>> = match blindings {
            Some(b) => {
                if (messages.len() - revealed_msg_indices.len()) != b.len() {
                    return Err(PSErrorKind::GeneralError {
                        msg: format!(
                            "No of blindings {} not equal to number of hidden messages {}",
                            b.len(),
                            (messages.len() - revealed_msg_indices.len())
                        ),
                    }
                    .into());
                }
                b.iter().map(Some).collect()
            }
            None => (0..(messages.len() - revealed_msg_indices.len()))
                .map(|_| None)
                .collect(),
        };

        let r = FieldElement::random();
        let t = FieldElement::random();

        // Transform signature to an aggregate signature on (messages, t)
        let sigma_prime_1 = &sig.sigma_1 * &r;
        let sigma_prime_2 = (&sig.sigma_2 + (&sig.sigma_1 * &t)) * &r;

        // +1 for `t`
        let hidden_msg_count = vk.Y_tilde.len() - revealed_msg_indices.len() + 1;
        let mut bases = OtherGroupVec::with_capacity(hidden_msg_count);
        let mut exponents = FieldElementVector::with_capacity(hidden_msg_count);
        bases.push(params.g_tilde.clone());
        exponents.push(t.clone());
        for i in 0..vk.Y_tilde.len() {
            if revealed_msg_indices.contains(&i) {
                continue;
            }
            bases.push(vk.Y_tilde[i].clone());
            exponents.push(messages[i].clone());
        }
        // Prove knowledge of m_1, m_2, ... for all hidden m_i and t in J = Y_tilde_1^m_1 * Y_tilde_2^m_2 * ..... * g_tilde^t
        let J = bases
            .multi_scalar_mul_const_time(exponents.as_slice())
            .unwrap();

        // For proving knowledge of messages in J.
        // Choose blinding for g_tilde randomly
        blindings.insert(0, None);
        let mut committing = ProverCommittingOtherGroup::new();
        for b in bases.as_slice() {
            committing.commit(b, blindings.remove(0));
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

    /// Return byte representation of public elements so they can be used for challenge computation.
    /// Takes bytes of the randomized signature, the "commitment" to non-revealed messages (J) and the
    /// generators and the commitment to randomness used in the proof of knowledge of "non-revealed" messages.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        bytes.append(&mut self.sig.to_bytes());
        bytes.append(&mut self.J.to_bytes());
        bytes.append(&mut self.pok_vc.to_bytes());
        bytes
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
    /// Return bytes that need to be hashed for generating challenge. Since the message only requires
    /// commitment to "non-revealed" messages of signature, generators of only those messages are
    /// to be considered for challenge creation.
    /// Takes bytes of the randomized signature, the "commitment" to non-revealed messages (J) and the
    /// generators and the commitment to randomness used in the proof of knowledge of "non-revealed" messages.
    pub fn get_bytes_for_challenge(
        &self,
        revealed_msg_indices: HashSet<usize>,
        vk: &Verkey,
        params: &Params,
    ) -> Vec<u8> {
        let mut bytes = vec![];
        bytes.append(&mut self.sig.to_bytes());
        bytes.append(&mut self.J.to_bytes());
        bytes.append(&mut params.g_tilde.to_bytes());
        for i in 0..vk.Y_tilde.len() {
            if revealed_msg_indices.contains(&i) {
                continue;
            }
            let mut b = vk.Y_tilde[i].to_bytes();
            bytes.append(&mut b);
        }
        bytes.append(&mut self.proof_vc.commitment.to_bytes());
        bytes
    }

    /// Get the response from post-challenge phase of the Sigma protocol for the given message index `msg_idx`.
    /// Used when comparing message equality
    pub fn get_resp_for_message(&self, msg_idx: usize) -> Result<FieldElement, PSError> {
        // 1 element in self.proof_vc.responses is reserved for the random `t`
        if msg_idx >= (self.proof_vc.responses.len() - 1) {
            return Err(PSErrorKind::GeneralError {
                msg: format!(
                    "Message index was given {} but should be less than {}",
                    msg_idx,
                    self.proof_vc.responses.len() - 1
                ),
            }
            .into());
        }
        // 1 added to the index, since 0th index is reserved for randomization (`t`)
        Ok(self.proof_vc.responses[1 + msg_idx].clone())
    }

    /// Verifies the proof. The verifier should generate the challenge on its own.
    pub fn verify(
        &self,
        vk: &Verkey,
        params: &Params,
        revealed_msgs: HashMap<usize, FieldElement>,
        challenge: &FieldElement,
    ) -> Result<bool, PSError> {
        if self.sig.sigma_1.is_identity() || self.sig.sigma_2.is_identity() {
            return Ok(false);
        }

        // +1 for `t`
        let hidden_msg_count = vk.Y_tilde.len() - revealed_msgs.len() + 1;
        let mut bases = OtherGroupVec::with_capacity(hidden_msg_count);
        bases.push(params.g_tilde.clone());
        for i in 0..vk.Y_tilde.len() {
            if revealed_msgs.contains_key(&i) {
                continue;
            }
            bases.push(vk.Y_tilde[i].clone());
        }
        if !self.proof_vc.verify(bases.as_slice(), &self.J, challenge)? {
            return Ok(false);
        }
        // e(sigma_prime_1, J*X_tilde) == e(sigma_prime_2, g_tilde) => e(sigma_prime_1, J*X_tilde) * e(sigma_prime_2^-1, g_tilde) == 1
        let mut j;
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
            j += b.multi_scalar_mul_var_time(e.as_slice()).unwrap();
            &j
        };
        // Slight optimization possible by precomputing inverse of g_tilde and storing to avoid inverse of sig.sigma_2
        let res = ate_2_pairing(
            &self.sig.sigma_1,
            &(J + &vk.X_tilde),
            &(-&self.sig.sigma_2),
            &params.g_tilde,
        );
        Ok(res.is_one())
    }
}

#[cfg(test)]
macro_rules! test_PoK_VC {
    ( $n:ident, $ProverCommitting:ident, $ProverCommitted:ident, $Proof:ident, $group_element:ident, $group_element_vec:ident ) => {
        let mut gens = $group_element_vec::with_capacity($n);
        let mut secrets = FieldElementVector::with_capacity($n);
        let mut commiting = $ProverCommitting::new();
        for _ in 0..$n - 1 {
            let g = $group_element::random();
            commiting.commit(&g, None);
            gens.push(g);
            secrets.push(FieldElement::random());
        }

        // Add one of the blindings externally
        let g = $group_element::random();
        let r = FieldElement::random();
        commiting.commit(&g, Some(&r));
        let (g_, r_) = commiting.get_index($n - 1).unwrap();
        assert_eq!(g, *g_);
        assert_eq!(r, *r_);
        gens.push(g);
        secrets.push(FieldElement::random());

        // Bound check for get_index
        assert!(commiting.get_index($n).is_err());
        assert!(commiting.get_index($n + 1).is_err());

        let committed = commiting.finish();
        let commitment = gens
            .multi_scalar_mul_const_time(secrets.as_slice())
            .unwrap();
        let challenge = committed.gen_challenge(commitment.to_bytes());
        let proof = committed.gen_proof(&challenge, secrets.as_slice()).unwrap();

        assert!(proof
            .verify(gens.as_slice(), &commitment, &challenge)
            .unwrap());

        // Unequal number of generators and responses
        let mut gens_1 = gens.clone();
        let g1 = $group_element::random();
        gens_1.push(g1);
        // More generators
        assert!(proof
            .verify(gens_1.as_slice(), &commitment, &challenge)
            .is_err());

        let mut gens_2 = gens.clone();
        gens_2.pop();
        // Less generators
        assert!(proof
            .verify(gens_2.as_slice(), &commitment, &challenge)
            .is_err());

        // Wrong commitment fails to verify
        assert!(!proof
            .verify(gens.as_slice(), &$group_element::random(), &challenge)
            .unwrap());
        // Wrong challenge fails to verify
        assert!(!proof
            .verify(gens.as_slice(), &commitment, &FieldElement::random())
            .unwrap());
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    // For benchmarking
    use super::super::keys::keygen;
    use std::time::{Duration, Instant};

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
    fn test_PoK_sig() {
        use signatures::ps::SignatureGroup;

        let count_msgs = 5;
        let params = Params::new("test".as_bytes());
        let (vk, sk) = keygen(count_msgs, &params);
        let msgs = FieldElementVector::random(count_msgs);
        let sig = Signature::new(msgs.as_slice(), &sk, &params).unwrap();
        assert!(sig.verify(msgs.as_slice(), &vk, &params).unwrap());

        let pok = PoKOfSignature::init(&sig, &vk, &params, msgs.as_slice(), None, HashSet::new())
            .unwrap();

        let chal = FieldElement::from_msg_hash(&pok.to_bytes());

        let proof = pok.gen_proof(&chal).unwrap();

        assert!(proof.verify(&vk, &params, HashMap::new(), &chal).unwrap());

        // Set signature elements to identity. Such signature should fail verification
        let mut proof_bad = proof.clone();
        proof_bad.sig.sigma_1 = SignatureGroup::identity();
        proof_bad.sig.sigma_2 = SignatureGroup::identity();
        assert!(!proof_bad
            .verify(&vk, &params, HashMap::new(), &chal)
            .unwrap());

        // PoK with supplied blindings
        let blindings = FieldElementVector::random(count_msgs);
        let pok_1 = PoKOfSignature::init(
            &sig,
            &vk,
            &params,
            msgs.as_slice(),
            Some(blindings.as_slice()),
            HashSet::new(),
        )
        .unwrap();
        let chal_prover = FieldElement::from_msg_hash(&pok_1.to_bytes());
        let proof_1 = pok_1.gen_proof(&chal_prover).unwrap();

        // The verifier generates the challenge on its own.
        let chal_bytes = proof_1.get_bytes_for_challenge(HashSet::new(), &vk, &params);
        let chal_verifier = FieldElement::from_msg_hash(&chal_bytes);
        assert!(proof_1
            .verify(&vk, &params, HashMap::new(), &chal_verifier)
            .unwrap());
    }

    #[test]
    fn test_PoK_sig_reveal_messages() {
        let count_msgs = 10;
        let params = Params::new("test".as_bytes());
        let (vk, sk) = keygen(count_msgs, &params);
        let msgs = FieldElementVector::random(count_msgs);
        let sig = Signature::new(msgs.as_slice(), &sk, &params).unwrap();
        assert!(sig.verify(msgs.as_slice(), &vk, &params).unwrap());

        let mut revealed_msg_indices = HashSet::new();
        revealed_msg_indices.insert(2);
        revealed_msg_indices.insert(4);
        revealed_msg_indices.insert(9);

        let pok = PoKOfSignature::init(
            &sig,
            &vk,
            &params,
            msgs.as_slice(),
            None,
            revealed_msg_indices.clone(),
        )
        .unwrap();

        let chal_prover = FieldElement::from_msg_hash(&pok.to_bytes());

        let proof = pok.gen_proof(&chal_prover).unwrap();

        let mut revealed_msgs = HashMap::new();
        for i in &revealed_msg_indices {
            revealed_msgs.insert(i.clone(), msgs[*i].clone());
        }

        // The verifier generates the challenge on its own.
        let chal_bytes = proof.get_bytes_for_challenge(revealed_msg_indices.clone(), &vk, &params);
        let chal_verifier = FieldElement::from_msg_hash(&chal_bytes);
        assert!(proof
            .verify(&vk, &params, revealed_msgs.clone(), &chal_verifier)
            .unwrap());

        // Reveal wrong message
        let mut revealed_msgs_1 = revealed_msgs.clone();
        revealed_msgs_1.insert(2, FieldElement::random());
        assert!(!proof
            .verify(&vk, &params, revealed_msgs_1.clone(), &chal_verifier)
            .unwrap());

        // PoK with supplied blindings
        let blindings = FieldElementVector::random(count_msgs - revealed_msg_indices.len());
        let pok_1 = PoKOfSignature::init(
            &sig,
            &vk,
            &params,
            msgs.as_slice(),
            Some(blindings.as_slice()),
            revealed_msg_indices.clone(),
        )
        .unwrap();
        let chal_prover = FieldElement::from_msg_hash(&pok_1.to_bytes());
        let proof_1 = pok_1.gen_proof(&chal_prover).unwrap();

        // The verifier generates the challenge on its own.
        let chal_bytes =
            proof_1.get_bytes_for_challenge(revealed_msg_indices.clone(), &vk, &params);
        let chal_verifier = FieldElement::from_msg_hash(&chal_bytes);
        assert!(proof_1
            .verify(&vk, &params, revealed_msgs.clone(), &chal_verifier)
            .unwrap());

        let blindings_more =
            FieldElementVector::random(count_msgs - revealed_msg_indices.len() + 1);
        assert!(PoKOfSignature::init(
            &sig,
            &vk,
            &params,
            msgs.as_slice(),
            Some(blindings_more.as_slice()),
            revealed_msg_indices.clone(),
        )
        .is_err());
        let blindings_less =
            FieldElementVector::random(count_msgs - revealed_msg_indices.len() - 1);
        assert!(PoKOfSignature::init(
            &sig,
            &vk,
            &params,
            msgs.as_slice(),
            Some(blindings_less.as_slice()),
            revealed_msg_indices.clone(),
        )
        .is_err());
    }

    #[test]
    fn test_PoK_sig_with_unequal_messages_and_verkey_elements() {
        let count_msgs = 5;
        let params = Params::new("test".as_bytes());
        let (vk, sk) = keygen(count_msgs, &params);
        let msgs = FieldElementVector::random(count_msgs);
        let sig = Signature::new(msgs.as_slice(), &sk, &params).unwrap();

        let bigger_msgs = FieldElementVector::random(count_msgs + 1);
        assert!(PoKOfSignature::init(
            &sig,
            &vk,
            &params,
            bigger_msgs.as_slice(),
            None,
            HashSet::new(),
        )
        .is_err());
    }

    #[test]
    fn test_PoK_sig_with_incorrect_reveal_indices() {
        let count_msgs = 5;
        let params = Params::new("test".as_bytes());
        let (vk, sk) = keygen(count_msgs, &params);
        let msgs = FieldElementVector::random(count_msgs);
        let sig = Signature::new(msgs.as_slice(), &sk, &params).unwrap();

        let mut hs = HashSet::new();
        hs.insert(count_msgs);
        assert!(PoKOfSignature::init(&sig, &vk, &params, msgs.as_slice(), None, hs).is_err());

        let mut hs = HashSet::new();
        hs.insert(count_msgs + 1);
        assert!(PoKOfSignature::init(&sig, &vk, &params, msgs.as_slice(), None, hs).is_err());

        let mut hs = HashSet::new();
        hs.insert(count_msgs - 1);
        assert!(PoKOfSignature::init(&sig, &vk, &params, msgs.as_slice(), None, hs).is_ok());
    }

    #[test]
    fn test_PoK_sig_with_verify_proof_error() {
        let count_msgs = 5;
        let params = Params::new("test".as_bytes());
        let (vk, sk) = keygen(count_msgs, &params);
        let msgs = FieldElementVector::random(count_msgs);
        let sig = Signature::new(msgs.as_slice(), &sk, &params).unwrap();

        let pok = PoKOfSignature::init(&sig, &vk, &params, msgs.as_slice(), None, HashSet::new())
            .unwrap();
        let chal_prover = FieldElement::from_msg_hash(&pok.to_bytes());
        let proof = pok.gen_proof(&chal_prover).unwrap();

        // The verifier generates the challenge on its own.
        let chal_bytes = proof.get_bytes_for_challenge(HashSet::new(), &vk, &params);
        let chal_verifier = FieldElement::from_msg_hash(&chal_bytes);

        // Verification fails with bad verkey
        let mut vk_1 = vk.clone();
        vk_1.Y_tilde.push(OtherGroup::new());
        assert!(proof
            .verify(&vk_1, &params, HashMap::new(), &chal_verifier)
            .is_err());

        // Verification passes with correct verkey
        assert!(proof
            .verify(&vk, &params, HashMap::new(), &chal_verifier)
            .unwrap());
    }

    #[test]
    fn test_PoK_multiple_sigs() {
        // Prove knowledge of multiple signatures together (using the same challenge)
        let count_msgs = 5;
        let params = Params::new("test".as_bytes());
        let (vk, sk) = keygen(count_msgs, &params);

        let msgs_1 = FieldElementVector::random(count_msgs);
        let sig_1 = Signature::new(msgs_1.as_slice(), &sk, &params).unwrap();
        assert!(sig_1.verify(msgs_1.as_slice(), &vk, &params).unwrap());

        let msgs_2 = FieldElementVector::random(count_msgs);
        let sig_2 = Signature::new(msgs_2.as_slice(), &sk, &params).unwrap();
        assert!(sig_2.verify(msgs_2.as_slice(), &vk, &params).unwrap());

        let pok_1 = PoKOfSignature::init(
            &sig_1,
            &vk,
            &params,
            msgs_1.as_slice(),
            None,
            HashSet::new(),
        )
        .unwrap();
        let pok_2 = PoKOfSignature::init(
            &sig_2,
            &vk,
            &params,
            msgs_2.as_slice(),
            None,
            HashSet::new(),
        )
        .unwrap();

        let mut chal_bytes = vec![];
        chal_bytes.append(&mut pok_1.to_bytes());
        chal_bytes.append(&mut pok_2.to_bytes());

        let chal_prover = FieldElement::from_msg_hash(&chal_bytes);

        let proof_1 = pok_1.gen_proof(&chal_prover).unwrap();
        let proof_2 = pok_2.gen_proof(&chal_prover).unwrap();

        // The verifier generates the challenge on its own.
        let mut chal_bytes = vec![];
        chal_bytes.append(&mut proof_1.get_bytes_for_challenge(HashSet::new(), &vk, &params));
        chal_bytes.append(&mut proof_2.get_bytes_for_challenge(HashSet::new(), &vk, &params));
        let chal_verifier = FieldElement::from_msg_hash(&chal_bytes);

        assert!(proof_1
            .verify(&vk, &params, HashMap::new(), &chal_verifier)
            .unwrap());
        assert!(proof_2
            .verify(&vk, &params, HashMap::new(), &chal_verifier)
            .unwrap());
    }

    #[test]
    fn test_PoK_multiple_sigs_with_same_msg() {
        // Prove knowledge of multiple signatures and the equality of a specific message under both signatures.
        // Knowledge of 2 signatures and their corresponding messages is being proven.
        // 2nd message in the 1st signature and 5th message in the 2nd signature are to be proven equal without revealing them

        let count_msgs = 5;
        let params = Params::new("test".as_bytes());
        let (vk, sk) = keygen(count_msgs, &params);

        let same_msg = FieldElement::random();
        let mut msgs_1 = FieldElementVector::random(count_msgs - 1);
        msgs_1.insert(1, same_msg.clone());
        let sig_1 = Signature::new(msgs_1.as_slice(), &sk, &params).unwrap();
        assert!(sig_1.verify(msgs_1.as_slice(), &vk, &params).unwrap());

        let mut msgs_2 = FieldElementVector::random(count_msgs - 1);
        msgs_2.insert(4, same_msg.clone());
        let sig_2 = Signature::new(msgs_2.as_slice(), &sk, &params).unwrap();
        assert!(sig_2.verify(msgs_2.as_slice(), &vk, &params).unwrap());

        // A particular message is same
        assert_eq!(msgs_1[1], msgs_2[4]);

        let same_blinding = FieldElement::random();

        let mut blindings_1 = FieldElementVector::random(count_msgs - 1);
        blindings_1.insert(1, same_blinding.clone());

        let mut blindings_2 = FieldElementVector::random(count_msgs - 1);
        blindings_2.insert(4, same_blinding.clone());

        // Blinding for the same message is kept same
        assert_eq!(blindings_1[1], blindings_2[4]);

        let pok_1 = PoKOfSignature::init(
            &sig_1,
            &vk,
            &params,
            msgs_1.as_slice(),
            Some(blindings_1.as_slice()),
            HashSet::new(),
        )
        .unwrap();
        let pok_2 = PoKOfSignature::init(
            &sig_2,
            &vk,
            &params,
            msgs_2.as_slice(),
            Some(blindings_2.as_slice()),
            HashSet::new(),
        )
        .unwrap();

        let mut chal_bytes = vec![];
        chal_bytes.append(&mut pok_1.to_bytes());
        chal_bytes.append(&mut pok_2.to_bytes());

        let chal_prover = FieldElement::from_msg_hash(&chal_bytes);

        let proof_1 = pok_1.gen_proof(&chal_prover).unwrap();
        let proof_2 = pok_2.gen_proof(&chal_prover).unwrap();

        // The verifier generates the challenge on its own.
        let mut chal_bytes = vec![];
        chal_bytes.append(&mut proof_1.get_bytes_for_challenge(HashSet::new(), &vk, &params));
        chal_bytes.append(&mut proof_2.get_bytes_for_challenge(HashSet::new(), &vk, &params));
        let chal_verifier = FieldElement::from_msg_hash(&chal_bytes);

        // Response for the same message should be same (this check is made by the verifier)
        // Response for the same message should be same (this check is made by the verifier)
        assert_eq!(
            proof_1.get_resp_for_message(1).unwrap(),
            proof_2.get_resp_for_message(4).unwrap()
        );

        assert!(proof_1
            .verify(&vk, &params, HashMap::new(), &chal_verifier)
            .unwrap());
        assert!(proof_2
            .verify(&vk, &params, HashMap::new(), &chal_verifier)
            .unwrap());
    }

    #[test]
    fn timing_pok_signature() {
        // Measure time to prove knowledge of signatures, both generation and verification of proof
        let iterations = 100;
        let count_msgs = 10;
        let params = Params::new("test".as_bytes());
        let (vk, sk) = keygen(count_msgs, &params);

        let msgs = FieldElementVector::random(count_msgs);
        let sig = Signature::new(msgs.as_slice(), &sk, &params).unwrap();

        let mut total_generating = Duration::new(0, 0);
        let mut total_verifying = Duration::new(0, 0);

        for _ in 0..iterations {
            let start = Instant::now();

            let pok =
                PoKOfSignature::init(&sig, &vk, &params, msgs.as_slice(), None, HashSet::new())
                    .unwrap();

            let chal_prover = FieldElement::from_msg_hash(&pok.to_bytes());

            let proof = pok.gen_proof(&chal_prover).unwrap();
            total_generating += start.elapsed();

            let start = Instant::now();
            // The verifier generates the challenge on its own.
            let chal_bytes = proof.get_bytes_for_challenge(HashSet::new(), &vk, &params);
            let chal_verifier = FieldElement::from_msg_hash(&chal_bytes);
            assert!(proof
                .verify(&vk, &params, HashMap::new(), &chal_verifier)
                .unwrap());
            total_verifying += start.elapsed();
        }

        println!(
            "Time to create {} proofs is {:?}",
            iterations, total_generating
        );
        println!(
            "Time to verify {} proofs is {:?}",
            iterations, total_verifying
        );
    }
}
