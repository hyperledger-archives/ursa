// Proof of knowledge of signature, committed values

use crate::errors::PSError;
use crate::keys::Verkey;
use crate::signature::Signature;
use crate::{ate_2_pairing, OtherGroup, OtherGroupVec, SignatureGroup, SignatureGroupVec};
use amcl_wrapper::field_elem::{FieldElement, FieldElementVector};
use amcl_wrapper::group_elem::{GroupElement, GroupElementVector};
use amcl_wrapper::group_elem_g1::{G1Vector, G1};
use amcl_wrapper::group_elem_g2::{G2Vector, G2};
use std::collections::{HashMap, HashSet};

// `ProverCommitting` will contains vectors of generators and random values.
// `ProverCommitting` has a `commit` method that optionally takes a value as blinding, if not provided, it creates its own.
// `ProverCommitting` has a `finish` method that results in creation of `ProverCommitted` object after consuming `ProverCommitting`
// `ProverCommitted` marks the end of commitment phase and has the final commitment.
// `ProverCommitted` has a method to generate the challenge by hashing all generators and commitment. It is optional
// to use this method as the challenge may come from a super-protocol or from verifier. It takes a vector of bytes that it includes for hashing for computing the challenge
// `ProverCommitted` has a method `gen_proof` to generate proof. It takes the secrets and the challenge to generate responses.
// During response generation `ProverCommitted` is consumed to create `Proof` object containing the commitments and responses.
// `Proof` can then be verified by the verifier.

/*pub struct ProverCommitting<'a, T: GroupElement> {
    gens: Vec<&'a T>,
    blindings: Vec<FieldElement>,
}

pub struct ProverCommitted<'a, T: GroupElement> {
    gens: Vec<&'a T>,
    blindings: Vec<FieldElement>,
    commitment: T
}

impl<'a, T> ProverCommitting<'a, T> where T: GroupElement {
    pub fn new() -> Self {
        Self {
            gens: vec![],
            blindings: vec![],
        }
    }

    pub fn commit(&mut self, gen: &'a T, blinding: Option<FieldElement>) -> usize {
        let blinding = match blinding {
            Some(b) => b,
            None => FieldElement::random()
        };
        let idx = self.gens.len();
        self.gens.push(gen);
        self.blindings.push(blinding);
        idx
    }

    pub fn finish(self) -> ProverCommitted<'a, T> {
        // XXX: Need multi-scalar multiplication to be implemented for GroupElementVector.
        // XXX: Also implement operator overloading for GroupElement.
        unimplemented!()
    }

    pub fn get_index(&self, idx: usize) -> Result<(&'a T, &FieldElement), PSError> {
        if idx >= self.gens.len() {
            return Err(PSError::GeneralError { msg: format!("index {} greater than size {}", idx, self.gens.len()) });
        }
        Ok((self.gens[idx], &self.blindings[idx]))
    }
}*/

macro_rules! impl_PoK_VC {
    ( $prover_committing:ident, $prover_committed:ident, $proof:ident, $group_element:ident, $group_element_vec:ident ) => {
        /// Proof of knowledge of messages in a vector commitment.
        /// Commit for each message.
        pub struct $prover_committing {
            gens: $group_element_vec,
            blindings: FieldElementVector,
        }

        /// Receive or generate challenge. Compute response and proof
        pub struct $prover_committed {
            gens: $group_element_vec,
            blindings: FieldElementVector,
            commitment: $group_element,
        }

        pub struct $proof {
            commitment: $group_element,
            responses: FieldElementVector,
        }

        impl $prover_committing {
            pub fn new() -> Self {
                Self {
                    gens: $group_element_vec::new(0),
                    blindings: FieldElementVector::new(0),
                }
            }

            /// generate a new random blinding if None provided
            pub fn commit(
                &mut self,
                gen: &$group_element,
                blinding: Option<&FieldElement>,
            ) -> usize {
                let blinding = match blinding {
                    Some(b) => b.clone(),
                    None => FieldElement::random(),
                };
                let idx = self.gens.len();
                self.gens.push(gen.clone());
                self.blindings.push(blinding);
                idx
            }

            /// Add pairwise product of (`self.gens`, self.blindings). Uses multi-exponentiation.
            pub fn finish(self) -> $prover_committed {
                let commitment = self
                    .gens
                    .multi_scalar_mul_const_time(&self.blindings)
                    .unwrap();
                $prover_committed {
                    gens: self.gens,
                    blindings: self.blindings,
                    commitment,
                }
            }

            pub fn get_index(
                &self,
                idx: usize,
            ) -> Result<(&$group_element, &FieldElement), PSError> {
                if idx >= self.gens.len() {
                    return Err(PSError::GeneralError {
                        msg: format!("index {} greater than size {}", idx, self.gens.len()),
                    });
                }
                Ok((&self.gens[idx], &self.blindings[idx]))
            }
        }

        impl $prover_committed {
            /// This step will be done by the main protocol for which this PoK is a sub-protocol
            pub fn gen_challenge(&self, mut extra: Vec<u8>) -> FieldElement {
                let mut bytes = vec![];
                for b in self.gens.as_slice() {
                    bytes.append(&mut b.to_bytes());
                }
                bytes.append(&mut self.commitment.to_bytes());
                bytes.append(&mut extra);
                FieldElement::from_msg_hash(&bytes)
            }

            /// For each secret, generate a response as self.blinding[i] - challenge*secrets[i].
            pub fn gen_proof(
                self,
                challenge: &FieldElement,
                secrets: &[FieldElement],
            ) -> Result<$proof, PSError> {
                if secrets.len() != self.gens.len() {
                    return Err(PSError::UnequalNoOfBasesExponents {
                        bases: self.gens.len(),
                        exponents: secrets.len(),
                    });
                }
                let mut responses = FieldElementVector::with_capacity(self.gens.len());
                for i in 0..self.gens.len() {
                    responses.push(&self.blindings[i] - (challenge * &secrets[i]));
                }
                Ok($proof {
                    commitment: self.commitment,
                    responses,
                })
            }
        }

        impl $proof {
            /// Verify that bases[0]^responses[0] * bases[0]^responses[0] * ... bases[i]^responses[i] * commitment^challenge == random_commitment
            pub fn verify(
                &self,
                bases: &[$group_element],
                commitment: &$group_element,
                challenge: &FieldElement,
            ) -> Result<bool, PSError> {
                // bases[0]^responses[0] * bases[0]^responses[0] * ... bases[i]^responses[i] * commitment^challenge == random_commitment
                // =>
                // bases[0]^responses[0] * bases[0]^responses[0] * ... bases[i]^responses[i] * commitment^challenge * random_commitment^-1 == 1
                let mut points = $group_element_vec::from(bases);
                let mut scalars = self.responses.clone();
                points.push(commitment.clone());
                scalars.push(challenge.clone());
                let pr = points.multi_scalar_mul_var_time(&scalars).unwrap() - &self.commitment;
                Ok(pr.is_identity())
            }
        }
    };
}

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
        let J = bases.multi_scalar_mul_const_time(&exponents).unwrap();

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
    fn test_PoK_VC() {
        // Proof of knowledge of messages and randomness in vector commitment.
        let n = 5;
        macro_rules! test_PoK_VC {
            ( $prover_committing:ident, $prover_committed:ident, $proof:ident, $group_element:ident, $group_element_vec:ident ) => {
                let mut gens = $group_element_vec::with_capacity(n);
                let mut secrets = FieldElementVector::with_capacity(n);
                let mut commiting = $prover_committing::new();
                for _ in 0..n - 1 {
                    let g = $group_element::random();
                    commiting.commit(&g, None);
                    gens.push(g);
                    secrets.push(FieldElement::random());
                }

                // Add one of the blindings externally
                let g = $group_element::random();
                let r = FieldElement::random();
                commiting.commit(&g, Some(&r));
                let (g_, r_) = commiting.get_index(n - 1).unwrap();
                assert_eq!(g, *g_);
                assert_eq!(r, *r_);
                gens.push(g);
                secrets.push(FieldElement::random());

                let committed = commiting.finish();
                let commitment = gens.multi_scalar_mul_const_time(&secrets).unwrap();
                let challenge = committed.gen_challenge(commitment.to_bytes());
                let proof = committed.gen_proof(&challenge, secrets.as_slice()).unwrap();

                assert!(proof
                    .verify(gens.as_slice(), &commitment, &challenge)
                    .unwrap());
                // Wrong challenge or commitment fails to verify
                assert!(!proof
                    .verify(gens.as_slice(), &$group_element::random(), &challenge)
                    .unwrap());
                assert!(!proof
                    .verify(gens.as_slice(), &commitment, &FieldElement::random())
                    .unwrap());
            };
        }

        test_PoK_VC!(
            ProverCommittingSignatureGroup,
            ProverCommittedSignatureGroup,
            ProofSignatureGroup,
            SignatureGroup,
            SignatureGroupVec
        );
        test_PoK_VC!(
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
