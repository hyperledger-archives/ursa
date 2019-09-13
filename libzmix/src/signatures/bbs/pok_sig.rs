use super::keys::PublicKey;
use super::signature::{compute_b_const_time, Signature};
use crate::commitments::pok_vc::{PoKVCError, PoKVCErrorKind};
use crate::errors::prelude::*;

use std::collections::{HashMap, HashSet};

use amcl_wrapper::extension_field_gt::GT;
use amcl_wrapper::field_elem::{FieldElement, FieldElementVector};
use amcl_wrapper::group_elem::{GroupElement, GroupElementVector};
use amcl_wrapper::group_elem_g1::{G1Vector, G1};
use amcl_wrapper::group_elem_g2::G2;

impl_PoK_VC!(ProverCommittingG1, ProverCommittedG1, ProofG1, G1, G1Vector);

// XXX: An optimization would be to combine the 2 relations into one by using the same techniques as Bulletproofs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoKOfSignature {
    pub a_prime: G1,
    pub a_bar: G1,
    pub d: G1,
    // For proving relation a_bar / d == a_prime^{-e} * h_0^r2
    pub pok_vc_1: ProverCommittedG1,
    secrets_1: FieldElementVector,
    // For proving relation g1 * h1^m1 * h2^m2.... for all disclosed messages m_i == d^r3 * h_0^{-s_prime} * h1^-m1 * h2^-m2.... for all undisclosed messages m_i
    pub pok_vc_2: ProverCommittedG1,
    secrets_2: FieldElementVector,
}

// Contains the randmomized signature as well as the proof of 2 discrete log relations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoKOfSignatureProof {
    pub a_prime: G1,
    pub a_bar: G1,
    pub d: G1,
    // Proof of relation a_bar / d == a_prime^{-e} * h_0^r2
    pub proof_vc_1: ProofG1,
    // Proof of relation g1 * h1^m1 * h2^m2.... for all disclosed messages m_i == d^r3 * h_0^{-s_prime} * h1^-m1 * h2^-m2.... for all undisclosed messages m_i
    pub proof_vc_2: ProofG1,
}

impl PoKOfSignature {
    pub fn init(
        signature: &Signature,
        vk: &PublicKey,
        messages: &[FieldElement],
        blindings: Option<&[FieldElement]>,
        revealed_msg_indices: HashSet<usize>,
    ) -> Result<Self, BBSError> {
        if messages.len() != vk.message_count() {
            return Err(BBSError::from_kind(
                BBSErrorKind::SigningErrorMessageCountMismatch(vk.message_count(), messages.len()),
            ));
        }
        for idx in &revealed_msg_indices {
            if *idx >= messages.len() {
                return Err(BBSError::from_kind(BBSErrorKind::GeneralError {
                    msg: format!("Index {} should be less than {}", idx, messages.len()),
                }));
            }
        }

        let mut blindings: Vec<Option<&FieldElement>> = match blindings {
            Some(b) => {
                if messages.len() - revealed_msg_indices.len() != b.len() {
                    return Err(BBSError::from_kind(BBSErrorKind::GeneralError {
                        msg: format!(
                            "Blindings {} != Hidden messages {}",
                            b.len(),
                            messages.len() - revealed_msg_indices.len()
                        ),
                    }));
                }
                b.iter().map(Some).collect()
            }
            None => (0..(messages.len() - revealed_msg_indices.len()))
                .map(|_| None)
                .collect(),
        };

        let r1 = FieldElement::random();
        let r2 = FieldElement::random();

        let b = compute_b_const_time(&G1::new(), vk, messages, &signature.s, 0);
        let a_prime = &signature.a * &r1;
        let a_bar = &(&b * &r1) - &(&a_prime * &signature.e);
        let d = b.binary_scalar_mul(&vk.h0, &r1, &(-&r2));

        let r3 = r1.inverse();
        let s_prime = &signature.s - &(&r2 * &r3);

        // For proving relation a_bar / d == a_prime^{-e} * h_0^r2
        let mut committing_1 = ProverCommittingG1::new();
        let mut secrets_1 = FieldElementVector::with_capacity(2);
        // For a_prime^{-e}
        committing_1.commit(&a_prime, None);
        secrets_1.push(-(&signature.e));
        // For h_0^r2
        committing_1.commit(&vk.h0, None);
        secrets_1.push(r2);
        let pok_vc_1 = committing_1.finish();

        // For proving relation g1 * h1^m1 * h2^m2.... for all disclosed messages m_i == d^r3 * h_0^{-s_prime} * h1^-m1 * h2^-m2.... for all undisclosed messages m_i
        // Usually the number of disclosed messages is much less than the number of hidden messages, its better to avoid negations in hidden messages and do
        // them in revealed messages. So transform the relation
        // g1 * h1^m1 * h2^m2.... * h_i^m_i for disclosed messages m_i = d^r3 * h_0^{-s_prime} * h1^-m1 * h2^-m2.... * h_j^-m_j for all undisclosed messages m_j
        // into
        // d^{-r3} * h_0^s_prime * h1^m1 * h2^m2.... * h_j^m_j = g1 * h1^-m1 * h2^-m2.... * h_i^-m_i. Moreover g1 * h1^-m1 * h2^-m2.... * h_i^-m_i is public
        // and can be efficiently computed as (g1 * h1^m1 * h2^m2.... * h_i^m_i)^-1 and inverse in elliptic group is a point negation which is very cheap
        let mut committing_2 = ProverCommittingG1::new();
        let mut secrets_2 =
            FieldElementVector::with_capacity(2 + vk.message_count() - revealed_msg_indices.len());
        // For d^-r3
        committing_2.commit(&d, None);
        secrets_2.push(-r3);
        // h_0^s_prime
        committing_2.commit(&vk.h0, None);
        secrets_2.push(s_prime);

        for i in 0..vk.message_count() {
            if revealed_msg_indices.contains(&i) {
                continue;
            }
            committing_2.commit(&vk.h[i], blindings.remove(0));
            secrets_2.push(messages[i].clone());
        }
        let pok_vc_2 = committing_2.finish();

        Ok(Self {
            a_prime,
            a_bar,
            d,
            pok_vc_1,
            secrets_1,
            pok_vc_2,
            secrets_2,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        bytes.append(&mut self.a_prime.to_bytes());
        bytes.append(&mut self.a_bar.to_bytes());
        bytes.append(&mut self.d.to_bytes());

        // For 1st PoKVC
        bytes.append(&mut self.pok_vc_1.to_bytes());

        // For 2nd PoKVC
        bytes.append(&mut self.pok_vc_2.to_bytes());

        bytes
    }

    pub fn gen_proof(self, challenge_hash: &FieldElement) -> Result<PoKOfSignatureProof, BBSError> {
        let proof_vc_1 = self
            .pok_vc_1
            .gen_proof(challenge_hash, self.secrets_1.as_slice())?;
        let proof_vc_2 = self
            .pok_vc_2
            .gen_proof(challenge_hash, self.secrets_2.as_slice())?;

        Ok(PoKOfSignatureProof {
            a_prime: self.a_prime,
            a_bar: self.a_bar,
            d: self.d,
            proof_vc_1,
            proof_vc_2,
        })
    }
}

impl PoKOfSignatureProof {
    pub fn verify(
        &self,
        vk: &PublicKey,
        revealed_msgs: HashMap<usize, FieldElement>,
        challenge: &FieldElement,
    ) -> Result<bool, BBSError> {
        vk.validate()?;
        for i in revealed_msgs.keys() {
            if *i >= vk.message_count() {
                return Err(BBSError::from_kind(BBSErrorKind::GeneralError {
                    msg: format!("Index {} should be less than {}", i, vk.message_count()),
                }));
            }
        }

        if self.a_prime.is_identity() {
            return Ok(false);
        }

        if !GT::ate_2_pairing(&self.a_prime, &vk.w, &(-&self.a_bar), &G2::generator()).is_one() {
            return Ok(false);
        }

        let mut bases = vec![];
        bases.push(self.a_prime.clone());
        bases.push(vk.h0.clone());
        // a_bar / d
        let a_bar_d = &self.a_bar - &self.d;
        if !self.proof_vc_1.verify(&bases, &a_bar_d, challenge)? {
            return Ok(false);
        }

        let mut bases_pok_vc_2 =
            G1Vector::with_capacity(2 + vk.message_count() - revealed_msgs.len());
        bases_pok_vc_2.push(self.d.clone());
        bases_pok_vc_2.push(vk.h0.clone());

        // `bases_disclosed` and `exponents` below are used to create g1 * h1^-m1 * h2^-m2.... for all disclosed messages m_i
        let mut bases_disclosed = G1Vector::with_capacity(1 + revealed_msgs.len());
        let mut exponents = FieldElementVector::with_capacity(1 + revealed_msgs.len());
        // XXX: g1 should come from a setup param and not generator
        bases_disclosed.push(G1::generator());
        exponents.push(FieldElement::one());
        for i in 0..vk.message_count() {
            if revealed_msgs.contains_key(&i) {
                let message = revealed_msgs.get(&i).unwrap();
                bases_disclosed.push(vk.h[i].clone());
                exponents.push(message.clone());
            } else {
                bases_pok_vc_2.push(vk.h[i].clone());
            }
        }
        // pr = g1 * h1^-m1 * h2^-m2.... = (g1 * h1^m1 * h2^m2....)^-1 for all disclosed messages m_i
        let pr = -bases_disclosed
            .multi_scalar_mul_var_time(&exponents)
            .unwrap();
        if !self
            .proof_vc_2
            .verify(bases_pok_vc_2.as_slice(), &pr, challenge)?
        {
            return Ok(false);
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use signatures::bbs::keys::generate;

    #[test]
    fn pok_signature_no_revealed_messages() {
        let message_count = 5;
        let messages = FieldElementVector::random(message_count);
        let (verkey, signkey) = generate(message_count).unwrap();

        let sig = Signature::new(messages.as_slice(), &signkey, &verkey).unwrap();
        let res = sig.verify(messages.as_slice(), &verkey);
        assert!(res.unwrap());

        let pok =
            PoKOfSignature::init(&sig, &verkey, messages.as_slice(), None, HashSet::new()).unwrap();
        let challenge = FieldElement::from_msg_hash(&pok.to_bytes());
        let proof = pok.gen_proof(&challenge).unwrap();
        assert!(proof.verify(&verkey, HashMap::new(), &challenge).unwrap());
    }

    #[test]
    fn pok_signature_revealed_message() {
        let message_count = 5;
        let messages = FieldElementVector::random(message_count);
        let (verkey, signkey) = generate(message_count).unwrap();

        let sig = Signature::new(messages.as_slice(), &signkey, &verkey).unwrap();
        let res = sig.verify(messages.as_slice(), &verkey);
        assert!(res.unwrap());

        let mut revealed_indices = HashSet::new();
        revealed_indices.insert(0);
        revealed_indices.insert(2);

        let pok = PoKOfSignature::init(
            &sig,
            &verkey,
            messages.as_slice(),
            None,
            revealed_indices.clone(),
        )
        .unwrap();
        let challenge = FieldElement::from_msg_hash(&pok.to_bytes());
        let proof = pok.gen_proof(&challenge).unwrap();

        let mut revealed_msgs = HashMap::new();
        for i in &revealed_indices {
            revealed_msgs.insert(i.clone(), messages[*i].clone());
        }
        assert!(proof
            .verify(&verkey, revealed_msgs.clone(), &challenge)
            .unwrap());

        // Reveal wrong message
        let mut revealed_msgs_1 = revealed_msgs.clone();
        revealed_msgs_1.insert(2, FieldElement::random());
        assert!(!proof
            .verify(&verkey, revealed_msgs_1.clone(), &challenge)
            .unwrap());

        //PoK with supplied blindings
        let blindings = FieldElementVector::random(message_count - revealed_indices.len());
        let pok = PoKOfSignature::init(
            &sig,
            &verkey,
            messages.as_slice(),
            Some(blindings.as_slice()),
            revealed_indices.clone(),
        )
        .unwrap();
        let mut revealed_msgs = HashMap::new();
        for i in &revealed_indices {
            revealed_msgs.insert(i.clone(), messages[*i].clone());
        }
        let challenge = FieldElement::from_msg_hash(&pok.to_bytes());
        let proof = pok.gen_proof(&challenge).unwrap();
        assert!(proof
            .verify(&verkey, revealed_msgs.clone(), &challenge)
            .unwrap());
    }
}
