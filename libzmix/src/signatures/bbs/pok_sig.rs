use super::signature::{Signature, compute_b_const_time};
use super::keys::PublicKey;
use crate::errors::prelude::*;

use serde::{Serialize, Deserialize};
use std::collections::{HashSet, HashMap};

use amcl_wrapper::field_elem::{FieldElement, FieldElementVector};
use amcl_wrapper::group_elem::{GroupElement, GroupElementVector};
use amcl_wrapper::group_elem_g1::{G1Vector, G1};
use amcl_wrapper::group_elem_g2::{G2Vector, G2};
use amcl_wrapper::extension_field_gt::GT;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofR {
    a_prime: G1,
    a_bar: G1,
    d: G1
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofP {
    e_responses: FieldElement,
    s_responses: FieldElement,
    r2_responses: FieldElement,
    r3_responses: FieldElement,
    message_responses: FieldElementVector
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoKOfSignature {
    proof_r: ProofR,
    messages: FieldElementVector,
    secrets: FieldElementVector,
    e_challenge: FieldElement,
    s_challenge: FieldElement,
    s_prime: FieldElement,
    r2: FieldElement,
    r3: FieldElement,
    r2_challenge: FieldElement,
    r3_challenge: FieldElement,
    t1: G1,
    t2: G1,
    e: FieldElement,
    s: FieldElement
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoKOfSignatureProof {
    proof_r: ProofR,
    proof_p: ProofP
}

impl PoKOfSignature {
    pub fn init(signature: &Signature,
                vk: &PublicKey,
                messages: &[FieldElement],
                revealed_msg_indices: HashSet<usize>) -> Result<Self, BBSError> {
        if messages.len() != vk.message_count() {
            return Err(BBSError::from_kind(BBSErrorKind::SigningErrorMessageCountMismatch(vk.message_count(), messages.len())));
        }
        for idx in &revealed_msg_indices {
            if *idx >= messages.len() {
                return Err(BBSError::from_kind(BBSErrorKind::GeneralError {
                    msg: format!("Index {} should be less than {}", idx, messages.len()),
                }));
            }
        }

        let r1 = FieldElement::random();
        let r2 = FieldElement::random();
        let e_challenge = FieldElement::random();
        let s_challenge = FieldElement::random();
        let r2_challenge = FieldElement::random();
        let r3_challenge = FieldElement::random();

        let b = compute_b_const_time(&G1::new(), vk, messages, &signature.s, 0);

        let a_prime = &signature.a * &r1;
        let a_bar = (&b * &r1) - (&a_prime * &signature.e);
        let d = b.binary_scalar_mul(&vk.h0, &r1, &r2);

        let r3 = r1.inverse();
        let mut s_prime = signature.s.clone();
        s_prime += &(&r2 * &r3);

        let t1 = a_prime.binary_scalar_mul(&vk.h0, &e_challenge, &r2_challenge);

        let mut bases = G1Vector::with_capacity(1 + vk.message_count() - revealed_msg_indices.len());
        let mut exponents = FieldElementVector::with_capacity(1 + vk.message_count() - revealed_msg_indices.len());

        bases.push(&vk.h0 * &s_challenge - &d * &r3_challenge);
        exponents.push(FieldElement::one());

        for i in 0..vk.message_count() {
            if revealed_msg_indices.contains(&i) {
                continue;
            }
            let r = FieldElement::random();
            exponents.push(r);
            bases.push(vk.h[i].clone());
        }

        let t2 = bases.multi_scalar_mul_const_time(&exponents).unwrap();

        Ok(PoKOfSignature {
            proof_r: ProofR { a_prime, a_bar, d },
            messages: messages.into(),
            secrets: exponents,
            e_challenge,
            s_challenge,
            s_prime,
            r2,
            r3,
            r2_challenge,
            r3_challenge,
            t1,
            t2,
            e: signature.e.clone(),
            s: signature.s.clone()
        })
    }

    pub fn gen_proof(self, challenge_hash: &FieldElement) -> Result<PoKOfSignatureProof, BBSError> {
        if self.secrets.len() != self.messages.len() {
            return Err(BBSError::from_kind(BBSErrorKind::GeneralError { msg: format!("Secrets length {} != {}", self.secrets.len(), self.messages.len()) }));
        }

        let e = self.e_challenge + self.e * challenge_hash;
        let s = self.s_challenge + self.s_prime * challenge_hash;
        let r2 = self.r2_challenge + self.r2 * challenge_hash;
        let r3 = self.r3_challenge + self.r3 * challenge_hash;
        let mut responses = Vec::new();
        for i in 0..self.secrets.len() {
            responses.push(&self.secrets[i] - &self.messages[i] * challenge_hash);
        }

        Ok(PoKOfSignatureProof {
            proof_r: self.proof_r,
            proof_p: ProofP {
                e_responses: e,
                s_responses: s,
                r2_responses: r2,
                r3_responses: r3,
                message_responses: responses.into()
            }
        })
    }
}

impl PoKOfSignatureProof {
    pub fn verify(&self, vk: &PublicKey, revealed_msgs: &HashMap<usize, FieldElement>, challenge: &FieldElement) -> Result<bool, BBSError> {
        for (i, _) in revealed_msgs {
            if *i > vk.message_count() {
                return Err(BBSError::from_kind(BBSErrorKind::GeneralError {
                    msg: format!("Index {} should be less than {}", i, vk.message_count()),
                }));
            }
        }

        if self.proof_r.a_prime.is_identity() {
            return Ok(false);
        }

        if GT::ate_2_pairing_cmp(&self.proof_r.a_prime, &vk.w, &self.proof_r.a_bar, &G2::generator()) {
            return Ok(false);
        }

        let mut r_value = revealed_msgs.iter().fold(G1::generator(), |b, (i, a)| b + &vk.h[*i] * a);

        let t1 = self.proof_r.a_prime.binary_scalar_mul(&self.proof_p.e_responses, &(&self.proof_r.a_bar - &self.proof_r.d), challenge) + (&vk.h0 * &self.proof_p.r2_responses);
        let mut t2 = r_value.binary_scalar_mul(challenge, &vk.h0, self.proof_p.s_responses) - &(self.proof_r.d * self.proof_p.r3_responses);


    }
}