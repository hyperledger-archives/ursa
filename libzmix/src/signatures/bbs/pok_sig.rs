use super::signature::{Signature, compute_b_const_time};
use super::keys::PublicKey;
use super::errors::*;

use serde::{Serialize, Deserialize};
use std::collections::HashSet;

use amcl_wrapper::field_elem::{FieldElement, FieldElementVector};
use amcl_wrapper::group_elem::{GroupElement, GroupElementVector};
use amcl_wrapper::group_elem_g1::{G1Vector, G1};
use amcl_wrapper::group_elem_g2::{G2Vector, G2};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoKOfSignature {
    a_prime: G1,
    a_bar: G1,
    d: G1,
    bases: G1Vector,
    secrets: FieldElementVector,
    e: FieldElement,
    s: FieldElement,
    s_prime: FieldElement,
    r2: FieldElement,
    r3: FieldElement,
    r2_challenge: FieldElement,
    r3_challenge: FieldElement,
    t1: G1,
    t2: G1,
    signature: Signature
}

pub struct PoKOfSignatureProof {

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
        let mut e = FieldElement::random();
        let mut s = FieldElement::random();
        let mut r2_challenge = FieldElement::random();
        let mut r3_challenge = FieldElement::random();

        let b = compute_b_const_time(&G1::new(), vk, messages, &signature.s, 0);

        let a_prime = &signature.a * &r1;
        let a_bar = (&b * &r1) - (&a_prime * &signature.e);
        let d = b.binary_scalar_mul(&vk.h0, &r1, &r2);

        let r3 = r1.inverse();
        let mut s_prime = signature.s.clone();
        s_prime += &(&r2 * &r3);

        let t1 = a_prime.binary_scalar_mul(&vk.h0, &e, &r2_challenge);

        let mut bases = G1Vector::with_capacity(1 + vk.message_count() - revealed_msg_indices.len());
        let mut exponents = FieldElementVector::with_capacity(1 + vk.message_count() - revealed_msg_indices.len());

        // d^r3~ / h0^s'~
        bases.push(&vk.h0 * &s - &d * &r3_challenge);
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
            a_prime,
            a_bar,
            d,
            bases,
            secrets: exponents,
            e,
            s,
            s_prime,
            r2,
            r3,
            r2_challenge,
            r3_challenge,
            t1,
            t2,
            signature: signature.clone()
        })
    }

    pub fn gen_proof(self, challenge_hash: &FieldElement) -> Result<PoKOfSignatureProof, BBSError> {
        if self.secrets.len() != self.bases.len() {
            return Err(BBSError::from_kind(BBSErrorKind::GeneralError { msg: format!("Secrets length {} != {}", self.secrets.len(), self.bases.len()) }));
        }

        let e = self.e + self.signature.e * challenge_hash;
    }
}