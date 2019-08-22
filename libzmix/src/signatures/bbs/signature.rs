use super::errors::{BBSErrorKind, BBSError};
use super::keys::{PublicKey, SecretKey};
use amcl_wrapper::{
    group_elem_g1::G1,
    group_elem_g2::G2,
    group_elem::GroupElement,
    field_elem::FieldElement,
    extension_field_gt::GT,
    constants::{GROUP_G1_SIZE, MODBYTES}
};

use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Signature {
    a: G1,
    e: FieldElement,
    s: FieldElement
}

impl Signature {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(GROUP_G1_SIZE + MODBYTES * 2);
        out.extend_from_slice(self.a.to_bytes().as_slice());
        out.extend_from_slice(self.e.to_bytes().as_slice());
        out.extend_from_slice(self.s.to_bytes().as_slice());
        out
    }

    pub fn from_bytes(data: &[u8]) -> Result<Signature, BBSError> {
        let expected = GROUP_G1_SIZE + MODBYTES * 2;
        if data.len() != expected {
            return Err(BBSError::from_kind(BBSErrorKind::SignatureIncorrectSize(
                data.len()
            )));
        }
        let mut index = 0;
        let a = G1::from_bytes(&data[0..GROUP_G1_SIZE]).map_err(|_| BBSError::from_kind(BBSErrorKind::SignatureValueIncorrectSize))?;
        index += GROUP_G1_SIZE;
        let e = FieldElement::from_bytes(&data[index..(index+MODBYTES)]).map_err(|_| BBSError::from_kind(BBSErrorKind::SignatureValueIncorrectSize))?;
        index += MODBYTES;
        let s = FieldElement::from_bytes(&data[index..(index+MODBYTES)]).map_err(|_| BBSError::from_kind(BBSErrorKind::SignatureValueIncorrectSize))?;
        Ok(Signature { a, e, s })
    }

    // No committed messages, All messages known to signer.
    pub fn new(messages: &[FieldElement], signkey: &SecretKey, verkey: &PublicKey) -> Result<Self, BBSError> {
        check_verkey_message(messages, verkey)?;
        let e = FieldElement::random();
        let s = FieldElement::random();
        let b = compute_b(&G1::new(), verkey, messages, &s, 0);
        let mut exp = signkey.clone();
        exp += &e;
        exp.inverse();
        let a = b * exp;
        Ok(Signature { a, e, s })
    }

    // 1 or more messages are captured in a commitment `commitment`. The remaining known messages are in `messages`.
    // This is a blind signature.
    pub fn new_with_committed_messages(commitment: &G1, messages: &[FieldElement], signkey: &SecretKey, verkey: &PublicKey) -> Result<Self, BBSError> {
        check_verkey_message(messages, verkey)?;
        let e = FieldElement::random();
        let s = FieldElement::random();
        let b = compute_b(commitment, verkey, messages, &s, verkey.message_count() - messages.len());
        let mut exp = signkey.clone();
        exp += &e;
        exp.inverse();
        let a = b * exp;
        Ok(Signature { a, e, s })
    }

    // Once signature on committed attributes (blind signature) is received, the signature needs to be unblinded.
    // Takes the blinding used in the commitment.
    pub fn get_unblinded_signature(&self, blinding: &FieldElement) -> Self {
        Signature { a: self.a.clone(), s: self.s.clone() + blinding, e: self.e.clone() }
    }

    // Verify a signature. During proof of knowledge also, this method is used after extending the verkey
    pub fn verify(&self, messages: &[FieldElement], verkey: &PublicKey) -> Result<bool, BBSError> {
        check_verkey_message(messages, verkey)?;
        let b = compute_b(&G1::new(), verkey, messages, &self.s, 0);
        let a = (&G2::generator() * &self.e) + &verkey.w;
        let res1 = GT::ate_pairing(&self.a, &a);
        let res2 = GT::ate_pairing(&b, &G2::generator());
        println!("res1 = {:?}", res1);
        println!("res2 = {:?}", res2);
        Ok(GT::ate_2_pairing_cmp(&self.a, &a, &b, &G2::generator()))
    }
}

fn compute_b(starting_value: &G1, public_key: &PublicKey, messages: &[FieldElement], blinding_factor: &FieldElement, offset: usize) -> G1 {
    let mut b = G1::generator();
    b += starting_value;

    let mut j = 0;
    let mut i = offset;


    while i + 1 < public_key.h.len() {
        let v1 = &messages[j];
        let v2 = &messages[j + 1];

        let p1 = &public_key.h[i];
        let p2 = &public_key.h[i + 1];


        b += p1.binary_scalar_mul(&p2, &v1, &v2);

        i += 2;
        j += 2;
    }

    if i < public_key.h.len() {
        let v = &messages[j];
        let p = &public_key.h[i];

        b += p.binary_scalar_mul(&public_key.h0, &v, &blinding_factor);
    } else {
        b += &public_key.h0 * blinding_factor;
    }
    b
}

fn check_verkey_message(messages: &[FieldElement], verkey: &PublicKey) -> Result<(), BBSError> {
    if messages.len() != verkey.message_count() {
        return Err(BBSError::from_kind(BBSErrorKind::SigningErrorMessageCountMismatch(verkey.message_count(), messages.len())));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::keys::generate;

    #[test]
    fn signature_serialization() {
        let sig = Signature { a: G1::random(), e: FieldElement::random(), s: FieldElement::random() };
        let bytes = sig.to_bytes();
        assert_eq!(bytes.len(), GROUP_G1_SIZE + MODBYTES * 2);
        let sig_2 = Signature::from_bytes(bytes.as_slice()).unwrap();
        assert_eq!(sig, sig_2);
    }
    #[test]
    fn gen_signature() {
        let message_count = 5;
        let mut messages = Vec::new();
        for _ in 0..message_count {
            messages.push(FieldElement::random());
        }
        let (verkey, signkey) = generate(message_count);

        let res = Signature::new(messages.as_slice(), &signkey, &verkey);
        assert!(res.is_ok());
        messages = Vec::new();
        let res = Signature::new(messages.as_slice(), &signkey, &verkey);
        assert!(res.is_err());
    }

    #[test]
    fn signature_validation() {
        let message_count = 5;
        let mut messages = Vec::new();
        for _ in 0..message_count {
            messages.push(FieldElement::random());
        }
        let (verkey, signkey) = generate(message_count);

        let sig = Signature::new(messages.as_slice(), &signkey, &verkey).unwrap();
        let res = sig.verify(messages.as_slice(), &verkey);
        assert!(res.is_ok());
        assert!(res.unwrap());

        messages = Vec::new();
        for _ in 0..message_count {
            messages.push(FieldElement::random());
        }
        let res = sig.verify(messages.as_slice(), &verkey);
        assert!(res.is_ok());
        assert!(!res.unwrap());
    }
}
