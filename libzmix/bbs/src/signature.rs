use super::types::*;
use crate::errors::prelude::*;
use crate::keys::{PublicKey, SecretKey};
use amcl_wrapper::{
    constants::{CURVE_ORDER_ELEMENT_SIZE, FIELD_ORDER_ELEMENT_SIZE, GROUP_G1_SIZE},
    extension_field_gt::GT,
    group_elem::{GroupElement, GroupElementVector},
    group_elem_g1::G1,
    group_elem_g2::G2,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Convenience module
pub mod prelude {
    pub use super::{BlindSignature, Signature, COMPRESSED_SIGNATURE_SIZE, SIGNATURE_SIZE};
}

macro_rules! check_verkey_message {
    ($statment:expr, $count1:expr, $count2:expr) => {
        if $statment {
            return Err(
                BBSErrorKind::PublicKeyGeneratorMessageCountMismatch($count1, $count2).into(),
            );
        }
    };
}

/// The number of bytes in a signature
pub const SIGNATURE_SIZE: usize = GROUP_G1_SIZE + FIELD_ORDER_ELEMENT_SIZE * 2;
/// The number of bytes in a compressed signature
pub const COMPRESSED_SIGNATURE_SIZE: usize =
    FIELD_ORDER_ELEMENT_SIZE + CURVE_ORDER_ELEMENT_SIZE * 2;

macro_rules! sig_byte_impl {
    () => {
        /// Convert the signature to raw bytes
        pub fn to_bytes(&self) -> [u8; SIGNATURE_SIZE] {
            let mut out = Vec::with_capacity(SIGNATURE_SIZE);
            out.extend_from_slice(&self.a.to_vec()[..]);
            out.extend_from_slice(&self.e.to_bytes()[..]);
            out.extend_from_slice(&self.s.to_bytes()[..]);
            *array_ref![out, 0, SIGNATURE_SIZE]
        }

        /// Conver the signature to a compressed form of raw bytes. Use when sending over the wire.
        pub fn to_compressed_bytes(&self) -> [u8; COMPRESSED_SIGNATURE_SIZE] {
            let mut out = [0u8; COMPRESSED_SIGNATURE_SIZE];
            out[..FIELD_ORDER_ELEMENT_SIZE].copy_from_slice(&self.a.to_compressed_bytes()[..]);
            let end = FIELD_ORDER_ELEMENT_SIZE + CURVE_ORDER_ELEMENT_SIZE;
            out[FIELD_ORDER_ELEMENT_SIZE..end].copy_from_slice(&self.e.to_compressed_bytes()[..]);
            out[end..].copy_from_slice(&self.s.to_compressed_bytes()[..]);
            out
        }

        /// Convert the byte slice into a Signature
        pub fn from_bytes(data: [u8; SIGNATURE_SIZE]) -> Self {
            let mut index = 0;
            let a = G1::from_slice(&data[..GROUP_G1_SIZE]).unwrap();
            index += GROUP_G1_SIZE;
            let e = SignatureNonce::from(*array_ref![data, index, FIELD_ORDER_ELEMENT_SIZE]);
            index += FIELD_ORDER_ELEMENT_SIZE;
            let s = SignatureNonce::from(*array_ref![data, index, FIELD_ORDER_ELEMENT_SIZE]);
            Self { a, e, s }
        }
    };
}

macro_rules! from_rules {
    ($type:ident) => {
        impl From<[u8; COMPRESSED_SIGNATURE_SIZE]> for $type {
            fn from(data: [u8; COMPRESSED_SIGNATURE_SIZE]) -> Self {
                Self::from(&data)
            }
        }

        impl From<&[u8; COMPRESSED_SIGNATURE_SIZE]> for $type {
            fn from(data: &[u8; COMPRESSED_SIGNATURE_SIZE]) -> Self {
                let a = G1::from(*array_ref![data, 0, FIELD_ORDER_ELEMENT_SIZE]);
                let e = SignatureMessage::from(array_ref![
                    data,
                    FIELD_ORDER_ELEMENT_SIZE,
                    CURVE_ORDER_ELEMENT_SIZE
                ]);
                let s = SignatureMessage::from(array_ref![
                    data,
                    FIELD_ORDER_ELEMENT_SIZE + CURVE_ORDER_ELEMENT_SIZE,
                    CURVE_ORDER_ELEMENT_SIZE
                ]);
                Self { a, e, s }
            }
        }
    };
}

/// A BBS+ blind signature
/// structurally identical to `Signature` but is used to help
/// with misuse and confusion.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlindSignature {
    /// A
    pub a: G1,
    /// e
    pub e: SignatureNonce,
    /// s
    pub s: SignatureNonce,
}

impl BlindSignature {
    /// 1 or more messages have been hidden by the signature recipient. The remaining
    /// known messages are in `messages`. The generator to which they correspond is in `message_indices`.
    ///
    /// `commitment`: h<sub>0</sub><sup>s</sup> * h<sub>[i]</sub><sup>m<sub>i</sub></sup>
    /// `messages`: Messages to be signed where each value is 0 < m ≤ r and the key is the index in the public.h to which is used as base
    /// `signkey`: The secret key for signing
    /// `verkey`: The corresponding public key to secret key
    pub fn new(
        commitment: &BlindedSignatureCommitment,
        messages: &BTreeMap<usize, SignatureMessage>,
        signkey: &SecretKey,
        verkey: &PublicKey,
    ) -> Result<Self, BBSError> {
        check_verkey_message!(
            messages.len() > verkey.message_count(),
            verkey.message_count(),
            messages.len()
        );
        let e = SignatureNonce::random();
        let s = SignatureNonce::random();

        let mut points = SignaturePointVector::with_capacity(messages.len() + 2);
        let mut scalars = SignatureMessageVector::with_capacity(messages.len() + 2);
        // g1*h0^blinding_factor*hi^mi.....
        points.push(G1::generator());
        scalars.push(SignatureNonce::one());
        points.push(verkey.h0.clone());
        scalars.push(s.clone());

        for (i, m) in messages.iter() {
            points.push(verkey.h[*i].clone());
            scalars.push(m.clone());
        }
        let b = commitment
            + points
                .multi_scalar_mul_const_time(scalars.as_slice())
                .unwrap();

        let mut exp = signkey.clone();
        exp += &e;
        exp.inverse_mut();
        let a = b * exp;
        Ok(Self { a, e, s })
    }

    /// Once signature on committed attributes (blind signature) is received, the signature needs to be unblinded.
    /// Takes the blinding factor used in the commitment.
    pub fn to_unblinded(&self, blinding: &SignatureBlinding) -> Signature {
        Signature {
            a: self.a.clone(),
            s: self.s.clone() + blinding,
            e: self.e.clone(),
        }
    }

    sig_byte_impl!();
}

/// A BBS+ signature.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Signature {
    /// A
    pub a: G1,
    /// e
    pub e: SignatureNonce,
    /// s
    pub s: SignatureNonce,
}

// https://eprint.iacr.org/2016/663.pdf Section 4.3
impl Signature {
    /// No committed messages, All messages known to signer.
    pub fn new(
        messages: &[SignatureMessage],
        signkey: &SecretKey,
        verkey: &PublicKey,
    ) -> Result<Self, BBSError> {
        check_verkey_message!(
            messages.len() > verkey.message_count(),
            verkey.message_count(),
            messages.len()
        );
        let e = SignatureNonce::random();
        let s = SignatureNonce::random();
        let b = compute_b_const_time(
            &G1::new(),
            verkey,
            messages,
            &s,
            verkey.message_count() - messages.len(),
        );
        let mut exp = signkey.clone();
        exp += &e;
        exp.inverse_mut();
        let a = b * exp;
        Ok(Self { a, e, s })
    }

    /// Generate the signature blinding factor that will be used to unblind the signature
    pub fn generate_blinding() -> SignatureBlinding {
        SignatureBlinding::random()
    }

    /// Verify a signature. During proof of knowledge also, this method is used after extending the verkey
    pub fn verify(
        &self,
        messages: &[SignatureMessage],
        verkey: &PublicKey,
    ) -> Result<bool, BBSError> {
        check_verkey_message!(
            messages.len() != verkey.message_count(),
            verkey.message_count(),
            messages.len()
        );
        let b = compute_b_var_time(&G1::new(), verkey, messages, &self.s, 0);
        let a = (&G2::generator() * &self.e) + &verkey.w;
        Ok(GT::ate_2_pairing(&self.a, &a, &(-&b), &G2::generator()).is_one())
    }

    sig_byte_impl!();
}

fn prep_vec_for_b(
    public_key: &PublicKey,
    messages: &[SignatureMessage],
    blinding_factor: &SignatureBlinding,
    offset: usize,
) -> (SignaturePointVector, SignatureMessageVector) {
    let mut points = SignaturePointVector::with_capacity(messages.len() + 2);
    let mut scalars = SignatureMessageVector::with_capacity(messages.len() + 2);
    // XXX: g1 should not be a generator but a setup param
    // prep for g1*h0^blinding_factor*hi^mi.....
    points.push(G1::generator());
    scalars.push(SignatureNonce::one());
    points.push(public_key.h0.clone());
    scalars.push(blinding_factor.clone());

    for i in 0..messages.len() {
        points.push(public_key.h[offset + i].clone());
        scalars.push(messages[i].clone());
    }
    (points, scalars)
}

/// Helper function for computing the `b` value. Internal helper function
pub(crate) fn compute_b_const_time(
    starting_value: &BlindedSignatureCommitment,
    public_key: &PublicKey,
    messages: &[SignatureMessage],
    blinding_factor: &SignatureBlinding,
    offset: usize,
) -> G1 {
    let (points, scalars) = prep_vec_for_b(public_key, messages, blinding_factor, offset);
    starting_value
        + points
            .multi_scalar_mul_const_time(scalars.as_slice())
            .unwrap()
}

/// Helper function for computing the `b` value. Internal helper function
pub(crate) fn compute_b_var_time(
    starting_value: &BlindedSignatureCommitment,
    public_key: &PublicKey,
    messages: &[SignatureMessage],
    blinding_factor: &SignatureBlinding,
    offset: usize,
) -> G1 {
    let (points, scalars) = prep_vec_for_b(public_key, messages, blinding_factor, offset);
    starting_value
        + points
            .multi_scalar_mul_var_time(scalars.as_slice())
            .unwrap()
}

from_rules!(BlindSignature);
from_rules!(Signature);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::generate;
    use crate::pok_vc::ProverCommittingG1;
    use crate::SignatureMessageVector;

    #[test]
    fn signature_serialization() {
        let sig = Signature {
            a: G1::random(),
            e: SignatureNonce::random(),
            s: SignatureNonce::random(),
        };
        let bytes = sig.to_bytes();
        assert_eq!(bytes.len(), SIGNATURE_SIZE);
        let sig_2 = Signature::from_bytes(bytes);
        assert_eq!(sig, sig_2);

        let bytes = sig.to_compressed_bytes();
        assert_eq!(bytes.len(), COMPRESSED_SIGNATURE_SIZE);
        let sig_2 = Signature::from(bytes);
        assert_eq!(sig, sig_2);
    }

    #[test]
    fn gen_signature() {
        let message_count = 5;
        let messages = SignatureMessageVector::random(message_count);
        let (verkey, signkey) = generate(message_count).unwrap();

        let res = Signature::new(messages.as_slice(), &signkey, &verkey);
        assert!(res.is_ok());
        let messages = Vec::new();
        let res = Signature::new(messages.as_slice(), &signkey, &verkey);
        assert!(res.is_ok());
    }

    #[test]
    fn signature_validation() {
        let message_count = 5;
        let messages = SignatureMessageVector::random(message_count);
        let (verkey, signkey) = generate(message_count).unwrap();

        let sig = Signature::new(messages.as_slice(), &signkey, &verkey).unwrap();
        let res = sig.verify(messages.as_slice(), &verkey);
        assert!(res.is_ok());
        assert!(res.unwrap());

        let mut messages = Vec::new();
        for _ in 0..message_count {
            messages.push(SignatureMessage::random());
        }
        let res = sig.verify(messages.as_slice(), &verkey);
        assert!(res.is_ok());
        assert!(!res.unwrap());
    }

    #[test]
    fn signature_committed_messages() {
        let message_count = 4;
        let messages = SignatureMessageVector::random(message_count);
        let (verkey, signkey) = generate(message_count).unwrap();

        //User blinds first attribute
        let blinding = Signature::generate_blinding();

        //User creates a random commitment, computes challenges and response. The proof of knowledge consists of a commitment and responses
        //User and signer engage in a proof of knowledge for `commitment`
        let commitment = &verkey.h0 * &blinding + &verkey.h[0] * &messages[0];

        let mut committing = ProverCommittingG1::new();
        committing.commit(&verkey.h0, None);
        committing.commit(&verkey.h[0], None);
        let committed = committing.finish();

        let mut hidden_msgs = Vec::new();
        hidden_msgs.push(blinding.clone());
        hidden_msgs.push(messages[0].clone());

        let mut bases = Vec::new();
        bases.push(verkey.h0.clone());
        bases.push(verkey.h[0].clone());

        let nonce = vec![1u8, 1u8, 1u8, 1u8, 2u8, 2u8, 2u8, 2u8];
        let mut extra = Vec::new();
        extra.extend_from_slice(&commitment.to_vec());
        extra.extend_from_slice(nonce.as_slice());
        let challenge_hash = committed.gen_challenge(extra);
        let proof = committed
            .gen_proof(&challenge_hash, hidden_msgs.as_slice())
            .unwrap();

        assert!(proof
            .verify(bases.as_slice(), &commitment, &challenge_hash)
            .unwrap());
        let mut known = BTreeMap::new();
        for i in 1..message_count {
            known.insert(i, messages[i].clone());
        }
        let sig = BlindSignature::new(&commitment, &known, &signkey, &verkey);
        assert!(proof
            .verify_complete_proof(
                bases.as_slice(),
                &commitment,
                &challenge_hash,
                nonce.as_slice()
            )
            .unwrap());

        assert!(sig.is_ok());
        let sig = sig.unwrap();

        let sig = sig.to_unblinded(&blinding);
        let res = sig.verify(messages.as_slice(), &verkey);
        assert!(res.is_ok());
        assert!(res.unwrap());
    }
}
