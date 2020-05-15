use crate::errors::prelude::*;
use crate::keys::prelude::*;
use crate::{
    multi_scalar_mul_const_time_g1, multi_scalar_mul_var_time_g1, Commitment, RandomElem,
    SignatureBlinding, SignatureMessage, FR_COMPRESSED_SIZE, G1_COMPRESSED_SIZE,
    G1_UNCOMPRESSED_SIZE,
};
use ff_zeroize::{Field, PrimeField};
use pairing_plus::{
    bls12_381::{Bls12, Fq12, Fr, FrRepr, G1, G2},
    serdes::SerDes,
    CurveAffine, CurveProjective, Engine,
};
use rand::prelude::*;
use serde::{
    de::{Error as DError, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::fmt::{Display, Formatter};
use std::io::Cursor;

/// Convenience module
pub mod prelude {
    pub use super::{
        BlindSignature, Signature, SIGNATURE_COMPRESSED_SIZE, SIGNATURE_UNCOMPRESSED_SIZE,
    };
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
pub const SIGNATURE_UNCOMPRESSED_SIZE: usize = G1_UNCOMPRESSED_SIZE + FR_COMPRESSED_SIZE * 2;
/// The number of bytes in a compressed signature
pub const SIGNATURE_COMPRESSED_SIZE: usize = G1_COMPRESSED_SIZE + FR_COMPRESSED_SIZE * 2;

macro_rules! to_bytes_impl {
    ($name:ident, $sigsize:expr, $g1size:expr, $compressed:expr) => {
        /// Convert to raw bytes form
        pub fn $name(&self) -> [u8; $sigsize] {
            let mut out = Vec::with_capacity($sigsize);
            self.a.serialize(&mut out, $compressed).unwrap();
            self.e.serialize(&mut out, $compressed).unwrap();
            self.s.serialize(&mut out, $compressed).unwrap();
            *array_ref![out, 0, $sigsize]
        }
    };
}

macro_rules! from_bytes_impl {
    ($name:ident, $sigsize:expr, $g1size:expr, $compressed:expr) => {
        impl From<[u8; $sigsize]> for $name {
            fn from(data: [u8; $sigsize]) -> Self {
                Self::from(&data)
            }
        }

        impl From<&[u8; $sigsize]> for $name {
            fn from(data: &[u8; $sigsize]) -> Self {
                let mut c = Cursor::new(data.as_ref());
                let a = G1::deserialize(&mut c, $compressed).unwrap();
                let e = Fr::deserialize(&mut c, $compressed).unwrap();
                let s = Fr::deserialize(&mut c, $compressed).unwrap();
                Self { a, e, s }
            }
        }
    };
}

macro_rules! try_from_impl {
    ($name:ident) => {
        impl TryFrom<&[u8]> for $name {
            type Error = BBSError;

            fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
                let mut value = value;
                let compressed = value.len() == SIGNATURE_COMPRESSED_SIZE;
                let a = G1::deserialize(&mut value, compressed).map_err(|_| {
                    BBSErrorKind::GeneralError {
                        msg: "Invalid bytes".to_string(),
                    }
                })?;
                let e = Fr::deserialize(&mut value, compressed).map_err(|_| {
                    BBSErrorKind::GeneralError {
                        msg: "Invalid bytes".to_string(),
                    }
                })?;
                let s = Fr::deserialize(&mut value, compressed).map_err(|_| {
                    BBSErrorKind::GeneralError {
                        msg: "Invalid bytes".to_string(),
                    }
                })?;
                Ok(Self { a, e, s })
            }
        }

        impl TryFrom<Vec<u8>> for $name {
            type Error = BBSError;

            fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
                Self::try_from(value.as_slice())
            }
        }
    };
}

/// A BBS+ blind signature
/// structurally identical to `Signature` but is used to help
/// with misuse and confusion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlindSignature {
    /// A
    pub(crate) a: G1,
    /// e
    pub(crate) e: Fr,
    /// s
    pub(crate) s: Fr,
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
        commitment: &Commitment,
        messages: &BTreeMap<usize, SignatureMessage>,
        signkey: &SecretKey,
        verkey: &PublicKey,
    ) -> Result<Self, BBSError> {
        check_verkey_message!(
            messages.len() > verkey.message_count(),
            verkey.message_count(),
            messages.len()
        );
        let mut rng = thread_rng();
        let e = Fr::random(&mut rng);
        let s = Fr::random(&mut rng);

        let mut points = Vec::with_capacity(messages.len() + 2);
        let mut scalars = Vec::with_capacity(messages.len() + 2);
        // g1*h0^blinding_factor*hi^mi.....
        points.push(commitment.0);
        scalars.push(Fr::from_repr(FrRepr::from(1)).unwrap());
        points.push(G1::one());
        scalars.push(Fr::from_repr(FrRepr::from(1)).unwrap());
        points.push(verkey.h0.0.clone());
        scalars.push(s.clone());

        for (i, m) in messages.iter() {
            points.push(verkey.h[*i].0.clone());
            scalars.push(m.0.clone());
        }

        let mut b = multi_scalar_mul_const_time_g1(&points, &scalars);

        let mut exp = signkey.0.clone();
        exp.add_assign(&e);
        b.mul_assign(exp.inverse().unwrap());
        Ok(Self { a: b, e, s })
    }

    /// Once signature on committed attributes (blind signature) is received, the signature needs to be unblinded.
    /// Takes the blinding factor used in the commitment.
    pub fn to_unblinded(&self, blinding: &SignatureBlinding) -> Signature {
        let mut s = self.s.clone();
        s.add_assign(&blinding.0);
        Signature {
            a: self.a.clone(),
            s,
            e: self.e.clone(),
        }
    }

    to_bytes_impl!(
        to_bytes_compressed_form,
        SIGNATURE_COMPRESSED_SIZE,
        G1_COMPRESSED_SIZE,
        true
    );
    to_bytes_impl!(
        to_bytes_uncompressed_form,
        SIGNATURE_UNCOMPRESSED_SIZE,
        G1_UNCOMPRESSED_SIZE,
        false
    );
}

from_bytes_impl!(
    BlindSignature,
    SIGNATURE_COMPRESSED_SIZE,
    G1_COMPRESSED_SIZE,
    true
);
from_bytes_impl!(
    BlindSignature,
    SIGNATURE_UNCOMPRESSED_SIZE,
    G1_UNCOMPRESSED_SIZE,
    false
);
try_from_impl!(BlindSignature);
serdes_impl!(BlindSignature);
display_impl!(BlindSignature);

/// A BBS+ signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    /// A
    pub(crate) a: G1,
    /// e
    pub(crate) e: Fr,
    /// s
    pub(crate) s: Fr,
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
        let mut rng = thread_rng();
        let e = Fr::random(&mut rng);
        let s = Fr::random(&mut rng);
        let mut b = Self::compute_b(&s, messages, verkey);
        let mut exp = signkey.0.clone();
        exp.add_assign(&e);
        b.mul_assign(exp.inverse().unwrap());
        Ok(Self { a: b, e, s })
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

        let mut pqz = Vec::new();
        let mut a = G2::one();
        a.mul_assign(self.e.clone());
        a.add_assign(&verkey.w.0);

        let mut b = self.get_b(messages, verkey);
        b.negate();
        let b = b.into_affine().prepare();
        let g2 = G2::one().into_affine().prepare();

        let a1 = self.a.into_affine().prepare();
        let a2 = a.into_affine().prepare();

        pqz.push((&a1, &a2));
        pqz.push((&b, &g2));
        Ok(
            //pair(a^(1/x+e), g2^(x+e), 1/b, g2)
            match Bls12::final_exponentiation(&Bls12::miller_loop(&pqz[..])) {
                None => false,
                Some(product) => product == Fq12::one(),
            },
        )
    }

    /// Helper function for computing the `b` value. Internal helper function
    pub(crate) fn get_b(&self, messages: &[SignatureMessage], verkey: &PublicKey) -> G1 {
        // Self::compute_b(&self.s, messages, verkey)
        let mut bases = Vec::with_capacity(messages.len() + 2);
        let mut scalars = Vec::with_capacity(messages.len() + 2);
        // g1*h0^blinding_factor*hi^mi.....
        bases.push(G1::one());
        scalars.push(Fr::from_repr(FrRepr::from(1)).unwrap());
        bases.push(verkey.h0.0.clone());
        scalars.push(self.s.clone());

        for i in 0..verkey.message_count() {
            bases.push(verkey.h[i].0.clone());
            scalars.push(messages[i].0.clone());
        }
        multi_scalar_mul_var_time_g1(&bases, &scalars)
    }

    fn compute_b(s: &Fr, messages: &[SignatureMessage], verkey: &PublicKey) -> G1 {
        let mut bases = Vec::with_capacity(messages.len() + 2);
        let mut scalars = Vec::with_capacity(messages.len() + 2);
        // g1*h0^blinding_factor*hi^mi.....
        bases.push(G1::one());
        scalars.push(Fr::from_repr(FrRepr::from(1)).unwrap());
        bases.push(verkey.h0.0.clone());
        scalars.push((*s).clone());

        let min = std::cmp::min(verkey.message_count(), messages.len());
        for i in 0..min {
            bases.push(verkey.h[i].0.clone());
            scalars.push(messages[i].0.clone());
        }
        multi_scalar_mul_const_time_g1(&bases, &scalars)
    }

    to_bytes_impl!(
        to_bytes_compressed_form,
        SIGNATURE_COMPRESSED_SIZE,
        G1_COMPRESSED_SIZE,
        true
    );
    to_bytes_impl!(
        to_bytes_uncompressed_form,
        SIGNATURE_UNCOMPRESSED_SIZE,
        G1_UNCOMPRESSED_SIZE,
        false
    );
}

from_bytes_impl!(
    Signature,
    SIGNATURE_COMPRESSED_SIZE,
    G1_COMPRESSED_SIZE,
    true
);
from_bytes_impl!(
    Signature,
    SIGNATURE_UNCOMPRESSED_SIZE,
    G1_UNCOMPRESSED_SIZE,
    false
);
try_from_impl!(Signature);
serdes_impl!(Signature);
display_impl!(Signature);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::generate;
    use crate::pok_vc::ProverCommittingG1;
    use crate::CommitmentBuilder;

    #[test]
    fn signature_serialization() {
        let mut rng = thread_rng();
        let sig = Signature {
            a: G1::random(&mut rng),
            e: Fr::random(&mut rng),
            s: Fr::random(&mut rng),
        };
        let bytes = sig.to_bytes_uncompressed_form();
        assert_eq!(bytes.len(), SIGNATURE_UNCOMPRESSED_SIZE);
        let sig_2 = Signature::from(bytes);
        assert_eq!(sig, sig_2);

        let bytes = sig.to_bytes_compressed_form();
        assert_eq!(bytes.len(), SIGNATURE_COMPRESSED_SIZE);
        let sig_2 = Signature::from(bytes);
        assert_eq!(sig, sig_2);
    }

    #[test]
    fn gen_signature() {
        let message_count = 5;
        let mut messages = Vec::new();
        for _ in 0..message_count {
            messages.push(SignatureMessage::random());
        }
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
        let mut messages = Vec::new();
        for _ in 0..message_count {
            messages.push(SignatureMessage::random());
        }
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
        let mut messages = Vec::new();
        for _ in 0..message_count {
            messages.push(SignatureMessage::random());
        }
        let (verkey, signkey) = generate(message_count).unwrap();

        //User blinds first attribute
        let blinding = Signature::generate_blinding();

        //User creates a random commitment, computes challenges and response. The proof of knowledge consists of a commitment and responses
        //User and signer engage in a proof of knowledge for `commitment`
        let mut builder = CommitmentBuilder::new();
        builder.add(verkey.h0.clone(), &blinding);
        builder.add(verkey.h[0].clone(), &messages[0]);
        let commitment = builder.finalize();

        let mut committing = ProverCommittingG1::new();
        committing.commit(verkey.h0.clone());
        committing.commit(verkey.h[0].clone());
        let committed = committing.finish();

        let mut hidden_msgs = Vec::new();
        hidden_msgs.push(SignatureMessage(blinding.0.clone()));
        hidden_msgs.push(messages[0].clone());

        let mut bases = Vec::new();
        bases.push(verkey.h0.clone());
        bases.push(verkey.h[0].clone());

        let nonce = vec![1u8, 1u8, 1u8, 1u8, 2u8, 2u8, 2u8, 2u8];
        let mut extra = Vec::new();
        extra.extend_from_slice(&commitment.to_bytes_uncompressed_form());
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
