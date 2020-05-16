//! Implements the BBS+ signature as defined in <https://eprint.iacr.org/2016/663.pdf>
//! in Section 4.3. Also included is ability to do zero-knowledge proofs as described
//! in Section 4.4 and 4.5.
//!
//! The BBS+ signature is a pairing-based ECC signature
//! that signs multiple messages instead of just one.
//! The signature and messages can be used to create signature proofs of knowledge
//! in zero-knowledge proofs in which the signature is not revealed and messages
//! can be selectively disclosed––some are revealed and some remain hidden.
//!
//! The signature also supports separating the signer and signature holder
//! where the holder creates commitments to messages which are hidden from the signer
//! and a signature blinding factor which is retained. The holder sends the commitment
//! to the signer who completes the signing process and sends the blinded signature back.
//! The holder can then un-blind the signature finishing a 2-PC computation
//!
//! BBS+ signatures can be used for TPM DAA attestations or Verifiable Credentials.

#![deny(
    missing_docs,
    unsafe_code,
    unused_import_braces,
    unused_lifetimes,
    unused_qualifications
)]

#[macro_use]
extern crate arrayref;

use blake2::digest::{generic_array::GenericArray, Input, VariableOutput};
use errors::prelude::*;
use ff_zeroize::{Field, PrimeField};
use keys::prelude::*;
use pairing_plus::{
    bls12_381::{Fr, G1Affine, G1, G2},
    hash_to_curve::HashToCurve,
    hash_to_field::{BaseFromRO, ExpandMsgXmd},
    serdes::SerDes,
    CurveAffine, CurveProjective,
};
use pok_sig::prelude::*;
use pok_vc::prelude::*;
use rand::prelude::*;
#[cfg(feature = "rayon")]
use rayon::prelude::*;
use std::fmt::{Display, Formatter};

use serde::{
    de::{Error as DError, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::collections::{BTreeMap, BTreeSet};
use std::convert::TryFrom;
use std::io::Cursor;

/// Number of bytes in scalar compressed form
pub const FR_COMPRESSED_SIZE: usize = 32;
/// Number of bytes in scalar uncompressed form
pub const FR_UNCOMPRESSED_SIZE: usize = 48;
/// Number of bytes in G1 X coordinate
pub const G1_COMPRESSED_SIZE: usize = 48;
/// Number of bytes in G1 X and Y coordinates
pub const G1_UNCOMPRESSED_SIZE: usize = 96;
/// Number of bytes in G2 X (a, b) coordinate
pub const G2_COMPRESSED_SIZE: usize = 96;
/// Number of bytes in G2 X(a, b) and Y(a, b) coordinates
pub const G2_UNCOMPRESSED_SIZE: usize = 192;

#[macro_use]
mod macros;
/// Proof messages
#[macro_use]
pub mod messages;
/// Macros and classes used for creating proofs of knowledge
#[macro_use]
pub mod pok_vc;
/// The errors that BBS+ throws
pub mod errors;
/// Represents steps taken by the issuer to create a BBS+ signature
/// whether its 2PC or all in one
pub mod issuer;
/// BBS+ key classes
pub mod keys;
/// Methods and structs for creating signature proofs of knowledge
pub mod pok_sig;
/// Represents steps taken by the prover to receive a BBS+ signature
/// and generate ZKPs
pub mod prover;
/// Methods and structs for creating signatures
pub mod signature;
/// Represents steps taken by the verifier to request signature proofs of knowledge
/// and selective disclosure proofs
pub mod verifier;

/// Trait for structs that have variable length bytes but use compressed Bls12 elements
pub trait ToVariableLengthBytes {
    /// The type that implements this trait
    type Output;
    /// The type of error to return
    type Error;

    /// Convert to raw compressed bytes
    fn to_bytes_compressed_form(&self) -> Vec<u8>;

    /// Convert from raw compressed bytes
    fn from_bytes_compressed_form<I: AsRef<[u8]>>(data: I) -> Result<Self::Output, Self::Error>;

    /// Convert to raw bytes
    fn to_bytes_uncompressed_form(&self) -> Vec<u8>;

    /// Convert from raw bytes
    fn from_bytes_uncompressed_form<I: AsRef<[u8]>>(data: I) -> Result<Self::Output, Self::Error>;
}

/// Struct can be generated randomly
pub trait RandomElem {
    /// The type that implements this trait
    type Output;

    /// Return a randomly generated type
    fn random() -> Self::Output;
}

/// Struct can be generated from hashing
pub trait HashElem {
    /// The type that implements this trait
    type Output;

    /// Return a type from hashing `data`
    fn hash<I: AsRef<[u8]>>(data: I) -> Self;
}

/// The type for creating commitments to messages that are hidden during issuance.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Commitment(pub(crate) G1);

impl Commitment {
    /// Compute a new commitment from multiple points and scalars
    pub fn new<B: AsRef<[G1]>, S: AsRef<[Fr]>>(bases: B, scalars: S) -> Self {
        Commitment(multi_scalar_mul_const_time_g1(bases, scalars))
    }

    to_fixed_length_bytes_impl!(Commitment, G1, G1_COMPRESSED_SIZE, G1_UNCOMPRESSED_SIZE);
}

as_ref_impl!(Commitment, G1);
from_impl!(Commitment, G1, G1_COMPRESSED_SIZE, G1_UNCOMPRESSED_SIZE);
display_impl!(Commitment);
serdes_impl!(Commitment);
hash_elem_impl!(Commitment, |data| { Commitment(hash_to_g1(data)) });

/// Wrapper for G1
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct GeneratorG1(pub(crate) G1);

impl GeneratorG1 {
    to_fixed_length_bytes_impl!(GeneratorG1, G1, G1_COMPRESSED_SIZE, G1_UNCOMPRESSED_SIZE);
}

as_ref_impl!(GeneratorG1, G1);
from_impl!(GeneratorG1, G1, G1_COMPRESSED_SIZE, G1_UNCOMPRESSED_SIZE);
display_impl!(GeneratorG1);
serdes_impl!(GeneratorG1);
hash_elem_impl!(GeneratorG1, |data| { GeneratorG1(hash_to_g1(data)) });
random_elem_impl!(GeneratorG1, { Self(G1::random(&mut thread_rng())) });

/// Wrapper for G2
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct GeneratorG2(pub(crate) G2);

impl GeneratorG2 {
    to_fixed_length_bytes_impl!(GeneratorG2, G2, G2_COMPRESSED_SIZE, G2_UNCOMPRESSED_SIZE);
}

as_ref_impl!(GeneratorG2, G2);
from_impl!(GeneratorG2, G2, G2_COMPRESSED_SIZE, G2_UNCOMPRESSED_SIZE);
display_impl!(GeneratorG2);
serdes_impl!(GeneratorG2);
hash_elem_impl!(GeneratorG2, |data| { GeneratorG2(hash_to_g2(data)) });

/// Convenience wrapper for creating commitments
#[derive(Clone, Debug)]
pub struct CommitmentBuilder {
    bases: Vec<G1>,
    scalars: Vec<Fr>,
}

impl CommitmentBuilder {
    /// Initialize a new builder
    pub fn new() -> Self {
        Self {
            bases: Vec::new(),
            scalars: Vec::new(),
        }
    }

    /// Add a new base and scalar to the commitment
    pub fn add<B: AsRef<G1>, S: AsRef<Fr>>(&mut self, base: B, scalar: S) {
        self.bases.push(base.as_ref().clone());
        self.scalars.push(scalar.as_ref().clone().into());
    }

    /// Convert to commitment
    pub fn finalize(self) -> Commitment {
        Commitment(multi_scalar_mul_const_time_g1(&self.bases, &self.scalars))
    }
}

/// The type for messages
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct SignatureMessage(pub(crate) Fr);

impl SignatureMessage {
    to_fixed_length_bytes_impl!(SignatureMessage, Fr, FR_COMPRESSED_SIZE, FR_COMPRESSED_SIZE);
}

as_ref_impl!(SignatureMessage, Fr);
from_impl!(SignatureMessage, Fr, FR_COMPRESSED_SIZE);
display_impl!(SignatureMessage);
serdes_impl!(SignatureMessage);
hash_elem_impl!(SignatureMessage, |data| {
    SignatureMessage(hash_to_fr(data))
});
random_elem_impl!(SignatureMessage, { Self(Fr::random(&mut thread_rng())) });

/// The type for nonces
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct ProofNonce(pub(crate) Fr);

impl ProofNonce {
    to_fixed_length_bytes_impl!(ProofNonce, Fr, FR_COMPRESSED_SIZE, FR_COMPRESSED_SIZE);
}

as_ref_impl!(ProofNonce, Fr);
from_impl!(ProofNonce, Fr, FR_COMPRESSED_SIZE);
display_impl!(ProofNonce);
serdes_impl!(ProofNonce);
hash_elem_impl!(ProofNonce, |data| { ProofNonce(hash_to_fr(data)) });
random_elem_impl!(ProofNonce, { Self(Fr::random(&mut thread_rng())) });

/// The Fiat-Shamir Challenge in proofs
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct ProofChallenge(pub(crate) Fr);

impl ProofChallenge {
    to_fixed_length_bytes_impl!(ProofChallenge, Fr, FR_COMPRESSED_SIZE, FR_COMPRESSED_SIZE);
}

as_ref_impl!(ProofChallenge, Fr);
from_impl!(ProofChallenge, Fr, FR_COMPRESSED_SIZE);
display_impl!(ProofChallenge);
serdes_impl!(ProofChallenge);
hash_elem_impl!(ProofChallenge, |data| { ProofChallenge(hash_to_fr(data)) });
random_elem_impl!(ProofChallenge, { Self(Fr::random(&mut thread_rng())) });

/// The type for blinding factors
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct SignatureBlinding(pub(crate) Fr);

impl SignatureBlinding {
    to_fixed_length_bytes_impl!(
        SignatureBlinding,
        Fr,
        FR_COMPRESSED_SIZE,
        FR_COMPRESSED_SIZE
    );
}

as_ref_impl!(SignatureBlinding, Fr);
from_impl!(SignatureBlinding, Fr, FR_COMPRESSED_SIZE);
display_impl!(SignatureBlinding);
serdes_impl!(SignatureBlinding);
hash_elem_impl!(SignatureBlinding, |data| {
    SignatureBlinding(hash_to_fr(data))
});
random_elem_impl!(SignatureBlinding, { Self(Fr::random(&mut thread_rng())) });

pub(crate) fn hash_to_g1<I: AsRef<[u8]>>(data: I) -> G1 {
    const DST: &[u8] = b"BLS12381G1_XMD:BLAKE2B_SSWU_RO_BBS+_SIGNATURES:1_0_0";
    <G1 as HashToCurve<ExpandMsgXmd<blake2::Blake2b>>>::hash_to_curve(data.as_ref(), DST)
}

pub(crate) fn hash_to_g2<I: AsRef<[u8]>>(data: I) -> G2 {
    const DST: &[u8] = b"BLS12381G2_XMD:BLAKE2B_SSWU_RO_BBS+_SIGNATURES:1_0_0";
    <G2 as HashToCurve<ExpandMsgXmd<blake2::Blake2b>>>::hash_to_curve(data.as_ref(), DST)
}

pub(crate) fn hash_to_fr<I: AsRef<[u8]>>(data: I) -> Fr {
    let mut res = GenericArray::default();
    let mut hasher = blake2::VarBlake2b::new(FR_UNCOMPRESSED_SIZE).unwrap();
    hasher.input(data.as_ref());
    hasher.variable_result(|out| {
        res.copy_from_slice(out);
    });
    Fr::from_okm(&res)
}

pub(crate) fn multi_scalar_mul_const_time_g1<G: AsRef<[G1]>, S: AsRef<[Fr]>>(
    bases: G,
    scalars: S,
) -> G1 {
    let bases: Vec<_> = bases.as_ref().iter().map(|b| b.into_affine()).collect();
    let scalars: Vec<[u64; 4]> = scalars
        .as_ref()
        .iter()
        .map(|s| {
            let mut t = [0u64; 4];
            t.clone_from_slice(s.into_repr().as_ref());
            t
        })
        .collect();
    // Annoying step to keep the borrow checker happy
    let s: Vec<&[u64; 4]> = scalars.iter().map(|u| u).collect();
    G1Affine::sum_of_products(bases.as_slice(), s.as_slice())
}

pub(crate) fn multi_scalar_mul_var_time_g1<G: AsRef<[G1]>, S: AsRef<[Fr]>>(
    bases: G,
    scalars: S,
) -> G1 {
    let bases = bases.as_ref();
    let scalars = scalars.as_ref();
    #[cfg(feature = "rayon")]
    {
        bases
            .par_iter()
            .zip(scalars.par_iter())
            .map(|(b, s)| {
                let mut t = b.clone();
                t.mul_assign(*s);
                t
            })
            .reduce(
                || G1::zero(),
                |mut acc, b| {
                    acc.add_assign(&b);
                    acc
                },
            )
    }
    #[cfg(not(feature = "rayon"))]
    {
        bases
            .iter()
            .zip(scalars.iter())
            .map(|(b, s)| {
                let mut t = b.clone();
                t.mul_assign(*s);
                t
            })
            .fold(G1::zero(), |mut acc, b| {
                acc.add_assign(&b);
                acc
            })
    }
}

/// Contains the data used for computing a blind signature and verifying
/// proof of hidden messages from a prover
#[derive(Debug, Clone)]
pub struct BlindSignatureContext {
    /// The blinded signature commitment
    pub commitment: Commitment,
    /// The challenge hash for the Fiat-Shamir heuristic
    pub challenge_hash: ProofChallenge,
    /// The proof for the hidden messages
    pub proof_of_hidden_messages: ProofG1,
}

impl BlindSignatureContext {
    fn to_bytes(&self, compressed: bool) -> Vec<u8> {
        let mut output = Vec::new();
        self.commitment
            .0
            .serialize(&mut output, compressed)
            .unwrap();
        self.challenge_hash
            .0
            .serialize(&mut output, compressed)
            .unwrap();
        output.append(&mut self.proof_of_hidden_messages.to_bytes(compressed));
        output
    }

    fn from_bytes(data: &[u8], g1_size: usize, compressed: bool) -> Result<Self, BBSError> {
        let min_size = g1_size * 2 + FR_COMPRESSED_SIZE + 4;
        let mut cursor = Cursor::new(data);
        if data.len() < min_size {
            return Err(BBSError::from(BBSErrorKind::InvalidNumberOfBytes(
                min_size,
                data.len(),
            )));
        }

        let commitment = Commitment(slice_to_elem!(&mut cursor, G1, compressed).map_err(|e| {
            BBSError::from_kind(BBSErrorKind::PoKVCError {
                msg: format!("{}", e),
            })
        })?);

        let end = g1_size + FR_COMPRESSED_SIZE;

        let challenge_hash =
            ProofChallenge(slice_to_elem!(&mut cursor, Fr, compressed).map_err(|e| {
                BBSError::from_kind(BBSErrorKind::PoKVCError {
                    msg: format!("{}", e),
                })
            })?);

        let proof_of_hidden_messages = ProofG1::from_bytes(&data[end..], g1_size, compressed)?;
        Ok(Self {
            commitment,
            challenge_hash,
            proof_of_hidden_messages,
        })
    }

    /// Assumes the proof of hidden messages
    /// If other proofs were included, those will need to be verified another
    /// way
    pub fn verify(
        &self,
        revealed_messages: &BTreeSet<usize>,
        verkey: &PublicKey,
        nonce: &ProofNonce,
    ) -> Result<bool, BBSError> {
        // Verify the proof
        // First get the generators used to create the commitment
        let mut bases = Vec::new();
        bases.push(verkey.h0.clone());
        for i in 0..verkey.message_count() {
            if !revealed_messages.contains(&i) {
                bases.push(verkey.h[i].clone());
            }
        }

        let mut commitment = self.proof_of_hidden_messages.get_challenge_contribution(
            bases.as_slice(),
            &self.commitment,
            &self.challenge_hash,
        )?;

        let mut challenge_bytes = Vec::new();
        for b in bases.iter() {
            b.0.serialize(&mut challenge_bytes, false).unwrap();
        }
        commitment.0.serialize(&mut challenge_bytes, false).unwrap();
        self.commitment
            .0
            .serialize(&mut challenge_bytes, false)
            .unwrap();
        challenge_bytes.extend_from_slice(&nonce.to_bytes_uncompressed_form()[..]);

        let mut challenge = SignatureMessage::hash(&challenge_bytes);
        challenge.0.sub_assign(&self.challenge_hash.0);

        commitment
            .0
            .sub_assign(&self.proof_of_hidden_messages.commitment);

        Ok(commitment.0.is_zero() && challenge.0.is_zero())
    }
}

impl ToVariableLengthBytes for BlindSignatureContext {
    type Output = Self;
    type Error = BBSError;

    fn to_bytes_compressed_form(&self) -> Vec<u8> {
        self.to_bytes(true)
    }

    fn from_bytes_compressed_form<I: AsRef<[u8]>>(data: I) -> Result<Self::Output, Self::Error> {
        Self::from_bytes(data.as_ref(), G1_COMPRESSED_SIZE, true)
    }

    fn to_bytes_uncompressed_form(&self) -> Vec<u8> {
        self.to_bytes(false)
    }

    fn from_bytes_uncompressed_form<I: AsRef<[u8]>>(data: I) -> Result<Self::Output, Self::Error> {
        Self::from_bytes(data.as_ref(), G1_UNCOMPRESSED_SIZE, false)
    }
}

try_from_impl!(BlindSignatureContext, BBSError);
serdes_impl!(BlindSignatureContext);

/// Contains the data from a verifier to a prover
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofRequest {
    /// Allow the prover to retrieve which messages should be revealed.
    /// Might be prompted in a GUI or CLI
    pub revealed_messages: BTreeSet<usize>,
    /// Allow the prover to know which public key for which the signature must
    /// be valid.
    pub verification_key: PublicKey,
}

impl ProofRequest {
    pub(crate) fn to_bytes(&self, compressed: bool) -> Vec<u8> {
        let revealed: Vec<usize> = (&self.revealed_messages).iter().map(|i| *i).collect();
        let mut temp =
            revealed_to_bitvector(self.verification_key.message_count(), revealed.as_slice());
        let mut key = self.verification_key.to_bytes(compressed);
        let mut output = (temp.len() as u32).to_be_bytes().to_vec();
        output.append(&mut temp);
        output.append(&mut key);
        output
    }

    pub(crate) fn from_bytes(
        data: &[u8],
        g1_size: usize,
        g2_size: usize,
        compressed: bool,
    ) -> Result<Self, BBSError> {
        let min_len = 8 + g1_size + g2_size;
        if data.len() < min_len {
            return Err(BBSErrorKind::InvalidNumberOfBytes(min_len, data.len()).into());
        }
        let bitvector_len = u32::from_be_bytes(*array_ref![data, 0, 4]) as usize;
        let offset = 4 + bitvector_len;
        let revealed_messages = bitvector_to_revealed(&data[4..offset]);
        let verification_key = PublicKey::from_bytes(&data[offset..], g1_size, compressed)?;
        Ok(Self {
            revealed_messages,
            verification_key,
        })
    }
}

impl ToVariableLengthBytes for ProofRequest {
    type Output = ProofRequest;
    type Error = BBSError;

    fn to_bytes_compressed_form(&self) -> Vec<u8> {
        self.to_bytes(true)
    }

    fn from_bytes_compressed_form<I: AsRef<[u8]>>(data: I) -> Result<Self::Output, Self::Error> {
        Self::from_bytes(data.as_ref(), G1_COMPRESSED_SIZE, G2_COMPRESSED_SIZE, true)
    }

    fn to_bytes_uncompressed_form(&self) -> Vec<u8> {
        self.to_bytes(false)
    }

    fn from_bytes_uncompressed_form<I: AsRef<[u8]>>(data: I) -> Result<Self::Output, Self::Error> {
        Self::from_bytes(
            data.as_ref(),
            G1_UNCOMPRESSED_SIZE,
            G2_UNCOMPRESSED_SIZE,
            false,
        )
    }
}

/// Contains the data from a prover to a verifier
#[derive(Debug, Clone)]
pub struct SignatureProof {
    /// The revealed messages as field elements
    pub revealed_messages: BTreeMap<usize, SignatureMessage>,
    /// The signature proof of knowledge
    pub proof: PoKOfSignatureProof,
}

impl SignatureProof {
    /// Convert to raw bytes
    pub(crate) fn to_bytes(&self, compressed: bool) -> Vec<u8> {
        let proof_bytes = self.proof.to_bytes(compressed);
        let proof_len = proof_bytes.len() as u32;

        let mut output =
            Vec::with_capacity(proof_len as usize + 4 * (self.revealed_messages.len() + 1));
        output.extend_from_slice(&proof_len.to_be_bytes()[..]);
        output.extend_from_slice(proof_bytes.as_slice());

        let revealed_messages_len = self.revealed_messages.len() as u32;
        output.extend_from_slice(&revealed_messages_len.to_be_bytes()[..]);
        for (i, m) in &self.revealed_messages {
            let ii = *i as u32;
            output.extend_from_slice(&ii.to_be_bytes()[..]);
            m.0.serialize(&mut output, compressed).unwrap();
        }

        output
    }

    /// Convert from raw bytes
    pub(crate) fn from_bytes(
        data: &[u8],
        g1_size: usize,
        compressed: bool,
    ) -> Result<Self, BBSError> {
        if data.len() < 8 {
            return Err(BBSError::from(BBSErrorKind::InvalidNumberOfBytes(
                8,
                data.len(),
            )));
        }

        let proof_len = u32::from_be_bytes(*array_ref![data, 0, 4]) as usize + 4;
        let proof = PoKOfSignatureProof::from_bytes(&data[4..proof_len], g1_size, compressed)
            .map_err(|e| BBSErrorKind::GeneralError {
                msg: format!("{:?}", e),
            })?;

        let mut offset = proof_len;
        let revealed_messages_len = u32::from_be_bytes(*array_ref![data, offset, 4]) as usize;
        offset += 4;
        let mut end = offset + 4;

        let mut revealed_messages = BTreeMap::new();
        for _ in 0..revealed_messages_len {
            let i = u32::from_be_bytes(*array_ref![data, offset, 4]) as usize;

            offset = end;
            end = offset + FR_COMPRESSED_SIZE;

            let m = SignatureMessage::from(array_ref![data, offset, FR_COMPRESSED_SIZE]);

            offset = end;
            end = offset + 4;

            revealed_messages.insert(i, m);
        }

        Ok(Self {
            revealed_messages,
            proof,
        })
    }
}

impl ToVariableLengthBytes for SignatureProof {
    type Output = SignatureProof;
    type Error = BBSError;

    /// Convert to raw bytes using compressed form for each element.
    fn to_bytes_compressed_form(&self) -> Vec<u8> {
        self.to_bytes(true)
    }

    /// Convert from compressed form raw bytes.
    fn from_bytes_compressed_form<I: AsRef<[u8]>>(data: I) -> Result<Self, BBSError> {
        Self::from_bytes(data.as_ref(), G1_COMPRESSED_SIZE, true)
    }

    fn to_bytes_uncompressed_form(&self) -> Vec<u8> {
        self.to_bytes(false)
    }

    fn from_bytes_uncompressed_form<I: AsRef<[u8]>>(data: I) -> Result<Self::Output, Self::Error> {
        Self::from_bytes(data.as_ref(), G1_UNCOMPRESSED_SIZE, false)
    }
}

try_from_impl!(SignatureProof, BBSError);
serdes_impl!(SignatureProof);

/// Expects `revealed` to be sorted
fn revealed_to_bitvector(total: usize, revealed: &[usize]) -> Vec<u8> {
    let mut bytes = vec![0u8; (total / 8) + 1];

    for r in revealed {
        let idx = *r / 8;
        let bit = (*r % 8) as u8;
        bytes[idx] |= 1u8 << bit;
    }

    // Convert to big endian
    bytes.reverse();
    bytes
}

/// Convert big-endian vector to u32
fn bitvector_to_revealed(data: &[u8]) -> BTreeSet<usize> {
    let mut revealed_messages = BTreeSet::new();
    let mut scalar = 0;

    for b in data.iter().rev() {
        let mut v = *b;
        let mut remaining = 8;
        while v > 0 {
            let revealed = v & 1u8;
            if revealed == 1 {
                revealed_messages.insert(scalar);
            }
            v >>= 1;
            scalar += 1;
            remaining -= 1;
        }
        scalar += remaining;
    }
    revealed_messages
}

/// Convenience importer
pub mod prelude {
    pub use super::{
        errors::prelude::*, issuer::Issuer, keys::prelude::*, messages::*, pok_sig::prelude::*,
        pok_vc::prelude::*, prover::Prover, signature::prelude::*, verifier::Verifier,
        BlindSignatureContext, Commitment, CommitmentBuilder, GeneratorG1, GeneratorG2, HashElem,
        ProofChallenge, ProofNonce, ProofRequest, RandomElem, SignatureBlinding, SignatureMessage,
        SignatureProof, ToVariableLengthBytes, FR_COMPRESSED_SIZE, G1_COMPRESSED_SIZE,
        G1_UNCOMPRESSED_SIZE, G2_COMPRESSED_SIZE, G2_UNCOMPRESSED_SIZE,
    };
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;
    use ff_zeroize::Field;
    use pairing_plus::{
        bls12_381::{Fr, G1},
        CurveProjective,
    };
    use rand::thread_rng;
    use std::collections::BTreeMap;

    #[ignore]
    #[test]
    fn speed_multi_scalar_test() {
        let count = 5;
        // let mut bases = Vec::new();
        let mut scalars = Vec::new();
        let mut rng = thread_rng();
        //
        for _ in 0..count {
            //     bases.push(G1::random(&mut rng));
            scalars.push(Fr::random(&mut rng));
        }
        let start = std::time::Instant::now();
        let (pk, sk) = generate(count).unwrap();
        println!("keygen = {:?}", std::time::Instant::now() - start);

        let msgs: Vec<SignatureMessage> = scalars.iter().map(|e| SignatureMessage(*e)).collect();
        let start = std::time::Instant::now();
        let sig = Signature::new(msgs.as_slice(), &sk, &pk).unwrap();
        println!("sig gen = {:?}", std::time::Instant::now() - start);
        let start = std::time::Instant::now();
        let temp = sig.verify(msgs.as_slice(), &pk);
        println!("sig verify = {:?}", std::time::Instant::now() - start);
        println!("temp = {:?}", temp);

        let start = std::time::Instant::now();
        let (dpk, _) = DeterministicPublicKey::new(Some(KeyGenOption::FromSecretKey(sk)));
        println!("dpkgen = {:?}", std::time::Instant::now() - start);
        let start = std::time::Instant::now();
        let _ = dpk.to_public_key(count);
        println!("to_public_key = {:?}", std::time::Instant::now() - start);
    }

    #[test]
    fn proof_request_bytes_test() {
        let (pk, _) = generate(5).unwrap();
        let pr = Verifier::new_proof_request(&[2, 3, 4], &pk).unwrap();

        let bytes = pr.to_bytes_compressed_form();
        let pr_1 = ProofRequest::from_bytes_compressed_form(&bytes);
        assert!(pr_1.is_ok());
        let pr_1 = pr_1.unwrap();
        let bytes_1 = pr_1.to_bytes_compressed_form();
        assert_eq!(bytes[..], bytes_1[..]);
    }

    #[test]
    fn blind_signature_context_bytes_test() {
        let b = BlindSignatureContext {
            commitment: Commitment(G1::one()),
            challenge_hash: ProofChallenge::random(),
            proof_of_hidden_messages: ProofG1 {
                commitment: G1::one(),
                responses: Vec::new(),
            },
        };

        let bytes = b.to_bytes_uncompressed_form();
        let res = BlindSignatureContext::from_bytes_uncompressed_form(&bytes);
        assert!(res.is_ok());
        assert_eq!(res.unwrap().to_bytes_uncompressed_form(), bytes);

        let b = BlindSignatureContext {
            commitment: Commitment(G1::one()),
            challenge_hash: ProofChallenge::random(),
            proof_of_hidden_messages: ProofG1 {
                commitment: G1::one(),
                responses: (0..10)
                    .collect::<Vec<usize>>()
                    .iter()
                    .map(|_| SignatureMessage::random().0)
                    .collect(),
            },
        };

        let bytes = b.to_bytes_compressed_form();
        let res = BlindSignatureContext::from_bytes_compressed_form(&bytes);
        assert!(res.is_ok());
        assert_eq!(res.unwrap().to_bytes_compressed_form(), bytes);
    }

    #[test]
    fn proof_bytes_test() {
        // No revealed messages
        let proof = SignatureProof {
            revealed_messages: BTreeMap::new(),
            proof: PoKOfSignatureProof {
                a_prime: G1::zero(),
                a_bar: G1::zero(),
                d: G1::zero(),
                proof_vc_1: ProofG1 {
                    commitment: G1::zero(),
                    responses: Vec::with_capacity(1),
                },
                proof_vc_2: ProofG1 {
                    commitment: G1::zero(),
                    responses: Vec::with_capacity(1),
                },
            },
        };

        let proof_bytes = proof.to_bytes_uncompressed_form();

        let proof_dup = SignatureProof::from_bytes_uncompressed_form(&proof_bytes);
        assert!(proof_dup.is_ok());

        let (pk, sk) = Issuer::new_keys(1).unwrap();
        let messages = vec![SignatureMessage::random()];
        let sig = Signature::new(messages.as_slice(), &sk, &pk).unwrap();

        let pr = Verifier::new_proof_request(&[0], &pk).unwrap();
        let pm = vec![pm_revealed_raw!(messages[0].clone())];
        let pok = Prover::commit_signature_pok(&pr, pm.as_slice(), &sig).unwrap();
        let nonce = ProofNonce::hash(&[0u8, 1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8, 8u8, 9u8]);
        let mut challenge_bytes = pok.to_bytes();
        challenge_bytes.extend_from_slice(&nonce.to_bytes_uncompressed_form()[..]);
        let challenge = ProofChallenge::hash(challenge_bytes.as_slice());

        let sig_proof = Prover::generate_signature_pok(pok, &challenge).unwrap();

        assert!(
            Verifier::verify_signature_pok(&pr, &sig_proof, &nonce)
                .unwrap()
                .len()
                == 1
        );
        let sig_proof_bytes = sig_proof.to_bytes_uncompressed_form();

        let sig_proof_dup = SignatureProof::from_bytes_uncompressed_form(&sig_proof_bytes);
        assert!(sig_proof_dup.is_ok());
        let sig_proof_dup = sig_proof_dup.unwrap();
        assert!(
            Verifier::verify_signature_pok(&pr, &sig_proof_dup, &nonce)
                .unwrap()
                .len()
                == 1
        );

        let sig_proof_bytes = sig_proof.to_bytes_compressed_form();

        let sig_proof_dup = SignatureProof::from_bytes_compressed_form(&sig_proof_bytes);
        assert!(sig_proof_dup.is_ok());
    }
}
