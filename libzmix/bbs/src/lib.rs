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

use errors::prelude::*;
use keys::prelude::*;
use pok_sig::prelude::*;
use pok_vc::prelude::*;

use amcl_wrapper::{
    constants::{
        CURVE_ORDER_ELEMENT_SIZE, FIELD_ORDER_ELEMENT_SIZE as MESSAGE_SIZE,
        GROUP_G1_SIZE as COMMITMENT_SIZE,
    },
    curve_order_elem::{CurveOrderElement, CurveOrderElementVector},
    group_elem::GroupElement,
    group_elem_g1::{G1Vector, G1},
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

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

/// The type for creating commitments to messages that are hidden during issuance.
pub type BlindedSignatureCommitment = G1;
/// The type for managing lists of generators
pub type SignaturePointVector = G1Vector;
/// The type for messages
pub type SignatureMessage = CurveOrderElement;
/// The type for managing lists of messages
pub type SignatureMessageVector = CurveOrderElementVector;
/// The type for nonces
pub type SignatureNonce = CurveOrderElement;
/// The type for blinding factors
pub type SignatureBlinding = CurveOrderElement;

mod types {
    pub use super::{
        BlindSignatureContext, BlindedSignatureCommitment, ProofRequest, SignatureBlinding,
        SignatureMessage, SignatureMessageVector, SignatureNonce, SignaturePointVector,
        SignatureProof,
    };
}

/// Convenience importing module
pub mod prelude {
    pub use super::{
        BlindSignatureContext, BlindedSignatureCommitment, ProofRequest, SignatureBlinding,
        SignatureMessage, SignatureMessageVector, SignatureNonce, SignaturePointVector,
        SignatureProof,
    };
    pub use crate::errors::prelude::*;
    pub use crate::issuer::Issuer;
    pub use crate::keys::prelude::*;
    pub use crate::messages::{HiddenMessage, ProofMessage};
    pub use crate::pok_sig::prelude::*;
    pub use crate::pok_vc::prelude::*;
    pub use crate::prover::Prover;
    pub use crate::signature::prelude::*;
    pub use crate::verifier::Verifier;
    pub use amcl_wrapper::constants::CURVE_ORDER_ELEMENT_SIZE as COMPRESSED_SECRET_KEY_SIZE;
    pub use amcl_wrapper::constants::FIELD_ORDER_ELEMENT_SIZE as COMPRESSED_PUBLIC_KEY_SIZE;
    pub use amcl_wrapper::constants::FIELD_ORDER_ELEMENT_SIZE as SECRET_KEY_SIZE;
    pub use amcl_wrapper::constants::FIELD_ORDER_ELEMENT_SIZE as MESSAGE_SIZE;
    pub use amcl_wrapper::constants::FIELD_ORDER_ELEMENT_SIZE as NONCE_SIZE;
    pub use amcl_wrapper::constants::FIELD_ORDER_ELEMENT_SIZE as BLINDING_FACTOR_SIZE;
    pub use amcl_wrapper::constants::GROUP_G1_SIZE as COMMITMENT_SIZE;
    pub use amcl_wrapper::group_elem::{GroupElement, GroupElementVector};
    pub use amcl_wrapper::types_g2::GROUP_G2_SIZE as PUBLIC_KEY_SIZE;
}

/// Contains the data used for computing a blind signature and verifying
/// proof of hidden messages from a prover
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlindSignatureContext {
    /// The blinded signature commitment
    pub commitment: BlindedSignatureCommitment,
    /// The challenge hash for the Fiat-Shamir heuristic
    pub challenge_hash: SignatureNonce,
    /// The proof for the hidden messages
    pub proof_of_hidden_messages: ProofG1,
}

impl BlindSignatureContext {
    /// Convert to raw bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let proof_bytes = self.proof_of_hidden_messages.to_bytes();
        let proof_len = proof_bytes.len() as u32;

        let mut output = Vec::with_capacity(proof_len as usize + COMMITMENT_SIZE + MESSAGE_SIZE);
        output.extend_from_slice(&self.commitment.to_vec()[..]);
        output.extend_from_slice(&self.challenge_hash.to_bytes()[..]);
        output.extend_from_slice(&proof_len.to_be_bytes()[..]);
        output.extend_from_slice(proof_bytes.as_slice());

        output
    }

    /// Convert from raw bytes
    pub fn from_bytes<I: AsRef<[u8]>>(data: I) -> Result<Self, BBSError> {
        let data = data.as_ref();

        if data.len() < COMMITMENT_SIZE + MESSAGE_SIZE + 4 {
            return Err(BBSError::from(BBSErrorKind::InvalidNumberOfBytes(
                4 + COMMITMENT_SIZE + MESSAGE_SIZE,
                data.len(),
            )));
        }

        let mut offset = COMMITMENT_SIZE + MESSAGE_SIZE;

        let commitment =
            BlindedSignatureCommitment::from_slice(&data[..COMMITMENT_SIZE]).map_err(|e| {
                BBSErrorKind::GeneralError {
                    msg: format!("{:?}", e),
                }
            })?;
        let challenge_hash = SignatureNonce::from(array_ref![data, COMMITMENT_SIZE, MESSAGE_SIZE]);

        let proof_len = u32::from_be_bytes(*array_ref![data, offset, 4]) as usize;
        offset += 4;
        let end = offset + proof_len;
        let proof_of_hidden_messages =
            ProofG1::from_bytes(&data[offset..end]).map_err(|e| BBSErrorKind::GeneralError {
                msg: format!("{:?}", e),
            })?;

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
        messages: &BTreeMap<usize, SignatureMessage>,
        verkey: &PublicKey,
        nonce: &SignatureNonce,
    ) -> Result<bool, BBSError> {
        // Verify the proof
        // First get the generators used to create the commitment
        let mut bases = Vec::new();
        bases.push(verkey.h0.clone());
        for i in 0..verkey.message_count() {
            if !messages.contains_key(&i) {
                bases.push(verkey.h[i].clone());
            }
        }

        let commitment = self.proof_of_hidden_messages.get_challenge_contribution(
            bases.as_slice(),
            &self.commitment,
            &self.challenge_hash,
        )?;

        let mut challenge_bytes = Vec::new();
        for b in bases.iter() {
            challenge_bytes.append(&mut b.to_vec())
        }
        challenge_bytes.extend_from_slice(&commitment.to_vec()[..]);
        challenge_bytes.extend_from_slice(self.commitment.to_vec().as_slice());
        challenge_bytes.extend_from_slice(&nonce.to_bytes()[..]);

        let challenge_result =
            SignatureMessage::from_msg_hash(challenge_bytes.as_slice()) - &self.challenge_hash;
        let commitment_result = commitment - &self.proof_of_hidden_messages.commitment;
        Ok(commitment_result.is_identity() && challenge_result.is_zero())
    }

    /// Convert to compressed form. Use for sending over the wire
    pub fn to_compressed_bytes(&self) -> Vec<u8> {
        let mut output = Vec::new();

        output.extend_from_slice(&self.commitment.to_compressed_bytes()[..]);
        output.extend_from_slice(&self.challenge_hash.to_compressed_bytes()[..]);
        output.extend_from_slice(&self.proof_of_hidden_messages.to_compressed_bytes()[..]);

        output
    }

    /// Load from compressed bytes
    pub fn from_compressed_bytes(data: &[u8]) -> Result<Self, BBSError> {
        if data.len() < MESSAGE_SIZE + CURVE_ORDER_ELEMENT_SIZE + 4 {
            return Err(BBSErrorKind::InvalidNumberOfBytes(
                MESSAGE_SIZE + CURVE_ORDER_ELEMENT_SIZE + 4,
                data.len(),
            )
            .into());
        }

        let commitment = BlindedSignatureCommitment::from(array_ref![data, 0, MESSAGE_SIZE]);
        let challenge_hash =
            SignatureNonce::from(array_ref![data, MESSAGE_SIZE, CURVE_ORDER_ELEMENT_SIZE]);
        let offset = MESSAGE_SIZE + CURVE_ORDER_ELEMENT_SIZE;
        let proof_of_hidden_messages = ProofG1::from_compressed_bytes(&data[offset..])?;

        Ok(Self {
            commitment,
            challenge_hash,
            proof_of_hidden_messages,
        })
    }
}

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
    /// Convert to raw bytes. Use when sending over the wire
    pub fn to_compressed_bytes(&self) -> Vec<u8> {
        let revealed_len = self.revealed_messages.len() as u32;

        let mut output = Vec::new();
        output.extend_from_slice(&revealed_len.to_be_bytes()[..]);
        for i in &self.revealed_messages {
            let ii = *i as u32;
            output.extend_from_slice(&ii.to_be_bytes()[..]);
        }
        output.extend_from_slice(self.verification_key.to_compressed_bytes().as_slice());
        output
    }

    /// Convert from raw bytes. Use when sending over the wire
    pub fn from_compressed_bytes<I: AsRef<[u8]>>(data: I) -> Result<Self, BBSError> {
        let data = data.as_ref();
        if data.len() < 4 + MESSAGE_SIZE * 2 {
            return Err(BBSError::from(BBSErrorKind::InvalidNumberOfBytes(
                4 + MESSAGE_SIZE * 2,
                data.len(),
            )));
        }

        let revealed_len = u32::from_be_bytes(*array_ref![data, 0, 4]) as usize;
        let mut offset = 4;
        let mut revealed_messages = BTreeSet::new();
        for _ in 0..revealed_len {
            let i = u32::from_be_bytes(*array_ref![data, offset, 4]) as usize;
            revealed_messages.insert(i);
            offset += 4;
        }
        let verification_key = PublicKey::from_compressed_bytes(&data[offset..])?;
        Ok(Self {
            revealed_messages,
            verification_key,
        })
    }
}

/// Contains the data from a prover to a verifier
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureProof {
    /// The revealed messages as field elements
    pub revealed_messages: BTreeMap<usize, SignatureMessage>,
    /// The signature proof of knowledge
    pub proof: PoKOfSignatureProof,
}

impl SignatureProof {
    /// Convert to raw bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let proof_bytes = self.proof.to_bytes();
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
            output.extend_from_slice(&m.to_bytes()[..]);
        }

        output
    }

    /// Convert from raw bytes
    pub fn from_bytes<I: AsRef<[u8]>>(data: I) -> Result<Self, BBSError> {
        let data = data.as_ref();

        if data.len() < 8 {
            return Err(BBSError::from(BBSErrorKind::InvalidNumberOfBytes(
                8,
                data.len(),
            )));
        }

        let proof_len = u32::from_be_bytes(*array_ref![data, 0, 4]) as usize + 4;
        let proof = PoKOfSignatureProof::from_bytes(&data[4..proof_len]).map_err(|e| {
            BBSErrorKind::GeneralError {
                msg: format!("{:?}", e),
            }
        })?;

        let mut offset = proof_len;
        let revealed_messages_len = u32::from_be_bytes(*array_ref![data, offset, 4]) as usize;
        offset += 4;
        let mut end = offset + 4;

        let mut revealed_messages = BTreeMap::new();
        for _ in 0..revealed_messages_len {
            let i = u32::from_be_bytes(*array_ref![data, offset, 4]) as usize;

            offset = end;
            end = offset + MESSAGE_SIZE;

            let m = SignatureMessage::from(array_ref![data, offset, MESSAGE_SIZE]);

            offset = end;
            end = offset + 4;

            revealed_messages.insert(i, m);
        }

        Ok(Self {
            revealed_messages,
            proof,
        })
    }

    /// Convert to compressed form. Use for sending over the wire
    pub fn to_compressed_bytes(&self) -> Vec<u8> {
        let proof_bytes = self.proof.to_compressed_bytes();
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
            output.extend_from_slice(&m.to_compressed_bytes()[..]);
        }

        output
    }

    /// Convert from compressed bytes. Use when sending over the wire
    pub fn from_compressed_bytes<I: AsRef<[u8]>>(data: I) -> Result<Self, BBSError> {
        let data = data.as_ref();

        if data.len() < 8 {
            return Err(BBSError::from(BBSErrorKind::InvalidNumberOfBytes(
                8,
                data.len(),
            )));
        }
        let proof_len = u32::from_be_bytes(*array_ref![data, 0, 4]) as usize + 4;
        let proof = PoKOfSignatureProof::from_compressed_bytes(&data[4..proof_len])?;
        let revealed_messages_len = u32::from_be_bytes(*array_ref![data, proof_len, 4]);
        let mut revealed_messages = BTreeMap::new();
        let mut offset = proof_len + 4;
        for _ in 0..revealed_messages_len {
            let i = u32::from_be_bytes(*array_ref![data, offset, 4]) as usize;
            offset += 4;
            let m = SignatureMessage::from(array_ref![data, offset, CURVE_ORDER_ELEMENT_SIZE]);
            offset += CURVE_ORDER_ELEMENT_SIZE;

            revealed_messages.insert(i, m);
        }

        Ok(Self {
            revealed_messages,
            proof,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;
    use amcl_wrapper::{group_elem::GroupElement, group_elem_g1::G1};
    use std::collections::BTreeMap;

    #[test]
    fn proof_request_bytes_test() {
        let (pk, _) = generate(5).unwrap();
        let pr = Verifier::new_proof_request(&[2, 3, 4], &pk).unwrap();

        let bytes = pr.to_compressed_bytes();
        let pr_1 = ProofRequest::from_compressed_bytes(&bytes);
        assert!(pr_1.is_ok());
        let pr_1 = pr_1.unwrap();
        let bytes_1 = pr_1.to_compressed_bytes();
        assert_eq!(bytes[..], bytes_1[..]);
    }

    #[test]
    fn blind_signature_context_bytes_test() {
        let b = BlindSignatureContext {
            commitment: G1::generator(),
            challenge_hash: SignatureMessage::random(),
            proof_of_hidden_messages: ProofG1 {
                commitment: G1::generator(),
                responses: SignatureMessageVector::new(0),
            },
        };

        let bytes = b.to_bytes();
        let res = BlindSignatureContext::from_bytes(&bytes);
        assert!(res.is_ok());
        assert_eq!(res.unwrap().to_bytes(), bytes);

        let b = BlindSignatureContext {
            commitment: G1::generator(),
            challenge_hash: SignatureMessage::random(),
            proof_of_hidden_messages: ProofG1 {
                commitment: G1::generator(),
                responses: SignatureMessageVector::new(10),
            },
        };

        let bytes = b.to_bytes();
        let res = BlindSignatureContext::from_bytes(&bytes);
        assert!(res.is_ok());
        assert_eq!(res.unwrap().to_bytes(), bytes);
    }

    #[test]
    fn proof_bytes_test() {
        // No revealed messages
        let proof = SignatureProof {
            revealed_messages: BTreeMap::new(),
            proof: PoKOfSignatureProof {
                a_prime: G1::new(),
                a_bar: G1::new(),
                d: G1::new(),
                proof_vc_1: ProofG1 {
                    commitment: G1::new(),
                    responses: SignatureMessageVector::with_capacity(1),
                },
                proof_vc_2: ProofG1 {
                    commitment: G1::new(),
                    responses: SignatureMessageVector::with_capacity(1),
                },
            },
        };

        let proof_bytes = proof.to_bytes();

        let proof_dup = SignatureProof::from_bytes(&proof_bytes);
        assert!(proof_dup.is_ok());

        let (pk, sk) = Issuer::new_keys(1).unwrap();
        let messages = vec![SignatureMessage::random()];
        let sig = Signature::new(messages.as_slice(), &sk, &pk).unwrap();

        let pr = Verifier::new_proof_request(&[0], &pk).unwrap();
        let pm = vec![pm_revealed_raw!(messages[0].clone())];
        let pok = Prover::commit_signature_pok(&pr, pm.as_slice(), &sig).unwrap();
        let nonce =
            SignatureNonce::from_msg_hash(&[0u8, 1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8, 8u8, 9u8]);
        let mut challenge_bytes = pok.to_bytes();
        challenge_bytes.extend_from_slice(&nonce.to_bytes()[..]);
        let challenge = SignatureNonce::from_msg_hash(challenge_bytes.as_slice());

        let sig_proof = Prover::generate_signature_pok(pok, &challenge).unwrap();

        assert!(
            Verifier::verify_signature_pok(&pr, &sig_proof, &nonce)
                .unwrap()
                .len()
                == 1
        );
        let sig_proof_bytes = sig_proof.to_bytes();

        let sig_proof_dup = SignatureProof::from_bytes(&sig_proof_bytes);
        assert!(sig_proof_dup.is_ok());
        let sig_proof_dup = sig_proof_dup.unwrap();
        assert!(
            Verifier::verify_signature_pok(&pr, &sig_proof_dup, &nonce)
                .unwrap()
                .len()
                == 1
        );

        let sig_proof_bytes = sig_proof.to_compressed_bytes();

        let sig_proof_dup = SignatureProof::from_compressed_bytes(&sig_proof_bytes);
        assert!(sig_proof_dup.is_ok());
    }
}
