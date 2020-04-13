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
    warnings,
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
    constants::{FieldElement_SIZE as MESSAGE_SIZE, GroupG1_SIZE as COMMITMENT_SIZE},
    field_elem::{FieldElement, FieldElementVector},
    group_elem::GroupElement,
    group_elem_g1::{G1Vector, G1},
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

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
pub type SignatureMessage = FieldElement;
/// The type for managing lists of messages
pub type SignatureMessageVector = FieldElementVector;
/// The type for nonces
pub type SignatureNonce = FieldElement;
/// The type for blinding factors
pub type SignatureBlinding = FieldElement;

mod types {
    pub use super::{
        BlindSignatureContext, BlindedSignatureCommitment, ProofRequest, SignatureBlinding,
        SignatureMessage, SignatureMessageVector, SignatureNonce, SignaturePointVector,
        SignatureProof, ProofMessage, HiddenMessage
    };
}

/// Convenience importing module
pub mod prelude {
    pub use super::{
        BlindSignatureContext, BlindedSignatureCommitment, ProofRequest, SignatureBlinding,
        SignatureMessage, SignatureMessageVector, SignatureNonce, SignaturePointVector,
        SignatureProof, ProofMessage, HiddenMessage
    };
    pub use crate::errors::prelude::*;
    pub use crate::issuer::Issuer;
    pub use crate::keys::prelude::*;
    pub use crate::pok_sig::prelude::*;
    pub use crate::pok_vc::prelude::*;
    pub use crate::prover::Prover;
    pub use crate::signature::prelude::*;
    pub use crate::verifier::Verifier;
    pub use amcl_wrapper::constants::FieldElement_SIZE as SECRET_KEY_SIZE;
    pub use amcl_wrapper::constants::FieldElement_SIZE as MESSAGE_SIZE;
    pub use amcl_wrapper::constants::GroupG1_SIZE as COMMITMENT_SIZE;
    pub use amcl_wrapper::group_elem::{GroupElement, GroupElementVector};
    pub use amcl_wrapper::types_g2::GroupG2_SIZE as PUBLIC_KEY_SIZE;
    pub use generic_array::typenum::U192 as DeterministicPublicKeySize;
    pub use generic_array::GenericArray;
}

/// Contains the data used for computing a blind signature and verifying
/// proof of hidden messages from a prover
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlindSignatureContext {
    commitment: BlindedSignatureCommitment,
    challenge_hash: SignatureNonce,
    proof_of_hidden_messages: ProofG1,
}

impl BlindSignatureContext {
    const MIN_LENGTH: usize = COMMITMENT_SIZE + MESSAGE_SIZE + 4;
    /// Convert to raw bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_cbor::to_vec(self).unwrap()
    }

    /// Convert from raw bytes
    pub fn from_bytes<I: AsRef<[u8]>>(data: I) -> Result<Self, BBSError> {
        let data = data.as_ref();
        serde_cbor::from_slice(data).map_err(|_| BBSError::from(BBSErrorKind::InvalidNumberOfBytes(Self::MIN_LENGTH, data.len())))
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
            challenge_bytes.append(&mut b.to_bytes())
        }
        challenge_bytes.append(&mut commitment.to_bytes());
        challenge_bytes.extend_from_slice(self.commitment.to_bytes().as_slice());
        challenge_bytes.extend_from_slice(&mut nonce.to_bytes());

        let challenge_result =
            SignatureMessage::from_msg_hash(challenge_bytes.as_slice()) - &self.challenge_hash;
        let commitment_result = commitment - &self.commitment;
        Ok(commitment_result.is_identity() && challenge_result.is_zero())
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
    /// Convert to raw bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_cbor::to_vec(self).unwrap()
    }

    /// Convert from raw bytes
    pub fn from_bytes<I: AsRef<[u8]>>(data: I) -> Result<Self, BBSError> {
        let data = data.as_ref();
        serde_cbor::from_slice(data).map_err(|_| BBSError::from(BBSErrorKind::InvalidNumberOfBytes(8, data.len())))
    }
}

/// Contains the data from a prover to a verifier
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureProof {
    revealed_messages: BTreeMap<usize, SignatureMessage>,
    proof: PoKOfSignatureProof,
}

impl SignatureProof {
    /// Convert to raw bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_cbor::to_vec(self).unwrap()
    }

    /// Convert from raw bytes
    pub fn from_bytes<I: AsRef<[u8]>>(data: I) -> Result<Self, BBSError> {
        let data = data.as_ref();
        serde_cbor::from_slice(data).map_err(|_| BBSError::from(BBSErrorKind::InvalidNumberOfBytes(8, data.len())))
    }
}

/// A message classification by the prover
pub enum ProofMessage {
    /// Message will be revealed to a verifier
    Revealed(SignatureMessage),
    /// Message will be hidden from a verifier
    Hidden(HiddenMessage)
}

impl ProofMessage{
    /// Extract the internal message
    pub fn get_message(&self) -> SignatureMessage {
        match *self {
            ProofMessage::Revealed(ref r) => r.clone(),
            ProofMessage::Hidden(ref h) => match h {
                HiddenMessage::ProofSpecificBlinding(ref p) => p.clone(),
                HiddenMessage::ExternalBlinding(ref m,_) => m.clone()
            }
        }
    }
}

/// Two types of hidden messages
pub enum HiddenMessage {
    /// Indicates the message is hidden and no other work is involved
    ///     so a blinding factor will be generated specific to this proof
    ProofSpecificBlinding(SignatureMessage),
    /// Indicates the message is hidden but it is involved with other proofs
    ///     like boundchecks, set memberships or inequalities, so the blinding factor
    ///     is provided from an external source.
    ExternalBlinding(SignatureMessage, SignatureNonce)
}


#[cfg(test)]
mod tests {
    use super::BlindSignatureContext;
    use crate::pok_vc::ProofG1;
    use crate::{SignatureMessage, SignatureMessageVector};
    use amcl_wrapper::{group_elem::GroupElement, group_elem_g1::G1};

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
}
