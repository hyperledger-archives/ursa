use crate::errors::prelude::*;
use crate::keys::prelude::*;
use crate::pok_vc::prelude::*;
use crate::signature::prelude::*;
/// The issuer generates keys and uses those to sign
/// credentials. There are two types of public keys:
/// `PublicKey` which generates all generators at random and
/// `DeterministicPublicKey` which only generates the commitment
/// to the secret key. `DeterministicPublicKey` can be converted to a
/// `PublicKey` later. The latter is primarily used for storing a shorter
/// key and looks just like a regular ECC key.
use crate::types::*;

use amcl_wrapper::{constants::GroupG1_SIZE, group_elem::GroupElement};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// This struct represents an Issuer of signatures or Signer.
/// Provided are methods for signing regularly where all messages are known
/// and 2PC where some are only known to the holder and a blind signature
/// is created.
pub struct Issuer;

impl Issuer {
    /// Create a keypair capable of signing `message_count` messages
    pub fn new_keys(message_count: usize) -> Result<(PublicKey, SecretKey), BBSError> {
        generate(message_count)
    }

    /// Create a keypair that uses the short public key
    pub fn new_short_keys(option: Option<KeyGenOption>) -> (DeterministicPublicKey, SecretKey) {
        DeterministicPublicKey::new(option)
    }

    /// Create a signature with no hidden messages
    pub fn sign(
        messages: &[SignatureMessage],
        signkey: &SecretKey,
        verkey: &PublicKey,
    ) -> Result<Signature, BBSError> {
        Signature::new(messages, signkey, verkey)
    }

    /// Verify a proof of committed messages and generate a blind signature
    pub fn blind_sign(
        ctx: BlindSignatureContext,
        messages: &BTreeMap<usize, SignatureMessage>,
        signkey: &SecretKey,
        verkey: &PublicKey,
    ) -> Result<BlindSignature, BBSError> {

        if ctx.verify(messages, verkey)? {
            BlindSignature::new(&ctx.commitment, messages, signkey, verkey)
        } else {
            Err(BBSErrorKind::GeneralError{ msg: format!("Invalid proof of committed messages") }.into())
        }
    }

    /// Create a nonce used for the blind signing context
    pub fn generate_signing_nonce() -> SignatureNonce {
        SignatureNonce::random()
    }
}

/// Contains the data used for computing a blind signature and verifying
/// proof of hidden messages from a holder
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlindSignatureContext {
    commitment: BlindedSignatureCommitment,
    challenge_hash: SignatureNonce,
    nonce: SignatureNonce,
    proof_of_hidden_messages: ProofG1,
}

impl BlindSignatureContext {
    /// Convert to raw bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(self.commitment.to_bytes().as_slice());
        result.extend_from_slice(self.challenge_hash.to_bytes().as_slice());
        println!("challenge_hash = {}", hex::encode(self.challenge_hash.to_bytes()));
        result.extend_from_slice(self.nonce.to_bytes().as_slice());
        let proof_bytes = self.proof_of_hidden_messages.to_bytes();
        let proof_len = proof_bytes.len() as u32;
        result.extend_from_slice(&proof_len.to_be_bytes()[..]);
        result.extend_from_slice(proof_bytes.as_slice());
        result
    }

    /// Convert from raw bytes
    pub fn from_bytes<I: AsRef<[u8]>>(data: I) -> Result<Self, BBSError> {
        let data = data.as_ref();

        if data.len() < GroupG1_SIZE * 3 + 4 {
            return Err(BBSErrorKind::InvalidNumberOfBytes(GroupG1_SIZE + 8, data.len()).into());
        }

        let mut offset = 0;
        let mut end = GroupG1_SIZE;
        let commitment =
            BlindedSignatureCommitment::from_bytes(&data[offset..end]).map_err(|e| {
                BBSErrorKind::GeneralError {
                    msg: format!("{:?}", e),
                }
            })?;

        offset = end;
        end = offset + GroupG1_SIZE;
        let challenge_hash = SignatureNonce::from_bytes(&data[offset..end]).map_err(|e| {
                BBSErrorKind::GeneralError {
                    msg: format!("{:?}", e),
                }
        })?;

        println!("challenge_hash = {}", hex::encode(&data[offset..end]));
        offset = end;
        end = offset + GroupG1_SIZE;

        let nonce = SignatureNonce::from_bytes(&data[offset..end]).map_err(|e| {
                BBSErrorKind::GeneralError {
                    msg: format!("{:?}", e),
                }
        })?;

        offset = end;
        end = offset + 4;
        let proof_len = u32::from_be_bytes(*array_ref![data, offset, 4]) as usize;
        offset = end;
        end = offset + proof_len;
        let proof_of_hidden_messages =
            ProofG1::from_bytes(&data[offset..end]).map_err(|e| BBSErrorKind::GeneralError {
                msg: format!("{:?}", e),
            })?;
        Ok(Self {
            commitment,
            challenge_hash,
            nonce,
            proof_of_hidden_messages,
        })
    }

    /// Assumes the proof of hidden messages
    /// If other proofs were included, those will need to be verified another
    /// way
    pub fn verify(&self, messages: &BTreeMap<usize, SignatureMessage>, verkey: &PublicKey) -> Result<bool, BBSError> {
        // Verify the proof
        // First get the generators used to create the commitment
        let mut bases = Vec::new();
        bases.push(verkey.h0.clone());
        for i in 0..verkey.message_count() {
            if !messages.contains_key(&i) {
                bases.push(verkey.h[i].clone());
            }
        }

        let commitment = self.proof_of_hidden_messages.get_challenge_contribution(bases.as_slice(), &self.commitment, &self.challenge_hash)?;

        let mut challenge_bytes = Vec::new();
        for b in bases.iter() {
            challenge_bytes.append(&mut b.to_bytes())
        }
        challenge_bytes.append(&mut commitment.to_bytes());
        challenge_bytes.extend_from_slice(self.commitment.to_bytes().as_slice());
        challenge_bytes.extend_from_slice(&mut self.nonce.to_bytes());

        let challenge_result = SignatureMessage::from_msg_hash(challenge_bytes.as_slice()) - &self.challenge_hash;
        let commitment_result = commitment - &self.commitment;
        Ok(commitment_result.is_identity() && challenge_result.is_zero())
    }
}

#[cfg(test)]
mod tests {
    use super::BlindSignatureContext;
    use crate::pok_vc::ProofG1;
    use crate::{SignatureMessageVector, SignatureNonce, SignatureMessage};
    use amcl_wrapper::{group_elem::GroupElement, group_elem_g1::G1};

    #[test]
    fn blind_signature_context_bytes_test() {
        let b = BlindSignatureContext {
            commitment: G1::generator(),
            challenge_hash: SignatureMessage::random(),
            nonce: SignatureNonce::zero(),
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
            nonce: SignatureNonce::random(),
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
