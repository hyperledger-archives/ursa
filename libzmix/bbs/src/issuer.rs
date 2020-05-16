use crate::errors::prelude::*;
use crate::keys::prelude::*;
use crate::signature::prelude::*;
/// The issuer generates keys and uses those to sign
/// credentials. There are two types of public keys:
/// `PublicKey` which generates all generators at random and
/// `DeterministicPublicKey` which only generates the commitment
/// to the secret key. `DeterministicPublicKey` can be converted to a
/// `PublicKey` later. The latter is primarily used for storing a shorter
/// key and looks just like a regular ECC key.
use crate::{BlindSignatureContext, ProofNonce, RandomElem, SignatureMessage};
use std::collections::{BTreeMap, BTreeSet};

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
        ctx: &BlindSignatureContext,
        messages: &BTreeMap<usize, SignatureMessage>,
        signkey: &SecretKey,
        verkey: &PublicKey,
        nonce: &ProofNonce,
    ) -> Result<BlindSignature, BBSError> {
        let revealed_messages: BTreeSet<usize> = messages.keys().map(|i| *i).collect();
        if ctx.verify(&revealed_messages, verkey, nonce)? {
            BlindSignature::new(&ctx.commitment, messages, signkey, verkey)
        } else {
            Err(BBSErrorKind::GeneralError {
                msg: format!("Invalid proof of committed messages"),
            }
            .into())
        }
    }

    /// Create a nonce used for the blind signing context
    pub fn generate_signing_nonce() -> ProofNonce {
        ProofNonce::random()
    }
}
