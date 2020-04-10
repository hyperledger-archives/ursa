/// The verifier of a signature or credential asks for messages to be revealed from
/// a prover and checks the signature proof of knowledge against a trusted issuer's public key.
use crate::prelude::*;
use std::collections::BTreeSet;

/// This struct represents an Verifier of signatures.
/// Provided are methods for generating a context to ask for revealed messages
/// and the prover keep all others hidden.
pub struct Verifier;

impl Verifier {
    /// Create a nonce used for the zero-knowledge proof context
    pub fn new_proof_request(
        revealed_message_indices: &[usize],
        verkey: &PublicKey,
    ) -> Result<ProofRequest, BBSError> {
        let revealed_messages = revealed_message_indices
            .into_iter()
            .map(|i| *i)
            .collect::<BTreeSet<usize>>();
        for i in &revealed_messages {
            if *i > verkey.h.len() {
                return Err(BBSErrorKind::PublicKeyGeneratorMessageCountMismatch(
                    *i,
                    verkey.h.len(),
                )
                .into());
            }
        }
        Ok(ProofRequest {
            nonce: SignatureNonce::random(),
            revealed_messages,
            verification_key: verkey.clone(),
        })
    }
}
