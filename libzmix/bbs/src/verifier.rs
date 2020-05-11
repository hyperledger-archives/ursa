use crate::errors::prelude::*;
use crate::keys::prelude::*;
use crate::pok_sig::prelude::*;
/// The verifier of a signature or credential asks for messages to be revealed from
/// a prover and checks the signature proof of knowledge against a trusted issuer's public key.
use crate::{
    HashElem, ProofChallenge, ProofNonce, ProofRequest, RandomElem, SignatureMessage,
    SignatureProof,
};
use std::collections::BTreeSet;

/// This struct represents an Verifier of signatures.
/// Provided are methods for generating a context to ask for revealed messages
/// and the prover keep all others hidden.
pub struct Verifier;

impl Verifier {
    /// Create a nonce used for the zero-knowledge proof context
    /// verkey: issuer's public key
    pub fn new_proof_request(
        revealed_message_indices: &[usize],
        verkey: &PublicKey,
    ) -> Result<ProofRequest, BBSError> {
        let revealed_messages = revealed_message_indices
            .iter()
            .copied()
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
            revealed_messages,
            verification_key: verkey.clone(),
        })
    }

    /// Check a signature proof of knowledge and selective disclosure proof
    pub fn verify_signature_pok(
        proof_request: &ProofRequest,
        signature_proof: &SignatureProof,
        nonce: &ProofNonce,
    ) -> Result<Vec<SignatureMessage>, BBSError> {
        let mut challenge_bytes = signature_proof.proof.get_bytes_for_challenge(
            proof_request.revealed_messages.clone(),
            &proof_request.verification_key,
        );
        challenge_bytes.extend_from_slice(&nonce.to_bytes_uncompressed_form()[..]);

        let challenge_verifier = ProofChallenge::hash(&challenge_bytes);
        match signature_proof.proof.verify(
            &proof_request.verification_key,
            &signature_proof.revealed_messages,
            &challenge_verifier,
        )? {
            PoKOfSignatureProofStatus::Success => Ok(signature_proof
                .revealed_messages
                .iter()
                .map(|(_, m)| m.clone())
                .collect::<Vec<SignatureMessage>>()),
            e => Err(BBSErrorKind::InvalidProof { status: e }.into()),
        }
    }

    /// Create a nonce used for the proof request context
    pub fn generate_proof_nonce() -> ProofNonce {
        ProofNonce::random()
    }
}
