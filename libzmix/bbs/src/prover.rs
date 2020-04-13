/// The prover of a signature or credential receives it from an
/// issuer and later proves to a verifier.
/// The prover can either have the issuer sign all messages
/// or can have some (0 to all) messages blindly signed by the issuer.
use crate::prelude::*;

use std::collections::BTreeMap;
use crate::ProofMessage;

/// This struct represents a Prover who receives signatures or proves with them.
/// Provided are methods for 2PC where some are only known to the prover and a blind signature
/// is created, unblinding signatures, verifying signatures, and creating signature proofs of knowledge
/// with selective disclosure proofs
pub struct Prover {}

impl Prover {
    /// Generate a unique message that will be used across multiple signatures.
    /// This `link_secret` is the same in all signatures and allows a prover to demonstrate
    /// that signatures were issued to the same identity. This value should be a blinded
    /// message in all signatures and never revealed to anyone.
    pub fn new_link_secret() -> SignatureMessage {
        SignatureMessage::random()
    }

    /// Create the structures need to send to an issuer to complete a blinded signature
    pub fn new_blind_signature_context(
        verkey: &PublicKey,
        messages: &BTreeMap<usize, SignatureMessage>,
        nonce: &SignatureNonce,
    ) -> Result<(BlindSignatureContext, SignatureBlinding), BBSError> {
        let blinding_factor = Signature::generate_blinding();

        let mut points = SignaturePointVector::with_capacity(messages.len() + 1);
        let mut scalars = SignatureMessageVector::with_capacity(messages.len() + 1);
        // h0^blinding_factor*hi^mi.....
        points.push(verkey.h0.clone());
        scalars.push(blinding_factor.clone());
        let mut committing = ProverCommittingG1::new();
        committing.commit(&verkey.h0, None);

        for (i, m) in messages {
            if *i > verkey.h.len() {
                return Err(BBSErrorKind::PublicKeyGeneratorMessageCountMismatch(
                    *i,
                    verkey.h.len(),
                )
                .into());
            }
            points.push(verkey.h[*i].clone());
            scalars.push(m.clone());
            committing.commit(&verkey.h[*i], None);
        }

        // Create a random commitment, compute challenges and response.
        // The proof of knowledge consists of a commitment and responses
        // Prover and issuer engage in a proof of knowledge for `commitment`
        let commitment = points
            .multi_scalar_mul_const_time(scalars.as_slice())
            .unwrap();
        let committed = committing.finish();

        let mut extra = Vec::new();
        extra.extend_from_slice(commitment.to_bytes().as_slice());
        extra.extend_from_slice(nonce.to_bytes().as_slice());
        let challenge_hash = committed.gen_challenge(extra);
        let proof_of_hidden_messages = committed
            .gen_proof(&challenge_hash, scalars.as_slice())
            .unwrap();

        Ok((
            BlindSignatureContext {
                challenge_hash,
                commitment,
                proof_of_hidden_messages,
            },
            blinding_factor,
        ))
    }

    /// Unblinds and verifies a signature received from an issuer
    pub fn complete_signature(
        verkey: &PublicKey,
        messages: &[SignatureMessage],
        blind_signature: &BlindSignature,
        blinding_factor: &SignatureBlinding,
    ) -> Result<Signature, BBSError> {
        let signature = blind_signature.to_unblinded(blinding_factor);
        if signature.verify(messages, verkey)? {
            Ok(signature)
        } else {
            Err(BBSErrorKind::GeneralError {
                msg: format!("Invalid signature."),
            }
            .into())
        }
    }

    /// Create a new signature proof of knowledge and selective disclosure proof
    /// from a verifier's request
    ///
    /// # Arguments
    /// * `request` - Proof request from verifier
    /// * `proof_messages` -
    /// If blinding_factor is Some(Nonce) then it will use that.
    /// If None, a blinding factor will be generated at random.
    pub fn commit_signature_pok(
        request: &ProofRequest,
        proof_messages: &[ProofMessage],
        signature: &Signature,
    ) -> Result<PoKOfSignature, BBSError> {
        PoKOfSignature::init(
            &signature,
            &request.verification_key,
            proof_messages
        )
    }

    /// Convert the a committed proof of signature knowledge to the proof
    pub fn generate_signature_pok(
        pok_sig: PoKOfSignature,
        challenge: &SignatureNonce
    ) -> Result<SignatureProof, BBSError> {

        let revealed_messages = (&pok_sig.revealed_messages).clone();
        let proof = pok_sig.gen_proof(&challenge)?;

        Ok(SignatureProof {
            revealed_messages,
            proof,
        })
    }
}
