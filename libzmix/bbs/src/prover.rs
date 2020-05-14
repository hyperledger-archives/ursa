use crate::errors::prelude::*;
use crate::keys::prelude::*;
use crate::messages::*;
use crate::pok_sig::prelude::*;
use crate::pok_vc::prelude::*;
use crate::signature::prelude::*;
/// The prover of a signature or credential receives it from an
/// issuer and later proves to a verifier.
/// The prover can either have the issuer sign all messages
/// or can have some (0 to all) messages blindly signed by the issuer.
use crate::{
    BlindSignatureContext, CommitmentBuilder, HashElem, ProofChallenge, ProofNonce, ProofRequest,
    RandomElem, SignatureBlinding, SignatureMessage, SignatureProof,
};
use std::collections::BTreeMap;

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
        nonce: &ProofNonce,
    ) -> Result<(BlindSignatureContext, SignatureBlinding), BBSError> {
        let blinding_factor = Signature::generate_blinding();
        let mut builder = CommitmentBuilder::new();

        // h0^blinding_factor*hi^mi.....
        builder.add(&verkey.h0, &blinding_factor);

        let mut committing = ProverCommittingG1::new();
        committing.commit(&verkey.h0);
        let mut secrets = Vec::new();
        secrets.push(SignatureMessage(blinding_factor.0));
        for (i, m) in messages {
            if *i > verkey.h.len() {
                return Err(BBSErrorKind::PublicKeyGeneratorMessageCountMismatch(
                    *i,
                    verkey.h.len(),
                )
                .into());
            }
            secrets.push(m.clone());
            builder.add(&verkey.h[*i], &m);
            committing.commit(&verkey.h[*i]);
        }

        // Create a random commitment, compute challenges and response.
        // The proof of knowledge consists of a commitment and responses
        // Prover and issuer engage in a proof of knowledge for `commitment`
        let commitment = builder.finalize();
        let committed = committing.finish();

        let mut extra = Vec::new();
        extra.extend_from_slice(&commitment.to_bytes_uncompressed_form()[..]);
        extra.extend_from_slice(&nonce.to_bytes_uncompressed_form()[..]);
        let challenge_hash = committed.gen_challenge(extra);
        let proof_of_hidden_messages = committed
            .gen_proof(&challenge_hash, secrets.as_slice())
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
        PoKOfSignature::init(&signature, &request.verification_key, proof_messages)
    }

    /// Create the challenge hash for a set of proofs
    ///
    /// # Arguments
    /// * `poks` - a vec of PoKOfSignature objects
    /// * `nonce` - a SignatureNonce
    /// * `claims` - a vec of strings the prover wishes to include in the challenge (may be empty)
    pub fn create_challenge_hash(
        pok_sigs: Vec<PoKOfSignature>,
        claims: Vec<&str>,
        nonce: &ProofNonce,
    ) -> Result<ProofChallenge, BBSError> {
        let mut bytes = Vec::new();

        for p in pok_sigs {
            bytes.extend_from_slice(p.to_bytes().as_slice());
        }
        bytes.extend_from_slice(&nonce.to_bytes_uncompressed_form()[..]);
        for c in claims {
            bytes.extend_from_slice(c.as_bytes());
        }

        let challenge = ProofChallenge::hash(&bytes);

        Ok(challenge)
    }

    /// Convert the a committed proof of signature knowledge to the proof
    pub fn generate_signature_pok(
        pok_sig: PoKOfSignature,
        challenge: &ProofChallenge,
    ) -> Result<SignatureProof, BBSError> {
        let revealed_messages = (&pok_sig.revealed_messages).clone();
        let proof = pok_sig.gen_proof(challenge)?;

        Ok(SignatureProof {
            revealed_messages,
            proof,
        })
    }
}
