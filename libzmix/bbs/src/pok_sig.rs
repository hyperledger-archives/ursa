use crate::errors::prelude::*;
use crate::keys::PublicKey;
use crate::pok_vc::prelude::*;
use crate::types::*;
use crate::signature::{compute_b_const_time, Signature};

use amcl_wrapper::constants::GroupG1_SIZE;
use amcl_wrapper::extension_field_gt::GT;
use amcl_wrapper::group_elem::{GroupElement, GroupElementVector};
use amcl_wrapper::group_elem_g1::{G1Vector, G1};
use amcl_wrapper::group_elem_g2::G2;

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Display, Formatter, Result as FmtResult};
use crate::ProofMessage;

/// Convenience importing module
pub mod prelude {
    pub use super::{PoKOfSignature, PoKOfSignatureProof, PoKOfSignatureProofStatus};
}

/// Proof of Knowledge of a Signature that is used by the prover
/// to construct `PoKOfSignatureProof`.
///
/// XXX: An optimization would be to combine the 2 relations into one by using the same techniques as Bulletproofs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoKOfSignature {
    /// A' in section 4.5
    pub a_prime: G1,
    /// \overline{A} in section 4.5
    pub a_bar: G1,
    /// d in section 4.5
    pub d: G1,
    /// For proving relation a_bar / d == a_prime^{-e} * h_0^r2
    pub pok_vc_1: ProverCommittedG1,
    /// The messages
    secrets_1: SignatureMessageVector,
    /// For proving relation g1 * h1^m1 * h2^m2.... for all disclosed messages m_i == d^r3 * h_0^{-s_prime} * h1^-m1 * h2^-m2.... for all undisclosed messages m_i
    pub pok_vc_2: ProverCommittedG1,
    /// The blinding factors
    secrets_2: SignatureMessageVector,
    /// revealed messages
    pub(crate) revealed_messages: BTreeMap<usize, SignatureMessage>
}

/// Indicates the status returned from `PoKOfSignatureProof`
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum PoKOfSignatureProofStatus {
    /// The proof verified
    Success,
    /// The proof failed because the signature proof of knowledge failed
    BadSignature,
    /// The proof failed because a hidden message was invalid when the proof was created
    BadHiddenMessage,
    /// The proof failed because a revealed message was invalid
    BadRevealedMessage,
}

impl PoKOfSignatureProofStatus {
    /// Return whether the proof succeeded or not
    pub fn is_valid(&self) -> bool {
        match *self {
            PoKOfSignatureProofStatus::Success => true,
            _ => false,
        }
    }
}

impl Display for PoKOfSignatureProofStatus {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match *self {
            PoKOfSignatureProofStatus::Success => write!(f, "Success"),
            PoKOfSignatureProofStatus::BadHiddenMessage => write!(
                f,
                "A message was supplied when the proof was created that was not signed"
            ),
            PoKOfSignatureProofStatus::BadRevealedMessage => {
                write!(f, "A revealed message was supplied that was not signed")
            }
            PoKOfSignatureProofStatus::BadSignature => {
                write!(f, "An invalid signature was supplied")
            }
        }
    }
}

/// The actual proof that is sent from prover to verifier.
///
/// Contains the proof of 2 discrete log relations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoKOfSignatureProof {
    /// A' in section 4.5
    pub a_prime: G1,
    /// \overline{A} in section 4.5
    pub a_bar: G1,
    /// d in section 4.5
    pub d: G1,
    /// Proof of relation a_bar / d == a_prime^{-e} * h_0^r2
    pub proof_vc_1: ProofG1,
    /// Proof of relation g1 * h1^m1 * h2^m2.... for all disclosed messages m_i == d^r3 * h_0^{-s_prime} * h1^-m1 * h2^-m2.... for all undisclosed messages m_i
    pub proof_vc_2: ProofG1,
}

impl PoKOfSignature {
    /// Creates the initial proof data before a Fiat-Shamir calculation
    pub fn init(
        signature: &Signature,
        vk: &PublicKey,
        messages: &[ProofMessage]
    ) -> Result<Self, BBSError> {
        if messages.len() != vk.message_count() {
            return Err(BBSError::from_kind(
                BBSErrorKind::PublicKeyGeneratorMessageCountMismatch(
                    vk.message_count(),
                    messages.len(),
                ),
            ));
        }

        let r1 = SignatureNonce::random();
        let r2 = SignatureNonce::random();

        let mut temp: Vec<SignatureMessage> = Vec::new();
        for i in 0..messages.len() {
            match &messages[i] {
                ProofMessage::Revealed(r) => temp.push(r.clone()),
                ProofMessage::Hidden(h) => match h {
                    HiddenMessage::ProofSpecificBlinding(m) => {
                        temp.push(m.clone())
                    },
                    HiddenMessage::ExternalBlinding(m,_) => {
                        temp.push(m.clone())
                    }
                }
            }
        }


        let b = compute_b_const_time(&G1::new(), vk, temp.as_slice(), &signature.s, 0);
        let a_prime = &signature.a * &r1;
        let a_bar = &(&b * &r1) - &(&a_prime * &signature.e);
        let d = b.binary_scalar_mul(&vk.h0, &r1, &(-&r2));

        let r3 = r1.inverse();
        let s_prime = &signature.s - &(&r2 * &r3);

        // For proving relation a_bar / d == a_prime^{-e} * h_0^r2
        let mut committing_1 = ProverCommittingG1::new();
        let mut secrets_1 = SignatureMessageVector::with_capacity(2);
        // For a_prime^{-e}
        committing_1.commit(&a_prime, None);
        secrets_1.push(-(&signature.e));
        // For h_0^r2
        committing_1.commit(&vk.h0, None);
        secrets_1.push(r2);
        let pok_vc_1 = committing_1.finish();

        // For proving relation g1 * h1^m1 * h2^m2.... for all disclosed messages m_i == d^r3 * h_0^{-s_prime} * h1^-m1 * h2^-m2.... for all undisclosed messages m_i
        // Usually the number of disclosed messages is much less than the number of hidden messages, its better to avoid negations in hidden messages and do
        // them in revealed messages. So transform the relation
        // g1 * h1^m1 * h2^m2.... * h_i^m_i for disclosed messages m_i = d^r3 * h_0^{-s_prime} * h1^-m1 * h2^-m2.... * h_j^-m_j for all undisclosed messages m_j
        // into
        // d^{-r3} * h_0^s_prime * h1^m1 * h2^m2.... * h_j^m_j = g1 * h1^-m1 * h2^-m2.... * h_i^-m_i. Moreover g1 * h1^-m1 * h2^-m2.... * h_i^-m_i is public
        // and can be efficiently computed as (g1 * h1^m1 * h2^m2.... * h_i^m_i)^-1 and inverse in elliptic group is a point negation which is very cheap
        let mut committing_2 = ProverCommittingG1::new();
        let mut secrets_2 =
            SignatureMessageVector::with_capacity(2 + messages.len());
        // For d^-r3
        committing_2.commit(&d, None);
        secrets_2.push(-r3);
        // h_0^s_prime
        committing_2.commit(&vk.h0, None);
        secrets_2.push(s_prime);

        let mut revealed_messages = BTreeMap::new();

        for i in 0..vk.message_count() {
            match &messages[i] {
                ProofMessage::Revealed(r) => {
                    revealed_messages.insert(i,r.clone());
                },
                ProofMessage::Hidden(h) => match h {
                    HiddenMessage::ProofSpecificBlinding(m) => {
                        committing_2.commit(&vk.h[i], None);
                        secrets_2.push(m.clone());
                    },
                    HiddenMessage::ExternalBlinding(e,b) => {
                        committing_2.commit(&vk.h[i], Some(b));
                        secrets_2.push(e.clone());
                    }
                }
            }
        }
        let pok_vc_2 = committing_2.finish();

        Ok(Self {
            a_prime,
            a_bar,
            d,
            pok_vc_1,
            secrets_1,
            pok_vc_2,
            secrets_2,
            revealed_messages
        })
    }

    /// Return byte representation of public elements so they can be used for challenge computation.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        bytes.append(&mut self.a_bar.to_bytes());

        // For 1st PoKVC
        // self.a_prime is included as part of self.pok_vc_1
        bytes.append(&mut self.pok_vc_1.to_bytes());

        // For 2nd PoKVC
        // self.d is included as part of self.pok_vc_2
        bytes.append(&mut self.pok_vc_2.to_bytes());

        bytes
    }

    /// Given the challenge value, compute the s values for Fiat-Shamir and return the actual
    /// proof to be sent to the verifier
    pub fn gen_proof(self, challenge_hash: &SignatureNonce) -> Result<PoKOfSignatureProof, BBSError> {
        let proof_vc_1 = self
            .pok_vc_1
            .gen_proof(challenge_hash, self.secrets_1.as_slice())?;
        let proof_vc_2 = self
            .pok_vc_2
            .gen_proof(challenge_hash, self.secrets_2.as_slice())?;

        Ok(PoKOfSignatureProof {
            a_prime: self.a_prime,
            a_bar: self.a_bar,
            d: self.d,
            proof_vc_1,
            proof_vc_2,
        })
    }
}

impl PoKOfSignatureProof {
    /// Return bytes that need to be hashed for generating challenge. Takes `self.a_bar`,
    /// `self.a_prime` and `self.d` and commitment and instance data of the two proof of knowledge protocols.
    pub fn get_bytes_for_challenge(
        &self,
        revealed_msg_indices: BTreeSet<usize>,
        vk: &PublicKey,
    ) -> Vec<u8> {
        let mut bytes = vec![];
        bytes.append(&mut self.a_bar.to_bytes());

        bytes.append(&mut self.a_prime.to_bytes());
        bytes.append(&mut vk.h0.to_bytes());
        bytes.append(&mut self.proof_vc_1.commitment.to_bytes());

        bytes.append(&mut self.d.to_bytes());
        bytes.append(&mut vk.h0.to_bytes());
        for i in 0..vk.message_count() {
            if revealed_msg_indices.contains(&i) {
                continue;
            }
            let mut b = vk.h[i].to_bytes();
            bytes.append(&mut b);
        }
        bytes.append(&mut self.proof_vc_2.commitment.to_bytes());
        bytes
    }

    /// Get the response from post-challenge phase of the Sigma protocol for the given message index `msg_idx`.
    /// Used when comparing message equality
    pub fn get_resp_for_message(&self, msg_idx: usize) -> Result<SignatureMessage, BBSError> {
        // 2 elements in self.proof_vc_2.responses are reserved for `&signature.e` and `r2`
        if msg_idx >= (self.proof_vc_2.responses.len() - 2) {
            return Err(BBSError::from_kind(BBSErrorKind::GeneralError {
                msg: format!(
                    "Message index was given {} but should be less than {}",
                    msg_idx,
                    self.proof_vc_2.responses.len() - 2
                ),
            }));
        }
        // 2 added to the index, since 0th and 1st index are reserved for `&signature.e` and `r2`
        Ok(self.proof_vc_2.responses[2 + msg_idx].clone())
    }

    /// Validate the proof
    pub fn verify(
        &self,
        vk: &PublicKey,
        revealed_msgs: &BTreeMap<usize, SignatureMessage>,
        challenge: &SignatureNonce,
    ) -> Result<PoKOfSignatureProofStatus, BBSError> {
        vk.validate()?;
        for i in revealed_msgs.keys() {
            if *i >= vk.message_count() {
                return Err(BBSError::from_kind(BBSErrorKind::GeneralError {
                    msg: format!("Index {} should be less than {}", i, vk.message_count()),
                }));
            }
        }

        if self.a_prime.is_identity() {
            return Ok(PoKOfSignatureProofStatus::BadSignature);
        }

        if !GT::ate_2_pairing(&self.a_prime, &vk.w, &(-&self.a_bar), &G2::generator()).is_one() {
            return Ok(PoKOfSignatureProofStatus::BadSignature);
        }

        let mut bases = vec![];
        bases.push(self.a_prime.clone());
        bases.push(vk.h0.clone());
        // a_bar / d
        let a_bar_d = &self.a_bar - &self.d;
        if !self.proof_vc_1.verify(&bases, &a_bar_d, challenge)? {
            return Ok(PoKOfSignatureProofStatus::BadHiddenMessage);
        }

        let mut bases_pok_vc_2 =
            G1Vector::with_capacity(2 + vk.message_count() - revealed_msgs.len());
        bases_pok_vc_2.push(self.d.clone());
        bases_pok_vc_2.push(vk.h0.clone());

        // `bases_disclosed` and `exponents` below are used to create g1 * h1^-m1 * h2^-m2.... for all disclosed messages m_i
        let mut bases_disclosed = G1Vector::with_capacity(1 + revealed_msgs.len());
        let mut exponents = SignatureMessageVector::with_capacity(1 + revealed_msgs.len());
        // XXX: g1 should come from a setup param and not generator
        bases_disclosed.push(G1::generator());
        exponents.push(SignatureNonce::one());
        for i in 0..vk.message_count() {
            if revealed_msgs.contains_key(&i) {
                let message = revealed_msgs.get(&i).unwrap();
                bases_disclosed.push(vk.h[i].clone());
                exponents.push(message.clone());
            } else {
                bases_pok_vc_2.push(vk.h[i].clone());
            }
        }
        // pr = g1 * h1^-m1 * h2^-m2.... = (g1 * h1^m1 * h2^m2....)^-1 for all disclosed messages m_i
        let pr = -bases_disclosed
            .multi_scalar_mul_var_time(exponents.as_slice())
            .unwrap();
        if !self
            .proof_vc_2
            .verify(bases_pok_vc_2.as_slice(), &pr, challenge)?
        {
            return Ok(PoKOfSignatureProofStatus::BadRevealedMessage);
        }
        Ok(PoKOfSignatureProofStatus::Success)
    }

    /// Convert the proof to raw bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut output = Vec::new();
        output.append(&mut self.a_prime.to_bytes());
        output.append(&mut self.a_bar.to_bytes());
        output.append(&mut self.d.to_bytes());
        let mut proof1_bytes = self.proof_vc_1.to_bytes();
        let proof1_len: u32 = proof1_bytes.len() as u32;
        output.extend_from_slice(&proof1_len.to_be_bytes()[..]);
        output.append(&mut proof1_bytes);
        let mut proof2_bytes = self.proof_vc_2.to_bytes();
        let proof2_len: u32 = proof2_bytes.len() as u32;
        output.extend_from_slice(&proof2_len.to_be_bytes()[..]);
        output.append(&mut proof2_bytes);
        output
    }

    /// Convert the byte slice into a proof
    pub fn from_bytes(data: &[u8]) -> Result<Self, BBSError> {
        if data.len() < GroupG1_SIZE * 3 {
            return Err(BBSError::from_kind(BBSErrorKind::PoKVCError {
                msg: format!("Invalid proof bytes. Expected {}", GroupG1_SIZE * 3),
            }));
        }
        let mut offset = 0;
        let mut end = GroupG1_SIZE;
        let a_prime = G1::from_bytes(&data[offset..end]).map_err(|e| {
            BBSError::from_kind(BBSErrorKind::PoKVCError {
                msg: format!("{}", e),
            })
        })?;

        offset = end;
        end = offset + GroupG1_SIZE;

        let a_bar = G1::from_bytes(&data[offset..end]).map_err(|e| {
            BBSError::from_kind(BBSErrorKind::PoKVCError {
                msg: format!("{}", e),
            })
        })?;
        offset = end;
        end = offset + GroupG1_SIZE;

        let d = G1::from_bytes(&data[offset..end]).map_err(|e| {
            BBSError::from_kind(BBSErrorKind::PoKVCError {
                msg: format!("{}", e),
            })
        })?;
        offset = end;
        end = offset + 4;
        let proof1_bytes = u32::from_be_bytes(*array_ref![data, offset, 4]) as usize;

        offset = end;
        end = offset + proof1_bytes;
        let proof_vc_1 = ProofG1::from_bytes(&data[offset..end]).map_err(|e| {
            BBSError::from_kind(BBSErrorKind::PoKVCError {
                msg: format!("{}", e),
            })
        })?;

        offset = end;
        end = offset + 4;
        let proof2_bytes = u32::from_be_bytes(*array_ref![data, offset, 4]) as usize;

        offset = end;
        end = offset + proof2_bytes;

        let proof_vc_2 = ProofG1::from_bytes(&data[offset..end]).map_err(|e| {
            BBSError::from_kind(BBSErrorKind::PoKVCError {
                msg: format!("{}", e),
            })
        })?;
        Ok(Self {
            a_prime,
            a_bar,
            d,
            proof_vc_1,
            proof_vc_2,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::generate;

    #[test]
    fn pok_signature_no_revealed_messages() {
        let message_count = 5;
        let messages = SignatureMessageVector::random(message_count);
        let (verkey, signkey) = generate(message_count).unwrap();

        let sig = Signature::new(messages.as_slice(), &signkey, &verkey).unwrap();
        let res = sig.verify(messages.as_slice(), &verkey);
        assert!(res.unwrap());
        let proof_messages = vec![
            ProofMessage::Hidden(HiddenMessage::ProofSpecificBlinding(messages[0].clone())),
            ProofMessage::Hidden(HiddenMessage::ProofSpecificBlinding(messages[1].clone())),
            ProofMessage::Hidden(HiddenMessage::ProofSpecificBlinding(messages[2].clone())),
            ProofMessage::Hidden(HiddenMessage::ProofSpecificBlinding(messages[3].clone())),
            ProofMessage::Hidden(HiddenMessage::ProofSpecificBlinding(messages[4].clone())),
        ];
        let revealed_msg: BTreeMap<usize, SignatureMessage> = BTreeMap::new();

        let pok = PoKOfSignature::init(&sig, &verkey, proof_messages.as_slice()).unwrap();
        let challenge_prover = SignatureNonce::from_msg_hash(&pok.to_bytes());
        let proof = pok.gen_proof(&challenge_prover).unwrap();

        // Test to_bytes
        let proof_bytes = proof.to_bytes();
        let proof_cp = PoKOfSignatureProof::from_bytes(&proof_bytes);
        assert!(proof_cp.is_ok());

        // The verifier generates the challenge on its own.
        let challenge_bytes = proof.get_bytes_for_challenge(BTreeSet::new(), &verkey);
        let challenge_verifier = SignatureNonce::from_msg_hash(&challenge_bytes);
        assert!(proof
            .verify(&verkey, &revealed_msg, &challenge_verifier)
            .unwrap().is_valid());
    }

    #[test]
    fn pok_signature_revealed_message() {
        let message_count = 5;
        let messages = SignatureMessageVector::random(message_count);
        let (verkey, signkey) = generate(message_count).unwrap();

        let sig = Signature::new(messages.as_slice(), &signkey, &verkey).unwrap();
        let res = sig.verify(messages.as_slice(), &verkey);
        assert!(res.unwrap());

        let mut proof_messages = vec![
            ProofMessage::Revealed(messages[0].clone()),
            ProofMessage::Hidden(HiddenMessage::ProofSpecificBlinding(messages[1].clone())),
            ProofMessage::Revealed(messages[2].clone()),
            ProofMessage::Hidden(HiddenMessage::ProofSpecificBlinding(messages[3].clone())),
            ProofMessage::Hidden(HiddenMessage::ProofSpecificBlinding(messages[4].clone())),
        ];

        let mut revealed_indices = BTreeSet::new();
        revealed_indices.insert(0);
        revealed_indices.insert(2);

        let pok = PoKOfSignature::init(
            &sig,
            &verkey,
            proof_messages.as_slice()
        )
        .unwrap();
        let challenge_prover = SignatureNonce::from_msg_hash(&pok.to_bytes());
        let proof = pok.gen_proof(&challenge_prover).unwrap();

        let mut revealed_msgs = BTreeMap::new();
        for i in &revealed_indices {
            revealed_msgs.insert(i.clone(), messages[*i].clone());
        }
        // The verifier generates the challenge on its own.
        let chal_bytes = proof.get_bytes_for_challenge(revealed_indices.clone(), &verkey);
        let challenge_verifier = SignatureNonce::from_msg_hash(&chal_bytes);
        assert!(proof
            .verify(&verkey, &revealed_msgs, &challenge_verifier)
            .unwrap().is_valid());

        // Reveal wrong message
        let mut revealed_msgs_1 = revealed_msgs.clone();
        revealed_msgs_1.insert(2, SignatureMessage::random());
        assert!(!proof
            .verify(&verkey, &revealed_msgs_1, &challenge_verifier)
            .unwrap().is_valid());

        // PoK with supplied blindings
        proof_messages[1] = ProofMessage::Hidden(HiddenMessage::ExternalBlinding(messages[1].clone(), SignatureNonce::random()));
        proof_messages[3] = ProofMessage::Hidden(HiddenMessage::ExternalBlinding(messages[3].clone(), SignatureNonce::random()));
        proof_messages[4] = ProofMessage::Hidden(HiddenMessage::ExternalBlinding(messages[4].clone(), SignatureNonce::random()));

        let pok = PoKOfSignature::init(
            &sig,
            &verkey,
            proof_messages.as_slice()
        )
        .unwrap();
        let mut revealed_msgs = BTreeMap::new();
        for i in &revealed_indices {
            revealed_msgs.insert(i.clone(), messages[*i].clone());
        }
        let challenge_prover = SignatureNonce::from_msg_hash(&pok.to_bytes());
        let proof = pok.gen_proof(&challenge_prover).unwrap();

        // The verifier generates the challenge on its own.
        let challenge_bytes = proof.get_bytes_for_challenge(revealed_indices.clone(), &verkey);
        let challenge_verifier = SignatureNonce::from_msg_hash(&challenge_bytes);
        assert!(proof
            .verify(&verkey, &revealed_msgs, &challenge_verifier)
            .unwrap().is_valid());
    }

    #[test]
    fn test_pok_multiple_sigs_with_same_msg() {
        // Prove knowledge of multiple signatures and the equality of a specific message under both signatures.
        // Knowledge of 2 signatures and their corresponding messages is being proven.
        // 2nd message in the 1st signature and 5th message in the 2nd signature are to be proven equal without revealing them

        let message_count = 5;
        let (vk, signkey) = generate(message_count).unwrap();

        let same_msg = SignatureMessage::random();
        let mut msgs_1 = SignatureMessageVector::random(message_count - 1);
        let mut proof_messages_1 = Vec::with_capacity(message_count);

        for m in msgs_1.iter() {
            proof_messages_1.push(ProofMessage::Hidden(HiddenMessage::ProofSpecificBlinding(m.clone())));
        }

        let same_blinding = SignatureNonce::random();
        msgs_1.insert(1, same_msg.clone());
        proof_messages_1.insert(1, ProofMessage::Hidden(HiddenMessage::ExternalBlinding(same_msg.clone(), same_blinding.clone())));

        let sig_1 = Signature::new(msgs_1.as_slice(), &signkey, &vk).unwrap();
        assert!(sig_1.verify(msgs_1.as_slice(), &vk).unwrap());

        let mut msgs_2 = SignatureMessageVector::random(message_count - 1);
        let mut proof_messages_2 = Vec::with_capacity(message_count);
        for m in msgs_2.iter() {
            proof_messages_2.push(ProofMessage::Hidden(HiddenMessage::ProofSpecificBlinding(m.clone())));
        }

        msgs_2.insert(4, same_msg.clone());
        proof_messages_2.insert(4, ProofMessage::Hidden(HiddenMessage::ExternalBlinding(same_msg.clone(), same_blinding.clone())));
        let sig_2 = Signature::new(msgs_2.as_slice(), &signkey, &vk).unwrap();
        assert!(sig_2.verify(msgs_2.as_slice(), &vk).unwrap());

        // A particular message is same
        assert_eq!(msgs_1[1], msgs_2[4]);

        let pok_1 = PoKOfSignature::init(
            &sig_1,
            &vk,
            proof_messages_1.as_slice()
        )
        .unwrap();
        let pok_2 = PoKOfSignature::init(
            &sig_2,
            &vk,
            proof_messages_2.as_slice()
        )
        .unwrap();

        let mut chal_bytes = vec![];
        chal_bytes.append(&mut pok_1.to_bytes());
        chal_bytes.append(&mut pok_2.to_bytes());

        let chal_prover = SignatureNonce::from_msg_hash(&chal_bytes);

        let proof_1 = pok_1.gen_proof(&chal_prover).unwrap();
        let proof_2 = pok_2.gen_proof(&chal_prover).unwrap();

        // The verifier generates the challenge on its own.
        let mut chal_bytes = vec![];
        chal_bytes.append(&mut proof_1.get_bytes_for_challenge(BTreeSet::new(), &vk));
        chal_bytes.append(&mut proof_2.get_bytes_for_challenge(BTreeSet::new(), &vk));
        let chal_verifier = SignatureNonce::from_msg_hash(&chal_bytes);

        // Response for the same message should be same (this check is made by the verifier)
        assert_eq!(
            proof_1.get_resp_for_message(1).unwrap(),
            proof_2.get_resp_for_message(4).unwrap()
        );
        let revealed = BTreeMap::new();
        assert!(proof_1
            .verify(&vk, &revealed, &chal_verifier)
            .unwrap().is_valid());
        assert!(proof_2
            .verify(&vk, &revealed, &chal_verifier)
            .unwrap().is_valid());
    }
}
