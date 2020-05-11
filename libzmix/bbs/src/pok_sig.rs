use crate::errors::prelude::*;
use crate::keys::PublicKey;
use crate::messages::*;
use crate::pok_vc::prelude::*;
use crate::signature::Signature;
use crate::{
    multi_scalar_mul_const_time_g1, Commitment, CommitmentBuilder, GeneratorG1, ProofChallenge,
    SignatureMessage, ToVariableLengthBytes, G1_COMPRESSED_SIZE, G1_UNCOMPRESSED_SIZE,
};

use ff_zeroize::{Field, PrimeField};
use pairing_plus::serdes::SerDes;
use pairing_plus::{
    bls12_381::{Bls12, Fq12, Fr, FrRepr, G1, G2},
    CurveAffine, CurveProjective, Engine,
};
use rand::thread_rng;
use serde::{
    de::{Error as DError, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::collections::{BTreeMap, BTreeSet};
use std::convert::TryFrom;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::io::Cursor;

/// Convenience importing module
pub mod prelude {
    pub use super::{PoKOfSignature, PoKOfSignatureProof, PoKOfSignatureProofStatus};
}

/// Proof of Knowledge of a Signature that is used by the prover
/// to construct `PoKOfSignatureProof`.
///
/// XXX: An optimization would be to combine the 2 relations into one by using the same techniques as Bulletproofs
#[derive(Debug, Clone)]
pub struct PoKOfSignature {
    /// A' in section 4.5
    a_prime: G1,
    /// \overline{A} in section 4.5
    a_bar: G1,
    /// d in section 4.5
    d: G1,
    /// For proving relation a_bar / d == a_prime^{-e} * h_0^r2
    pok_vc_1: ProverCommittedG1,
    /// The messages
    secrets_1: Vec<Fr>,
    /// For proving relation g1 * h1^m1 * h2^m2.... for all disclosed messages m_i == d^r3 * h_0^{-s_prime} * h1^-m1 * h2^-m2.... for all undisclosed messages m_i
    pok_vc_2: ProverCommittedG1,
    /// The blinding factors
    secrets_2: Vec<Fr>,
    /// revealed messages
    pub(crate) revealed_messages: BTreeMap<usize, SignatureMessage>,
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
    pub fn is_valid(self) -> bool {
        match self {
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
                "a message was supplied when the proof was created that was not signed or a message was revealed that was initially hidden"
            ),
            PoKOfSignatureProofStatus::BadRevealedMessage => {
                write!(f, "a revealed message was supplied that was not signed or a message was revealed that was initially hidden")
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
#[derive(Debug, Clone)]
pub struct PoKOfSignatureProof {
    /// A' in section 4.5
    pub(crate) a_prime: G1,
    /// \overline{A} in section 4.5
    pub(crate) a_bar: G1,
    /// d in section 4.5
    pub(crate) d: G1,
    /// Proof of relation a_bar / d == a_prime^{-e} * h_0^r2
    pub(crate) proof_vc_1: ProofG1,
    /// Proof of relation g1 * h1^m1 * h2^m2.... for all disclosed messages m_i == d^r3 * h_0^{-s_prime} * h1^-m1 * h2^-m2.... for all undisclosed messages m_i
    pub(crate) proof_vc_2: ProofG1,
}

impl PoKOfSignature {
    /// Creates the initial proof data before a Fiat-Shamir calculation
    pub fn init(
        signature: &Signature,
        vk: &PublicKey,
        messages: &[ProofMessage],
    ) -> Result<Self, BBSError> {
        if messages.len() != vk.message_count() {
            return Err(BBSError::from_kind(
                BBSErrorKind::PublicKeyGeneratorMessageCountMismatch(
                    vk.message_count(),
                    messages.len(),
                ),
            ));
        }
        let sig_messages = messages
            .iter()
            .map(|m| m.get_message())
            .collect::<Vec<SignatureMessage>>();
        if !signature.verify(sig_messages.as_slice(), &vk)? {
            return Err(BBSErrorKind::PoKVCError {
                msg: "The messages and signature do not match.".to_string(),
            }
            .into());
        }

        let mut rng = thread_rng();
        let r1 = Fr::random(&mut rng);
        let r2 = Fr::random(&mut rng);

        let mut temp: Vec<SignatureMessage> = Vec::new();
        for i in 0..messages.len() {
            match &messages[i] {
                ProofMessage::Revealed(r) => temp.push(r.clone()),
                ProofMessage::Hidden(HiddenMessage::ProofSpecificBlinding(m)) => {
                    temp.push(m.clone())
                }
                ProofMessage::Hidden(HiddenMessage::ExternalBlinding(m, _)) => temp.push(m.clone()),
            }
        }

        let b = signature.get_b(temp.as_slice(), &vk);

        let mut a_prime = signature.a;
        a_prime.mul_assign(r1);

        let mut a_bar_denom = a_prime;
        a_bar_denom.mul_assign(signature.e.clone());

        let mut a_bar = b;
        a_bar.mul_assign(r1);
        a_bar.sub_assign(&a_bar_denom);

        let mut r2_d = r2;
        r2_d.negate();
        let mut builder = CommitmentBuilder::new();
        builder.add(&GeneratorG1(b), &SignatureMessage(r1));
        builder.add(&vk.h0, &SignatureMessage(r2_d));

        // d = b^r1 h0^-r2
        let d = builder.finalize().0;

        let r3 = r1.inverse().unwrap();

        // s' = s - r2 r3
        let mut s_prime = r2;
        s_prime.mul_assign(&r3);
        s_prime.negate();
        s_prime.add_assign(&signature.s);

        // For proving relation a_bar / d == a_prime^{-e} * h_0^r2
        let mut committing_1 = ProverCommittingG1::new();
        let mut secrets_1 = Vec::with_capacity(2);
        // For a_prime^{-e}
        committing_1.commit(&GeneratorG1(a_prime));
        let mut sig_e = signature.e.clone();
        sig_e.negate();
        secrets_1.push(sig_e);
        // For h_0^r2
        committing_1.commit(&vk.h0);
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
        let mut secrets_2 = Vec::with_capacity(2 + messages.len());
        // For d^-r3
        committing_2.commit(&GeneratorG1(d));
        let mut r3_d = r3;
        r3_d.negate();
        secrets_2.push(r3_d);
        // h_0^s_prime
        committing_2.commit(&vk.h0);
        secrets_2.push(s_prime);

        let mut revealed_messages = BTreeMap::new();

        for i in 0..vk.message_count() {
            match &messages[i] {
                ProofMessage::Revealed(r) => {
                    revealed_messages.insert(i, r.clone());
                }
                ProofMessage::Hidden(HiddenMessage::ProofSpecificBlinding(m)) => {
                    committing_2.commit(&vk.h[i]);
                    secrets_2.push(m.0.clone());
                }
                ProofMessage::Hidden(HiddenMessage::ExternalBlinding(e, b)) => {
                    committing_2.commit_with(&vk.h[i], b);
                    secrets_2.push(e.0.clone());
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
            revealed_messages,
        })
    }

    /// Return byte representation of public elements so they can be used for challenge computation.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        self.a_bar.serialize(&mut bytes, false).unwrap();

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
    pub fn gen_proof(
        self,
        challenge_hash: &ProofChallenge,
    ) -> Result<PoKOfSignatureProof, BBSError> {
        let secrets_1: Vec<_> = self
            .secrets_1
            .iter()
            .map(|s| SignatureMessage((*s).clone()))
            .collect();
        let secrets_2: Vec<_> = self
            .secrets_2
            .iter()
            .map(|s| SignatureMessage((*s).clone()))
            .collect();
        let proof_vc_1 = self
            .pok_vc_1
            .gen_proof(challenge_hash, secrets_1.as_slice())?;
        let proof_vc_2 = self
            .pok_vc_2
            .gen_proof(challenge_hash, secrets_2.as_slice())?;

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
        self.a_bar.serialize(&mut bytes, false).unwrap();
        self.a_prime.serialize(&mut bytes, false).unwrap();
        vk.h0.0.serialize(&mut bytes, false).unwrap();
        self.proof_vc_1
            .commitment
            .serialize(&mut bytes, false)
            .unwrap();
        self.d.serialize(&mut bytes, false).unwrap();
        vk.h0.0.serialize(&mut bytes, false).unwrap();
        for i in 0..vk.message_count() {
            if revealed_msg_indices.contains(&i) {
                continue;
            }
            vk.h[i].0.serialize(&mut bytes, false).unwrap();
        }
        self.proof_vc_2
            .commitment
            .serialize(&mut bytes, false)
            .unwrap();
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
        Ok(SignatureMessage(
            self.proof_vc_2.responses[2 + msg_idx].clone(),
        ))
    }

    /// Validate the proof
    pub fn verify(
        &self,
        vk: &PublicKey,
        revealed_msgs: &BTreeMap<usize, SignatureMessage>,
        challenge: &ProofChallenge,
    ) -> Result<PoKOfSignatureProofStatus, BBSError> {
        vk.validate()?;
        for i in revealed_msgs.keys() {
            if *i >= vk.message_count() {
                return Err(BBSError::from_kind(BBSErrorKind::GeneralError {
                    msg: format!("Index {} should be less than {}", i, vk.message_count()),
                }));
            }
        }

        if self.a_prime.is_zero() {
            return Ok(PoKOfSignatureProofStatus::BadSignature);
        }

        let mut a_bar = self.a_bar;
        a_bar.negate();
        match Bls12::final_exponentiation(&Bls12::miller_loop(&[
            (
                &self.a_prime.into_affine().prepare(),
                &vk.w.0.into_affine().prepare(),
            ),
            (
                &a_bar.into_affine().prepare(),
                &G2::one().into_affine().prepare(),
            ),
        ])) {
            None => return Ok(PoKOfSignatureProofStatus::BadSignature),
            Some(product) => {
                if product != Fq12::one() {
                    return Ok(PoKOfSignatureProofStatus::BadSignature);
                }
            }
        };

        let mut bases = vec![];
        bases.push(GeneratorG1(self.a_prime.clone()));
        bases.push(vk.h0.clone());
        // a_bar / d
        let mut a_bar_d = self.a_bar;
        a_bar_d.sub_assign(&self.d);
        // let a_bar_d = &self.a_bar - &self.d;
        if !self
            .proof_vc_1
            .verify(&bases, &Commitment(a_bar_d), &challenge)?
        {
            return Ok(PoKOfSignatureProofStatus::BadHiddenMessage);
        }

        let mut bases_pok_vc_2 = Vec::with_capacity(2 + vk.message_count() - revealed_msgs.len());
        bases_pok_vc_2.push(GeneratorG1(self.d.clone()));
        bases_pok_vc_2.push(vk.h0.clone());

        // `bases_disclosed` and `exponents` below are used to create g1 * h1^-m1 * h2^-m2.... for all disclosed messages m_i
        let mut bases_disclosed = Vec::with_capacity(1 + revealed_msgs.len());
        let mut exponents = Vec::with_capacity(1 + revealed_msgs.len());
        // XXX: g1 should come from a setup param and not generator
        bases_disclosed.push(G1::one());
        exponents.push(Fr::from_repr(FrRepr::from(1u64)).unwrap());
        for i in 0..vk.message_count() {
            if revealed_msgs.contains_key(&i) {
                let message = revealed_msgs.get(&i).unwrap();
                bases_disclosed.push(vk.h[i].0.clone());
                exponents.push(message.0.clone());
            } else {
                bases_pok_vc_2.push(vk.h[i].clone());
            }
        }
        // pr = g1 * h1^-m1 * h2^-m2.... = (g1 * h1^m1 * h2^m2....)^-1 for all disclosed messages m_i
        let mut pr = Commitment(multi_scalar_mul_const_time_g1(&bases_disclosed, &exponents));
        pr.0.negate();
        match self
            .proof_vc_2
            .verify(bases_pok_vc_2.as_slice(), &pr, challenge)
        {
            Ok(b) => {
                if b {
                    Ok(PoKOfSignatureProofStatus::Success)
                } else {
                    Ok(PoKOfSignatureProofStatus::BadRevealedMessage)
                }
            }
            Err(_) => Ok(PoKOfSignatureProofStatus::BadRevealedMessage),
        }
    }

    /// Convert the proof to raw bytes
    pub(crate) fn to_bytes(&self, compressed: bool) -> Vec<u8> {
        let mut output = Vec::new();
        self.a_prime.serialize(&mut output, compressed).unwrap();
        self.a_bar.serialize(&mut output, compressed).unwrap();
        self.d.serialize(&mut output, compressed).unwrap();
        let mut proof1_bytes = self.proof_vc_1.to_bytes(compressed);
        let proof1_len: u32 = proof1_bytes.len() as u32;
        output.extend_from_slice(&proof1_len.to_be_bytes()[..]);
        output.append(&mut proof1_bytes);
        let mut proof2_bytes = self.proof_vc_2.to_bytes(compressed);
        output.append(&mut proof2_bytes);
        output
    }

    /// Convert the byte slice into a proof
    pub(crate) fn from_bytes(
        data: &[u8],
        g1_size: usize,
        compressed: bool,
    ) -> Result<Self, BBSError> {
        if data.len() < g1_size * 3 {
            return Err(BBSError::from_kind(BBSErrorKind::PoKVCError {
                msg: format!("Invalid proof bytes. Expected {}", g1_size * 3),
            }));
        }
        let mut c = Cursor::new(data.as_ref());
        let mut offset;
        let mut end = g1_size;
        let a_prime = slice_to_elem!(&mut c, G1, compressed).map_err(|e| {
            BBSError::from_kind(BBSErrorKind::PoKVCError {
                msg: format!("{}", e),
            })
        })?;

        offset = end;
        end = offset + g1_size;

        let a_bar = slice_to_elem!(&mut c, G1, compressed).map_err(|e| {
            BBSError::from_kind(BBSErrorKind::PoKVCError {
                msg: format!("{}", e),
            })
        })?;
        offset = end;
        end = offset + g1_size;

        let d = slice_to_elem!(&mut c, G1, compressed).map_err(|e| {
            BBSError::from_kind(BBSErrorKind::PoKVCError {
                msg: format!("{}", e),
            })
        })?;
        offset = end;
        end = offset + 4;
        let proof1_bytes = u32::from_be_bytes(*array_ref![data, offset, 4]) as usize;

        offset = end;
        end = offset + proof1_bytes;
        let proof_vc_1 =
            ProofG1::from_bytes(&data[offset..end], g1_size, compressed).map_err(|e| {
                BBSError::from_kind(BBSErrorKind::PoKVCError {
                    msg: format!("{}", e),
                })
            })?;

        let proof_vc_2 = ProofG1::from_bytes(&data[end..], g1_size, compressed).map_err(|e| {
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

impl ToVariableLengthBytes for PoKOfSignatureProof {
    type Output = PoKOfSignatureProof;
    type Error = BBSError;

    /// Convert the proof to a compressed raw bytes form.
    fn to_bytes_compressed_form(&self) -> Vec<u8> {
        self.to_bytes(true)
    }

    /// Convert compressed byte slice into a proof
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

try_from_impl!(PoKOfSignatureProof, BBSError);
serdes_impl!(PoKOfSignatureProof);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::generate;
    use crate::{HashElem, ProofNonce, RandomElem};

    #[test]
    fn pok_signature_no_revealed_messages() {
        let message_count = 5;
        let mut messages = Vec::new();
        for _ in 0..message_count {
            messages.push(SignatureMessage::random());
        }
        let (verkey, signkey) = generate(message_count).unwrap();

        let sig = Signature::new(messages.as_slice(), &signkey, &verkey).unwrap();
        let res = sig.verify(messages.as_slice(), &verkey);
        assert!(res.unwrap());
        let proof_messages = vec![
            pm_hidden_raw!(messages[0].clone()),
            pm_hidden_raw!(messages[1].clone()),
            pm_hidden_raw!(messages[2].clone()),
            pm_hidden_raw!(messages[3].clone()),
            pm_hidden_raw!(messages[4].clone()),
        ];
        let revealed_msg: BTreeMap<usize, SignatureMessage> = BTreeMap::new();

        let pok = PoKOfSignature::init(&sig, &verkey, proof_messages.as_slice()).unwrap();
        let challenge_prover = ProofChallenge::hash(&pok.to_bytes());
        let proof = pok.gen_proof(&challenge_prover).unwrap();

        // Test to_bytes
        let proof_bytes = proof.to_bytes_uncompressed_form();
        let proof_cp = PoKOfSignatureProof::from_bytes_uncompressed_form(&proof_bytes);
        assert!(proof_cp.is_ok());

        let proof_bytes = proof.to_bytes_compressed_form();
        let proof_cp = PoKOfSignatureProof::from_bytes_compressed_form(&proof_bytes);
        assert!(proof_cp.is_ok());

        // The verifier generates the challenge on its own.
        let challenge_bytes = proof.get_bytes_for_challenge(BTreeSet::new(), &verkey);
        let challenge_verifier = ProofChallenge::hash(&challenge_bytes);
        assert!(proof
            .verify(&verkey, &revealed_msg, &challenge_verifier)
            .unwrap()
            .is_valid());
    }

    #[test]
    fn pok_signature_revealed_message() {
        let message_count = 5;
        let messages: Vec<SignatureMessage> = (0..message_count)
            .collect::<Vec<usize>>()
            .iter()
            .map(|_| SignatureMessage::random())
            .collect();
        let (verkey, signkey) = generate(message_count).unwrap();

        let sig = Signature::new(messages.as_slice(), &signkey, &verkey).unwrap();
        let res = sig.verify(messages.as_slice(), &verkey);
        assert!(res.unwrap());

        let mut proof_messages = vec![
            pm_revealed_raw!(messages[0].clone()),
            pm_hidden_raw!(messages[1].clone()),
            pm_revealed_raw!(messages[2].clone()),
            pm_hidden_raw!(messages[3].clone()),
            pm_hidden_raw!(messages[4].clone()),
        ];

        let mut revealed_indices = BTreeSet::new();
        revealed_indices.insert(0);
        revealed_indices.insert(2);

        let pok = PoKOfSignature::init(&sig, &verkey, proof_messages.as_slice()).unwrap();
        let challenge_prover = ProofChallenge::hash(&pok.to_bytes());
        let proof = pok.gen_proof(&challenge_prover).unwrap();

        let mut revealed_msgs = BTreeMap::new();
        for i in &revealed_indices {
            revealed_msgs.insert(i.clone(), messages[*i].clone());
        }
        // The verifier generates the challenge on its own.
        let chal_bytes = proof.get_bytes_for_challenge(revealed_indices.clone(), &verkey);
        let challenge_verifier = ProofChallenge::hash(&chal_bytes);
        assert!(proof
            .verify(&verkey, &revealed_msgs, &challenge_verifier)
            .unwrap()
            .is_valid());

        // Reveal wrong message
        let mut revealed_msgs_1 = revealed_msgs.clone();
        revealed_msgs_1.insert(2, SignatureMessage::random());
        assert!(!proof
            .verify(&verkey, &revealed_msgs_1, &challenge_verifier)
            .unwrap()
            .is_valid());

        // PoK with supplied blindings
        proof_messages[1] = pm_hidden_raw!(messages[1].clone(), ProofNonce::random());
        proof_messages[3] = pm_hidden_raw!(messages[3].clone(), ProofNonce::random());
        proof_messages[4] = pm_hidden_raw!(messages[4].clone(), ProofNonce::random());

        let pok = PoKOfSignature::init(&sig, &verkey, proof_messages.as_slice()).unwrap();

        let mut revealed_msgs = BTreeMap::new();
        for i in &revealed_indices {
            revealed_msgs.insert(i.clone(), messages[*i].clone());
        }
        let challenge_prover = ProofChallenge::hash(&pok.to_bytes());
        let proof = pok.gen_proof(&challenge_prover).unwrap();

        // The verifier generates the challenge on its own.
        let challenge_bytes = proof.get_bytes_for_challenge(revealed_indices.clone(), &verkey);
        let challenge_verifier = ProofChallenge::hash(&challenge_bytes);
        assert!(proof
            .verify(&verkey, &revealed_msgs, &challenge_verifier)
            .unwrap()
            .is_valid());
    }

    #[test]
    fn test_pok_multiple_sigs_with_same_msg() {
        // Prove knowledge of multiple signatures and the equality of a specific message under both signatures.
        // Knowledge of 2 signatures and their corresponding messages is being proven.
        // 2nd message in the 1st signature and 5th message in the 2nd signature are to be proven equal without revealing them

        let message_count = 5;
        let (vk, signkey) = generate(message_count).unwrap();

        let same_msg = SignatureMessage::random();
        let mut msgs_1: Vec<SignatureMessage> = (0..message_count - 1)
            .collect::<Vec<usize>>()
            .iter()
            .map(|_| SignatureMessage::random())
            .collect();
        let mut proof_messages_1 = Vec::with_capacity(message_count);

        for m in msgs_1.iter() {
            proof_messages_1.push(pm_hidden_raw!(m.clone()));
        }

        let same_blinding = ProofNonce::random();
        msgs_1.insert(1, same_msg.clone());
        proof_messages_1.insert(1, pm_hidden_raw!(same_msg.clone(), same_blinding.clone()));

        let sig_1 = Signature::new(msgs_1.as_slice(), &signkey, &vk).unwrap();
        assert!(sig_1.verify(msgs_1.as_slice(), &vk).unwrap());

        let mut msgs_2: Vec<SignatureMessage> = (0..message_count - 1)
            .collect::<Vec<usize>>()
            .iter()
            .map(|_| SignatureMessage::random())
            .collect();
        let mut proof_messages_2 = Vec::with_capacity(message_count);
        for m in msgs_2.iter() {
            proof_messages_2.push(pm_hidden_raw!(m.clone()));
        }

        msgs_2.insert(4, same_msg.clone());
        proof_messages_2.insert(4, pm_hidden_raw!(same_msg.clone(), same_blinding.clone()));
        let sig_2 = Signature::new(msgs_2.as_slice(), &signkey, &vk).unwrap();
        assert!(sig_2.verify(msgs_2.as_slice(), &vk).unwrap());

        // A particular message is same
        assert_eq!(msgs_1[1], msgs_2[4]);

        let pok_1 = PoKOfSignature::init(&sig_1, &vk, proof_messages_1.as_slice()).unwrap();
        let pok_2 = PoKOfSignature::init(&sig_2, &vk, proof_messages_2.as_slice()).unwrap();

        let mut chal_bytes = vec![];
        chal_bytes.append(&mut pok_1.to_bytes());
        chal_bytes.append(&mut pok_2.to_bytes());

        let chal_prover = ProofChallenge::hash(&chal_bytes);

        let proof_1 = pok_1.gen_proof(&chal_prover).unwrap();
        let proof_2 = pok_2.gen_proof(&chal_prover).unwrap();

        // The verifier generates the challenge on its own.
        let mut chal_bytes = vec![];
        chal_bytes.append(&mut proof_1.get_bytes_for_challenge(BTreeSet::new(), &vk));
        chal_bytes.append(&mut proof_2.get_bytes_for_challenge(BTreeSet::new(), &vk));
        let chal_verifier = ProofChallenge::hash(&chal_bytes);

        // Response for the same message should be same (this check is made by the verifier)
        assert_eq!(
            proof_1.get_resp_for_message(1).unwrap(),
            proof_2.get_resp_for_message(4).unwrap()
        );
        let revealed = BTreeMap::new();
        assert!(proof_1
            .verify(&vk, &revealed, &chal_verifier)
            .unwrap()
            .is_valid());
        assert!(proof_2
            .verify(&vk, &revealed, &chal_verifier)
            .unwrap()
            .is_valid());
    }
}
