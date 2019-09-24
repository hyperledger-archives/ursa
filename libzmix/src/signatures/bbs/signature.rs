use super::super::SignatureBlinding;
use super::super::SignatureMessage;
use super::keys::{PublicKey, SecretKey};
use crate::errors::prelude::*;
use amcl_wrapper::{
    constants::{GroupG1_SIZE, MODBYTES},
    extension_field_gt::GT,
    field_elem::FieldElement,
    group_elem::{GroupElement, GroupElementVector},
    group_elem_g1::G1,
    group_elem_g2::G2,
};

use amcl_wrapper::field_elem::FieldElementVector;
use amcl_wrapper::group_elem_g1::G1Vector;

macro_rules! check_verkey_message {
    ($statment:expr, $count1:expr, $count2:expr) => {
        if $statment {
            return Err(BBSError::from_kind(
                BBSErrorKind::SigningErrorMessageCountMismatch($count1, $count2),
            ));
        }
    };
}

/// A BBS+ signature.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Signature {
    pub a: G1,
    pub e: FieldElement,
    pub s: FieldElement,
}

// https://eprint.iacr.org/2016/663.pdf Section 4.3
impl Signature {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(GroupG1_SIZE + MODBYTES * 2);
        out.extend_from_slice(self.a.to_bytes().as_slice());
        out.extend_from_slice(self.e.to_bytes().as_slice());
        out.extend_from_slice(self.s.to_bytes().as_slice());
        out
    }

    pub fn from_bytes(data: &[u8]) -> Result<Signature, BBSError> {
        let expected = GroupG1_SIZE + MODBYTES * 2;
        if data.len() != expected {
            return Err(BBSError::from_kind(BBSErrorKind::SignatureIncorrectSize(
                data.len(),
            )));
        }
        let mut index = 0;
        let a = G1::from_bytes(&data[0..GroupG1_SIZE])
            .map_err(|_| BBSError::from_kind(BBSErrorKind::SignatureValueIncorrectSize))?;
        index += GroupG1_SIZE;
        let e = FieldElement::from_bytes(&data[index..(index + MODBYTES)])
            .map_err(|_| BBSError::from_kind(BBSErrorKind::SignatureValueIncorrectSize))?;
        index += MODBYTES;
        let s = FieldElement::from_bytes(&data[index..(index + MODBYTES)])
            .map_err(|_| BBSError::from_kind(BBSErrorKind::SignatureValueIncorrectSize))?;
        Ok(Signature { a, e, s })
    }

    // No committed messages, All messages known to signer.
    pub fn new(
        messages: &[SignatureMessage],
        signkey: &SecretKey,
        verkey: &PublicKey,
    ) -> Result<Self, BBSError> {
        check_verkey_message!(messages.is_empty(), verkey.message_count(), messages.len());
        Signature::new_with_committed_messages(&G1::new(), messages, signkey, verkey)
    }

    // 1 or more messages are captured in `commitment`. The remaining known messages are in `messages`.
    // This is a blind signature.
    pub fn new_with_committed_messages(
        commitment: &G1,
        messages: &[SignatureMessage],
        signkey: &SecretKey,
        verkey: &PublicKey,
    ) -> Result<Self, BBSError> {
        check_verkey_message!(
            messages.len() > verkey.message_count(),
            verkey.message_count(),
            messages.len()
        );
        let e = FieldElement::random();
        let s = FieldElement::random();
        let b = compute_b_const_time(
            commitment,
            verkey,
            messages,
            &s,
            verkey.message_count() - messages.len(),
        );
        let mut exp = signkey.clone();
        exp += &e;
        exp.inverse_mut();
        let a = b * exp;
        Ok(Signature { a, e, s })
    }

    pub fn generate_blinding() -> SignatureBlinding {
        SignatureBlinding::random()
    }

    // Once signature on committed attributes (blind signature) is received, the signature needs to be unblinded.
    // Takes the blinding used in the commitment.
    pub fn get_unblinded_signature(&self, blinding: &SignatureBlinding) -> Self {
        Signature {
            a: self.a.clone(),
            s: self.s.clone() + blinding,
            e: self.e.clone(),
        }
    }

    // Verify a signature. During proof of knowledge also, this method is used after extending the verkey
    pub fn verify(
        &self,
        messages: &[SignatureMessage],
        verkey: &PublicKey,
    ) -> Result<bool, BBSError> {
        check_verkey_message!(
            messages.len() != verkey.message_count(),
            verkey.message_count(),
            messages.len()
        );
        let b = compute_b_var_time(&G1::new(), verkey, messages, &self.s, 0);
        let a = (&G2::generator() * &self.e) + &verkey.w;
        Ok(GT::ate_2_pairing(&self.a, &a, &(-&b), &G2::generator()).is_one())
    }
}

fn prep_vec_for_b(
    public_key: &PublicKey,
    messages: &[FieldElement],
    blinding_factor: &FieldElement,
    offset: usize,
) -> (G1Vector, FieldElementVector) {
    let mut points = G1Vector::with_capacity(messages.len() + 2);
    let mut scalars = FieldElementVector::with_capacity(messages.len() + 2);
    // XXX: g1 should not be a generator but a setup param
    // prep for g1*h0^blinding_factor*hi^mi.....
    points.push(G1::generator());
    scalars.push(FieldElement::one());
    points.push(public_key.h0.clone());
    scalars.push(blinding_factor.clone());

    for i in 0..messages.len() {
        points.push(public_key.h[offset + i].clone());
        scalars.push(messages[i].clone());
    }
    (points, scalars)
}

/// Helper function for computing the `b` value. Internal helper function
pub fn compute_b_const_time(
    starting_value: &G1,
    public_key: &PublicKey,
    messages: &[FieldElement],
    blinding_factor: &FieldElement,
    offset: usize,
) -> G1 {
    let (points, scalars) = prep_vec_for_b(public_key, messages, blinding_factor, offset);
    starting_value + points.multi_scalar_mul_const_time(&scalars).unwrap()
}

/// Helper function for computing the `b` value. Internal helper function
pub fn compute_b_var_time(
    starting_value: &G1,
    public_key: &PublicKey,
    messages: &[FieldElement],
    blinding_factor: &FieldElement,
    offset: usize,
) -> G1 {
    let (points, scalars) = prep_vec_for_b(public_key, messages, blinding_factor, offset);
    starting_value + points.multi_scalar_mul_var_time(&scalars).unwrap()
}

#[cfg(test)]
mod tests {
    use super::super::keys::generate;
    use super::super::pok_sig::ProverCommittingG1;
    use super::*;

    #[test]
    fn signature_serialization() {
        let sig = Signature {
            a: G1::random(),
            e: FieldElement::random(),
            s: FieldElement::random(),
        };
        let bytes = sig.to_bytes();
        assert_eq!(bytes.len(), GroupG1_SIZE + MODBYTES * 2);
        let sig_2 = Signature::from_bytes(bytes.as_slice()).unwrap();
        assert_eq!(sig, sig_2);
    }

    #[test]
    fn gen_signature() {
        let message_count = 5;
        let messages = FieldElementVector::random(message_count);
        let (verkey, signkey) = generate(message_count).unwrap();

        let res = Signature::new(messages.as_slice(), &signkey, &verkey);
        assert!(res.is_ok());
        let messages = Vec::new();
        let res = Signature::new(messages.as_slice(), &signkey, &verkey);
        assert!(res.is_err());
    }

    #[test]
    fn signature_validation() {
        let message_count = 5;
        let messages = FieldElementVector::random(message_count);
        let (verkey, signkey) = generate(message_count).unwrap();

        let sig = Signature::new(messages.as_slice(), &signkey, &verkey).unwrap();
        let res = sig.verify(messages.as_slice(), &verkey);
        assert!(res.is_ok());
        assert!(res.unwrap());

        let mut messages = Vec::new();
        for _ in 0..message_count {
            messages.push(FieldElement::random());
        }
        let res = sig.verify(messages.as_slice(), &verkey);
        assert!(res.is_ok());
        assert!(!res.unwrap());
    }

    #[test]
    fn signature_committed_messages() {
        let message_count = 4;
        let messages = FieldElementVector::random(message_count);
        let (verkey, signkey) = generate(message_count).unwrap();

        //User blinds first attribute
        let blinding = Signature::generate_blinding();

        //User creates a random commitment, computes challenges and response. The proof of knowledge consists of a commitment and responses
        //User and signer engage in a proof of knowledge for `commitment`
        let commitment = &verkey.h0 * &blinding + &verkey.h[0] * &messages[0];

        let mut committing = ProverCommittingG1::new();
        committing.commit(&verkey.h0, None);
        committing.commit(&verkey.h[0], None);
        let committed = committing.finish();

        let mut hidden_msgs = Vec::new();
        hidden_msgs.push(blinding.clone());
        hidden_msgs.push(messages[0].clone());

        let mut bases = Vec::new();
        bases.push(verkey.h0.clone());
        bases.push(verkey.h[0].clone());

        let challenge_hash = committed.gen_challenge(commitment.to_bytes());
        let proof = committed
            .gen_proof(&challenge_hash, hidden_msgs.as_slice())
            .unwrap();

        assert!(proof
            .verify(bases.as_slice(), &commitment, &challenge_hash)
            .unwrap());
        let sig = Signature::new_with_committed_messages(
            &commitment,
            &messages.as_slice()[1..],
            &signkey,
            &verkey,
        );
        assert!(sig.is_ok());
        let sig = sig.unwrap();
        //First test should fail since the signature is blinded
        let res = sig.verify(messages.as_slice(), &verkey);
        assert!(res.is_ok());
        assert!(!res.unwrap());

        let sig = sig.get_unblinded_signature(&blinding);
        let res = sig.verify(messages.as_slice(), &verkey);
        assert!(res.is_ok());
        assert!(res.unwrap());
    }
}
