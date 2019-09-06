use crate::amcl_wrapper::group_elem::GroupElementVector;
use crate::errors::{PSError, PSErrorKind};
use crate::keys::{Sigkey, Verkey};
use crate::{ate_2_pairing, OtherGroup, OtherGroupVec, SignatureGroup, SignatureGroupVec};
use amcl_wrapper::field_elem::{FieldElement, FieldElementVector};
use amcl_wrapper::group_elem::GroupElement;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Signature {
    pub sigma_1: SignatureGroup,
    pub sigma_2: SignatureGroup,
}

/// Section  6.1 of paper
impl Signature {
    /// No committed messages. All messages known to signer.
    pub fn new(
        messages: &[FieldElement],
        sigkey: &Sigkey,
        verkey: &Verkey,
    ) -> Result<Self, PSError> {
        Self::check_verkey_and_messages_compat(messages, verkey)?;
        let u = FieldElement::random();
        let sigma_1 = &verkey.g * &u;
        let mut points = SignatureGroupVec::new(0);
        let mut scalars = FieldElementVector::new(0);
        points.push(sigkey.X.clone());
        scalars.push(FieldElement::one());
        for i in 0..messages.len() {
            scalars.push(messages[i].clone());
            points.push(verkey.Y[i].clone());
        }
        let sigma_2 = points.multi_scalar_mul_const_time(&scalars).unwrap() * &u;
        Ok(Signature { sigma_1, sigma_2 })
    }

    /// 1 or more messages are captured in a commitment `commitment`. The remaining known messages are in `messages`.
    /// This is a blind signature.
    pub fn new_with_committed_messages(
        commitment: &SignatureGroup,
        messages: &[FieldElement],
        sigkey: &Sigkey,
        verkey: &Verkey,
    ) -> Result<Self, PSError> {
        verkey.validate()?;
        // There should be commitment to at least one message
        if messages.len() >= verkey.Y.len() {
            return Err(PSErrorKind::UnsupportedNoOfMessages {
                expected: messages.len(),
                given: verkey.Y.len(),
            }.into());
        }

        let u = FieldElement::random();
        let sigma_1 = &verkey.g * &u;
        let mut points = SignatureGroupVec::new(0);
        let mut scalars = FieldElementVector::new(0);
        points.push(sigkey.X.clone());
        scalars.push(FieldElement::one());
        points.push(commitment.clone());
        scalars.push(FieldElement::one());
        let diff = (verkey.Y.len() - messages.len());
        for i in 0..messages.len() {
            scalars.push(messages[i].clone());
            points.push(verkey.Y[diff + i].clone());
        }
        let sigma_2 = points.multi_scalar_mul_const_time(&scalars).unwrap() * &u;
        Ok(Signature { sigma_1, sigma_2 })
    }

    /// Verify a signature. During proof of knowledge also, this method is used after extending the verkey
    pub fn verify(&self, messages: &[FieldElement], verkey: &Verkey) -> Result<bool, PSError> {
        Self::check_verkey_and_messages_compat(messages, verkey)?;
        let mut points = OtherGroupVec::new(0);
        let mut scalars = FieldElementVector::new(0);
        points.push(verkey.X_tilde.clone());
        scalars.push(FieldElement::one());
        for i in 0..messages.len() {
            scalars.push(messages[i].clone());
            points.push(verkey.Y_tilde[i].clone());
        }
        // pr = X_tilde * Y_tilde[0]^messages[0] * Y_tilde[1]^messages[1] * .... Y_tilde[i]^messages[i]
        let pr = points.multi_scalar_mul_var_time(&scalars).unwrap();
        // check e(sigma_1, pr) == e(sigma_2, g_tilde) => e(sigma_1, pr) * e(sigma_2, g_tilde)^-1 == 1
        let neg_g_tilde = verkey.g_tilde.negation();
        let res = ate_2_pairing(&self.sigma_1, &pr, &self.sigma_2, &neg_g_tilde);
        Ok(res.is_one())
    }

    /// Once signature on committed attributes (blind signature) is received, the signature needs to be unblinded.
    /// Takes the blinding used in the commitment.
    pub fn get_unblinded_signature(&self, blinding: &FieldElement) -> Self {
        let sigma_1 = self.sigma_1.clone();
        let sigma_1_t = &sigma_1 * blinding;
        let sigma_2 = &self.sigma_2 - sigma_1_t;
        Self { sigma_1, sigma_2 }
    }

    pub fn check_verkey_and_messages_compat(
        messages: &[FieldElement],
        verkey: &Verkey,
    ) -> Result<(), PSError> {
        verkey.validate()?;
        if messages.len() != verkey.Y.len() {
            return Err(PSErrorKind::UnsupportedNoOfMessages {
                expected: messages.len(),
                given: verkey.Y.len(),
            }.into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::keygen;
    // For benchmarking
    use std::time::{Duration, Instant};

    #[test]
    fn test_signature_all_known_messages() {
        for i in 0..10 {
            let count_msgs = (i % 5) + 1;
            let (sk, vk) = keygen(count_msgs, "test".as_bytes());
            let msgs = FieldElementVector::random(count_msgs);
            let msgs = msgs.as_slice();
            let sig = Signature::new(msgs, &sk, &vk).unwrap();
            assert!(sig.verify(msgs, &vk).unwrap());
        }
    }

    #[test]
    fn test_signature_single_committed_message() {
        for _ in 0..10 {
            let count_msgs = 1;
            let (sk, vk) = keygen(count_msgs, "test".as_bytes());
            let msg = FieldElement::random();
            let blinding = FieldElement::random();

            // commitment = Y[0]^msg * g^blinding
            let comm = (&vk.Y[0] * &msg) + (&vk.g * &blinding);

            let sig_blinded = Signature::new_with_committed_messages(&comm, &[], &sk, &vk).unwrap();
            let sig_unblinded = sig_blinded.get_unblinded_signature(&blinding);
            assert!(sig_unblinded.verify(&[msg], &vk).unwrap());
        }
    }

    #[test]
    fn test_signature_many_committed_messages() {
        for i in 0..10 {
            let count_msgs = (i % 5) + 1;
            let (sk, vk) = keygen(count_msgs, "test".as_bytes());
            let msgs = FieldElementVector::random(count_msgs);
            let blinding = FieldElement::random();

            // XXX: In production always use multi-scalar multiplication
            let mut comm = SignatureGroup::new();
            for i in 0..count_msgs {
                comm += (&vk.Y[i] * &msgs[i]);
            }
            comm += (&vk.g * &blinding);
            let sig_blinded = Signature::new_with_committed_messages(&comm, &[], &sk, &vk).unwrap();
            let sig_unblinded = sig_blinded.get_unblinded_signature(&blinding);
            assert!(sig_unblinded.verify(msgs.as_slice(), &vk).unwrap());
        }
    }

    #[test]
    fn test_signature_known_and_committed_messages() {
        for i in 0..10 {
            let count_msgs = (i % 6) + 1;
            let committed_msgs = (i % count_msgs) + 1;
            let (sk, vk) = keygen(count_msgs, "test".as_bytes());
            let msgs = FieldElementVector::random(count_msgs);
            let blinding = FieldElement::random();

            // XXX: In production always use multi-scalar multiplication
            let mut comm = SignatureGroup::new();
            for i in 0..committed_msgs {
                comm += (&vk.Y[i] * &msgs[i]);
            }
            comm += (&vk.g * &blinding);

            let sig_blinded = Signature::new_with_committed_messages(
                &comm,
                &msgs.as_slice()[committed_msgs..count_msgs],
                &sk,
                &vk,
            )
            .unwrap();
            let sig_unblinded = sig_blinded.get_unblinded_signature(&blinding);
            assert!(sig_unblinded.verify(msgs.as_slice(), &vk).unwrap());
        }
    }

    #[test]
    fn test_sig_with_unequal_messages_and_verkey_elements() {
        let (sk, vk) = keygen(5, "test".as_bytes());
        let msgs_1 = FieldElementVector::random(6);
        assert!(Signature::new(msgs_1.as_slice(), &sk, &vk).is_err());

        let msgs_2 = FieldElementVector::random(4);
        assert!(Signature::new(msgs_2.as_slice(), &sk, &vk).is_err());
    }

    #[test]
    fn test_committed_sig_with_incorrect_no_of_messages_and_verkey_elements() {
        let (sk, vk) = keygen(5, "test".as_bytes());
        let msgs_1 = FieldElementVector::random(5);
        let blinding = FieldElement::random();

        // No of messages should be at least one less than size of vk.Y
        assert!(Signature::new_with_committed_messages(
            &SignatureGroup::random(),
            &msgs_1.as_slice(),
            &sk,
            &vk
        )
        .is_err());

        let mut comm = SignatureGroup::new();
        for i in 0..5 {
            comm += (&vk.Y[i] * &msgs_1[i]);
        }
        comm += (&vk.g * &blinding);
        let msgs_2 = FieldElementVector::random(6);
        assert!(
            Signature::new_with_committed_messages(&comm, &msgs_2.as_slice(), &sk, &vk).is_err()
        );
    }

    #[test]
    fn timing_signature_over_known_and_committed_messages() {
        // Measure time to create and verify signatures. Verifying time will include time to unblind the signature as well.
        let iterations = 100;
        let count_msgs = 10;
        let committed_msgs = 3;
        let (sk, vk) = keygen(count_msgs, "test".as_bytes());
        let mut total_signing = Duration::new(0, 0);
        let mut total_verifying = Duration::new(0, 0);
        for _ in 0..iterations {
            let msgs = FieldElementVector::random(count_msgs);
            let blinding = FieldElement::random();
            // XXX: In production always use multi-scalar multiplication
            let mut comm = SignatureGroup::new();
            for i in 0..committed_msgs {
                comm += (&vk.Y[i] * &msgs[i]);
            }
            comm += (&vk.g * &blinding);

            let start = Instant::now();
            let sig_blinded = Signature::new_with_committed_messages(
                &comm,
                &msgs.as_slice()[committed_msgs..count_msgs],
                &sk,
                &vk,
            )
            .unwrap();
            total_signing += start.elapsed();

            let start = Instant::now();
            let sig_unblinded = sig_blinded.get_unblinded_signature(&blinding);
            assert!(sig_unblinded.verify(msgs.as_slice(), &vk).unwrap());
            total_verifying += start.elapsed();
        }

        println!(
            "Time to create {} signatures is {:?}",
            iterations, total_signing
        );
        println!(
            "Time to verify {} signatures is {:?}",
            iterations, total_verifying
        );
    }
}
