use super::errors::{PSError, PSErrorKind};
use super::keys::{Sigkey, Verkey};
use super::{ate_2_pairing, OtherGroupVec, SignatureGroup};
use crate::amcl_wrapper::group_elem::GroupElementVector;
use amcl_wrapper::field_elem::{FieldElement, FieldElementVector};
use amcl_wrapper::group_elem::GroupElement;
use signatures::ps::keys::Params;

/// Created by the signer when no blinded messages. Also the receiver of a blind signature can get
/// this by unblinding the blind signature.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Signature {
    pub sigma_1: SignatureGroup,
    pub sigma_2: SignatureGroup,
}

/// Section  4.2 of paper
impl Signature {
    /// Signer creates a signature.
    pub fn new(
        messages: &[FieldElement],
        sigkey: &Sigkey,
        params: &Params,
    ) -> Result<Self, PSError> {
        Self::check_sigkey_and_messages_compat(messages, sigkey)?;
        // A random h should be generated which is same as generating a random u and then computing h = g^u
        let u = FieldElement::random();
        let (sigma_1, sigma_2) =
            Self::sign_with_sigma_1_generated_from_given_exp(messages, sigkey, &u, 0, &params.g)?;
        Ok(Self { sigma_1, sigma_2 })
    }

    // Generate signature when first element of signature tuple is generated using given exponent
    pub fn sign_with_sigma_1_generated_from_given_exp(
        messages: &[FieldElement],
        sigkey: &Sigkey,
        u: &FieldElement,
        offset: usize,
        g: &SignatureGroup,
    ) -> Result<(SignatureGroup, SignatureGroup), PSError> {
        if offset + messages.len() != sigkey.y.len() {
            return Err(PSErrorKind::UnsupportedNoOfMessages {
                expected: offset + messages.len(),
                given: sigkey.y.len(),
            }
            .into());
        }
        // h = g^u
        let h = g * u;
        // h^(x + y_j*m_j + y_{j+1}*m_{j+1} + y_{j+2}*m_{j+2} + ...) = g^{u * (x + y_j*m_j + y_{j+1}*m_{j+1} + y_{j+2}*m_{j+2} + ...)}
        let mut exp = sigkey.x.clone();
        for i in 0..messages.len() {
            exp += &sigkey.y[offset + i] * &messages[i];
        }
        let h_exp = &h * &exp;
        Ok((h, h_exp))
    }

    /// Verify a signature. During proof of knowledge also, this method is used after extending the verkey
    pub fn verify(
        &self,
        messages: &[FieldElement],
        vk: &Verkey,
        params: &Params,
    ) -> Result<bool, PSError> {
        if self.sigma_1.is_identity() || self.sigma_2.is_identity() {
            return Ok(false);
        }
        Self::check_verkey_and_messages_compat(messages, vk)?;
        let mut Y_m_bases = OtherGroupVec::with_capacity(messages.len());
        let mut Y_m_exps = FieldElementVector::with_capacity(messages.len());
        for i in 0..messages.len() {
            Y_m_bases.push(vk.Y_tilde[i].clone());
            Y_m_exps.push(messages[i].clone());
        }
        // Y_m = X_tilde * Y_tilde[1]^m_1 * Y_tilde[2]^m_2 * ...Y_tilde[i]^m_i
        let Y_m = &vk.X_tilde
            + &(Y_m_bases
                .multi_scalar_mul_var_time(Y_m_exps.as_slice())
                .unwrap());
        // e(sigma_1, Y_m) == e(sigma_2, g2) => e(sigma_1, Y_m) * e(-sigma_2, g2) == 1, if precomputation can be used, then
        // inverse in sigma_2 can be avoided since inverse of g_tilde can be precomputed
        let e = ate_2_pairing(
            &self.sigma_1,
            &Y_m,
            &(self.sigma_2.negation()),
            &params.g_tilde,
        );
        Ok(e.is_one())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        bytes.append(&mut self.sigma_1.to_bytes());
        bytes.append(&mut self.sigma_2.to_bytes());
        bytes
    }

    pub fn check_sigkey_and_messages_compat(
        messages: &[FieldElement],
        sigkey: &Sigkey,
    ) -> Result<(), PSError> {
        if messages.len() != sigkey.y.len() {
            return Err(PSErrorKind::UnsupportedNoOfMessages {
                expected: messages.len(),
                given: sigkey.y.len(),
            }
            .into());
        }
        Ok(())
    }

    pub fn check_verkey_and_messages_compat(
        messages: &[FieldElement],
        verkey: &Verkey,
    ) -> Result<(), PSError> {
        if messages.len() != verkey.Y_tilde.len() {
            return Err(PSErrorKind::UnsupportedNoOfMessages {
                expected: messages.len(),
                given: verkey.Y_tilde.len(),
            }
            .into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::keys::keygen;
    use super::*;

    #[test]
    fn test_signature_all_known_messages() {
        let params = Params::new("test".as_bytes());
        for i in 0..10 {
            let count_msgs = (i % 5) + 1;
            let (vk, sk) = keygen(count_msgs, &params);
            let msgs = FieldElementVector::random(count_msgs);
            let msgs = msgs.as_slice();
            let sig = Signature::new(msgs, &sk, &params).unwrap();
            assert!(sig.verify(msgs, &vk, &params).unwrap());
        }
    }

    #[test]
    fn test_sig_with_unequal_messages_and_verkey_elements() {
        let params = Params::new("test".as_bytes());
        let (_, sk) = keygen(5, &params);
        let msgs_1 = FieldElementVector::random(6);
        assert!(Signature::new(msgs_1.as_slice(), &sk, &params).is_err());

        let msgs_2 = FieldElementVector::random(4);
        assert!(Signature::new(msgs_2.as_slice(), &sk, &params).is_err());
    }

    #[test]
    fn test_signature_as_identity() {
        // When signature consists of identity elements, proof verification fails.
        let count_msgs = 5;
        let params = Params::new("test".as_bytes());
        let (vk, _) = keygen(count_msgs, &params);

        let msgs = FieldElementVector::random(count_msgs);
        let sig_bad = Signature {
            sigma_1: SignatureGroup::identity(),
            sigma_2: SignatureGroup::identity(),
        };
        assert!(!sig_bad.verify(msgs.as_slice(), &vk, &params).unwrap());
    }
}
