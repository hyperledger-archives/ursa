use amcl_wrapper::field_elem::FieldElement;
use amcl_wrapper::group_elem::GroupElement;

use crate::errors::PSError;
use crate::{OtherGroup, SignatureGroup};

pub struct Sigkey {
    pub X: SignatureGroup,
}

#[derive(Clone, Debug)]
pub struct Verkey {
    pub g: SignatureGroup,
    pub g_tilde: OtherGroup,
    pub X_tilde: OtherGroup,
    pub Y: Vec<SignatureGroup>,
    pub Y_tilde: Vec<OtherGroup>,
}

impl Verkey {
    pub fn validate(&self) -> Result<(), PSError> {
        if self.Y.len() != self.Y_tilde.len() {
            return Err(PSError::InvalidVerkey {
                y: self.Y.len(),
                y_tilde: self.Y_tilde.len(),
            });
        }
        Ok(())
    }
}

pub fn keygen(count_messages: usize, label: &[u8]) -> (Sigkey, Verkey) {
    // TODO: Take PRNG as argument
    let g = SignatureGroup::from_msg_hash(&[label, " : g".as_bytes()].concat());
    let g_tilde = OtherGroup::from_msg_hash(&[label, " : g_tilde".as_bytes()].concat());
    let x = FieldElement::random();
    let mut Y = vec![];
    let mut Y_tilde = vec![];
    let X = &g * &x;
    let X_tilde = &g_tilde * &x;
    for i in 0..count_messages {
        let y = FieldElement::random();
        Y.push(&g * &y);
        Y_tilde.push(&g_tilde * &y);
    }
    (
        Sigkey { X },
        Verkey {
            g,
            g_tilde,
            X_tilde,
            Y,
            Y_tilde,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    // For benchmarking
    use std::time::{Duration, Instant};

    #[test]
    fn test_keygen() {
        let count_msgs = 5;
        let (sk, vk) = keygen(count_msgs, "test".as_bytes());
        assert!(vk.validate().is_ok());
        assert_eq!(vk.Y.len(), count_msgs);
        assert_eq!(vk.Y_tilde.len(), count_msgs);
    }
}
