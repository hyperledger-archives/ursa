use amcl_wrapper::field_elem::FieldElement;
use amcl_wrapper::group_elem::GroupElement;

use crate::errors::{PSError, PSErrorKind};
use crate::{OtherGroup, SignatureGroup};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Sigkey {
    pub X: SignatureGroup,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
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
            return Err(PSErrorKind::InvalidVerkey {
                y: self.Y.len(),
                y_tilde: self.Y_tilde.len(),
            }
            .into());
        }
        Ok(())
    }
}

pub fn keygen(count_messages: usize, label: &[u8]) -> (Sigkey, Verkey) {
    let g = SignatureGroup::from_msg_hash(&[label, " : g".as_bytes()].concat());
    let g_tilde = OtherGroup::from_msg_hash(&[label, " : g_tilde".as_bytes()].concat());
    let x = FieldElement::random();
    let mut Y = vec![];
    let mut Y_tilde = vec![];
    let X = &g * &x;
    let X_tilde = &g_tilde * &x;
    for _ in 0..count_messages {
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
        let (_, vk) = keygen(count_msgs, "test".as_bytes());
        assert!(vk.validate().is_ok());
        assert_eq!(vk.Y.len(), count_msgs);
        assert_eq!(vk.Y_tilde.len(), count_msgs);
    }

    #[test]
    fn test_verkey_validate() {
        let (_, vk) = keygen(5, "test".as_bytes());
        assert!(vk.validate().is_ok());

        let mut vk_1 = vk.clone();
        vk_1.Y_tilde.push(OtherGroup::new());
        assert!(vk_1.validate().is_err());

        let mut vk_2 = vk.clone();
        vk_2.Y.push(SignatureGroup::new());
        assert!(vk_2.validate().is_err());
    }

}
