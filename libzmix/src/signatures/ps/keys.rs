use amcl_wrapper::field_elem::FieldElement;
use amcl_wrapper::group_elem::GroupElement;

use super::errors::{PSError, PSErrorKind};
use super::{OtherGroup, SignatureGroup};

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

pub fn keygen(count_messages: usize, label: &[u8]) -> (Verkey, Sigkey) {
    let g = SignatureGroup::from_msg_hash(&[label, b" : g"].concat());
    let g_tilde = OtherGroup::from_msg_hash(&[label, b" : g_tilde"].concat());
    let x = FieldElement::random();
    let mut Y = vec![];
    let mut Y_tilde = vec![];
    let X = &g * &x;
    let X_tilde = &g_tilde * &x;
    for _ in 0..count_messages {
        // It is mandatory that all Y and Y_tilde have same discrete log wrt. g and g_tilde respectively.
        // But once Y and Y_tilde are generated, y is not needed.
        let y = FieldElement::random();
        Y.push(&g * &y);
        Y_tilde.push(&g_tilde * &y);
    }
    (
        Verkey {
            g,
            g_tilde,
            X_tilde,
            Y,
            Y_tilde,
        },
        Sigkey { X },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keygen() {
        let count_msgs = 5;
        let (vk, _) = keygen(count_msgs, "test".as_bytes());
        assert!(vk.validate().is_ok());
        assert_eq!(vk.Y.len(), count_msgs);
        assert_eq!(vk.Y_tilde.len(), count_msgs);
    }

    #[test]
    fn test_verkey_validate() {
        let (vk, _) = keygen(5, "test".as_bytes());
        assert!(vk.validate().is_ok());

        let mut vk_1 = vk.clone();
        vk_1.Y_tilde.push(OtherGroup::new());
        assert!(vk_1.validate().is_err());

        let mut vk_2 = vk.clone();
        vk_2.Y.push(SignatureGroup::new());
        assert!(vk_2.validate().is_err());
    }
}
