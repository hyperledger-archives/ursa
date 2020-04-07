use amcl_wrapper::{
    constants::GroupG1_SIZE, errors::SerzDeserzError, field_elem::FieldElement,
    group_elem::GroupElement, group_elem_g1::G1, group_elem_g2::G2, types_g2::GroupG2_SIZE,
};
use hash2curve::{bls381g1::Bls12381G1Sswu, HashToCurveXmd};
use hash2curve::DomainSeparationTag;

use crate::errors::prelude::*;

pub mod prelude {
    pub use super::{generate, PublicKey, SecretKey, DeterministicPublicKey};
    pub use hash2curve::DomainSeparationTag;
    pub use amcl_wrapper::constants::FieldElement_SIZE as SECRET_KEY_SIZE;
    pub use amcl_wrapper::constants::FieldElement_SIZE as MESSAGE_SIZE;
    pub use amcl_wrapper::constants::GroupG1_SIZE as COMMITMENT_SIZE;
    pub use amcl_wrapper::types_g2::GroupG2_SIZE as PUBLIC_KEY_SIZE;
}

#[derive(Debug, Clone)]
pub enum KeyGenOption {
    UseSeed(Vec<u8>),
    FromSecretKey(Vec<u8>)
}

// https://eprint.iacr.org/2016/663.pdf Section 4.3
pub type SecretKey = FieldElement;

/// `PublicKey` consists of a blinding generator `h0`, a commitment to the secret key `w`
/// and a generator for each message in `h`
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PublicKey {
    pub h0: G1,     //blinding factor base
    pub h: Vec<G1>, //base for each message to be signed
    pub w: G2,      //commitment to private key
}

impl PublicKey {
    pub fn message_count(&self) -> usize {
        self.h.len()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(GroupG1_SIZE * (self.h.len() + 1) + 4 + GroupG2_SIZE);
        out.extend_from_slice(self.w.to_bytes().as_slice());
        out.extend_from_slice(self.h0.to_bytes().as_slice());
        out.extend_from_slice(&(self.h.len() as u32).to_be_bytes());
        for p in &self.h {
            out.extend_from_slice(p.to_bytes().as_slice());
        }
        out
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, SerzDeserzError> {
        let mut index = 0;
        let w = G2::from_bytes(&data[0..GroupG2_SIZE])?;
        index += GroupG2_SIZE;
        let h0 = G1::from_bytes(&data[index..(index + GroupG1_SIZE)])?;
        index += GroupG1_SIZE;
        let h_size = u32::from_be_bytes([
            data[index],
            data[index + 1],
            data[index + 2],
            data[index + 3],
        ]) as usize;
        let mut h = Vec::with_capacity(h_size);
        index += 4;
        for _ in 0..h_size {
            let p = G1::from_bytes(&data[index..(index + GroupG1_SIZE)])?;
            h.push(p);
            index += GroupG1_SIZE;
        }
        Ok(PublicKey { w, h0, h })
    }

    // Make sure no generator is identity
    pub fn validate(&self) -> Result<(), BBSError> {
        if self.h0.is_identity() || self.w.is_identity() || self.h.iter().any(|v| v.is_identity()) {
            Err(BBSError::from_kind(BBSErrorKind::MalformedPublicKey))
        } else {
            Ok(())
        }
    }
}

/// Used to deterministically generate all other generators given a commitment to a private key
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeterministicPublicKey {
    w: G2,
}

impl DeterministicPublicKey {
    /// Generates a random `Secretkey` and only creates the commitment to it
    pub fn new(option: Option<KeyGenOption>) -> (Self, SecretKey) {
        let secret = match option {
            Some(ref o) => match o {
                KeyGenOption::UseSeed(ref v) => FieldElement::from_msg_hash(v.as_slice()),
                KeyGenOption::FromSecretKey(ref sk) => FieldElement::from_bytes(&sk[..]).unwrap()
            },
            None => FieldElement::random()
        };
        let w = &G2::generator() * &secret;
        (Self { w }, secret)
    }

    /// Convert to a normal public key but deterministically derive all the generators
    pub fn to_public_key(&self, message_count: usize, dst: DomainSeparationTag) -> PublicKey {
        let point_hasher = Bls12381G1Sswu::new(dst);

        let mut data = Vec::with_capacity(message_count);
        data.extend_from_slice(&self.w.to_bytes());
        data.push(0u8);
        data.extend_from_slice(&(message_count.clone() as u32).to_be_bytes()[..]);
        let h0: G1 = point_hasher
            .hash_to_curve_xmd::<sha2::Sha256>(data.as_slice())
            .unwrap().0
            .into();
        let mut current_h = h0.clone();
        let mut h = Vec::new();
        for i in 1..message_count {
            data.clear();
            data.extend_from_slice(&current_h.to_bytes());
            data.push(0u8);
            data.extend_from_slice(&(i as u32).to_be_bytes()[..]);
            current_h = point_hasher
                .hash_to_curve_xmd::<sha2::Sha256>(data.as_slice())
                .unwrap().0
                .into();
            h.push(current_h.clone());
        }

        PublicKey {
            w: self.w.clone(),
            h0,
            h,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.w.to_bytes()
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, SerzDeserzError> {
        let w = G2::from_bytes(&data)?;
        Ok(DeterministicPublicKey { w })
    }
}

impl From<G2> for DeterministicPublicKey {
    fn from(w: G2) -> Self {
        DeterministicPublicKey { w }
    }
}

/// Create a new BBS+ keypair
pub fn generate(message_count: usize) -> Result<(PublicKey, SecretKey), BBSError> {
    if message_count == 0 {
        return Err(BBSError::from_kind(BBSErrorKind::KeyGenError));
    }
    let secret = FieldElement::random();

    // Super paranoid could allow a context to generate the generator from a well known value
    // Not doing this for now since any generator in a prime field should be okay.
    let w = &G2::generator() * &secret;
    let mut h = Vec::new();
    for _ in 0..message_count {
        h.push(G1::random());
    }
    Ok((
        PublicKey {
            w,
            h0: G1::random(),
            h,
        },
        secret,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_generate() {
        let res = generate(0);
        assert!(res.is_err());
        //Check to make sure key has correct size
        let (public_key, _) = generate(1).unwrap();
        let bytes = public_key.to_bytes();
        assert_eq!(bytes.len(), GroupG1_SIZE * 2 + 4 + GroupG2_SIZE);

        let (public_key, _) = generate(5).unwrap();
        assert_eq!(public_key.message_count(), 5);
        //Check key doesn't contain any invalid points
        assert!(public_key.validate().is_ok());
        let bytes = public_key.to_bytes();
        assert_eq!(bytes.len(), GroupG1_SIZE * 6 + 4 + GroupG2_SIZE);
        //Check serialization is working
        let public_key_2 = PublicKey::from_bytes(bytes.as_slice()).unwrap();
        assert_eq!(public_key_2, public_key);
    }

    #[test]
    fn key_conversion() {
        let (dpk, _) = DeterministicPublicKey::new(None);
        let dst = DomainSeparationTag::new(b"TEST", None, None, None).unwrap();

        let pk = dpk.to_public_key(5, dst);

        for i in 0..pk.h.len() {
            assert_ne!(pk.h0, pk.h[i], "h[0] == h[{}]", i + 1);

            for j in (i+1)..pk.h.len() {
                assert_ne!(pk.h[i], pk.h[j], "h[{}] == h[{}]", i + 1, j + 1);
            }
        }
    }
}
