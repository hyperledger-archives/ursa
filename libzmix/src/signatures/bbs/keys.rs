use amcl_wrapper::{
    field_elem::FieldElement,
    group_elem::GroupElement,
    group_elem_g1::G1,
    group_elem_g2::G2,
    constants::GROUP_G1_SIZE,
    types_g2::GROUP_G2_SIZE,
    errors::SerzDeserzError,
};
use serde::{Serialize, Deserialize};

pub type SecretKey = FieldElement;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PublicKey {
    pub h0: G1,      //blinding factor base
    pub h: Vec<G1>,  //base for each message to be signed
    pub w: G2        //commitment to private key
}

impl PublicKey {
    pub fn message_count(&self) -> usize { self.h.len() }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(GROUP_G1_SIZE*(self.h.len() + 1) + 4 + GROUP_G2_SIZE);
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
        let w = G2::from_bytes(&data[0..GROUP_G2_SIZE])?;
        index += GROUP_G2_SIZE;
        let h0 = G1::from_bytes(&data[index..(index+GROUP_G1_SIZE)])?;
        index += GROUP_G1_SIZE;
        let h_size = u32::from_be_bytes([data[index], data[index+1], data[index+2], data[index+3]]) as usize;
        let mut h = Vec::with_capacity(h_size);
        index += 4;
        for _ in 0..h_size {
            let p = G1::from_bytes(&data[index..(index+GROUP_G1_SIZE)])?;
            h.push(p);
            index += GROUP_G1_SIZE;
        }
        Ok(PublicKey { w, h0, h })
    }
}

pub fn generate(message_count: usize) -> (PublicKey, SecretKey) {
    let secret = FieldElement::random();

    // XXX: Choosing G2::generator() temporarily. The generator should be a setup parameter in practice
    let w = &G2::generator() * &secret;
    let mut h = Vec::new();
    for _ in 0..message_count {
        h.push(G1::random());
    }
    (PublicKey { w, h0: G1::random(), h }, secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_generate() {
        let (public_key, _) = generate(0);
        let bytes = public_key.to_bytes();
        assert_eq!(bytes.len(), GROUP_G1_SIZE + 4 + GROUP_G2_SIZE);

        let (public_key, _) = generate(5);
        assert_eq!(public_key.message_count(), 5);
        let bytes = public_key.to_bytes();
        assert_eq!(bytes.len(), GROUP_G1_SIZE * 6 + 4 + GROUP_G2_SIZE);
        let public_key_2 = PublicKey::from_bytes(bytes.as_slice()).unwrap();
        assert_eq!(public_key_2, public_key);
    }
}
