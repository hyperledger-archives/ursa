extern crate amcl;

use std::collections::HashMap;

use self::amcl::bls381::ecp::ECP;
use self::amcl::bls381::ecp2::ECP2;
use self::amcl::bls381::mpin::{SHA256, hash_id};
use self::amcl::bls381::big::{NLEN, MODBYTES};

use hash_functions::{HashFunction, HashError};

struct BLS12_381_SHA256 {
    msg: Vec<u8>,
    digest: [u8; MODBYTES]
}

impl HashFunction for BLS12_381_SHA256  {
    fn new(args: Option<HashMap<String, &[u8]>>) -> Result<Self, HashError> {
        if args.is_some() {
            return Err(HashError::InvalidArgs(String::from("Does not expect any args")))
        }

        Ok(BLS12_381_SHA256 {
            msg: vec![],
            digest: [0; MODBYTES],
        })
    }

    fn update(&mut self, input: &[u8]) {
        self.msg.extend_from_slice(input);
        let mut h: [u8; MODBYTES] = [0; MODBYTES];
        hash_id(SHA256, &self.msg, &mut h);
        self.digest = h;
    }

    fn digest(&self, length: Option<usize>) -> Result<Vec<u8>, HashError> {
        match length {
            Some(l) => {
                let d = self.digest.to_vec();
                if l > d.len() {
                    return Err(HashError::InvalidDigestLength(String::from("Does not expect any args")))
                } else {
                    Ok(d[0..l].to_vec())
                }
            }
            None => Ok(self.digest.to_vec())
        }
    }
}

impl BLS12_381_SHA256 {
    // Map the digest to group G1
    pub fn hash_on_group_g1(&self) -> Result<ECP, HashError> {
        Ok(ECP::mapit(&self.digest(None)?))
    }

    // Map the digest to group G2
    pub fn hash_on_group_g2(&self) -> Result<ECP2, HashError> {
        Ok(ECP2::mapit(&self.digest(None)?))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn gen_test_msgs<'a>() -> Vec<&'a str> {
        vec!["hello world",
             "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum.",
             "",
             "Contrary to popular belief, Lorem Ipsum is not simply random text. It has roots in a piece of classical Latin literature from 45 BC, making it over 2000 years old. Richard McClintock, a Latin professor at Hampden-Sydney College in Virginia, looked up one of the more obscure Latin words, consectetur, from a Lorem Ipsum passage, and going through the cites of the word in classical literature, discovered the undoubtable source."
        ]
    }

    #[test]
    fn test_msg_digest() {
        let hm: HashMap<String, &[u8]> = HashMap::new();
        let hf = BLS12_381_SHA256::new(Some(hm));
        assert!(hf.is_err());

        for msg in &gen_test_msgs() {
            let mut hf = BLS12_381_SHA256::new(None).unwrap();
            hf.update(msg.as_bytes());
            let d1 = hf.digest(None).unwrap();

            let mut hf = BLS12_381_SHA256::new(None).unwrap();
            hf.update(msg.as_bytes());
            let d2 = hf.digest(None).unwrap();

            assert_eq!(d1, d2);

            let d = hf.digest(Some(MODBYTES+1));
            assert!(d.is_err());

            for n in vec![1, 2, 10, 20, MODBYTES] {
                let d = hf.digest(Some(MODBYTES-n)).unwrap();
                assert_eq!(d2[0..MODBYTES-n], d[0..MODBYTES-n]);
            }
        }

        let mut hf1 = BLS12_381_SHA256::new(None).unwrap();
        for msg in &gen_test_msgs() {
            hf1.update(msg.as_bytes());
        }
        let d1 = hf1.digest(None).unwrap();

        let mut hf2 = BLS12_381_SHA256::new(None).unwrap();
        for msg in &gen_test_msgs() {
            hf2.update(msg.as_bytes());
        }
        let d2 = hf2.digest(None).unwrap();

        assert_eq!(d1, d2);
    }

    #[test]
    fn test_hashing_on_groups() {
        for msg in &gen_test_msgs() {
            let mut hf = BLS12_381_SHA256::new(None).unwrap();
            hf.update(msg.as_bytes());
            let mut g1n1 = hf.hash_on_group_g1().unwrap();
            let mut g2n1 = hf.hash_on_group_g2().unwrap();

            let mut hf = BLS12_381_SHA256::new(None).unwrap();
            hf.update(msg.as_bytes());
            let mut g1n2 = hf.hash_on_group_g1().unwrap();
            let mut g2n2 = hf.hash_on_group_g2().unwrap();

            assert_eq!(g1n1.tostring(), g1n2.tostring());
            assert_eq!(g2n1.tostring(), g2n2.tostring());

        }
    }
}