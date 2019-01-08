use std::collections::HashMap;

use amcl::bls381::ecp::ECP;
use amcl::bls381::ecp2::ECP2;
use amcl::bls381::mpin::{SHA256, hash_id};
use amcl::bls381::big::MODBYTES;

use hash_functions::{HashFunction, HashError};

const GROUP1_DOMAIN_SEP: u8 = 1;
const GROUP2_DOMAIN_SEP: u8 = 2;


pub struct BLS12_381_SHA256_G1 {
    msg: Vec<u8>,
    digest: [u8; MODBYTES]
}

impl HashFunction for BLS12_381_SHA256_G1 {
    fn new(args: Option<HashMap<String, &[u8]>>) -> Result<Self, HashError> {
        if args.is_some() {
            return Err(HashError::InvalidArgs(String::from("Does not expect any args")))
        }

        Ok(BLS12_381_SHA256_G1 {
            msg: vec![],
            digest: [0; MODBYTES],
        })
    }

    fn update(&mut self, input: &[u8]) {
        self.msg.push(GROUP1_DOMAIN_SEP);
        self.msg.extend_from_slice(input);
        let mut h: [u8; MODBYTES] = [0; MODBYTES];
        hash_id(SHA256, &self.msg, &mut h);
        self.digest = h;
    }

    fn digest(&self, length: Option<usize>) -> Result<Vec<u8>, HashError> {
        let mut hash_point = self.hash_on_group();
        let mut digest_bytes: [u8; 2*MODBYTES+1] = [0; 2*MODBYTES+1];
        hash_point.tobytes(&mut digest_bytes, false);
        return_digest(&digest_bytes, length)
    }
}

impl BLS12_381_SHA256_G1 {
    // Map the digest to group G1
    pub fn hash_on_group(&self) -> ECP {
        ECP::mapit(&self.digest)
    }
}

pub struct BLS12_381_SHA256_G2 {
    msg: Vec<u8>,
    digest: [u8; MODBYTES]
}

impl HashFunction for BLS12_381_SHA256_G2 {
    fn new(args: Option<HashMap<String, &[u8]>>) -> Result<Self, HashError> {
        if args.is_some() {
            return Err(HashError::InvalidArgs(String::from("Does not expect any args")))
        }

        Ok(BLS12_381_SHA256_G2 {
            msg: vec![],
            digest: [0; MODBYTES],
        })
    }

    fn update(&mut self, input: &[u8]) {
        self.msg.push(GROUP2_DOMAIN_SEP);
        self.msg.extend_from_slice(input);
        let mut h: [u8; MODBYTES] = [0; MODBYTES];
        hash_id(SHA256, &self.msg, &mut h);
        self.digest = h;
    }

    fn digest(&self, length: Option<usize>) -> Result<Vec<u8>, HashError> {
        let mut hash_point = self.hash_on_group();
        let mut digest_bytes: [u8; 4*MODBYTES] = [0; 4*MODBYTES];
        hash_point.tobytes(&mut digest_bytes);
        return_digest(&digest_bytes, length)
    }
}

impl BLS12_381_SHA256_G2 {
    // Map the digest to group G2
    pub fn hash_on_group(&self) -> ECP2 {
        ECP2::mapit(&self.digest)
    }
}

fn return_digest(digest_bytes: &[u8], length: Option<usize>) -> Result<Vec<u8>, HashError> {
    match length {
        Some(l) => {
            if l > digest_bytes.len() {
                return Err(HashError::InvalidDigestLength(String::from("Length greater than digest")))
            } else {
                Ok(digest_bytes[0..l].to_vec())
            }
        }
        None => Ok(digest_bytes.to_vec())
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

    macro_rules! digest_test {
        ( $HashFunc:ident, $output_byte_size:expr ) => {

            for msg in &gen_test_msgs() {
                let mut hf = $HashFunc::new(None).unwrap();
                hf.update(msg.as_bytes());
                let d1 = hf.digest(None).unwrap();

                let mut hf = $HashFunc::new(None).unwrap();
                hf.update(msg.as_bytes());
                let d2 = hf.digest(None).unwrap();

                assert_eq!(d1, d2);

                let d = hf.digest(Some($output_byte_size+10));
                assert!(d.is_err());

                for n in vec![1, 2, 10, 20, $output_byte_size] {
                    let d = hf.digest(Some($output_byte_size-n)).unwrap();
                    assert_eq!(d2[0..$output_byte_size-n], d[0..$output_byte_size-n]);
                }
            }

            let mut hf1 = $HashFunc::new(None).unwrap();
            for msg in &gen_test_msgs() {
                hf1.update(msg.as_bytes());
            }
            let d1 = hf1.digest(None).unwrap();

            let mut hf2 = $HashFunc::new(None).unwrap();
            for msg in &gen_test_msgs() {
                hf2.update(msg.as_bytes());
            }
            let d2 = hf2.digest(None).unwrap();

            assert_eq!(d1, d2);
        };
    }

    macro_rules! hashing_on_groups_test {
        ( $HashFunc:ident ) => {
            for msg in &gen_test_msgs() {
                let mut hf = $HashFunc::new(None).unwrap();
                hf.update(msg.as_bytes());
                let mut g1n1 = hf.hash_on_group();

                let mut hf = $HashFunc::new(None).unwrap();
                hf.update(msg.as_bytes());
                let mut g1n2 = hf.hash_on_group();

                assert_eq!(g1n1.tostring(), g1n2.tostring());

            }
        }
    }

    #[test]
    fn test_msg_digest() {
        let hm: HashMap<String, &[u8]> = HashMap::new();
        let hf = BLS12_381_SHA256_G1::new(Some(hm));
        assert!(hf.is_err());

        digest_test!(BLS12_381_SHA256_G1, 2*MODBYTES+1);
        digest_test!(BLS12_381_SHA256_G2, 4*MODBYTES);
    }

    #[test]
    fn test_hashing_on_groups() {
        hashing_on_groups_test!(BLS12_381_SHA256_G1);
        hashing_on_groups_test!(BLS12_381_SHA256_G2);
    }
}
