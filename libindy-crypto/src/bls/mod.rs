extern crate serde_json;

use errors::common::CommonError;
use pair::amcl::{GroupOrderElement, PointG2, PointG1, Pair};

extern crate sha1;

pub struct Bls {}

impl Bls {
    pub fn create_generator() -> Result<Vec<u8>, CommonError> {
        PointG2::new()?.to_bytes()
    }

    pub fn generate_keys(g: Vec<u8>, seed: Option<Vec<u8>>) -> Result<(Vec<u8>, Vec<u8>), CommonError> {
        let g = PointG2::from_bytes(&g)?;

        let sign_key = match seed {
            Some(s) => GroupOrderElement::new_from_seed(s)?,
            _ => GroupOrderElement::new()?
        };
        let ver_key = g.mul(&sign_key)?;

        Ok((sign_key.to_bytes()?, ver_key.to_bytes()?))
    }

    pub fn sign(message: &str, sign_key: Vec<u8>, ver_key: Vec<u8>) -> Result<Vec<u8>, CommonError> {
        let ver_key = PointG2::from_bytes(&ver_key)?;
        let sign_key = GroupOrderElement::from_bytes(&sign_key)?;

        let h = Bls::_h(message, &ver_key)?;

        let signature = h.mul(&sign_key)?;
        signature.to_bytes()
    }

    pub fn create_multi_sig(signatures_b: Vec<Vec<u8>>) -> Result<Vec<u8>, CommonError> {
        let mut signatures: Vec<PointG1> = Vec::new();
        for s in signatures_b {
            signatures.push(PointG1::from_bytes(&s)?)
        }

        let mut multi_sig = PointG1::new_inf()?;
        for signature in signatures {
            multi_sig = multi_sig.add(&signature)?;
        }
        Ok(multi_sig.to_bytes()?)
    }

    pub fn verify(signature: Vec<u8>, message: &str, pk: Vec<u8>, g: Vec<u8>) -> Result<bool, CommonError> {
        let signature = PointG1::from_bytes(&signature)?;
        let pk = PointG2::from_bytes(&pk)?;
        let g = PointG2::from_bytes(&g)?;

        let h = Bls::_h(message, &pk)?;

        Ok(Pair::pair(&signature, &g)?.eq(&Pair::pair(&h, &pk)?))
    }

    pub fn verify_multi_sig(signature: Vec<u8>, message: &str, pub_keys: Vec<Vec<u8>>, g: Vec<u8>) -> Result<bool, CommonError> {
        let signature = PointG1::from_bytes(&signature)?;
        let g = PointG2::from_bytes(&g)?;

        let mut pks: Vec<PointG2> = Vec::new();
        for pk in pub_keys {
            pks.push(PointG2::from_bytes(&pk)?)
        }

        let mut multi_sig_e_list: Vec<Pair> = Vec::new();
        for pk in pks {
            let h = Bls::_h(message, &pk)?;
            multi_sig_e_list.push(Pair::pair(&h, &pk)?);
        }

        let mut multi_sig_e = multi_sig_e_list.get(0).ok_or(CommonError::InvalidStructure(format!("Element not found")))?.clone();
        for e in multi_sig_e_list[1..].to_vec() {
            multi_sig_e = multi_sig_e.mul(&e)?;
        }

        Ok(Pair::pair(&signature, &g)?.eq(&multi_sig_e))
    }

    fn _h(message: &str, pk: &PointG2) -> Result<PointG1, CommonError> {
        let m = Bls::_get_msg_for_sign(message, pk)?;

        let mut res = sha1::Sha1::new();
        res.update(&m);

        Ok(PointG1::from_hash(&res.digest().bytes().to_vec())?)
    }

    fn _get_msg_for_sign(message: &str, pk: &PointG2) -> Result<Vec<u8>, CommonError> {
        let mut msg_bytes = message.as_bytes().to_vec();
        let pk_bytes = pk.to_bytes()?;
        msg_bytes.extend(pk_bytes);
        Ok(msg_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_keys_works() {
        let g = PointG2::new().unwrap();
        Bls::generate_keys(g.to_bytes().unwrap(), None).unwrap();
    }

    #[test]
    fn generate_keys_works_for_seed() {
        let g = PointG2::new().unwrap();
        let seed: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8];
        Bls::generate_keys(g.to_bytes().unwrap(), None).unwrap();
    }

    #[test]
    fn sign_works() {
        let g = PointG2::new().unwrap();
        let (sk, pk) = Bls::generate_keys(g.to_bytes().unwrap(), None).unwrap();
        Bls::sign("message", sk, pk).unwrap();
    }

    #[test]
    fn multi_sign_works() {
        let g = PointG2::new().unwrap();
        let (sk, pk) = Bls::generate_keys(g.to_bytes().unwrap(), None).unwrap();
        let signatures: Vec<Vec<u8>> = vec![
            Bls::sign("message1", sk.clone(), pk.clone()).unwrap(),
            Bls::sign("message2", sk, pk).unwrap()
        ];

        Bls::create_multi_sig(signatures).unwrap();
    }

    #[test]
    fn verify_works() {
        let message = "message";
        let g = PointG2::new().unwrap();
        let (sk, pk) = Bls::generate_keys(g.to_bytes().unwrap(), None).unwrap();
        let signature = Bls::sign(message, sk, pk.clone()).unwrap();
        assert!(Bls::verify(signature, message, pk, g.to_bytes().unwrap()).unwrap())
    }

    #[test]
    fn verify_multi_sig_works() {
        let message = "message";
        let g = PointG2::new().unwrap();
        let (sk1, pk1) = Bls::generate_keys(g.to_bytes().unwrap(), None).unwrap();
        let (sk2, pk2) = Bls::generate_keys(g.to_bytes().unwrap(), None).unwrap();
        let pks = vec![pk1.clone(), pk2.clone()];

        let signatures: Vec<Vec<u8>> = vec![
            Bls::sign(message, sk1, pk1).unwrap(),
            Bls::sign(message, sk2, pk2).unwrap()
        ];

        let signature = Bls::create_multi_sig(signatures).unwrap();
        assert!(Bls::verify_multi_sig(signature, message, pks, g.to_bytes().unwrap()).unwrap())
    }
}