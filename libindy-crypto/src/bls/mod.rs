extern crate serde_json;

use errors::common::CommonError;
use utils::crypto::pair::{GroupOrderElement, PointG2, PointG1, Pair};

extern crate sha1;

pub struct BlsService {}

impl BlsService {
    pub fn generate_keys(g: &str, seed: Option<Vec<u8>>) -> Result<(String, String), CommonError> {
        let g = PointG2::from_string(g)?;

        let sign_key = match seed {
            Some(s) => GroupOrderElement::new_from_seed(s)?,
            _ => GroupOrderElement::new()?
        };
        let ver_key = g.mul(&sign_key)?;

        Ok((sign_key.to_string()?, ver_key.to_string()?))
    }

    pub fn sign(message: &str, sign_key: &str, ver_key: &str) -> Result<String, CommonError> {
        let ver_key = PointG2::from_string(ver_key)?;
        let sign_key = GroupOrderElement::from_string(sign_key)?;

        let h = BlsService::_h(message, &ver_key)?;
        let signature = h.mul(&sign_key)?;
        Ok(signature.to_string()?)
    }

    pub fn create_multi_sig(signatures: &str) -> Result<String, CommonError> {
        let signatures: Vec<PointG1> = serde_json::from_str(signatures)
            .map_err(map_err_trace!())
            .map_err(|err| CommonError::InvalidStructure(format!("Invalid signatures: {}", err.to_string())))?;

        let multi_sig = signatures.get(0).ok_or(CommonError::InvalidStructure(format!("Element not found")))?;

        for signature in signatures[1..].to_vec() {
            multi_sig.add(&signature)?;
        }
        Ok(multi_sig.to_string()?)
    }

    pub fn verify(signature: &str, message: &str, pk: &str, g: &str) -> Result<bool, CommonError> {
        let signature = PointG1::from_string(signature)?;
        let pk = PointG2::from_string(pk)?;
        let g = PointG2::from_string(g)?;

        let h = BlsService::_h(message, &pk)?;

        println!("{:?}", pk);
        println!("{:?}", h);

        Ok(Pair::pair(&signature, &g)?.eq(&Pair::pair(&h, &pk)?))
    }

    pub fn verify_multi_sig(signature: &str, message: &str, pks: &str, g: &str) -> Result<bool, CommonError> {
        let signature = PointG1::from_string(signature)?;
        let g = PointG2::from_string(g)?;
        let pks: Vec<PointG2> = serde_json::from_str(pks)
            .map_err(map_err_trace!())
            .map_err(|err| CommonError::InvalidStructure(format!("Invalid public keys: {}", err.to_string())))?;

        let mut multi_sig_e_list: Vec<Pair> = Vec::new();
        for pk in pks {
            let h = BlsService::_h(message, &pk)?;
            multi_sig_e_list.push(Pair::pair(&h, &pk)?);
        }

        let multi_sig_e = multi_sig_e_list.get(0).ok_or(CommonError::InvalidStructure(format!("Element not found")))?;

        for e in multi_sig_e_list[1..].to_vec() {
            multi_sig_e.mul(&e)?;
        }

        Ok(Pair::pair(&signature, &g)?.eq(&multi_sig_e))
    }

    fn _h(message: &str, pk: &PointG2) -> Result<PointG1, CommonError> {
        let m = BlsService::_get_msg_for_sign(message, pk)?;

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
        BlsService::generate_keys(&g.to_string().unwrap(), None).unwrap();
    }

    #[test]
    fn sign_works() {
        let g = PointG2::new().unwrap();
        let (sk, pk) = BlsService::generate_keys(&g.to_string().unwrap(), None).unwrap();
        BlsService::sign("message", &sk.to_string(), &pk.to_string()).unwrap();
    }

    #[test]
    fn multi_sign_works() {
        let g = PointG2::new().unwrap();
        let (sk, pk) = BlsService::generate_keys(&g.to_string().unwrap(), None).unwrap();
        let signatures: Vec<String> = vec![
            BlsService::sign("message1", &sk, &pk).unwrap(),
            BlsService::sign("message2", &sk, &pk).unwrap()
        ];
        let signatures_str = serde_json::to_string(&signatures).unwrap();

        BlsService::create_multi_sig(&signatures_str).unwrap();
    }

    #[test]
    fn verify_works() {
        let message = "message";
        let g = PointG2::new().unwrap();
        let (sk, pk) = BlsService::generate_keys(&g.to_string().unwrap(), None).unwrap();
        let signature = BlsService::sign(message, &sk, &pk).unwrap();
        assert!(BlsService::verify(&signature, message, &pk, &g.to_string().unwrap()).unwrap())
    }

    #[test]
    fn verify_multi_sig_works() {
        let message = "message";
        let g = PointG2::new().unwrap();
        let (sk1, pk1) = BlsService::generate_keys(&g.to_string().unwrap(), None).unwrap();
        let (sk2, pk2) = BlsService::generate_keys(&g.to_string().unwrap(), None).unwrap();
        let pks = vec![pk1.clone(), pk2.clone()];

        let signatures: Vec<String> = vec![
            BlsService::sign(message, &sk1, &pk1).unwrap(),
            BlsService::sign(message, &sk2, &pk2).unwrap()
        ];
        let signatures_str = serde_json::to_string(&signatures).unwrap();
        let pks_str = serde_json::to_string(&pks).unwrap();

        let signature = BlsService::create_multi_sig(&signatures_str).unwrap();
        assert!(BlsService::verify_multi_sig(&signature, message, &pks_str, &g.to_string().unwrap()).unwrap())
    }
}