use signatures::SignatureScheme;
use signatures::ed25519::Ed25519Sha512 as Ed25519Sha512Impl;
use keys::{KeyGenOption, PublicKey, PrivateKey};

use wasm_bindgen::prelude::*;

use super::KeyPair;

#[wasm_bindgen]
pub struct Ed25519Sha512(Ed25519Sha512Impl);

#[wasm_bindgen]
#[allow(non_snake_case)]
impl Ed25519Sha512 {
    pub fn new() -> Ed25519Sha512 {
        Ed25519Sha512(Ed25519Sha512Impl::new())
    }

    pub fn keypair(&self) -> Result<KeyPair, JsValue> {
        let (pk, sk) = self.0.keypair(None).map_err(|e|e.to_string())?;
        Ok(KeyPair { pk, sk })
    }

    pub fn keyPairFromSeed(&self, seed: &[u8]) -> Result<KeyPair, JsValue> {
        let (pk, sk) = self.0.keypair(Some(KeyGenOption::UseSeed(seed.to_vec()))).map_err(|e|e.to_string())?;
        Ok(KeyPair { pk, sk })
    }

    pub fn keyPairFromPrivateKey(&self, sk: &PrivateKey) -> Result<KeyPair, JsValue> {
        let (pk, sk) = self.0.keypair(Some(KeyGenOption::FromSecretKey(sk.clone()))).map_err(|e|e.to_string())?;
        Ok(KeyPair { pk, sk })
    }

    pub fn sign(&self, message: &[u8], sk: &PrivateKey)-> Result<Vec<u8>, JsValue> {
        let sig = self.0.sign(message, sk).map_err(|e|e.to_string())?;
        Ok(sig)
    }

    pub fn verify(&self, message: &[u8], signature: &[u8], pk: &PublicKey) -> Result<bool, JsValue> {
        Ok(self.0.verify(message, signature, pk).map_err(|e|e.to_string())?)
    }
}
