use signatures::SignatureScheme;
use signatures::secp256k1::EcdsaSecp256k1Sha256 as EcdsaSecp256k1Sha256Impl;
use signatures::EcdsaPublicKeyHandler;
use keys::{KeyGenOption, PublicKey, PrivateKey};

use wasm_bindgen::prelude::*;

use super::KeyPair;

#[wasm_bindgen]
pub struct EcdsaSecp256k1Sha256(EcdsaSecp256k1Sha256Impl);

#[wasm_bindgen]
#[allow(non_snake_case)]
impl EcdsaSecp256k1Sha256 {
    pub fn new() -> EcdsaSecp256k1Sha256 {
        EcdsaSecp256k1Sha256(EcdsaSecp256k1Sha256Impl::new())
    }

     pub fn keypair(&self) -> Result<KeyPair, JsValue> {
        let (pk, sk) = maperr!(self.0.keypair(None));
        Ok(KeyPair { pk, sk })
    }

    pub fn keyPairFromSeed(&self, seed: &[u8]) -> Result<KeyPair, JsValue> {
        let (pk, sk) = maperr!(self.0.keypair(Some(KeyGenOption::UseSeed(seed.to_vec()))));
        Ok(KeyPair { pk, sk })
    }

    pub fn getPublicKey(&self, sk: &PrivateKey) -> Result<PublicKey, JsValue> {
        let (pk, _) = maperr!(self.0.keypair(Some(KeyGenOption::FromSecretKey(sk.clone()))));
        Ok(pk)
    }

    pub fn sign(&self, message: &[u8], sk: &PrivateKey)-> Result<Vec<u8>, JsValue> {
        let sig = maperr!(self.0.sign(message, sk));
        Ok(sig)
    }

    pub fn verify(&self, message: &[u8], signature: &[u8], pk: &PublicKey) -> Result<bool, JsValue> {
        Ok(maperr!(self.0.verify(message, signature, pk)))
    }

    pub fn normalizeS(&self, signature: &mut [u8]) -> Result<(), JsValue>  {
        maperr!(self.0.normalize_s(signature));
        Ok(())
    }

    pub fn publicKeyCompressed(&self, pk: &PublicKey) -> PublicKey {
        PublicKey(self.0.public_key_compressed(pk))
    }

    pub fn publicKeyUncompressed(&self, pk: &PublicKey) -> PublicKey {
        PublicKey(self.0.public_key_uncompressed(pk))
    }

    pub fn parseToPublicKey(&self, bytes: &[u8]) -> Result<PublicKey, JsValue> {
        Ok(maperr!(self.0.parse(bytes)))
    }
}
