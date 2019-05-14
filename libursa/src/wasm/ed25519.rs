use keys::{KeyGenOption, PrivateKey, PublicKey};
use signatures::ed25519::Ed25519Sha512 as Ed25519Sha512Impl;
use signatures::SignatureScheme;

use wasm_bindgen::prelude::*;

use super::{KeyPair, WasmPrivateKey, WasmPublicKey};

#[wasm_bindgen]
pub struct Ed25519Sha512(Ed25519Sha512Impl);

#[wasm_bindgen]
#[allow(non_snake_case)]
impl Ed25519Sha512 {
    pub fn new() -> Ed25519Sha512 {
        Ed25519Sha512(Ed25519Sha512Impl::new())
    }

    pub fn keypair(&self) -> Result<KeyPair, JsValue> {
        let (pk, sk) = maperr!(self.0.keypair(None));
        let pk = WasmPublicKey::from(&pk);
        let sk = WasmPrivateKey::from(&sk);
        Ok(KeyPair { pk, sk })
    }

    pub fn keyPairFromSeed(&self, seed: &[u8]) -> Result<KeyPair, JsValue> {
        let (pk, sk) = maperr!(self.0.keypair(Some(KeyGenOption::UseSeed(seed.to_vec()))));
        let pk = WasmPublicKey::from(&pk);
        let sk = WasmPrivateKey::from(&sk);
        Ok(KeyPair { pk, sk })
    }

    pub fn getPublicKey(&self, sk: &WasmPrivateKey) -> Result<WasmPublicKey, JsValue> {
        let sk = PrivateKey::from(sk);
        let (pk, _) = maperr!(self
            .0
            .keypair(Some(KeyGenOption::FromSecretKey(sk.clone()))));
        let pk = WasmPublicKey::from(&pk);
        Ok(pk)
    }

    pub fn sign(&self, message: &[u8], sk: &WasmPrivateKey) -> Result<Vec<u8>, JsValue> {
        let sk = PrivateKey::from(sk);
        let sig = maperr!(self.0.sign(message, &sk));
        Ok(sig)
    }

    pub fn verify(
        &self,
        message: &[u8],
        signature: &[u8],
        pk: &WasmPublicKey,
    ) -> Result<bool, JsValue> {
        let pk = PublicKey::from(pk);
        Ok(maperr!(self.0.verify(message, signature, &pk)))
    }
}
