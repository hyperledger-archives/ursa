use keys::KeyGenOption;
use signatures::prelude::Ed25519Sha512 as Ed25519Sha512Impl;

use wasm_bindgen::prelude::*;

use super::{KeyPair, WasmPrivateKey, WasmPublicKey};

#[wasm_bindgen]
pub struct Ed25519Sha512;

#[wasm_bindgen]
#[allow(non_snake_case)]
impl Ed25519Sha512 {
    pub fn new() -> Self {
        Self
    }

    pub fn keypair(&self) -> Result<KeyPair, JsValue> {
        let (pk, sk) = maperr!(Ed25519Sha512Impl::keypair(None));
        Ok(KeyPair {
            pk: pk.into(),
            sk: sk.into(),
        })
    }

    pub fn keyPairFromSeed(&self, seed: &[u8]) -> Result<KeyPair, JsValue> {
        let (pk, sk) = maperr!(Ed25519Sha512Impl::keypair(Some(KeyGenOption::UseSeed(
            seed.to_vec()
        ))));
        Ok(KeyPair {
            pk: pk.into(),
            sk: sk.into(),
        })
    }

    pub fn getPublicKey(&self, sk: &WasmPrivateKey) -> Result<WasmPublicKey, JsValue> {
        let sk = sk.into();
        let (pk, _) = maperr!(Ed25519Sha512Impl::keypair(Some(
            KeyGenOption::FromSecretKey(sk)
        )));
        Ok(pk.into())
    }

    pub fn sign(&self, message: &[u8], sk: &WasmPrivateKey) -> Result<Vec<u8>, JsValue> {
        let sk = sk.into();
        let sig = maperr!(Ed25519Sha512Impl::sign(message, &sk));
        Ok(sig)
    }

    pub fn verify(
        &self,
        message: &[u8],
        signature: &[u8],
        pk: &WasmPublicKey,
    ) -> Result<bool, JsValue> {
        let pk = pk.into();
        Ok(maperr!(Ed25519Sha512Impl::verify(message, signature, &pk)))
    }
}
