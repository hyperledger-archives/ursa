use keys::KeyGenOption;
use signatures::{prelude::Ed25519Sha512 as Ed25519Sha512Impl, SignatureScheme};

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
        let scheme = Ed25519Sha512Impl {};
        let (pk, sk) = maperr!(scheme.keypair(None));
        Ok(KeyPair {
            pk: pk.into(),
            sk: sk.into(),
        })
    }

    pub fn keyPairFromSeed(&self, seed: &[u8]) -> Result<KeyPair, JsValue> {
        let scheme = Ed25519Sha512Impl {};
        let (pk, sk) = maperr!(scheme.keypair(Some(KeyGenOption::UseSeed(seed.to_vec()))));
        Ok(KeyPair {
            pk: pk.into(),
            sk: sk.into(),
        })
    }

    pub fn getPublicKey(&self, sk: &WasmPrivateKey) -> Result<WasmPublicKey, JsValue> {
        let sk = sk.into();
        let scheme = Ed25519Sha512Impl {};
        let (pk, _) = maperr!(scheme.keypair(Some(KeyGenOption::FromSecretKey(sk))));
        Ok(pk.into())
    }

    pub fn sign(&self, message: &[u8], sk: &WasmPrivateKey) -> Result<Vec<u8>, JsValue> {
        let sk = sk.into();
        let scheme = Ed25519Sha512Impl {};
        let sig = maperr!(scheme.sign(message, &sk));
        Ok(sig)
    }

    pub fn verify(
        &self,
        message: &[u8],
        signature: &[u8],
        pk: &WasmPublicKey,
    ) -> Result<bool, JsValue> {
        let pk = pk.into();
        let scheme = Ed25519Sha512Impl {};
        Ok(maperr!(scheme.verify(message, signature, &pk)))
    }
}
