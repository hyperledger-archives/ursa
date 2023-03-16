use kex::{x25519::X25519Sha256 as X25519Sha256Impl, KeyExchangeScheme};
use keys::{KeyGenOption, PrivateKey, PublicKey};

use wasm_bindgen::prelude::*;

use super::{KeyPair, WasmPrivateKey, WasmPublicKey, WasmSessionKey};

#[wasm_bindgen]
pub struct X25519Sha256;

#[wasm_bindgen]
impl X25519Sha256 {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self
    }

    pub fn keypair(&self) -> Result<KeyPair, JsValue> {
        let scheme = X25519Sha256Impl {};
        let (pk, sk) = maperr!(scheme.keypair(None));
        Ok(KeyPair {
            pk: pk.into(),
            sk: sk.into(),
        })
    }

    #[wasm_bindgen(js_name = keypair_from_seed)]
    pub fn key_pair_from_seed(&self, seed: &[u8]) -> Result<KeyPair, JsValue> {
        let scheme = X25519Sha256Impl {};
        let (pk, sk) = maperr!(scheme.keypair(Some(KeyGenOption::UseSeed(seed.to_vec()))));
        Ok(KeyPair {
            pk: pk.into(),
            sk: sk.into(),
        })
    }

    #[wasm_bindgen(js_name = getPublicKey)]
    pub fn get_public_key(&self, sk: &WasmPrivateKey) -> Result<WasmPublicKey, JsValue> {
        let sk = sk.into();
        let scheme = X25519Sha256Impl {};
        let (pk, _) = maperr!(scheme.keypair(Some(KeyGenOption::FromSecretKey(sk))));
        Ok(pk.into())
    }

    #[wasm_bindgen(js_name = computeSharedSecret)]
    pub fn compute_shared_secret(
        &self,
        sk: &WasmPrivateKey,
        pk: &WasmPublicKey,
    ) -> Result<WasmSessionKey, JsValue> {
        let sk = PrivateKey::from(sk);
        let pk = PublicKey::from(pk);
        let scheme = X25519Sha256Impl {};
        let secret = maperr!(scheme.compute_shared_secret(&sk, &pk));
        let secret = WasmSessionKey::from(secret);
        Ok(secret)
    }
}
