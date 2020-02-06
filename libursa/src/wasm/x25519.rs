use kex::{x25519::X25519Sha256 as X25519Sha256Impl, KeyExchangeScheme};
use keys::{KeyGenOption, PrivateKey, PublicKey};

use wasm_bindgen::prelude::*;

use super::{KeyPair, WasmPrivateKey, WasmPublicKey, WasmSessionKey};

#[wasm_bindgen]
pub struct X25519Sha256;

#[wasm_bindgen]
#[allow(non_snake_case)]
impl X25519Sha256 {
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

    pub fn keyPairFromSeed(&self, seed: &[u8]) -> Result<KeyPair, JsValue> {
        let scheme = X25519Sha256Impl {};
        let (pk, sk) = maperr!(scheme.keypair(Some(KeyGenOption::UseSeed(seed.to_vec()))));
        Ok(KeyPair {
            pk: pk.into(),
            sk: sk.into(),
        })
    }

    pub fn getPublicKey(&self, sk: &WasmPrivateKey) -> Result<WasmPublicKey, JsValue> {
        let sk = sk.into();
        let scheme = X25519Sha256Impl {};
        let (pk, _) = maperr!(scheme.keypair(Some(KeyGenOption::FromSecretKey(sk))));
        Ok(pk.into())
    }

    pub fn computeSharedSecret(
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
