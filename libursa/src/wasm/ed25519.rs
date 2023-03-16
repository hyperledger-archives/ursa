use keys::KeyGenOption;
use signatures::{prelude::Ed25519Sha512 as Ed25519Sha512Impl, SignatureScheme};

use wasm_bindgen::prelude::*;

use crate::keys::{PrivateKey, PublicKey};

use super::KeyPair;

#[wasm_bindgen]
pub struct Ed25519Sha512 {
    keypair: KeyPair,
}

#[wasm_bindgen]
impl Ed25519Sha512 {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<Ed25519Sha512, JsValue> {
        let scheme = Ed25519Sha512Impl {};
        let (pk, sk) = maperr!(scheme.keypair(None));
        Ok(Self {
            keypair: KeyPair {
                pk: pk.into(),
                sk: sk.into(),
            },
        })
    }

    #[wasm_bindgen(js_name = fromSeed)]
    pub fn from_seed(seed: &[u8]) -> Result<Ed25519Sha512, JsValue> {
        let scheme = Ed25519Sha512Impl {};
        let (pk, sk) = maperr!(scheme.keypair(Some(KeyGenOption::UseSeed(seed.to_vec()))));
        Ok(Self {
            keypair: KeyPair {
                pk: pk.into(),
                sk: sk.into(),
            },
        })
    }

    #[wasm_bindgen(js_name = fromPrivateKey)]
    pub fn from_private_key(sk: &[u8]) -> Result<Ed25519Sha512, JsValue> {
        let scheme = Ed25519Sha512Impl {};
        let pk = PrivateKey(sk.into());
        let (pk, sk) = maperr!(scheme.keypair(Some(KeyGenOption::FromSecretKey(pk))));
        Ok(Self {
            keypair: KeyPair {
                pk: pk.into(),
                sk: sk.into(),
            },
        })
    }

    #[wasm_bindgen(js_name = getPulicKey)]
    pub fn get_public_key(&self) -> Result<Vec<u8>, JsValue> {
        let sk = &self.keypair.sk;
        let scheme = Ed25519Sha512Impl {};
        let (pk, _) = maperr!(scheme.keypair(Some(KeyGenOption::FromSecretKey(sk.into()))));
        Ok(pk.0.to_vec())
    }

    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, JsValue> {
        let sk = &self.keypair.sk;
        let scheme = Ed25519Sha512Impl {};
        let sig = maperr!(scheme.sign(message, &sk.into()));
        Ok(sig)
    }

    pub fn verify(message: &[u8], signature: &[u8], pk: &[u8]) -> Result<bool, JsValue> {
        let pk = PublicKey(pk.into());
        let scheme = Ed25519Sha512Impl {};
        Ok(maperr!(scheme.verify(message, signature, &pk)))
    }
}
