use kex::{secp256k1::EcdhSecp256k1Sha256 as EcdhSecp256k1Sha256Impl, KeyExchangeScheme};
use keys::{KeyGenOption, PrivateKey, PublicKey};
use signatures::{
    secp256k1::EcdsaSecp256k1Sha256 as EcdsaSecp256k1Sha256Impl, EcdsaPublicKeyHandler,
    SignatureScheme,
};

use wasm_bindgen::prelude::*;

use super::{KeyPair, WasmPrivateKey, WasmPublicKey, WasmSessionKey};

#[wasm_bindgen]
pub struct EcdsaSecp256k1Sha256(EcdsaSecp256k1Sha256Impl);

#[wasm_bindgen]
impl EcdsaSecp256k1Sha256 {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        EcdsaSecp256k1Sha256(EcdsaSecp256k1Sha256Impl::new())
    }

    pub fn keypair(&self) -> Result<KeyPair, JsValue> {
        let (pk, sk) = maperr!(self.0.keypair(None));
        let pk = WasmPublicKey::from(&pk);
        let sk = WasmPrivateKey::from(&sk);
        Ok(KeyPair { pk, sk })
    }

    #[wasm_bindgen(js_name = keypairFromSeed)]
    pub fn keypair_from_seed(&self, seed: &[u8]) -> Result<KeyPair, JsValue> {
        let (pk, sk) = maperr!(self.0.keypair(Some(KeyGenOption::UseSeed(seed.to_vec()))));
        let pk = WasmPublicKey::from(&pk);
        let sk = WasmPrivateKey::from(&sk);
        Ok(KeyPair { pk, sk })
    }

    #[wasm_bindgen(js_name = getPublicKey)]
    pub fn get_public_key(&self, sk: &WasmPrivateKey) -> Result<WasmPublicKey, JsValue> {
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

    #[wasm_bindgen(js_name = normalizeS)]
    pub fn normalize_s(&self, signature: &mut [u8]) -> Result<(), JsValue> {
        maperr!(self.0.normalize_s(signature));
        Ok(())
    }

    #[wasm_bindgen(js_name = publicKeyCompressed)]
    pub fn public_key_compressed(&self, pk: &WasmPublicKey) -> WasmPublicKey {
        let pk = PublicKey::from(pk);
        WasmPublicKey::from(self.0.public_key_compressed(&pk))
    }

    #[wasm_bindgen(js_name = publicKeyUnCompressed)]
    pub fn public_key_uncompressed(&self, pk: &WasmPublicKey) -> WasmPublicKey {
        let pk = PublicKey::from(pk);
        WasmPublicKey::from(self.0.public_key_uncompressed(&pk))
    }

    #[wasm_bindgen(js_name = parseToPublicKey)]
    pub fn parse_to_public_key(&self, bytes: &[u8]) -> Result<WasmPublicKey, JsValue> {
        let pk = maperr!(self.0.parse(bytes));
        Ok(WasmPublicKey::from(&pk))
    }
}

#[wasm_bindgen]
pub struct EcdhSecp256k1Sha256(EcdhSecp256k1Sha256Impl);

#[wasm_bindgen]
impl EcdhSecp256k1Sha256 {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        EcdhSecp256k1Sha256(EcdhSecp256k1Sha256Impl::new())
    }

    pub fn keypair(&self) -> Result<KeyPair, JsValue> {
        let (pk, sk) = maperr!(self.0.keypair(None));
        let pk = WasmPublicKey::from(&pk);
        let sk = WasmPrivateKey::from(&sk);
        Ok(KeyPair { pk, sk })
    }

    #[wasm_bindgen(js_name = keypair_from_seed)]
    pub fn keypair_from_seed(&self, seed: &[u8]) -> Result<KeyPair, JsValue> {
        let (pk, sk) = maperr!(self.0.keypair(Some(KeyGenOption::UseSeed(seed.to_vec()))));
        let pk = WasmPublicKey::from(&pk);
        let sk = WasmPrivateKey::from(&sk);
        Ok(KeyPair { pk, sk })
    }

    #[wasm_bindgen(js_name = getPublicKey)]
    pub fn get_public_key(&self, sk: &WasmPrivateKey) -> Result<WasmPublicKey, JsValue> {
        let sk = PrivateKey::from(sk);
        let (pk, _) = maperr!(self
            .0
            .keypair(Some(KeyGenOption::FromSecretKey(sk.clone()))));
        let pk = WasmPublicKey::from(&pk);
        Ok(pk)
    }

    #[wasm_bindgen(js_name = computeSharedSecret)]
    pub fn compute_shared_secret(
        &self,
        sk: &WasmPrivateKey,
        pk: &WasmPublicKey,
    ) -> Result<WasmSessionKey, JsValue> {
        let sk = PrivateKey::from(sk);
        let pk = PublicKey::from(pk);
        let secret = maperr!(self.0.compute_shared_secret(&sk, &pk));
        let secret = WasmSessionKey::from(secret);
        Ok(secret)
    }
}
