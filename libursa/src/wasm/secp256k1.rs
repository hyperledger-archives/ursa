use keys::{KeyGenOption, PrivateKey, PublicKey};
use signatures::secp256k1::EcdsaSecp256k1Sha256 as EcdsaSecp256k1Sha256Impl;
use signatures::EcdsaPublicKeyHandler;
use signatures::SignatureScheme;

use wasm_bindgen::prelude::*;

use super::{KeyPair, WasmPrivateKey, WasmPublicKey};

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

    pub fn normalizeS(&self, signature: &mut [u8]) -> Result<(), JsValue> {
        maperr!(self.0.normalize_s(signature));
        Ok(())
    }

    pub fn publicKeyCompressed(&self, pk: &WasmPublicKey) -> WasmPublicKey {
        let pk = PublicKey::from(pk);
        WasmPublicKey::from(self.0.public_key_compressed(&pk))
    }

    pub fn publicKeyUncompressed(&self, pk: &WasmPublicKey) -> WasmPublicKey {
        let pk = PublicKey::from(pk);
        WasmPublicKey::from(self.0.public_key_uncompressed(&pk))
    }

    pub fn parseToPublicKey(&self, bytes: &[u8]) -> Result<WasmPublicKey, JsValue> {
        let pk = maperr!(self.0.parse(bytes));
        Ok(WasmPublicKey::from(&pk))
    }
}
