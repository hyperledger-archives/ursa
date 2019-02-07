use signatures::SignatureScheme;
use signatures::ed25519::Ed25519Sha512;
use keys::{KeyGenOption, PublicKey, PrivateKey};

use wasm_bindgen::prelude::*;

use super::KeyPair;

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn ed25519New() -> Ed25519Sha512 {
    Ed25519Sha512::new()
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn ed25519KeyPair(ed25519: &Ed25519Sha512) -> Result<KeyPair, JsValue> {
    let (pk, sk) = ed25519.keypair(None).map_err(|e| e.to_string())?;
    Ok(KeyPair { pk, sk })
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn ed25519KeyPairFromSeed(ed25519: &Ed25519Sha512, seed: &[u8]) -> Result<KeyPair, JsValue> {
    let (pk, sk) = ed25519.keypair(Some(KeyGenOption::UseSeed(seed.to_vec()))).map_err(|e|e.to_string())?;
    Ok(KeyPair { pk, sk })
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn ed25519KeyPairFromSecretKey(ed25519: &Ed25519Sha512, sk: &PrivateKey) -> Result<KeyPair, JsValue> {
    let (pk, sk) = ed25519.keypair(Some(KeyGenOption::FromSecretKey(sk.clone()))).map_err(|e|e.to_string())?;
    Ok(KeyPair { pk, sk })
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn ed25519Sign(ed25519: &Ed25519Sha512, message: &str, sk: &PrivateKey) -> Result<Vec<u8>, JsValue> {
    let sig = ed25519.sign(message.as_bytes(), &sk).map_err(|e|e.to_string())?;
    Ok(sig)
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn ed25519Verify(ed25519: &Ed25519Sha512, message: &str, signature: &[u8], pk: &PublicKey) -> Result<bool, JsValue> {
    Ok(ed25519.verify(message.as_bytes(),signature, pk).map_err(|e|e.to_string())?)
}
