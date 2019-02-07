use signatures::SignatureScheme;
use signatures::secp256k1::EcdsaSecp256k1Sha256;
use keys::{KeyGenOption, PublicKey, PrivateKey};

use wasm_bindgen::prelude::*;

use super::KeyPair;

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn secp256k1New() -> EcdsaSecp256k1Sha256 {
    EcdsaSecp256k1Sha256::new()
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn secp256k1KeyPair(secp256k1: &EcdsaSecp256k1Sha256) -> Result<KeyPair, JsValue> {
    let (pk, sk) = secp256k1.keypair(None).map_err(|e| e.to_string())?;
    Ok(KeyPair { pk, sk })
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn secp256k1KeyPairFromSeed(secp256k1: &EcdsaSecp256k1Sha256, seed: &[u8]) -> Result<KeyPair, JsValue> {
    let (pk, sk) = secp256k1.keypair(Some(KeyGenOption::UseSeed(seed.to_vec()))).map_err(|e|e.to_string())?;
    Ok(KeyPair { pk, sk })
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn secp256k1KeyPairFromSecretKey(secp256k1: &EcdsaSecp256k1Sha256, sk: &PrivateKey) -> Result<KeyPair, JsValue> {
    let (pk, sk) = secp256k1.keypair(Some(KeyGenOption::FromSecretKey(sk.clone()))).map_err(|e|e.to_string())?;
    Ok(KeyPair { pk, sk })
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn secp256k1Sign(secp256k1: &EcdsaSecp256k1Sha256, message: &str, sk: &PrivateKey) -> Result<Vec<u8>, JsValue> {
    let sig = secp256k1.sign(message.as_bytes(), &sk).map_err(|e|e.to_string())?;
    Ok(sig)
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn secp256k1Verify(secp256k1: &EcdsaSecp256k1Sha256, message: &str, signature: &[u8], pk: &PublicKey) -> Result<bool, JsValue> {
    Ok(secp256k1.verify(message.as_bytes(),signature, pk).map_err(|e|e.to_string())?)
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn secp256k1NormaliseS(secp256k1: &EcdsaSecp256k1Sha256, signature: &mut [u8]) -> Result<(), JsValue> {
    secp256k1.normalize_s(signature).map_err(|e|e.to_string())?;
    Ok(())
}
