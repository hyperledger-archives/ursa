use signatures::SignatureScheme;
use signatures::secp256k1::EcdsaSecp256k1Sha256;
use keys::{KeyPairOption, PublicKey, PrivateKey};
use encoding::hex::{bin2hex, hex2bin};

use wasm_bindgen::prelude::*;
use super::convert_from_js;

#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct KeyPair {
    pk: PublicKey,
    sk: PrivateKey
}

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
pub fn secp256k1KeyPairFromSeed(secp256k1: &EcdsaSecp256k1Sha256, seed: &str) -> Result<KeyPair, JsValue> {
    let seed = hex2bin(seed).map_err(|e|e.to_string())?;
    let (pk, sk) = secp256k1.keypair(Some(KeyPairOption::UseSeed(seed))).map_err(|e|e.to_string())?;
    Ok(KeyPair { pk, sk })
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn secp256k1KeyPairFromSecretKey(secp256k1: &EcdsaSecp256k1Sha256, sk: &PrivateKey) -> Result<KeyPair, JsValue> {
    let (pk, sk) = secp256k1.keypair(Some(KeyPairOption::FromSecretKey(sk.clone()))).map_err(|e|e.to_string())?;
    Ok(KeyPair { pk, sk })
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn secp256k1Sign(secp256k1: &JsValue, message: &str, sk: &PrivateKey) -> Result<JsValue, JsValue> {
    let secp256k1: EcdsaSecp256k1Sha256 = convert_from_js(secp256k1)?;

    let sig = secp256k1.sign(message.as_bytes(), &sk).map_err(|e|e.to_string())?;
    Ok(JsValue::from_serde(&bin2hex(sig.as_slice())).unwrap())
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn secp256k1Verify(secp256k1: &JsValue, message: &str, signature: &str, pk: &PublicKey) -> Result<bool, JsValue> {
    let secp256k1: EcdsaSecp256k1Sha256 = convert_from_js(secp256k1)?;
    let signature = hex2bin(signature).map_err(|e|e.to_string())?;
    Ok(secp256k1.verify(message.as_bytes(),signature.as_slice(), pk).map_err(|e|e.to_string())?)
}

//pub fn secp256k1NormalizeS(secp256k1: &JsValue, ) -> Result<JsValue, JsValue> {
//    let secp256k1: EcdsaSecp256k1Sha256 = convert_from_js(secp256k1)?;
//}
