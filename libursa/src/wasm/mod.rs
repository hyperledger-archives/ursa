#[macro_use]
mod macros;
#[cfg(feature = "bls")]
pub mod bls;

pub mod secp256k1;
pub mod ed25519;

#[cfg(feature = "cl")]
pub mod cl;

use keys::{PublicKey, PrivateKey};

use wasm_bindgen::prelude::*;
use errors::{UrsaCryptoError, ToErrorCode};
use serde;

#[wasm_bindgen]
#[derive(Debug, Serialize, Deserialize)]
pub struct KeyPair {
    pk: PublicKey,
    sk: PrivateKey
}

impl From<UrsaCryptoError> for JsValue {
    fn from(err: UrsaCryptoError) -> JsValue {
        let error_code = err.to_error_code();
        JsValue::from_serde(&error_code).unwrap()
    }
}

fn convert_from_js<T>(val: &JsValue) -> Result<T, UrsaCryptoError>
where
    for<'a> T: serde::Deserialize<'a>,
{
    match val.into_serde() {
        Ok(unwrapped) => Ok(unwrapped),
        Err(_) => Err(UrsaCryptoError::InvalidStructure(
            "Invalid argument".to_string(),
        )),
    }
}
