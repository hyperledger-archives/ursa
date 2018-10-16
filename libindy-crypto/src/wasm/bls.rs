use wasm_bindgen::prelude::*;
use wasm::web_sys::console;

use console_error_panic_hook;
use bls::*;
use errors::IndyCryptoError;
use errors::ToErrorCode;

impl From<IndyCryptoError> for JsValue {
    fn from(err: IndyCryptoError) -> JsValue {
        let error_code = err.to_error_code();
        JsValue::from_serde(&error_code).unwrap()
    }
}

#[wasm_bindgen]
pub fn create_sign_key() -> Result<Vec<u8>, JsValue> {
    console_error_panic_hook::set_once();
    console::log_1(&"Creating SignKey".into());
    let sk = SignKey::new(None)?;
    console::log_1(&"Created SignKey".into());
    Ok(sk.as_bytes().to_vec())
}

#[wasm_bindgen]
pub fn bls_sign(message: &[u8], sign_key: &[u8]) -> Result<Vec<u8>, JsValue> {
    console::log_2(&"Signing message".into(), &format!("{:?}", message).into());
    let sk = SignKey::from_bytes(sign_key)?;
    console::log_1(&"Got SignKey".into());
    let signature = Bls::sign(message, &sk)?;
    console::log_1(&"Signed message".into());
    let signature_bytes = signature.as_bytes().to_vec();
    Ok(signature_bytes)
}
