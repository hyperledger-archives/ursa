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
pub fn create_sign_key() -> Result<JsValue, JsValue> {
    console_error_panic_hook::set_once();
    console::log_1(&"Creating SignKey".into());
    let sk = SignKey::new(None)?;
    console::log_1(&"Created SignKey".into());
    Ok(JsValue::from_serde(sk.as_bytes()).unwrap())
}


#[wasm_bindgen]
pub fn bls_sign(message: &[u8], sign_key: &[u8]) -> Result<JsValue, JsValue> {
    console::log_2(&"Signing message".into(), &format!("{:?}", message).into());
    let sk = SignKey::from_bytes(sign_key)?;
    console::log_1(&"Got SignKey".into());
    let signature = Bls::sign(message, &sk)?;
    console::log_1(&"Signed message".into());
    Ok(JsValue::from_serde(signature.as_bytes()).unwrap())
}
