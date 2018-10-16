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
pub fn create_generator() -> Result<JsValue, JsValue> {
    console::log_1(&"Creating Generator".into());
    let gen = Generator::new()?;
    console::log_1(&"Created Generator".into());
    Ok(JsValue::from_serde(&gen).unwrap())
}

#[wasm_bindgen]
pub fn create_sign_key() -> Result<JsValue, JsValue> {
    console_error_panic_hook::set_once();
    console::log_1(&"Creating SignKey".into());
    let sk = SignKey::new(None)?;
    console::log_1(&"Created SignKey".into());
    Ok(JsValue::from_serde(&sk).unwrap())
}

#[wasm_bindgen]
pub fn bls_sign(message: &[u8], sign_key: &JsValue) -> Result<JsValue, JsValue> {
    console::log_2(&"Signing message".into(), &format!("{:?}", message).into());
    let sk: SignKey = sign_key.into_serde().unwrap();
    console::log_1(&"Got SignKey".into());
    let signature = Bls::sign(message, &sk)?;
    console::log_1(&"Signed message".into());
    Ok(JsValue::from_serde(&signature).unwrap())
}

#[wasm_bindgen]
pub fn create_ver_key(generator: &JsValue, sign_key: &JsValue) -> Result<JsValue, JsValue> {
    console::log_1(&"Creating VerKey".into());
    let gen: Generator = generator.into_serde().unwrap();
    let sk: SignKey = sign_key.into_serde().unwrap();
    let vk = VerKey::new(&gen, &sk)?;
    console::log_1(&"Created VerKey".into());
    Ok(JsValue::from_serde(&vk).unwrap())
}

#[wasm_bindgen]
pub fn create_proof_of_possession(ver_key: &JsValue, sign_key: &JsValue) -> Result<JsValue, JsValue> {
    console::log_1(&"Creating ProofOfPossession".into());
    let vk: VerKey = ver_key.into_serde().unwrap();
    let sk: SignKey = sign_key.into_serde().unwrap();
    let pop = ProofOfPossession::new(&vk, &sk)?;
    console::log_1(&"Created ProofOfPossession".into());
    Ok(JsValue::from_serde(&pop).unwrap())
}

#[wasm_bindgen]
pub fn create_multi_signature(signatures: Vec<JsValue>) -> Result<JsValue, JsValue> {
    console::log_1(&"Creating MultiSignature".into());
    let sigs: Vec<Signature> = signatures.iter().map(|x| {
        x.into_serde().unwrap()
    }).collect();
    let ms = MultiSignature::new(sigs.iter().collect::<Vec<_>>().as_slice())?;
    console::log_1(&"Created MultiSignature".into());
    Ok(JsValue::from_serde(&ms).unwrap())
}

#[wasm_bindgen]
pub fn bls_verify(signature: &JsValue, message: &[u8], ver_key: &JsValue, generator: &JsValue) -> Result<bool, JsValue> {
    let sig = signature.into_serde().unwrap();
    let vk = ver_key.into_serde().unwrap();
    let gen = generator.into_serde().unwrap();
    Ok(Bls::verify(&sig, message, &vk, &gen)?)
}

#[wasm_bindgen]
pub fn bls_verify_proof_of_possession(proof_of_possession: &JsValue, ver_key: &JsValue, generator: &JsValue) -> Result<bool, JsValue> {
    let pop: ProofOfPossession = proof_of_possession.into_serde().unwrap();
    let vk = ver_key.into_serde().unwrap();
    let gen = generator.into_serde().unwrap();
    Ok(Bls::verify_proof_of_posession(&pop, &vk, &gen)?)
}

#[wasm_bindgen]
pub fn bls_verify_multi_sig(multi_sig: &JsValue, message: &[u8], ver_keys: Vec<JsValue>, generator: &JsValue) -> Result<bool, JsValue> {
    let ms: MultiSignature = multi_sig.into_serde().unwrap();
    let vks: Vec<VerKey> = ver_keys.iter().map(|x| {
        x.into_serde().unwrap()
    }).collect();
    let gen: Generator = generator.into_serde().unwrap();
    Ok(Bls::verify_multi_sig(&ms, message, vks.iter().collect::<Vec<_>>().as_slice(), &gen)?)
}
