use wasm_bindgen::prelude::*;

use bls;
use super::convert_from_js;

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn blsGenerator() -> Result<bls::Generator, JsValue> {
    Ok(bls::Generator::new().map_err(|e|e.to_string())?)
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn blsGeneratorAsBytes(generator: &bls::Generator) -> Result<Vec<u8>, JsValue> {
    Ok(generator.as_bytes().to_vec())
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn blsGeneratorFromBytes(bytes: &[u8]) -> Result<bls::Generator, JsValue> {
    let gen = bls::Generator::from_bytes(bytes).map_err(|e|e.to_string())?;
    Ok(gen)
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn blsSignKey(seed: Option<Vec<u8>>) -> Result<bls::SignKey, JsValue> {
    let seedOption = seed.as_ref().map(|v| v.as_slice());
    Ok(bls::SignKey::new(seedOption)?)
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn blsSignKeyAsBytes(signKey: &bls::SignKey) -> Result<Vec<u8>, JsValue> {
    Ok(signKey.as_bytes().to_vec())
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn blsSignKeyFromBytes(bytes: &[u8]) -> Result<bls::SignKey, JsValue> {
    Ok(bls::SignKey::from_bytes(bytes)?)
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn blsSign(message: &[u8], signKey: &bls::SignKey) -> Result<bls::Signature, JsValue> {
    Ok(bls::Bls::sign(message, &signKey)?)
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn blsVerKey(generator: &bls::Generator, signKey: &bls::SignKey) -> Result<bls::VerKey, JsValue> {
    Ok(bls::VerKey::new(&generator, &signKey)?)
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn blsVerKeyAsBytes(verKey: &bls::VerKey) -> Result<Vec<u8>, JsValue> {
    Ok(verKey.as_bytes().to_vec())
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn blsVerKeyFromBytes(bytes: &[u8]) -> Result<bls::VerKey, JsValue> {
    Ok(bls::VerKey::from_bytes(bytes)?)
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn blsProofOfPossession(vk: &bls::VerKey, sk: &bls::SignKey) -> Result<bls::ProofOfPossession, JsValue> {
    Ok(bls::ProofOfPossession::new(&vk, &sk)?)
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn blsProofOfPossessionAsBytes(proofOfPossession: &bls::ProofOfPossession) -> Result<Vec<u8>, JsValue> {
    Ok(proofOfPossession.as_bytes().to_vec())
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn blsProofOfPossessionFromBytes(bytes: &[u8]) -> Result<bls::ProofOfPossession, JsValue> {
    Ok(bls::ProofOfPossession::from_bytes(bytes)?)
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn blsMultiSignature(signatures: Vec<JsValue>) -> Result<bls::MultiSignature, JsValue> {
    let sigs: Vec<bls::Signature> = signatures.iter().map(|x| x.into_serde().unwrap()).collect();
    Ok(bls::MultiSignature::new(sigs.iter().collect::<Vec<_>>().as_slice())?)
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn blsMultiSignatureAsBytes(multiSignature: &bls::MultiSignature) -> Result<Vec<u8>, JsValue> {
    Ok(multiSignature.as_bytes().to_vec())
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn blsMultiSignatureFromBytes(bytes: &[u8]) -> Result<bls::MultiSignature, JsValue> {
    Ok(bls::MultiSignature::from_bytes(bytes)?)
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn blsVerify(
    sig: &bls::Signature,
    message: &[u8],
    vk: &bls::VerKey,
    gen: &bls::Generator,
) -> Result<bool, JsValue> {
    Ok(bls::Bls::verify(&sig, message, &vk, &gen)?)
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn blsVerifyProofOfPossession(
    pop: &bls::ProofOfPossession,
    vk: &bls::VerKey,
    gen: &bls::Generator,
) -> Result<bool, JsValue> {
    Ok(bls::Bls::verify_proof_of_posession(&pop, &vk, &gen)?)
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn blsVerifyMultiSig(
    ms: &bls::MultiSignature,
    message: &[u8],
    verKeys: Vec<JsValue>,
    gen: &bls::Generator,
) -> Result<bool, JsValue> {
    let vks: Vec<bls::VerKey> = verKeys
        .iter()
        .map(|x| {
            // TODO: Handle error case
            convert_from_js(x).unwrap()
        }).collect();
    Ok(bls::Bls::verify_multi_sig(
        &ms,
        message,
        vks.iter().collect::<Vec<_>>().as_slice(),
        &gen,
    )?)
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn blsSignatureAsBytes(sig: &bls::Signature) -> Result<Vec<u8>, JsValue> {
    Ok(sig.as_bytes().to_vec())
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn blsSignatureFromBytes(bytes: &[u8]) -> Result<bls::Signature, JsValue> {
    Ok(bls::Signature::from_bytes(bytes)?)
}
