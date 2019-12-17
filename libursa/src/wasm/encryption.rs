use aead::{generic_array::typenum::Unsigned, NewAead};
use encryption::random_vec;
use encryption::symm::prelude::*;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
#[derive(Debug, Serialize, Deserialize)]
pub struct WasmCipherKey {
    cipher: EncryptorType,
    key: String,
}

macro_rules! operation_impl {
    ($name:ident) => {
        fn $name(cipher_key: WasmCipherKey, aad: &[u8], input: &[u8]) -> Result<Vec<u8>, JsValue> {
            let symmkey = maperr!(hex::decode(cipher_key.key));
            if !cipher_key.cipher.is_valid_keysize(symmkey.len()) {
                return Err(JsValue::from_str("Invalid key length"));
            }
            let encryptor = cipher_key.cipher.gen_encryptor(symmkey.as_slice());
            Ok(maperr!(encryptor.$name(aad, input)))
        }
    };
}

#[wasm_bindgen]
pub struct UrsaEncryptor {}

#[wasm_bindgen]
impl UrsaEncryptor {
    pub fn new(cipher: &str) -> Result<WasmCipherKey, JsValue> {
        let cipher = maperr!(EncryptorType::from_str(cipher));
        let key_size = get_keysize(cipher);

        Ok(WasmCipherKey {
            cipher,
            key: hex::encode(&maperr!(random_vec(key_size))),
        })
    }

    pub fn with_key(cipher: &str, key: &str) -> Result<WasmCipherKey, JsValue> {
        let cipher = maperr!(EncryptorType::from_str(cipher));
        let key_size = get_keysize(cipher);
        if key_size == maperr!(hex::decode(key)).len() {
            Ok(WasmCipherKey {
                cipher,
                key: key.to_string(),
            })
        } else {
            Err(JsValue::from_str("Invalid key length for given cipher"))
        }
    }

    pub fn encrypt(
        &self,
        cipher_key: WasmCipherKey,
        aad: &[u8],
        input: &[u8],
    ) -> Result<Vec<u8>, JsValue> {
        encrypt_easy(cipher_key, aad, input)
    }

    pub fn decrypt(
        &self,
        cipher_key: WasmCipherKey,
        aad: &[u8],
        input: &[u8],
    ) -> Result<Vec<u8>, JsValue> {
        decrypt_easy(cipher_key, aad, input)
    }
}

fn get_keysize(cipher: EncryptorType) -> usize {
    match cipher {
        EncryptorType::Aes128CbcHmac256 => {
            <<Aes128CbcHmac256 as NewAead>::KeySize as Unsigned>::to_usize()
        }
        EncryptorType::Aes256CbcHmac512 => {
            <<Aes256CbcHmac512 as NewAead>::KeySize as Unsigned>::to_usize()
        }
        EncryptorType::Aes128Gcm => <<Aes128Gcm as NewAead>::KeySize as Unsigned>::to_usize(),
        EncryptorType::Aes256Gcm => <<Aes256Gcm as NewAead>::KeySize as Unsigned>::to_usize(),
        EncryptorType::XChaCha20Poly1305 => {
            <<XChaCha20Poly1305 as NewAead>::KeySize as Unsigned>::to_usize()
        }
    }
}

operation_impl!(encrypt_easy);
operation_impl!(decrypt_easy);
