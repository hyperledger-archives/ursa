use zeroize::Zeroize;
use encoding::hex::{bin2hex, hex2bin};
use std::ops::Drop;

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

// A private key instance.
/// The underlying content is dependent on implementation.
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct PrivateKey(pub Vec<u8>);
impl_bytearray!(PrivateKey);

#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct PublicKey(pub Vec<u8>);
impl_bytearray!(PublicKey);

#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct SessionKey(pub Vec<u8>);
impl_bytearray!(SessionKey);

#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct MacKey(pub Vec<u8>);
impl_bytearray!(MacKey);

//#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum KeyGenOption {
    UseSeed(Vec<u8>),
    FromSecretKey(PrivateKey)
}

impl Drop for KeyGenOption {
    fn drop(&mut self) {
        match self {
            KeyGenOption::UseSeed(ref mut v) => v.zeroize(),
            KeyGenOption::FromSecretKey(ref mut s) => s.zeroize()
        }
    }
}

#[test]
fn serialize_tests() {
    let t = vec![1u8, 1u8, 2u8, 2u8, 3u8, 3u8, 4u8, 4u8];
    let e = KeyGenOption::UseSeed(t[..].to_vec());
    let s = ::serde_json::to_string(&e).unwrap();
    assert_eq!(r#"{"UseSeed":[1,1,2,2,3,3,4,4]}"#, s);
    let f: KeyGenOption = ::serde_json::from_str(&s).unwrap();
    assert_eq!(KeyGenOption::UseSeed(t), f);
    let sk = PrivateKey(vec![1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 2u8]);
    let e = KeyGenOption::FromSecretKey(sk);
    assert_eq!(r#"{"FromSecretKey":"01010101010102"}"#, ::serde_json::to_string(&e).unwrap());
}
