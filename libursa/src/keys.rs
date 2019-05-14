use encoding::hex::{bin2hex, hex2bin};
use std::ops::Drop;
use zeroize::Zeroize;

// A private key instance.
/// The underlying content is dependent on implementation.
pub struct PrivateKey(pub Vec<u8>);
impl_bytearray!(PrivateKey);

pub struct PublicKey(pub Vec<u8>);
impl_bytearray!(PublicKey);

pub struct SessionKey(pub Vec<u8>);
impl_bytearray!(SessionKey);

pub struct MacKey(pub Vec<u8>);
impl_bytearray!(MacKey);

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum KeyGenOption {
    UseSeed(Vec<u8>),
    FromSecretKey(PrivateKey),
}

impl Drop for KeyGenOption {
    fn drop(&mut self) {
        match self {
            KeyGenOption::UseSeed(ref mut v) => v.zeroize(),
            KeyGenOption::FromSecretKey(ref mut s) => s.zeroize(),
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
    assert_eq!(
        r#"{"FromSecretKey":"01010101010102"}"#,
        ::serde_json::to_string(&e).unwrap()
    );
}
