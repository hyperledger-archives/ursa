#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::ops::Drop;
use zeroize::Zeroize;

// A private key instance.
pub trait PrivateKey: Zeroize {
    fn to_bytes(&self, compressed: bool) -> Vec<u8>;
    fn from_bytes(data: &[u8], compressed: bool) -> UrsaResult<Self>;
}

pub trait PublicKey: Zeroize {
    fn to_bytes(&self, compressed: bool) -> Vec<u8>;
    fn from_bytes(data: &[u8], compressed: bool) -> UrsaResult<Self>
}

pub trait SessionKey: Zeroize {
    fn to_bytes(&self, compressed: bool) -> Vec<u8>;
    fn from_bytes(data: &[u8], compressed: bool) -> UrsaResult<Self>
}

pub trait MacKey: Zeroize {
    fn to_bytes(&self, compressed: bool) -> Vec<u8>;
    fn from_bytes(data: &[u8], compressed: bool) -> UrsaResult<Self>
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, PartialEq, Eq)]
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

#[cfg(feature = "serde")]
#[test]
fn serialize_tests() {
    let t = vec![1u8, 1u8, 2u8, 2u8, 3u8, 3u8, 4u8, 4u8];
    let e = KeyGenOption::UseSeed(t[..].to_vec());
    let s = serde_json::to_string(&e).unwrap();
    assert_eq!(r#"{"UseSeed":[1,1,2,2,3,3,4,4]}"#, s);
    let f: KeyGenOption = serde_json::from_str(&s).unwrap();
    assert_eq!(KeyGenOption::UseSeed(t), f);
    let sk = PrivateKey(vec![1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 2u8]);
    let e = KeyGenOption::FromSecretKey(sk);
    assert_eq!(
        r#"{"FromSecretKey":"01010101010102"}"#,
        serde_json::to_string(&e).unwrap()
    );


}

//#[test]
//fn new_serialize_test() {
//
//
//    struct RandomKeyAlgorithm;
//    impl PrivateKey for RandomKeyAlgorithm {
//
//        fn to_bytes(&self, compressed: bool) -> Vec<u8> {
//
//
//        }
//
//    }
//
//
//
//}
