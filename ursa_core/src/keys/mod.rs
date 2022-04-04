use super::errors::UrsaCryptoResult;
use zeroize::Zeroize;

// A private key instance.
pub trait PrivateKey: Zeroize {
    fn to_bytes(&self, compressed: bool) -> Vec<u8>;
    fn from_bytes(data: &[u8], compressed: bool) -> UrsaCryptoResult<&Self>;
}

pub trait PublicKey: Zeroize {
    fn to_bytes(&self, compressed: bool) -> Vec<u8>;
    fn from_bytes(data: &[u8], compressed: bool) -> UrsaCryptoResult<&Self>;
}

pub trait SessionKey: Zeroize {
    fn to_bytes(&self, compressed: bool) -> Vec<u8>;
    fn from_bytes(data: &[u8], compressed: bool) -> UrsaCryptoResult<&Self>;
}

pub trait MacKey: Zeroize {
    fn to_bytes(&self, compressed: bool) -> Vec<u8>;
    fn from_bytes(data: &[u8], compressed: bool) -> UrsaCryptoResult<&Self>;
}
