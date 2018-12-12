#[cfg(feature = "wasm")]
extern crate wasm_bindgen;
#[cfg(feature = "wasm")]
extern crate console_error_panic_hook;

/// Portable try to solely use Rust and no external C libraries.
/// This is considered less secure only because the Rust code may not have had a
/// security audited yet.
///
/// Native uses external C libraries that have had a security audit performed
#[cfg(feature = "pair_amcl")]
extern crate amcl;
extern crate amcl_3;
#[macro_use]
extern crate arrayref;
extern crate env_logger;
#[macro_use]
extern crate log;
extern crate rand;
extern crate rand_chacha;
extern crate sha2;
extern crate sha3;
#[cfg(any(test, all(feature = "native", not(feature = "portable"))))]
extern crate libsodium_ffi;
#[cfg(all(feature = "portable", not(feature = "native")))]
extern crate crypto as rcrypto;
#[cfg(any(test, all(feature = "native", not(feature = "portable"))))]
extern crate secp256k1 as libsecp256k1;
#[cfg(all(feature = "portable", not(feature = "native")))]
extern crate rustlibsecp256k1;

// To use macros from util inside of other modules it must me loaded first.
#[macro_use]
pub mod utils;

#[cfg(feature = "serialization")]
extern crate serde;

#[cfg(feature = "serialization")]
#[allow(unused_imports)] // Remove false positive warning. See https://github.com/rust-lang/rust/issues/44342
#[macro_use]
extern crate serde_derive;

#[cfg(not(test))]
#[cfg(feature = "serialization")]
extern crate serde_json;

#[cfg(test)]
#[cfg(feature = "serialization")]
#[macro_use]
extern crate serde_json;

#[cfg(feature = "bn_openssl")]
extern crate openssl;

#[cfg(feature = "bn_openssl")]
extern crate int_traits;

#[cfg(feature = "ffi")]
extern crate libc;

extern crate time;

extern crate blake2b_simd;

#[cfg(feature = "cl")]
#[macro_use]
pub mod cl;
pub mod bls;

#[cfg(feature = "bn_openssl")]
#[path = "bn/openssl.rs"]
pub mod bn;

pub mod errors;
#[cfg(feature = "ffi")]
pub mod ffi;

#[cfg(feature = "pair_amcl")]
#[path = "pair/amcl.rs"]
pub mod pair;

#[macro_use]
extern crate lazy_static;

pub mod hash;
pub mod keys;
pub mod signatures;
pub mod encoding;
#[derive(Debug)]
pub enum CryptoError {
    /// Returned when trying to create an algorithm which does not exist.
    NoSuchAlgorithm(String),
    /// Returned when an error occurs during deserialization of a Private or
    /// Public key from various formats.
    ParseError(String),
    /// Returned when an error occurs during the signing process.
    SigningError(String),
    /// Returned when an error occurs during key generation
    KeyGenError(String),
    /// Returned when an error occurs during digest generation
    DigestGenError(String)
}

#[cfg(feature = "native")]
impl From<libsecp256k1::Error> for CryptoError {
    fn from(error: libsecp256k1::Error) -> CryptoError {
        match error {
            libsecp256k1::Error::IncorrectSignature => CryptoError::ParseError("Incorrect Signature".to_string()),
            libsecp256k1::Error::InvalidMessage => CryptoError::ParseError("Invalid Message".to_string()),
            libsecp256k1::Error::InvalidPublicKey => CryptoError::ParseError("Invalid Public Key".to_string()),
            libsecp256k1::Error::InvalidSignature => CryptoError::ParseError("Invalid Signature".to_string()),
            libsecp256k1::Error::InvalidSecretKey => CryptoError::ParseError("Invalid Secret Key".to_string()),
            libsecp256k1::Error::InvalidRecoveryId => CryptoError::ParseError("Invalid Recovery Id".to_string()),
            libsecp256k1::Error::InvalidTweak => CryptoError::ParseError("Invalid Tweak".to_string())
        }
    }
}
