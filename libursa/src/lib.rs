#[cfg(feature = "wasm")]
extern crate console_error_panic_hook;
#[cfg(feature = "wasm")]
extern crate js_sys;
#[deny(
    warnings,
    unused_qualifications,
    unused_import_braces,
    trivial_casts,
    trivial_numeric_casts
)]
#[cfg(feature = "wasm")]
extern crate wasm_bindgen;

/// Portable try to solely use Rust and no external C libraries.
/// This is considered less secure only because the Rust code may not have had a
/// security audited yet.
///
/// Native uses external C libraries that have had a security audit performed
#[cfg(feature = "pair_amcl")]
extern crate amcl;
#[macro_use]
extern crate arrayref;
extern crate env_logger;
extern crate failure;
#[macro_use]
extern crate log;
pub extern crate blake2;
extern crate generic_array;
#[cfg(test)]
extern crate libsodium_ffi;
extern crate rand;
extern crate rand_chacha;
#[cfg(all(feature = "portable", not(feature = "native")))]
extern crate rustlibsecp256k1;
#[cfg(any(test, all(feature = "native", not(feature = "portable"))))]
extern crate secp256k1 as libsecp256k1;
pub extern crate sha2;
pub extern crate sha3;
extern crate zeroize;

// To use macros from util inside of other modules it must me loaded first.
#[macro_use]
pub mod utils;

#[cfg(feature = "serialization")]
extern crate serde;

#[cfg(feature = "serialization")]
#[allow(unused_imports)] // Remove false positive warning. See https://github.com/rust-lang/rust/issues/44342
#[macro_use]
extern crate serde_derive;

#[cfg(feature = "serialization")]
#[macro_use]
extern crate serde_json;

#[cfg(any(test, feature = "bn_openssl"))]
extern crate openssl;

#[cfg(any(feature = "bn_openssl", feature = "bn_rust"))]
extern crate int_traits;

#[cfg(feature = "bn_rust")]
extern crate glass_pumpkin;
#[cfg(feature = "bn_rust")]
extern crate num_bigint;
#[cfg(feature = "bn_rust")]
extern crate num_integer;
#[cfg(feature = "bn_rust")]
extern crate num_traits;
#[cfg(feature = "ffi")]
#[macro_use]
extern crate ffi_support;

extern crate time;

extern crate ed25519_dalek;

#[cfg(feature = "cl")]
#[macro_use]
pub mod cl;
#[cfg(feature = "bls")]
pub mod bls;

#[cfg(feature = "bn_openssl")]
#[path = "bn/openssl.rs"]
pub mod bn;

#[cfg(feature = "bn_rust")]
#[path = "bn/rust.rs"]
pub mod bn;

pub mod errors;
#[cfg(feature = "ffi")]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub mod ffi;

#[cfg(feature = "pair_amcl")]
#[path = "pair/amcl.rs"]
pub mod pair;

#[macro_use]
extern crate lazy_static;

pub mod encoding;
pub mod hash;
pub mod keys;
pub mod signatures;

#[cfg(feature = "wasm")]
pub mod wasm;

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
    DigestGenError(String),
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            CryptoError::NoSuchAlgorithm(s) => write!(f, "NoSuchAlgorithm({})", s),
            CryptoError::ParseError(s) => write!(f, "ParseError({})", s),
            CryptoError::SigningError(s) => write!(f, "SigningError({})", s),
            CryptoError::KeyGenError(s) => write!(f, "KeyGenError({})", s),
            CryptoError::DigestGenError(s) => write!(f, "DigestGenError({})", s),
        }
    }
}

#[cfg(feature = "native")]
impl From<libsecp256k1::Error> for CryptoError {
    fn from(error: libsecp256k1::Error) -> CryptoError {
        match error {
            libsecp256k1::Error::IncorrectSignature => {
                CryptoError::ParseError("Incorrect Signature".to_string())
            }
            libsecp256k1::Error::InvalidMessage => {
                CryptoError::ParseError("Invalid Message".to_string())
            }
            libsecp256k1::Error::InvalidPublicKey => {
                CryptoError::ParseError("Invalid Public Key".to_string())
            }
            libsecp256k1::Error::InvalidSignature => {
                CryptoError::ParseError("Invalid Signature".to_string())
            }
            libsecp256k1::Error::InvalidSecretKey => {
                CryptoError::ParseError("Invalid Secret Key".to_string())
            }
            libsecp256k1::Error::InvalidRecoveryId => {
                CryptoError::ParseError("Invalid Recovery Id".to_string())
            }
            libsecp256k1::Error::InvalidTweak => {
                CryptoError::ParseError("Invalid Tweak".to_string())
            }
        }
    }
}
