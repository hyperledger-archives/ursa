#![deny(unused_import_braces, trivial_numeric_casts)]

#[cfg(all(feature = "ecdsa_secp256k1", feature = "ecdsa_secp256k1_native"))]
compile_error!("Cannot compile both features 'ecdsa_sepc256k1' and 'ecdsa_secp256k1_native'");
#[cfg(all(feature = "ecdsa_secp256k1", feature = "ecdsa_secp256k1_asm"))]
compile_error!("Cannot compile both features 'ecdsa_sepc256k1' and 'ecdsa_secp256k1_asm'");
#[cfg(all(feature = "ecdsa_secp256k1_native", feature = "ecdsa_secp256k1_asm"))]
compile_error!("Cannot compile both features 'ecdsa_sepc256k1_native' and 'ecdsa_secp256k1_asm'");
#[cfg(all(feature = "ed25519", feature = "ed25519_asm"))]
compile_error!("Cannot compile both features 'ed25519' and 'ed25519_asm'");
#[cfg(all(feature = "cl", feature = "cl_native"))]
compile_error!("Cannot compile both features 'cl' and 'cl_native'");

#[cfg(feature = "aead")]
extern crate aead;
#[cfg(feature = "aes")]
extern crate aes;
#[cfg(feature = "aes-gcm")]
extern crate aes_gcm;
#[cfg(feature = "amcl")]
extern crate amcl;
#[cfg(feature = "block-modes")]
extern crate block_modes;
#[cfg(feature = "block-padding")]
extern crate block_padding;
#[cfg(feature = "hmac")]
extern crate hmac;
#[cfg(any(test, feature = "libsodium-ffi"))]
extern crate libsodium_ffi;
#[cfg(any(test, feature = "openssl"))]
extern crate openssl;
#[cfg(feature = "rand")]
extern crate rand;
#[cfg(feature = "rand_chacha")]
extern crate rand_chacha;
#[cfg(feature = "rustchacha20poly1305")]
extern crate rustchacha20poly1305;
#[cfg(feature = "subtle")]
extern crate subtle;
#[cfg(feature = "lazy_static")]
#[macro_use]
extern crate lazy_static;
#[cfg(feature = "blake2")]
pub extern crate blake2;
#[cfg(test)]
extern crate bytebuffer;
#[cfg(feature = "ed25519-dalek")]
extern crate ed25519_dalek;
#[cfg(feature = "sha2")]
pub extern crate sha2;
#[cfg(feature = "sha3")]
pub extern crate sha3;
#[cfg(feature = "zeroize")]
extern crate zeroize;
#[cfg(feature = "arrayref")]
#[macro_use]
extern crate arrayref;
#[cfg(feature = "amcl_wrapper")]
extern crate amcl_wrapper;
#[cfg(feature = "failure")]
extern crate failure;
#[cfg(feature = "glass_pumpkin")]
extern crate glass_pumpkin;
#[cfg(feature = "int_traits")]
extern crate int_traits;
#[cfg(feature = "log")]
#[cfg_attr(
    any(
        feature = "cl",
        feature = "cl_native",
        feature = "sharing",
        feature = "sharing_native",
        feature = "ffi"
    ),
    macro_use
)]
extern crate log;
#[cfg(feature = "num-bigint")]
extern crate num_bigint;
#[cfg(feature = "num-integer")]
extern crate num_integer;
#[cfg(feature = "num-traits")]
extern crate num_traits;

#[cfg(any(test, feature = "bitcoinsecp256k1"))]
extern crate bitcoinsecp256k1;
#[cfg(feature = "k256")]
extern crate k256;

#[cfg(feature = "serde")]
extern crate serde;
#[cfg(any(test, feature = "ffi"))]
#[cfg_attr(
    any(
        feature = "cl",
        feature = "cl_native",
        feature = "ffi",
        feature = "wasm"
    ),
    macro_use
)]
extern crate serde_json;
#[cfg(feature = "ffi")]
#[macro_use]
extern crate ffi_support;
#[cfg(feature = "console_error_panic_hook")]
extern crate console_error_panic_hook;
#[cfg(feature = "curve25519-dalek")]
extern crate curve25519_dalek;
#[cfg(feature = "hex")]
extern crate hex;
#[cfg(feature = "hkdf")]
extern crate hkdf;
#[cfg(feature = "js-sys")]
extern crate js_sys;
#[cfg(feature = "wasm-bindgen")]
extern crate wasm_bindgen;
#[cfg(feature = "x25519-dalek")]
extern crate x25519_dalek;

#[cfg(any(
    feature = "bls_bls12381",
    feature = "cl",
    feature = "cl_native",
    feature = "ecdh_secp256k1",
    feature = "ecdh_secp256k1_native",
    feature = "ecdh_secp256k1_asm",
    feature = "ecdsa_secp256k1",
    feature = "ecdsa_secp256k1_native",
    feature = "ecdsa_secp256k1_asm",
    feature = "ed25519",
    feature = "ed25519_asm",
    feature = "ffi",
    feature = "x25519",
    feature = "x25519_asm",
    feature = "wasm"
))]
#[macro_use]
pub mod utils;

#[cfg(any(feature = "bls_bn254", feature = "bls_bn254_asm"))]
pub mod bls;
#[cfg(any(feature = "cl_native", feature = "sharing_native"))]
#[path = "bn/openssl.rs"]
pub mod bn;
#[cfg(any(feature = "cl", feature = "sharing"))]
#[path = "bn/rust.rs"]
pub mod bn;
#[cfg(any(feature = "cl", feature = "cl_native"))]
pub mod cl;
#[cfg(any(
    feature = "aescbc",
    feature = "aescbc_native",
    feature = "aesgcm",
    feature = "aesgcm_native",
    feature = "chacha20poly1305",
    feature = "chacha20poly1305_native"
))]
pub mod encryption;
#[cfg(any(
    feature = "bls_bn254",
    feature = "bls_bn254_asm",
    feature = "ecdsa_secp256k1_native",
    feature = "ecdsa_secp256k1_asm",
    feature = "cl",
    feature = "cl_native",
    feature = "sharing",
    feature = "sharing_native",
    feature = "ffi",
    feature = "wasm"
))]
pub mod errors;
#[cfg(feature = "ffi")]
pub mod ffi;
#[cfg(any(feature = "blake2", feature = "sha2", feature = "sha3"))]
pub mod hash;
#[cfg(any(
    feature = "ecdh_secp256k1",
    feature = "ecdh_secp256k1_native",
    feature = "ecdh_secp256k1_asm",
    feature = "x25519",
    feature = "x25519_asm"
))]
pub mod kex;
#[cfg(any(
    feature = "bls_bls12381",
    feature = "ecdh_secp256k1",
    feature = "ecdh_secp256k1_native",
    feature = "ecdh_secp256k1_asm",
    feature = "ecdsa_secp256k1",
    feature = "ecdsa_secp256k1_native",
    feature = "ecdsa_secp256k1_asm",
    feature = "ed25519",
    feature = "ed25519_asm",
    feature = "x25519",
    feature = "x25519_asm",
    feature = "wasm"
))]
pub mod keys;
#[cfg(any(
    feature = "bls_bn254",
    feature = "bls_bn254_asm",
    feature = "cl",
    feature = "cl_native"
))]
#[path = "pair/amcl.rs"]
pub mod pair;
#[cfg(any(feature = "sharing", feature = "sharing_native"))]
pub mod sharing;
#[cfg(any(
    feature = "ed25519",
    feature = "ed25519_asm",
    feature = "ecdsa_secp256k1",
    feature = "ecdsa_secp256k1_native",
    feature = "ecdsa_secp256k1_asm",
    feature = "bls_bls12381"
))]
pub mod signatures;
#[cfg(feature = "wasm")]
pub mod wasm;

pub type CryptoResult<T> = Result<T, CryptoError>;

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
    /// A General purpose error message that doesn't fit in any category
    GeneralError(String),
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            CryptoError::NoSuchAlgorithm(s) => write!(f, "NoSuchAlgorithm({})", s),
            CryptoError::ParseError(s) => write!(f, "ParseError({})", s),
            CryptoError::SigningError(s) => write!(f, "SigningError({})", s),
            CryptoError::KeyGenError(s) => write!(f, "KeyGenError({})", s),
            CryptoError::DigestGenError(s) => write!(f, "DigestGenError({})", s),
            CryptoError::GeneralError(m) => write!(f, "GeneralError({})", m),
        }
    }
}

#[cfg(feature = "bitcoinsecp256k1")]
impl From<bitcoinsecp256k1::Error> for CryptoError {
    fn from(error: bitcoinsecp256k1::Error) -> CryptoError {
        match error {
            bitcoinsecp256k1::Error::IncorrectSignature => {
                CryptoError::ParseError("Incorrect Signature".to_string())
            }
            bitcoinsecp256k1::Error::InvalidMessage => {
                CryptoError::ParseError("Invalid Message".to_string())
            }
            bitcoinsecp256k1::Error::InvalidPublicKey => {
                CryptoError::ParseError("Invalid Public Key".to_string())
            }
            bitcoinsecp256k1::Error::InvalidSignature => {
                CryptoError::ParseError("Invalid Signature".to_string())
            }
            bitcoinsecp256k1::Error::InvalidSecretKey => {
                CryptoError::ParseError("Invalid Secret Key".to_string())
            }
            bitcoinsecp256k1::Error::InvalidRecoveryId => {
                CryptoError::ParseError("Invalid Recovery Id".to_string())
            }
            bitcoinsecp256k1::Error::InvalidTweak => {
                CryptoError::ParseError("Invalid Tweak".to_string())
            }
            bitcoinsecp256k1::Error::NotEnoughMemory => {
                CryptoError::ParseError("Not Enough Memory".to_string())
            }
        }
    }
}

#[cfg(any(
    feature = "bls_bn254",
    feature = "bls_bn254_asm",
    feature = "ecdsa_secp256k1_native",
    feature = "ecdsa_secp256k1_asm",
    feature = "cl",
    feature = "cl_native",
    feature = "sharing",
    feature = "sharing_native",
    feature = "ffi",
    feature = "wasm"
))]
impl From<errors::UrsaCryptoError> for CryptoError {
    fn from(err: errors::UrsaCryptoError) -> Self {
        let kind = err.kind();
        CryptoError::GeneralError(format!("{}", kind))
    }
}
