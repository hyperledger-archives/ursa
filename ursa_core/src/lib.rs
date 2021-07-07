#![deny(unused_import_braces, trivial_numeric_casts)]


#[cfg(feature = "serde")]
extern crate serde;

#[cfg(feature = "zeroize")]
extern crate zeroize;

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


#[cfg(any(feature = "cl_native", feature = "sharing_native"))]
#[path = "bn/openssl.rs"]
pub mod bn;
#[cfg(any(feature = "cl", feature = "sharing"))]
#[path = "bn/rust.rs"]
pub mod bn;
