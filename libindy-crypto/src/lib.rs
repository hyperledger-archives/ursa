#[cfg(feature = "wasm")]
extern crate wasm_bindgen;
#[cfg(feature = "wasm")]
extern crate console_error_panic_hook;

#[cfg(feature = "pair_amcl")]
extern crate amcl;
extern crate env_logger;
#[macro_use]
extern crate log;
extern crate rand;
extern crate sha2;
extern crate sha3;

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

#[cfg(feature = "wasm")]
pub mod wasm;
