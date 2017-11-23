extern crate amcl;
extern crate env_logger;
#[macro_use]
extern crate log;
extern crate rand;
extern crate sha2;

// To use macros from util inside of other modules it must me loaded first.
#[macro_use]
mod utils;

#[cfg(feature = "serialization")]
extern crate serde;

#[cfg(feature = "serialization")]
#[allow(unused_imports)] // Remove false positive warning. See https://github.com/rust-lang/rust/issues/44342
#[macro_use]
extern crate serde_derive;

#[cfg(feature = "serialization")]
extern crate serde_json;

#[cfg(feature = "bn_openssl")]
extern crate openssl;

#[cfg(feature = "bn_openssl")]
extern crate int_traits;

extern crate libc;

extern crate time;

pub mod cl;
pub mod bls;

#[cfg(feature = "bn_openssl")]
#[path = "bn/openssl.rs"]
pub mod bn;

pub mod errors;
pub mod ffi;

#[cfg(feature = "pair_amcl")]
#[path = "pair/amcl.rs"]
pub mod pair;