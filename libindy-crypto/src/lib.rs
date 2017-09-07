extern crate amcl;
extern crate rand;
extern crate sha1;

// To use macros from util inside of other modules it must me loaded first.
#[macro_use]
mod utils;

pub mod bls;
pub mod errors;
pub mod ffi;

#[cfg(feature = "pair_amcl")]
#[path = "pair/amcl.rs"]
pub mod pair;