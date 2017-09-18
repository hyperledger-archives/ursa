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
#[macro_use]
extern crate serde_derive;

pub mod bls;
pub mod errors;
pub mod ffi;

#[cfg(feature = "pair_amcl")]
#[path = "pair/amcl.rs"]
pub mod pair;