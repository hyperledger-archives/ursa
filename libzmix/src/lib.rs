//#[macro_use]
//extern crate lazy_static;
pub extern crate amcl_wrapper;
extern crate failure;
#[macro_use]
extern crate arrayref;
#[macro_use]
extern crate serde;
extern crate serde_json;

extern crate bulletproofs_amcl as bulletproofs;
#[cfg(feature = "hash2curve")]
pub extern crate hash2curve;
#[cfg(feature = "hex")]
extern crate hex;
extern crate merlin;
extern crate rand;
#[cfg(feature = "sha2")]
extern crate sha2;
#[cfg(feature = "sha3")]
extern crate sha3;
#[cfg(feature = "ursa")]
pub extern crate ursa;

#[macro_use]
pub mod commitments;
#[macro_use]
pub mod errors;
pub mod signatures;
#[cfg(feature = "ver_enc")]
pub mod verifiable_encryption;
