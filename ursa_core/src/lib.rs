extern crate log;
extern crate serde;
extern crate zeroize;
extern crate failure;
#[cfg(any(feature = "cl_native", feature = "sharing_native"))]
#[path = "bn/openssl.rs"]
pub mod bn;
#[cfg(any(feature = "cl", feature = "sharing"))]
#[path = "bn/rust.rs"]
pub mod bn;
pub mod errors;
pub mod keys;


