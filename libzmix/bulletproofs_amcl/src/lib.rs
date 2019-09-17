#![allow(non_snake_case)]

#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate amcl_wrapper;

extern crate serde;

#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate serde_json;

#[macro_use]
pub mod errors;

#[macro_use]
pub mod utils;

mod transcript;

pub mod ipp;

pub mod r1cs;
