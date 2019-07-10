#![allow(non_snake_case)]

#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate amcl_wrapper;

#[macro_use]
pub mod errors;

#[macro_use]
pub mod utils;

mod transcript;

pub mod ipp;

pub mod r1cs;
