// TODO: FIXME: It must be removed after code layout stabilization!
#![allow(dead_code)]
#![allow(unused_variables)]

#[macro_use]
extern crate log;

extern crate lazy_static;

extern crate sha1;

// Note that to use macroses from util inside of other modules it must me loaded first!
#[macro_use]
mod utils;

pub mod api;
mod bls;
mod errors;

#[cfg(test)]
mod tests {
    //use super::*;

    #[test]
    fn dummy() {
        assert! (true, "Dummy check!");
    }
}
