#[macro_use]
extern crate serde_json;

pub mod commitments;
pub mod ffi;
pub mod zkl;
pub mod prf;
pub mod hash_functions;
pub mod signatures;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
