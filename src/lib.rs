pub mod commitments;
pub mod ffi;
pub mod zkl;
pub mod hash_functions;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
