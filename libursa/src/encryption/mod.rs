//! Encryption is categorized as public key encryption or symmetric encryption
//! `symm` provides symmetric AEAD cryptographic algorithms.
use aead::generic_array::{ArrayLength, GenericArray};
use aead::Error;
use rand::{rngs::OsRng, RngCore};

pub mod symm;

// Helpful for generating bytes using the operating system random number generator
pub fn random_vec(bytes: usize) -> Result<Vec<u8>, Error> {
    let mut value = vec![0u8; bytes];
    OsRng.fill_bytes(value.as_mut_slice());
    Ok(value)
}

pub fn random_bytes<T: ArrayLength<u8>>() -> Result<GenericArray<u8, T>, Error> {
    Ok(GenericArray::clone_from_slice(
        random_vec(T::to_usize())?.as_slice(),
    ))
}
