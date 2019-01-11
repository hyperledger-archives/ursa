use CryptoError;

#[derive(Debug)]
pub enum DigestAlgorithm {
    Sha2_256,
    Sha2_384,
    Sha2_512,
    Blake2b256,
    Blake2b384,
    Blake2b512
}

pub fn digest(algorithm: DigestAlgorithm, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    match algorithm {
        DigestAlgorithm::Sha2_256 => {
            let mut hash = sha2::Sha256::new();
            hash.update(message);
            hash.finalize()
        },
        DigestAlgorithm::Sha2_384 => {
            let mut hash = sha2::Sha384::new();
            hash.update(message);
            hash.finalize()
        },
        DigestAlgorithm::Sha2_512 => {
            let mut hash = sha2::Sha512::new();
            hash.update(message);
            hash.finalize()
        }
        DigestAlgorithm::Blake2b256 => {
            let mut hash = blake2::Blake2b256::new();
            hash.update(message);
            hash.finalize()
        }
        DigestAlgorithm::Blake2b384 => {
            let mut hash = blake2::Blake2b384::new();
            hash.update(message);
            hash.finalize()
        },
        DigestAlgorithm::Blake2b512 => {
            let mut hash = blake2::Blake2b512::new();
            hash.update(message);
            hash.finalize()
        }
    }
}

pub trait Digest {
    fn new() -> Self where Self : Sized;
    fn reset(&mut self);
    fn update(&mut self, data: &[u8]);
    fn finalize(&mut self) -> Result<Vec<u8>, CryptoError>;
}

pub mod sha2;
pub mod blake2;
