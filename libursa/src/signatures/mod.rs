pub mod ed25519;
pub mod secp256k1;

use keys::{KeyGenOption, PrivateKey, PublicKey};
use CryptoError;

pub trait SignatureScheme {
    fn new() -> Self;
    fn keypair(
        &self,
        options: Option<KeyGenOption>,
    ) -> Result<(PublicKey, PrivateKey), CryptoError>;
    fn sign(&self, message: &[u8], sk: &PrivateKey) -> Result<Vec<u8>, CryptoError>;
    fn verify(&self, message: &[u8], signature: &[u8], pk: &PublicKey)
        -> Result<bool, CryptoError>;
    fn signature_size() -> usize;
    fn private_key_size() -> usize;
    fn public_key_size() -> usize;
}

pub struct Signer<'a, 'b, T: 'a + SignatureScheme> {
    scheme: &'a T,
    key: &'b PrivateKey,
}

impl<'a, 'b, T: 'a + SignatureScheme> Signer<'a, 'b, T> {
    /// Constructs a new Signer
    ///
    /// # Arguments
    ///
    /// * `scheme` - a cryptographic signature scheme
    /// * `private_key` - private key
    pub fn new(scheme: &'a T, key: &'b PrivateKey) -> Self {
        Signer { scheme, key }
    }

    /// Signs the given message.
    ///
    /// # Arguments
    ///
    /// * `message` - the message bytes
    ///
    /// # Returns
    ///
    /// * `signature` - the signature bytes
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.scheme.sign(message, self.key)
    }

    /// Return the public key for this Signer instance.
    ///
    /// # Returns
    ///
    /// * `public_key` - the public key instance
    pub fn get_public_key(&self) -> Result<PublicKey, CryptoError> {
        let sk = PrivateKey(self.key[..].to_vec());
        let (pubk, _) = self
            .scheme
            .keypair(Some(KeyGenOption::FromSecretKey(sk)))
            .unwrap();
        Ok(pubk)
    }
}

pub trait EcdsaPublicKeyHandler {
    /// Returns the compressed bytes
    fn public_key_compressed(&self, pk: &PublicKey) -> Vec<u8>;
    /// Returns the uncompressed bytes
    fn public_key_uncompressed(&self, pk: &PublicKey) -> Vec<u8>;
    /// Read raw bytes into key struct. Can be either compressed or uncompressed
    fn parse(&self, data: &[u8]) -> Result<PublicKey, CryptoError>;
    fn public_key_uncompressed_size() -> usize;
}
