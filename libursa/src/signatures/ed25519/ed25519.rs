use super::super::{KeyGenOption, SignatureScheme};
use ed25519_dalek::{Keypair, PublicKey as PK, Signature};
pub use ed25519_dalek::{
    EXPANDED_SECRET_KEY_LENGTH as PRIVATE_KEY_SIZE, PUBLIC_KEY_LENGTH as PUBLIC_KEY_SIZE,
    SIGNATURE_LENGTH as SIGNATURE_SIZE,
};
use keys::{PrivateKey, PublicKey};
use rand::rngs::OsRng;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use sha2::Digest;
use zeroize::Zeroize;

use CryptoError;

pub const ALGORITHM_NAME: &str = "ED25519_SHA2_512";

pub struct Ed25519Sha512;

impl SignatureScheme for Ed25519Sha512 {
    fn new() -> Self {
        Self
    }
    fn keypair(
        &self,
        option: Option<KeyGenOption>,
    ) -> Result<(PublicKey, PrivateKey), CryptoError> {
        let kp = match option {
            Some(mut o) => match o {
                KeyGenOption::UseSeed(ref mut s) => {
                    let hash = sha2::Sha256::digest(s.as_slice());
                    s.zeroize();
                    let mut rng = ChaChaRng::from_seed(*array_ref!(hash.as_slice(), 0, 32));
                    Keypair::generate(&mut rng)
                }
                KeyGenOption::FromSecretKey(ref s) => Keypair::from_bytes(&s[..])
                    .map_err(|e| CryptoError::KeyGenError(e.to_string()))?,
            },
            None => {
                let mut rng =
                    OsRng::new().map_err(|e| CryptoError::KeyGenError(e.msg.to_string()))?;
                Keypair::generate(&mut rng)
            }
        };
        Ok((
            PublicKey(kp.public.to_bytes().to_vec()),
            PrivateKey(kp.to_bytes().to_vec()),
        ))
    }
    fn sign(&self, message: &[u8], sk: &PrivateKey) -> Result<Vec<u8>, CryptoError> {
        let kp =
            Keypair::from_bytes(&sk[..]).map_err(|e| CryptoError::KeyGenError(e.to_string()))?;
        Ok(kp.sign(message).to_bytes().to_vec())
    }
    fn verify(
        &self,
        message: &[u8],
        signature: &[u8],
        pk: &PublicKey,
    ) -> Result<bool, CryptoError> {
        let p = PK::from_bytes(&pk[..]).map_err(|e| CryptoError::ParseError(e.to_string()))?;
        let s =
            Signature::from_bytes(signature).map_err(|e| CryptoError::ParseError(e.to_string()))?;
        p.verify(message, &s)
            .map_err(|e| CryptoError::SigningError(e.to_string()))?;
        Ok(true)
    }
    fn signature_size() -> usize {
        SIGNATURE_SIZE
    }
    fn private_key_size() -> usize {
        PRIVATE_KEY_SIZE
    }
    fn public_key_size() -> usize {
        PUBLIC_KEY_SIZE
    }
}
