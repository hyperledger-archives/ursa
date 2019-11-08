use super::super::*;
use super::*;

use crypto;
use keys::{KeyGenOption, PrivateKey, PublicKey};
use rand::{rngs::OsRng, RngCore, SeedableRng};
use rand_chacha::ChaChaRng;
use sha2::Digest;
use zeroize::Zeroize;
use CryptoError;

#[derive(Serialize, Deserialize)]
pub struct Ed25519Sha512;

impl Ed25519Sha512 {
    pub fn keypair(option: Option<KeyGenOption>) -> Result<(PublicKey, PrivateKey), CryptoError> {
        let s = Ed25519Sha512 {};
        s.keypair(option)
    }

    pub fn sign(message: &[u8], sk: &PrivateKey) -> Result<Vec<u8>, CryptoError> {
        let s = Ed25519Sha512 {};
        s.sign(message, sk)
    }

    pub fn verify(message: &[u8], signature: &[u8], pk: &PublicKey) -> Result<bool, CryptoError> {
        let s = Ed25519Sha512 {};
        s.verify(message, signature, pk)
    }
}

impl SignatureScheme for Ed25519Sha512 {
    fn new() -> Self {
        Self
    }
    fn keypair(
        &self,
        option: Option<KeyGenOption>,
    ) -> Result<(PublicKey, PrivateKey), CryptoError> {
        let (sk, pk) = match option {
            Some(ref o) => match o {
                KeyGenOption::UseSeed(ref s) => {
                    let hash = sha2::Sha256::digest(s.as_slice());
                    let mut rng = ChaChaRng::from_seed(*array_ref!(hash.as_slice(), 0, 32));
                    let mut seed = [0u8; PRIVATE_KEY_SIZE];
                    rng.fill_bytes(&mut seed);
                    let pair = crypto::ed25519::keypair(&seed);
                    seed.zeroize();
                    pair
                }
                KeyGenOption::FromSecretKey(ref s) => {
                    (*array_ref!(s, 0, 64), *array_ref!(s, 32, 32))
                }
            },
            None => {
                let mut rng =
                    OsRng::new().map_err(|err| CryptoError::KeyGenError(format!("{}", err)))?;
                let mut seed = [0u8; 32];
                rng.fill_bytes(&mut seed);
                crypto::ed25519::keypair(&seed)
            }
        };
        Ok((PublicKey(pk.to_vec()), PrivateKey(sk.to_vec())))
    }
    fn sign(&self, message: &[u8], sk: &PrivateKey) -> Result<Vec<u8>, CryptoError> {
        Ok(crypto::ed25519::signature(message, &sk[..]).to_vec())
    }
    fn verify(
        &self,
        message: &[u8],
        signature: &[u8],
        pk: &PublicKey,
    ) -> Result<bool, CryptoError> {
        if signature.len() != SIGNATURE_SIZE {
            return Err(CryptoError::ParseError(
                "Invalid signature length".to_string(),
            ));
        }
        Ok(crypto::ed25519::verify(message, &pk[..], signature))
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
