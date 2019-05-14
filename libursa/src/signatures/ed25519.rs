use super::{KeyGenOption, PrivateKey, PublicKey, SignatureScheme};
use ed25519_dalek::{Keypair, PublicKey as PK, Signature};
pub use ed25519_dalek::{
    EXPANDED_SECRET_KEY_LENGTH as PRIVATE_KEY_SIZE, PUBLIC_KEY_LENGTH as PUBLIC_KEY_SIZE,
    SIGNATURE_LENGTH as SIGNATURE_SIZE,
};
use rand::rngs::OsRng;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use sha2::Digest;
use zeroize::Zeroize;
use CryptoError;

pub const ALGORITHM_NAME: &str = "ED25519_SHA2_512";

#[cfg_attr(feature = "wasm", derive(Serialize, Deserialize))]
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

#[cfg(test)]
mod test {
    use super::super::Signer;
    use super::*;
    use encoding::hex::{bin2hex, hex2bin};
    use libsodium_ffi as ffi;

    const MESSAGE_1: &[u8] = b"This is a dummy message for use with tests";
    const SIGNATURE_1: &str = "451b5b8e8725321541954997781de51f4142e4a56bab68d24f6a6b92615de5eefb74134138315859a32c7cf5fe5a488bc545e2e08e5eedfd1fb10188d532d808";
    const PRIVATE_KEY: &str = "1c1179a560d092b90458fe6ab8291215a427fcd6b3927cb240701778ef55201927c96646f2d4632d4fc241f84cbc427fbc3ecaa95becba55088d6c7b81fc5bbf";
    const PUBLIC_KEY: &str = "27c96646f2d4632d4fc241f84cbc427fbc3ecaa95becba55088d6c7b81fc5bbf";

    #[test]
    #[ignore]
    fn create_new_keys() {
        let scheme = Ed25519Sha512::new();
        let (p, s) = scheme.keypair(None).unwrap();

        println!("{:?}", s);
        println!("{:?}", p);
    }

    #[test]
    fn ed25519_load_keys() {
        let scheme = Ed25519Sha512::new();
        let secret = PrivateKey(hex2bin(PRIVATE_KEY).unwrap());
        let sres = scheme.keypair(Some(KeyGenOption::FromSecretKey(secret)));
        assert!(sres.is_ok());
        let (p1, s1) = sres.unwrap();
        assert_eq!(s1, PrivateKey(hex2bin(PRIVATE_KEY).unwrap()));
        assert_eq!(p1, PublicKey(hex2bin(PUBLIC_KEY).unwrap()));
    }

    #[test]
    fn ed25519_verify() {
        let scheme = Ed25519Sha512::new();
        let secret = PrivateKey(hex2bin(PRIVATE_KEY).unwrap());
        let (p, _) = scheme
            .keypair(Some(KeyGenOption::FromSecretKey(secret)))
            .unwrap();

        let result = scheme.verify(&MESSAGE_1, hex2bin(SIGNATURE_1).unwrap().as_slice(), &p);
        assert!(result.is_ok());
        assert!(result.unwrap());

        //Check if signatures produced here can be verified by libsodium
        let signature = hex2bin(SIGNATURE_1).unwrap();
        let res = unsafe {
            ffi::crypto_sign_ed25519_verify_detached(
                signature.as_slice().as_ptr() as *const u8,
                MESSAGE_1.as_ptr() as *const u8,
                MESSAGE_1.len() as u64,
                p.as_ptr() as *const u8,
            )
        };
        assert_eq!(res, 0);
    }

    #[test]
    fn ed25519_sign() {
        let scheme = Ed25519Sha512::new();
        let secret = PrivateKey(hex2bin(PRIVATE_KEY).unwrap());
        let (p, s) = scheme
            .keypair(Some(KeyGenOption::FromSecretKey(secret)))
            .unwrap();

        match scheme.sign(&MESSAGE_1, &s) {
            Ok(sig) => {
                let result = scheme.verify(&MESSAGE_1, &sig, &p);
                assert!(result.is_ok());
                assert!(result.unwrap());

                assert_eq!(sig.len(), SIGNATURE_SIZE);
                assert_eq!(bin2hex(sig.as_slice()), SIGNATURE_1);

                //Check if libsodium signs the message and this module still can verify it
                //And that private keys can sign with other libraries
                let mut signature = [0u8; ffi::crypto_sign_ed25519_BYTES];
                unsafe {
                    ffi::crypto_sign_ed25519_detached(
                        signature.as_mut_ptr() as *mut u8,
                        0u64 as *mut u64,
                        MESSAGE_1.as_ptr() as *const u8,
                        MESSAGE_1.len() as u64,
                        s.as_ptr() as *const u8,
                    )
                };
                let result = scheme.verify(&MESSAGE_1, &signature, &p);
                assert!(result.is_ok());
                assert!(result.unwrap());
            }
            Err(e) => assert!(false, e),
        }
        let signer = Signer::new(&scheme, &s);
        match signer.sign(&MESSAGE_1) {
            Ok(signed) => {
                let result = scheme.verify(&MESSAGE_1, &signed, &p);
                assert!(result.is_ok());
                assert!(result.unwrap());
            }
            Err(er) => assert!(false, er),
        }
    }
}
