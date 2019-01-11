use super::*;
use CryptoError;

pub const PRIVATE_KEY_SIZE: usize = 64;
pub const PUBLIC_KEY_SIZE: usize = 32;
pub const SIGNATURE_SIZE: usize = 64;
pub const ALGORITHM_NAME: &str = "ED25519_SHA2_512";

pub struct Ed25519Sha512(ed25519_sha2_512::Ed25519Sha512Impl);

impl SignatureScheme for Ed25519Sha512 {
    fn new() -> Ed25519Sha512 {
        Ed25519Sha512(ed25519_sha2_512::Ed25519Sha512Impl::new())
    }
    fn keypair(&self, option: Option<KeyPairOption>) -> Result<(PublicKey, PrivateKey), CryptoError> {
        self.0.keypair(option)
    }
    fn sign(&self, message: &[u8], sk: &PrivateKey) -> Result<Vec<u8>, CryptoError> {
        self.0.sign(message, sk)
    }
    fn verify(&self, message: &[u8], signature: &[u8], pk: &PublicKey) -> Result<bool, CryptoError> {
        self.0.verify(message, signature, pk)
    }
    fn signature_size() -> usize { SIGNATURE_SIZE }
    fn private_key_size() -> usize { PRIVATE_KEY_SIZE }
    fn public_key_size() -> usize { PUBLIC_KEY_SIZE }
}

#[cfg(all(feature = "native", not(feature = "portable")))]
mod ed25519_sha2_512 {
    use super::*;
    use libsodium_ffi as ffi;

    use rand_chacha::ChaChaRng;
    use rand::{RngCore, SeedableRng};

    pub struct Ed25519Sha512Impl{}

    impl Ed25519Sha512Impl {
        pub fn new() -> Ed25519Sha512Impl {
            unsafe {
                ffi::sodium_init()
            };
            Ed25519Sha512Impl{}
        }
        pub fn keypair(&self, option: Option<KeyPairOption>) -> Result<(PublicKey, PrivateKey), CryptoError> {
            let mut sk = [0u8; ffi::crypto_sign_ed25519_SECRETKEYBYTES];
            let mut pk = [0u8; ffi::crypto_sign_ed25519_PUBLICKEYBYTES];
            let res = match option {
                    Some(o) => {
                        match o {
                            KeyPairOption::UseSeed(s) => {
                                let mut seed = [0u8; ffi::crypto_sign_ed25519_SECRETKEYBYTES];
                                let mut rng = ChaChaRng::from_seed(*array_ref!(s.as_slice(), 0, 32));
                                rng.fill_bytes(&mut seed);
                                unsafe {
                                    ffi::crypto_sign_seed_keypair(pk.as_mut_ptr() as *mut u8,
                                                                  sk.as_mut_ptr() as *mut u8,
                                                                  seed.as_ptr() as *const u8)
                                }
                            },
                            KeyPairOption::FromSecretKey(secret) => {
                                array_copy!(secret, sk);
                                array_copy!(secret, ffi::crypto_sign_ed25519_PUBLICKEYBYTES, pk, 0, ffi::crypto_sign_ed25519_PUBLICKEYBYTES);
                                0
                            }
                        }
                    },
                    None => unsafe {
                        ffi::crypto_sign_keypair(pk.as_mut_ptr() as *mut u8, sk.as_mut_ptr() as *mut u8)
                    }
                };
            if res == 0 {
                Ok((PublicKey(pk.to_vec()), PrivateKey(sk.to_vec())))
            } else {
                Err(CryptoError::KeyGenError("Unable to generate new keys".to_string()))
            }
        }
        pub fn sign(&self, message: &[u8], sk: &PrivateKey) -> Result<Vec<u8>, CryptoError> {
            let mut signature = [0u8; ffi::crypto_sign_ed25519_BYTES];
            let res = unsafe {
                ffi::crypto_sign_ed25519_detached(signature.as_mut_ptr() as *mut u8,
                                                  0u64 as *mut u64,
                                                  message.as_ptr() as *const u8,
                                                  message.len() as u64,
                                                  sk.as_ptr() as *const u8)
            };
            if res == 0 {
                let mut sig = Vec::new();
                sig.extend_from_slice(&signature);
                Ok(sig)
            } else {
                Err(CryptoError::SigningError("An error occurred while signing".to_string()))
            }
        }
        pub fn verify(&self, message: &[u8], signature: &[u8], pk: &PublicKey) -> Result<bool, CryptoError> {
            let res = unsafe {
                ffi::crypto_sign_ed25519_verify_detached(signature.as_ptr() as *const u8,
                                                         message.as_ptr() as *const u8,
                                                         message.len() as u64,
                                                         pk.as_ptr() as *const u8)
            };
            Ok(res == 0)
        }
    }
}

#[cfg(all(feature = "portable", not(feature = "native")))]
mod ed25519_sha2_512 {
    use super::*;
    use rcrypto;

    use hash::{digest, DigestAlgorithm};
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaChaRng;
    use rand::rngs::OsRng;

    pub struct Ed25519Sha512Impl{}

    impl Ed25519Sha512Impl {
        pub fn new() -> Ed25519Sha512Impl { Ed25519Sha512Impl{} }
        pub fn keypair(&self, option: Option<KeyPairOption>) -> Result<(PublicKey, PrivateKey), CryptoError> {
            let (sk, pk): ([u8; PRIVATE_KEY_SIZE], [u8; PUBLIC_KEY_SIZE]) = match option {
                    Some(o) => {
                        match o {
                            KeyPairOption::UseSeed(s) => {
                                let mut seed = [0u8; PRIVATE_KEY_SIZE];
                                let hash = digest(DigestAlgorithm::Sha2_256, &s.as_slice())?;
                                let mut rng = ChaChaRng::from_seed(*array_ref!(hash, 0, 32));
                                rng.fill_bytes(&mut seed);
                                rcrypto::ed25519::keypair(&seed)
                            },
                            KeyPairOption::FromSecretKey(s) => (*array_ref!(s, 0, 64), *array_ref!(s, 32, 32))
                        }
                    },
                    None => {
                        let mut rng = OsRng::new().map_err(|err| CryptoError::KeyGenError(format!("{}", err)))?;
                        let mut seed = [0u8; 32];
                        rng.fill_bytes(&mut seed);
                        rcrypto::ed25519::keypair(&seed)
                    }
                };
            Ok((PublicKey(pk.to_vec()), PrivateKey(sk.to_vec())))
        }
        pub fn sign(&self, message: &[u8], sk: &PrivateKey) -> Result<Vec<u8>, CryptoError> {
            Ok(rcrypto::ed25519::signature(message, &sk[..]).to_vec())
        }
        pub fn verify(&self, message: &[u8], signature: &[u8], pk: &PublicKey) -> Result<bool, CryptoError> {
            if signature.len() != SIGNATURE_SIZE {
                Err(CryptoError::ParseError("Invalid signature length".to_string()))?
            }
            Ok(rcrypto::ed25519::verify(message, &pk[..], signature))
        }
    }
}

#[cfg(test)]
mod test {
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
        let sres = scheme.keypair(Some(KeyPairOption::FromSecretKey(&secret)));
        assert!(sres.is_ok());
        let (p1, s1) = sres.unwrap();
        assert_eq!(s1, PrivateKey(hex2bin(PRIVATE_KEY).unwrap()));
        assert_eq!(p1, PublicKey(hex2bin(PUBLIC_KEY).unwrap()));
    }

    #[test]
    fn ed25519_verify() {
        let scheme = Ed25519Sha512::new();
        let secret = PrivateKey(hex2bin(PRIVATE_KEY).unwrap());
        let (p, _) = scheme.keypair(Some(KeyPairOption::FromSecretKey(&secret))).unwrap();

        let result = scheme.verify(&MESSAGE_1, hex2bin(SIGNATURE_1).unwrap().as_slice(), &p);
        assert!(result.is_ok());
        assert!(result.unwrap());

        //Check if signatures produced here can be verified by libsodium
        let signature = hex2bin(SIGNATURE_1).unwrap();
        let res = unsafe {
            ffi::crypto_sign_ed25519_verify_detached(signature.as_slice().as_ptr() as *const u8,
                                                     MESSAGE_1.as_ptr() as *const u8,
                                                     MESSAGE_1.len() as u64,
                                                     p.as_ptr() as *const u8)
        };
        assert_eq!(res, 0);
    }

    #[test]
    fn ed25519_sign() {
        let scheme = Ed25519Sha512::new();
        let secret = PrivateKey(hex2bin(PRIVATE_KEY).unwrap());
        let (p, s) = scheme.keypair(Some(KeyPairOption::FromSecretKey(&secret))).unwrap();

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
                    ffi::crypto_sign_ed25519_detached(signature.as_mut_ptr() as *mut u8,
                                                      0u64 as *mut u64,
                                                      MESSAGE_1.as_ptr() as *const u8,
                                                      MESSAGE_1.len() as u64,
                                                      s.as_ptr() as *const u8)
                };
                let result = scheme.verify(&MESSAGE_1, &signature, &p);
                assert!(result.is_ok());
                assert!(result.unwrap());
            },
            Err(e) => assert!(false, e)
        }
        let signer = Signer::new(&scheme, &s);
        match signer.sign(&MESSAGE_1) {
            Ok(signed) => {
                let result = scheme.verify(&MESSAGE_1, &signed, &p);
                assert!(result.is_ok());
                assert!(result.unwrap());
            },
            Err(er) => assert!(false, er)
        }
    }
}
