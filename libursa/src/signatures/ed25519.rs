pub const ALGORITHM_NAME: &str = "ED25519_SHA2_512";

use super::{KeyGenOption, SignatureScheme};
#[cfg(any(feature = "x25519", feature = "x25519_asm"))]
use ed25519_dalek::SecretKey as SK;
use ed25519_dalek::{Keypair, PublicKey as PK, Signature, Signer, Verifier};
pub use ed25519_dalek::{
    EXPANDED_SECRET_KEY_LENGTH as PRIVATE_KEY_SIZE, PUBLIC_KEY_LENGTH as PUBLIC_KEY_SIZE,
    SIGNATURE_LENGTH as SIGNATURE_SIZE,
};
use keys::{PrivateKey, PublicKey};
use rand::rngs::OsRng;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use sha2::Digest;
use std::convert::TryFrom;
use zeroize::Zeroize;

use CryptoError;

pub struct Ed25519Sha512;

#[cfg(any(feature = "x25519", feature = "x25519_asm"))]
impl Ed25519Sha512 {
    /// Creates a curve25519 key from an ed25519 public key.
    ///
    /// Used to derive the public key for DH key exchange.
    ///
    /// # Example
    /// ```
    /// use ursa::signatures::ed25519::Ed25519Sha512;
    /// use ursa::signatures::SignatureScheme;
    ///
    /// let (pk, sk) = Ed25519Sha512::new().keypair(None).unwrap();
    /// let curve_pk = Ed25519Sha512::ver_key_to_key_exchange(&pk).unwrap();
    /// let curve_sk = Ed25519Sha512::sign_key_to_key_exchange(&sk).unwrap();
    /// ```
    pub fn ver_key_to_key_exchange(pk: &PublicKey) -> Result<PublicKey, CryptoError> {
        use curve25519_dalek::edwards::CompressedEdwardsY;

        // Verify it's a valid public key
        PK::from_bytes(&pk[..]).map_err(|e| CryptoError::ParseError(e.to_string()))?;
        // PublicKey is a CompressedEdwardsY in dalek. So we decompress it to get the
        // EdwardsPoint which can then be used convert to the Montgomery Form.
        let cey = CompressedEdwardsY::from_slice(&pk[..]);
        match cey.decompress() {
            Some(ep) => Ok(PublicKey(ep.to_montgomery().as_bytes().to_vec())),
            None => Err(CryptoError::ParseError(format!(
                "Invalid public key provided. Cannot convert to key exchange key"
            ))),
        }
    }

    /// Creates a curve25519 key from an ed25519 private key.
    ///
    /// Used to derive the private key for DH key exchange.
    ///
    /// # Example
    /// ```
    /// use ursa::signatures::ed25519::Ed25519Sha512;
    /// use ursa::signatures::SignatureScheme;
    ///
    /// let (pk, sk) = Ed25519Sha512::new().keypair(None).unwrap();
    /// let curve_pk = Ed25519Sha512::ver_key_to_key_exchange(&pk).unwrap();
    /// let curve_sk = Ed25519Sha512::sign_key_to_key_exchange(&sk).unwrap();
    /// ```
    pub fn sign_key_to_key_exchange(sk: &PrivateKey) -> Result<PrivateKey, CryptoError> {
        // Length is normally 64 but we only need the secret from the first half
        if sk.len() < 32 {
            return Err(CryptoError::ParseError(format!(
                "Invalid private key provided"
            )));
        }
        // hash secret
        let hash = sha2::Sha512::digest(&sk[..32]);
        let mut output = [0u8; 32];
        output.copy_from_slice(&hash[..32]);
        // clamp result
        let secret = x25519_dalek::StaticSecret::from(output);
        Ok(PrivateKey(secret.to_bytes().to_vec()))
    }

    /// Expand an ed25519 keypair from the input key material.
    ///
    /// Used to derive a complete keypair from a predetermined secret.
    ///
    /// # Example
    /// ```
    /// use ursa::signatures::ed25519::Ed25519Sha512;
    ///
    /// let ikm = b"000000000000000000000000000Test1";
    /// let (pk, sk) = Ed25519Sha512::expand_keypair(ikm).unwrap();
    /// ```
    pub fn expand_keypair(ikm: &[u8]) -> Result<(PublicKey, PrivateKey), CryptoError> {
        if ikm.len() < 32 {
            return Err(CryptoError::ParseError(format!(
                "Invalid key material provided"
            )));
        }
        let mut private = vec![0u8; 64];
        private[..32].copy_from_slice(&ikm[..32]);
        let sk = SK::from_bytes(&ikm[..32]).unwrap();
        let pk = PK::from(&sk).to_bytes().to_vec();
        private[32..].copy_from_slice(pk.as_ref());
        Ok((PublicKey(pk), PrivateKey(private)))
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
                let mut rng = OsRng::default();
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
            Signature::try_from(signature).map_err(|e| CryptoError::ParseError(e.to_string()))?;
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
    use self::Ed25519Sha512;
    use super::super::{SignatureScheme, Signer};
    use super::*;
    use keys::{KeyGenOption, PrivateKey, PublicKey};
    use libsodium_ffi as ffi;

    const MESSAGE_1: &[u8] = b"This is a dummy message for use with tests";
    const SIGNATURE_1: &str = "451b5b8e8725321541954997781de51f4142e4a56bab68d24f6a6b92615de5eefb74134138315859a32c7cf5fe5a488bc545e2e08e5eedfd1fb10188d532d808";
    const PRIVATE_KEY: &str = "1c1179a560d092b90458fe6ab8291215a427fcd6b3927cb240701778ef55201927c96646f2d4632d4fc241f84cbc427fbc3ecaa95becba55088d6c7b81fc5bbf";
    const PUBLIC_KEY: &str = "27c96646f2d4632d4fc241f84cbc427fbc3ecaa95becba55088d6c7b81fc5bbf";
    #[cfg(any(feature = "x25519", feature = "x25519_asm"))]
    const PRIVATE_KEY_X25519: &str =
        "08e7286c232ec71b37918533ea0229bf0c75d3db4731df1c5c03c45bc909475f";
    #[cfg(any(feature = "x25519", feature = "x25519_asm"))]
    const PUBLIC_KEY_X25519: &str =
        "9b4260484c889158c128796103dc8d8b883977f2ef7efb0facb12b6ca9b2ae3d";

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
        let secret = PrivateKey(hex::decode(PRIVATE_KEY).unwrap());
        let sres = scheme.keypair(Some(KeyGenOption::FromSecretKey(secret)));
        assert!(sres.is_ok());
        let (p1, s1) = sres.unwrap();
        assert_eq!(s1, PrivateKey(hex::decode(PRIVATE_KEY).unwrap()));
        assert_eq!(p1, PublicKey(hex::decode(PUBLIC_KEY).unwrap()));
    }

    #[test]
    fn ed25519_verify() {
        let scheme = Ed25519Sha512::new();
        let secret = PrivateKey(hex::decode(PRIVATE_KEY).unwrap());
        let (p, _) = scheme
            .keypair(Some(KeyGenOption::FromSecretKey(secret)))
            .unwrap();

        let result = scheme.verify(&MESSAGE_1, hex::decode(SIGNATURE_1).unwrap().as_slice(), &p);
        assert!(result.is_ok());
        assert!(result.unwrap());

        //Check if signatures produced here can be verified by libsodium
        let signature = hex::decode(SIGNATURE_1).unwrap();
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
        let secret = PrivateKey(hex::decode(PRIVATE_KEY).unwrap());
        let (p, s) = scheme
            .keypair(Some(KeyGenOption::FromSecretKey(secret)))
            .unwrap();

        match scheme.sign(&MESSAGE_1, &s) {
            Ok(sig) => {
                let result = scheme.verify(&MESSAGE_1, &sig, &p);
                assert!(result.is_ok());
                assert!(result.unwrap());

                assert_eq!(sig.len(), SIGNATURE_SIZE);
                assert_eq!(hex::encode(sig.as_slice()), SIGNATURE_1);

                //Check if libsodium signs the message and this module still can verify it
                //And that private keys can sign with other libraries
                let mut signature = [0u8; ffi::crypto_sign_ed25519_BYTES as usize];
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
            Err(e) => assert!(false, "{}", e),
        }
        let signer = Signer::new(&scheme, &s);
        match signer.sign(&MESSAGE_1) {
            Ok(signed) => {
                let result = scheme.verify(&MESSAGE_1, &signed, &p);
                assert!(result.is_ok());
                assert!(result.unwrap());
            }
            Err(er) => assert!(false, "{}", er),
        }
    }

    #[cfg(any(feature = "x25519", feature = "x25519_asm"))]
    #[test]
    fn ed25519_to_x25519_default() {
        let scheme = Ed25519Sha512::new();
        let (p, _) = scheme.keypair(None).unwrap();

        let res = Ed25519Sha512::ver_key_to_key_exchange(&p);
        assert!(res.is_ok());
    }

    #[cfg(any(feature = "x25519", feature = "x25519_asm"))]
    #[test]
    fn ed25519_to_x25519_verify() {
        let sk = PrivateKey(hex::decode(PRIVATE_KEY).unwrap());
        let pk = PublicKey(hex::decode(PUBLIC_KEY).unwrap());

        let x_pk = Ed25519Sha512::ver_key_to_key_exchange(&pk).unwrap();
        assert_eq!(hex::encode(&x_pk), PUBLIC_KEY_X25519);

        let x_sk = Ed25519Sha512::sign_key_to_key_exchange(&sk).unwrap();
        assert_eq!(hex::encode(&x_sk), PRIVATE_KEY_X25519);
    }

    #[cfg(any(feature = "x25519", feature = "x25519_asm"))]
    #[test]
    fn nacl_derive_from_seed() {
        let seed = b"000000000000000000000000Trustee1";
        let test_sk = hex::decode("3030303030303030303030303030303030303030303030305472757374656531e33aaf381fffa6109ad591fdc38717945f8fabf7abf02086ae401c63e9913097").unwrap();
        let test_pk = &test_sk[32..];

        let (pk, sk) = Ed25519Sha512::expand_keypair(seed).unwrap();
        assert_eq!(pk.0, test_pk);
        assert_eq!(sk.0, test_sk);
    }
}
