use super::*;
use rand::rngs::OsRng;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use sha2::Digest;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroize;

use CryptoError;

pub struct X25519Sha256;

impl KeyExchangeScheme for X25519Sha256 {
    fn new() -> Self {
        Self
    }

    fn keypair(
        &self,
        option: Option<KeyGenOption>,
    ) -> Result<(PublicKey, PrivateKey), CryptoError> {
        let (pk, sk) = match option {
            Some(mut o) => match o {
                KeyGenOption::UseSeed(ref mut s) => {
                    let hash = sha2::Sha256::digest(s.as_slice());
                    s.zeroize();
                    let mut rng = ChaChaRng::from_seed(*array_ref!(hash.as_slice(), 0, 32));
                    let sk = StaticSecret::new(&mut rng);
                    let pk = X25519PublicKey::from(&sk);
                    (pk, sk)
                }
                KeyGenOption::FromSecretKey(ref s) => {
                    let sk = StaticSecret::from(*array_ref!(&s[..], 0, 32));
                    let pk = X25519PublicKey::from(&sk);
                    (pk, sk)
                }
            },
            None => {
                let mut rng = OsRng::default();
                let sk = StaticSecret::new(&mut rng);
                let pk = X25519PublicKey::from(&sk);
                (pk, sk)
            }
        };
        Ok((
            PublicKey(pk.as_bytes().to_vec()),
            PrivateKey(sk.to_bytes().to_vec()),
        ))
    }

    fn compute_shared_secret(
        &self,
        local_private_key: &PrivateKey,
        remote_public_key: &PublicKey,
    ) -> Result<SessionKey, CryptoError> {
        let sk = StaticSecret::from(*array_ref!(&local_private_key[..], 0, 32));
        let pk = X25519PublicKey::from(*array_ref!(&remote_public_key[..], 0, 32));
        let shared_secret = sk.diffie_hellman(&pk);
        let hash = sha2::Sha256::digest(shared_secret.as_bytes());
        Ok(SessionKey(hash.as_slice().to_vec()))
    }

    fn public_key_size() -> usize {
        32
    }
    fn private_key_size() -> usize {
        32
    }
    fn shared_secret_size() -> usize {
        32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(any(feature = "ed25519", feature = "ed25519_asm"))]
    #[test]
    fn convert_from_sig_keys() {
        use signatures::{ed25519::Ed25519Sha512, SignatureScheme};
        let sig_scheme = Ed25519Sha512::new();
        let (pk, sk) = sig_scheme.keypair(None).unwrap();
        let res = Ed25519Sha512::ver_key_to_key_exchange(&pk);
        assert!(res.is_ok());
        let pk1 = res.unwrap();
        let kex_scheme = X25519Sha256::new();
        let res = kex_scheme.compute_shared_secret(&sk, &pk1);
        assert!(res.is_ok());
    }

    #[test]
    fn key_exchange() {
        let scheme = X25519Sha256::new();
        let res = scheme.keypair(None);
        assert!(res.is_ok());
        let (pk, sk) = res.unwrap();
        let res = scheme.compute_shared_secret(&sk, &pk);
        assert!(res.is_ok());
        let res = scheme.keypair(None);
        assert!(res.is_ok());
        let (pk1, sk1) = res.unwrap();
        let res = scheme.compute_shared_secret(&sk1, &pk);
        assert!(res.is_ok());
        let res = scheme.compute_shared_secret(&sk, &pk1);
        assert!(res.is_ok());

        let res = scheme.keypair(Some(KeyGenOption::FromSecretKey(sk.clone())));
        assert!(res.is_ok());
        let (pk1, sk1) = res.unwrap();
        assert_eq!(pk1, pk);
        assert_eq!(sk1, sk);
    }
}
