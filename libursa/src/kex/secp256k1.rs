use super::*;

use CryptoError;

pub const PRIVATE_KEY_SIZE: usize = 32;
pub const PUBLIC_KEY_SIZE: usize = 33;

pub struct EcdhSecp256k1Sha256(ecdh_secp256k1::EcdhSecp256k1Impl);

impl KeyExchangeScheme for EcdhSecp256k1Sha256 {
    fn new() -> Self {
        Self(ecdh_secp256k1::EcdhSecp256k1Impl::new())
    }

    fn keypair(
        &self,
        option: Option<KeyGenOption>,
    ) -> Result<(PublicKey, PrivateKey), CryptoError> {
        self.0.keypair::<sha2::Sha256>(option)
    }

    fn compute_shared_secret(
        &self,
        local_private_key: &PrivateKey,
        remote_public_key: &PublicKey,
    ) -> Result<SessionKey, CryptoError> {
        self.0
            .compute_shared_secret::<sha2::Sha256>(local_private_key, remote_public_key)
    }

    fn public_key_size() -> usize {
        PUBLIC_KEY_SIZE
    }
    fn private_key_size() -> usize {
        PRIVATE_KEY_SIZE
    }
    fn shared_secret_size() -> usize {
        PRIVATE_KEY_SIZE
    }
}

#[cfg(any(feature = "ecdh_secp256k1_native", feature = "ecdh_secp256k1_asm"))]
mod ecdh_secp256k1 {
    use super::*;
    use libsecp256k1::{
        ecdh::SharedSecret,
        key::{PublicKey as Secp256k1PublicKey, SecretKey},
    };
    use rand::rngs::OsRng;
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaChaRng;
    use sha2::digest::generic_array::typenum::U32;
    use sha2::Digest;
    use zeroize::Zeroize;

    pub struct EcdhSecp256k1Impl(libsecp256k1::Secp256k1<libsecp256k1::All>);

    impl EcdhSecp256k1Impl {
        pub fn new() -> Self {
            Self(libsecp256k1::Secp256k1::new())
        }
        pub fn keypair<D>(
            &self,
            option: Option<KeyGenOption>,
        ) -> Result<(PublicKey, PrivateKey), CryptoError>
        where
            D: Digest<OutputSize = U32>,
        {
            let sk = match option {
                Some(mut o) => match o {
                    KeyGenOption::UseSeed(ref mut seed) => {
                        let mut s = [0u8; PRIVATE_KEY_SIZE];
                        let mut rng = ChaChaRng::from_seed(*array_ref!(seed.as_slice(), 0, 32));
                        seed.zeroize();
                        rng.fill_bytes(&mut s);
                        let k = D::digest(&s);
                        s.zeroize();
                        libsecp256k1::key::SecretKey::from_slice(k.as_slice())?
                    }
                    KeyGenOption::FromSecretKey(ref s) => {
                        libsecp256k1::key::SecretKey::from_slice(&s[..])?
                    }
                },
                None => {
                    let mut rng =
                        OsRng::new().map_err(|err| CryptoError::KeyGenError(format!("{}", err)))?;
                    let mut s = [0u8; PRIVATE_KEY_SIZE];
                    rng.fill_bytes(&mut s);
                    let k = D::digest(&s);
                    s.zeroize();
                    libsecp256k1::key::SecretKey::from_slice(k.as_slice())?
                }
            };
            let pk = libsecp256k1::key::PublicKey::from_secret_key(&self.0, &sk);
            Ok((
                PublicKey(pk.serialize().to_vec()),
                PrivateKey(sk[..].to_vec()),
            ))
        }

        pub fn compute_shared_secret<D>(
            &self,
            local_private_key: &PrivateKey,
            remote_public_key: &PublicKey,
        ) -> Result<SessionKey, CryptoError>
        where
            D: Digest<OutputSize = U32>,
        {
            let sk = SecretKey::from_slice(&local_private_key[..])?;
            let pk = Secp256k1PublicKey::from_slice(&remote_public_key[..])?;
            let secret = SharedSecret::new(&pk, &sk);
            Ok(SessionKey(secret.as_ref().to_vec()))
        }
    }
}

#[cfg(feature = "ecdh_secp256k1")]
mod ecdh_secp256k1 {
    use super::*;

    use rand::rngs::OsRng;
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaChaRng;
    use rustlibsecp256k1::{PublicKey as Secp256k1PublicKey, SecretKey, SharedSecret};

    #[cfg(feature = "serde")]
    use serde::{Deserialize, Serialize};

    use sha2::digest::generic_array::typenum::U32;
    use sha2::Digest;
    use zeroize::Zeroize;
    const PUBLIC_UNCOMPRESSED_KEY_SIZE: usize = 65;

    use amcl::secp256k1::{ecdh, ecp};

    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    pub struct EcdhSecp256k1Impl;

    impl EcdhSecp256k1Impl {
        pub fn new() -> Self {
            Self
        }
        pub fn keypair<D>(
            &self,
            option: Option<KeyGenOption>,
        ) -> Result<(PublicKey, PrivateKey), CryptoError>
        where
            D: Digest<OutputSize = U32>,
        {
            let mut sk = [0u8; PRIVATE_KEY_SIZE];
            match option {
                Some(mut o) => match o {
                    KeyGenOption::UseSeed(ref mut seed) => {
                        let mut rng =
                            ChaChaRng::from_seed(*array_ref!(seed.as_slice(), 0, PRIVATE_KEY_SIZE));
                        seed.zeroize();
                        rng.fill_bytes(&mut sk);

                        let d = D::digest(&sk[..]);
                        array_copy!(d.as_slice(), sk)
                    }
                    KeyGenOption::FromSecretKey(ref s) => array_copy!(s, sk),
                },
                None => {
                    OsRng.fill_bytes(&mut sk);
                    let d = D::digest(&sk[..]);
                    sk.clone_from_slice(d.as_slice());
                }
            };
            let mut pk = [0u8; PUBLIC_UNCOMPRESSED_KEY_SIZE];
            ecdh::key_pair_generate(None, &mut sk, &mut pk);
            let mut compressed = [0u8; PUBLIC_KEY_SIZE];
            ecp::ECP::frombytes(&pk[..]).tobytes(&mut compressed, true);
            Ok((PublicKey(compressed.to_vec()), PrivateKey(sk.to_vec())))
        }

        pub fn compute_shared_secret<D>(
            &self,
            local_private_key: &PrivateKey,
            remote_public_key: &PublicKey,
        ) -> Result<SessionKey, CryptoError>
        where
            D: Digest<OutputSize = U32> + Default,
        {
            let sk = SecretKey::parse(array_ref!(&local_private_key[..], 0, PRIVATE_KEY_SIZE))
                .map_err(|e| CryptoError::ParseError(format!("{:?}", e)))?;
            let mut uncompressed = [0u8; PUBLIC_UNCOMPRESSED_KEY_SIZE];
            ecp::ECP::frombytes(&remote_public_key[..]).tobytes(&mut uncompressed, false);
            let pk = Secp256k1PublicKey::parse(&uncompressed)
                .map_err(|e| CryptoError::DigestGenError(format!("{:?}", e)))?;

            let secret: SharedSecret<D> = SharedSecret::new(&pk, &sk)
                .map_err(|e| CryptoError::DigestGenError(format!("{:?}", e)))?;
            Ok(SessionKey(secret.as_ref().to_vec()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_exchange() {
        let scheme = EcdhSecp256k1Sha256::new();
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

    #[test]
    fn secp256k1_compatibility() {
        use libsecp256k1::{
            ecdh::SharedSecret,
            key::{PublicKey, SecretKey},
        };

        let scheme = EcdhSecp256k1Sha256::new();
        let (pk, sk) = scheme.keypair(None).unwrap();

        let sk1 = SecretKey::from_slice(&sk[..]).unwrap();
        let pk1 = PublicKey::from_slice(&pk[..]).unwrap();
        let secret = SharedSecret::new(&pk1, &sk1);
        assert_eq!(
            secret.as_ref(),
            scheme.compute_shared_secret(&sk, &pk).unwrap().as_ref()
        );
    }
}
