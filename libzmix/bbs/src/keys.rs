use crate::errors::prelude::*;
use crate::{
    hash_to_g2, GeneratorG1, GeneratorG2, HashElem, RandomElem, ToVariableLengthBytes,
    FR_COMPRESSED_SIZE, FR_UNCOMPRESSED_SIZE, G1_COMPRESSED_SIZE, G1_UNCOMPRESSED_SIZE,
    G2_COMPRESSED_SIZE, G2_UNCOMPRESSED_SIZE,
};
use blake2::{digest::generic_array::GenericArray, Blake2b};
use pairing_plus::{
    bls12_381::{Fr, G1, G2},
    hash_to_field::BaseFromRO,
    serdes::SerDes,
    CurveProjective,
};
use rand::prelude::*;
#[cfg(feature = "rayon")]
use rayon::prelude::*;
use serde::{
    de::{Error as DError, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::io::{Cursor, Read};
use std::{
    convert::TryFrom,
    fmt::{Display, Formatter},
};
use zeroize::Zeroize;

/// Convenience importing module
pub mod prelude {
    pub use super::{
        generate, DeterministicPublicKey, KeyGenOption, PublicKey, SecretKey,
        DETERMINISTIC_PUBLIC_KEY_COMPRESSED_SIZE,
    };
}

/// The various ways a key can be constructed other than random
#[derive(Debug, Clone)]
pub enum KeyGenOption {
    /// The hash of these bytes will be used as the private key
    UseSeed(Vec<u8>),
    /// The actual secret key, used to construct the public key
    FromSecretKey(SecretKey),
}

/// The secret key is field element 0 < `x` < `r`
/// where `r` is the curve order. See Section 4.3 in
/// <https://eprint.iacr.org/2016/663.pdf>
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretKey(pub(crate) Fr);

impl SecretKey {
    to_fixed_length_bytes_impl!(SecretKey, Fr, FR_COMPRESSED_SIZE, FR_COMPRESSED_SIZE);
}

from_impl!(SecretKey, Fr, FR_COMPRESSED_SIZE);
display_impl!(SecretKey);
serdes_impl!(SecretKey);
hash_elem_impl!(SecretKey, |data| { generate_secret_key(Some(data)) });
random_elem_impl!(SecretKey, { generate_secret_key(None) });

impl Zeroize for SecretKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// `PublicKey` consists of a blinding generator `h_0`,
/// a commitment to the secret key `w`
/// and a generator for each message in `h`
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey {
    /// Blinding factor generator
    pub h0: GeneratorG1,
    /// Base for each message to be signed
    pub h: Vec<GeneratorG1>,
    /// Commitment to the private key
    pub w: GeneratorG2,
}

impl PublicKey {
    /// Return how many messages this public key can be used to sign
    pub fn message_count(&self) -> usize {
        self.h.len()
    }

    /// Convert the key to raw bytes
    pub(crate) fn to_bytes(&self, compressed: bool) -> Vec<u8> {
        let mut out = Vec::new();
        self.w.0.serialize(&mut out, compressed).unwrap();
        self.h0.0.serialize(&mut out, compressed).unwrap();
        out.extend_from_slice(&(self.h.len() as u32).to_be_bytes());
        for p in &self.h {
            p.0.serialize(&mut out, compressed).unwrap();
        }
        out
    }

    /// Convert the byte slice into a public key
    pub(crate) fn from_bytes(
        data: &[u8],
        g1_size: usize,
        compressed: bool,
    ) -> Result<Self, BBSError> {
        if (data.len() - 4) % g1_size != 0 {
            return Err(BBSErrorKind::MalformedPublicKey.into());
        }
        let mut c = Cursor::new(data.as_ref());
        let w = GeneratorG2(
            G2::deserialize(&mut c, compressed)
                .map_err(|_| BBSError::from_kind(BBSErrorKind::MalformedPublicKey))?,
        );
        let h0 = GeneratorG1(
            G1::deserialize(&mut c, compressed)
                .map_err(|_| BBSError::from_kind(BBSErrorKind::MalformedPublicKey))?,
        );

        let mut h_bytes = [0u8; 4];
        c.read_exact(&mut h_bytes).unwrap();

        let h_size = u32::from_be_bytes(h_bytes) as usize;
        let mut h = Vec::with_capacity(h_size);
        for _ in 0..h_size {
            let p = GeneratorG1(
                G1::deserialize(&mut c, compressed)
                    .map_err(|_| BBSError::from_kind(BBSErrorKind::MalformedPublicKey))?,
            );
            h.push(p);
        }
        let pk = Self { w, h0, h };
        pk.validate()?;
        Ok(pk)
    }

    /// Make sure no generator is identity
    pub fn validate(&self) -> Result<(), BBSError> {
        if self.h0.0.is_zero() || self.w.0.is_zero() || self.h.iter().any(|v| v.0.is_zero()) {
            Err(BBSError::from_kind(BBSErrorKind::MalformedPublicKey))
        } else {
            Ok(())
        }
    }
}

impl ToVariableLengthBytes for PublicKey {
    type Output = PublicKey;
    type Error = BBSError;

    fn to_bytes_compressed_form(&self) -> Vec<u8> {
        self.to_bytes(true)
    }

    fn from_bytes_compressed_form<I: AsRef<[u8]>>(data: I) -> Result<Self::Output, Self::Error> {
        Self::from_bytes(data.as_ref(), G1_COMPRESSED_SIZE, true)
    }

    fn to_bytes_uncompressed_form(&self) -> Vec<u8> {
        self.to_bytes(false)
    }

    fn from_bytes_uncompressed_form<I: AsRef<[u8]>>(data: I) -> Result<Self::Output, Self::Error> {
        Self::from_bytes(data.as_ref(), G1_UNCOMPRESSED_SIZE, false)
    }
}

try_from_impl!(PublicKey, BBSError);
display_impl!(PublicKey);
serdes_impl!(PublicKey);

/// Size of a compressed deterministic public key
pub const DETERMINISTIC_PUBLIC_KEY_COMPRESSED_SIZE: usize = G2_COMPRESSED_SIZE;

/// Used to deterministically generate all other generators given a commitment to a private key
/// This is effectively a BLS signature public key
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeterministicPublicKey(pub(crate) G2);

impl DeterministicPublicKey {
    to_fixed_length_bytes_impl!(
        DeterministicPublicKey,
        G2,
        G2_COMPRESSED_SIZE,
        G2_UNCOMPRESSED_SIZE
    );
}

as_ref_impl!(DeterministicPublicKey, G2);
from_impl!(
    DeterministicPublicKey,
    G2,
    G2_COMPRESSED_SIZE,
    G2_UNCOMPRESSED_SIZE
);
display_impl!(DeterministicPublicKey);
serdes_impl!(DeterministicPublicKey);
hash_elem_impl!(DeterministicPublicKey, |data| {
    DeterministicPublicKey(hash_to_g2(data))
});

impl DeterministicPublicKey {
    /// Generates a random `Secretkey` and only creates the commitment to it
    pub fn new(option: Option<KeyGenOption>) -> (Self, SecretKey) {
        let secret = match option {
            Some(ref o) => match o {
                KeyGenOption::UseSeed(ref v) => generate_secret_key(Some(v)),
                KeyGenOption::FromSecretKey(ref sk) => sk.clone(),
            },
            None => generate_secret_key(None),
        };
        let mut w = G2::one();
        w.mul_assign(secret.0.clone());
        (Self(w), secret)
    }

    /// Convert to a normal public key but deterministically derive all the generators
    /// using the hash to curve algorithm BLS12381G1_XMD:SHA-256_SSWU_RO denoted as H2C
    /// h_0 <- H2C(w || I2OSP(0, 4) || I2OSP(0, 1) || I2OSP(message_count, 4))
    /// h_i <- H2C(w || I2OSP(i, 4) || I2OSP(0, 1) || I2OSP(message_count, 4))
    pub fn to_public_key(&self, message_count: usize) -> Result<PublicKey, BBSError> {
        if message_count == 0 {
            return Err(BBSErrorKind::KeyGenError.into());
        }
        let mc_bytes = (message_count as u32).to_be_bytes();
        let mut data = Vec::with_capacity(9 + G2_UNCOMPRESSED_SIZE);
        self.0
            .serialize(&mut data, false)
            .map_err(|_| BBSError::from_kind(BBSErrorKind::KeyGenError))?;
        // Spacer
        data.push(0u8);
        let offset = data.len();
        // i
        data.push(0u8);
        data.push(0u8);
        data.push(0u8);
        data.push(0u8);
        let end = data.len();
        // Spacer
        data.push(0u8);
        // message_count
        data.extend_from_slice(&mc_bytes[..]);

        let gen_count: Vec<usize> = (0..=message_count).collect();

        #[cfg(feature = "rayon")]
        let temp_iter = gen_count.par_iter();
        #[cfg(not(feature = "rayon"))]
        let temp_iter = gen_count.iter();

        let h = temp_iter
            .map(|i| {
                let mut temp = data.clone();
                let ii = *i as u32;
                temp[offset..end].copy_from_slice(&(ii.to_be_bytes())[..]);
                GeneratorG1::hash(temp)
            })
            .collect::<Vec<GeneratorG1>>();

        Ok(PublicKey {
            w: GeneratorG2(self.0.clone()),
            h0: h[0].clone(),
            h: h[1..].to_vec(),
        })
    }
}

/// Create a new BBS+ keypair. The generators of the public key are generated at random
pub fn generate(message_count: usize) -> Result<(PublicKey, SecretKey), BBSError> {
    if message_count == 0 {
        return Err(BBSError::from_kind(BBSErrorKind::KeyGenError));
    }
    let secret = generate_secret_key(None);

    let mut w = G2::one();
    w.mul_assign(secret.0.clone());
    let gen_count: Vec<usize> = (0..=message_count).collect();

    #[cfg(feature = "rayon")]
    let temp_iter = gen_count.par_iter();
    #[cfg(not(feature = "rayon"))]
    let temp_iter = gen_count.iter();

    let h = temp_iter
        .map(|_| {
            let mut rng = thread_rng();
            let mut seed = [0u8; 32];
            rng.fill_bytes(&mut seed);
            GeneratorG1::hash(seed)
        })
        .collect::<Vec<GeneratorG1>>();
    Ok((
        PublicKey {
            w: GeneratorG2(w),
            h0: h[0].clone(),
            h: h[1..].to_vec(),
        },
        secret,
    ))
}

/// Similar to https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-2.3
/// info is left blank
fn generate_secret_key(ikm: Option<&[u8]>) -> SecretKey {
    let salt = b"BBS-SIG-KEYGEN-SALT-";
    let info = [0u8, FR_UNCOMPRESSED_SIZE as u8]; // I2OSP(L, 2)
    let ikm = match ikm {
        Some(v) => {
            let mut t = vec![0u8; v.len() + 1];
            t[..v.len()].copy_from_slice(v);
            t
        }
        None => {
            let mut bytes = vec![0u8; FR_COMPRESSED_SIZE + 1];
            thread_rng().fill_bytes(bytes.as_mut_slice());
            bytes[FR_COMPRESSED_SIZE] = 0;
            bytes
        }
    };
    let mut okm = [0u8; FR_UNCOMPRESSED_SIZE];
    let h = hkdf::Hkdf::<Blake2b>::new(Some(&salt[..]), &ikm);
    h.expand(&info[..], &mut okm).unwrap();
    SecretKey(Fr::from_okm(GenericArray::from_slice(&okm[..])))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_generate() {
        let res = generate(0);
        assert!(res.is_err());
        //Check to make sure key has correct size
        let (public_key, _) = generate(1).unwrap();
        let bytes = public_key.to_bytes_uncompressed_form();
        assert_eq!(
            bytes.len(),
            G1_UNCOMPRESSED_SIZE * 2 + 4 + G2_UNCOMPRESSED_SIZE
        );

        let (public_key, _) = generate(5).unwrap();
        assert_eq!(public_key.message_count(), 5);
        //Check key doesn't contain any invalid points
        assert!(public_key.validate().is_ok());
        let bytes = public_key.to_bytes_uncompressed_form();
        assert_eq!(
            bytes.len(),
            G1_UNCOMPRESSED_SIZE * 6 + 4 + G2_UNCOMPRESSED_SIZE
        );
        //Check serialization is working
        let public_key_2 = PublicKey::from_bytes_uncompressed_form(bytes.as_slice()).unwrap();
        assert_eq!(public_key_2, public_key);

        let bytes = public_key.to_bytes_compressed_form();
        assert_eq!(bytes.len(), G1_COMPRESSED_SIZE * 6 + 4 + G2_COMPRESSED_SIZE);
        let public_key_3 = PublicKey::from_bytes_compressed_form(bytes.as_slice());
        assert!(public_key_3.is_ok());
        assert_eq!(public_key_3.unwrap(), public_key);
    }

    #[test]
    fn key_conversion() {
        let (dpk, _) = DeterministicPublicKey::new(None);
        let res = dpk.to_public_key(5);

        assert!(res.is_ok());

        let pk = res.unwrap();
        assert_eq!(pk.message_count(), 5);

        for i in 0..pk.h.len() {
            assert_ne!(pk.h0, pk.h[i], "h[0] == h[{}]", i + 1);

            for j in (i + 1)..pk.h.len() {
                assert_ne!(pk.h[i], pk.h[j], "h[{}] == h[{}]", i + 1, j + 1);
            }
        }

        let res = dpk.to_public_key(0);

        assert!(res.is_err());
    }

    #[test]
    fn key_from_seed() {
        let seed = vec![0u8; 32];
        let (dpk, sk) = DeterministicPublicKey::new(Some(KeyGenOption::UseSeed(seed)));

        assert_eq!("a171467362a8fbbc444889efc39e53a5e683ec85fbed19aa1fd89edb5cdb9751871b4db568d8476892f0b6444ca854b50a1c354388c17055a6b8a9d8d5a647b25d41055ce73fb57e158394aea51a9c824b726f258f3e97a90723cc753a459eec", hex::encode(&dpk.to_bytes_compressed_form()[..]));
        assert_eq!(
            "0eb25c421350947e8c99faeaee643d64f9e01c568467e5de41050cc4190e8db8",
            hex::encode(&sk.to_bytes_compressed_form()[..])
        );

        let seed = vec![1u8; 24];
        let (dpk, sk) = DeterministicPublicKey::new(Some(KeyGenOption::UseSeed(seed)));

        assert_eq!("8dae8c4d40a8ec909e0d5c8541fc0edcfd46d302078edd246ea626853d5376d0a789481abd39ddba5e5145b950a580781802f6c7e70b24f492a1bd4d8edd596e0413fb88c9664bcca65e77460b8cf46680b4f689f28a2731f39891cdb96229c4", hex::encode(&dpk.to_bytes_compressed_form()[..]));
        assert_eq!(
            "3ac2bb3f5bfe0db27d5da9842ddb750326f7094d7aeeed78d474862f233f2948",
            hex::encode(&sk.to_bytes_compressed_form()[..])
        );
    }

    #[test]
    fn key_compression() {
        let (pk, sk) = generate(3).unwrap();

        assert_eq!(292, pk.to_bytes_compressed_form().len());
        assert_eq!(FR_COMPRESSED_SIZE, sk.to_bytes_compressed_form().len());

        let (dpk, sk) = DeterministicPublicKey::new(Some(KeyGenOption::FromSecretKey(sk)));
        assert_eq!(96, dpk.to_bytes_compressed_form().len());

        let res = PublicKey::from_bytes_compressed_form(pk.to_bytes_compressed_form());
        assert!(res.is_ok());

        assert!(res.unwrap().to_bytes_compressed_form() == pk.to_bytes_compressed_form());

        let dpk1 = DeterministicPublicKey::from(dpk.to_bytes_compressed_form());
        assert!(&dpk1.to_bytes_compressed_form()[..] == &dpk.to_bytes_compressed_form()[..]);

        let sk1 = SecretKey::from(sk.to_bytes_compressed_form());
        assert!(&sk1.to_bytes_compressed_form()[..] == &sk.to_bytes_compressed_form()[..]);
    }
}
