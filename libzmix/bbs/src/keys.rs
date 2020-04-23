use amcl_wrapper::{
    constants::{FIELD_ORDER_ELEMENT_SIZE, GROUP_G1_SIZE, GROUP_G2_SIZE},
    curve_order_elem::CurveOrderElement,
    errors::SerzDeserzError,
    group_elem::GroupElement,
    group_elem_g1::G1,
    group_elem_g2::G2,
};
use hash2curve::DomainSeparationTag;
use hash2curve::{bls381g1::Bls12381G1Sswu, HashToCurveXmd};
use serde::{Deserialize, Serialize};

use crate::errors::prelude::*;
use crate::CompressedBytes;
use rayon::prelude::*;

/// Convenience importing module
pub mod prelude {
    pub use super::{
        generate, DeterministicPublicKey, KeyGenOption, PublicKey, SecretKey,
        COMPRESSED_DETERMINISTIC_PUBLIC_KEY_SIZE,
    };
    pub use hash2curve::DomainSeparationTag;
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
pub type SecretKey = CurveOrderElement;

/// `PublicKey` consists of a blinding generator `h_0`,
/// a commitment to the secret key `w`
/// and a generator for each message in `h`
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PublicKey {
    /// Blinding factor generator
    pub h0: G1,
    /// Base for each message to be signed
    pub h: Vec<G1>,
    /// Commitment to the private key
    pub w: G2,
}

impl PublicKey {
    /// Return how many messages this public key can be used to sign
    pub fn message_count(&self) -> usize {
        self.h.len()
    }

    /// Convert the key to raw bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(GROUP_G1_SIZE * (self.h.len() + 1) + 4 + GROUP_G2_SIZE);
        out.extend_from_slice(self.w.to_vec().as_slice());
        out.extend_from_slice(self.h0.to_vec().as_slice());
        out.extend_from_slice(&(self.h.len() as u32).to_be_bytes());
        for p in &self.h {
            out.extend_from_slice(p.to_vec().as_slice());
        }
        out
    }

    /// Convert the byte slice into a public key
    pub fn from_bytes(data: &[u8]) -> Result<Self, SerzDeserzError> {
        let mut index = 0;
        let w = G2::from(array_ref![data, 0, GROUP_G2_SIZE]);
        index += GROUP_G2_SIZE;
        let h0 = G1::from(array_ref![data, index, GROUP_G1_SIZE]);
        index += GROUP_G1_SIZE;
        let h_size = u32::from_be_bytes([
            data[index],
            data[index + 1],
            data[index + 2],
            data[index + 3],
        ]) as usize;
        let mut h = Vec::with_capacity(h_size);
        index += 4;
        for _ in 0..h_size {
            let p = G1::from(array_ref![data, index, GROUP_G1_SIZE]);
            h.push(p);
            index += GROUP_G1_SIZE;
        }
        Ok(PublicKey { w, h0, h })
    }

    /// Make sure no generator is identity
    pub fn validate(&self) -> Result<(), BBSError> {
        if self.h0.is_identity() || self.w.is_identity() || self.h.iter().any(|v| v.is_identity()) {
            Err(BBSError::from_kind(BBSErrorKind::MalformedPublicKey))
        } else {
            Ok(())
        }
    }
}

impl CompressedBytes for PublicKey {
    type Output = PublicKey;
    type Error = BBSError;

    /// Convert the key to raw bytes. Use when sending over the wire
    fn to_compressed_bytes(&self) -> Vec<u8> {
        let h_len = self.h.len() as u32;
        let mut output = Vec::with_capacity(FIELD_ORDER_ELEMENT_SIZE * (3 + self.h.len()));
        output.extend_from_slice(&self.w.to_compressed_bytes()[..]);
        output.extend_from_slice(&self.h0.to_compressed_bytes()[..]);
        output.extend_from_slice(&h_len.to_be_bytes()[..]);
        for p in &self.h {
            output.extend_from_slice(&p.to_compressed_bytes()[..]);
        }
        output
    }

    /// Convert from raw bytes. Use when sending over the wire
    fn from_compressed_bytes<I: AsRef<[u8]>>(data: I) -> Result<Self, BBSError> {
        const MIN_SIZE: usize = FIELD_ORDER_ELEMENT_SIZE * 3;
        let data = data.as_ref();
        let len = (data.len() - 4) % FIELD_ORDER_ELEMENT_SIZE;
        if len != 0 {
            return Err(BBSErrorKind::InvalidNumberOfBytes(MIN_SIZE, data.len()).into());
        }
        let w = G2::from(array_ref![data, 0, FIELD_ORDER_ELEMENT_SIZE * 2]);
        let h0 = G1::from(array_ref![
            data,
            FIELD_ORDER_ELEMENT_SIZE * 2,
            FIELD_ORDER_ELEMENT_SIZE
        ]);
        let h_len = u32::from_be_bytes(*array_ref![data, MIN_SIZE, 4]) as usize;
        let mut h = Vec::with_capacity(h_len);
        let mut offset = MIN_SIZE + 4;
        for _ in 0..h_len {
            let h_i = G1::from(array_ref![data, offset, FIELD_ORDER_ELEMENT_SIZE]);
            h.push(h_i);
            offset += FIELD_ORDER_ELEMENT_SIZE;
        }

        Ok(Self { w, h0, h })
    }
}

/// Size of a compressed deterministic public key
pub const COMPRESSED_DETERMINISTIC_PUBLIC_KEY_SIZE: usize = 2 * FIELD_ORDER_ELEMENT_SIZE;

/// Used to deterministically generate all other generators given a commitment to a private key
/// This is effectively a BLS signature public key
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeterministicPublicKey {
    w: G2,
}

impl DeterministicPublicKey {
    /// Generates a random `Secretkey` and only creates the commitment to it
    pub fn new(option: Option<KeyGenOption>) -> (Self, SecretKey) {
        let secret = match option {
            Some(ref o) => match o {
                KeyGenOption::UseSeed(ref v) => CurveOrderElement::from_msg_hash(v.as_slice()),
                KeyGenOption::FromSecretKey(ref sk) => sk.clone(),
            },
            None => CurveOrderElement::random(),
        };
        let w = &G2::generator() * &secret;
        (Self { w }, secret)
    }

    /// Convert to a normal public key but deterministically derive all the generators
    /// using the hash to curve algorithm BLS12381G1_XMD:SHA-256_SSWU_RO denoted as H2C
    /// h_0 <- H2C(w || I2OSP(0, 4) || I2OSP(0, 1) || I2OSP(message_count, 4))
    /// h_i <- H2C(w || I2OSP(i, 4) || I2OSP(0, 1) || I2OSP(message_count, 4))
    pub fn to_public_key(
        &self,
        message_count: usize,
        dst: DomainSeparationTag,
    ) -> Result<PublicKey, BBSError> {
        if message_count == 0 {
            return Err(BBSError::from_kind(BBSErrorKind::KeyGenError));
        }
        let point_hasher = Bls12381G1Sswu::new(dst);

        let mc_bytes = (message_count as u32).to_be_bytes();

        let h = (0..=message_count)
            .collect::<Vec<usize>>()
            .par_iter()
            .map(|i| self.hash_to_curve(*i as u32, mc_bytes, &point_hasher))
            .collect::<Vec<G1>>();

        Ok(PublicKey {
            w: self.w.clone(),
            h0: h[0].clone(),
            h: h[1..].to_vec(),
        })
    }

    fn hash_to_curve(&self, i: u32, mc_count: [u8; 4], hasher: &Bls12381G1Sswu) -> G1 {
        const HASH_LEN: usize = 9 + GROUP_G2_SIZE;
        let mut data = Vec::with_capacity(HASH_LEN);
        data.extend_from_slice(self.w.to_vec().as_slice());
        data.extend_from_slice(&i.to_be_bytes()[..]);
        data.push(0u8);
        data.extend_from_slice(&mc_count[..]);
        hasher
            .hash_to_curve_xmd::<sha2::Sha256>(data.as_slice())
            .unwrap()
            .0
            .into()
    }

    /// Convert the key to raw bytes
    pub fn to_bytes(&self) -> [u8; GROUP_G2_SIZE] {
        self.w.to_bytes()
    }

    /// Convert the byte slice into a public key
    pub fn from_bytes(data: [u8; GROUP_G2_SIZE]) -> Self {
        let w = G2::from(data);
        DeterministicPublicKey { w }
    }

    /// Conver the key to raw bytes in compressed form
    pub fn to_compressed_bytes(&self) -> [u8; 2 * FIELD_ORDER_ELEMENT_SIZE] {
        self.w.to_compressed_bytes()
    }
}

impl From<G2> for DeterministicPublicKey {
    fn from(w: G2) -> Self {
        DeterministicPublicKey { w }
    }
}

impl From<[u8; 2 * FIELD_ORDER_ELEMENT_SIZE]> for DeterministicPublicKey {
    fn from(data: [u8; 2 * FIELD_ORDER_ELEMENT_SIZE]) -> Self {
        Self::from(&data)
    }
}

impl From<&[u8; 2 * FIELD_ORDER_ELEMENT_SIZE]> for DeterministicPublicKey {
    fn from(data: &[u8; 2 * FIELD_ORDER_ELEMENT_SIZE]) -> Self {
        let w = G2::from(data);
        DeterministicPublicKey { w }
    }
}

/// Create a new BBS+ keypair. The generators of the public key are generated at random
pub fn generate(message_count: usize) -> Result<(PublicKey, SecretKey), BBSError> {
    if message_count == 0 {
        return Err(BBSError::from_kind(BBSErrorKind::KeyGenError));
    }
    let secret = CurveOrderElement::random();

    // Super paranoid could allow a context to generate the generator from a well known value
    // Not doing this for now since any generator in a prime field should be okay.
    let w = &G2::generator() * &secret;
    let h = (0..=message_count)
        .collect::<Vec<usize>>()
        .par_iter()
        .map(|_| G1::random())
        .collect::<Vec<G1>>();
    Ok((
        PublicKey {
            w,
            h0: h[0].clone(),
            h: h[1..].to_vec(),
        },
        secret,
    ))
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
        let bytes = public_key.to_bytes();
        assert_eq!(bytes.len(), GROUP_G1_SIZE * 2 + 4 + GROUP_G2_SIZE);

        let (public_key, _) = generate(5).unwrap();
        assert_eq!(public_key.message_count(), 5);
        //Check key doesn't contain any invalid points
        assert!(public_key.validate().is_ok());
        let bytes = public_key.to_bytes();
        assert_eq!(bytes.len(), GROUP_G1_SIZE * 6 + 4 + GROUP_G2_SIZE);
        //Check serialization is working
        let public_key_2 = PublicKey::from_bytes(bytes.as_slice()).unwrap();
        assert_eq!(public_key_2, public_key);
    }

    #[test]
    fn key_conversion() {
        let (dpk, _) = DeterministicPublicKey::new(None);
        let dst = DomainSeparationTag::new(b"TEST", None, None, None).unwrap();

        let res = dpk.to_public_key(5, dst.clone());

        assert!(res.is_ok());

        let pk = res.unwrap();
        assert_eq!(pk.message_count(), 5);

        for i in 0..pk.h.len() {
            assert_ne!(pk.h0, pk.h[i], "h[0] == h[{}]", i + 1);

            for j in (i + 1)..pk.h.len() {
                assert_ne!(pk.h[i], pk.h[j], "h[{}] == h[{}]", i + 1, j + 1);
            }
        }

        let res = dpk.to_public_key(0, dst);

        assert!(res.is_err());
    }
}
