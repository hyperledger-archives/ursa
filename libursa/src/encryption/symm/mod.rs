//! A suite of Authenticated Encryption with Associated Data (AEAD) cryptographic ciphers.
//!
//! Provided are three different ciphers: AES-CBC-HMAC, AES-GCM, and XCHACHA20-POLY1305.
//! Each cipher can be built using a native mode which allows some of them
//! to take advantage of high performance AES-NI and CLMUL CPU intrinsics
//! or software implementations.
//!
//! When going to server or targeted mobile platforms, it is preferred to use native mode.
//! When targeting web based solutions, use `portable` mode which allows for builds to
//! wasm.
//!
//! Each AEAD algorithm provides `encrypt_easy` and `decrypt_easy` methods which hides the complexity
//! of generating a secure nonce of appropriate size with the ciphertext.
//! The `encrypt_easy` prepends the nonce to the front of the ciphertext and `decrypt_easy` expects
//! the nonce to be prepended to the front of the ciphertext.
//!
//! More advanced users may use `encrypt` and `decrypt` directly. These two methods require the
//! caller to supply a nonce with sufficient entropy and should never be reused when encrypting
//! with the same `key`.
//!
//! The convenience struct `SymmetricEncryptor` exists to allow users to easily switch between
//! algorithms by using any algorithm that implements the `Encryptor` trait.
//!
//! AES-CBC-HMAC uses OpenSSL for native mode and the crates `aes`, `block_modes`, `hmac`, `sha2`, `subtle` for portable mode.
//! The `aes` crate allows for taking advantage of AES-NI instrinsics by using the following `RUSTFLAGS`
//!
//! ```text
//! RUSTFLAGS="-Ctarget-cpu=sandybridge -Ctarget-feature=+aes,+sse2,+sse4.1,+ssse3"
//! ```
//!
//! AES-GCM uses OpenSSL for native mode and the crate `aes-gcm` for portable mode.
//! XCHACHA20POLY1305 uses Libsodium for native mode and the crate `chacha20poly1305` for portable mode.
//!
//! More ciphers will added as needed like AES-GCM-SIV or [XCHACHA20POLY1305-SIV](https://tools.ietf.org/id/draft-madden-generalised-siv-00.html)
//! where using poly1305 instead of HMAC might be appropriate.

use super::random_bytes;
use aead::{
    generic_array::{typenum::Unsigned, ArrayLength, GenericArray},
    Aead, Error, NewAead, Payload,
};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::str::FromStr;

#[cfg(feature = "serde")]
macro_rules! serialize_impl {
    ($name:ident, $serializevisitor:ident) => {
        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_newtype_struct(
                    stringify!($name),
                    hex::encode(&self.key.as_slice()).as_str(),
                )
            }
        }

        impl<'a> Deserialize<'a> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'a>,
            {
                struct $serializevisitor;

                impl<'a> Visitor<'a> for $serializevisitor {
                    type Value = $name;

                    fn expecting(
                        &self,
                        formatter: &mut ::std::fmt::Formatter,
                    ) -> ::std::fmt::Result {
                        formatter.write_str(stringify!($name))
                    }

                    fn visit_str<E>(self, value: &str) -> Result<$name, E>
                    where
                        E: serde::de::Error,
                    {
                        let key = hex::decode(value).map_err(E::custom)?;
                        Ok($name::new(GenericArray::from_slice(key.as_slice())))
                    }
                }

                deserializer.deserialize_str($serializevisitor)
            }
        }
    };
}

macro_rules! drop_impl {
    ($structname:ident) => {
        impl Zeroize for $structname {
            fn zeroize(&mut self) {
                self.key.as_mut_slice().zeroize();
            }
        }

        impl Drop for $structname {
            fn drop(&mut self) {
                self.zeroize();
            }
        }
    };
}

macro_rules! default_impl {
    ($name:ident) => {
        impl Default for $name {
            fn default() -> Self {
                $name::new(&$name::key_gen().unwrap())
            }
        }
    };
}

/// A generic symmetric encryption wrapper
///
/// # Usage
///
/// ```
/// extern crate ursa;
/// use ursa::encryption::symm::prelude::*;
///
/// let encryptor = SymmetricEncryptor::<Aes128Gcm>::default();
/// let aad = b"Using Aes128Gcm to encrypt data";
/// let message = b"Hidden message";
/// let res = encryptor.encrypt_easy(aad.as_ref(), message.as_ref());
/// assert!(res.is_ok());
///
/// let ciphertext = res.unwrap();
/// let res = encryptor.decrypt_easy(aad.as_ref(), ciphertext.as_slice());
/// assert!(res.is_ok());
/// assert_eq!(res.unwrap().as_slice(), message);
/// ```
#[derive(Debug)]
pub struct SymmetricEncryptor<E: Encryptor> {
    encryptor: E,
}

impl<E: Encryptor> SymmetricEncryptor<E> {
    pub fn new(encryptor: E) -> Self {
        Self { encryptor }
    }

    pub fn new_with_key<A: AsRef<[u8]>>(key: A) -> Result<Self, Error> {
        Ok(Self {
            encryptor: <E as NewAead>::new(GenericArray::from_slice(key.as_ref())),
        })
    }

    // Encrypt `plaintext` and integrity protect `aad`. The result is the ciphertext.
    // This method handles safely generating a `nonce` and prepends it to the ciphertext
    pub fn encrypt_easy<A: AsRef<[u8]>>(&self, aad: A, plaintext: A) -> Result<Vec<u8>, Error> {
        self.encryptor.encrypt_easy(aad, plaintext)
    }

    // Encrypt `plaintext` and integrity protect `aad`. The result is the ciphertext.
    pub fn encrypt<A: AsRef<[u8]>>(
        &self,
        nonce: A,
        aad: A,
        plaintext: A,
    ) -> Result<Vec<u8>, Error> {
        let nonce = GenericArray::from_slice(nonce.as_ref());
        let payload = Payload {
            msg: plaintext.as_ref(),
            aad: aad.as_ref(),
        };
        self.encryptor.encrypt(nonce, payload)
    }

    // Decrypt `ciphertext` using integrity protected `aad`. The result is the plaintext if successful
    // or an error if the `ciphetext` cannot be decrypted due to tampering, an incorrect `aad` value,
    // or incorrect key.
    // `aad` must be the same value used in `encrypt_easy`. Expects the nonce to be prepended to
    // the `ciphertext`
    pub fn decrypt_easy<A: AsRef<[u8]>>(&self, aad: A, ciphertext: A) -> Result<Vec<u8>, Error> {
        self.encryptor.decrypt_easy(aad, ciphertext)
    }

    // Decrypt `ciphertext` using integrity protected `aad`. The result is the plaintext if successful
    // or an error if the `ciphetext` cannot be decrypted due to tampering, an incorrect `aad` value,
    // or incorrect key.
    // `aad` must be the same value used in `encrypt_easy`.
    pub fn decrypt<A: AsRef<[u8]>>(
        &self,
        nonce: A,
        aad: A,
        ciphertext: A,
    ) -> Result<Vec<u8>, Error> {
        let nonce = GenericArray::from_slice(nonce.as_ref());
        let payload = Payload {
            msg: ciphertext.as_ref(),
            aad: aad.as_ref(),
        };
        self.encryptor.decrypt(nonce, payload)
    }

    // Similar to `encrypt_easy` but reads from a stream instead of a slice
    pub fn encrypt_buffer<A: AsRef<[u8]>, I: Read, O: Write>(
        &self,
        aad: A,
        plaintext: &mut I,
        ciphertext: &mut O,
    ) -> Result<(), Error> {
        self.encryptor.encrypt_buffer(aad, plaintext, ciphertext)
    }

    // Similar to `decrypt_easy` but reads from a stream instead of a slice
    pub fn decrypt_buffer<A: AsRef<[u8]>, I: Read, O: Write>(
        &self,
        aad: A,
        ciphertext: &mut I,
        plaintext: &mut O,
    ) -> Result<(), Error> {
        self.encryptor.decrypt_buffer(aad, ciphertext, plaintext)
    }
}

impl<E: Encryptor + Default> Default for SymmetricEncryptor<E> {
    fn default() -> Self {
        SymmetricEncryptor {
            encryptor: E::default(),
        }
    }
}

/// Generic encryptor trait that all ciphers should extend.
pub trait Encryptor: Aead + NewAead {
    /// The minimum size that the ciphertext will yield from plaintext
    type MinSize: ArrayLength<u8>;

    fn encrypt_easy<M: AsRef<[u8]>>(&self, aad: M, plaintext: M) -> Result<Vec<u8>, Error> {
        let nonce = Self::nonce_gen()?;
        let payload = Payload {
            msg: plaintext.as_ref(),
            aad: aad.as_ref(),
        };
        let ciphertext = self.encrypt(&nonce, payload)?;
        let mut result = nonce.to_vec();
        result.extend_from_slice(ciphertext.as_slice());
        Ok(result)
    }

    fn decrypt_easy<M: AsRef<[u8]>>(&self, aad: M, ciphertext: M) -> Result<Vec<u8>, Error> {
        let ciphertext = ciphertext.as_ref();
        if ciphertext.len() < Self::MinSize::to_usize() {
            return Err(Error);
        }

        let nonce = GenericArray::from_slice(&ciphertext[..Self::NonceSize::to_usize()]);
        let payload = Payload {
            msg: &ciphertext[Self::NonceSize::to_usize()..],
            aad: aad.as_ref(),
        };
        let plaintext = self.decrypt(&nonce, payload)?;
        Ok(plaintext)
    }

    fn encrypt_buffer<M: AsRef<[u8]>, I: Read, O: Write>(
        &self,
        aad: M,
        plaintext: &mut I,
        ciphertext: &mut O,
    ) -> Result<(), Error> {
        let p = read_buffer(plaintext)?;
        let c = self.encrypt_easy(aad.as_ref(), p.as_slice())?;
        ciphertext.write_all(c.as_slice()).map_err(|_| Error)?;
        Ok(())
    }

    fn decrypt_buffer<M: AsRef<[u8]>, I: Read, O: Write>(
        &self,
        aad: M,
        ciphertext: &mut I,
        plaintext: &mut O,
    ) -> Result<(), Error> {
        let c = read_buffer(ciphertext)?;
        let p = self.decrypt_easy(aad.as_ref(), c.as_slice())?;
        plaintext.write_all(p.as_slice()).map_err(|_| Error)?;
        Ok(())
    }

    fn key_gen() -> Result<GenericArray<u8, Self::KeySize>, Error> {
        random_bytes()
    }

    fn nonce_gen() -> Result<GenericArray<u8, Self::NonceSize>, Error> {
        random_bytes()
    }
}

/// The `DynEncryptor` trait is a modification of `Encryptor` trait suitable
/// for trait objects as used in `EncryptorType::gen_encryptor`.
pub trait DynEncryptor {
    fn keysize(&self) -> usize;
    fn noncesize(&self) -> usize;
    fn encrypt_easy(&self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error>;
    fn encrypt(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error>;
    fn decrypt_easy(&self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error>;
    fn decrypt(&self, nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error>;
}

impl<D: Encryptor> DynEncryptor for D {
    fn keysize(&self) -> usize {
        <Self as NewAead>::KeySize::to_usize()
    }

    fn noncesize(&self) -> usize {
        <Self as Aead>::NonceSize::to_usize()
    }

    fn encrypt_easy(&self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        self.encrypt_easy(aad, plaintext)
    }

    fn encrypt(&self, nonce: &[u8], aad: &[u8], msg: &[u8]) -> Result<Vec<u8>, Error> {
        let nonce = GenericArray::clone_from_slice(nonce);
        let payload = Payload { msg, aad };
        self.encrypt(&nonce, payload)
    }

    fn decrypt_easy(&self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        self.decrypt_easy(aad, ciphertext)
    }

    fn decrypt(&self, nonce: &[u8], aad: &[u8], msg: &[u8]) -> Result<Vec<u8>, Error> {
        let nonce = GenericArray::clone_from_slice(nonce);
        let payload = Payload { msg, aad };
        self.decrypt(&nonce, payload)
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum EncryptorType {
    #[cfg(any(feature = "aescbc", feature = "aescbc_native"))]
    Aes128CbcHmac256,
    #[cfg(any(feature = "aescbc", feature = "aescbc_native"))]
    Aes256CbcHmac512,
    #[cfg(any(feature = "aesgcm", feature = "aesgcm_native"))]
    Aes128Gcm,
    #[cfg(any(feature = "aesgcm", feature = "aesgcm_native"))]
    Aes256Gcm,
    #[cfg(any(feature = "chacha20poly1305", feature = "chacha20poly1305_native"))]
    XChaCha20Poly1305,
}

impl EncryptorType {
    pub fn is_valid_keysize(self, size: usize) -> bool {
        match self {
            #[cfg(any(feature = "aescbc", feature = "aescbc_native"))]
            EncryptorType::Aes128CbcHmac256 => {
                size == <aescbc::Aes128CbcHmac256 as NewAead>::KeySize::to_usize()
            }
            #[cfg(any(feature = "aescbc", feature = "aescbc_native"))]
            EncryptorType::Aes256CbcHmac512 => {
                size == <aescbc::Aes256CbcHmac512 as NewAead>::KeySize::to_usize()
            }
            #[cfg(any(feature = "aesgcm", feature = "aesgcm_native"))]
            EncryptorType::Aes128Gcm => size == <aesgcm::Aes128Gcm as NewAead>::KeySize::to_usize(),
            #[cfg(any(feature = "aesgcm", feature = "aesgcm_native"))]
            EncryptorType::Aes256Gcm => size == <aesgcm::Aes256Gcm as NewAead>::KeySize::to_usize(),
            #[cfg(any(feature = "chacha20poly1305", feature = "chacha20poly1305_native"))]
            EncryptorType::XChaCha20Poly1305 => {
                size == <xchacha20poly1305::XChaCha20Poly1305 as NewAead>::KeySize::to_usize()
            }
        }
    }

    pub fn is_valid_noncesize(self, size: usize) -> bool {
        match self {
            #[cfg(any(feature = "aescbc", feature = "aescbc_native"))]
            EncryptorType::Aes128CbcHmac256 => {
                size == <aescbc::Aes128CbcHmac256 as Aead>::NonceSize::to_usize()
            }
            #[cfg(any(feature = "aescbc", feature = "aescbc_native"))]
            EncryptorType::Aes256CbcHmac512 => {
                size == <aescbc::Aes256CbcHmac512 as Aead>::NonceSize::to_usize()
            }
            #[cfg(any(feature = "aesgcm", feature = "aesgcm_native"))]
            EncryptorType::Aes128Gcm => size == <aesgcm::Aes128Gcm as Aead>::NonceSize::to_usize(),
            #[cfg(any(feature = "aesgcm", feature = "aesgcm_native"))]
            EncryptorType::Aes256Gcm => size == <aesgcm::Aes256Gcm as Aead>::NonceSize::to_usize(),
            #[cfg(any(feature = "chacha20poly1305", feature = "chacha20poly1305_native"))]
            EncryptorType::XChaCha20Poly1305 => {
                size == <xchacha20poly1305::XChaCha20Poly1305 as Aead>::NonceSize::to_usize()
            }
        }
    }

    pub fn gen_encryptor<A: AsRef<[u8]>>(self, key: A) -> Box<dyn DynEncryptor> {
        match self {
            #[cfg(any(feature = "aescbc", feature = "aescbc_native"))]
            EncryptorType::Aes128CbcHmac256 => Box::new(aescbc::Aes128CbcHmac256::new(
                GenericArray::from_slice(key.as_ref()),
            )),
            #[cfg(any(feature = "aescbc", feature = "aescbc_native"))]
            EncryptorType::Aes256CbcHmac512 => Box::new(aescbc::Aes256CbcHmac512::new(
                GenericArray::from_slice(key.as_ref()),
            )),
            #[cfg(any(feature = "aesgcm", feature = "aesgcm_native"))]
            EncryptorType::Aes128Gcm => Box::new(aesgcm::Aes128Gcm::new(GenericArray::from_slice(
                key.as_ref(),
            ))),
            #[cfg(any(feature = "aesgcm", feature = "aesgcm_native"))]
            EncryptorType::Aes256Gcm => Box::new(aesgcm::Aes256Gcm::new(GenericArray::from_slice(
                key.as_ref(),
            ))),
            #[cfg(any(feature = "chacha20poly1305", feature = "chacha20poly1305_native"))]
            EncryptorType::XChaCha20Poly1305 => Box::new(
                xchacha20poly1305::XChaCha20Poly1305::new(GenericArray::from_slice(key.as_ref())),
            ),
        }
    }
}

impl FromStr for EncryptorType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            #[cfg(any(feature = "aescbc", feature = "aescbc_native"))]
            "aes-128-cbc-hmac-256" => Ok(EncryptorType::Aes128CbcHmac256),
            #[cfg(any(feature = "aescbc", feature = "aescbc_native"))]
            "aes-256-cbc-hmac-512" => Ok(EncryptorType::Aes256CbcHmac512),
            #[cfg(any(feature = "aesgcm", feature = "aesgcm_native"))]
            "aes-128-gcm" => Ok(EncryptorType::Aes128Gcm),
            #[cfg(any(feature = "aesgcm", feature = "aesgcm_native"))]
            "aes-256-gcm" => Ok(EncryptorType::Aes256Gcm),
            #[cfg(any(feature = "chacha20poly1305", feature = "chacha20poly1305_native"))]
            "xchacha20poly1305" => Ok(EncryptorType::XChaCha20Poly1305),
            _ => Err(format!("Invalid type: {}", s)),
        }
    }
}

impl std::fmt::Display for EncryptorType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let s = match *self {
            #[cfg(any(feature = "aescbc", feature = "aescbc_native"))]
            EncryptorType::Aes128CbcHmac256 => "aes-128-cbc-hmac-256",
            #[cfg(any(feature = "aescbc", feature = "aescbc_native"))]
            EncryptorType::Aes256CbcHmac512 => "aes-256-cbc-hmac-512",
            #[cfg(any(feature = "aesgcm", feature = "aesgcm_native"))]
            EncryptorType::Aes128Gcm => "aes-128-gcm",
            #[cfg(any(feature = "aesgcm", feature = "aesgcm_native"))]
            EncryptorType::Aes256Gcm => "aes-256-gcm",
            #[cfg(any(feature = "chacha20poly1305", feature = "chacha20poly1305_native"))]
            EncryptorType::XChaCha20Poly1305 => "xchacha20poly1305",
        };
        write!(f, "{}", s)
    }
}

fn read_buffer<I: Read>(buffer: &mut I) -> Result<Vec<u8>, Error> {
    let mut v = Vec::new();
    let bytes_read = buffer.read_to_end(&mut v).map_err(|_| Error)?;
    v.truncate(bytes_read);
    Ok(v)
}

#[cfg(test)]
macro_rules! tests_impl {
    ($name:ident) => {
        use super::*;
        use bytebuffer::ByteBuffer;

        #[test]
        fn encrypt_easy_works() {
            let aes = $name::default();
            let aad = Vec::new();
            let message = b"Hello and Goodbye!".to_vec();
            let res = aes.encrypt_easy(&aad, &message);
            assert!(res.is_ok());
            let ciphertext = res.unwrap();
            let res = aes.decrypt_easy(&aad, &ciphertext);
            assert!(res.is_ok());
            assert_eq!(message, res.unwrap());
        }

        #[test]
        fn encrypt_works() {
            let aes = $name::default();
            let nonce = $name::nonce_gen().unwrap();
            let aad = b"encrypt test".to_vec();
            let message = b"Hello and Goodbye!".to_vec();
            let payload = Payload { msg: message.as_slice(), aad: aad.as_slice() };
            let res = aes.encrypt(&nonce, payload);
            assert!(res.is_ok());
            let ciphertext = res.unwrap();
            let payload = Payload { msg: ciphertext.as_slice(), aad: aad.as_slice() };
            let res = aes.decrypt(&nonce, payload);
            assert!(res.is_ok());
            assert_eq!(message, res.unwrap());
        }

        #[test]
        fn decrypt_should_fail() {
            let aes = $name::default();
            let aad = b"decrypt should fail".to_vec();
            let message = b"Hello and Goodbye!".to_vec();
            let res = aes.encrypt_easy(&aad, &message);
            assert!(res.is_ok());
            let mut ciphertext = res.unwrap();

            let aad = b"decrypt should succeed".to_vec();
            let res = aes.decrypt_easy(&aad, &ciphertext);
            assert!(res.is_err());

            let aad = b"decrypt should fail".to_vec();
            ciphertext[0] ^= ciphertext[1];
            let res = aes.decrypt_easy(&aad, &ciphertext);
            assert!(res.is_err());
        }

        #[test]
        fn buffer_works() {
            let aes = $name::default();
            let aad = b"buffer works".to_vec();
            let dummytext = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";
            let mut buffer = ByteBuffer::from_bytes(&dummytext[..]);
            let mut ciphertext = Vec::new();
            let res = aes.encrypt_buffer(&aad, &mut buffer, &mut ciphertext);
            assert!(res.is_ok());
            let mut cipher_buffer = ByteBuffer::from_bytes(ciphertext.as_slice());
            let mut plaintext = Vec::new();
            let res = aes.decrypt_buffer(&aad, &mut cipher_buffer, &mut plaintext);
            assert!(res.is_ok());
            assert_eq!(dummytext.to_vec(), plaintext);
        }

        #[cfg(feature = "serde")]
        #[test]
        fn serialization() {
            let aes = $name::default();
            let serialized = serde_json::to_string(&aes).unwrap();
            let deserialized: $name = serde_json::from_str(&serialized).unwrap();
            assert_eq!(aes, deserialized);
        }

        #[test]
        fn zeroed_on_drop() {
            let mut aes = $name::new(&$name::key_gen().unwrap());
            aes.zeroize();

            fn as_bytes<T>(x: &T) -> &[u8] {
                use std::mem;
                use std::slice;

                unsafe {
                    slice::from_raw_parts(x as *const T as *const u8, mem::size_of_val(x))
                }
            }

            assert!(as_bytes(&aes.key).iter().all(|b| *b == 0u8));
        }
    };
}

#[cfg(feature = "aescbc_native")]
#[path = "aescbc_asm.rs"]
pub mod aescbc;
#[cfg(feature = "aescbc")]
#[path = "aescbc.rs"]
pub mod aescbc;

#[cfg(feature = "aesgcm_native")]
#[path = "aesgcm_asm.rs"]
pub mod aesgcm;
#[cfg(feature = "aesgcm")]
#[path = "aesgcm.rs"]
pub mod aesgcm;

#[cfg(feature = "chacha20poly1305_native")]
#[path = "chacha20poly1305_asm.rs"]
pub mod chacha20poly1305;

#[cfg(feature = "chacha20poly1305")]
#[path = "chacha20poly1305.rs"]
pub mod chacha20poly1305;

#[cfg(feature = "chacha20poly1305_native")]
#[path = "xchacha20poly1305_asm.rs"]
pub mod xchacha20poly1305;

#[cfg(feature = "chacha20poly1305")]
#[path = "xchacha20poly1305.rs"]
pub mod xchacha20poly1305;

pub mod prelude {
    #[cfg(any(feature = "aescbc", feature = "aescbc_native"))]
    pub use super::aescbc::{Aes128CbcHmac256, Aes256CbcHmac512};
    #[cfg(any(feature = "aesgcm", feature = "aesgcm_native"))]
    pub use super::aesgcm::{Aes128Gcm, Aes256Gcm};
    #[cfg(any(feature = "chacha20poly1305", feature = "chacha20poly1305_native"))]
    pub use super::chacha20poly1305::ChaCha20Poly1305;
    #[cfg(any(feature = "chacha20poly1305", feature = "chacha20poly1305_native"))]
    pub use super::xchacha20poly1305::XChaCha20Poly1305;
    pub use super::{DynEncryptor, Encryptor, EncryptorType, SymmetricEncryptor};
}
