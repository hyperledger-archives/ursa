use super::Encryptor;
use aead::{
    generic_array::{
        typenum::{Unsigned, U0, U12, U16, U32},
        GenericArray,
    },
    Aead, Error, NewAead, Payload,
};
use openssl::symm::{
    decrypt_aead as openssl_decrypt, encrypt_aead as openssl_encrypt, Cipher as OpenSslCipher,
};
#[cfg(feature = "serde")]
use serde::{de::Visitor, Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroize;

macro_rules! aes_gcm_impl {
    ($name:ident, $cipherid:ident, $keysize:ident, $visitor:ident) => {
        #[derive(Debug, Clone, Eq, PartialEq)]
        pub struct $name {
            key: GenericArray<u8, $keysize>,
        }

        impl Encryptor for $name {
            type MinSize = U32;
        }

        impl NewAead for $name {
            type KeySize = $keysize;

            fn new(key: &GenericArray<u8, Self::KeySize>) -> Self {
                Self { key: *key }
            }
        }

        impl Aead for $name {
            type NonceSize = U12;
            type TagSize = U16;
            type CiphertextOverhead = U0;

            fn encrypt<'msg, 'aad>(
                &self,
                nonce: &GenericArray<u8, Self::NonceSize>,
                plaintext: impl Into<Payload<'msg, 'aad>>,
            ) -> Result<Vec<u8>, Error> {
                let payload = plaintext.into();
                let mut tag = vec![0u8; Self::TagSize::to_usize()];

                let mut ciphertext = openssl_encrypt(
                    OpenSslCipher::$cipherid(),
                    self.key.as_slice(),
                    Some(nonce.as_slice()),
                    payload.aad,
                    payload.msg,
                    tag.as_mut_slice(),
                )
                .map_err(|_| Error)?;
                ciphertext.extend_from_slice(tag.as_slice());
                Ok(ciphertext)
            }

            fn decrypt<'msg, 'aad>(
                &self,
                nonce: &GenericArray<u8, Self::NonceSize>,
                ciphertext: impl Into<Payload<'msg, 'aad>>,
            ) -> Result<Vec<u8>, Error> {
                let payload = ciphertext.into();

                if payload.msg.len() < Self::TagSize::to_usize() + Self::NonceSize::to_usize() {
                    return Err(Error);
                }

                let tag_start = payload.msg.len() - Self::TagSize::to_usize();
                let plaintext = openssl_decrypt(
                    OpenSslCipher::$cipherid(),
                    self.key.as_slice(),
                    Some(nonce.as_slice()),
                    payload.aad,
                    &payload.msg[..tag_start],
                    &payload.msg[tag_start..],
                )
                .map_err(|_| Error)?;
                Ok(plaintext)
            }
        }

        default_impl!($name);
        drop_impl!($name);
        #[cfg(feature = "serde")]
        serialize_impl!($name, $visitor);
    };
}

aes_gcm_impl!(Aes128Gcm, aes_128_gcm, U16, Aes128GcmVisitor);
aes_gcm_impl!(Aes256Gcm, aes_256_gcm, U32, Aes256GcmVisitor);

#[cfg(test)]
mod aes128_gcm_tests {
    tests_impl!(Aes128Gcm);
}

#[cfg(test)]
mod aes256_gcm_tests {
    tests_impl!(Aes256Gcm);
}
