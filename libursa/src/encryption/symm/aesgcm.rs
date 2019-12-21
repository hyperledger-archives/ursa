use super::Encryptor;
use aead::{generic_array::GenericArray, Aead, Error, NewAead, Payload};
use aes_gcm::{Aes128Gcm as SysAes128Gcm, Aes256Gcm as SysAes256Gcm};
use generic_array::typenum::{Unsigned, U0, U12, U16, U32};
#[cfg(feature = "serialization")]
use serde::de::{Deserialize, Deserializer, Error as DError, Visitor};
#[cfg(feature = "serialization")]
use serde::ser::{Serialize, Serializer};
use zeroize::Zeroize;

macro_rules! aes_gcm_impl {
    ($name:ident, $algoname:ident, $keysize:ident, $visitor:ident) => {
        #[derive(Debug, Clone, Eq, PartialEq)]
        pub struct $name {
            key: GenericArray<u8, $keysize>,
        }

        impl Encryptor for $name {
            type MinSize = U32;
        }

        impl NewAead for $name {
            type KeySize = $keysize;

            fn new(key: GenericArray<u8, Self::KeySize>) -> Self {
                Self { key }
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
                let aes = $algoname::new(self.key);
                aes.encrypt(nonce, payload)
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

                let aes = $algoname::new(self.key);
                aes.decrypt(nonce, payload)
            }
        }

        default_impl!($name);
        drop_impl!($name);
        serialize_impl!($name, $visitor);
    };
}

aes_gcm_impl!(Aes128Gcm, SysAes128Gcm, U16, Aes128GcmVisitor);
aes_gcm_impl!(Aes256Gcm, SysAes256Gcm, U32, Aes256GcmVisitor);

#[cfg(test)]
mod aes128_gcm_tests {
    tests_impl!(Aes128Gcm);
}

#[cfg(test)]
mod aes256_gcm_tests {
    tests_impl!(Aes256Gcm);
}
