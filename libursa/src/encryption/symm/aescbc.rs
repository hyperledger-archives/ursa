use super::Encryptor;
use aead::{
    generic_array::{
        typenum::{Unsigned, U0, U16, U32, U48, U64},
        GenericArray,
    },
    Aead, Error, NewAead, Payload,
};
use aes::{Aes128, Aes256};
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};
use hmac::{Hmac, Mac, NewMac};
#[cfg(feature = "serde")]
use serde::{de::Visitor, Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Sha256, Sha512};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

type Aes128Cbc = Cbc<Aes128, Pkcs7>;
type Aes256Cbc = Cbc<Aes256, Pkcs7>;
type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

macro_rules! aes_cbc_hmac_impl {
    ($name:ident, $algokeysize:ident, $keysize:ident, $noncesize:ident, $tagsize:ident, $algo:ident, $hash:ident, $visitor:ident) => {
        #[derive(Debug, Clone, Eq, PartialEq)]
        pub struct $name {
            key: GenericArray<u8, $keysize>,
        }

        impl Encryptor for $name {
            type MinSize = U48;
        }

        impl NewAead for $name {
            type KeySize = $keysize;

            fn new(key: &GenericArray<u8, $keysize>) -> Self {
                Self { key: *key }
            }
        }

        impl Aead for $name {
            type NonceSize = $noncesize;
            type TagSize = $tagsize;
            type CiphertextOverhead = U0;

            fn encrypt<'msg, 'aad>(
                &self,
                nonce: &GenericArray<u8, Self::NonceSize>,
                plaintext: impl Into<Payload<'msg, 'aad>>,
            ) -> Result<Vec<u8>, Error> {
                let payload = plaintext.into();
                let encryptor =
                    $algo::new_var(&self.key[..$algokeysize::to_usize()], &nonce.as_slice())
                        .map_err(|_| Error)?;
                let mut ciphertext = encryptor.encrypt_vec(payload.msg);
                let mut hmac = $hash::new_from_slice(&self.key[$algokeysize::to_usize()..])
                    .map_err(|_| Error)?;
                hmac.update(payload.aad);
                hmac.update(nonce.as_slice());
                hmac.update(ciphertext.as_slice());
                let hash = hmac.finalize().into_bytes();
                ciphertext.extend_from_slice(hash.as_slice());
                Ok(ciphertext)
            }

            fn decrypt<'msg, 'aad>(
                &self,
                nonce: &GenericArray<u8, Self::NonceSize>,
                ciphertext: impl Into<Payload<'msg, 'aad>>,
            ) -> Result<Vec<u8>, Error> {
                let payload = ciphertext.into();

                if payload.msg.len() < Self::TagSize::to_usize() + $algokeysize::to_usize() {
                    return Err(Error);
                }

                let tag_start = payload.msg.len() - Self::TagSize::to_usize();
                let buffer = Vec::from(&payload.msg[..tag_start]);
                let tag = Vec::from(&payload.msg[tag_start..]);

                let mut hmac = $hash::new_from_slice(&self.key[$algokeysize::to_usize()..])
                    .map_err(|_| Error)?;
                hmac.update(payload.aad);
                hmac.update(nonce.as_slice());
                hmac.update(buffer.as_slice());
                let expected_tag = hmac.finalize().into_bytes();

                if expected_tag.ct_eq(&tag).unwrap_u8() == 1 {
                    let decryptor =
                        $algo::new_var(&self.key[..$algokeysize::to_usize()], &nonce.as_slice())
                            .map_err(|_| Error)?;
                    let plaintext = decryptor
                        .decrypt_vec(buffer.as_slice())
                        .map_err(|_| Error)?;
                    Ok(plaintext)
                } else {
                    Err(Error)
                }
            }
        }

        default_impl!($name);
        drop_impl!($name);
        #[cfg(feature = "serde")]
        serialize_impl!($name, $visitor);
    };
}

aes_cbc_hmac_impl!(
    Aes128CbcHmac256,
    U16,
    U32,
    U16,
    U32,
    Aes128Cbc,
    HmacSha256,
    Aes128CbcHmac256Visitor
);
aes_cbc_hmac_impl!(
    Aes256CbcHmac512,
    U32,
    U64,
    U16,
    U64,
    Aes256Cbc,
    HmacSha512,
    Aes256CbcHmac512Visitor
);

#[cfg(test)]
mod aes128_cbc_hmac256_tests {
    tests_impl!(Aes128CbcHmac256);
}

#[cfg(test)]
mod aes256_cbc_hmac512_tests {
    tests_impl!(Aes256CbcHmac512);
}
