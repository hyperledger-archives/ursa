use super::Encryptor;
use aead::{
    generic_array::{
        typenum::{Unsigned, U0, U16, U32, U48, U64},
        GenericArray,
    },
    Aead, Error, NewAead, Payload,
};
use openssl::{
    hash::MessageDigest,
    memcmp,
    pkey::PKey,
    sign::Signer,
    symm::{decrypt as openssl_decrypt, encrypt as openssl_encrypt, Cipher as OpenSslCipher},
};
#[cfg(feature = "serde")]
use serde::{de::Visitor, Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroize;

macro_rules! aes_cbc_hmac_impl {
    ($name:ident, $cipherid:ident, $keysize:ident, $noncesize:ident, $tagsize:ident, $macid:ident, $visitor:ident) => {
        #[derive(Debug, Clone, Eq, PartialEq)]
        pub struct $name {
            key: GenericArray<u8, $keysize>,
        }

        impl Encryptor for $name {
            type MinSize = U48;
        }

        impl NewAead for $name {
            type KeySize = $keysize;

            fn new(key: &GenericArray<u8, Self::KeySize>) -> Self {
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
                let cipher = OpenSslCipher::$cipherid();

                let mut ciphertext = openssl_encrypt(
                    cipher,
                    &self.key[..cipher.key_len()],
                    Some(nonce.as_slice()),
                    payload.msg,
                )
                .map_err(|_| Error)?;

                let sslkey = PKey::hmac(&self.key[cipher.key_len()..]).map_err(|_| Error)?;
                let mut hmac = Signer::new(MessageDigest::$macid(), &sslkey).map_err(|_| Error)?;

                hmac.update(payload.aad).map_err(|_| Error)?;
                hmac.update(nonce.as_slice()).map_err(|_| Error)?;
                hmac.update(ciphertext.as_slice()).map_err(|_| Error)?;
                let mac = hmac.sign_to_vec().map_err(|_| Error)?;
                ciphertext.extend_from_slice(mac.as_slice());
                Ok(ciphertext)
            }

            fn decrypt<'msg, 'aad>(
                &self,
                nonce: &GenericArray<u8, Self::NonceSize>,
                ciphertext: impl Into<Payload<'msg, 'aad>>,
            ) -> Result<Vec<u8>, Error> {
                let payload = ciphertext.into();
                let cipher = OpenSslCipher::$cipherid();

                if payload.msg.len() < Self::TagSize::to_usize() + cipher.key_len() {
                    return Err(Error);
                }

                let tag_start = payload.msg.len() - Self::TagSize::to_usize();
                let buffer = Vec::from(&payload.msg[..tag_start]);
                let tag = Vec::from(&payload.msg[tag_start..]);
                let sslkey = PKey::hmac(&self.key[cipher.key_len()..]).map_err(|_| Error)?;
                let mut hmac = Signer::new(MessageDigest::$macid(), &sslkey).map_err(|_| Error)?;
                hmac.update(payload.aad).map_err(|_| Error)?;
                hmac.update(nonce.as_slice()).map_err(|_| Error)?;
                hmac.update(buffer.as_slice()).map_err(|_| Error)?;
                let mac = hmac.sign_to_vec().map_err(|_| Error)?;
                if memcmp::eq(&mac, &tag) {
                    let plaintext = openssl_decrypt(
                        cipher,
                        &self.key[..cipher.key_len()],
                        Some(nonce.as_slice()),
                        buffer.as_slice(),
                    )
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
    aes_128_cbc,
    U32,
    U16,
    U32,
    sha256,
    Aes128CbcHmac256Visitor
);
aes_cbc_hmac_impl!(
    Aes256CbcHmac512,
    aes_256_cbc,
    U64,
    U16,
    U64,
    sha512,
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
