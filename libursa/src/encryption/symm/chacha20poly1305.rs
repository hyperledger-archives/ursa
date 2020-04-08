use super::Encryptor;
use aead::{
    generic_array::{
        typenum::{U0, U12, U16, U32, U36},
        GenericArray,
    },
    Aead, Error, NewAead, Payload,
};
use rustchacha20poly1305::ChaCha20Poly1305 as SysChaCha20Poly1305;
#[cfg(feature = "serde")]
use serde::{de::Visitor, Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroize;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ChaCha20Poly1305 {
    key: GenericArray<u8, U32>,
}

impl Encryptor for ChaCha20Poly1305 {
    type MinSize = U36;
}

impl NewAead for ChaCha20Poly1305 {
    type KeySize = U32;

    fn new(key: GenericArray<u8, Self::KeySize>) -> Self {
        Self { key }
    }
}

impl Aead for ChaCha20Poly1305 {
    type NonceSize = U12;
    type TagSize = U16;
    type CiphertextOverhead = U0;

    fn encrypt<'msg, 'aad>(
        &self,
        nonce: &GenericArray<u8, Self::NonceSize>,
        plaintext: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<Vec<u8>, Error> {
        let aead = SysChaCha20Poly1305::new(self.key.clone());
        let ciphertext = aead.encrypt(nonce, plaintext)?;
        Ok(ciphertext)
    }

    fn decrypt<'msg, 'aad>(
        &self,
        nonce: &GenericArray<u8, Self::NonceSize>,
        ciphertext: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<Vec<u8>, Error> {
        let aead = SysChaCha20Poly1305::new(self.key.clone());
        let plaintext = aead.decrypt(nonce, ciphertext)?;
        Ok(plaintext)
    }

    // TODO
    fn encrypt_in_place_detached(
        &self,
        _nonce: &GenericArray<u8, Self::NonceSize>,
        _associated_data: &[u8],
        _buffer: &mut [u8],
    ) -> Result<GenericArray<u8, Self::TagSize>, Error> {
        unimplemented!();
    }

    // TODO
    fn decrypt_in_place_detached(
        &self,
        _nonce: &GenericArray<u8, Self::NonceSize>,
        _associated_data: &[u8],
        _buffer: &mut [u8],
        _tag: &GenericArray<u8, Self::TagSize>,
    ) -> Result<(), Error> {
        unimplemented!();
    }
}

default_impl!(ChaCha20Poly1305);
drop_impl!(ChaCha20Poly1305);
#[cfg(feature = "serde")]
serialize_impl!(ChaCha20Poly1305, ChaCha20Poly1305Visitor);

#[cfg(test)]
mod tests {
    tests_impl!(ChaCha20Poly1305);
}
