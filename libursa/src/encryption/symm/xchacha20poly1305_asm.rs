use super::Encryptor;
use aead::{
    generic_array::{
        typenum::{Unsigned, U0, U16, U24, U32, U48},
        GenericArray,
    },
    Aead, Error, NewAead, Payload,
};
#[cfg(feature = "serde")]
use serde::{de::Visitor, Deserialize, Deserializer, Serialize, Serializer};
use std::{
    os::raw,
    ptr,
    sync::atomic::{AtomicBool, Ordering},
};
use zeroize::Zeroize;

lazy_static! {
    static ref INIT: AtomicBool = AtomicBool::new(false);
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct XChaCha20Poly1305 {
    key: GenericArray<u8, U32>,
}

impl Encryptor for XChaCha20Poly1305 {
    type MinSize = U48;
}

impl NewAead for XChaCha20Poly1305 {
    type KeySize = U32;

    fn new(key: GenericArray<u8, Self::KeySize>) -> Self {
        if !INIT.load(Ordering::Relaxed) {
            INIT.store(true, Ordering::Release);
            unsafe {
                libsodium_ffi::sodium_init();
            }
        }
        Self { key }
    }
}

impl Aead for XChaCha20Poly1305 {
    type NonceSize = U24;
    type TagSize = U16;
    type CiphertextOverhead = U0;

    fn encrypt<'msg, 'aad>(
        &self,
        nonce: &GenericArray<u8, Self::NonceSize>,
        plaintext: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<Vec<u8>, Error> {
        let payload = plaintext.into();
        let mut ciphertext = Vec::with_capacity(payload.msg.len() + Self::TagSize::to_usize());
        let mut clen = ciphertext.len() as raw::c_ulonglong;

        unsafe {
            libsodium_ffi::crypto_aead_xchacha20poly1305_ietf_encrypt(
                ciphertext.as_mut_ptr(),
                &mut clen,
                payload.msg.as_ptr(),
                payload.msg.len() as raw::c_ulonglong,
                payload.aad.as_ptr(),
                payload.aad.len() as raw::c_ulonglong,
                ptr::null_mut(),
                nonce.as_slice().as_ptr(),
                self.key.as_slice().as_ptr(),
            );
            ciphertext.set_len(clen as usize);
        }
        Ok(ciphertext)
    }

    fn decrypt<'msg, 'aad>(
        &self,
        nonce: &GenericArray<u8, Self::NonceSize>,
        ciphertext: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<Vec<u8>, Error> {
        let payload = ciphertext.into();
        if payload.msg.len() < Self::TagSize::to_usize() {
            return Err(Error);
        }
        let mut plaintext = Vec::with_capacity(payload.msg.len() - Self::TagSize::to_usize());
        let mut plen = plaintext.len() as raw::c_ulonglong;

        unsafe {
            let res = libsodium_ffi::crypto_aead_xchacha20poly1305_ietf_decrypt(
                plaintext.as_mut_ptr(),
                &mut plen,
                ptr::null_mut(),
                payload.msg.as_ptr(),
                payload.msg.len() as raw::c_ulonglong,
                payload.aad.as_ptr(),
                payload.aad.len() as raw::c_ulonglong,
                nonce.as_slice().as_ptr(),
                self.key.as_slice().as_ptr(),
            );
            if res != 0 {
                return Err(Error);
            }
            plaintext.set_len(plen as usize);
        }
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

default_impl!(XChaCha20Poly1305);
drop_impl!(XChaCha20Poly1305);
#[cfg(feature = "serde")]
serialize_impl!(XChaCha20Poly1305, XChaCha20Poly1305Visitor);
#[cfg(test)]
mod tests {
    tests_impl!(XChaCha20Poly1305);
}
