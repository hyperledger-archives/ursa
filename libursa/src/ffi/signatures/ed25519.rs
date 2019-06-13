//! FFI functions to the ed25519 signatures
//!
//! Example of how to use these functions from C
//! #include <stdio.h>
//! #include <stdlib.h>
//! #include <string.h>
//! #include "ursa_crypto.h"
//! 
//! int main(void) {
//!     struct ByteBuffer* public_key;
//!     struct ByteBuffer* private_key;
//!     struct ByteBuffer* seed;
//!     struct ByteBuffer* message;
//!     struct ByteBuffer* signature;
//!     struct ExternError* err;
//!     int i;
//! 
//!     public_key = malloc(sizeof(struct ByteBuffer));
//!     private_key = malloc(sizeof(struct ByteBuffer));
//!     err = malloc(sizeof(struct ExternError));
//! 
//!     seed = malloc(sizeof(struct ByteBuffer));
//!     seed->len = 10;
//!     seed->data = malloc(10);
//!     memset(seed->data, 3, 10);
//! 
//!     printf("Try to generate keys\n");
//!     printf("Seed.len=%lld\n", seed->len);
//!     printf("Seed.data=%d,%d,%d,%d,%d\n", seed->data[0], seed->data[1], seed->data[2], seed->data[3], seed->data[4]);
//! 
//!     if (!ursa_ed25519_keypair_from_seed(seed->data, seed->len, public_key, private_key, err)) {
//!         printf("Failed to generate keys\n");
//!         return 1;
//!     }
//! 
//!     free(seed);
//! 
//!     printf("Success from seed!\n");
//! 
//!     if (!ursa_ed25519_keypair_new(public_key, private_key, err)) {
//!         printf("Failed to generate keys\n");
//!         return 1;
//!     }
//!     printf("Generated keys\n");
//! 
//!     signature = malloc(sizeof(struct ByteBuffer));
//! 
//!     message = malloc(sizeof(struct ByteBuffer));
//! 
//!     message->len = 7;
//!     message->data = malloc(7);
//!     message->data[0] = 'a';
//!     message->data[1] = ' ';
//!     message->data[2] = 'T';
//!     message->data[3] = 'e';
//!     message->data[4] = 's';
//!     message->data[5] = 't';
//!     message->data[6] = 0;
//!     printf("Message is %s\n", message->data);
//!     printf("Message.len=%lld\n", message->len);
//!     printf("public_key->len=%lld\n", public_key->len);
//!     printf("private_key->len=%lld\n", private_key->len);
//! 
//!     for (i = 0; i < private_key->len; i++) {
//!         printf("\"%d\"", private_key->data[i]);
//!     }
//!     printf("\n");
//! 
//!     if (!ursa_ed25519_sign(message->data, message->len, private_key->data, private_key->len, signature, err)) {
//!         printf("Failed to sign.\n");
//!         return 1;
//!     }
//! 
//!     printf("Signed!\n");
//! 
//!     if (!ursa_ed25519_verify(message->data, message->len, signature->data, signature->len, public_key->data, public_key->len, err)) {
//!         printf("Verification failed.");
//!         return 1;
//!     }
//!     printf("Verified!\n");
//! 
//!     free(public_key);
//!     free(private_key);
//!     free(err);
//!     free(message);
//!     free(signature);
//! 
//!     printf("End!\n");
//!     return 0;
//! }


use keys::{KeyGenOption, PrivateKey, PublicKey};
use signatures::ed25519;
use signatures::SignatureScheme;

use ffi_support::{ByteBuffer, ErrorCode, ExternError};

macro_rules! rust_slice {
    ($x:ident, $len:expr) => {
        let $x = unsafe { std::slice::from_raw_parts($x, $len) };
    };
}

pub mod ed25519_error_codes {
    pub const KEYPAIR_ERROR: i32 = 1;
    pub const SIGNING_ERROR: i32 = 2;
    pub const VERIFY_ERROR: i32 = 3;
    pub const INVALID_PARAM1: i32 = 4;
    pub const INVALID_PARAM2: i32 = 5;
}

/// Return the number of bytes in an Ed25519 public key - 32 bytes
#[no_mangle]
pub extern "C" fn ursa_ed25519_get_public_key_size() -> i32 {
    ed25519::PUBLIC_KEY_SIZE as i32
}

/// Return the number of bytes in an Ed25519 private key - 64 bytes
#[no_mangle]
pub extern "C" fn ursa_ed25519_get_private_key_size() -> i32 {
    ed25519::PRIVATE_KEY_SIZE as i32
}

/// Return the number of bytes in an Ed25519 signature 64 bytes
#[no_mangle]
pub extern "C" fn ursa_ed25519_get_signature_size() -> i32 {
    ed25519::SIGNATURE_SIZE as i32
}

/// Create a new keypair.
/// Caller will need to free the memory for on `public_key` and `private_key`
#[no_mangle]
pub extern "C" fn ursa_ed25519_keypair_new(
    public_key: &mut ByteBuffer,
    private_key: &mut ByteBuffer,
    err: &mut ExternError,
) -> i32 {
    ursa_ed25519_keypair_gen(None, public_key, Some(private_key), err)
}

/// Create a new keypair from a seed.
/// Caller will need to free the memory for on `public_key` and `private_key`
#[no_mangle]
pub extern "C" fn ursa_ed25519_keypair_from_seed(
    seed: *const u8,
    seed_len: usize,
    public_key: &mut ByteBuffer,
    private_key: &mut ByteBuffer,
    err: &mut ExternError,
) -> i32 {
    if !check_useful_byte_array(seed, seed_len, err) {
        return 0;
    }
    rust_slice!(seed, seed_len);
    ursa_ed25519_keypair_gen(
        Some(KeyGenOption::UseSeed(seed.to_vec())),
        public_key,
        Some(private_key),
        err,
    )
}

/// Create a new keypair from a seed.
/// Caller will need to free the memory for on `public_key` and `private_key`
#[no_mangle]
pub extern "C" fn ursa_ed25519_get_public_key(
    private_key: *const u8,
    private_key_len: usize,
    public_key: &mut ByteBuffer,
    err: &mut ExternError,
) -> i32 {
    if !check_useful_byte_array(private_key, private_key_len, err) {
        return 0;
    }
    rust_slice!(private_key, private_key_len);
    ursa_ed25519_keypair_gen(
        Some(KeyGenOption::FromSecretKey(PrivateKey(
            private_key.to_vec(),
        ))),
        public_key,
        None,
        err,
    )
}

/// Sign a message
/// Caller will need to free the memory for on `signature`
#[no_mangle]
pub extern "C" fn ursa_ed25519_sign(
    message: *const u8,
    message_len: usize,
    private_key: *const u8,
    private_key_len: usize,
    signature: &mut ByteBuffer,
    err: &mut ExternError,
) -> i32 {
    if !check_useful_byte_array(message, message_len, err) {
        return 0;
    }
    if !check_useful_byte_array(private_key, private_key_len, err) {
        return 0;
    }
    rust_slice!(message, message_len);
    rust_slice!(private_key, private_key_len);

    let scheme = ed25519::Ed25519Sha512::new();
    let sk = PrivateKey(private_key.to_vec());

    match scheme.sign(message, &sk) {
        Ok(sig) => {
            *err = ExternError::success();
            *signature = ByteBuffer::from_vec(sig);
            1
        }
        Err(e) => {
            *err = ExternError::new_error(
                ErrorCode::new(ed25519_error_codes::SIGNING_ERROR),
                e.to_string(),
            );
            0
        }
    }
}

/// Verify a signature over a message
#[no_mangle]
pub extern "C" fn ursa_ed25519_verify(
    message: *const u8,
    message_len: usize,
    signature: *const u8,
    signature_len: usize,
    public_key: *const u8,
    public_key_len: usize,
    err: &mut ExternError,
) -> i32 {
    if !check_useful_byte_array(message, message_len, err) {
        return 0;
    }
    if !check_useful_byte_array(signature, signature_len, err) {
        return 0;
    }
    if !check_useful_byte_array(public_key, public_key_len, err) {
        return 0;
    }

    let scheme = ed25519::Ed25519Sha512::new();
    rust_slice!(message, message_len);
    rust_slice!(signature, signature_len);
    rust_slice!(public_key, public_key_len);
    let pk = PublicKey(public_key.to_vec());

    match scheme.verify(message, signature, &pk) {
        Ok(b) => {
            if b {
                *err = ExternError::success();
                1
            } else {
                0
            }
        }
        Err(e) => {
            *err = ExternError::new_error(
                ErrorCode::new(ed25519_error_codes::VERIFY_ERROR),
                e.to_string(),
            );
            0
        }
    }
}

fn ursa_ed25519_keypair_gen(
    option: Option<KeyGenOption>,
    public_key: &mut ByteBuffer,
    private_key: Option<&mut ByteBuffer>,
    err: &mut ExternError,
) -> i32 {
    let scheme = ed25519::Ed25519Sha512::new();
    match scheme.keypair(option) {
        Ok((pk, sk)) => {
            *err = ExternError::success();
            *public_key = ByteBuffer::from_vec(pk.0.to_vec());
            if let Some(s) = private_key {
                *s = ByteBuffer::from_vec(sk.0.to_vec());
            }
            1
        }
        Err(e) => {
            *err = ExternError::new_error(
                ErrorCode::new(ed25519_error_codes::KEYPAIR_ERROR),
                e.to_string(),
            );
            0
        }
    }
}

fn check_useful_byte_array(ptr: *const u8, len: usize, err: &mut ExternError) -> bool {
    if ptr.is_null() {
        *err = ExternError::new_error(
            ErrorCode::new(ed25519_error_codes::INVALID_PARAM1),
            "Invalid pointer has been passed".to_string(),
        );
        return false;
    }

    if len == 0 {
        *err = ExternError::new_error(
            ErrorCode::new(ed25519_error_codes::INVALID_PARAM2),
            "Array length must be greater than 0".to_string(),
        );
        return false;
    }
    true
}

define_bytebuffer_destructor!(ursa_ed25519_bytebuffer_free);

#[cfg(test)]
mod tests {
    use super::*;
    use encoding::hex::bin2hex;

    #[test]
    fn ffi_keypair() {
        let mut public_key = ByteBuffer::new_with_size(ursa_ed25519_get_public_key_size() as usize);
        let mut private_key = ByteBuffer::new_with_size(ursa_ed25519_get_private_key_size() as usize);
        let mut error = ExternError::success();
        let res = ursa_ed25519_keypair_new(&mut public_key, &mut private_key, &mut error);

        assert_eq!(res, 1);
        assert!(error.get_code().is_success());
        let pk = public_key.into_vec();
        let sk = private_key.into_vec();

        assert_eq!(pk.len(), ed25519::PUBLIC_KEY_SIZE);
        assert_eq!(sk.len(), ed25519::PRIVATE_KEY_SIZE);
        assert!(!pk.iter().all(|b| *b == 0u8));
        assert!(!sk.iter().all(|b| *b == 0u8));

        let mut public_key = ByteBuffer::new_with_size(ursa_ed25519_get_public_key_size() as usize);
        let mut private_key = ByteBuffer::new_with_size(ursa_ed25519_get_private_key_size() as usize);
        let seed = vec![1u8; 32];
        let res = ursa_ed25519_keypair_from_seed(seed.as_ptr(), seed.len(), &mut public_key, &mut private_key, &mut error);
        assert_eq!(res, 1);
        assert!(error.get_code().is_success());
        let pk = public_key.into_vec();
        let sk = private_key.into_vec();
        assert_eq!("3b77a042f1de02f6d5f418f36a20fd68c8329fe3bbfbecd26a2d72878cd827f8".to_string(), bin2hex(pk.as_slice()));
        assert_eq!("b2ff47a7b9693f810e1b8c3dea9659628838977a4b08a8306cb56d1395c8cd153b77a042f1de02f6d5f418f36a20fd68c8329fe3bbfbecd26a2d72878cd827f8".to_string(), bin2hex(sk.as_slice()));

        let mut public_key = ByteBuffer::new_with_size(ursa_ed25519_get_public_key_size() as usize);
        let res = ursa_ed25519_get_public_key(sk.as_ptr(), sk.len(), &mut public_key, &mut error);
        assert_eq!(res, 1);
        assert!(error.get_code().is_success());
        assert_eq!(pk, public_key.into_vec());

        let mut public_key = ByteBuffer::new_with_size(ursa_ed25519_get_public_key_size() as usize);
        let mut private_key = ByteBuffer::new_with_size(ursa_ed25519_get_private_key_size() as usize);
        let res = ursa_ed25519_get_public_key(pk.as_ptr(), pk.len(), &mut public_key, &mut error);
        assert_eq!(res, 0);
        assert_eq!(error.get_message().into_string(), "KeyGenError(Keypair must be 64 bytes in length)".to_string());
        let seed = std::ptr::null();
        let res = ursa_ed25519_keypair_from_seed(seed as *const u8, 0, &mut public_key, &mut private_key, &mut error);
        assert_eq!(res, 0);
        assert_eq!(error.get_message().into_string(), "Invalid pointer has been passed".to_string());
        public_key.destroy();
        private_key.destroy();
    }

    #[test]
    fn ffi_ed25519_sign() {
        let mut public_key = ByteBuffer::new_with_size(ursa_ed25519_get_public_key_size() as usize);
        let mut private_key = ByteBuffer::new_with_size(ursa_ed25519_get_private_key_size() as usize);
        let mut error = ExternError::success();
        let seed = vec![1u8; 32];
        let res = ursa_ed25519_keypair_from_seed(seed.as_ptr(), seed.len(), &mut public_key, &mut private_key, &mut error);
        assert_eq!(res, 1);
        assert!(error.get_code().is_success());
        let pk = public_key.into_vec();
        let sk = private_key.into_vec();

        let mut signature = ByteBuffer::new_with_size(ursa_ed25519_get_signature_size() as usize);
        let message = b"Wepa! This is a message that should be signed.";
        let res = ursa_ed25519_sign(message.as_ptr(), message.len(), sk.as_ptr(), sk.len(), &mut signature, &mut error);
        assert_eq!(res, 1);
        assert!(error.get_code().is_success());

        let sig = signature.into_vec();
        assert_eq!("f61dc466c3094522987cf9bdbadf8a455bc9401d0e56e1a7696483de85c646216648eb9f7f8003822d4c8702016ffe3b4a218ed776776ae5b53d5394bbadb509".to_string(), bin2hex(sig.as_slice()));
        let res = ursa_ed25519_verify(message.as_ptr(), message.len(), sig.as_ptr(), sig.len(), pk.as_ptr(), pk.len(), &mut error);
        assert_eq!(res, 1);
        assert!(error.get_code().is_success());
    }
}
