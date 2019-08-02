// FFI functions to the ed25519 signatures
//
// Example of how to use these functions from C
// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
// #include "ursa_crypto.h"
//
// int main(void) {
//     struct ByteBuffer* public_key;
//     struct ByteBuffer* private_key;
//     struct ByteBuffer* seed;
//     struct ByteBuffer* message;
//     struct ByteBuffer* signature;
//     struct ExternError* err;
//     int i;
//
//     public_key = (ByteBuffer *)malloc(sizeof(struct ByteBuffer));
//     private_key = (ByteBuffer *)malloc(sizeof(struct ByteBuffer));
//     err = (ExternError *)malloc(sizeof(struct ExternError));
//
//     seed = (ByteBuffer *)malloc(sizeof(struct ByteBuffer));
//     seed->len = 10;
//     seed->data = (uint8_t *)malloc(10);
//     memset(seed->data, 3, 10);
//
//     printf("Try to generate keys\n");
//     printf("Seed.len=%lld\n", seed->len);
//     printf("Seed.data=%d,%d,%d,%d,%d\n", seed->data[0], seed->data[1], seed->data[2], seed->data[3], seed->data[4]);
//
//     if (!ursa_ed25519_keypair_from_seed(seed, public_key, private_key, err)) {
//         printf("Failed to generate keys\n");
//         return 1;
//     }
//
//     ursa_ed25519_bytebuffer_free(*public_key);
//     ursa_ed25519_bytebuffer_free(*private_key);
//
//     free(seed->data);
//     free(seed);
//
//     printf("Success from seed!\n");
//
//     if (!ursa_ed25519_keypair_new(public_key, private_key, err)) {
//         printf("Failed to generate keys\n");
//
//         ursa_ed25519_bytebuffer_free(*public_key);
//         ursa_ed25519_bytebuffer_free(*private_key);
//
//         free(public_key);
//         free(private_key);
//
//         ursa_ed25519_string_free(err->message);
//         free(err);
//
//         return 1;
//     }
//     printf("Generated keys\n");
//
//     signature = (ByteBuffer *)malloc(sizeof(struct ByteBuffer));
//
//     message = (ByteBuffer *)malloc(sizeof(struct ByteBuffer));
//
//     message->len = 7;
//     message->data = (uint8_t *)malloc(7);
//     message->data[0] = 'a';
//     message->data[1] = ' ';
//     message->data[2] = 'T';
//     message->data[3] = 'e';
//     message->data[4] = 's';
//     message->data[5] = 't';
//     message->data[6] = 0;
//     printf("Message is %s\n", message->data);
//     printf("Message.len=%lld\n", message->len);
//     printf("public_key->len=%lld\n", public_key->len);
//     printf("private_key->len=%lld\n", private_key->len);
//
//     for (i = 0; i < private_key->len; i++) {
//         printf("\"%d\"", private_key->data[i]);
//     }
//     printf("\n");
//
//     if (!ursa_ed25519_sign(message, private_key, signature, err)) {
//         printf("Failed to sign.\n");
//
//         ursa_ed25519_bytebuffer_free(*public_key);
//         ursa_ed25519_bytebuffer_free(*private_key);
//
//         free(public_key);
//         free(private_key);
//         free(message->data);
//         free(message);
//         free(signature);
//
//         ursa_ed25519_string_free(err->message);
//         free(err);
//
//         return 1;
//     }
//
//     printf("Signed!\n");
//
//     if (!ursa_ed25519_verify(message, signature, public_key, err)) {
//         printf("Verification failed.");
//
//         ursa_ed25519_bytebuffer_free(*public_key);
//         ursa_ed25519_bytebuffer_free(*private_key);
//         ursa_ed25519_bytebuffer_free(*signature);
//
//         free(public_key);
//         free(private_key);
//         free(message->data);
//         free(message);
//         free(signature);
//
//         ursa_ed25519_string_free(err->message);
//         free(err);
//
//         return 1;
//     }
//     printf("Verified!\n");
//
//     // ExternError messages also need to be freed from memory
//     ursa_ed25519_bytebuffer_free(*signature);
//     free(message->data);
//     message->len = 0;
//
//     if (!ursa_ed25519_sign(message->data, message->len, private_key->data, private_key->len, signature, err)) {
//         printf("Expected signing error: %s\n", err->message);
//
//         ursa_ed25519_string_free(err->message);
//     }
//
//
//     ursa_ed25519_bytebuffer_free(*public_key);
//     ursa_ed25519_bytebuffer_free(*private_key);
//
//     free(public_key);
//     free(private_key);
//     free(err);
//     free(message);
//     free(signature);
//
//     printf("End!\n");
//     return 0;
// }

use super::super::ByteArray;
use keys::{KeyGenOption, PrivateKey, PublicKey};
use signatures::ed25519;
use signatures::SignatureScheme;

use ffi_support::{ByteBuffer, ErrorCode, ExternError};

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
/// Caller will need to call `ursa_ed25519_bytebuffer_free` on `public_key` and `private_key`
/// to free the memory.
/// If an error occurs, caller will need to call `ursa_ed25519_string_free`
/// on `err.message` to free the memory.
#[no_mangle]
pub extern "C" fn ursa_ed25519_keypair_new(
    public_key: &mut ByteBuffer,
    private_key: &mut ByteBuffer,
    err: &mut ExternError,
) -> i32 {
    ursa_ed25519_keypair_gen(None, public_key, Some(private_key), err)
}

/// Create a new keypair from a seed.
/// Caller will need to call `ursa_ed25519_bytebuffer_free` on `public_key` and `private_key`
/// to free the memory.
/// If an error occurs, caller will need to call `ursa_ed25519_string_free`
/// on `err.message` to free the memory.
#[no_mangle]
pub extern "C" fn ursa_ed25519_keypair_from_seed(
    seed: &ByteArray,
    public_key: &mut ByteBuffer,
    private_key: &mut ByteBuffer,
    err: &mut ExternError,
) -> i32 {
    ursa_ed25519_keypair_gen(
        Some(KeyGenOption::UseSeed(seed.to_vec())),
        public_key,
        Some(private_key),
        err,
    )
}

/// Get a public key from a private key.
/// Caller will need to call `ursa_ed25519_bytebuffer_free` on `public_key` and `private_key`
/// to free the memory.
/// If an error occurs, caller will need to call `ursa_ed25519_string_free`
/// on `err.message` to free the memory.
#[no_mangle]
pub extern "C" fn ursa_ed25519_get_public_key(
    private_key: &ByteArray,
    public_key: &mut ByteBuffer,
    err: &mut ExternError,
) -> i32 {
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
/// Caller will need to call `ursa_ed25519_bytebuffer_free` on `signature`
/// to free the memory.
/// If an error occurs, caller will need to call `ursa_ed25519_string_free`
/// on `err.message` to free the memory.
#[no_mangle]
pub extern "C" fn ursa_ed25519_sign(
    message: &ByteArray,
    private_key: &ByteArray,
    signature: &mut ByteBuffer,
    err: &mut ExternError,
) -> i32 {
    let scheme = ed25519::Ed25519Sha512::new();
    let sk = PrivateKey(private_key.to_vec());

    match scheme.sign(message.to_vec().as_slice(), &sk) {
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
/// If an error occurs, caller will need to call `ursa_ed25519_string_free`
/// on `err.message` to free the memory.
#[no_mangle]
pub extern "C" fn ursa_ed25519_verify(
    message: &ByteArray,
    signature: &ByteArray,
    public_key: &ByteArray,
    err: &mut ExternError,
) -> i32 {
    let scheme = ed25519::Ed25519Sha512::new();
    let pk = PublicKey(public_key.to_vec());

    match scheme.verify(
        message.to_vec().as_slice(),
        signature.to_vec().as_slice(),
        &pk,
    ) {
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

define_bytebuffer_destructor!(ursa_ed25519_bytebuffer_free);
define_string_destructor!(ursa_ed25519_string_free);

#[cfg(test)]
mod tests {
    use super::*;
    use encoding::hex::bin2hex;

    #[test]
    fn ffi_keypair() {
        let mut public_key = ByteBuffer::new_with_size(ursa_ed25519_get_public_key_size() as usize);
        let mut private_key =
            ByteBuffer::new_with_size(ursa_ed25519_get_private_key_size() as usize);
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
        let mut private_key =
            ByteBuffer::new_with_size(ursa_ed25519_get_private_key_size() as usize);
        let seed = vec![1u8; 32];
        let seed_wrapper = ByteArray::from(&seed);
        let res = ursa_ed25519_keypair_from_seed(
            &seed_wrapper,
            &mut public_key,
            &mut private_key,
            &mut error,
        );
        assert_eq!(res, 1);
        assert!(error.get_code().is_success());
        let pk = public_key.into_vec();
        let sk = private_key.into_vec();
        assert_eq!(
            "3b77a042f1de02f6d5f418f36a20fd68c8329fe3bbfbecd26a2d72878cd827f8".to_string(),
            bin2hex(pk.as_slice())
        );
        assert_eq!("b2ff47a7b9693f810e1b8c3dea9659628838977a4b08a8306cb56d1395c8cd153b77a042f1de02f6d5f418f36a20fd68c8329fe3bbfbecd26a2d72878cd827f8".to_string(), bin2hex(sk.as_slice()));

        let mut public_key = ByteBuffer::new_with_size(ursa_ed25519_get_public_key_size() as usize);
        let sk_wrapper = ByteArray::from(&sk);
        let res = ursa_ed25519_get_public_key(&sk_wrapper, &mut public_key, &mut error);
        assert_eq!(res, 1);
        assert!(error.get_code().is_success());
        assert_eq!(pk, public_key.into_vec());

        let mut public_key = ByteBuffer::new_with_size(ursa_ed25519_get_public_key_size() as usize);
        let mut private_key =
            ByteBuffer::new_with_size(ursa_ed25519_get_private_key_size() as usize);
        let pk_wrapper = ByteArray::from(&pk);
        let res = ursa_ed25519_get_public_key(&pk_wrapper, &mut public_key, &mut error);
        assert_eq!(res, 0);
        assert_eq!(
            error.get_message().into_string(),
            "KeyGenError(Keypair must be 64 bytes in length)".to_string()
        );
        let seed = ByteArray::default();
        let res =
            ursa_ed25519_keypair_from_seed(&seed, &mut public_key, &mut private_key, &mut error);
        assert_eq!(res, 1);
        public_key.destroy();
        private_key.destroy();
    }

    #[test]
    fn ffi_ed25519_sign() {
        let mut public_key = ByteBuffer::new_with_size(ursa_ed25519_get_public_key_size() as usize);
        let mut private_key =
            ByteBuffer::new_with_size(ursa_ed25519_get_private_key_size() as usize);
        let mut error = ExternError::success();
        let seed = vec![1u8; 32];
        let seed_wrapper = ByteArray::from(&seed);
        let res = ursa_ed25519_keypair_from_seed(
            &seed_wrapper,
            &mut public_key,
            &mut private_key,
            &mut error,
        );
        assert_eq!(res, 1);
        assert!(error.get_code().is_success());
        let pk = public_key.into_vec();
        let sk = private_key.into_vec();

        let mut signature = ByteBuffer::new_with_size(ursa_ed25519_get_signature_size() as usize);
        let message = b"Wepa! This is a message that should be signed.";
        let message_wrapper = ByteArray::from(&message[..]);
        let sk_wrapper = ByteArray::from(&sk);

        let res = ursa_ed25519_sign(&message_wrapper, &sk_wrapper, &mut signature, &mut error);
        assert_eq!(res, 1);
        assert!(error.get_code().is_success());

        let sig = signature.into_vec();
        let sig_wrapper = ByteArray::from(&sig);
        let pk_wrapper = ByteArray::from(&pk);
        assert_eq!("f61dc466c3094522987cf9bdbadf8a455bc9401d0e56e1a7696483de85c646216648eb9f7f8003822d4c8702016ffe3b4a218ed776776ae5b53d5394bbadb509".to_string(), bin2hex(sig.as_slice()));
        let res = ursa_ed25519_verify(&message_wrapper, &sig_wrapper, &pk_wrapper, &mut error);
        assert_eq!(res, 1);
        assert!(error.get_code().is_success());
    }
}
