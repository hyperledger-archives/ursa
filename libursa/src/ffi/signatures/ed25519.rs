use keys::{KeyGenOption, PublicKey, PrivateKey};
use signatures::SignatureScheme;
use signatures::ed25519;

use ffi_support::{ExternError, ErrorCode, ByteBuffer};

pub mod ed25519_error_codes {
    pub const KEYPAIR_ERROR: i32 = 1;
    pub const SIGNING_ERROR: i32 = 2;
    pub const VERIFY_ERROR: i32 = 3;
}

#[no_mangle]
pub extern "C" fn ursa_ed25519_get_public_key_size() -> i32 {
    ed25519::PUBLIC_KEY_SIZE as i32
}

#[no_mangle]
pub extern "C" fn ursa_ed25519_get_private_key_size() -> i32 {
    ed25519::PRIVATE_KEY_SIZE as i32
}

#[no_mangle]
pub extern "C" fn ursa_ed25519_get_signature_size() -> i32 {
    ed25519::SIGNATURE_SIZE as i32
}

/// Create a new keypair.
/// Call will need to call `ursa_ed25519_bytebuffer_free` on `public_key` and `private_key` to
/// free the memory
#[no_mangle]
pub extern "C" fn ursa_ed25519_keypair_new(public_key: &mut ByteBuffer, private_key: &mut ByteBuffer, err: &mut ExternError) -> i32 {
    ursa_ed25519_keypair_gen(None, public_key, Some(private_key), err)
}

/// Create a new keypair from a seed.
/// Call will need to call `ursa_ed25519_bytebuffer_free` on `public_key` and `private_key` to
/// free the memory
#[no_mangle]
pub extern "C" fn ursa_ed25519_keypair_from_seed(seed: ByteBuffer, public_key: &mut ByteBuffer, private_key: &mut ByteBuffer, err: &mut ExternError) -> i32 {
    let s = seed.into_vec();
    ursa_ed25519_keypair_gen(Some(KeyGenOption::UseSeed(s)), public_key, Some(private_key), err)
}

/// Create a new keypair from a seed.
/// Call will need to call `ursa_ed25519_bytebuffer_free` on `public_key` to
/// free the memory
#[no_mangle]
pub extern "C" fn ursa_ed25519_get_public_key(private_key: ByteBuffer, public_key: &mut ByteBuffer, err: &mut ExternError) -> i32 {
    let sk = PrivateKey(private_key.into_vec());
    ursa_ed25519_keypair_gen(Some(KeyGenOption::FromSecretKey(sk)), public_key, None, err)
}

/// Sign a message
/// Call will need to call `ursa_ed25519_bytebuffer_free` on `signature` to
/// free the memory
#[no_mangle]
pub extern "C" fn ursa_ed25519_sign(message: ByteBuffer, private_key: ByteBuffer, signature: &mut ByteBuffer, err: &mut ExternError) -> i32 {
    let scheme = ed25519::Ed25519Sha512::new();
    let msg = message.into_vec();
    let sk = PrivateKey(private_key.into_vec());
//
    match scheme.sign(msg.as_slice(), &sk) {
        Ok(sig) => {
            *err = ExternError::success();
            *signature = ByteBuffer::from_vec(sig);
            1
        },
        Err(e) => {
            *err = ExternError::new_error(ErrorCode::new(ed25519_error_codes::SIGNING_ERROR), e.to_string());
            0
        }
    }
}

/// Verify a signature over a message
#[no_mangle]
pub extern "C" fn ursa_ed25519_verify(message: ByteBuffer, signature: ByteBuffer, public_key: ByteBuffer, err: &mut ExternError) -> i32 {
    let scheme = ed25519::Ed25519Sha512::new();
    let pk = PublicKey(public_key.into_vec());
    let msg = message.into_vec();
    let sig =  signature.into_vec();

    let res = match scheme.verify(msg.as_slice(), sig.as_slice(), &pk) {
        Ok(b) => {
            if b {
                *err = ExternError::success();
                1
            } else {
                0
            }
        },
        Err(e) => {
            *err = ExternError::new_error(ErrorCode::new(ed25519_error_codes::VERIFY_ERROR), e.to_string());
            0
        }
    };
    res
}

fn ursa_ed25519_keypair_gen(option: Option<KeyGenOption>, public_key: &mut ByteBuffer, private_key: Option<&mut ByteBuffer>, err: &mut ExternError) -> i32 {
    let scheme = ed25519::Ed25519Sha512::new();
    let res = match scheme.keypair(option) {
        Ok((pk, sk)) => {
            *err = ExternError::success();
            *public_key = ByteBuffer::from_vec(pk.0.to_vec());
            if let Some(s) = private_key {
                *s = ByteBuffer::from_vec(sk.0.to_vec());
            }
            1
        },
        Err(e) => {
            *err = ExternError::new_error(ErrorCode::new(ed25519_error_codes::KEYPAIR_ERROR), e.to_string());
            0
        }
    };
    res
}


define_bytebuffer_destructor!(ursa_ed25519_bytebuffer_free);
