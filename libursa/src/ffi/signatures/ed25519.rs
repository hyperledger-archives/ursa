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
pub extern "C" fn ursa_ed25519_keypair_new(
    public_key: &mut ByteBuffer,
    private_key: &mut ByteBuffer,
    err: &mut ExternError,
) -> i32 {
    ursa_ed25519_keypair_gen(None, public_key, Some(private_key), err)
}

/// Create a new keypair from a seed.
/// Call will need to call `ursa_ed25519_bytebuffer_free` on `public_key` and `private_key` to
/// free the memory
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
    //    check_useful_byte_array!(seed, seed_len, err, ed25519_error_codes::INVALID_PARAM1, ed25519_error_codes::INVALID_PARAM2);
    ursa_ed25519_keypair_gen(
        Some(KeyGenOption::UseSeed(seed.to_vec())),
        public_key,
        Some(private_key),
        err,
    )
}

/// Create a new keypair from a seed.
/// Call will need to call `ursa_ed25519_bytebuffer_free` on `public_key` to
/// free the memory
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
/// Call will need to call `ursa_ed25519_bytebuffer_free` on `signature` to
/// free the memory
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

    let res = match scheme.verify(message, signature, &pk) {
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
    };
    res
}

fn ursa_ed25519_keypair_gen(
    option: Option<KeyGenOption>,
    public_key: &mut ByteBuffer,
    private_key: Option<&mut ByteBuffer>,
    err: &mut ExternError,
) -> i32 {
    let scheme = ed25519::Ed25519Sha512::new();
    let res = match scheme.keypair(option) {
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
    };
    res
}

fn check_useful_byte_array(ptr: *const u8, len: usize, err: &mut ExternError) -> bool {
    if ptr.is_null() {
        *err = ExternError::new_error(
            ErrorCode::new(ed25519_error_codes::INVALID_PARAM1),
            "Invalid pointer has been passed".to_string(),
        );
        return false;
    }

    if len <= 0 {
        *err = ExternError::new_error(
            ErrorCode::new(ed25519_error_codes::INVALID_PARAM2),
            "Array length must be greater than 0".to_string(),
        );
        return false;
    }
    true
}

define_bytebuffer_destructor!(ursa_ed25519_bytebuffer_free);
