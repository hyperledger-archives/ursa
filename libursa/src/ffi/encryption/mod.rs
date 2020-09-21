use super::ByteArray;
use aead::{generic_array::typenum::Unsigned, Aead, NewAead};
use encryption::random_vec;
use encryption::symm::prelude::*;
use ffi_support::{ByteBuffer, ErrorCode, ExternError, FfiStr};
use std::ffi::CString;
use std::str::FromStr;

pub mod encryption_error_codes {
    pub const ENCRYPTION_ERROR: i32 = 6;
    pub const DECRYPTION_ERROR: i32 = 7;
    pub const INVALID_KEY_LENGTH: i32 = 8;
    pub const INVALID_NONCE_LENGTH: i32 = 9;
    pub const INVALID_CIPHER: i32 = 11;
}

macro_rules! ffi_encryption_size {
    ($func_name:ident, $trait_name:ident, $property_name:ident, $struct_name:ident) => {
        #[no_mangle]
        pub extern "C" fn $func_name() -> usize {
            <<$struct_name as $trait_name>::$property_name as Unsigned>::to_usize()
        }
    };
}

macro_rules! ffi_encryption_impl {
    ($func_name:ident, $operation:ident, $operation_easy:ident, $error_code:expr) => {
        #[no_mangle]
        pub extern "C" fn $func_name(
            output: &mut ByteBuffer,
            algorithm: &FfiStr<'_>,
            key: &ByteArray,
            nonce: &ByteArray,
            aad: &ByteArray,
            input: &ByteArray,
            err: &mut ExternError,
        ) -> i32 {
            *err = ExternError::success();
            let key = key.to_vec();
            let aad = aad.to_vec();
            let nonce = nonce.to_opt_vec();
            let algorithm = algorithm.as_str();
            let input = input.to_vec();
            let cipher_res = EncryptorType::from_str(algorithm);
            let cipher;
            let aes: Box<dyn DynEncryptor>;

            match cipher_res {
                Ok(c) => {
                    cipher = c;
                    if !cipher.is_valid_keysize(key.len()) {
                        *err = ExternError::new_error(
                            ErrorCode::new(encryption_error_codes::INVALID_KEY_LENGTH),
                            "Invalid key length",
                        );
                        return 0;
                    }
                    aes = c.gen_encryptor(key.as_slice());
                }
                Err(e) => {
                    *err = ExternError::new_error(
                        ErrorCode::new(encryption_error_codes::INVALID_CIPHER),
                        e,
                    );
                    return 0;
                }
            };

            let res = match nonce {
                Some(n) => {
                    if aes.noncesize() != n.len() {
                        *err = ExternError::new_error(
                            ErrorCode::new(encryption_error_codes::INVALID_NONCE_LENGTH),
                            "Invalid nonce length",
                        );
                        return 0;
                    }
                    aes.$operation(n.as_slice(), aad.as_slice(), input.as_slice())
                }
                None => aes.$operation_easy(aad.as_slice(), input.as_slice()),
            };

            match res {
                Ok(c) => {
                    *output = ByteBuffer::from_vec(c);
                    1
                }
                Err(_) => {
                    *err = ExternError::new_error(ErrorCode::new($error_code), "");
                    0
                }
            }
        }
    };
}

macro_rules! ffi_encryption_alias {
    ($func_name:ident, $algorithm:ident, $operation:ident) => {
        #[no_mangle]
        pub extern "C" fn $func_name(
            output: &mut ByteBuffer,
            key: &ByteArray,
            nonce: &ByteArray,
            aad: &ByteArray,
            input: &ByteArray,
            err: &mut ExternError,
        ) -> i32 {
            let alg = CString::new(EncryptorType::$algorithm.to_string()).unwrap();
            let alg_ptr = unsafe { FfiStr::from_raw(alg.as_ptr()) };
            $operation(output, &alg_ptr, key, nonce, aad, input, err)
        }
    };
}

#[cfg(test)]
macro_rules! ffi_encryption_test {
    ($func_name:ident, $algorithm:ident, $keysize:ident, $noncesize:ident) => {
        #[test]
        fn $func_name() {
            let mut error = ExternError::success();
            let mut key = ByteBuffer::default();
            let mut nonce = ByteBuffer::default();
            let res = random_bytes(&mut key, $keysize(), &mut error);
            assert_eq!(1, res);
            let res = random_bytes(&mut nonce, $noncesize(), &mut error);
            assert_eq!(1, res);
            let aad = ByteArray::from(b"ffi/encryption/mod".to_vec());
            let msg = ByteArray::from(b"Goodbye Cruel World!".to_vec());
            let key = ByteArray::from(key);
            let nonce = ByteArray::from(nonce);
            let mut ciphertext = ByteBuffer::default();
            let alg = CString::new(EncryptorType::$algorithm.to_string()).unwrap();
            let alg_ptr = unsafe { FfiStr::from_raw(alg.as_ptr()) };
            let res = ursa_encrypt(
                &mut ciphertext,
                &alg_ptr,
                &key,
                &nonce,
                &aad,
                &msg,
                &mut error,
            );
            assert_eq!(1, res);
            let mut plaintext = ByteBuffer::default();
            let ciphertext = ByteArray::from(ciphertext);
            let res = ursa_decrypt(
                &mut plaintext,
                &alg_ptr,
                &key,
                &nonce,
                &aad,
                &ciphertext,
                &mut error,
            );
            println!("ursa_decrypt = {:?}", error);
            assert_eq!(1, res);
            assert_eq!(plaintext.destroy_into_vec(), msg.to_vec());

            //Correctly handles no nonce
            let nonce = ByteArray::default();
            let mut ciphertext = ByteBuffer::default();
            let res = ursa_encrypt(
                &mut ciphertext,
                &alg_ptr,
                &key,
                &nonce,
                &aad,
                &msg,
                &mut error,
            );
            assert_eq!(1, res);
            let mut plaintext = ByteBuffer::default();
            let ciphertext = ByteArray::from(ciphertext);
            let res = ursa_decrypt(
                &mut plaintext,
                &alg_ptr,
                &key,
                &nonce,
                &aad,
                &ciphertext,
                &mut error,
            );
            assert_eq!(1, res);
            assert_eq!(plaintext.destroy_into_vec(), msg.to_vec());
        }
    };
}

ffi_encryption_alias!(
    ursa_aes128_cbc_hmac256_encrypt,
    Aes128CbcHmac256,
    ursa_encrypt
);
ffi_encryption_alias!(
    ursa_aes128_cbc_hmac256_decrypt,
    Aes128CbcHmac256,
    ursa_decrypt
);
ffi_encryption_alias!(
    ursa_aes256_cbc_hmac512_encrypt,
    Aes256CbcHmac512,
    ursa_encrypt
);
ffi_encryption_alias!(
    ursa_aes256_cbc_hmac512_decrypt,
    Aes256CbcHmac512,
    ursa_decrypt
);
ffi_encryption_alias!(ursa_aes128_gcm_encrypt, Aes128Gcm, ursa_encrypt);
ffi_encryption_alias!(ursa_aes128_gcm_decrypt, Aes128Gcm, ursa_decrypt);
ffi_encryption_alias!(ursa_aes256_gcm_encrypt, Aes256Gcm, ursa_encrypt);
ffi_encryption_alias!(ursa_aes256_gcm_decrypt, Aes256Gcm, ursa_decrypt);
ffi_encryption_alias!(
    ursa_xchacha20_poly1305_encrypt,
    XChaCha20Poly1305,
    ursa_encrypt
);
ffi_encryption_alias!(
    ursa_xchacha20_poly1305_decrypt,
    XChaCha20Poly1305,
    ursa_decrypt
);

ffi_encryption_size!(
    ursa_aes128_cbc_hmac256_keysize,
    NewAead,
    KeySize,
    Aes128CbcHmac256
);
ffi_encryption_size!(
    ursa_aes128_cbc_hmac256_noncesize,
    Aead,
    NonceSize,
    Aes128CbcHmac256
);
ffi_encryption_size!(
    ursa_aes128_cbc_hmac256_tagsize,
    Aead,
    TagSize,
    Aes128CbcHmac256
);

ffi_encryption_size!(
    ursa_aes256_cbc_hmac512_keysize,
    NewAead,
    KeySize,
    Aes256CbcHmac512
);
ffi_encryption_size!(
    ursa_aes256_cbc_hmac512_noncesize,
    Aead,
    NonceSize,
    Aes256CbcHmac512
);
ffi_encryption_size!(
    ursa_aes256_cbc_hmac512_tagsize,
    Aead,
    TagSize,
    Aes256CbcHmac512
);

ffi_encryption_size!(ursa_aes128_gcm_keysize, NewAead, KeySize, Aes128Gcm);
ffi_encryption_size!(ursa_aes128_gcm_noncesize, Aead, NonceSize, Aes128Gcm);
ffi_encryption_size!(ursa_aes128_gcm_tagsize, Aead, TagSize, Aes128Gcm);

ffi_encryption_size!(ursa_aes256_gcm_keysize, NewAead, KeySize, Aes256Gcm);
ffi_encryption_size!(ursa_aes256_gcm_noncesize, Aead, NonceSize, Aes256Gcm);
ffi_encryption_size!(ursa_aes256_gcm_tagsize, Aead, TagSize, Aes256Gcm);

ffi_encryption_size!(
    ursa_xchacha20_poly1305_keysize,
    NewAead,
    KeySize,
    XChaCha20Poly1305
);
ffi_encryption_size!(
    ursa_xchacha20_poly1305_noncesize,
    Aead,
    NonceSize,
    XChaCha20Poly1305
);
ffi_encryption_size!(
    ursa_xchacha20_poly1305_tagsize,
    Aead,
    TagSize,
    XChaCha20Poly1305
);

ffi_encryption_impl!(
    ursa_encrypt,
    encrypt,
    encrypt_easy,
    encryption_error_codes::ENCRYPTION_ERROR
);
ffi_encryption_impl!(
    ursa_decrypt,
    decrypt,
    decrypt_easy,
    encryption_error_codes::DECRYPTION_ERROR
);

#[no_mangle]
pub extern "C" fn random_bytes(
    output: &mut ByteBuffer,
    bytes: usize,
    err: &mut ExternError,
) -> i32 {
    *err = ExternError::success();
    let res = random_vec(bytes);
    match res {
        Ok(v) => {
            *output = ByteBuffer::from_vec(v);
            1
        }
        Err(_) => {
            *err = ExternError::new_error(ErrorCode::new(10), "Unable to generate random bytes");
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ffi_support::{ByteBuffer, ExternError};

    ffi_encryption_test!(
        aes128_cbc_hmac256_encryption,
        Aes128CbcHmac256,
        ursa_aes128_cbc_hmac256_keysize,
        ursa_aes128_cbc_hmac256_noncesize
    );
    ffi_encryption_test!(
        aes256_cbc_hmac512_encryption,
        Aes256CbcHmac512,
        ursa_aes256_cbc_hmac512_keysize,
        ursa_aes256_cbc_hmac512_noncesize
    );
    ffi_encryption_test!(
        aes128_gcm_encryption,
        Aes128Gcm,
        ursa_aes128_gcm_keysize,
        ursa_aes128_gcm_noncesize
    );
    ffi_encryption_test!(
        aes256_gcm_encryption,
        Aes256Gcm,
        ursa_aes256_gcm_keysize,
        ursa_aes256_gcm_noncesize
    );
    ffi_encryption_test!(
        xchacha20_poly1305_encryption,
        XChaCha20Poly1305,
        ursa_xchacha20_poly1305_keysize,
        ursa_xchacha20_poly1305_noncesize
    );
}
