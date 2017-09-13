use ffi::ErrorCode;
use errors::ToErrorCode;
use utils::ctypes::CTypesUtils;
use bls::Bls;

use std::slice;

/// Creates and returns random generator point that satisfy BLS algorithm requirements.
///
/// BLS algorithm requires choosing of generator point that must be known to all parties.
/// The most of BLS methods require generator to be provided.
///
/// Note: allocated buffer referenced by (gen_p, gen_len_p) must be deallocated by calling
/// indy_crypto_bls_free_array.
///
/// # Arguments
/// * `gen_p` - Reference that will contain generator point buffer pointer
/// * `gen_len_p` - Reference that will contain generator point buffer len
#[no_mangle]
pub  extern fn indy_crypto_bls_create_generator(gen_p: *mut *const u8,
                                                gen_len_p: *mut usize) -> ErrorCode {
    check_useful_c_byte_array_ptr!(gen_p, gen_len_p, ErrorCode::CommonInvalidParam1, ErrorCode::CommonInvalidParam2);

    match Bls::create_generator() {
        Ok(gen) => {
            let (gen, gen_len) = CTypesUtils::vec_to_c_byte_array(gen);
            unsafe {
                *gen_p = gen;
                *gen_len_p = gen_len;
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    }
}

/// Generates and returns random (or known if seed provided) pair of sign and verification keys
///
/// Note: allocated buffers referenced by (sign_key_p, sign_key_len_p) and (ver_key_p, ver_key_len_p)
/// must be deallocated by calling indy_crypto_bls_free_array.
///
/// # Arguments
///
/// * `gen` - Generator point buffer pointer
/// * `gen_len` - Generator point buffer len
/// * `seed` - Seed buffer pinter
/// * `seed_len` - Seed buffer pinter len
/// * `sign_key_p` - Reference that will contain sign key buffer pointer
/// * `sign_key_len_p` - Reference that will contain sign key buffer len
/// * `ver_key_p` - Reference that will contain verification key buffer pointer
/// * `ver_key_len_p` - Reference that will contain verification key buffer len
#[no_mangle]
pub  extern fn indy_crypto_bls_generate_keys(gen: *const u8,
                                             gen_len: usize,
                                             seed: *const u8,
                                             seed_len: usize,
                                             sign_key_p: *mut *const u8,
                                             sign_key_len_p: *mut usize,
                                             ver_key_p: *mut *const u8,
                                             ver_key_len_p: *mut usize) -> ErrorCode {
    check_useful_c_byte_array!(gen, gen_len, ErrorCode::CommonInvalidParam1, ErrorCode::CommonInvalidParam2);
    check_useful_opt_c_byte_array!(seed, seed_len, ErrorCode::CommonInvalidParam3, ErrorCode::CommonInvalidParam4);
    check_useful_c_byte_array_ptr!(sign_key_p, sign_key_len_p, ErrorCode::CommonInvalidParam5, ErrorCode::CommonInvalidParam6);
    check_useful_c_byte_array_ptr!(ver_key_p, ver_key_len_p, ErrorCode::CommonInvalidParam7, ErrorCode::CommonInvalidParam8);

    match Bls::generate_keys(gen, seed) {
        Ok((sign_key, ver_key)) => {
            let (sign_key, sign_key_len) = CTypesUtils::vec_to_c_byte_array(sign_key);
            let (ver_key, ver_key_len) = CTypesUtils::vec_to_c_byte_array(ver_key);
            unsafe {
                *sign_key_p = sign_key;
                *sign_key_len_p = sign_key_len;
                *ver_key_p = ver_key;
                *ver_key_len_p = ver_key_len;
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    }
}

/// Signs the message and returns signature.
///
/// Note: allocated buffer referenced by (signature_p, signature_len_p) must be
/// deallocated by calling indy_crypto_bls_free_array.
///
/// # Arguments
///
/// * `message` - Message to sign buffer pointer
/// * `message_len` - Message to sign buffer len
/// * `sign_key` - Sign key buffer pointer
/// * `sign_key_len` - Sign key buffer len
/// * `signature_p` - Reference that will contain signature buffer pointer
/// * `signature_len_p` - Reference that will contain signature buffer len
#[no_mangle]
pub  extern fn indy_crypto_bls_sign(message: *const u8,
                                    message_len: usize,
                                    sign_key: *const u8,
                                    sign_key_len: usize,
                                    signature_p: *mut *const u8,
                                    signature_len_p: *mut usize) -> ErrorCode {
    check_useful_c_byte_array!(message, message_len, ErrorCode::CommonInvalidParam1, ErrorCode::CommonInvalidParam2);
    check_useful_c_byte_array!(sign_key, sign_key_len, ErrorCode::CommonInvalidParam3, ErrorCode::CommonInvalidParam4);
    check_useful_c_byte_array_ptr!(signature_p, signature_len_p, ErrorCode::CommonInvalidParam5, ErrorCode::CommonInvalidParam6);

    match Bls::sign(message, sign_key) {
        Ok(signature) => {
            let (signature, signature_len) = CTypesUtils::vec_to_c_byte_array(signature);
            unsafe {
                *signature_p = signature;
                *signature_len_p = signature_len;
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    }
}

/// Generates and returns multi signature for provided list of signatures.
///
/// Note: allocated buffer referenced by (multi_sig_p, multi_sig_len_p) must be
/// deallocated by calling indy_crypto_bls_free_array.
///
/// # Arguments
///
/// * `signatures` - Pointer to buffer that contains pointers to signature buffers
/// * `signature_lens` - Pointer to buffer that contains lens of signature buffers
/// * `signatures_len` - Len of buffer that contains pointers to signature buffers
/// * `multi_sig_p` - Reference that will contain multi signature buffer pointer
/// * `multi_sig_len_p` - Reference that will contain multi signature buffer len
#[no_mangle]
pub  extern fn indy_crypto_bls_create_multi_signature(signatures: *const *const u8,
                                                      signature_lens: *const usize,
                                                      signatures_len: usize,
                                                      multi_sig_p: *mut *const u8,
                                                      multi_sig_len_p: *mut usize) -> ErrorCode {
    let signatures: &[*const u8] = unsafe { slice::from_raw_parts(signatures, signatures_len) };
    let signature_lens: &[usize] = unsafe { slice::from_raw_parts(signature_lens, signatures_len) };
    let signatures: Vec<&[u8]> =
        (0..signatures_len)
            .map(|i| unsafe { slice::from_raw_parts(signatures[i], signature_lens[i]) })
            .collect();

    check_useful_c_byte_array_ptr!(multi_sig_p, multi_sig_len_p, ErrorCode::CommonInvalidParam4, ErrorCode::CommonInvalidParam5);

    match Bls::create_multi_sig(&signatures) {
        Ok(multi_sig) => {
            let (multi_sig, multi_sig_len) = CTypesUtils::vec_to_c_byte_array(multi_sig);
            unsafe {
                *multi_sig_p = multi_sig;
                *multi_sig_len_p = multi_sig_len;
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    }
}

/// Verifies the message signature and returns true - if signature valid or false otherwise.
///
/// # Arguments
///
/// * `signature` - Signature to verify buffer pointer
/// * `signature_len` - Signature to verify buffer len
/// * `message` - Message to verify buffer pointer
/// * `message_len` - Message to verify buffer len
/// * `ver_key` - Verification key buffer pinter
/// * `ver_key_len` - Verification key buffer len
/// * `gen` - Generator point buffer pointer
/// * `gen_len` - Generator point buffer len
/// * `valid_p` - Reference that will be filled with true - if signature valid or false otherwise.
#[no_mangle]
pub  extern fn indy_crypto_bsl_verify(signature: *const u8,
                                      signature_len: usize,
                                      message: *const u8,
                                      message_len: usize,
                                      ver_key: *const u8,
                                      ver_key_len: usize,
                                      gen: *const u8,
                                      gen_len: usize,
                                      valid_p: *mut bool) -> ErrorCode {
    check_useful_c_byte_array!(signature, signature_len, ErrorCode::CommonInvalidParam1, ErrorCode::CommonInvalidParam2);
    check_useful_c_byte_array!(message, message_len, ErrorCode::CommonInvalidParam3, ErrorCode::CommonInvalidParam4);
    check_useful_c_byte_array!(ver_key, ver_key_len, ErrorCode::CommonInvalidParam5, ErrorCode::CommonInvalidParam6);
    check_useful_c_byte_array!(gen, gen_len, ErrorCode::CommonInvalidParam7, ErrorCode::CommonInvalidParam8);
    check_useful_c_ptr!(valid_p, ErrorCode::CommonInvalidParam9);

    match Bls::verify(signature, message, ver_key, gen) {
        Ok(valid) => {
            unsafe { *valid_p = valid; }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    }
}

/// Verifies the message multi signature and returns true - if signature valid or false otherwise.
///
/// # Arguments
///
/// * `multi_sig` - Multi signature to verify buffer pointer
/// * `multi_sig` - Multi signature to verify buffer len
/// * `message` - Message to verify buffer pointer
/// * `message_len` - Message to verify buffer len
/// * `ver_keys` - Pointer to buffer that contains pointers to verification key buffers
/// * `ver_key_lens` - Pointer to buffer that contains lens of verification key buffers
/// * `ver_keys_len` - Len of buffer that contains pointers to verification key buffers
/// * `gen` - Generator point buffer pointer
/// * `gen_len` - Generator point buffer len
/// * `valid_p` - Reference that will be filled with true - if signature valid or false otherwise.
#[no_mangle]
pub  extern fn indy_crypto_bls_verify_multi_sig(multi_sig: *const u8,
                                                multi_sig_len: usize,
                                                message: *const u8,
                                                message_len: usize,
                                                ver_keys: *const *const u8,
                                                ver_key_lens: *const usize,
                                                ver_keys_len: usize,
                                                gen: *const u8,
                                                gen_len: usize,
                                                valid_p: *mut bool) -> ErrorCode {
    check_useful_c_byte_array!(multi_sig, multi_sig_len, ErrorCode::CommonInvalidParam1, ErrorCode::CommonInvalidParam2);
    check_useful_c_byte_array!(message, message_len, ErrorCode::CommonInvalidParam3, ErrorCode::CommonInvalidParam4);

    let ver_keys: &[*const u8] = unsafe { slice::from_raw_parts(ver_keys, ver_keys_len) };
    let ver_key_lens: &[usize] = unsafe { slice::from_raw_parts(ver_key_lens, ver_keys_len) };
    let ver_keys: Vec<&[u8]> =
        (0..ver_keys_len)
            .map(|i| unsafe { slice::from_raw_parts(ver_keys[i], ver_key_lens[i]) })
            .collect();

    check_useful_c_byte_array!(gen, gen_len, ErrorCode::CommonInvalidParam8, ErrorCode::CommonInvalidParam9);
    check_useful_c_ptr!(valid_p, ErrorCode::CommonInvalidParam10);

    match Bls::verify_multi_sig(multi_sig, message, &ver_keys, gen) {
        Ok(valid) => {
            unsafe { *valid_p = valid; }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    }
}

#[no_mangle]
pub  extern fn indy_crypto_bls_free_array(ptr: *const u8,
                                          len: usize) -> ErrorCode {
    if ptr.is_null() {
        return ErrorCode::CommonInvalidParam1;
    }

    if len <= 0 {
        return ErrorCode::CommonInvalidParam2;
    }

    CTypesUtils::c_byte_array_to_vec(ptr as *mut u8, len);
    ErrorCode::Success
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;

    #[test]
    fn indy_crypto_bls_create_generator_works() {
        let mut gen: *const u8 = ptr::null();
        let mut gen_len: usize = 0;

        let err_code = indy_crypto_bls_create_generator(&mut gen, &mut gen_len);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!gen.is_null());
        assert!(gen_len > 0);

        let err_code = indy_crypto_bls_free_array(gen, gen_len);
        assert_eq!(err_code, ErrorCode::Success);
    }

    #[test]
    fn indy_crypto_bls_generate_keys_works() {
        let mut gen: *const u8 = ptr::null();
        let mut gen_len: usize = 0;

        let err_code = indy_crypto_bls_create_generator(&mut gen, &mut gen_len);
        assert_eq!(err_code, ErrorCode::Success);

        let seed: *const u8 = ptr::null();
        let seed_len: usize = 0;

        let mut sign_key: *const u8 = ptr::null();
        let mut sign_key_len: usize = 0;
        let mut ver_key: *const u8 = ptr::null();
        let mut ver_key_len: usize = 0;

        let err_code = indy_crypto_bls_generate_keys(gen, gen_len,
                                                     seed, seed_len,
                                                     &mut sign_key, &mut sign_key_len,
                                                     &mut ver_key, &mut ver_key_len);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!sign_key.is_null());
        assert!(sign_key_len > 0);
        assert!(!ver_key.is_null());
        assert!(ver_key_len > 0);

        let err_code = indy_crypto_bls_free_array(gen, gen_len);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = indy_crypto_bls_free_array(sign_key, sign_key_len);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = indy_crypto_bls_free_array(ver_key, ver_key_len);
        assert_eq!(err_code, ErrorCode::Success);
    }

    #[test]
    fn generate_keys_works_for_seed() {
        let mut gen: *const u8 = ptr::null();
        let mut gen_len: usize = 0;

        let err_code = indy_crypto_bls_create_generator(&mut gen, &mut gen_len);
        assert_eq!(err_code, ErrorCode::Success);

        let seed_v = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4,
                          5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8,
                          9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8];
        let seed = seed_v.as_ptr();
        let seed_len = seed_v.len();

        let mut sign_key: *const u8 = ptr::null();
        let mut sign_key_len: usize = 0;
        let mut ver_key: *const u8 = ptr::null();
        let mut ver_key_len: usize = 0;

        let err_code = indy_crypto_bls_generate_keys(gen, gen_len,
                                                     seed, seed_len, &mut sign_key,
                                                     &mut sign_key_len,
                                                     &mut ver_key, &mut ver_key_len);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!sign_key.is_null());
        assert!(sign_key_len > 0);
        assert!(!ver_key.is_null());
        assert!(ver_key_len > 0);

        let err_code = indy_crypto_bls_free_array(gen, gen_len);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = indy_crypto_bls_free_array(sign_key, sign_key_len);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = indy_crypto_bls_free_array(ver_key, ver_key_len);
        assert_eq!(err_code, ErrorCode::Success);
    }

    #[test]
    fn indy_crypto_bls_sign_works() {
        let mut gen: *const u8 = ptr::null();
        let mut gen_len: usize = 0;

        let err_code = indy_crypto_bls_create_generator(&mut gen, &mut gen_len);
        assert_eq!(err_code, ErrorCode::Success);

        let seed: *const u8 = ptr::null();
        let seed_len: usize = 0;

        let mut sign_key: *const u8 = ptr::null();
        let mut sign_key_len: usize = 0;
        let mut ver_key: *const u8 = ptr::null();
        let mut ver_key_len: usize = 0;

        let err_code = indy_crypto_bls_generate_keys(gen, gen_len,
                                                     seed, seed_len,
                                                     &mut sign_key, &mut sign_key_len,
                                                     &mut ver_key, &mut ver_key_len);
        assert_eq!(err_code, ErrorCode::Success);

        let message_v = vec![1, 2, 3, 4, 5];
        let message = message_v.as_ptr();
        let message_len = message_v.len();

        let mut signature: *const u8 = ptr::null();
        let mut signature_len: usize = 0;

        let err_code = indy_crypto_bls_sign(message, message_len,
                                            sign_key, sign_key_len,
                                            &mut signature, &mut signature_len);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!signature.is_null());
        assert!(signature_len > 0);

        let err_code = indy_crypto_bls_free_array(gen, gen_len);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = indy_crypto_bls_free_array(sign_key, sign_key_len);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = indy_crypto_bls_free_array(ver_key, ver_key_len);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = indy_crypto_bls_free_array(signature, signature_len);
        assert_eq!(err_code, ErrorCode::Success);
    }

    #[test]
    fn indy_crypto_bls_create_multi_signature_works() {
        let mut gen: *const u8 = ptr::null();
        let mut gen_len: usize = 0;

        let err_code = indy_crypto_bls_create_generator(&mut gen, &mut gen_len);
        assert_eq!(err_code, ErrorCode::Success);

        let seed: *const u8 = ptr::null();
        let seed_len: usize = 0;

        let mut sign_key1: *const u8 = ptr::null();
        let mut sign_key1_len: usize = 0;
        let mut ver_key1: *const u8 = ptr::null();
        let mut ver_key1_len: usize = 0;

        let err_code = indy_crypto_bls_generate_keys(gen, gen_len,
                                                     seed, seed_len,
                                                     &mut sign_key1, &mut sign_key1_len,
                                                     &mut ver_key1, &mut ver_key1_len);
        assert_eq!(err_code, ErrorCode::Success);

        let mut sign_key2: *const u8 = ptr::null();
        let mut sign_key2_len: usize = 0;
        let mut ver_key2: *const u8 = ptr::null();
        let mut ver_key2_len: usize = 0;

        let err_code = indy_crypto_bls_generate_keys(gen, gen_len,
                                                     seed, seed_len,
                                                     &mut sign_key2, &mut sign_key2_len,
                                                     &mut ver_key2, &mut ver_key2_len);
        assert_eq!(err_code, ErrorCode::Success);

        let message_v = vec![1, 2, 3, 4, 5];
        let message = message_v.as_ptr();
        let message_len = message_v.len();

        let mut signature1: *const u8 = ptr::null();
        let mut signature1_len: usize = 0;

        let err_code = indy_crypto_bls_sign(message, message_len,
                                            sign_key1, sign_key1_len,
                                            &mut signature1, &mut signature1_len);
        assert_eq!(err_code, ErrorCode::Success);

        let mut signature2: *const u8 = ptr::null();
        let mut signature2_len: usize = 0;

        let err_code = indy_crypto_bls_sign(message, message_len,
                                            sign_key2, sign_key2_len,
                                            &mut signature2, &mut signature2_len);
        assert_eq!(err_code, ErrorCode::Success);

        let signatures_v = vec![
            signature1,
            signature2
        ];
        let signatures = signatures_v.as_ptr();
        let signatures_len = signatures_v.len();

        let signature_lens_v = vec![
            signature1_len,
            signature2_len
        ];
        let signature_lens = signature_lens_v.as_ptr();

        let mut multi_sig: *const u8 = ptr::null();
        let mut multi_sig_len: usize = 0;

        let err_code = indy_crypto_bls_create_multi_signature(signatures, signature_lens, signatures_len,
                                                              &mut multi_sig, &mut multi_sig_len);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!multi_sig.is_null());
        assert!(multi_sig_len > 0);

        let err_code = indy_crypto_bls_free_array(gen, gen_len);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = indy_crypto_bls_free_array(sign_key1, sign_key1_len);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = indy_crypto_bls_free_array(ver_key1, ver_key1_len);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = indy_crypto_bls_free_array(signature1, signature1_len);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = indy_crypto_bls_free_array(signature2, signature2_len);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = indy_crypto_bls_free_array(multi_sig, multi_sig_len);
        assert_eq!(err_code, ErrorCode::Success);
    }


    #[test]
    fn indy_crypto_bsl_verify_works() {
        let mut gen: *const u8 = ptr::null();
        let mut gen_len: usize = 0;

        let err_code = indy_crypto_bls_create_generator(&mut gen, &mut gen_len);
        assert_eq!(err_code, ErrorCode::Success);

        let seed: *const u8 = ptr::null();
        let seed_len: usize = 0;

        let mut sign_key: *const u8 = ptr::null();
        let mut sign_key_len: usize = 0;
        let mut ver_key: *const u8 = ptr::null();
        let mut ver_key_len: usize = 0;

        let err_code = indy_crypto_bls_generate_keys(gen, gen_len,
                                                     seed, seed_len,
                                                     &mut sign_key, &mut sign_key_len,
                                                     &mut ver_key, &mut ver_key_len);
        assert_eq!(err_code, ErrorCode::Success);

        let message_v = vec![1, 2, 3, 4, 5];
        let message = message_v.as_ptr();
        let message_len = message_v.len();

        let mut signature: *const u8 = ptr::null();
        let mut signature_len: usize = 0;

        let err_code = indy_crypto_bls_sign(message, message_len,
                                            sign_key, sign_key_len,
                                            &mut signature, &mut signature_len);
        assert_eq!(err_code, ErrorCode::Success);

        let mut valid = false;

        let err_code = indy_crypto_bsl_verify(signature, signature_len,
                                              message, message_len,
                                              ver_key, ver_key_len,
                                              gen, gen_len, &mut valid);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(valid);

        let err_code = indy_crypto_bls_free_array(gen, gen_len);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = indy_crypto_bls_free_array(sign_key, sign_key_len);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = indy_crypto_bls_free_array(ver_key, ver_key_len);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = indy_crypto_bls_free_array(signature, signature_len);
        assert_eq!(err_code, ErrorCode::Success);
    }

    #[test]
    fn indy_crypto_bls_verify_multi_sig_works() {
        let mut gen: *const u8 = ptr::null();
        let mut gen_len: usize = 0;

        let err_code = indy_crypto_bls_create_generator(&mut gen, &mut gen_len);
        assert_eq!(err_code, ErrorCode::Success);

        let seed: *const u8 = ptr::null();
        let seed_len: usize = 0;

        let mut sign_key1: *const u8 = ptr::null();
        let mut sign_key1_len: usize = 0;
        let mut ver_key1: *const u8 = ptr::null();
        let mut ver_key1_len: usize = 0;

        let err_code = indy_crypto_bls_generate_keys(gen, gen_len,
                                                     seed, seed_len,
                                                     &mut sign_key1, &mut sign_key1_len,
                                                     &mut ver_key1, &mut ver_key1_len);
        assert_eq!(err_code, ErrorCode::Success);

        let mut sign_key2: *const u8 = ptr::null();
        let mut sign_key2_len: usize = 0;
        let mut ver_key2: *const u8 = ptr::null();
        let mut ver_key2_len: usize = 0;

        let err_code = indy_crypto_bls_generate_keys(gen, gen_len,
                                                     seed, seed_len,
                                                     &mut sign_key2, &mut sign_key2_len,
                                                     &mut ver_key2, &mut ver_key2_len);
        assert_eq!(err_code, ErrorCode::Success);

        let message_v = vec![1, 2, 3, 4, 5];
        let message = message_v.as_ptr();
        let message_len = message_v.len();

        let mut signature1: *const u8 = ptr::null();
        let mut signature1_len: usize = 0;

        let err_code = indy_crypto_bls_sign(message, message_len,
                                            sign_key1, sign_key1_len,
                                            &mut signature1, &mut signature1_len);
        assert_eq!(err_code, ErrorCode::Success);

        let mut signature2: *const u8 = ptr::null();
        let mut signature2_len: usize = 0;

        let err_code = indy_crypto_bls_sign(message, message_len,
                                            sign_key2, sign_key2_len,
                                            &mut signature2, &mut signature2_len);
        assert_eq!(err_code, ErrorCode::Success);

        let signatures_v = vec![
            signature1,
            signature2
        ];
        let signatures = signatures_v.as_ptr();
        let signatures_len = signatures_v.len();

        let signature_lens_v = vec![
            signature1_len,
            signature2_len
        ];
        let signature_lens = signature_lens_v.as_ptr();

        let mut multi_sig: *const u8 = ptr::null();
        let mut multi_sig_len: usize = 0;

        let err_code = indy_crypto_bls_create_multi_signature(signatures, signature_lens, signatures_len,
                                                              &mut multi_sig, &mut multi_sig_len);
        assert_eq!(err_code, ErrorCode::Success);

        let ver_keys_v = vec![
            ver_key1,
            ver_key2
        ];
        let ver_keys = ver_keys_v.as_ptr();
        let ver_keys_len = ver_keys_v.len();

        let ver_key_lens_v = vec![
            ver_key1_len,
            ver_key2_len
        ];
        let ver_key_lens = ver_key_lens_v.as_ptr();

        let mut valid = false;

        let err_code = indy_crypto_bls_verify_multi_sig(multi_sig, multi_sig_len,
                                                        message, message_len,
                                                        ver_keys, ver_key_lens, ver_keys_len,
                                                        gen, gen_len,
                                                        &mut valid);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(valid);

        let err_code = indy_crypto_bls_free_array(gen, gen_len);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = indy_crypto_bls_free_array(sign_key1, sign_key1_len);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = indy_crypto_bls_free_array(ver_key1, ver_key1_len);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = indy_crypto_bls_free_array(signature1, signature1_len);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = indy_crypto_bls_free_array(signature2, signature2_len);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = indy_crypto_bls_free_array(multi_sig, multi_sig_len);
        assert_eq!(err_code, ErrorCode::Success);
    }
}