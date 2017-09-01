extern crate libc;

use ffi::ErrorCode;
use errors::ToErrorCode;
use utils::ctypes::CTypesUtils;
use bls::Bls;

use self::libc::c_char;
use std::slice;

#[no_mangle]
pub  extern fn indy_crypto_bls_create_generator(gen_p: *mut *const c_char,
                                                gen_len: *mut u32) -> ErrorCode {
    match Bls::create_generator() {
        Ok(g) => {
            let (g, g_l) = CTypesUtils::vec_to_c_byte_array(&g);
            unsafe { *gen_p = g; }
            unsafe { *gen_len = g_l; }
            return ErrorCode::Success;
        }
        Err(err) => err.to_error_code()
    }
}

#[no_mangle]
pub  extern fn indy_crypto_generate_keys(gen: *const u8,
                                         gen_len: u32,
                                         seed: *const u8,
                                         seed_len: u32,
                                         sign_key_p: *mut *const c_char,
                                         sign_key_len: *mut u32,
                                         ver_key_p: *mut *const c_char,
                                         ver_key_len: *mut u32) -> ErrorCode {
    check_useful_byte_array!(gen, gen_len, ErrorCode::CommonInvalidParam1);
    check_useful_opt_byte_array!(seed, seed_len, ErrorCode::CommonInvalidParam3);

    match Bls::generate_keys(gen, seed) {
        Ok((sign_key, ver_key)) => {
            let (sign_key, sign_key_l) = CTypesUtils::vec_to_c_byte_array(&sign_key);
            let (ver_key, ver_key_l) = CTypesUtils::vec_to_c_byte_array(&ver_key);
            unsafe { *sign_key_p = sign_key; }
            unsafe { *sign_key_len = sign_key_l; }
            unsafe { *ver_key_p = ver_key; }
            unsafe { *ver_key_len = ver_key_l; }
            return ErrorCode::Success;
        }
        Err(err) => err.to_error_code()
    }
}

#[no_mangle]
pub  extern fn indy_crypto_sign(message: *const c_char,
                                sign_key: *const u8,
                                sign_key_len: u32,
                                ver_key: *const u8,
                                ver_key_len: u32,
                                signature_p: *mut *const c_char,
                                signature_len: *mut u32) -> ErrorCode {
    check_useful_c_str!(message, ErrorCode::CommonInvalidParam1);
    check_useful_byte_array!(sign_key, sign_key_len, ErrorCode::CommonInvalidParam3);
    check_useful_byte_array!(ver_key, ver_key_len, ErrorCode::CommonInvalidParam5);

    match Bls::sign(&message, sign_key, ver_key) {
        Ok(signature) => {
            let (signature, signature_l) = CTypesUtils::vec_to_c_byte_array(&signature);
            unsafe { *signature_p = signature; }
            unsafe { *signature_len = signature_l; }
            return ErrorCode::Success;
        }
        Err(err) => err.to_error_code()
    }
}

#[no_mangle]
pub  extern fn indy_crypto_create_multi_signature(signatures_raw: *const u8,
                                                  signatures_len: u32,
                                                  signature_ptr: *mut *const c_char,
                                                  signature_len: *mut u32) -> ErrorCode {
    unimplemented!()
    //    check_useful_byte_array!(signatures_raw, signatures_len, ErrorCode::CommonInvalidParam1);
    //
    //    match Bls::create_multi_sig(signatures_raw) {
    //        Ok(signature) => {
    //            let (signature, signature_l) = vec_to_pointer(&signature);
    //            unsafe { *signature_ptr = signature; }
    //            unsafe { *signature_len = signature_l; }
    //            return ErrorCode::Success;
    //        }
    //        Err(err) => err.to_error_code()
    //    }
}

#[no_mangle]
pub  extern fn indy_crypto_verify(signature: *const u8,
                                  signature_len: u32,
                                  message: *const c_char,
                                  ver_key: *const u8,
                                  ver_key_len: u32,
                                  gen: *const u8,
                                  gen_len: u32,
                                  valid: *mut bool) -> ErrorCode {
    check_useful_byte_array!(signature, signature_len, ErrorCode::CommonInvalidParam1);
    check_useful_c_str!(message, ErrorCode::CommonInvalidParam3);
    check_useful_byte_array!(ver_key, ver_key_len, ErrorCode::CommonInvalidParam4);
    check_useful_byte_array!(gen, gen_len, ErrorCode::CommonInvalidParam6);

    match Bls::verify(signature, &message, ver_key, gen) {
        Ok(v) => {
            unsafe { *valid = v; }
            return ErrorCode::Success;
        }
        Err(err) => err.to_error_code()
    }
}

#[no_mangle]
pub  extern fn indy_crypto_verify_multi_sig(command_handle: i32,
                                            signature: *const c_char,
                                            message: *const c_char,
                                            ver_keys: *const c_char,
                                            g: *const c_char,
                                            cb: Option<extern fn(xcommand_handle: i32, err: ErrorCode, valid: bool)>) -> ErrorCode {
    unimplemented!()
    //    check_useful_c_str!(signature, ErrorCode::CommonInvalidParam2);
    //    check_useful_c_str!(message, ErrorCode::CommonInvalidParam3);
    //    check_useful_c_str!(ver_keys, ErrorCode::CommonInvalidParam4);
    //    check_useful_c_str!(g, ErrorCode::CommonInvalidParam5);
    //    check_useful_c_callback!(cb, ErrorCode::CommonInvalidParam6);
    //
    //    let result = Bls::verify_multi_sig(&signature, &message, &ver_keys, &g);
    //    let (err, valid) = result_to_err_code_1!(result, false);
    //    cb(command_handle, err, valid);
    //    err
}