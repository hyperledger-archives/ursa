extern crate libc;

use ffi::ErrorCode;
use errors::ToErrorCode;
use utils::cstring::CStringUtils;
use bls::BlsService;
use std::ffi::CString;

use self::libc::c_char;

use utils::byte_array::vec_to_pointer;
use std::slice;

#[no_mangle]
pub  extern fn indy_crypto_bls_create_generator(g_ptr: *mut *const c_char,
                                                g_len: *mut u32) -> ErrorCode {
    match BlsService::create_generator() {
        Ok(g) => {
            let (g, g_l) = vec_to_pointer(&g);
            unsafe { *g_ptr = g; }
            unsafe { *g_len = g_l; }
            return ErrorCode::Success;
        }
        Err(err) => err.to_error_code()
    }
}

#[no_mangle]
pub  extern fn indy_crypto_generate_keys(g_raw: *const u8,
                                         g_len: u32,
                                         nonce_raw: *const u8,
                                         nonce_len: u32,
                                         sign_key_ptr: *mut *const c_char,
                                         sign_key_len: *mut u32,
                                         ver_key_ptr: *mut *const c_char,
                                         ver_key_len: *mut u32) -> ErrorCode {
    get_byte_array!(g_raw, g_len, ErrorCode::CommonInvalidParam1);
    check_useful_opt_byte_array!(nonce_raw, nonce_len, ErrorCode::CommonInvalidParam3);

    match BlsService::generate_keys(g_raw, nonce_raw) {
        Ok((sign_key, ver_key)) => {
            let (sign_key, sign_key_l) = vec_to_pointer(&sign_key);
            let (ver_key, ver_key_l) = vec_to_pointer(&ver_key);
            unsafe { *sign_key_ptr = sign_key; }
            unsafe { *sign_key_len = sign_key_l; }
            unsafe { *ver_key_ptr = ver_key; }
            unsafe { *ver_key_len = ver_key_l; }
            return ErrorCode::Success;
        }
        Err(err) => err.to_error_code()
    }
}

#[no_mangle]
pub  extern fn indy_crypto_sign(message: *const c_char,
                                sign_key_raw: *const u8,
                                sign_key_len: u32,
                                ver_key_raw: *const u8,
                                ver_key_len: u32,
                                signature_ptr: *mut *const c_char,
                                signature_len: *mut u32) -> ErrorCode {
    check_useful_c_str!(message, ErrorCode::CommonInvalidParam1);
    get_byte_array!(sign_key_raw, sign_key_len, ErrorCode::CommonInvalidParam3);
    get_byte_array!(ver_key_raw, ver_key_len, ErrorCode::CommonInvalidParam5);

    match BlsService::sign(&message, sign_key_raw, ver_key_raw) {
        Ok(signature) => {
            let (signature, signature_l) = vec_to_pointer(&signature);
            unsafe { *signature_ptr = signature; }
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
//    get_byte_array!(signatures_raw, signatures_len, ErrorCode::CommonInvalidParam1);
//
//    match BlsService::create_multi_sig(signatures_raw) {
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
pub  extern fn indy_crypto_verify(signatures_raw: *const u8,
                                  signatures_len: u32,
                                  message: *const c_char,
                                  ver_key_raw: *const u8,
                                  ver_key_len: u32,
                                  g_raw: *const u8,
                                  g_len: u32,
                                  valid: *mut bool) -> ErrorCode {
    get_byte_array!(signatures_raw, signatures_len, ErrorCode::CommonInvalidParam1);
    check_useful_c_str!(message, ErrorCode::CommonInvalidParam3);
    get_byte_array!(ver_key_raw, ver_key_len, ErrorCode::CommonInvalidParam4);
    get_byte_array!(g_raw, g_len, ErrorCode::CommonInvalidParam6);

    match BlsService::verify(signatures_raw, &message, ver_key_raw, g_raw) {
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
    //    let result = BlsService::verify_multi_sig(&signature, &message, &ver_keys, &g);
    //    let (err, valid) = result_to_err_code_1!(result, false);
    //    cb(command_handle, err, valid);
    //    err
}