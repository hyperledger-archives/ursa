extern crate libc;

use ffi::ErrorCode;
use errors::ToErrorCode;
use utils::cstring::CStringUtils;
use bls::BlsService;

use self::libc::c_char;

use utils::byte_array::vec_to_pointer;


#[no_mangle]
pub  extern fn indy_crypto_generate_keys(g: *const c_char,
                                         g_raw: *mut *const c_char,
                                         g_len: *mut u32,
                                         sign_key_raw: *mut *const c_char,
                                         sign_key_len: *mut u32,
                                         ver_key_raw: *mut *const c_char,
                                         ver_key_len: *mut u32) -> ErrorCode {
    unimplemented!()
    //    get_byte_array!(g_raw, g_len, ErrorCode::CommonInvalidParam4);
//    check_useful_c_callback!(cb, ErrorCode::CommonInvalidParam3);
//
//    let result = BlsService::generate_keys(&g_raw);
//    let (err, sign_key, ver_key) = result_to_err_code_2!(result, String::new(), String::new());
//
//    unsafe { *value_ptr = CString::new(value.as_str()).unwrap().into_raw(); }
//
//
//    let sign_key = CStringUtils::string_to_cstring(sign_key);
//    let ver_key = CStringUtils::string_to_cstring(ver_key);
//    cb(command_handle, err, sign_key.as_ptr(), ver_key.as_ptr());
//    err
}

#[no_mangle]
pub  extern fn indy_crypto_sign(command_handle: i32,
                                message: *const c_char,
                                sign_key: *const c_char,
                                ver_key: *const c_char,
                                cb: Option<extern fn(xcommand_handle: i32, err: ErrorCode, signature: *const c_char)>) -> ErrorCode {
    unimplemented!()
//    check_useful_c_str!(message, ErrorCode::CommonInvalidParam2);
//    check_useful_c_str!(sign_key, ErrorCode::CommonInvalidParam3);
//    check_useful_c_str!(ver_key, ErrorCode::CommonInvalidParam4);
//    check_useful_c_callback!(cb, ErrorCode::CommonInvalidParam5);
//
//    let result = BlsService::sign(&message, &sign_key, &ver_key);
//    let (err, signature) = result_to_err_code_1!(result, String::new());
//    let signature = CStringUtils::string_to_cstring(signature);
//    cb(command_handle, err, signature.as_ptr());
//    err
}

#[no_mangle]
pub  extern fn indy_crypto_create_multi_signature(command_handle: i32,
                                                  signatures: *const c_char,
                                                  cb: Option<extern fn(xcommand_handle: i32, err: ErrorCode, multi_signature: *const c_char)>) -> ErrorCode {
    unimplemented!()
//    check_useful_c_str!(signatures, ErrorCode::CommonInvalidParam2);
//    check_useful_c_callback!(cb, ErrorCode::CommonInvalidParam1);
//
//    let result = BlsService::create_multi_sig(&signatures);
//    let (err, multi_signature) = result_to_err_code_1!(result, String::new());
//    let multi_signature = CStringUtils::string_to_cstring(multi_signature);
//    cb(command_handle, err, multi_signature.as_ptr());
//    err
}

#[no_mangle]
pub  extern fn indy_crypto_verify(command_handle: i32,
                                  signature: *const c_char,
                                  message: *const c_char,
                                  ver_key: *const c_char,
                                  g: *const c_char,
                                  cb: Option<extern fn(xcommand_handle: i32, err: ErrorCode, valid: bool)>) -> ErrorCode {
    unimplemented!()
//    check_useful_c_str!(signature, ErrorCode::CommonInvalidParam2);
//    check_useful_c_str!(message, ErrorCode::CommonInvalidParam3);
//    check_useful_c_str!(ver_key, ErrorCode::CommonInvalidParam4);
//    check_useful_c_str!(g, ErrorCode::CommonInvalidParam5);
//    check_useful_c_callback!(cb, ErrorCode::CommonInvalidParam6);
//
//    let result = BlsService::verify(&signature, &message, &ver_key, &g);
//    let (err, valid) = result_to_err_code_1!(result, false);
//    cb(command_handle, err, valid);
//    err
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