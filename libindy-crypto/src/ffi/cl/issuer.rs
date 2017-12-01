use cl::issuer::*;
use cl::*;
use errors::ToErrorCode;
use ffi::ErrorCode;
use utils::ctypes::CTypesUtils;
use utils::json::{JsonEncodable, JsonDecodable};

use libc::c_char;

use std::os::raw::c_void;

/// Creates and returns issuer keys (public and private) entities.
///
/// Note that keys instances deallocation must be performed by
/// calling indy_crypto_cl_issuer_public_key_free and indy_crypto_cl_issuer_private_key_free.
///
/// # Arguments
/// * `claim_schema` - Reference that contains claim schema instance pointer.
/// * `non_revocation_part` - If true non revocation part of issuer keys will be generated.
/// * `issuer_pub_key_p` - Reference that will contain issuer public key instance pointer.
/// * `issuer_priv_key_p` - Reference that will contain issuer private key instance pointer.
#[no_mangle]
pub extern fn indy_crypto_cl_issuer_new_keys(claim_schema: *const c_void,
                                             non_revocation_part: bool,
                                             issuer_pub_key_p: *mut *const c_void,
                                             issuer_priv_key_p: *mut *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_issuer_new_keys: >>> claim_schema: {:?}, non_revocation_part: {:?}, issuer_pub_key_p: {:?}, issuer_priv_key_p: {:?}",
           claim_schema, non_revocation_part, issuer_pub_key_p, issuer_priv_key_p);

    check_useful_c_reference!(claim_schema, ClaimSchema, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(issuer_pub_key_p, ErrorCode::CommonInvalidParam3);
    check_useful_c_ptr!(issuer_priv_key_p, ErrorCode::CommonInvalidParam4);

    trace!("indy_crypto_cl_issuer_new_keys: entities: claim_schema: {:?}, non_revocation_part: {:?}", non_revocation_part, claim_schema);

    let res = match Issuer::new_keys(claim_schema, non_revocation_part) {
        Ok((issuer_pub_key, issuer_priv_key)) => {
            trace!("indy_crypto_cl_issuer_new_keys: issuer_pub_key: {:?}, issuer_priv_key: {:?}", issuer_pub_key, issuer_priv_key);
            unsafe {
                *issuer_pub_key_p = Box::into_raw(Box::new(issuer_pub_key)) as *const c_void;
                *issuer_priv_key_p = Box::into_raw(Box::new(issuer_priv_key)) as *const c_void;
                trace!("indy_crypto_cl_issuer_new_keys: *issuer_pub_key_p: {:?}, *issuer_priv_key_p: {:?}", *issuer_pub_key_p, *issuer_priv_key_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_cl_issuer_new_keys: <<< res: {:?}", res);
    res
}

/// Returns json representation of issuer public key.
///
/// # Arguments
/// * `issuer_pub_key` - Reference that contains issuer public key instance pointer.
/// * `issuer_pub_key_p` - Reference that will contain issuer public key json.
#[no_mangle]
pub extern fn indy_crypto_cl_issuer_public_key_to_json(issuer_pub_key: *const c_void,
                                                       issuer_pub_key_json_p: *mut *const c_char) -> ErrorCode {
    trace!("indy_crypto_cl_issuer_public_key_to_json: >>> issuer_pub_key: {:?}, issuer_pub_key_json_p: {:?}", issuer_pub_key, issuer_pub_key_json_p);

    check_useful_c_reference!(issuer_pub_key, IssuerPublicKey, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(issuer_pub_key_json_p, ErrorCode::CommonInvalidParam2);

    trace!("indy_crypto_cl_issuer_public_key_to_json: entity >>> issuer_pub_key: {:?}", issuer_pub_key);

    let res = match issuer_pub_key.to_json() {
        Ok(issuer_pub_key_json) => {
            trace!("indy_crypto_cl_issuer_public_key_to_json: issuer_pub_key_json: {:?}", issuer_pub_key_json);
            unsafe {
                let issuer_pub_key_json = CTypesUtils::string_to_cstring(issuer_pub_key_json);
                *issuer_pub_key_json_p = issuer_pub_key_json.into_raw();
                trace!("indy_crypto_cl_issuer_private_key_to_json: issuer_pub_key_json_p: {:?}", *issuer_pub_key_json_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_cl_issuer_public_key_to_json: <<< res: {:?}", res);
    res
}

/// Creates and returns issuer public key from json.
///
/// Note: Issuer public key instance deallocation must be performed
/// by calling indy_crypto_cl_issuer_public_key_free
///
/// # Arguments
/// * `issuer_pub_key_json` - Reference that contains issuer public key json.
/// * `issuer_pub_key_p` - Reference that will contain issuer public key instance pointer.
#[no_mangle]
pub extern fn indy_crypto_cl_issuer_public_key_from_json(issuer_pub_key_json: *const c_char,
                                                         issuer_pub_key_p: *mut *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_issuer_public_key_from_json: >>> issuer_pub_key_json: {:?}, issuer_pub_key_p: {:?}", issuer_pub_key_json, issuer_pub_key_p);

    check_useful_c_str!(issuer_pub_key_json, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(issuer_pub_key_p, ErrorCode::CommonInvalidParam2);

    trace!("indy_crypto_cl_issuer_public_key_from_json: entity: issuer_pub_key_json: {:?}", issuer_pub_key_json);

    let res = match IssuerPublicKey::from_json(&issuer_pub_key_json) {
        Ok(issuer_pub_key) => {
            trace!("indy_crypto_cl_issuer_public_key_from_json: issuer_pub_key: {:?}", issuer_pub_key);
            unsafe {
                *issuer_pub_key_p = Box::into_raw(Box::new(issuer_pub_key)) as *const c_void;
                trace!("indy_crypto_cl_issuer_public_key_from_json: *issuer_pub_key_p: {:?}", *issuer_pub_key_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_cl_issuer_public_key_from_json: <<< res: {:?}", res);
    res
}

/// Deallocates issuer public key instance.
///
/// # Arguments
/// * `issuer_pub_key` - Reference that contains issuer public key instance pointer.
#[no_mangle]
pub extern fn indy_crypto_cl_issuer_public_key_free(issuer_pub_key: *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_issuer_public_key_free: >>> issuer_pub_key: {:?}", issuer_pub_key);

    check_useful_c_ptr!(issuer_pub_key, ErrorCode::CommonInvalidParam1);

    let issuer_pub_key = unsafe { Box::from_raw(issuer_pub_key as *mut IssuerPublicKey); };
    trace!("indy_crypto_cl_issuer_public_key_free: entity: issuer_pub_key: {:?}", issuer_pub_key);

    let res = ErrorCode::Success;

    trace!("indy_crypto_cl_issuer_public_key_free: <<< res: {:?}", res);
    res
}

/// Returns json representation of issuer private key.
///
/// # Arguments
/// * `issuer_priv_key` - Reference that contains issuer private key instance pointer.
/// * `issuer_pub_key_p` - Reference that will contain issuer private key json.
#[no_mangle]
pub extern fn indy_crypto_cl_issuer_private_key_to_json(issuer_priv_key: *const c_void,
                                                        issuer_priv_key_json_p: *mut *const c_char) -> ErrorCode {
    trace!("indy_crypto_cl_issuer_private_key_to_json: >>> issuer_priv_key: {:?}, issuer_priv_key_json_p: {:?}", issuer_priv_key, issuer_priv_key_json_p);

    check_useful_c_reference!(issuer_priv_key, IssuerPrivateKey, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(issuer_priv_key_json_p, ErrorCode::CommonInvalidParam2);

    trace!("indy_crypto_cl_issuer_private_key_to_json: entity >>> issuer_priv_key: {:?}", issuer_priv_key);

    let res = match issuer_priv_key.to_json() {
        Ok(issuer_priv_key_json) => {
            trace!("indy_crypto_cl_issuer_private_key_to_json: issuer_priv_key_json: {:?}", issuer_priv_key_json);
            unsafe {
                let issuer_priv_key_json = CTypesUtils::string_to_cstring(issuer_priv_key_json);
                *issuer_priv_key_json_p = issuer_priv_key_json.into_raw();
                trace!("indy_crypto_cl_issuer_private_key_to_json: issuer_priv_key_json_p: {:?}", *issuer_priv_key_json_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_cl_issuer_private_key_to_json: <<< res: {:?}", res);
    res
}

/// Creates and returns issuer private key from json.
///
/// Note: Issuer private key instance deallocation must be performed
/// by calling indy_crypto_cl_issuer_private_key_free
///
/// # Arguments
/// * `issuer_priv_key_json` - Reference that contains issuer private key json.
/// * `issuer_priv_key_p` - Reference that will contain issuer private key instance pointer.
#[no_mangle]
pub extern fn indy_crypto_cl_issuer_private_key_from_json(issuer_priv_key_json: *const c_char,
                                                          issuer_priv_key_p: *mut *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_issuer_private_key_from_json: >>> issuer_priv_key_json: {:?}, issuer_priv_key_p: {:?}", issuer_priv_key_json, issuer_priv_key_p);

    check_useful_c_str!(issuer_priv_key_json, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(issuer_priv_key_p, ErrorCode::CommonInvalidParam2);

    trace!("indy_crypto_cl_issuer_private_key_from_json: entity: issuer_priv_key_json: {:?}", issuer_priv_key_json);

    let res = match IssuerPrivateKey::from_json(&issuer_priv_key_json) {
        Ok(issuer_priv_key) => {
            trace!("indy_crypto_cl_issuer_private_key_from_json: issuer_priv_key: {:?}", issuer_priv_key);
            unsafe {
                *issuer_priv_key_p = Box::into_raw(Box::new(issuer_priv_key)) as *const c_void;
                trace!("indy_crypto_cl_issuer_private_key_from_json: *issuer_priv_key_p: {:?}", *issuer_priv_key_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_cl_issuer_private_key_from_json: <<< res: {:?}", res);
    res
}

/// Deallocates issuer private key instance.
///
/// # Arguments
/// * `issuer_priv_key` - Reference that contains issuer private key instance pointer.
#[no_mangle]
pub extern fn indy_crypto_cl_issuer_private_key_free(issuer_priv_key: *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_issuer_private_key_free: >>> issuer_priv_key: {:?}", issuer_priv_key);

    check_useful_c_ptr!(issuer_priv_key, ErrorCode::CommonInvalidParam1);

    let issuer_priv_key = unsafe { Box::from_raw(issuer_priv_key as *mut IssuerPrivateKey); };
    trace!("indy_crypto_cl_issuer_private_key_free: entity: issuer_priv_key: {:?}", issuer_priv_key);

    let res = ErrorCode::Success;

    trace!("indy_crypto_cl_issuer_private_key_free: <<< res: {:?}", res);
    res
}

/// Creates and returns revocation registries (public and private) entities.
///
/// Note that keys registries deallocation must be performed by
/// calling indy_crypto_cl_revocation_registry_public_free and
/// indy_crypto_cl_revocation_registry_private_free.
///
/// # Arguments
/// * `issuer_pub_key` - Reference that contains issuer pub key instance pointer.
/// * `max_claim_num` - Max claim number in generated registry.
/// * `rev_reg_pub_p` - Reference that will contain revocation registry public instance pointer.
/// * `rev_reg_priv_p` - Reference that will contain revocation registry private instance pointer.
#[no_mangle]
pub extern fn indy_crypto_cl_issuer_new_revocation_registry(issuer_pub_key: *const c_void,
                                                            max_claim_num: u32,
                                                            rev_reg_pub_p: *mut *const c_void,
                                                            rev_reg_priv_p: *mut *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_issuer_new_revocation_registry: >>> issuer_pub_key: {:?}, max_claim_num: {:?}, rev_reg_pub_p: {:?}, rev_reg_priv_p: {:?}",
           issuer_pub_key, max_claim_num, rev_reg_pub_p, rev_reg_priv_p);

    check_useful_c_reference!(issuer_pub_key, IssuerPublicKey, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(rev_reg_pub_p, ErrorCode::CommonInvalidParam3);
    check_useful_c_ptr!(rev_reg_priv_p, ErrorCode::CommonInvalidParam4);

    trace!("indy_crypto_cl_issuer_new_revocation_registry: entities: issuer_pub_key: {:?}, max_claim_num: {:?}", issuer_pub_key, max_claim_num);

    let res = match Issuer::new_revocation_registry(issuer_pub_key, max_claim_num) {
        Ok((rev_reg_pub, rev_reg_priv)) => {
            trace!("indy_crypto_cl_issuer_new_revocation_registry: rev_reg_pub: {:?}, rev_reg_priv: {:?}", rev_reg_pub, rev_reg_priv);
            unsafe {
                *rev_reg_pub_p = Box::into_raw(Box::new(rev_reg_pub)) as *const c_void;
                *rev_reg_priv_p = Box::into_raw(Box::new(rev_reg_priv)) as *const c_void;
                trace!("indy_crypto_cl_issuer_new_revocation_registry: *rev_reg_pub_p: {:?}, *rev_reg_priv_p: {:?}", *rev_reg_pub_p, *rev_reg_priv_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_cl_issuer_new_revocation_registry: <<< res: {:?}", res);
    res
}

/// Returns json representation of revocation registry public.
///
/// # Arguments
/// * `rev_reg_public` - Reference that contains issuer revocation registry public pointer.
/// * `rev_reg_public_json_p` - Reference that will contain revocation registry public json.
#[no_mangle]
pub extern fn indy_crypto_cl_revocation_registry_public_to_json(rev_reg_public: *const c_void,
                                                                rev_reg_public_json_p: *mut *const c_char) -> ErrorCode {
    trace!("indy_crypto_cl_revocation_registry_public_to_json: >>> rev_reg_public: {:?}, rev_reg_public_json_p: {:?}", rev_reg_public, rev_reg_public_json_p);

    check_useful_c_reference!(rev_reg_public, RevocationRegistryPublic, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(rev_reg_public_json_p, ErrorCode::CommonInvalidParam2);

    trace!("indy_crypto_cl_revocation_registry_public_to_json: entity >>> rev_reg_public: {:?}", rev_reg_public);

    let res = match rev_reg_public.to_json() {
        Ok(rev_reg_public_json) => {
            trace!("indy_crypto_cl_revocation_registry_public_to_json: rev_reg_public_json: {:?}", rev_reg_public_json);
            unsafe {
                let rev_reg_public_json = CTypesUtils::string_to_cstring(rev_reg_public_json);
                *rev_reg_public_json_p = rev_reg_public_json.into_raw();
                trace!("indy_crypto_cl_revocation_registry_public_to_json: rev_reg_public_json_p: {:?}", *rev_reg_public_json_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_cl_revocation_registry_public_to_json: <<< res: {:?}", res);
    res
}

/// Creates and returns revocation registry public from json.
///
/// Note: Revocation registry public instance deallocation must be performed
/// by calling indy_crypto_cl_revocation_registry_public_free
///
/// # Arguments
/// * `rev_reg_public_json` - Reference that contains revocation registry public json.
/// * `rev_reg_public_p` - Reference that will contain revocation registry public instance pointer.
#[no_mangle]
pub extern fn indy_crypto_cl_revocation_registry_public_from_json(rev_reg_public_json: *const c_char,
                                                                  rev_reg_public_p: *mut *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_revocation_registry_public_from_json: >>> rev_reg_public_json: {:?}, rev_reg_public_p: {:?}", rev_reg_public_json, rev_reg_public_p);

    check_useful_c_str!(rev_reg_public_json, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(rev_reg_public_p, ErrorCode::CommonInvalidParam2);

    trace!("indy_crypto_cl_revocation_registry_public_from_json: entity: rev_reg_public_json: {:?}", rev_reg_public_json);

    let res = match RevocationRegistryPublic::from_json(&rev_reg_public_json) {
        Ok(rev_reg_public) => {
            trace!("indy_crypto_cl_revocation_registry_public_from_json: rev_reg_public: {:?}", rev_reg_public);
            unsafe {
                *rev_reg_public_p = Box::into_raw(Box::new(rev_reg_public)) as *const c_void;
                trace!("indy_crypto_cl_revocation_registry_public_from_json: *rev_reg_public_p: {:?}", *rev_reg_public_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_cl_revocation_registry_public_from_json: <<< res: {:?}", res);
    res
}

/// Deallocates revocation registry public instance.
///
/// # Arguments
/// * `rev_reg_pub` - Reference that contains revocation registry public instance pointer.
#[no_mangle]
pub extern fn indy_crypto_cl_revocation_registry_public_free(rev_reg_pub: *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_revocation_registry_public_free: >>> rev_reg_pub: {:?}", rev_reg_pub);

    check_useful_c_ptr!(rev_reg_pub, ErrorCode::CommonInvalidParam1);
    let rev_reg_pub = unsafe { Box::from_raw(rev_reg_pub as *mut RevocationRegistryPublic); };
    trace!("indy_crypto_cl_revocation_registry_public_free: entity: rev_reg_pub: {:?}", rev_reg_pub);

    let res = ErrorCode::Success;

    trace!("indy_crypto_cl_revocation_registry_public_free: <<< res: {:?}", res);
    res
}

/// Returns json representation of revocation registry private.
///
/// # Arguments
/// * `rev_reg_private` - Reference that contains issuer revocation registry private pointer.
/// * `rev_reg_private_json_p` - Reference that will contain revocation registry private json
#[no_mangle]
pub extern fn indy_crypto_cl_revocation_registry_private_to_json(rev_reg_private: *const c_void,
                                                                 rev_reg_private_json_p: *mut *const c_char) -> ErrorCode {
    trace!("indy_crypto_cl_revocation_registry_private_to_json: >>> rev_reg_private: {:?}, rev_reg_private_json_p: {:?}", rev_reg_private, rev_reg_private_json_p);

    check_useful_c_reference!(rev_reg_private, RevocationRegistryPrivate, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(rev_reg_private_json_p, ErrorCode::CommonInvalidParam2);

    trace!("indy_crypto_cl_revocation_registry_private_to_json: entity >>> rev_reg_private: {:?}", rev_reg_private);

    let res = match rev_reg_private.to_json() {
        Ok(rev_reg_private_json) => {
            trace!("indy_crypto_cl_revocation_registry_private_to_json: rev_reg_private_json: {:?}", rev_reg_private_json);
            unsafe {
                let rev_reg_private_json = CTypesUtils::string_to_cstring(rev_reg_private_json);
                *rev_reg_private_json_p = rev_reg_private_json.into_raw();
                trace!("indy_crypto_cl_revocation_registry_private_to_json: rev_reg_private_json_p: {:?}", *rev_reg_private_json_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_cl_revocation_registry_private_to_json: <<< res: {:?}", res);
    res
}

/// Creates and returns revocation registry private from json.
///
/// Note: Revocation registry private instance deallocation must be performed
/// by calling indy_crypto_cl_revocation_registry_private_free
///
/// # Arguments
/// * `rev_reg_private_json` - Reference that contains revocation registry private json.
/// * `rev_reg_private_p` - Reference that will contain revocation registry private instance pointer
#[no_mangle]
pub extern fn indy_crypto_cl_revocation_registry_private_from_json(rev_reg_private_json: *const c_char,
                                                                   rev_reg_private_p: *mut *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_revocation_registry_private_from_json: >>> rev_reg_private_json: {:?}, rev_reg_private_p: {:?}", rev_reg_private_json, rev_reg_private_p);

    check_useful_c_str!(rev_reg_private_json, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(rev_reg_private_p, ErrorCode::CommonInvalidParam2);

    trace!("indy_crypto_cl_revocation_registry_private_from_json: entity: rev_reg_private_json: {:?}", rev_reg_private_json);

    let res = match RevocationRegistryPrivate::from_json(&rev_reg_private_json) {
        Ok(rev_reg_private) => {
            trace!("indy_crypto_cl_revocation_registry_private_from_json: rev_reg_private: {:?}", rev_reg_private);
            unsafe {
                *rev_reg_private_p = Box::into_raw(Box::new(rev_reg_private)) as *const c_void;
                trace!("indy_crypto_cl_revocation_registry_private_from_json: *rev_reg_private_p: {:?}", *rev_reg_private_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_cl_revocation_registry_private_from_json: <<< res: {:?}", res);
    res
}

/// Deallocates revocation registry private instance.
///
/// # Arguments
/// * `rev_reg_priv` - Reference that contains revocation registry private instance pointer.
#[no_mangle]
pub extern fn indy_crypto_cl_revocation_registry_private_free(rev_reg_priv: *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_revocation_registry_private_free: >>> rev_reg_priv: {:?}", rev_reg_priv);

    check_useful_c_ptr!(rev_reg_priv, ErrorCode::CommonInvalidParam1);

    let rev_reg_priv = unsafe { Box::from_raw(rev_reg_priv as *mut RevocationRegistryPrivate); };
    trace!("indy_crypto_cl_revocation_registry_private_free: entity: rev_reg_priv: {:?}", rev_reg_priv);

    let res = ErrorCode::Success;

    trace!("indy_crypto_cl_revocation_registry_private_free: <<< res: {:?}", res);
    res
}

/// Sign given claim values instance.
///
/// Note that claim_signature deallocation must be performed by
/// calling indy_crypto_cl_claim_signature_free.
///
/// # Arguments
/// * `prover_id` - Reference that contains prover identifier as null terminated string.
/// * `blinded_ms` - Reference that contains blinded master secret instance pointer.
/// * `claim_values` - Reference that contains claim values instance pointer.
/// * `issuer_pub_key` - Reference that contains issuer public key instance pointer.
/// * `issuer_priv_key` - Reference that contains issuer private key instance pointer.
/// * `rev_idx` - (Optional) User index in revocation accumulator. Required for non-revocation claim_signature part generation.
/// * `rev_reg_pub` - (Optional) Reference that contains revocation registry public instance pointer.
/// * `rev_reg_priv` - (Optional) Reference that contains revocation registry private instance pointer.
/// * `claim_signature_p` - Reference that will contain claim signature instance pointer.
#[no_mangle]
pub extern fn indy_crypto_cl_issuer_sign_claim(prover_id: *const c_char,
                                               blinded_ms: *const c_void,
                                               claim_values: *const c_void,
                                               issuer_pub_key: *const c_void,
                                               issuer_priv_key: *const c_void,
                                               rev_idx: i32,
                                               rev_reg_pub: *const c_void,
                                               rev_reg_priv: *const c_void,
                                               claim_signature_p: *mut *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_issuer_sign_claim: >>> prover_id: {:?}, blinded_ms: {:?}, claim_values: {:?}, issuer_pub_key: {:?}, \
    issuer_priv_key: {:?}, rev_idx: {:?}, rev_reg_pub: {:?}, rev_reg_priv: {:?}, claim_signature_p: {:?}",
           prover_id, blinded_ms, claim_values, issuer_pub_key, issuer_priv_key, rev_idx, rev_reg_pub, rev_reg_priv, claim_signature_p);

    check_useful_c_str!(prover_id, ErrorCode::CommonInvalidParam1);
    check_useful_c_reference!(blinded_ms, BlindedMasterSecret, ErrorCode::CommonInvalidParam2);
    check_useful_c_reference!(claim_values, ClaimValues, ErrorCode::CommonInvalidParam3);
    check_useful_c_reference!(issuer_pub_key, IssuerPublicKey, ErrorCode::CommonInvalidParam4);
    check_useful_c_reference!(issuer_priv_key, IssuerPrivateKey, ErrorCode::CommonInvalidParam5);
    check_useful_opt_c_reference!(rev_reg_priv, RevocationRegistryPrivate);
    check_useful_c_ptr!(claim_signature_p, ErrorCode::CommonInvalidParam9);

    let rev_idx = if rev_idx != -1 { Some(rev_idx as u32) } else { None };

    let mut rev_reg_pub = if rev_reg_pub.is_null() { None } else {
        Some(unsafe { Box::from_raw(rev_reg_pub as *mut RevocationRegistryPublic) })
    };

    trace!("indy_crypto_cl_issuer_sign_claim: entities: prover_id: {:?}, blinded_ms: {:?}, claim_values: {:?}, issuer_pub_key: {:?}, \
    issuer_priv_key: {:?}, rev_idx: {:?}, rev_reg_pub: {:?}, rev_reg_priv: {:?}",
           prover_id, blinded_ms, claim_values, issuer_pub_key, issuer_priv_key, rev_idx, rev_reg_pub, rev_reg_priv);

    let res = match Issuer::sign_claim(&prover_id,
                                       &blinded_ms,
                                       &claim_values,
                                       &issuer_pub_key,
                                       &issuer_priv_key,
                                       rev_idx,
                                       rev_reg_pub.as_mut().map(Box::as_mut),
                                       rev_reg_priv) {
        Ok(claim_signature) => {
            trace!("indy_crypto_cl_issuer_sign_claim: claim_signature: {:?}", claim_signature);
            unsafe {
                rev_reg_pub.map(Box::into_raw);
                *claim_signature_p = Box::into_raw(Box::new(claim_signature)) as *const c_void;
                trace!("indy_crypto_cl_issuer_sign_claim: *claim_signature_p: {:?}", *claim_signature_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_cl_issuer_sign_claim: <<< res: {:?}", res);
    res
}

/// Returns json representation of claim signature.
///
/// # Arguments
/// * `claim_signature` - Reference that contains claim signature private pointer.
/// * `claim_signature_json_p` - Reference that will contain claim signature json.
#[no_mangle]
pub extern fn indy_crypto_cl_claim_signature_to_json(claim_signature: *const c_void,
                                                     claim_signature_json_p: *mut *const c_char) -> ErrorCode {
    trace!("indy_crypto_cl_claim_signature_to_json: >>> claim_signature: {:?}, claim_signature_json_p: {:?}", claim_signature, claim_signature_json_p);

    check_useful_c_reference!(claim_signature, ClaimSignature, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(claim_signature_json_p, ErrorCode::CommonInvalidParam2);

    trace!("indy_crypto_cl_claim_signature_to_json: entity >>> claim_signature: {:?}", claim_signature);

    let res = match claim_signature.to_json() {
        Ok(claim_signature_json) => {
            trace!("indy_crypto_cl_claim_signature_to_json: claim_signature_json: {:?}", claim_signature_json);
            unsafe {
                let claim_signature_json = CTypesUtils::string_to_cstring(claim_signature_json);
                *claim_signature_json_p = claim_signature_json.into_raw();
                trace!("indy_crypto_cl_claim_signature_to_json: claim_signature_json_p: {:?}", *claim_signature_json_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_cl_claim_signature_to_json: <<< res: {:?}", res);
    res
}

/// Creates and returns claim signature from json.
///
/// Note: Claim signature instance deallocation must be performed
/// by calling indy_crypto_cl_claim_signature_free
///
/// # Arguments
/// * `claim_signature_json` - Reference that contains claim signature json.
/// * `claim_signature_p` - Reference that will contain claim signature instance pointer.
#[no_mangle]
pub extern fn indy_crypto_cl_claim_signature_from_json(claim_signature_json: *const c_char,
                                                       claim_signature_p: *mut *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_claim_signature_from_json: >>> claim_signature_json: {:?}, claim_signature_p: {:?}", claim_signature_json, claim_signature_p);

    check_useful_c_str!(claim_signature_json, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(claim_signature_p, ErrorCode::CommonInvalidParam2);

    trace!("indy_crypto_cl_claim_signature_from_json: entity: claim_signature_json: {:?}", claim_signature_json);

    let res = match ClaimSignature::from_json(&claim_signature_json) {
        Ok(claim_signature) => {
            trace!("indy_crypto_cl_claim_signature_from_json: claim_signature: {:?}", claim_signature);
            unsafe {
                *claim_signature_p = Box::into_raw(Box::new(claim_signature)) as *const c_void;
                trace!("indy_crypto_cl_claim_signature_from_json: *claim_signature_p: {:?}", *claim_signature_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_cl_claim_signature_from_json: <<< res: {:?}", res);
    res
}

/// Deallocates claim signature signature instance.
///
/// # Arguments
/// * `claim_signature` - Reference that contains claim signature instance pointer.
#[no_mangle]
pub extern fn indy_crypto_cl_claim_signature_free(claim_signature: *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_claim_signature_free: >>> claim_signature: {:?}", claim_signature);

    check_useful_c_ptr!(claim_signature, ErrorCode::CommonInvalidParam1);

    let claim_signature = unsafe { Box::from_raw(claim_signature as *mut ClaimSignature); };
    trace!("indy_crypto_cl_claim_signature_free: entity: claim_signature: {:?}", claim_signature);
    let res = ErrorCode::Success;

    trace!("indy_crypto_cl_claim_signature_free: <<< res: {:?}", res);
    res
}

/// Revokes a claim by a revoc_id in a given revoc-registry.
///
/// # Arguments
/// * `rev_reg_pub` - Reference that contain revocation registry instance pointer.
///  * rev_idx` - index of the user in the accumulator
#[no_mangle]
pub extern fn indy_crypto_cl_issuer_revoke_claim(rev_reg_pub: *const c_void,
                                                 rev_idx: u32) -> ErrorCode {
    trace!("indy_crypto_cl_issuer_revoke_claim: >>> rev_reg_pub: {:?}, rev_idx: {:?}", rev_reg_pub, rev_idx);

    check_useful_mut_c_reference!(rev_reg_pub, RevocationRegistryPublic, ErrorCode::CommonInvalidParam1);

    trace!("indy_crypto_cl_issuer_revoke_claim: entities: rev_reg_pub: {:?}, rev_idx: {:?}", rev_reg_pub, rev_idx);

    let res = match Issuer::revoke_claim(rev_reg_pub, rev_idx) {
        Ok(()) => ErrorCode::Success,
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_cl_issuer_revoke_claim: <<< res: {:?}", res);
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::ptr;
    use ffi::cl::mocks::*;
    use ffi::cl::issuer::mocks::*;
    use ffi::cl::prover::mocks::*;

    #[test]
    fn indy_crypto_cl_issuer_new_keys_works() {
        let claim_schema = _claim_schema();
        let mut issuer_pub_key: *const c_void = ptr::null();
        let mut issuer_priv_key: *const c_void = ptr::null();

        let err_code = indy_crypto_cl_issuer_new_keys(claim_schema,
                                                      true,
                                                      &mut issuer_pub_key,
                                                      &mut issuer_priv_key);

        assert_eq!(err_code, ErrorCode::Success);
        assert!(!issuer_pub_key.is_null());
        assert!(!issuer_priv_key.is_null());

        _free_claim_schema(claim_schema);
        _free_issuer_keys(issuer_pub_key, issuer_priv_key);
    }

    #[test]
    fn indy_crypto_cl_issuer_public_key_to_json_works() {
        let claim_schema = _claim_schema();
        let (issuer_pub_key, issuer_priv_key) = _issuer_keys();

        let mut issuer_pub_key_json_p: *const c_char = ptr::null();
        let err_code = indy_crypto_cl_issuer_public_key_to_json(issuer_pub_key, &mut issuer_pub_key_json_p);
        assert_eq!(err_code, ErrorCode::Success);

        _free_claim_schema(claim_schema);
        _free_issuer_keys(issuer_pub_key, issuer_priv_key);
    }

    #[test]
    fn indy_crypto_cl_issuer_public_key_from_json_works() {
        let claim_schema = _claim_schema();
        let (issuer_pub_key, issuer_priv_key) = _issuer_keys();

        let mut issuer_pub_key_json_p: *const c_char = ptr::null();
        let err_code = indy_crypto_cl_issuer_public_key_to_json(issuer_pub_key, &mut issuer_pub_key_json_p);
        assert_eq!(err_code, ErrorCode::Success);

        let mut issuer_pub_key_p: *const c_void = ptr::null();
        let err_code = indy_crypto_cl_issuer_public_key_from_json(issuer_pub_key_json_p, &mut issuer_pub_key_p);
        assert_eq!(err_code, ErrorCode::Success);

        _free_claim_schema(claim_schema);
        _free_issuer_keys(issuer_pub_key, issuer_priv_key);
    }

    #[test]
    fn indy_crypto_cl_issuer_private_key_to_json_works() {
        let claim_schema = _claim_schema();
        let (issuer_pub_key, issuer_priv_key) = _issuer_keys();

        let mut issuer_priv_key_json_p: *const c_char = ptr::null();
        let err_code = indy_crypto_cl_issuer_private_key_to_json(issuer_priv_key, &mut issuer_priv_key_json_p);
        assert_eq!(err_code, ErrorCode::Success);

        _free_claim_schema(claim_schema);
        _free_issuer_keys(issuer_pub_key, issuer_priv_key);
    }

    #[test]
    fn indy_crypto_cl_issuer_private_key_from_json_works() {
        let claim_schema = _claim_schema();
        let (issuer_pub_key, issuer_priv_key) = _issuer_keys();

        let mut issuer_priv_key_json_p: *const c_char = ptr::null();
        let err_code = indy_crypto_cl_issuer_private_key_to_json(issuer_priv_key, &mut issuer_priv_key_json_p);
        assert_eq!(err_code, ErrorCode::Success);

        let mut issuer_priv_key_p: *const c_void = ptr::null();
        let err_code = indy_crypto_cl_issuer_private_key_from_json(issuer_priv_key_json_p, &mut issuer_priv_key_p);
        assert_eq!(err_code, ErrorCode::Success);

        _free_claim_schema(claim_schema);
        _free_issuer_keys(issuer_pub_key, issuer_priv_key);
    }

    #[test]
    fn indy_crypto_cl_issuer_keys_free_works() {
        let (issuer_pub_key, issuer_priv_key) = _issuer_keys();

        let err_code = indy_crypto_cl_issuer_public_key_free(issuer_pub_key);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = indy_crypto_cl_issuer_private_key_free(issuer_priv_key);
        assert_eq!(err_code, ErrorCode::Success);
    }

    #[test]
    fn indy_crypto_cl_issuer_new_revocation_registry_works() {
        let (issuer_pub_key, issuer_priv_key) = _issuer_keys();
        let mut rev_reg_pub: *const c_void = ptr::null();
        let mut rev_reg_priv: *const c_void = ptr::null();

        let err_code = indy_crypto_cl_issuer_new_revocation_registry(issuer_pub_key, 100, &mut rev_reg_pub, &mut rev_reg_priv);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!rev_reg_pub.is_null());
        assert!(!rev_reg_priv.is_null());

        _free_issuer_keys(issuer_pub_key, issuer_priv_key);
        _free_revocation_registry(rev_reg_pub, rev_reg_priv);
    }

    #[test]
    fn indy_crypto_cl_revocation_registry_public_to_json_works() {
        let (issuer_pub_key, issuer_priv_key) = _issuer_keys();
        let (rev_reg_pub, rev_reg_priv) = _revocation_registry(issuer_pub_key);

        let mut rev_reg_pub_json_p: *const c_char = ptr::null();
        let err_code = indy_crypto_cl_revocation_registry_public_to_json(rev_reg_pub, &mut rev_reg_pub_json_p);
        assert_eq!(err_code, ErrorCode::Success);

        _free_issuer_keys(issuer_pub_key, issuer_priv_key);
        _free_revocation_registry(rev_reg_pub, rev_reg_priv);
    }

    #[test]
    fn indy_crypto_cl_revocation_registry_public_from_json_works() {
        let (issuer_pub_key, issuer_priv_key) = _issuer_keys();
        let (rev_reg_pub, rev_reg_priv) = _revocation_registry(issuer_pub_key);

        let mut rev_reg_pub_json_p: *const c_char = ptr::null();
        let err_code = indy_crypto_cl_revocation_registry_public_to_json(rev_reg_pub, &mut rev_reg_pub_json_p);
        assert_eq!(err_code, ErrorCode::Success);

        let mut rev_reg_pub_p: *const c_void = ptr::null();
        let err_code = indy_crypto_cl_revocation_registry_public_from_json(rev_reg_pub_json_p, &mut rev_reg_pub_p);
        assert_eq!(err_code, ErrorCode::Success);

        _free_issuer_keys(issuer_pub_key, issuer_priv_key);
        _free_revocation_registry(rev_reg_pub, rev_reg_priv);
    }

    #[test]
    fn indy_crypto_cl_revocation_registry_private_to_json_works() {
        let (issuer_pub_key, issuer_priv_key) = _issuer_keys();
        let (rev_reg_pub, rev_reg_priv) = _revocation_registry(issuer_pub_key);

        let mut rev_reg_priv_json_p: *const c_char = ptr::null();
        let err_code = indy_crypto_cl_revocation_registry_private_to_json(rev_reg_priv, &mut rev_reg_priv_json_p);
        assert_eq!(err_code, ErrorCode::Success);

        _free_issuer_keys(issuer_pub_key, issuer_priv_key);
        _free_revocation_registry(rev_reg_pub, rev_reg_priv);
    }

    #[test]
    fn indy_crypto_cl_revocation_registry_private_from_json_works() {
        let (issuer_pub_key, issuer_priv_key) = _issuer_keys();
        let (rev_reg_pub, rev_reg_priv) = _revocation_registry(issuer_pub_key);

        let mut rev_reg_priv_json_p: *const c_char = ptr::null();
        let err_code = indy_crypto_cl_revocation_registry_private_to_json(rev_reg_priv, &mut rev_reg_priv_json_p);
        assert_eq!(err_code, ErrorCode::Success);

        let mut rev_reg_priv_p: *const c_void = ptr::null();
        let err_code = indy_crypto_cl_revocation_registry_private_from_json(rev_reg_priv_json_p, &mut rev_reg_priv_p);
        assert_eq!(err_code, ErrorCode::Success);

        _free_issuer_keys(issuer_pub_key, issuer_priv_key);
        _free_revocation_registry(rev_reg_pub, rev_reg_priv);
    }

    #[test]
    fn indy_crypto_cl_revocation_registries_free_works() {
        let (issuer_pub_key, issuer_priv_key) = _issuer_keys();
        let (rev_reg_pub, rev_reg_priv) = _revocation_registry(issuer_pub_key);

        let err_code = indy_crypto_cl_revocation_registry_public_free(rev_reg_pub);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = indy_crypto_cl_revocation_registry_private_free(rev_reg_priv);
        assert_eq!(err_code, ErrorCode::Success);

        _free_issuer_keys(issuer_pub_key, issuer_priv_key);
    }

    #[test]
    fn indy_crypto_cl_issuer_sign_claim_works() {
        let prover_id = _prover_did();
        let claim_values = _claim_values();
        let (issuer_pub_key, issuer_priv_key) = _issuer_keys();
        let (rev_reg_pub, rev_reg_priv) = _revocation_registry(issuer_pub_key);
        let master_secret = _master_secret();
        let (blinded_master_secret, master_secret_blinding_data) = _blinded_master_secret(issuer_pub_key, master_secret);
        let rev_idx = 1;

        let mut claim_signature: *const c_void = ptr::null();
        let err_code = indy_crypto_cl_issuer_sign_claim(prover_id.as_ptr(),
                                                        blinded_master_secret,
                                                        claim_values,
                                                        issuer_pub_key,
                                                        issuer_priv_key,
                                                        rev_idx,
                                                        rev_reg_pub,
                                                        rev_reg_priv,
                                                        &mut claim_signature);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!claim_signature.is_null());

        _free_issuer_keys(issuer_pub_key, issuer_priv_key);
        _free_revocation_registry(rev_reg_pub, rev_reg_priv);
        _free_claim_values(claim_values);
        _free_blinded_master_secret(blinded_master_secret, master_secret_blinding_data);
        _free_master_secret(master_secret);
        _free_claim_signature(claim_signature);
    }

    #[test]
    fn indy_crypto_cl_claim_signature_to_json_works() {
        let claim_values = _claim_values();
        let (issuer_pub_key, issuer_priv_key) = _issuer_keys();
        let (rev_reg_pub, rev_reg_priv) = _revocation_registry(issuer_pub_key);
        let master_secret = _master_secret();
        let (blinded_master_secret, master_secret_blinding_data) = _blinded_master_secret(issuer_pub_key, master_secret);
        let claim_signature = _claim_signature(blinded_master_secret, issuer_pub_key, issuer_priv_key, rev_reg_pub, rev_reg_priv);


        let mut claim_signature_json_p: *const c_char = ptr::null();
        let err_code = indy_crypto_cl_claim_signature_to_json(claim_signature, &mut claim_signature_json_p);
        assert_eq!(err_code, ErrorCode::Success);

        _free_issuer_keys(issuer_pub_key, issuer_priv_key);
        _free_revocation_registry(rev_reg_pub, rev_reg_priv);
        _free_claim_values(claim_values);
        _free_blinded_master_secret(blinded_master_secret, master_secret_blinding_data);
        _free_master_secret(master_secret);
        _free_claim_signature(claim_signature);
    }

    #[test]
    fn indy_crypto_cl_claim_signature_from_json_works() {
        let claim_values = _claim_values();
        let (issuer_pub_key, issuer_priv_key) = _issuer_keys();
        let (rev_reg_pub, rev_reg_priv) = _revocation_registry(issuer_pub_key);
        let master_secret = _master_secret();
        let (blinded_master_secret, master_secret_blinding_data) = _blinded_master_secret(issuer_pub_key, master_secret);
        let claim_signature = _claim_signature(blinded_master_secret, issuer_pub_key, issuer_priv_key, rev_reg_pub, rev_reg_priv);

        let mut claim_signature_json_p: *const c_char = ptr::null();
        let err_code = indy_crypto_cl_claim_signature_to_json(claim_signature, &mut claim_signature_json_p);
        assert_eq!(err_code, ErrorCode::Success);

        let mut claim_signature_p: *const c_void = ptr::null();
        let err_code = indy_crypto_cl_claim_signature_from_json(claim_signature_json_p, &mut claim_signature_p);
        assert_eq!(err_code, ErrorCode::Success);

        _free_issuer_keys(issuer_pub_key, issuer_priv_key);
        _free_revocation_registry(rev_reg_pub, rev_reg_priv);
        _free_claim_values(claim_values);
        _free_blinded_master_secret(blinded_master_secret, master_secret_blinding_data);
        _free_master_secret(master_secret);
        _free_claim_signature(claim_signature);
    }

    #[test]
    fn indy_crypto_cl_claim_signature_free_works() {
        let (issuer_pub_key, issuer_priv_key) = _issuer_keys();
        let (rev_reg_pub, rev_reg_priv) = _revocation_registry(issuer_pub_key);
        let master_secret = _master_secret();
        let (blinded_master_secret, master_secret_blinding_data) = _blinded_master_secret(issuer_pub_key, master_secret);
        let claim_signature = _claim_signature(blinded_master_secret, issuer_pub_key, issuer_priv_key, rev_reg_pub, rev_reg_priv);

        let err_code = indy_crypto_cl_claim_signature_free(claim_signature);
        assert_eq!(err_code, ErrorCode::Success);

        _free_issuer_keys(issuer_pub_key, issuer_priv_key);
        _free_revocation_registry(rev_reg_pub, rev_reg_priv);
        _free_blinded_master_secret(blinded_master_secret, master_secret_blinding_data);
        _free_master_secret(master_secret);
    }

    #[test]
    fn indy_crypto_cl_issuer_revoke_claim_works() {
        let (issuer_pub_key, issuer_priv_key) = _issuer_keys();
        let (rev_reg_pub, rev_reg_priv) = _revocation_registry(issuer_pub_key);
        let master_secret = _master_secret();
        let (blinded_master_secret, master_secret_blinding_data) = _blinded_master_secret(issuer_pub_key, master_secret);
        let claim_signature = _claim_signature(blinded_master_secret, issuer_pub_key, issuer_priv_key, rev_reg_pub, rev_reg_priv);

        let err_code = indy_crypto_cl_issuer_revoke_claim(rev_reg_pub, 1);
        assert_eq!(err_code, ErrorCode::Success);

        _free_issuer_keys(issuer_pub_key, issuer_priv_key);
        _free_revocation_registry(rev_reg_pub, rev_reg_priv);
        _free_blinded_master_secret(blinded_master_secret, master_secret_blinding_data);
        _free_master_secret(master_secret);
        _free_claim_signature(claim_signature);
    }
}

pub mod mocks {
    use super::*;

    use std::ffi::CString;
    use std::ptr;
    use ffi::cl::mocks::*;

    pub fn _issuer_keys() -> (*const c_void, *const c_void) {
        let claim_schema = _claim_schema();

        let mut issuer_pub_key: *const c_void = ptr::null();
        let mut issuer_priv_key: *const c_void = ptr::null();

        let err_code = indy_crypto_cl_issuer_new_keys(claim_schema, true, &mut issuer_pub_key, &mut issuer_priv_key);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!issuer_pub_key.is_null());
        assert!(!issuer_priv_key.is_null());

        _free_claim_schema(claim_schema);

        (issuer_pub_key, issuer_priv_key)
    }

    pub fn _free_issuer_keys(issuer_pub_key: *const c_void, issuer_priv_key: *const c_void) {
        let err_code = indy_crypto_cl_issuer_public_key_free(issuer_pub_key);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = indy_crypto_cl_issuer_private_key_free(issuer_priv_key);
        assert_eq!(err_code, ErrorCode::Success);
    }

    pub fn _revocation_registry(issuer_pub_key: *const c_void) -> (*const c_void, *const c_void) {
        let mut rev_reg_pub: *const c_void = ptr::null();
        let mut rev_reg_priv: *const c_void = ptr::null();

        let err_code = indy_crypto_cl_issuer_new_revocation_registry(issuer_pub_key, 100, &mut rev_reg_pub, &mut rev_reg_priv);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!rev_reg_pub.is_null());
        assert!(!rev_reg_priv.is_null());

        (rev_reg_pub, rev_reg_priv)
    }

    pub fn _free_revocation_registry(rev_reg_pub: *const c_void, rev_reg_priv: *const c_void) {
        let err_code = indy_crypto_cl_revocation_registry_public_free(rev_reg_pub);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = indy_crypto_cl_revocation_registry_private_free(rev_reg_priv);
        assert_eq!(err_code, ErrorCode::Success);
    }

    pub fn _claim_signature(blinded_master_secret: *const c_void, issuer_pub_key: *const c_void, issuer_priv_key: *const c_void,
                            rev_reg_pub: *const c_void, rev_reg_priv: *const c_void) -> *const c_void {
        let prover_id = _prover_did();
        let claim_values = _claim_values();
        let rev_idx = 1;

        let mut claim_signature: *const c_void = ptr::null();
        let err_code = indy_crypto_cl_issuer_sign_claim(prover_id.as_ptr(),
                                                        blinded_master_secret,
                                                        claim_values,
                                                        issuer_pub_key,
                                                        issuer_priv_key,
                                                        rev_idx,
                                                        rev_reg_pub,
                                                        rev_reg_priv,
                                                        &mut claim_signature);

        assert_eq!(err_code, ErrorCode::Success);
        assert!(!claim_signature.is_null());

        _free_claim_values(claim_values);

        claim_signature
    }

    pub fn _free_claim_signature(claim_signature: *const c_void) {
        let err_code = indy_crypto_cl_claim_signature_free(claim_signature);
        assert_eq!(err_code, ErrorCode::Success);
    }

    pub fn _prover_did() -> CString {
        CString::new("CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW").unwrap()
    }
}