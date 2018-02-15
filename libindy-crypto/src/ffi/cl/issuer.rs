use cl::issuer::*;
use cl::*;
use errors::ToErrorCode;
use ffi::ErrorCode;
use ffi::cl::{FFITailTake, FFITailPut, FFITailsAccessor};
use utils::ctypes::CTypesUtils;
use utils::json::{JsonEncodable, JsonDecodable};

use libc::c_char;

use std::os::raw::c_void;
use std::ptr::null;

/// Creates and returns issuer keys (public and private) entities.
///
/// Note that issuer public key instances deallocation must be performed by
/// calling indy_crypto_cl_issuer_public_key_free.
///
/// Note that issuer private key instances deallocation must be performed by
/// calling indy_crypto_cl_issuer_private_key_free,
/// indy_crypto_cl_issuer_key_correctness_proof_free.
///
/// Note that issuer key correctness proof instances deallocation must be performed by
/// calling indy_crypto_cl_issuer_key_correctness_proof_free.
///
/// # Arguments
/// * `claim_schema` - Reference that contains claim schema instance pointer.
/// * `support_revocation` - If true non revocation part of issuer keys will be generated.
/// * `issuer_pub_key_p` - Reference that will contain issuer public key instance pointer.
/// * `issuer_priv_key_p` - Reference that will contain issuer private key instance pointer.
/// * `issuer_key_correctness_proof_p` - Reference that will contain keys correctness proof instance pointer.
#[no_mangle]
pub extern fn indy_crypto_cl_issuer_new_keys(claim_schema: *const c_void,
                                             support_revocation: bool,
                                             issuer_pub_key_p: *mut *const c_void,
                                             issuer_priv_key_p: *mut *const c_void,
                                             issuer_key_correctness_proof_p: *mut *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_issuer_new_keys: >>> claim_schema: {:?}, support_revocation: {:?}, issuer_pub_key_p: {:?}, issuer_priv_key_p: {:?},\
     issuer_key_correctness_proof_p: {:?}", claim_schema, support_revocation, issuer_pub_key_p, issuer_priv_key_p, issuer_key_correctness_proof_p);

    check_useful_c_reference!(claim_schema, CredentialSchema, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(issuer_pub_key_p, ErrorCode::CommonInvalidParam3);
    check_useful_c_ptr!(issuer_priv_key_p, ErrorCode::CommonInvalidParam4);
    check_useful_c_ptr!(issuer_key_correctness_proof_p, ErrorCode::CommonInvalidParam5);

    trace!("indy_crypto_cl_issuer_new_keys: entities: claim_schema: {:?}, support_revocation: {:?}", support_revocation, claim_schema);

    let res = match Issuer::new_credential_def(claim_schema, support_revocation) {
        Ok((issuer_pub_key, issuer_priv_key, issuer_key_correctness_proof)) => {
            trace!("indy_crypto_cl_issuer_new_keys: issuer_pub_key: {:?}, issuer_priv_key: {:?}, issuer_key_correctness_proof: {:?}",
                   issuer_pub_key, issuer_priv_key, issuer_key_correctness_proof);
            unsafe {
                *issuer_pub_key_p = Box::into_raw(Box::new(issuer_pub_key)) as *const c_void;
                *issuer_priv_key_p = Box::into_raw(Box::new(issuer_priv_key)) as *const c_void;
                *issuer_key_correctness_proof_p = Box::into_raw(Box::new(issuer_key_correctness_proof)) as *const c_void;
                trace!("indy_crypto_cl_issuer_new_keys: *issuer_pub_key_p: {:?}, *issuer_priv_key_p: {:?}, *issuer_key_correctness_proof_p: {:?}",
                       *issuer_pub_key_p, *issuer_priv_key_p, *issuer_key_correctness_proof_p);
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

    check_useful_c_reference!(issuer_pub_key, CredentialPublicKey, ErrorCode::CommonInvalidParam1);
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

    let res = match CredentialPublicKey::from_json(&issuer_pub_key_json) {
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

    let issuer_pub_key = unsafe { Box::from_raw(issuer_pub_key as *mut CredentialPublicKey); };
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

    check_useful_c_reference!(issuer_priv_key, CredentialPrivateKey, ErrorCode::CommonInvalidParam1);
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

    let res = match CredentialPrivateKey::from_json(&issuer_priv_key_json) {
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

    let issuer_priv_key = unsafe { Box::from_raw(issuer_priv_key as *mut CredentialPrivateKey); };
    trace!("indy_crypto_cl_issuer_private_key_free: entity: issuer_priv_key: {:?}", issuer_priv_key);

    let res = ErrorCode::Success;

    trace!("indy_crypto_cl_issuer_private_key_free: <<< res: {:?}", res);
    res
}

/// Returns json representation of key correctness proof.
///
/// # Arguments
/// * `issuer_key_correctness_proof` - Reference that contains issuer key correctness proof instance pointer.
/// * `issuer_key_correctness_proof_p` - Reference that will contain issuer key correctness proof json.
#[no_mangle]
pub extern fn indy_crypto_cl_issuer_key_correctness_proof_to_json(issuer_key_correctness_proof: *const c_void,
                                                                  issuer_key_correctness_proof_json_p: *mut *const c_char) -> ErrorCode {
    trace!("indy_crypto_cl_issuer_key_correctness_proof_to_json: >>> issuer_key_correctness_proof: {:?}, issuer_key_correctness_proof_p: {:?}",
           issuer_key_correctness_proof, issuer_key_correctness_proof_json_p);

    check_useful_c_reference!(issuer_key_correctness_proof, CredentialKeyCorrectnessProof, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(issuer_key_correctness_proof_json_p, ErrorCode::CommonInvalidParam2);

    trace!("indy_crypto_cl_issuer_key_correctness_proof_to_json: entity >>> issuer_key_correctness_proof: {:?}", issuer_key_correctness_proof);

    let res = match issuer_key_correctness_proof.to_json() {
        Ok(issuer_key_correctness_proof_json) => {
            trace!("indy_crypto_cl_issuer_key_correctness_proof_to_json: issuer_key_correctness_proof_json: {:?}", issuer_key_correctness_proof_json);
            unsafe {
                let issuer_key_correctness_proof_json = CTypesUtils::string_to_cstring(issuer_key_correctness_proof_json);
                *issuer_key_correctness_proof_json_p = issuer_key_correctness_proof_json.into_raw();
                trace!("indy_crypto_cl_issuer_key_correctness_proof_to_json: issuer_key_correctness_proof_json_p: {:?}", *issuer_key_correctness_proof_json_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_cl_issuer_key_correctness_proof_to_json: <<< res: {:?}", res);
    res
}

/// Creates and returns issuer key correctness proof from json.
///
/// Note: Issuer key correctness proof instance deallocation must be performed
/// by calling indy_crypto_cl_issuer_key_correctness_proof_free
///
/// # Arguments
/// * `key_correctness_proof_json` - Reference that contains issuer key correctness proof json.
/// * `key_correctness_proof_p` - Reference that will contain issuer key correctness proof instance pointer.
#[no_mangle]
pub extern fn indy_crypto_cl_issuer_key_correctness_proof_from_json(issuer_key_correctness_proof_json: *const c_char,
                                                                    issuer_key_correctness_proof_p: *mut *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_issuer_key_correctness_proof_from_json: >>> issuer_key_correctness_proof_json: {:?}, issuer_key_correctness_proof_p: {:?}",
           issuer_key_correctness_proof_json, issuer_key_correctness_proof_p);

    check_useful_c_str!(issuer_key_correctness_proof_json, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(issuer_key_correctness_proof_p, ErrorCode::CommonInvalidParam2);

    trace!("indy_crypto_cl_issuer_key_correctness_proof_from_json: entity: issuer_key_correctness_proof_json: {:?}", issuer_key_correctness_proof_json);

    let res = match CredentialKeyCorrectnessProof::from_json(&issuer_key_correctness_proof_json) {
        Ok(issuer_key_correctness_proof) => {
            trace!("indy_crypto_cl_issuer_key_correctness_proof_from_json: issuer_key_correctness_proof: {:?}", issuer_key_correctness_proof);
            unsafe {
                *issuer_key_correctness_proof_p = Box::into_raw(Box::new(issuer_key_correctness_proof)) as *const c_void;
                trace!("indy_crypto_cl_issuer_key_correctness_proof_from_json: *issuer_key_correctness_proof_p: {:?}", *issuer_key_correctness_proof_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_cl_issuer_key_correctness_proof_from_json: <<< res: {:?}", res);
    res
}

/// Deallocates issuer key correctness proof instance.
///
/// # Arguments
/// * `issuer_key_correctness_proof` - Reference that contains issuer key correctness proof instance pointer.
#[no_mangle]
pub extern fn indy_crypto_cl_issuer_issuer_key_correctness_proof_free(issuer_key_correctness_proof: *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_issuer_issuer_key_correctness_proof_free: >>> issuer_key_correctness_proof: {:?}", issuer_key_correctness_proof);

    check_useful_c_ptr!(issuer_key_correctness_proof, ErrorCode::CommonInvalidParam1);

    let issuer_key_correctness_proof = unsafe { Box::from_raw(issuer_key_correctness_proof as *mut CredentialKeyCorrectnessProof); };
    trace!("indy_crypto_cl_issuer_issuer_key_correctness_proof_free: entity: issuer_key_correctness_proof: {:?}", issuer_key_correctness_proof);

    let res = ErrorCode::Success;

    trace!("indy_crypto_cl_issuer_issuer_key_correctness_proof_free: <<< res: {:?}", res);
    res
}

/// Creates and returns revocation registries (public and private) entities.
///
/// Note that keys registries deallocation must be performed by
/// calling indy_crypto_cl_revocation_key_public_free and
/// indy_crypto_cl_revocation_key_private_free.
///
/// # Arguments
/// * `issuer_pub_key` - Reference that contains issuer pub key instance pointer.
/// * `max_claim_num` - Max claim number in generated registry.
/// * `issuance_by_default` - Type of issuance. 
/// If true all indices are assumed to be issued and initial accumulator is calculated over all indices
/// If false nothing is issued initially accumulator is 1
/// * `rev_key_pub_p` - Reference that will contain revocation key public instance pointer.
/// * `rev_key_priv_p` - Reference that will contain revocation key private instance pointer.
/// * `rev_reg_entry_p` - Reference that will contain revocation registry entry instance pointer.
/// * `rev_tails_generator_p` - Reference that will contain revocation tails generator instance pointer.
#[no_mangle]
pub extern fn indy_crypto_cl_issuer_new_revocation_registry(issuer_pub_key: *const c_void,
                                                            max_claim_num: u32,
                                                            issuance_by_default: bool,
                                                            rev_key_pub_p: *mut *const c_void,
                                                            rev_key_priv_p: *mut *const c_void,
                                                            rev_reg_entry_p: *mut *const c_void,
                                                            rev_tails_generator_p: *mut *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_issuer_new_revocation_registry: >>> issuer_pub_key: {:?}, max_claim_num: {:?}, rev_key_pub_p: {:?}, rev_key_priv_p: {:?}, \
    rev_reg_entry_p: {:?}, rev_tails_generator_p: {:?}",
           issuer_pub_key, max_claim_num, rev_key_pub_p, rev_key_priv_p, rev_reg_entry_p, rev_tails_generator_p);

    check_useful_c_reference!(issuer_pub_key, CredentialPublicKey, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(rev_key_pub_p, ErrorCode::CommonInvalidParam4);
    check_useful_c_ptr!(rev_key_priv_p, ErrorCode::CommonInvalidParam5);
    check_useful_c_ptr!(rev_reg_entry_p, ErrorCode::CommonInvalidParam6);
    check_useful_c_ptr!(rev_tails_generator_p, ErrorCode::CommonInvalidParam7);

    trace!("indy_crypto_cl_issuer_new_revocation_registry: entities: issuer_pub_key: {:?}, max_claim_num: {:?}", issuer_pub_key, max_claim_num);

    let res = match Issuer::new_revocation_registry_def(issuer_pub_key, max_claim_num, issuance_by_default) {
        Ok((rev_key_pub, rev_key_priv, rev_reg_entry, rev_tails_generator)) => {
            trace!("indy_crypto_cl_issuer_new_revocation_registry: rev_key_pub_p: {:?}, rev_key_priv: {:?}, rev_reg_entry: {:?}, rev_tails_generator: {:?}",
                   rev_key_pub_p, rev_key_priv, rev_reg_entry, rev_tails_generator);
            unsafe {
                *rev_key_pub_p = Box::into_raw(Box::new(rev_key_pub)) as *const c_void;
                *rev_key_priv_p = Box::into_raw(Box::new(rev_key_priv)) as *const c_void;
                *rev_reg_entry_p = Box::into_raw(Box::new(rev_reg_entry)) as *const c_void;
                *rev_tails_generator_p = Box::into_raw(Box::new(rev_tails_generator)) as *const c_void;
                trace!("indy_crypto_cl_issuer_new_revocation_registry: *rev_key_pub_p: {:?}, *rev_key_priv_p: {:?}, *rev_reg_entry_p: {:?}, *rev_tails_generator_p: {:?}",
                       *rev_key_pub_p, *rev_key_priv_p, *rev_reg_entry_p, *rev_tails_generator_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_cl_issuer_new_revocation_registry: <<< res: {:?}", res);
    res
}

/// Returns json representation of revocation key public.
///
/// # Arguments
/// * `rev_key_pub` - Reference that contains issuer revocation key public pointer.
/// * `rev_key_pub_json_p` - Reference that will contain revocation key public json.
#[no_mangle]
pub extern fn indy_crypto_cl_revocation_key_public_to_json(rev_key_pub: *const c_void,
                                                           rev_key_pub_json_p: *mut *const c_char) -> ErrorCode {
    trace!("indy_crypto_cl_revocation_key_public_to_json: >>> rev_key_pub: {:?}, rev_key_pub_json_p: {:?}",
           rev_key_pub, rev_key_pub_json_p);

    check_useful_c_reference!(rev_key_pub, RevocationKeyPublic, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(rev_key_pub_json_p, ErrorCode::CommonInvalidParam2);

    trace!("indy_crypto_cl_revocation_key_public_to_json: entity >>> rev_key_pub: {:?}", rev_key_pub);

    let res = match rev_key_pub.to_json() {
        Ok(rev_key_pub_json) => {
            trace!("indy_crypto_cl_revocation_key_public_to_json: rev_key_pub_json: {:?}", rev_key_pub_json);
            unsafe {
                let rev_reg_def_pub_json = CTypesUtils::string_to_cstring(rev_key_pub_json);
                *rev_key_pub_json_p = rev_reg_def_pub_json.into_raw();
                trace!("indy_crypto_cl_revocation_key_public_to_json: rev_key_pub_json_p: {:?}", *rev_key_pub_json_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_cl_revocation_key_public_to_json: <<< res: {:?}", res);
    res
}

/// Creates and returns revocation key public from json.
///
/// Note: Revocation registry public instance deallocation must be performed
/// by calling indy_crypto_cl_revocation_key_public_free
///
/// # Arguments
/// * `rev_key_pub_json` - Reference that contains revocation key public json.
/// * `rev_key_pub_p` - Reference that will contain revocation key public instance pointer.
#[no_mangle]
pub extern fn indy_crypto_cl_revocation_key_public_from_json(rev_key_pub_json: *const c_char,
                                                             rev_key_pub_p: *mut *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_revocation_key_public_from_json: >>> rev_key_pub_json: {:?}, rev_key_pub_p: {:?}", rev_key_pub_json, rev_key_pub_p);

    check_useful_c_str!(rev_key_pub_json, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(rev_key_pub_p, ErrorCode::CommonInvalidParam2);

    trace!("indy_crypto_cl_revocation_key_public_from_json: entity: rev_key_pub_json: {:?}", rev_key_pub_json);

    let res = match RevocationKeyPublic::from_json(&rev_key_pub_json) {
        Ok(rev_key_pub) => {
            trace!("indy_crypto_cl_revocation_key_public_from_json: rev_key_pub: {:?}", rev_key_pub);
            unsafe {
                *rev_key_pub_p = Box::into_raw(Box::new(rev_key_pub)) as *const c_void;
                trace!("indy_crypto_cl_revocation_key_public_from_json: *rev_key_pub_p: {:?}", *rev_key_pub_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_cl_revocation_key_public_from_json: <<< res: {:?}", res);
    res
}

/// Deallocates revocation registry public instance.
///
/// # Arguments
/// * `rev_key_pub` - Reference that contains revocation key public instance pointer.
#[no_mangle]
pub extern fn indy_crypto_cl_revocation_key_public_free(rev_key_pub: *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_revocation_key_public_free: >>> rev_key_pub: {:?}", rev_key_pub);

    check_useful_c_ptr!(rev_key_pub, ErrorCode::CommonInvalidParam1);
    let rev_key_pub = unsafe { Box::from_raw(rev_key_pub as *mut RevocationKeyPublic); };
    trace!("indy_crypto_cl_revocation_key_public_free: entity: rev_key_pub: {:?}", rev_key_pub);

    let res = ErrorCode::Success;

    trace!("indy_crypto_cl_revocation_key_public_free: <<< res: {:?}", res);
    res
}

/// Returns json representation of revocation key private.
///
/// # Arguments
/// * `rev_key_priv` - Reference that contains issuer revocation key private pointer.
/// * `rev_key_priv_json_p` - Reference that will contain revocation key private json
#[no_mangle]
pub extern fn indy_crypto_cl_revocation_key_private_to_json(rev_key_priv: *const c_void,
                                                            rev_key_priv_json_p: *mut *const c_char) -> ErrorCode {
    trace!("indy_crypto_cl_revocation_key_private_to_json: >>> rev_key_priv: {:?}, rev_key_priv_json_p: {:?}",
           rev_key_priv, rev_key_priv_json_p);

    check_useful_c_reference!(rev_key_priv, RevocationKeyPrivate, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(rev_key_priv_json_p, ErrorCode::CommonInvalidParam2);

    trace!("indy_crypto_cl_revocation_key_private_to_json: entity >>> rev_key_priv: {:?}", rev_key_priv);

    let res = match rev_key_priv.to_json() {
        Ok(rev_key_priv_json) => {
            trace!("indy_crypto_cl_revocation_key_private_to_json: rev_key_priv_json: {:?}", rev_key_priv_json);
            unsafe {
                let rev_reg_def_priv_json = CTypesUtils::string_to_cstring(rev_key_priv_json);
                *rev_key_priv_json_p = rev_reg_def_priv_json.into_raw();
                trace!("indy_crypto_cl_revocation_key_private_to_json: rev_key_priv_json_p: {:?}", *rev_key_priv_json_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_cl_revocation_key_private_to_json: <<< res: {:?}", res);
    res
}

/// Creates and returns revocation key private from json.
///
/// Note: Revocation registry private instance deallocation must be performed
/// by calling indy_crypto_cl_revocation_key_private_free
///
/// # Arguments
/// * `rev_key_priv_json` - Reference that contains revocation key private json.
/// * `rev_key_priv_p` - Reference that will contain revocation key private instance pointer
#[no_mangle]
pub extern fn indy_crypto_cl_revocation_key_private_from_json(rev_key_priv_json: *const c_char,
                                                              rev_key_priv_p: *mut *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_revocation_key_private_from_json: >>> rev_key_priv_json: {:?}, rev_key_priv_p: {:?}",
           rev_key_priv_json, rev_key_priv_p);

    check_useful_c_str!(rev_key_priv_json, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(rev_key_priv_p, ErrorCode::CommonInvalidParam2);

    trace!("indy_crypto_cl_revocation_key_private_from_json: entity: rev_key_priv_json: {:?}", rev_key_priv_json);

    let res = match RevocationKeyPrivate::from_json(&rev_key_priv_json) {
        Ok(rev_key_priv) => {
            trace!("indy_crypto_cl_revocation_key_private_from_json: rev_key_priv: {:?}", rev_key_priv);
            unsafe {
                *rev_key_priv_p = Box::into_raw(Box::new(rev_key_priv)) as *const c_void;
                trace!("indy_crypto_cl_revocation_key_private_from_json: *rev_key_priv_p: {:?}", *rev_key_priv_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_cl_revocation_key_private_from_json: <<< res: {:?}", res);
    res
}

/// Deallocates revocation key private instance.
///
/// # Arguments
/// * `rev_key_priv` - Reference that contains revocation key private instance pointer.
#[no_mangle]
pub extern fn indy_crypto_cl_revocation_key_private_free(rev_key_priv: *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_revocation_key_private_free: >>> rev_key_priv: {:?}", rev_key_priv);

    check_useful_c_ptr!(rev_key_priv, ErrorCode::CommonInvalidParam1);

    let rev_key_priv = unsafe { Box::from_raw(rev_key_priv as *mut RevocationKeyPrivate); };
    trace!("indy_crypto_cl_revocation_key_private_free: entity: rev_key_priv: {:?}", rev_key_priv);

    let res = ErrorCode::Success;

    trace!("indy_crypto_cl_revocation_key_private_free: <<< res: {:?}", res);
    res
}


/// Returns json representation of revocation registry entry.
///
/// # Arguments
/// * `rev_reg_entry` - Reference that contains issuer revocation registry entry pointer.
/// * `rev_reg_entry_p` - Reference that will contain revocation registry entry json
#[no_mangle]
pub extern fn indy_crypto_cl_revocation_registry_entry_to_json(rev_reg_entry: *const c_void,
                                                               rev_reg_entry_json_p: *mut *const c_char) -> ErrorCode {
    trace!("indy_crypto_cl_revocation_registry_entry_to_json: >>> rev_reg_entry: {:?}, rev_reg_entry_json_p: {:?}",
           rev_reg_entry, rev_reg_entry_json_p);

    check_useful_c_reference!(rev_reg_entry, RevocationKeyPrivate, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(rev_reg_entry_json_p, ErrorCode::CommonInvalidParam2);

    trace!("indy_crypto_cl_revocation_registry_entry_to_json: entity >>> rev_reg_entry: {:?}", rev_reg_entry);

    let res = match rev_reg_entry.to_json() {
        Ok(rev_reg_entry_json) => {
            trace!("indy_crypto_cl_revocation_registry_entry_to_json: rev_reg_entry_json: {:?}", rev_reg_entry_json);
            unsafe {
                let rev_reg_entry_json = CTypesUtils::string_to_cstring(rev_reg_entry_json);
                *rev_reg_entry_json_p = rev_reg_entry_json.into_raw();
                trace!("indy_crypto_cl_revocation_registry_entry_to_json: rev_reg_entry_json_p: {:?}", *rev_reg_entry_json_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_cl_revocation_registry_entry_to_json: <<< res: {:?}", res);
    res
}

/// Creates and returns revocation registry entry from json.
///
/// Note: Revocation registry private instance deallocation must be performed
/// by calling indy_crypto_cl_revocation_registry_entry_free
///
/// # Arguments
/// * `rev_reg_entry_json` - Reference that contains revocation registry entry json.
/// * `rev_reg_entry_p` - Reference that will contain revocation registry entry instance pointer
#[no_mangle]
pub extern fn indy_crypto_cl_revocation_registry_entry_from_json(rev_reg_entry_json: *const c_char,
                                                                 rev_reg_entry_p: *mut *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_revocation_registry_entry_from_json: >>> rev_reg_entry_json: {:?}, rev_reg_entry_p: {:?}",
           rev_reg_entry_json, rev_reg_entry_p);

    check_useful_c_str!(rev_reg_entry_json, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(rev_reg_entry_p, ErrorCode::CommonInvalidParam2);

    trace!("indy_crypto_cl_revocation_registry_entry_from_json: entity: rev_reg_entry_json: {:?}", rev_reg_entry_json);

    let res = match RevocationRegistryDelta::from_json(&rev_reg_entry_json) {
        Ok(rev_reg_entry) => {
            trace!("indy_crypto_cl_revocation_registry_entry_from_json: rev_reg_entry: {:?}", rev_reg_entry);
            unsafe {
                *rev_reg_entry_p = Box::into_raw(Box::new(rev_reg_entry)) as *const c_void;
                trace!("indy_crypto_cl_revocation_registry_entry_from_json: *rev_reg_entry_p: {:?}", *rev_reg_entry_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_cl_revocation_registry_entry_from_json: <<< res: {:?}", res);
    res
}

/// Deallocates revocation registry entry instance.
///
/// # Arguments
/// * `rev_reg_entry` - Reference that contains revocation registry entry instance pointer.
#[no_mangle]
pub extern fn indy_crypto_cl_revocation_registry_entry_free(rev_reg_entry: *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_revocation_registry_entry_free: >>> rev_reg_entry: {:?}", rev_reg_entry);

    check_useful_c_ptr!(rev_reg_entry, ErrorCode::CommonInvalidParam1);

    let rev_reg_entry = unsafe { Box::from_raw(rev_reg_entry as *mut RevocationRegistryDelta); };
    trace!("indy_crypto_cl_revocation_registry_entry_free: entity: rev_reg_entry: {:?}", rev_reg_entry);

    let res = ErrorCode::Success;

    trace!("indy_crypto_cl_revocation_registry_entry_free: <<< res: {:?}", res);
    res
}

/// Deallocates revocation registry tails generator instance.
///
/// # Arguments
/// * `rev_reg_entry` - Reference that contains revocation registry tails generator instance pointer.
#[no_mangle]
pub extern fn indy_crypto_cl_revocation_registry_tails_generator_free(rev_tails_generator: *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_revocation_registry_tails_generator_free: >>> rev_tails_generator: {:?}", rev_tails_generator);

    check_useful_c_ptr!(rev_tails_generator, ErrorCode::CommonInvalidParam1);

    let rev_tails_generator = unsafe { Box::from_raw(rev_tails_generator as *mut RevocationTailsGenerator); };
    trace!("indy_crypto_cl_revocation_registry_tails_generator_free: entity: rev_tails_generator: {:?}", rev_tails_generator);

    let res = ErrorCode::Success;

    trace!("indy_crypto_cl_revocation_registry_tails_generator_free: <<< res: {:?}", res);
    res
}

/// Sign given credential values with primary only part.
///
/// # Arguments
/// * `prover_id` - Prover identifier.
/// * `blinded_master_secret` - Blinded master secret.
/// * `blinded_master_secret_correctness_proof` - Blinded master secret correctness proof.
/// * `master_secret_blinding_nonce` - Nonce used for blinded_master_secret_correctness_proof verification.
/// * `credential_issuance_nonce` - Nonce used for creating of signature correctness proof.
/// * `credential_values` - Claim values to be signed.
/// * `credential_pub_key` - credential public key.
/// * `credential_priv_key` - credential private key.
/// * `credential_signature_p` - Reference that will contain credential signature instance pointer.
/// * `credential_signature_correctness_proof_p` - Reference that will contain credential signature correctness proof instance pointer.
#[no_mangle]
pub extern fn indy_crypto_cl_issuer_sign_credential(prover_id: *const c_char,
                                                    blinded_ms: *const c_void,
                                                    blinded_master_secret_correctness_proof: *const c_void,
                                                    master_secret_blinding_nonce: *const c_void,
                                                    credential_issuance_nonce: *const c_void,
                                                    credential_values: *const c_void,
                                                    credential_pub_key: *const c_void,
                                                    credential_priv_key: *const c_void,
                                                    credential_signature_p: *mut *const c_void,
                                                    credential_signature_correctness_proof_p: *mut *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_issuer_sign_credential: >>> prover_id: {:?}, blinded_ms: {:?}, blinded_master_secret_correctness_proof: {:?}, \
        master_secret_blinding_nonce: {:?}, credential_issuance_nonce: {:?}, credential_values: {:?}, credential_pub_key: {:?}, credential_priv_key: {:?}, \
        credential_signature_p: {:?}, credential_signature_correctness_proof_p: {:?}",
           prover_id, blinded_ms, blinded_master_secret_correctness_proof,
           master_secret_blinding_nonce, credential_issuance_nonce, credential_values, credential_pub_key, credential_priv_key,
           credential_signature_p, credential_signature_correctness_proof_p);

    check_useful_c_str!(prover_id, ErrorCode::CommonInvalidParam1);
    check_useful_c_reference!(blinded_ms, BlindedMasterSecret, ErrorCode::CommonInvalidParam2);
    check_useful_c_reference!(blinded_master_secret_correctness_proof, BlindedMasterSecretCorrectnessProof, ErrorCode::CommonInvalidParam3);
    check_useful_c_reference!(master_secret_blinding_nonce, Nonce, ErrorCode::CommonInvalidParam4);
    check_useful_c_reference!(credential_issuance_nonce, Nonce, ErrorCode::CommonInvalidParam5);
    check_useful_c_reference!(credential_values, CredentialValues, ErrorCode::CommonInvalidParam6);
    check_useful_c_reference!(credential_pub_key, CredentialPublicKey, ErrorCode::CommonInvalidParam7);
    check_useful_c_reference!(credential_priv_key, CredentialPrivateKey, ErrorCode::CommonInvalidParam8);
    check_useful_c_ptr!(credential_signature_p, ErrorCode::CommonInvalidParam10);
    check_useful_c_ptr!(credential_signature_correctness_proof_p, ErrorCode::CommonInvalidParam11);

    trace!("indy_crypto_cl_issuer_sign_credential: >>> prover_id: {:?}, blinded_ms: {:?}, blinded_master_secret_correctness_proof: {:?}, master_secret_blinding_nonce: {:?}, \
        credential_issuance_nonce: {:?}, credential_values: {:?}, credential_pub_key: {:?}, credential_priv_key: {:?}",
           prover_id, blinded_ms, blinded_master_secret_correctness_proof, master_secret_blinding_nonce, credential_issuance_nonce,
           credential_values, credential_pub_key, credential_priv_key);

    let res = match Issuer::sign_credential(&prover_id,
                                            &blinded_ms,
                                            &blinded_master_secret_correctness_proof,
                                            &master_secret_blinding_nonce,
                                            &credential_issuance_nonce,
                                            &credential_values,
                                            &credential_pub_key,
                                            &credential_priv_key) {
        Ok((credential_signature, credential_signature_correctness_proof)) => {
            trace!("indy_crypto_cl_issuer_sign_credential: credential_signature: {:?}, credential_signature_correctness_proof: {:?}",
                   credential_signature, credential_signature_correctness_proof);
            unsafe {
                *credential_signature_p = Box::into_raw(Box::new(credential_signature)) as *const c_void;
                *credential_signature_correctness_proof_p = Box::into_raw(Box::new(credential_signature_correctness_proof)) as *const c_void;
                trace!("indy_crypto_cl_issuer_sign_credential: *credential_signature_p: {:?}, *credential_signature_correctness_proof_p: {:?}",
                       *credential_signature_p, *credential_signature_correctness_proof_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_cl_issuer_sign_credential: <<< res: {:?}", res);
    ErrorCode::Success
}

/// Sign given credential values with both primary and revocation parts.
///
/// # Arguments
/// * `prover_id` - Prover identifier.
/// * `blinded_master_secret` - Blinded master secret.
/// * `blinded_master_secret_correctness_proof` - Blinded master secret correctness proof.
/// * `master_secret_blinding_nonce` - Nonce used for blinded_master_secret_correctness_proof verification.
/// * `credential_issuance_nonce` - Nonce used for creating of signature correctness proof.
/// * `credential_values` - Claim values to be signed.
/// * `credential_pub_key` - credential public key.
/// * `credential_priv_key` - credential private key.
/// * `rev_idx` - User index in revocation accumulator. Required for non-revocation credential_signature part generation.
/// * `max_cred_num` - Max credential number in generated registry.
/// * `rev_reg` - Revocation registry.
/// * `rev_key_priv` - Revocation registry private key.
/// * `rev_tails_accessor` - Revocation registry tails accessor.
/// * `credential_signature_p` - Reference that will contain credential signature instance pointer.
/// * `credential_signature_correctness_proof_p` - Reference that will contain credential signature correctness proof instance pointer.
#[no_mangle]
pub extern fn indy_crypto_cl_issuer_sign_credential_with_revoc(prover_id: *const c_char,
                                                               blinded_ms: *const c_void,
                                                               blinded_master_secret_correctness_proof: *const c_void,
                                                               master_secret_blinding_nonce: *const c_void,
                                                               credential_issuance_nonce: *const c_void,
                                                               credential_values: *const c_void,
                                                               credential_pub_key: *const c_void,
                                                               credential_priv_key: *const c_void,
                                                               rev_idx: u32,
                                                               max_cred_num: u32,
                                                               issuance_by_default: bool,
                                                               rev_reg: *const c_void,
                                                               rev_key_priv: *const c_void,
                                                               ctx_tails: *const c_void,
                                                               take_tail: FFITailTake,
                                                               put_tail: FFITailPut,
                                                               credential_signature_p: *mut *const c_void,
                                                               credential_signature_correctness_proof_p: *mut *const c_void,
                                                               revocation_registry_delta_p: *mut *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_issuer_sign_credential: >>> prover_id: {:?}, blinded_ms: {:?}, blinded_master_secret_correctness_proof: {:?}, \
        master_secret_blinding_nonce: {:?}, credential_issuance_nonce: {:?}, credential_values: {:?}, credential_pub_key: {:?}, credential_priv_key: {:?}, \
        rev_idx: {:?}, rev_reg_def_pub: {:?}, rev_reg_priv: {:?}, credential_signature_p: {:?}, credential_signature_correctness_proof_p: {:?}",
           prover_id, blinded_ms, blinded_master_secret_correctness_proof, master_secret_blinding_nonce, credential_issuance_nonce,
           credential_values, credential_pub_key, credential_priv_key, rev_idx, rev_reg, rev_key_priv, credential_signature_p, credential_signature_correctness_proof_p);

    check_useful_c_str!(prover_id, ErrorCode::CommonInvalidParam1);
    check_useful_c_reference!(blinded_ms, BlindedMasterSecret, ErrorCode::CommonInvalidParam2);
    check_useful_c_reference!(blinded_master_secret_correctness_proof, BlindedMasterSecretCorrectnessProof, ErrorCode::CommonInvalidParam3);
    check_useful_c_reference!(master_secret_blinding_nonce, Nonce, ErrorCode::CommonInvalidParam4);
    check_useful_c_reference!(credential_issuance_nonce, Nonce, ErrorCode::CommonInvalidParam5);
    check_useful_c_reference!(credential_values, CredentialValues, ErrorCode::CommonInvalidParam6);
    check_useful_c_reference!(credential_pub_key, CredentialPublicKey, ErrorCode::CommonInvalidParam7);
    check_useful_c_reference!(credential_priv_key, CredentialPrivateKey, ErrorCode::CommonInvalidParam8);
    check_useful_mut_c_reference!(rev_reg, RevocationRegistry, ErrorCode::CommonInvalidParam12);
    check_useful_c_reference!(rev_key_priv, RevocationKeyPrivate, ErrorCode::CommonInvalidState); //TODO invalid param
    check_useful_c_ptr!(credential_signature_p, ErrorCode::CommonInvalidState); //TODO invalid param
    check_useful_c_ptr!(credential_signature_correctness_proof_p, ErrorCode::CommonInvalidState); //TODO invalid param

    trace!("indy_crypto_cl_issuer_sign_credential: >>> prover_id: {:?}, blinded_ms: {:?}, blinded_master_secret_correctness_proof: {:?}, master_secret_blinding_nonce: {:?}, \
        credential_issuance_nonce: {:?}, credential_values: {:?}, credential_pub_key: {:?}, credential_priv_key: {:?}, rev_idx: {:?}, rev_reg: {:?}, rev_key_priv: {:?}",
           prover_id, blinded_ms, blinded_master_secret_correctness_proof, master_secret_blinding_nonce, credential_issuance_nonce,
           credential_values, credential_pub_key, credential_priv_key, rev_idx, rev_reg, rev_key_priv);

    let rta = FFITailsAccessor::new(ctx_tails, take_tail, put_tail);
    let res = match Issuer::sign_credential_with_revoc(&prover_id,
                                                       &blinded_ms,
                                                       &blinded_master_secret_correctness_proof,
                                                       &master_secret_blinding_nonce,
                                                       &credential_issuance_nonce,
                                                       &credential_values,
                                                       &credential_pub_key,
                                                       &credential_priv_key,
                                                       rev_idx,
                                                       max_cred_num,
                                                       issuance_by_default,
                                                       rev_reg,
                                                       rev_key_priv,
                                                       &rta) {
        Ok((credential_signature, credential_signature_correctness_proof, delta)) => {
            trace!("indy_crypto_cl_issuer_sign_credential: credential_signature: {:?}, credential_signature_correctness_proof: {:?}",
                   credential_signature, credential_signature_correctness_proof);
            unsafe {
                *credential_signature_p = Box::into_raw(Box::new(credential_signature)) as *const c_void;
                *credential_signature_correctness_proof_p = Box::into_raw(Box::new(credential_signature_correctness_proof)) as *const c_void;
                *revocation_registry_delta_p = if let Some(delta) = delta { Box::into_raw(Box::new(delta)) as *const c_void } else { null() };
                trace!("indy_crypto_cl_issuer_sign_credential: *credential_signature_p: {:?}, *credential_signature_correctness_proof_p: {:?}",
                       *credential_signature_p, *credential_signature_correctness_proof_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_cl_issuer_sign_credential: <<< res: {:?}", res);
    ErrorCode::Success
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

    check_useful_c_reference!(claim_signature, CredentialSignature, ErrorCode::CommonInvalidParam1);
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

    let res = match CredentialSignature::from_json(&claim_signature_json) {
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

    let claim_signature = unsafe { Box::from_raw(claim_signature as *mut CredentialSignature); };
    trace!("indy_crypto_cl_claim_signature_free: entity: claim_signature: {:?}", claim_signature);
    let res = ErrorCode::Success;

    trace!("indy_crypto_cl_claim_signature_free: <<< res: {:?}", res);
    res
}

/// Returns json representation of signature correctness proof.
///
/// # Arguments
/// * `signature_correctness_proof` - Reference that contains signature correctness proof instance pointer.
/// * `signature_correctness_proof_json_p` - Reference that will contain signature correctness proof json.
#[no_mangle]
pub extern fn indy_crypto_cl_signature_correctness_proof_to_json(signature_correctness_proof: *const c_void,
                                                                 signature_correctness_proof_json_p: *mut *const c_char) -> ErrorCode {
    trace!("indy_crypto_cl_signature_correctness_proof_to_json: >>> signature_correctness_proof: {:?}, signature_correctness_proof_json_p: {:?}",
           signature_correctness_proof, signature_correctness_proof_json_p);

    check_useful_c_reference!(signature_correctness_proof, SignatureCorrectnessProof, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(signature_correctness_proof_json_p, ErrorCode::CommonInvalidParam2);

    trace!("indy_crypto_cl_signature_correctness_proof_to_json: entity >>> signature_correctness_proof: {:?}", signature_correctness_proof);

    let res = match signature_correctness_proof.to_json() {
        Ok(signature_correctness_proof_json) => {
            trace!("indy_crypto_cl_signature_correctness_proof_to_json: signature_correctness_proof_json: {:?}", signature_correctness_proof_json);
            unsafe {
                let signature_correctness_proof_json = CTypesUtils::string_to_cstring(signature_correctness_proof_json);
                *signature_correctness_proof_json_p = signature_correctness_proof_json.into_raw();
                trace!("indy_crypto_cl_signature_correctness_proof_to_json: signature_correctness_proof_json_p: {:?}", *signature_correctness_proof_json_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_cl_signature_correctness_proof_to_json: <<< res: {:?}", res);
    res
}

/// Creates and returns signature correctness proof from json.
///
/// Note: Signature correctness proof instance deallocation must be performed
/// by calling indy_crypto_cl_signature_correctness_proof_free
///
/// # Arguments
/// * `signature_correctness_proof_json` - Reference that contains signature correctness proof json.
/// * `signature_correctness_proof_p` - Reference that will contain signature correctness proof instance pointer.
#[no_mangle]
pub extern fn indy_crypto_cl_signature_correctness_proof_from_json(signature_correctness_proof_json: *const c_char,
                                                                   signature_correctness_proof_p: *mut *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_signature_correctness_proof_from_json: >>> signature_correctness_proof_json: {:?}, signature_correctness_proof_p: {:?}",
           signature_correctness_proof_json, signature_correctness_proof_p);

    check_useful_c_str!(signature_correctness_proof_json, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(signature_correctness_proof_p, ErrorCode::CommonInvalidParam2);

    trace!("indy_crypto_cl_signature_correctness_proof_from_json: entity: signature_correctness_proof_json: {:?}", signature_correctness_proof_json);

    let res = match SignatureCorrectnessProof::from_json(&signature_correctness_proof_json) {
        Ok(signature_correctness_proof) => {
            trace!("indy_crypto_cl_signature_correctness_proof_from_json: signature_correctness_proof: {:?}", signature_correctness_proof);
            unsafe {
                *signature_correctness_proof_p = Box::into_raw(Box::new(signature_correctness_proof)) as *const c_void;
                trace!("indy_crypto_cl_signature_correctness_proof_from_json: *signature_correctness_proof_p: {:?}", *signature_correctness_proof_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_cl_signature_correctness_proof_from_json: <<< res: {:?}", res);
    res
}

/// Deallocates signature correctness proof instance.
///
/// # Arguments
/// * `signature_correctness_proof` - Reference that contains signature correctness proof instance pointer.
#[no_mangle]
pub extern fn indy_crypto_cl_signature_correctness_proof_free(signature_correctness_proof: *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_signature_correctness_proof_free: >>> signature_correctness_proof: {:?}", signature_correctness_proof);

    check_useful_c_ptr!(signature_correctness_proof, ErrorCode::CommonInvalidParam1);

    let signature_correctness_proof = unsafe { Box::from_raw(signature_correctness_proof as *mut SignatureCorrectnessProof); };
    trace!("indy_crypto_cl_signature_correctness_proof_free: entity: signature_correctness_proof: {:?}", signature_correctness_proof);
    let res = ErrorCode::Success;

    trace!("indy_crypto_cl_signature_correctness_proof_free: <<< res: {:?}", res);
    res
}

/// Revokes a credential by a revoc_id in a given revoc-registry.
///
/// # Arguments
/// * `rev_reg` - Reference that contain revocation registry instance pointer.
///  * rev_idx` - index of the user in the accumulator
#[no_mangle]
#[allow(unused_variables)]
pub extern fn indy_crypto_cl_issuer_revoke_credential(rev_reg: *const c_void,
                                                      max_cred_num: u32,
                                                      rev_idx: u32,
                                                      ctx_tails: *const c_void,
                                                      take_tail: FFITailTake,
                                                      put_tail: FFITailPut,
                                                      rev_reg_delta_p: *mut *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_issuer_revoke_credential: >>> rev_reg: {:?}, max_cred_num: {:?}, rev_idx: {:?}, ctx_tails {:?}, take_tail {:?}, put_tail {:?}, rev_reg_delta_p {:?}",
           rev_reg, max_cred_num, rev_idx, ctx_tails, take_tail, put_tail, rev_reg_delta_p);

    check_useful_mut_c_reference!(rev_reg, RevocationRegistry, ErrorCode::CommonInvalidParam1);

    trace!("indy_crypto_cl_issuer_revoke_credential: entities: rev_reg: {:?}", rev_reg);

    let rta = FFITailsAccessor::new(ctx_tails, take_tail, put_tail);
    let res = match Issuer::revoke_credential(rev_reg, max_cred_num, rev_idx, &rta) {
        Ok(rev_reg_delta) => {
            unsafe {
                *rev_reg_delta_p = Box::into_raw(Box::new(rev_reg_delta)) as *const c_void;
                trace!("indy_crypto_cl_issuer_revoke_credential: *rev_reg_delta_p: {:?}", *rev_reg_delta_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_cl_issuer_revoke_credential: <<< res: {:?}", res);
    ErrorCode::Success
}
//
//#[cfg(test)]
//mod tests {
//    use super::*;
//
//    use std::ptr;
//    use ffi::cl::mocks::*;
//    use ffi::cl::issuer::mocks::*;
//    use ffi::cl::prover::mocks::*;
//
//    #[test]
//    fn indy_crypto_cl_issuer_new_keys_works() {
//        let claim_schema = _claim_schema();
//        let mut issuer_pub_key: *const c_void = ptr::null();
//        let mut issuer_priv_key: *const c_void = ptr::null();
//        let mut issuer_key_correctness_proof: *const c_void = ptr::null();
//
//        let err_code = indy_crypto_cl_issuer_new_keys(claim_schema,
//                                                      true,
//                                                      &mut issuer_pub_key,
//                                                      &mut issuer_priv_key,
//                                                      &mut issuer_key_correctness_proof);
//
//        assert_eq!(err_code, ErrorCode::Success);
//        assert!(!issuer_pub_key.is_null());
//        assert!(!issuer_priv_key.is_null());
//        assert!(!issuer_key_correctness_proof.is_null());
//
//        _free_claim_schema(claim_schema);
//        _free_issuer_keys(issuer_pub_key, issuer_priv_key, issuer_key_correctness_proof);
//    }
//
//    #[test]
//    fn indy_crypto_cl_issuer_public_key_to_json_works() {
//        let claim_schema = _claim_schema();
//        let (issuer_pub_key, issuer_priv_key, issuer_key_correctness_proof) = _issuer_keys();
//
//        let mut issuer_pub_key_json_p: *const c_char = ptr::null();
//        let err_code = indy_crypto_cl_issuer_public_key_to_json(issuer_pub_key, &mut issuer_pub_key_json_p);
//        assert_eq!(err_code, ErrorCode::Success);
//
//        _free_claim_schema(claim_schema);
//        _free_issuer_keys(issuer_pub_key, issuer_priv_key, issuer_key_correctness_proof);
//    }
//
//    #[test]
//    fn indy_crypto_cl_issuer_public_key_from_json_works() {
//        let claim_schema = _claim_schema();
//        let (issuer_pub_key, issuer_priv_key, issuer_key_correctness_proof) = _issuer_keys();
//
//        let mut issuer_pub_key_json_p: *const c_char = ptr::null();
//        let err_code = indy_crypto_cl_issuer_public_key_to_json(issuer_pub_key, &mut issuer_pub_key_json_p);
//        assert_eq!(err_code, ErrorCode::Success);
//
//        let mut issuer_pub_key_p: *const c_void = ptr::null();
//        let err_code = indy_crypto_cl_issuer_public_key_from_json(issuer_pub_key_json_p, &mut issuer_pub_key_p);
//        assert_eq!(err_code, ErrorCode::Success);
//
//        _free_claim_schema(claim_schema);
//        _free_issuer_keys(issuer_pub_key, issuer_priv_key, issuer_key_correctness_proof);
//    }
//
//    #[test]
//    fn indy_crypto_cl_issuer_private_key_to_json_works() {
//        let claim_schema = _claim_schema();
//        let (issuer_pub_key, issuer_priv_key, issuer_key_correctness_proof) = _issuer_keys();
//
//        let mut issuer_priv_key_json_p: *const c_char = ptr::null();
//        let err_code = indy_crypto_cl_issuer_private_key_to_json(issuer_priv_key, &mut issuer_priv_key_json_p);
//        assert_eq!(err_code, ErrorCode::Success);
//
//        _free_claim_schema(claim_schema);
//        _free_issuer_keys(issuer_pub_key, issuer_priv_key, issuer_key_correctness_proof);
//    }
//
//    #[test]
//    fn indy_crypto_cl_issuer_private_key_from_json_works() {
//        let claim_schema = _claim_schema();
//        let (issuer_pub_key, issuer_priv_key, issuer_key_correctness_proof) = _issuer_keys();
//
//        let mut issuer_priv_key_json_p: *const c_char = ptr::null();
//        let err_code = indy_crypto_cl_issuer_private_key_to_json(issuer_priv_key, &mut issuer_priv_key_json_p);
//        assert_eq!(err_code, ErrorCode::Success);
//
//        let mut issuer_priv_key_p: *const c_void = ptr::null();
//        let err_code = indy_crypto_cl_issuer_private_key_from_json(issuer_priv_key_json_p, &mut issuer_priv_key_p);
//        assert_eq!(err_code, ErrorCode::Success);
//
//        _free_claim_schema(claim_schema);
//        _free_issuer_keys(issuer_pub_key, issuer_priv_key, issuer_key_correctness_proof);
//    }
//
//    #[test]
//    fn indy_crypto_cl_issuer_key_correctness_proof_to_json_works() {
//        let claim_schema = _claim_schema();
//        let (issuer_pub_key, issuer_priv_key, issuer_key_correctness_proof) = _issuer_keys();
//
//        let mut issuer_key_correctness_proof_json_p: *const c_char = ptr::null();
//        let err_code = indy_crypto_cl_issuer_key_correctness_proof_to_json(issuer_key_correctness_proof, &mut issuer_key_correctness_proof_json_p);
//        assert_eq!(err_code, ErrorCode::Success);
//
//        _free_claim_schema(claim_schema);
//        _free_issuer_keys(issuer_pub_key, issuer_priv_key, issuer_key_correctness_proof);
//    }
//
//    #[test]
//    fn indy_crypto_cl_issuer_key_correctness_proof_from_json_works() {
//        let claim_schema = _claim_schema();
//        let (issuer_pub_key, issuer_priv_key, issuer_key_correctness_proof) = _issuer_keys();
//
//        let mut issuer_key_correctness_proof_json_p: *const c_char = ptr::null();
//        let err_code = indy_crypto_cl_issuer_key_correctness_proof_to_json(issuer_key_correctness_proof, &mut issuer_key_correctness_proof_json_p);
//        assert_eq!(err_code, ErrorCode::Success);
//
//        let mut issuer_key_correctness_proof_p: *const c_void = ptr::null();
//        let err_code = indy_crypto_cl_issuer_key_correctness_proof_from_json(issuer_key_correctness_proof_json_p,
//                                                                             &mut issuer_key_correctness_proof_p);
//        assert_eq!(err_code, ErrorCode::Success);
//
//        _free_claim_schema(claim_schema);
//        _free_issuer_keys(issuer_pub_key, issuer_priv_key, issuer_key_correctness_proof);
//    }
//
//    #[test]
//    fn indy_crypto_cl_issuer_keys_free_works() {
//        let (issuer_pub_key, issuer_priv_key, issuer_key_correctness_proof) = _issuer_keys();
//
//        let err_code = indy_crypto_cl_issuer_public_key_free(issuer_pub_key);
//        assert_eq!(err_code, ErrorCode::Success);
//
//        let err_code = indy_crypto_cl_issuer_private_key_free(issuer_priv_key);
//        assert_eq!(err_code, ErrorCode::Success);
//
//        let err_code = indy_crypto_cl_issuer_issuer_key_correctness_proof_free(issuer_key_correctness_proof);
//        assert_eq!(err_code, ErrorCode::Success);
//    }
//
//    #[test]
//    fn indy_crypto_cl_issuer_new_revocation_registry_works() {
//        let (issuer_pub_key, issuer_priv_key, issuer_key_correctness_proof) = _issuer_keys();
//        let mut rev_reg_def_pub_p: *const c_void = ptr::null();
//        let mut rev_reg_def_priv_p: *const c_void = ptr::null();
//        let mut rev_reg_entry_p: *const c_void = ptr::null();
//        let mut rev_tails_generator_p: *const c_void = ptr::null();
//
//        let err_code = indy_crypto_cl_issuer_new_revocation_registry(issuer_pub_key,
//                                                                     100,
//                                                                     false,
//                                                                     &mut rev_reg_def_pub_p,
//                                                                     &mut rev_reg_def_priv_p,
//                                                                     &mut rev_reg_entry_p,
//                                                                     &mut rev_tails_generator_p);
//        assert_eq!(err_code, ErrorCode::Success);
//        assert!(!rev_reg_def_pub_p.is_null());
//        assert!(!rev_reg_def_priv_p.is_null());
//        assert!(!rev_reg_entry_p.is_null());
//        assert!(!rev_tails_generator_p.is_null());
//
//        _free_issuer_keys(issuer_pub_key, issuer_priv_key, issuer_key_correctness_proof);
//        _free_revocation_registry(rev_reg_def_pub_p, rev_reg_def_priv_p, rev_reg_entry_p, rev_tails_generator_p);
//    }
//
//    #[test]
//    fn indy_crypto_cl_revocation_key_public_to_json_works() {
//        let (issuer_pub_key, issuer_priv_key, issuer_key_correctness_proof) = _issuer_keys();
//        let (rev_reg_def_pub_p, rev_reg_priv) = _revocation_registry(issuer_pub_key);
//
//        let mut rev_reg_def_pub_p_json_p: *const c_char = ptr::null();
//        let err_code = indy_crypto_cl_revocation_key_public_to_json(rev_reg_def_pub_p, &mut rev_reg_def_pub_p_json_p);
//        assert_eq!(err_code, ErrorCode::Success);
//
//        _free_issuer_keys(issuer_pub_key, issuer_priv_key, issuer_key_correctness_proof);
//        _free_revocation_registry(rev_reg_def_pub_p, rev_reg_priv);
//    }
//
//    #[test]
//    fn indy_crypto_cl_revocation_key_public_from_json_works() {
//        let (issuer_pub_key, issuer_priv_key, issuer_key_correctness_proof) = _issuer_keys();
//        let (rev_reg_def_pub_p, rev_reg_priv) = _revocation_registry(issuer_pub_key);
//
//        let mut rev_reg_def_pub_p_json_p: *const c_char = ptr::null();
//        let err_code = indy_crypto_cl_revocation_key_public_to_json(rev_reg_def_pub_p, &mut rev_reg_def_pub_p_json_p);
//        assert_eq!(err_code, ErrorCode::Success);
//
//        let mut rev_reg_def_pub_p_p: *const c_void = ptr::null();
//        let err_code = indy_crypto_cl_revocation_key_public_from_json(rev_reg_def_pub_p_json_p, &mut rev_reg_def_pub_p_p);
//        assert_eq!(err_code, ErrorCode::Success);
//
//        _free_issuer_keys(issuer_pub_key, issuer_priv_key, issuer_key_correctness_proof);
//        _free_revocation_registry(rev_reg_def_pub_p, rev_reg_priv);
//    }
//
//    #[test]
//    fn indy_crypto_cl_revocation_key_private_to_json_works() {
//        let (issuer_pub_key, issuer_priv_key, issuer_key_correctness_proof) = _issuer_keys();
//        let (rev_reg_def_pub_p, rev_reg_priv) = _revocation_registry(issuer_pub_key);
//
//        let mut rev_reg_priv_json_p: *const c_char = ptr::null();
//        let err_code = indy_crypto_cl_revocation_key_private_to_json(rev_reg_priv, &mut rev_reg_priv_json_p);
//        assert_eq!(err_code, ErrorCode::Success);
//
//        _free_issuer_keys(issuer_pub_key, issuer_priv_key, issuer_key_correctness_proof);
//        _free_revocation_registry(rev_reg_def_pub_p, rev_reg_priv);
//    }
//
//    #[test]
//    fn indy_crypto_cl_revocation_key_private_from_json_works() {
//        let (issuer_pub_key, issuer_priv_key, issuer_key_correctness_proof) = _issuer_keys();
//        let (rev_reg_def_pub_p, rev_reg_priv) = _revocation_registry(issuer_pub_key);
//
//        let mut rev_reg_priv_json_p: *const c_char = ptr::null();
//        let err_code = indy_crypto_cl_revocation_key_private_to_json(rev_reg_priv, &mut rev_reg_priv_json_p);
//        assert_eq!(err_code, ErrorCode::Success);
//
//        let mut rev_reg_def_priv_p: *const c_void = ptr::null();
//        let err_code = indy_crypto_cl_revocation_key_private_from_json(rev_reg_priv_json_p, &mut rev_reg_def_priv_p);
//        assert_eq!(err_code, ErrorCode::Success);
//
//        _free_issuer_keys(issuer_pub_key, issuer_priv_key, issuer_key_correctness_proof);
//        _free_revocation_registry(rev_reg_def_pub_p, rev_reg_priv);
//    }
//
//    #[test]
//    fn indy_crypto_cl_revocation_registries_free_works() {
//        let (issuer_pub_key, issuer_priv_key, issuer_key_correctness_proof) = _issuer_keys();
//        let (rev_reg_def_pub_p, rev_reg_priv) = _revocation_registry(issuer_pub_key);
//
//        let err_code = indy_crypto_cl_revocation_key_public_free(rev_reg_def_pub_p);
//        assert_eq!(err_code, ErrorCode::Success);
//
//        let err_code = indy_crypto_cl_revocation_key_private_free(rev_reg_priv);
//        assert_eq!(err_code, ErrorCode::Success);
//
//        _free_issuer_keys(issuer_pub_key, issuer_priv_key, issuer_key_correctness_proof);
//    }
//
//    #[test]
//    fn indy_crypto_cl_issuer_sign_claim_works() {
//        let prover_id = _prover_did();
//        let claim_values = _claim_values();
//        let (issuer_pub_key, issuer_priv_key, issuer_key_correctness_proof) = _issuer_keys();
//        let (rev_reg_def_pub_p, rev_reg_priv) = _revocation_registry(issuer_pub_key);
//        let master_secret = _master_secret();
//        let master_secret_blinding_nonce = _nonce();
//        let (blinded_master_secret, master_secret_blinding_data,
//            blinded_master_secret_correctness_proof) = _blinded_master_secret(issuer_pub_key,
//                                                                              issuer_key_correctness_proof,
//                                                                              master_secret,
//                                                                              master_secret_blinding_nonce);
//        let rev_idx = 1;
//        let claim_issuance_nonce = _nonce();
//        let mut claim_signature: *const c_void = ptr::null();
//        let mut signature_correctness_proof: *const c_void = ptr::null();
//        let err_code = indy_crypto_cl_issuer_sign_claim(prover_id.as_ptr(),
//                                                        blinded_master_secret,
//                                                        blinded_master_secret_correctness_proof,
//                                                        master_secret_blinding_nonce,
//                                                        claim_issuance_nonce,
//                                                        claim_values,
//                                                        issuer_pub_key,
//                                                        issuer_priv_key,
//                                                        rev_idx,
//                                                        rev_reg_def_pub_p,
//                                                        rev_reg_priv,
//                                                        &mut claim_signature,
//                                                        &mut signature_correctness_proof);
//        assert_eq!(err_code, ErrorCode::Success);
//        assert!(!claim_signature.is_null());
//        assert!(!signature_correctness_proof.is_null());
//
//        _free_issuer_keys(issuer_pub_key, issuer_priv_key, issuer_key_correctness_proof);
//        _free_revocation_registry(rev_reg_def_pub_p, rev_reg_priv);
//        _free_claim_values(claim_values);
//        _free_blinded_master_secret(blinded_master_secret, master_secret_blinding_data, blinded_master_secret_correctness_proof);
//        _free_nonce(master_secret_blinding_nonce);
//        _free_nonce(claim_issuance_nonce);
//        _free_master_secret(master_secret);
//        _free_claim_signature(claim_signature, signature_correctness_proof);
//    }
//
//    #[test]
//    fn indy_crypto_cl_claim_signature_to_json_works() {
//        let claim_values = _claim_values();
//        let (issuer_pub_key, issuer_priv_key, issuer_key_correctness_proof) = _issuer_keys();
//        let (rev_reg_def_pub_p, rev_reg_priv) = _revocation_registry(issuer_pub_key);
//        let master_secret = _master_secret();
//        let master_secret_blinding_nonce = _nonce();
//        let (blinded_master_secret, master_secret_blinding_data,
//            blinded_master_secret_correctness_proof) = _blinded_master_secret(issuer_pub_key,
//                                                                              issuer_key_correctness_proof,
//                                                                              master_secret,
//                                                                              master_secret_blinding_nonce);
//        let claim_issuance_nonce = _nonce();
//        let (claim_signature, signature_correctness_proof) = _claim_signature(blinded_master_secret,
//                                                                              blinded_master_secret_correctness_proof,
//                                                                              master_secret_blinding_nonce,
//                                                                              claim_issuance_nonce,
//                                                                              issuer_pub_key,
//                                                                              issuer_priv_key,
//                                                                              rev_reg_def_pub_p,
//                                                                              rev_reg_priv);
//
//
//        let mut claim_signature_json_p: *const c_char = ptr::null();
//        let err_code = indy_crypto_cl_claim_signature_to_json(claim_signature, &mut claim_signature_json_p);
//        assert_eq!(err_code, ErrorCode::Success);
//
//        _free_issuer_keys(issuer_pub_key, issuer_priv_key, issuer_key_correctness_proof);
//        _free_revocation_registry(rev_reg_def_pub_p, rev_reg_priv);
//        _free_claim_values(claim_values);
//        _free_blinded_master_secret(blinded_master_secret, master_secret_blinding_data, blinded_master_secret_correctness_proof);
//        _free_master_secret(master_secret);
//        _free_nonce(master_secret_blinding_nonce);
//        _free_nonce(claim_issuance_nonce);
//        _free_claim_signature(claim_signature, signature_correctness_proof);
//    }
//
//    #[test]
//    fn indy_crypto_cl_claim_signature_from_json_works() {
//        let claim_values = _claim_values();
//        let (issuer_pub_key, issuer_priv_key, issuer_key_correctness_proof) = _issuer_keys();
//        let (rev_reg_def_pub_p, rev_reg_priv) = _revocation_registry(issuer_pub_key);
//        let master_secret = _master_secret();
//        let master_secret_blinding_nonce = _nonce();
//        let (blinded_master_secret, master_secret_blinding_data,
//            blinded_master_secret_correctness_proof) = _blinded_master_secret(issuer_pub_key,
//                                                                              issuer_key_correctness_proof,
//                                                                              master_secret,
//                                                                              master_secret_blinding_nonce);
//        let claim_issuance_nonce = _nonce();
//        let (claim_signature, signature_correctness_proof) = _claim_signature(blinded_master_secret,
//                                                                              blinded_master_secret_correctness_proof,
//                                                                              master_secret_blinding_nonce,
//                                                                              claim_issuance_nonce,
//                                                                              issuer_pub_key,
//                                                                              issuer_priv_key,
//                                                                              rev_reg_def_pub_p,
//                                                                              rev_reg_priv);
//
//        let mut claim_signature_json_p: *const c_char = ptr::null();
//        let err_code = indy_crypto_cl_claim_signature_to_json(claim_signature, &mut claim_signature_json_p);
//        assert_eq!(err_code, ErrorCode::Success);
//
//        let mut claim_signature_p: *const c_void = ptr::null();
//        let err_code = indy_crypto_cl_claim_signature_from_json(claim_signature_json_p, &mut claim_signature_p);
//        assert_eq!(err_code, ErrorCode::Success);
//
//        _free_issuer_keys(issuer_pub_key, issuer_priv_key, issuer_key_correctness_proof);
//        _free_revocation_registry(rev_reg_def_pub_p, rev_reg_priv);
//        _free_claim_values(claim_values);
//        _free_blinded_master_secret(blinded_master_secret, master_secret_blinding_data, blinded_master_secret_correctness_proof);
//        _free_master_secret(master_secret);
//        _free_nonce(master_secret_blinding_nonce);
//        _free_nonce(claim_issuance_nonce);
//        _free_claim_signature(claim_signature, signature_correctness_proof);
//    }
//
//    #[test]
//    fn indy_crypto_cl_signature_correctness_proof_to_json_works() {
//        let claim_values = _claim_values();
//        let (issuer_pub_key, issuer_priv_key, issuer_key_correctness_proof) = _issuer_keys();
//        let (rev_reg_def_pub_p, rev_reg_priv) = _revocation_registry(issuer_pub_key);
//        let master_secret = _master_secret();
//        let master_secret_blinding_nonce = _nonce();
//        let (blinded_master_secret, master_secret_blinding_data,
//            blinded_master_secret_correctness_proof) = _blinded_master_secret(issuer_pub_key,
//                                                                              issuer_key_correctness_proof,
//                                                                              master_secret,
//                                                                              master_secret_blinding_nonce);
//        let claim_issuance_nonce = _nonce();
//        let (claim_signature, signature_correctness_proof) = _claim_signature(blinded_master_secret,
//                                                                              blinded_master_secret_correctness_proof,
//                                                                              master_secret_blinding_nonce,
//                                                                              claim_issuance_nonce,
//                                                                              issuer_pub_key,
//                                                                              issuer_priv_key,
//                                                                              rev_reg_def_pub_p,
//                                                                              rev_reg_priv);
//
//
//        let mut signature_correctness_proof_json_p: *const c_char = ptr::null();
//        let err_code = indy_crypto_cl_signature_correctness_proof_to_json(signature_correctness_proof,
//                                                                          &mut signature_correctness_proof_json_p);
//        assert_eq!(err_code, ErrorCode::Success);
//
//        _free_issuer_keys(issuer_pub_key, issuer_priv_key, issuer_key_correctness_proof);
//        _free_revocation_registry(rev_reg_def_pub_p, rev_reg_priv);
//        _free_claim_values(claim_values);
//        _free_blinded_master_secret(blinded_master_secret, master_secret_blinding_data, blinded_master_secret_correctness_proof);
//        _free_master_secret(master_secret);
//        _free_nonce(master_secret_blinding_nonce);
//        _free_nonce(claim_issuance_nonce);
//        _free_claim_signature(claim_signature, signature_correctness_proof);
//    }
//
//    #[test]
//    fn indy_crypto_cl_signature_correctness_proof_from_json_works() {
//        let claim_values = _claim_values();
//        let (issuer_pub_key, issuer_priv_key, issuer_key_correctness_proof) = _issuer_keys();
//        let (rev_reg_def_pub_p, rev_reg_priv) = _revocation_registry(issuer_pub_key);
//        let master_secret = _master_secret();
//        let master_secret_blinding_nonce = _nonce();
//        let (blinded_master_secret, master_secret_blinding_data,
//            blinded_master_secret_correctness_proof) = _blinded_master_secret(issuer_pub_key,
//                                                                              issuer_key_correctness_proof,
//                                                                              master_secret,
//                                                                              master_secret_blinding_nonce);
//        let claim_issuance_nonce = _nonce();
//        let (claim_signature, signature_correctness_proof) = _claim_signature(blinded_master_secret,
//                                                                              blinded_master_secret_correctness_proof,
//                                                                              master_secret_blinding_nonce,
//                                                                              claim_issuance_nonce,
//                                                                              issuer_pub_key,
//                                                                              issuer_priv_key,
//                                                                              rev_reg_def_pub_p,
//                                                                              rev_reg_priv);
//
//        let mut signature_correctness_proof_json_p: *const c_char = ptr::null();
//        let err_code = indy_crypto_cl_signature_correctness_proof_to_json(signature_correctness_proof,
//                                                                          &mut signature_correctness_proof_json_p);
//        assert_eq!(err_code, ErrorCode::Success);
//
//        let mut signature_correctness_proof_p: *const c_void = ptr::null();
//        let err_code = indy_crypto_cl_signature_correctness_proof_from_json(signature_correctness_proof_json_p,
//                                                                            &mut signature_correctness_proof_p);
//        assert_eq!(err_code, ErrorCode::Success);
//
//        _free_issuer_keys(issuer_pub_key, issuer_priv_key, issuer_key_correctness_proof);
//        _free_revocation_registry(rev_reg_def_pub_p, rev_reg_priv);
//        _free_claim_values(claim_values);
//        _free_blinded_master_secret(blinded_master_secret, master_secret_blinding_data, blinded_master_secret_correctness_proof);
//        _free_master_secret(master_secret);
//        _free_nonce(master_secret_blinding_nonce);
//        _free_nonce(claim_issuance_nonce);
//        _free_claim_signature(claim_signature, signature_correctness_proof);
//    }
//
//    #[test]
//    fn indy_crypto_cl_claim_signature_free_works() {
//        let (issuer_pub_key, issuer_priv_key, issuer_key_correctness_proof) = _issuer_keys();
//        let (rev_reg_def_pub_p, rev_reg_priv) = _revocation_registry(issuer_pub_key);
//        let master_secret = _master_secret();
//        let master_secret_blinding_nonce = _nonce();
//        let (blinded_master_secret, master_secret_blinding_data,
//            blinded_master_secret_correctness_proof) = _blinded_master_secret(issuer_pub_key,
//                                                                              issuer_key_correctness_proof,
//                                                                              master_secret,
//                                                                              master_secret_blinding_nonce);
//        let claim_issuance_nonce = _nonce();
//        let (claim_signature, signature_correctness_proof) = _claim_signature(blinded_master_secret,
//                                                                              blinded_master_secret_correctness_proof,
//                                                                              master_secret_blinding_nonce,
//                                                                              claim_issuance_nonce,
//                                                                              issuer_pub_key,
//                                                                              issuer_priv_key,
//                                                                              rev_reg_def_pub_p,
//                                                                              rev_reg_priv);
//        let err_code = indy_crypto_cl_claim_signature_free(claim_signature);
//        assert_eq!(err_code, ErrorCode::Success);
//
//        let err_code = indy_crypto_cl_signature_correctness_proof_free(signature_correctness_proof);
//        assert_eq!(err_code, ErrorCode::Success);
//
//        _free_issuer_keys(issuer_pub_key, issuer_priv_key, issuer_key_correctness_proof);
//        _free_revocation_registry(rev_reg_def_pub_p, rev_reg_priv);
//        _free_blinded_master_secret(blinded_master_secret, master_secret_blinding_data, blinded_master_secret_correctness_proof);
//        _free_master_secret(master_secret);
//        _free_nonce(master_secret_blinding_nonce);
//        _free_nonce(claim_issuance_nonce);
//    }
//
//    #[test]
//    fn indy_crypto_cl_issuer_revoke_claim_works() {
//        let (issuer_pub_key, issuer_priv_key, issuer_key_correctness_proof) = _issuer_keys();
//        let (rev_reg_def_pub_p, rev_reg_priv) = _revocation_registry(issuer_pub_key);
//        let master_secret = _master_secret();
//        let master_secret_blinding_nonce = _nonce();
//        let (blinded_master_secret, master_secret_blinding_data,
//            blinded_master_secret_correctness_proof) = _blinded_master_secret(issuer_pub_key,
//                                                                              issuer_key_correctness_proof,
//                                                                              master_secret,
//                                                                              master_secret_blinding_nonce);
//        let claim_issuance_nonce = _nonce();
//        let (claim_signature, signature_correctness_proof) = _claim_signature(blinded_master_secret,
//                                                                              blinded_master_secret_correctness_proof,
//                                                                              master_secret_blinding_nonce,
//                                                                              claim_issuance_nonce,
//                                                                              issuer_pub_key,
//                                                                              issuer_priv_key,
//                                                                              rev_reg_def_pub_p,
//                                                                              rev_reg_priv);
//        let err_code = indy_crypto_cl_issuer_revoke_claim(rev_reg_def_pub_p, 1);
//        assert_eq!(err_code, ErrorCode::Success);
//
//        _free_issuer_keys(issuer_pub_key, issuer_priv_key, issuer_key_correctness_proof);
//        _free_revocation_registry(rev_reg_def_pub_p, rev_reg_priv);
//        _free_blinded_master_secret(blinded_master_secret, master_secret_blinding_data, blinded_master_secret_correctness_proof);
//        _free_master_secret(master_secret);
//        _free_nonce(master_secret_blinding_nonce);
//        _free_nonce(claim_issuance_nonce);
//        _free_claim_signature(claim_signature, signature_correctness_proof);
//    }
//}
//
//pub mod mocks {
//    use super::*;
//
//    use std::ffi::CString;
//    use std::ptr;
//    use ffi::cl::mocks::*;
//
//    pub fn _issuer_keys() -> (*const c_void, *const c_void, *const c_void) {
//        let claim_schema = _claim_schema();
//
//        let mut issuer_pub_key: *const c_void = ptr::null();
//        let mut issuer_priv_key: *const c_void = ptr::null();
//        let mut issuer_key_correctness_proof: *const c_void = ptr::null();
//
//        let err_code = indy_crypto_cl_issuer_new_keys(claim_schema,
//                                                      true,
//                                                      &mut issuer_pub_key,
//                                                      &mut issuer_priv_key,
//                                                      &mut issuer_key_correctness_proof);
//        assert_eq!(err_code, ErrorCode::Success);
//        assert!(!issuer_pub_key.is_null());
//        assert!(!issuer_priv_key.is_null());
//        assert!(!issuer_key_correctness_proof.is_null());
//
//        _free_claim_schema(claim_schema);
//
//        (issuer_pub_key, issuer_priv_key, issuer_key_correctness_proof)
//    }
//
//    pub fn _free_issuer_keys(issuer_pub_key: *const c_void, issuer_priv_key: *const c_void, issuer_key_correctness_proof: *const c_void) {
//        let err_code = indy_crypto_cl_issuer_public_key_free(issuer_pub_key);
//        assert_eq!(err_code, ErrorCode::Success);
//
//        let err_code = indy_crypto_cl_issuer_private_key_free(issuer_priv_key);
//        assert_eq!(err_code, ErrorCode::Success);
//
//        let err_code = indy_crypto_cl_issuer_issuer_key_correctness_proof_free(issuer_key_correctness_proof);
//        assert_eq!(err_code, ErrorCode::Success);
//    }
//
//    pub fn _revocation_registry(issuer_pub_key: *const c_void) -> (*const c_void, *const c_void, *const c_void, *const c_void) {
//        let mut rev_reg_def_pub_p: *const c_void = ptr::null();
//        let mut rev_reg_priv_p: *const c_void = ptr::null();
//        let mut rev_reg_entry_p: *const c_void = ptr::null();
//        let mut rev_tails_generator_p: *const c_void = ptr::null();
//
//        let err_code = indy_crypto_cl_issuer_new_revocation_registry(issuer_pub_key,
//                                                                     100,
//                                                                     false,
//                                                                     &mut rev_reg_def_pub_p,
//                                                                     &mut rev_reg_priv_p,
//                                                                     &mut rev_reg_entry_p,
//                                                                     &mut rev_tails_generator_p);
//        assert_eq!(err_code, ErrorCode::Success);
//        assert!(!rev_reg_def_pub_p.is_null());
//        assert!(!rev_reg_priv_p.is_null());
//        assert!(!rev_reg_entry_p.is_null());
//        assert!(!rev_tails_generator_p.is_null());
//
//        (rev_reg_def_pub_p, rev_reg_priv_p, rev_reg_entry_p, rev_tails_generator_p)
//    }
//
//    pub fn _free_revocation_registry(rev_reg_def_pub: *const c_void, rev_reg_priv: *const c_void,
//                                     rev_reg_entry: *const c_void, rev_tails_generator: *const c_void) {
//        let err_code = indy_crypto_cl_revocation_key_public_free(rev_reg_def_pub);
//        assert_eq!(err_code, ErrorCode::Success);
//
//        let err_code = indy_crypto_cl_revocation_key_private_free(rev_reg_priv);
//        assert_eq!(err_code, ErrorCode::Success);
//
//        let err_code = indy_crypto_cl_revocation_registry_entry_free(rev_reg_entry);
//        assert_eq!(err_code, ErrorCode::Success);
//
//        let err_code = indy_crypto_cl_revocation_registry_tails_generator_free(rev_tails_generator);
//        assert_eq!(err_code, ErrorCode::Success);
//    }
//
//    pub fn _claim_signature(blinded_master_secret: *const c_void, blinded_master_secret_correctness_proof: *const c_void,
//                            master_secret_blinding_nonce: *const c_void, claim_issuance_nonce: *const c_void, issuer_pub_key: *const c_void,
//                            issuer_priv_key: *const c_void, rev_reg_def_pub_p: *const c_void, rev_reg_priv: *const c_void) -> (*const c_void, *const c_void) {
//        let prover_id = _prover_did();
//        let claim_values = _claim_values();
//        let rev_idx = 1;
//
//        let mut claim_signature: *const c_void = ptr::null();
//        let mut signature_correctness_proof: *const c_void = ptr::null();
//        let err_code = indy_crypto_cl_issuer_sign_claim(prover_id.as_ptr(),
//                                                        blinded_master_secret,
//                                                        blinded_master_secret_correctness_proof,
//                                                        master_secret_blinding_nonce,
//                                                        claim_issuance_nonce,
//                                                        claim_values,
//                                                        issuer_pub_key,
//                                                        issuer_priv_key,
//                                                        rev_idx,
//                                                        rev_reg_def_pub_p,
//                                                        rev_reg_priv,
//                                                        &mut claim_signature,
//                                                        &mut signature_correctness_proof);
//
//        assert_eq!(err_code, ErrorCode::Success);
//        assert!(!claim_signature.is_null());
//        assert!(!signature_correctness_proof.is_null());
//
//        _free_claim_values(claim_values);
//
//        (claim_signature, signature_correctness_proof)
//    }
//
//    pub fn _free_claim_signature(claim_signature: *const c_void, signature_correctness_proof: *const c_void) {
//        let err_code = indy_crypto_cl_claim_signature_free(claim_signature);
//        assert_eq!(err_code, ErrorCode::Success);
//
//        let err_code = indy_crypto_cl_signature_correctness_proof_free(signature_correctness_proof);
//        assert_eq!(err_code, ErrorCode::Success);
//    }
//
//    pub fn _prover_did() -> CString {
//        CString::new("CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW").unwrap()
//    }
//}