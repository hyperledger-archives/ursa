use cl::prover::*;
use cl::*;
use errors::ToErrorCode;
use ffi::ErrorCode;
use utils::ctypes::CTypesUtils;
use utils::json::{JsonEncodable, JsonDecodable};

use libc::c_char;

use std::os::raw::c_void;

/// Creates a master secret.
///
/// Note that master secret deallocation must be performed by
/// calling indy_crypto_cl_master_secret_free.
///
/// # Arguments
/// * `master_secret_p` - Reference that will contain master secret instance pointer.
#[no_mangle]
pub extern fn indy_crypto_cl_prover_new_master_secret(master_secret_p: *mut *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_prover_new_master_secret: >>> {:?}", master_secret_p);

    check_useful_c_ptr!(master_secret_p, ErrorCode::CommonInvalidParam1);

    let res = match Prover::new_master_secret() {
        Ok(master_secret) => {
            trace!("indy_crypto_cl_prover_new_master_secret: master_secret: {:?}", master_secret);
            unsafe {
                *master_secret_p = Box::into_raw(Box::new(master_secret)) as *const c_void;
                trace!("indy_crypto_cl_prover_new_master_secret: *master_secret_p: {:?}", *master_secret_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_cl_prover_new_master_secret: <<< res: {:?}", res);
    res
}

/// Returns json representation of master secret.
///
/// # Arguments
/// * `master_secret` - Reference that contains master secret instance pointer.
/// * `master_secret_json_p` - Reference that will contain master secret json.
#[no_mangle]
pub extern fn indy_crypto_cl_master_secret_to_json(master_secret: *const c_void,
                                                   master_secret_json_p: *mut *const c_char) -> ErrorCode {
    trace!("indy_crypto_cl_master_secret_to_json: >>> master_secret: {:?}, master_secret_json_p: {:?}", master_secret, master_secret_json_p);

    check_useful_c_reference!(master_secret, MasterSecret, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(master_secret_json_p, ErrorCode::CommonInvalidParam2);

    trace!("indy_crypto_cl_master_secret_to_json: entity >>> master_secret: {:?}", master_secret);

    let res = match master_secret.to_json() {
        Ok(master_secret_json) => {
            trace!("indy_crypto_cl_master_secret_to_json: master_secret_json: {:?}", master_secret_json);
            unsafe {
                let master_secret_json = CTypesUtils::string_to_cstring(master_secret_json);
                *master_secret_json_p = master_secret_json.into_raw();
                trace!("indy_crypto_cl_master_secret_to_json: master_secret_json_p: {:?}", *master_secret_json_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_cl_master_secret_to_json: <<< res: {:?}", res);
    res
}

/// Creates and returns master secret from json.
///
/// Note: Master secret instance deallocation must be performed
/// by calling indy_crypto_cl_master_secret_free.
///
/// # Arguments
/// * `master_secret_json` - Reference that contains master secret json.
/// * `master_secret_p` - Reference that will contain master secret instance pointer.
#[no_mangle]
pub extern fn indy_crypto_cl_master_secret_from_json(master_secret_json: *const c_char,
                                                     master_secret_p: *mut *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_master_secret_from_json: >>> master_secret_json: {:?}, master_secret_p: {:?}", master_secret_json, master_secret_p);

    check_useful_c_str!(master_secret_json, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(master_secret_p, ErrorCode::CommonInvalidParam2);

    trace!("indy_crypto_cl_master_secret_from_json: entity: master_secret_json: {:?}", master_secret_json);

    let res = match MasterSecret::from_json(&master_secret_json) {
        Ok(master_secret) => {
            trace!("indy_crypto_cl_master_secret_from_json: master_secret: {:?}", master_secret);
            unsafe {
                *master_secret_p = Box::into_raw(Box::new(master_secret)) as *const c_void;
                trace!("indy_crypto_cl_master_secret_from_json: *master_secret_p: {:?}", *master_secret_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_cl_master_secret_from_json: <<< res: {:?}", res);
    res
}

/// Deallocates master secret instance.
///
/// # Arguments
/// * `master_secret` - Reference that contains master secret instance pointer.
#[no_mangle]
pub extern fn indy_crypto_cl_master_secret_free(master_secret: *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_master_secret_free: >>> master_secret: {:?}", master_secret);

    check_useful_c_ptr!(master_secret, ErrorCode::CommonInvalidParam1);

    let master_secret = unsafe { Box::from_raw(master_secret as *mut MasterSecret); };
    trace!("indy_crypto_cl_master_secret_free: entity: master_secret: {:?}", master_secret);

    let res = ErrorCode::Success;
    trace!("indy_crypto_cl_master_secret_free: <<< res: {:?}", res);

    res
}

/// Creates blinded master secret for given issuer key and master secret.
///
/// Note that blinded master secret deallocation must be performed by
/// calling indy_crypto_cl_blinded_master_secret_free.
///
/// Note that master secret blinding data deallocation must be performed by
/// calling indy_crypto_cl_master_secret_blinding_data_free.
///
/// Note that blinded master secret proof correctness deallocation must be performed by
/// calling indy_crypto_cl_blinded_master_secret_correctness_proof_free.
///
/// # Arguments
/// * `credential_pub_key` - Reference that contains credential public key instance pointer.
/// * `credential_key_correctness_proof` - Reference that contains credential key correctness proof instance pointer.
/// * `master_secret` - Reference that contains master secret instance pointer.
/// * `master_secret_blinding_nonce` - Reference that contains nonce instance pointer.
/// * `blinded_master_secret_p` - Reference that will contain blinded master secret instance pointer.
/// * `master_secret_blinding_data_p` - Reference that will contain master secret blinding data instance pointer.
/// * `blinded_master_secret_correctness_proof_p` - Reference that will contain blinded master secret correctness proof instance pointer.
#[no_mangle]
pub extern fn indy_crypto_cl_prover_blind_master_secret(credential_pub_key: *const c_void,
                                                        credential_key_correctness_proof: *const c_void,
                                                        master_secret: *const c_void,
                                                        master_secret_blinding_nonce: *const c_void,
                                                        blinded_master_secret_p: *mut *const c_void,
                                                        master_secret_blinding_data_p: *mut *const c_void,
                                                        blinded_master_secret_correctness_proof_p: *mut *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_prover_blind_master_secret: >>> credential_pub_key: {:?}, credential_key_correctness_proof: {:?}, master_secret: {:?}, \
    master_secret_blinding_nonce: {:?}, blinded_master_secret_p: {:?}, master_secret_blinding_data_p: {:?}, blinded_master_secret_correctness_proof_p: {:?}",
           credential_pub_key, credential_key_correctness_proof, master_secret, master_secret_blinding_nonce, blinded_master_secret_p,
           master_secret_blinding_data_p, blinded_master_secret_correctness_proof_p);

    check_useful_c_reference!(credential_pub_key, CredentialPublicKey, ErrorCode::CommonInvalidParam1);
    check_useful_c_reference!(credential_key_correctness_proof, CredentialKeyCorrectnessProof, ErrorCode::CommonInvalidParam2);
    check_useful_c_reference!(master_secret, MasterSecret, ErrorCode::CommonInvalidParam3);
    check_useful_c_reference!(master_secret_blinding_nonce, Nonce, ErrorCode::CommonInvalidParam4);
    check_useful_c_ptr!(blinded_master_secret_p, ErrorCode::CommonInvalidParam5);
    check_useful_c_ptr!(master_secret_blinding_data_p, ErrorCode::CommonInvalidParam6);
    check_useful_c_ptr!(blinded_master_secret_correctness_proof_p, ErrorCode::CommonInvalidParam7);

    trace!("indy_crypto_cl_prover_blind_master_secret: entities: credential_pub_key: {:?}, credential_key_correctness_proof: {:?}, master_secret: {:?}, \
    master_secret_blinding_nonce: {:?}", credential_pub_key, credential_key_correctness_proof, master_secret, master_secret_blinding_nonce);

    let res = match Prover::blind_master_secret(credential_pub_key, credential_key_correctness_proof, master_secret, master_secret_blinding_nonce) {
        Ok((blinded_master_secret, master_secret_blinding_data, blinded_master_secret_correctness_proof)) => {
            trace!("indy_crypto_cl_prover_blind_master_secret: blinded_master_secret: {:?}, master_secret_blinding_data: {:?}, \
            blinded_master_secret_correctness_proof: {:?}", blinded_master_secret, master_secret_blinding_data, blinded_master_secret_correctness_proof);
            unsafe {
                *blinded_master_secret_p = Box::into_raw(Box::new(blinded_master_secret)) as *const c_void;
                *master_secret_blinding_data_p = Box::into_raw(Box::new(master_secret_blinding_data)) as *const c_void;
                *blinded_master_secret_correctness_proof_p = Box::into_raw(Box::new(blinded_master_secret_correctness_proof)) as *const c_void;
                trace!("indy_crypto_cl_prover_blind_master_secret: *blinded_master_secret_p: {:?}, *master_secret_blinding_data_p: {:?}, \
                *blinded_master_secret_correctness_proof_p: {:?}",
                       *blinded_master_secret_p, *master_secret_blinding_data_p, *blinded_master_secret_correctness_proof_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_cl_prover_blind_master_secret: <<< res: {:?}", res);
    res
}

/// Returns json representation of blinded master secret.
///
/// # Arguments
/// * `blinded_master_secret` - Reference that contains Blinded master secret pointer.
/// * `blinded_master_secret_json_p` - Reference that will contain blinded master secret json.
#[no_mangle]
pub extern fn indy_crypto_cl_blinded_master_secret_to_json(blinded_master_secret: *const c_void,
                                                           blinded_master_secret_json_p: *mut *const c_char) -> ErrorCode {
    trace!("indy_crypto_cl_blinded_master_secret_to_json: >>> blinded_master_secret: {:?}, blinded_master_secret_json_p: {:?}", blinded_master_secret, blinded_master_secret_json_p);

    check_useful_c_reference!(blinded_master_secret, BlindedMasterSecret, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(blinded_master_secret_json_p, ErrorCode::CommonInvalidParam2);

    trace!("indy_crypto_cl_blinded_master_secret_to_json: entity >>> blinded_master_secret: {:?}", blinded_master_secret);

    let res = match blinded_master_secret.to_json() {
        Ok(blinded_master_secret_json) => {
            trace!("indy_crypto_cl_blinded_master_secret_to_json: blinded_master_secret_json: {:?}", blinded_master_secret_json);
            unsafe {
                let blinded_master_secret_json = CTypesUtils::string_to_cstring(blinded_master_secret_json);
                *blinded_master_secret_json_p = blinded_master_secret_json.into_raw();

                trace!("indy_crypto_cl_blinded_master_secret_to_json: blinded_master_secret_json_p: {:?}", *blinded_master_secret_json_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_cl_blinded_master_secret_to_json: <<< res: {:?}", res);
    res
}

/// Creates and returns blinded master secret from json.
///
/// Note: Blinded master secret instance deallocation must be performed
/// by calling indy_crypto_cl_blinded_master_secret_free
///
/// # Arguments
/// * `blinded_master_secret_json` - Reference that contains blinded master secret json.
/// * `blinded_master_secret_p` - Reference that will contain blinded master secret instance pointer.
#[no_mangle]
pub extern fn indy_crypto_cl_blinded_master_secret_from_json(blinded_master_secret_json: *const c_char,
                                                             blinded_master_secret_p: *mut *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_blinded_master_secret_from_json: >>> blinded_master_secret_json: {:?}, blinded_master_secret_p: {:?}", blinded_master_secret_json, blinded_master_secret_p);

    check_useful_c_str!(blinded_master_secret_json, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(blinded_master_secret_p, ErrorCode::CommonInvalidParam2);

    trace!("indy_crypto_cl_blinded_master_secret_from_json: entity: blinded_master_secret_json: {:?}", blinded_master_secret_json);

    let res = match BlindedMasterSecret::from_json(&blinded_master_secret_json) {
        Ok(blinded_master_secret) => {
            trace!("indy_crypto_cl_blinded_master_secret_from_json: blinded_master_secret: {:?}", blinded_master_secret);
            unsafe {
                *blinded_master_secret_p = Box::into_raw(Box::new(blinded_master_secret)) as *const c_void;
                trace!("indy_crypto_cl_blinded_master_secret_from_json: *blinded_master_secret_p: {:?}", *blinded_master_secret_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_cl_blinded_master_secret_from_json: <<< res: {:?}", res);
    res
}

/// Deallocates  blinded master secret instance.
///
/// # Arguments
/// * `blinded_master_secret` - Reference that contains blinded master secret instance pointer.
#[no_mangle]
pub extern fn indy_crypto_cl_blinded_master_secret_free(blinded_master_secret: *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_blinded_master_secret_free: >>> blinded_master_secret: {:?}", blinded_master_secret);

    check_useful_c_ptr!(blinded_master_secret, ErrorCode::CommonInvalidParam1);

    let blinded_master_secret = unsafe { Box::from_raw(blinded_master_secret as *mut MasterSecret); };
    trace!("indy_crypto_cl_master_secret_free: entity: blinded_master_secret: {:?}", blinded_master_secret);

    let res = ErrorCode::Success;

    trace!("indy_crypto_cl_blinded_master_secret_free: <<< res: {:?}", res);
    res
}

/// Returns json representation of master secret blinding data.
///
/// # Arguments
/// * `master_secret_blinding_data` - Reference that contains master secret blinding data pointer.
/// * `master_secret_blinding_data_json_p` - Reference that will contain master secret blinding data json.
#[no_mangle]
pub extern fn indy_crypto_cl_master_secret_blinding_data_to_json(master_secret_blinding_data: *const c_void,
                                                                 master_secret_blinding_data_json_p: *mut *const c_char) -> ErrorCode {
    trace!("indy_crypto_cl_master_secret_blinding_data_to_json: >>> master_secret_blinding_data: {:?}, master_secret_blinding_data_json_p: {:?}", master_secret_blinding_data, master_secret_blinding_data_json_p);

    check_useful_c_reference!(master_secret_blinding_data, MasterSecretBlindingData, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(master_secret_blinding_data_json_p, ErrorCode::CommonInvalidParam2);

    trace!("indy_crypto_cl_master_secret_blinding_data_to_json: entity >>> master_secret_blinding_data: {:?}", master_secret_blinding_data);

    let res = match master_secret_blinding_data.to_json() {
        Ok(master_secret_blinding_data_json) => {
            trace!("indy_crypto_cl_master_secret_blinding_data_to_json: master_secret_blinding_data_json: {:?}", master_secret_blinding_data_json);
            unsafe {
                let master_secret_blinding_data_json = CTypesUtils::string_to_cstring(master_secret_blinding_data_json);
                *master_secret_blinding_data_json_p = master_secret_blinding_data_json.into_raw();
                trace!("indy_crypto_cl_master_secret_blinding_data_to_json: master_secret_blinding_data_json_p: {:?}", *master_secret_blinding_data_json_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_cl_blinded_master_secret_to_json: <<< res: {:?}", res);
    res
}

/// Creates and returns master secret blinding data json.
///
/// Note: Master secret blinding data instance deallocation must be performed
/// by calling indy_crypto_cl_master_secret_blinding_data_free.
///
/// # Arguments
/// * `master_secret_blinding_data_json` - Reference that contains master secret blinding data json.
/// * `blinded_master_secret_p` - Reference that will contain master secret blinding data instance pointer.
#[no_mangle]
pub extern fn indy_crypto_cl_master_secret_blinding_data_from_json(master_secret_blinding_data_json: *const c_char,
                                                                   master_secret_blinding_data_p: *mut *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_master_secret_blinding_data_from_json: >>> master_secret_blinding_data_json: {:?}, blinded_master_secret_p: {:?}", master_secret_blinding_data_json, master_secret_blinding_data_p);

    check_useful_c_str!(master_secret_blinding_data_json, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(master_secret_blinding_data_p, ErrorCode::CommonInvalidParam2);

    trace!("indy_crypto_cl_master_secret_blinding_data_from_json: entity: master_secret_blinding_data_json: {:?}", master_secret_blinding_data_json);

    let res = match MasterSecretBlindingData::from_json(&master_secret_blinding_data_json) {
        Ok(master_secret_blinding_data) => {
            trace!("indy_crypto_cl_master_secret_blinding_data_from_json: master_secret_blinding_data: {:?}", master_secret_blinding_data);
            unsafe {
                *master_secret_blinding_data_p = Box::into_raw(Box::new(master_secret_blinding_data)) as *const c_void;
                trace!("indy_crypto_cl_master_secret_blinding_data_from_json: *blinded_master_secret_p: {:?}", *master_secret_blinding_data_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_cl_master_secret_blinding_data_from_json: <<< res: {:?}", res);
    res
}

/// Deallocates master secret blinding data instance.
///
/// # Arguments
/// * `master_secret_blinding_data` - Reference that contains master secret  blinding data instance pointer.
#[no_mangle]
pub extern fn indy_crypto_cl_master_secret_blinding_data_free(master_secret_blinding_data: *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_master_secret_blinding_data_free: >>> master_secret_blinding_data: {:?}", master_secret_blinding_data);

    check_useful_c_ptr!(master_secret_blinding_data, ErrorCode::CommonInvalidParam1);

    let master_secret_blinding_data = unsafe { Box::from_raw(master_secret_blinding_data as *mut MasterSecretBlindingData); };
    trace!("indy_crypto_cl_master_secret_blinding_data_free: entity: master_secret_blinding_data: {:?}", master_secret_blinding_data);

    let res = ErrorCode::Success;

    trace!("indy_crypto_cl_master_secret_blinding_data_free: <<< res: {:?}", res);
    res
}

/// Returns json representation of blinded master secret correctness proof.
///
/// # Arguments
/// * `blinded_master_secret_correctness_proof` - Reference that contains blinded master_secret correctness proof pointer.
/// * `blinded_master_secret_correctness_proof_json_p` - Reference that will contain blinded master secret correctness proof json.
#[no_mangle]
pub extern fn indy_crypto_cl_blinded_master_secret_correctness_proof_to_json(blinded_master_secret_correctness_proof: *const c_void,
                                                                             blinded_master_secret_correctness_proof_json_p: *mut *const c_char) -> ErrorCode {
    trace!("indy_crypto_cl_blinded_master_secret_correctness_proof_to_json: >>> blinded_master_secret_correctness_proof: {:?},\
     blinded_master_secret_correctness_proof_json_p: {:?}", blinded_master_secret_correctness_proof, blinded_master_secret_correctness_proof_json_p);

    check_useful_c_reference!(blinded_master_secret_correctness_proof, BlindedMasterSecretCorrectnessProof, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(blinded_master_secret_correctness_proof_json_p, ErrorCode::CommonInvalidParam2);

    trace!("indy_crypto_cl_blinded_master_secret_correctness_proof_to_json: entity >>> blinded_master_secret_correctness_proof: {:?}",
           blinded_master_secret_correctness_proof);

    let res = match blinded_master_secret_correctness_proof.to_json() {
        Ok(blinded_master_secret_correctness_proof_json) => {
            trace!("indy_crypto_cl_blinded_master_secret_correctness_proof_to_json: blinded_master_secret_correctness_proof: {:?}",
                   blinded_master_secret_correctness_proof_json);
            unsafe {
                let blinded_master_secret_correctness_proof_json = CTypesUtils::string_to_cstring(blinded_master_secret_correctness_proof_json);
                *blinded_master_secret_correctness_proof_json_p = blinded_master_secret_correctness_proof_json.into_raw();
                trace!("indy_crypto_cl_blinded_master_secret_correctness_proof_to_json: blinded_master_secret_correctness_proof_json_p: {:?}",
                       *blinded_master_secret_correctness_proof_json_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_cl_blinded_master_secret_correctness_proof_to_json: <<< res: {:?}", res);
    res
}

/// Creates and returns blinded master secret correctness proof json.
///
/// Note: Blinded master secret correctness proof instance deallocation must be performed
/// by calling indy_crypto_cl_blinded_master_secret_correctness_proof_free.
///
/// # Arguments
/// * `blinded_master_secret_correctness_proof_json` - Reference that contains blinded master secret correctness proof json.
/// * `blinded_master_secret_correctness_proof_p` - Reference that will contain blinded master secret correctness proof instance pointer.
#[no_mangle]
pub extern fn indy_crypto_cl_blinded_master_secret_correctness_proof_from_json(blinded_master_secret_correctness_proof_json: *const c_char,
                                                                               blinded_master_secret_correctness_proof_p: *mut *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_blinded_master_secret_correctness_proof_from_json: >>> blinded_master_secret_correctness_proof_json: {:?},\
     blinded_master_secret_correctness_proof_p: {:?}", blinded_master_secret_correctness_proof_json, blinded_master_secret_correctness_proof_p);

    check_useful_c_str!(blinded_master_secret_correctness_proof_json, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(blinded_master_secret_correctness_proof_p, ErrorCode::CommonInvalidParam2);

    trace!("indy_crypto_cl_blinded_master_secret_correctness_proof_from_json: entity: blinded_master_secret_correctness_proof_json: {:?}",
           blinded_master_secret_correctness_proof_json);

    let res = match BlindedMasterSecretCorrectnessProof::from_json(&blinded_master_secret_correctness_proof_json) {
        Ok(blinded_master_secret_correctness_proof) => {
            trace!("indy_crypto_cl_blinded_master_secret_correctness_proof_from_json: blinded_master_secret_correctness_proof: {:?}",
                   blinded_master_secret_correctness_proof);
            unsafe {
                *blinded_master_secret_correctness_proof_p = Box::into_raw(Box::new(blinded_master_secret_correctness_proof)) as *const c_void;
                trace!("indy_crypto_cl_blinded_master_secret_correctness_proof_from_json: *blinded_master_secret_correctness_proof_p: {:?}",
                       *blinded_master_secret_correctness_proof_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_cl_blinded_master_secret_correctness_proof_from_json: <<< res: {:?}", res);
    res
}

/// Deallocates blinded master secret correctness proof instance.
///
/// # Arguments
/// * `blinded_master_secret_correctness_proof` - Reference that contains blinded master secret correctness proof instance pointer.
#[no_mangle]
pub extern fn indy_crypto_cl_blinded_master_secret_correctness_proof_free(blinded_master_secret_correctness_proof: *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_blinded_master_secret_correctness_proof_free: >>> blinded_master_secret_correctness_proof: {:?}",
           blinded_master_secret_correctness_proof);

    check_useful_c_ptr!(blinded_master_secret_correctness_proof, ErrorCode::CommonInvalidParam1);

    let blinded_master_secret_correctness_proof = unsafe { Box::from_raw(blinded_master_secret_correctness_proof as *mut BlindedMasterSecretCorrectnessProof); };
    trace!("indy_crypto_cl_blinded_master_secret_correctness_proof_free: entity: blinded_master_secret_correctness_proof: {:?}", blinded_master_secret_correctness_proof);

    let res = ErrorCode::Success;

    trace!("indy_crypto_cl_blinded_master_secret_correctness_proof_free: <<< res: {:?}", res);
    res
}

/// Updates the credential signature by a master secret blinding data.
///
/// # Arguments
/// * `credential_signature` - Credential signature instance pointer generated by Issuer.
/// * `credential_values` - Credential values instance pointer.
/// * `signature_correctness_proof` - Credential signature correctness proof instance pointer.
/// * `master_secret_blinding_data` - Master secret blinding data instance pointer.
/// * `master_secret` - Master secret instance pointer.
/// * `credential_pub_key` - Credential public key instance pointer.
/// * `nonce` -  Nonce instance pointer was used by Issuer for the creation of signature_correctness_proof.
/// * `rev_key_pub` - (Optional) Revocation registry public key  instance pointer.
/// * `rev_reg` - (Optional) Revocation registry  instance pointer.
/// * `witness` - (Optional) Witness instance pointer.
#[no_mangle]
#[allow(unused_variables)]
pub extern fn indy_crypto_cl_prover_process_credential_signature(credential_signature: *const c_void,
                                                                 credential_values: *const c_void,
                                                                 signature_correctness_proof: *const c_void,
                                                                 master_secret_blinding_data: *const c_void,
                                                                 master_secret: *const c_void,
                                                                 credential_pub_key: *const c_void,
                                                                 credential_issuance_nonce: *const c_void,
                                                                 rev_key_pub: *const c_void,
                                                                 rev_reg: *const c_void,
                                                                 witness: *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_prover_process_credential_signature: >>> credential_signature: {:?}, signature_correctness_proof: {:?}, master_secret_blinding_data: {:?}, \
        master_secret: {:?}, credential_pub_key: {:?}, credential_issuance_nonce: {:?}, rev_key_pub: {:?}, rev_reg {:?}, witness {:?}",
           credential_signature, signature_correctness_proof, master_secret_blinding_data, master_secret, credential_pub_key, credential_issuance_nonce, rev_key_pub, rev_reg, witness);

    check_useful_mut_c_reference!(credential_signature, CredentialSignature, ErrorCode::CommonInvalidParam1);
    check_useful_c_reference!(credential_values, CredentialValues, ErrorCode::CommonInvalidParam1);
    check_useful_c_reference!(signature_correctness_proof, SignatureCorrectnessProof, ErrorCode::CommonInvalidParam2);
    check_useful_c_reference!(master_secret_blinding_data, MasterSecretBlindingData, ErrorCode::CommonInvalidParam3);
    check_useful_c_reference!(master_secret, MasterSecret, ErrorCode::CommonInvalidParam4);
    check_useful_c_reference!(credential_pub_key, CredentialPublicKey, ErrorCode::CommonInvalidParam5);
    check_useful_c_reference!(credential_issuance_nonce, Nonce, ErrorCode::CommonInvalidParam6);
    check_useful_opt_c_reference!(rev_key_pub, RevocationKeyPublic);
    check_useful_opt_c_reference!(rev_reg, RevocationRegistry);
    check_useful_opt_c_reference!(witness, Witness);

    trace!("indy_crypto_cl_prover_process_credential_signature: >>> credential_signature: {:?}, credential_values: {:?}, signature_correctness_proof: {:?}, \
        master_secret: {:?}, credential_pub_key: {:?}, credential_issuance_nonce: {:?}, rev_key_pub: {:?}, rev_reg {:?}, witness {:?}",
           credential_signature, signature_correctness_proof, master_secret_blinding_data, master_secret, credential_pub_key, credential_issuance_nonce, rev_key_pub, rev_reg, witness);

    let res = match Prover::process_credential_signature(credential_signature,
                                                         credential_values,
                                                         signature_correctness_proof,
                                                         master_secret_blinding_data,
                                                         master_secret,
                                                         credential_pub_key,
                                                         credential_issuance_nonce,
                                                         rev_key_pub,
                                                         rev_reg,
                                                         witness) {
        Ok(()) => ErrorCode::Success,
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_cl_prover_process_credential_signature: <<< res: {:?}", res);
    ErrorCode::Success
}

/// Creates and returns proof builder.
///
/// The purpose of proof builder is building of proof entity according to the given request .
///
/// Note that proof builder deallocation must be performed by
/// calling indy_crypto_cl_proof_builder_finalize.
///
/// # Arguments
/// * `proof_builder_p` - Reference that will contain proof builder instance pointer.
#[no_mangle]
pub extern fn indy_crypto_cl_prover_new_proof_builder(proof_builder_p: *mut *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_prover_new_proof_builder: >>> {:?}", proof_builder_p);

    check_useful_c_ptr!(proof_builder_p, ErrorCode::CommonInvalidParam1);

    let res = match Prover::new_proof_builder() {
        Ok(proof_builder) => {
            trace!("indy_crypto_cl_prover_new_proof_builder: proof_builder: {:?}", proof_builder);
            unsafe {
                *proof_builder_p = Box::into_raw(Box::new(proof_builder)) as *const c_void;
                trace!("indy_crypto_cl_prover_new_proof_builder: *proof_builder_p: {:?}", *proof_builder_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_cl_prover_new_proof_builder: <<< res: {:?}", res);
    res
}

#[no_mangle]
pub extern fn indy_crypto_cl_proof_builder_add_sub_proof_request(proof_builder: *const c_void,
                                                                 key_id: *const c_char,
                                                                 sub_proof_request: *const c_void,
                                                                 credential_schema: *const c_void,
                                                                 credential_signature: *const c_void,
                                                                 credential_values: *const c_void,
                                                                 credential_pub_key: *const c_void,
                                                                 rev_reg: *const c_void,
                                                                 witness: *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_proof_builder_add_sub_proof_request: >>> proof_builder: {:?}, key_id: {:?}, sub_proof_request: {:?}, credential_schema: {:?}, \
                credential_signature: {:?}, credential_values: {:?}, credential_pub_key: {:?}, rev_reg: {:?}, witness: {:?}",
           proof_builder, key_id, sub_proof_request, credential_schema, credential_signature, credential_values, credential_pub_key, rev_reg, witness);

    check_useful_mut_c_reference!(proof_builder, ProofBuilder, ErrorCode::CommonInvalidParam1);
    check_useful_c_str!(key_id, ErrorCode::CommonInvalidParam2);
    check_useful_c_reference!(sub_proof_request, SubProofRequest, ErrorCode::CommonInvalidParam3);
    check_useful_c_reference!(credential_schema, CredentialSchema, ErrorCode::CommonInvalidParam4);
    check_useful_c_reference!(credential_signature, CredentialSignature, ErrorCode::CommonInvalidParam5);
    check_useful_c_reference!(credential_values, CredentialValues, ErrorCode::CommonInvalidParam6);
    check_useful_c_reference!(credential_pub_key, CredentialPublicKey, ErrorCode::CommonInvalidParam7);
    check_useful_opt_c_reference!(rev_reg, RevocationRegistry);
    check_useful_opt_c_reference!(witness, Witness);

    trace!("indy_crypto_cl_proof_builder_add_sub_proof_request: entities: proof_builder: {:?}, key_id: {:?}, sub_proof_request: {:?}, credential_schema: {:?}, \
                credential_signature: {:?}, credential_values: {:?}, credential_pub_key: {:?}, rev_reg: {:?}, witness: {:?}",
           proof_builder, key_id, sub_proof_request, credential_schema, credential_signature, credential_values, credential_pub_key, rev_reg, witness);

    let res = match proof_builder.add_sub_proof_request(&key_id,
                                                        sub_proof_request,
                                                        credential_schema,
                                                        credential_signature,
                                                        credential_values,
                                                        credential_pub_key,
                                                        rev_reg,
                                                        witness) {
        Ok(()) => ErrorCode::Success,
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_cl_proof_builder_add_sub_proof_request: <<< res: {:?}", res);
    ErrorCode::Success
}


/// Finalize proof.
///
/// Note that proof deallocation must be performed by
/// calling indy_crypto_cl_proof_free.
///
/// # Arguments
/// * `proof_builder` - Reference that contain proof builder instance pointer.
/// * `nonce` - Reference that contain nonce instance pointer.
/// * `master_secret` - Reference that contain master secret instance pointer.
/// * `proof_p` - Reference that will contain proof instance pointer.
#[no_mangle]
pub extern fn indy_crypto_cl_proof_builder_finalize(proof_builder: *const c_void,
                                                    nonce: *const c_void,
                                                    master_secret: *const c_void,
                                                    proof_p: *mut *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_proof_builder_finalize: >>> proof_builder: {:?}, nonce: {:?}, master_secret: {:?}, proof_p: {:?}",
           proof_builder, nonce, master_secret, proof_p);

    check_useful_c_ptr!(proof_builder, ErrorCode::CommonInvalidParam1);
    check_useful_c_reference!(nonce, Nonce, ErrorCode::CommonInvalidParam2);
    check_useful_c_reference!(master_secret, MasterSecret, ErrorCode::CommonInvalidParam3);
    check_useful_c_ptr!(proof_p, ErrorCode::CommonInvalidParam4);

    let proof_builder = unsafe { Box::from_raw(proof_builder as *mut ProofBuilder) };

    trace!("indy_crypto_cl_proof_builder_finalize: entities: proof_builder: {:?}, nonce: {:?}, master_secret: {:?}",
           proof_builder, nonce, master_secret);

    let res = match proof_builder.finalize(nonce, master_secret) {
        Ok(proof) => {
            trace!("indy_crypto_cl_proof_builder_finalize: proof: {:?}", proof);
            unsafe {
                *proof_p = Box::into_raw(Box::new(proof)) as *const c_void;
                trace!("indy_crypto_cl_proof_builder_finalize: *proof_p: {:?}", *proof_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_cl_proof_builder_finalize: <<< res: {:?}", res);
    res
}

/// Returns json representation of proof.
///
/// # Arguments
/// * `proof` - Reference that contains proof instance pointer.
/// * `proof_json_p` - Reference that will contain proof json.
#[no_mangle]
pub extern fn indy_crypto_cl_proof_to_json(proof: *const c_void,
                                           proof_json_p: *mut *const c_char) -> ErrorCode {
    trace!("indy_crypto_cl_proof_to_json: >>> proof: {:?}, proof_json_p: {:?}", proof, proof_json_p);

    check_useful_c_reference!(proof, Proof, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(proof_json_p, ErrorCode::CommonInvalidParam2);

    trace!("indy_crypto_cl_proof_to_json: entity >>> proof: {:?}", proof);

    let res = match proof.to_json() {
        Ok(proof_json) => {
            trace!("indy_crypto_cl_proof_to_json: proof_json: {:?}", proof_json);
            unsafe {
                let proof_json = CTypesUtils::string_to_cstring(proof_json);
                *proof_json_p = proof_json.into_raw();
                trace!("indy_crypto_cl_proof_to_json: proof_json_p: {:?}", *proof_json_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_cl_proof_to_json: <<< res: {:?}", res);
    res
}

/// Creates and returns proof json.
///
/// Note: Proof instance deallocation must be performed by calling indy_crypto_cl_proof_free.
///
/// # Arguments
/// * `proof_json` - Reference that contains proof json.
/// * `proof_p` - Reference that will contain proof instance pointer.
#[no_mangle]
pub extern fn indy_crypto_cl_proof_from_json(proof_json: *const c_char,
                                             proof_p: *mut *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_proof_from_json: >>> proof_json: {:?}, proof_p: {:?}", proof_json, proof_p);

    check_useful_c_str!(proof_json, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(proof_p, ErrorCode::CommonInvalidParam2);

    trace!("indy_crypto_cl_proof_from_json: entity: proof_json: {:?}", proof_json);

    let res = match Proof::from_json(&proof_json) {
        Ok(proof) => {
            trace!("indy_crypto_cl_proof_from_json: proof: {:?}", proof);
            unsafe {
                *proof_p = Box::into_raw(Box::new(proof)) as *const c_void;
                trace!("indy_crypto_cl_proof_from_json: *proof_p: {:?}", *proof_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_cl_proof_from_json: <<< res: {:?}", res);
    res
}

/// Deallocates proof instance.
///
/// # Arguments
/// * `proof` - Reference that contains proof instance pointer.
#[no_mangle]
pub extern fn indy_crypto_cl_proof_free(proof: *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_proof_free: >>> proof: {:?}", proof);

    check_useful_c_ptr!(proof, ErrorCode::CommonInvalidParam1);

    let proof = unsafe { Box::from_raw(proof as *mut Proof); };
    trace!("indy_crypto_cl_proof_free: entity: proof: {:?}", proof);

    let res = ErrorCode::Success;

    trace!("indy_crypto_cl_proof_free: <<< res: {:?}", res);
    res
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::ffi::CString;
    use std::ptr;
    use ffi::cl::mocks::*;
    use ffi::cl::issuer::mocks::*;
    use ffi::cl::prover::mocks::*;

    #[test]
    fn indy_crypto_cl_prover_new_master_secret_works() {
        let mut master_secret_p: *const c_void = ptr::null();
        let err_code = indy_crypto_cl_prover_new_master_secret(&mut master_secret_p);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!master_secret_p.is_null());

        _free_master_secret(master_secret_p)
    }

    #[test]
    fn indy_crypto_cl_master_secret_to_json_works() {
        let master_secret = _master_secret();

        let mut master_secret_json_p: *const c_char = ptr::null();
        let err_code = indy_crypto_cl_master_secret_to_json(master_secret, &mut master_secret_json_p);
        assert_eq!(err_code, ErrorCode::Success);

        _free_master_secret(master_secret)
    }

    #[test]
    fn indy_crypto_cl_master_secret_from_json_works() {
        let master_secret = _master_secret();

        let mut master_secret_json_p: *const c_char = ptr::null();
        let err_code = indy_crypto_cl_master_secret_to_json(master_secret, &mut master_secret_json_p);
        assert_eq!(err_code, ErrorCode::Success);

        let mut master_secret_p: *const c_void = ptr::null();
        let err_code = indy_crypto_cl_master_secret_from_json(master_secret_json_p, &mut master_secret_p);
        assert_eq!(err_code, ErrorCode::Success);

        _free_master_secret(master_secret)
    }

    #[test]
    fn indy_crypto_cl_prover_master_secret_free_works() {
        let master_secret = _master_secret();

        let err_code = indy_crypto_cl_master_secret_free(master_secret);
        assert_eq!(err_code, ErrorCode::Success);
    }

    #[test]
    fn indy_crypto_cl_prover_blind_master_secret_works() {
        let master_secret = _master_secret();
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) = _credential_def();
        let master_secret_blinding_nonce = _nonce();

        let mut blinded_master_secret_p: *const c_void = ptr::null();
        let mut master_secret_blinding_data_p: *const c_void = ptr::null();
        let mut blinded_master_secret_correctness_proof_p: *const c_void = ptr::null();

        let err_code = indy_crypto_cl_prover_blind_master_secret(credential_pub_key,
                                                                 credential_key_correctness_proof,
                                                                 master_secret,
                                                                 master_secret_blinding_nonce,
                                                                 &mut blinded_master_secret_p,
                                                                 &mut master_secret_blinding_data_p,
                                                                 &mut blinded_master_secret_correctness_proof_p);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!blinded_master_secret_p.is_null());
        assert!(!master_secret_blinding_data_p.is_null());

        _free_blinded_master_secret(blinded_master_secret_p,
                                    master_secret_blinding_data_p,
                                    blinded_master_secret_correctness_proof_p);
        _free_master_secret(master_secret);
        _free_credential_def(credential_pub_key, credential_priv_key, credential_key_correctness_proof);
        _free_nonce(master_secret_blinding_nonce);
    }

    #[test]
    fn indy_crypto_cl_prover_blinded_master_secret_free_works() {
        let master_secret = _master_secret();
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) = _credential_def();
        let master_secret_blinding_nonce = _nonce();
        let (blinded_master_secret, master_secret_blinding_data,
            blinded_master_secret_correctness_proof) = _blinded_master_secret(credential_pub_key,
                                                                              credential_key_correctness_proof,
                                                                              master_secret,
                                                                              master_secret_blinding_nonce);
        let err_code = indy_crypto_cl_blinded_master_secret_free(blinded_master_secret);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = indy_crypto_cl_master_secret_blinding_data_free(master_secret_blinding_data);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = indy_crypto_cl_blinded_master_secret_correctness_proof_free(blinded_master_secret_correctness_proof);
        assert_eq!(err_code, ErrorCode::Success);

        _free_credential_def(credential_pub_key, credential_priv_key, credential_key_correctness_proof);
        _free_master_secret(master_secret);
        _free_nonce(master_secret_blinding_nonce);
    }

    #[test]
    fn indy_crypto_cl_prover_blinded_master_secret_to_json_works() {
        let master_secret = _master_secret();
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) = _credential_def();
        let master_secret_blinding_nonce = _nonce();
        let (blinded_master_secret, master_secret_blinding_data,
            blinded_master_secret_correctness_proof) = _blinded_master_secret(credential_pub_key,
                                                                              credential_key_correctness_proof,
                                                                              master_secret,
                                                                              master_secret_blinding_nonce);

        let mut blinded_master_secret_json_p: *const c_char = ptr::null();
        let err_code = indy_crypto_cl_blinded_master_secret_to_json(blinded_master_secret, &mut blinded_master_secret_json_p);
        assert_eq!(err_code, ErrorCode::Success);

        _free_credential_def(credential_pub_key, credential_priv_key, credential_key_correctness_proof);
        _free_master_secret(master_secret);
        _free_nonce(master_secret_blinding_nonce);
        _free_blinded_master_secret(blinded_master_secret, master_secret_blinding_data, blinded_master_secret_correctness_proof);
    }

    #[test]
    fn indy_crypto_cl_prover_blinded_master_secret_from_json_works() {
        let master_secret = _master_secret();
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) = _credential_def();
        let master_secret_blinding_nonce = _nonce();
        let (blinded_master_secret, master_secret_blinding_data,
            blinded_master_secret_correctness_proof) = _blinded_master_secret(credential_pub_key,
                                                                              credential_key_correctness_proof,
                                                                              master_secret,
                                                                              master_secret_blinding_nonce);

        let mut blinded_master_secret_json_p: *const c_char = ptr::null();
        let err_code = indy_crypto_cl_blinded_master_secret_to_json(blinded_master_secret, &mut blinded_master_secret_json_p);
        assert_eq!(err_code, ErrorCode::Success);

        let mut blinded_master_secret_p: *const c_void = ptr::null();
        let err_code = indy_crypto_cl_blinded_master_secret_from_json(blinded_master_secret_json_p,
                                                                      &mut blinded_master_secret_p);
        assert_eq!(err_code, ErrorCode::Success);

        _free_credential_def(credential_pub_key, credential_priv_key, credential_key_correctness_proof);
        _free_master_secret(master_secret);
        _free_nonce(master_secret_blinding_nonce);
        _free_blinded_master_secret(blinded_master_secret, master_secret_blinding_data, blinded_master_secret_correctness_proof);
    }

    #[test]
    fn indy_crypto_cl_prover_master_secret_blinding_data_to_json_works() {
        let master_secret = _master_secret();
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) = _credential_def();
        let master_secret_blinding_nonce = _nonce();
        let (blinded_master_secret, master_secret_blinding_data,
            blinded_master_secret_correctness_proof) = _blinded_master_secret(credential_pub_key,
                                                                              credential_key_correctness_proof,
                                                                              master_secret,
                                                                              master_secret_blinding_nonce);

        let mut master_secret_blinding_data_json_p: *const c_char = ptr::null();
        let err_code = indy_crypto_cl_master_secret_blinding_data_to_json(master_secret_blinding_data,
                                                                          &mut master_secret_blinding_data_json_p);
        assert_eq!(err_code, ErrorCode::Success);

        _free_credential_def(credential_pub_key, credential_priv_key, credential_key_correctness_proof);
        _free_master_secret(master_secret);
        _free_nonce(master_secret_blinding_nonce);
        _free_blinded_master_secret(blinded_master_secret, master_secret_blinding_data, blinded_master_secret_correctness_proof);
    }

    #[test]
    fn indy_crypto_cl_prover_master_secret_blinding_data_from_json_works() {
        let master_secret = _master_secret();
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) = _credential_def();
        let master_secret_blinding_nonce = _nonce();
        let (blinded_master_secret, master_secret_blinding_data,
            blinded_master_secret_correctness_proof) = _blinded_master_secret(credential_pub_key,
                                                                              credential_key_correctness_proof,
                                                                              master_secret,
                                                                              master_secret_blinding_nonce);

        let mut master_secret_blinding_data_json_p: *const c_char = ptr::null();
        let err_code = indy_crypto_cl_master_secret_blinding_data_to_json(master_secret_blinding_data,
                                                                          &mut master_secret_blinding_data_json_p);
        assert_eq!(err_code, ErrorCode::Success);

        let mut master_secret_blinding_data_p: *const c_void = ptr::null();
        let err_code = indy_crypto_cl_master_secret_blinding_data_from_json(master_secret_blinding_data_json_p,
                                                                            &mut master_secret_blinding_data_p);
        assert_eq!(err_code, ErrorCode::Success);

        _free_credential_def(credential_pub_key, credential_priv_key, credential_key_correctness_proof);
        _free_master_secret(master_secret);
        _free_nonce(master_secret_blinding_nonce);
        _free_blinded_master_secret(blinded_master_secret, master_secret_blinding_data, blinded_master_secret_correctness_proof);
    }

    #[test]
    fn indy_crypto_cl_prover_blinded_master_secret_correctness_proof_to_json_works() {
        let master_secret = _master_secret();
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) = _credential_def();
        let master_secret_blinding_nonce = _nonce();
        let (blinded_master_secret, master_secret_blinding_data,
            blinded_master_secret_correctness_proof) = _blinded_master_secret(credential_pub_key,
                                                                              credential_key_correctness_proof,
                                                                              master_secret,
                                                                              master_secret_blinding_nonce);

        let mut blinded_master_secret_correctness_proof_json_p: *const c_char = ptr::null();
        let err_code = indy_crypto_cl_blinded_master_secret_correctness_proof_to_json(blinded_master_secret_correctness_proof,
                                                                                      &mut blinded_master_secret_correctness_proof_json_p);
        assert_eq!(err_code, ErrorCode::Success);

        _free_credential_def(credential_pub_key, credential_priv_key, credential_key_correctness_proof);
        _free_master_secret(master_secret);
        _free_nonce(master_secret_blinding_nonce);
        _free_blinded_master_secret(blinded_master_secret, master_secret_blinding_data, blinded_master_secret_correctness_proof);
    }

    #[test]
    fn indy_crypto_cl_prover_blinded_master_secret_correctness_proof_from_json_works() {
        let master_secret = _master_secret();
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) = _credential_def();
        let master_secret_blinding_nonce = _nonce();
        let (blinded_master_secret, master_secret_blinding_data,
            blinded_master_secret_correctness_proof) = _blinded_master_secret(credential_pub_key,
                                                                              credential_key_correctness_proof,
                                                                              master_secret,
                                                                              master_secret_blinding_nonce);

        let mut blinded_master_secret_correctness_proof_json_p: *const c_char = ptr::null();
        let err_code = indy_crypto_cl_blinded_master_secret_correctness_proof_to_json(blinded_master_secret_correctness_proof,
                                                                                      &mut blinded_master_secret_correctness_proof_json_p);
        assert_eq!(err_code, ErrorCode::Success);

        let mut blinded_master_secret_correctness_proof_p: *const c_void = ptr::null();
        let err_code = indy_crypto_cl_blinded_master_secret_correctness_proof_from_json(blinded_master_secret_correctness_proof_json_p,
                                                                                        &mut blinded_master_secret_correctness_proof_p);
        assert_eq!(err_code, ErrorCode::Success);

        _free_credential_def(credential_pub_key, credential_priv_key, credential_key_correctness_proof);
        _free_master_secret(master_secret);
        _free_nonce(master_secret_blinding_nonce);
        _free_blinded_master_secret(blinded_master_secret, master_secret_blinding_data, blinded_master_secret_correctness_proof);
    }

    #[test]
    fn indy_crypto_cl_prover_process_credential_signature_signature_works() {
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) = _credential_def();
        let master_secret = _master_secret();
        let master_secret_blinding_nonce = _nonce();
        let credential_values = _credential_values();
        let (blinded_master_secret, master_secret_blinding_data,
            blinded_master_secret_correctness_proof) = _blinded_master_secret(credential_pub_key,
                                                                              credential_key_correctness_proof,
                                                                              master_secret,
                                                                              master_secret_blinding_nonce);

        let credential_issuance_nonce = _nonce();
        let (credential_signature, signature_correctness_proof) =
            _credential_signature(blinded_master_secret,
                                  blinded_master_secret_correctness_proof,
                                  master_secret_blinding_nonce,
                                  credential_issuance_nonce,
                                  credential_pub_key,
                                  credential_priv_key);
        let err_code = indy_crypto_cl_prover_process_credential_signature(credential_signature,
                                                                          credential_values,
                                                                          signature_correctness_proof,
                                                                          master_secret_blinding_data,
                                                                          master_secret,
                                                                          credential_pub_key,
                                                                          credential_issuance_nonce,
                                                                          ptr::null(),
                                                                          ptr::null(),
                                                                          ptr::null());
        assert_eq!(err_code, ErrorCode::Success);

        _free_credential_def(credential_pub_key, credential_priv_key, credential_key_correctness_proof);
        _free_blinded_master_secret(blinded_master_secret, master_secret_blinding_data, blinded_master_secret_correctness_proof);
        _free_master_secret(master_secret);
        _free_nonce(master_secret_blinding_nonce);
        _free_nonce(credential_issuance_nonce);
        _free_credential_signature(credential_signature, signature_correctness_proof);
    }

    #[test]
    fn indy_crypto_cl_prover_proof_builder_new_works() {
        let mut proof_builder: *const c_void = ptr::null();
        let err_code = indy_crypto_cl_prover_new_proof_builder(&mut proof_builder);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!proof_builder.is_null());

        let nonce = _nonce();
        let master_secret = _master_secret();

        _free_proof_builder(proof_builder, nonce, master_secret);
    }

    #[test]
    fn indy_crypto_cl_prover_proof_builder_add_sub_proof_request_works() {
        let uuid = CString::new("uuid").unwrap();
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) = _credential_def();
        let master_secret = _master_secret();
        let master_secret_blinding_nonce = _nonce();
        let (blinded_master_secret, master_secret_blinding_data,
            blinded_master_secret_correctness_proof) = _blinded_master_secret(credential_pub_key,
                                                                              credential_key_correctness_proof,
                                                                              master_secret,
                                                                              master_secret_blinding_nonce);
        let credential_values = _credential_values();
        let sub_proof_request = _sub_proof_request();
        let credential_schema = _credential_schema();
        let credential_issuance_nonce = _nonce();
        let (credential_signature, signature_correctness_proof) = _credential_signature(blinded_master_secret,
                                                                                        blinded_master_secret_correctness_proof,
                                                                                        master_secret_blinding_nonce,
                                                                                        credential_issuance_nonce,
                                                                                        credential_pub_key,
                                                                                        credential_pub_key);
        _process_credential_signature(credential_signature,
                                      signature_correctness_proof,
                                      master_secret_blinding_data,
                                      master_secret,
                                      credential_pub_key,
                                      credential_issuance_nonce,
                                      ptr::null(),
                                      ptr::null(),
                                      ptr::null());
        let proof_builder = _proof_builder();

        let err_code = indy_crypto_cl_proof_builder_add_sub_proof_request(proof_builder,
                                                                          uuid.as_ptr(),
                                                                          sub_proof_request,
                                                                          credential_schema,
                                                                          credential_signature,
                                                                          credential_values,
                                                                          credential_pub_key,
                                                                          ptr::null(),
                                                                          ptr::null());
        assert_eq!(err_code, ErrorCode::Success);

        let nonce = _nonce();

        _free_proof_builder(proof_builder, nonce, master_secret);
        _free_credential_def(credential_pub_key, credential_priv_key, credential_key_correctness_proof);
        _free_master_secret(master_secret);
        _free_blinded_master_secret(blinded_master_secret, master_secret_blinding_data, blinded_master_secret_correctness_proof);
        _free_nonce(master_secret_blinding_nonce);
        _free_nonce(credential_issuance_nonce);
        _free_credential_values(credential_values);
        _free_sub_proof_request(sub_proof_request);
        _free_credential_signature(credential_signature, signature_correctness_proof);
    }

    #[test]
    fn indy_crypto_cl_prover_proof_builder_finalize_works() {
        let uuid = CString::new("uuid").unwrap();
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) = _credential_def();
        let master_secret = _master_secret();
        let master_secret_blinding_nonce = _nonce();
        let (blinded_master_secret, master_secret_blinding_data,
            blinded_master_secret_correctness_proof) = _blinded_master_secret(credential_pub_key,
                                                                              credential_key_correctness_proof,
                                                                              master_secret,
                                                                              master_secret_blinding_nonce);
        let credential_values = _credential_values();
        let sub_proof_request = _sub_proof_request();
        let credential_schema = _credential_schema();
        let credential_issuance_nonce = _nonce();
        let (credential_signature, signature_correctness_proof) = _credential_signature(blinded_master_secret,
                                                                                        blinded_master_secret_correctness_proof,
                                                                                        master_secret_blinding_nonce,
                                                                                        credential_issuance_nonce,
                                                                                        credential_pub_key,
                                                                                        credential_priv_key);
        _process_credential_signature(credential_signature,
                                      signature_correctness_proof,
                                      master_secret_blinding_data,
                                      master_secret,
                                      credential_pub_key,
                                      credential_issuance_nonce,
                                      ptr::null(),
                                      ptr::null(),
                                      ptr::null());
        let proof_builder = _proof_builder();

        let err_code = indy_crypto_cl_proof_builder_add_sub_proof_request(proof_builder,
                                                                          uuid.as_ptr(),
                                                                          sub_proof_request,
                                                                          credential_schema,
                                                                          credential_signature,
                                                                          credential_values,
                                                                          credential_pub_key,
                                                                          ptr::null(),
                                                                          ptr::null());
        assert_eq!(err_code, ErrorCode::Success);

        let nonce = _nonce();

        let mut proof: *const c_void = ptr::null();
        let err_code = indy_crypto_cl_proof_builder_finalize(proof_builder, nonce, master_secret, &mut proof);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!proof.is_null());

        _free_credential_def(credential_pub_key, credential_priv_key, credential_key_correctness_proof);
        _free_master_secret(master_secret);
        _free_blinded_master_secret(blinded_master_secret, master_secret_blinding_data, blinded_master_secret_correctness_proof);
        _free_nonce(master_secret_blinding_nonce);
        _free_nonce(credential_issuance_nonce);
        _free_credential_values(credential_values);
        _free_sub_proof_request(sub_proof_request);
        _free_credential_signature(credential_signature, signature_correctness_proof);
        _free_proof(proof);
    }

    #[test]
    fn indy_crypto_cl_proof_to_json_works() {
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) = _credential_def();
        let master_secret = _master_secret();
        let master_secret_blinding_nonce = _nonce();
        let (blinded_master_secret, master_secret_blinding_data,
            blinded_master_secret_correctness_proof) = _blinded_master_secret(credential_pub_key,
                                                                              credential_key_correctness_proof,
                                                                              master_secret,
                                                                              master_secret_blinding_nonce);
        let credential_issuance_nonce = _nonce();
        let (credential_signature, signature_correctness_proof) = _credential_signature(blinded_master_secret,
                                                                                        blinded_master_secret_correctness_proof,
                                                                                        master_secret_blinding_nonce,
                                                                                        credential_issuance_nonce,
                                                                                        credential_pub_key,
                                                                                        credential_priv_key);
        _process_credential_signature(credential_signature,
                                      signature_correctness_proof,
                                      master_secret_blinding_data,
                                      master_secret,
                                      credential_pub_key,
                                      credential_issuance_nonce,
                                      ptr::null(),
                                      ptr::null(),
                                      ptr::null());

        let proof_building_nonce = _nonce();
        let proof = _proof(credential_pub_key,
                           credential_signature,
                           proof_building_nonce,
                           master_secret,
                           ptr::null(),
                           ptr::null());

        let mut proof_json_p: *const c_char = ptr::null();
        let err_code = indy_crypto_cl_proof_to_json(proof, &mut proof_json_p);
        assert_eq!(err_code, ErrorCode::Success);

        _free_credential_def(credential_pub_key, credential_priv_key, credential_key_correctness_proof);
        _free_master_secret(master_secret);
        _free_blinded_master_secret(blinded_master_secret, master_secret_blinding_data, blinded_master_secret_correctness_proof);
        _free_nonce(master_secret_blinding_nonce);
        _free_nonce(credential_issuance_nonce);
        _free_nonce(proof_building_nonce);
        _free_credential_signature(credential_signature, signature_correctness_proof);
        _free_proof(proof);
    }

    #[test]
    fn indy_crypto_cl_proof_from_json_works() {
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) = _credential_def();
        let master_secret = _master_secret();
        let master_secret_blinding_nonce = _nonce();
        let (blinded_master_secret, master_secret_blinding_data,
            blinded_master_secret_correctness_proof) = _blinded_master_secret(credential_pub_key,
                                                                              credential_key_correctness_proof,
                                                                              master_secret,
                                                                              master_secret_blinding_nonce);
        let credential_issuance_nonce = _nonce();
        let (credential_signature, signature_correctness_proof) = _credential_signature(blinded_master_secret,
                                                                                        blinded_master_secret_correctness_proof,
                                                                                        master_secret_blinding_nonce,
                                                                                        credential_issuance_nonce,
                                                                                        credential_pub_key,
                                                                                        credential_priv_key);
        _process_credential_signature(credential_signature,
                                      signature_correctness_proof,
                                      master_secret_blinding_data,
                                      master_secret,
                                      credential_pub_key,
                                      credential_issuance_nonce,
                                      ptr::null(),
                                      ptr::null(),
                                      ptr::null());

        let proof_building_nonce = _nonce();
        let proof = _proof(credential_pub_key,
                           credential_signature,
                           proof_building_nonce,
                           master_secret,
                           ptr::null(),
                           ptr::null());

        let mut proof_json_p: *const c_char = ptr::null();
        let err_code = indy_crypto_cl_proof_to_json(proof, &mut proof_json_p);
        assert_eq!(err_code, ErrorCode::Success);

        let mut proof_p: *const c_void = ptr::null();
        let err_code = indy_crypto_cl_proof_from_json(proof_json_p, &mut proof_p);
        assert_eq!(err_code, ErrorCode::Success);

        _free_credential_def(credential_pub_key, credential_priv_key, credential_key_correctness_proof);
        _free_master_secret(master_secret);
        _free_blinded_master_secret(blinded_master_secret, master_secret_blinding_data, blinded_master_secret_correctness_proof);
        _free_nonce(master_secret_blinding_nonce);
        _free_nonce(credential_issuance_nonce);
        _free_nonce(proof_building_nonce);
        _free_credential_signature(credential_signature, signature_correctness_proof);
        _free_proof(proof);
    }

    #[test]
    fn indy_crypto_cl_proof_free_works() {
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) = _credential_def();
        let master_secret = _master_secret();
        let master_secret_blinding_nonce = _nonce();
        let (blinded_master_secret, master_secret_blinding_data,
            blinded_master_secret_correctness_proof) = _blinded_master_secret(credential_pub_key,
                                                                              credential_key_correctness_proof,
                                                                              master_secret,
                                                                              master_secret_blinding_nonce);
        let credential_issuance_nonce = _nonce();
        let (credential_signature, signature_correctness_proof) = _credential_signature(blinded_master_secret,
                                                                                        blinded_master_secret_correctness_proof,
                                                                                        master_secret_blinding_nonce,
                                                                                        credential_issuance_nonce,
                                                                                        credential_pub_key,
                                                                                        credential_priv_key);
        _process_credential_signature(credential_signature,
                                      signature_correctness_proof,
                                      master_secret_blinding_data,
                                      master_secret,
                                      credential_pub_key,
                                      credential_issuance_nonce,
                                      ptr::null(),
                                      ptr::null(),
                                      ptr::null());

        let proof_building_nonce = _nonce();
        let proof = _proof(credential_pub_key,
                           credential_signature,
                           proof_building_nonce,
                           master_secret,
                           ptr::null(),
                           ptr::null());

        _free_credential_def(credential_pub_key, credential_priv_key, credential_key_correctness_proof);
        _free_master_secret(master_secret);
        _free_blinded_master_secret(blinded_master_secret, master_secret_blinding_data, blinded_master_secret_correctness_proof);
        _free_nonce(master_secret_blinding_nonce);
        _free_nonce(credential_issuance_nonce);
        _free_nonce(proof_building_nonce);
        _free_credential_signature(credential_signature, signature_correctness_proof);

        let err_code = indy_crypto_cl_proof_free(proof);
        assert_eq!(err_code, ErrorCode::Success);
    }
}

pub mod mocks {
    use super::*;

    use std::ptr;
    use std::ffi::CString;
    use ffi::cl::mocks::*;

    pub fn _master_secret() -> *const c_void {
        let mut master_secret_p: *const c_void = ptr::null();
        let err_code = indy_crypto_cl_prover_new_master_secret(&mut master_secret_p);

        assert_eq!(err_code, ErrorCode::Success);
        assert!(!master_secret_p.is_null());

        master_secret_p
    }

    pub fn _free_master_secret(master_secret: *const c_void) {
        let err_code = indy_crypto_cl_master_secret_free(master_secret);
        assert_eq!(err_code, ErrorCode::Success);
    }

    pub fn _blinded_master_secret(credential_pub_key: *const c_void,
                                  credential_key_correctness_proof: *const c_void,
                                  master_secret: *const c_void,
                                  master_secret_blinding_nonce: *const c_void) -> (*const c_void, *const c_void, *const c_void) {
        let mut blinded_master_secret_p: *const c_void = ptr::null();
        let mut master_secret_blinding_data_p: *const c_void = ptr::null();
        let mut blinded_master_secret_correctness_proof_p: *const c_void = ptr::null();

        let err_code = indy_crypto_cl_prover_blind_master_secret(credential_pub_key,
                                                                 credential_key_correctness_proof,
                                                                 master_secret,
                                                                 master_secret_blinding_nonce,
                                                                 &mut blinded_master_secret_p,
                                                                 &mut master_secret_blinding_data_p,
                                                                 &mut blinded_master_secret_correctness_proof_p);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!blinded_master_secret_p.is_null());
        assert!(!master_secret_blinding_data_p.is_null());
        assert!(!blinded_master_secret_correctness_proof_p.is_null());

        (blinded_master_secret_p, master_secret_blinding_data_p, blinded_master_secret_correctness_proof_p)
    }

    pub fn _free_blinded_master_secret(blinded_master_secret: *const c_void, master_secret_blinding_data: *const c_void,
                                       blinded_master_secret_correctness_proof: *const c_void) {
        let err_code = indy_crypto_cl_blinded_master_secret_free(blinded_master_secret);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = indy_crypto_cl_master_secret_blinding_data_free(master_secret_blinding_data);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = indy_crypto_cl_blinded_master_secret_correctness_proof_free(blinded_master_secret_correctness_proof);
        assert_eq!(err_code, ErrorCode::Success);
    }

    pub fn _process_credential_signature(credential_signature: *const c_void, signature_correctness_proof: *const c_void,
                                         master_secret_blinding_data: *const c_void, master_secret: *const c_void,
                                         credential_pub_key: *const c_void, credential_issuance_nonce: *const c_void,
                                         rev_key_pub: *const c_void, rev_reg: *const c_void, witness: *const c_void) {
        let credential_values = _credential_values();
        let err_code = indy_crypto_cl_prover_process_credential_signature(credential_signature,
                                                                          credential_values,
                                                                          signature_correctness_proof,
                                                                          master_secret_blinding_data,
                                                                          master_secret,
                                                                          credential_pub_key,
                                                                          credential_issuance_nonce,
                                                                          rev_key_pub,
                                                                          rev_reg,
                                                                          witness);
        assert_eq!(err_code, ErrorCode::Success);
        _free_credential_values(credential_values);
    }

    pub fn _proof_builder() -> *const c_void {
        let mut proof_builder: *const c_void = ptr::null();
        let err_code = indy_crypto_cl_prover_new_proof_builder(&mut proof_builder);

        assert_eq!(err_code, ErrorCode::Success);
        assert!(!proof_builder.is_null());

        proof_builder
    }

    pub fn _free_proof_builder(proof_builder: *const c_void, nonce: *const c_void, master_secret: *const c_void) {
        let mut proof: *const c_void = ptr::null();
        let err_code = indy_crypto_cl_proof_builder_finalize(proof_builder, nonce, master_secret, &mut proof);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!proof.is_null());
    }

    pub fn _proof(credential_pub_key: *const c_void, credential_signature: *const c_void,
                  nonce: *const c_void, master_secret: *const c_void,
                  rev_reg: *const c_void, witness: *const c_void) -> *const c_void {
        let proof_builder = _proof_builder();
        let credential_schema = _credential_schema();
        let credential_values = _credential_values();
        let sub_proof_request = _sub_proof_request();
        let key_id = CString::new("key_id").unwrap();

        indy_crypto_cl_proof_builder_add_sub_proof_request(proof_builder,
                                                           key_id.as_ptr(),
                                                           sub_proof_request,
                                                           credential_schema,
                                                           credential_signature,
                                                           credential_values,
                                                           credential_pub_key,
                                                           rev_reg,
                                                           witness);

        let mut proof: *const c_void = ptr::null();
        let err_code = indy_crypto_cl_proof_builder_finalize(proof_builder,
                                                             nonce,
                                                             master_secret,
                                                             &mut proof);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!proof.is_null());

        _free_credential_schema(credential_schema);
        _free_credential_values(credential_values);
        _free_sub_proof_request(sub_proof_request);

        proof
    }

    pub fn _free_proof(proof: *const c_void) {
        let err_code = indy_crypto_cl_proof_free(proof);
        assert_eq!(err_code, ErrorCode::Success);
    }
}