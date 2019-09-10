use cl::prover::*;
use cl::*;
use errors::prelude::*;
use ffi::ErrorCode;
use utils::ctypes::*;

use serde_json;
use std::os::raw::{c_char, c_void};

/// Creates a master secret.
///
/// Note that master secret deallocation must be performed by
/// calling ursa_cl_master_secret_free.
///
/// # Arguments
/// * `master_secret_p` - Reference that will contain master secret instance pointer.
#[no_mangle]
pub extern "C" fn ursa_cl_prover_new_master_secret(
    master_secret_p: *mut *const c_void,
) -> ErrorCode {
    trace!(
        "ursa_cl_prover_new_master_secret: >>> {:?}",
        master_secret_p
    );

    check_useful_c_ptr!(master_secret_p, ErrorCode::CommonInvalidParam1);

    let res = match Prover::new_master_secret() {
        Ok(master_secret) => {
            trace!(
                "ursa_cl_prover_new_master_secret: master_secret: {:?}",
                master_secret
            );
            unsafe {
                *master_secret_p = Box::into_raw(Box::new(master_secret)) as *const c_void;
                trace!(
                    "ursa_cl_prover_new_master_secret: *master_secret_p: {:?}",
                    *master_secret_p
                );
            }
            ErrorCode::Success
        }
        Err(err) => err.into(),
    };

    trace!("ursa_cl_prover_new_master_secret: <<< res: {:?}", res);
    res
}

/// Returns json representation of master secret.
///
/// # Arguments
/// * `master_secret` - Reference that contains master secret instance pointer.
/// * `master_secret_json_p` - Reference that will contain master secret json.
#[no_mangle]
pub extern "C" fn ursa_cl_master_secret_to_json(
    master_secret: *const c_void,
    master_secret_json_p: *mut *const c_char,
) -> ErrorCode {
    trace!(
        "ursa_cl_master_secret_to_json: >>> master_secret: {:?}, master_secret_json_p: {:?}",
        master_secret,
        master_secret_json_p
    );

    check_useful_c_reference!(master_secret, MasterSecret, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(master_secret_json_p, ErrorCode::CommonInvalidParam2);

    trace!(
        "ursa_cl_master_secret_to_json: entity >>> master_secret: {:?}",
        master_secret
    );

    let res = match serde_json::to_string(master_secret) {
        Ok(master_secret_json) => {
            trace!(
                "ursa_cl_master_secret_to_json: master_secret_json: {:?}",
                master_secret_json
            );
            unsafe {
                let master_secret_json = string_to_cstring(master_secret_json);
                *master_secret_json_p = master_secret_json.into_raw();
                trace!(
                    "ursa_cl_master_secret_to_json: master_secret_json_p: {:?}",
                    *master_secret_json_p
                );
            }
            ErrorCode::Success
        }
        Err(err) => err
            .to_ursa(
                UrsaCryptoErrorKind::InvalidState,
                "Unable to serialize master secret as json",
            )
            .into(),
    };

    trace!("ursa_cl_master_secret_to_json: <<< res: {:?}", res);
    res
}

/// Creates and returns master secret from json.
///
/// Note: Master secret instance deallocation must be performed
/// by calling ursa_cl_master_secret_free.
///
/// # Arguments
/// * `master_secret_json` - Reference that contains master secret json.
/// * `master_secret_p` - Reference that will contain master secret instance pointer.
#[no_mangle]
pub extern "C" fn ursa_cl_master_secret_from_json(
    master_secret_json: *const c_char,
    master_secret_p: *mut *const c_void,
) -> ErrorCode {
    trace!(
        "ursa_cl_master_secret_from_json: >>> master_secret_json: {:?}, master_secret_p: {:?}",
        master_secret_json,
        master_secret_p
    );

    check_useful_c_str!(master_secret_json, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(master_secret_p, ErrorCode::CommonInvalidParam2);

    trace!(
        "ursa_cl_master_secret_from_json: entity: master_secret_json: {:?}",
        master_secret_json
    );

    let res = match serde_json::from_str::<MasterSecret>(&master_secret_json) {
        Ok(master_secret) => {
            trace!(
                "ursa_cl_master_secret_from_json: master_secret: {:?}",
                master_secret
            );
            unsafe {
                *master_secret_p = Box::into_raw(Box::new(master_secret)) as *const c_void;
                trace!(
                    "ursa_cl_master_secret_from_json: *master_secret_p: {:?}",
                    *master_secret_p
                );
            }
            ErrorCode::Success
        }
        Err(err) => err
            .to_ursa(
                UrsaCryptoErrorKind::InvalidStructure,
                "Unable to deserialize master secret from json",
            )
            .into(),
    };

    trace!("ursa_cl_master_secret_from_json: <<< res: {:?}", res);
    res
}

/// Deallocates master secret instance.
///
/// # Arguments
/// * `master_secret` - Reference that contains master secret instance pointer.
#[no_mangle]
pub extern "C" fn ursa_cl_master_secret_free(master_secret: *const c_void) -> ErrorCode {
    trace!(
        "ursa_cl_master_secret_free: >>> master_secret: {:?}",
        master_secret
    );

    check_useful_c_ptr!(master_secret, ErrorCode::CommonInvalidParam1);

    let master_secret = unsafe { Box::from_raw(master_secret as *mut MasterSecret) };
    trace!(
        "ursa_cl_master_secret_free: entity: master_secret: {:?}",
        master_secret
    );

    let res = ErrorCode::Success;
    trace!("ursa_cl_master_secret_free: <<< res: {:?}", res);

    res
}

/// Creates blinded credential secrets for given issuer key and master secret.
///
/// Note that blinded credential secrets deallocation must be performed by
/// calling ursa_cl_blinded_credential_secrets_free.
///
/// Note that credential secrets blinding factors deallocation must be performed by
/// calling ursa_cl_credential_secrets_blinding_factors_free.
///
/// Note that blinded credential secrets correctness proof deallocation must be performed by
/// calling ursa_cl_blinded_credential_secrets_correctness_proof_free.
///
/// # Arguments
/// * `credential_pub_key` - Reference that contains credential public key instance pointer.
/// * `credential_key_correctness_proof` - Reference that contains credential key correctness proof instance pointer.
/// * `credential_values` - Reference that contains credential values pointer.
/// * `credential_nonce` - Reference that contains nonce instance pointer.
/// * `blinded_credential_secrets_p` - Reference that will contain blinded credential secrets instance pointer.
/// * `credential_secrets_blinding_factors_p` - Reference that will contain credential secrets blinding factors instance pointer.
/// * `blinded_credential_secrets_correctness_proof_p` - Reference that will contain blinded credential secrets correctness proof instance pointer.
#[no_mangle]
pub extern "C" fn ursa_cl_prover_blind_credential_secrets(
    credential_pub_key: *const c_void,
    credential_key_correctness_proof: *const c_void,
    credential_values: *const c_void,
    credential_nonce: *const c_void,
    blinded_credential_secrets_p: *mut *const c_void,
    credential_secrets_blinding_factors_p: *mut *const c_void,
    blinded_credential_secrets_correctness_proof_p: *mut *const c_void,
) -> ErrorCode {
    trace!(
        "ursa_cl_prover_blind_credential_secrets: >>> credential_pub_key: {:?}, \
         credential_key_correctness_proof: {:?}, \
         credential_values: {:?}, \
         credential_nonce: {:?}, \
         blinded_credential_secrets_p: {:?}, \
         credential_secrets_blinding_factors_p: {:?}, \
         blinded_credential_secrets_correctness_proof_p: {:?}",
        credential_pub_key,
        credential_key_correctness_proof,
        credential_values,
        credential_nonce,
        blinded_credential_secrets_p,
        credential_secrets_blinding_factors_p,
        blinded_credential_secrets_correctness_proof_p
    );

    check_useful_c_reference!(
        credential_pub_key,
        CredentialPublicKey,
        ErrorCode::CommonInvalidParam1
    );
    check_useful_c_reference!(
        credential_key_correctness_proof,
        CredentialKeyCorrectnessProof,
        ErrorCode::CommonInvalidParam2
    );
    check_useful_c_reference!(
        credential_values,
        CredentialValues,
        ErrorCode::CommonInvalidParam3
    );
    check_useful_c_reference!(credential_nonce, Nonce, ErrorCode::CommonInvalidParam4);
    check_useful_c_ptr!(blinded_credential_secrets_p, ErrorCode::CommonInvalidParam5);
    check_useful_c_ptr!(
        credential_secrets_blinding_factors_p,
        ErrorCode::CommonInvalidParam6
    );
    check_useful_c_ptr!(
        blinded_credential_secrets_correctness_proof_p,
        ErrorCode::CommonInvalidParam7
    );

    trace!(
        "ursa_cl_prover_blind_credential_secrets: inputs: credential_pub_key: {:?}, \
         credential_key_correctness_proof: {:?}, \
         credential_values: {:?}, \
         credential_nonce: {:?}",
        credential_pub_key,
        credential_key_correctness_proof,
        credential_values,
        credential_nonce
    );

    let res = match Prover::blind_credential_secrets(
        credential_pub_key,
        credential_key_correctness_proof,
        credential_values,
        credential_nonce,
    ) {
        Ok((
            blinded_credential_secrets,
            credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof,
        )) => {
            trace!(
                "ursa_cl_prover_blind_credential_secrets: blinded_credential_secrets: {:?}, \
                 credential_secrets_blinding_factors: {:?}, \
                 blinded_credential_secrets_correctness_proof: {:?}",
                blinded_credential_secrets,
                credential_secrets_blinding_factors,
                blinded_credential_secrets_correctness_proof
            );
            unsafe {
                *blinded_credential_secrets_p =
                    Box::into_raw(Box::new(blinded_credential_secrets)) as *const c_void;
                *credential_secrets_blinding_factors_p =
                    Box::into_raw(Box::new(credential_secrets_blinding_factors)) as *const c_void;
                *blinded_credential_secrets_correctness_proof_p =
                    Box::into_raw(Box::new(blinded_credential_secrets_correctness_proof))
                        as *const c_void;
                trace!("ursa_cl_prover_blind_credential_secrets: *blinded_credential_secrets_p: {:?}, \
                                                                        *credential_secrets_blinding_factors_p: {:?}, \
                                                                        *blinded_credential_secrets_correctness_proof_p: {:?}",
                                                                        *blinded_credential_secrets_p,
                                                                        *credential_secrets_blinding_factors_p,
                                                                        *blinded_credential_secrets_correctness_proof_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.into(),
    };

    trace!(
        "ursa_cl_prover_blind_credential_secrets: <<< res: {:?}",
        res
    );
    res
}

/// Returns json representation of blinded credential secrets.
///
/// # Arguments
/// * `blinded_credential_secrets` - Reference that contains Blinded credential secrets pointer.
/// * `blinded_credential_secrets_json_p` - Reference that will contain blinded credential secrets json.
#[no_mangle]
pub extern "C" fn ursa_cl_blinded_credential_secrets_to_json(
    blinded_credential_secrets: *const c_void,
    blinded_credential_secrets_json_p: *mut *const c_char,
) -> ErrorCode {
    trace!(
        "ursa_cl_blinded_credential_secrets_to_json: >>> blinded_credential_secrets: {:?}\n\
         blinded_credential_secrets_json_p: {:?}",
        blinded_credential_secrets,
        blinded_credential_secrets_json_p
    );

    check_useful_c_reference!(
        blinded_credential_secrets,
        BlindedCredentialSecrets,
        ErrorCode::CommonInvalidParam1
    );
    check_useful_c_ptr!(
        blinded_credential_secrets_json_p,
        ErrorCode::CommonInvalidParam2
    );

    trace!(
        "ursa_cl_blinded_credential_secrets_to_json: entity >>> blinded_credential_secrets: {:?}",
        blinded_credential_secrets
    );

    let res = match serde_json::to_string(blinded_credential_secrets) {
        Ok(blinded_credential_secrets_json) => {
            trace!(
                "ursa_cl_blinded_credential_secrets_to_json: blinded_credential_secrets_json: {:?}",
                blinded_credential_secrets_json
            );
            unsafe {
                let blinded_credential_secrets_json =
                    string_to_cstring(blinded_credential_secrets_json);
                *blinded_credential_secrets_json_p = blinded_credential_secrets_json.into_raw();

                trace!("ursa_cl_blinded_credential_secrets_to_json: blinded_credential_secrets_json_p: {:?}", *blinded_credential_secrets_json_p);
            }
            ErrorCode::Success
        }
        Err(err) => err
            .to_ursa(
                UrsaCryptoErrorKind::InvalidState,
                "Unable to serialize blinded credential secret as json",
            )
            .into(),
    };

    trace!(
        "ursa_cl_blinded_credential_secrets_to_json: <<< res: {:?}",
        res
    );
    res
}

/// Creates and returns blinded credential secrets from json.
///
/// Note: Blinded credential secrets instance deallocation must be performed
/// by calling ursa_cl_blinded_credential_secrets_free
///
/// # Arguments
/// * `blinded_credential_secrets_json` - Reference that contains blinded credential secret json.
/// * `blinded_credential_secrets_p` - Reference that will contain blinded credential secret instance pointer.
#[no_mangle]
pub extern "C" fn ursa_cl_blinded_credential_secrets_from_json(
    blinded_credential_secrets_json: *const c_char,
    blinded_credential_secrets_p: *mut *const c_void,
) -> ErrorCode {
    trace!("ursa_cl_blinded_credential_secrets_from_json: >>> blinded_credential_secrets_json: {:?}, blinded_credential_secrets_p: {:?}", blinded_credential_secrets_json, blinded_credential_secrets_p);

    check_useful_c_str!(
        blinded_credential_secrets_json,
        ErrorCode::CommonInvalidParam1
    );
    check_useful_c_ptr!(blinded_credential_secrets_p, ErrorCode::CommonInvalidParam2);

    trace!("ursa_cl_blinded_credential_secrets_from_json: entity: blinded_credential_secrets_json: {:?}", blinded_credential_secrets_json);

    let res = match serde_json::from_str::<BlindedCredentialSecrets>(
        &blinded_credential_secrets_json,
    ) {
        Ok(blinded_credential_secrets) => {
            trace!(
                "ursa_cl_blinded_credential_secrets_from_json: blinded_credential_secrets: {:?}",
                blinded_credential_secrets
            );
            unsafe {
                *blinded_credential_secrets_p =
                    Box::into_raw(Box::new(blinded_credential_secrets)) as *const c_void;
                trace!("ursa_cl_blinded_credential_secrets_from_json: *blinded_credential_secrets_p: {:?}", *blinded_credential_secrets_p);
            }
            ErrorCode::Success
        }
        Err(err) => err
            .to_ursa(
                UrsaCryptoErrorKind::InvalidStructure,
                "Unable to deserialize blinded credential secret from json",
            )
            .into(),
    };

    trace!(
        "ursa_cl_blinded_credential_secrets_from_json: <<< res: {:?}",
        res
    );
    res
}

/// Deallocates  blinded credential secrets instance.
///
/// # Arguments
/// * `blinded_credential_secrets` - Reference that contains blinded credential secrets instance pointer.
#[no_mangle]
pub extern "C" fn ursa_cl_blinded_credential_secrets_free(
    blinded_credential_secrets: *const c_void,
) -> ErrorCode {
    trace!(
        "ursa_cl_blinded_credential_secrets_free: >>> blinded_credential_secrets: {:?}",
        blinded_credential_secrets
    );

    check_useful_c_ptr!(blinded_credential_secrets, ErrorCode::CommonInvalidParam1);

    let blinded_credential_secrets =
        unsafe { Box::from_raw(blinded_credential_secrets as *mut BlindedCredentialSecrets) };
    trace!(
        "ursa_cl_blinded_credential_secrets_free: entity: blinded_credential_secrets: {:?}",
        blinded_credential_secrets
    );

    let res = ErrorCode::Success;

    trace!(
        "ursa_cl_blinded_credential_secrets_free: <<< res: {:?}",
        res
    );
    res
}

/// Returns json representation of credential secrets blinding factors.
///
/// # Arguments
/// * `credential_secrets_blinding_factors` - Reference that contains credential secrets blinding factors pointer.
/// * `credential_secrets_blinding_factors_json_p` - Reference that will contain credential secrets blinding factors json.
#[no_mangle]
pub extern "C" fn ursa_cl_credential_secrets_blinding_factors_to_json(
    credential_secrets_blinding_factors: *const c_void,
    credential_secrets_blinding_factors_json_p: *mut *const c_char,
) -> ErrorCode {
    trace!("ursa_cl_credential_secret_blinding_factors_to_json: >>> credential_secrets_blinding_factors: {:?}\n\
                                                                           credential_secrets_blinding_factors_json_p: {:?}", credential_secrets_blinding_factors, credential_secrets_blinding_factors_json_p);

    check_useful_c_reference!(
        credential_secrets_blinding_factors,
        CredentialSecretsBlindingFactors,
        ErrorCode::CommonInvalidParam1
    );
    check_useful_c_ptr!(
        credential_secrets_blinding_factors_json_p,
        ErrorCode::CommonInvalidParam2
    );

    trace!("ursa_cl_credential_secret_blinding_factors_to_json: entity >>> credential_secrets_blinding_factors: {:?}", credential_secrets_blinding_factors);

    let res = match serde_json::to_string(credential_secrets_blinding_factors) {
        Ok(credential_secrets_blinding_factors_json) => {
            trace!("ursa_cl_credential_secret_blinding_factors_to_json: credential_secrets_blinding_factors_json: {:?}", credential_secrets_blinding_factors_json);
            unsafe {
                let credential_secrets_blinding_factors_json =
                    string_to_cstring(credential_secrets_blinding_factors_json);
                *credential_secrets_blinding_factors_json_p =
                    credential_secrets_blinding_factors_json.into_raw();
                trace!("ursa_cl_credential_secret_blinding_factors_to_json: credential_secrets_blinding_factors_json_p: {:?}", *credential_secrets_blinding_factors_json_p);
            }
            ErrorCode::Success
        }
        Err(err) => err
            .to_ursa(
                UrsaCryptoErrorKind::InvalidState,
                "Unable to serialize blinded credential secret factors as json",
            )
            .into(),
    };

    trace!(
        "ursa_cl_credential_secret_blinding_factors_to_json: <<< res: {:?}",
        res
    );
    res
}

/// Creates and returns credential secrets blinding factors json.
///
/// Note: Credential secrets blinding factors instance deallocation must be performed
/// by calling ursa_cl_credential_secrets_blinding_factors_free.
///
/// # Arguments
/// * `credential_secrets_blinding_factors_json` - Reference that contains credential secrets blinding factors json.
/// * `credential_secrets_blinding_factors_p` - Reference that will contain credential secrets blinding factors instance pointer.
#[no_mangle]
pub extern "C" fn ursa_cl_credential_secrets_blinding_factors_from_json(
    credential_secrets_blinding_factors_json: *const c_char,
    credential_secrets_blinding_factors_p: *mut *const c_void,
) -> ErrorCode {
    trace!("ursa_cl_credential_secrets_blinding_factors_from_json: >>> credential_secrets_blinding_factors_json: {:?}\n\
                                                                              credential_secrets_blinding_factors_p: {:?}", credential_secrets_blinding_factors_json, credential_secrets_blinding_factors_p);

    check_useful_c_str!(
        credential_secrets_blinding_factors_json,
        ErrorCode::CommonInvalidParam1
    );
    check_useful_c_ptr!(
        credential_secrets_blinding_factors_p,
        ErrorCode::CommonInvalidParam2
    );

    trace!("ursa_cl_credential_secrets_blinding_factors_from_json: entity: credential_secrets_blinding_factors_json: {:?}", credential_secrets_blinding_factors_json);

    let res = match serde_json::from_str::<CredentialSecretsBlindingFactors>(
        &credential_secrets_blinding_factors_json,
    ) {
        Ok(credential_secrets_blinding_factors) => {
            trace!("ursa_cl_credential_secrets_blinding_factors_from_json: credential_secrets_blinding_factors: {:?}", credential_secrets_blinding_factors);
            unsafe {
                *credential_secrets_blinding_factors_p =
                    Box::into_raw(Box::new(credential_secrets_blinding_factors)) as *const c_void;
                trace!("ursa_cl_credential_secrets_blinding_factors_from_json: *credential_secrets_blinding_factors_p: {:?}", *credential_secrets_blinding_factors_p);
            }
            ErrorCode::Success
        }
        Err(err) => err
            .to_ursa(
                UrsaCryptoErrorKind::InvalidStructure,
                "Unable to deserialize blinded credential secret factors from json",
            )
            .into(),
    };

    trace!(
        "ursa_cl_credential_secrets_blinding_factors_from_json: <<< res: {:?}",
        res
    );
    res
}

/// Deallocates credential secrets blinding factors instance.
///
/// # Arguments
/// * `credential_secrets_blinding_factors` - Reference that contains credential secrets blinding factors instance pointer.
#[no_mangle]
pub extern "C" fn ursa_cl_credential_secrets_blinding_factors_free(
    credential_secrets_blinding_factors: *const c_void,
) -> ErrorCode {
    trace!("ursa_cl_credential_secrets_blinding_factors_free: >>> credential_secrets_blinding_factors: {:?}", credential_secrets_blinding_factors);

    check_useful_c_ptr!(
        credential_secrets_blinding_factors,
        ErrorCode::CommonInvalidParam1
    );

    let credential_secrets_blinding_factors = unsafe {
        Box::from_raw(credential_secrets_blinding_factors as *mut CredentialSecretsBlindingFactors)
    };
    trace!("ursa_cl_credential_secrets_blinding_factors_free: entity: credential_secrets_blinding_factors: {:?}", credential_secrets_blinding_factors);

    let res = ErrorCode::Success;

    trace!(
        "ursa_cl_credential_secrets_blinding_factors_free: <<< res: {:?}",
        res
    );
    res
}

/// Returns json representation of blinded credential secrets correctness proof.
///
/// # Arguments
/// * `blinded_credential_secrets_correctness_proof` - Reference that contains blinded credential secrets correctness proof pointer.
/// * `blinded_credential_secrets_correctness_proof_json_p` - Reference that will contain blinded credential secrets correctness proof json.
#[no_mangle]
pub extern "C" fn ursa_cl_blinded_credential_secrets_correctness_proof_to_json(
    blinded_credential_secrets_correctness_proof: *const c_void,
    blinded_credential_secrets_correctness_proof_json_p: *mut *const c_char,
) -> ErrorCode {
    trace!("ursa_cl_blinded_credential_secrets_correctness_proof_to_json: >>> blinded_credential_secrets_correctness_proof: {:?}\n\
                                                                                     blinded_credential_secrets_correctness_proof_json_p: {:?}", blinded_credential_secrets_correctness_proof, blinded_credential_secrets_correctness_proof_json_p);

    check_useful_c_reference!(
        blinded_credential_secrets_correctness_proof,
        BlindedCredentialSecretsCorrectnessProof,
        ErrorCode::CommonInvalidParam1
    );
    check_useful_c_ptr!(
        blinded_credential_secrets_correctness_proof_json_p,
        ErrorCode::CommonInvalidParam2
    );

    trace!("ursa_cl_blinded_credential_secrets_correctness_proof_to_json: entity >>> blinded_credential_secrets_correctness_proof: {:?}",
           blinded_credential_secrets_correctness_proof);

    let res = match serde_json::to_string(blinded_credential_secrets_correctness_proof) {
        Ok(blinded_credential_secrets_correctness_proof_json) => {
            trace!("ursa_cl_blinded_credential_secrets_correctness_proof_to_json: blinded_credential_secrets_correctness_proof: {:?}",
                   blinded_credential_secrets_correctness_proof_json);
            unsafe {
                let blinded_credential_secrets_correctness_proof_json =
                    string_to_cstring(blinded_credential_secrets_correctness_proof_json);
                *blinded_credential_secrets_correctness_proof_json_p =
                    blinded_credential_secrets_correctness_proof_json.into_raw();
                trace!("ursa_cl_blinded_credential_secrets_correctness_proof_to_json: blinded_credential_secrets_correctness_proof_json_p: {:?}",
                       *blinded_credential_secrets_correctness_proof_json_p);
            }
            ErrorCode::Success
        }
        Err(err) => err
            .to_ursa(
                UrsaCryptoErrorKind::InvalidState,
                "Unable to serialize blinded credential secrets correctness proof as json",
            )
            .into(),
    };

    trace!(
        "ursa_cl_blinded_credential_secrets_correctness_proof_to_json: <<< res: {:?}",
        res
    );
    res
}

/// Creates and returns blinded credential secrets correctness proof json.
///
/// Note: Blinded credential secrets correctness proof instance deallocation must be performed
/// by calling ursa_cl_blinded_credential_secrets_correctness_proof_free.
///
/// # Arguments
/// * `blinded_credential_secrets_correctness_proof_json` - Reference that contains blinded credential secrets correctness proof json.
/// * `blinded_credential_secrets_correctness_proof_p` - Reference that will contain blinded credential secret correctness proof instance pointer.
#[no_mangle]
pub extern "C" fn ursa_cl_blinded_credential_secrets_correctness_proof_from_json(
    blinded_credential_secrets_correctness_proof_json: *const c_char,
    blinded_credential_secrets_correctness_proof_p: *mut *const c_void,
) -> ErrorCode {
    trace!("ursa_cl_blinded_credential_secrets_correctness_proof_from_json: >>> blinded_credential_secrets_correctness_proof_json: {:?},\
     blinded_credential_secrets_correctness_proof_p: {:?}", blinded_credential_secrets_correctness_proof_json, blinded_credential_secrets_correctness_proof_p);

    check_useful_c_str!(
        blinded_credential_secrets_correctness_proof_json,
        ErrorCode::CommonInvalidParam1
    );
    check_useful_c_ptr!(
        blinded_credential_secrets_correctness_proof_p,
        ErrorCode::CommonInvalidParam2
    );

    trace!("ursa_cl_blinded_credential_secrets_correctness_proof_from_json: entity: blinded_credential_secrets_correctness_proof_json: {:?}",
           blinded_credential_secrets_correctness_proof_json);

    let res = match serde_json::from_str::<BlindedCredentialSecretsCorrectnessProof>(
        &blinded_credential_secrets_correctness_proof_json,
    ) {
        Ok(blinded_credential_secrets_correctness_proof) => {
            trace!("ursa_cl_blinded_credential_secrets_correctness_proof_from_json: blinded_credential_secrets_correctness_proof: {:?}",
                   blinded_credential_secrets_correctness_proof);
            unsafe {
                *blinded_credential_secrets_correctness_proof_p =
                    Box::into_raw(Box::new(blinded_credential_secrets_correctness_proof))
                        as *const c_void;
                trace!("ursa_cl_blinded_credential_secrets_correctness_proof_from_json: *blinded_credential_secrets_correctness_proof_p: {:?}",
                       *blinded_credential_secrets_correctness_proof_p);
            }
            ErrorCode::Success
        }
        Err(err) => err
            .to_ursa(
                UrsaCryptoErrorKind::InvalidStructure,
                "Unable to deserialize blinded credential secret correctness proof from json",
            )
            .into(),
    };

    trace!(
        "ursa_cl_blinded_credential_secrets_correctness_proof_from_json: <<< res: {:?}",
        res
    );
    res
}

/// Deallocates blinded credential secrets correctness proof instance.
///
/// # Arguments
/// * `blinded_credential_secrets_correctness_proof` - Reference that contains blinded credential secrets correctness proof instance pointer.
#[no_mangle]
pub extern "C" fn ursa_cl_blinded_credential_secrets_correctness_proof_free(
    blinded_credential_secrets_correctness_proof: *const c_void,
) -> ErrorCode {
    trace!("ursa_cl_blinded_credential_secrets_correctness_proof_free: >>> blinded_credential_secrets_correctness_proof: {:?}",
           blinded_credential_secrets_correctness_proof);

    check_useful_c_ptr!(
        blinded_credential_secrets_correctness_proof,
        ErrorCode::CommonInvalidParam1
    );

    let blinded_credential_secrets_correctness_proof = unsafe {
        Box::from_raw(
            blinded_credential_secrets_correctness_proof
                as *mut BlindedCredentialSecretsCorrectnessProof,
        )
    };
    trace!("ursa_cl_blinded_credential_secrets_correctness_proof_free: entity: blinded_credential_secrets_correctness_proof: {:?}", blinded_credential_secrets_correctness_proof);

    let res = ErrorCode::Success;

    trace!(
        "ursa_cl_blinded_credential_secrets_correctness_proof_free: <<< res: {:?}",
        res
    );
    res
}

/// Updates the credential signature by a credential secrets blinding factors.
///
/// # Arguments
/// * `credential_signature` - Credential signature instance pointer generated by Issuer.
/// * `credential_values` - Credential values instance pointer.
/// * `signature_correctness_proof` - Credential signature correctness proof instance pointer.
/// * `credential_secrets_blinding_factors` - Credential secrets blinding factors instance pointer.
/// * `credential_pub_key` - Credential public key instance pointer.
/// * `nonce` -  Nonce instance pointer was used by Issuer for the creation of signature_correctness_proof.
/// * `rev_key_pub` - (Optional) Revocation registry public key  instance pointer.
/// * `rev_reg` - (Optional) Revocation registry  instance pointer.
/// * `witness` - (Optional) Witness instance pointer.
#[no_mangle]
#[allow(unused_variables)]
pub extern "C" fn ursa_cl_prover_process_credential_signature(
    credential_signature: *const c_void,
    credential_values: *const c_void,
    signature_correctness_proof: *const c_void,
    credential_secrets_blinding_factors: *const c_void,
    credential_pub_key: *const c_void,
    credential_issuance_nonce: *const c_void,
    rev_key_pub: *const c_void,
    rev_reg: *const c_void,
    witness: *const c_void,
) -> ErrorCode {
    trace!(
        "ursa_cl_prover_process_credential_signature: >>> credential_signature: {:?}\n\
         signature_correctness_proof: {:?}\n\
         credential_secrets_blinding_factors: {:?}\n\
         credential_pub_key: {:?}\n\
         credential_issuance_nonce: {:?}\n\
         rev_key_pub: {:?}\n\
         rev_reg {:?}\n\
         witness {:?}",
        credential_signature,
        signature_correctness_proof,
        credential_secrets_blinding_factors,
        credential_pub_key,
        credential_issuance_nonce,
        rev_key_pub,
        rev_reg,
        witness
    );

    check_useful_mut_c_reference!(
        credential_signature,
        CredentialSignature,
        ErrorCode::CommonInvalidParam1
    );
    check_useful_c_reference!(
        credential_values,
        CredentialValues,
        ErrorCode::CommonInvalidParam2
    );
    check_useful_c_reference!(
        signature_correctness_proof,
        SignatureCorrectnessProof,
        ErrorCode::CommonInvalidParam3
    );
    check_useful_c_reference!(
        credential_secrets_blinding_factors,
        CredentialSecretsBlindingFactors,
        ErrorCode::CommonInvalidParam4
    );
    check_useful_c_reference!(
        credential_pub_key,
        CredentialPublicKey,
        ErrorCode::CommonInvalidParam5
    );
    check_useful_c_reference!(
        credential_issuance_nonce,
        Nonce,
        ErrorCode::CommonInvalidParam6
    );
    check_useful_opt_c_reference!(rev_key_pub, RevocationKeyPublic);
    check_useful_opt_c_reference!(rev_reg, RevocationRegistry);
    check_useful_opt_c_reference!(witness, Witness);

    trace!(
        "ursa_cl_prover_process_credential_signature: >>> credential_signature: {:?}\n\
         credential_values: {:?}\n\
         signature_correctness_proof: {:?}\n\
         credential_secrets_blinding_factors: {:?}\n\
         credential_pub_key: {:?}\n\
         credential_issuance_nonce: {:?}\n\
         rev_key_pub: {:?}\n\
         rev_reg {:?}, witness {:?}",
        credential_signature,
        credential_values,
        signature_correctness_proof,
        credential_secrets_blinding_factors,
        credential_pub_key,
        credential_issuance_nonce,
        rev_key_pub,
        rev_reg,
        witness
    );

    let res = match Prover::process_credential_signature(
        credential_signature,
        credential_values,
        signature_correctness_proof,
        credential_secrets_blinding_factors,
        credential_pub_key,
        credential_issuance_nonce,
        rev_key_pub,
        rev_reg,
        witness,
    ) {
        Ok(()) => ErrorCode::Success,
        Err(err) => err.into(),
    };

    trace!(
        "ursa_cl_prover_process_credential_signature: <<< res: {:?}",
        res
    );
    res
}

#[no_mangle]
#[allow(unused_variables)]
pub extern "C" fn ursa_cl_prover_get_credential_revocation_index(
    credential_signature: *const c_void,
    cred_rev_indx: *mut u32,
) -> ErrorCode {
    trace!("ursa_cl_prover_get_credential_revocation_index: >>> credential_signature: {:?}, cred_rev_indx: {:?}",
           credential_signature, cred_rev_indx);

    check_useful_c_reference!(
        credential_signature,
        CredentialSignature,
        ErrorCode::CommonInvalidParam1
    );

    trace!(
        "ursa_cl_prover_get_credential_revocation_index: >>> credential_signature: {:?}",
        credential_signature
    );

    let res = match credential_signature.extract_index() {
        Some(index) => {
            trace!(
                "ursa_cl_prover_get_credential_revocation_index: index: {:?}",
                index
            );
            unsafe {
                *cred_rev_indx = index;
            }
            trace!(
                "ursa_cl_prover_get_credential_revocation_index: *cred_rev_indx: {:?}",
                cred_rev_indx
            );
            ErrorCode::Success
        }
        None => err_msg(
            UrsaCryptoErrorKind::InvalidState,
            "Unable to extract credential revocation index",
        )
        .into(),
    };

    trace!(
        "ursa_cl_prover_get_credential_revocation_index: <<< res: {:?}",
        res
    );
    res
}

/// Creates and returns proof builder.
///
/// The purpose of proof builder is building of proof entity according to the given request .
///
/// Note that proof builder deallocation must be performed by
/// calling ursa_cl_proof_builder_finalize.
///
/// # Arguments
/// * `proof_builder_p` - Reference that will contain proof builder instance pointer.
#[no_mangle]
pub extern "C" fn ursa_cl_prover_new_proof_builder(
    proof_builder_p: *mut *const c_void,
) -> ErrorCode {
    trace!(
        "ursa_cl_prover_new_proof_builder: >>> {:?}",
        proof_builder_p
    );

    check_useful_c_ptr!(proof_builder_p, ErrorCode::CommonInvalidParam1);

    let res = match Prover::new_proof_builder() {
        Ok(proof_builder) => {
            trace!(
                "ursa_cl_prover_new_proof_builder: proof_builder: {:?}",
                proof_builder
            );
            unsafe {
                *proof_builder_p = Box::into_raw(Box::new(proof_builder)) as *const c_void;
                trace!(
                    "ursa_cl_prover_new_proof_builder: *proof_builder_p: {:?}",
                    *proof_builder_p
                );
            }
            ErrorCode::Success
        }
        Err(err) => err.into(),
    };

    trace!("ursa_cl_prover_new_proof_builder: <<< res: {:?}", res);
    res
}

/// Add a common attribute to the proof builder
///
/// # Arguments
/// * `proof_builder` - Reference that contain proof builder instance pointer.
/// * `attribute_name` - Common attribute's name

#[no_mangle]
pub extern "C" fn ursa_cl_proof_builder_add_common_attribute(
    proof_builder: *const c_void,
    attribute_name: *const c_char,
) -> ErrorCode {
    trace!(
        "ursa_cl_proof_builder_add_common_attribute: >>> proof_builder: {:?}, attribute_name: {:?}",
        proof_builder,
        attribute_name
    );

    check_useful_mut_c_reference!(proof_builder, ProofBuilder, ErrorCode::CommonInvalidParam1);
    check_useful_c_str!(attribute_name, ErrorCode::CommonInvalidParam2);

    trace!(
        "ursa_cl_proof_builder_add_common_attribute: entities: proof_builder: {:?}, attribute_name: {:?}",
        proof_builder,
        attribute_name
    );

    match proof_builder.add_common_attribute(&attribute_name) {
        Ok(()) => ErrorCode::Success,
        Err(err) => err.into(),
    }
}

/// Add a sub proof request to the proof builder
///
/// # Arguments
/// * `proof_builder` - Reference that contain proof builder instance pointer.
/// * `sub_proof_request` - Reference that contain sub proof request instance pointer.
/// * `credential_schema` - Reference that contains credential schema instance pointer.
/// * `non_credential_schema` - Reference that contains non credential schema instance pointer.
/// * `credential_signature` - Reference that contains the credential signature pointer.
/// * `credential_values` - Reference that contains credential values instance pointer.
/// * `credential_pub_key` - Reference that contains credential public key instance pointer.
/// * `rev_reg` - (Optional) Reference that will contain revocation registry public instance pointer.
/// * `witness` - (Optional) Reference that will contain witness instance pointer.
#[no_mangle]
pub extern "C" fn ursa_cl_proof_builder_add_sub_proof_request(
    proof_builder: *const c_void,
    sub_proof_request: *const c_void,
    credential_schema: *const c_void,
    non_credential_schema: *const c_void,
    credential_signature: *const c_void,
    credential_values: *const c_void,
    credential_pub_key: *const c_void,
    rev_reg: *const c_void,
    witness: *const c_void,
) -> ErrorCode {
    trace!(
        "ursa_cl_proof_builder_add_sub_proof_request: >>> proof_builder: {:?}, \
         sub_proof_request: {:?}, \
         credential_schema: {:?}, \
         non_credential_schema: {:?}, \
         credential_signature: {:?}, \
         credential_values: {:?}, \
         credential_pub_key: {:?}, \
         rev_reg: {:?}, \
         witness: {:?}",
        proof_builder,
        sub_proof_request,
        credential_schema,
        non_credential_schema,
        credential_signature,
        credential_values,
        credential_pub_key,
        rev_reg,
        witness
    );

    check_useful_mut_c_reference!(proof_builder, ProofBuilder, ErrorCode::CommonInvalidParam1);
    check_useful_c_reference!(
        sub_proof_request,
        SubProofRequest,
        ErrorCode::CommonInvalidParam2
    );
    check_useful_c_reference!(
        credential_schema,
        CredentialSchema,
        ErrorCode::CommonInvalidParam3
    );
    check_useful_c_reference!(
        non_credential_schema,
        NonCredentialSchema,
        ErrorCode::CommonInvalidParam4
    );
    check_useful_c_reference!(
        credential_signature,
        CredentialSignature,
        ErrorCode::CommonInvalidParam5
    );
    check_useful_c_reference!(
        credential_values,
        CredentialValues,
        ErrorCode::CommonInvalidParam6
    );
    check_useful_c_reference!(
        credential_pub_key,
        CredentialPublicKey,
        ErrorCode::CommonInvalidParam7
    );
    check_useful_opt_c_reference!(rev_reg, RevocationRegistry);
    check_useful_opt_c_reference!(witness, Witness);

    trace!(
        "ursa_cl_proof_builder_add_sub_proof_request: entities: proof_builder: {:?}, \
         sub_proof_request: {:?}, \
         credential_schema: {:?}, \
         non_credential_schema: {:?}, \
         credential_signature: {:?}, \
         credential_values: {:?}, \
         credential_pub_key: {:?}, \
         rev_reg: {:?}, \
         witness: {:?}",
        proof_builder,
        sub_proof_request,
        credential_schema,
        non_credential_schema,
        credential_signature,
        credential_values,
        credential_pub_key,
        rev_reg,
        witness
    );

    let res = match proof_builder.add_sub_proof_request(
        sub_proof_request,
        credential_schema,
        non_credential_schema,
        credential_signature,
        credential_values,
        credential_pub_key,
        rev_reg,
        witness,
    ) {
        Ok(()) => ErrorCode::Success,
        Err(err) => err.into(),
    };

    trace!(
        "ursa_cl_proof_builder_add_sub_proof_request: <<< res: {:?}",
        res
    );
    res
}

/// Finalize proof.
///
/// Note that proof deallocation must be performed by
/// calling ursa_cl_proof_free.
///
/// # Arguments
/// * `proof_builder` - Reference that contain proof builder instance pointer.
/// * `nonce` - Reference that contain nonce instance pointer.
/// * `proof_p` - Reference that will contain proof instance pointer.
#[no_mangle]
pub extern "C" fn ursa_cl_proof_builder_finalize(
    proof_builder: *const c_void,
    nonce: *const c_void,
    proof_p: *mut *const c_void,
) -> ErrorCode {
    trace!(
        "ursa_cl_proof_builder_finalize: >>> proof_builder: {:?}, nonce: {:?}, proof_p: {:?}",
        proof_builder,
        nonce,
        proof_p
    );

    check_useful_c_ptr!(proof_builder, ErrorCode::CommonInvalidParam1);
    check_useful_c_reference!(nonce, Nonce, ErrorCode::CommonInvalidParam2);
    check_useful_c_ptr!(proof_p, ErrorCode::CommonInvalidParam3);

    let proof_builder = unsafe { Box::from_raw(proof_builder as *mut ProofBuilder) };

    trace!(
        "ursa_cl_proof_builder_finalize: entities: proof_builder: {:?}, nonce: {:?}",
        proof_builder,
        nonce
    );

    let res = match proof_builder.finalize(nonce) {
        Ok(proof) => {
            trace!("ursa_cl_proof_builder_finalize: proof: {:?}", proof);
            unsafe {
                *proof_p = Box::into_raw(Box::new(proof)) as *const c_void;
                trace!("ursa_cl_proof_builder_finalize: *proof_p: {:?}", *proof_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.into(),
    };

    trace!("ursa_cl_proof_builder_finalize: <<< res: {:?}", res);
    res
}

/// Returns json representation of proof.
///
/// # Arguments
/// * `proof` - Reference that contains proof instance pointer.
/// * `proof_json_p` - Reference that will contain proof json.
#[no_mangle]
pub extern "C" fn ursa_cl_proof_to_json(
    proof: *const c_void,
    proof_json_p: *mut *const c_char,
) -> ErrorCode {
    trace!(
        "ursa_cl_proof_to_json: >>> proof: {:?}, proof_json_p: {:?}",
        proof,
        proof_json_p
    );

    check_useful_c_reference!(proof, Proof, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(proof_json_p, ErrorCode::CommonInvalidParam2);

    trace!("ursa_cl_proof_to_json: entity >>> proof: {:?}", proof);

    let res = match serde_json::to_string(proof) {
        Ok(proof_json) => {
            trace!("ursa_cl_proof_to_json: proof_json: {:?}", proof_json);
            unsafe {
                let proof_json = string_to_cstring(proof_json);
                *proof_json_p = proof_json.into_raw();
                trace!("ursa_cl_proof_to_json: proof_json_p: {:?}", *proof_json_p);
            }
            ErrorCode::Success
        }
        Err(err) => err
            .to_ursa(
                UrsaCryptoErrorKind::InvalidState,
                "Unable to serialize proof as json",
            )
            .into(),
    };

    trace!("ursa_cl_proof_to_json: <<< res: {:?}", res);
    res
}

/// Creates and returns proof json.
///
/// Note: Proof instance deallocation must be performed by calling ursa_cl_proof_free.
///
/// # Arguments
/// * `proof_json` - Reference that contains proof json.
/// * `proof_p` - Reference that will contain proof instance pointer.
#[no_mangle]
pub extern "C" fn ursa_cl_proof_from_json(
    proof_json: *const c_char,
    proof_p: *mut *const c_void,
) -> ErrorCode {
    trace!(
        "ursa_cl_proof_from_json: >>> proof_json: {:?}, proof_p: {:?}",
        proof_json,
        proof_p
    );

    check_useful_c_str!(proof_json, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(proof_p, ErrorCode::CommonInvalidParam2);

    trace!(
        "ursa_cl_proof_from_json: entity: proof_json: {:?}",
        proof_json
    );

    let res = match serde_json::from_str::<Proof>(&proof_json) {
        Ok(proof) => {
            trace!("ursa_cl_proof_from_json: proof: {:?}", proof);
            unsafe {
                *proof_p = Box::into_raw(Box::new(proof)) as *const c_void;
                trace!("ursa_cl_proof_from_json: *proof_p: {:?}", *proof_p);
            }
            ErrorCode::Success
        }
        Err(err) => err
            .to_ursa(
                UrsaCryptoErrorKind::InvalidStructure,
                "Unable to deserialize proof from json",
            )
            .into(),
    };

    trace!("ursa_cl_proof_from_json: <<< res: {:?}", res);
    res
}

/// Deallocates proof instance.
///
/// # Arguments
/// * `proof` - Reference that contains proof instance pointer.
#[no_mangle]
pub extern "C" fn ursa_cl_proof_free(proof: *const c_void) -> ErrorCode {
    trace!("ursa_cl_proof_free: >>> proof: {:?}", proof);

    check_useful_c_ptr!(proof, ErrorCode::CommonInvalidParam1);

    let proof = unsafe { Box::from_raw(proof as *mut Proof) };
    trace!("ursa_cl_proof_free: entity: proof: {:?}", proof);

    let res = ErrorCode::Success;

    trace!("ursa_cl_proof_free: <<< res: {:?}", res);
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    use ffi::cl::issuer::mocks::*;
    use ffi::cl::mocks::*;
    use ffi::cl::prover::mocks::*;
    use std::ptr;

    // Master secret is now called link secret.
    pub static LINK_SECRET: &'static str = "master_secret";

    #[test]
    fn ursa_cl_prover_new_master_secret_works() {
        let mut master_secret_p: *const c_void = ptr::null();
        let err_code = ursa_cl_prover_new_master_secret(&mut master_secret_p);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!master_secret_p.is_null());

        _free_master_secret(master_secret_p)
    }

    #[test]
    fn ursa_cl_master_secret_to_json_works() {
        let master_secret = _master_secret();

        let mut master_secret_json_p: *const c_char = ptr::null();
        let err_code = ursa_cl_master_secret_to_json(master_secret, &mut master_secret_json_p);
        assert_eq!(err_code, ErrorCode::Success);

        _free_master_secret(master_secret)
    }

    #[test]
    fn ursa_cl_master_secret_from_json_works() {
        let master_secret = _master_secret();

        let mut master_secret_json_p: *const c_char = ptr::null();
        let err_code = ursa_cl_master_secret_to_json(master_secret, &mut master_secret_json_p);
        assert_eq!(err_code, ErrorCode::Success);

        let mut master_secret_p: *const c_void = ptr::null();
        let err_code = ursa_cl_master_secret_from_json(master_secret_json_p, &mut master_secret_p);
        assert_eq!(err_code, ErrorCode::Success);

        _free_master_secret(master_secret)
    }

    #[test]
    fn ursa_cl_prover_master_secret_free_works() {
        let master_secret = _master_secret();

        let err_code = ursa_cl_master_secret_free(master_secret);
        assert_eq!(err_code, ErrorCode::Success);
    }

    #[test]
    fn ursa_cl_prover_blind_credential_secrets_works() {
        let credential_values = _credential_values();
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
            _credential_def();
        let credential_nonce = _nonce();

        let mut blinded_credential_secrets_p: *const c_void = ptr::null();
        let mut credential_secrets_blinding_factors_p: *const c_void = ptr::null();
        let mut blinded_credential_secrets_correctness_proof_p: *const c_void = ptr::null();

        let err_code = ursa_cl_prover_blind_credential_secrets(
            credential_pub_key,
            credential_key_correctness_proof,
            credential_values,
            credential_nonce,
            &mut blinded_credential_secrets_p,
            &mut credential_secrets_blinding_factors_p,
            &mut blinded_credential_secrets_correctness_proof_p,
        );
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!blinded_credential_secrets_p.is_null());
        assert!(!credential_secrets_blinding_factors_p.is_null());

        _free_blinded_credential_secrets(
            blinded_credential_secrets_p,
            credential_secrets_blinding_factors_p,
            blinded_credential_secrets_correctness_proof_p,
        );
        _free_credential_values(credential_values);
        _free_credential_def(
            credential_pub_key,
            credential_priv_key,
            credential_key_correctness_proof,
        );
        _free_nonce(credential_nonce);
    }

    #[test]
    fn ursa_cl_prover_blinded_credential_secrets_free_works() {
        let credential_values = _credential_values();
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
            _credential_def();
        let credential_nonce = _nonce();
        let (
            blinded_credential_secrets,
            credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof,
        ) = _blinded_credential_secrets(
            credential_pub_key,
            credential_key_correctness_proof,
            credential_values,
            credential_nonce,
        );
        let err_code = ursa_cl_blinded_credential_secrets_free(blinded_credential_secrets);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code =
            ursa_cl_credential_secrets_blinding_factors_free(credential_secrets_blinding_factors);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_cl_blinded_credential_secrets_correctness_proof_free(
            blinded_credential_secrets_correctness_proof,
        );
        assert_eq!(err_code, ErrorCode::Success);

        _free_credential_def(
            credential_pub_key,
            credential_priv_key,
            credential_key_correctness_proof,
        );
        _free_credential_values(credential_values);
        _free_nonce(credential_nonce);
    }

    #[test]
    fn ursa_cl_prover_blinded_credential_secrets_to_json_works() {
        let credential_values = _credential_values();
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
            _credential_def();
        let credential_nonce = _nonce();
        let (
            blinded_credential_secrets,
            credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof,
        ) = _blinded_credential_secrets(
            credential_pub_key,
            credential_key_correctness_proof,
            credential_values,
            credential_nonce,
        );

        let mut blinded_credential_secrets_json_p: *const c_char = ptr::null();
        let err_code = ursa_cl_blinded_credential_secrets_to_json(
            blinded_credential_secrets,
            &mut blinded_credential_secrets_json_p,
        );
        assert_eq!(err_code, ErrorCode::Success);

        _free_credential_def(
            credential_pub_key,
            credential_priv_key,
            credential_key_correctness_proof,
        );
        _free_credential_values(credential_values);
        _free_nonce(credential_nonce);
        _free_blinded_credential_secrets(
            blinded_credential_secrets,
            credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof,
        );
    }

    #[test]
    fn ursa_cl_prover_proof_builder_add_common_attribute_works() {
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
            _credential_def();
        let credential_values = _credential_values();
        let credential_nonce = _nonce();
        let (
            blinded_credential_secrets,
            credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof,
        ) = _blinded_credential_secrets(
            credential_pub_key,
            credential_key_correctness_proof,
            credential_values,
            credential_nonce,
        );
        let sub_proof_request = _sub_proof_request();
        let credential_schema = _credential_schema();
        let non_credential_schema = _non_credential_schema();
        let credential_issuance_nonce = _nonce();
        let (credential_signature, signature_correctness_proof) = _credential_signature(
            blinded_credential_secrets,
            blinded_credential_secrets_correctness_proof,
            credential_nonce,
            credential_issuance_nonce,
            credential_values,
            credential_pub_key,
            credential_priv_key,
        );
        _process_credential_signature(
            credential_signature,
            signature_correctness_proof,
            credential_secrets_blinding_factors,
            credential_values,
            credential_pub_key,
            credential_issuance_nonce,
            ptr::null(),
            ptr::null(),
            ptr::null(),
        );
        let proof_builder = _proof_builder();

        let common_attr_name = string_to_cstring(String::from(LINK_SECRET));
        let err_code =
            ursa_cl_proof_builder_add_common_attribute(proof_builder, common_attr_name.as_ptr());
        assert_eq!(err_code, ErrorCode::Success);

        let nonce = _nonce();

        _free_proof_builder(proof_builder, nonce);
        _free_credential_def(
            credential_pub_key,
            credential_priv_key,
            credential_key_correctness_proof,
        );
        _free_blinded_credential_secrets(
            blinded_credential_secrets,
            credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof,
        );
        _free_nonce(credential_nonce);
        _free_nonce(credential_issuance_nonce);
        _free_credential_values(credential_values);
        _free_sub_proof_request(sub_proof_request);
        _free_credential_signature(credential_signature, signature_correctness_proof);
        _free_credential_schema(credential_schema);
        _free_non_credential_schema(non_credential_schema);
    }

    #[test]
    fn ursa_cl_prover_proof_builder_add_sub_proof_request_works() {
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
            _credential_def();
        let credential_values = _credential_values();
        let credential_nonce = _nonce();
        let (
            blinded_credential_secrets,
            credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof,
        ) = _blinded_credential_secrets(
            credential_pub_key,
            credential_key_correctness_proof,
            credential_values,
            credential_nonce,
        );
        let sub_proof_request = _sub_proof_request();
        let credential_schema = _credential_schema();
        let non_credential_schema = _non_credential_schema();
        let credential_issuance_nonce = _nonce();
        let (credential_signature, signature_correctness_proof) = _credential_signature(
            blinded_credential_secrets,
            blinded_credential_secrets_correctness_proof,
            credential_nonce,
            credential_issuance_nonce,
            credential_values,
            credential_pub_key,
            credential_priv_key,
        );
        _process_credential_signature(
            credential_signature,
            signature_correctness_proof,
            credential_secrets_blinding_factors,
            credential_values,
            credential_pub_key,
            credential_issuance_nonce,
            ptr::null(),
            ptr::null(),
            ptr::null(),
        );
        let proof_builder = _proof_builder();

        let err_code = ursa_cl_proof_builder_add_sub_proof_request(
            proof_builder,
            sub_proof_request,
            credential_schema,
            non_credential_schema,
            credential_signature,
            credential_values,
            credential_pub_key,
            ptr::null(),
            ptr::null(),
        );
        assert_eq!(err_code, ErrorCode::Success);

        let nonce = _nonce();

        _free_proof_builder(proof_builder, nonce);
        _free_credential_def(
            credential_pub_key,
            credential_priv_key,
            credential_key_correctness_proof,
        );
        _free_blinded_credential_secrets(
            blinded_credential_secrets,
            credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof,
        );
        _free_nonce(credential_nonce);
        _free_nonce(credential_issuance_nonce);
        _free_credential_values(credential_values);
        _free_sub_proof_request(sub_proof_request);
        _free_credential_signature(credential_signature, signature_correctness_proof);
        _free_credential_schema(credential_schema);
        _free_non_credential_schema(non_credential_schema);
    }

    #[test]
    fn ursa_cl_prover_blinded_credential_secrets_from_json_works() {
        let credential_values = _credential_values();
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
            _credential_def();
        let credential_nonce = _nonce();
        let (
            blinded_credential_secrets,
            credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof,
        ) = _blinded_credential_secrets(
            credential_pub_key,
            credential_key_correctness_proof,
            credential_values,
            credential_nonce,
        );

        let mut blinded_credential_secrets_json_p: *const c_char = ptr::null();
        let err_code = ursa_cl_blinded_credential_secrets_to_json(
            blinded_credential_secrets,
            &mut blinded_credential_secrets_json_p,
        );
        assert_eq!(err_code, ErrorCode::Success);

        let mut blinded_credential_secrets_p: *const c_void = ptr::null();
        let err_code = ursa_cl_blinded_credential_secrets_from_json(
            blinded_credential_secrets_json_p,
            &mut blinded_credential_secrets_p,
        );
        assert_eq!(err_code, ErrorCode::Success);

        _free_credential_def(
            credential_pub_key,
            credential_priv_key,
            credential_key_correctness_proof,
        );
        _free_credential_values(credential_values);
        _free_nonce(credential_nonce);
        _free_blinded_credential_secrets(
            blinded_credential_secrets,
            credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof,
        );
    }

    #[test]
    fn ursa_cl_prover_credential_secrets_blinding_factors_to_json_works() {
        let credential_values = _credential_values();
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
            _credential_def();
        let credential_nonce = _nonce();
        let (
            blinded_credential_secrets,
            credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof,
        ) = _blinded_credential_secrets(
            credential_pub_key,
            credential_key_correctness_proof,
            credential_values,
            credential_nonce,
        );

        let mut credential_secrets_blinding_factors_json_p: *const c_char = ptr::null();
        let err_code = ursa_cl_credential_secrets_blinding_factors_to_json(
            credential_secrets_blinding_factors,
            &mut credential_secrets_blinding_factors_json_p,
        );
        assert_eq!(err_code, ErrorCode::Success);

        _free_credential_def(
            credential_pub_key,
            credential_priv_key,
            credential_key_correctness_proof,
        );
        _free_credential_values(credential_values);
        _free_nonce(credential_nonce);
        _free_blinded_credential_secrets(
            blinded_credential_secrets,
            credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof,
        );
    }

    #[test]
    fn ursa_cl_prover_credential_secrets_blinding_factors_from_json_works() {
        let credential_values = _credential_values();
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
            _credential_def();
        let credential_nonce = _nonce();
        let (
            blinded_credential_secrets,
            credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof,
        ) = _blinded_credential_secrets(
            credential_pub_key,
            credential_key_correctness_proof,
            credential_values,
            credential_nonce,
        );

        let mut credential_secrets_blinding_factors_json_p: *const c_char = ptr::null();
        let err_code = ursa_cl_credential_secrets_blinding_factors_to_json(
            credential_secrets_blinding_factors,
            &mut credential_secrets_blinding_factors_json_p,
        );
        assert_eq!(err_code, ErrorCode::Success);

        let mut credential_secrets_blinding_factors_p: *const c_void = ptr::null();
        let err_code = ursa_cl_credential_secrets_blinding_factors_from_json(
            credential_secrets_blinding_factors_json_p,
            &mut credential_secrets_blinding_factors_p,
        );
        assert_eq!(err_code, ErrorCode::Success);

        _free_credential_def(
            credential_pub_key,
            credential_priv_key,
            credential_key_correctness_proof,
        );
        _free_credential_values(credential_values);
        _free_nonce(credential_nonce);
        _free_blinded_credential_secrets(
            blinded_credential_secrets,
            credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof,
        );
    }

    #[test]
    fn ursa_cl_prover_blinded_credential_secrets_correctness_proof_to_json_works() {
        let credential_values = _credential_values();
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
            _credential_def();
        let credential_nonce = _nonce();
        let (
            blinded_credential_secrets,
            credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof,
        ) = _blinded_credential_secrets(
            credential_pub_key,
            credential_key_correctness_proof,
            credential_values,
            credential_nonce,
        );

        let mut blinded_credential_secrets_correctness_proof_json_p: *const c_char = ptr::null();
        let err_code = ursa_cl_blinded_credential_secrets_correctness_proof_to_json(
            blinded_credential_secrets_correctness_proof,
            &mut blinded_credential_secrets_correctness_proof_json_p,
        );
        assert_eq!(err_code, ErrorCode::Success);

        _free_credential_def(
            credential_pub_key,
            credential_priv_key,
            credential_key_correctness_proof,
        );
        _free_credential_values(credential_values);
        _free_nonce(credential_nonce);
        _free_blinded_credential_secrets(
            blinded_credential_secrets,
            credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof,
        );
    }

    #[test]
    fn ursa_cl_prover_blinded_credential_secrets_correctness_proof_from_json_works() {
        let credential_values = _credential_values();
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
            _credential_def();
        let credential_nonce = _nonce();
        let (
            blinded_credential_secrets,
            credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof,
        ) = _blinded_credential_secrets(
            credential_pub_key,
            credential_key_correctness_proof,
            credential_values,
            credential_nonce,
        );

        let mut blinded_credential_secrets_correctness_proof_json_p: *const c_char = ptr::null();
        let err_code = ursa_cl_blinded_credential_secrets_correctness_proof_to_json(
            blinded_credential_secrets_correctness_proof,
            &mut blinded_credential_secrets_correctness_proof_json_p,
        );
        assert_eq!(err_code, ErrorCode::Success);

        let mut blinded_credential_secrets_correctness_proof_p: *const c_void = ptr::null();
        let err_code = ursa_cl_blinded_credential_secrets_correctness_proof_from_json(
            blinded_credential_secrets_correctness_proof_json_p,
            &mut blinded_credential_secrets_correctness_proof_p,
        );
        assert_eq!(err_code, ErrorCode::Success);

        _free_credential_def(
            credential_pub_key,
            credential_priv_key,
            credential_key_correctness_proof,
        );
        _free_credential_values(credential_values);
        _free_nonce(credential_nonce);
        _free_blinded_credential_secrets(
            blinded_credential_secrets,
            credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof,
        );
    }

    #[test]
    fn ursa_cl_prover_process_credential_signature_signature_works() {
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
            _credential_def();
        let credential_nonce = _nonce();
        let credential_values = _credential_values();
        let (
            blinded_credential_secrets,
            credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof,
        ) = _blinded_credential_secrets(
            credential_pub_key,
            credential_key_correctness_proof,
            credential_values,
            credential_nonce,
        );

        let credential_issuance_nonce = _nonce();
        let (credential_signature, signature_correctness_proof) = _credential_signature(
            blinded_credential_secrets,
            blinded_credential_secrets_correctness_proof,
            credential_nonce,
            credential_issuance_nonce,
            credential_values,
            credential_pub_key,
            credential_priv_key,
        );
        let err_code = ursa_cl_prover_process_credential_signature(
            credential_signature,
            credential_values,
            signature_correctness_proof,
            credential_secrets_blinding_factors,
            credential_pub_key,
            credential_issuance_nonce,
            ptr::null(),
            ptr::null(),
            ptr::null(),
        );
        assert_eq!(err_code, ErrorCode::Success);

        _free_credential_def(
            credential_pub_key,
            credential_priv_key,
            credential_key_correctness_proof,
        );
        _free_blinded_credential_secrets(
            blinded_credential_secrets,
            credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof,
        );
        _free_credential_values(credential_values);
        _free_nonce(credential_nonce);
        _free_nonce(credential_issuance_nonce);
        _free_credential_signature(credential_signature, signature_correctness_proof);
    }

    #[test]
    fn ursa_cl_prover_proof_builder_new_works() {
        let mut proof_builder: *const c_void = ptr::null();
        let err_code = ursa_cl_prover_new_proof_builder(&mut proof_builder);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!proof_builder.is_null());

        let nonce = _nonce();

        _free_proof_builder(proof_builder, nonce);
    }

    #[test]
    fn ursa_cl_prover_proof_builder_finalize_works() {
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
            _credential_def();
        let credential_nonce = _nonce();
        let credential_values = _credential_values();
        let (
            blinded_credential_secrets,
            credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof,
        ) = _blinded_credential_secrets(
            credential_pub_key,
            credential_key_correctness_proof,
            credential_values,
            credential_nonce,
        );

        let sub_proof_request = _sub_proof_request();
        let credential_schema = _credential_schema();
        let non_credential_schema = _non_credential_schema();
        let credential_issuance_nonce = _nonce();
        let (credential_signature, signature_correctness_proof) = _credential_signature(
            blinded_credential_secrets,
            blinded_credential_secrets_correctness_proof,
            credential_nonce,
            credential_issuance_nonce,
            credential_values,
            credential_pub_key,
            credential_priv_key,
        );
        _process_credential_signature(
            credential_signature,
            signature_correctness_proof,
            credential_secrets_blinding_factors,
            credential_values,
            credential_pub_key,
            credential_issuance_nonce,
            ptr::null(),
            ptr::null(),
            ptr::null(),
        );
        let proof_builder = _proof_builder();

        let err_code = ursa_cl_proof_builder_add_sub_proof_request(
            proof_builder,
            sub_proof_request,
            credential_schema,
            non_credential_schema,
            credential_signature,
            credential_values,
            credential_pub_key,
            ptr::null(),
            ptr::null(),
        );
        assert_eq!(err_code, ErrorCode::Success);

        let nonce = _nonce();

        let mut proof: *const c_void = ptr::null();
        let err_code = ursa_cl_proof_builder_finalize(proof_builder, nonce, &mut proof);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!proof.is_null());

        _free_credential_def(
            credential_pub_key,
            credential_priv_key,
            credential_key_correctness_proof,
        );
        _free_blinded_credential_secrets(
            blinded_credential_secrets,
            credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof,
        );
        _free_nonce(credential_nonce);
        _free_nonce(credential_issuance_nonce);
        _free_credential_values(credential_values);
        _free_sub_proof_request(sub_proof_request);
        _free_credential_signature(credential_signature, signature_correctness_proof);
        _free_proof(proof);
        _free_credential_schema(credential_schema);
        _free_non_credential_schema(non_credential_schema);
    }

    #[test]
    fn ursa_cl_proof_to_json_works() {
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
            _credential_def();
        let credential_values = _credential_values();
        let credential_nonce = _nonce();
        let (
            blinded_credential_secrets,
            credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof,
        ) = _blinded_credential_secrets(
            credential_pub_key,
            credential_key_correctness_proof,
            credential_values,
            credential_nonce,
        );
        let credential_issuance_nonce = _nonce();
        let (credential_signature, signature_correctness_proof) = _credential_signature(
            blinded_credential_secrets,
            blinded_credential_secrets_correctness_proof,
            credential_nonce,
            credential_issuance_nonce,
            credential_values,
            credential_pub_key,
            credential_priv_key,
        );
        _process_credential_signature(
            credential_signature,
            signature_correctness_proof,
            credential_secrets_blinding_factors,
            credential_values,
            credential_pub_key,
            credential_issuance_nonce,
            ptr::null(),
            ptr::null(),
            ptr::null(),
        );

        let proof_building_nonce = _nonce();
        let proof = _proof(
            credential_pub_key,
            credential_signature,
            proof_building_nonce,
            credential_values,
            ptr::null(),
            ptr::null(),
        );

        let mut proof_json_p: *const c_char = ptr::null();
        let err_code = ursa_cl_proof_to_json(proof, &mut proof_json_p);
        assert_eq!(err_code, ErrorCode::Success);

        _free_credential_def(
            credential_pub_key,
            credential_priv_key,
            credential_key_correctness_proof,
        );
        _free_blinded_credential_secrets(
            blinded_credential_secrets,
            credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof,
        );
        _free_nonce(credential_nonce);
        _free_nonce(credential_issuance_nonce);
        _free_nonce(proof_building_nonce);
        _free_credential_signature(credential_signature, signature_correctness_proof);
        _free_proof(proof);
    }

    #[test]
    fn ursa_cl_proof_from_json_works() {
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
            _credential_def();
        let credential_values = _credential_values();
        let credential_nonce = _nonce();
        let (
            blinded_credential_secrets,
            credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof,
        ) = _blinded_credential_secrets(
            credential_pub_key,
            credential_key_correctness_proof,
            credential_values,
            credential_nonce,
        );
        let credential_issuance_nonce = _nonce();
        let (credential_signature, signature_correctness_proof) = _credential_signature(
            blinded_credential_secrets,
            blinded_credential_secrets_correctness_proof,
            credential_nonce,
            credential_issuance_nonce,
            credential_values,
            credential_pub_key,
            credential_priv_key,
        );
        _process_credential_signature(
            credential_signature,
            signature_correctness_proof,
            credential_secrets_blinding_factors,
            credential_values,
            credential_pub_key,
            credential_issuance_nonce,
            ptr::null(),
            ptr::null(),
            ptr::null(),
        );

        let proof_building_nonce = _nonce();
        let proof = _proof(
            credential_pub_key,
            credential_signature,
            proof_building_nonce,
            credential_values,
            ptr::null(),
            ptr::null(),
        );

        let mut proof_json_p: *const c_char = ptr::null();
        let err_code = ursa_cl_proof_to_json(proof, &mut proof_json_p);
        assert_eq!(err_code, ErrorCode::Success);

        let mut proof_p: *const c_void = ptr::null();
        let err_code = ursa_cl_proof_from_json(proof_json_p, &mut proof_p);
        assert_eq!(err_code, ErrorCode::Success);

        _free_credential_def(
            credential_pub_key,
            credential_priv_key,
            credential_key_correctness_proof,
        );
        _free_blinded_credential_secrets(
            blinded_credential_secrets,
            credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof,
        );
        _free_nonce(credential_nonce);
        _free_nonce(credential_issuance_nonce);
        _free_nonce(proof_building_nonce);
        _free_credential_signature(credential_signature, signature_correctness_proof);
        _free_proof(proof);
    }

    #[test]
    fn ursa_cl_proof_free_works() {
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
            _credential_def();
        let credential_values = _credential_values();
        let credential_nonce = _nonce();
        let (
            blinded_credential_secrets,
            credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof,
        ) = _blinded_credential_secrets(
            credential_pub_key,
            credential_key_correctness_proof,
            credential_values,
            credential_nonce,
        );
        let credential_issuance_nonce = _nonce();
        let (credential_signature, signature_correctness_proof) = _credential_signature(
            blinded_credential_secrets,
            blinded_credential_secrets_correctness_proof,
            credential_nonce,
            credential_issuance_nonce,
            credential_values,
            credential_pub_key,
            credential_priv_key,
        );
        _process_credential_signature(
            credential_signature,
            signature_correctness_proof,
            credential_secrets_blinding_factors,
            credential_values,
            credential_pub_key,
            credential_issuance_nonce,
            ptr::null(),
            ptr::null(),
            ptr::null(),
        );

        let proof_building_nonce = _nonce();
        let proof = _proof(
            credential_pub_key,
            credential_signature,
            proof_building_nonce,
            credential_values,
            ptr::null(),
            ptr::null(),
        );

        _free_credential_def(
            credential_pub_key,
            credential_priv_key,
            credential_key_correctness_proof,
        );
        _free_blinded_credential_secrets(
            blinded_credential_secrets,
            credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof,
        );
        _free_nonce(credential_nonce);
        _free_nonce(credential_issuance_nonce);
        _free_nonce(proof_building_nonce);
        _free_credential_signature(credential_signature, signature_correctness_proof);

        let err_code = ursa_cl_proof_free(proof);
        assert_eq!(err_code, ErrorCode::Success);
    }

    #[test]
    fn ursa_cl_prover_get_credential_revocation_index_works() {
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
            _credential_def();
        let (rev_key_pub, rev_key_priv, rev_reg, rev_tails_generator) =
            _revocation_registry_def(credential_pub_key);
        let credential_values = _credential_values();
        let credential_nonce = _nonce();
        let (
            blinded_credential_secrets,
            credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof,
        ) = _blinded_credential_secrets(
            credential_pub_key,
            credential_key_correctness_proof,
            credential_values,
            credential_nonce,
        );
        let credential_issuance_nonce = _nonce();
        let tail_storage = FFISimpleTailStorage::new(rev_tails_generator);

        let (credential_signature, signature_correctness_proof, _) =
            _credential_signature_with_revoc(
                blinded_credential_secrets,
                blinded_credential_secrets_correctness_proof,
                credential_nonce,
                credential_issuance_nonce,
                credential_values,
                credential_pub_key,
                credential_priv_key,
                rev_key_priv,
                rev_reg,
                tail_storage.get_ctx(),
            );

        let mut cred_rev_idx_p: u32 = 0;
        let err_code = ursa_cl_prover_get_credential_revocation_index(
            credential_signature,
            &mut cred_rev_idx_p,
        );
        assert_eq!(err_code, ErrorCode::Success);

        _free_credential_def(
            credential_pub_key,
            credential_priv_key,
            credential_key_correctness_proof,
        );
        _free_revocation_registry_def(rev_key_pub, rev_key_priv, rev_reg, rev_tails_generator);
        _free_credential_values(credential_values);
        _free_blinded_credential_secrets(
            blinded_credential_secrets,
            credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof,
        );
        _free_nonce(credential_nonce);
        _free_nonce(credential_issuance_nonce);
        _free_credential_signature(credential_signature, signature_correctness_proof);
    }
}

#[cfg(test)]
pub mod mocks {
    use super::*;

    use ffi::cl::mocks::*;
    use std::ptr;

    pub fn _master_secret() -> *const c_void {
        let mut master_secret_p: *const c_void = ptr::null();
        let err_code = ursa_cl_prover_new_master_secret(&mut master_secret_p);

        assert_eq!(err_code, ErrorCode::Success);
        assert!(!master_secret_p.is_null());

        master_secret_p
    }

    pub fn _free_master_secret(master_secret: *const c_void) {
        let err_code = ursa_cl_master_secret_free(master_secret);
        assert_eq!(err_code, ErrorCode::Success);
    }

    pub fn _blinded_credential_secrets(
        credential_pub_key: *const c_void,
        credential_key_correctness_proof: *const c_void,
        credential_values: *const c_void,
        credential_nonce: *const c_void,
    ) -> (*const c_void, *const c_void, *const c_void) {
        let mut blinded_credential_secrets_p: *const c_void = ptr::null();
        let mut credential_secrets_blinding_factors_p: *const c_void = ptr::null();
        let mut blinded_credential_secrets_correctness_proof_p: *const c_void = ptr::null();

        let err_code = ursa_cl_prover_blind_credential_secrets(
            credential_pub_key,
            credential_key_correctness_proof,
            credential_values,
            credential_nonce,
            &mut blinded_credential_secrets_p,
            &mut credential_secrets_blinding_factors_p,
            &mut blinded_credential_secrets_correctness_proof_p,
        );
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!blinded_credential_secrets_p.is_null());
        assert!(!credential_secrets_blinding_factors_p.is_null());
        assert!(!blinded_credential_secrets_correctness_proof_p.is_null());

        (
            blinded_credential_secrets_p,
            credential_secrets_blinding_factors_p,
            blinded_credential_secrets_correctness_proof_p,
        )
    }

    pub fn _free_blinded_credential_secrets(
        blinded_credential_secrets: *const c_void,
        credential_secrets_blinding_factors: *const c_void,
        blinded_credential_secrets_correctness_proof: *const c_void,
    ) {
        let err_code = ursa_cl_blinded_credential_secrets_free(blinded_credential_secrets);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code =
            ursa_cl_credential_secrets_blinding_factors_free(credential_secrets_blinding_factors);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_cl_blinded_credential_secrets_correctness_proof_free(
            blinded_credential_secrets_correctness_proof,
        );
        assert_eq!(err_code, ErrorCode::Success);
    }

    pub fn _process_credential_signature(
        credential_signature: *const c_void,
        signature_correctness_proof: *const c_void,
        credential_secrets_blinding_factors: *const c_void,
        credential_values: *const c_void,
        credential_pub_key: *const c_void,
        credential_issuance_nonce: *const c_void,
        rev_key_pub: *const c_void,
        rev_reg: *const c_void,
        witness: *const c_void,
    ) {
        let err_code = ursa_cl_prover_process_credential_signature(
            credential_signature,
            credential_values,
            signature_correctness_proof,
            credential_secrets_blinding_factors,
            credential_pub_key,
            credential_issuance_nonce,
            rev_key_pub,
            rev_reg,
            witness,
        );
        assert_eq!(err_code, ErrorCode::Success);
    }

    pub fn _proof_builder() -> *const c_void {
        let mut proof_builder: *const c_void = ptr::null();
        let err_code = ursa_cl_prover_new_proof_builder(&mut proof_builder);

        assert_eq!(err_code, ErrorCode::Success);
        assert!(!proof_builder.is_null());

        proof_builder
    }

    pub fn _free_proof_builder(proof_builder: *const c_void, nonce: *const c_void) {
        let mut proof: *const c_void = ptr::null();
        let err_code = ursa_cl_proof_builder_finalize(proof_builder, nonce, &mut proof);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!proof.is_null());
    }

    pub fn _proof(
        credential_pub_key: *const c_void,
        credential_signature: *const c_void,
        nonce: *const c_void,
        credential_values: *const c_void,
        rev_reg: *const c_void,
        witness: *const c_void,
    ) -> *const c_void {
        let proof_builder = _proof_builder();
        let credential_schema = _credential_schema();
        let non_credential_schema = _non_credential_schema();
        let sub_proof_request = _sub_proof_request();

        ursa_cl_proof_builder_add_sub_proof_request(
            proof_builder,
            sub_proof_request,
            credential_schema,
            non_credential_schema,
            credential_signature,
            credential_values,
            credential_pub_key,
            rev_reg,
            witness,
        );

        let mut proof: *const c_void = ptr::null();
        let err_code = ursa_cl_proof_builder_finalize(proof_builder, nonce, &mut proof);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!proof.is_null());

        _free_credential_schema(credential_schema);
        _free_non_credential_schema(non_credential_schema);
        _free_credential_values(credential_values);
        _free_sub_proof_request(sub_proof_request);

        proof
    }

    pub fn _free_proof(proof: *const c_void) {
        let err_code = ursa_cl_proof_free(proof);
        assert_eq!(err_code, ErrorCode::Success);
    }
}
