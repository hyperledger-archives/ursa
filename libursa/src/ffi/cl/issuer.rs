use cl::issuer::*;
use cl::*;
use errors::prelude::*;
use ffi::cl::{FFITailPut, FFITailTake, FFITailsAccessor};
use ffi::ErrorCode;
use utils::ctypes::*;

use serde_json;
use std::collections::HashSet;
use std::iter::FromIterator;
use std::os::raw::{c_char, c_void};
use std::ptr::null;
use std::slice;

/// Creates and returns credential definition (public and private keys, correctness proof) entities.
///
/// Note that credential public key instances deallocation must be performed by
/// calling ursa_cl_credential_public_key_free.
///
/// Note that credential private key instances deallocation must be performed by
/// calling ursa_cl_credential_private_key_free.
///
/// Note that credential key correctness proof instances deallocation must be performed by
/// calling ursa_cl_credential_key_correctness_proof_free.
///
/// # Arguments
/// * `credential_schema` - Reference that contains credential schema instance pointer.
/// * `non_credential_schema` - Reference that contains non credential schema instance pointer
/// * `support_revocation` - If true non revocation part of credential keys will be generated.
/// * `credential_pub_key_p` - Reference that will contain credential public key instance pointer.
/// * `credential_priv_key_p` - Reference that will contain credential private key instance pointer.
/// * `credential_key_correctness_proof_p` - Reference that will contain credential keys correctness proof instance pointer.
#[no_mangle]
pub extern "C" fn ursa_cl_issuer_new_credential_def(
    credential_schema: *const c_void,
    non_credential_schema: *const c_void,
    support_revocation: bool,
    credential_pub_key_p: *mut *const c_void,
    credential_priv_key_p: *mut *const c_void,
    credential_key_correctness_proof_p: *mut *const c_void,
) -> ErrorCode {
    trace!(
        "ursa_cl_issuer_new_credential_def: >>> credential_schema: {:?}, \
         non_credential_schema: {:?}, \
         support_revocation: {:?}, \
         credential_pub_key_p: {:?}, \
         credential_priv_key_p: {:?},\
         credential_key_correctness_proof_p: {:?}",
        credential_schema,
        non_credential_schema,
        support_revocation,
        credential_pub_key_p,
        credential_priv_key_p,
        credential_key_correctness_proof_p
    );

    check_useful_c_reference!(
        credential_schema,
        CredentialSchema,
        ErrorCode::CommonInvalidParam1
    );
    check_useful_c_reference!(
        non_credential_schema,
        NonCredentialSchema,
        ErrorCode::CommonInvalidParam2
    );
    check_useful_c_ptr!(credential_pub_key_p, ErrorCode::CommonInvalidParam3);
    check_useful_c_ptr!(credential_priv_key_p, ErrorCode::CommonInvalidParam4);
    check_useful_c_ptr!(
        credential_key_correctness_proof_p,
        ErrorCode::CommonInvalidParam5
    );

    trace!(
        "ursa_cl_issuer_new_credential_def: entities: \
         credential_schema: {:?}, \
         non_credential_schema: {:?}, \
         support_revocation: {:?}",
        credential_schema,
        non_credential_schema,
        support_revocation
    );

    let res = match Issuer::new_credential_def(
        credential_schema,
        non_credential_schema,
        support_revocation,
    ) {
        Ok((credential_pub_key, credential_priv_key, credential_key_correctness_proof)) => {
            trace!("ursa_cl_issuer_new_credential_def: credential_pub_key: {:?}, credential_priv_key: {:?}, credential_key_correctness_proof: {:?}",
                   credential_pub_key, secret!(&credential_priv_key), credential_key_correctness_proof);
            unsafe {
                *credential_pub_key_p =
                    Box::into_raw(Box::new(credential_pub_key)) as *const c_void;
                *credential_priv_key_p =
                    Box::into_raw(Box::new(credential_priv_key)) as *const c_void;
                *credential_key_correctness_proof_p =
                    Box::into_raw(Box::new(credential_key_correctness_proof)) as *const c_void;
                trace!("ursa_cl_issuer_new_credential_def: *credential_pub_key_p: {:?}, *credential_priv_key_p: {:?}, *credential_key_correctness_proof_p: {:?}",
                       *credential_pub_key_p, *credential_priv_key_p, *credential_key_correctness_proof_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.into(),
    };

    trace!("ursa_cl_issuer_new_credential_def: <<< res: {:?}", res);
    res
}

/// Returns json representation of credential public key.
///
/// # Arguments
/// * `credential_pub_key` - Reference that contains credential public key instance pointer.
/// * `credential_pub_key_p` - Reference that will contain credential public key json.
#[no_mangle]
pub extern "C" fn ursa_cl_credential_public_key_to_json(
    credential_pub_key: *const c_void,
    credential_pub_key_json_p: *mut *const c_char,
) -> ErrorCode {
    trace!("ursa_cl_credential_public_key_to_json: >>> credential_pub_key: {:?}, credential_pub_key_json_p: {:?}", credential_pub_key, credential_pub_key_json_p);

    check_useful_c_reference!(
        credential_pub_key,
        CredentialPublicKey,
        ErrorCode::CommonInvalidParam1
    );
    check_useful_c_ptr!(credential_pub_key_json_p, ErrorCode::CommonInvalidParam2);

    trace!(
        "ursa_cl_credential_public_key_to_json: entity >>> credential_pub_key: {:?}",
        credential_pub_key
    );

    let res = match serde_json::to_string(credential_pub_key) {
        Ok(credential_pub_key_json) => {
            trace!(
                "ursa_cl_credential_public_key_to_json: credential_pub_key_json: {:?}",
                credential_pub_key_json
            );
            unsafe {
                let issuer_pub_key_json = string_to_cstring(credential_pub_key_json);
                *credential_pub_key_json_p = issuer_pub_key_json.into_raw();
                trace!(
                    "ursa_cl_credential_private_key_to_json: credential_pub_key_json_p: {:?}",
                    *credential_pub_key_json_p
                );
            }
            ErrorCode::Success
        }
        Err(err) => err
            .to_ursa(
                UrsaCryptoErrorKind::InvalidState,
                "Unable to serialize credential public key as json",
            )
            .into(),
    };

    trace!("ursa_cl_credential_public_key_to_json: <<< res: {:?}", res);
    res
}

/// Creates and returns credential public key from json.
///
/// Note: Credential public key instance deallocation must be performed
/// by calling ursa_cl_credential_public_key_free
///
/// # Arguments
/// * `credential_pub_key_json` - Reference that contains credential public key json.
/// * `credential_pub_key_p` - Reference that will contain credential public key instance pointer.
#[no_mangle]
pub extern "C" fn ursa_cl_credential_public_key_from_json(
    credential_pub_key_json: *const c_char,
    credential_pub_key_p: *mut *const c_void,
) -> ErrorCode {
    trace!("ursa_cl_credential_public_key_from_json: >>> credential_pub_key_json: {:?}, credential_pub_key_p: {:?}", credential_pub_key_json, credential_pub_key_p);

    check_useful_c_str!(credential_pub_key_json, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(credential_pub_key_p, ErrorCode::CommonInvalidParam2);

    trace!(
        "ursa_cl_credential_public_key_from_json: entity: credential_pub_key_json: {:?}",
        credential_pub_key_json
    );

    let res = match serde_json::from_str::<CredentialPublicKey>(&credential_pub_key_json) {
        Ok(credential_pub_key) => {
            trace!(
                "ursa_cl_credential_public_key_from_json: credential_pub_key: {:?}",
                credential_pub_key
            );
            unsafe {
                *credential_pub_key_p =
                    Box::into_raw(Box::new(credential_pub_key)) as *const c_void;
                trace!(
                    "ursa_cl_credential_public_key_from_json: *credential_pub_key_p: {:?}",
                    *credential_pub_key_p
                );
            }
            ErrorCode::Success
        }
        Err(err) => err
            .to_ursa(
                UrsaCryptoErrorKind::InvalidStructure,
                "Unable to deserialize credential public key from json",
            )
            .into(),
    };

    trace!(
        "ursa_cl_credential_public_key_from_json: <<< res: {:?}",
        res
    );
    res
}

/// Deallocates credential public key instance.
///
/// # Arguments
/// * `credential_pub_key` - Reference that contains credential public key instance pointer.
#[no_mangle]
pub extern "C" fn ursa_cl_credential_public_key_free(
    credential_pub_key: *const c_void,
) -> ErrorCode {
    trace!(
        "ursa_cl_credential_public_key_free: >>> credential_pub_key: {:?}",
        credential_pub_key
    );

    check_useful_c_ptr!(credential_pub_key, ErrorCode::CommonInvalidParam1);

    let credential_pub_key =
        unsafe { Box::from_raw(credential_pub_key as *mut CredentialPublicKey) };
    trace!(
        "ursa_cl_credential_public_key_free: entity: credential_pub_key: {:?}",
        credential_pub_key
    );

    let res = ErrorCode::Success;

    trace!("ursa_cl_credential_public_key_free: <<< res: {:?}", res);
    res
}

/// Returns json representation of credential private key.
///
/// # Arguments
/// * `credential_priv_key` - Reference that contains credential private key instance pointer.
/// * `credential_pub_key_p` - Reference that will contain credential private key json.
#[no_mangle]
pub extern "C" fn ursa_cl_credential_private_key_to_json(
    credential_priv_key: *const c_void,
    credential_priv_key_json_p: *mut *const c_char,
) -> ErrorCode {
    trace!("ursa_cl_credential_private_key_to_json: >>> credential_priv_key: {:?}, credential_priv_key_json_p: {:?}", credential_priv_key, credential_priv_key_json_p);

    check_useful_c_reference!(
        credential_priv_key,
        CredentialPrivateKey,
        ErrorCode::CommonInvalidParam1
    );
    check_useful_c_ptr!(credential_priv_key_json_p, ErrorCode::CommonInvalidParam2);

    trace!(
        "ursa_cl_credential_private_key_to_json: entity >>> credential_priv_key: {:?}",
        secret!(&credential_priv_key)
    );

    let res = match serde_json::to_string(credential_priv_key) {
        Ok(credential_priv_key_json) => {
            trace!(
                "ursa_cl_credential_private_key_to_json: credential_priv_key_json: {:?}",
                secret!(&credential_priv_key_json)
            );
            unsafe {
                let credential_priv_key_json = string_to_cstring(credential_priv_key_json);
                *credential_priv_key_json_p = credential_priv_key_json.into_raw();
                trace!(
                    "ursa_cl_credential_private_key_to_json: credential_priv_key_json_p: {:?}",
                    *credential_priv_key_json_p
                );
            }
            ErrorCode::Success
        }
        Err(err) => err
            .to_ursa(
                UrsaCryptoErrorKind::InvalidState,
                "Unable to serialize credential private key as json",
            )
            .into(),
    };

    trace!("ursa_cl_credential_private_key_to_json: <<< res: {:?}", res);
    res
}

/// Creates and returns credential private key from json.
///
/// Note: Credential private key instance deallocation must be performed
/// by calling ursa_cl_credential_private_key_free
///
/// # Arguments
/// * `credential_priv_key_json` - Reference that contains credential private key json.
/// * `credential_priv_key_p` - Reference that will contain credential private key instance pointer.
#[no_mangle]
pub extern "C" fn ursa_cl_credential_private_key_from_json(
    credential_priv_key_json: *const c_char,
    credential_priv_key_p: *mut *const c_void,
) -> ErrorCode {
    trace!("ursa_cl_credential_private_key_from_json: >>> credential_priv_key_json: {:?}, credential_priv_key_p: {:?}", credential_priv_key_json, credential_priv_key_p);

    check_useful_c_str!(credential_priv_key_json, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(credential_priv_key_p, ErrorCode::CommonInvalidParam2);

    trace!(
        "ursa_cl_credential_private_key_from_json: entity: credential_priv_key_json: {:?}",
        secret!(&credential_priv_key_json)
    );

    let res = match serde_json::from_str::<CredentialPrivateKey>(&credential_priv_key_json) {
        Ok(credential_priv_key) => {
            trace!(
                "ursa_cl_credential_private_key_from_json: credential_priv_key: {:?}",
                secret!(&credential_priv_key)
            );
            unsafe {
                *credential_priv_key_p =
                    Box::into_raw(Box::new(credential_priv_key)) as *const c_void;
                trace!(
                    "ursa_cl_credential_private_key_from_json: *credential_priv_key_p: {:?}",
                    *credential_priv_key_p
                );
            }
            ErrorCode::Success
        }
        Err(err) => err
            .to_ursa(
                UrsaCryptoErrorKind::InvalidStructure,
                "Unable to deserialize credential private key from json",
            )
            .into(),
    };

    trace!(
        "ursa_cl_credential_private_key_from_json: <<< res: {:?}",
        res
    );
    res
}

/// Deallocates credential private key instance.
///
/// # Arguments
/// * `credential_priv_key` - Reference that contains credential private key instance pointer.
#[no_mangle]
pub extern "C" fn ursa_cl_credential_private_key_free(
    credential_priv_key: *const c_void,
) -> ErrorCode {
    trace!(
        "ursa_cl_credential_private_key_free: >>> credential_priv_key: {:?}",
        credential_priv_key
    );

    check_useful_c_ptr!(credential_priv_key, ErrorCode::CommonInvalidParam1);

    let _credential_priv_key =
        unsafe { Box::from_raw(credential_priv_key as *mut CredentialPrivateKey) };
    trace!(
        "ursa_cl_credential_private_key_free: entity: credential_priv_key: {:?}",
        secret!(_credential_priv_key)
    );

    let res = ErrorCode::Success;

    trace!("ursa_cl_credential_private_key_free: <<< res: {:?}", res);
    res
}

/// Returns json representation of credential key correctness proof.
///
/// # Arguments
/// * `credential_key_correctness_proof` - Reference that contains credential key correctness proof instance pointer.
/// * `credential_key_correctness_proof_p` - Reference that will contain credential key correctness proof json.
#[no_mangle]
pub extern "C" fn ursa_cl_credential_key_correctness_proof_to_json(
    credential_key_correctness_proof: *const c_void,
    credential_key_correctness_proof_json_p: *mut *const c_char,
) -> ErrorCode {
    trace!("ursa_cl_credential_key_correctness_proof_to_json: >>> credential_key_correctness_proof: {:?}, credential_key_correctness_proof_p: {:?}",
           credential_key_correctness_proof, credential_key_correctness_proof_json_p);

    check_useful_c_reference!(
        credential_key_correctness_proof,
        CredentialKeyCorrectnessProof,
        ErrorCode::CommonInvalidParam1
    );
    check_useful_c_ptr!(
        credential_key_correctness_proof_json_p,
        ErrorCode::CommonInvalidParam2
    );

    trace!("ursa_cl_credential_key_correctness_proof_to_json: entity >>> credential_key_correctness_proof: {:?}", credential_key_correctness_proof);

    let res = match serde_json::to_string(credential_key_correctness_proof) {
        Ok(credential_key_correctness_proof_json) => {
            trace!("ursa_cl_credential_key_correctness_proof_to_json: credential_key_correctness_proof_json: {:?}", credential_key_correctness_proof_json);
            unsafe {
                let credential_key_correctness_proof_json =
                    string_to_cstring(credential_key_correctness_proof_json);
                *credential_key_correctness_proof_json_p =
                    credential_key_correctness_proof_json.into_raw();
                trace!("ursa_cl_credential_key_correctness_proof_to_json: credential_key_correctness_proof_json_p: {:?}", *credential_key_correctness_proof_json_p);
            }
            ErrorCode::Success
        }
        Err(err) => err
            .to_ursa(
                UrsaCryptoErrorKind::InvalidState,
                "Unable to serialize credential key correctness proof as json",
            )
            .into(),
    };

    trace!(
        "ursa_cl_credential_key_correctness_proof_to_json: <<< res: {:?}",
        res
    );
    res
}

/// Creates and returns credential key correctness proof from json.
///
/// Note: Credential key correctness proof instance deallocation must be performed
/// by calling ursa_cl_credential_key_correctness_proof_free
///
/// # Arguments
/// * `credential_key_correctness_proof_json` - Reference that contains credential key correctness proof json.
/// * `credential_key_correctness_proof_p` - Reference that will contain credential key correctness proof instance pointer.
#[no_mangle]
pub extern "C" fn ursa_cl_credential_key_correctness_proof_from_json(
    credential_key_correctness_proof_json: *const c_char,
    credential_key_correctness_proof_p: *mut *const c_void,
) -> ErrorCode {
    trace!("ursa_cl_credential_key_correctness_proof_from_json: >>> credential_key_correctness_proof_json: {:?}, credential_key_correctness_proof_p: {:?}",
           credential_key_correctness_proof_json, credential_key_correctness_proof_p);

    check_useful_c_str!(
        credential_key_correctness_proof_json,
        ErrorCode::CommonInvalidParam1
    );
    check_useful_c_ptr!(
        credential_key_correctness_proof_p,
        ErrorCode::CommonInvalidParam2
    );

    trace!("ursa_cl_credential_key_correctness_proof_from_json: entity: credential_key_correctness_proof_json: {:?}", credential_key_correctness_proof_json);

    let res = match serde_json::from_str::<CredentialKeyCorrectnessProof>(
        &credential_key_correctness_proof_json,
    ) {
        Ok(credential_key_correctness_proof) => {
            trace!("ursa_cl_credential_key_correctness_proof_from_json: credential_key_correctness_proof: {:?}", credential_key_correctness_proof);
            unsafe {
                *credential_key_correctness_proof_p =
                    Box::into_raw(Box::new(credential_key_correctness_proof)) as *const c_void;
                trace!("ursa_cl_credential_key_correctness_proof_from_json: *credential_key_correctness_proof_p: {:?}", *credential_key_correctness_proof_p);
            }
            ErrorCode::Success
        }
        Err(err) => err
            .to_ursa(
                UrsaCryptoErrorKind::InvalidStructure,
                "Unable to deserialize credential key correctness proof from json",
            )
            .into(),
    };

    trace!(
        "ursa_cl_credential_key_correctness_proof_from_json: <<< res: {:?}",
        res
    );
    res
}

/// Deallocates credential key correctness proof instance.
///
/// # Arguments
/// * `credential_key_correctness_proof` - Reference that contains credential key correctness proof instance pointer.
#[no_mangle]
pub extern "C" fn ursa_cl_credential_key_correctness_proof_free(
    credential_key_correctness_proof: *const c_void,
) -> ErrorCode {
    trace!(
        "ursa_cl_credential_key_correctness_proof_free: >>> credential_key_correctness_proof: {:?}",
        credential_key_correctness_proof
    );

    check_useful_c_ptr!(
        credential_key_correctness_proof,
        ErrorCode::CommonInvalidParam1
    );

    let credential_key_correctness_proof = unsafe {
        Box::from_raw(credential_key_correctness_proof as *mut CredentialKeyCorrectnessProof)
    };
    trace!("ursa_cl_credential_key_correctness_proof_free: entity: credential_key_correctness_proof: {:?}", credential_key_correctness_proof);

    let res = ErrorCode::Success;

    trace!(
        "ursa_cl_credential_key_correctness_proof_free: <<< res: {:?}",
        res
    );
    res
}

/// Creates and returns revocation registries definition (public and private keys, accumulator, tails generator) entities.
///
/// Note that keys registries deallocation must be performed by
/// calling ursa_cl_revocation_key_public_free and
/// ursa_cl_revocation_key_private_free.
///
/// Note that accumulator deallocation must be performed by
/// calling ursa_cl_revocation_registry_free.
///
/// Note that tails generator deallocation must be performed by
/// calling ursa_cl_revocation_tails_generator_free.
///
/// # Arguments
/// * `credential_pub_key` - Reference that contains credential pub key instance pointer.
/// * `max_cred_num` - Max credential number in generated registry.
/// * `issuance_by_default` - Type of issuance.
/// If true all indices are assumed to be issued and initial accumulator is calculated over all indices
/// If false nothing is issued initially accumulator is 1
/// * `rev_key_pub_p` - Reference that will contain revocation key public instance pointer.
/// * `rev_key_priv_p` - Reference that will contain revocation key private instance pointer.
/// * `rev_reg_p` - Reference that will contain revocation registry instance pointer.
/// * `rev_tails_generator_p` - Reference that will contain revocation tails generator instance pointer.
#[no_mangle]
pub extern "C" fn ursa_cl_issuer_new_revocation_registry_def(
    credential_pub_key: *const c_void,
    max_cred_num: u32,
    issuance_by_default: bool,
    rev_key_pub_p: *mut *const c_void,
    rev_key_priv_p: *mut *const c_void,
    rev_reg_p: *mut *const c_void,
    rev_tails_generator_p: *mut *const c_void,
) -> ErrorCode {
    trace!("ursa_cl_issuer_new_revocation_registry_def: >>> credential_pub_key: {:?}, max_cred_num: {:?}, rev_key_pub_p: {:?}, rev_key_priv_p: {:?}, \
    rev_reg_p: {:?}, rev_tails_generator_p: {:?}",
           credential_pub_key, max_cred_num, rev_key_pub_p, rev_key_priv_p, rev_reg_p, rev_tails_generator_p);

    check_useful_c_reference!(
        credential_pub_key,
        CredentialPublicKey,
        ErrorCode::CommonInvalidParam1
    );
    check_useful_c_ptr!(rev_key_pub_p, ErrorCode::CommonInvalidParam4);
    check_useful_c_ptr!(rev_key_priv_p, ErrorCode::CommonInvalidParam5);
    check_useful_c_ptr!(rev_reg_p, ErrorCode::CommonInvalidParam6);
    check_useful_c_ptr!(rev_tails_generator_p, ErrorCode::CommonInvalidParam7);

    trace!("ursa_cl_issuer_new_revocation_registry_def: entities: credential_pub_key: {:?}, max_cred_num: {:?}", credential_pub_key, max_cred_num);

    let res = match Issuer::new_revocation_registry_def(
        credential_pub_key,
        max_cred_num,
        issuance_by_default,
    ) {
        Ok((rev_key_pub, rev_key_priv, rev_reg, rev_tails_generator)) => {
            trace!("ursa_cl_issuer_new_revocation_registry_def: rev_key_pub_p: {:?}, rev_key_priv: {:?}, rev_reg: {:?}, rev_tails_generator: {:?}",
                   rev_key_pub_p, secret!(&rev_key_priv), rev_reg, rev_tails_generator);
            unsafe {
                *rev_key_pub_p = Box::into_raw(Box::new(rev_key_pub)) as *const c_void;
                *rev_key_priv_p = Box::into_raw(Box::new(rev_key_priv)) as *const c_void;
                *rev_reg_p = Box::into_raw(Box::new(rev_reg)) as *const c_void;
                *rev_tails_generator_p =
                    Box::into_raw(Box::new(rev_tails_generator)) as *const c_void;
                trace!("ursa_cl_issuer_new_revocation_registry_def: *rev_key_pub_p: {:?}, *rev_key_priv_p: {:?}, *rev_reg_p: {:?}, *rev_tails_generator_p: {:?}",
                       *rev_key_pub_p, *rev_key_priv_p, *rev_reg_p, *rev_tails_generator_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.into(),
    };

    trace!(
        "ursa_cl_issuer_new_revocation_registry_def: <<< res: {:?}",
        res
    );
    res
}

/// Returns json representation of revocation key public.
///
/// # Arguments
/// * `rev_key_pub` - Reference that contains revocation key public pointer.
/// * `rev_key_pub_json_p` - Reference that will contain revocation key public json.
#[no_mangle]
pub extern "C" fn ursa_cl_revocation_key_public_to_json(
    rev_key_pub: *const c_void,
    rev_key_pub_json_p: *mut *const c_char,
) -> ErrorCode {
    trace!(
        "ursa_cl_revocation_key_public_to_json: >>> rev_key_pub: {:?}, rev_key_pub_json_p: {:?}",
        rev_key_pub,
        rev_key_pub_json_p
    );

    check_useful_c_reference!(
        rev_key_pub,
        RevocationKeyPublic,
        ErrorCode::CommonInvalidParam1
    );
    check_useful_c_ptr!(rev_key_pub_json_p, ErrorCode::CommonInvalidParam2);

    trace!(
        "ursa_cl_revocation_key_public_to_json: entity >>> rev_key_pub: {:?}",
        rev_key_pub
    );

    let res = match serde_json::to_string(rev_key_pub) {
        Ok(rev_key_pub_json) => {
            trace!(
                "ursa_cl_revocation_key_public_to_json: rev_key_pub_json: {:?}",
                rev_key_pub_json
            );
            unsafe {
                let rev_reg_def_pub_json = string_to_cstring(rev_key_pub_json);
                *rev_key_pub_json_p = rev_reg_def_pub_json.into_raw();
                trace!(
                    "ursa_cl_revocation_key_public_to_json: rev_key_pub_json_p: {:?}",
                    *rev_key_pub_json_p
                );
            }
            ErrorCode::Success
        }
        Err(err) => err
            .to_ursa(
                UrsaCryptoErrorKind::InvalidState,
                "Unable to serialize revocation key public as json",
            )
            .into(),
    };

    trace!("ursa_cl_revocation_key_public_to_json: <<< res: {:?}", res);
    res
}

/// Creates and returns revocation key public from json.
///
/// Note: Revocation registry public instance deallocation must be performed
/// by calling ursa_cl_revocation_key_public_free
///
/// # Arguments
/// * `rev_key_pub_json` - Reference that contains revocation key public json.
/// * `rev_key_pub_p` - Reference that will contain revocation key public instance pointer.
#[no_mangle]
pub extern "C" fn ursa_cl_revocation_key_public_from_json(
    rev_key_pub_json: *const c_char,
    rev_key_pub_p: *mut *const c_void,
) -> ErrorCode {
    trace!(
        "ursa_cl_revocation_key_public_from_json: >>> rev_key_pub_json: {:?}, rev_key_pub_p: {:?}",
        rev_key_pub_json,
        rev_key_pub_p
    );

    check_useful_c_str!(rev_key_pub_json, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(rev_key_pub_p, ErrorCode::CommonInvalidParam2);

    trace!(
        "ursa_cl_revocation_key_public_from_json: entity: rev_key_pub_json: {:?}",
        rev_key_pub_json
    );

    let res = match serde_json::from_str::<RevocationKeyPublic>(&rev_key_pub_json) {
        Ok(rev_key_pub) => {
            trace!(
                "ursa_cl_revocation_key_public_from_json: rev_key_pub: {:?}",
                rev_key_pub
            );
            unsafe {
                *rev_key_pub_p = Box::into_raw(Box::new(rev_key_pub)) as *const c_void;
                trace!(
                    "ursa_cl_revocation_key_public_from_json: *rev_key_pub_p: {:?}",
                    *rev_key_pub_p
                );
            }
            ErrorCode::Success
        }
        Err(err) => err
            .to_ursa(
                UrsaCryptoErrorKind::InvalidStructure,
                "Unable to deserialize revocation key public from json",
            )
            .into(),
    };

    trace!(
        "ursa_cl_revocation_key_public_from_json: <<< res: {:?}",
        res
    );
    res
}

/// Deallocates revocation key public instance.
///
/// # Arguments
/// * `rev_key_pub` - Reference that contains revocation key public instance pointer.
#[no_mangle]
pub extern "C" fn ursa_cl_revocation_key_public_free(rev_key_pub: *const c_void) -> ErrorCode {
    trace!(
        "ursa_cl_revocation_key_public_free: >>> rev_key_pub: {:?}",
        rev_key_pub
    );

    check_useful_c_ptr!(rev_key_pub, ErrorCode::CommonInvalidParam1);
    let rev_key_pub = unsafe { Box::from_raw(rev_key_pub as *mut RevocationKeyPublic) };
    trace!(
        "ursa_cl_revocation_key_public_free: entity: rev_key_pub: {:?}",
        rev_key_pub
    );

    let res = ErrorCode::Success;

    trace!("ursa_cl_revocation_key_public_free: <<< res: {:?}", res);
    res
}

/// Returns json representation of revocation key private.
///
/// # Arguments
/// * `rev_key_priv` - Reference that contains issuer revocation key private pointer.
/// * `rev_key_priv_json_p` - Reference that will contain revocation key private json
#[no_mangle]
pub extern "C" fn ursa_cl_revocation_key_private_to_json(
    rev_key_priv: *const c_void,
    rev_key_priv_json_p: *mut *const c_char,
) -> ErrorCode {
    trace!(
        "ursa_cl_revocation_key_private_to_json: >>> rev_key_priv: {:?}, rev_key_priv_json_p: {:?}",
        rev_key_priv,
        rev_key_priv_json_p
    );

    check_useful_c_reference!(
        rev_key_priv,
        RevocationKeyPrivate,
        ErrorCode::CommonInvalidParam1
    );
    check_useful_c_ptr!(rev_key_priv_json_p, ErrorCode::CommonInvalidParam2);

    trace!(
        "ursa_cl_revocation_key_private_to_json: entity >>> rev_key_priv: {:?}",
        secret!(&rev_key_priv)
    );

    let res = match serde_json::to_string(rev_key_priv) {
        Ok(rev_key_priv_json) => {
            trace!(
                "ursa_cl_revocation_key_private_to_json: rev_key_priv_json: {:?}",
                secret!(&rev_key_priv_json)
            );
            unsafe {
                let rev_reg_def_priv_json = string_to_cstring(rev_key_priv_json);
                *rev_key_priv_json_p = rev_reg_def_priv_json.into_raw();
                trace!(
                    "ursa_cl_revocation_key_private_to_json: rev_key_priv_json_p: {:?}",
                    *rev_key_priv_json_p
                );
            }
            ErrorCode::Success
        }
        Err(err) => err
            .to_ursa(
                UrsaCryptoErrorKind::InvalidState,
                "Unable to serialize revocation key private as json",
            )
            .into(),
    };

    trace!("ursa_cl_revocation_key_private_to_json: <<< res: {:?}", res);
    res
}

/// Creates and returns revocation key private from json.
///
/// Note: Revocation registry private instance deallocation must be performed
/// by calling ursa_cl_revocation_key_private_free
///
/// # Arguments
/// * `rev_key_priv_json` - Reference that contains revocation key private json.
/// * `rev_key_priv_p` - Reference that will contain revocation key private instance pointer
#[no_mangle]
pub extern "C" fn ursa_cl_revocation_key_private_from_json(
    rev_key_priv_json: *const c_char,
    rev_key_priv_p: *mut *const c_void,
) -> ErrorCode {
    trace!("ursa_cl_revocation_key_private_from_json: >>> rev_key_priv_json: {:?}, rev_key_priv_p: {:?}",
           rev_key_priv_json, rev_key_priv_p);

    check_useful_c_str!(rev_key_priv_json, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(rev_key_priv_p, ErrorCode::CommonInvalidParam2);

    trace!(
        "ursa_cl_revocation_key_private_from_json: entity: rev_key_priv_json: {:?}",
        secret!(&rev_key_priv_json)
    );

    let res = match serde_json::from_str::<RevocationKeyPrivate>(&rev_key_priv_json) {
        Ok(rev_key_priv) => {
            trace!(
                "ursa_cl_revocation_key_private_from_json: rev_key_priv: {:?}",
                secret!(&rev_key_priv)
            );
            unsafe {
                *rev_key_priv_p = Box::into_raw(Box::new(rev_key_priv)) as *const c_void;
                trace!(
                    "ursa_cl_revocation_key_private_from_json: *rev_key_priv_p: {:?}",
                    *rev_key_priv_p
                );
            }
            ErrorCode::Success
        }
        Err(err) => err
            .to_ursa(
                UrsaCryptoErrorKind::InvalidStructure,
                "Unable to deserialize revocation key private from json",
            )
            .into(),
    };

    trace!(
        "ursa_cl_revocation_key_private_from_json: <<< res: {:?}",
        res
    );
    res
}

/// Deallocates revocation key private instance.
///
/// # Arguments
/// * `rev_key_priv` - Reference that contains revocation key private instance pointer.
#[no_mangle]
pub extern "C" fn ursa_cl_revocation_key_private_free(rev_key_priv: *const c_void) -> ErrorCode {
    trace!(
        "ursa_cl_revocation_key_private_free: >>> rev_key_priv: {:?}",
        rev_key_priv
    );

    check_useful_c_ptr!(rev_key_priv, ErrorCode::CommonInvalidParam1);

    let _rev_key_priv = unsafe { Box::from_raw(rev_key_priv as *mut RevocationKeyPrivate) };
    trace!(
        "ursa_cl_revocation_key_private_free: entity: rev_key_priv: {:?}",
        secret!(_rev_key_priv)
    );

    let res = ErrorCode::Success;

    trace!("ursa_cl_revocation_key_private_free: <<< res: {:?}", res);
    res
}

/// Returns json representation of revocation registry.
///
/// # Arguments
/// * `rev_reg` - Reference that contains revocation registry pointer.
/// * `rev_reg_p` - Reference that will contain revocation registry json
#[no_mangle]
pub extern "C" fn ursa_cl_revocation_registry_to_json(
    rev_reg: *const c_void,
    rev_reg_json_p: *mut *const c_char,
) -> ErrorCode {
    trace!(
        "ursa_cl_revocation_registry_to_json: >>> rev_reg: {:?}, rev_reg_json_p: {:?}",
        rev_reg,
        rev_reg_json_p
    );

    check_useful_c_reference!(rev_reg, RevocationRegistry, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(rev_reg_json_p, ErrorCode::CommonInvalidParam2);

    trace!(
        "ursa_cl_revocation_registry_to_json: entity >>> rev_reg: {:?}",
        rev_reg
    );

    let res = match serde_json::to_string(rev_reg) {
        Ok(rev_reg_json) => {
            trace!(
                "ursa_cl_revocation_registry_to_json: rev_reg_json: {:?}",
                rev_reg_json
            );
            unsafe {
                let rev_reg_json = string_to_cstring(rev_reg_json);
                *rev_reg_json_p = rev_reg_json.into_raw();
                trace!(
                    "ursa_cl_revocation_registry_to_json: rev_reg_json_p: {:?}",
                    *rev_reg_json_p
                );
            }
            ErrorCode::Success
        }
        Err(err) => err
            .to_ursa(
                UrsaCryptoErrorKind::InvalidState,
                "Unable to serialize revocation registry as json",
            )
            .into(),
    };

    trace!("ursa_cl_revocation_registry_to_json: <<< res: {:?}", res);
    res
}

/// Creates and returns revocation registry from json.
///
/// Note: Revocation registry instance deallocation must be performed
/// by calling ursa_cl_revocation_registry_free
///
/// # Arguments
/// * `rev_reg_json` - Reference that contains revocation registry json.
/// * `rev_reg_p` - Reference that will contain revocation registry instance pointer
#[no_mangle]
pub extern "C" fn ursa_cl_revocation_registry_from_json(
    rev_reg_json: *const c_char,
    rev_reg_p: *mut *const c_void,
) -> ErrorCode {
    trace!(
        "ursa_cl_revocation_registry_from_json: >>> rev_reg_json: {:?}, rev_reg_p: {:?}",
        rev_reg_json,
        rev_reg_p
    );

    check_useful_c_str!(rev_reg_json, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(rev_reg_p, ErrorCode::CommonInvalidParam2);

    trace!(
        "ursa_cl_revocation_registry_from_json: entity: rev_reg_json: {:?}",
        rev_reg_json
    );

    let res = match serde_json::from_str::<RevocationRegistry>(&rev_reg_json) {
        Ok(rev_reg) => {
            trace!(
                "ursa_cl_revocation_registry_from_json: rev_reg: {:?}",
                rev_reg
            );
            unsafe {
                *rev_reg_p = Box::into_raw(Box::new(rev_reg)) as *const c_void;
                trace!(
                    "ursa_cl_revocation_registry_from_json: *rev_reg_p: {:?}",
                    *rev_reg_p
                );
            }
            ErrorCode::Success
        }
        Err(err) => err
            .to_ursa(
                UrsaCryptoErrorKind::InvalidStructure,
                "Unable to deserialize revocation registry from json",
            )
            .into(),
    };

    trace!("ursa_cl_revocation_registry_from_json: <<< res: {:?}", res);
    res
}

/// Deallocates revocation registry instance.
///
/// # Arguments
/// * `rev_reg` - Reference that contains revocation registry instance pointer.
#[no_mangle]
pub extern "C" fn ursa_cl_revocation_registry_free(rev_reg: *const c_void) -> ErrorCode {
    trace!(
        "ursa_cl_revocation_registry_free: >>> rev_reg: {:?}",
        rev_reg
    );

    check_useful_c_ptr!(rev_reg, ErrorCode::CommonInvalidParam1);

    let rev_reg = unsafe { Box::from_raw(rev_reg as *mut RevocationRegistry) };
    trace!(
        "ursa_cl_revocation_registry_free: entity: rev_reg: {:?}",
        rev_reg
    );

    let res = ErrorCode::Success;

    trace!("ursa_cl_revocation_registry_free: <<< res: {:?}", res);
    res
}

/// Returns json representation of revocation tails generator.
///
/// # Arguments
/// * `rev_tails_generator` - Reference that contains revocation tails generator pointer.
/// * `rev_tails_generator_p` - Reference that will contain revocation tails generator json
#[no_mangle]
pub extern "C" fn ursa_cl_revocation_tails_generator_to_json(
    rev_tails_generator: *const c_void,
    rev_tails_generator_json_p: *mut *const c_char,
) -> ErrorCode {
    trace!("ursa_cl_revocation_tails_generator_to_json: >>> rev_tails_generator: {:?}, rev_tails_generator_json_p: {:?}",
           rev_tails_generator, rev_tails_generator_json_p);

    check_useful_c_reference!(
        rev_tails_generator,
        RevocationTailsGenerator,
        ErrorCode::CommonInvalidParam1
    );
    check_useful_c_ptr!(rev_tails_generator_json_p, ErrorCode::CommonInvalidParam2);

    trace!(
        "ursa_cl_revocation_tails_generator_to_json: entity >>> rev_tails_generator: {:?}",
        rev_tails_generator
    );

    let res = match serde_json::to_string(rev_tails_generator) {
        Ok(rev_tails_generator_json) => {
            trace!(
                "ursa_cl_revocation_tails_generator_to_json: rev_tails_generator_json: {:?}",
                rev_tails_generator_json
            );
            unsafe {
                let rev_tails_generator_json = string_to_cstring(rev_tails_generator_json);
                *rev_tails_generator_json_p = rev_tails_generator_json.into_raw();
                trace!(
                    "ursa_cl_revocation_tails_generator_to_json: rev_tails_generator_json_p: {:?}",
                    *rev_tails_generator_json_p
                );
            }
            ErrorCode::Success
        }
        Err(err) => err
            .to_ursa(
                UrsaCryptoErrorKind::InvalidState,
                "Unable to serialize revocation tails generator as json",
            )
            .into(),
    };

    trace!(
        "ursa_cl_revocation_tails_generator_to_json: <<< res: {:?}",
        res
    );
    res
}

/// Creates and returns revocation tails generator from json.
///
/// Note: Revocation tails generator instance deallocation must be performed
/// by calling ursa_cl_revocation_tails_generator_free
///
/// # Arguments
/// * `rev_tails_generator_json` - Reference that contains revocation tails generator json.
/// * `rev_tails_generator_p` - Reference that will contain revocation tails generator instance pointer
#[no_mangle]
pub extern "C" fn ursa_cl_revocation_tails_generator_from_json(
    rev_tails_generator_json: *const c_char,
    rev_tails_generator_p: *mut *const c_void,
) -> ErrorCode {
    trace!("ursa_cl_revocation_tails_generator_from_json: >>> rev_tails_generator_json: {:?}, rev_tails_generator_p: {:?}",
           rev_tails_generator_json, rev_tails_generator_p);

    check_useful_c_str!(rev_tails_generator_json, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(rev_tails_generator_p, ErrorCode::CommonInvalidParam2);

    trace!(
        "ursa_cl_revocation_tails_generator_from_json: entity: rev_tails_generator_json: {:?}",
        rev_tails_generator_json
    );

    let res = match serde_json::from_str::<RevocationTailsGenerator>(&rev_tails_generator_json) {
        Ok(rev_tails_generator) => {
            trace!(
                "ursa_cl_revocation_tails_generator_from_json: rev_tails_generator: {:?}",
                rev_tails_generator
            );
            unsafe {
                *rev_tails_generator_p =
                    Box::into_raw(Box::new(rev_tails_generator)) as *const c_void;
                trace!(
                    "ursa_cl_revocation_tails_generator_from_json: *rev_tails_generator_p: {:?}",
                    *rev_tails_generator_p
                );
            }
            ErrorCode::Success
        }
        Err(err) => err
            .to_ursa(
                UrsaCryptoErrorKind::InvalidStructure,
                "Unable to deserialize revocation tails generator from json",
            )
            .into(),
    };

    trace!(
        "ursa_cl_revocation_tails_generator_from_json: <<< res: {:?}",
        res
    );
    res
}

/// Deallocates revocation tails generator instance.
///
/// # Arguments
/// * `rev_tails_generator` - Reference that contains revocation tails generator instance pointer.
#[no_mangle]
pub extern "C" fn ursa_cl_revocation_tails_generator_free(
    rev_tails_generator: *const c_void,
) -> ErrorCode {
    trace!(
        "ursa_cl_revocation_tails_generator_free: >>> rev_tails_generator: {:?}",
        rev_tails_generator
    );

    check_useful_c_ptr!(rev_tails_generator, ErrorCode::CommonInvalidParam1);

    let rev_tails_generator =
        unsafe { Box::from_raw(rev_tails_generator as *mut RevocationTailsGenerator) };
    trace!(
        "ursa_cl_revocation_tails_generator_free: entity: rev_tails_generator: {:?}",
        rev_tails_generator
    );

    let res = ErrorCode::Success;

    trace!(
        "ursa_cl_revocation_tails_generator_free: <<< res: {:?}",
        res
    );
    res
}

/// Signs credential values with primary keys only.
///
/// Note that credential signature instances deallocation must be performed by
/// calling ursa_cl_credential_signature_free.
///
/// Note that credential signature correctness proof instances deallocation must be performed by
/// calling ursa_cl_signature_correctness_proof_free.
///
/// # Arguments
/// * `prover_id` - Prover identifier.
/// * `blinded_credential_secrets` - Blinded master secret instance pointer generated by Prover.
/// * `blinded_credential_secrets_correctness_proof` - Blinded master secret correctness proof instance pointer.
/// * `credential_nonce` - Nonce instance pointer used for verification of blinded_credential_secrets_correctness_proof.
/// * `credential_issuance_nonce` - Nonce instance pointer used for creation of signature_correctness_proof.
/// * `credential_values` - Credential values to be signed instance pointer.
/// * `credential_pub_key` - Credential public key instance pointer.
/// * `credential_priv_key` - Credential private key instance pointer.
/// * `credential_signature_p` - Reference that will contain credential signature instance pointer.
/// * `credential_signature_correctness_proof_p` - Reference that will contain credential signature correctness proof instance pointer.
#[no_mangle]
pub extern "C" fn ursa_cl_issuer_sign_credential(
    prover_id: *const c_char,
    blinded_credential_secrets: *const c_void,
    blinded_credential_secrets_correctness_proof: *const c_void,
    credential_nonce: *const c_void,
    credential_issuance_nonce: *const c_void,
    credential_values: *const c_void,
    credential_pub_key: *const c_void,
    credential_priv_key: *const c_void,
    credential_signature_p: *mut *const c_void,
    credential_signature_correctness_proof_p: *mut *const c_void,
) -> ErrorCode {
    trace!("ursa_cl_issuer_sign_credential: >>> prover_id: {:?}, blinded_credential_secrets: {:?}, blinded_credential_secrets_correctness_proof: {:?}, \
        credential_nonce: {:?}, credential_issuance_nonce: {:?}, credential_values: {:?}, credential_pub_key: {:?}, credential_priv_key: {:?}, \
        credential_signature_p: {:?}, credential_signature_correctness_proof_p: {:?}",
           prover_id, blinded_credential_secrets, blinded_credential_secrets_correctness_proof,
           credential_nonce, credential_issuance_nonce, credential_values, credential_pub_key, credential_priv_key,
           credential_signature_p, credential_signature_correctness_proof_p);

    check_useful_c_str!(prover_id, ErrorCode::CommonInvalidParam1);
    check_useful_c_reference!(
        blinded_credential_secrets,
        BlindedCredentialSecrets,
        ErrorCode::CommonInvalidParam2
    );
    check_useful_c_reference!(
        blinded_credential_secrets_correctness_proof,
        BlindedCredentialSecretsCorrectnessProof,
        ErrorCode::CommonInvalidParam3
    );
    check_useful_c_reference!(credential_nonce, Nonce, ErrorCode::CommonInvalidParam4);
    check_useful_c_reference!(
        credential_issuance_nonce,
        Nonce,
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
    check_useful_c_reference!(
        credential_priv_key,
        CredentialPrivateKey,
        ErrorCode::CommonInvalidParam8
    );
    check_useful_c_ptr!(credential_signature_p, ErrorCode::CommonInvalidParam10);
    check_useful_c_ptr!(
        credential_signature_correctness_proof_p,
        ErrorCode::CommonInvalidParam11
    );

    trace!("ursa_cl_issuer_sign_credential: >>> prover_id: {:?}, blinded_credential_secrets: {:?}, blinded_credential_secrets_correctness_proof: {:?},\
     credential_nonce: {:?}, credential_issuance_nonce: {:?}, credential_values: {:?}, credential_pub_key: {:?}, credential_priv_key: {:?}",
           prover_id, blinded_credential_secrets, blinded_credential_secrets_correctness_proof, credential_nonce, credential_issuance_nonce,
           secret!(&credential_values), credential_pub_key, secret!(&credential_priv_key));

    let res = match Issuer::sign_credential(
        &prover_id,
        &blinded_credential_secrets,
        &blinded_credential_secrets_correctness_proof,
        &credential_nonce,
        &credential_issuance_nonce,
        &credential_values,
        &credential_pub_key,
        &credential_priv_key,
    ) {
        Ok((credential_signature, credential_signature_correctness_proof)) => {
            trace!("ursa_cl_issuer_sign_credential: credential_signature: {:?}, credential_signature_correctness_proof: {:?}",
                   secret!(&credential_signature), credential_signature_correctness_proof);
            unsafe {
                *credential_signature_p =
                    Box::into_raw(Box::new(credential_signature)) as *const c_void;
                *credential_signature_correctness_proof_p =
                    Box::into_raw(Box::new(credential_signature_correctness_proof))
                        as *const c_void;
                trace!("ursa_cl_issuer_sign_credential: *credential_signature_p: {:?}, *credential_signature_correctness_proof_p: {:?}",
                       *credential_signature_p, *credential_signature_correctness_proof_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.into(),
    };

    trace!("ursa_cl_issuer_sign_credential: <<< res: {:?}", res);
    res
}

/// Signs credential values with both primary and revocation keys.
///
///
/// Note that credential signature instances deallocation must be performed by
/// calling ursa_cl_credential_signature_free.
///
/// Note that credential signature correctness proof instances deallocation must be performed by
/// calling ursa_cl_signature_correctness_proof_free.
///
///
/// Note that credential signature correctness proof instances deallocation must be performed by
/// calling ursa_cl_revocation_registry_delta_free.
///
/// # Arguments
/// * `prover_id` - Prover identifier.
/// * `blinded_credential_secrets` - Blinded master secret instance pointer generated by Prover.
/// * `blinded_credential_secrets_correctness_proof` - Blinded master secret correctness proof instance pointer.
/// * `credential_nonce` - Nonce instance pointer used for verification of blinded_credential_secrets_correctness_proof.
/// * `credential_issuance_nonce` - Nonce instance pointer used for creation of signature_correctness_proof.
/// * `credential_values` - Credential values to be signed instance pointer.
/// * `credential_pub_key` - Credential public key instance pointer.
/// * `credential_priv_key` - Credential private key instance pointer.
/// * `rev_idx` - User index in revocation accumulator. Required for non-revocation credential_signature part generation.
/// * `max_cred_num` - Max credential number in generated registry.
/// * `rev_reg` - Revocation registry instance pointer.
/// * `rev_key_priv` - Revocation registry private key instance pointer.
/// * `credential_signature_p` - Reference that will contain credential signature instance pointer.
/// * `credential_signature_correctness_proof_p` - Reference that will contain credential signature correctness proof instance pointer.
/// * `revocation_registry_delta_p` - Reference that will contain revocation registry delta instance pointer.
#[no_mangle]
pub extern "C" fn ursa_cl_issuer_sign_credential_with_revoc(
    prover_id: *const c_char,
    blinded_credential_secrets: *const c_void,
    blinded_credential_secrets_correctness_proof: *const c_void,
    credential_nonce: *const c_void,
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
    revocation_registry_delta_p: *mut *const c_void,
) -> ErrorCode {
    trace!("ursa_cl_issuer_sign_credential: >>> prover_id: {:?}, blinded_credential_secrets: {:?}, blinded_credential_secrets_correctness_proof: {:?}, \
        credential_nonce: {:?}, credential_issuance_nonce: {:?}, credential_values: {:?}, credential_pub_key: {:?}, credential_priv_key: {:?}, \
        rev_idx: {:?}, rev_key_pub: {:?}, rev_key_priv: {:?}, credential_signature_p: {:?}, credential_signature_correctness_proof_p: {:?}",
           prover_id, blinded_credential_secrets, blinded_credential_secrets_correctness_proof, credential_nonce, credential_issuance_nonce,
           credential_values, credential_pub_key, credential_priv_key, rev_idx, rev_reg, rev_key_priv, credential_signature_p, credential_signature_correctness_proof_p);

    check_useful_c_str!(prover_id, ErrorCode::CommonInvalidParam1);
    check_useful_c_reference!(
        blinded_credential_secrets,
        BlindedCredentialSecrets,
        ErrorCode::CommonInvalidParam2
    );
    check_useful_c_reference!(
        blinded_credential_secrets_correctness_proof,
        BlindedCredentialSecretsCorrectnessProof,
        ErrorCode::CommonInvalidParam3
    );
    check_useful_c_reference!(credential_nonce, Nonce, ErrorCode::CommonInvalidParam4);
    check_useful_c_reference!(
        credential_issuance_nonce,
        Nonce,
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
    check_useful_c_reference!(
        credential_priv_key,
        CredentialPrivateKey,
        ErrorCode::CommonInvalidParam8
    );
    check_useful_mut_c_reference!(rev_reg, RevocationRegistry, ErrorCode::CommonInvalidParam12);
    check_useful_c_reference!(
        rev_key_priv,
        RevocationKeyPrivate,
        ErrorCode::CommonInvalidState
    ); //TODO invalid param
    check_useful_c_ptr!(credential_signature_p, ErrorCode::CommonInvalidState); //TODO invalid param
    check_useful_c_ptr!(
        credential_signature_correctness_proof_p,
        ErrorCode::CommonInvalidState
    ); //TODO invalid param
    check_useful_c_ptr!(revocation_registry_delta_p, ErrorCode::CommonInvalidState); //TODO invalid param

    trace!("ursa_cl_issuer_sign_credential: >>> prover_id: {:?}, blinded_credential_secrets: {:?}, blinded_credential_secrets_correctness_proof: {:?}, \
    credential_nonce: {:?}, credential_issuance_nonce: {:?}, credential_values: {:?}, credential_pub_key: {:?}, credential_priv_key: {:?}, \
    rev_idx: {:?}, rev_reg: {:?}, rev_key_priv: {:?}", prover_id, blinded_credential_secrets, blinded_credential_secrets_correctness_proof, credential_nonce,
           credential_issuance_nonce, secret!(credential_values), credential_pub_key, secret!(credential_priv_key), secret!(rev_idx), rev_reg, secret!(rev_key_priv));

    let rta = FFITailsAccessor::new(ctx_tails, take_tail, put_tail);
    let res = match Issuer::sign_credential_with_revoc(
        &prover_id,
        &blinded_credential_secrets,
        &blinded_credential_secrets_correctness_proof,
        &credential_nonce,
        &credential_issuance_nonce,
        &credential_values,
        &credential_pub_key,
        &credential_priv_key,
        rev_idx,
        max_cred_num,
        issuance_by_default,
        rev_reg,
        rev_key_priv,
        &rta,
    ) {
        Ok((credential_signature, credential_signature_correctness_proof, delta)) => {
            trace!("ursa_cl_issuer_sign_credential: credential_signature: {:?}, credential_signature_correctness_proof: {:?}",
                   secret!(&credential_signature), credential_signature_correctness_proof);
            unsafe {
                *credential_signature_p =
                    Box::into_raw(Box::new(credential_signature)) as *const c_void;
                *credential_signature_correctness_proof_p =
                    Box::into_raw(Box::new(credential_signature_correctness_proof))
                        as *const c_void;
                *revocation_registry_delta_p = if let Some(delta) = delta {
                    Box::into_raw(Box::new(delta)) as *const c_void
                } else {
                    null()
                };
                trace!("ursa_cl_issuer_sign_credential: *credential_signature_p: {:?}, *credential_signature_correctness_proof_p: {:?}",
                       *credential_signature_p, *credential_signature_correctness_proof_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.into(),
    };

    trace!("ursa_cl_issuer_sign_credential: <<< res: {:?}", res);
    res
}

/// Returns json representation of credential signature.
///
/// # Arguments
/// * `credential_signature` - Reference that contains credential signature pointer.
/// * `credential_signature_json_p` - Reference that will contain credential signature json.
#[no_mangle]
pub extern "C" fn ursa_cl_credential_signature_to_json(
    credential_signature: *const c_void,
    credential_signature_json_p: *mut *const c_char,
) -> ErrorCode {
    trace!("ursa_cl_credential_signature_to_json: >>> credential_signature: {:?}, credential_signature_json_p: {:?}",
           credential_signature, credential_signature_json_p);

    check_useful_c_reference!(
        credential_signature,
        CredentialSignature,
        ErrorCode::CommonInvalidParam1
    );
    check_useful_c_ptr!(credential_signature_json_p, ErrorCode::CommonInvalidParam2);

    trace!(
        "ursa_cl_credential_signature_to_json: entity >>> credential_signature: {:?}",
        secret!(&credential_signature)
    );

    let res = match serde_json::to_string(credential_signature) {
        Ok(credential_signature_json) => {
            trace!(
                "ursa_cl_credential_signature_to_json: credential_signature_json: {:?}",
                secret!(&credential_signature_json)
            );
            unsafe {
                let credential_signature_json = string_to_cstring(credential_signature_json);
                *credential_signature_json_p = credential_signature_json.into_raw();
                trace!(
                    "ursa_cl_credential_signature_to_json: credential_signature_json_p: {:?}",
                    *credential_signature_json_p
                );
            }
            ErrorCode::Success
        }
        Err(err) => err
            .to_ursa(
                UrsaCryptoErrorKind::InvalidState,
                "Unable to serialize credential signature as json",
            )
            .into(),
    };

    trace!("ursa_cl_credential_signature_to_json: <<< res: {:?}", res);
    res
}

/// Creates and returns credential signature from json.
///
/// Note: Credential signature instance deallocation must be performed
/// by calling ursa_cl_credential_signature_free
///
/// # Arguments
/// * `credential_signature_json` - Reference that contains credential signature json.
/// * `credential_signature_p` - Reference that will contain credential signature instance pointer.
#[no_mangle]
pub extern "C" fn ursa_cl_credential_signature_from_json(
    credential_signature_json: *const c_char,
    credential_signature_p: *mut *const c_void,
) -> ErrorCode {
    trace!("ursa_cl_credential_signature_from_json: >>> credential_signature_json: {:?}, credential_signature_p: {:?}",
           credential_signature_json, credential_signature_p);

    check_useful_c_str!(credential_signature_json, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(credential_signature_p, ErrorCode::CommonInvalidParam2);

    trace!(
        "ursa_cl_credential_signature_from_json: entity: credential_signature_json: {:?}",
        secret!(&credential_signature_json)
    );

    let res = match serde_json::from_str::<CredentialSignature>(&credential_signature_json) {
        Ok(credential_signature) => {
            trace!(
                "ursa_cl_credential_signature_from_json: credential_signature: {:?}",
                secret!(&credential_signature)
            );
            unsafe {
                *credential_signature_p =
                    Box::into_raw(Box::new(credential_signature)) as *const c_void;
                trace!(
                    "ursa_cl_credential_signature_from_json: *credential_signature_p: {:?}",
                    *credential_signature_p
                );
            }
            ErrorCode::Success
        }
        Err(err) => err
            .to_ursa(
                UrsaCryptoErrorKind::InvalidStructure,
                "Unable to deserialize credential signature from json",
            )
            .into(),
    };

    trace!("ursa_cl_credential_signature_from_json: <<< res: {:?}", res);
    res
}

/// Deallocates credential signature signature instance.
///
/// # Arguments
/// * `credential_signature` - Reference that contains credential signature instance pointer.
#[no_mangle]
pub extern "C" fn ursa_cl_credential_signature_free(
    credential_signature: *const c_void,
) -> ErrorCode {
    trace!(
        "ursa_cl_credential_signature_free: >>> credential_signature: {:?}",
        credential_signature
    );

    check_useful_c_ptr!(credential_signature, ErrorCode::CommonInvalidParam1);

    let _credential_signature =
        unsafe { Box::from_raw(credential_signature as *mut CredentialSignature) };
    trace!(
        "ursa_cl_credential_signature_free: entity: credential_signature: {:?}",
        secret!(_credential_signature)
    );
    let res = ErrorCode::Success;

    trace!("ursa_cl_credential_signature_free: <<< res: {:?}", res);
    res
}

/// Returns json representation of signature correctness proof.
///
/// # Arguments
/// * `signature_correctness_proof` - Reference that contains signature correctness proof instance pointer.
/// * `signature_correctness_proof_json_p` - Reference that will contain signature correctness proof json.
#[no_mangle]
pub extern "C" fn ursa_cl_signature_correctness_proof_to_json(
    signature_correctness_proof: *const c_void,
    signature_correctness_proof_json_p: *mut *const c_char,
) -> ErrorCode {
    trace!("ursa_cl_signature_correctness_proof_to_json: >>> signature_correctness_proof: {:?}, signature_correctness_proof_json_p: {:?}",
           signature_correctness_proof, signature_correctness_proof_json_p);

    check_useful_c_reference!(
        signature_correctness_proof,
        SignatureCorrectnessProof,
        ErrorCode::CommonInvalidParam1
    );
    check_useful_c_ptr!(
        signature_correctness_proof_json_p,
        ErrorCode::CommonInvalidParam2
    );

    trace!(
        "ursa_cl_signature_correctness_proof_to_json: entity >>> signature_correctness_proof: {:?}",
        signature_correctness_proof
    );

    let res = match serde_json::to_string(signature_correctness_proof) {
        Ok(signature_correctness_proof_json) => {
            trace!("ursa_cl_signature_correctness_proof_to_json: signature_correctness_proof_json: {:?}", signature_correctness_proof_json);
            unsafe {
                let signature_correctness_proof_json =
                    string_to_cstring(signature_correctness_proof_json);
                *signature_correctness_proof_json_p = signature_correctness_proof_json.into_raw();
                trace!("ursa_cl_signature_correctness_proof_to_json: signature_correctness_proof_json_p: {:?}", *signature_correctness_proof_json_p);
            }
            ErrorCode::Success
        }
        Err(err) => err
            .to_ursa(
                UrsaCryptoErrorKind::InvalidState,
                "Unable to serialize signature correctness proof as json",
            )
            .into(),
    };

    trace!(
        "ursa_cl_signature_correctness_proof_to_json: <<< res: {:?}",
        res
    );
    res
}

/// Creates and returns signature correctness proof from json.
///
/// Note: Signature correctness proof instance deallocation must be performed
/// by calling ursa_cl_signature_correctness_proof_free
///
/// # Arguments
/// * `signature_correctness_proof_json` - Reference that contains signature correctness proof json.
/// * `signature_correctness_proof_p` - Reference that will contain signature correctness proof instance pointer.
#[no_mangle]
pub extern "C" fn ursa_cl_signature_correctness_proof_from_json(
    signature_correctness_proof_json: *const c_char,
    signature_correctness_proof_p: *mut *const c_void,
) -> ErrorCode {
    trace!("ursa_cl_signature_correctness_proof_from_json: >>> signature_correctness_proof_json: {:?}, signature_correctness_proof_p: {:?}",
           signature_correctness_proof_json, signature_correctness_proof_p);

    check_useful_c_str!(
        signature_correctness_proof_json,
        ErrorCode::CommonInvalidParam1
    );
    check_useful_c_ptr!(
        signature_correctness_proof_p,
        ErrorCode::CommonInvalidParam2
    );

    trace!("ursa_cl_signature_correctness_proof_from_json: entity: signature_correctness_proof_json: {:?}", signature_correctness_proof_json);

    let res = match serde_json::from_str::<SignatureCorrectnessProof>(
        &signature_correctness_proof_json,
    ) {
        Ok(signature_correctness_proof) => {
            trace!(
                "ursa_cl_signature_correctness_proof_from_json: signature_correctness_proof: {:?}",
                signature_correctness_proof
            );
            unsafe {
                *signature_correctness_proof_p =
                    Box::into_raw(Box::new(signature_correctness_proof)) as *const c_void;
                trace!("ursa_cl_signature_correctness_proof_from_json: *signature_correctness_proof_p: {:?}", *signature_correctness_proof_p);
            }
            ErrorCode::Success
        }
        Err(err) => err
            .to_ursa(
                UrsaCryptoErrorKind::InvalidStructure,
                "Unable to deserialize signature correctness proof from json",
            )
            .into(),
    };

    trace!(
        "ursa_cl_signature_correctness_proof_from_json: <<< res: {:?}",
        res
    );
    res
}

/// Deallocates signature correctness proof instance.
///
/// # Arguments
/// * `signature_correctness_proof` - Reference that contains signature correctness proof instance pointer.
#[no_mangle]
pub extern "C" fn ursa_cl_signature_correctness_proof_free(
    signature_correctness_proof: *const c_void,
) -> ErrorCode {
    trace!(
        "ursa_cl_signature_correctness_proof_free: >>> signature_correctness_proof: {:?}",
        signature_correctness_proof
    );

    check_useful_c_ptr!(signature_correctness_proof, ErrorCode::CommonInvalidParam1);

    let signature_correctness_proof =
        unsafe { Box::from_raw(signature_correctness_proof as *mut SignatureCorrectnessProof) };
    trace!(
        "ursa_cl_signature_correctness_proof_free: entity: signature_correctness_proof: {:?}",
        signature_correctness_proof
    );
    let res = ErrorCode::Success;

    trace!(
        "ursa_cl_signature_correctness_proof_free: <<< res: {:?}",
        res
    );
    res
}

/// Returns json representation of revocation registry delta.
///
/// # Arguments
/// * `revocation_registry_delta` - Reference that contains revocation registry delta instance pointer.
/// * `revocation_registry_delta_json_p` - Reference that will contain revocation registry delta json.
#[no_mangle]
pub extern "C" fn ursa_cl_revocation_registry_delta_to_json(
    revocation_registry_delta: *const c_void,
    revocation_registry_delta_json_p: *mut *const c_char,
) -> ErrorCode {
    trace!("ursa_cl_revocation_registry_delta_to_json: >>> revocation_registry_delta: {:?}, revocation_registry_delta_json_p: {:?}",
           revocation_registry_delta, revocation_registry_delta_json_p);

    check_useful_c_reference!(
        revocation_registry_delta,
        SignatureCorrectnessProof,
        ErrorCode::CommonInvalidParam1
    );
    check_useful_c_ptr!(
        revocation_registry_delta_json_p,
        ErrorCode::CommonInvalidParam2
    );

    trace!(
        "ursa_cl_revocation_registry_delta_to_json: entity >>> revocation_registry_delta: {:?}",
        revocation_registry_delta
    );

    let res = match serde_json::to_string(revocation_registry_delta) {
        Ok(revocation_registry_delta_json) => {
            trace!(
                "ursa_cl_revocation_registry_delta_to_json: revocation_registry_delta_json: {:?}",
                revocation_registry_delta_json
            );
            unsafe {
                let revocation_registry_delta_json =
                    string_to_cstring(revocation_registry_delta_json);
                *revocation_registry_delta_json_p = revocation_registry_delta_json.into_raw();
                trace!("ursa_cl_revocation_registry_delta_to_json: revocation_registry_delta_json_p: {:?}", *revocation_registry_delta_json_p);
            }
            ErrorCode::Success
        }
        Err(err) => err
            .to_ursa(
                UrsaCryptoErrorKind::InvalidState,
                "Unable to serialize revocation registry delta as json",
            )
            .into(),
    };

    trace!(
        "ursa_cl_revocation_registry_delta_to_json: <<< res: {:?}",
        res
    );
    res
}

/// Creates and returns revocation registry delta from json.
///
/// Note: Revocation registry delta instance deallocation must be performed
/// by calling ursa_cl_revocation_registry_delta_free
///
/// # Arguments
/// * `revocation_registry_delta_json` - Reference that contains revocation registry delta json.
/// * `revocation_registry_delta_p` - Reference that will contain revocation registry delta instance pointer.
#[no_mangle]
pub extern "C" fn ursa_cl_revocation_registry_delta_from_json(
    revocation_registry_delta_json: *const c_char,
    revocation_registry_delta_p: *mut *const c_void,
) -> ErrorCode {
    trace!("ursa_cl_revocation_registry_delta_from_json: >>> revocation_registry_delta_json: {:?}, revocation_registry_delta_p: {:?}",
           revocation_registry_delta_json, revocation_registry_delta_p);

    check_useful_c_str!(
        revocation_registry_delta_json,
        ErrorCode::CommonInvalidParam1
    );
    check_useful_c_ptr!(revocation_registry_delta_p, ErrorCode::CommonInvalidParam2);

    trace!(
        "ursa_cl_revocation_registry_delta_from_json: entity: revocation_registry_delta_json: {:?}",
        revocation_registry_delta_json
    );

    let res = match serde_json::from_str::<SignatureCorrectnessProof>(
        &revocation_registry_delta_json,
    ) {
        Ok(revocation_registry_delta) => {
            trace!(
                "ursa_cl_revocation_registry_delta_from_json: revocation_registry_delta: {:?}",
                revocation_registry_delta
            );
            unsafe {
                *revocation_registry_delta_p =
                    Box::into_raw(Box::new(revocation_registry_delta)) as *const c_void;
                trace!("ursa_cl_revocation_registry_delta_from_json: *revocation_registry_delta_p: {:?}", *revocation_registry_delta_p);
            }
            ErrorCode::Success
        }
        Err(err) => err
            .to_ursa(
                UrsaCryptoErrorKind::InvalidStructure,
                "Unable to deserialize revocation registry delta from json",
            )
            .into(),
    };

    trace!(
        "ursa_cl_revocation_registry_delta_from_json: <<< res: {:?}",
        res
    );
    res
}

/// Deallocates revocation registry delta instance.
///
/// # Arguments
/// * `revocation_registry_delta` - Reference that contains revocation registry delta instance pointer.
#[no_mangle]
pub extern "C" fn ursa_cl_revocation_registry_delta_free(
    revocation_registry_delta: *const c_void,
) -> ErrorCode {
    trace!(
        "ursa_cl_revocation_registry_delta_free: >>> revocation_registry_delta: {:?}",
        revocation_registry_delta
    );

    check_useful_c_ptr!(revocation_registry_delta, ErrorCode::CommonInvalidParam1);

    let revocation_registry_delta =
        unsafe { Box::from_raw(revocation_registry_delta as *mut RevocationRegistryDelta) };
    trace!(
        "ursa_cl_revocation_registry_delta_free: entity: revocation_registry_delta: {:?}",
        revocation_registry_delta
    );
    let res = ErrorCode::Success;

    trace!("ursa_cl_revocation_registry_delta_free: <<< res: {:?}", res);
    res
}

#[no_mangle]
pub extern "C" fn ursa_revocation_registry_delta_from_parts(
    rev_reg_from: *const c_void,
    rev_reg_to: *const c_void,
    issued: *const u32,
    issued_len: usize,
    revoked: *const u32,
    revoked_len: usize,
    rev_reg_delta_p: *mut *const c_void,
) -> ErrorCode {
    trace!("ursa_revocation_registry_delta_from_parts: >>> rev_reg_from: {:?}, rev_reg_to: {:?}, issued: {:?},\
     issued_len: {:?}, revoked: {:?}, revoked_len: {:?}, rev_reg_delta_p: {:?}",
           rev_reg_from, rev_reg_to, issued, issued_len, revoked, revoked_len, rev_reg_delta_p);

    check_useful_opt_c_reference!(rev_reg_from, RevocationRegistry);
    check_useful_c_reference!(
        rev_reg_to,
        RevocationRegistry,
        ErrorCode::CommonInvalidParam2
    );
    check_useful_hashset!(
        issued,
        issued_len,
        ErrorCode::CommonInvalidParam3,
        ErrorCode::CommonInvalidParam4
    );
    check_useful_hashset!(
        revoked,
        revoked_len,
        ErrorCode::CommonInvalidParam5,
        ErrorCode::CommonInvalidParam6
    );

    trace!("ursa_revocation_registry_delta_from_parts: >>> rev_reg_from: {:?}, rev_reg_to: {:?}, issued: {:?}, revoked: {:?}",
           rev_reg_from, rev_reg_to, issued, revoked);

    let rev_reg_delta =
        RevocationRegistryDelta::from_parts(rev_reg_from, rev_reg_to, &issued, &revoked);

    trace!(
        "ursa_revocation_registry_delta_from_parts: rev_reg_delta: {:?}",
        rev_reg_delta
    );

    unsafe {
        *rev_reg_delta_p = Box::into_raw(Box::new(rev_reg_delta)) as *const c_void;
        trace!(
            "ursa_revocation_registry_delta_from_parts: *rev_reg_delta_p: {:?}",
            *rev_reg_delta_p
        );
    }

    let res = ErrorCode::Success;

    trace!(
        "ursa_revocation_registry_delta_from_parts: <<< res: {:?}",
        res
    );
    res
}

/// Revokes a credential by a rev_idx in a given revocation registry.
///
/// # Arguments
/// * `rev_reg` - Reference that contain revocation registry instance pointer.
///  * max_cred_num` - Max credential number in revocation registry.
///  * rev_idx` - Index of the user in the revocation registry.
#[no_mangle]
#[allow(unused_variables)]
pub extern "C" fn ursa_cl_issuer_revoke_credential(
    rev_reg: *const c_void,
    max_cred_num: u32,
    rev_idx: u32,
    ctx_tails: *const c_void,
    take_tail: FFITailTake,
    put_tail: FFITailPut,
    rev_reg_delta_p: *mut *const c_void,
) -> ErrorCode {
    trace!("ursa_cl_issuer_revoke_credential: >>> rev_reg: {:?}, max_cred_num: {:?}, rev_idx: {:?}, ctx_tails {:?}, take_tail {:?}, \
    put_tail {:?}, rev_reg_delta_p {:?}", rev_reg, max_cred_num, rev_idx, ctx_tails, take_tail, put_tail, rev_reg_delta_p);

    check_useful_mut_c_reference!(rev_reg, RevocationRegistry, ErrorCode::CommonInvalidParam1);

    trace!(
        "ursa_cl_issuer_revoke_credential: entities: rev_reg: {:?}",
        secret!(&rev_reg)
    );

    let rta = FFITailsAccessor::new(ctx_tails, take_tail, put_tail);
    let res = match Issuer::revoke_credential(rev_reg, max_cred_num, rev_idx, &rta) {
        Ok(rev_reg_delta) => {
            unsafe {
                *rev_reg_delta_p = Box::into_raw(Box::new(rev_reg_delta)) as *const c_void;
                trace!(
                    "ursa_cl_issuer_revoke_credential: *rev_reg_delta_p: {:?}",
                    *rev_reg_delta_p
                );
            }
            ErrorCode::Success
        }
        Err(err) => err.into(),
    };

    trace!("ursa_cl_issuer_revoke_credential: <<< res: {:?}", res);
    res
}

/// Recovery a credential by a rev_idx in a given revocation registry
///
/// # Arguments
/// * `rev_reg` - Reference that contain revocation registry instance pointer.
///  * max_cred_num` - Max credential number in revocation registry.
///  * rev_idx` - Index of the user in the revocation registry.
#[no_mangle]
#[allow(unused_variables)]
pub extern "C" fn ursa_cl_issuer_recovery_credential(
    rev_reg: *const c_void,
    max_cred_num: u32,
    rev_idx: u32,
    ctx_tails: *const c_void,
    take_tail: FFITailTake,
    put_tail: FFITailPut,
    rev_reg_delta_p: *mut *const c_void,
) -> ErrorCode {
    trace!("ursa_cl_issuer_recovery_credential: >>> rev_reg: {:?}, max_cred_num: {:?}, rev_idx: {:?}, ctx_tails {:?}, take_tail {:?}, \
    put_tail {:?}, rev_reg_delta_p {:?}", rev_reg, max_cred_num, rev_idx, ctx_tails, take_tail, put_tail, rev_reg_delta_p);

    check_useful_mut_c_reference!(rev_reg, RevocationRegistry, ErrorCode::CommonInvalidParam1);

    trace!(
        "ursa_cl_issuer_recovery_credential: entities: rev_reg: {:?}",
        rev_reg
    );

    let rta = FFITailsAccessor::new(ctx_tails, take_tail, put_tail);
    let res = match Issuer::recovery_credential(rev_reg, max_cred_num, rev_idx, &rta) {
        Ok(rev_reg_delta) => {
            unsafe {
                *rev_reg_delta_p = Box::into_raw(Box::new(rev_reg_delta)) as *const c_void;
                trace!(
                    "ursa_cl_issuer_recovery_credential: *rev_reg_delta_p: {:?}",
                    *rev_reg_delta_p
                );
            }
            ErrorCode::Success
        }
        Err(err) => err.into(),
    };

    trace!("ursa_cl_issuer_recovery_credential: <<< res: {:?}", res);
    res
}

#[no_mangle]
pub extern "C" fn ursa_cl_issuer_merge_revocation_registry_deltas(
    revoc_reg_delta: *const c_void,
    other_revoc_reg_delta: *const c_void,
    merged_revoc_reg_delta_p: *mut *const c_void,
) -> ErrorCode {
    trace!("ursa_cl_issuer_merge_revocation_registry_deltas: >>> revoc_reg_delta: {:?}, other_revoc_reg_delta: {:?}",
           revoc_reg_delta, other_revoc_reg_delta);

    check_useful_mut_c_reference!(
        revoc_reg_delta,
        RevocationRegistryDelta,
        ErrorCode::CommonInvalidParam1
    );
    check_useful_c_reference!(
        other_revoc_reg_delta,
        RevocationRegistryDelta,
        ErrorCode::CommonInvalidParam2
    );

    trace!("ursa_cl_issuer_merge_revocation_registry_deltas: entities: revoc_reg_delta: {:?}, other_revoc_reg_delta: {:?}",
           revoc_reg_delta, other_revoc_reg_delta);

    let res = match revoc_reg_delta.merge(other_revoc_reg_delta) {
        Ok(_) => {
            trace!("ursa_cl_issuer_merge_revocation_registry_deltas: merged_revoc_reg_delta: ()");
            unsafe {
                *merged_revoc_reg_delta_p = Box::into_raw(Box::new(())) as *const c_void;
                trace!("ursa_cl_issuer_merge_revocation_registry_deltas: *merged_revoc_reg_delta_p: {:?}", *merged_revoc_reg_delta_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.into(),
    };

    trace!(
        "ursa_cl_issuer_merge_revocation_registry_deltas: <<< res: {:?}",
        res
    );
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    use ffi::cl::issuer::mocks::*;
    use ffi::cl::mocks::*;
    use ffi::cl::prover::mocks::*;
    use std::ptr;

    #[test]
    fn ursa_cl_issuer_new_credential_def_works() {
        let credential_schema = _credential_schema();
        let non_credential_schema = _non_credential_schema();
        let mut credential_pub_key: *const c_void = ptr::null();
        let mut credential_priv_key: *const c_void = ptr::null();
        let mut credential_key_correctness_proof: *const c_void = ptr::null();

        let err_code = ursa_cl_issuer_new_credential_def(
            credential_schema,
            non_credential_schema,
            true,
            &mut credential_pub_key,
            &mut credential_priv_key,
            &mut credential_key_correctness_proof,
        );

        assert_eq!(err_code, ErrorCode::Success);
        assert!(!credential_pub_key.is_null());
        assert!(!credential_priv_key.is_null());
        assert!(!credential_key_correctness_proof.is_null());

        _free_credential_schema(credential_schema);
        _free_non_credential_schema(non_credential_schema);
        _free_credential_def(
            credential_pub_key,
            credential_priv_key,
            credential_key_correctness_proof,
        );
    }

    #[test]
    fn ursa_cl_credential_public_key_to_json_works() {
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
            _credential_def();

        let mut credential_pub_key_json_p: *const c_char = ptr::null();
        let err_code = ursa_cl_credential_public_key_to_json(
            credential_pub_key,
            &mut credential_pub_key_json_p,
        );
        assert_eq!(err_code, ErrorCode::Success);

        _free_credential_def(
            credential_pub_key,
            credential_priv_key,
            credential_key_correctness_proof,
        );
    }

    #[test]
    fn ursa_cl_credential_public_key_from_json_works() {
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
            _credential_def();

        let mut credential_pub_key_json_p: *const c_char = ptr::null();
        let err_code = ursa_cl_credential_public_key_to_json(
            credential_pub_key,
            &mut credential_pub_key_json_p,
        );
        assert_eq!(err_code, ErrorCode::Success);

        let mut credential_pub_key_p: *const c_void = ptr::null();
        let err_code = ursa_cl_credential_public_key_from_json(
            credential_pub_key_json_p,
            &mut credential_pub_key_p,
        );
        assert_eq!(err_code, ErrorCode::Success);

        _free_credential_def(
            credential_pub_key,
            credential_priv_key,
            credential_key_correctness_proof,
        );
    }

    #[test]
    fn ursa_cl_credential_private_key_to_json_works() {
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
            _credential_def();

        let mut credential_priv_key_json_p: *const c_char = ptr::null();
        let err_code = ursa_cl_credential_private_key_to_json(
            credential_priv_key,
            &mut credential_priv_key_json_p,
        );
        assert_eq!(err_code, ErrorCode::Success);

        _free_credential_def(
            credential_pub_key,
            credential_priv_key,
            credential_key_correctness_proof,
        );
    }

    #[test]
    fn ursa_cl_credential_private_key_from_json_works() {
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
            _credential_def();

        let mut credential_priv_key_json_p: *const c_char = ptr::null();
        let err_code = ursa_cl_credential_private_key_to_json(
            credential_priv_key,
            &mut credential_priv_key_json_p,
        );
        assert_eq!(err_code, ErrorCode::Success);

        let mut credential_priv_key_p: *const c_void = ptr::null();
        let err_code = ursa_cl_credential_private_key_from_json(
            credential_priv_key_json_p,
            &mut credential_priv_key_p,
        );
        assert_eq!(err_code, ErrorCode::Success);

        _free_credential_def(
            credential_pub_key,
            credential_priv_key,
            credential_key_correctness_proof,
        );
    }

    #[test]
    fn ursa_cl_credential_key_correctness_proof_to_json_works() {
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
            _credential_def();

        let mut credential_key_correctness_proof_json_p: *const c_char = ptr::null();
        let err_code = ursa_cl_credential_key_correctness_proof_to_json(
            credential_key_correctness_proof,
            &mut credential_key_correctness_proof_json_p,
        );
        assert_eq!(err_code, ErrorCode::Success);

        _free_credential_def(
            credential_pub_key,
            credential_priv_key,
            credential_key_correctness_proof,
        );
    }

    #[test]
    fn ursa_cl_issuer_key_correctness_proof_from_json_works() {
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
            _credential_def();

        let mut credential_key_correctness_proof_json_p: *const c_char = ptr::null();
        let err_code = ursa_cl_credential_key_correctness_proof_to_json(
            credential_key_correctness_proof,
            &mut credential_key_correctness_proof_json_p,
        );
        assert_eq!(err_code, ErrorCode::Success);

        let mut credential_key_correctness_proof_p: *const c_void = ptr::null();
        let err_code = ursa_cl_credential_key_correctness_proof_from_json(
            credential_key_correctness_proof_json_p,
            &mut credential_key_correctness_proof_p,
        );
        assert_eq!(err_code, ErrorCode::Success);

        _free_credential_def(
            credential_pub_key,
            credential_priv_key,
            credential_key_correctness_proof,
        );
    }

    #[test]
    fn ursa_cl_credential_def_free_works() {
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
            _credential_def();

        let err_code = ursa_cl_credential_public_key_free(credential_pub_key);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_cl_credential_private_key_free(credential_priv_key);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code =
            ursa_cl_credential_key_correctness_proof_free(credential_key_correctness_proof);
        assert_eq!(err_code, ErrorCode::Success);
    }

    #[test]
    fn ursa_cl_issuer_new_revocation_registry_def_works() {
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
            _credential_def();
        let mut rev_key_pub_p: *const c_void = ptr::null();
        let mut rev_key_priv_p: *const c_void = ptr::null();
        let mut rev_reg_p: *const c_void = ptr::null();
        let mut rev_tails_generator_p: *const c_void = ptr::null();

        let err_code = ursa_cl_issuer_new_revocation_registry_def(
            credential_pub_key,
            100,
            false,
            &mut rev_key_pub_p,
            &mut rev_key_priv_p,
            &mut rev_reg_p,
            &mut rev_tails_generator_p,
        );
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!rev_key_pub_p.is_null());
        assert!(!rev_key_priv_p.is_null());
        assert!(!rev_reg_p.is_null());
        assert!(!rev_tails_generator_p.is_null());

        _free_credential_def(
            credential_pub_key,
            credential_priv_key,
            credential_key_correctness_proof,
        );
        _free_revocation_registry_def(
            rev_key_pub_p,
            rev_key_priv_p,
            rev_reg_p,
            rev_tails_generator_p,
        );
    }

    #[test]
    fn ursa_cl_revocation_key_public_to_json_works() {
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
            _credential_def();
        let (rev_key_pub, rev_key_priv, rev_reg, rev_tails_generator) =
            _revocation_registry_def(credential_pub_key);

        let mut rev_key_pub_json_p: *const c_char = ptr::null();
        let err_code = ursa_cl_revocation_key_public_to_json(rev_key_pub, &mut rev_key_pub_json_p);
        assert_eq!(err_code, ErrorCode::Success);

        _free_credential_def(
            credential_pub_key,
            credential_priv_key,
            credential_key_correctness_proof,
        );
        _free_revocation_registry_def(rev_key_pub, rev_key_priv, rev_reg, rev_tails_generator);
    }

    #[test]
    fn ursa_cl_revocation_key_public_from_json_works() {
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
            _credential_def();
        let (rev_key_pub, rev_key_priv, rev_reg, rev_tails_generator) =
            _revocation_registry_def(credential_pub_key);

        let mut rev_key_pub_json_p: *const c_char = ptr::null();
        let err_code = ursa_cl_revocation_key_public_to_json(rev_key_pub, &mut rev_key_pub_json_p);
        assert_eq!(err_code, ErrorCode::Success);

        let mut rev_key_pub_p: *const c_void = ptr::null();
        let err_code =
            ursa_cl_revocation_key_public_from_json(rev_key_pub_json_p, &mut rev_key_pub_p);
        assert_eq!(err_code, ErrorCode::Success);

        _free_credential_def(
            credential_pub_key,
            credential_priv_key,
            credential_key_correctness_proof,
        );
        _free_revocation_registry_def(rev_key_pub, rev_key_priv, rev_reg, rev_tails_generator);
    }

    #[test]
    fn ursa_cl_revocation_key_private_to_json_works() {
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
            _credential_def();
        let (rev_key_pub, rev_key_priv, rev_reg, rev_tails_generator) =
            _revocation_registry_def(credential_pub_key);

        let mut rev_key_priv_json_p: *const c_char = ptr::null();
        let err_code =
            ursa_cl_revocation_key_private_to_json(rev_key_priv, &mut rev_key_priv_json_p);
        assert_eq!(err_code, ErrorCode::Success);

        _free_credential_def(
            credential_pub_key,
            credential_priv_key,
            credential_key_correctness_proof,
        );
        _free_revocation_registry_def(rev_key_pub, rev_key_priv, rev_reg, rev_tails_generator);
    }

    #[test]
    fn ursa_cl_revocation_key_private_from_json_works() {
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
            _credential_def();
        let (rev_key_pub, rev_key_priv, rev_reg, rev_tails_generator) =
            _revocation_registry_def(credential_pub_key);

        let mut rev_key_priv_json_p: *const c_char = ptr::null();
        let err_code =
            ursa_cl_revocation_key_private_to_json(rev_key_priv, &mut rev_key_priv_json_p);
        assert_eq!(err_code, ErrorCode::Success);

        let mut rev_key_priv_p: *const c_void = ptr::null();
        let err_code =
            ursa_cl_revocation_key_private_from_json(rev_key_priv_json_p, &mut rev_key_priv_p);
        assert_eq!(err_code, ErrorCode::Success);

        _free_credential_def(
            credential_pub_key,
            credential_priv_key,
            credential_key_correctness_proof,
        );
        _free_revocation_registry_def(rev_key_pub, rev_key_priv, rev_reg, rev_tails_generator);
    }

    #[test]
    fn ursa_cl_revocation_registry_to_json_works() {
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
            _credential_def();
        let (rev_key_pub, rev_key_priv, rev_reg, rev_tails_generator) =
            _revocation_registry_def(credential_pub_key);

        let mut rev_reg_json_p: *const c_char = ptr::null();
        let err_code = ursa_cl_revocation_registry_to_json(rev_reg, &mut rev_reg_json_p);
        assert_eq!(err_code, ErrorCode::Success);

        _free_credential_def(
            credential_pub_key,
            credential_priv_key,
            credential_key_correctness_proof,
        );
        _free_revocation_registry_def(rev_key_pub, rev_key_priv, rev_reg, rev_tails_generator);
    }

    #[test]
    fn ursa_cl_revocation_registry_from_json_works() {
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
            _credential_def();
        let (rev_key_pub, rev_key_priv, rev_reg, rev_tails_generator) =
            _revocation_registry_def(credential_pub_key);

        let mut rev_reg_json_p: *const c_char = ptr::null();
        let err_code = ursa_cl_revocation_registry_to_json(rev_reg, &mut rev_reg_json_p);
        assert_eq!(err_code, ErrorCode::Success);

        let mut rev_reg_p: *const c_void = ptr::null();
        let err_code = ursa_cl_revocation_registry_from_json(rev_reg_json_p, &mut rev_reg_p);
        assert_eq!(err_code, ErrorCode::Success);

        _free_credential_def(
            credential_pub_key,
            credential_priv_key,
            credential_key_correctness_proof,
        );
        _free_revocation_registry_def(rev_key_pub, rev_key_priv, rev_reg, rev_tails_generator);
    }

    #[test]
    fn ursa_cl_revocation_tails_generator_to_json_works() {
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
            _credential_def();
        let (rev_key_pub, rev_key_priv, rev_reg, rev_tails_generator) =
            _revocation_registry_def(credential_pub_key);

        let mut rev_tails_generator_json_p: *const c_char = ptr::null();
        let err_code = ursa_cl_revocation_tails_generator_to_json(
            rev_tails_generator,
            &mut rev_tails_generator_json_p,
        );
        assert_eq!(err_code, ErrorCode::Success);

        _free_credential_def(
            credential_pub_key,
            credential_priv_key,
            credential_key_correctness_proof,
        );
        _free_revocation_registry_def(rev_key_pub, rev_key_priv, rev_reg, rev_tails_generator);
    }

    #[test]
    fn ursa_cl_revocation_tails_generator_from_json_works() {
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
            _credential_def();
        let (rev_key_pub, rev_key_priv, rev_reg, rev_tails_generator) =
            _revocation_registry_def(credential_pub_key);

        let mut rev_tails_generator_json_p: *const c_char = ptr::null();
        let err_code = ursa_cl_revocation_tails_generator_to_json(
            rev_tails_generator,
            &mut rev_tails_generator_json_p,
        );
        assert_eq!(err_code, ErrorCode::Success);

        let mut rev_tails_generator_p: *const c_void = ptr::null();
        let err_code = ursa_cl_revocation_tails_generator_from_json(
            rev_tails_generator_json_p,
            &mut rev_tails_generator_p,
        );
        assert_eq!(err_code, ErrorCode::Success);

        _free_credential_def(
            credential_pub_key,
            credential_priv_key,
            credential_key_correctness_proof,
        );
        _free_revocation_registry_def(rev_key_pub, rev_key_priv, rev_reg, rev_tails_generator);
    }

    #[test]
    fn ursa_cl_revocation_registry_def_free_works() {
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
            _credential_def();
        let (rev_key_pub, rev_key_priv, rev_reg, rev_tails_generator) =
            _revocation_registry_def(credential_pub_key);

        let err_code = ursa_cl_revocation_key_public_free(rev_key_pub);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_cl_revocation_key_private_free(rev_key_priv);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_cl_revocation_registry_free(rev_reg);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_cl_revocation_tails_generator_free(rev_tails_generator);
        assert_eq!(err_code, ErrorCode::Success);

        _free_credential_def(
            credential_pub_key,
            credential_priv_key,
            credential_key_correctness_proof,
        );
    }

    #[test]
    fn ursa_cl_issuer_sign_credential_with_revoc_works() {
        let prover_id = _prover_did();
        let credential_values = _credential_values();
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
            _credential_def();
        let (rev_key_pub, rev_key_priv, rev_reg, rev_tails_generator) =
            _revocation_registry_def(credential_pub_key);
        let credential_nonce = _nonce();
        let credential_issuance_nonce = _nonce();
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
        let rev_idx = 1;
        let max_cred_num = 5;
        let issuance_by_default = false;

        let tail_storage = FFISimpleTailStorage::new(rev_tails_generator);

        let mut credential_signature_p: *const c_void = ptr::null();
        let mut credential_signature_correctness_proof_p: *const c_void = ptr::null();
        let mut revocation_registry_delta_p: *const c_void = ptr::null();
        let err_code = ursa_cl_issuer_sign_credential_with_revoc(
            prover_id.as_ptr(),
            blinded_credential_secrets,
            blinded_credential_secrets_correctness_proof,
            credential_nonce,
            credential_issuance_nonce,
            credential_values,
            credential_pub_key,
            credential_priv_key,
            rev_idx,
            max_cred_num,
            issuance_by_default,
            rev_reg,
            rev_key_priv,
            tail_storage.get_ctx(),
            FFISimpleTailStorage::tail_take,
            FFISimpleTailStorage::tail_put,
            &mut credential_signature_p,
            &mut credential_signature_correctness_proof_p,
            &mut revocation_registry_delta_p,
        );
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!credential_signature_p.is_null());
        assert!(!credential_signature_correctness_proof_p.is_null());
        assert!(!revocation_registry_delta_p.is_null());

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
        _free_credential_signature_with_revoc(
            credential_signature_p,
            credential_signature_correctness_proof_p,
            revocation_registry_delta_p,
        );
    }

    #[test]
    fn ursa_cl_issuer_sign_credential_works() {
        let prover_id = _prover_did();
        let credential_values = _credential_values();
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
            _credential_def();
        let credential_nonce = _nonce();
        let credential_issuance_nonce = _nonce();
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

        let mut credential_signature_p: *const c_void = ptr::null();
        let mut credential_signature_correctness_proof_p: *const c_void = ptr::null();
        let err_code = ursa_cl_issuer_sign_credential(
            prover_id.as_ptr(),
            blinded_credential_secrets,
            blinded_credential_secrets_correctness_proof,
            credential_nonce,
            credential_issuance_nonce,
            credential_values,
            credential_pub_key,
            credential_priv_key,
            &mut credential_signature_p,
            &mut credential_signature_correctness_proof_p,
        );
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!credential_signature_p.is_null());
        assert!(!credential_signature_correctness_proof_p.is_null());

        _free_credential_def(
            credential_pub_key,
            credential_priv_key,
            credential_key_correctness_proof,
        );
        _free_credential_values(credential_values);
        _free_blinded_credential_secrets(
            blinded_credential_secrets,
            credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof,
        );
        _free_nonce(credential_nonce);
        _free_nonce(credential_issuance_nonce);
        _free_credential_signature(
            credential_signature_p,
            credential_signature_correctness_proof_p,
        );
    }

    #[test]
    fn ursa_cl_credential_signature_to_json_works() {
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

        let mut credential_signature_json_p: *const c_char = ptr::null();
        let err_code = ursa_cl_credential_signature_to_json(
            credential_signature,
            &mut credential_signature_json_p,
        );
        assert_eq!(err_code, ErrorCode::Success);

        _free_credential_def(
            credential_pub_key,
            credential_priv_key,
            credential_key_correctness_proof,
        );
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

    #[test]
    fn ursa_cl_credential_signature_from_json_works() {
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

        let mut credential_signature_json_p: *const c_char = ptr::null();
        let err_code = ursa_cl_credential_signature_to_json(
            credential_signature,
            &mut credential_signature_json_p,
        );
        assert_eq!(err_code, ErrorCode::Success);

        let mut credential_signature_p: *const c_void = ptr::null();
        let err_code = ursa_cl_credential_signature_from_json(
            credential_signature_json_p,
            &mut credential_signature_p,
        );
        assert_eq!(err_code, ErrorCode::Success);

        _free_credential_def(
            credential_pub_key,
            credential_priv_key,
            credential_key_correctness_proof,
        );
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

    #[test]
    fn ursa_cl_signature_correctness_proof_to_json_works() {
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

        let mut signature_correctness_proof_json_p: *const c_char = ptr::null();
        let err_code = ursa_cl_signature_correctness_proof_to_json(
            signature_correctness_proof,
            &mut signature_correctness_proof_json_p,
        );
        assert_eq!(err_code, ErrorCode::Success);

        _free_credential_def(
            credential_pub_key,
            credential_priv_key,
            credential_key_correctness_proof,
        );
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

    #[test]
    fn ursa_cl_signature_correctness_proof_from_json_works() {
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

        let mut signature_correctness_proof_json_p: *const c_char = ptr::null();
        let err_code = ursa_cl_signature_correctness_proof_to_json(
            signature_correctness_proof,
            &mut signature_correctness_proof_json_p,
        );
        assert_eq!(err_code, ErrorCode::Success);

        let mut signature_correctness_proof_p: *const c_void = ptr::null();
        let err_code = ursa_cl_signature_correctness_proof_from_json(
            signature_correctness_proof_json_p,
            &mut signature_correctness_proof_p,
        );
        assert_eq!(err_code, ErrorCode::Success);

        _free_credential_def(
            credential_pub_key,
            credential_priv_key,
            credential_key_correctness_proof,
        );
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

    #[test]
    fn ursa_cl_credential_signature_free_works() {
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
        let err_code = ursa_cl_credential_signature_free(credential_signature);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_cl_signature_correctness_proof_free(signature_correctness_proof);
        assert_eq!(err_code, ErrorCode::Success);

        _free_credential_def(
            credential_pub_key,
            credential_priv_key,
            credential_key_correctness_proof,
        );
        _free_credential_values(credential_values);
        _free_blinded_credential_secrets(
            blinded_credential_secrets,
            credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof,
        );
        _free_nonce(credential_nonce);
        _free_nonce(credential_issuance_nonce);
    }

    #[test]
    fn ursa_cl_issuer_revoke_credential_works() {
        let credential_values = _credential_values();
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
            _credential_def();
        let (rev_key_pub, rev_key_priv, rev_reg, rev_tails_generator) =
            _revocation_registry_def(credential_pub_key);
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

        let (credential_signature, signature_correctness_proof, revocation_registry_delta) =
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

        let mut revocation_registry_delta_p: *const c_void = ptr::null();

        let err_code = ursa_cl_issuer_revoke_credential(
            rev_reg,
            5,
            1,
            tail_storage.get_ctx(),
            FFISimpleTailStorage::tail_take,
            FFISimpleTailStorage::tail_put,
            &mut revocation_registry_delta_p,
        );
        assert_eq!(err_code, ErrorCode::Success);

        _free_credential_def(
            credential_pub_key,
            credential_priv_key,
            credential_key_correctness_proof,
        );
        _free_revocation_registry_def(rev_key_pub, rev_key_priv, rev_reg, rev_tails_generator);
        _free_blinded_credential_secrets(
            blinded_credential_secrets,
            credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof,
        );
        _free_nonce(credential_nonce);
        _free_nonce(credential_issuance_nonce);
        _free_credential_signature_with_revoc(
            credential_signature,
            signature_correctness_proof,
            revocation_registry_delta,
        );
    }

    #[test]
    fn ursa_cl_revocation_registry_delta_from_parts_works() {
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
            _credential_def();
        let (rev_key_pub, rev_key_priv, rev_reg, rev_tails_generator) =
            _revocation_registry_def(credential_pub_key);

        let rev_reg_from: *const c_void = ptr::null();

        let issued_h = vec![1];
        let issued = issued_h.as_ptr();
        let issued_len = issued_h.len();

        let revoked_h = vec![];
        let revoked = revoked_h.as_ptr();
        let revoked_len = revoked_h.len();

        let mut rev_reg_delta_p: *const c_void = ptr::null();

        let err_code = ursa_revocation_registry_delta_from_parts(
            rev_reg_from,
            rev_reg,
            issued,
            issued_len,
            revoked,
            revoked_len,
            &mut rev_reg_delta_p,
        );
        assert_eq!(err_code, ErrorCode::Success);

        _free_credential_def(
            credential_pub_key,
            credential_priv_key,
            credential_key_correctness_proof,
        );
        _free_revocation_registry_def(rev_key_pub, rev_key_priv, rev_reg, rev_tails_generator);
    }

    #[test]
    fn ursa_cl_issuer_merge_revoc_deltas_works() {
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

        let (credential_signature, signature_correctness_proof, revocation_registry_delta) =
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

        let mut revocation_registry_delta_p: *const c_void = ptr::null();

        let err_code = ursa_cl_issuer_revoke_credential(
            rev_reg,
            5,
            1,
            tail_storage.get_ctx(),
            FFISimpleTailStorage::tail_take,
            FFISimpleTailStorage::tail_put,
            &mut revocation_registry_delta_p,
        );
        assert_eq!(err_code, ErrorCode::Success);

        let mut merged_revocation_registry_delta_p: *const c_void = ptr::null();

        let err_code = ursa_cl_issuer_merge_revocation_registry_deltas(
            revocation_registry_delta,
            revocation_registry_delta_p,
            &mut merged_revocation_registry_delta_p,
        );
        assert_eq!(err_code, ErrorCode::Success);

        _free_credential_def(
            credential_pub_key,
            credential_priv_key,
            credential_key_correctness_proof,
        );
        _free_revocation_registry_def(rev_key_pub, rev_key_priv, rev_reg, rev_tails_generator);
        _free_blinded_credential_secrets(
            blinded_credential_secrets,
            credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof,
        );
        _free_credential_values(credential_values);
        _free_nonce(credential_nonce);
        _free_nonce(credential_issuance_nonce);
        _free_credential_signature_with_revoc(
            credential_signature,
            signature_correctness_proof,
            revocation_registry_delta,
        );
    }
}

#[cfg(test)]
pub mod mocks {
    use super::*;

    use ffi::cl::mocks::*;
    use std::ffi::CString;
    use std::ptr;

    pub fn _credential_def() -> (*const c_void, *const c_void, *const c_void) {
        let credential_schema = _credential_schema();
        let non_credential_schema = _non_credential_schema();

        let mut credential_pub_key: *const c_void = ptr::null();
        let mut credential_priv_key: *const c_void = ptr::null();
        let mut credential_key_correctness_proof: *const c_void = ptr::null();

        let err_code = ursa_cl_issuer_new_credential_def(
            credential_schema,
            non_credential_schema,
            true,
            &mut credential_pub_key,
            &mut credential_priv_key,
            &mut credential_key_correctness_proof,
        );
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!credential_pub_key.is_null());
        assert!(!credential_priv_key.is_null());
        assert!(!credential_key_correctness_proof.is_null());

        _free_credential_schema(credential_schema);
        _free_non_credential_schema(non_credential_schema);

        (
            credential_pub_key,
            credential_priv_key,
            credential_key_correctness_proof,
        )
    }

    pub fn _free_credential_def(
        credential_pub_key: *const c_void,
        credential_priv_key: *const c_void,
        credential_key_correctness_proof: *const c_void,
    ) {
        let err_code = ursa_cl_credential_public_key_free(credential_pub_key);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_cl_credential_private_key_free(credential_priv_key);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code =
            ursa_cl_credential_key_correctness_proof_free(credential_key_correctness_proof);
        assert_eq!(err_code, ErrorCode::Success);
    }

    pub fn _revocation_registry_def(
        credential_pub_key: *const c_void,
    ) -> (*const c_void, *const c_void, *const c_void, *const c_void) {
        let mut rev_key_pub_p: *const c_void = ptr::null();
        let mut rev_key_priv_p: *const c_void = ptr::null();
        let mut rev_reg_p: *const c_void = ptr::null();
        let mut rev_tails_generator_p: *const c_void = ptr::null();

        let err_code = ursa_cl_issuer_new_revocation_registry_def(
            credential_pub_key,
            5,
            false,
            &mut rev_key_pub_p,
            &mut rev_key_priv_p,
            &mut rev_reg_p,
            &mut rev_tails_generator_p,
        );
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!rev_key_pub_p.is_null());
        assert!(!rev_key_priv_p.is_null());
        assert!(!rev_reg_p.is_null());
        assert!(!rev_tails_generator_p.is_null());

        (
            rev_key_pub_p,
            rev_key_priv_p,
            rev_reg_p,
            rev_tails_generator_p,
        )
    }

    pub fn _free_revocation_registry_def(
        rev_key_pub: *const c_void,
        rev_key_priv: *const c_void,
        rev_reg: *const c_void,
        rev_tails_generator: *const c_void,
    ) {
        let err_code = ursa_cl_revocation_key_public_free(rev_key_pub);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_cl_revocation_key_private_free(rev_key_priv);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_cl_revocation_registry_free(rev_reg);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_cl_revocation_tails_generator_free(rev_tails_generator);
        assert_eq!(err_code, ErrorCode::Success);
    }

    pub fn _credential_signature(
        blinded_credential_secrets: *const c_void,
        blinded_credential_secrets_correctness_proof: *const c_void,
        credential_nonce: *const c_void,
        credential_issuance_nonce: *const c_void,
        credential_values: *const c_void,
        credential_pub_key: *const c_void,
        credential_priv_key: *const c_void,
    ) -> (*const c_void, *const c_void) {
        let prover_id = _prover_did();

        let mut credential_signature_p: *const c_void = ptr::null();
        let mut credential_signature_correctness_proof_p: *const c_void = ptr::null();
        let err_code = ursa_cl_issuer_sign_credential(
            prover_id.as_ptr(),
            blinded_credential_secrets,
            blinded_credential_secrets_correctness_proof,
            credential_nonce,
            credential_issuance_nonce,
            credential_values,
            credential_pub_key,
            credential_priv_key,
            &mut credential_signature_p,
            &mut credential_signature_correctness_proof_p,
        );

        assert_eq!(err_code, ErrorCode::Success);
        assert!(!credential_signature_p.is_null());
        assert!(!credential_signature_correctness_proof_p.is_null());

        //        _free_credential_values(credential_values);

        (
            credential_signature_p,
            credential_signature_correctness_proof_p,
        )
    }

    pub fn _credential_signature_with_revoc(
        blinded_credential_secrets: *const c_void,
        blinded_credential_secrets_correctness_proof: *const c_void,
        credential_nonce: *const c_void,
        credential_issuance_nonce: *const c_void,
        credential_values: *const c_void,
        credential_pub_key: *const c_void,
        credential_priv_key: *const c_void,
        rev_key_priv: *const c_void,
        rev_reg: *const c_void,
        tail_storage_ctx: *const c_void,
    ) -> (*const c_void, *const c_void, *const c_void) {
        let prover_id = _prover_did();
        let rev_idx = 1;
        let max_cred_num = 5;
        let issuance_by_default = false;

        let mut credential_signature_p: *const c_void = ptr::null();
        let mut credential_signature_correctness_proof_p: *const c_void = ptr::null();
        let mut revocation_registry_delta_p: *const c_void = ptr::null();
        let err_code = ursa_cl_issuer_sign_credential_with_revoc(
            prover_id.as_ptr(),
            blinded_credential_secrets,
            blinded_credential_secrets_correctness_proof,
            credential_nonce,
            credential_issuance_nonce,
            credential_values,
            credential_pub_key,
            credential_priv_key,
            rev_idx,
            max_cred_num,
            issuance_by_default,
            rev_reg,
            rev_key_priv,
            tail_storage_ctx,
            FFISimpleTailStorage::tail_take,
            FFISimpleTailStorage::tail_put,
            &mut credential_signature_p,
            &mut credential_signature_correctness_proof_p,
            &mut revocation_registry_delta_p,
        );

        assert_eq!(err_code, ErrorCode::Success);
        assert!(!credential_signature_p.is_null());
        assert!(!revocation_registry_delta_p.is_null());
        assert!(!credential_signature_correctness_proof_p.is_null());

        //        _free_credential_values(credential_values);

        (
            credential_signature_p,
            credential_signature_correctness_proof_p,
            revocation_registry_delta_p,
        )
    }

    pub fn _free_credential_signature(
        credential_signature: *const c_void,
        signature_correctness_proof: *const c_void,
    ) {
        let err_code = ursa_cl_credential_signature_free(credential_signature);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_cl_signature_correctness_proof_free(signature_correctness_proof);
        assert_eq!(err_code, ErrorCode::Success);
    }

    pub fn _free_credential_signature_with_revoc(
        credential_signature: *const c_void,
        signature_correctness_proof: *const c_void,
        revocation_registry_delta: *const c_void,
    ) {
        let err_code = ursa_cl_credential_signature_free(credential_signature);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_cl_signature_correctness_proof_free(signature_correctness_proof);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_cl_revocation_registry_delta_free(revocation_registry_delta);
        assert_eq!(err_code, ErrorCode::Success);
    }

    pub fn _prover_did() -> CString {
        CString::new("CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW").unwrap()
    }
}
