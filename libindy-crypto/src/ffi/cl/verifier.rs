use cl::verifier::*;
use cl::types::*;
use errors::ToErrorCode;
use ffi::ErrorCode;
use utils::ctypes::CTypesUtils;

use libc::c_char;

use std::os::raw::c_void;

/// Creates random nonce
///
/// Note that nonce deallocation must be performed by calling indy_crypto_cl_nonce_free
///
/// # Arguments
/// * `nonce_p` - Reference that will contain nonce instance pointer.
#[no_mangle]
pub extern fn indy_crypto_cl_verify_new_nonce(nonce_p: *mut *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_verify_new_nonce: >>> {:?}", nonce_p);

    check_useful_c_ptr!(nonce_p, ErrorCode::CommonInvalidParam1);

    let res = match Verifier::new_nonce() {
        Ok(nonce) => {
            trace!("indy_crypto_cl_verify_new_nonce: nonce: {:?}", nonce);
            unsafe {
                *nonce_p = Box::into_raw(Box::new(nonce)) as *const c_void;
                trace!("indy_crypto_cl_verify_new_nonce: *nonce_p: {:?}", *nonce_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_cl_verify_new_nonce: <<< res: {:?}", res);
    res
}


/// Deallocates nonce instance.
///
/// # Arguments
/// * `nonce_p` - Nonce instance pointer
#[no_mangle]
pub extern fn indy_crypto_cl_nonce_free(nonce_p: *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_nonce_free: >>> nonce_p: {:?}", nonce_p);

    check_useful_c_ptr!(nonce_p, ErrorCode::CommonInvalidParam1);

    unsafe { Box::from_raw(nonce_p as *mut MasterSecret); }
    let res = ErrorCode::Success;

    trace!("indy_crypto_cl_nonce_free: <<< res: {:?}", res);
    res
}

/// Creates and returns proof verifier.
///
/// Note that proof verifier deallocation must be performed by
/// calling indy_crypto_cl_proof_verifier_finalize
///
/// # Arguments
/// * `proof_verifier_p` - Reference that will contain proof builder instance pointer.
#[no_mangle]
pub extern fn indy_crypto_cl_verifier_new_proof_verifier(proof_verifier_p: *mut *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_verifier_new_proof_verifier: >>> {:?}", proof_verifier_p);

    check_useful_c_ptr!(proof_verifier_p, ErrorCode::CommonInvalidParam1);

    let res = match Verifier::new_proof_verifier() {
        Ok(proof_verifier) => {
            trace!("indy_crypto_cl_verifier_new_proof_verifier: proof_verifier: {:?}", proof_verifier);
            unsafe {
                *proof_verifier_p = Box::into_raw(Box::new(proof_verifier)) as *const c_void;
                trace!("indy_crypto_cl_verifier_new_proof_verifier: *proof_verifier_p: {:?}", *proof_verifier_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_cl_verifier_new_proof_verifier: <<< res: {:?}", res);
    res
}

/// Add sub proof request to proof verifier.
///
/// # Arguments
/// * `proof_verifier_p` - Reference that contain proof verifier instance pointer.
/// * `issuer_key_id` - unique identifier.
/// * `pub_key_p` - Reference that contain public key instance pointer.
/// * `r_reg_p` - Reference that contain public revocation registry instance pointer.
/// * `sub_proof_request_p` - Reference that contain requested attributes and predicates instance pointer.
/// * `claim_schema_p` - Reference that contain claim schema instance pointer.
#[no_mangle]
pub extern fn indy_crypto_cl_proof_verifier_add_sub_proof_request(proof_verifier_p: *const c_void,
                                                                  issuer_key_id: *const c_char,
                                                                  pub_key_p: *const c_void,
                                                                  r_reg_p: *const c_void,
                                                                  sub_proof_request_p: *const c_void,
                                                                  claim_schema_p: *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_proof_verifier_add_sub_proof_request: >>> proof_verifier_p: {:?},issuer_key_id: {:?},pub_key_p: {:?},\
            r_reg_p: {:?},sub_proof_request_p: {:?}", proof_verifier_p, issuer_key_id, pub_key_p, r_reg_p, sub_proof_request_p);

    check_useful_c_ptr!(proof_verifier_p, ErrorCode::CommonInvalidParam1);
    check_useful_c_str!(issuer_key_id, ErrorCode::CommonInvalidParam2);
    check_useful_c_ptr!(pub_key_p,  ErrorCode::CommonInvalidParam3);
    check_useful_c_ptr!(r_reg_p, ErrorCode::CommonInvalidParam3);
    check_useful_c_ptr!(sub_proof_request_p, ErrorCode::CommonInvalidParam3);
    check_useful_c_ptr!(claim_schema_p, ErrorCode::CommonInvalidParam3);

    let mut proof_verifier = unsafe { *Box::from_raw(proof_verifier_p as *mut ProofVerifier) };
    let pub_key: IssuerPublicKey = unsafe { *Box::from_raw(pub_key_p as *mut IssuerPublicKey) };
    let r_reg: Option<RevocationRegistryPublic> = if r_reg_p.is_null() { None } else { Some(unsafe { *Box::from_raw(r_reg_p as *mut RevocationRegistryPublic) }) };
    let sub_proof_request: SubProofRequest = unsafe { *Box::from_raw(sub_proof_request_p as *mut SubProofRequest) };
    let claim_schema: ClaimSchema = unsafe { *Box::from_raw(claim_schema_p as *mut ClaimSchema) };

    let res = match ProofVerifier::add_sub_proof_request(&mut proof_verifier,
                                                         &issuer_key_id,
                                                         pub_key,
                                                         r_reg,
                                                         sub_proof_request,
                                                         claim_schema) {
        Ok(()) => ErrorCode::Success,
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_cl_proof_verifier_add_sub_proof_request: <<< res: {:?}", res);
    res
}


/// Verify proof
///
/// # Arguments
/// * `proof_verifier_p` - Reference that contain proof verifier instance pointer.
/// * `proof_p` - Reference that contain nonce instance pointer.
/// * `nonce_p` - Reference that contain master secret instance pointer.
/// * `valid_p` - Reference that will be filled with true - if proof valid or false otherwise.
#[no_mangle]
pub extern fn indy_crypto_cl_proof_builder_verify(proof_verifier_p: *const c_void,
                                                  proof_p: *const c_void,
                                                  nonce_p: *const c_void,
                                                  valid_p: *mut bool) -> ErrorCode {
    trace!("indy_crypto_cl_proof_builder_verify: >>> proof_verifier_p: {:?}, proof_p: {:?}, nonce_p: {:?}", proof_verifier_p, proof_p, nonce_p);

    check_useful_c_ptr!(proof_verifier_p, ErrorCode::CommonInvalidParam1);
    check_useful_c_reference!(proof_p, Proof, ErrorCode::CommonInvalidParam2);
    check_useful_c_reference!(nonce_p, Nonce, ErrorCode::CommonInvalidParam2);

    let mut proof_verifier = unsafe { Box::from_raw(proof_verifier_p as *mut ProofVerifier) };

    let res = match ProofVerifier::verify(&mut proof_verifier,
                                          proof_p,
                                          nonce_p) {
        Ok(valid) => {
            trace!("indy_crypto_cl_proof_builder_verify: valid: {:?}", valid);
            unsafe {
                *valid_p = valid; 
                trace!("indy_crypto_cl_proof_builder_verify: *valid_p: {:?}", *valid_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_cl_proof_builder_verify: <<< res: {:?}", res);
    res
}