use cl::prover::*;
use cl::*;
use errors::ToErrorCode;
use ffi::ErrorCode;
use utils::ctypes::CTypesUtils;

use libc::c_char;

use std::os::raw::c_void;

/// Creates a master secret
///
/// Note that master secret deallocation must be performed by
/// calling indy_crypto_cl_master_secret_free
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

/// Deallocates master secret instance.
///
/// # Arguments
/// * `master_secret` - Master secret instance pointer
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

/// Creates blinded master secret for given issuer key and master secret
///
/// Note that blinded master secret deallocation must be performed by
/// calling indy_crypto_cl_blinded_master_secret_free
///
/// Note that master secret blinding data deallocation must be performed by
/// calling indy_crypto_cl_master_secret_blinding_data_free
///
/// # Arguments
/// * `issuer_pub_key` - Reference that contain public keys instance pointer.
/// * `master_secret` - Reference that contain master secret instance pointer.
/// * `blinded_master_secret_p` - Reference that will contain blinded master secret instance pointer.
/// * `master_secret_blinding_data_p` - Reference that will contain master secret blinding data instance pointer.
#[no_mangle]
pub extern fn indy_crypto_cl_prover_blind_master_secret(issuer_pub_key: *const c_void,
                                                        master_secret: *const c_void,
                                                        blinded_master_secret_p: *mut *const c_void,
                                                        master_secret_blinding_data_p: *mut *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_prover_blind_master_secret: >>> issuer_pub_key: {:?}, master_secret: {:?}, blinded_master_secret_p: {:?}, master_secret_blinding_data_p: {:?}",
           issuer_pub_key, master_secret, blinded_master_secret_p, master_secret_blinding_data_p);

    check_useful_c_reference!(issuer_pub_key, IssuerPublicKey, ErrorCode::CommonInvalidParam1);
    check_useful_c_reference!(master_secret, MasterSecret, ErrorCode::CommonInvalidParam2);
    check_useful_c_ptr!(blinded_master_secret_p, ErrorCode::CommonInvalidParam3);
    check_useful_c_ptr!(master_secret_blinding_data_p, ErrorCode::CommonInvalidParam4);

    trace!("indy_crypto_cl_prover_blind_master_secret: entities: issuer_pub_key: {:?}, master_secret: {:?}, blinded_master_secret_p: {:?}, master_secret_blinding_data_p: {:?}",
           issuer_pub_key, master_secret, blinded_master_secret_p, master_secret_blinding_data_p);

    let res = match Prover::blind_master_secret(issuer_pub_key, master_secret) {
        Ok((blinded_master_secret, master_secret_blinding_data)) => {
            trace!("indy_crypto_cl_prover_blind_master_secret: blinded_master_secret: {:?}, master_secret_blinding_data: {:?}",
                   blinded_master_secret, master_secret_blinding_data);
            unsafe {
                *blinded_master_secret_p = Box::into_raw(Box::new(blinded_master_secret)) as *const c_void;
                *master_secret_blinding_data_p = Box::into_raw(Box::new(master_secret_blinding_data)) as *const c_void;
                trace!("indy_crypto_cl_prover_blind_master_secret: *blinded_master_secret_p: {:?}, *master_secret_blinding_data_p: {:?}",
                       *blinded_master_secret_p, *master_secret_blinding_data_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_cl_prover_blind_master_secret: <<< res: {:?}", res);
    res
}

/// Deallocates  blinded master secret instance.
///
/// # Arguments
/// * `blinded_master_secret` - Blinded master secret instance pointer
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

/// Deallocates master secret blinding data instance.
///
/// # Arguments
/// * `master_secret_blinding_data` - Master secret instance pointer
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

/// Updates the claim signature by a master secret blinding data.
///
/// # Arguments
/// * `claim_signature` - Reference that contain claim signature instance pointer.
/// * `master_secret_blinding_data` - Reference that contain master secret blinding data instance pointer.
/// * `issuer_pub_key` - Reference that containissuer public key instance pointer.
/// * `rev_reg_pub` - Reference that contain revocation registry instance pointer.
#[no_mangle]
pub extern fn indy_crypto_cl_prover_process_claim_signature(claim_signature: *const c_void,
                                                            master_secret_blinding_data: *const c_void,
                                                            issuer_pub_key: *const c_void,
                                                            rev_reg_pub: *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_prover_process_claim_signature: >>> claim_signature: {:?}, master_secret_blinding_data: {:?}, issuer_pub_key: {:?}, rev_reg_pub: {:?}",
           claim_signature, master_secret_blinding_data, issuer_pub_key, rev_reg_pub);

    check_useful_mut_c_reference!(claim_signature, ClaimSignature, ErrorCode::CommonInvalidParam1);
    check_useful_c_reference!(master_secret_blinding_data, MasterSecretBlindingData, ErrorCode::CommonInvalidParam2);
    check_useful_c_reference!(issuer_pub_key, IssuerPublicKey, ErrorCode::CommonInvalidParam3);
    check_useful_opt_c_reference!(rev_reg_pub, RevocationRegistryPublic, ErrorCode::CommonInvalidParam4);

    trace!("indy_crypto_cl_prover_process_claim_signature: entities: claim_signature: {:?}, master_secret_blinding_data: {:?}, issuer_pub_key: {:?}, rev_reg_pub: {:?}",
           claim_signature, master_secret_blinding_data, issuer_pub_key, rev_reg_pub);

    let res = match Prover::process_claim_signature(claim_signature,
                                                    master_secret_blinding_data,
                                                    issuer_pub_key,
                                                    rev_reg_pub) {
        Ok(()) => ErrorCode::Success,
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_cl_prover_process_claim_signature: <<< res: {:?}", res);
    res
}

/// Creates and returns proof builder.
///
/// Note that proof builder deallocation must be performed by
/// calling indy_crypto_cl_proof_builder_finalize
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

/// Add sub proof request to proof builder which will be used fo building of proof.
///
/// # Arguments
/// * `proof_builder` - Reference that contain proof builder instance pointer.
/// * `key_id` - unique claim_signature identifier.
/// * `claim_schema` - Reference that contain claim schema instance pointer.
/// * `claim_signature` - Reference that contain claim signature instance pointer.
/// * `claim_values` - Reference that contain claim values instance pointer.
/// * `issuer_pub_key` - Reference that contain public key instance pointer.
/// * `rev_reg_bub` - Reference that contain public revocation registry instance pointer.
/// * `sub_proof_request` - Reference that contain requested attributes and predicates instance pointer.
#[no_mangle]
pub extern fn indy_crypto_cl_proof_builder_add_sub_proof_request(proof_builder: *const c_void,
                                                                 key_id: *const c_char,
                                                                 claim_schema: *const c_void,
                                                                 claim_signature: *const c_void,
                                                                 claim_values: *const c_void,
                                                                 issuer_pub_key: *const c_void,
                                                                 rev_reg_bub: *const c_void,
                                                                 sub_proof_request: *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_proof_builder_add_sub_proof_request: >>> proof_builder: {:?},key_id: {:?},claim_signature: {:?},\
            claim_values: {:?}, issuer_pub_key: {:?}, rev_reg_bub: {:?}, sub_proof_request: {:?}, claim_schema: {:?}",
           proof_builder, key_id, claim_signature, claim_values, issuer_pub_key, rev_reg_bub, sub_proof_request, claim_schema);

    check_useful_mut_c_reference!(proof_builder, ProofBuilder, ErrorCode::CommonInvalidParam1);
    check_useful_c_str!(key_id, ErrorCode::CommonInvalidParam2);
    check_useful_c_reference!(claim_schema, ClaimSchema, ErrorCode::CommonInvalidParam3);
    check_useful_c_reference!(claim_signature, ClaimSignature, ErrorCode::CommonInvalidParam4);
    check_useful_c_reference!(claim_values, ClaimValues, ErrorCode::CommonInvalidParam5);
    check_useful_c_reference!(issuer_pub_key, IssuerPublicKey, ErrorCode::CommonInvalidParam6);
    check_useful_opt_c_reference!(rev_reg_bub, RevocationRegistryPublic, ErrorCode::CommonInvalidParam7);
    check_useful_c_reference!(sub_proof_request, SubProofRequest, ErrorCode::CommonInvalidParam8);

    trace!("indy_crypto_cl_proof_builder_add_sub_proof_request: entities: proof_builder: {:?}, key_id: {:?}, claim_signature: {:?}, \
            claim_values: {:?}, issuer_pub_key: {:?}, rev_reg_bub: {:?}, sub_proof_request: {:?}, claim_schema: {:?}",
           proof_builder, key_id, claim_signature, claim_values, issuer_pub_key, rev_reg_bub, sub_proof_request, claim_schema);

    let res = match proof_builder.add_sub_proof_request(&key_id,
                                                        claim_signature,
                                                        claim_values,
                                                        issuer_pub_key,
                                                        rev_reg_bub,
                                                        sub_proof_request,
                                                        claim_schema) {
        Ok(()) => ErrorCode::Success,
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_cl_proof_builder_add_sub_proof_request: <<< res: {:?}", res);
    res
}


/// Finalize proof
///
/// Note that proof deallocation must be performed by
/// calling indy_crypto_cl_proof_free
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

/// Deallocates proof instance.
///
/// # Arguments
/// * `proof` - Proof instance pointer
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
    use ffi::cl::verifier::mocks::*;

    #[test]
    fn indy_crypto_cl_prover_new_master_secret_works() {
        let mut master_secret_p: *const c_void = ptr::null();
        let err_code = indy_crypto_cl_prover_new_master_secret(&mut master_secret_p);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!master_secret_p.is_null());

        _free_master_secret(master_secret_p)
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
        let (pub_keys, _) = _issuer_keys();

        let mut blinded_master_secret_p: *const c_void = ptr::null();
        let mut master_secret_blinding_data_p: *const c_void = ptr::null();

        let err_code = indy_crypto_cl_prover_blind_master_secret(pub_keys, master_secret,
                                                                 &mut blinded_master_secret_p, &mut master_secret_blinding_data_p);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!blinded_master_secret_p.is_null());
        assert!(!master_secret_blinding_data_p.is_null());

        _free_blinded_master_secret(blinded_master_secret_p, master_secret_blinding_data_p);
    }

    #[test]
    fn indy_crypto_cl_prover_blinded_master_secret_free_works() {
        let master_secret = _master_secret();
        let (pub_keys, _) = _issuer_keys();

        let (blinded_master_secret, master_secret_blinding_data) = _blinded_master_secret(pub_keys, master_secret);

        let err_code = indy_crypto_cl_blinded_master_secret_free(blinded_master_secret);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = indy_crypto_cl_master_secret_blinding_data_free(master_secret_blinding_data);
        assert_eq!(err_code, ErrorCode::Success);
    }

    #[test]
    fn indy_crypto_cl_prover_process_claim_signature_signature_works() {
        let (issuer_pub_key, issuer_priv_key) = _issuer_keys();
        let (rev_reg_pub, rev_reg_priv) = _revocation_registry(issuer_pub_key);
        let master_secret = _master_secret();
        let (blinded_master_secret, master_secret_blinding_data) = _blinded_master_secret(issuer_pub_key, master_secret);

        let claim_signature = _claim_signature(blinded_master_secret, issuer_pub_key, issuer_priv_key, rev_reg_pub, rev_reg_priv);

        let err_code = indy_crypto_cl_prover_process_claim_signature(claim_signature,
                                                                     master_secret_blinding_data,
                                                                     issuer_pub_key,
                                                                     rev_reg_pub);
        assert_eq!(err_code, ErrorCode::Success);

        _free_issuer_keys(issuer_pub_key, issuer_priv_key);
        _free_revocation_registry(rev_reg_pub, rev_reg_priv);
        _free_blinded_master_secret(blinded_master_secret, master_secret_blinding_data);
        _free_master_secret(master_secret);
        _free_claim_signature(claim_signature);
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
        let (issuer_pub_key, issuer_priv_key) = _issuer_keys();
        let (rev_reg_pub, rev_reg_priv) = _revocation_registry(issuer_pub_key);
        let master_secret = _master_secret();
        let (blinded_master_secret, master_secret_blinding_data) = _blinded_master_secret(issuer_pub_key, master_secret);
        let claim_values = _claim_values();
        let sub_proof_request = _sub_proof_request();
        let claim_schema = _claim_schema();

        let claim_signature = _claim_signature(blinded_master_secret, issuer_pub_key, issuer_priv_key, rev_reg_pub, rev_reg_priv);
        _process_claim_signature(claim_signature, master_secret_blinding_data, issuer_pub_key, rev_reg_pub);

        let proof_builder = _proof_builder();

        indy_crypto_cl_proof_builder_add_sub_proof_request(proof_builder,
                                                           uuid.as_ptr(),
                                                           claim_schema,
                                                           claim_signature,
                                                           claim_values,
                                                           issuer_pub_key,
                                                           rev_reg_pub,
                                                           sub_proof_request);

        let nonce = _nonce();

        _free_proof_builder(proof_builder, nonce, master_secret);

        _free_issuer_keys(issuer_pub_key, issuer_priv_key);
        _free_revocation_registry(rev_reg_pub, rev_reg_priv);
        _free_master_secret(master_secret);
        _free_blinded_master_secret(blinded_master_secret, master_secret_blinding_data);
        _free_claim_values(claim_values);
        _free_sub_proof_request(sub_proof_request);
        _free_claim_signature(claim_signature);
    }

    #[test]
    fn indy_crypto_cl_prover_proof_builder_finalize_works() {
        let uuid = CString::new("uuid").unwrap();
        let (issuer_pub_key, issuer_priv_key) = _issuer_keys();
        let (rev_reg_pub, rev_reg_priv) = _revocation_registry(issuer_pub_key);
        let master_secret = _master_secret();
        let (blinded_master_secret, master_secret_blinding_data) = _blinded_master_secret(issuer_pub_key, master_secret);
        let claim_values = _claim_values();
        let sub_proof_request = _sub_proof_request();
        let claim_schema = _claim_schema();
        let claim_signature = _claim_signature(blinded_master_secret, issuer_pub_key, issuer_priv_key, rev_reg_pub, rev_reg_priv);
        _process_claim_signature(claim_signature, master_secret_blinding_data, issuer_pub_key, rev_reg_pub);

        let proof_builder = _proof_builder();

        indy_crypto_cl_proof_builder_add_sub_proof_request(proof_builder,
                                                           uuid.as_ptr(),
                                                           claim_schema,
                                                           claim_signature,
                                                           claim_values,
                                                           issuer_pub_key,
                                                           rev_reg_pub,
                                                           sub_proof_request);
        let nonce = _nonce();

        let mut proof: *const c_void = ptr::null();
        let err_code = indy_crypto_cl_proof_builder_finalize(proof_builder,
                                                             nonce,
                                                             master_secret,
                                                             &mut proof);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!proof.is_null());

        _free_issuer_keys(issuer_pub_key, issuer_priv_key);
        _free_revocation_registry(rev_reg_pub, rev_reg_priv);
        _free_master_secret(master_secret);
        _free_blinded_master_secret(blinded_master_secret, master_secret_blinding_data);
        _free_claim_values(claim_values);
        _free_sub_proof_request(sub_proof_request);
        _free_claim_signature(claim_signature);
        _free_proof(proof);
    }

    #[test]
    fn indy_crypto_cl_proof_free_works() {
        super::super::super::indy_crypto_init_logger();

        let (issuer_pub_key, issuer_priv_key) = _issuer_keys();
        let (rev_reg_pub, rev_reg_priv) = _revocation_registry(issuer_pub_key);
        let master_secret = _master_secret();
        let (blinded_master_secret, master_secret_blinding_data) = _blinded_master_secret(issuer_pub_key, master_secret);
        let nonce = _nonce();
        let claim_signature = _claim_signature(blinded_master_secret, issuer_pub_key, issuer_priv_key, rev_reg_pub, rev_reg_priv);
        _process_claim_signature(claim_signature, master_secret_blinding_data, issuer_pub_key, rev_reg_pub);

        let proof = _proof(issuer_pub_key, rev_reg_pub, claim_signature, nonce, master_secret);

        _free_issuer_keys(issuer_pub_key, issuer_priv_key);
        _free_revocation_registry(rev_reg_pub, rev_reg_priv);
        _free_master_secret(master_secret);
        _free_blinded_master_secret(blinded_master_secret, master_secret_blinding_data);
        _free_nonce(nonce);
        _free_claim_signature(claim_signature);

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

    pub fn _blinded_master_secret(issuer_pub_key: *const c_void, master_secret: *const c_void) -> (*const c_void, *const c_void) {
        let mut blinded_master_secret_p: *const c_void = ptr::null();
        let mut master_secret_blinding_data_p: *const c_void = ptr::null();

        let err_code = indy_crypto_cl_prover_blind_master_secret(issuer_pub_key, master_secret,
                                                                 &mut blinded_master_secret_p, &mut master_secret_blinding_data_p);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!blinded_master_secret_p.is_null());
        assert!(!master_secret_blinding_data_p.is_null());

        (blinded_master_secret_p, master_secret_blinding_data_p)
    }

    pub fn _free_blinded_master_secret(blinded_master_secret: *const c_void, master_secret_blinding_data: *const c_void) {
        let err_code = indy_crypto_cl_blinded_master_secret_free(blinded_master_secret);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = indy_crypto_cl_master_secret_blinding_data_free(master_secret_blinding_data);
        assert_eq!(err_code, ErrorCode::Success);
    }

    pub fn _process_claim_signature(claim_signature: *const c_void, master_secret_blinding_data: *const c_void,
                                    issuer_pub_key: *const c_void, rev_reg_pub: *const c_void) {
        let err_code = indy_crypto_cl_prover_process_claim_signature(claim_signature, master_secret_blinding_data, issuer_pub_key, rev_reg_pub);
        assert_eq!(err_code, ErrorCode::Success);
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

    pub fn _proof(issuer_pub_key: *const c_void, rev_reg_pub: *const c_void, claim_signature: *const c_void,
                  nonce: *const c_void, master_secret: *const c_void) -> *const c_void {
        let proof_builder = _proof_builder();
        let claim_schema = _claim_schema();
        let claim_values = _claim_values();
        let sub_proof_request = _sub_proof_request();
        let key_id = CString::new("key_id").unwrap();

        indy_crypto_cl_proof_builder_add_sub_proof_request(proof_builder,
                                                           key_id.as_ptr(),
                                                           claim_schema,
                                                           claim_signature,
                                                           claim_values,
                                                           issuer_pub_key,
                                                           rev_reg_pub,
                                                           sub_proof_request);

        let mut proof: *const c_void = ptr::null();
        let err_code = indy_crypto_cl_proof_builder_finalize(proof_builder,
                                                             nonce,
                                                             master_secret,
                                                             &mut proof);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!proof.is_null());

        //        _free_claim_schema(claim_schema);
        //        _free_claim_values(claim_values);
        //        _free_sub_proof_request(sub_proof_request);

        proof
    }

    pub fn _free_proof(proof: *const c_void) {
        let err_code = indy_crypto_cl_proof_free(proof);
        assert_eq!(err_code, ErrorCode::Success);
    }
}