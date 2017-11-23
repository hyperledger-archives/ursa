use cl::prover::*;
use cl::types::*;
use errors::ToErrorCode;
use ffi::ErrorCode;
use utils::ctypes::CTypesUtils;

use libc::c_char;

use std::os::raw::c_void;

use bn::BigNumber;


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
/// * `master_secret_p` - Master secret instance pointer
#[no_mangle]
pub extern fn indy_crypto_cl_master_secret_free(master_secret_p: *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_master_secret_free: >>> master_secret_p: {:?}", master_secret_p);

    check_useful_c_ptr!(master_secret_p, ErrorCode::CommonInvalidParam1);

    unsafe { Box::from_raw(master_secret_p as *mut MasterSecret); }
    let res = ErrorCode::Success;

    trace!("indy_crypto_cl_master_secret_free: <<< res: {:?}", res);
    res
}

/// Creates blinded master secret for given keys and master secret
///
/// Note that blinded master secret deallocation must be performed by
/// calling indy_crypto_cl_blinded_master_secret_free
///
/// Note that blinded master secret data deallocation must be performed by
/// calling indy_crypto_cl_blinded_master_secret_data_free
///
/// # Arguments
/// * `pub_key_p` - Reference that contain public keys instance pointer.
/// * `master_secret_p` - Reference that contain master secret instance pointer.
/// * `blinded_master_secret_p` - Reference that will contain blinded master secret instance pointer.
/// * `blinded_master_secret_data_p` - Reference that will contain blinded master secret data instance pointer.
#[no_mangle]
pub extern fn indy_crypto_cl_prover_blinded_master_secret(pub_key_p: *const c_void,
                                                          master_secret_p: *const c_void,
                                                          blinded_master_secret_p: *mut *const c_void,
                                                          blinded_master_secret_data_p: *mut *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_prover_blinded_master_secret: >>> pub_key_p: {:?}, master_secret_p: {:?}, blinded_master_secret_p: {:?}, blinded_master_secret_data_p: {:?}",
           pub_key_p, master_secret_p, blinded_master_secret_p, blinded_master_secret_data_p);

    check_useful_c_reference!(pub_key_p, IssuerPublicKey, ErrorCode::CommonInvalidParam1);
    check_useful_c_reference!(master_secret_p, MasterSecret, ErrorCode::CommonInvalidParam2);
    check_useful_c_ptr!(blinded_master_secret_p, ErrorCode::CommonInvalidParam3);
    check_useful_c_ptr!(blinded_master_secret_data_p, ErrorCode::CommonInvalidParam4);

    let res = match Prover::blinded_master_secret(pub_key_p, master_secret_p) {
        Ok((blinded_master_secret, blinded_master_secret_data)) => {
            trace!("indy_crypto_cl_prover_blinded_master_secret: blinded_master_secret: {:?}, blinded_master_secret_data: {:?}",
                   blinded_master_secret, blinded_master_secret_data);
            unsafe {
                *blinded_master_secret_p = Box::into_raw(Box::new(blinded_master_secret)) as *const c_void;
                *blinded_master_secret_data_p = Box::into_raw(Box::new(blinded_master_secret_data)) as *const c_void;
                trace!("indy_crypto_cl_prover_blinded_master_secret: *blinded_master_secret_p: {:?}, *blinded_master_secret_p: {:?}",
                       *blinded_master_secret_p, *blinded_master_secret_data_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_cl_prover_blinded_master_secret: <<< res: {:?}", res);
    res
}

/// Deallocates  blinded master secret instance.
///
/// # Arguments
/// * `blinded_master_secret_p` - Master secret instance pointer
#[no_mangle]
pub extern fn indy_crypto_cl_blinded_master_secret_free(blinded_master_secret_p: *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_blinded_master_secret_free: >>> blinded_master_secret_p: {:?}", blinded_master_secret_p);

    check_useful_c_ptr!(blinded_master_secret_p, ErrorCode::CommonInvalidParam1);

    unsafe { Box::from_raw(blinded_master_secret_p as *mut MasterSecret); }
    let res = ErrorCode::Success;

    trace!("indy_crypto_cl_blinded_master_secret_free: <<< res: {:?}", res);
    res
}

/// Deallocates blinded master secret data instance.
///
/// # Arguments
/// * `blinded_master_secret_data_p` - Master secret instance pointer
#[no_mangle]
pub extern fn indy_crypto_cl_blinded_master_secret_data_free(blinded_master_secret_data_p: *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_blinded_master_secret_data_free: >>> blinded_master_secret_data_p: {:?}", blinded_master_secret_data_p);

    check_useful_c_ptr!(blinded_master_secret_data_p, ErrorCode::CommonInvalidParam1);

    unsafe { Box::from_raw(blinded_master_secret_data_p as *mut MasterSecret); }
    let res = ErrorCode::Success;

    trace!("indy_crypto_cl_blinded_master_secret_data_free: <<< res: {:?}", res);
    res
}

/// Updates the claim_signature by a master secret blinded data.
///
///
/// # Arguments
/// * `claim_signature_p` - Reference that contain claim_signature signature instance pointer.
/// * `blinded_master_secret_data_p` - Reference that contain blinded master secret data instance pointer.
/// * `r_pub_key_p` - Reference that contain revocation public key instance pointer.
/// * `r_reg` - Reference that contain revocation registry instance pointer.
#[no_mangle]
pub extern fn indy_crypto_cl_prover_process_claim(claim_signature_p: *const c_void,
                                                  blinded_master_secret_data_p: *const c_void,
                                                  pub_key_p: *const c_void,
                                                  r_reg: *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_prover_process_claim: >>> claim_signature_p: {:?}, blinded_master_secret_data_p: {:?}, r_pub_key_p: {:?}, r_reg: {:?}",
           claim_signature_p, blinded_master_secret_data_p, pub_key_p, r_reg);

    check_useful_c_ptr!(claim_signature_p, ErrorCode::CommonInvalidParam1);
    check_useful_c_reference!(blinded_master_secret_data_p, BlindedMasterSecretData, ErrorCode::CommonInvalidParam2);
    check_useful_c_reference!(pub_key_p, IssuerPublicKey, ErrorCode::CommonInvalidParam3);
    check_useful_opt_c_reference!(r_reg, RevocationRegistryPublic, ErrorCode::CommonInvalidParam4);

    let mut claim_signature = unsafe { Box::from_raw(claim_signature_p as *mut ClaimSignature) };


    let res = match Prover::process_claim_signature(&mut claim_signature,
                                                    blinded_master_secret_data_p,
                                                    pub_key_p,
                                                    r_reg) {
        Ok(()) => {
            Box::into_raw(claim_signature);
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_cl_prover_process_claim: <<< res: {:?}", res);
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
/// * `proof_builder_p` - Reference that contain proof builder instance pointer.
/// * `uuid` - unique claim_signature identifier.
/// * `claim_signature_p` - Reference that contain claim_signature instance pointer.
/// * `claim_values_p` - Reference that contain claim_signature attributes instance pointer.
/// * `pub_key_p` - Reference that contain public key instance pointer.
/// * `r_reg_p` - Reference that contain public revocation registry instance pointer.
/// * `sub_proof_request_p` - Reference that contain requested attributes and predicates instance pointer.
/// * `claim_schema_p` - Reference that contain claim schema instance pointer.
#[no_mangle]
pub extern fn indy_crypto_cl_proof_builder_add_sub_proof_request(proof_builder_p: *const c_void,
                                                                 uuid: *const c_char,
                                                                 claim_signature_p: *const c_void,
                                                                 claim_values_p: *const c_void,
                                                                 pub_key_p: *const c_void,
                                                                 r_reg_p: *const c_void,
                                                                 sub_proof_request_p: *const c_void,
                                                                 claim_schema_p: *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_proof_builder_add_sub_proof_request: >>> proof_builder_p: {:?},uuid: {:?},claim_signature_p: {:?},\
            claim_values_p: {:?},pub_key_p: {:?},r_reg_p: {:?}, sub_proof_request_p: {:?}, claim_schema_p: {:?}",
           proof_builder_p, uuid, claim_signature_p, claim_values_p, pub_key_p, r_reg_p, sub_proof_request_p, claim_schema_p);

    check_useful_c_ptr!(proof_builder_p, ErrorCode::CommonInvalidParam1);
    check_useful_c_str!(uuid, ErrorCode::CommonInvalidParam2);
    check_useful_c_reference!(claim_signature_p, ClaimSignature, ErrorCode::CommonInvalidParam3);
    check_useful_c_ptr!(claim_values_p, ErrorCode::CommonInvalidParam4);
    check_useful_c_reference!(pub_key_p, IssuerPublicKey, ErrorCode::CommonInvalidParam5);
    check_useful_opt_c_reference!(r_reg_p, RevocationRegistryPublic, ErrorCode::CommonInvalidParam6);
    check_useful_c_ptr!(sub_proof_request_p, ErrorCode::CommonInvalidParam7);
    check_useful_c_ptr!(claim_schema_p, ErrorCode::CommonInvalidParam8);

    let mut proof_builder = unsafe { Box::from_raw(proof_builder_p as *mut ProofBuilder) };
    let claim_values = unsafe { *Box::from_raw(claim_values_p as *mut ClaimValues) };
    let sub_proof_request = unsafe { *Box::from_raw(sub_proof_request_p as *mut SubProofRequest) };
    let claim_schema = unsafe { *Box::from_raw(claim_schema_p as *mut ClaimSchema) };

    let res = match ProofBuilder::add_sub_proof_request(&mut proof_builder,
                                                        &uuid,
                                                        claim_signature_p,
                                                        claim_values,
                                                        pub_key_p,
                                                        r_reg_p,
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
/// * `proof_builder_p` - Reference that contain proof builder instance pointer.
/// * `nonce_p` - Reference that contain nonce instance pointer.
/// * `master_secret_p` - Reference that contain master secret instance pointer.
/// * `proof_p` - Reference that will contain proof instance pointer.
#[no_mangle]
pub extern fn indy_crypto_cl_proof_builder_finalize(proof_builder_p: *const c_void,
                                                    nonce_p: *const c_void,
                                                    master_secret_p: *const c_void,
                                                    proof_p: *mut *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_proof_builder_finalize: >>> proof_builder_p: {:?}, nonce_p: {:?}, master_secret_p: {:?}, proof_p: {:?}",
           proof_builder_p, nonce_p, master_secret_p, proof_p);

    check_useful_c_ptr!(proof_builder_p, ErrorCode::CommonInvalidParam1);
    check_useful_c_reference!(nonce_p, Nonce, ErrorCode::CommonInvalidParam2);
    check_useful_c_reference!(master_secret_p, MasterSecret, ErrorCode::CommonInvalidParam2);
    check_useful_c_ptr!(proof_p, ErrorCode::CommonInvalidParam4);

    let mut proof_builder = unsafe { Box::from_raw(proof_builder_p as *mut ProofBuilder) };

    let res = match ProofBuilder::finalize(&mut proof_builder, nonce_p, master_secret_p) {
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
/// * `proof_p` - Proof builder instance pointer
#[no_mangle]
pub extern fn indy_crypto_cl_proof_free(proof_p: *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_proof_free: >>> proof_p: {:?}", proof_p);

    check_useful_c_ptr!(proof_p, ErrorCode::CommonInvalidParam1);

    unsafe { Box::from_raw(proof_p as *mut Proof); }
    let res = ErrorCode::Success;

    trace!("indy_crypto_cl_proof_free: <<< res: {:?}", res);
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
    fn indy_crypto_cl_prover_blinded_master_secret_works() {
        let master_secret = _master_secret();
        let (pub_keys, _) = _issuer_keys();

        let mut blinded_master_secret_p: *const c_void = ptr::null();
        let mut blinded_master_secret_data_p: *const c_void = ptr::null();

        let err_code = indy_crypto_cl_prover_blinded_master_secret(pub_keys, master_secret,
                                                                   &mut blinded_master_secret_p, &mut blinded_master_secret_data_p);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!blinded_master_secret_p.is_null());
        assert!(!blinded_master_secret_data_p.is_null());

        _free_blinded_master_secret(blinded_master_secret_p, blinded_master_secret_data_p);
    }

    #[test]
    fn indy_crypto_cl_prover_blinded_master_secret_free_works() {
        let master_secret = _master_secret();
        let (pub_keys, _) = _issuer_keys();

        let (blinded_master_secret, blinded_master_secret_data) = _blinded_master_secret(pub_keys, master_secret);

        let err_code = indy_crypto_cl_blinded_master_secret_free(blinded_master_secret);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = indy_crypto_cl_blinded_master_secret_data_free(blinded_master_secret_data);
        assert_eq!(err_code, ErrorCode::Success);
    }

    #[test]
    fn indy_crypto_cl_prover_process_claim_signature_works() {
        let (issuer_pub_key, issuer_priv_key) = _issuer_keys();
        let (rev_reg_pub, rev_reg_priv) = _revocation_registry(issuer_pub_key);
        let master_secret = _master_secret();
        let (blinded_master_secret, blinded_master_secret_data) = _blinded_master_secret(issuer_pub_key, master_secret);
        let claim_values = _claim_values();

        let claim_signature = _claim_signature(blinded_master_secret, issuer_pub_key, issuer_priv_key, rev_reg_pub, rev_reg_priv, claim_values);

        let err_code = indy_crypto_cl_prover_process_claim(claim_signature,
                                                           blinded_master_secret_data,
                                                           issuer_pub_key,
                                                           rev_reg_pub);
        assert_eq!(err_code, ErrorCode::Success);

        _free_issuer_keys(issuer_pub_key, issuer_priv_key);
        _free_revocation_registry(rev_reg_pub, rev_reg_priv);
        _free_blinded_master_secret(blinded_master_secret, blinded_master_secret_data);
        _free_claim_values(claim_values);

        _free_claim_signature(claim_signature);
    }

    //    #[test]
    //    fn indy_crypto_cl_prover_proof_builder_new_works() {
    //        let mut proof_builder: *const c_void = ptr::null();
    //        let err_code = indy_crypto_cl_prover_new_proof_builder(&mut proof_builder);
    //
    //        assert_eq!(err_code, ErrorCode::Success);
    //        assert!(!proof_builder.is_null());
    //
    //        let nonce = _nonce();
    //        let master_secret = _master_secret();
    //
    //        _free_proof_builder(proof_builder, nonce, master_secret);
    //    }

    //    #[test]
    //    fn indy_crypto_cl_prover_proof_builder_add_claim_works() {
    //        let uuid = CString::new("uuid").unwrap();
    //        let (issuer_pub_key, issuer_priv_key) = _issuer_keys();
    //        let (rev_reg_pub, rev_reg_priv) = _revocation_registry(issuer_pub_key);
    //        let master_secret = _master_secret();
    //        let (blinded_master_secret, blinded_master_secret_data) = _blinded_master_secret(issuer_pub_key, master_secret);
    //        let claim_values = _claim_values();
    //        let sub_proof_request = _sub_proof_request();
    //        let claim_values = _claim_values();
    //
    //        let claim_signature = _claim(blinded_master_secret, issuer_pub_key, issuer_priv_key, rev_reg_pub, rev_reg_priv, claim_values);
    //
    //        let mut proof_builder = _proof_builder();
    //
    //        indy_crypto_cl_proof_builder_add_sub_proof_request(proof_builder,
    //                                                             uuid.as_ptr(),
    //                                                             claim_signature,
    //                                                             claim_values,
    //                                                             issuer_pub_key,
    //                                                             rev_reg_pub,
    //                                                             sub_proof_request);
    //        let nonce = _nonce();
    //        _free_proof_builder(proof_builder, nonce, master_secret);
    //    }
    //
    //    #[test]
    //    fn indy_crypto_cl_prover_proof_builder_finalize_works() {
    //        let uuid = CString::new("uuid").unwrap();
    //        let (issuer_pub_key, issuer_priv_key) = _issuer_keys();
    //        let (rev_reg_pub, rev_reg_priv) = _revocation_registry(issuer_pub_key);
    //        let master_secret = _master_secret();
    //        let (blinded_master_secret, blinded_master_secret_data) = _blinded_master_secret(issuer_pub_key, master_secret);
    //        let claim_values = _claim_values();
    //        let sub_proof_request = _sub_proof_request();
    //
    //        let claim_signature = _claim(blinded_master_secret, issuer_pub_key, issuer_priv_key, rev_reg_pub, rev_reg_priv, claim_values);
    //
    //        let mut proof_builder = _proof_builder();
    //
    //
    //        indy_crypto_cl_proof_builder_add_sub_proof_request(proof_builder,
    //                                                             uuid.as_ptr(),
    //                                                             claim_signature,
    //                                                             claim_values,
    //                                                             issuer_pub_key,
    //                                                             rev_reg_pub,
    //                                                             sub_proof_request);
    //
    //        let nonce = _nonce();
    //
    //        let mut proof: *const c_void = ptr::null();
    //        let err_code = indy_crypto_cl_proof_builder_finalize(proof_builder,
    //                                                                           nonce,
    //                                                                           master_secret,
    //                                                                           &mut proof);
    //        assert_eq!(err_code, ErrorCode::Success);
    //        assert!(!proof.is_null());
    //        //
    //        //        _free_proof(proof);
    //    }
    //
    //    #[test]
    //    fn indy_crypto_cl_proof_free_works() {
    //        let proof = _proof();
    //
    //        let err_code = indy_crypto_cl_proof_free(proof);
    //        assert_eq!(err_code, ErrorCode::Success);
    //    }
}

pub mod mocks {
    use super::*;

    use std::ptr;
    use std::ffi::CString;
    use ffi::cl::mocks::*;
    use ffi::cl::issuer::mocks::*;

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

    pub fn _blinded_master_secret(pub_keys: *const c_void, master_secret: *const c_void) -> (*const c_void, *const c_void) {
        let mut blinded_master_secret_p: *const c_void = ptr::null();
        let mut blinded_master_secret_data_p: *const c_void = ptr::null();

        let err_code = indy_crypto_cl_prover_blinded_master_secret(pub_keys, master_secret,
                                                                   &mut blinded_master_secret_p, &mut blinded_master_secret_data_p);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!blinded_master_secret_p.is_null());
        assert!(!blinded_master_secret_data_p.is_null());

        (blinded_master_secret_p, blinded_master_secret_data_p)
    }

    pub fn _free_blinded_master_secret(blinded_master_secret_p: *const c_void, blinded_master_secret_data_p: *const c_void) {
        let err_code = indy_crypto_cl_blinded_master_secret_free(blinded_master_secret_p);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = indy_crypto_cl_blinded_master_secret_data_free(blinded_master_secret_data_p);
        assert_eq!(err_code, ErrorCode::Success);
    }

    pub fn _nonce() -> *const c_void {
        let nonce = BigNumber::rand(80).unwrap();
        let nonce_p = Box::into_raw(Box::new(nonce)) as *const c_void;

        nonce_p
    }

    pub fn _proof_builder() -> *const c_void {
        let mut proof_builder: *const c_void = ptr::null();
        let err_code = indy_crypto_cl_prover_new_proof_builder(&mut proof_builder);

        assert_eq!(err_code, ErrorCode::Success);
        assert!(!proof_builder.is_null());

        proof_builder
    }

    pub fn _free_proof_builder(proof_builder: *const c_void, nonce_p: *const c_void, master_secret: *const c_void) {
        let mut proof: *const c_void = ptr::null();

        let err_code = indy_crypto_cl_proof_builder_finalize(proof_builder,
                                                             nonce_p,
                                                             master_secret,
                                                             &mut proof);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!proof.is_null());
    }

    pub fn _proof() -> *const c_void {
        let uuid = CString::new("uuid").unwrap();
        let (issuer_pub_key, issuer_priv_key) = _issuer_keys();
        let (rev_reg_pub, rev_reg_priv) = _revocation_registry(issuer_pub_key);
        let master_secret = _master_secret();
        let (blinded_master_secret, _) = _blinded_master_secret(issuer_pub_key, master_secret);
        let claim_values = _claim_values();
        let claim_schema = _claim_schema();
        let sub_proof_request = _sub_proof_request();

        let claim_signature = _claim_signature(blinded_master_secret, issuer_pub_key, issuer_priv_key, rev_reg_pub, rev_reg_priv, claim_values);

        let proof_builder = _proof_builder();

        indy_crypto_cl_proof_builder_add_sub_proof_request(proof_builder,
                                                           uuid.as_ptr(),
                                                           claim_signature,
                                                           claim_values,
                                                           issuer_pub_key,
                                                           rev_reg_pub,
                                                           sub_proof_request,
                                                           claim_schema);

        let nonce = BigNumber::rand(80);
        let nonce_p = Box::into_raw(Box::new(nonce)) as *const c_void;

        let mut proof: *const c_void = ptr::null();

        let err_code = indy_crypto_cl_proof_builder_finalize(proof_builder,
                                                             nonce_p,
                                                             master_secret,
                                                             &mut proof);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!proof.is_null());

        proof
    }

    pub fn _free_proof(proof: *const c_void) {
        let err_code = indy_crypto_cl_proof_free(proof);
        assert_eq!(err_code, ErrorCode::Success);
    }
}