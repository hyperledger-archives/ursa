use anoncreds::prover::*;
use anoncreds::types::*;

use ffi::ErrorCode;
use errors::ToErrorCode;
use utils::ctypes::CTypesUtils;

use libc::c_char;

use std::os::raw::c_void;
use bn::BigNumber;


/// Creates a master secret
///
/// Note that master secret deallocation must be performed by
/// calling indy_crypto_anoncreds_prover_master_secret_free
///
///
/// # Arguments
/// * `master_secret_p` - Reference that will contain master secret instance pointer.
#[no_mangle]
pub extern fn indy_crypto_anoncreds_prover_generate_master_secret(master_secret_p: *mut *const c_void) -> ErrorCode {
    trace!("indy_crypto_anoncreds_prover_generate_master_secret: >>> {:?}", master_secret_p);

    check_useful_c_ptr!(master_secret_p, ErrorCode::CommonInvalidParam1);

    let res = match Prover::generate_master_secret() {
        Ok(master_secret) => {
            trace!("indy_crypto_anoncreds_prover_generate_master_secret: master_secret: {:?}", master_secret);
            unsafe {
                *master_secret_p = Box::into_raw(Box::new(master_secret)) as *const c_void;
                trace!("indy_crypto_anoncreds_prover_generate_master_secret: *master_secret_p: {:?}", *master_secret_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_anoncreds_prover_generate_master_secret: <<< res: {:?}", res);
    res
}

/// Deallocates master secret instance.
///
/// # Arguments
/// * `master_secret_p` - Master secret instance pointer
#[no_mangle]
pub extern fn indy_crypto_anoncreds_prover_master_secret_free(master_secret_p: *const c_void) -> ErrorCode {
    trace!("indy_crypto_anoncreds_prover_master_secret_free: >>> claim_p: {:?}", master_secret_p);

    check_useful_c_ptr!(master_secret_p, ErrorCode::CommonInvalidParam1);

    unsafe { Box::from_raw(master_secret_p as *mut MasterSecret); }
    let res = ErrorCode::Success;

    trace!("indy_crypto_anoncreds_prover_master_secret_free: <<< res: {:?}", res);
    res
}

/// Creates blinded master secret for given keys and master secret
///
/// Note that blinded master secret deallocation must be performed by
/// calling indy_crypto_anoncreds_prover_blinded_master_secret_free
///
/// Note that blinded master secret data deallocation must be performed by
/// calling indy_crypto_anoncreds_prover_blinded_master_secret_data_free
///
/// # Arguments
/// * `pub_key_p` - Reference that contain public keys instance pointer.
/// * `master_secret_p` - Reference that contain master secret instance pointer.
/// * `blinded_master_secret_p` - Reference that will contain blinded master secret instance pointer.
/// * `blinded_master_secret_data_p` - Reference that will contain blinded master secret data instance pointer.
#[no_mangle]
pub extern fn indy_crypto_anoncreds_prover_generate_blinded_master_secret(pub_key_p: *const c_void,
                                                                          master_secret_p: *const c_void,
                                                                          blinded_master_secret_p: *mut *const c_void,
                                                                          blinded_master_secret_data_p: *mut *const c_void) -> ErrorCode {
    trace!("indy_crypto_anoncreds_generate_blinded_master_secret: >>> pub_key_p: {:?}, master_secret_p: {:?}, blinded_master_secret_p: {:?}, blinded_master_secret_data_p: {:?}",
           pub_key_p, master_secret_p, blinded_master_secret_p, blinded_master_secret_data_p);

    check_useful_c_reference!(pub_key_p, IssuerPublicKey, ErrorCode::CommonInvalidParam1);
    check_useful_c_reference!(master_secret_p, MasterSecret, ErrorCode::CommonInvalidParam2);
    check_useful_c_ptr!(blinded_master_secret_p, ErrorCode::CommonInvalidParam3);
    check_useful_c_ptr!(blinded_master_secret_data_p, ErrorCode::CommonInvalidParam4);

    let res = match Prover::generate_blinded_master_secret(pub_key_p, master_secret_p) {
        Ok((blinded_master_secret, blinded_master_secret_data)) => {
            trace!("indy_crypto_anoncreds_generate_blinded_master_secret: blinded_master_secret: {:?}, blinded_master_secret_data: {:?}",
                   blinded_master_secret, blinded_master_secret_data);
            unsafe {
                *blinded_master_secret_p = Box::into_raw(Box::new(blinded_master_secret)) as *const c_void;
                *blinded_master_secret_data_p = Box::into_raw(Box::new(blinded_master_secret_data)) as *const c_void;
                trace!("indy_crypto_anoncreds_generate_blinded_master_secret: *blinded_master_secret_p: {:?}, *blinded_master_secret_p: {:?}",
                       *blinded_master_secret_p, *blinded_master_secret_data_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_anoncreds_generate_blinded_master_secret: <<< res: {:?}", res);
    res
}

/// Deallocates  blinded master secret instance.
///
/// # Arguments
/// * `blinded_master_secret_p` - Master secret instance pointer
#[no_mangle]
pub extern fn indy_crypto_anoncreds_prover_blinded_master_secret_free(blinded_master_secret_p: *const c_void) -> ErrorCode {
    trace!("indy_crypto_anoncreds_prover_blinded_master_secret_free: >>> blinded_master_secret_p: {:?}", blinded_master_secret_p);

    check_useful_c_ptr!(blinded_master_secret_p, ErrorCode::CommonInvalidParam1);

    unsafe { Box::from_raw(blinded_master_secret_p as *mut MasterSecret); }
    let res = ErrorCode::Success;

    trace!("indy_crypto_anoncreds_prover_blinded_master_secret_free: <<< res: {:?}", res);
    res
}

/// Deallocates  blinded master secret data instance.
///
/// # Arguments
/// * `blinded_master_secret_data_p` - Master secret instance pointer
#[no_mangle]
pub extern fn indy_crypto_anoncreds_prover_blinded_master_secret_data_free(blinded_master_secret_data_p: *const c_void) -> ErrorCode {
    trace!("indy_crypto_anoncreds_prover_blinded_master_secret_data_free: >>> blinded_master_secret_data_p: {:?}", blinded_master_secret_data_p);

    check_useful_c_ptr!(blinded_master_secret_data_p, ErrorCode::CommonInvalidParam1);

    unsafe { Box::from_raw(blinded_master_secret_data_p as *mut MasterSecret); }
    let res = ErrorCode::Success;

    trace!("indy_crypto_anoncreds_prover_blinded_master_secret_data_free: <<< res: {:?}", res);
    res
}

/// Updates the claim by a master secret blinded data.
///
///
/// # Arguments
/// * `claim_p` - Reference that contain claim instance pointer.
/// * `blinded_master_secret_data_p` - Reference that contain blinded master secret data instance pointer.
/// * `r_pub_key_p` - Reference that contain revocation public key instance pointer.
/// * `r_reg` - Reference that contain revocation registry instance pointer.
#[no_mangle]
pub extern fn indy_crypto_anoncreds_prover_process_claim(claim_p: *const c_void,
                                                         blinded_master_secret_data_p: *const c_void,
                                                         pub_key_p: *const c_void,
                                                         r_reg: *const c_void) -> ErrorCode {
    trace!("indy_crypto_anoncreds_prover_process_claim: >>> claim_p: {:?}, blinded_master_secret_data_p: {:?}, r_pub_key_p: {:?}, r_reg: {:?}",
           claim_p, blinded_master_secret_data_p, pub_key_p, r_reg);

    check_useful_c_ptr!(claim_p, ErrorCode::CommonInvalidParam1);
    check_useful_c_reference!(blinded_master_secret_data_p, BlindedMasterSecretData, ErrorCode::CommonInvalidParam2);
    check_useful_c_reference!(pub_key_p, IssuerPublicKey, ErrorCode::CommonInvalidParam3);
    check_useful_opt_c_reference!(r_reg, RevocationRegistryPublic, ErrorCode::CommonInvalidParam4);

    let mut claim = unsafe { Box::from_raw(claim_p as *mut Claim) };


    let res = match Prover::process_claim(&mut claim,
                                          blinded_master_secret_data_p,
                                          pub_key_p,
                                          r_reg) {
        Ok(()) => {
            Box::into_raw(claim);
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_anoncreds_prover_process_claim: <<< res: {:?}", res);
    res
}

/// Creates and returns proof builder.
///
/// Note that proof builder deallocation must be performed by
/// calling indy_crypto_anoncreds_prover_proof_builder_finalize
///
/// # Arguments
/// * `proof_builder_p` - Reference that will contain proof builder instance pointer.
#[no_mangle]
pub extern fn indy_crypto_anoncreds_prover_proof_builder_new(proof_builder_p: *mut *const c_void) -> ErrorCode {
    trace!("indy_crypto_anoncreds_prover_proof_builder_new: >>> {:?}", proof_builder_p);

    check_useful_c_ptr!(proof_builder_p, ErrorCode::CommonInvalidParam1);

    let res = match ProofBuilder::new() {
        Ok(proof_builder) => {
            trace!("indy_crypto_anoncreds_prover_proof_builder_new: proof_builder: {:?}", proof_builder);
            unsafe {
                *proof_builder_p = Box::into_raw(Box::new(proof_builder)) as *const c_void;
                trace!("indy_crypto_anoncreds_prover_proof_builder_new: *proof_builder_p: {:?}", *proof_builder_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_anoncreds_prover_proof_builder_new: <<< res: {:?}", res);
    res
}

/// Add claim to proof builder which will be used fo building of proof.
///
/// # Arguments
/// * `proof_builder_p` - Reference that contain proof builder instance pointer.
/// * `uuid` - unique claim identifier.
/// * `claim_p` - Reference that contain claim instance pointer.
/// * `claim_attributes_values_p` - Reference that contain claim attributes instance pointer.
/// * `pub_key_p` - Reference that contain public key instance pointer.
/// * `r_reg_p` - Reference that contain public revocation registry instance pointer.
/// * `attrs_with_predicates_p` - Reference that contain requested attributes and predicates instance pointer.
#[no_mangle]
pub extern fn indy_crypto_anoncreds_prover_proof_builder_add_claim(proof_builder_p: *const c_void,
                                                                   uuid: *const c_char,
                                                                   claim_p: *const c_void,
                                                                   claim_attributes_values_p: *const c_void,
                                                                   pub_key_p: *const c_void,
                                                                   r_reg_p: *const c_void,
                                                                   attrs_with_predicates_p: *const c_void) -> ErrorCode {
    trace!("indy_crypto_anoncreds_prover_proof_builder_add_claim: >>> proof_builder_p: {:?},uuid: {:?},claim_p: {:?},\
            claim_attributes_values_p: {:?},pub_key_p: {:?},r_reg_p: {:?},,attrs_with_predicates_p: {:?}",
           proof_builder_p, uuid, claim_p, claim_attributes_values_p, pub_key_p, r_reg_p, attrs_with_predicates_p);

    check_useful_c_ptr!(proof_builder_p, ErrorCode::CommonInvalidParam1);
    check_useful_c_str!(uuid, ErrorCode::CommonInvalidParam2);
    check_useful_c_reference!(claim_p, Claim, ErrorCode::CommonInvalidParam3);
    check_useful_c_reference!(claim_attributes_values_p, ClaimAttributesValues, ErrorCode::CommonInvalidParam3);
    check_useful_c_reference!(pub_key_p, IssuerPublicKey, ErrorCode::CommonInvalidParam3);
    check_useful_opt_c_reference!(r_reg_p, RevocationRegistryPublic, ErrorCode::CommonInvalidParam3);
    check_useful_c_reference!(attrs_with_predicates_p, AttrsWithPredicates, ErrorCode::CommonInvalidParam3);

    let mut proof_builder = unsafe { Box::from_raw(proof_builder_p as *mut ProofBuilder) };

    let res = match ProofBuilder::add_claim(&mut proof_builder,
                                            &uuid,
                                            claim_p,
                                            claim_attributes_values_p,
                                            pub_key_p,
                                            r_reg_p,
                                            attrs_with_predicates_p) {
        Ok(()) => ErrorCode::Success,
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_anoncreds_prover_proof_builder_add_claim: <<< res: {:?}", res);
    res
}


/// Finalize proof
///
/// Note that proof deallocation must be performed by
/// calling indy_crypto_anoncreds_proof_free
///
/// # Arguments
/// * `proof_builder_p` - Reference that contain proof builder instance pointer.
/// * `proof_req_p` - Reference that contain proof request instance pointer.
/// * `master_secret_p` - Reference that contain master secret instance pointer.
/// * `proof_p` - Reference that will contain proof instance pointer.
#[no_mangle]
pub extern fn indy_crypto_anoncreds_prover_proof_builder_finalize(proof_builder_p: *const c_void,
                                                                  nonce_p: *const c_void,
                                                                  master_secret_p: *const c_void,
                                                                  proof_p: *mut *const c_void) -> ErrorCode {
    trace!("indy_crypto_anoncreds_prover_proof_builder_finalize: >>> proof_builder_p: {:?}, nonce_p: {:?}, master_secret_p: {:?}, proof_p: {:?}",
           proof_builder_p, nonce_p, master_secret_p, proof_p);

    check_useful_c_ptr!(proof_builder_p, ErrorCode::CommonInvalidParam1);
    check_useful_c_reference!(nonce_p, BigNumber, ErrorCode::CommonInvalidParam2);
    check_useful_c_reference!(master_secret_p, MasterSecret, ErrorCode::CommonInvalidParam2);
    check_useful_c_ptr!(proof_p, ErrorCode::CommonInvalidParam4);

    let mut proof_builder = unsafe { Box::from_raw(proof_builder_p as *mut ProofBuilder) };

    let res = match ProofBuilder::finalize(&mut proof_builder, nonce_p, master_secret_p) {
        Ok(proof) => {
            trace!("indy_crypto_anoncreds_prover_proof_builder_finalize: proof: {:?}", proof);
            unsafe {
                *proof_p = Box::into_raw(Box::new(proof)) as *const c_void;
                trace!("indy_crypto_anoncreds_prover_proof_builder_finalize: *proof_p: {:?}", *proof_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_anoncreds_prover_proof_builder_finalize: <<< res: {:?}", res);
    res
}

/// Deallocates proof instance.
///
/// # Arguments
/// * `proof_p` - Proof builder instance pointer
#[no_mangle]
pub extern fn indy_crypto_anoncreds_proof_free(proof_p: *const c_void) -> ErrorCode {
    trace!("indy_crypto_anoncreds_proof_free: >>> proof_p: {:?}", proof_p);

    check_useful_c_ptr!(proof_p, ErrorCode::CommonInvalidParam1);

    unsafe { Box::from_raw(proof_p as *mut Proof); }
    let res = ErrorCode::Success;

    trace!("indy_crypto_anoncreds_proof_free: <<< res: {:?}", res);
    res
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::ptr;
    use std::ffi::CString;
    use ffi::anoncreds::mocks::*;
    use ffi::issuer::mocks::*;
    use ffi::prover::mocks::*;

    #[test]
    fn indy_crypto_anoncreds_prover_generate_master_secret_works() {
        let mut master_secret_p: *const c_void = ptr::null();
        let err_code = indy_crypto_anoncreds_prover_generate_master_secret(&mut master_secret_p);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!master_secret_p.is_null());

        _free_master_secret(master_secret_p)
    }

    #[test]
    fn indy_crypto_anoncreds_prover_master_secret_free_works() {
        let master_secret = _master_secret();

        let err_code = indy_crypto_anoncreds_prover_master_secret_free(master_secret);
        assert_eq!(err_code, ErrorCode::Success);
    }

    #[test]
    fn indy_crypto_anoncreds_prover_generate_blinded_master_secret_works() {
        let master_secret = _master_secret();
        let (pub_keys, _) = _issuer_keys();

        let mut blinded_master_secret_p: *const c_void = ptr::null();
        let mut blinded_master_secret_data_p: *const c_void = ptr::null();

        let err_code = indy_crypto_anoncreds_prover_generate_blinded_master_secret(pub_keys, master_secret,
                                                                                   &mut blinded_master_secret_p, &mut blinded_master_secret_data_p);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!blinded_master_secret_p.is_null());
        assert!(!blinded_master_secret_data_p.is_null());

        _free_blinded_master_secret(blinded_master_secret_p, blinded_master_secret_data_p);
    }

    #[test]
    fn indy_crypto_anoncreds_prover_blinded_master_secret_data_free_works() {
        let master_secret = _master_secret();
        let (pub_keys, _) = _issuer_keys();

        let (blinded_master_secret, blinded_master_secret_data) = _blinded_master_secret(pub_keys, master_secret);

        let err_code = indy_crypto_anoncreds_prover_blinded_master_secret_free(blinded_master_secret);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = indy_crypto_anoncreds_prover_blinded_master_secret_data_free(blinded_master_secret_data);
        assert_eq!(err_code, ErrorCode::Success);
    }

    #[test]
    fn indy_crypto_anoncreds_prover_process_claim_works() {
        let (issuer_pub_key, issuer_priv_key) = _issuer_keys();
        let (rev_reg_pub, rev_reg_priv) = _revocation_registry(issuer_pub_key);
        let master_secret = _master_secret();
        let (blinded_master_secret, blinded_master_secret_data) = _blinded_master_secret(issuer_pub_key, master_secret);
        let attr_values = _claim_attrs_values();

        let claim = _claim(blinded_master_secret, issuer_pub_key, issuer_priv_key, rev_reg_pub, rev_reg_priv, attr_values);

        let err_code = indy_crypto_anoncreds_prover_process_claim(claim,
                                                                  blinded_master_secret_data,
                                                                  issuer_pub_key,
                                                                  rev_reg_pub);
        assert_eq!(err_code, ErrorCode::Success);

        _free_issuer_keys(issuer_pub_key, issuer_priv_key);
        _free_revocation_registry(rev_reg_pub, rev_reg_priv);
        _free_blinded_master_secret(blinded_master_secret, blinded_master_secret_data);
        _free_claim_attrs_values(attr_values);

        _free_claim(claim);
    }

    //    #[test]
    //    fn indy_crypto_anoncreds_prover_proof_builder_new_works() {
    //        let mut proof_builder: *const c_void = ptr::null();
    //        let err_code = indy_crypto_anoncreds_prover_proof_builder_new(&mut proof_builder);
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
    //    fn indy_crypto_anoncreds_prover_proof_builder_add_claim_works() {
    //        let uuid = CString::new("uuid").unwrap();
    //        let (issuer_pub_key, issuer_priv_key) = _issuer_keys();
    //        let (rev_reg_pub, rev_reg_priv) = _revocation_registry(issuer_pub_key);
    //        let master_secret = _master_secret();
    //        let (blinded_master_secret, blinded_master_secret_data) = _blinded_master_secret(issuer_pub_key, master_secret);
    //        let attr_values = _claim_attrs_values();
    //        let attrs_with_predicates = _attrs_with_predicates();
    //        let attr_values = _claim_attrs_values();
    //
    //        let claim = _claim(blinded_master_secret, issuer_pub_key, issuer_priv_key, rev_reg_pub, rev_reg_priv, attr_values);
    //
    //        let mut proof_builder = _proof_builder();
    //
    //        indy_crypto_anoncreds_prover_proof_builder_add_claim(proof_builder,
    //                                                             uuid.as_ptr(),
    //                                                             claim,
    //                                                             attr_values,
    //                                                             issuer_pub_key,
    //                                                             rev_reg_pub,
    //                                                             attrs_with_predicates);
    //        let nonce = _nonce();
    //        _free_proof_builder(proof_builder, nonce, master_secret);
    //    }
//
    //    #[test]
    //    fn indy_crypto_anoncreds_prover_proof_builder_finalize_works() {
    //        let uuid = CString::new("uuid").unwrap();
    //        let (issuer_pub_key, issuer_priv_key) = _issuer_keys();
    //        let (rev_reg_pub, rev_reg_priv) = _revocation_registry(issuer_pub_key);
    //        let master_secret = _master_secret();
    //        let (blinded_master_secret, blinded_master_secret_data) = _blinded_master_secret(issuer_pub_key, master_secret);
    //        let attr_values = _claim_attrs_values();
    //        let attrs_with_predicates = _attrs_with_predicates();
    //
    //        let claim = _claim(blinded_master_secret, issuer_pub_key, issuer_priv_key, rev_reg_pub, rev_reg_priv, attr_values);
    //
    //        let mut proof_builder = _proof_builder();
    //
    //
    //        indy_crypto_anoncreds_prover_proof_builder_add_claim(proof_builder,
    //                                                             uuid.as_ptr(),
    //                                                             claim,
    //                                                             attr_values,
    //                                                             issuer_pub_key,
    //                                                             rev_reg_pub,
    //                                                             attrs_with_predicates);
    //
    //        let nonce = _nonce();
    //
    //        let mut proof: *const c_void = ptr::null();
    //        let err_code = indy_crypto_anoncreds_prover_proof_builder_finalize(proof_builder,
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
    //    fn indy_crypto_anoncreds_proof_free_works() {
    //        let proof = _proof();
    //
    //        let err_code = indy_crypto_anoncreds_proof_free(proof);
    //        assert_eq!(err_code, ErrorCode::Success);
    //    }
}

pub mod mocks {
    use super::*;

    use std::ptr;
    use std::ffi::CString;
    use ffi::anoncreds::mocks::*;
    use ffi::issuer::mocks::*;

    pub fn _master_secret() -> *const c_void {
        let mut master_secret_p: *const c_void = ptr::null();
        let err_code = indy_crypto_anoncreds_prover_generate_master_secret(&mut master_secret_p);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!master_secret_p.is_null());

        master_secret_p
    }

    pub fn _free_master_secret(master_secret: *const c_void) {
        let err_code = indy_crypto_anoncreds_prover_master_secret_free(master_secret);
        assert_eq!(err_code, ErrorCode::Success);
    }

    pub fn _blinded_master_secret(pub_keys: *const c_void, master_secret: *const c_void) -> (*const c_void, *const c_void) {
        let mut blinded_master_secret_p: *const c_void = ptr::null();
        let mut blinded_master_secret_data_p: *const c_void = ptr::null();

        let err_code = indy_crypto_anoncreds_prover_generate_blinded_master_secret(pub_keys, master_secret,
                                                                                   &mut blinded_master_secret_p, &mut blinded_master_secret_data_p);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!blinded_master_secret_p.is_null());
        assert!(!blinded_master_secret_data_p.is_null());

        (blinded_master_secret_p, blinded_master_secret_data_p)
    }

    pub fn _free_blinded_master_secret(blinded_master_secret_p: *const c_void, blinded_master_secret_data_p: *const c_void) {
        let err_code = indy_crypto_anoncreds_prover_blinded_master_secret_free(blinded_master_secret_p);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = indy_crypto_anoncreds_prover_blinded_master_secret_data_free(blinded_master_secret_data_p);
        assert_eq!(err_code, ErrorCode::Success);
    }

    pub fn _nonce() -> *const c_void {
        let nonce = BigNumber::rand(80).unwrap();
        let nonce_p = Box::into_raw(Box::new(nonce)) as *const c_void;

        nonce_p
    }

    pub fn _proof_builder() -> *const c_void {
        let mut proof_builder: *const c_void = ptr::null();
        let err_code = indy_crypto_anoncreds_prover_proof_builder_new(&mut proof_builder);

        assert_eq!(err_code, ErrorCode::Success);
        assert!(!proof_builder.is_null());

        proof_builder
    }

    pub fn _free_proof_builder(proof_builder: *const c_void, nonce_p: *const c_void, master_secret: *const c_void) {
        let mut proof: *const c_void = ptr::null();

        let err_code = indy_crypto_anoncreds_prover_proof_builder_finalize(proof_builder,
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
        let (blinded_master_secret, blinded_master_secret_data) = _blinded_master_secret(issuer_pub_key, master_secret);
        let attr_values = _claim_attrs_values();
        let attrs_with_predicates = _attrs_with_predicates();

        let claim = _claim(blinded_master_secret, issuer_pub_key, issuer_priv_key, rev_reg_pub, rev_reg_priv, attr_values);

        let mut proof_builder = _proof_builder();

        indy_crypto_anoncreds_prover_proof_builder_add_claim(proof_builder,
                                                             uuid.as_ptr(),
                                                             claim,
                                                             attr_values,
                                                             issuer_pub_key,
                                                             rev_reg_pub,
                                                             attrs_with_predicates);

        let nonce = BigNumber::rand(80);
        let nonce_p = Box::into_raw(Box::new(nonce)) as *const c_void;

        let mut proof: *const c_void = ptr::null();

        let err_code = indy_crypto_anoncreds_prover_proof_builder_finalize(proof_builder,
                                                                           nonce_p,
                                                                           master_secret,
                                                                           &mut proof);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!proof.is_null());

        proof
    }

    pub fn _free_proof(proof: *const c_void) {
        let err_code = indy_crypto_anoncreds_proof_free(proof);
        assert_eq!(err_code, ErrorCode::Success);
    }
}