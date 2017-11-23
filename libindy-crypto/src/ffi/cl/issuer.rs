use cl::issuer::*;
use cl::types::*;
use errors::ToErrorCode;
use ffi::ErrorCode;
use utils::ctypes::CTypesUtils;

use libc::c_char;

use std::os::raw::c_void;


/// Creates and returns issuer keys (public and private) entities.
///
/// Note that keys instances deallocation must be performed by
/// calling indy_crypto_cl_issuer_public_key_free and indy_crypto_cl_issuer_private_key_free.
///
/// # Arguments
/// * `claim_schema` - claim_signature schema instance pointer.
/// * `gen_rev_part` - If true non revocation part of issuer keys will be generated.
/// * `issuer_pub_key_p` - Reference that will contain issuer public key instance pointer.
/// * `issuer_priv_key_p` - Reference that will contain issuer private key instance pointer.
#[no_mangle]
pub extern fn indy_crypto_cl_issuer_new_keys(claim_schema: *const c_void,
                                             gen_rev_part: bool,
                                             issuer_pub_key_p: *mut *const c_void,
                                             issuer_priv_key_p: *mut *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_issuer_new_keys: >>> claim_schema: {:?}, gen_rev_part: {:?}, issuer_pub_key_p: {:?}, issuer_priv_key_p: {:?}",
           claim_schema, gen_rev_part, issuer_pub_key_p, issuer_priv_key_p);

    check_useful_c_reference!(claim_schema, ClaimSchema, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(issuer_pub_key_p, ErrorCode::CommonInvalidParam3);
    check_useful_c_ptr!(issuer_priv_key_p, ErrorCode::CommonInvalidParam4);

    let res = match Issuer::new_keys(claim_schema, gen_rev_part) {
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

/// Deallocates issuer public key instance.
///
/// # Arguments
/// * `issuer_pub_key` - Issuer public key instance pointer
#[no_mangle]
pub extern fn indy_crypto_cl_issuer_public_key_free(issuer_pub_key: *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_issuer_public_key_free: >>> issuer_pub_key: {:?}", issuer_pub_key);

    check_useful_c_ptr!(issuer_pub_key, ErrorCode::CommonInvalidParam1);

    unsafe { Box::from_raw(issuer_pub_key as *mut IssuerPublicKey); }
    let res = ErrorCode::Success;

    trace!("indy_crypto_cl_issuer_public_key_free: <<< res: {:?}", res);
    res
}

/// Deallocates issuer private key instance.
///
/// # Arguments
/// * `issuer_priv_key` - Issuer private key instance pointer
#[no_mangle]
pub extern fn indy_crypto_cl_issuer_private_key_free(issuer_priv_key: *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_issuer_public_key_free: >>> issuer_priv_key: {:?}", issuer_priv_key);

    check_useful_c_ptr!(issuer_priv_key, ErrorCode::CommonInvalidParam1);

    unsafe { Box::from_raw(issuer_priv_key as *mut IssuerPrimaryPrivateKey); }
    let res = ErrorCode::Success;

    trace!("indy_crypto_cl_issuer_public_key_free: <<< res: {:?}", res);
    res
}

/// Creates and returns revocation registries (public and private) entities.
///
/// Note that keys registries deallocation must be performed by
/// calling indy_crypto_cl_revocation_registry_public_free and
/// indy_crypto_cl_revocation_registry_private_free.
///
/// # Arguments
/// * `issuer_pub_key` - Issuer pub key instance pointer.
/// * `max_claim_num` - Max claim_signature number in generated registry.
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

/// Deallocates revocation registry public instance.
///
/// # Arguments
/// * `rev_reg_pub` - Revocation registry public instance pointer
#[no_mangle]
pub extern fn indy_crypto_cl_revocation_registry_public_free(rev_reg_pub: *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_revocation_registry_public_free: >>> rev_reg_pub: {:?}", rev_reg_pub);

    check_useful_c_ptr!(rev_reg_pub, ErrorCode::CommonInvalidParam1);
    unsafe { Box::from_raw(rev_reg_pub as *mut RevocationRegistryPublic); }
    let res = ErrorCode::Success;

    trace!("indy_crypto_cl_revocation_registry_public_free: <<< res: {:?}", res);
    res
}

/// Deallocates revocation registry private instance.
///
/// # Arguments
/// * `rev_reg_priv` - Revocation registry private instance pointer
#[no_mangle]
pub extern fn indy_crypto_cl_revocation_registry_private_free(rev_reg_priv: *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_revocation_registry_private_free: >>> rev_reg_priv: {:?}", rev_reg_priv);

    check_useful_c_ptr!(rev_reg_priv, ErrorCode::CommonInvalidParam1);

    unsafe { Box::from_raw(rev_reg_priv as *mut RevocationRegistryPrivate); }
    let res = ErrorCode::Success;

    trace!("indy_crypto_cl_revocation_registry_private_free: <<< res: {:?}", res);
    res
}

/// Sign given claim_signature values instance.
///
/// Note that claim_signature deallocation must be performed by
/// calling indy_crypto_cl_claim_signature_free
///
/// # Arguments
/// * `prover_id` - Prover identifier as null terminated string.
/// * `blinded_ms_p` - Blinded master secret instance pointer.
/// * `claim_values_p` - claim_signature values instance pointer.
/// * `issuer_pub_key_p` - Issuer public key instance pointer.
/// * `issuer_priv_key_p` - Issuer private key instance pointer.
/// * `rev_idx` - (Optional) User index in revocation accumulator. Required for non-revocation claim_signature part generation.
/// * `rev_reg_public_p` - (Optional) Revocation registry public instance pointer.
/// * `rev_reg_private_p` - (Optional) Revocation registry private instance pointer.
/// * `claim_signature_p` - Reference that will contain revocation registry private instance pointer.
#[no_mangle]
pub extern fn indy_crypto_cl_issuer_sign_claim(prover_id: *const c_char,
                                               blinded_ms_p: *const c_void,
                                               claim_values_p: *const c_void,
                                               issuer_pub_key_p: *const c_void,
                                               issuer_priv_key_p: *const c_void,
                                               rev_idx: i32,
                                               rev_reg_public_p: *const c_void,
                                               rev_reg_private_p: *const c_void,
                                               claim_signature_p: *mut *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_issuer_sign_claim: >>> prover_id: {:?}, blinded_ms_p: {:?}, claim_values_p: {:?}, issuer_pub_key_p: {:?}, \
    issuer_priv_key_p: {:?}, rev_idx: {:?}, rev_reg_public_p: {:?}, rev_reg_private_p: {:?}, claim_signature_p: {:?}",
           prover_id, blinded_ms_p, claim_values_p, issuer_pub_key_p, issuer_priv_key_p, rev_idx, rev_reg_public_p, rev_reg_private_p, claim_signature_p);

    check_useful_c_str!(prover_id, ErrorCode::CommonInvalidParam1);
    check_useful_c_reference!(blinded_ms_p, BlindedMasterSecret, ErrorCode::CommonInvalidParam2);
    check_useful_c_reference!(claim_values_p, ClaimValues, ErrorCode::CommonInvalidParam3);
    check_useful_c_reference!(issuer_pub_key_p, IssuerPublicKey, ErrorCode::CommonInvalidParam4);
    check_useful_c_reference!(issuer_priv_key_p, IssuerPrivateKey, ErrorCode::CommonInvalidParam5);
    check_useful_opt_c_reference!(rev_reg_private_p, RevocationRegistryPrivate, ErrorCode::CommonInvalidParam7);

    let rev_idx = if rev_idx != -1 { Some(rev_idx as u32) } else { None };

    let mut rev_reg_public = if rev_reg_public_p.is_null() { None } else {
        Some(unsafe { Box::from_raw(rev_reg_public_p as *mut RevocationRegistryPublic) })
    };

    let res = match Issuer::sign_claim(&prover_id,
                                       &blinded_ms_p,
                                       &claim_values_p,
                                       &issuer_pub_key_p,
                                       &issuer_priv_key_p,
                                       rev_idx,
                                       rev_reg_public.as_mut().map(|r| r.as_mut()),
                                       rev_reg_private_p) {
        Ok(claim_signature) => {
            trace!("indy_crypto_cl_issuer_sign_claim: claim_signature: {:?}", claim_signature);
            unsafe {
                *claim_signature_p = Box::into_raw(Box::new(claim_signature)) as *const c_void;
                rev_reg_public.map(Box::into_raw);
                trace!("indy_crypto_cl_issuer_sign_claim: *claim_signature_p: {:?}", *claim_signature_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_cl_issuer_sign_claim: <<< res: {:?}", res);
    res
}

/// Deallocates claim_signature signature instance.
///
/// # Arguments
/// * `claim_signature_p` - Revocation claim_signature signature instance pointer
#[no_mangle]
pub extern fn indy_crypto_cl_claim_signature_free(claim_signature_p: *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_claim_signature_free: >>> claim_signature_p: {:?}", claim_signature_p);

    check_useful_c_ptr!(claim_signature_p, ErrorCode::CommonInvalidParam1);

    unsafe { Box::from_raw(claim_signature_p as *mut ClaimSignature); }
    let res = ErrorCode::Success;

    trace!("indy_crypto_cl_claim_signature_free: <<< res: {:?}", res);
    res
}

/// Revokes a claim_signature by a revoc_id in a given revoc-registry
///
/// # Arguments
/// * `r_reg_p` - Reference that contain revocation registry instance pointer.
///  * acc_idx` - index of the user in the accumulator
#[no_mangle]
pub extern fn indy_crypto_cl_issuer_revoke_claim(r_reg_p: *const c_void,
                                                 acc_idx: u32) -> ErrorCode {
    trace!("indy_crypto_cl_issuer_revoke_claim: >>> r_reg_p: {:?}, acc_idx: {:?}", r_reg_p, acc_idx);

    check_useful_c_ptr!(r_reg_p, ErrorCode::CommonInvalidParam1);

    let mut r_reg_p = unsafe { Box::from_raw(r_reg_p as *mut RevocationRegistryPublic) };

    let res = match Issuer::revoke_claim(&mut r_reg_p, acc_idx) {
        Ok(()) => {
            Box::into_raw(r_reg_p);
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_cl_issuer_revoke_claim: <<< res: {:?}", res);
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
    fn indy_crypto_cl_issuer_new_keys_works() {
        let claim_schema = _claim_schema();
        let mut issuer_pub_key: *const c_void = ptr::null();
        let mut issuer_priv_key: *const c_void = ptr::null();

        let err_code = indy_crypto_cl_issuer_new_keys(claim_schema, true, &mut issuer_pub_key, &mut issuer_priv_key);

        assert_eq!(err_code, ErrorCode::Success);
        assert!(!issuer_pub_key.is_null());
        assert!(!issuer_priv_key.is_null());

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
        let prover_id = CString::new("CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW").unwrap();
        let claim_values = _claim_values();
        let (issuer_pub_key, issuer_priv_key) = _issuer_keys();
        let (rev_reg_pub, rev_reg_priv) = _revocation_registry(issuer_pub_key);
        let master_secret = _master_secret();
        let (blinded_master_secret, blinded_master_secret_data) = _blinded_master_secret(issuer_pub_key, master_secret);
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
        _free_blinded_master_secret(blinded_master_secret, blinded_master_secret_data);
        _free_claim_signature(claim_signature);
    }

    #[test]
    fn indy_crypto_cl_claim_signature_free_works() {
        let (issuer_pub_key, issuer_priv_key) = _issuer_keys();
        let (rev_reg_pub, rev_reg_priv) = _revocation_registry(issuer_pub_key);
        let master_secret = _master_secret();
        let (blinded_master_secret, blinded_master_secret_data) = _blinded_master_secret(issuer_pub_key, master_secret);
        let claim_values = _claim_values();

        let claim_signature = _claim_signature(blinded_master_secret, issuer_pub_key, issuer_priv_key, rev_reg_pub, rev_reg_priv, claim_values);

        _free_issuer_keys(issuer_pub_key, issuer_priv_key);
        _free_revocation_registry(rev_reg_pub, rev_reg_priv);
        _free_blinded_master_secret(blinded_master_secret, blinded_master_secret_data);
        _free_claim_values(claim_values);

        let err_code = indy_crypto_cl_claim_signature_free(claim_signature);
        assert_eq!(err_code, ErrorCode::Success);
    }

    #[test]
    fn indy_crypto_cl_issuer_revoke_claim_works() {
        let (issuer_pub_key, issuer_priv_key) = _issuer_keys();
        let (rev_reg_pub_p, rev_reg_priv_p) = _revocation_registry(issuer_pub_key);
        let master_secret = _master_secret();
        let (blinded_master_secret, blinded_master_secret_data) = _blinded_master_secret(issuer_pub_key, master_secret);
        let claim_values = _claim_values();

        let claim_signature = _claim_signature(blinded_master_secret, issuer_pub_key, issuer_priv_key, rev_reg_pub_p, rev_reg_priv_p, claim_values);

        let err_code = indy_crypto_cl_issuer_revoke_claim(rev_reg_pub_p, 1);
        assert_eq!(err_code, ErrorCode::Success);

        _free_issuer_keys(issuer_pub_key, issuer_priv_key);
        _free_revocation_registry(rev_reg_pub_p, rev_reg_priv_p);
        _free_blinded_master_secret(blinded_master_secret, blinded_master_secret_data);
        _free_claim_signature(claim_signature);
        _free_claim_values(claim_values);
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
                            rev_reg_pub: *const c_void, rev_reg_priv: *const c_void, claim_values: *const c_void) -> *const c_void {
        let prover_id = CString::new("CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW").unwrap();
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

        claim_signature
    }

    pub fn _free_claim_signature(claim_signature: *const c_void) {
        let err_code = indy_crypto_cl_claim_signature_free(claim_signature);
        assert_eq!(err_code, ErrorCode::Success);
    }
}