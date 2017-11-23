use anoncreds::issuer::*;
use anoncreds::types::*;

use ffi::ErrorCode;
use errors::ToErrorCode;
use utils::ctypes::CTypesUtils;

use libc::c_char;

use std::os::raw::c_void;


/// Creates and returns issuer keys (public and private) entities.
///
/// Note that keys instances deallocation must be performed by
/// calling indy_crypto_anoncreds_issuer_public_key_free and indy_crypto_anoncreds_issuer_private_key_free.
///
/// # Arguments
/// * `claim_attrs` - Claim attributes instance pointer.
/// * `gen_rev_part` - If true non revocation part of issuer keys will be generated.
/// * `issuer_pub_key_p` - Reference that will contain issuer public key instance pointer.
/// * `issuer_priv_key_p` - Reference that will contain issuer private key instance pointer.
#[no_mangle]
pub extern fn indy_crypto_anoncreds_issuer_new_keys(claim_attrs: *const c_void,
                                                    gen_rev_part: bool,
                                                    issuer_pub_key_p: *mut *const c_void,
                                                    issuer_priv_key_p: *mut *const c_void) -> ErrorCode {
    trace!("indy_crypto_anoncreds_issuer_new_keys: >>> gen_rev_part: {:?}, issuer_pub_key_p: {:?}, issuer_priv_key_p: {:?}",
           gen_rev_part, issuer_pub_key_p, issuer_priv_key_p);

    check_useful_c_reference!(claim_attrs, ClaimAttributes, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(issuer_pub_key_p, ErrorCode::CommonInvalidParam3);
    check_useful_c_ptr!(issuer_priv_key_p, ErrorCode::CommonInvalidParam4);

    let res = match Issuer::new_keys(claim_attrs, gen_rev_part) {
        Ok((issuer_pub_key, issuer_priv_key)) => {
            trace!("indy_crypto_anoncreds_issuer_new_keys: issuer_pub_key: {:?}, issuer_priv_key: {:?}", issuer_pub_key, issuer_priv_key);
            unsafe {
                *issuer_pub_key_p = Box::into_raw(Box::new(issuer_pub_key)) as *const c_void;
                *issuer_priv_key_p = Box::into_raw(Box::new(issuer_priv_key)) as *const c_void;
                trace!("indy_crypto_anoncreds_issuer_new_keys: *issuer_pub_key_p: {:?}, *issuer_priv_key_p: {:?}", *issuer_pub_key_p, *issuer_priv_key_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_anoncreds_issuer_new_keys: <<< res: {:?}", res);
    res
}

/// Deallocates issuer public key instance.
///
/// # Arguments
/// * `issuer_pub_key` - Issuer public key instance pointer
#[no_mangle]
pub extern fn indy_crypto_anoncreds_issuer_public_key_free(issuer_pub_key: *const c_void) -> ErrorCode {
    trace!("indy_crypto_anoncreds_issuer_public_key_free: >>> issuer_pub_key: {:?}", issuer_pub_key);

    check_useful_c_ptr!(issuer_pub_key, ErrorCode::CommonInvalidParam1);

    unsafe { Box::from_raw(issuer_pub_key as *mut IssuerPublicKey); }
    let res = ErrorCode::Success;

    trace!("indy_crypto_anoncreds_issuer_public_key_free: <<< res: {:?}", res);
    res
}

/// Deallocates issuer private key instance.
///
/// # Arguments
/// * `issuer_priv_key` - Issuer private key instance pointer
#[no_mangle]
pub extern fn indy_crypto_anoncreds_issuer_private_key_free(issuer_priv_key: *const c_void) -> ErrorCode {
    trace!("indy_crypto_anoncreds_issuer_public_key_free: >>> issuer_priv_key: {:?}", issuer_priv_key);

    check_useful_c_ptr!(issuer_priv_key, ErrorCode::CommonInvalidParam1);

    unsafe { Box::from_raw(issuer_priv_key as *mut IssuerPrimaryPrivateKey); }
    let res = ErrorCode::Success;

    trace!("indy_crypto_anoncreds_issuer_public_key_free: <<< res: {:?}", res);
    res
}

/// Creates and returns revocation registries (public and private) entities.
///
/// Note that keys registries deallocation must be performed by
/// calling indy_crypto_anoncreds_revocation_registry_public_free and
/// indy_crypto_anoncreds_revocation_registry_private_free.
///
/// # Arguments
/// * `issuer_pub_key` - Issuer pub key instance pointer.
/// * `max_claim_num` - Max claim number in generated registry.
/// * `rev_reg_pub_p` - Reference that will contain revocation registry public instance pointer.
/// * `rev_reg_priv_p` - Reference that will contain revocation registry private instance pointer.
#[no_mangle]
pub extern fn indy_crypto_anoncreds_issuer_new_revocation_registry(issuer_pub_key: *const c_void,
                                                                   max_claim_num: u32,
                                                                   rev_reg_pub_p: *mut *const c_void,
                                                                   rev_reg_priv_p: *mut *const c_void) -> ErrorCode {
    trace!("indy_crypto_anoncreds_issuer_new_revocation_registry: >>> rev_reg_pub: {:?}, max_claim_num: {:?}, rev_reg_pub_p: {:?}, rev_reg_priv_p: {:?}",
           issuer_pub_key, max_claim_num, rev_reg_pub_p, rev_reg_priv_p);

    check_useful_c_reference!(issuer_pub_key, IssuerPublicKey, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(rev_reg_pub_p, ErrorCode::CommonInvalidParam3);
    check_useful_c_ptr!(rev_reg_priv_p, ErrorCode::CommonInvalidParam4);

    let res = match Issuer::new_revocation_registry(issuer_pub_key, max_claim_num) {
        Ok((rev_reg_pub, rev_reg_priv)) => {
            trace!("indy_crypto_anoncreds_issuer_new_revocation_registry: rev_reg_pub: {:?}, rev_reg_priv: {:?}", rev_reg_pub, rev_reg_priv);
            unsafe {
                *rev_reg_pub_p = Box::into_raw(Box::new(rev_reg_pub)) as *const c_void;
                *rev_reg_priv_p = Box::into_raw(Box::new(rev_reg_priv)) as *const c_void;
                trace!("indy_crypto_anoncreds_issuer_new_revocation_registry: *rev_reg_pub_p: {:?}, *rev_reg_priv_p: {:?}", *rev_reg_pub_p, *rev_reg_priv_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_anoncreds_issuer_new_revocation_registry: <<< res: {:?}", res);
    res
}

/// Deallocates revocation registry public instance.
///
/// # Arguments
/// * `rev_reg_pub` - Revocation registry public instance pointer
#[no_mangle]
pub extern fn indy_crypto_anoncreds_revocation_registry_public_free(rev_reg_pub: *const c_void) -> ErrorCode {
    trace!("indy_crypto_anoncreds_revocation_registry_public_free: >>> rev_reg_pub: {:?}", rev_reg_pub);

    check_useful_c_ptr!(rev_reg_pub, ErrorCode::CommonInvalidParam1);
    unsafe { Box::from_raw(rev_reg_pub as *mut RevocationRegistryPublic); }
    let res = ErrorCode::Success;

    trace!("indy_crypto_anoncreds_revocation_registry_public_free: <<< res: {:?}", res);
    res
}

/// Deallocates revocation registry private instance.
///
/// # Arguments
/// * `rev_reg_priv` - Revocation registry private instance pointer
#[no_mangle]
pub extern fn indy_crypto_anoncreds_revocation_registry_private_free(rev_reg_priv: *const c_void) -> ErrorCode {
    trace!("indy_crypto_anoncreds_revocation_registry_private_free: >>> rev_reg_priv: {:?}", rev_reg_priv);

    check_useful_c_ptr!(rev_reg_priv, ErrorCode::CommonInvalidParam1);

    unsafe { Box::from_raw(rev_reg_priv as *mut RevocationRegistryPrivate); }
    let res = ErrorCode::Success;

    trace!("indy_crypto_anoncreds_revocation_registry_private_free: <<< res: {:?}", res);
    res
}

/// Creates and returns claim entitity instance.
///
/// Note that claim deallocation must be performed by
/// calling indy_crypto_anoncreds_claim_free
///
/// # Arguments
/// * `prover_id` - Prover identifier as null terminated string.
/// * `blinded_ms_p` - Blinded master secret instance pointer.
/// * `attr_values_p` - Claim attributes values instance pointer.
/// * `issuer_pub_key_p` - Issuer public key instance pointer.
/// * `issuer_priv_key_p` - Issuer private key instance pointer.
/// * `rev_idx` - (Optional) User index in revocation accumulator. Required for non-revocation claim part generation.
/// * `rev_reg_public_p` - (Optional) Revocation registry public instance pointer.
/// * `rev_reg_private_p` - (Optional) Revocation registry private instance pointer.
/// * `claim_p` - Reference that will contain revocation registry private instance pointer.
#[no_mangle]
pub extern fn indy_crypto_anoncreds_issuer_new_claim(prover_id: *const c_char,
                                                     blinded_ms_p: *const c_void,
                                                     attr_values_p: *const c_void,
                                                     issuer_pub_key_p: *const c_void,
                                                     issuer_priv_key_p: *const c_void,
                                                     rev_idx: i32,
                                                     rev_reg_public_p: *const c_void,
                                                     rev_reg_private_p: *const c_void,
                                                     claim_p: *mut *const c_void) -> ErrorCode {
    trace!("indy_crypto_anoncreds_issuer_new_claim: >>> prover_id: {:?}, blinded_ms_p: {:?}, attr_values_p: {:?}, issuer_pub_key_p: {:?}, \
    issuer_priv_key_p: {:?}, rev_idx: {:?}, rev_reg_public_p: {:?}, rev_reg_private_p: {:?}, claim_p: {:?}",
           prover_id, blinded_ms_p, attr_values_p, issuer_pub_key_p, issuer_priv_key_p, rev_idx, rev_reg_public_p, rev_reg_private_p, claim_p);

    check_useful_c_str!(prover_id, ErrorCode::CommonInvalidParam1);
    check_useful_c_reference!(blinded_ms_p, BlindedMasterSecret, ErrorCode::CommonInvalidParam2);
    check_useful_c_reference!(attr_values_p, ClaimAttributesValues, ErrorCode::CommonInvalidParam3);
    check_useful_c_reference!(issuer_pub_key_p, IssuerPublicKey, ErrorCode::CommonInvalidParam4);
    check_useful_c_reference!(issuer_priv_key_p, IssuerPrivateKey, ErrorCode::CommonInvalidParam5);
    check_useful_opt_c_reference!(rev_reg_private_p, RevocationRegistryPrivate, ErrorCode::CommonInvalidParam7);

    let rev_idx = if rev_idx != -1 { Some(rev_idx as u32) } else { None };

    let mut rev_reg_public = if rev_reg_public_p.is_null() { None } else {
        Some(unsafe { Box::from_raw(rev_reg_public_p as *mut RevocationRegistryPublic) })
    };

    let res = match Issuer::new_claim(&prover_id,
                                      &blinded_ms_p,
                                      &attr_values_p,
                                      &issuer_pub_key_p,
                                      &issuer_priv_key_p,
                                      rev_idx,
                                      rev_reg_public.as_mut().map(|r| r.as_mut()),
                                      rev_reg_private_p) {
        Ok(claim) => {
            trace!("indy_crypto_anoncreds_issuer_new_claim: claim: {:?}", claim);
            unsafe {
                *claim_p = Box::into_raw(Box::new(claim)) as *const c_void;
                rev_reg_public.map(Box::into_raw);
                trace!("indy_crypto_anoncreds_issuer_new_claim: *claim_p: {:?}", *claim_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_anoncreds_issuer_new_claim: <<< res: {:?}", res);
    res
}

/// Deallocates claim instance.
///
/// # Arguments
/// * `rev_reg_priv` - Revocation registry private instance pointer
#[no_mangle]
pub extern fn indy_crypto_anoncreds_claim_free(claim_p: *const c_void) -> ErrorCode {
    trace!("indy_crypto_anoncreds_claim_free: >>> claim_p: {:?}", claim_p);

    check_useful_c_ptr!(claim_p, ErrorCode::CommonInvalidParam1);

    unsafe { Box::from_raw(claim_p as *mut Claim); }
    let res = ErrorCode::Success;

    trace!("indy_crypto_anoncreds_claim_free: <<< res: {:?}", res);
    res
}

/// Revokes a user identified by a revoc_id in a given revoc-registry
///
/// # Arguments
/// * `r_reg_p` - Reference that contain accumulator instance pointer.
///  * acc_idx` - index of the user in the accumulator
#[no_mangle]
pub extern fn indy_crypto_anoncreds_issuer_revoke(r_reg_p: *const c_void,
                                                  acc_idx: u32) -> ErrorCode {
    trace!("indy_crypto_anoncreds_issuer_revoke: >>> r_reg_p: {:?}, acc_idx: {:?}", r_reg_p, acc_idx);

    check_useful_c_ptr!(r_reg_p, ErrorCode::CommonInvalidParam1);

    let mut r_reg_p = unsafe { Box::from_raw(r_reg_p as *mut RevocationRegistryPublic) };

    let res = match Issuer::revoke(&mut r_reg_p, acc_idx) {
        Ok(()) => {
            Box::into_raw(r_reg_p);
            ErrorCode::Success
        },
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_anoncreds_issuer_revoke: <<< res: {:?}", res);
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::ffi::CString;
    use std::ptr;
    use ffi::anoncreds::mocks::*;
    use ffi::issuer::mocks::*;
    use ffi::prover::mocks::*;

    #[test]
    fn indy_crypto_anoncreds_issuer_new_keys_works() {
        let claim_attrs = _claim_attrs();
        let mut issuer_pub_key: *const c_void = ptr::null();
        let mut issuer_priv_key: *const c_void = ptr::null();

        let err_code = indy_crypto_anoncreds_issuer_new_keys(claim_attrs, true, &mut issuer_pub_key, &mut issuer_priv_key);

        assert_eq!(err_code, ErrorCode::Success);
        assert!(!issuer_pub_key.is_null());
        assert!(!issuer_priv_key.is_null());

        _free_claim_attrs(claim_attrs);
        _free_issuer_keys(issuer_pub_key, issuer_priv_key);
    }

    #[test]
    fn indy_crypto_anoncreds_issuer_keys_free_works() {
        let (issuer_pub_key, issuer_priv_key) = _issuer_keys();

        let err_code = indy_crypto_anoncreds_issuer_public_key_free(issuer_pub_key);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = indy_crypto_anoncreds_issuer_private_key_free(issuer_priv_key);
        assert_eq!(err_code, ErrorCode::Success);
    }

    #[test]
    fn indy_crypto_anoncreds_issuer_new_revocation_registry_works() {
        let (issuer_pub_key, issuer_priv_key) = _issuer_keys();
        let mut rev_reg_pub: *const c_void = ptr::null();
        let mut rev_reg_priv: *const c_void = ptr::null();

        let err_code = indy_crypto_anoncreds_issuer_new_revocation_registry(issuer_pub_key, 100, &mut rev_reg_pub, &mut rev_reg_priv);

        assert_eq!(err_code, ErrorCode::Success);
        assert!(!rev_reg_pub.is_null());
        assert!(!rev_reg_priv.is_null());

        _free_issuer_keys(issuer_pub_key, issuer_priv_key);
        _free_revocation_registry(rev_reg_pub, rev_reg_priv);
    }

    #[test]
    fn indy_crypto_anoncreds_revocation_registries_free_works() {
        let (issuer_pub_key, issuer_priv_key) = _issuer_keys();
        let (rev_reg_pub, rev_reg_priv) = _revocation_registry(issuer_pub_key);

        let err_code = indy_crypto_anoncreds_revocation_registry_public_free(rev_reg_pub);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = indy_crypto_anoncreds_revocation_registry_private_free(rev_reg_priv);
        assert_eq!(err_code, ErrorCode::Success);

        _free_issuer_keys(issuer_pub_key, issuer_priv_key);
    }

    #[test]
    fn indy_crypto_anoncreds_issuer_new_claim_works() {
        let prover_id = CString::new("CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW").unwrap();
        let attr_values = _claim_attrs_values();
        let (issuer_pub_key, issuer_priv_key) = _issuer_keys();
        let (rev_reg_pub, rev_reg_priv) = _revocation_registry(issuer_pub_key);
        let master_secret = _master_secret();
        let (blinded_master_secret, blinded_master_secret_data) = _blinded_master_secret(issuer_pub_key, master_secret);
        let rev_idx = 1;

        let mut claim: *const c_void = ptr::null();

        let err_code = indy_crypto_anoncreds_issuer_new_claim(prover_id.as_ptr(),
                                                              blinded_master_secret,
                                                              attr_values,
                                                              issuer_pub_key,
                                                              issuer_priv_key,
                                                              rev_idx,
                                                              rev_reg_pub,
                                                              rev_reg_priv,
                                                              &mut claim);

        assert_eq!(err_code, ErrorCode::Success);
        assert!(!claim.is_null());

        _free_issuer_keys(issuer_pub_key, issuer_priv_key);
        _free_revocation_registry(rev_reg_pub, rev_reg_priv);
        _free_claim_attrs_values(attr_values);
        _free_blinded_master_secret(blinded_master_secret, blinded_master_secret_data);

        _free_claim(claim);
    }

    #[test]
    fn indy_crypto_anoncreds_claim_free_works() {
        let (issuer_pub_key, issuer_priv_key) = _issuer_keys();
        let (rev_reg_pub, rev_reg_priv) = _revocation_registry(issuer_pub_key);
        let master_secret = _master_secret();
        let (blinded_master_secret, blinded_master_secret_data) = _blinded_master_secret(issuer_pub_key, master_secret);
        let attr_values = _claim_attrs_values();

        let claim = _claim(blinded_master_secret, issuer_pub_key, issuer_priv_key, rev_reg_pub, rev_reg_priv, attr_values);

        _free_issuer_keys(issuer_pub_key, issuer_priv_key);
        _free_revocation_registry(rev_reg_pub, rev_reg_priv);
        _free_blinded_master_secret(blinded_master_secret, blinded_master_secret_data);
        _free_claim_attrs_values(attr_values);

        let err_code = indy_crypto_anoncreds_claim_free(claim);
        assert_eq!(err_code, ErrorCode::Success);
    }

    #[test]
    fn indy_crypto_anoncreds_issuer_revoke_works() {
        let (issuer_pub_key, issuer_priv_key) = _issuer_keys();
        let (rev_reg_pub_p, rev_reg_priv_p) = _revocation_registry(issuer_pub_key);
        let master_secret = _master_secret();
        let (blinded_master_secret, blinded_master_secret_data) = _blinded_master_secret(issuer_pub_key, master_secret);
        let attr_values = _claim_attrs_values();

        let claim = _claim(blinded_master_secret, issuer_pub_key, issuer_priv_key, rev_reg_pub_p, rev_reg_priv_p, attr_values);

        let err_code = indy_crypto_anoncreds_issuer_revoke(rev_reg_pub_p, 1);
        assert_eq!(err_code, ErrorCode::Success);

        _free_issuer_keys(issuer_pub_key, issuer_priv_key);
        _free_revocation_registry(rev_reg_pub_p, rev_reg_priv_p);
        _free_blinded_master_secret(blinded_master_secret, blinded_master_secret_data);
        _free_claim(claim);
        _free_claim_attrs_values(attr_values);
    }
}

pub mod mocks {
    use super::*;

    use std::ffi::CString;
    use std::ptr;
    use ffi::anoncreds::mocks::*;

    pub fn _issuer_keys() -> (*const c_void, *const c_void) {
        let claim_attrs = _claim_attrs();

        let mut issuer_pub_key: *const c_void = ptr::null();
        let mut issuer_priv_key: *const c_void = ptr::null();

        let err_code = indy_crypto_anoncreds_issuer_new_keys(claim_attrs, true, &mut issuer_pub_key, &mut issuer_priv_key);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!issuer_pub_key.is_null());
        assert!(!issuer_priv_key.is_null());

        _free_claim_attrs(claim_attrs);

        (issuer_pub_key, issuer_priv_key)
    }

    pub fn _free_issuer_keys(issuer_pub_key: *const c_void, issuer_priv_key: *const c_void) {
        let err_code = indy_crypto_anoncreds_issuer_public_key_free(issuer_pub_key);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = indy_crypto_anoncreds_issuer_private_key_free(issuer_priv_key);
        assert_eq!(err_code, ErrorCode::Success);
    }

    pub fn _revocation_registry(issuer_pub_key: *const c_void) -> (*const c_void, *const c_void) {
        let mut rev_reg_pub: *const c_void = ptr::null();
        let mut rev_reg_priv: *const c_void = ptr::null();

        let err_code = indy_crypto_anoncreds_issuer_new_revocation_registry(issuer_pub_key, 100, &mut rev_reg_pub, &mut rev_reg_priv);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!rev_reg_pub.is_null());
        assert!(!rev_reg_priv.is_null());

        (rev_reg_pub, rev_reg_priv)
    }

    pub fn _free_revocation_registry(rev_reg_pub: *const c_void, rev_reg_priv: *const c_void) {
        let err_code = indy_crypto_anoncreds_revocation_registry_public_free(rev_reg_pub);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = indy_crypto_anoncreds_revocation_registry_private_free(rev_reg_priv);
        assert_eq!(err_code, ErrorCode::Success);
    }

    pub fn _claim(blinded_master_secret: *const c_void, issuer_pub_key: *const c_void, issuer_priv_key: *const c_void,
                  rev_reg_pub: *const c_void, rev_reg_priv: *const c_void, attr_values: *const c_void) -> *const c_void {
        let prover_id = CString::new("CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW").unwrap();
        let attr_values = _claim_attrs_values();
        let rev_idx = 1;

        let mut claim: *const c_void = ptr::null();

        let err_code = indy_crypto_anoncreds_issuer_new_claim(prover_id.as_ptr(),
                                                              blinded_master_secret,
                                                              attr_values,
                                                              issuer_pub_key,
                                                              issuer_priv_key,
                                                              rev_idx,
                                                              rev_reg_pub,
                                                              rev_reg_priv,
                                                              &mut claim);

        assert_eq!(err_code, ErrorCode::Success);
        assert!(!claim.is_null());

        claim
    }

    pub fn _free_claim(claim: *const c_void) {
        let err_code = indy_crypto_anoncreds_claim_free(claim);
        assert_eq!(err_code, ErrorCode::Success);
    }
}