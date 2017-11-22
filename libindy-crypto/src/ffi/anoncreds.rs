use anoncreds::*;
use anoncreds::issuer::*;
use anoncreds::prover::*;
use anoncreds::types::*;

use ffi::ErrorCode;
use ffi::indy_crypto_init_logger;
use errors::ToErrorCode;
use utils::ctypes::CTypesUtils;

use libc::c_char;

use std::os::raw::c_void;
use std::slice;


/// Creates and returns claims attributes entity builder.
///
/// The purpose of claim attributes builder is building of claim attributes entity that
/// represents claim attributes set.
///
/// Note: Claims attributes builder instance deallocation must be performed by
/// calling indy_crypto_anoncreds_claim_attributes_builder_finalize.
///
/// # Arguments
/// * `claim_attrs_builder_p` - Reference that will contain claims attributes builder instance pointer.
#[no_mangle]
pub extern fn indy_crypto_anoncreds_claim_attributes_builder_new(claim_attrs_builder_p: *mut *const c_void) -> ErrorCode {
    trace!("indy_crypto_anoncreds_claim_attributes_builder_new: >>> claim_attrs_builder_p: {:?}", claim_attrs_builder_p);

    check_useful_c_ptr!(claim_attrs_builder_p, ErrorCode::CommonInvalidParam1);

    let res = match ClaimAttributesBuilder::new() {
        Ok(claim_attrs_builder) => {
            trace!("indy_crypto_anoncreds_claim_attributes_builder_new: claim_attrs_builder: {:?}", claim_attrs_builder);
            unsafe {
                *claim_attrs_builder_p = Box::into_raw(Box::new(claim_attrs_builder)) as *const c_void;
                trace!("indy_crypto_anoncreds_claim_attributes_builder_new: *claim_attrs_builder_p: {:?}", *claim_attrs_builder_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_anoncreds_claim_attributes_builder_new: <<< res: {:?}", res);
    res
}

/// Adds new attribute to claim attributes set.
///
/// Note that this function returns new claim attribute builder instance pointer. The old one
/// becomes invalid.
///
/// # Arguments
/// * `claim_attrs_builder` - Claim attribute builder instance pointer
/// * `attr` - Claim attr to add as null terminated string.
/// * `claim_attrs_builder_p` - Reference that will contain new claims attributes builder instance pointer.
#[no_mangle]
pub extern fn indy_crypto_anoncreds_claim_attributes_builder_add_attr(claim_attrs_builder: *const c_void,
                                                                      attr: *const c_char,
                                                                      claim_attrs_builder_p: *mut *const c_void) -> ErrorCode {
    trace!("indy_crypto_anoncreds_claim_attributes_builder_add_attr: >>> claim_attrs_builder: {:?}, attr: {:?}, claim_attrs_builder_p: {:?}", claim_attrs_builder, attr, claim_attrs_builder_p);

    check_useful_c_ptr!(claim_attrs_builder, ErrorCode::CommonInvalidParam1);
    check_useful_c_str!(attr, ErrorCode::CommonInvalidParam2);
    check_useful_c_ptr!(claim_attrs_builder_p, ErrorCode::CommonInvalidParam3);

    let mut claim_attrs_builder = unsafe { Box::from_raw(claim_attrs_builder as *mut ClaimAttributesBuilder) };

    let res = match claim_attrs_builder.add_attr(&attr) {
        Ok(claim_attrs_builder) => {
            trace!("indy_crypto_anoncreds_claim_attributes_builder_add_attr: claim_attrs_builder: {:?}", claim_attrs_builder);
            unsafe {
                *claim_attrs_builder_p = Box::into_raw(Box::new(claim_attrs_builder)) as *const c_void;
                trace!("indy_crypto_anoncreds_claim_attributes_builder_add_attr: *claim_attrs_builder_p: {:?}", *claim_attrs_builder_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_anoncreds_claim_attributes_builder_add_attr: <<< res: {:?}", res);
    res
}

/// Deallocates claim attribute builder and returns claim attributes entity instead.
///
/// Note: Claims attributes builder instance deallocation must be performed by
/// calling indy_crypto_anoncreds_claim_attributes_free.
///
/// # Arguments
/// * `claim_attrs_builder` - Claim attribute builder instance pointer
/// * `claim_attrs_p` - Reference that will contain claims attributes instance pointer.
#[no_mangle]
pub extern fn indy_crypto_anoncreds_claim_attributes_builder_finalize(claim_attrs_builder: *const c_void,
                                                                      claim_attrs_p: *mut *const c_void) -> ErrorCode {
    trace!("indy_crypto_anoncreds_claim_attributes_builder_finalize: >>> claim_attrs_builder: {:?}, claim_attrs_p: {:?}", claim_attrs_builder, claim_attrs_p);

    check_useful_c_ptr!(claim_attrs_builder, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(claim_attrs_p, ErrorCode::CommonInvalidParam2);

    let claim_attrs_builder = unsafe { Box::from_raw(claim_attrs_builder as *mut ClaimAttributesBuilder) };

    let res = match claim_attrs_builder.finalize() {
        Ok(claims_attrs) => {
            trace!("indy_crypto_anoncreds_claim_attributes_builder_finalize: claims_attrs: {:?}", claims_attrs);
            unsafe {
                *claim_attrs_p = Box::into_raw(Box::new(claims_attrs)) as *const c_void;
                trace!("indy_crypto_anoncreds_claim_attributes_builder_finalize: *claim_attrs_p: {:?}", *claim_attrs_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_anoncreds_claim_attributes_builder_finalize: <<< res: {:?}", res);
    res
}

/// Deallocates claim attributes instance.
///
/// # Arguments
/// * `claims_attrs` - Claim attributes instance pointer
#[no_mangle]
pub extern fn indy_crypto_anoncreds_claim_attributes_free(claims_attrs: *const c_void) -> ErrorCode {
    trace!("indy_crypto_anoncreds_claim_attributes_free: >>> claims_attrs: {:?}", claims_attrs);

    check_useful_c_ptr!(claims_attrs, ErrorCode::CommonInvalidParam1);

    unsafe { Box::from_raw(claims_attrs as *mut ClaimAttributes); }
    let res = ErrorCode::Success;

    trace!("indy_crypto_anoncreds_claim_attributes_free: <<< res: {:?}", res);
    res
}

/// Creates and returns claims attributes values entity builder.
///
/// The purpose of claim attributes values builder is building of claim attributes values entity that
/// represents claim attributes values map.
///
/// Note: Claims attributes values builder instance deallocation must be performed by
/// calling indy_crypto_anoncreds_claim_attributes_values_builder_finalize.
///
/// # Arguments
/// * `claim_attrs_values_builder_p` - Reference that will contain claims attributes values builder instance pointer.
#[no_mangle]
pub extern fn indy_crypto_anoncreds_claim_attributes_values_builder_new(claim_attrs_values_builder_p: *mut *const c_void) -> ErrorCode {
    trace!("indy_crypto_anoncreds_claim_attributes_values_builder_new: >>> claim_attrs_values_builder_p: {:?}", claim_attrs_values_builder_p);

    check_useful_c_ptr!(claim_attrs_values_builder_p, ErrorCode::CommonInvalidParam1);

    let res = match ClaimAttributesValuesBuilder::new() {
        Ok(claim_attrs_values_builder) => {
            trace!("indy_crypto_anoncreds_claim_attributes_values_builder_new: claim_attrs_values_builder: {:?}", claim_attrs_values_builder);
            unsafe {
                *claim_attrs_values_builder_p = Box::into_raw(Box::new(claim_attrs_values_builder)) as *const c_void;
                trace!("indy_crypto_anoncreds_claim_attributes_values_builder_new: *claim_attrs_values_builder_p: {:?}", *claim_attrs_values_builder_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_anoncreds_claim_attributes_values_builder_new: <<< res: {:?}", res);
    res
}

/// Adds new attribute dec_value to claim attributes values map.
///
/// Note that this function returns new claim attribute dec_value builder instance pointer. The old one
/// becomes invalid.
///
/// # Arguments
/// * `claim_attrs_values_builder` - Claim attributes values builder instance pointer
/// * `attr` - Claim attr to add as null terminated string.
/// * `dec_value` - Claim attr dec_value. Decimal BigNum representation as null terminated string.
/// * `claim_attrs_values_builder_p` - Reference that will contain new claims attributes builder instance pointer.
#[no_mangle]
pub extern fn indy_crypto_anoncreds_claim_attributes_values_builder_add_attr_value(claim_attrs_values_builder: *const c_void,
                                                                                   attr: *const c_char,
                                                                                   dec_value: *const c_char,
                                                                                   claim_attrs_values_builder_p: *mut *const c_void) -> ErrorCode {
    trace!("indy_crypto_anoncreds_claim_attributes_values_builder_add_attr_value: >>> claim_attrs_values_builder: {:?}, attr: {:?}, dec_value: {:?}, claim_attrs_values_builder_p: {:?}", claim_attrs_values_builder, attr, dec_value, claim_attrs_values_builder_p);

    check_useful_c_ptr!(claim_attrs_values_builder, ErrorCode::CommonInvalidParam1);
    check_useful_c_str!(attr, ErrorCode::CommonInvalidParam2);
    check_useful_c_str!(dec_value, ErrorCode::CommonInvalidParam3);
    check_useful_c_ptr!(claim_attrs_values_builder_p, ErrorCode::CommonInvalidParam4);

    let mut claim_attrs_values_builder = unsafe { Box::from_raw(claim_attrs_values_builder as *mut ClaimAttributesValuesBuilder) };

    let res = match claim_attrs_values_builder.add_attr_value(&attr, &dec_value) {
        Ok(claim_attrs_values_builder) => {
            trace!("indy_crypto_anoncreds_claim_attributes_values_builder_add_attr_value: claim_attrs_values_builder: {:?}", claim_attrs_values_builder);
            unsafe {
                *claim_attrs_values_builder_p = Box::into_raw(Box::new(claim_attrs_values_builder)) as *const c_void;
                trace!("indy_crypto_anoncreds_claim_attributes_values_builder_add_attr_value: *claim_attrs_values_builder_p: {:?}", *claim_attrs_values_builder_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_anoncreds_claim_attributes_values_builder_add_attr_value: <<< res: {:?}", res);
    res
}

/// Deallocates claim attribute values builder and returns claim attributes values entity instead.
///
/// Note: Claims attributes values builder instance deallocation must be performed by
/// calling indy_crypto_anoncreds_claim_attributes_values_free.
///
/// # Arguments
/// * `claim_attrs_values_builder` - Claim attribute builder instance pointer
/// * `claim_attrs_values_p` - Reference that will contain claims attributes values instance pointer.
#[no_mangle]
pub extern fn indy_crypto_anoncreds_claim_attributes_values_builder_finalize(claim_attrs_values_builder: *const c_void,
                                                                             claim_attrs_values_p: *mut *const c_void) -> ErrorCode {
    trace!("indy_crypto_anoncreds_claim_attributes_values_builder_finalize: >>> claim_attrs_values_builder: {:?}, claim_attrs_values_p: {:?}", claim_attrs_values_builder, claim_attrs_values_p);

    check_useful_c_ptr!(claim_attrs_values_builder, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(claim_attrs_values_p, ErrorCode::CommonInvalidParam2);

    let claim_attrs_values_builder = unsafe { Box::from_raw(claim_attrs_values_builder as *mut ClaimAttributesValuesBuilder) };

    let res = match claim_attrs_values_builder.finalize() {
        Ok(claims_attrs_values) => {
            trace!("indy_crypto_anoncreds_claim_attributes_values_builder_finalize: claims_attrs_values: {:?}", claims_attrs_values);
            unsafe {
                *claim_attrs_values_p = Box::into_raw(Box::new(claims_attrs_values)) as *const c_void;
                trace!("indy_crypto_anoncreds_claim_attributes_values_builder_finalize: *claim_attrs_values_p: {:?}", *claim_attrs_values_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_anoncreds_claim_attributes_values_builder_finalize: <<< res: {:?}", res);
    res
}

/// Deallocates claim attributes values instance.
///
/// # Arguments
/// * `claims_attrs_values` - Claim attributes values instance pointer
#[no_mangle]
pub extern fn indy_crypto_anoncreds_claim_attributes_values_free(claims_attrs_values: *const c_void) -> ErrorCode {
    trace!("indy_crypto_anoncreds_claim_attributes_values_free: >>> claims_attrs_values: {:?}", claims_attrs_values);

    check_useful_c_ptr!(claims_attrs_values, ErrorCode::CommonInvalidParam1);

    unsafe { Box::from_raw(claims_attrs_values as *mut ClaimAttributesValues); }
    let res = ErrorCode::Success;

    trace!("indy_crypto_anoncreds_claim_attributes_values_free: <<< res: {:?}", res);
    res
}

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
pub extern fn indy_crypto_anoncreds_new_claim(prover_id: *const c_char,
                                              blinded_ms_p: *const c_void,
                                              attr_values_p: *const c_void,
                                              issuer_pub_key_p: *const c_void,
                                              issuer_priv_key_p: *const c_void,
                                              rev_idx: i32,
                                              rev_reg_public_p: *const c_void,
                                              rev_reg_private_p: *const c_void,
                                              claim_p: *mut *const c_void) -> ErrorCode {
    trace!("indy_crypto_anoncreds_new_claim: >>> prover_id: {:?}, blinded_ms_p: {:?}, attr_values_p: {:?}, issuer_pub_key_p: {:?}, \
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
            trace!("indy_crypto_anoncreds_new_claim: claim: {:?}", claim);
            unsafe {
                *claim_p = Box::into_raw(Box::new(claim)) as *const c_void;
                trace!("indy_crypto_anoncreds_new_claim: *claim_p: {:?}", *claim_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_anoncreds_new_claim: <<< res: {:?}", res);
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
/// * `r_acc_p` - Reference that contain accumulator instance pointer.
///  * r_acc_tails` - Reference that contain accumulator tails instance pointer.
///  * acc_idx` - index of the user in the accumulator
#[no_mangle]
pub extern fn indy_crypto_anoncreds_revoke(r_acc_p: *mut *const c_void,
                                           r_acc_tails_p: *const c_void,
                                           acc_idx: u32) -> ErrorCode {
    trace!("indy_crypto_anoncreds_revoke: >>> r_acc_p: {:?}, r_acc_tails_p: {:?}, acc_idx: {:?}", r_acc_p, r_acc_tails_p, acc_idx);

    check_useful_c_ptr!(r_acc_p, ErrorCode::CommonInvalidParam1);
    check_useful_c_reference!(r_acc_tails_p, RevocationAccumulatorTails, ErrorCode::CommonInvalidParam2);

    let mut r_acc = unsafe { Box::from_raw(r_acc_p as *mut RevocationAccumulator) };

    let res = match Issuer::revoke(&mut r_acc, r_acc_tails_p, acc_idx) {
        Ok(()) => ErrorCode::Success,
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_anoncreds_revoke: <<< res: {:?}", res);
    res
}

/// Creates a master secret
///
/// Note that master secret deallocation must be performed by
/// calling indy_crypto_anoncreds_master_secret_free
///
///
/// # Arguments
/// * `master_secret_p` - Reference that will contain master secret instance pointer.
#[no_mangle]
pub extern fn indy_crypto_anoncreds_generate_master_secret(master_secret_p: *mut *const c_void) -> ErrorCode {
    trace!("indy_crypto_anoncreds_generate_master_secret: >>> ");

    let res = match Prover::generate_master_secret() {
        Ok(master_secret) => {
            trace!("indy_crypto_anoncreds_generate_master_secret: master_secret: {:?}", master_secret);
            unsafe {
                *master_secret_p = Box::into_raw(Box::new(master_secret)) as *const c_void;
                trace!("indy_crypto_anoncreds_generate_master_secret: *master_secret_p: {:?}", *master_secret_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_anoncreds_generate_master_secret: <<< res: {:?}", res);
    res
}

/// Deallocates master secret instance.
///
/// # Arguments
/// * `master_secret_p` - Master secret instance pointer
#[no_mangle]
pub extern fn indy_crypto_anoncreds_master_secret_free(master_secret_p: *const c_void) -> ErrorCode {
    trace!("indy_crypto_anoncreds_master_secret_free: >>> claim_p: {:?}", master_secret_p);

    check_useful_c_ptr!(master_secret_p, ErrorCode::CommonInvalidParam1);

    unsafe { Box::from_raw(master_secret_p as *mut MasterSecret); }
    let res = ErrorCode::Success;

    trace!("indy_crypto_anoncreds_master_secret_free: <<< res: {:?}", res);
    res
}

/// Creates blinded master secret for given keys and master secret
///
/// Note that blinded master secret deallocation must be performed by
/// calling indy_crypto_anoncreds_blinded_master_secret_free
///
/// Note that blinded master secret data deallocation must be performed by
/// calling indy_crypto_anoncreds_blinded_master_secret_data_free
///
/// # Arguments
/// * `pub_key_p` - Reference that contain public keys instance pointer.
/// * `master_secret_p` - Reference that contain master secret instance pointer.
/// * `blinded_master_secret_p` - Reference that will contain blinded master secret instance pointer.
/// * `blinded_master_secret_data_p` - Reference that will contain blinded master secret data instance pointer.
#[no_mangle]
pub extern fn indy_crypto_anoncreds_generate_blinded_master_secret(pub_key_p: *const c_void,
                                                                   master_secret_p: *const c_void,
                                                                   blinded_master_secret_p: *mut *const c_void,
                                                                   blinded_master_secret_data_p: *mut *const c_void) -> ErrorCode {
    trace!("indy_crypto_anoncreds_generate_blinded_master_secret: >>> pub_key_p: {:?}, master_secret_p: {:?}, blinded_master_secret_p: {:?}, blinded_master_secret_data_p: {:?}",
           pub_key_p, master_secret_p, blinded_master_secret_p, blinded_master_secret_data_p);

    check_useful_c_reference!(pub_key_p, IssuerPublicKey, ErrorCode::CommonInvalidParam1);
    check_useful_c_reference!(master_secret_p, MasterSecret, ErrorCode::CommonInvalidParam2);

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
pub extern fn indy_crypto_anoncreds_blinded_master_secret_free(blinded_master_secret_p: *const c_void) -> ErrorCode {
    trace!("indy_crypto_anoncreds_blinded_master_secret_free: >>> blinded_master_secret_p: {:?}", blinded_master_secret_p);

    check_useful_c_ptr!(blinded_master_secret_p, ErrorCode::CommonInvalidParam1);

    unsafe { Box::from_raw(blinded_master_secret_p as *mut MasterSecret); }
    let res = ErrorCode::Success;

    trace!("indy_crypto_anoncreds_blinded_master_secret_free: <<< res: {:?}", res);
    res
}

/// Deallocates  blinded master secret data instance.
///
/// # Arguments
/// * `blinded_master_secret_data_p` - Master secret instance pointer
#[no_mangle]
pub extern fn indy_crypto_anoncreds_blinded_master_secret_data_free(blinded_master_secret_data_p: *const c_void) -> ErrorCode {
    trace!("indy_crypto_anoncreds_blinded_master_secret_data_free: >>> blinded_master_secret_data_p: {:?}", blinded_master_secret_data_p);

    check_useful_c_ptr!(blinded_master_secret_data_p, ErrorCode::CommonInvalidParam1);

    unsafe { Box::from_raw(blinded_master_secret_data_p as *mut MasterSecret); }
    let res = ErrorCode::Success;

    trace!("indy_crypto_anoncreds_blinded_master_secret_data_free: <<< res: {:?}", res);
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
pub extern fn indy_crypto_anoncreds_process_claim(claim_p: *const c_void,
                                                  blinded_master_secret_data_p: *const c_void,
                                                  r_pub_key_p: *const c_void,
                                                  r_reg: *const c_void) -> ErrorCode {
    trace!("indy_crypto_anoncreds_process_claim: >>> claim_p: {:?}, blinded_master_secret_data_p: {:?}, r_pub_key_p: {:?}, r_reg: {:?}",
           claim_p, blinded_master_secret_data_p, r_pub_key_p, r_reg);

    check_useful_c_ptr!(claim_p, ErrorCode::CommonInvalidParam1);
    check_useful_c_reference!(blinded_master_secret_data_p, BlindedMasterSecretData, ErrorCode::CommonInvalidParam2);
    check_useful_opt_c_reference!(r_pub_key_p, IssuerRevocationPublicKey, ErrorCode::CommonInvalidParam3);
    check_useful_opt_c_reference!(r_reg, RevocationRegistryPublic, ErrorCode::CommonInvalidParam4);

    let mut claim = unsafe { Box::from_raw(claim_p as *mut Claim) };


    let res = match Prover::process_claim(&mut claim,
                                          blinded_master_secret_data_p,
                                          r_pub_key_p,
                                          r_reg) {
        Ok(()) => ErrorCode::Success,
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_anoncreds_process_claim: <<< res: {:?}", res);
    res
}

/// Creates and returns attributes with predicates entity builder.
///
/// The purpose of claim attributes builder is building of atributes with predicates entity that
/// represents proof request set.
///
/// Note: AttrsWithPredicatesBuilder attributes builder instance deallocation must be performed by
/// calling indy_crypto_anoncreds_attrs_with_predicates_builder_finalize.
///
/// # Arguments
/// * `attrs_with_predicates_builder_p` - Reference that will contain attributes with predicates builder instance pointer.
#[no_mangle]
pub extern fn indy_crypto_anoncreds_attrs_with_predicates_builder_new(attrs_with_predicates_builder_p: *mut *const c_void) -> ErrorCode {
    trace!("indy_crypto_anoncreds_attrs_with_predicates_builder_new: >>> attrs_with_predicates_builder_p: {:?}", attrs_with_predicates_builder_p);

    check_useful_c_ptr!(attrs_with_predicates_builder_p, ErrorCode::CommonInvalidParam1);

    let res = match AttrsWithPredicatesBuilder::new() {
        Ok(attrs_with_predicates_builder) => {
            trace!("indy_crypto_anoncreds_attrs_with_predicates_builder_new: attrs_with_predicates_builder: {:?}", attrs_with_predicates_builder);
            unsafe {
                *attrs_with_predicates_builder_p = Box::into_raw(Box::new(attrs_with_predicates_builder)) as *const c_void;
                trace!("indy_crypto_anoncreds_attrs_with_predicates_builder_new: *attrs_with_predicates_builder_p: {:?}", *attrs_with_predicates_builder_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_anoncreds_attrs_with_predicates_builder_new: <<< res: {:?}", res);
    res
}

/// Adds new revealed attribute set.
///
/// Note that this function returns new attrs with predicates builder instance pointer. The old one
/// becomes invalid.
///
/// # Arguments
/// * `attrs_with_predicates_builder` - Attributes with predicates builder instance pointer
/// * `attr` - Claim attr to add as null terminated string.
/// * `attrs_with_predicates_builder_p` - Reference that will contain new claims attributes builder instance pointer.
#[no_mangle]
pub extern fn indy_crypto_anoncreds_attrs_with_predicates_builder_add_revealed_attr(attrs_with_predicates_builder: *const c_void,
                                                                                    attr: *const c_char,
                                                                                    attrs_with_predicates_builder_p: *mut *const c_void) -> ErrorCode {
    trace!("indy_crypto_anoncreds_attrs_with_predicates_builder_add_revealed_attr: >>> attrs_with_predicates_builder: {:?}, attr: {:?}, attrs_with_predicates_builder_p: {:?}",
           attrs_with_predicates_builder, attr, attrs_with_predicates_builder_p);

    check_useful_c_ptr!(attrs_with_predicates_builder, ErrorCode::CommonInvalidParam1);
    check_useful_c_str!(attr, ErrorCode::CommonInvalidParam2);
    check_useful_c_ptr!(attrs_with_predicates_builder_p, ErrorCode::CommonInvalidParam3);

    let mut attrs_with_predicates_builder = unsafe { Box::from_raw(attrs_with_predicates_builder as *mut AttrsWithPredicatesBuilder) };

    let res = match attrs_with_predicates_builder.add_revealed_attr(&attr) {
        Ok(add_revealed_attr) => {
            trace!("indy_crypto_anoncreds_attrs_with_predicates_builder_add_revealed_attr: add_revealed_attr: {:?}", add_revealed_attr);
            unsafe {
                *attrs_with_predicates_builder_p = Box::into_raw(Box::new(attrs_with_predicates_builder_p)) as *const c_void;
                trace!("indy_crypto_anoncreds_attrs_with_predicates_builder_add_revealed_attr: *attrs_with_predicates_builder_p: {:?}", *attrs_with_predicates_builder_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_anoncreds_attrs_with_predicates_builder_add_revealed_attr: <<< res: {:?}", res);
    res
}

/// Adds new revealed attribute set.
///
/// Note that this function returns new attrs with predicates builder instance pointer. The old one
/// becomes invalid.
///
/// # Arguments
/// * `attrs_with_predicates_builder` - Attributes with predicates builder instance pointer
/// * `attr` - Claim attr to add as null terminated string.
/// * `attrs_with_predicates_builder_p` - Reference that will contain new claims attributes builder instance pointer.
#[no_mangle]
pub extern fn indy_crypto_anoncreds_attrs_with_predicates_builder_add_unrevealed_attr(attrs_with_predicates_builder: *const c_void,
                                                                                      attr: *const c_char,
                                                                                      attrs_with_predicates_builder_p: *mut *const c_void) -> ErrorCode {
    trace!("indy_crypto_anoncreds_attrs_with_predicates_builder_add_unrevealed_attr: >>> attrs_with_predicates_builder: {:?}, attr: {:?}, attrs_with_predicates_builder_p: {:?}",
           attrs_with_predicates_builder, attr, attrs_with_predicates_builder_p);

    check_useful_c_ptr!(attrs_with_predicates_builder, ErrorCode::CommonInvalidParam1);
    check_useful_c_str!(attr, ErrorCode::CommonInvalidParam2);
    check_useful_c_ptr!(attrs_with_predicates_builder_p, ErrorCode::CommonInvalidParam3);

    let mut attrs_with_predicates_builder = unsafe { Box::from_raw(attrs_with_predicates_builder as *mut AttrsWithPredicatesBuilder) };

    let res = match attrs_with_predicates_builder.add_unrevealed_attr(&attr) {
        Ok(add_revealed_attr) => {
            trace!("indy_crypto_anoncreds_attrs_with_predicates_builder_add_unrevealed_attr: add_revealed_attr: {:?}", add_revealed_attr);
            unsafe {
                *attrs_with_predicates_builder_p = Box::into_raw(Box::new(attrs_with_predicates_builder_p)) as *const c_void;
                trace!("indy_crypto_anoncreds_attrs_with_predicates_builder_add_unrevealed_attr: *attrs_with_predicates_builder_p: {:?}", *attrs_with_predicates_builder_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_anoncreds_attrs_with_predicates_builder_add_unrevealed_attr: <<< res: {:?}", res);
    res
}

/// Adds predicate set.
///
/// Note that this function returns new attrs with predicates builder instance pointer. The old one
/// becomes invalid.
///
/// # Arguments
/// * `attrs_with_predicates_builder` - Attributes with predicates builder instance pointer
/// * `predicate` - predicate to add as null terminated string.
/// * `attrs_with_predicates_builder_p` - Reference that will contain new claims attributes builder instance pointer.
#[no_mangle]
pub extern fn indy_crypto_anoncreds_attrs_with_predicates_builder_add_predicate(attrs_with_predicates_builder: *const c_void,
                                                                                predicate: *const c_char,
                                                                                attrs_with_predicates_builder_p: *mut *const c_void) -> ErrorCode {
    trace!("indy_crypto_anoncreds_attrs_with_predicates_builder_add_predicate: >>> attrs_with_predicates_builder: {:?}, predicate: {:?}, attrs_with_predicates_builder_p: {:?}",
           attrs_with_predicates_builder, predicate, attrs_with_predicates_builder_p);

    check_useful_c_ptr!(attrs_with_predicates_builder, ErrorCode::CommonInvalidParam1);
    check_useful_c_reference!(predicate, Predicate, ErrorCode::CommonInvalidParam2);
    check_useful_c_ptr!(attrs_with_predicates_builder_p, ErrorCode::CommonInvalidParam3);

    let mut attrs_with_predicates_builder = unsafe { Box::from_raw(attrs_with_predicates_builder as *mut AttrsWithPredicatesBuilder) };

    let res = match attrs_with_predicates_builder.add_predicate(predicate) {
        Ok(add_revealed_attr) => {
            trace!("indy_crypto_anoncreds_attrs_with_predicates_builder_add_predicate: add_revealed_attr: {:?}", add_revealed_attr);
            unsafe {
                *attrs_with_predicates_builder_p = Box::into_raw(Box::new(attrs_with_predicates_builder_p)) as *const c_void;
                trace!("indy_crypto_anoncreds_attrs_with_predicates_builder_add_predicate: *attrs_with_predicates_builder_p: {:?}", *attrs_with_predicates_builder_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_anoncreds_attrs_with_predicates_builder_add_predicate: <<< res: {:?}", res);
    res
}

/// Deallocates attrs with predicate builder and returns claim attributes entity instead.
///
/// Note: Attrs with predicates builder instance deallocation must be performed by
/// calling indy_crypto_anoncreds_claim_attributes_free.
///
/// # Arguments
/// * `claim_attrs_builder` - Claim attribute builder instance pointer
/// * `claim_attrs_p` - Reference that will contain claims attributes instance pointer.
#[no_mangle]
pub extern fn indy_crypto_anoncreds_attrs_with_predicates_builder_finalize(attrs_with_predicates_builder: *const c_void,
                                                                           attrs_with_predicates_p: *mut *const c_void) -> ErrorCode {
    trace!("indy_crypto_anoncreds_attrs_with_predicates_builder_finalize: >>> attrs_with_predicates_builder: {:?}, attrs_with_predicates_p: {:?}",
           attrs_with_predicates_builder, attrs_with_predicates_p);

    check_useful_c_ptr!(attrs_with_predicates_builder, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(attrs_with_predicates_p, ErrorCode::CommonInvalidParam2);

    let attrs_with_predicates_builder = unsafe { Box::from_raw(attrs_with_predicates_builder as *mut AttrsWithPredicatesBuilder) };

    let res = match attrs_with_predicates_builder.finalize() {
        Ok(attrs_with_predicates) => {
            trace!("indy_crypto_anoncreds_attrs_with_predicates_builder_finalize: attrs_with_predicates: {:?}", attrs_with_predicates);
            unsafe {
                *attrs_with_predicates_p = Box::into_raw(Box::new(attrs_with_predicates)) as *const c_void;
                trace!("indy_crypto_anoncreds_attrs_with_predicates_builder_finalize: *attrs_with_predicates_p: {:?}", *attrs_with_predicates_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_anoncreds_attrs_with_predicates_builder_finalize: <<< res: {:?}", res);
    res
}

/// Deallocates claim attributes instance.
///
/// # Arguments
/// * `claims_attrs` - Claim attributes instance pointer
#[no_mangle]
pub extern fn indy_crypto_anoncreds_attrs_with_predicates_free(attrs_with_predicates: *const c_void) -> ErrorCode {
    trace!("indy_crypto_anoncreds_attrs_with_predicates_free: >>> attrs_with_predicates: {:?}", attrs_with_predicates);

    check_useful_c_ptr!(attrs_with_predicates, ErrorCode::CommonInvalidParam1);

    unsafe { Box::from_raw(attrs_with_predicates as *mut AttrsWithPredicates); }
    let res = ErrorCode::Success;

    trace!("indy_crypto_anoncreds_attrs_with_predicates_free: <<< res: {:?}", res);
    res
}

/// Creates and returns proof builder.
///
/// Note that proof buildera deallocation must be performed by
/// calling indy_crypto_anoncreds_proof_builder_free
///
/// Note: Claims proof builder instance deallocation must be performed by
/// calling indy_crypto_anoncreds_proof_builder_finalize.
///
/// # Arguments
/// * `proof_builder_p` - Reference that will contain proof builder instance pointer.
#[no_mangle]
pub extern fn indy_crypto_anoncreds_proof_builder_new(proof_builder_p: *mut *const c_void) -> ErrorCode {
    trace!("indy_crypto_anoncreds_proof_builder_new: >>>");

    let res = match ProofBuilder::new() {
        Ok(proof_builder) => {
            trace!("indy_crypto_anoncreds_proof_builder_new: proof_builder: {:?}", proof_builder);
            unsafe {
                *proof_builder_p = Box::into_raw(Box::new(proof_builder)) as *const c_void;
                trace!("indy_crypto_anoncreds_proof_builder_new: *proof_builder_p: {:?}", *proof_builder_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_anoncreds_proof_builder_new: <<< res: {:?}", res);
    res
}

/// Add claim to proof builder which will be used fo building of proof.
///
/// # Arguments
/// * `proof_builder_p` - Reference that contain proof builder instance pointer.
/// * `uuid` - Uuid.
/// * `claim_p` - Reference that contain claim instance pointer.
/// * `claim_attributes_values_p` - Reference that contain claim attributes instance pointer.
/// * `pub_key_p` - Reference that contain public key instance pointer.
/// * `r_reg_p` - Reference that contain public revocation registry instance pointer.
/// * `attrs_with_predicates_p` - Reference that contain requested attributes and predicates instance pointer.
#[no_mangle]
pub extern fn indy_crypto_anoncreds_proof_builder_add_claim(proof_builder_p: *const c_void,
                                                            uuid: *const c_char,
                                                            claim_p: *const c_void,
                                                            claim_attributes_values_p: *const c_void,
                                                            pub_key_p: *const c_void,
                                                            r_reg_p: *const c_void,
                                                            attrs_with_predicates_p: *const c_void) -> ErrorCode {
    trace!("indy_crypto_anoncreds_proof_builder_add_claim: >>> proof_builder_p: {:?},uuid: {:?},claim_p: {:?},\
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

    trace!("indy_crypto_anoncreds_proof_builder_add_claim: <<< res: {:?}", res);
    res
}


/// Finalize proof
///
/// Note that blinded master secret deallocation must be performed by
/// calling indy_crypto_anoncreds_blinded_master_secret_free
///
/// Note that blinded proof deallocation must be performed by
/// calling indy_crypto_anoncreds_proof_free
///
/// # Arguments
/// * `proof_builder_p` - Reference that contain public keys instance pointer.
/// * `proof_req_p` - Reference that contain proof request instance pointer.
/// * `master_secret_p` - Reference that contain master secret instance pointer.
/// * `proof_p` - Reference that will contain proof instance pointer.
#[no_mangle]
pub extern fn indy_crypto_anoncreds_proof_builder_finilize(proof_builder_p: *const c_void,
                                                           proof_req_p: *const c_void,
                                                           master_secret_p: *const c_void,
                                                           proof_p: *mut *const c_void) -> ErrorCode {
    trace!("indy_crypto_anoncreds_proof_builder_finilize: >>> proof_builder_p: {:?}, proof_req_p: {:?}, master_secret_p: {:?}, proof_p: {:?}",
           proof_builder_p, proof_req_p, master_secret_p, proof_p);

    check_useful_c_ptr!(proof_builder_p, ErrorCode::CommonInvalidParam1);
    check_useful_c_reference!(proof_req_p, ProofRequest, ErrorCode::CommonInvalidParam2);
    check_useful_c_reference!(master_secret_p, MasterSecret, ErrorCode::CommonInvalidParam2);

    let mut proof_builder = unsafe { Box::from_raw(proof_builder_p as *mut ProofBuilder) };

    let res = match ProofBuilder::finalize(&mut proof_builder, proof_req_p, master_secret_p) {
        Ok(proof) => {
            trace!("indy_crypto_anoncreds_proof_builder_finilize: proof: {:?}", proof);
            unsafe {
                *proof_p = Box::into_raw(Box::new(proof)) as *const c_void;
                trace!("indy_crypto_anoncreds_proof_builder_finilize: *proof_p: {:?}", *proof_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_anoncreds_proof_builder_finilize: <<< res: {:?}", res);
    res
}

/// Deallocates proof builder instance.
///
/// # Arguments
/// * `blinded_master_secret_data_p` - Proof builder instance pointer
#[no_mangle]
pub extern fn indy_crypto_anoncreds_proof_builder_free(proof_builder_p: *const c_void) -> ErrorCode {
    trace!("indy_crypto_anoncreds_proof_builder_free: >>> proof_builder_p: {:?}", proof_builder_p);

    check_useful_c_ptr!(proof_builder_p, ErrorCode::CommonInvalidParam1);

    unsafe { Box::from_raw(proof_builder_p as *mut ProofBuilder); }
    let res = ErrorCode::Success;

    trace!("indy_crypto_anoncreds_proof_builder_free: <<< res: {:?}", res);
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::ffi::CString;
    use std::ptr;

    #[test]
    fn indy_crypto_anoncreds_claim_attributes_builder_new_works() {
        let mut claim_attrs_builder: *const c_void = ptr::null();
        let err_code = indy_crypto_anoncreds_claim_attributes_builder_new(&mut claim_attrs_builder);

        assert_eq!(err_code, ErrorCode::Success);
        assert!(!claim_attrs_builder.is_null());

        _free_claim_attrs_builder(claim_attrs_builder);
    }

    #[test]
    fn indy_crypto_anoncreds_claim_attributes_builder_add_attr_works() {
        let mut claim_attrs_builder = _claim_attrs_builder();

        let attr = CString::new("sex").unwrap();
        let err_code = indy_crypto_anoncreds_claim_attributes_builder_add_attr(claim_attrs_builder, attr.as_ptr(), &mut claim_attrs_builder);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!claim_attrs_builder.is_null());

        let attr = CString::new("name").unwrap();
        let err_code = indy_crypto_anoncreds_claim_attributes_builder_add_attr(claim_attrs_builder, attr.as_ptr(), &mut claim_attrs_builder);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!claim_attrs_builder.is_null());

        let attr = CString::new("age").unwrap();
        let err_code = indy_crypto_anoncreds_claim_attributes_builder_add_attr(claim_attrs_builder, attr.as_ptr(), &mut claim_attrs_builder);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!claim_attrs_builder.is_null());

        _free_claim_attrs_builder(claim_attrs_builder);
    }

    #[test]
    fn indy_crypto_anoncreds_claim_attributes_builder_finalize_works() {
        let mut claim_attrs_builder = _claim_attrs_builder();

        let attr = CString::new("sex").unwrap();
        let err_code = indy_crypto_anoncreds_claim_attributes_builder_add_attr(claim_attrs_builder, attr.as_ptr(), &mut claim_attrs_builder);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!claim_attrs_builder.is_null());

        let mut claim_attrs: *const c_void = ptr::null();
        indy_crypto_anoncreds_claim_attributes_builder_finalize(claim_attrs_builder, &mut claim_attrs);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!claim_attrs.is_null());

        _free_claim_attrs(claim_attrs);
    }

    #[test]
    fn indy_crypto_anoncreds_claim_attributes_free_works() {
        let mut claim_attrs = _claim_attrs();

        let err_code = indy_crypto_anoncreds_claim_attributes_free(claim_attrs);
        assert_eq!(err_code, ErrorCode::Success);
    }

    #[test]
    fn indy_crypto_anoncreds_claim_attributes_values_builder_new_works() {
        let mut claim_attrs_values_builder: *const c_void = ptr::null();
        let err_code = indy_crypto_anoncreds_claim_attributes_values_builder_new(&mut claim_attrs_values_builder);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!claim_attrs_values_builder.is_null());

        _free_claim_attrs_values_builder(claim_attrs_values_builder);
    }

    #[test]
    fn indy_crypto_anoncreds_claim_attributes_values_builder_add_attr_value_works() {
        let mut claim_attrs_values_builder = _claim_attrs_values_builder();

        let attr = CString::new("sex").unwrap();
        let dec_value = CString::new("89057765651800459030103911598694169835931320404459570102253965466045532669865684092518362135930940112502263498496335250135601124519172068317163741086983519494043168252186111551835366571584950296764626458785776311514968350600732183408950813066589742888246925358509482561838243805468775416479523402043160919428168650069477488093758569936116799246881809224343325540306266957664475026390533069487455816053169001876208052109360113102565642529699056163373190930839656498261278601357214695582219007449398650197048218304260447909283768896882743373383452996855450316360259637079070460616248922547314789644935074980711243164129").unwrap();
        let err_code = indy_crypto_anoncreds_claim_attributes_values_builder_add_attr_value(claim_attrs_values_builder,
                                                                                            attr.as_ptr(),
                                                                                            dec_value.as_ptr(),
                                                                                            &mut claim_attrs_values_builder);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!claim_attrs_values_builder.is_null());

        let attr = CString::new("name").unwrap();
        let dec_value = CString::new("58606710922154038918005745652863947546479611221487923871520854046018234465128105585608812090213473225037875788462225679336791123783441657062831589984290779844020407065450830035885267846722229953206567087435754612694085258455822926492275621650532276267042885213400704012011608869094703483233081911010530256094461587809601298503874283124334225428746479707531278882536314925285434699376158578239556590141035593717362562548075653598376080466948478266094753818404986494459240364648986755479857098110402626477624280802323635285059064580583239726433768663879431610261724430965980430886959304486699145098822052003020688956471").unwrap();
        let err_code = indy_crypto_anoncreds_claim_attributes_values_builder_add_attr_value(claim_attrs_values_builder,
                                                                                            attr.as_ptr(),
                                                                                            dec_value.as_ptr(),
                                                                                            &mut claim_attrs_values_builder);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!claim_attrs_values_builder.is_null());

        _free_claim_attrs_values_builder(claim_attrs_values_builder);
    }

    #[test]
    fn indy_crypto_anoncreds_claim_attributes_values_free_works() {
        let mut claim_attrs_values = _claim_attrs_values();

        let err_code = indy_crypto_anoncreds_claim_attributes_values_free(claim_attrs_values);
        assert_eq!(err_code, ErrorCode::Success);
    }

    #[test]
    fn indy_crypto_anoncreds_issuer_new_keys_works() {
        let mut claim_attrs = _claim_attrs();
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
    fn indy_crypto_anoncreds_generate_master_secret_works() {
        let mut master_secret_p: *const c_void = ptr::null();
        let err_code = indy_crypto_anoncreds_generate_master_secret(&mut master_secret_p);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!master_secret_p.is_null());
    }

    fn _claim_attrs_builder() -> *const c_void {
        let mut claim_attrs_builder: *const c_void = ptr::null();
        let err_code = indy_crypto_anoncreds_claim_attributes_builder_new(&mut claim_attrs_builder);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!claim_attrs_builder.is_null());

        claim_attrs_builder
    }

    fn _free_claim_attrs_builder(claim_attrs_builder: *const c_void) {
        let mut claim_attrs: *const c_void = ptr::null();
        let err_code = indy_crypto_anoncreds_claim_attributes_builder_finalize(claim_attrs_builder, &mut claim_attrs);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!claim_attrs.is_null());

        _free_claim_attrs(claim_attrs);
    }

    fn _claim_attrs() -> *const c_void {
        let mut claim_attrs_builder = _claim_attrs_builder();

        let attr = CString::new("name").unwrap();
        let err_code = indy_crypto_anoncreds_claim_attributes_builder_add_attr(claim_attrs_builder, attr.as_ptr(), &mut claim_attrs_builder);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!claim_attrs_builder.is_null());


        let attr = CString::new("age").unwrap();
        let err_code = indy_crypto_anoncreds_claim_attributes_builder_add_attr(claim_attrs_builder, attr.as_ptr(), &mut claim_attrs_builder);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!claim_attrs_builder.is_null());

        let attr = CString::new("sex").unwrap();
        let err_code = indy_crypto_anoncreds_claim_attributes_builder_add_attr(claim_attrs_builder, attr.as_ptr(), &mut claim_attrs_builder);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!claim_attrs_builder.is_null());

        let attr = CString::new("height").unwrap();
        let err_code = indy_crypto_anoncreds_claim_attributes_builder_add_attr(claim_attrs_builder, attr.as_ptr(), &mut claim_attrs_builder);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!claim_attrs_builder.is_null());

        let mut claim_attrs: *const c_void = ptr::null();
        indy_crypto_anoncreds_claim_attributes_builder_finalize(claim_attrs_builder, &mut claim_attrs);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!claim_attrs.is_null());

        claim_attrs
    }

    fn _free_claim_attrs(claim_attrs: *const c_void) {
        let err_code = indy_crypto_anoncreds_claim_attributes_free(claim_attrs);
        assert_eq!(err_code, ErrorCode::Success);
    }

    fn _claim_attrs_values_builder() -> *const c_void {
        let mut claim_attrs_values_builder: *const c_void = ptr::null();
        let err_code = indy_crypto_anoncreds_claim_attributes_values_builder_new(&mut claim_attrs_values_builder);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!claim_attrs_values_builder.is_null());

        claim_attrs_values_builder
    }

    fn _free_claim_attrs_values_builder(claim_attrs_values_builder: *const c_void) {
        let mut claim_attrs_values: *const c_void = ptr::null();
        let err_code = indy_crypto_anoncreds_claim_attributes_values_builder_finalize(claim_attrs_values_builder, &mut claim_attrs_values);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!claim_attrs_values.is_null());

        _free_claim_attrs_values(claim_attrs_values);
    }

    fn _claim_attrs_values() -> *const c_void {
        let mut claim_attrs_values_builder = _claim_attrs_values_builder();

        let attr = CString::new("name").unwrap();
        let dec_value = CString::new("1139481716457488690172217916278103335").unwrap();
        let err_code = indy_crypto_anoncreds_claim_attributes_values_builder_add_attr_value(claim_attrs_values_builder,
                                                                                            attr.as_ptr(),
                                                                                            dec_value.as_ptr(),
                                                                                            &mut claim_attrs_values_builder);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!claim_attrs_values_builder.is_null());

        let attr = CString::new("age").unwrap();
        let dec_value = CString::new("33").unwrap();
        let err_code = indy_crypto_anoncreds_claim_attributes_values_builder_add_attr_value(claim_attrs_values_builder,
                                                                                            attr.as_ptr(),
                                                                                            dec_value.as_ptr(),
                                                                                            &mut claim_attrs_values_builder);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!claim_attrs_values_builder.is_null());

        let attr = CString::new("sex").unwrap();
        let dec_value = CString::new("5944657099558967239210949258394887428692050081607692519917050011144233115103").unwrap();
        let err_code = indy_crypto_anoncreds_claim_attributes_values_builder_add_attr_value(claim_attrs_values_builder,
                                                                                            attr.as_ptr(),
                                                                                            dec_value.as_ptr(),
                                                                                            &mut claim_attrs_values_builder);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!claim_attrs_values_builder.is_null());

        let attr = CString::new("height").unwrap();
        let dec_value = CString::new("175").unwrap();
        let err_code = indy_crypto_anoncreds_claim_attributes_values_builder_add_attr_value(claim_attrs_values_builder,
                                                                                            attr.as_ptr(),
                                                                                            dec_value.as_ptr(),
                                                                                            &mut claim_attrs_values_builder);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!claim_attrs_values_builder.is_null());


        let mut claim_attrs_values: *const c_void = ptr::null();
        indy_crypto_anoncreds_claim_attributes_values_builder_finalize(claim_attrs_values_builder, &mut claim_attrs_values);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!claim_attrs_values.is_null());

        claim_attrs_values
    }

    fn _free_claim_attrs_values(claim_attrs_values: *const c_void) {
        let err_code = indy_crypto_anoncreds_claim_attributes_values_free(claim_attrs_values);
        assert_eq!(err_code, ErrorCode::Success);
    }

    fn _issuer_keys() -> (*const c_void, *const c_void) {
        let mut claim_attrs = _claim_attrs();

        let mut issuer_pub_key: *const c_void = ptr::null();
        let mut issuer_priv_key: *const c_void = ptr::null();

        let err_code = indy_crypto_anoncreds_issuer_new_keys(claim_attrs, true, &mut issuer_pub_key, &mut issuer_priv_key);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!issuer_pub_key.is_null());
        assert!(!issuer_priv_key.is_null());

        _free_claim_attrs(claim_attrs);

        (issuer_pub_key, issuer_priv_key)
    }

    fn _free_issuer_keys(issuer_pub_key: *const c_void, issuer_priv_key: *const c_void) {
        let err_code = indy_crypto_anoncreds_issuer_public_key_free(issuer_pub_key);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = indy_crypto_anoncreds_issuer_private_key_free(issuer_priv_key);
        assert_eq!(err_code, ErrorCode::Success);
    }

    fn _revocation_registry(issuer_pub_key: *const c_void) -> (*const c_void, *const c_void) {
        let mut rev_reg_pub: *const c_void = ptr::null();
        let mut rev_reg_priv: *const c_void = ptr::null();

        let err_code = indy_crypto_anoncreds_issuer_new_revocation_registry(issuer_pub_key, 100, &mut rev_reg_pub, &mut rev_reg_priv);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!rev_reg_pub.is_null());
        assert!(!rev_reg_priv.is_null());

        (rev_reg_pub, rev_reg_priv)
    }

    fn _free_revocation_registry(rev_reg_pub: *const c_void, rev_reg_priv: *const c_void) {
        let err_code = indy_crypto_anoncreds_revocation_registry_public_free(rev_reg_pub);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = indy_crypto_anoncreds_revocation_registry_private_free(rev_reg_priv);
        assert_eq!(err_code, ErrorCode::Success);
    }
}