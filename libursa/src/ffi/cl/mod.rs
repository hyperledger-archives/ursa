use cl::issuer::Issuer;
use cl::verifier::Verifier;
use cl::*;
use errors::prelude::*;
use ffi::ErrorCode;
use utils::ctypes::*;

use serde_json;
use std::os::raw::{c_char, c_void};
use std::ptr;

pub mod issuer;
pub mod prover;
pub mod verifier;

type FFITailTake =
    extern "C" fn(ctx: *const c_void, idx: u32, tail_p: *mut *const c_void) -> ErrorCode;
type FFITailPut = extern "C" fn(ctx: *const c_void, tail: *const c_void) -> ErrorCode;

#[no_mangle]
pub extern "C" fn ursa_cl_tails_generator_next(
    rev_tails_generator: *const c_void,
    tail_p: *mut *const c_void,
) -> ErrorCode {
    trace!(
        "ursa_cl_tails_generator_next: >>> rev_tails_generator: {:?}, tail_p {:?}",
        rev_tails_generator,
        tail_p
    );

    check_useful_mut_c_reference!(
        rev_tails_generator,
        RevocationTailsGenerator,
        ErrorCode::CommonInvalidParam1
    );
    check_useful_c_ptr!(tail_p, ErrorCode::CommonInvalidParam2);

    let res = match rev_tails_generator.try_next() {
        Ok(tail) => {
            unsafe {
                if let Some(tail) = tail {
                    *tail_p = Box::into_raw(Box::new(tail)) as *const c_void;
                } else {
                    *tail_p = ptr::null();
                }
                trace!("ursa_cl_tails_generator_next: *tail_p: {:?}", *tail_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.into(),
    };

    trace!("ursa_cl_tails_generator_next: <<< {:?}", res);
    res
}

#[no_mangle]
pub extern "C" fn ursa_cl_tails_generator_count(
    rev_tails_generator: *const c_void,
    count_p: *mut u32,
) -> ErrorCode {
    trace!(
        "ursa_cl_tails_generator_count: >>> rev_tails_generator: {:?}, count_p {:?}",
        rev_tails_generator,
        count_p
    );

    check_useful_mut_c_reference!(
        rev_tails_generator,
        RevocationTailsGenerator,
        ErrorCode::CommonInvalidParam1
    );
    check_useful_c_ptr!(count_p, ErrorCode::CommonInvalidParam2);

    let cnt = rev_tails_generator.count();
    unsafe {
        *count_p = cnt;
        trace!("ursa_cl_tails_generator_count: *count_p: {:?}", *count_p);
    }
    let res = ErrorCode::Success;

    trace!("ursa_cl_tails_generator_count: <<< {:?}", res);
    res
}

#[no_mangle]
pub extern "C" fn ursa_cl_tail_free(tail: *const c_void) -> ErrorCode {
    trace!("ursa_cl_tail_free: >>> tail: {:?}", tail);

    check_useful_c_ptr!(tail, ErrorCode::CommonInvalidParam1);

    let tail = unsafe { Box::from_raw(tail as *mut Tail) };
    trace!("ursa_cl_tail_free: entity: tail: {:?}", tail);

    let res = ErrorCode::Success;

    trace!("ursa_cl_tail_free: <<< res: {:?}", res);
    res
}

#[no_mangle]
pub extern "C" fn ursa_cl_witness_new(
    rev_idx: u32,
    max_cred_num: u32,
    issuance_by_default: bool,
    rev_reg_delta: *const c_void,
    ctx_tails: *const c_void,
    take_tail: FFITailTake,
    put_tail: FFITailPut,
    witness_p: *mut *const c_void,
) -> ErrorCode {
    trace!("ursa_cl_witness_new: >>> rev_idx: {:?}, max_cred_num {}, issuance_by_default {}, rev_reg_delta {:?}, ctx_tails {:?}, take_tail {:?}, \
    put_tail {:?}, witness_p {:?}", rev_idx, max_cred_num, issuance_by_default, rev_reg_delta, ctx_tails, take_tail, put_tail, witness_p);

    check_useful_c_reference!(
        rev_reg_delta,
        RevocationRegistryDelta,
        ErrorCode::CommonInvalidParam3
    );

    let rta = FFITailsAccessor::new(ctx_tails, take_tail, put_tail);
    let res = match Witness::new(
        rev_idx,
        max_cred_num,
        issuance_by_default,
        rev_reg_delta,
        &rta,
    ) {
        Ok(witness) => {
            unsafe {
                *witness_p = Box::into_raw(Box::new(witness)) as *const c_void;
                trace!("ursa_cl_witness_new: *witness_p: {:?}", *witness_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.into(),
    };

    trace!("ursa_cl_witness_new: <<< res: {:?}", res);
    res
}

#[no_mangle]
pub extern "C" fn ursa_cl_witness_update(
    rev_idx: u32,
    max_cred_num: u32,
    rev_reg_delta: *const c_void,
    witness: *mut c_void,
    ctx_tails: *const c_void,
    take_tail: FFITailTake,
    put_tail: FFITailPut,
) -> ErrorCode {
    trace!("ursa_cl_witness_update: >>> rev_idx: {:?}, max_cred_num {}, rev_reg_delta {:?}, ctx_tails {:?}, take_tail {:?}, put_tail {:?}, witness {:?}",
           rev_idx, max_cred_num, rev_reg_delta, ctx_tails, take_tail, put_tail, witness);

    check_useful_c_reference!(
        rev_reg_delta,
        RevocationRegistryDelta,
        ErrorCode::CommonInvalidParam3
    );
    check_useful_mut_c_reference!(witness, Witness, ErrorCode::CommonInvalidParam4);

    let rta = FFITailsAccessor::new(ctx_tails, take_tail, put_tail);
    let res = match witness.update(rev_idx, max_cred_num, rev_reg_delta, &rta) {
        Ok(()) => ErrorCode::Success,
        Err(err) => err.into(),
    };

    trace!("ursa_cl_witness_update: <<< res: {:?}", res);
    res
}

#[no_mangle]
pub extern "C" fn ursa_cl_witness_free(witness: *const c_void) -> ErrorCode {
    trace!("ursa_cl_witness_free: >>> witness: {:?}", witness);

    check_useful_c_ptr!(witness, ErrorCode::CommonInvalidParam1);

    let witness = unsafe { Box::from_raw(witness as *mut Witness) };
    trace!("ursa_cl_witness_free: entity: witness: {:?}", witness);

    let res = ErrorCode::Success;

    trace!("ursa_cl_witness_free: <<< res: {:?}", res);
    res
}

/// Creates and returns credential schema entity builder.
///
/// The purpose of credential schema builder is building of credential schema entity that
/// represents credential schema attributes set.
///
/// Note: Credential schema builder instance deallocation must be performed by
/// calling ursa_cl_credential_schema_builder_finalize.
///
/// # Arguments
/// * `credential_schema_builder_p` - Reference that will contain credentials attributes builder instance pointer.
#[no_mangle]
pub extern "C" fn ursa_cl_credential_schema_builder_new(
    credential_schema_builder_p: *mut *const c_void,
) -> ErrorCode {
    trace!(
        "ursa_cl_credential_schema_builder_new: >>> credential_schema_builder_p: {:?}",
        credential_schema_builder_p
    );

    check_useful_c_ptr!(credential_schema_builder_p, ErrorCode::CommonInvalidParam1);

    let res = match Issuer::new_credential_schema_builder() {
        Ok(credential_schema_builder) => {
            trace!(
                "ursa_cl_credential_schema_builder_new: credential_schema_builder: {:?}",
                credential_schema_builder
            );
            unsafe {
                *credential_schema_builder_p =
                    Box::into_raw(Box::new(credential_schema_builder)) as *const c_void;
                trace!(
                    "ursa_cl_credential_schema_builder_new: *credential_schema_builder_p: {:?}",
                    *credential_schema_builder_p
                );
            }
            ErrorCode::Success
        }
        Err(err) => err.into(),
    };

    trace!("ursa_cl_credential_schema_builder_new: <<< res: {:?}", res);
    res
}

/// Adds new attribute to credential schema.
///
/// # Arguments
/// * `credential_schema_builder` - Reference that contains credential schema builder instance pointer.
/// * `attr` - Attribute to add as null terminated string.
#[no_mangle]
pub extern "C" fn ursa_cl_credential_schema_builder_add_attr(
    credential_schema_builder: *const c_void,
    attr: *const c_char,
) -> ErrorCode {
    trace!("ursa_cl_credential_schema_builder_add_attr: >>> credential_schema_builder: {:?}, attr: {:?}", credential_schema_builder, attr);

    check_useful_mut_c_reference!(
        credential_schema_builder,
        CredentialSchemaBuilder,
        ErrorCode::CommonInvalidParam1
    );
    check_useful_c_str!(attr, ErrorCode::CommonInvalidParam2);

    trace!("ursa_cl_credential_schema_builder_add_attr: entities: credential_schema_builder: {:?}, attr: {:?}", credential_schema_builder, attr);

    let res = match credential_schema_builder.add_attr(&attr) {
        Ok(_) => ErrorCode::Success,
        Err(err) => err.into(),
    };

    trace!(
        "ursa_cl_credential_schema_builder_add_attr: <<< res: {:?}",
        res
    );
    res
}

/// Deallocates credential schema builder and returns credential schema entity instead.
///
/// Note: Credentials schema instance deallocation must be performed by
/// calling ursa_cl_credential_schema_free.
///
/// # Arguments
/// * `credential_schema_builder` - Reference that contains credential schema builder instance pointer
/// * `credential_schema_p` - Reference that will contain credentials schema instance pointer.
#[no_mangle]
pub extern "C" fn ursa_cl_credential_schema_builder_finalize(
    credential_schema_builder: *const c_void,
    credential_schema_p: *mut *const c_void,
) -> ErrorCode {
    trace!("ursa_cl_credential_schema_builder_finalize: >>> credential_schema_builder: {:?}, credential_schema_p: {:?}", credential_schema_builder, credential_schema_p);

    check_useful_c_ptr!(credential_schema_builder, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(credential_schema_p, ErrorCode::CommonInvalidParam2);

    let credential_schema_builder =
        unsafe { Box::from_raw(credential_schema_builder as *mut CredentialSchemaBuilder) };

    trace!(
        "ursa_cl_credential_schema_builder_finalize: entities: credential_schema_builder: {:?}",
        credential_schema_builder
    );

    let res = match credential_schema_builder.finalize() {
        Ok(credential_schema) => {
            trace!(
                "ursa_cl_credential_schema_builder_finalize: credential_schema: {:?}",
                credential_schema
            );
            unsafe {
                *credential_schema_p = Box::into_raw(Box::new(credential_schema)) as *const c_void;
                trace!(
                    "ursa_cl_credential_schema_builder_finalize: *credential_schema_p: {:?}",
                    *credential_schema_p
                );
            }
            ErrorCode::Success
        }
        Err(err) => err.into(),
    };

    trace!(
        "ursa_cl_credential_schema_builder_finalize: <<< res: {:?}",
        res
    );
    res
}

/// Deallocates credential schema instance.
///
/// # Arguments
/// * `credential_schema` - Reference that contains credential schema instance pointer.
#[no_mangle]
pub extern "C" fn ursa_cl_credential_schema_free(credential_schema: *const c_void) -> ErrorCode {
    trace!(
        "ursa_cl_credential_schema_free: >>> credential_schema: {:?}",
        credential_schema
    );

    check_useful_c_ptr!(credential_schema, ErrorCode::CommonInvalidParam1);

    let credential_schema = unsafe { Box::from_raw(credential_schema as *mut CredentialSchema) };
    trace!(
        "ursa_cl_credential_schema_free: entity: credential_schema: {:?}",
        credential_schema
    );

    let res = ErrorCode::Success;

    trace!("ursa_cl_credential_schema_free: <<< res: {:?}", res);
    res
}

/// Creates and returns non credential schema builder.
///
/// The purpose of non credential schema builder is building of non credential schema that
/// represents non credential schema attributes set. These are attributes added to schemas that are not on the ledger
///
/// Note: Non credential schema builder instance deallocation must be performed by
/// calling ursa_cl_non_credential_schema_builder_finalize.
///
/// # Arguments
/// * `credential_schema_builder_p` - Reference that will contain credentials attributes builder instance pointer.
#[no_mangle]
pub extern "C" fn ursa_cl_non_credential_schema_builder_new(
    non_credential_schema_builder_p: *mut *const c_void,
) -> ErrorCode {
    trace!(
        "ursa_cl_non_credential_schema_builder_new: >>> non_credential_schema_builder_p: {:?}",
        non_credential_schema_builder_p
    );

    check_useful_c_ptr!(
        non_credential_schema_builder_p,
        ErrorCode::CommonInvalidParam1
    );

    let res = match Issuer::new_non_credential_schema_builder() {
        Ok(non_credential_schema_builder) => {
            trace!(
                "ursa_cl_credential_schema_builder_new: non_credential_schema_builder: {:?}",
                non_credential_schema_builder
            );
            unsafe {
                *non_credential_schema_builder_p =
                    Box::into_raw(Box::new(non_credential_schema_builder)) as *const c_void;
                trace!(
                    "ursa_cl_credential_schema_builder_new: *credential_schema_builder_p: {:?}",
                    *non_credential_schema_builder_p
                );
            }
            ErrorCode::Success
        }
        Err(err) => err.into(),
    };

    trace!(
        "ursa_cl_non_credential_schema_builder_new: <<< res: {:?}",
        res
    );
    res
}

/// Adds new attribute to non credential schema.
///
/// # Arguments
/// * `non_credential_schema_builder` - Reference that contains non credential schema builder instance pointer.
/// * `attr` - Attribute to add as null terminated string.
#[no_mangle]
pub extern "C" fn ursa_cl_non_credential_schema_builder_add_attr(
    non_credential_schema_builder: *const c_void,
    attr: *const c_char,
) -> ErrorCode {
    trace!("ursa_cl_credential_schema_builder_add_attr: >>> non_credential_schema_builder: {:?}, attr: {:?}", non_credential_schema_builder, attr);

    check_useful_mut_c_reference!(
        non_credential_schema_builder,
        NonCredentialSchemaBuilder,
        ErrorCode::CommonInvalidParam1
    );
    check_useful_c_str!(attr, ErrorCode::CommonInvalidParam2);

    trace!("ursa_cl_credential_schema_builder_add_attr: entities: credential_schema_builder: {:?}, attr: {:?}", non_credential_schema_builder, attr);

    let res = match non_credential_schema_builder.add_attr(&attr) {
        Ok(_) => ErrorCode::Success,
        Err(err) => err.into(),
    };

    trace!(
        "ursa_cl_non_credential_schema_builder_add_attr: <<< res: {:?}",
        res
    );
    res
}

/// Deallocates non_credential schema builder and returns non credential schema entity instead.
///
/// Note: Non credential schema instance deallocation must be performed by
/// calling ursa_cl_non_credential_schema_free.
///
/// # Arguments
/// * `non_credential_schema_builder` - Reference that contains non credential schema builder instance pointer
/// * `non_credential_schema_p` - Reference that will contain non credentials schema instance pointer.
#[no_mangle]
pub extern "C" fn ursa_cl_non_credential_schema_builder_finalize(
    non_credential_schema_builder: *const c_void,
    non_credential_schema_p: *mut *const c_void,
) -> ErrorCode {
    trace!("ursa_cl_non_credential_schema_builder_finalize: >>> non_credential_schema_builder: {:?}, non_credential_schema_p: {:?}", non_credential_schema_builder, non_credential_schema_p);

    check_useful_c_ptr!(
        non_credential_schema_builder,
        ErrorCode::CommonInvalidParam1
    );
    check_useful_c_ptr!(non_credential_schema_p, ErrorCode::CommonInvalidParam2);

    let non_credential_schema_builder =
        unsafe { Box::from_raw(non_credential_schema_builder as *mut NonCredentialSchemaBuilder) };

    trace!(
        "ursa_cl_non_credential_schema_builder_finalize: entities: credential_schema_builder: {:?}",
        non_credential_schema_builder
    );

    let res = match non_credential_schema_builder.finalize() {
        Ok(non_credential_schema) => {
            trace!(
                "ursa_cl_non_credential_schema_builder_finalize: credential_schema: {:?}",
                non_credential_schema
            );
            unsafe {
                *non_credential_schema_p =
                    Box::into_raw(Box::new(non_credential_schema)) as *const c_void;
                trace!(
                    "ursa_cl_non_credential_schema_builder_finalize: *credential_schema_p: {:?}",
                    *non_credential_schema_p
                );
            }
            ErrorCode::Success
        }
        Err(err) => err.into(),
    };

    trace!(
        "ursa_cl_non_credential_schema_builder_finalize: <<< res: {:?}",
        res
    );
    res
}

/// Deallocates credential schema instance.
///
/// # Arguments
/// * `non_credential_schema` - Reference that contains non credential schema instance pointer.
#[no_mangle]
pub extern "C" fn ursa_cl_non_credential_schema_free(
    non_credential_schema: *const c_void,
) -> ErrorCode {
    trace!(
        "ursa_cl_non_credential_schema_free: >>> non_credential_schema: {:?}",
        non_credential_schema
    );

    check_useful_c_ptr!(non_credential_schema, ErrorCode::CommonInvalidParam1);

    let non_credential_schema =
        unsafe { Box::from_raw(non_credential_schema as *mut NonCredentialSchema) };
    trace!(
        "ursa_cl_non_credential_schema_free: entity: credential_schema: {:?}",
        non_credential_schema
    );

    let res = ErrorCode::Success;

    trace!("ursa_cl_non_credential_schema_free: <<< res: {:?}", res);
    res
}

/// Creates and returns credentials values entity builder.
///
/// The purpose of credential values builder is building of credential values entity that
/// represents credential attributes values map.
///
/// Note: Credentials values builder instance deallocation must be performed by
/// calling ursa_cl_credential_values_builder_finalize.
///
/// # Arguments
/// * `credential_values_builder_p` - Reference that will contain credentials values builder instance pointer.
#[no_mangle]
pub extern "C" fn ursa_cl_credential_values_builder_new(
    credential_values_builder_p: *mut *const c_void,
) -> ErrorCode {
    trace!(
        "ursa_cl_credential_values_builder_new: >>> credential_values_builder_p: {:?}",
        credential_values_builder_p
    );

    check_useful_c_ptr!(credential_values_builder_p, ErrorCode::CommonInvalidParam1);

    let res = match Issuer::new_credential_values_builder() {
        Ok(credential_values_builder) => {
            trace!(
                "ursa_cl_credential_values_builder_new: credential_values_builder: {:?}",
                credential_values_builder
            );
            unsafe {
                *credential_values_builder_p =
                    Box::into_raw(Box::new(credential_values_builder)) as *const c_void;
                trace!(
                    "ursa_cl_credential_values_builder_new: *credential_values_builder_p: {:?}",
                    *credential_values_builder_p
                );
            }
            ErrorCode::Success
        }
        Err(err) => err.into(),
    };

    trace!("ursa_cl_credential_values_builder_new: <<< res: {:?}", res);
    res
}

/// Adds new known attribute dec_value to credential values map.
///
/// # Arguments
/// * `credential_values_builder` - Reference that contains credential values builder instance pointer.
/// * `attr` - Credential attr to add as null terminated string.
/// * `dec_value` - Credential attr dec_value. Decimal BigNum representation as null terminated string.
#[no_mangle]
pub extern "C" fn ursa_cl_credential_values_builder_add_dec_known(
    credential_values_builder: *const c_void,
    attr: *const c_char,
    dec_value: *const c_char,
) -> ErrorCode {
    trace!("ursa_cl_credential_values_builder_add_dec_known: >>> credential_values_builder: {:?}, attr: {:?}, dec_value: {:?}",
           credential_values_builder, attr, dec_value);

    check_useful_mut_c_reference!(
        credential_values_builder,
        CredentialValuesBuilder,
        ErrorCode::CommonInvalidParam1
    );
    check_useful_c_str!(attr, ErrorCode::CommonInvalidParam2);
    check_useful_c_str!(dec_value, ErrorCode::CommonInvalidParam3);

    trace!("ursa_cl_credential_values_builder_add_dec_known: entities: credential_values_builder: {:?}, attr: {:?}, dec_value: {:?}", credential_values_builder, attr, dec_value);

    let res = match credential_values_builder.add_dec_known(&attr, &dec_value) {
        Ok(_) => ErrorCode::Success,
        Err(err) => err.into(),
    };

    trace!(
        "ursa_cl_credential_values_builder_add_dec_known: <<< res: {:?}",
        res
    );
    res
}

/// Adds new hidden attribute dec_value to credential values map.
///
/// # Arguments
/// * `credential_values_builder` - Reference that contains credential values builder instance pointer.
/// * `attr` - Credential attr to add as null terminated string.
/// * `dec_value` - Credential attr dec_value. Decimal BigNum representation as null terminated string.
#[no_mangle]
pub extern "C" fn ursa_cl_credential_values_builder_add_dec_hidden(
    credential_values_builder: *const c_void,
    attr: *const c_char,
    dec_value: *const c_char,
) -> ErrorCode {
    trace!("ursa_cl_credential_values_builder_add_dec_hidden: >>> credential_values_builder: {:?}, attr: {:?}, dec_value: {:?}",
           credential_values_builder, attr, dec_value);

    check_useful_mut_c_reference!(
        credential_values_builder,
        CredentialValuesBuilder,
        ErrorCode::CommonInvalidParam1
    );
    check_useful_c_str!(attr, ErrorCode::CommonInvalidParam2);
    check_useful_c_str!(dec_value, ErrorCode::CommonInvalidParam3);

    trace!("ursa_cl_credential_values_builder_add_dec_hidden: entities: credential_values_builder: {:?}, attr: {:?}, dec_value: {:?}", credential_values_builder, attr, dec_value);

    let res = match credential_values_builder.add_dec_hidden(&attr, &dec_value) {
        Ok(_) => ErrorCode::Success,
        Err(err) => err.into(),
    };

    trace!(
        "ursa_cl_credential_values_builder_add_dec_hidden: <<< res: {:?}",
        res
    );
    res
}

/// Adds new hidden attribute dec_value to credential values map.
///
/// # Arguments
/// * `credential_values_builder` - Reference that contains credential values builder instance pointer.
/// * `attr` - Credential attr to add as null terminated string.
/// * `dec_value` - Credential attr dec_value. Decimal BigNum representation as null terminated string.
/// * `dec_blinding_factor` - Credential blinding factor. Decimal BigNum representation as null terminated string
#[no_mangle]
pub extern "C" fn ursa_cl_credential_values_builder_add_dec_commitment(
    credential_values_builder: *const c_void,
    attr: *const c_char,
    dec_value: *const c_char,
    dec_blinding_factor: *const c_char,
) -> ErrorCode {
    trace!("ursa_cl_credential_values_builder_add_dec_commitment: >>> credential_values_builder: {:?}, attr: {:?}, dec_value: {:?}, dec_blinding_factor: {:?}",
           credential_values_builder, attr, dec_value, dec_blinding_factor);

    check_useful_mut_c_reference!(
        credential_values_builder,
        CredentialValuesBuilder,
        ErrorCode::CommonInvalidParam1
    );
    check_useful_c_str!(attr, ErrorCode::CommonInvalidParam2);
    check_useful_c_str!(dec_value, ErrorCode::CommonInvalidParam3);
    check_useful_c_str!(dec_blinding_factor, ErrorCode::CommonInvalidParam4);

    trace!("ursa_cl_credential_values_builder_add_dec_commitment: entities: credential_values_builder: {:?}, attr: {:?}, dec_value: {:?}, dec_blinding_factor: {:?}", credential_values_builder, attr, dec_value, dec_blinding_factor);

    let res =
        match credential_values_builder.add_dec_commitment(&attr, &dec_value, &dec_blinding_factor)
        {
            Ok(_) => ErrorCode::Success,
            Err(err) => err.into(),
        };

    trace!(
        "ursa_cl_credential_values_builder_add_dec_commitment: <<< res: {:?}",
        res
    );
    res
}

/// Deallocates credential values builder and returns credential values entity instead.
///
/// Note: Credentials values instance deallocation must be performed by
/// calling ursa_cl_credential_values_free.
///
/// # Arguments
/// * `credential_values_builder` - Reference that contains credential attribute builder instance pointer.
/// * `credential_values_p` - Reference that will contain credentials values instance pointer.
#[no_mangle]
pub extern "C" fn ursa_cl_credential_values_builder_finalize(
    credential_values_builder: *const c_void,
    credential_values_p: *mut *const c_void,
) -> ErrorCode {
    trace!("ursa_cl_credential_values_builder_finalize: >>> credential_values_builder: {:?}, credential_values_p: {:?}", credential_values_builder, credential_values_p);

    check_useful_c_ptr!(credential_values_builder, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(credential_values_p, ErrorCode::CommonInvalidParam2);

    let credential_values_builder =
        unsafe { Box::from_raw(credential_values_builder as *mut CredentialValuesBuilder) };

    trace!(
        "ursa_cl_credential_values_builder_finalize: entities: credential_values_builder: {:?}",
        credential_values_builder
    );

    let res = match credential_values_builder.finalize() {
        Ok(credential_values) => {
            trace!(
                "ursa_cl_credential_values_builder_finalize: credential_values: {:?}",
                credential_values
            );
            unsafe {
                *credential_values_p = Box::into_raw(Box::new(credential_values)) as *const c_void;
                trace!(
                    "ursa_cl_credential_values_builder_finalize: *credential_values_p: {:?}",
                    *credential_values_p
                );
            }
            ErrorCode::Success
        }
        Err(err) => err.into(),
    };

    trace!(
        "ursa_cl_credential_values_builder_finalize: <<< res: {:?}",
        res
    );
    res
}

/// Deallocates credential values instance.
///
/// # Arguments
/// * `credential_values` - Credential values instance pointer
#[no_mangle]
pub extern "C" fn ursa_cl_credential_values_free(credential_values: *const c_void) -> ErrorCode {
    trace!(
        "ursa_cl_credential_values_free: >>> credential_values: {:?}",
        credential_values
    );

    check_useful_c_ptr!(credential_values, ErrorCode::CommonInvalidParam1);

    let credential_values = unsafe { Box::from_raw(credential_values as *mut CredentialValues) };
    trace!(
        "ursa_cl_credential_values_free: entity: credential_values: {:?}",
        credential_values
    );

    let res = ErrorCode::Success;

    trace!("ursa_cl_credential_values_free: <<< res: {:?}", res);
    res
}

/// Creates and returns sub proof request entity builder.
///
/// The purpose of sub proof request builder is building of sub proof request entity that
/// represents requested attributes and predicates.
///
/// Note: sub proof request builder instance deallocation must be performed by
/// calling ursa_cl_sub_proof_request_builder_finalize.
///
/// # Arguments
/// * `sub_proof_request_builder_p` - Reference that will contain sub proof request builder instance pointer.
#[no_mangle]
pub extern "C" fn ursa_cl_sub_proof_request_builder_new(
    sub_proof_request_builder_p: *mut *const c_void,
) -> ErrorCode {
    trace!(
        "ursa_cl_sub_proof_request_builder_new: >>> sub_proof_request_builder_p: {:?}",
        sub_proof_request_builder_p
    );

    check_useful_c_ptr!(sub_proof_request_builder_p, ErrorCode::CommonInvalidParam1);

    let res = match Verifier::new_sub_proof_request_builder() {
        Ok(sub_proof_request_builder) => {
            trace!(
                "ursa_cl_sub_proof_request_builder_new: sub_proof_request_builder: {:?}",
                sub_proof_request_builder
            );
            unsafe {
                *sub_proof_request_builder_p =
                    Box::into_raw(Box::new(sub_proof_request_builder)) as *const c_void;
                trace!(
                    "ursa_cl_sub_proof_request_builder_new: *sub_proof_request_builder_p: {:?}",
                    *sub_proof_request_builder_p
                );
            }
            ErrorCode::Success
        }
        Err(err) => err.into(),
    };

    trace!("ursa_cl_sub_proof_request_builder_new: <<< res: {:?}", res);
    res
}

/// Adds new revealed attribute to sub proof request.
///
/// # Arguments
/// * `sub_proof_request_builder` - Reference that contains sub proof request builder instance pointer.
/// * `attr` - Credential attr to add as null terminated string.
#[no_mangle]
pub extern "C" fn ursa_cl_sub_proof_request_builder_add_revealed_attr(
    sub_proof_request_builder: *const c_void,
    attr: *const c_char,
) -> ErrorCode {
    trace!("ursa_cl_sub_proof_request_builder_add_revealed_attr: >>> sub_proof_request_builder: {:?}, attr: {:?}",
           sub_proof_request_builder, attr);

    check_useful_mut_c_reference!(
        sub_proof_request_builder,
        SubProofRequestBuilder,
        ErrorCode::CommonInvalidParam1
    );
    check_useful_c_str!(attr, ErrorCode::CommonInvalidParam2);

    trace!("ursa_cl_sub_proof_request_builder_add_revealed_attr: entities: sub_proof_request_builder: {:?}, attr: {:?}",
           sub_proof_request_builder, attr);

    let res = match sub_proof_request_builder.add_revealed_attr(&attr) {
        Ok(_) => ErrorCode::Success,
        Err(err) => err.into(),
    };

    trace!(
        "ursa_cl_sub_proof_request_builder_add_revealed_attr: <<< res: {:?}",
        res
    );
    res
}

/// Adds predicate to sub proof request.
///
/// # Arguments
/// * `sub_proof_request_builder` - Reference that contains sub proof request builder instance pointer.
/// * `attr_name` - Related attribute
/// * `p_type` - Predicate type (Currently `GE` only).
/// * `value` - Requested value.
#[no_mangle]
pub extern "C" fn ursa_cl_sub_proof_request_builder_add_predicate(
    sub_proof_request_builder: *const c_void,
    attr_name: *const c_char,
    p_type: *const c_char,
    value: i32,
) -> ErrorCode {
    trace!("ursa_cl_sub_proof_request_builder_add_predicate: >>> sub_proof_request_builder: {:?}, attr_name: {:?}, p_type: {:?}, value: {:?}",
           sub_proof_request_builder, attr_name, p_type, value);

    check_useful_mut_c_reference!(
        sub_proof_request_builder,
        SubProofRequestBuilder,
        ErrorCode::CommonInvalidParam1
    );
    check_useful_c_str!(attr_name, ErrorCode::CommonInvalidParam2);
    check_useful_c_str!(p_type, ErrorCode::CommonInvalidParam3);

    trace!("ursa_cl_sub_proof_request_builder_add_predicate: entities: >>> sub_proof_request_builder: {:?}, attr_name: {:?}, p_type: {:?}, value: {:?}",
           sub_proof_request_builder, attr_name, p_type, value);

    let res = match sub_proof_request_builder.add_predicate(&attr_name, &p_type, value) {
        Ok(_) => ErrorCode::Success,
        Err(err) => err.into(),
    };

    trace!(
        "ursa_cl_sub_proof_request_builder_add_predicate: <<< res: {:?}",
        res
    );
    res
}

/// Deallocates sub proof request builder and returns sub proof request entity instead.
///
/// Note: Sub proof request instance deallocation must be performed by
/// calling ursa_cl_sub_proof_request_free.
///
/// # Arguments
/// * `sub_proof_request_builder` - Reference that contains sub proof request builder instance pointer.
/// * `sub_proof_request_p` - Reference that will contain sub proof request instance pointer.
#[no_mangle]
pub extern "C" fn ursa_cl_sub_proof_request_builder_finalize(
    sub_proof_request_builder: *const c_void,
    sub_proof_request_p: *mut *const c_void,
) -> ErrorCode {
    trace!("ursa_cl_sub_proof_request_builder_finalize: >>> sub_proof_request_builder: {:?}, sub_proof_request_p: {:?}",
           sub_proof_request_builder, sub_proof_request_p);

    check_useful_c_ptr!(sub_proof_request_builder, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(sub_proof_request_p, ErrorCode::CommonInvalidParam2);

    let sub_proof_request_builder =
        unsafe { Box::from_raw(sub_proof_request_builder as *mut SubProofRequestBuilder) };

    trace!(
        "ursa_cl_sub_proof_request_builder_finalize: entities: sub_proof_request_builder: {:?}",
        sub_proof_request_builder
    );

    let res = match sub_proof_request_builder.finalize() {
        Ok(sub_proof_request) => {
            trace!(
                "ursa_cl_sub_proof_request_builder_finalize: sub_proof_request: {:?}",
                sub_proof_request
            );
            unsafe {
                *sub_proof_request_p = Box::into_raw(Box::new(sub_proof_request)) as *const c_void;
                trace!(
                    "ursa_cl_sub_proof_request_builder_finalize: *sub_proof_request_p: {:?}",
                    *sub_proof_request_p
                );
            }
            ErrorCode::Success
        }
        Err(err) => err.into(),
    };

    trace!(
        "ursa_cl_sub_proof_request_builder_finalize: <<< res: {:?}",
        res
    );
    res
}

/// Deallocates sub proof request instance.
///
/// # Arguments
/// * `sub_proof_request` - Reference that contains sub proof request instance pointer.
#[no_mangle]
pub extern "C" fn ursa_cl_sub_proof_request_free(sub_proof_request: *const c_void) -> ErrorCode {
    trace!(
        "ursa_cl_sub_proof_request_free: >>> sub_proof_request: {:?}",
        sub_proof_request
    );

    check_useful_c_ptr!(sub_proof_request, ErrorCode::CommonInvalidParam1);

    let sub_proof_request = unsafe { Box::from_raw(sub_proof_request as *mut SubProofRequest) };
    trace!(
        "ursa_cl_sub_proof_request_free: entity: sub_proof_request: {:?}",
        sub_proof_request
    );

    let res = ErrorCode::Success;

    trace!("ursa_cl_sub_proof_request_free: <<< res: {:?}", res);
    res
}

/// Creates random nonce.
///
/// Note that nonce deallocation must be performed by calling ursa_cl_nonce_free.
///
/// # Arguments
/// * `nonce_p` - Reference that will contain nonce instance pointer.
#[no_mangle]
pub extern "C" fn ursa_cl_new_nonce(nonce_p: *mut *const c_void) -> ErrorCode {
    trace!("ursa_cl_new_nonce: >>> {:?}", nonce_p);

    check_useful_c_ptr!(nonce_p, ErrorCode::CommonInvalidParam1);

    let res = match new_nonce() {
        Ok(nonce) => {
            trace!("ursa_cl_new_nonce: nonce: {:?}", nonce);
            unsafe {
                *nonce_p = Box::into_raw(Box::new(nonce)) as *const c_void;
                trace!("ursa_cl_new_nonce: *nonce_p: {:?}", *nonce_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.into(),
    };

    trace!("ursa_cl_new_nonce: <<< res: {:?}", res);
    res
}

/// Returns json representation of nonce.
///
/// # Arguments
/// * `nonce` - Reference that contains nonce instance pointer.
/// * `nonce_json_p` - Reference that will contain nonce json.
#[no_mangle]
pub extern "C" fn ursa_cl_nonce_to_json(
    nonce: *const c_void,
    nonce_json_p: *mut *const c_char,
) -> ErrorCode {
    trace!(
        "ursa_cl_nonce_to_json: >>> nonce: {:?}, nonce_json_p: {:?}",
        nonce,
        nonce_json_p
    );

    check_useful_c_reference!(nonce, Nonce, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(nonce_json_p, ErrorCode::CommonInvalidParam2);

    trace!("ursa_cl_nonce_to_json: entity >>> nonce: {:?}", nonce);

    let res = match serde_json::to_string(nonce) {
        Ok(nonce_json) => {
            trace!("ursa_cl_nonce_to_json: nonce_json: {:?}", nonce_json);
            unsafe {
                let nonce_json = string_to_cstring(nonce_json);
                *nonce_json_p = nonce_json.into_raw();
                trace!("ursa_cl_nonce_to_json: nonce_json_p: {:?}", *nonce_json_p);
            }
            ErrorCode::Success
        }
        Err(err) => err
            .to_ursa(
                UrsaCryptoErrorKind::InvalidState,
                "Unable to serialize nonce as json",
            )
            .into(),
    };

    trace!("ursa_cl_nonce_to_json: <<< res: {:?}", res);
    res
}

/// Creates and returns nonce json.
///
/// Note: Nonce instance deallocation must be performed by calling ursa_cl_nonce_free.
///
/// # Arguments
/// * `nonce_json` - Reference that contains nonce json.
/// * `nonce_p` - Reference that will contain nonce instance pointer.
#[no_mangle]
pub extern "C" fn ursa_cl_nonce_from_json(
    nonce_json: *const c_char,
    nonce_p: *mut *const c_void,
) -> ErrorCode {
    trace!(
        "ursa_cl_nonce_from_json: >>> nonce_json: {:?}, nonce_p: {:?}",
        nonce_json,
        nonce_p
    );

    check_useful_c_str!(nonce_json, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(nonce_p, ErrorCode::CommonInvalidParam2);

    trace!(
        "ursa_cl_nonce_from_json: entity: nonce_json: {:?}",
        nonce_json
    );

    let res = match serde_json::from_str::<Nonce>(&nonce_json) {
        Ok(nonce) => {
            trace!("ursa_cl_nonce_from_json: nonce: {:?}", nonce);
            unsafe {
                *nonce_p = Box::into_raw(Box::new(nonce)) as *const c_void;
                trace!("ursa_cl_nonce_from_json: *nonce_p: {:?}", *nonce_p);
            }
            ErrorCode::Success
        }
        Err(err) => err
            .to_ursa(
                UrsaCryptoErrorKind::InvalidStructure,
                "Unable to deserialize nonce from json",
            )
            .into(),
    };

    trace!("ursa_cl_nonce_from_json: <<< res: {:?}", res);
    res
}

/// Deallocates nonce instance.
///
/// # Arguments
/// * `nonce` - Reference that contains nonce instance pointer.
#[no_mangle]
pub extern "C" fn ursa_cl_nonce_free(nonce: *const c_void) -> ErrorCode {
    trace!("ursa_cl_nonce_free: >>> nonce: {:?}", nonce);

    check_useful_c_ptr!(nonce, ErrorCode::CommonInvalidParam1);

    let nonce = unsafe { Box::from_raw(nonce as *mut Nonce) };
    trace!("ursa_cl_nonce_free: entity: nonce: {:?}", nonce);

    let res = ErrorCode::Success;

    trace!("ursa_cl_nonce_free: <<< res: {:?}", res);
    res
}

struct FFITailsAccessor {
    ctx: *const c_void,
    take: FFITailTake,
    put: FFITailPut,
}

impl FFITailsAccessor {
    pub fn new(ctx: *const c_void, take: FFITailTake, put: FFITailPut) -> Self {
        FFITailsAccessor { ctx, take, put }
    }
}

impl RevocationTailsAccessor for FFITailsAccessor {
    fn access_tail(&self, tail_id: u32, accessor: &mut dyn FnMut(&Tail)) -> UrsaCryptoResult<()> {
        let mut tail_p = ptr::null();

        let res = (self.take)(self.ctx, tail_id, &mut tail_p);
        if res != ErrorCode::Success || tail_p.is_null() {
            return Err(err_msg(UrsaCryptoErrorKind::InvalidState,
                               format!("FFI call take_tail {:?} (ctx {:?}, id {}) failed: tail_p {:?}, returned error code {:?}",
                                       self.take, self.ctx, tail_id, tail_p, res)));
        }
        let tail: *const Tail = tail_p as *const Tail;

        accessor(&unsafe { *tail });

        let res = (self.put)(self.ctx, tail_p);
        if res != ErrorCode::Success {
            return Err(err_msg(UrsaCryptoErrorKind::InvalidState,
                               format!("FFI call put_tail {:?} (ctx {:?}, tail_p {:?}) failed: returned error code {:?}",
                                       self.take, self.ctx, tail_p, res)));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ffi::cl::mocks::*;
    use std::ffi::CString;
    use std::ptr;

    #[test]
    fn ursa_cl_credential_schema_builder_new_works() {
        let mut credential_schema_builder: *const c_void = ptr::null();
        let err_code = ursa_cl_credential_schema_builder_new(&mut credential_schema_builder);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!credential_schema_builder.is_null());

        _free_credential_schema_builder(credential_schema_builder);
    }

    #[test]
    fn ursa_cl_non_credential_schema_builder_new_works() {
        let mut non_credential_schema_builder: *const c_void = ptr::null();
        let err_code =
            ursa_cl_non_credential_schema_builder_new(&mut non_credential_schema_builder);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!non_credential_schema_builder.is_null());

        _free_non_credential_schema_builder(non_credential_schema_builder);
    }

    #[test]
    fn ursa_cl_credential_schema_builder_add_attr_works() {
        let credential_schema_builder = _credential_schema_builder();

        let attr = CString::new("sex").unwrap();
        let err_code =
            ursa_cl_credential_schema_builder_add_attr(credential_schema_builder, attr.as_ptr());
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!credential_schema_builder.is_null());

        let attr = CString::new("name").unwrap();
        let err_code =
            ursa_cl_credential_schema_builder_add_attr(credential_schema_builder, attr.as_ptr());
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!credential_schema_builder.is_null());

        let attr = CString::new("age").unwrap();
        let err_code =
            ursa_cl_credential_schema_builder_add_attr(credential_schema_builder, attr.as_ptr());
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!credential_schema_builder.is_null());

        _free_credential_schema_builder(credential_schema_builder);
    }

    #[test]
    fn ursa_cl_non_credential_schema_builder_add_attr_works() {
        let non_credential_schema_builder = _non_credential_schema_builder();

        let attr = CString::new("sex").unwrap();
        let err_code = ursa_cl_non_credential_schema_builder_add_attr(
            non_credential_schema_builder,
            attr.as_ptr(),
        );
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!non_credential_schema_builder.is_null());

        let attr = CString::new("name").unwrap();
        let err_code = ursa_cl_non_credential_schema_builder_add_attr(
            non_credential_schema_builder,
            attr.as_ptr(),
        );
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!non_credential_schema_builder.is_null());

        let attr = CString::new("age").unwrap();
        let err_code = ursa_cl_non_credential_schema_builder_add_attr(
            non_credential_schema_builder,
            attr.as_ptr(),
        );
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!non_credential_schema_builder.is_null());

        _free_non_credential_schema_builder(non_credential_schema_builder);
    }

    #[test]
    fn ursa_cl_credential_schema_builder_finalize_works() {
        let credential_schema_builder = _credential_schema_builder();

        let attr = CString::new("sex").unwrap();
        let err_code =
            ursa_cl_credential_schema_builder_add_attr(credential_schema_builder, attr.as_ptr());
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!credential_schema_builder.is_null());

        let mut credential_schema: *const c_void = ptr::null();
        ursa_cl_credential_schema_builder_finalize(
            credential_schema_builder,
            &mut credential_schema,
        );
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!credential_schema.is_null());

        _free_credential_schema(credential_schema);
    }

    #[test]
    fn ursa_cl_non_credential_schema_builder_finalize_works() {
        let non_credential_schema_builder = _non_credential_schema_builder();

        let attr = CString::new("master_secret").unwrap();
        let err_code = ursa_cl_non_credential_schema_builder_add_attr(
            non_credential_schema_builder,
            attr.as_ptr(),
        );
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!non_credential_schema_builder.is_null());

        let mut non_credential_schema: *const c_void = ptr::null();
        ursa_cl_non_credential_schema_builder_finalize(
            non_credential_schema_builder,
            &mut non_credential_schema,
        );
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!non_credential_schema.is_null());

        _free_non_credential_schema(non_credential_schema);
    }

    #[test]
    fn ursa_cl_credential_schema_free_works() {
        let credential_schema = _credential_schema();

        let err_code = ursa_cl_credential_schema_free(credential_schema);
        assert_eq!(err_code, ErrorCode::Success);
    }

    #[test]
    fn ursa_cl_non_credential_schema_free_works() {
        let non_credential_schema = _non_credential_schema();

        let err_code = ursa_cl_non_credential_schema_free(non_credential_schema);
        assert_eq!(err_code, ErrorCode::Success);
    }

    #[test]
    fn ursa_cl_credential_values_builder_new_works() {
        let mut credential_values_builder: *const c_void = ptr::null();
        let err_code = ursa_cl_credential_values_builder_new(&mut credential_values_builder);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!credential_values_builder.is_null());

        _free_credential_values_builder(credential_values_builder);
    }

    #[test]
    fn ursa_cl_credential_values_builder_add_dec_known_works() {
        let credential_values_builder = _credential_values_builder();

        let attr = CString::new("sex").unwrap();
        let dec_value = CString::new("89057765651800459030103911598694169835931320404459570102253965466045532669865684092518362135930940112502263498496335250135601124519172068317163741086983519494043168252186111551835366571584950296764626458785776311514968350600732183408950813066589742888246925358509482561838243805468775416479523402043160919428168650069477488093758569936116799246881809224343325540306266957664475026390533069487455816053169001876208052109360113102565642529699056163373190930839656498261278601357214695582219007449398650197048218304260447909283768896882743373383452996855450316360259637079070460616248922547314789644935074980711243164129").unwrap();
        let err_code = ursa_cl_credential_values_builder_add_dec_known(
            credential_values_builder,
            attr.as_ptr(),
            dec_value.as_ptr(),
        );
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!credential_values_builder.is_null());

        let attr = CString::new("name").unwrap();
        let dec_value = CString::new("58606710922154038918005745652863947546479611221487923871520854046018234465128105585608812090213473225037875788462225679336791123783441657062831589984290779844020407065450830035885267846722229953206567087435754612694085258455822926492275621650532276267042885213400704012011608869094703483233081911010530256094461587809601298503874283124334225428746479707531278882536314925285434699376158578239556590141035593717362562548075653598376080466948478266094753818404986494459240364648986755479857098110402626477624280802323635285059064580583239726433768663879431610261724430965980430886959304486699145098822052003020688956471").unwrap();
        let err_code = ursa_cl_credential_values_builder_add_dec_known(
            credential_values_builder,
            attr.as_ptr(),
            dec_value.as_ptr(),
        );
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!credential_values_builder.is_null());

        _free_credential_values_builder(credential_values_builder);
    }

    #[test]
    fn ursa_cl_credential_values_builder_add_dec_hidden_works() {
        let credential_values_builder = _credential_values_builder();

        let attr = CString::new("master_secret").unwrap();
        let dec_value = CString::new("89057765651800459030103911598694169835931320404459570102253965466045532669865684092518362135930940112502263498496335250135601124519172068317163741086983519494043168252186111551835366571584950296764626458785776311514968350600732183408950813066589742888246925358509482561838243805468775416479523402043160919428168650069477488093758569936116799246881809224343325540306266957664475026390533069487455816053169001876208052109360113102565642529699056163373190930839656498261278601357214695582219007449398650197048218304260447909283768896882743373383452996855450316360259637079070460616248922547314789644935074980711243164129").unwrap();
        let err_code = ursa_cl_credential_values_builder_add_dec_hidden(
            credential_values_builder,
            attr.as_ptr(),
            dec_value.as_ptr(),
        );
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!credential_values_builder.is_null());

        let attr = CString::new("policy_address").unwrap();
        let dec_value = CString::new("58606710922154038918005745652863947546479611221487923871520854046018234465128105585608812090213473225037875788462225679336791123783441657062831589984290779844020407065450830035885267846722229953206567087435754612694085258455822926492275621650532276267042885213400704012011608869094703483233081911010530256094461587809601298503874283124334225428746479707531278882536314925285434699376158578239556590141035593717362562548075653598376080466948478266094753818404986494459240364648986755479857098110402626477624280802323635285059064580583239726433768663879431610261724430965980430886959304486699145098822052003020688956471").unwrap();
        let err_code = ursa_cl_credential_values_builder_add_dec_hidden(
            credential_values_builder,
            attr.as_ptr(),
            dec_value.as_ptr(),
        );
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!credential_values_builder.is_null());

        _free_credential_values_builder(credential_values_builder);
    }

    #[test]
    fn ursa_cl_credential_values_builder_add_dec_commitment_works() {
        let credential_values_builder = _credential_values_builder();

        let attr = CString::new("ssn").unwrap();
        let dec_value = CString::new("89057765651800459030103911598694169835931320404459570102253965466045532669865684092518362135930940112502263498496335250135601124519172068317163741086983519494043168252186111551835366571584950296764626458785776311514968350600732183408950813066589742888246925358509482561838243805468775416479523402043160919428168650069477488093758569936116799246881809224343325540306266957664475026390533069487455816053169001876208052109360113102565642529699056163373190930839656498261278601357214695582219007449398650197048218304260447909283768896882743373383452996855450316360259637079070460616248922547314789644935074980711243164129").unwrap();
        let dec_blinding_factor = CString::new("33057765651800459030103911598694169835931320404459570102253965466045532669865684092518362135930940112502263498496335250135601124519172068317163741086983519494043168252186111551835366571584950296764626458785776311514968350600732183408950813066589742888246925358509482561838243805468775416479523402043160919428168650069477488093758569936116799246881809224343325540306266957664475026390533069487455816053169001876208052109360113102565642529699056163373190930839656498261278601357214695582219007449398650197048218304260447909283768896882743373383452996855450316360259637079070460616248922547314789644935074980711243163018").unwrap();

        let err_code = ursa_cl_credential_values_builder_add_dec_commitment(
            credential_values_builder,
            attr.as_ptr(),
            dec_value.as_ptr(),
            dec_blinding_factor.as_ptr(),
        );
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!credential_values_builder.is_null());

        _free_credential_values_builder(credential_values_builder);
    }

    #[test]
    fn ursa_cl_credential_values_free_works() {
        let credential_values = _credential_values();

        let err_code = ursa_cl_credential_values_free(credential_values);
        assert_eq!(err_code, ErrorCode::Success);
    }

    #[test]
    fn ursa_cl_sub_proof_request_builder_new_works() {
        let mut sub_proof_request_builder: *const c_void = ptr::null();
        let err_code = ursa_cl_sub_proof_request_builder_new(&mut sub_proof_request_builder);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!sub_proof_request_builder.is_null());

        _free_sub_proof_request_builder(sub_proof_request_builder);
    }

    #[test]
    fn ursa_cl_sub_proof_request_builder_add_revealed_attr_works() {
        let sub_proof_request_builder = _sub_proof_request_builder();

        let attr = CString::new("sex").unwrap();
        let err_code = ursa_cl_sub_proof_request_builder_add_revealed_attr(
            sub_proof_request_builder,
            attr.as_ptr(),
        );
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!sub_proof_request_builder.is_null());

        let attr = CString::new("name").unwrap();
        let err_code = ursa_cl_sub_proof_request_builder_add_revealed_attr(
            sub_proof_request_builder,
            attr.as_ptr(),
        );
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!sub_proof_request_builder.is_null());

        _free_sub_proof_request_builder(sub_proof_request_builder);
    }

    #[test]
    fn ursa_cl_sub_proof_request_builder_add_predicate_works() {
        let sub_proof_request_builder = _sub_proof_request_builder();

        let attr_name = CString::new("age").unwrap();
        let p_type = CString::new("GE").unwrap();
        let value = 18;

        let err_code = ursa_cl_sub_proof_request_builder_add_predicate(
            sub_proof_request_builder,
            attr_name.as_ptr(),
            p_type.as_ptr(),
            value,
        );
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!sub_proof_request_builder.is_null());

        _free_sub_proof_request_builder(sub_proof_request_builder);
    }

    #[test]
    fn ursa_cl_sub_proof_request_builder_finalize_works() {
        let sub_proof_request_builder = _sub_proof_request_builder();

        let attr = CString::new("sex").unwrap();
        let err_code = ursa_cl_sub_proof_request_builder_add_revealed_attr(
            sub_proof_request_builder,
            attr.as_ptr(),
        );
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!sub_proof_request_builder.is_null());

        let mut sub_proof_request: *const c_void = ptr::null();
        ursa_cl_sub_proof_request_builder_finalize(
            sub_proof_request_builder,
            &mut sub_proof_request,
        );
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!sub_proof_request.is_null());

        _free_sub_proof_request(sub_proof_request);
    }

    #[test]
    fn ursa_cl_sub_proof_request_free_works() {
        let sub_proof_request = _sub_proof_request();

        let err_code = ursa_cl_sub_proof_request_free(sub_proof_request);
        assert_eq!(err_code, ErrorCode::Success);
    }

    #[test]
    fn ursa_cl_new_nonce_works() {
        let mut nonce_p: *const c_void = ptr::null();
        let err_code = ursa_cl_new_nonce(&mut nonce_p);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!nonce_p.is_null());

        _free_nonce(nonce_p)
    }

    #[test]
    fn ursa_cl_nonce_to_json_works() {
        let nonce = _nonce();

        let mut nonce_json_p: *const c_char = ptr::null();
        let err_code = ursa_cl_nonce_to_json(nonce, &mut nonce_json_p);
        assert_eq!(err_code, ErrorCode::Success);

        _free_nonce(nonce)
    }

    #[test]
    fn ursa_cl_nonce_from_json_works() {
        let nonce = _nonce();

        let mut nonce_json_p: *const c_char = ptr::null();
        let err_code = ursa_cl_nonce_to_json(nonce, &mut nonce_json_p);
        assert_eq!(err_code, ErrorCode::Success);

        let mut nonce_p: *const c_void = ptr::null();
        let err_code = ursa_cl_nonce_from_json(nonce_json_p, &mut nonce_p);
        assert_eq!(err_code, ErrorCode::Success);

        _free_nonce(nonce)
    }

    #[test]
    fn ursa_cl_nonce_free_works() {
        let nonce = _nonce();

        let err_code = ursa_cl_nonce_free(nonce);
        assert_eq!(err_code, ErrorCode::Success);
    }
}

#[cfg(test)]
pub mod mocks {
    use super::*;

    use std::ffi::CString;
    use std::ptr;

    pub fn _credential_schema_builder() -> *const c_void {
        let mut credential_schema_builder: *const c_void = ptr::null();
        let err_code = ursa_cl_credential_schema_builder_new(&mut credential_schema_builder);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!credential_schema_builder.is_null());

        credential_schema_builder
    }

    pub fn _non_credential_schema_builder() -> *const c_void {
        let mut non_credential_schema_builder: *const c_void = ptr::null();
        let err_code =
            ursa_cl_non_credential_schema_builder_new(&mut non_credential_schema_builder);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!non_credential_schema_builder.is_null());

        non_credential_schema_builder
    }

    pub fn _free_credential_schema_builder(credential_schema_builder: *const c_void) {
        let mut credential_schema: *const c_void = ptr::null();
        let err_code = ursa_cl_credential_schema_builder_finalize(
            credential_schema_builder,
            &mut credential_schema,
        );
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!credential_schema.is_null());

        _free_credential_schema(credential_schema);
    }

    pub fn _free_non_credential_schema_builder(non_credential_schema_builder: *const c_void) {
        let mut non_credential_schema: *const c_void = ptr::null();
        let err_code = ursa_cl_credential_schema_builder_finalize(
            non_credential_schema_builder,
            &mut non_credential_schema,
        );
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!non_credential_schema.is_null());

        _free_non_credential_schema(non_credential_schema);
    }

    pub fn _credential_schema() -> *const c_void {
        let credential_schema_builder = _credential_schema_builder();

        let attr = CString::new("name").unwrap();
        let err_code =
            ursa_cl_credential_schema_builder_add_attr(credential_schema_builder, attr.as_ptr());
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!credential_schema_builder.is_null());

        let attr = CString::new("sex").unwrap();
        let err_code =
            ursa_cl_credential_schema_builder_add_attr(credential_schema_builder, attr.as_ptr());
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!credential_schema_builder.is_null());

        let attr = CString::new("age").unwrap();
        let err_code =
            ursa_cl_credential_schema_builder_add_attr(credential_schema_builder, attr.as_ptr());
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!credential_schema_builder.is_null());

        let attr = CString::new("height").unwrap();
        let err_code =
            ursa_cl_credential_schema_builder_add_attr(credential_schema_builder, attr.as_ptr());
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!credential_schema_builder.is_null());

        let mut credential_schema_p: *const c_void = ptr::null();
        ursa_cl_credential_schema_builder_finalize(
            credential_schema_builder,
            &mut credential_schema_p,
        );
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!credential_schema_p.is_null());

        credential_schema_p
    }

    pub fn _non_credential_schema() -> *const c_void {
        let non_credential_schema_builder = _non_credential_schema_builder();

        let attr = CString::new("master_secret").unwrap();
        let err_code = ursa_cl_non_credential_schema_builder_add_attr(
            non_credential_schema_builder,
            attr.as_ptr(),
        );
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!non_credential_schema_builder.is_null());

        let mut non_credential_schema_p: *const c_void = ptr::null();
        ursa_cl_non_credential_schema_builder_finalize(
            non_credential_schema_builder,
            &mut non_credential_schema_p,
        );
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!non_credential_schema_p.is_null());

        non_credential_schema_p
    }

    pub fn _free_credential_schema(credential_schema: *const c_void) {
        let err_code = ursa_cl_credential_schema_free(credential_schema);
        assert_eq!(err_code, ErrorCode::Success);
    }

    pub fn _free_non_credential_schema(non_credential_schema: *const c_void) {
        let err_code = ursa_cl_non_credential_schema_free(non_credential_schema);
        assert_eq!(err_code, ErrorCode::Success);
    }

    pub fn _credential_values_builder() -> *const c_void {
        let mut credential_values_builder: *const c_void = ptr::null();
        let err_code = ursa_cl_credential_values_builder_new(&mut credential_values_builder);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!credential_values_builder.is_null());

        credential_values_builder
    }

    pub fn _free_credential_values_builder(credential_values_builder: *const c_void) {
        let mut credential_values: *const c_void = ptr::null();
        let err_code = ursa_cl_credential_values_builder_finalize(
            credential_values_builder,
            &mut credential_values,
        );
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!credential_values.is_null());

        _free_credential_values(credential_values);
    }

    pub fn _credential_values() -> *const c_void {
        let credential_values_builder = _credential_values_builder();

        let attr = CString::new("master_secret").unwrap();
        let dec_value = CString::new("89057765651800459030103911598694169835931320404459570102253965466045532669865684092518362135930940112502263498496335250135601124519172068317163741086983519494043168252186111551835366571584950296764626458785776311514968350600732183408950813066589742888246925358509482561838243805468775416479523402043160919428168650069477488093758569936116799246881809224343325540306266957664475026390533069487455816053169001876208052109360113102565642529699056163373190930839656498261278601357214695582219007449398650197048218304260447909283768896882743373383452996855450316360259637079070460616248922547314789644935074980711243164129").unwrap();
        let err_code = ursa_cl_credential_values_builder_add_dec_hidden(
            credential_values_builder,
            attr.as_ptr(),
            dec_value.as_ptr(),
        );
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!credential_values_builder.is_null());

        let attr = CString::new("name").unwrap();
        let dec_value = CString::new("1139481716457488690172217916278103335").unwrap();
        let err_code = ursa_cl_credential_values_builder_add_dec_known(
            credential_values_builder,
            attr.as_ptr(),
            dec_value.as_ptr(),
        );
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!credential_values_builder.is_null());

        let attr = CString::new("sex").unwrap();
        let dec_value = CString::new(
            "5944657099558967239210949258394887428692050081607692519917050011144233115103",
        )
        .unwrap();
        let err_code = ursa_cl_credential_values_builder_add_dec_known(
            credential_values_builder,
            attr.as_ptr(),
            dec_value.as_ptr(),
        );
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!credential_values_builder.is_null());

        let attr = CString::new("age").unwrap();
        let dec_value = CString::new("28").unwrap();
        let err_code = ursa_cl_credential_values_builder_add_dec_known(
            credential_values_builder,
            attr.as_ptr(),
            dec_value.as_ptr(),
        );
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!credential_values_builder.is_null());

        let attr = CString::new("height").unwrap();
        let dec_value = CString::new("175").unwrap();
        let err_code = ursa_cl_credential_values_builder_add_dec_known(
            credential_values_builder,
            attr.as_ptr(),
            dec_value.as_ptr(),
        );
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!credential_values_builder.is_null());

        let mut credential_values: *const c_void = ptr::null();
        ursa_cl_credential_values_builder_finalize(
            credential_values_builder,
            &mut credential_values,
        );
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!credential_values.is_null());

        credential_values
    }

    pub fn _free_credential_values(credential_values: *const c_void) {
        let err_code = ursa_cl_credential_values_free(credential_values);
        assert_eq!(err_code, ErrorCode::Success);
    }

    pub fn _sub_proof_request_builder() -> *const c_void {
        let mut sub_proof_request_builder: *const c_void = ptr::null();
        let err_code = ursa_cl_sub_proof_request_builder_new(&mut sub_proof_request_builder);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!sub_proof_request_builder.is_null());

        sub_proof_request_builder
    }

    pub fn _free_sub_proof_request_builder(sub_proof_request_builder: *const c_void) {
        let mut sub_proof_request: *const c_void = ptr::null();
        let err_code = ursa_cl_sub_proof_request_builder_finalize(
            sub_proof_request_builder,
            &mut sub_proof_request,
        );
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!sub_proof_request.is_null());

        _free_sub_proof_request(sub_proof_request);
    }

    pub fn _sub_proof_request() -> *const c_void {
        let sub_proof_request_builder = _sub_proof_request_builder();

        let revealed_attr = CString::new("name").unwrap();
        let err_code = ursa_cl_sub_proof_request_builder_add_revealed_attr(
            sub_proof_request_builder,
            revealed_attr.as_ptr(),
        );
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!sub_proof_request_builder.is_null());

        let attr_name = CString::new("age").unwrap();
        let p_type = CString::new("GE").unwrap();
        let value = 18;

        let err_code = ursa_cl_sub_proof_request_builder_add_predicate(
            sub_proof_request_builder,
            attr_name.as_ptr(),
            p_type.as_ptr(),
            value,
        );
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!sub_proof_request_builder.is_null());

        let mut sub_proof_request: *const c_void = ptr::null();
        ursa_cl_sub_proof_request_builder_finalize(
            sub_proof_request_builder,
            &mut sub_proof_request,
        );
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!sub_proof_request.is_null());

        sub_proof_request
    }

    pub fn _free_sub_proof_request(sub_proof_request: *const c_void) {
        let err_code = ursa_cl_sub_proof_request_free(sub_proof_request);
        assert_eq!(err_code, ErrorCode::Success);
    }

    pub fn _nonce() -> *const c_void {
        let mut nonce_p: *const c_void = ptr::null();
        let err_code = ursa_cl_new_nonce(&mut nonce_p);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!nonce_p.is_null());

        nonce_p
    }

    pub fn _free_nonce(nonce: *const c_void) {
        let err_code = ursa_cl_nonce_free(nonce);
        assert_eq!(err_code, ErrorCode::Success);
    }

    pub fn _witness(rev_reg_delta: *const c_void, get_storage_ctx: *const c_void) -> *const c_void {
        let rev_idx = 1;
        let max_cred_num = 5;

        let mut witness_p: *const c_void = ptr::null();
        let err_code = ursa_cl_witness_new(
            rev_idx,
            max_cred_num,
            false,
            rev_reg_delta,
            get_storage_ctx,
            FFISimpleTailStorage::tail_take,
            FFISimpleTailStorage::tail_put,
            &mut witness_p,
        );
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!witness_p.is_null());

        witness_p
    }

    pub fn _free_witness(witness: *const c_void) {
        let err_code = ursa_cl_witness_free(witness);
        assert_eq!(err_code, ErrorCode::Success);
    }

    pub struct FFISimpleTailStorage {
        tails: Box<Vec<*const c_void>>,
    }

    impl FFISimpleTailStorage {
        pub fn new(rev_tails_generator: *const c_void) -> Self {
            let mut tails = Vec::new();
            let mut cnt = 0u32;
            let res = ursa_cl_tails_generator_count(rev_tails_generator, &mut cnt);
            assert_eq!(res, ErrorCode::Success);
            for _ in 0..cnt {
                let mut tail = ptr::null();
                let res = ursa_cl_tails_generator_next(rev_tails_generator, &mut tail);
                assert_eq!(res, ErrorCode::Success);
                tails.push(tail);
            }
            Self {
                tails: Box::new(tails),
            }
        }

        pub fn get_ctx(&self) -> *const c_void {
            let ctx: *const Vec<*const c_void> = &*self.tails;
            ctx as *const c_void
        }

        pub extern "C" fn tail_put(_ctx: *const c_void, _tail: *const c_void) -> ErrorCode {
            ErrorCode::Success
        }

        pub extern "C" fn tail_take(
            ctx: *const c_void,
            idx: u32,
            tail_p: *mut *const c_void,
        ) -> ErrorCode {
            let tails: &Vec<*const c_void> = unsafe { &*(ctx as *const Vec<*const c_void>) };

            let tail: *const c_void = *tails.get(idx as usize).unwrap();

            unsafe { *tail_p = tail };

            ErrorCode::Success
        }
    }
}
