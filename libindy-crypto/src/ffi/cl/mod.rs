use cl::*;
use cl::issuer::Issuer;
use cl::verifier::Verifier;
use errors::ToErrorCode;
use ffi::ErrorCode;
use utils::ctypes::CTypesUtils;
use utils::json::{JsonEncodable, JsonDecodable};

use libc::c_char;

use std::os::raw::c_void;

pub mod issuer;
pub mod prover;
pub mod verifier;

/// Creates and returns claim schema entity builder.
///
/// The purpose of claim schema builder is building of claim schema entity that
/// represents claim schema attributes set.
///
/// Note: Claim schema builder instance deallocation must be performed by
/// calling indy_crypto_cl_claim_schema_builder_finalize.
///
/// # Arguments
/// * `claim_schema_builder_p` - Reference that will contain claims attributes builder instance pointer.
#[no_mangle]
pub extern fn indy_crypto_cl_claim_schema_builder_new(claim_schema_builder_p: *mut *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_claim_schema_builder_new: >>> claim_schema_builder_p: {:?}", claim_schema_builder_p);

    check_useful_c_ptr!(claim_schema_builder_p, ErrorCode::CommonInvalidParam1);

    let res = match Issuer::new_claim_schema_builder() {
        Ok(claim_schema_builder) => {
            trace!("indy_crypto_cl_claim_schema_builder_new: claim_schema_builder: {:?}", claim_schema_builder);
            unsafe {
                *claim_schema_builder_p = Box::into_raw(Box::new(claim_schema_builder)) as *const c_void;
                trace!("indy_crypto_cl_claim_schema_builder_new: *claim_schema_builder_p: {:?}", *claim_schema_builder_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_cl_claim_schema_builder_new: <<< res: {:?}", res);
    res
}

/// Adds new attribute to claim schema.
///
/// # Arguments
/// * `claim_schema_builder` - Reference that contains claim schema builder instance pointer.
/// * `attr` - Attribute to add as null terminated string.
#[no_mangle]
pub extern fn indy_crypto_cl_claim_schema_builder_add_attr(claim_schema_builder: *const c_void,
                                                           attr: *const c_char) -> ErrorCode {
    trace!("indy_crypto_cl_claim_schema_builder_add_attr: >>> claim_schema_builder: {:?}, attr: {:?}", claim_schema_builder, attr);

    check_useful_mut_c_reference!(claim_schema_builder, ClaimSchemaBuilder, ErrorCode::CommonInvalidParam1);
    check_useful_c_str!(attr, ErrorCode::CommonInvalidParam2);

    trace!("indy_crypto_cl_claim_schema_builder_add_attr: entities: claim_schema_builder: {:?}, attr: {:?}", claim_schema_builder, attr);

    let res = match claim_schema_builder.add_attr(&attr) {
        Ok(_) => ErrorCode::Success,
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_cl_claim_schema_builder_add_attr: <<< res: {:?}", res);
    res
}

/// Deallocates claim schema builder and returns claim schema entity instead.
///
/// Note: Claims schema instance deallocation must be performed by
/// calling indy_crypto_cl_claim_schema_free.
///
/// # Arguments
/// * `claim_schema_builder` - Reference that contains claim schema builder instance pointer
/// * `claim_schema_p` - Reference that will contain claims schema instance pointer.
#[no_mangle]
pub extern fn indy_crypto_cl_claim_schema_builder_finalize(claim_schema_builder: *const c_void,
                                                           claim_schema_p: *mut *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_claim_schema_builder_finalize: >>> claim_schema_builder: {:?}, claim_schema_p: {:?}", claim_schema_builder, claim_schema_p);

    check_useful_c_ptr!(claim_schema_builder, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(claim_schema_p, ErrorCode::CommonInvalidParam2);

    let claim_schema_builder = unsafe { Box::from_raw(claim_schema_builder as *mut ClaimSchemaBuilder) };

    trace!("indy_crypto_cl_claim_schema_builder_finalize: entities: claim_schema_builder: {:?}", claim_schema_builder);

    let res = match claim_schema_builder.finalize() {
        Ok(claim_schema) => {
            trace!("indy_crypto_cl_claim_schema_builder_finalize: claim_schema: {:?}", claim_schema);
            unsafe {
                *claim_schema_p = Box::into_raw(Box::new(claim_schema)) as *const c_void;
                trace!("indy_crypto_cl_claim_schema_builder_finalize: *claim_schema_p: {:?}", *claim_schema_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_cl_claim_schema_builder_finalize: <<< res: {:?}", res);
    res
}

/// Deallocates claim schema instance.
///
/// # Arguments
/// * `claim_schema` - Reference that contains claim schema instance pointer.
#[no_mangle]
pub extern fn indy_crypto_cl_claim_schema_free(claim_schema: *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_claim_schema_free: >>> claim_schema: {:?}", claim_schema);

    check_useful_c_ptr!(claim_schema, ErrorCode::CommonInvalidParam1);

    let claim_schema = unsafe { Box::from_raw(claim_schema as *mut ClaimSchema); };
    trace!("indy_crypto_cl_claim_schema_free: entity: claim_schema: {:?}", claim_schema);

    let res = ErrorCode::Success;

    trace!("indy_crypto_cl_claim_schema_free: <<< res: {:?}", res);
    res
}

/// Creates and returns claims values entity builder.
///
/// The purpose of claim values builder is building of claim values entity that
/// represents claim attributes values map.
///
/// Note: Claims values builder instance deallocation must be performed by
/// calling indy_crypto_cl_claim_values_builder_finalize.
///
/// # Arguments
/// * `claim_values_builder_p` - Reference that will contain claims values builder instance pointer.
#[no_mangle]
pub extern fn indy_crypto_cl_claim_values_builder_new(claim_values_builder_p: *mut *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_claim_values_builder_new: >>> claim_values_builder_p: {:?}", claim_values_builder_p);

    check_useful_c_ptr!(claim_values_builder_p, ErrorCode::CommonInvalidParam1);

    let res = match Issuer::new_claim_values_builder() {
        Ok(claim_values_builder) => {
            trace!("indy_crypto_cl_claim_values_builder_new: claim_values_builder: {:?}", claim_values_builder);
            unsafe {
                *claim_values_builder_p = Box::into_raw(Box::new(claim_values_builder)) as *const c_void;
                trace!("indy_crypto_cl_claim_values_builder_new: *claim_values_builder_p: {:?}", *claim_values_builder_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_cl_claim_values_builder_new: <<< res: {:?}", res);
    res
}

/// Adds new attribute dec_value to claim values map.
///
/// # Arguments
/// * `claim_values_builder` - Reference that contains claim values builder instance pointer.
/// * `attr` - Claim attr to add as null terminated string.
/// * `dec_value` - Claim attr dec_value. Decimal BigNum representation as null terminated string.
#[no_mangle]
pub extern fn indy_crypto_cl_claim_values_builder_add_value(claim_values_builder: *const c_void,
                                                            attr: *const c_char,
                                                            dec_value: *const c_char) -> ErrorCode {
    trace!("indy_crypto_cl_claim_values_builder_add_value: >>> claim_values_builder: {:?}, attr: {:?}, dec_value: {:?}",
           claim_values_builder, attr, dec_value);

    check_useful_mut_c_reference!(claim_values_builder, ClaimValuesBuilder, ErrorCode::CommonInvalidParam1);
    check_useful_c_str!(attr, ErrorCode::CommonInvalidParam2);
    check_useful_c_str!(dec_value, ErrorCode::CommonInvalidParam3);

    trace!("indy_crypto_cl_claim_values_builder_add_value: entities: claim_values_builder: {:?}, attr: {:?}, dec_value: {:?}", claim_values_builder, attr, dec_value);

    let res = match claim_values_builder.add_value(&attr, &dec_value) {
        Ok(_) => ErrorCode::Success,
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_cl_claim_values_builder_add_value: <<< res: {:?}", res);
    res
}

/// Deallocates claim values builder and returns claim values entity instead.
///
/// Note: Claims values instance deallocation must be performed by
/// calling indy_crypto_cl_claim_values_free.
///
/// # Arguments
/// * `claim_values_builder` - Reference that contains claim attribute builder instance pointer.
/// * `claim_values_p` - Reference that will contain claims values instance pointer.
#[no_mangle]
pub extern fn indy_crypto_cl_claim_values_builder_finalize(claim_values_builder: *const c_void,
                                                           claim_values_p: *mut *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_claim_values_builder_finalize: >>> claim_values_builder: {:?}, claim_values_p: {:?}", claim_values_builder, claim_values_p);

    check_useful_c_ptr!(claim_values_builder, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(claim_values_p, ErrorCode::CommonInvalidParam2);

    let claim_values_builder = unsafe { Box::from_raw(claim_values_builder as *mut ClaimValuesBuilder) };

    trace!("indy_crypto_cl_claim_values_builder_finalize: entities: claim_values_builder: {:?}", claim_values_builder);

    let res = match claim_values_builder.finalize() {
        Ok(claim_values) => {
            trace!("indy_crypto_cl_claim_values_builder_finalize: claim_values: {:?}", claim_values);
            unsafe {
                *claim_values_p = Box::into_raw(Box::new(claim_values)) as *const c_void;
                trace!("indy_crypto_cl_claim_values_builder_finalize: *claim_values_p: {:?}", *claim_values_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_cl_claim_values_builder_finalize: <<< res: {:?}", res);
    res
}

/// Deallocates claim values instance.
///
/// # Arguments
/// * `claim_values` - Claim values instance pointer
#[no_mangle]
pub extern fn indy_crypto_cl_claim_values_free(claim_values: *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_claim_values_free: >>> claim_values: {:?}", claim_values);

    check_useful_c_ptr!(claim_values, ErrorCode::CommonInvalidParam1);

    let claim_values = unsafe { Box::from_raw(claim_values as *mut ClaimValues); };
    trace!("indy_crypto_cl_claim_values_free: entity: claim_values: {:?}", claim_values);

    let res = ErrorCode::Success;

    trace!("indy_crypto_cl_claim_values_free: <<< res: {:?}", res);
    res
}

/// Creates and returns sub proof request entity builder.
///
/// The purpose of sub proof request builder is building of sub proof request entity that
/// represents requested attributes and predicates.
///
/// Note: sub proof request builder instance deallocation must be performed by
/// calling indy_crypto_cl_sub_proof_request_builder_finalize.
///
/// # Arguments
/// * `sub_proof_request_builder_p` - Reference that will contain sub proof request builder instance pointer.
#[no_mangle]
pub extern fn indy_crypto_cl_sub_proof_request_builder_new(sub_proof_request_builder_p: *mut *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_sub_proof_request_builder_new: >>> sub_proof_request_builder_p: {:?}", sub_proof_request_builder_p);

    check_useful_c_ptr!(sub_proof_request_builder_p, ErrorCode::CommonInvalidParam1);

    let res = match Verifier::new_sub_proof_request_builder() {
        Ok(sub_proof_request_builder) => {
            trace!("indy_crypto_cl_sub_proof_request_builder_new: sub_proof_request_builder: {:?}", sub_proof_request_builder);
            unsafe {
                *sub_proof_request_builder_p = Box::into_raw(Box::new(sub_proof_request_builder)) as *const c_void;
                trace!("indy_crypto_cl_sub_proof_request_builder_new: *sub_proof_request_builder_p: {:?}", *sub_proof_request_builder_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_cl_sub_proof_request_builder_new: <<< res: {:?}", res);
    res
}

/// Adds new revealed attribute to sub proof request.
///
/// # Arguments
/// * `sub_proof_request_builder` - Reference that contains sub proof request builder instance pointer.
/// * `attr` - Claim attr to add as null terminated string.
#[no_mangle]
pub extern fn indy_crypto_cl_sub_proof_request_builder_add_revealed_attr(sub_proof_request_builder: *const c_void,
                                                                         attr: *const c_char) -> ErrorCode {
    trace!("indy_crypto_cl_sub_proof_request_builder_add_revealed_attr: >>> sub_proof_request_builder: {:?}, attr: {:?}",
           sub_proof_request_builder, attr);

    check_useful_mut_c_reference!(sub_proof_request_builder, SubProofRequestBuilder, ErrorCode::CommonInvalidParam1);
    check_useful_c_str!(attr, ErrorCode::CommonInvalidParam2);

    trace!("indy_crypto_cl_sub_proof_request_builder_add_revealed_attr: entities: sub_proof_request_builder: {:?}, attr: {:?}",
           sub_proof_request_builder, attr);

    let res = match sub_proof_request_builder.add_revealed_attr(&attr) {
        Ok(_) => ErrorCode::Success,
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_cl_sub_proof_request_builder_add_revealed_attr: <<< res: {:?}", res);
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
pub extern fn indy_crypto_cl_sub_proof_request_builder_add_predicate(sub_proof_request_builder: *const c_void,
                                                                     attr_name: *const c_char,
                                                                     p_type: *const c_char,
                                                                     value: i32) -> ErrorCode {
    trace!("indy_crypto_cl_sub_proof_request_builder_add_predicate: >>> sub_proof_request_builder: {:?}, attr_name: {:?}, p_type: {:?}, value: {:?}",
           sub_proof_request_builder, attr_name, p_type, value);

    check_useful_mut_c_reference!(sub_proof_request_builder, SubProofRequestBuilder, ErrorCode::CommonInvalidParam1);
    check_useful_c_str!(attr_name, ErrorCode::CommonInvalidParam2);
    check_useful_c_str!(p_type, ErrorCode::CommonInvalidParam3);

    trace!("indy_crypto_cl_sub_proof_request_builder_add_predicate: entities: >>> sub_proof_request_builder: {:?}, attr_name: {:?}, p_type: {:?}, value: {:?}",
           sub_proof_request_builder, attr_name, p_type, value);

    let res = match sub_proof_request_builder.add_predicate(&attr_name, &p_type, value) {
        Ok(_) => ErrorCode::Success,
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_cl_sub_proof_request_builder_add_predicate: <<< res: {:?}", res);
    res
}

/// Deallocates sub proof request builder and returns sub proof request entity instead.
///
/// Note: Sub proof request instance deallocation must be performed by
/// calling indy_crypto_cl_sub_proof_request_free.
///
/// # Arguments
/// * `sub_proof_request_builder` - Reference that contains sub proof request builder instance pointer.
/// * `sub_proof_request_p` - Reference that will contain sub proof request instance pointer.
#[no_mangle]
pub extern fn indy_crypto_cl_sub_proof_request_builder_finalize(sub_proof_request_builder: *const c_void,
                                                                sub_proof_request_p: *mut *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_sub_proof_request_builder_finalize: >>> sub_proof_request_builder: {:?}, sub_proof_request_p: {:?}",
           sub_proof_request_builder, sub_proof_request_p);

    check_useful_c_ptr!(sub_proof_request_builder, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(sub_proof_request_p, ErrorCode::CommonInvalidParam2);

    let sub_proof_request_builder = unsafe { Box::from_raw(sub_proof_request_builder as *mut SubProofRequestBuilder) };

    trace!("indy_crypto_cl_sub_proof_request_builder_finalize: entities: sub_proof_request_builder: {:?}", sub_proof_request_builder);

    let res = match sub_proof_request_builder.finalize() {
        Ok(sub_proof_request) => {
            trace!("indy_crypto_cl_sub_proof_request_builder_finalize: sub_proof_request: {:?}", sub_proof_request);
            unsafe {
                *sub_proof_request_p = Box::into_raw(Box::new(sub_proof_request)) as *const c_void;
                trace!("indy_crypto_cl_sub_proof_request_builder_finalize: *sub_proof_request_p: {:?}", *sub_proof_request_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_cl_sub_proof_request_builder_finalize: <<< res: {:?}", res);
    res
}

/// Deallocates sub proof request instance.
///
/// # Arguments
/// * `sub_proof_request` - Reference that contains sub proof request instance pointer.
#[no_mangle]
pub extern fn indy_crypto_cl_sub_proof_request_free(sub_proof_request: *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_sub_proof_request_free: >>> sub_proof_request: {:?}", sub_proof_request);

    check_useful_c_ptr!(sub_proof_request, ErrorCode::CommonInvalidParam1);

    let sub_proof_request = unsafe { Box::from_raw(sub_proof_request as *mut SubProofRequest); };
    trace!("indy_crypto_cl_sub_proof_request_free: entity: sub_proof_request: {:?}", sub_proof_request);

    let res = ErrorCode::Success;

    trace!("indy_crypto_cl_sub_proof_request_free: <<< res: {:?}", res);
    res
}

/// Creates random nonce.
///
/// Note that nonce deallocation must be performed by calling indy_crypto_cl_nonce_free.
///
/// # Arguments
/// * `nonce_p` - Reference that will contain nonce instance pointer.
#[no_mangle]
pub extern fn indy_crypto_cl_new_nonce(nonce_p: *mut *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_new_nonce: >>> {:?}", nonce_p);

    check_useful_c_ptr!(nonce_p, ErrorCode::CommonInvalidParam1);

    let res = match new_nonce() {
        Ok(nonce) => {
            trace!("indy_crypto_cl_new_nonce: nonce: {:?}", nonce);
            unsafe {
                *nonce_p = Box::into_raw(Box::new(nonce)) as *const c_void;
                trace!("indy_crypto_cl_new_nonce: *nonce_p: {:?}", *nonce_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_cl_new_nonce: <<< res: {:?}", res);
    res
}

/// Returns json representation of nonce.
///
/// # Arguments
/// * `nonce` - Reference that contains nonce instance pointer.
/// * `nonce_json_p` - Reference that will contain nonce json.
#[no_mangle]
pub extern fn indy_crypto_cl_nonce_to_json(nonce: *const c_void,
                                           nonce_json_p: *mut *const c_char) -> ErrorCode {
    trace!("indy_crypto_cl_nonce_to_json: >>> nonce: {:?}, nonce_json_p: {:?}", nonce, nonce_json_p);

    check_useful_c_reference!(nonce, Nonce, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(nonce_json_p, ErrorCode::CommonInvalidParam2);

    trace!("indy_crypto_cl_nonce_to_json: entity >>> nonce: {:?}", nonce);

    let res = match nonce.to_json() {
        Ok(nonce_json) => {
            trace!("indy_crypto_cl_nonce_to_json: nonce_json: {:?}", nonce_json);
            unsafe {
                let nonce_json = CTypesUtils::string_to_cstring(nonce_json);
                *nonce_json_p = nonce_json.into_raw();
                trace!("indy_crypto_cl_nonce_to_json: nonce_json_p: {:?}", *nonce_json_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_cl_nonce_to_json: <<< res: {:?}", res);
    res
}

/// Creates and returns nonce json.
///
/// Note: Nonce instance deallocation must be performed by calling indy_crypto_cl_nonce_free.
///
/// # Arguments
/// * `nonce_json` - Reference that contains nonce json.
/// * `nonce_p` - Reference that will contain nonce instance pointer.
#[no_mangle]
pub extern fn indy_crypto_cl_nonce_from_json(nonce_json: *const c_char,
                                             nonce_p: *mut *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_nonce_from_json: >>> nonce_json: {:?}, nonce_p: {:?}", nonce_json, nonce_p);

    check_useful_c_str!(nonce_json, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(nonce_p, ErrorCode::CommonInvalidParam2);

    trace!("indy_crypto_cl_nonce_from_json: entity: nonce_json: {:?}", nonce_json);

    let res = match Nonce::from_json(&nonce_json) {
        Ok(nonce) => {
            trace!("indy_crypto_cl_nonce_from_json: nonce: {:?}", nonce);
            unsafe {
                *nonce_p = Box::into_raw(Box::new(nonce)) as *const c_void;
                trace!("indy_crypto_cl_nonce_from_json: *nonce_p: {:?}", *nonce_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("indy_crypto_cl_nonce_from_json: <<< res: {:?}", res);
    res
}

/// Deallocates nonce instance.
///
/// # Arguments
/// * `nonce` - Reference that contains nonce instance pointer.
#[no_mangle]
pub extern fn indy_crypto_cl_nonce_free(nonce: *const c_void) -> ErrorCode {
    trace!("indy_crypto_cl_nonce_free: >>> nonce: {:?}", nonce);

    check_useful_c_ptr!(nonce, ErrorCode::CommonInvalidParam1);

    let nonce = unsafe { Box::from_raw(nonce as *mut Nonce); };
    trace!("indy_crypto_cl_nonce_free: entity: nonce: {:?}", nonce);

    let res = ErrorCode::Success;

    trace!("indy_crypto_cl_nonce_free: <<< res: {:?}", res);
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::ffi::CString;
    use std::ptr;
    use ffi::cl::mocks::*;

    #[test]
    fn indy_crypto_cl_claim_schema_builder_new_works() {
        let mut claim_schema_builder: *const c_void = ptr::null();
        let err_code = indy_crypto_cl_claim_schema_builder_new(&mut claim_schema_builder);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!claim_schema_builder.is_null());

        _free_claim_schema_builder(claim_schema_builder);
    }

    #[test]
    fn indy_crypto_cl_claim_schema_builder_add_attr_works() {
        let claim_schema_builder = _claim_schema_builder();

        let attr = CString::new("sex").unwrap();
        let err_code = indy_crypto_cl_claim_schema_builder_add_attr(claim_schema_builder, attr.as_ptr());
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!claim_schema_builder.is_null());

        let attr = CString::new("name").unwrap();
        let err_code = indy_crypto_cl_claim_schema_builder_add_attr(claim_schema_builder, attr.as_ptr());
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!claim_schema_builder.is_null());

        let attr = CString::new("age").unwrap();
        let err_code = indy_crypto_cl_claim_schema_builder_add_attr(claim_schema_builder, attr.as_ptr());
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!claim_schema_builder.is_null());

        _free_claim_schema_builder(claim_schema_builder);
    }

    #[test]
    fn indy_crypto_cl_claim_schema_builder_finalize_works() {
        let claim_schema_builder = _claim_schema_builder();

        let attr = CString::new("sex").unwrap();
        let err_code = indy_crypto_cl_claim_schema_builder_add_attr(claim_schema_builder, attr.as_ptr());
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!claim_schema_builder.is_null());

        let mut claim_schema: *const c_void = ptr::null();
        indy_crypto_cl_claim_schema_builder_finalize(claim_schema_builder, &mut claim_schema);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!claim_schema.is_null());

        _free_claim_schema(claim_schema);
    }

    #[test]
    fn indy_crypto_cl_claim_schema_free_works() {
        let claim_schema = _claim_schema();

        let err_code = indy_crypto_cl_claim_schema_free(claim_schema);
        assert_eq!(err_code, ErrorCode::Success);
    }

    #[test]
    fn indy_crypto_cl_claim_values_builder_new_works() {
        let mut claim_values_builder: *const c_void = ptr::null();
        let err_code = indy_crypto_cl_claim_values_builder_new(&mut claim_values_builder);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!claim_values_builder.is_null());

        _free_claim_values_builder(claim_values_builder);
    }

    #[test]
    fn indy_crypto_cl_claim_values_builder_add_value_works() {
        let claim_values_builder = _claim_values_builder();

        let attr = CString::new("sex").unwrap();
        let dec_value = CString::new("89057765651800459030103911598694169835931320404459570102253965466045532669865684092518362135930940112502263498496335250135601124519172068317163741086983519494043168252186111551835366571584950296764626458785776311514968350600732183408950813066589742888246925358509482561838243805468775416479523402043160919428168650069477488093758569936116799246881809224343325540306266957664475026390533069487455816053169001876208052109360113102565642529699056163373190930839656498261278601357214695582219007449398650197048218304260447909283768896882743373383452996855450316360259637079070460616248922547314789644935074980711243164129").unwrap();
        let err_code = indy_crypto_cl_claim_values_builder_add_value(claim_values_builder, attr.as_ptr(), dec_value.as_ptr());
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!claim_values_builder.is_null());

        let attr = CString::new("name").unwrap();
        let dec_value = CString::new("58606710922154038918005745652863947546479611221487923871520854046018234465128105585608812090213473225037875788462225679336791123783441657062831589984290779844020407065450830035885267846722229953206567087435754612694085258455822926492275621650532276267042885213400704012011608869094703483233081911010530256094461587809601298503874283124334225428746479707531278882536314925285434699376158578239556590141035593717362562548075653598376080466948478266094753818404986494459240364648986755479857098110402626477624280802323635285059064580583239726433768663879431610261724430965980430886959304486699145098822052003020688956471").unwrap();
        let err_code = indy_crypto_cl_claim_values_builder_add_value(claim_values_builder, attr.as_ptr(), dec_value.as_ptr());
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!claim_values_builder.is_null());

        _free_claim_values_builder(claim_values_builder);
    }

    #[test]
    fn indy_crypto_cl_claim_values_free_works() {
        let claim_values = _claim_values();

        let err_code = indy_crypto_cl_claim_values_free(claim_values);
        assert_eq!(err_code, ErrorCode::Success);
    }

    #[test]
    fn indy_crypto_cl_sub_proof_request_builder_new_works() {
        let mut sub_proof_request_builder: *const c_void = ptr::null();
        let err_code = indy_crypto_cl_sub_proof_request_builder_new(&mut sub_proof_request_builder);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!sub_proof_request_builder.is_null());

        _free_sub_proof_request_builder(sub_proof_request_builder);
    }

    #[test]
    fn indy_crypto_cl_sub_proof_request_builder_add_revealed_attr_works() {
        let sub_proof_request_builder = _sub_proof_request_builder();

        let attr = CString::new("sex").unwrap();
        let err_code = indy_crypto_cl_sub_proof_request_builder_add_revealed_attr(sub_proof_request_builder, attr.as_ptr());
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!sub_proof_request_builder.is_null());

        let attr = CString::new("name").unwrap();
        let err_code = indy_crypto_cl_sub_proof_request_builder_add_revealed_attr(sub_proof_request_builder, attr.as_ptr());
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!sub_proof_request_builder.is_null());

        _free_sub_proof_request_builder(sub_proof_request_builder);
    }

    #[test]
    fn indy_crypto_cl_sub_proof_request_builder_add_predicate_works() {
        let sub_proof_request_builder = _sub_proof_request_builder();

        let attr_name = CString::new("age").unwrap();
        let p_type = CString::new("GE").unwrap();
        let value = 18;

        let err_code = indy_crypto_cl_sub_proof_request_builder_add_predicate(sub_proof_request_builder, attr_name.as_ptr(), p_type.as_ptr(), value);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!sub_proof_request_builder.is_null());

        _free_sub_proof_request_builder(sub_proof_request_builder);
    }

    #[test]
    fn indy_crypto_cl_sub_proof_request_builder_finalize_works() {
        let sub_proof_request_builder = _sub_proof_request_builder();

        let attr = CString::new("sex").unwrap();
        let err_code = indy_crypto_cl_sub_proof_request_builder_add_revealed_attr(sub_proof_request_builder, attr.as_ptr());
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!sub_proof_request_builder.is_null());

        let mut sub_proof_request: *const c_void = ptr::null();
        indy_crypto_cl_sub_proof_request_builder_finalize(sub_proof_request_builder, &mut sub_proof_request);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!sub_proof_request.is_null());

        _free_sub_proof_request(sub_proof_request);
    }

    #[test]
    fn indy_crypto_cl_sub_proof_request_free_works() {
        let sub_proof_request = _sub_proof_request();

        let err_code = indy_crypto_cl_sub_proof_request_free(sub_proof_request);
        assert_eq!(err_code, ErrorCode::Success);
    }

    #[test]
    fn indy_crypto_cl_new_nonce_works() {
        let mut nonce_p: *const c_void = ptr::null();
        let err_code = indy_crypto_cl_new_nonce(&mut nonce_p);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!nonce_p.is_null());

        _free_nonce(nonce_p)
    }

    #[test]
    fn indy_crypto_cl_nonce_to_json_works() {
        let nonce = _nonce();

        let mut nonce_json_p: *const c_char = ptr::null();
        let err_code = indy_crypto_cl_nonce_to_json(nonce, &mut nonce_json_p);
        assert_eq!(err_code, ErrorCode::Success);

        _free_nonce(nonce)
    }

    #[test]
    fn indy_crypto_cl_nonce_from_json_works() {
        let nonce = _nonce();

        let mut nonce_json_p: *const c_char = ptr::null();
        let err_code = indy_crypto_cl_nonce_to_json(nonce, &mut nonce_json_p);
        assert_eq!(err_code, ErrorCode::Success);

        let mut nonce_p: *const c_void = ptr::null();
        let err_code = indy_crypto_cl_nonce_from_json(nonce_json_p, &mut nonce_p);
        assert_eq!(err_code, ErrorCode::Success);

        _free_nonce(nonce)
    }

    #[test]
    fn indy_crypto_cl_nonce_free_works() {
        let nonce = _nonce();

        let err_code = indy_crypto_cl_nonce_free(nonce);
        assert_eq!(err_code, ErrorCode::Success);
    }
}

pub mod mocks {
    use super::*;

    use std::ffi::CString;
    use std::ptr;


    pub fn _claim_schema_builder() -> *const c_void {
        let mut claim_schema_builder: *const c_void = ptr::null();
        let err_code = indy_crypto_cl_claim_schema_builder_new(&mut claim_schema_builder);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!claim_schema_builder.is_null());

        claim_schema_builder
    }

    pub fn _free_claim_schema_builder(claim_schema_builder: *const c_void) {
        let mut claim_schema: *const c_void = ptr::null();
        let err_code = indy_crypto_cl_claim_schema_builder_finalize(claim_schema_builder, &mut claim_schema);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!claim_schema.is_null());

        _free_claim_schema(claim_schema);
    }

    pub fn _claim_schema() -> *const c_void {
        let claim_schema_builder = _claim_schema_builder();

        let attr = CString::new("name").unwrap();
        let err_code = indy_crypto_cl_claim_schema_builder_add_attr(claim_schema_builder, attr.as_ptr());
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!claim_schema_builder.is_null());

        let attr = CString::new("sex").unwrap();
        let err_code = indy_crypto_cl_claim_schema_builder_add_attr(claim_schema_builder, attr.as_ptr());
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!claim_schema_builder.is_null());

        let attr = CString::new("age").unwrap();
        let err_code = indy_crypto_cl_claim_schema_builder_add_attr(claim_schema_builder, attr.as_ptr());
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!claim_schema_builder.is_null());

        let attr = CString::new("height").unwrap();
        let err_code = indy_crypto_cl_claim_schema_builder_add_attr(claim_schema_builder, attr.as_ptr());
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!claim_schema_builder.is_null());

        let mut claim_schema: *const c_void = ptr::null();
        indy_crypto_cl_claim_schema_builder_finalize(claim_schema_builder, &mut claim_schema);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!claim_schema.is_null());

        claim_schema
    }

    pub fn _free_claim_schema(claim_schema: *const c_void) {
        let err_code = indy_crypto_cl_claim_schema_free(claim_schema);
        assert_eq!(err_code, ErrorCode::Success);
    }

    pub fn _claim_values_builder() -> *const c_void {
        let mut claim_values_builder: *const c_void = ptr::null();
        let err_code = indy_crypto_cl_claim_values_builder_new(&mut claim_values_builder);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!claim_values_builder.is_null());

        claim_values_builder
    }

    pub fn _free_claim_values_builder(claim_values_builder: *const c_void) {
        let mut claim_values: *const c_void = ptr::null();
        let err_code = indy_crypto_cl_claim_values_builder_finalize(claim_values_builder, &mut claim_values);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!claim_values.is_null());

        _free_claim_values(claim_values);
    }

    pub fn _claim_values() -> *const c_void {
        let claim_values_builder = _claim_values_builder();

        let attr = CString::new("name").unwrap();
        let dec_value = CString::new("1139481716457488690172217916278103335").unwrap();
        let err_code = indy_crypto_cl_claim_values_builder_add_value(claim_values_builder,
                                                                     attr.as_ptr(),
                                                                     dec_value.as_ptr());
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!claim_values_builder.is_null());

        let attr = CString::new("sex").unwrap();
        let dec_value = CString::new("5944657099558967239210949258394887428692050081607692519917050011144233115103").unwrap();
        let err_code = indy_crypto_cl_claim_values_builder_add_value(claim_values_builder,
                                                                     attr.as_ptr(),
                                                                     dec_value.as_ptr());
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!claim_values_builder.is_null());

        let attr = CString::new("age").unwrap();
        let dec_value = CString::new("28").unwrap();
        let err_code = indy_crypto_cl_claim_values_builder_add_value(claim_values_builder,
                                                                     attr.as_ptr(),
                                                                     dec_value.as_ptr());
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!claim_values_builder.is_null());

        let attr = CString::new("height").unwrap();
        let dec_value = CString::new("175").unwrap();
        let err_code = indy_crypto_cl_claim_values_builder_add_value(claim_values_builder,
                                                                     attr.as_ptr(),
                                                                     dec_value.as_ptr());
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!claim_values_builder.is_null());

        let mut claim_values: *const c_void = ptr::null();
        indy_crypto_cl_claim_values_builder_finalize(claim_values_builder, &mut claim_values);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!claim_values.is_null());

        claim_values
    }

    pub fn _free_claim_values(claim_values: *const c_void) {
        let err_code = indy_crypto_cl_claim_values_free(claim_values);
        assert_eq!(err_code, ErrorCode::Success);
    }

    pub fn _sub_proof_request_builder() -> *const c_void {
        let mut sub_proof_request_builder: *const c_void = ptr::null();
        let err_code = indy_crypto_cl_sub_proof_request_builder_new(&mut sub_proof_request_builder);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!sub_proof_request_builder.is_null());

        sub_proof_request_builder
    }

    pub fn _free_sub_proof_request_builder(sub_proof_request_builder: *const c_void) {
        let mut sub_proof_request: *const c_void = ptr::null();
        let err_code = indy_crypto_cl_sub_proof_request_builder_finalize(sub_proof_request_builder, &mut sub_proof_request);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!sub_proof_request.is_null());

        _free_sub_proof_request(sub_proof_request);
    }

    pub fn _sub_proof_request() -> *const c_void {
        let sub_proof_request_builder = _sub_proof_request_builder();

        let revealed_attr = CString::new("name").unwrap();
        let err_code = indy_crypto_cl_sub_proof_request_builder_add_revealed_attr(sub_proof_request_builder, revealed_attr.as_ptr());
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!sub_proof_request_builder.is_null());

        let attr_name = CString::new("age").unwrap();
        let p_type = CString::new("GE").unwrap();
        let value = 18;

        let err_code = indy_crypto_cl_sub_proof_request_builder_add_predicate(sub_proof_request_builder, attr_name.as_ptr(), p_type.as_ptr(), value);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!sub_proof_request_builder.is_null());

        let mut sub_proof_request: *const c_void = ptr::null();
        indy_crypto_cl_sub_proof_request_builder_finalize(sub_proof_request_builder, &mut sub_proof_request);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!sub_proof_request.is_null());

        sub_proof_request
    }

    pub fn _free_sub_proof_request(sub_proof_request: *const c_void) {
        let err_code = indy_crypto_cl_sub_proof_request_free(sub_proof_request);
        assert_eq!(err_code, ErrorCode::Success);
    }

    pub fn _nonce() -> *const c_void {
        let mut nonce_p: *const c_void = ptr::null();
        let err_code = indy_crypto_cl_new_nonce(&mut nonce_p);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!nonce_p.is_null());

        nonce_p
    }

    pub fn _free_nonce(nonce: *const c_void) {
        let err_code = indy_crypto_cl_nonce_free(nonce);
        assert_eq!(err_code, ErrorCode::Success);
    }
}