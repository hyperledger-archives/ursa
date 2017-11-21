use anoncreds::*;
use anoncreds::issuer::*;
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
    check_useful_c_ptr!(claim_attrs_builder_p, ErrorCode::CommonInvalidParam1);

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

        let mut claim_attrs: *const c_void = ptr::null();
        indy_crypto_anoncreds_claim_attributes_builder_finalize(claim_attrs_builder, &mut claim_attrs);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!claim_attrs.is_null());

        indy_crypto_anoncreds_claim_attributes_free(claim_attrs);
        assert_eq!(err_code, ErrorCode::Success);
    }

    #[test]
    fn indy_crypto_anoncreds_claim_attributes_builder_add_attr_works() {
        let mut claim_attrs_builder: *const c_void = ptr::null();
        let err_code = indy_crypto_anoncreds_claim_attributes_builder_new(&mut claim_attrs_builder);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!claim_attrs_builder.is_null());

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

        let mut claim_attrs: *const c_void = ptr::null();
        indy_crypto_anoncreds_claim_attributes_builder_finalize(claim_attrs_builder, &mut claim_attrs);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!claim_attrs.is_null());

        indy_crypto_anoncreds_claim_attributes_free(claim_attrs);
        assert_eq!(err_code, ErrorCode::Success);
    }

    #[test]
    fn indy_crypto_anoncreds_claim_attributes_builder_finalize_works() {
        let mut claim_attrs_builder: *const c_void = ptr::null();
        let err_code = indy_crypto_anoncreds_claim_attributes_builder_new(&mut claim_attrs_builder);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!claim_attrs_builder.is_null());

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

        let mut claim_attrs: *const c_void = ptr::null();
        indy_crypto_anoncreds_claim_attributes_builder_finalize(claim_attrs_builder, &mut claim_attrs);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!claim_attrs.is_null());

        indy_crypto_anoncreds_claim_attributes_free(claim_attrs);
        assert_eq!(err_code, ErrorCode::Success);
    }
}