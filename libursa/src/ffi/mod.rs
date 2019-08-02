pub mod bls;
pub mod cl;
pub mod logger;
pub mod signatures;

use errors::prelude::*;
use std::os::raw::c_char;

/// Used for receiving a ByteBuffer from C that was allocated by either C or Rust.
/// If Rust allocated, then the outgoing struct is ffi_support::ByteBuffer
/// Caller is responsible for calling free where applicable.
///
/// C will not notice a difference and can use the same struct
#[repr(C)]
pub struct ByteArray {
    length: usize,
    data: *const u8,
}

impl Default for ByteArray {
    fn default() -> ByteArray {
        ByteArray {
            length: 0,
            data: std::ptr::null(),
        }
    }
}

impl ByteArray {
    pub fn to_vec(&self) -> Vec<u8> {
        if self.data.is_null() || self.length == 0 {
            Vec::new()
        } else {
            unsafe { std::slice::from_raw_parts(self.data, self.length).to_vec() }
        }
    }
}

impl From<&Vec<u8>> for ByteArray {
    fn from(input: &Vec<u8>) -> ByteArray {
        ByteArray {
            length: input.len(),
            data: input.as_slice().as_ptr() as *const u8,
        }
    }
}

impl From<&[u8]> for ByteArray {
    fn from(input: &[u8]) -> ByteArray {
        ByteArray {
            length: input.len(),
            data: input.as_ptr() as *const u8,
        }
    }
}

#[derive(Debug, PartialEq, Copy, Clone)]
#[repr(usize)]
pub enum ErrorCode {
    Success = 0,

    // Common errors

    // Caller passed invalid value as param 1 (null, invalid json and etc..)
    CommonInvalidParam1 = 100,

    // Caller passed invalid value as param 2 (null, invalid json and etc..)
    CommonInvalidParam2 = 101,

    // Caller passed invalid value as param 3 (null, invalid json and etc..)
    CommonInvalidParam3 = 102,

    // Caller passed invalid value as param 4 (null, invalid json and etc..)
    CommonInvalidParam4 = 103,

    // Caller passed invalid value as param 5 (null, invalid json and etc..)
    CommonInvalidParam5 = 104,

    // Caller passed invalid value as param 6 (null, invalid json and etc..)
    CommonInvalidParam6 = 105,

    // Caller passed invalid value as param 7 (null, invalid json and etc..)
    CommonInvalidParam7 = 106,

    // Caller passed invalid value as param 8 (null, invalid json and etc..)
    CommonInvalidParam8 = 107,

    // Caller passed invalid value as param 9 (null, invalid json and etc..)
    CommonInvalidParam9 = 108,

    // Caller passed invalid value as param 10 (null, invalid json and etc..)
    CommonInvalidParam10 = 109,

    // Caller passed invalid value as param 11 (null, invalid json and etc..)
    CommonInvalidParam11 = 110,

    // Caller passed invalid value as param 11 (null, invalid json and etc..)
    CommonInvalidParam12 = 111,

    // Invalid library state was detected in runtime. It signals library bug
    CommonInvalidState = 112,

    // Object (json, config, key, credential and etc...) passed by library caller has invalid structure
    CommonInvalidStructure = 113,

    // IO Error
    CommonIOError = 114,

    // Trying to issue non-revocation credential with full anoncreds revocation accumulator
    AnoncredsRevocationAccumulatorIsFull = 115,

    // Invalid revocation accumulator index
    AnoncredsInvalidRevocationAccumulatorIndex = 116,

    // Credential revoked
    AnoncredsCredentialRevoked = 117,

    // Proof rejected
    AnoncredsProofRejected = 118,
}

/// Get details for last occurred error.
///
/// NOTE: Error is stored until the next one occurs.
///       Returning pointer has the same lifetime.
///
/// #Params
/// * `error_json_p` - Reference that will contain error details (if any error has occurred before)
///  in the format:
/// {
///     "backtrace": Optional<str> - error backtrace.
///         Collecting of backtrace can be enabled by setting environment variable `RUST_BACKTRACE=1`
///     "message": str - human-readable error description
/// }
///
#[no_mangle]
pub extern "C" fn ursa_get_current_error(error_json_p: *mut *const c_char) {
    trace!(
        "ursa_get_current_error >>> error_json_p: {:?}",
        error_json_p
    );

    let error = get_current_error_c_json();
    unsafe { *error_json_p = error };

    trace!("ursa_get_current_error: <<<");
}

#[cfg(test)]
mod tests {
    use super::*;

    use ffi::cl::issuer::ursa_cl_credential_private_key_from_json;
    use std::ptr;
    use utils::ctypes::*;

    #[test]
    fn ursa_get_current_error_works() {
        ursa_cl_credential_private_key_from_json(ptr::null(), &mut ptr::null());

        let mut error_json_p: *const c_char = ptr::null();
        ursa_get_current_error(&mut error_json_p);

        let error_json_1 = c_str_to_string(error_json_p).unwrap();
        assert!(error_json_1.is_some());

        let credential_priv_key = string_to_cstring("some wrong data".to_string());
        ursa_cl_credential_private_key_from_json(credential_priv_key.as_ptr(), &mut ptr::null());

        ursa_get_current_error(&mut error_json_p);

        let error_json_2 = c_str_to_string(error_json_p).unwrap();
        assert!(error_json_2.is_some());

        assert_ne!(error_json_1.unwrap(), error_json_2.unwrap());
    }
}
