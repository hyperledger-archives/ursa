extern crate libc;

use self::libc::c_char;

use std::ffi::CStr;
use std::str::Utf8Error;
use std::ffi::CString;
use std::mem;

pub struct CTypesUtils {}

impl CTypesUtils {
    pub fn c_str_to_string(cstr: *const c_char) -> Result<Option<String>, Utf8Error> {
        if cstr.is_null() {
            return Ok(None)
        }

        unsafe {
            match CStr::from_ptr(cstr).to_str() {
                Ok(str) => Ok(Some(str.to_string())),
                Err(err) => Err(err)
            }
        }
    }

    pub fn string_to_cstring(s: String) -> CString {
        CString::new(s).unwrap()
    }

    //Returnable pointer is valid only before first vector modification
    pub fn vec_to_c_byte_array(v: &Vec<u8>) -> (*const i8, u32) {
        let len = v.len() as u32;
        let res = (v.as_ptr() as *const i8, len);
        mem::forget(v);
        res
    }
}

macro_rules! check_useful_c_str {
    ($x:ident, $e:expr) => {
        let $x = match CTypesUtils::c_str_to_string($x) {
            Ok(Some(val)) => val,
            Ok(None) => return $e,
            Err(_) => return $e
        };

        if $x.is_empty() {
            return $e
        }
    }
}

macro_rules! check_useful_opt_c_str {
    ($x:ident, $e:expr) => {
        let $x = match CTypesUtils::c_str_to_string($x) {
            Ok(Some(val)) => if val.is_empty() { None } else { Some(val) },
            Ok(None) => None,
            Err(_) => return $e
        };
    }
}

macro_rules! check_useful_byte_array {
    ($x:ident, $l:expr, $e:expr) => {
        if $x.is_null() {
            return $e
        }

        let $x =  unsafe { slice::from_raw_parts($x, $l as usize) };
        let $x = $x.to_vec();
    }
}

macro_rules! check_useful_opt_byte_array {
    ($x:ident, $l:expr, $e:expr) => {
        if $x.is_null() {
            let $x: Option<Vec<u8>> = None;
        }

        let $x =  unsafe { slice::from_raw_parts($x, $l as usize) };
        let $x: Option<Vec<u8>> = Some($x.to_vec());
    }
}