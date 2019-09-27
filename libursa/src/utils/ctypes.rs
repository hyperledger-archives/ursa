use std::os::raw::c_char;

use std::ffi::CStr;
use std::ffi::CString;
use std::str::Utf8Error;

pub fn c_str_to_string(cstr: *const c_char) -> Result<Option<String>, Utf8Error> {
    if cstr.is_null() {
        return Ok(None);
    }

    unsafe {
        match CStr::from_ptr(cstr).to_str() {
            Ok(str) => Ok(Some(str.to_string())),
            Err(err) => Err(err),
        }
    }
}

pub fn string_to_cstring(s: String) -> CString {
    CString::new(s).unwrap()
}

macro_rules! check_useful_c_byte_array {
    ($ptr:ident, $len:expr, $err1:expr, $err2:expr) => {
        if $ptr.is_null() {
            set_current_error(&err_msg($err1.into(), "Invalid pointer has been passed"));
            return $err1;
        }

        if $len <= 0 {
            set_current_error(&err_msg(
                $err2.into(),
                "Array length must be greater than 0",
            ));
            return $err2;
        }

        let $ptr = unsafe { slice::from_raw_parts($ptr, $len) };
    };
}

macro_rules! check_useful_opt_c_byte_array {
    ($ptr:ident, $len:expr, $err1:expr, $err2:expr) => {
        if !$ptr.is_null() && $len <= 0 {
            set_current_error(&err_msg($err2.into(), "Invalid pointer has been passed"));
            return $err2;
        }

        let $ptr = if $ptr.is_null() {
            None
        } else {
            unsafe { Some(slice::from_raw_parts($ptr, $len)) }
        };
    };
}

macro_rules! check_useful_c_reference {
    ($ptr:ident, $type:ty, $err:expr) => {
        if $ptr.is_null() {
            set_current_error(&err_msg($err.into(), "Invalid pointer has been passed"));
            return $err;
        }

        let $ptr: &$type = unsafe { &*($ptr as *const $type) };
    };
}

macro_rules! check_useful_mut_c_reference {
    ($ptr:ident, $type:ty, $err:expr) => {
        if $ptr.is_null() {
            set_current_error(&err_msg($err.into(), "Invalid pointer has been passed"));
            return $err;
        }

        let $ptr: &mut $type = unsafe { &mut *($ptr as *mut $type) };
    };
}

macro_rules! check_useful_opt_c_reference {
    ($ptr:ident, $type:ty) => {
        let $ptr: Option<&$type> = if $ptr.is_null() {
            None
        } else {
            Some(unsafe { &*($ptr as *const $type) })
        };
    };
}

macro_rules! check_useful_c_reference_array {
    ($ptrs:ident, $ptrs_len:ident, $type:ty, $err1:expr, $err2:expr) => {
        if $ptrs.is_null() {
            set_current_error(&err_msg($err2.into(), "Invalid pointer has been passed"));
            return $err1;
        }

        if $ptrs_len <= 0 {
            set_current_error(&err_msg(
                $err2.into(),
                "Array length must be greater than 0",
            ));
            return $err2;
        }

        let $ptrs: Vec<&$type> = unsafe { slice::from_raw_parts($ptrs, $ptrs_len) }
            .iter()
            .map(|ptr| unsafe { &*(*ptr as *const $type) })
            .collect();
    };
}

macro_rules! check_useful_hashset {
    ($ptr:ident, $len:expr, $err1:expr, $err2:expr) => {
        if $ptr.is_null() {
            set_current_error(&err_msg($err2.into(), "Invalid pointer has been passed"));
            return $err1;
        }

        let $ptr = HashSet::from_iter(unsafe { slice::from_raw_parts($ptr, $len) }.iter().cloned());
    };
}

macro_rules! check_useful_c_ptr {
    ($ptr:ident, $err1:expr) => {
        if $ptr.is_null() {
            set_current_error(&err_msg($err1.into(), "Invalid pointer has been passed"));
            return $err1;
        }
    };
}

macro_rules! check_useful_c_str {
    ($x:ident, $e:expr) => {
        let $x = match c_str_to_string($x) {
            Ok(Some(val)) => val,
            _ => {
                set_current_error(&err_msg($e.into(), "Invalid pointer has been passed"));
                return $e;
            }
        };

        if $x.is_empty() {
            set_current_error(&err_msg($e.into(), "Empty string has been passed"));
            return $e;
        }
    };
}

macro_rules! check_useful_opt_c_str {
    ($x:ident, $e:expr) => {
        let $x = match c_str_to_string($x) {
            Ok(opt_val) => opt_val,
            Err(_) => {
                set_current_error(&err_msg($e.into(), "Invalid pointer has been passed"));
                return $e;
            }
        };
    };
}

macro_rules! check_useful_c_callback {
    ($x:ident, $e:expr) => {
        let $x = match $x {
            Some($x) => $x,
            None => {
                set_current_error(&err_msg($e.into(), "Empty callback has been passed"));
                return $e;
            }
        };
    };
}
