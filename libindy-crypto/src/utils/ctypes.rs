use std::mem;

pub struct CTypesUtils {}

impl CTypesUtils {
    // Returns vector len and data pointer and forces Rust to unmanage vector memory.
    // It can be used only for vector with len == capacity. Otherwise
    // it will be impossible to free this memory correctly
    // Returned pointer is valid only before first vector modification
    // De-allocation must be performed by calling c_byte_array_to_vec only!
    pub fn vec_to_c_byte_array(vec: Vec<u8>) -> (*const u8, usize) {
        assert!(vec.len() == vec.capacity());
        let res = (vec.as_ptr(), vec.len());
        mem::forget(vec);
        res
    }

    // It works only with pointers crated by vec_to_c_byte_array!
    pub fn c_byte_array_to_vec(ptr: *mut u8, len: usize) -> Vec<u8> {
        unsafe { Vec::from_raw_parts(ptr, len, len) }
    }
}

macro_rules! check_useful_c_byte_array {
    ($ptr:ident, $len:expr, $err1:expr, $err2:expr) => {
        if $ptr.is_null() {
            return $err1
        }

        if $len <= 0 {
            return $err2
        }

        let $ptr = unsafe { slice::from_raw_parts($ptr, $len) };
    }
}

macro_rules! check_useful_opt_c_byte_array {
    ($ptr:ident, $len:expr, $err1:expr, $err2:expr) => {
        if !$ptr.is_null() && $len <= 0 {
            return $err2
        }

        let $ptr = if $ptr.is_null() {
            None
        } else {
            unsafe { Some(slice::from_raw_parts($ptr, $len)) }
        };
    }
}

macro_rules! check_useful_c_byte_array_ptr {
    ($ptr_p:ident, $len_p:expr, $err1:expr, $err2:expr) => {
        if $ptr_p.is_null() {
            return $err1
        }

        if $len_p.is_null() {
            return $err2
        }
    }
}

macro_rules! check_useful_c_ptr {
    ($ptr:ident, $err1:expr) => {
        if $ptr.is_null() {
            return $err1
        }
    }
}