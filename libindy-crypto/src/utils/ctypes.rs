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

macro_rules! check_useful_c_reference {
    ($ptr:ident, $type:ty, $err:expr) => {
        if $ptr.is_null() {
            return $err
        }

        let $ptr: &$type = unsafe { &*($ptr as *const $type) };;
    }
}

macro_rules! check_useful_c_reference_array {
    ($ptrs:ident, $ptrs_len:ident, $type:ty, $err1:expr, $err2:expr) => {
        if $ptrs.is_null() {
            return $err1
        }

        if $ptrs_len <= 0 {
            return $err2
        }

        let $ptrs: Vec<&$type> =
            unsafe { slice::from_raw_parts($ptrs, $ptrs_len) }
                .iter()
                .map(|ptr| unsafe { &*(*ptr as *const $type) })
                .collect();
    }
}

macro_rules! check_useful_c_ptr {
    ($ptr:ident, $err1:expr) => {
        if $ptr.is_null() {
            return $err1
        }
    }
}