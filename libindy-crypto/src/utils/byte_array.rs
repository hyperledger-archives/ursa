use std::mem;

macro_rules! get_byte_array {
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

//Returnable pointer is valid only before first vector modification
pub fn vec_to_pointer(v: &Vec<u8>) -> (*const i8, u32) {
    let len = v.len() as u32;
    let res = (v.as_ptr() as *const i8, len);
    mem::forget(v);
    res
}