use bls::*;
use errors::prelude::*;

use ffi::ErrorCode;
use std::os::raw::c_void;
use std::slice;

/// Creates and returns random generator point that satisfy BLS algorithm requirements.
///
/// BLS algorithm requires choosing of generator point that must be known to all parties.
/// The most of BLS methods require generator to be provided.
///
/// Note: Generator instance deallocation must be performed by calling ursa_bls_generator_free
///
/// # Arguments
/// * `gen_p` - Reference that will contain generator instance pointer
#[no_mangle]
pub extern "C" fn ursa_bls_generator_new(gen_p: *mut *const c_void) -> ErrorCode {
    trace!("ursa_bls_generator_new: >>> gen_p: {:?}", gen_p);

    check_useful_c_ptr!(gen_p, ErrorCode::CommonInvalidParam1);

    let res = match Generator::new() {
        Ok(gen) => {
            trace!("ursa_bls_generator_new: gen: {:?}", gen);
            unsafe {
                *gen_p = Box::into_raw(Box::new(gen)) as *const c_void;
                trace!("ursa_bls_generator_new: *gen_p: {:?}", *gen_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.into(),
    };

    trace!("ursa_bls_generator_new: <<< res: {:?}", res);
    res
}

/// Creates and returns generator point from bytes representation.
///
/// Note: Generator instance deallocation must be performed by calling ursa_bls_generator_free
///
/// # Arguments
/// * `bytes` - Bytes buffer pointer
/// * `bytes_len` - Bytes buffer len
/// * `gen_p` - Reference that will contain generator instance pointer
#[no_mangle]
pub extern "C" fn ursa_bls_generator_from_bytes(
    bytes: *const u8,
    bytes_len: usize,
    gen_p: *mut *const c_void,
) -> ErrorCode {
    trace!(
        "ursa_bls_generator_from_bytes: >>> bytes: {:?}, bytes_len: {:?}, gen_p: {:?}",
        bytes,
        bytes_len,
        gen_p
    );

    check_useful_c_byte_array!(
        bytes,
        bytes_len,
        ErrorCode::CommonInvalidParam1,
        ErrorCode::CommonInvalidParam2
    );
    check_useful_c_ptr!(gen_p, ErrorCode::CommonInvalidParam1);

    trace!("ursa_bls_generator_from_bytes: bytes: {:?}", bytes);

    let res = match Generator::from_bytes(bytes) {
        Ok(gen) => {
            trace!("ursa_bls_generator_from_bytes: gen: {:?}", gen);
            unsafe {
                *gen_p = Box::into_raw(Box::new(gen)) as *const c_void;
                trace!("ursa_bls_generator_from_bytes: *gen_p: {:?}", *gen_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.into(),
    };

    trace!("ursa_bls_generator_from_bytes: <<< res: {:?}", res);
    res
}

/// Returns bytes representation of generator point.
///
/// Note: Returned buffer lifetime is the same as generator instance.
///
/// # Arguments
/// * `gen` - Generator instance pointer
/// * `bytes_p` - Pointer that will contains bytes buffer
/// * `bytes_len_p` - Pointer that will contains bytes buffer len
#[no_mangle]
pub extern "C" fn ursa_bls_generator_as_bytes(
    gen: *const c_void,
    bytes_p: *mut *const u8,
    bytes_len_p: *mut usize,
) -> ErrorCode {
    trace!(
        "ursa_bls_generator_as_bytes: >>> gen: {:?}, bytes_p: {:?}, bytes_len_p: {:?}",
        gen,
        bytes_p,
        bytes_len_p
    );

    check_useful_c_reference!(gen, Generator, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(bytes_p, ErrorCode::CommonInvalidParam2);
    check_useful_c_ptr!(bytes_len_p, ErrorCode::CommonInvalidParam3);

    trace!("ursa_bls_generator_as_bytes: >>> gen: {:?}", gen);

    unsafe {
        *bytes_p = gen.as_bytes().as_ptr();
        *bytes_len_p = gen.as_bytes().len();
    };

    let res = ErrorCode::Success;

    trace!("ursa_bls_generator_as_bytes: <<< res: {:?}", res);
    res
}

/// Deallocates generator instance.
///
/// # Arguments
/// * `gen` - Generator instance pointer
#[no_mangle]
pub extern "C" fn ursa_bls_generator_free(gen: *const c_void) -> ErrorCode {
    trace!("ursa_bls_generator_free: >>> gen: {:?}", gen);

    check_useful_c_ptr!(gen, ErrorCode::CommonInvalidParam1);

    unsafe {
        Box::from_raw(gen as *mut Generator);
    }
    let res = ErrorCode::Success;

    trace!("ursa_bls_generator_free: <<< res: {:?}", res);
    res
}

/// Creates and returns random (or seeded from seed) BLS sign key algorithm requirements.
///
/// Note: Sign Key instance deallocation must be performed by calling ursa_bls_sign_key_free.
///
/// # Arguments
/// * `seed` - Seed buffer pointer. For random generation null must be passed.
/// * `seed` - Seed buffer len.
/// * `gen_p` - Reference that will contain sign key instance pointer
#[no_mangle]
pub extern "C" fn ursa_bls_sign_key_new(
    seed: *const u8,
    seed_len: usize,
    sign_key_p: *mut *const c_void,
) -> ErrorCode {
    trace!(
        "ursa_bls_sign_key_new: >>> seed: {:?}, seed_len: {:?}, sign_key_p: {:?}",
        seed,
        seed_len,
        sign_key_p
    );

    check_useful_opt_c_byte_array!(
        seed,
        seed_len,
        ErrorCode::CommonInvalidParam1,
        ErrorCode::CommonInvalidParam2
    );

    trace!("ursa_bls_sign_key_new: seed: {:?}", secret!(&seed));

    let res = match SignKey::new(seed) {
        Ok(sign_key) => {
            trace!("ursa_bls_generator_new: gen: {:?}", secret!(&sign_key));
            unsafe {
                *sign_key_p = Box::into_raw(Box::new(sign_key)) as *const c_void;
                trace!("ursa_bls_sign_key_new: *sign_key_p: {:?}", *sign_key_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.into(),
    };

    trace!("ursa_bls_sign_key_new: <<< res: {:?}", res);
    res
}

/// Creates and returns sign key from bytes representation.
///
/// Note: Sign key instance deallocation must be performed by calling ursa_bls_sign_key_free
///
/// # Arguments
/// * `bytes` - Bytes buffer pointer
/// * `bytes_len` - Bytes buffer len
/// * `sign_key_p` - Reference that will contain sign key instance pointer
#[no_mangle]
pub extern "C" fn ursa_bls_sign_key_from_bytes(
    bytes: *const u8,
    bytes_len: usize,
    sign_key_p: *mut *const c_void,
) -> ErrorCode {
    trace!(
        "ursa_bls_sign_key_from_bytes: >>> bytes: {:?}, bytes_len: {:?}, gen_p: {:?}",
        bytes,
        bytes_len,
        sign_key_p
    );

    check_useful_c_byte_array!(
        bytes,
        bytes_len,
        ErrorCode::CommonInvalidParam1,
        ErrorCode::CommonInvalidParam2
    );
    check_useful_c_ptr!(sign_key_p, ErrorCode::CommonInvalidParam1);

    trace!("ursa_bls_sign_key_from_bytes: bytes: {:?}", secret!(&bytes));

    let res = match SignKey::from_bytes(bytes) {
        Ok(sign_key) => {
            trace!(
                "ursa_bls_sign_key_from_bytes: sign_key: {:?}",
                secret!(&sign_key)
            );
            unsafe {
                *sign_key_p = Box::into_raw(Box::new(sign_key)) as *const c_void;
                trace!(
                    "ursa_bls_sign_key_from_bytes: *sign_key_p: {:?}",
                    *sign_key_p
                );
            }
            ErrorCode::Success
        }
        Err(err) => err.into(),
    };

    trace!("ursa_bls_sign_key_from_bytes: <<< res: {:?}", res);
    res
}

/// Returns bytes representation of sign key.
///
/// Note: Returned buffer lifetime is the same as sign key instance.
///
/// # Arguments
/// * `sign_key` - Sign key instance pointer
/// * `bytes_p` - Pointer that will contains bytes buffer
/// * `bytes_len_p` - Pointer that will contains bytes buffer len
#[no_mangle]
pub extern "C" fn ursa_bls_sign_key_as_bytes(
    sign_key: *const c_void,
    bytes_p: *mut *const u8,
    bytes_len_p: *mut usize,
) -> ErrorCode {
    trace!(
        "ursa_bls_sign_key_as_bytes: >>> sign_key: {:?}, bytes_p: {:?}, bytes_len_p: {:?}",
        sign_key,
        bytes_p,
        bytes_len_p
    );

    check_useful_c_reference!(sign_key, SignKey, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(bytes_p, ErrorCode::CommonInvalidParam2);
    check_useful_c_ptr!(bytes_len_p, ErrorCode::CommonInvalidParam3);

    trace!(
        "ursa_bls_sign_key_as_bytes: sign_key: {:?}",
        secret!(sign_key)
    );

    unsafe {
        *bytes_p = sign_key.as_bytes().as_ptr();
        *bytes_len_p = sign_key.as_bytes().len();
    };

    let res = ErrorCode::Success;

    trace!("ursa_bls_sign_key_as_bytes: <<< res: {:?}", res);
    res
}

/// Deallocates sign key instance.
///
/// # Arguments
/// * `sign_key` - Sign key instance pointer
#[no_mangle]
pub extern "C" fn ursa_bls_sign_key_free(sign_key: *const c_void) -> ErrorCode {
    check_useful_c_ptr!(sign_key, ErrorCode::CommonInvalidParam1);

    trace!(
        "ursa_bls_sign_key_free: >>> sign_key: {:?}",
        secret!(sign_key)
    );

    unsafe {
        Box::from_raw(sign_key as *mut SignKey);
    }
    let res = ErrorCode::Success;

    trace!("ursa_bls_sign_key_free: <<< res: {:?}", res);
    res
}

/// Creates and returns BLS ver key that corresponds to sign key.
///
/// Note: Verification key instance deallocation must be performed by calling ursa_bls_ver_key_free.
///
/// # Arguments
/// * `gen` - Generator point instance
/// * `sign_key` - Sign key instance
/// * `ver_key_p` - Reference that will contain verification key instance pointer
#[no_mangle]
pub extern "C" fn ursa_bls_ver_key_new(
    gen: *const c_void,
    sign_key: *const c_void,
    ver_key_p: *mut *const c_void,
) -> ErrorCode {
    trace!(
        "ursa_bls_ver_key_new: >>> gen: {:?}, sign_key: {:?}, ver_key_p: {:?}",
        gen,
        sign_key,
        ver_key_p
    );

    check_useful_c_reference!(gen, Generator, ErrorCode::CommonInvalidParam1);
    check_useful_c_reference!(sign_key, SignKey, ErrorCode::CommonInvalidParam2);

    trace!(
        "ursa_bls_ver_key_new: gen: {:?}, sign_key: {:?}",
        gen,
        secret!(sign_key)
    );

    let res = match VerKey::new(gen, sign_key) {
        Ok(ver_key) => {
            trace!("ursa_bls_ver_key_new: ver_key: {:?}", ver_key);
            unsafe {
                *ver_key_p = Box::into_raw(Box::new(ver_key)) as *const c_void;
                trace!("ursa_bls_ver_key_new: *ver_key_p: {:?}", *ver_key_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.into(),
    };

    trace!("ursa_bls_sign_key_new: <<< res: {:?}", res);
    res
}

/// Creates and returns verification key from bytes representation.
///
/// Note: Verification key instance deallocation must be performed by calling ursa_bls_very_key_free
///
/// # Arguments
/// * `bytes` - Bytes buffer pointer
/// * `bytes_len` - Bytes buffer len
/// * `ver_key_p` - Reference that will contain verification key instance pointer
#[no_mangle]
pub extern "C" fn ursa_bls_ver_key_from_bytes(
    bytes: *const u8,
    bytes_len: usize,
    ver_key_p: *mut *const c_void,
) -> ErrorCode {
    trace!(
        "ursa_bls_ver_key_from_bytes: >>> bytes: {:?}, bytes_len: {:?}, gen_p: {:?}",
        bytes,
        bytes_len,
        ver_key_p
    );

    check_useful_c_byte_array!(
        bytes,
        bytes_len,
        ErrorCode::CommonInvalidParam1,
        ErrorCode::CommonInvalidParam2
    );
    check_useful_c_ptr!(ver_key_p, ErrorCode::CommonInvalidParam1);

    trace!("ursa_bls_ver_key_from_bytes: bytes: {:?}", bytes);

    let res = match VerKey::from_bytes(bytes) {
        Ok(ver_key) => {
            trace!("ursa_bls_ver_key_from_bytes: sign_key: {:?}", ver_key);
            unsafe {
                *ver_key_p = Box::into_raw(Box::new(ver_key)) as *const c_void;
                trace!("ursa_bls_ver_key_from_bytes: *ver_key_p: {:?}", *ver_key_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.into(),
    };

    trace!("ursa_bls_ver_key_from_bytes: <<< res: {:?}", res);
    res
}

/// Returns bytes representation of verification key.
///
/// Note: Returned buffer lifetime is the same as verification key instance.
///
/// # Arguments
/// * `ver_key` - Verification key instance pointer
/// * `bytes_p` - Pointer that will contains bytes buffer
/// * `bytes_len_p` - Pointer that will contains bytes buffer len
#[no_mangle]
pub extern "C" fn ursa_bls_ver_key_as_bytes(
    ver_key: *const c_void,
    bytes_p: *mut *const u8,
    bytes_len_p: *mut usize,
) -> ErrorCode {
    trace!(
        "ursa_bls_sign_key_as_bytes: >>> ver_key: {:?}, bytes_p: {:?}, bytes_len_p: {:?}",
        ver_key,
        bytes_p,
        bytes_len_p
    );

    check_useful_c_reference!(ver_key, VerKey, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(bytes_p, ErrorCode::CommonInvalidParam2);
    check_useful_c_ptr!(bytes_len_p, ErrorCode::CommonInvalidParam3);

    trace!("ursa_bls_ver_key_as_bytes: ver_key: {:?}", ver_key);

    unsafe {
        *bytes_p = ver_key.as_bytes().as_ptr();
        *bytes_len_p = ver_key.as_bytes().len();
    };

    let res = ErrorCode::Success;

    trace!("ursa_bls_ver_key_as_bytes: <<< res: {:?}", res);
    res
}

/// Deallocates verification key instance.
///
/// # Arguments
/// * `ver_key` - Verification key instance pointer
#[no_mangle]
pub extern "C" fn ursa_bls_ver_key_free(ver_key: *const c_void) -> ErrorCode {
    check_useful_c_ptr!(ver_key, ErrorCode::CommonInvalidParam1);

    trace!("ursa_bls_ver_key_free: >>> ver_key: {:?}", ver_key);

    unsafe {
        Box::from_raw(ver_key as *mut VerKey);
    }
    let res = ErrorCode::Success;

    trace!("ursa_bls_ver_key_free: <<< res: {:?}", res);
    res
}

/// Creates and returns BLS proof of possession that corresponds to ver key and sign key.
///
/// Note: Proof of possession instance deallocation must be performed by calling ursa_bls_pop_free.
///
/// # Arguments
/// * `ver_key` - Ver key instance
/// * `sign_key` - Sign key instance
/// * `pop_p` - Reference that will contain proof of possession instance pointer
#[no_mangle]
pub extern "C" fn ursa_bls_pop_new(
    ver_key: *const c_void,
    sign_key: *const c_void,
    pop_p: *mut *const c_void,
) -> ErrorCode {
    trace!(
        "ursa_bls_pop_new: >>> ver_key: {:?}, sign_key: {:?}, pop_p: {:?}",
        ver_key,
        sign_key,
        pop_p
    );

    check_useful_c_reference!(ver_key, VerKey, ErrorCode::CommonInvalidParam1);
    check_useful_c_reference!(sign_key, SignKey, ErrorCode::CommonInvalidParam2);

    trace!(
        "ursa_bls_pop_new: ver_key: {:?}, sign_key: {:?}",
        ver_key,
        sign_key
    );

    let res = match ProofOfPossession::new(ver_key, sign_key) {
        Ok(pop) => {
            trace!("ursa_bls_pop_new: pop: {:?}", pop);
            unsafe {
                *pop_p = Box::into_raw(Box::new(pop)) as *const c_void;
                trace!("ursa_bls_pop_new: *pop_p: {:?}", *pop_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.into(),
    };

    trace!("ursa_bls_pop_new: <<< res: {:?}", res);
    res
}

/// Creates and returns proof of possession from bytes representation.
///
/// Note: Proof of possession instance deallocation must be performed by calling ursa_bls_pop_free
///
/// # Arguments
/// * `bytes` - Bytes buffer pointer
/// * `bytes_len` - Bytes buffer len
/// * `pop_p` - Reference that will contain proof of possession instance pointer
#[no_mangle]
pub extern "C" fn ursa_bls_pop_from_bytes(
    bytes: *const u8,
    bytes_len: usize,
    pop_p: *mut *const c_void,
) -> ErrorCode {
    trace!(
        "ursa_bls_pop_from_bytes: >>> bytes: {:?}, bytes_len: {:?}, gen_p: {:?}",
        bytes,
        bytes_len,
        pop_p
    );

    check_useful_c_byte_array!(
        bytes,
        bytes_len,
        ErrorCode::CommonInvalidParam1,
        ErrorCode::CommonInvalidParam2
    );
    check_useful_c_ptr!(pop_p, ErrorCode::CommonInvalidParam3);

    trace!("ursa_bls_pop_from_bytes: bytes: {:?}", bytes);

    let res = match ProofOfPossession::from_bytes(bytes) {
        Ok(pop) => {
            trace!("ursa_bls_pop_from_bytes: pop: {:?}", pop);
            unsafe {
                *pop_p = Box::into_raw(Box::new(pop)) as *const c_void;
                trace!("ursa_bls_pop_from_bytes: *pop_p: {:?}", *pop_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.into(),
    };

    trace!("ursa_bls_pop_from_bytes: <<< res: {:?}", res);
    res
}

/// Returns bytes representation of proof of possession.
///
/// Note: Returned buffer lifetime is the same as proof of possession instance.
///
/// # Arguments
/// * `pop` - Proof of possession instance pointer
/// * `bytes_p` - Pointer that will contains bytes buffer
/// * `bytes_len_p` - Pointer that will contains bytes buffer len
#[no_mangle]
pub extern "C" fn ursa_bls_pop_as_bytes(
    pop: *const c_void,
    bytes_p: *mut *const u8,
    bytes_len_p: *mut usize,
) -> ErrorCode {
    trace!(
        "ursa_bls_pop_as_bytes: >>> pop: {:?}, bytes_p: {:?}, bytes_len_p: {:?}",
        pop,
        bytes_p,
        bytes_len_p
    );

    check_useful_c_reference!(pop, ProofOfPossession, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(bytes_p, ErrorCode::CommonInvalidParam2);
    check_useful_c_ptr!(bytes_len_p, ErrorCode::CommonInvalidParam3);

    trace!("ursa_bls_pop_as_bytes: pop: {:?}", pop);

    unsafe {
        *bytes_p = pop.as_bytes().as_ptr();
        *bytes_len_p = pop.as_bytes().len();
    };

    let res = ErrorCode::Success;

    trace!("ursa_bls_pop_as_bytes: <<< res: {:?}", res);
    res
}

/// Deallocates proof of possession instance.
///
/// # Arguments
/// * `pop` - Proof of possession instance pointer
#[no_mangle]
pub extern "C" fn ursa_bls_pop_free(pop: *const c_void) -> ErrorCode {
    check_useful_c_ptr!(pop, ErrorCode::CommonInvalidParam1);

    trace!("ursa_bls_pop_free: >>> pop: {:?}", pop);

    unsafe {
        Box::from_raw(pop as *mut ProofOfPossession);
    }
    let res = ErrorCode::Success;

    trace!("ursa_bls_pop_free: <<< res: {:?}", res);
    res
}

/// Creates and returns signature from bytes representation.
///
/// Note: Signature instance deallocation must be performed by calling ursa_bls_signature_free
///
/// # Arguments
/// * `bytes` - Bytes buffer pointer
/// * `bytes_len` - Bytes buffer len
/// * `signature_p` - Reference that will contain signature instance pointer
#[no_mangle]
pub extern "C" fn ursa_bls_signature_from_bytes(
    bytes: *const u8,
    bytes_len: usize,
    signature_p: *mut *const c_void,
) -> ErrorCode {
    trace!(
        "ursa_bls_signature_from_bytes: >>> bytes: {:?}, bytes_len: {:?}, signature_p: {:?}",
        bytes,
        bytes_len,
        signature_p
    );

    check_useful_c_byte_array!(
        bytes,
        bytes_len,
        ErrorCode::CommonInvalidParam1,
        ErrorCode::CommonInvalidParam2
    );
    check_useful_c_ptr!(signature_p, ErrorCode::CommonInvalidParam1);

    trace!("ursa_bls_signature_from_bytes: bytes: {:?}", bytes);

    let res = match Signature::from_bytes(bytes) {
        Ok(signature) => {
            trace!("ursa_bls_signature_from_bytes: signature: {:?}", signature);
            unsafe {
                *signature_p = Box::into_raw(Box::new(signature)) as *const c_void;
                trace!(
                    "ursa_bls_signature_from_bytes: *signature_p: {:?}",
                    *signature_p
                );
            }
            ErrorCode::Success
        }
        Err(err) => err.into(),
    };

    trace!("ursa_bls_signature_from_bytes: <<< res: {:?}", res);
    res
}

/// Returns bytes representation of signature.
///
/// Note: Returned buffer lifetime is the same as signature instance.
///
/// # Arguments
/// * `signature` - Signature instance pointer
/// * `bytes_p` - Pointer that will contains bytes buffer
/// * `bytes_len_p` - Pointer that will contains bytes buffer len
#[no_mangle]
pub extern "C" fn ursa_bls_signature_as_bytes(
    signature: *const c_void,
    bytes_p: *mut *const u8,
    bytes_len_p: *mut usize,
) -> ErrorCode {
    trace!(
        "ursa_bls_signature_as_bytes: >>> signature: {:?}, bytes_p: {:?}, bytes_len_p: {:?}",
        signature,
        bytes_p,
        bytes_len_p
    );

    check_useful_c_reference!(signature, Signature, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(bytes_p, ErrorCode::CommonInvalidParam2);
    check_useful_c_ptr!(bytes_len_p, ErrorCode::CommonInvalidParam3);

    trace!("ursa_bls_signature_as_bytes: signature: {:?}", signature);

    unsafe {
        *bytes_p = signature.as_bytes().as_ptr();
        *bytes_len_p = signature.as_bytes().len();
    };

    let res = ErrorCode::Success;

    trace!("ursa_bls_signature_as_bytes: <<< res: {:?}", res);
    res
}

/// Deallocates signature instance.
///
/// # Arguments
/// * `signature` - Signature instance pointer
#[no_mangle]
pub extern "C" fn ursa_bls_signature_free(signature: *const c_void) -> ErrorCode {
    check_useful_c_ptr!(signature, ErrorCode::CommonInvalidParam1);

    trace!("ursa_bls_signature_free: >>> signature: {:?}", signature);

    unsafe {
        Box::from_raw(signature as *mut Signature);
    }
    let res = ErrorCode::Success;

    trace!("ursa_bls_signature_free: <<< res: {:?}", res);
    res
}

/// Creates and returns multi signature for provided list of signatures.
///
/// Note: Multi signature instance deallocation must be performed by calling ursa_bls_multi_signature_free.
///
/// # Arguments
/// * `signatures` - Signature instance pointers array
/// * `signatures_len` - Signature instance pointers array len
/// * `multi_sig_p` - Reference that will contain multi signature instance pointer
#[no_mangle]
pub extern "C" fn ursa_bls_multi_signature_new(
    signatures: *const *const c_void,
    signatures_len: usize,
    multi_sig_p: *mut *const c_void,
) -> ErrorCode {
    trace!("ursa_bls_multi_signature_new: >>> signatures: {:?}, signatures_len: {:?}, multi_sig_p: {:?}", signatures, signatures_len, multi_sig_p);

    check_useful_c_reference_array!(
        signatures,
        signatures_len,
        Signature,
        ErrorCode::CommonInvalidParam1,
        ErrorCode::CommonInvalidParam2
    );
    check_useful_c_ptr!(multi_sig_p, ErrorCode::CommonInvalidParam3);

    trace!("ursa_bls_multi_signature_new: signatures: {:?}", signatures);

    let res = match MultiSignature::new(&signatures) {
        Ok(multi_sig) => {
            trace!("ursa_bls_multi_signature_new: multi_sig: {:?}", multi_sig);
            unsafe {
                *multi_sig_p = Box::into_raw(Box::new(multi_sig)) as *const c_void;
                trace!(
                    "ursa_bls_multi_signature_new: *multi_sig_p: {:?}",
                    *multi_sig_p
                );
            }
            ErrorCode::Success
        }
        Err(err) => err.into(),
    };

    trace!("ursa_bls_multi_signature_new: <<< res: {:?}", res);
    res
}

/// Creates and returns multi signature from bytes representation.
///
/// Note: Multi signature instance deallocation must be performed by calling ursa_bls_multi_signature_free
///
/// # Arguments
/// * `bytes` - Bytes buffer pointer
/// * `bytes_len` - Bytes buffer len
/// * `multi_sig_p` - Reference that will contain multi signature instance pointer
#[no_mangle]
pub extern "C" fn ursa_bls_multi_signature_from_bytes(
    bytes: *const u8,
    bytes_len: usize,
    multi_sig_p: *mut *const c_void,
) -> ErrorCode {
    trace!(
        "ursa_bls_multi_signature_from_bytes: >>> bytes: {:?}, bytes_len: {:?}, multi_sig_p: {:?}",
        bytes,
        bytes_len,
        multi_sig_p
    );

    check_useful_c_byte_array!(
        bytes,
        bytes_len,
        ErrorCode::CommonInvalidParam1,
        ErrorCode::CommonInvalidParam2
    );
    check_useful_c_ptr!(multi_sig_p, ErrorCode::CommonInvalidParam1);

    trace!("ursa_bls_multi_signature_from_bytes: bytes: {:?}", bytes);

    let res = match MultiSignature::from_bytes(bytes) {
        Ok(multi_sig) => {
            trace!(
                "ursa_bls_multi_signature_from_bytes: multi_sig: {:?}",
                multi_sig
            );
            unsafe {
                *multi_sig_p = Box::into_raw(Box::new(multi_sig)) as *const c_void;
                trace!(
                    "ursa_bls_multi_signature_from_bytes: *multi_sig_p: {:?}",
                    *multi_sig_p
                );
            }
            ErrorCode::Success
        }
        Err(err) => err.into(),
    };

    trace!("ursa_bls_multi_signature_from_bytes: <<< res: {:?}", res);
    res
}

/// Returns bytes representation of multi signature.
///
/// Note: Returned buffer lifetime is the same as multi signature instance.
///
/// # Arguments
/// * `multi_sig` - Multi signature instance pointer
/// * `bytes_p` - Pointer that will contains bytes buffer
/// * `bytes_len_p` - Pointer that will contains bytes buffer len
#[no_mangle]
pub extern "C" fn ursa_bls_multi_signature_as_bytes(
    multi_sig: *const c_void,
    bytes_p: *mut *const u8,
    bytes_len_p: *mut usize,
) -> ErrorCode {
    trace!(
        "ursa_bls_multi_signature_as_bytes: >>> multi_sig: {:?}, bytes_p: {:?}, bytes_len_p: {:?}",
        multi_sig,
        bytes_p,
        bytes_len_p
    );

    check_useful_c_ptr!(multi_sig, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(bytes_p, ErrorCode::CommonInvalidParam2);
    check_useful_c_ptr!(bytes_len_p, ErrorCode::CommonInvalidParam3);

    let multi_sig = unsafe { &*(multi_sig as *const MultiSignature) };
    trace!(
        "ursa_bls_multi_signature_as_bytes: multi_sig: {:?}",
        multi_sig
    );

    unsafe {
        *bytes_p = multi_sig.as_bytes().as_ptr();
        *bytes_len_p = multi_sig.as_bytes().len();
    };

    let res = ErrorCode::Success;

    trace!("ursa_bls_multi_signature_as_bytes: <<< res: {:?}", res);
    res
}

/// Deallocates multi signature instance.
///
/// # Arguments
/// * `multi_sig` - Multi signature instance pointer
#[no_mangle]
pub extern "C" fn ursa_bls_multi_signature_free(multi_sig: *const c_void) -> ErrorCode {
    check_useful_c_ptr!(multi_sig, ErrorCode::CommonInvalidParam1);

    trace!(
        "ursa_bls_multi_signature_free: >>> multi_sig: {:?}",
        multi_sig
    );

    unsafe {
        Box::from_raw(multi_sig as *mut MultiSignature);
    }
    let res = ErrorCode::Success;

    trace!("ursa_bls_multi_signature_free: <<< res: {:?}", res);
    res
}

/// Signs the message and returns signature.
///
/// Note: allocated buffer referenced by (signature_p, signature_len_p) must be
/// deallocated by calling ursa_bls_free_array.
///
/// # Arguments
///
/// * `message` - Message to sign buffer pointer
/// * `message_len` - Message to sign buffer len
/// * `sign_key` - Pointer to Sign Key instance
/// * `signature_p` - Reference that will contain Signture Instance pointer
#[no_mangle]
pub extern "C" fn ursa_bls_sign(
    message: *const u8,
    message_len: usize,
    sign_key: *const c_void,
    signature_p: *mut *const c_void,
) -> ErrorCode {
    trace!(
        "ursa_bls_sign: >>> message: {:?}, message_len: {:?}, sign_key: {:?}, signature_p: {:?}",
        message,
        message_len,
        sign_key,
        signature_p
    );

    check_useful_c_byte_array!(
        message,
        message_len,
        ErrorCode::CommonInvalidParam1,
        ErrorCode::CommonInvalidParam2
    );
    check_useful_c_reference!(sign_key, SignKey, ErrorCode::CommonInvalidParam3);
    check_useful_c_ptr!(signature_p, ErrorCode::CommonInvalidParam5);

    trace!(
        "ursa_bls_sign: message: {:?}, sign_key: {:?}",
        message,
        secret!(sign_key)
    );

    let res = match Bls::sign(message, sign_key) {
        Ok(signature) => {
            unsafe {
                trace!("ursa_bls_sign: signature: {:?}", signature);
                *signature_p = Box::into_raw(Box::new(signature)) as *const c_void;
                trace!("ursa_bls_sign: *signature_p: {:?}", *signature_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.into(),
    };

    trace!("ursa_bls_sign: <<< res: {:?}", res);
    res
}

/// Verifies the message signature and returns true - if signature valid or false otherwise.
///
/// # Arguments
///
/// * `signature` - Signature instance pointer
/// * `message` - Message to verify buffer pointer
/// * `message_len` - Message to verify buffer len
/// * `ver_key` - Verification key instance pinter
/// * `gen` - Generator instance pointer
/// * `valid_p` - Reference that will be filled with true - if signature valid or false otherwise.
#[no_mangle]
pub extern "C" fn ursa_bls_verify(
    signature: *const c_void,
    message: *const u8,
    message_len: usize,
    ver_key: *const c_void,
    gen: *const c_void,
    valid_p: *mut bool,
) -> ErrorCode {
    trace!("ursa_bls_verify: >>> signature: {:?}, message: {:?}, message_len: {:?}, ver_key: {:?}, gen: {:?}, valid_p: {:?}", signature, message, message_len, ver_key, gen, valid_p);

    check_useful_c_reference!(signature, Signature, ErrorCode::CommonInvalidParam1);
    check_useful_c_byte_array!(
        message,
        message_len,
        ErrorCode::CommonInvalidParam2,
        ErrorCode::CommonInvalidParam3
    );
    check_useful_c_reference!(ver_key, VerKey, ErrorCode::CommonInvalidParam4);
    check_useful_c_reference!(gen, Generator, ErrorCode::CommonInvalidParam5);
    check_useful_c_ptr!(valid_p, ErrorCode::CommonInvalidParam6);

    trace!(
        "ursa_bls_verify: signature: {:?}, message: {:?}, ver_key: {:?}, gen: {:?}",
        signature,
        message,
        ver_key,
        gen
    );

    let res = match Bls::verify(signature, message, ver_key, gen) {
        Ok(valid) => {
            trace!("ursa_bls_verify: valid: {:?}", valid);
            unsafe {
                *valid_p = valid;
            }
            ErrorCode::Success
        }
        Err(err) => err.into(),
    };

    trace!("ursa_bls_verify: <<< res: {:?}", res);
    res
}

/// Verifies the message multi signature and returns true - if signature valid or false otherwise.
///
/// # Arguments
///
/// * `multi_sig` - Multi signature instance pointer
/// * `message` - Message to verify buffer pointer
/// * `message_len` - Message to verify buffer len
/// * `ver_keys` - Verification key instance pointers array
/// * `ver_keys_len` - Verification keys instance pointers array len
/// * `gen` - Generator point instance
/// * `valid_p` - Reference that will be filled with true - if signature valid or false otherwise.
#[no_mangle]
pub extern "C" fn ursa_bls_verify_multi_sig(
    multi_sig: *const c_void,
    message: *const u8,
    message_len: usize,
    ver_keys: *const *const c_void,
    ver_keys_len: usize,
    gen: *const c_void,
    valid_p: *mut bool,
) -> ErrorCode {
    trace!("ursa_bls_verify_multi_sig: >>> multi_sig: {:?}, message: {:?}, message_len: {:?}, ver_keys: {:?}, ver_keys_len: {:?}, gen: {:?}, valid_p: {:?}", multi_sig, message, message_len, ver_keys, ver_keys_len, gen, valid_p);

    check_useful_c_reference!(multi_sig, MultiSignature, ErrorCode::CommonInvalidParam1);
    check_useful_c_byte_array!(
        message,
        message_len,
        ErrorCode::CommonInvalidParam2,
        ErrorCode::CommonInvalidParam3
    );
    check_useful_c_reference_array!(
        ver_keys,
        ver_keys_len,
        VerKey,
        ErrorCode::CommonInvalidParam4,
        ErrorCode::CommonInvalidParam5
    );
    check_useful_c_reference!(gen, Generator, ErrorCode::CommonInvalidParam6);
    check_useful_c_ptr!(valid_p, ErrorCode::CommonInvalidParam7);

    trace!(
        "ursa_bls_verify_multi_sig: multi_sig: {:?}, message: {:?}, ver_keys: {:?}, gen: {:?}",
        multi_sig,
        message,
        ver_keys,
        gen
    );

    let res = match Bls::verify_multi_sig(multi_sig, message, &ver_keys, gen) {
        Ok(valid) => {
            trace!("ursa_bls_verify_multi_sig: valid: {:?}", valid);
            unsafe {
                *valid_p = valid;
            }
            ErrorCode::Success
        }
        Err(err) => err.into(),
    };

    trace!("ursa_bls_verify_multi_sig: <<< res: {:?}", res);
    res
}

/// Verifies the proof of possession and returns true - if signature valid or false otherwise.
///
/// # Arguments
///
/// * `pop` - Proof of possession
/// * `ver_key` - Verification key instance pinter
/// * `gen` - Generator instance pointer
/// * `valid_p` - Reference that will be filled with true - if signature valid or false otherwise.
#[no_mangle]
pub extern "C" fn ursa_bls_verify_pop(
    pop: *const c_void,
    ver_key: *const c_void,
    gen: *const c_void,
    valid_p: *mut bool,
) -> ErrorCode {
    trace!(
        "ursa_bls_verify_pop: >>> pop: {:?}, ver_key: {:?}, gen: {:?}, valid_p: {:?}",
        pop,
        ver_key,
        gen,
        valid_p
    );

    check_useful_c_reference!(pop, ProofOfPossession, ErrorCode::CommonInvalidParam1);
    check_useful_c_reference!(ver_key, VerKey, ErrorCode::CommonInvalidParam2);
    check_useful_c_reference!(gen, Generator, ErrorCode::CommonInvalidParam3);
    check_useful_c_ptr!(valid_p, ErrorCode::CommonInvalidParam4);

    trace!(
        "ursa_bls_verify_pop: pop: {:?}, ver_key: {:?}, gen: {:?}",
        pop,
        ver_key,
        gen
    );

    let res = match Bls::verify_proof_of_posession(pop, ver_key, gen) {
        Ok(valid) => {
            trace!("ursa_bls_verify_pop: valid: {:?}", valid);
            unsafe {
                *valid_p = valid;
            }
            ErrorCode::Success
        }
        Err(err) => err.into(),
    };

    trace!("ursa_bls_verify_pop: <<< res: {:?}", res);
    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;

    #[test]
    fn ursa_bls_generator_new_works() {
        let mut gen: *const c_void = ptr::null();

        let err_code = ursa_bls_generator_new(&mut gen);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!gen.is_null());

        let err_code = ursa_bls_generator_free(gen);
        assert_eq!(err_code, ErrorCode::Success);
    }

    #[test]
    fn ursa_bls_generator_as_bytes_works() {
        let mut gen: *const c_void = ptr::null();
        let err_code = ursa_bls_generator_new(&mut gen);
        assert_eq!(err_code, ErrorCode::Success);

        let mut bytes: *const u8 = ptr::null();
        let mut bytes_len: usize = 0;
        let err_code = ursa_bls_generator_as_bytes(gen, &mut bytes, &mut bytes_len);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!gen.is_null());
        assert!(bytes_len > 0);

        let err_code = ursa_bls_generator_free(gen);
        assert_eq!(err_code, ErrorCode::Success);
    }

    #[test]
    fn ursa_bls_generator_from_bytes_works() {
        let mut gen: *const c_void = ptr::null();
        let err_code = ursa_bls_generator_new(&mut gen);
        assert_eq!(err_code, ErrorCode::Success);

        let mut bytes: *const u8 = ptr::null();
        let mut bytes_len: usize = 0;
        let err_code = ursa_bls_generator_as_bytes(gen, &mut bytes, &mut bytes_len);
        assert_eq!(err_code, ErrorCode::Success);

        let mut gen2: *const c_void = ptr::null();
        let err_code = ursa_bls_generator_from_bytes(bytes, bytes_len, &mut gen2);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_generator_free(gen);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_generator_free(gen2);
        assert_eq!(err_code, ErrorCode::Success);
    }

    #[test]
    fn ursa_bls_generator_free_works() {
        let mut gen: *const c_void = ptr::null();

        let err_code = ursa_bls_generator_new(&mut gen);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!gen.is_null());

        let err_code = ursa_bls_generator_free(gen);
        assert_eq!(err_code, ErrorCode::Success);
    }

    #[test]
    fn ursa_bls_sign_key_new_works() {
        let mut sign_key: *const c_void = ptr::null();
        let seed: *const u8 = ptr::null();
        let seed_len: usize = 0;

        let err_code = ursa_bls_sign_key_new(seed, seed_len, &mut sign_key);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!sign_key.is_null());

        let err_code = ursa_bls_sign_key_free(sign_key);
        assert_eq!(err_code, ErrorCode::Success);
    }

    #[test]
    fn ursa_bls_sign_key_new_works_for_seed() {
        let mut sign_key: *const c_void = ptr::null();

        let seed_v = vec![
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 2, 3, 4, 5, 6, 7, 8, 9, 10, 21, 2, 3, 4, 5, 6, 7, 8,
            9, 10, 31, 32,
        ];
        let seed = seed_v.as_ptr();
        let seed_len = seed_v.len();

        let err_code = ursa_bls_sign_key_new(seed, seed_len, &mut sign_key);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!sign_key.is_null());

        let err_code = ursa_bls_sign_key_free(sign_key);
        assert_eq!(err_code, ErrorCode::Success);
    }

    #[test]
    fn ursa_bls_sign_key_as_bytes_works() {
        let mut sign_key: *const c_void = ptr::null();
        let seed: *const u8 = ptr::null();
        let seed_len: usize = 0;
        let err_code = ursa_bls_sign_key_new(seed, seed_len, &mut sign_key);
        assert_eq!(err_code, ErrorCode::Success);

        let mut bytes: *const u8 = ptr::null();
        let mut bytes_len: usize = 0;
        let err_code = ursa_bls_sign_key_as_bytes(sign_key, &mut bytes, &mut bytes_len);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!bytes.is_null());
        assert!(bytes_len > 0);

        let err_code = ursa_bls_sign_key_free(sign_key);
        assert_eq!(err_code, ErrorCode::Success);
    }

    #[test]
    fn ursa_bls_sign_key_from_bytes_works() {
        let mut sign_key: *const c_void = ptr::null();
        let seed: *const u8 = ptr::null();
        let seed_len: usize = 0;
        let err_code = ursa_bls_sign_key_new(seed, seed_len, &mut sign_key);
        assert_eq!(err_code, ErrorCode::Success);

        let mut bytes: *const u8 = ptr::null();
        let mut bytes_len: usize = 0;
        let err_code = ursa_bls_sign_key_as_bytes(sign_key, &mut bytes, &mut bytes_len);
        assert_eq!(err_code, ErrorCode::Success);

        let mut sign_key2: *const c_void = ptr::null();
        let err_code = ursa_bls_sign_key_from_bytes(bytes, bytes_len, &mut sign_key2);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_sign_key_free(sign_key);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_sign_key_free(sign_key2);
        assert_eq!(err_code, ErrorCode::Success);
    }

    #[test]
    fn ursa_bls_sign_key_free_works() {
        let mut sign_key: *const c_void = ptr::null();
        let seed: *const u8 = ptr::null();
        let seed_len: usize = 0;
        let err_code = ursa_bls_sign_key_new(seed, seed_len, &mut sign_key);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_sign_key_free(sign_key);
        assert_eq!(err_code, ErrorCode::Success);
    }

    #[test]
    fn ursa_bls_ver_key_new_works() {
        let mut gen: *const c_void = ptr::null();
        let err_code = ursa_bls_generator_new(&mut gen);
        assert_eq!(err_code, ErrorCode::Success);

        let mut sign_key: *const c_void = ptr::null();
        let seed: *const u8 = ptr::null();
        let seed_len: usize = 0;
        let err_code = ursa_bls_sign_key_new(seed, seed_len, &mut sign_key);
        assert_eq!(err_code, ErrorCode::Success);

        let mut ver_key: *const c_void = ptr::null();
        let err_code = ursa_bls_ver_key_new(gen, sign_key, &mut ver_key);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!ver_key.is_null());

        let err_code = ursa_bls_generator_free(gen);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_sign_key_free(sign_key);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_ver_key_free(ver_key);
        assert_eq!(err_code, ErrorCode::Success);
    }

    #[test]
    fn ursa_bls_ver_key_as_bytes_works() {
        let mut gen: *const c_void = ptr::null();
        let err_code = ursa_bls_generator_new(&mut gen);
        assert_eq!(err_code, ErrorCode::Success);

        let mut sign_key: *const c_void = ptr::null();
        let seed: *const u8 = ptr::null();
        let seed_len: usize = 0;
        let err_code = ursa_bls_sign_key_new(seed, seed_len, &mut sign_key);
        assert_eq!(err_code, ErrorCode::Success);

        let mut ver_key: *const c_void = ptr::null();
        let err_code = ursa_bls_ver_key_new(gen, sign_key, &mut ver_key);
        assert_eq!(err_code, ErrorCode::Success);

        let mut bytes: *const u8 = ptr::null();
        let mut bytes_len: usize = 0;
        let err_code = ursa_bls_ver_key_as_bytes(ver_key, &mut bytes, &mut bytes_len);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!bytes.is_null());
        assert!(bytes_len > 0);

        let err_code = ursa_bls_generator_free(gen);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_sign_key_free(sign_key);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_ver_key_free(ver_key);
        assert_eq!(err_code, ErrorCode::Success);
    }

    #[test]
    fn ursa_bls_ver_key_from_bytes_works() {
        let mut gen: *const c_void = ptr::null();
        let err_code = ursa_bls_generator_new(&mut gen);
        assert_eq!(err_code, ErrorCode::Success);

        let mut sign_key: *const c_void = ptr::null();
        let seed: *const u8 = ptr::null();
        let seed_len: usize = 0;
        let err_code = ursa_bls_sign_key_new(seed, seed_len, &mut sign_key);
        assert_eq!(err_code, ErrorCode::Success);

        let mut ver_key: *const c_void = ptr::null();
        let err_code = ursa_bls_ver_key_new(gen, sign_key, &mut ver_key);
        assert_eq!(err_code, ErrorCode::Success);

        let mut bytes: *const u8 = ptr::null();
        let mut bytes_len: usize = 0;
        let err_code = ursa_bls_ver_key_as_bytes(ver_key, &mut bytes, &mut bytes_len);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!bytes.is_null());
        assert!(bytes_len > 0);

        let mut ver_key2: *const c_void = ptr::null();
        let err_code = ursa_bls_ver_key_from_bytes(bytes, bytes_len, &mut ver_key2);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_generator_free(gen);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_sign_key_free(sign_key);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_ver_key_free(ver_key);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_ver_key_free(ver_key2);
        assert_eq!(err_code, ErrorCode::Success);
    }

    #[test]
    fn ursa_bls_ver_key_free_works() {
        let mut gen: *const c_void = ptr::null();
        let err_code = ursa_bls_generator_new(&mut gen);
        assert_eq!(err_code, ErrorCode::Success);

        let mut sign_key: *const c_void = ptr::null();
        let seed: *const u8 = ptr::null();
        let seed_len: usize = 0;
        let err_code = ursa_bls_sign_key_new(seed, seed_len, &mut sign_key);
        assert_eq!(err_code, ErrorCode::Success);

        let mut ver_key: *const c_void = ptr::null();
        let err_code = ursa_bls_ver_key_new(gen, sign_key, &mut ver_key);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_generator_free(gen);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_sign_key_free(sign_key);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_ver_key_free(ver_key);
        assert_eq!(err_code, ErrorCode::Success);
    }

    #[test]
    fn ursa_bls_signature_as_bytes_works() {
        let mut sign_key: *const c_void = ptr::null();
        let seed: *const u8 = ptr::null();
        let seed_len: usize = 0;
        let err_code = ursa_bls_sign_key_new(seed, seed_len, &mut sign_key);
        assert_eq!(err_code, ErrorCode::Success);

        let message_v = vec![1, 2, 3, 4, 5];
        let message = message_v.as_ptr();
        let message_len = message_v.len();

        let mut signature: *const c_void = ptr::null();
        let err_code = ursa_bls_sign(message, message_len, sign_key, &mut signature);
        assert_eq!(err_code, ErrorCode::Success);

        let mut bytes: *const u8 = ptr::null();
        let mut bytes_len: usize = 0;
        let err_code = ursa_bls_signature_as_bytes(signature, &mut bytes, &mut bytes_len);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!bytes.is_null());
        assert!(bytes_len > 0);

        let err_code = ursa_bls_sign_key_free(sign_key);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_signature_free(signature);
        assert_eq!(err_code, ErrorCode::Success);
    }

    #[test]
    fn ursa_bls_signature_from_bytes_works() {
        let mut sign_key: *const c_void = ptr::null();
        let seed: *const u8 = ptr::null();
        let seed_len: usize = 0;
        let err_code = ursa_bls_sign_key_new(seed, seed_len, &mut sign_key);
        assert_eq!(err_code, ErrorCode::Success);

        let message_v = vec![1, 2, 3, 4, 5];
        let message = message_v.as_ptr();
        let message_len = message_v.len();

        let mut signature: *const c_void = ptr::null();
        let err_code = ursa_bls_sign(message, message_len, sign_key, &mut signature);
        assert_eq!(err_code, ErrorCode::Success);

        let mut bytes: *const u8 = ptr::null();
        let mut bytes_len: usize = 0;
        let err_code = ursa_bls_signature_as_bytes(signature, &mut bytes, &mut bytes_len);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!bytes.is_null());
        assert!(bytes_len > 0);

        let mut signature2: *const c_void = ptr::null();
        let err_code = ursa_bls_signature_from_bytes(bytes, bytes_len, &mut signature2);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_sign_key_free(sign_key);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_signature_free(signature);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_signature_free(signature2);
        assert_eq!(err_code, ErrorCode::Success);
    }

    #[test]
    fn ursa_bls_signature_free_works() {
        let mut sign_key: *const c_void = ptr::null();
        let seed: *const u8 = ptr::null();
        let seed_len: usize = 0;
        let err_code = ursa_bls_sign_key_new(seed, seed_len, &mut sign_key);
        assert_eq!(err_code, ErrorCode::Success);

        let message_v = vec![1, 2, 3, 4, 5];
        let message = message_v.as_ptr();
        let message_len = message_v.len();

        let mut signature: *const c_void = ptr::null();
        let err_code = ursa_bls_sign(message, message_len, sign_key, &mut signature);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_sign_key_free(sign_key);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_signature_free(signature);
        assert_eq!(err_code, ErrorCode::Success);
    }

    #[test]
    fn ursa_bls_multi_signature_new_works() {
        let mut sign_key1: *const c_void = ptr::null();
        let seed: *const u8 = ptr::null();
        let seed_len: usize = 0;
        let err_code = ursa_bls_sign_key_new(seed, seed_len, &mut sign_key1);
        assert_eq!(err_code, ErrorCode::Success);

        let mut sign_key2: *const c_void = ptr::null();
        let seed: *const u8 = ptr::null();
        let seed_len: usize = 0;
        let err_code = ursa_bls_sign_key_new(seed, seed_len, &mut sign_key2);
        assert_eq!(err_code, ErrorCode::Success);

        let message_v = vec![1, 2, 3, 4, 5];
        let message = message_v.as_ptr();
        let message_len = message_v.len();

        let mut signature1: *const c_void = ptr::null();
        let err_code = ursa_bls_sign(message, message_len, sign_key1, &mut signature1);
        assert_eq!(err_code, ErrorCode::Success);

        let mut signature2: *const c_void = ptr::null();
        let err_code = ursa_bls_sign(message, message_len, sign_key2, &mut signature2);
        assert_eq!(err_code, ErrorCode::Success);

        let signatures = [signature1, signature2];

        let mut multi_sig: *const c_void = ptr::null();
        let err_code =
            ursa_bls_multi_signature_new(signatures.as_ptr(), signatures.len(), &mut multi_sig);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!multi_sig.is_null());

        let err_code = ursa_bls_sign_key_free(sign_key1);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_sign_key_free(sign_key2);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_signature_free(signature1);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_signature_free(signature2);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_multi_signature_free(multi_sig);
        assert_eq!(err_code, ErrorCode::Success);
    }

    #[test]
    fn ursa_bls_multi_signature_as_bytes_works() {
        let mut sign_key1: *const c_void = ptr::null();
        let seed: *const u8 = ptr::null();
        let seed_len: usize = 0;
        let err_code = ursa_bls_sign_key_new(seed, seed_len, &mut sign_key1);
        assert_eq!(err_code, ErrorCode::Success);

        let mut sign_key2: *const c_void = ptr::null();
        let seed: *const u8 = ptr::null();
        let seed_len: usize = 0;
        let err_code = ursa_bls_sign_key_new(seed, seed_len, &mut sign_key2);
        assert_eq!(err_code, ErrorCode::Success);

        let message_v = vec![1, 2, 3, 4, 5];
        let message = message_v.as_ptr();
        let message_len = message_v.len();

        let mut signature1: *const c_void = ptr::null();
        let err_code = ursa_bls_sign(message, message_len, sign_key1, &mut signature1);
        assert_eq!(err_code, ErrorCode::Success);

        let mut signature2: *const c_void = ptr::null();
        let err_code = ursa_bls_sign(message, message_len, sign_key2, &mut signature2);
        assert_eq!(err_code, ErrorCode::Success);

        let signatures = [signature1, signature2];

        let mut multi_sig: *const c_void = ptr::null();
        let err_code =
            ursa_bls_multi_signature_new(signatures.as_ptr(), signatures.len(), &mut multi_sig);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!multi_sig.is_null());

        let mut bytes: *const u8 = ptr::null();
        let mut bytes_len: usize = 0;
        let err_code = ursa_bls_multi_signature_as_bytes(multi_sig, &mut bytes, &mut bytes_len);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!bytes.is_null());
        assert!(bytes_len > 0);

        let err_code = ursa_bls_sign_key_free(sign_key1);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_sign_key_free(sign_key2);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_signature_free(signature1);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_signature_free(signature2);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_multi_signature_free(multi_sig);
        assert_eq!(err_code, ErrorCode::Success);
    }

    #[test]
    fn ursa_bls_multi_signature_from_bytes_works() {
        let mut sign_key1: *const c_void = ptr::null();
        let seed: *const u8 = ptr::null();
        let seed_len: usize = 0;
        let err_code = ursa_bls_sign_key_new(seed, seed_len, &mut sign_key1);
        assert_eq!(err_code, ErrorCode::Success);

        let mut sign_key2: *const c_void = ptr::null();
        let seed: *const u8 = ptr::null();
        let seed_len: usize = 0;
        let err_code = ursa_bls_sign_key_new(seed, seed_len, &mut sign_key2);
        assert_eq!(err_code, ErrorCode::Success);

        let message_v = vec![1, 2, 3, 4, 5];
        let message = message_v.as_ptr();
        let message_len = message_v.len();

        let mut signature1: *const c_void = ptr::null();
        let err_code = ursa_bls_sign(message, message_len, sign_key1, &mut signature1);
        assert_eq!(err_code, ErrorCode::Success);

        let mut signature2: *const c_void = ptr::null();
        let err_code = ursa_bls_sign(message, message_len, sign_key2, &mut signature2);
        assert_eq!(err_code, ErrorCode::Success);

        let signatures = [signature1, signature2];

        let mut multi_sig: *const c_void = ptr::null();
        let err_code =
            ursa_bls_multi_signature_new(signatures.as_ptr(), signatures.len(), &mut multi_sig);
        assert_eq!(err_code, ErrorCode::Success);

        let mut bytes: *const u8 = ptr::null();
        let mut bytes_len: usize = 0;
        let err_code = ursa_bls_multi_signature_as_bytes(multi_sig, &mut bytes, &mut bytes_len);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!bytes.is_null());
        assert!(bytes_len > 0);

        let mut multi_sig2: *const c_void = ptr::null();
        let err_code = ursa_bls_multi_signature_from_bytes(bytes, bytes_len, &mut multi_sig2);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!multi_sig2.is_null());

        let err_code = ursa_bls_sign_key_free(sign_key1);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_sign_key_free(sign_key2);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_signature_free(signature1);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_signature_free(signature2);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_multi_signature_free(multi_sig);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_multi_signature_free(multi_sig2);
        assert_eq!(err_code, ErrorCode::Success);
    }

    #[test]
    fn ursa_bls_multi_signature_free_works() {
        let mut sign_key1: *const c_void = ptr::null();
        let seed: *const u8 = ptr::null();
        let seed_len: usize = 0;
        let err_code = ursa_bls_sign_key_new(seed, seed_len, &mut sign_key1);
        assert_eq!(err_code, ErrorCode::Success);

        let mut sign_key2: *const c_void = ptr::null();
        let seed: *const u8 = ptr::null();
        let seed_len: usize = 0;
        let err_code = ursa_bls_sign_key_new(seed, seed_len, &mut sign_key2);
        assert_eq!(err_code, ErrorCode::Success);

        let message_v = vec![1, 2, 3, 4, 5];
        let message = message_v.as_ptr();
        let message_len = message_v.len();

        let mut signature1: *const c_void = ptr::null();
        let err_code = ursa_bls_sign(message, message_len, sign_key1, &mut signature1);
        assert_eq!(err_code, ErrorCode::Success);

        let mut signature2: *const c_void = ptr::null();
        let err_code = ursa_bls_sign(message, message_len, sign_key2, &mut signature2);
        assert_eq!(err_code, ErrorCode::Success);

        let signatures = [signature1, signature2];

        let mut multi_sig: *const c_void = ptr::null();
        let err_code =
            ursa_bls_multi_signature_new(signatures.as_ptr(), signatures.len(), &mut multi_sig);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_sign_key_free(sign_key1);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_sign_key_free(sign_key2);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_signature_free(signature1);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_signature_free(signature2);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_multi_signature_free(multi_sig);
        assert_eq!(err_code, ErrorCode::Success);
    }

    #[test]
    fn ursa_bls_verify_works() {
        let mut gen: *const c_void = ptr::null();
        let err_code = ursa_bls_generator_new(&mut gen);
        assert_eq!(err_code, ErrorCode::Success);

        let mut sign_key: *const c_void = ptr::null();
        let seed: *const u8 = ptr::null();
        let seed_len: usize = 0;
        let err_code = ursa_bls_sign_key_new(seed, seed_len, &mut sign_key);
        assert_eq!(err_code, ErrorCode::Success);

        let mut ver_key: *const c_void = ptr::null();
        let err_code = ursa_bls_ver_key_new(gen, sign_key, &mut ver_key);
        assert_eq!(err_code, ErrorCode::Success);

        let message_v = vec![1, 2, 3, 4, 5];
        let message = message_v.as_ptr();
        let message_len = message_v.len();

        let mut signature: *const c_void = ptr::null();
        let err_code = ursa_bls_sign(message, message_len, sign_key, &mut signature);
        assert_eq!(err_code, ErrorCode::Success);

        let mut valid = false;

        let err_code = ursa_bls_verify(signature, message, message_len, ver_key, gen, &mut valid);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(valid);

        let err_code = ursa_bls_generator_free(gen);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_sign_key_free(sign_key);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_ver_key_free(ver_key);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_signature_free(signature);
        assert_eq!(err_code, ErrorCode::Success);
    }

    #[test]
    fn ursa_bls_verify_works_for_invalid() {
        let mut gen: *const c_void = ptr::null();
        let err_code = ursa_bls_generator_new(&mut gen);
        assert_eq!(err_code, ErrorCode::Success);

        let mut sign_key: *const c_void = ptr::null();
        let seed: *const u8 = ptr::null();
        let seed_len: usize = 0;
        let err_code = ursa_bls_sign_key_new(seed, seed_len, &mut sign_key);
        assert_eq!(err_code, ErrorCode::Success);

        let mut sign_key2: *const c_void = ptr::null();
        let seed: *const u8 = ptr::null();
        let seed_len: usize = 0;
        let err_code = ursa_bls_sign_key_new(seed, seed_len, &mut sign_key2);
        assert_eq!(err_code, ErrorCode::Success);

        let mut ver_key: *const c_void = ptr::null();
        let err_code = ursa_bls_ver_key_new(gen, sign_key2, &mut ver_key);
        assert_eq!(err_code, ErrorCode::Success);

        let message_v = vec![1, 2, 3, 4, 5];
        let message = message_v.as_ptr();
        let message_len = message_v.len();

        let mut signature: *const c_void = ptr::null();
        let err_code = ursa_bls_sign(message, message_len, sign_key, &mut signature);
        assert_eq!(err_code, ErrorCode::Success);

        let mut valid = false;

        let err_code = ursa_bls_verify(signature, message, message_len, ver_key, gen, &mut valid);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!valid);

        let err_code = ursa_bls_generator_free(gen);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_sign_key_free(sign_key);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_sign_key_free(sign_key2);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_ver_key_free(ver_key);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_signature_free(signature);
        assert_eq!(err_code, ErrorCode::Success);
    }

    #[test]
    fn ursa_bls_pop_new_works() {
        let mut gen: *const c_void = ptr::null();
        let err_code = ursa_bls_generator_new(&mut gen);
        assert_eq!(err_code, ErrorCode::Success);

        let mut sign_key: *const c_void = ptr::null();
        let seed: *const u8 = ptr::null();
        let seed_len: usize = 0;
        let err_code = ursa_bls_sign_key_new(seed, seed_len, &mut sign_key);
        assert_eq!(err_code, ErrorCode::Success);

        let mut ver_key: *const c_void = ptr::null();
        let err_code = ursa_bls_ver_key_new(gen, sign_key, &mut ver_key);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!ver_key.is_null());

        let mut pop: *const c_void = ptr::null();
        let err_code = ursa_bls_pop_new(ver_key, sign_key, &mut pop);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!pop.is_null());

        let err_code = ursa_bls_generator_free(gen);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_sign_key_free(sign_key);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_ver_key_free(ver_key);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_pop_free(pop);
        assert_eq!(err_code, ErrorCode::Success);
    }

    #[test]
    fn ursa_bls_pop_as_bytes_works() {
        let mut gen: *const c_void = ptr::null();
        let err_code = ursa_bls_generator_new(&mut gen);
        assert_eq!(err_code, ErrorCode::Success);

        let mut sign_key: *const c_void = ptr::null();
        let seed: *const u8 = ptr::null();
        let seed_len: usize = 0;
        let err_code = ursa_bls_sign_key_new(seed, seed_len, &mut sign_key);
        assert_eq!(err_code, ErrorCode::Success);

        let mut ver_key: *const c_void = ptr::null();
        let err_code = ursa_bls_ver_key_new(gen, sign_key, &mut ver_key);
        assert_eq!(err_code, ErrorCode::Success);

        let mut pop: *const c_void = ptr::null();
        let err_code = ursa_bls_pop_new(ver_key, sign_key, &mut pop);
        assert_eq!(err_code, ErrorCode::Success);

        let mut bytes: *const u8 = ptr::null();
        let mut bytes_len: usize = 0;
        let err_code = ursa_bls_pop_as_bytes(pop, &mut bytes, &mut bytes_len);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!bytes.is_null());
        assert!(bytes_len > 0);

        let err_code = ursa_bls_generator_free(gen);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_sign_key_free(sign_key);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_ver_key_free(ver_key);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_pop_free(pop);
        assert_eq!(err_code, ErrorCode::Success);
    }

    #[test]
    fn ursa_bls_pop_from_bytes_works() {
        let mut gen: *const c_void = ptr::null();
        let err_code = ursa_bls_generator_new(&mut gen);
        assert_eq!(err_code, ErrorCode::Success);

        let mut sign_key: *const c_void = ptr::null();
        let seed: *const u8 = ptr::null();
        let seed_len: usize = 0;
        let err_code = ursa_bls_sign_key_new(seed, seed_len, &mut sign_key);
        assert_eq!(err_code, ErrorCode::Success);

        let mut ver_key: *const c_void = ptr::null();
        let err_code = ursa_bls_ver_key_new(gen, sign_key, &mut ver_key);
        assert_eq!(err_code, ErrorCode::Success);

        let mut pop: *const c_void = ptr::null();
        let err_code = ursa_bls_pop_new(ver_key, sign_key, &mut pop);
        assert_eq!(err_code, ErrorCode::Success);

        let mut bytes: *const u8 = ptr::null();
        let mut bytes_len: usize = 0;
        let err_code = ursa_bls_pop_as_bytes(pop, &mut bytes, &mut bytes_len);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!bytes.is_null());
        assert!(bytes_len > 0);

        let mut pop2: *const c_void = ptr::null();
        let err_code = ursa_bls_pop_from_bytes(bytes, bytes_len, &mut pop2);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_generator_free(gen);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_sign_key_free(sign_key);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_ver_key_free(ver_key);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_pop_free(pop);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_pop_free(pop2);
        assert_eq!(err_code, ErrorCode::Success);
    }

    #[test]
    fn ursa_bls_pop_free_works() {
        let mut gen: *const c_void = ptr::null();
        let err_code = ursa_bls_generator_new(&mut gen);
        assert_eq!(err_code, ErrorCode::Success);

        let mut sign_key: *const c_void = ptr::null();
        let seed: *const u8 = ptr::null();
        let seed_len: usize = 0;
        let err_code = ursa_bls_sign_key_new(seed, seed_len, &mut sign_key);
        assert_eq!(err_code, ErrorCode::Success);

        let mut ver_key: *const c_void = ptr::null();
        let err_code = ursa_bls_ver_key_new(gen, sign_key, &mut ver_key);
        assert_eq!(err_code, ErrorCode::Success);

        let mut pop: *const c_void = ptr::null();
        let err_code = ursa_bls_pop_new(ver_key, sign_key, &mut pop);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_generator_free(gen);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_sign_key_free(sign_key);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_ver_key_free(ver_key);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_pop_free(pop);
        assert_eq!(err_code, ErrorCode::Success);
    }

    #[test]
    fn ursa_bls_verify_pop_works() {
        let mut gen: *const c_void = ptr::null();
        let err_code = ursa_bls_generator_new(&mut gen);
        assert_eq!(err_code, ErrorCode::Success);

        let mut sign_key: *const c_void = ptr::null();
        let seed: *const u8 = ptr::null();
        let seed_len: usize = 0;
        let err_code = ursa_bls_sign_key_new(seed, seed_len, &mut sign_key);
        assert_eq!(err_code, ErrorCode::Success);

        let mut ver_key: *const c_void = ptr::null();
        let err_code = ursa_bls_ver_key_new(gen, sign_key, &mut ver_key);
        assert_eq!(err_code, ErrorCode::Success);

        let mut pop: *const c_void = ptr::null();
        let err_code = ursa_bls_pop_new(ver_key, sign_key, &mut pop);
        assert_eq!(err_code, ErrorCode::Success);

        let mut valid = false;

        let err_code = ursa_bls_verify_pop(pop, ver_key, gen, &mut valid);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(valid);

        let err_code = ursa_bls_generator_free(gen);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_sign_key_free(sign_key);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_ver_key_free(ver_key);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_pop_free(pop);
        assert_eq!(err_code, ErrorCode::Success);
    }

    #[test]
    fn ursa_bls_verify_multi_sig_works() {
        let mut gen: *const c_void = ptr::null();
        let err_code = ursa_bls_generator_new(&mut gen);
        assert_eq!(err_code, ErrorCode::Success);

        let mut sign_key1: *const c_void = ptr::null();
        let seed: *const u8 = ptr::null();
        let seed_len: usize = 0;
        let err_code = ursa_bls_sign_key_new(seed, seed_len, &mut sign_key1);
        assert_eq!(err_code, ErrorCode::Success);

        let mut sign_key2: *const c_void = ptr::null();
        let seed: *const u8 = ptr::null();
        let seed_len: usize = 0;
        let err_code = ursa_bls_sign_key_new(seed, seed_len, &mut sign_key2);
        assert_eq!(err_code, ErrorCode::Success);

        let message_v = vec![1, 2, 3, 4, 5];
        let message = message_v.as_ptr();
        let message_len = message_v.len();

        let mut signature1: *const c_void = ptr::null();
        let err_code = ursa_bls_sign(message, message_len, sign_key1, &mut signature1);
        assert_eq!(err_code, ErrorCode::Success);

        let mut signature2: *const c_void = ptr::null();
        let err_code = ursa_bls_sign(message, message_len, sign_key2, &mut signature2);
        assert_eq!(err_code, ErrorCode::Success);

        let signatures = [signature1, signature2];

        let mut multi_sig: *const c_void = ptr::null();
        let err_code =
            ursa_bls_multi_signature_new(signatures.as_ptr(), signatures.len(), &mut multi_sig);
        assert_eq!(err_code, ErrorCode::Success);

        let mut ver_key1: *const c_void = ptr::null();
        let err_code = ursa_bls_ver_key_new(gen, sign_key1, &mut ver_key1);
        assert_eq!(err_code, ErrorCode::Success);

        let mut ver_key2: *const c_void = ptr::null();
        let err_code = ursa_bls_ver_key_new(gen, sign_key2, &mut ver_key2);
        assert_eq!(err_code, ErrorCode::Success);

        let ver_keys = [ver_key1, ver_key2];
        let mut valid = false;

        let err_code = ursa_bls_verify_multi_sig(
            multi_sig,
            message,
            message_len,
            ver_keys.as_ptr(),
            ver_keys.len(),
            gen,
            &mut valid,
        );
        assert_eq!(err_code, ErrorCode::Success);
        assert!(valid);

        let err_code = ursa_bls_generator_free(gen);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_sign_key_free(sign_key1);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_sign_key_free(sign_key2);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_ver_key_free(ver_key1);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_ver_key_free(ver_key2);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_signature_free(signature1);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_signature_free(signature2);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_multi_signature_free(multi_sig);
        assert_eq!(err_code, ErrorCode::Success);
    }

    #[test]
    fn ursa_bls_verify_multi_sig_works_for_invalid() {
        let mut gen: *const c_void = ptr::null();
        let err_code = ursa_bls_generator_new(&mut gen);
        assert_eq!(err_code, ErrorCode::Success);

        let mut sign_key1: *const c_void = ptr::null();
        let seed: *const u8 = ptr::null();
        let seed_len: usize = 0;
        let err_code = ursa_bls_sign_key_new(seed, seed_len, &mut sign_key1);
        assert_eq!(err_code, ErrorCode::Success);

        let mut sign_key2: *const c_void = ptr::null();
        let seed: *const u8 = ptr::null();
        let seed_len: usize = 0;
        let err_code = ursa_bls_sign_key_new(seed, seed_len, &mut sign_key2);
        assert_eq!(err_code, ErrorCode::Success);

        let mut sign_key3: *const c_void = ptr::null();
        let seed: *const u8 = ptr::null();
        let seed_len: usize = 0;
        let err_code = ursa_bls_sign_key_new(seed, seed_len, &mut sign_key3);
        assert_eq!(err_code, ErrorCode::Success);

        let message_v = vec![1, 2, 3, 4, 5];
        let message = message_v.as_ptr();
        let message_len = message_v.len();

        let mut signature1: *const c_void = ptr::null();
        let err_code = ursa_bls_sign(message, message_len, sign_key1, &mut signature1);
        assert_eq!(err_code, ErrorCode::Success);

        let mut signature2: *const c_void = ptr::null();
        let err_code = ursa_bls_sign(message, message_len, sign_key2, &mut signature2);
        assert_eq!(err_code, ErrorCode::Success);

        let signatures = [signature1, signature2];

        let mut multi_sig: *const c_void = ptr::null();
        let err_code =
            ursa_bls_multi_signature_new(signatures.as_ptr(), signatures.len(), &mut multi_sig);
        assert_eq!(err_code, ErrorCode::Success);

        let mut ver_key1: *const c_void = ptr::null();
        let err_code = ursa_bls_ver_key_new(gen, sign_key1, &mut ver_key1);
        assert_eq!(err_code, ErrorCode::Success);

        let mut ver_key2: *const c_void = ptr::null();
        let err_code = ursa_bls_ver_key_new(gen, sign_key3, &mut ver_key2);
        assert_eq!(err_code, ErrorCode::Success);

        let ver_keys = [ver_key1, ver_key2];
        let mut valid = false;

        let err_code = ursa_bls_verify_multi_sig(
            multi_sig,
            message,
            message_len,
            ver_keys.as_ptr(),
            ver_keys.len(),
            gen,
            &mut valid,
        );
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!valid);

        let err_code = ursa_bls_generator_free(gen);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_sign_key_free(sign_key1);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_sign_key_free(sign_key2);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_sign_key_free(sign_key3);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_ver_key_free(ver_key1);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_ver_key_free(ver_key2);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_signature_free(signature1);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_signature_free(signature2);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = ursa_bls_multi_signature_free(multi_sig);
        assert_eq!(err_code, ErrorCode::Success);
    }
}
