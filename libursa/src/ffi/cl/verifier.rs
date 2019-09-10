use cl::verifier::*;
use cl::*;
use errors::prelude::*;
use ffi::ErrorCode;
use utils::ctypes::*;

use std::os::raw::{c_char, c_void};

/// Creates and returns proof verifier.
///
/// Note that proof verifier deallocation must be performed by
/// calling ursa_cl_proof_verifier_finalize.
///
/// # Arguments
/// * `proof_verifier_p` - Reference that will contain proof verifier instance pointer.
#[no_mangle]
pub extern "C" fn ursa_cl_verifier_new_proof_verifier(
    proof_verifier_p: *mut *const c_void,
) -> ErrorCode {
    trace!(
        "ursa_cl_verifier_new_proof_verifier: >>> {:?}",
        proof_verifier_p
    );

    check_useful_c_ptr!(proof_verifier_p, ErrorCode::CommonInvalidParam1);

    let res = match Verifier::new_proof_verifier() {
        Ok(proof_verifier) => {
            trace!(
                "ursa_cl_verifier_new_proof_verifier: proof_verifier: {:?}",
                proof_verifier
            );
            unsafe {
                *proof_verifier_p = Box::into_raw(Box::new(proof_verifier)) as *const c_void;
                trace!(
                    "ursa_cl_verifier_new_proof_verifier: *proof_verifier_p: {:?}",
                    *proof_verifier_p
                );
            }
            ErrorCode::Success
        }
        Err(err) => err.into(),
    };

    trace!("ursa_cl_verifier_new_proof_verifier: <<< res: {:?}", res);
    res
}

/// Add a common attribute to the proof verifier
///
/// # Arguments
/// * `proof_builder` - Reference that contain proof verifier instance pointer.
/// * `attribute_name` - Common attribute's name

#[no_mangle]
pub extern "C" fn ursa_cl_proof_verifier_add_common_attribute(
    proof_verifier: *const c_void,
    attribute_name: *const c_char,
) -> ErrorCode {
    trace!(
        "ursa_cl_proof_verifier_add_common_attribute: >>> proof_verifier: {:?}, attribute_name: {:?}",
        proof_verifier,
        attribute_name
    );

    check_useful_mut_c_reference!(
        proof_verifier,
        ProofVerifier,
        ErrorCode::CommonInvalidParam1
    );
    check_useful_c_str!(attribute_name, ErrorCode::CommonInvalidParam2);

    trace!(
        "ursa_cl_proof_verifier_add_common_attribute: entities: proof_verifier: {:?}, attribute_name: {:?}",
        proof_verifier,
        attribute_name
    );

    match proof_verifier.add_common_attribute(&attribute_name) {
        Ok(()) => ErrorCode::Success,
        Err(err) => err.into(),
    }
}

#[no_mangle]
pub extern "C" fn ursa_cl_proof_verifier_add_sub_proof_request(
    proof_verifier: *const c_void,
    sub_proof_request: *const c_void,
    credential_schema: *const c_void,
    non_credential_schema: *const c_void,
    credential_pub_key: *const c_void,
    rev_key_pub: *const c_void,
    rev_reg: *const c_void,
) -> ErrorCode {
    trace!(
        "ursa_cl_proof_verifier_add_sub_proof_request: >>> proof_verifier: {:?}, \
         sub_proof_request: {:?} ,\
         credential_schema: {:?}, \
         non_credential_schema: {:?}, \
         credential_pub_key: {:?}, \
         rev_key_pub: {:?}, \
         rev_reg: {:?}",
        proof_verifier,
        sub_proof_request,
        credential_schema,
        non_credential_schema,
        credential_pub_key,
        rev_key_pub,
        rev_reg
    );

    check_useful_mut_c_reference!(
        proof_verifier,
        ProofVerifier,
        ErrorCode::CommonInvalidParam1
    );
    check_useful_c_reference!(
        sub_proof_request,
        SubProofRequest,
        ErrorCode::CommonInvalidParam2
    );
    check_useful_c_reference!(
        credential_schema,
        CredentialSchema,
        ErrorCode::CommonInvalidParam3
    );
    check_useful_c_reference!(
        non_credential_schema,
        NonCredentialSchema,
        ErrorCode::CommonInvalidParam4
    );
    check_useful_c_reference!(
        credential_pub_key,
        CredentialPublicKey,
        ErrorCode::CommonInvalidParam5
    );
    check_useful_opt_c_reference!(rev_key_pub, RevocationKeyPublic);
    check_useful_opt_c_reference!(rev_reg, RevocationRegistry);

    trace!("ursa_cl_proof_verifier_add_sub_proof_request: entities: proof_verifier: {:?}, sub_proof_request: {:?},\
                credential_schema: {:?}, non_credential_schema: {:?}, credential_pub_key: {:?}, rev_key_pub: {:?}, rev_reg: {:?}",
           proof_verifier, sub_proof_request, credential_schema, non_credential_schema, credential_pub_key, rev_key_pub, rev_reg);

    let res = match proof_verifier.add_sub_proof_request(
        sub_proof_request,
        credential_schema,
        non_credential_schema,
        credential_pub_key,
        rev_key_pub,
        rev_reg,
    ) {
        Ok(()) => ErrorCode::Success,
        Err(err) => err.into(),
    };

    trace!(
        "ursa_cl_proof_verifier_add_sub_proof_request: <<< res: {:?}",
        res
    );
    res
}

/// Verifies proof and deallocates proof verifier.
///
/// # Arguments
/// * `proof_verifier` - Reference that contain proof verifier instance pointer.
/// * `proof` - Reference that contain proof instance pointer.
/// * `nonce` - Reference that contain nonce instance pointer.
/// * `valid_p` - Reference that will be filled with true - if proof valid or false otherwise.
#[no_mangle]
pub extern "C" fn ursa_cl_proof_verifier_verify(
    proof_verifier: *const c_void,
    proof: *const c_void,
    nonce: *const c_void,
    valid_p: *mut bool,
) -> ErrorCode {
    trace!("ursa_cl_proof_verifier_verify: >>> proof_verifier: {:?}, proof: {:?}, nonce: {:?}, valid_p: {:?}", proof_verifier, proof, nonce, valid_p);

    check_useful_c_ptr!(proof_verifier, ErrorCode::CommonInvalidParam1);
    check_useful_c_reference!(proof, Proof, ErrorCode::CommonInvalidParam2);
    check_useful_c_reference!(nonce, Nonce, ErrorCode::CommonInvalidParam3);
    check_useful_c_ptr!(valid_p, ErrorCode::CommonInvalidParam4);

    let mut proof_verifier = unsafe { Box::from_raw(proof_verifier as *mut ProofVerifier) };

    trace!("ursa_cl_proof_verifier_verify: entities: >>> proof_verifier: {:?}, proof: {:?}, nonce: {:?}", proof_verifier, proof, nonce);

    let res = match proof_verifier.verify(proof, nonce) {
        Ok(valid) => {
            trace!("ursa_cl_proof_verifier_verify: valid: {:?}", valid);
            unsafe {
                *valid_p = valid;
                trace!("ursa_cl_proof_verifier_verify: *valid_p: {:?}", *valid_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.into(),
    };

    trace!("ursa_cl_proof_verifier_verify: <<< res: {:?}", res);
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    use super::super::issuer::mocks::*;
    use super::super::prover::mocks::*;
    use super::mocks::*;
    use ffi::cl::mocks::*;
    use std::ptr;

    // Master secret is now called link secret.
    pub static LINK_SECRET: &'static str = "master_secret";

    #[test]
    fn ursa_cl_verifier_new_proof_verifier_works() {
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
            _credential_def();
        let credential_values = _credential_values();
        let credential_nonce = _nonce();
        let (
            blinded_credential_secrets,
            credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof,
        ) = _blinded_credential_secrets(
            credential_pub_key,
            credential_key_correctness_proof,
            credential_values,
            credential_nonce,
        );
        let credential_issuance_nonce = _nonce();
        let (credential_signature, signature_correctness_proof) = _credential_signature(
            blinded_credential_secrets,
            blinded_credential_secrets_correctness_proof,
            credential_nonce,
            credential_issuance_nonce,
            credential_values,
            credential_pub_key,
            credential_priv_key,
        );
        let credential_schema = _credential_schema();
        let non_credential_schema = _non_credential_schema();
        let sub_proof_request = _sub_proof_request();
        _process_credential_signature(
            credential_signature,
            signature_correctness_proof,
            credential_secrets_blinding_factors,
            credential_values,
            credential_pub_key,
            credential_issuance_nonce,
            ptr::null(),
            ptr::null(),
            ptr::null(),
        );

        let proof_building_nonce = _nonce();
        let proof = _proof(
            credential_pub_key,
            credential_signature,
            proof_building_nonce,
            credential_values,
            ptr::null(),
            ptr::null(),
        );

        let mut proof_verifier_p: *const c_void = ptr::null();
        let err_code = ursa_cl_verifier_new_proof_verifier(&mut proof_verifier_p);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!proof_verifier_p.is_null());

        _add_sub_proof_request(
            proof_verifier_p,
            credential_schema,
            non_credential_schema,
            credential_pub_key,
            sub_proof_request,
            ptr::null(),
            ptr::null(),
        );
        _free_proof_verifier(proof_verifier_p, proof, proof_building_nonce);
        _free_credential_def(
            credential_pub_key,
            credential_priv_key,
            credential_key_correctness_proof,
        );
        _free_blinded_credential_secrets(
            blinded_credential_secrets,
            credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof,
        );
        _free_nonce(credential_nonce);
        _free_nonce(credential_issuance_nonce);
        _free_nonce(proof_building_nonce);
        _free_credential_schema(credential_schema);
        _free_sub_proof_request(sub_proof_request);
        _free_credential_signature(credential_signature, signature_correctness_proof);
    }

    #[test]
    fn ursa_cl_proof_verifier_add_common_attribute_works() {
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
            _credential_def();
        let credential_values = _credential_values();
        let credential_nonce = _nonce();
        let (
            blinded_credential_secrets,
            credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof,
        ) = _blinded_credential_secrets(
            credential_pub_key,
            credential_key_correctness_proof,
            credential_values,
            credential_nonce,
        );
        let credential_issuance_nonce = _nonce();
        let (credential_signature, signature_correctness_proof) = _credential_signature(
            blinded_credential_secrets,
            blinded_credential_secrets_correctness_proof,
            credential_nonce,
            credential_issuance_nonce,
            credential_values,
            credential_pub_key,
            credential_priv_key,
        );
        let credential_schema = _credential_schema();
        let non_credential_schema = _non_credential_schema();
        let sub_proof_request = _sub_proof_request();
        _process_credential_signature(
            credential_signature,
            signature_correctness_proof,
            credential_secrets_blinding_factors,
            credential_values,
            credential_pub_key,
            credential_issuance_nonce,
            ptr::null(),
            ptr::null(),
            ptr::null(),
        );

        let proof_building_nonce = _nonce();
        let proof = _proof(
            credential_pub_key,
            credential_signature,
            proof_building_nonce,
            credential_values,
            ptr::null(),
            ptr::null(),
        );

        let proof_verifier = _proof_verifier();

        let common_attr_name = string_to_cstring(String::from(LINK_SECRET));
        let err_code =
            ursa_cl_proof_verifier_add_common_attribute(proof_verifier, common_attr_name.as_ptr());
        assert_eq!(err_code, ErrorCode::Success);

        // This is needed because `_free_proof_verifier` need a `proof_verifier` with same number of sub proof requests as the `proof` does
        ursa_cl_proof_verifier_add_sub_proof_request(
            proof_verifier,
            sub_proof_request,
            credential_schema,
            non_credential_schema,
            credential_pub_key,
            ptr::null(),
            ptr::null(),
        );

        _free_proof_verifier(proof_verifier, proof, proof_building_nonce);
        _free_credential_def(
            credential_pub_key,
            credential_priv_key,
            credential_key_correctness_proof,
        );
        _free_blinded_credential_secrets(
            blinded_credential_secrets,
            credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof,
        );
        _free_nonce(credential_nonce);
        _free_nonce(credential_issuance_nonce);
        _free_nonce(proof_building_nonce);
        _free_credential_schema(credential_schema);
        _free_sub_proof_request(sub_proof_request);
        _free_credential_signature(credential_signature, signature_correctness_proof);
    }

    #[test]
    fn ursa_cl_proof_verifier_add_sub_proof_request_works() {
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
            _credential_def();
        let credential_values = _credential_values();
        let credential_nonce = _nonce();
        let (
            blinded_credential_secrets,
            credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof,
        ) = _blinded_credential_secrets(
            credential_pub_key,
            credential_key_correctness_proof,
            credential_values,
            credential_nonce,
        );
        let credential_issuance_nonce = _nonce();
        let (credential_signature, signature_correctness_proof) = _credential_signature(
            blinded_credential_secrets,
            blinded_credential_secrets_correctness_proof,
            credential_nonce,
            credential_issuance_nonce,
            credential_values,
            credential_pub_key,
            credential_priv_key,
        );
        let credential_schema = _credential_schema();
        let non_credential_schema = _non_credential_schema();
        let sub_proof_request = _sub_proof_request();
        _process_credential_signature(
            credential_signature,
            signature_correctness_proof,
            credential_secrets_blinding_factors,
            credential_values,
            credential_pub_key,
            credential_issuance_nonce,
            ptr::null(),
            ptr::null(),
            ptr::null(),
        );

        let proof_building_nonce = _nonce();
        let proof = _proof(
            credential_pub_key,
            credential_signature,
            proof_building_nonce,
            credential_values,
            ptr::null(),
            ptr::null(),
        );

        let proof_verifier = _proof_verifier();

        let err_code = ursa_cl_proof_verifier_add_sub_proof_request(
            proof_verifier,
            sub_proof_request,
            credential_schema,
            non_credential_schema,
            credential_pub_key,
            ptr::null(),
            ptr::null(),
        );
        assert_eq!(err_code, ErrorCode::Success);

        _free_proof_verifier(proof_verifier, proof, proof_building_nonce);
        _free_credential_def(
            credential_pub_key,
            credential_priv_key,
            credential_key_correctness_proof,
        );
        _free_blinded_credential_secrets(
            blinded_credential_secrets,
            credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof,
        );
        _free_nonce(credential_nonce);
        _free_nonce(credential_issuance_nonce);
        _free_nonce(proof_building_nonce);
        _free_credential_schema(credential_schema);
        _free_sub_proof_request(sub_proof_request);
        _free_credential_signature(credential_signature, signature_correctness_proof);
    }

    #[test]
    fn ursa_cl_proof_verifier_verify_works_for_primary_proof() {
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
            _credential_def();
        let credential_values = _credential_values();
        let credential_nonce = _nonce();
        let (
            blinded_credential_secrets,
            credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof,
        ) = _blinded_credential_secrets(
            credential_pub_key,
            credential_key_correctness_proof,
            credential_values,
            credential_nonce,
        );
        let credential_issuance_nonce = _nonce();
        let (credential_signature, signature_correctness_proof) = _credential_signature(
            blinded_credential_secrets,
            blinded_credential_secrets_correctness_proof,
            credential_nonce,
            credential_issuance_nonce,
            credential_values,
            credential_pub_key,
            credential_priv_key,
        );
        let credential_schema = _credential_schema();
        let non_credential_schema = _non_credential_schema();
        let sub_proof_request = _sub_proof_request();
        _process_credential_signature(
            credential_signature,
            signature_correctness_proof,
            credential_secrets_blinding_factors,
            credential_values,
            credential_pub_key,
            credential_issuance_nonce,
            ptr::null(),
            ptr::null(),
            ptr::null(),
        );

        let proof_building_nonce = _nonce();
        let proof = _proof(
            credential_pub_key,
            credential_signature,
            proof_building_nonce,
            credential_values,
            ptr::null(),
            ptr::null(),
        );

        let proof_verifier = _proof_verifier();
        _add_sub_proof_request(
            proof_verifier,
            credential_schema,
            non_credential_schema,
            credential_pub_key,
            sub_proof_request,
            ptr::null(),
            ptr::null(),
        );

        let mut valid = false;
        let err_code =
            ursa_cl_proof_verifier_verify(proof_verifier, proof, proof_building_nonce, &mut valid);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(valid);

        _free_credential_def(
            credential_pub_key,
            credential_priv_key,
            credential_key_correctness_proof,
        );
        _free_blinded_credential_secrets(
            blinded_credential_secrets,
            credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof,
        );
        _free_nonce(credential_nonce);
        _free_nonce(credential_issuance_nonce);
        _free_nonce(proof_building_nonce);
        _free_credential_schema(credential_schema);
        _free_sub_proof_request(sub_proof_request);
        _free_credential_signature(credential_signature, signature_correctness_proof);
    }

    #[test]
    fn ursa_cl_proof_verifier_verify_works_for_revocation_proof() {
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
            _credential_def();
        let (rev_key_pub, rev_key_priv, rev_reg, rev_tails_generator) =
            _revocation_registry_def(credential_pub_key);
        let credential_values = _credential_values();
        let credential_nonce = _nonce();
        let (
            blinded_credential_secrets,
            credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof,
        ) = _blinded_credential_secrets(
            credential_pub_key,
            credential_key_correctness_proof,
            credential_values,
            credential_nonce,
        );
        let credential_issuance_nonce = _nonce();
        let tail_storage = FFISimpleTailStorage::new(rev_tails_generator);

        let (credential_signature, signature_correctness_proof, rev_reg_delta) =
            _credential_signature_with_revoc(
                blinded_credential_secrets,
                blinded_credential_secrets_correctness_proof,
                credential_nonce,
                credential_issuance_nonce,
                credential_values,
                credential_pub_key,
                credential_priv_key,
                rev_key_priv,
                rev_reg,
                tail_storage.get_ctx(),
            );
        let credential_schema = _credential_schema();
        let non_credential_schema = _non_credential_schema();
        let sub_proof_request = _sub_proof_request();
        let witness = _witness(rev_reg_delta, tail_storage.get_ctx());
        _process_credential_signature(
            credential_signature,
            signature_correctness_proof,
            credential_secrets_blinding_factors,
            credential_values,
            credential_pub_key,
            credential_issuance_nonce,
            rev_key_pub,
            rev_reg,
            witness,
        );

        let proof_building_nonce = _nonce();
        let proof = _proof(
            credential_pub_key,
            credential_signature,
            proof_building_nonce,
            credential_values,
            rev_reg,
            witness,
        );

        let proof_verifier = _proof_verifier();
        _add_sub_proof_request(
            proof_verifier,
            credential_schema,
            non_credential_schema,
            credential_pub_key,
            sub_proof_request,
            rev_key_pub,
            rev_reg,
        );

        let mut valid = false;
        let err_code =
            ursa_cl_proof_verifier_verify(proof_verifier, proof, proof_building_nonce, &mut valid);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(valid);

        _free_credential_def(
            credential_pub_key,
            credential_priv_key,
            credential_key_correctness_proof,
        );
        _free_blinded_credential_secrets(
            blinded_credential_secrets,
            credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof,
        );
        _free_nonce(credential_nonce);
        _free_nonce(credential_issuance_nonce);
        _free_nonce(proof_building_nonce);
        _free_witness(witness);
        _free_credential_schema(credential_schema);
        _free_sub_proof_request(sub_proof_request);
        _free_credential_signature(credential_signature, signature_correctness_proof);
    }
}

#[cfg(test)]
pub mod mocks {
    use super::*;
    use std::ptr;

    pub fn _proof_verifier() -> *const c_void {
        let mut proof_verifier_p: *const c_void = ptr::null();
        let err_code = ursa_cl_verifier_new_proof_verifier(&mut proof_verifier_p);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!proof_verifier_p.is_null());

        proof_verifier_p
    }

    pub fn _add_sub_proof_request(
        proof_verifier: *const c_void,
        credential_schema: *const c_void,
        non_credential_schema: *const c_void,
        credential_pub_key: *const c_void,
        sub_proof_request: *const c_void,
        rev_key_pub: *const c_void,
        rev_reg: *const c_void,
    ) {
        let err_code = ursa_cl_proof_verifier_add_sub_proof_request(
            proof_verifier,
            sub_proof_request,
            credential_schema,
            non_credential_schema,
            credential_pub_key,
            rev_key_pub,
            rev_reg,
        );
        assert_eq!(err_code, ErrorCode::Success);
    }

    pub fn _free_proof_verifier(
        proof_verifier: *const c_void,
        proof: *const c_void,
        nonce: *const c_void,
    ) {
        let mut valid = false;
        let err_code = ursa_cl_proof_verifier_verify(proof_verifier, proof, nonce, &mut valid);
        assert_eq!(err_code, ErrorCode::Success);
    }
}
