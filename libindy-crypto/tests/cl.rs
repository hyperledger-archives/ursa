#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate indy_crypto;

use indy_crypto::cl::{new_nonce, Witness, RevocationRegistry, RevocationRegistryDelta, SimpleTailsAccessor};
use indy_crypto::cl::issuer::Issuer;
use indy_crypto::cl::prover::Prover;
use indy_crypto::cl::verifier::Verifier;
use indy_crypto::pair::PointG2;
use std::collections::HashSet;

pub const PROVER_ID: &'static str = "CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW";

mod test {
    use super::*;
    use indy_crypto::ffi::ErrorCode;
    use indy_crypto::errors::ToErrorCode;

    #[test]
    fn anoncreds_demo() {
        // 1. Prover creates master secret
        let master_secret = Prover::new_master_secret().unwrap();

        // Issuer creates GVT credential
        // 2. Issuer creates GVT credential schema
        let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
        credential_schema_builder.add_attr("name").unwrap();
        credential_schema_builder.add_attr("sex").unwrap();
        credential_schema_builder.add_attr("age").unwrap();
        credential_schema_builder.add_attr("height").unwrap();
        let gvt_credential_schema = credential_schema_builder.finalize().unwrap();

        // 3. Issuer creates GVT credential definition
        let (gvt_credential_pub_key, gvt_credential_priv_key, gvt_credential_key_correctness_proof) =
            Issuer::new_credential_def(&gvt_credential_schema, true).unwrap();

        // 4. Issuer creates GVT revocation registry with IssuanceOnDemand type
        let gvt_max_cred_num = 5;
        let gvt_issuance_by_default = false;
        let (gvt_rev_key_pub, gvt_rev_key_priv, mut gvt_rev_reg, mut gvt_rev_tails_generator) =
            Issuer::new_revocation_registry_def(&gvt_credential_pub_key, gvt_max_cred_num, gvt_issuance_by_default).unwrap();

        let gvt_simple_tail_accessor = SimpleTailsAccessor::new(&mut gvt_rev_tails_generator).unwrap();

        // 5. Issuer creates nonce used Prover to blind master secret
        let gvt_master_secret_blinding_nonce = new_nonce().unwrap();

        // 6. Prover blinds master secret
        let (gvt_blinded_master_secret, gvt_master_secret_blinding_data, gvt_blinded_master_secret_correctness_proof) =
            Prover::blind_master_secret(&gvt_credential_pub_key,
                                        &gvt_credential_key_correctness_proof,
                                        &master_secret,
                                        &gvt_master_secret_blinding_nonce).unwrap();

        // 7. Prover creates nonce used Issuer to credential issue
        let gvt_credential_issuance_nonce = new_nonce().unwrap();

        // 8. Issuer creates GVT credential values
        let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();
        credential_values_builder.add_value("name", "1139481716457488690172217916278103335").unwrap();
        credential_values_builder.add_value("sex", "5944657099558967239210949258394887428692050081607692519917050011144233115103").unwrap();
        credential_values_builder.add_value("age", "28").unwrap();
        credential_values_builder.add_value("height", "175").unwrap();
        let gvt_credential_values = credential_values_builder.finalize().unwrap();

        // 9. Issuer signs GVT credential values
        let gvt_rev_idx = 1;
        let (mut gvt_credential_signature, gvt_signature_correctness_proof, gvt_rev_reg_delta) =
            Issuer::sign_credential_with_revoc(PROVER_ID,
                                               &gvt_blinded_master_secret,
                                               &gvt_blinded_master_secret_correctness_proof,
                                               &gvt_master_secret_blinding_nonce,
                                               &gvt_credential_issuance_nonce,
                                               &gvt_credential_values,
                                               &gvt_credential_pub_key,
                                               &gvt_credential_priv_key,
                                               gvt_rev_idx,
                                               gvt_max_cred_num,
                                               gvt_issuance_by_default,
                                               &mut gvt_rev_reg,
                                               &gvt_rev_key_priv,
                                               &gvt_simple_tail_accessor).unwrap();

        // 10. Prover creates GVT witness
        let gvt_witness = Witness::new(gvt_rev_idx,
                                       gvt_max_cred_num,
                                       &gvt_rev_reg_delta.unwrap(),
                                       &gvt_simple_tail_accessor).unwrap();

        // 11. Prover processes GVT credential signature
        Prover::process_credential_signature(&mut gvt_credential_signature,
                                             &gvt_credential_values,
                                             &gvt_signature_correctness_proof,
                                             &gvt_master_secret_blinding_data,
                                             &master_secret,
                                             &gvt_credential_pub_key,
                                             &gvt_credential_issuance_nonce,
                                             Some(&gvt_rev_key_pub),
                                             Some(&gvt_rev_reg),
                                             Some(&gvt_witness)).unwrap();

        // Issuer creates XYZ credential
        // 12. Issuer creates XYZ credential schema
        let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
        credential_schema_builder.add_attr("period").unwrap();
        credential_schema_builder.add_attr("status").unwrap();
        let xyz_credential_schema = credential_schema_builder.finalize().unwrap();

        // 13. Issuer creates XYZ credential definition (with revocation keys)
        let (xyz_credential_pub_key, xyz_credential_priv_key, xyz_credential_key_correctness_proof) =
            Issuer::new_credential_def(&xyz_credential_schema, true).unwrap();

        // 14. Issuer creates XYZ revocation registry with IssuanceByDefault type
        let xyz_max_cred_num = 5;
        let xyz_issuance_by_default = true;
        let (xyz_rev_key_pub, xyz_rev_key_priv, mut xyz_rev_reg, mut xyz_rev_tails_generator) =
            Issuer::new_revocation_registry_def(&xyz_credential_pub_key, xyz_max_cred_num, xyz_issuance_by_default).unwrap();

        let xyz_simple_tail_accessor = SimpleTailsAccessor::new(&mut xyz_rev_tails_generator).unwrap();

        // 15. Issuer creates nonce used Prover to blind master secret
        let xyz_master_secret_blinding_nonce = new_nonce().unwrap();

        // 16. Prover blinds master secret
        let (xyz_blinded_master_secret, xyz_master_secret_blinding_data, xyz_blinded_master_secret_correctness_proof) =
            Prover::blind_master_secret(&xyz_credential_pub_key,
                                        &xyz_credential_key_correctness_proof,
                                        &master_secret,
                                        &xyz_master_secret_blinding_nonce).unwrap();

        // 17. Prover creates nonce used Issuer to credential issue
        let xyz_credential_issuance_nonce = new_nonce().unwrap();

        // 18. Issuer creates XYZ credential values
        let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();
        credential_values_builder.add_value("status", "51792877103171595686471452153480627530895").unwrap();
        credential_values_builder.add_value("period", "8").unwrap();
        let xyz_credential_values = credential_values_builder.finalize().unwrap();

        // 19. Issuer signs XYZ credential values
        let xyz_rev_idx = 1;
        let (mut xyz_credential_signature, xyz_signature_correctness_proof, xyz_rev_reg_delta) =
            Issuer::sign_credential_with_revoc(PROVER_ID,
                                               &xyz_blinded_master_secret,
                                               &xyz_blinded_master_secret_correctness_proof,
                                               &xyz_master_secret_blinding_nonce,
                                               &xyz_credential_issuance_nonce,
                                               &xyz_credential_values,
                                               &xyz_credential_pub_key,
                                               &xyz_credential_priv_key,
                                               xyz_rev_idx,
                                               xyz_max_cred_num,
                                               xyz_issuance_by_default,
                                               &mut xyz_rev_reg,
                                               &xyz_rev_key_priv,
                                               &xyz_simple_tail_accessor).unwrap();
        assert!(xyz_rev_reg_delta.is_none());
        let xyz_rev_reg_delta = RegistryDelta::from_rev_reg(&xyz_rev_reg, xyz_max_cred_num);

        // 20. Prover creates XYZ witness
        let xyz_witness = Witness::new(xyz_rev_idx,
                                       xyz_max_cred_num,
                                       &xyz_rev_reg_delta.to_delta(),
                                       &xyz_simple_tail_accessor).unwrap();

        // 21. Prover processes XYZ credential signature
        Prover::process_credential_signature(&mut xyz_credential_signature,
                                             &xyz_credential_values,
                                             &xyz_signature_correctness_proof,
                                             &xyz_master_secret_blinding_data,
                                             &master_secret,
                                             &xyz_credential_pub_key,
                                             &xyz_credential_issuance_nonce,
                                             Some(&xyz_rev_key_pub),
                                             Some(&xyz_rev_reg),
                                             Some(&xyz_witness)).unwrap();

        // 22. Verifier creates sub proof request related to GVT credential
        let mut sub_proof_request_builder = Verifier::new_sub_proof_request_builder().unwrap();
        sub_proof_request_builder.add_revealed_attr("name").unwrap();
        sub_proof_request_builder.add_predicate("age", "GE", 18).unwrap();
        let gvt_sub_proof_request = sub_proof_request_builder.finalize().unwrap();

        // 23. Verifier creates sub proof request related to XYZ credential
        let mut sub_proof_request_builder = Verifier::new_sub_proof_request_builder().unwrap();
        sub_proof_request_builder.add_revealed_attr("status").unwrap();
        sub_proof_request_builder.add_predicate("period", "GE", 4).unwrap();
        let xyz_sub_proof_request = sub_proof_request_builder.finalize().unwrap();

        // 24. Verifier creates nonce
        let nonce = new_nonce().unwrap();

        // 25. Prover creates proof for two sub proof requests
        let gvt_key_id = "gvt_key_id";
        let xyz_key_id = "xyz_key_id";
        let mut proof_builder = Prover::new_proof_builder().unwrap();

        proof_builder.add_sub_proof_request(gvt_key_id,
                                            &gvt_sub_proof_request,
                                            &gvt_credential_schema,
                                            &gvt_credential_signature,
                                            &gvt_credential_values,
                                            &gvt_credential_pub_key,
                                            Some(&gvt_rev_reg),
                                            Some(&gvt_witness)).unwrap();

        proof_builder.add_sub_proof_request(xyz_key_id,
                                            &xyz_sub_proof_request,
                                            &xyz_credential_schema,
                                            &xyz_credential_signature,
                                            &xyz_credential_values,
                                            &xyz_credential_pub_key,
                                            Some(&xyz_rev_reg),
                                            Some(&xyz_witness)).unwrap();

        let proof = proof_builder.finalize(&nonce, &master_secret).unwrap();

        // 26. Verifier verifies proof
        let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
        proof_verifier.add_sub_proof_request(gvt_key_id,
                                             &gvt_sub_proof_request,
                                             &gvt_credential_schema,
                                             &gvt_credential_pub_key,
                                             Some(&gvt_rev_key_pub),
                                             Some(&gvt_rev_reg)).unwrap();

        proof_verifier.add_sub_proof_request(xyz_key_id,
                                             &xyz_sub_proof_request,
                                             &xyz_credential_schema,
                                             &xyz_credential_pub_key,
                                             Some(&xyz_rev_key_pub),
                                             Some(&xyz_rev_reg)).unwrap();

        assert!(proof_verifier.verify(&proof, &nonce).unwrap());
    }

    #[test]
    fn anoncreds_works_for_primary_proof_only() {
        // 1. Issuer creates credential schema
        let credential_schema = helpers::gvt_credential_schema();

        // 2. Issuer creates credential definition
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
            Issuer::new_credential_def(&credential_schema, false).unwrap();

        // 3. Prover creates master secret
        let master_secret = Prover::new_master_secret().unwrap();

        // 4. Issuer creates nonce used Prover to blind master secret
        let master_secret_blinding_nonce = new_nonce().unwrap();

        // 5. Prover blinds master secret
        let (blinded_ms, master_secret_blinding_data, blinded_master_secret_correctness_proof) =
            Prover::blind_master_secret(&credential_pub_key,
                                        &credential_key_correctness_proof,
                                        &master_secret,
                                        &master_secret_blinding_nonce).unwrap();

        // 6. Prover creates nonce used Issuer to credential issue
        let credential_issuance_nonce = new_nonce().unwrap();

        // 7. Issuer creates credential values
        let credential_values = helpers::gvt_credential_values();

        // 8. Issuer signs credential values
        let (mut credential_signature, signature_correctness_proof) = Issuer::sign_credential(PROVER_ID,
                                                                                              &blinded_ms,
                                                                                              &blinded_master_secret_correctness_proof,
                                                                                              &master_secret_blinding_nonce,
                                                                                              &credential_issuance_nonce,
                                                                                              &credential_values,
                                                                                              &credential_pub_key,
                                                                                              &credential_priv_key).unwrap();

        // 9. Prover processes credential signature
        Prover::process_credential_signature(&mut credential_signature,
                                             &credential_values,
                                             &signature_correctness_proof,
                                             &master_secret_blinding_data,
                                             &master_secret,
                                             &credential_pub_key,
                                             &credential_issuance_nonce,
                                             None, None, None).unwrap();

        // 10. Verifier create sub proof request
        let sub_proof_request = helpers::gvt_sub_proof_request();

        // 11. Verifier creates nonce
        let nonce = new_nonce().unwrap();

        // 12. Prover creates proof
        let key_id = "issuer_key_id_1";
        let mut proof_builder = Prover::new_proof_builder().unwrap();
        proof_builder.add_sub_proof_request(key_id,
                                            &sub_proof_request,
                                            &credential_schema,
                                            &credential_signature,
                                            &credential_values,
                                            &credential_pub_key,
                                            None,
                                            None).unwrap();
        let proof = proof_builder.finalize(&nonce, &master_secret).unwrap();

        // 13. Verifier verifies proof
        let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
        proof_verifier.add_sub_proof_request(key_id,
                                             &sub_proof_request,
                                             &credential_schema,
                                             &credential_pub_key,
                                             None,
                                             None).unwrap();
        assert!(proof_verifier.verify(&proof, &nonce).unwrap());
    }

    #[test]
    fn anoncreds_works_for_revocation_proof_issuance_on_demand() {
        // 1. Issuer creates credential schema
        let credential_schema = helpers::gvt_credential_schema();

        // 2. Issuer creates credential definition(with revocation keys)
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, true).unwrap();

        // 4. Issuer creates revocation registry with IssuanceOnDemand type
        let max_cred_num = 5;
        let issuance_by_default = false;
        let (rev_key_pub, rev_key_priv, mut rev_reg, mut rev_tails_generator) =
            Issuer::new_revocation_registry_def(&credential_pub_key, max_cred_num, issuance_by_default).unwrap();

        let simple_tail_accessor = SimpleTailsAccessor::new(&mut rev_tails_generator).unwrap();

        // 4. Prover creates master secret
        let master_secret = Prover::new_master_secret().unwrap();

        // 5. Issuer creates nonce used Prover to blind master secret
        let master_secret_blinding_nonce = new_nonce().unwrap();

        // 6. Prover blinds master secret
        let (blinded_master_secret, master_secret_blinding_data, blinded_master_secret_correctness_proof) =
            Prover::blind_master_secret(&credential_pub_key,
                                        &credential_key_correctness_proof,
                                        &master_secret,
                                        &master_secret_blinding_nonce).unwrap();

        // 7. Prover creates nonce used Issuer to credential issue
        let credential_issuance_nonce = new_nonce().unwrap();

        // 8. Issuer creates and sign credential values
        let credential_values = helpers::gvt_credential_values();

        let rev_idx = 1;
        let (mut credential_signature, signature_correctness_proof, rev_reg_delta) =
            Issuer::sign_credential_with_revoc(PROVER_ID,
                                               &blinded_master_secret,
                                               &blinded_master_secret_correctness_proof,
                                               &master_secret_blinding_nonce,
                                               &credential_issuance_nonce,
                                               &credential_values,
                                               &credential_pub_key,
                                               &credential_priv_key,
                                               rev_idx,
                                               max_cred_num,
                                               issuance_by_default,
                                               &mut rev_reg,
                                               &rev_key_priv,
                                               &simple_tail_accessor).unwrap();

        // 9. Prover creates witness
        let witness = Witness::new(rev_idx,
                                   max_cred_num,
                                   &rev_reg_delta.unwrap(),
                                   &simple_tail_accessor).unwrap();

        // 10. Prover processes credential signature
        Prover::process_credential_signature(&mut credential_signature,
                                             &credential_values,
                                             &signature_correctness_proof,
                                             &master_secret_blinding_data,
                                             &master_secret,
                                             &credential_pub_key,
                                             &credential_issuance_nonce,
                                             Some(&rev_key_pub),
                                             Some(&rev_reg),
                                             Some(&witness)).unwrap();


        // 11. Verifier creates nonce
        let nonce = new_nonce().unwrap();

        // 12. Verifier create sub proof request
        let sub_proof_request = helpers::gvt_sub_proof_request();

        // 13. Prover creates proof
        let mut proof_builder = Prover::new_proof_builder().unwrap();
        let key_id = "key_id";
        proof_builder.add_sub_proof_request(key_id,
                                            &sub_proof_request,
                                            &credential_schema,
                                            &credential_signature,
                                            &credential_values,
                                            &credential_pub_key,
                                            Some(&rev_reg),
                                            Some(&witness)).unwrap();
        let proof = proof_builder.finalize(&nonce, &master_secret).unwrap();

        // 14. Verifier verifies proof
        let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
        proof_verifier.add_sub_proof_request(key_id,
                                             &sub_proof_request,
                                             &credential_schema,
                                             &credential_pub_key,
                                             Some(&rev_key_pub),
                                             Some(&rev_reg)).unwrap();
        assert!(proof_verifier.verify(&proof, &nonce).unwrap());
    }

    #[test]
    fn anoncreds_works_for_revocation_proof_issuance_by_default() {
        // 1. Issuer creates credential schema
        let credential_schema = helpers::gvt_credential_schema();

        // 2. Issuer creates credential definition(with revocation keys)
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, true).unwrap();

        // 4. Issuer creates GVT revocation registry with IssuanceByDefault type
        let max_cred_num = 5;
        let issuance_by_default = true;
        let (rev_key_pub, rev_key_priv, mut rev_reg, mut rev_tails_generator) =
            Issuer::new_revocation_registry_def(&credential_pub_key, max_cred_num, issuance_by_default).unwrap();

        let simple_tail_accessor = SimpleTailsAccessor::new(&mut rev_tails_generator).unwrap();

        // 4. Prover creates master secret
        let master_secret = Prover::new_master_secret().unwrap();

        // 5. Issuer creates nonce used Prover to blind master secret
        let master_secret_blinding_nonce = new_nonce().unwrap();

        // 6. Prover blinds master secret
        let (blinded_master_secret, master_secret_blinding_data, blinded_master_secret_correctness_proof) =
            Prover::blind_master_secret(&credential_pub_key,
                                        &credential_key_correctness_proof,
                                        &master_secret,
                                        &master_secret_blinding_nonce).unwrap();

        // 7. Prover creates nonce used Issuer to credential issue
        let credential_issuance_nonce = new_nonce().unwrap();

        // 8. Issuer creates and sign credential values
        let credential_values = helpers::gvt_credential_values();

        let rev_idx = 1;
        let (mut credential_signature, signature_correctness_proof, rev_reg_delta) =
            Issuer::sign_credential_with_revoc(PROVER_ID,
                                               &blinded_master_secret,
                                               &blinded_master_secret_correctness_proof,
                                               &master_secret_blinding_nonce,
                                               &credential_issuance_nonce,
                                               &credential_values,
                                               &credential_pub_key,
                                               &credential_priv_key,
                                               rev_idx,
                                               max_cred_num,
                                               issuance_by_default,
                                               &mut rev_reg,
                                               &rev_key_priv,
                                               &simple_tail_accessor).unwrap();
        assert!(rev_reg_delta.is_none());

        let rev_reg_delta = RegistryDelta::from_rev_reg(&rev_reg, max_cred_num);

        // 9. Prover creates witness
        let witness = Witness::new(rev_idx,
                                   max_cred_num,
                                   &rev_reg_delta.to_delta(),
                                   &simple_tail_accessor).unwrap();

        // 10. Prover processes credential signature
        Prover::process_credential_signature(&mut credential_signature,
                                             &credential_values,
                                             &signature_correctness_proof,
                                             &master_secret_blinding_data,
                                             &master_secret,
                                             &credential_pub_key,
                                             &credential_issuance_nonce,
                                             Some(&rev_key_pub),
                                             Some(&rev_reg),
                                             Some(&witness)).unwrap();

        // 11. Verifier creates nonce
        let nonce = new_nonce().unwrap();

        // 12. Verifier create sub proof request
        let sub_proof_request = helpers::gvt_sub_proof_request();

        // 13. Prover creates proof
        let mut proof_builder = Prover::new_proof_builder().unwrap();
        let key_id = "key_id";
        proof_builder.add_sub_proof_request(key_id,
                                            &sub_proof_request,
                                            &credential_schema,
                                            &credential_signature,
                                            &credential_values,
                                            &credential_pub_key,
                                            Some(&rev_reg),
                                            Some(&witness)).unwrap();
        let proof = proof_builder.finalize(&nonce, &master_secret).unwrap();

        // 14. Verifier verifies proof
        let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
        proof_verifier.add_sub_proof_request(key_id,
                                             &sub_proof_request,
                                             &credential_schema,
                                             &credential_pub_key,
                                             Some(&rev_key_pub),
                                             Some(&rev_reg)).unwrap();
        assert!(proof_verifier.verify(&proof, &nonce).unwrap());
    }

    #[test]
    fn anoncreds_works_for_multiple_credentials_used_for_proof() {
        // 1. Prover creates master secret
        let master_secret = Prover::new_master_secret().unwrap();

        // 2. Issuer creates and signs GVT credential for Prover
        let gvt_credential_schema = helpers::gvt_credential_schema();
        let (gvt_credential_pub_key, gvt_credential_priv_key, gvt_credential_key_correctness_proof) =
            Issuer::new_credential_def(&gvt_credential_schema, false).unwrap();

        let gvt_master_secret_blinding_nonce = new_nonce().unwrap();

        let (gvt_blinded_master_secret, gvt_master_secret_blinding_data, gvt_blinded_master_secret_correctness_proof) =
            Prover::blind_master_secret(&gvt_credential_pub_key,
                                        &gvt_credential_key_correctness_proof,
                                        &master_secret,
                                        &gvt_master_secret_blinding_nonce).unwrap();

        let gvt_credential_issuance_nonce = new_nonce().unwrap();

        let gvt_credential_values = helpers::gvt_credential_values();

        let (mut gvt_credential_signature, gvt_signature_correctness_proof) = Issuer::sign_credential(PROVER_ID,
                                                                                                      &gvt_blinded_master_secret,
                                                                                                      &gvt_blinded_master_secret_correctness_proof,
                                                                                                      &gvt_master_secret_blinding_nonce,
                                                                                                      &gvt_credential_issuance_nonce,
                                                                                                      &gvt_credential_values,
                                                                                                      &gvt_credential_pub_key,
                                                                                                      &gvt_credential_priv_key).unwrap();

        // 3. Prover processes GVT credential
        Prover::process_credential_signature(&mut gvt_credential_signature,
                                             &gvt_credential_values,
                                             &gvt_signature_correctness_proof,
                                             &gvt_master_secret_blinding_data,
                                             &master_secret,
                                             &gvt_credential_pub_key,
                                             &gvt_credential_issuance_nonce,
                                             None, None, None).unwrap();

        // 4. Issuer creates and signs XYZ credential for Prover
        let xyz_credential_schema = helpers::xyz_credential_schema();
        let (xyz_credential_pub_key, xyz_credential_priv_key, xyz_credential_key_correctness_proof) =
            Issuer::new_credential_def(&xyz_credential_schema, false).unwrap();

        let xyz_master_secret_blinding_nonce = new_nonce().unwrap();

        let (xyz_blinded_master_secret, xyz_master_secret_blinding_data, xyz_blinded_master_secret_correctness_proof) =
            Prover::blind_master_secret(&xyz_credential_pub_key,
                                        &xyz_credential_key_correctness_proof,
                                        &master_secret,
                                        &xyz_master_secret_blinding_nonce).unwrap();

        let xyz_credential_issuance_nonce = new_nonce().unwrap();

        let xyz_credential_values = helpers::xyz_credential_values();
        let (mut xyz_credential_signature, xyz_signature_correctness_proof) = Issuer::sign_credential(PROVER_ID,
                                                                                                      &xyz_blinded_master_secret,
                                                                                                      &xyz_blinded_master_secret_correctness_proof,
                                                                                                      &xyz_master_secret_blinding_nonce,
                                                                                                      &xyz_credential_issuance_nonce,
                                                                                                      &xyz_credential_values,
                                                                                                      &xyz_credential_pub_key,
                                                                                                      &xyz_credential_priv_key).unwrap();

        // 5. Prover processes XYZ credential
        Prover::process_credential_signature(&mut xyz_credential_signature,
                                             &xyz_credential_values,
                                             &xyz_signature_correctness_proof,
                                             &xyz_master_secret_blinding_data,
                                             &master_secret,
                                             &xyz_credential_pub_key,
                                             &xyz_credential_issuance_nonce,
                                             None, None, None).unwrap();
        // 6. Verifier creates nonce
        let nonce = new_nonce().unwrap();

        // 7. Verifier creates proof request which contains two sub proof requests: GVT and XYZ
        let gvt_sub_proof_request = helpers::gvt_sub_proof_request();
        let xyz_sub_proof_request = helpers::xyz_sub_proof_request();

        // 8. Prover creates proof builder
        let mut proof_builder = Prover::new_proof_builder().unwrap();

        let gvt_key_id = "gvt_key_id";
        // 9. Prover adds GVT sub proof request
        proof_builder.add_sub_proof_request(gvt_key_id,
                                            &gvt_sub_proof_request,
                                            &gvt_credential_schema,
                                            &gvt_credential_signature,
                                            &gvt_credential_values,
                                            &gvt_credential_pub_key,
                                            None, None).unwrap();

        // 10. Prover adds XYZ sub proof request
        let xyz_key_id = "xyz_key_id";
        proof_builder.add_sub_proof_request(xyz_key_id,
                                            &xyz_sub_proof_request,
                                            &xyz_credential_schema,
                                            &xyz_credential_signature,
                                            &xyz_credential_values,
                                            &xyz_credential_pub_key,
                                            None, None).unwrap();

        // 11. Prover gets proof which contains sub proofs for GVT and XYZ sub proof requests
        let proof = proof_builder.finalize(&nonce, &master_secret).unwrap();

        // 12. Verifier verifies proof for GVT and XYZ sub proof requests
        let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
        proof_verifier.add_sub_proof_request(gvt_key_id,
                                             &gvt_sub_proof_request,
                                             &gvt_credential_schema,
                                             &gvt_credential_pub_key,
                                             None, None).unwrap();
        proof_verifier.add_sub_proof_request(xyz_key_id,
                                             &xyz_sub_proof_request,
                                             &xyz_credential_schema,
                                             &xyz_credential_pub_key,
                                             None, None).unwrap();

        assert!(proof_verifier.verify(&proof, &nonce).unwrap());
    }

    #[test]
    fn anoncreds_works_for_revocation_proof_for_three_credentials_proving_first() {
        // 1. Issuer creates credential schema
        let credential_schema = helpers::gvt_credential_schema();

        // 2. Issuer creates credential definition(with revocation keys)
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, true).unwrap();

        // 3. Issuer creates revocation registry
        let max_cred_num = 5;
        let issuance_by_default = false;
        let (rev_key_pub, rev_key_priv, mut rev_reg, mut rev_tails_generator) =
            Issuer::new_revocation_registry_def(&credential_pub_key, max_cred_num, issuance_by_default).unwrap();

        let simple_tail_accessor = SimpleTailsAccessor::new(&mut rev_tails_generator).unwrap();

        // 4. Issuer issues first credential
        let master_secret_1 = Prover::new_master_secret().unwrap();
        let master_secret_blinding_nonce = new_nonce().unwrap();
        let (blinded_master_secret, master_secret_blinding_data, blinded_master_secret_correctness_proof) =
            Prover::blind_master_secret(&credential_pub_key,
                                        &credential_key_correctness_proof,
                                        &master_secret_1,
                                        &master_secret_blinding_nonce).unwrap();
        let credential_issuance_nonce = new_nonce().unwrap();
        let credential_values = helpers::gvt_credential_values();
        let rev_idx_1 = 1;
        let (mut credential_signature_1, signature_correctness_proof, rev_reg_delta) =
            Issuer::sign_credential_with_revoc(PROVER_ID,
                                               &blinded_master_secret,
                                               &blinded_master_secret_correctness_proof,
                                               &master_secret_blinding_nonce,
                                               &credential_issuance_nonce,
                                               &credential_values,
                                               &credential_pub_key,
                                               &credential_priv_key,
                                               rev_idx_1,
                                               max_cred_num,
                                               issuance_by_default,
                                               &mut rev_reg,
                                               &rev_key_priv,
                                               &simple_tail_accessor).unwrap();
        let mut full_delta = rev_reg_delta.unwrap();

        let mut witness_1 = Witness::new(rev_idx_1,
                                         max_cred_num,
                                         &full_delta,
                                         &simple_tail_accessor).unwrap();

        Prover::process_credential_signature(&mut credential_signature_1,
                                             &credential_values,
                                             &signature_correctness_proof,
                                             &master_secret_blinding_data,
                                             &master_secret_1,
                                             &credential_pub_key,
                                             &credential_issuance_nonce,
                                             Some(&rev_key_pub),
                                             Some(&rev_reg),
                                             Some(&witness_1)).unwrap();

        // 5. Issuer issues second credential
        let master_secret_2 = Prover::new_master_secret().unwrap();
        let master_secret_blinding_nonce = new_nonce().unwrap();
        let (blinded_master_secret, master_secret_blinding_data, blinded_master_secret_correctness_proof) =
            Prover::blind_master_secret(&credential_pub_key,
                                        &credential_key_correctness_proof,
                                        &master_secret_2,
                                        &master_secret_blinding_nonce).unwrap();
        let credential_issuance_nonce = new_nonce().unwrap();
        let credential_values = helpers::gvt_credential_values();
        let rev_idx_2 = 2;
        let (mut credential_signature_2, signature_correctness_proof, rev_reg_delta) =
            Issuer::sign_credential_with_revoc(PROVER_ID,
                                               &blinded_master_secret,
                                               &blinded_master_secret_correctness_proof,
                                               &master_secret_blinding_nonce,
                                               &credential_issuance_nonce,
                                               &credential_values,
                                               &credential_pub_key,
                                               &credential_priv_key,
                                               rev_idx_2,
                                               max_cred_num,
                                               issuance_by_default,
                                               &mut rev_reg,
                                               &rev_key_priv,
                                               &simple_tail_accessor).unwrap();

        full_delta.merge(&rev_reg_delta.unwrap()).unwrap();

        let witness_2 = Witness::new(rev_idx_2,
                                     max_cred_num,
                                     &full_delta,
                                     &simple_tail_accessor).unwrap();

        Prover::process_credential_signature(&mut credential_signature_2,
                                             &credential_values,
                                             &signature_correctness_proof,
                                             &master_secret_blinding_data,
                                             &master_secret_2,
                                             &credential_pub_key,
                                             &credential_issuance_nonce,
                                             Some(&rev_key_pub),
                                             Some(&rev_reg),
                                             Some(&witness_2)).unwrap();

        // 6. Issuer issues third credential
        let master_secret_3 = Prover::new_master_secret().unwrap();
        let master_secret_blinding_nonce = new_nonce().unwrap();
        let (blinded_master_secret, master_secret_blinding_data, blinded_master_secret_correctness_proof) =
            Prover::blind_master_secret(&credential_pub_key,
                                        &credential_key_correctness_proof,
                                        &master_secret_3,
                                        &master_secret_blinding_nonce).unwrap();
        let credential_issuance_nonce = new_nonce().unwrap();
        let credential_values = helpers::gvt_credential_values();
        let rev_idx_3 = 3;
        let (mut credential_signature_3, signature_correctness_proof, rev_reg_delta) =
            Issuer::sign_credential_with_revoc(PROVER_ID,
                                               &blinded_master_secret,
                                               &blinded_master_secret_correctness_proof,
                                               &master_secret_blinding_nonce,
                                               &credential_issuance_nonce,
                                               &credential_values,
                                               &credential_pub_key,
                                               &credential_priv_key,
                                               rev_idx_3,
                                               max_cred_num,
                                               issuance_by_default,
                                               &mut rev_reg,
                                               &rev_key_priv,
                                               &simple_tail_accessor).unwrap();
        full_delta.merge(&rev_reg_delta.unwrap()).unwrap();

        let witness_3 = Witness::new(rev_idx_3,
                                     max_cred_num,
                                     &full_delta,
                                     &simple_tail_accessor).unwrap();

        Prover::process_credential_signature(&mut credential_signature_3,
                                             &credential_values,
                                             &signature_correctness_proof,
                                             &master_secret_blinding_data,
                                             &master_secret_3,
                                             &credential_pub_key,
                                             &credential_issuance_nonce,
                                             Some(&rev_key_pub),
                                             Some(&rev_reg),
                                             Some(&witness_3)).unwrap();

        // 7. Verifier creates nonce
        let nonce = new_nonce().unwrap();

        // 8. Verifier creates sub proof request
        let sub_proof_request = helpers::gvt_sub_proof_request();

        // Proving first credential
        // 9. Prover updates witness_1
        witness_1.update(rev_idx_1, max_cred_num, &full_delta, &simple_tail_accessor).unwrap();

        // 10. Prover creates proof
        let mut proof_builder = Prover::new_proof_builder().unwrap();
        let key_id = "key_id";
        proof_builder.add_sub_proof_request(key_id,
                                            &sub_proof_request,
                                            &credential_schema,
                                            &credential_signature_1,
                                            &credential_values,
                                            &credential_pub_key,
                                            Some(&rev_reg),
                                            Some(&witness_1)).unwrap();
        let proof = proof_builder.finalize(&nonce, &master_secret_1).unwrap();

        // 11. Verifier verifies proof
        let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
        proof_verifier.add_sub_proof_request(key_id,
                                             &sub_proof_request,
                                             &credential_schema,
                                             &credential_pub_key,
                                             Some(&rev_key_pub),
                                             Some(&rev_reg)).unwrap();
        assert!(proof_verifier.verify(&proof, &nonce).unwrap());
    }

    #[test]
    fn anoncreds_works_for_revocation_proof_for_three_credentials_revoke_first_proving_third() {
        // 1. Issuer creates credential schema
        let credential_schema = helpers::gvt_credential_schema();

        // 2. Issuer creates credential definition(with revocation keys)
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, true).unwrap();

        // 3. Issuer creates revocation registry
        let max_cred_num = 5;
        let issuance_by_default = false;
        let (rev_key_pub, rev_key_priv, mut rev_reg, mut rev_tails_generator) =
            Issuer::new_revocation_registry_def(&credential_pub_key, max_cred_num, issuance_by_default).unwrap();

        let simple_tail_accessor = SimpleTailsAccessor::new(&mut rev_tails_generator).unwrap();

        // 4. Issuer issues first credential
        let master_secret_1 = Prover::new_master_secret().unwrap();
        let master_secret_blinding_nonce = new_nonce().unwrap();
        let (blinded_master_secret, master_secret_blinding_data, blinded_master_secret_correctness_proof) =
            Prover::blind_master_secret(&credential_pub_key,
                                        &credential_key_correctness_proof,
                                        &master_secret_1,
                                        &master_secret_blinding_nonce).unwrap();
        let credential_issuance_nonce = new_nonce().unwrap();
        let credential_values = helpers::gvt_credential_values();
        let rev_idx_1 = 1;
        let (mut credential_signature_1, signature_correctness_proof, rev_reg_delta) =
            Issuer::sign_credential_with_revoc(PROVER_ID,
                                               &blinded_master_secret,
                                               &blinded_master_secret_correctness_proof,
                                               &master_secret_blinding_nonce,
                                               &credential_issuance_nonce,
                                               &credential_values,
                                               &credential_pub_key,
                                               &credential_priv_key,
                                               rev_idx_1,
                                               max_cred_num,
                                               issuance_by_default,
                                               &mut rev_reg,
                                               &rev_key_priv,
                                               &simple_tail_accessor).unwrap();
        let mut full_delta = rev_reg_delta.unwrap();

        let witness_1 = Witness::new(rev_idx_1,
                                     max_cred_num,
                                     &full_delta,
                                     &simple_tail_accessor).unwrap();

        Prover::process_credential_signature(&mut credential_signature_1,
                                             &credential_values,
                                             &signature_correctness_proof,
                                             &master_secret_blinding_data,
                                             &master_secret_1,
                                             &credential_pub_key,
                                             &credential_issuance_nonce,
                                             Some(&rev_key_pub),
                                             Some(&rev_reg),
                                             Some(&witness_1)).unwrap();

        // 5. Issuer issues second credential
        let master_secret_2 = Prover::new_master_secret().unwrap();
        let master_secret_blinding_nonce = new_nonce().unwrap();
        let (blinded_master_secret, master_secret_blinding_data, blinded_master_secret_correctness_proof) =
            Prover::blind_master_secret(&credential_pub_key,
                                        &credential_key_correctness_proof,
                                        &master_secret_2,
                                        &master_secret_blinding_nonce).unwrap();
        let credential_issuance_nonce = new_nonce().unwrap();
        let credential_values = helpers::gvt_credential_values();
        let rev_idx_2 = 2;
        let (mut credential_signature_2, signature_correctness_proof, rev_reg_delta) =
            Issuer::sign_credential_with_revoc(PROVER_ID,
                                               &blinded_master_secret,
                                               &blinded_master_secret_correctness_proof,
                                               &master_secret_blinding_nonce,
                                               &credential_issuance_nonce,
                                               &credential_values,
                                               &credential_pub_key,
                                               &credential_priv_key,
                                               rev_idx_2,
                                               max_cred_num,
                                               issuance_by_default,
                                               &mut rev_reg,
                                               &rev_key_priv,
                                               &simple_tail_accessor).unwrap();
        full_delta.merge(&rev_reg_delta.unwrap()).unwrap();

        let witness_2 = Witness::new(rev_idx_2,
                                     max_cred_num,
                                     &full_delta,
                                     &simple_tail_accessor).unwrap();

        Prover::process_credential_signature(&mut credential_signature_2,
                                             &credential_values,
                                             &signature_correctness_proof,
                                             &master_secret_blinding_data,
                                             &master_secret_2,
                                             &credential_pub_key,
                                             &credential_issuance_nonce,
                                             Some(&rev_key_pub),
                                             Some(&rev_reg),
                                             Some(&witness_2)).unwrap();

        // 6. Issuer issues third credential
        let master_secret_3 = Prover::new_master_secret().unwrap();
        let master_secret_blinding_nonce = new_nonce().unwrap();
        let (blinded_master_secret, master_secret_blinding_data, blinded_master_secret_correctness_proof) =
            Prover::blind_master_secret(&credential_pub_key,
                                        &credential_key_correctness_proof,
                                        &master_secret_3,
                                        &master_secret_blinding_nonce).unwrap();
        let credential_issuance_nonce = new_nonce().unwrap();
        let credential_values = helpers::gvt_credential_values();
        let rev_idx_3 = 3;
        let (mut credential_signature_3, signature_correctness_proof, rev_reg_delta) =
            Issuer::sign_credential_with_revoc(PROVER_ID,
                                               &blinded_master_secret,
                                               &blinded_master_secret_correctness_proof,
                                               &master_secret_blinding_nonce,
                                               &credential_issuance_nonce,
                                               &credential_values,
                                               &credential_pub_key,
                                               &credential_priv_key,
                                               rev_idx_3,
                                               max_cred_num,
                                               issuance_by_default,
                                               &mut rev_reg,
                                               &rev_key_priv,
                                               &simple_tail_accessor).unwrap();
        full_delta.merge(&rev_reg_delta.unwrap()).unwrap();
        let mut delta_for_third = RegistryDelta::from_rev_reg(&rev_reg, 0).to_delta();

        let mut witness_3 = Witness::new(rev_idx_3,
                                         max_cred_num,
                                         &full_delta,
                                         &simple_tail_accessor).unwrap();

        Prover::process_credential_signature(&mut credential_signature_3,
                                             &credential_values,
                                             &signature_correctness_proof,
                                             &master_secret_blinding_data,
                                             &master_secret_3,
                                             &credential_pub_key,
                                             &credential_issuance_nonce,
                                             Some(&rev_key_pub),
                                             Some(&rev_reg),
                                             Some(&witness_3)).unwrap();

        // 7. Issuer revokes first credential
        let rev_reg_delta = Issuer::revoke_credential(&mut rev_reg, max_cred_num, rev_idx_1, &simple_tail_accessor).unwrap();
        full_delta.merge(&rev_reg_delta).unwrap();
        delta_for_third.merge(&rev_reg_delta).unwrap();

        // 8. Verifier creates nonce
        let nonce = new_nonce().unwrap();

        // 9. Verifier creates sub proof request
        let sub_proof_request = helpers::gvt_sub_proof_request();

        // Proving third credential
        // 10. Prover updates witness_1
        witness_3.update(rev_idx_3, max_cred_num, &delta_for_third, &simple_tail_accessor).unwrap();

        // 11. Prover creates proof
        let mut proof_builder = Prover::new_proof_builder().unwrap();
        let key_id = "key_id";
        proof_builder.add_sub_proof_request(key_id,
                                            &sub_proof_request,
                                            &credential_schema,
                                            &credential_signature_3,
                                            &credential_values,
                                            &credential_pub_key,
                                            Some(&rev_reg),
                                            Some(&witness_3)).unwrap();
        let proof = proof_builder.finalize(&nonce, &master_secret_3).unwrap();

        // 12. Verifier verifies proof
        let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
        proof_verifier.add_sub_proof_request(key_id,
                                             &sub_proof_request,
                                             &credential_schema,
                                             &credential_pub_key,
                                             Some(&rev_key_pub),
                                             Some(&rev_reg)).unwrap();
        assert!(proof_verifier.verify(&proof, &nonce).unwrap());
    }

    #[test]
    fn anoncreds_works_for_revocation_proof_for_three_credentials_revoke_third_proving_first() {
        // 1. Issuer creates credential schema
        let credential_schema = helpers::gvt_credential_schema();

        // 2. Issuer creates credential definition(with revocation keys)
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, true).unwrap();

        // 3. Issuer creates revocation registry
        let max_cred_num = 5;
        let issuance_by_default = false;
        let (rev_key_pub, rev_key_priv, mut rev_reg, mut rev_tails_generator) =
            Issuer::new_revocation_registry_def(&credential_pub_key, max_cred_num, issuance_by_default).unwrap();

        let simple_tail_accessor = SimpleTailsAccessor::new(&mut rev_tails_generator).unwrap();

        // 4. Issuer issues first credential
        let master_secret_1 = Prover::new_master_secret().unwrap();
        let master_secret_blinding_nonce = new_nonce().unwrap();
        let (blinded_master_secret, master_secret_blinding_data, blinded_master_secret_correctness_proof) =
            Prover::blind_master_secret(&credential_pub_key,
                                        &credential_key_correctness_proof,
                                        &master_secret_1,
                                        &master_secret_blinding_nonce).unwrap();
        let credential_issuance_nonce = new_nonce().unwrap();
        let credential_values = helpers::gvt_credential_values();
        let rev_idx_1 = 1;
        let (mut credential_signature_1, signature_correctness_proof, rev_reg_delta) =
            Issuer::sign_credential_with_revoc(PROVER_ID,
                                               &blinded_master_secret,
                                               &blinded_master_secret_correctness_proof,
                                               &master_secret_blinding_nonce,
                                               &credential_issuance_nonce,
                                               &credential_values,
                                               &credential_pub_key,
                                               &credential_priv_key,
                                               rev_idx_1,
                                               max_cred_num,
                                               issuance_by_default,
                                               &mut rev_reg,
                                               &rev_key_priv,
                                               &simple_tail_accessor).unwrap();

        let mut full_delta = rev_reg_delta.unwrap();

        let mut witness_1 = Witness::new(rev_idx_1,
                                         max_cred_num,
                                         &full_delta,
                                         &simple_tail_accessor).unwrap();

        Prover::process_credential_signature(&mut credential_signature_1,
                                             &credential_values,
                                             &signature_correctness_proof,
                                             &master_secret_blinding_data,
                                             &master_secret_1,
                                             &credential_pub_key,
                                             &credential_issuance_nonce,
                                             Some(&rev_key_pub),
                                             Some(&rev_reg),
                                             Some(&witness_1)).unwrap();

        // 5. Issuer issues second credential
        let master_secret_2 = Prover::new_master_secret().unwrap();
        let master_secret_blinding_nonce = new_nonce().unwrap();
        let (blinded_master_secret, master_secret_blinding_data, blinded_master_secret_correctness_proof) =
            Prover::blind_master_secret(&credential_pub_key,
                                        &credential_key_correctness_proof,
                                        &master_secret_2,
                                        &master_secret_blinding_nonce).unwrap();
        let credential_issuance_nonce = new_nonce().unwrap();
        let credential_values = helpers::gvt_credential_values();
        let rev_idx_2 = 2;
        let (mut credential_signature_2, signature_correctness_proof, rev_reg_delta) =
            Issuer::sign_credential_with_revoc(PROVER_ID,
                                               &blinded_master_secret,
                                               &blinded_master_secret_correctness_proof,
                                               &master_secret_blinding_nonce,
                                               &credential_issuance_nonce,
                                               &credential_values,
                                               &credential_pub_key,
                                               &credential_priv_key,
                                               rev_idx_2,
                                               max_cred_num,
                                               issuance_by_default,
                                               &mut rev_reg,
                                               &rev_key_priv,
                                               &simple_tail_accessor).unwrap();
        full_delta.merge(&rev_reg_delta.unwrap()).unwrap();

        let witness_2 = Witness::new(rev_idx_2,
                                     max_cred_num,
                                     &full_delta,
                                     &simple_tail_accessor).unwrap();

        Prover::process_credential_signature(&mut credential_signature_2,
                                             &credential_values,
                                             &signature_correctness_proof,
                                             &master_secret_blinding_data,
                                             &master_secret_2,
                                             &credential_pub_key,
                                             &credential_issuance_nonce,
                                             Some(&rev_key_pub),
                                             Some(&rev_reg),
                                             Some(&witness_2)).unwrap();

        // 6. Issuer issues third credential
        let master_secret_3 = Prover::new_master_secret().unwrap();
        let master_secret_blinding_nonce = new_nonce().unwrap();
        let (blinded_master_secret, master_secret_blinding_data, blinded_master_secret_correctness_proof) =
            Prover::blind_master_secret(&credential_pub_key,
                                        &credential_key_correctness_proof,
                                        &master_secret_3,
                                        &master_secret_blinding_nonce).unwrap();
        let credential_issuance_nonce = new_nonce().unwrap();
        let credential_values = helpers::gvt_credential_values();
        let rev_idx_3 = 3;
        let (mut credential_signature_3, signature_correctness_proof, rev_reg_delta) =
            Issuer::sign_credential_with_revoc(PROVER_ID,
                                               &blinded_master_secret,
                                               &blinded_master_secret_correctness_proof,
                                               &master_secret_blinding_nonce,
                                               &credential_issuance_nonce,
                                               &credential_values,
                                               &credential_pub_key,
                                               &credential_priv_key,
                                               rev_idx_3,
                                               max_cred_num,
                                               issuance_by_default,
                                               &mut rev_reg,
                                               &rev_key_priv,
                                               &simple_tail_accessor).unwrap();
        full_delta.merge(&rev_reg_delta.unwrap()).unwrap();

        let witness_3 = Witness::new(rev_idx_3,
                                     max_cred_num,
                                     &full_delta,
                                     &simple_tail_accessor).unwrap();

        Prover::process_credential_signature(&mut credential_signature_3,
                                             &credential_values,
                                             &signature_correctness_proof,
                                             &master_secret_blinding_data,
                                             &master_secret_3,
                                             &credential_pub_key,
                                             &credential_issuance_nonce,
                                             Some(&rev_key_pub),
                                             Some(&rev_reg),
                                             Some(&witness_3)).unwrap();

        // 7. Issuer revokes third credential
        let rev_reg_delta = Issuer::revoke_credential(&mut rev_reg, max_cred_num, rev_idx_3, &simple_tail_accessor).unwrap();
        full_delta.merge(&rev_reg_delta).unwrap();

        // 8. Verifier creates nonce
        let nonce = new_nonce().unwrap();

        // 9. Verifier creates sub proof request
        let sub_proof_request = helpers::gvt_sub_proof_request();

        // Proving first credential
        // 10. Prover updates witness_1
        witness_1.update(rev_idx_1, max_cred_num, &full_delta, &simple_tail_accessor).unwrap();

        // 11. Prover creates proof
        let mut proof_builder = Prover::new_proof_builder().unwrap();
        let key_id = "key_id";
        proof_builder.add_sub_proof_request(key_id,
                                            &sub_proof_request,
                                            &credential_schema,
                                            &credential_signature_1,
                                            &credential_values,
                                            &credential_pub_key,
                                            Some(&rev_reg),
                                            Some(&witness_1)).unwrap();
        let proof = proof_builder.finalize(&nonce, &master_secret_1).unwrap();

        // 12. Verifier verifies proof
        let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
        proof_verifier.add_sub_proof_request(key_id,
                                             &sub_proof_request,
                                             &credential_schema,
                                             &credential_pub_key,
                                             Some(&rev_key_pub),
                                             Some(&rev_reg)).unwrap();
        assert!(proof_verifier.verify(&proof, &nonce).unwrap());
    }

    #[test]
    fn anoncreds_works_for_revocation_proof_for_three_credentials_revoke_first_and_third_proving_second() {
        // 1. Issuer creates credential schema
        let credential_schema = helpers::gvt_credential_schema();

        // 2. Issuer creates credential definition(with revocation keys)
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, true).unwrap();

        // 3. Issuer creates revocation registry
        let max_cred_num = 5;
        let issuance_by_default = false;
        let (rev_key_pub, rev_key_priv, mut rev_reg, mut rev_tails_generator) =
            Issuer::new_revocation_registry_def(&credential_pub_key, max_cred_num, issuance_by_default).unwrap();

        let simple_tail_accessor = SimpleTailsAccessor::new(&mut rev_tails_generator).unwrap();

        // 4. Issuer issues first credential
        let master_secret_1 = Prover::new_master_secret().unwrap();
        let master_secret_blinding_nonce = new_nonce().unwrap();
        let (blinded_master_secret, master_secret_blinding_data, blinded_master_secret_correctness_proof) =
            Prover::blind_master_secret(&credential_pub_key,
                                        &credential_key_correctness_proof,
                                        &master_secret_1,
                                        &master_secret_blinding_nonce).unwrap();
        let credential_issuance_nonce = new_nonce().unwrap();
        let credential_values = helpers::gvt_credential_values();
        let rev_idx_1 = 1;
        let (mut credential_signature_1, signature_correctness_proof, rev_reg_delta) =
            Issuer::sign_credential_with_revoc(PROVER_ID,
                                               &blinded_master_secret,
                                               &blinded_master_secret_correctness_proof,
                                               &master_secret_blinding_nonce,
                                               &credential_issuance_nonce,
                                               &credential_values,
                                               &credential_pub_key,
                                               &credential_priv_key,
                                               rev_idx_1,
                                               max_cred_num,
                                               issuance_by_default,
                                               &mut rev_reg,
                                               &rev_key_priv,
                                               &simple_tail_accessor).unwrap();
        let mut full_delta = rev_reg_delta.unwrap();

        let witness_1 = Witness::new(rev_idx_1,
                                     max_cred_num,
                                     &full_delta,
                                     &simple_tail_accessor).unwrap();

        Prover::process_credential_signature(&mut credential_signature_1,
                                             &credential_values,
                                             &signature_correctness_proof,
                                             &master_secret_blinding_data,
                                             &master_secret_1,
                                             &credential_pub_key,
                                             &credential_issuance_nonce,
                                             Some(&rev_key_pub),
                                             Some(&rev_reg),
                                             Some(&witness_1)).unwrap();

        // 5. Issuer issues second credential
        let master_secret_2 = Prover::new_master_secret().unwrap();
        let master_secret_blinding_nonce = new_nonce().unwrap();
        let (blinded_master_secret, master_secret_blinding_data, blinded_master_secret_correctness_proof) =
            Prover::blind_master_secret(&credential_pub_key,
                                        &credential_key_correctness_proof,
                                        &master_secret_2,
                                        &master_secret_blinding_nonce).unwrap();
        let credential_issuance_nonce = new_nonce().unwrap();
        let credential_values = helpers::gvt_credential_values();
        let rev_idx_2 = 2;
        let (mut credential_signature_2, signature_correctness_proof, rev_reg_delta) =
            Issuer::sign_credential_with_revoc(PROVER_ID,
                                               &blinded_master_secret,
                                               &blinded_master_secret_correctness_proof,
                                               &master_secret_blinding_nonce,
                                               &credential_issuance_nonce,
                                               &credential_values,
                                               &credential_pub_key,
                                               &credential_priv_key,
                                               rev_idx_2,
                                               max_cred_num,
                                               issuance_by_default,
                                               &mut rev_reg,
                                               &rev_key_priv,
                                               &simple_tail_accessor).unwrap();
        full_delta.merge(&rev_reg_delta.unwrap()).unwrap();
        let mut delta_for_second = RegistryDelta::from_rev_reg(&rev_reg, 0).to_delta();

        let mut witness_2 = Witness::new(rev_idx_2,
                                         max_cred_num,
                                         &full_delta,
                                         &simple_tail_accessor).unwrap();

        Prover::process_credential_signature(&mut credential_signature_2,
                                             &credential_values,
                                             &signature_correctness_proof,
                                             &master_secret_blinding_data,
                                             &master_secret_2,
                                             &credential_pub_key,
                                             &credential_issuance_nonce,
                                             Some(&rev_key_pub),
                                             Some(&rev_reg),
                                             Some(&witness_2)).unwrap();

        // 6. Issuer issues third credential
        let master_secret_3 = Prover::new_master_secret().unwrap();
        let master_secret_blinding_nonce = new_nonce().unwrap();
        let (blinded_master_secret, master_secret_blinding_data, blinded_master_secret_correctness_proof) =
            Prover::blind_master_secret(&credential_pub_key,
                                        &credential_key_correctness_proof,
                                        &master_secret_3,
                                        &master_secret_blinding_nonce).unwrap();
        let credential_issuance_nonce = new_nonce().unwrap();
        let credential_values = helpers::gvt_credential_values();
        let rev_idx_3 = 3;
        let (mut credential_signature_3, signature_correctness_proof, rev_reg_delta) =
            Issuer::sign_credential_with_revoc(PROVER_ID,
                                               &blinded_master_secret,
                                               &blinded_master_secret_correctness_proof,
                                               &master_secret_blinding_nonce,
                                               &credential_issuance_nonce,
                                               &credential_values,
                                               &credential_pub_key,
                                               &credential_priv_key,
                                               rev_idx_3,
                                               max_cred_num,
                                               issuance_by_default,
                                               &mut rev_reg,
                                               &rev_key_priv,
                                               &simple_tail_accessor).unwrap();
        let rev_reg_delta = rev_reg_delta.unwrap();
        full_delta.merge(&rev_reg_delta).unwrap();
        delta_for_second.merge(&rev_reg_delta).unwrap();

        let witness_3 = Witness::new(rev_idx_3,
                                     max_cred_num,
                                     &full_delta,
                                     &simple_tail_accessor).unwrap();

        Prover::process_credential_signature(&mut credential_signature_3,
                                             &credential_values,
                                             &signature_correctness_proof,
                                             &master_secret_blinding_data,
                                             &master_secret_3,
                                             &credential_pub_key,
                                             &credential_issuance_nonce,
                                             Some(&rev_key_pub),
                                             Some(&rev_reg),
                                             Some(&witness_3)).unwrap();

        // 7. Issuer revokes first credential
        let rev_reg_delta = Issuer::revoke_credential(&mut rev_reg, max_cred_num, rev_idx_1, &simple_tail_accessor).unwrap();
        full_delta.merge(&rev_reg_delta).unwrap();
        delta_for_second.merge(&rev_reg_delta).unwrap();

        // 8. Issuer revokes third credential
        let rev_reg_delta = Issuer::revoke_credential(&mut rev_reg, max_cred_num, rev_idx_3, &simple_tail_accessor).unwrap();
        full_delta.merge(&rev_reg_delta).unwrap();
        delta_for_second.merge(&rev_reg_delta).unwrap();

        // 9. Verifier creates nonce
        let nonce = new_nonce().unwrap();

        // 10. Verifier creates sub proof request
        let sub_proof_request = helpers::gvt_sub_proof_request();

        // Proving second credential
        // 11. Prover updates witness_2
        witness_2.update(rev_idx_2, max_cred_num, &delta_for_second, &simple_tail_accessor).unwrap();

        // 12. Prover creates proof
        let mut proof_builder = Prover::new_proof_builder().unwrap();
        let key_id = "key_id";
        proof_builder.add_sub_proof_request(key_id,
                                            &sub_proof_request,
                                            &credential_schema,
                                            &credential_signature_2,
                                            &credential_values,
                                            &credential_pub_key,
                                            Some(&rev_reg),
                                            Some(&witness_2)).unwrap();
        let proof = proof_builder.finalize(&nonce, &master_secret_2).unwrap();

        // 13. Verifier verifies proof
        let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
        proof_verifier.add_sub_proof_request(key_id,
                                             &sub_proof_request,
                                             &credential_schema,
                                             &credential_pub_key,
                                             Some(&rev_key_pub),
                                             Some(&rev_reg)).unwrap();
        assert!(proof_verifier.verify(&proof, &nonce).unwrap());
    }

    #[test]
    fn anoncreds_works_for_proof_created_before_credential_revoked() {
        // 1. Issuer creates credential schema
        let credential_schema = helpers::gvt_credential_schema();

        // 2. Issuer creates credential definition(with revocation keys)
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, true).unwrap();

        // 3. Issuer creates revocation registry
        let max_cred_num = 5;
        let issuance_by_default = false;
        let (rev_key_pub, rev_key_priv, mut rev_reg, mut rev_tails_generator) =
            Issuer::new_revocation_registry_def(&credential_pub_key, max_cred_num, issuance_by_default).unwrap();

        let simple_tail_accessor = SimpleTailsAccessor::new(&mut rev_tails_generator).unwrap();

        // 4. Prover creates master secret
        let master_secret = Prover::new_master_secret().unwrap();

        // 5. Issuer creates nonce used Prover to blind master secret
        let master_secret_blinding_nonce = new_nonce().unwrap();

        // 6. Prover blinds master secret
        let (blinded_master_secret, master_secret_blinding_data, blinded_master_secret_correctness_proof) =
            Prover::blind_master_secret(&credential_pub_key,
                                        &credential_key_correctness_proof,
                                        &master_secret,
                                        &master_secret_blinding_nonce).unwrap();

        // 7. Prover creates nonce used Issuer to credential issue
        let credential_issuance_nonce = new_nonce().unwrap();

        // 8. Issuer creates and sign credential values
        let credential_values = helpers::gvt_credential_values();

        let rev_idx = 1;
        let (mut credential_signature, signature_correctness_proof, rev_reg_delta) =
            Issuer::sign_credential_with_revoc(PROVER_ID,
                                               &blinded_master_secret,
                                               &blinded_master_secret_correctness_proof,
                                               &master_secret_blinding_nonce,
                                               &credential_issuance_nonce,
                                               &credential_values,
                                               &credential_pub_key,
                                               &credential_priv_key,
                                               rev_idx,
                                               max_cred_num,
                                               issuance_by_default,
                                               &mut rev_reg,
                                               &rev_key_priv,
                                               &simple_tail_accessor).unwrap();

        // 9. Prover creates witness
        let witness = Witness::new(rev_idx,
                                   max_cred_num,
                                   &rev_reg_delta.unwrap(),
                                   &simple_tail_accessor).unwrap();

        // 10. Prover processes credential signature
        Prover::process_credential_signature(&mut credential_signature,
                                             &credential_values,
                                             &signature_correctness_proof,
                                             &master_secret_blinding_data,
                                             &master_secret,
                                             &credential_pub_key,
                                             &credential_issuance_nonce,
                                             Some(&rev_key_pub),
                                             Some(&rev_reg),
                                             Some(&witness)).unwrap();

        // 11. Verifier creates nonce
        let nonce = new_nonce().unwrap();

        // 12. Verifier create sub proof request
        let sub_proof_request = helpers::gvt_sub_proof_request();

        // 13. Prover creates proof
        let mut proof_builder = Prover::new_proof_builder().unwrap();
        let key_id = "key_id";
        proof_builder.add_sub_proof_request(key_id,
                                            &sub_proof_request,
                                            &credential_schema,
                                            &credential_signature,
                                            &credential_values,
                                            &credential_pub_key,
                                            Some(&rev_reg),
                                            Some(&witness)).unwrap();
        let proof = proof_builder.finalize(&nonce, &master_secret).unwrap();

        // 14. Issuer revokes credential used for proof building
        Issuer::revoke_credential(&mut rev_reg, max_cred_num, rev_idx, &simple_tail_accessor).unwrap();

        // 15. Verifier verifies proof
        let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
        proof_verifier.add_sub_proof_request(key_id,
                                             &sub_proof_request,
                                             &credential_schema,
                                             &credential_pub_key,
                                             Some(&rev_key_pub),
                                             Some(&rev_reg)).unwrap();
        assert_eq!(false, proof_verifier.verify(&proof, &nonce).unwrap());
    }

    #[test]
    fn anoncreds_works_for_proof_created_after_credential_revoked() {
        // 1. Issuer creates credential schema
        let credential_schema = helpers::gvt_credential_schema();

        // 2. Issuer creates credential definition(with revocation keys)
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, true).unwrap();

        // 3. Issuer creates revocation registry
        let max_cred_num = 5;
        let issuance_by_default = false;
        let (rev_key_pub, rev_key_priv, mut rev_reg, mut rev_tails_generator) =
            Issuer::new_revocation_registry_def(&credential_pub_key, max_cred_num, issuance_by_default).unwrap();

        let simple_tail_accessor = SimpleTailsAccessor::new(&mut rev_tails_generator).unwrap();

        // 4. Prover creates master secret
        let master_secret = Prover::new_master_secret().unwrap();

        // 5. Issuer creates nonce used Prover to blind master secret
        let master_secret_blinding_nonce = new_nonce().unwrap();

        // 6. Prover blinds master secret
        let (blinded_master_secret, master_secret_blinding_data, blinded_master_secret_correctness_proof) =
            Prover::blind_master_secret(&credential_pub_key,
                                        &credential_key_correctness_proof,
                                        &master_secret,
                                        &master_secret_blinding_nonce).unwrap();

        // 7. Prover creates nonce used Issuer to credential issue
        let credential_issuance_nonce = new_nonce().unwrap();

        // 8. Issuer creates and sign credential values
        let credential_values = helpers::gvt_credential_values();

        let rev_idx = 1;
        let (mut credential_signature, signature_correctness_proof, rev_reg_delta) =
            Issuer::sign_credential_with_revoc(PROVER_ID,
                                               &blinded_master_secret,
                                               &blinded_master_secret_correctness_proof,
                                               &master_secret_blinding_nonce,
                                               &credential_issuance_nonce,
                                               &credential_values,
                                               &credential_pub_key,
                                               &credential_priv_key,
                                               rev_idx,
                                               max_cred_num,
                                               issuance_by_default,
                                               &mut rev_reg,
                                               &rev_key_priv,
                                               &simple_tail_accessor).unwrap();

        // 9. Prover creates witness
        let witness = Witness::new(rev_idx,
                                   max_cred_num,
                                   &rev_reg_delta.unwrap(),
                                   &simple_tail_accessor).unwrap();

        // 10. Prover processes credential signature
        Prover::process_credential_signature(&mut credential_signature,
                                             &credential_values,
                                             &signature_correctness_proof,
                                             &master_secret_blinding_data,
                                             &master_secret,
                                             &credential_pub_key,
                                             &credential_issuance_nonce,
                                             Some(&rev_key_pub),
                                             Some(&rev_reg),
                                             Some(&witness)).unwrap();

        // 11. Verifier creates nonce
        let nonce = new_nonce().unwrap();

        // 12. Verifier create sub proof request
        let sub_proof_request = helpers::gvt_sub_proof_request();

        // 13. Issuer revokes credential
        Issuer::revoke_credential(&mut rev_reg, max_cred_num, rev_idx, &simple_tail_accessor).unwrap();

        // 14. Prover creates proof
        let mut proof_builder = Prover::new_proof_builder().unwrap();
        let key_id = "key_id";
        proof_builder.add_sub_proof_request(key_id,
                                            &sub_proof_request,
                                            &credential_schema,
                                            &credential_signature,
                                            &credential_values,
                                            &credential_pub_key,
                                            Some(&rev_reg),
                                            Some(&witness)).unwrap();
        let proof = proof_builder.finalize(&nonce, &master_secret).unwrap();

        // 15. Verifier verifies proof
        let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
        proof_verifier.add_sub_proof_request(key_id,
                                             &sub_proof_request,
                                             &credential_schema,
                                             &credential_pub_key,
                                             Some(&rev_key_pub),
                                             Some(&rev_reg)).unwrap();
        assert_eq!(false, proof_verifier.verify(&proof, &nonce).unwrap());
    }

    #[test]
    #[ignore]
    fn anoncreds_works_for_full_accumulator() {
        // 1. Issuer creates credential schema
        let credential_schema = helpers::gvt_credential_schema();

        // 2. Issuer creates credential definition(with revocation keys)
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, true).unwrap();

        // 3. Issuer creates revocation registry for only 1 credential
        let max_cred_num = 1;
        let (_, rev_key_priv, mut rev_reg, mut rev_tails_generator) =
            Issuer::new_revocation_registry_def(&credential_pub_key, max_cred_num, false).unwrap();

        let simple_tail_accessor = SimpleTailsAccessor::new(&mut rev_tails_generator).unwrap();

        // 4. Prover creates master secret
        let master_secret = Prover::new_master_secret().unwrap();

        // 5. Issuer creates nonce used Prover to blind master secret
        let master_secret_blinding_nonce = new_nonce().unwrap();

        // 6. Prover blinds master secret
        let (blinded_master_secret, _, blinded_master_secret_correctness_proof) =
            Prover::blind_master_secret(&credential_pub_key,
                                        &credential_key_correctness_proof,
                                        &master_secret,
                                        &master_secret_blinding_nonce).unwrap();

        // 7. Prover creates nonce used Issuer to credential issue
        let credential_issuance_nonce = new_nonce().unwrap();

        // 8. Issuer creates and sign first credential values
        let credential_values = helpers::gvt_credential_values();

        Issuer::sign_credential_with_revoc(PROVER_ID,
                                           &blinded_master_secret,
                                           &blinded_master_secret_correctness_proof,
                                           &master_secret_blinding_nonce,
                                           &credential_issuance_nonce,
                                           &credential_values,
                                           &credential_pub_key,
                                           &credential_priv_key,
                                           1,
                                           max_cred_num,
                                           false,
                                           &mut rev_reg,
                                           &rev_key_priv,
                                           &simple_tail_accessor).unwrap();

        // 9. Issuer creates and sign second credential values
        let res = Issuer::sign_credential_with_revoc(&format!("{}2", PROVER_ID),
                                                     &blinded_master_secret,
                                                     &blinded_master_secret_correctness_proof,
                                                     &master_secret_blinding_nonce,
                                                     &credential_issuance_nonce,
                                                     &credential_values,
                                                     &credential_pub_key,
                                                     &credential_priv_key,
                                                     2,
                                                     max_cred_num,
                                                     false,
                                                     &mut rev_reg,
                                                     &rev_key_priv,
                                                     &simple_tail_accessor);
        assert_eq!(ErrorCode::AnoncredsRevocationAccumulatorIsFull, res.unwrap_err().to_error_code());
    }

    #[test]
    #[ignore]
    fn anoncreds_works_for_reissue_credential() {
        // 1. Issuer creates credential schema
        let credential_schema = helpers::gvt_credential_schema();

        // 2. Issuer creates credential definition(with revocation keys)
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, true).unwrap();

        // 3. Issuer creates revocation registry
        let max_cred_num = 1;
        let (rev_key_pub, rev_key_priv, mut rev_reg, mut rev_tails_generator) =
            Issuer::new_revocation_registry_def(&credential_pub_key, max_cred_num, false).unwrap();

        let simple_tail_accessor = SimpleTailsAccessor::new(&mut rev_tails_generator).unwrap();

        let rev_idx = 1;

        // FIRST Issue of credential
        // 4. Prover creates master secret
        let master_secret = Prover::new_master_secret().unwrap();

        // 5. Issuer creates nonce used Prover to blind master secret
        let master_secret_blinding_nonce = new_nonce().unwrap();

        // 6. Prover blinds master secret
        let (blinded_master_secret, master_secret_blinding_data, blinded_master_secret_correctness_proof) =
            Prover::blind_master_secret(&credential_pub_key,
                                        &credential_key_correctness_proof,
                                        &master_secret,
                                        &master_secret_blinding_nonce).unwrap();

        // 7. Prover creates nonce used Issuer to credential issue
        let credential_issuance_nonce = new_nonce().unwrap();

        // 8. Issuer creates and signs credential values
        let credential_values = helpers::gvt_credential_values();
        let (mut credential_signature, signature_correctness_proof, rev_reg_delta) =
            Issuer::sign_credential_with_revoc(PROVER_ID,
                                               &blinded_master_secret,
                                               &blinded_master_secret_correctness_proof,
                                               &master_secret_blinding_nonce,
                                               &credential_issuance_nonce,
                                               &credential_values,
                                               &credential_pub_key,
                                               &credential_priv_key,
                                               rev_idx,
                                               max_cred_num,
                                               false,
                                               &mut rev_reg,
                                               &rev_key_priv,
                                               &simple_tail_accessor).unwrap();

        let mut full_delta = rev_reg_delta.unwrap();

        // 9. Prover creates witness
        let witness = Witness::new(rev_idx,
                                   max_cred_num,
                                   &full_delta,
                                   &simple_tail_accessor).unwrap();

        // 10. Prover processes credential signature
        Prover::process_credential_signature(&mut credential_signature,
                                             &credential_values,
                                             &signature_correctness_proof,
                                             &master_secret_blinding_data,
                                             &master_secret,
                                             &credential_pub_key,
                                             &credential_issuance_nonce,
                                             Some(&rev_key_pub),
                                             Some(&rev_reg),
                                             Some(&witness)).unwrap();

        // Create proof by issued credential
        // 11. Verifier creates nonce
        let nonce = new_nonce().unwrap();

        // 12. Verifier creates sub proof request
        let sub_proof_request = helpers::gvt_sub_proof_request();

        // 13. Prover creates proof
        let mut proof_builder = Prover::new_proof_builder().unwrap();
        let key_id = "key_id";
        proof_builder.add_sub_proof_request(key_id,
                                            &sub_proof_request,
                                            &credential_schema,
                                            &credential_signature,
                                            &credential_values,
                                            &credential_pub_key,
                                            Some(&rev_reg),
                                            Some(&witness)).unwrap();
        let proof = proof_builder.finalize(&nonce, &master_secret).unwrap();

        // 14. Verifier verifies proof
        let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
        proof_verifier.add_sub_proof_request(key_id,
                                             &sub_proof_request,
                                             &credential_schema,
                                             &credential_pub_key,
                                             Some(&rev_key_pub),
                                             Some(&rev_reg)).unwrap();
        assert_eq!(true, proof_verifier.verify(&proof, &nonce).unwrap());

        // 15. Issuer revokes credential used for proof building
        let rev_reg_delta = Issuer::revoke_credential(&mut rev_reg, rev_idx, max_cred_num, &simple_tail_accessor).unwrap();
        full_delta.merge(&rev_reg_delta).unwrap();

        // 16. Verifier verifies proof after revocation
        let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
        proof_verifier.add_sub_proof_request(key_id,
                                             &sub_proof_request,
                                             &credential_schema,
                                             &credential_pub_key,
                                             Some(&rev_key_pub),
                                             Some(&rev_reg)).unwrap();
        assert_eq!(false, proof_verifier.verify(&proof, &nonce).unwrap());

        // Reissue credential with different values but same rev_index

        // 16. Issuer creates nonce used Prover to blind master secret
        let new_master_secret_blinding_nonce = new_nonce().unwrap();

        // 17. Prover blinds master secret
        let (new_blinded_master_secret, new_master_secret_blinding_data, new_blinded_master_secret_correctness_proof) =
            Prover::blind_master_secret(&credential_pub_key,
                                        &credential_key_correctness_proof,
                                        &master_secret,
                                        &new_master_secret_blinding_nonce).unwrap();

        // 18. Prover creates nonce used Issuer to new credential issue
        let new_credential_issuance_nonce = new_nonce().unwrap();

        // 19. Issuer creates and signs new credential values
        let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();
        credential_values_builder.add_value("name", "1139481716457488690172217916278103335").unwrap();
        credential_values_builder.add_value("sex", "5944657099558967239210949258394887428692050081607692519917050011144233115103").unwrap();
        credential_values_builder.add_value("age", "44").unwrap();
        credential_values_builder.add_value("height", "165").unwrap();
        let credential_values = credential_values_builder.finalize().unwrap();

        let (mut new_credential_signature, new_signature_correctness_proof, rev_reg_delta) =
            Issuer::sign_credential_with_revoc(PROVER_ID,
                                               &new_blinded_master_secret,
                                               &new_blinded_master_secret_correctness_proof,
                                               &new_master_secret_blinding_nonce,
                                               &new_credential_issuance_nonce,
                                               &credential_values,
                                               &credential_pub_key,
                                               &credential_priv_key,
                                               rev_idx,
                                               max_cred_num,
                                               false,
                                               &mut rev_reg,
                                               &rev_key_priv,
                                               &simple_tail_accessor).unwrap();
        full_delta.merge(&rev_reg_delta.unwrap()).unwrap();

        let witness = Witness::new(rev_idx,
                                   max_cred_num,
                                   &full_delta,
                                   &simple_tail_accessor).unwrap();

        // 20. Prover processes new credential signature
        Prover::process_credential_signature(&mut new_credential_signature,
                                             &credential_values,
                                             &new_signature_correctness_proof,
                                             &new_master_secret_blinding_data,
                                             &master_secret,
                                             &credential_pub_key,
                                             &new_credential_issuance_nonce,
                                             Some(&rev_key_pub),
                                             Some(&rev_reg),
                                             Some(&witness)).unwrap();
        // 21. Prover creates proof using new credential
        let mut new_proof_builder = Prover::new_proof_builder().unwrap();

        new_proof_builder.add_sub_proof_request(key_id,
                                                &sub_proof_request,
                                                &credential_schema,
                                                &new_credential_signature,
                                                &credential_values,
                                                &credential_pub_key,
                                                Some(&rev_reg),
                                                Some(&witness)).unwrap();

        let new_proof = proof_builder.finalize(&nonce, &master_secret).unwrap();

        // 22. Verifier verifies proof created by new credential
        let mut new_proof_verifier = Verifier::new_proof_verifier().unwrap();
        new_proof_verifier.add_sub_proof_request(key_id,
                                                 &sub_proof_request,
                                                 &credential_schema,
                                                 &credential_pub_key,
                                                 Some(&rev_key_pub),
                                                 Some(&rev_reg)).unwrap();
        assert!(new_proof_verifier.verify(&new_proof, &nonce).unwrap());

        // 23. Verifier verifies proof created before the first credential had been revoked
        let mut old_proof_verifier = Verifier::new_proof_verifier().unwrap();
        old_proof_verifier.add_sub_proof_request(key_id,
                                                 &sub_proof_request,
                                                 &credential_schema,
                                                 &credential_pub_key,
                                                 Some(&rev_key_pub),
                                                 Some(&rev_reg)).unwrap();
        assert_eq!(false, old_proof_verifier.verify(&proof, &nonce).unwrap());
    }

    #[test]
    fn anoncreds_works_for_missed_process_credential_step() {
        // 1. Issuer creates credential schema
        let credential_schema = helpers::gvt_credential_schema();

        // 2. Issuer creates credential definition
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, false).unwrap();

        // 3. Prover creates master secret
        let master_secret = Prover::new_master_secret().unwrap();

        // 4. Issuer creates nonce used Prover to blind master secret
        let master_secret_blinding_nonce = new_nonce().unwrap();

        // 5. Prover blinds master secret
        let (blinded_master_secret, _, blinded_master_secret_correctness_proof) =
            Prover::blind_master_secret(&credential_pub_key,
                                        &credential_key_correctness_proof,
                                        &master_secret,
                                        &master_secret_blinding_nonce).unwrap();

        // 6. Prover creates nonce used Issuer to credential issue
        let credential_issuance_nonce = new_nonce().unwrap();

        // 7. Issuer creates and signs credential values
        let credential_values = helpers::gvt_credential_values();
        let (credential_signature, _) = Issuer::sign_credential(PROVER_ID,
                                                                &blinded_master_secret,
                                                                &blinded_master_secret_correctness_proof,
                                                                &master_secret_blinding_nonce,
                                                                &credential_issuance_nonce,
                                                                &credential_values,
                                                                &credential_pub_key,
                                                                &credential_priv_key).unwrap();

        // 8. Verifier creates nonce and sub proof request
        let nonce = new_nonce().unwrap();
        let sub_proof_request = helpers::gvt_sub_proof_request();

        // 9. Prover creates proof by sub proof request not corresponded to verifier proof request
        let key_id = "key_id";

        let mut proof_builder = Prover::new_proof_builder().unwrap();
        proof_builder.add_sub_proof_request(key_id,
                                            &sub_proof_request,
                                            &credential_schema,
                                            &credential_signature,
                                            &credential_values,
                                            &credential_pub_key,
                                            None, None).unwrap();
        let proof = proof_builder.finalize(&nonce, &master_secret).unwrap();

        // 10. Verifier verifies proof
        let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
        proof_verifier.add_sub_proof_request(key_id,
                                             &sub_proof_request,
                                             &credential_schema,
                                             &credential_pub_key,
                                             None, None).unwrap();
        assert_eq!(false, proof_verifier.verify(&proof, &nonce).unwrap());
    }

    #[test]
    fn anoncreds_works_for_proof_created_with_wrong_master_secret() {
        // 1. Issuer creates credential schema
        let credential_schema = helpers::gvt_credential_schema();

        // 2. Issuer creates credential definition
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, false).unwrap();

        // 3. Prover creates master secret
        let master_secret = Prover::new_master_secret().unwrap();

        // 4. Issuer creates nonce used Prover to blind master secret
        let master_secret_blinding_nonce = new_nonce().unwrap();

        // 5. Prover blinds master secret
        let (blinded_master_secret, master_secret_blinding_data, blinded_master_secret_correctness_proof) =
            Prover::blind_master_secret(&credential_pub_key,
                                        &credential_key_correctness_proof,
                                        &master_secret,
                                        &master_secret_blinding_nonce).unwrap();

        // 6. Prover creates nonce used Issuer to credential issue
        let credential_issuance_nonce = new_nonce().unwrap();

        // 7. Issuer creates and signs credential values wrong keys
        let credential_values = helpers::gvt_credential_values();
        let (mut credential_signature, signature_correctness_proof) = Issuer::sign_credential(PROVER_ID,
                                                                                              &blinded_master_secret,
                                                                                              &blinded_master_secret_correctness_proof,
                                                                                              &master_secret_blinding_nonce,
                                                                                              &credential_issuance_nonce,
                                                                                              &credential_values,
                                                                                              &credential_pub_key,
                                                                                              &credential_priv_key).unwrap();

        // 8. Prover processes credential signature
        Prover::process_credential_signature(&mut credential_signature,
                                             &credential_values,
                                             &signature_correctness_proof,
                                             &master_secret_blinding_data,
                                             &master_secret,
                                             &credential_pub_key,
                                             &credential_issuance_nonce,
                                             None, None, None).unwrap();

        // 9. Verifier creates nonce and sub proof request
        let nonce = new_nonce().unwrap();
        let sub_proof_request = helpers::gvt_sub_proof_request();

        // 10. Prover creates proof by sub proof request not corresponded to verifier proof request
        let key_id = "key_id";

        let mut proof_builder = Prover::new_proof_builder().unwrap();
        proof_builder.add_sub_proof_request(key_id,
                                            &sub_proof_request,
                                            &credential_schema,
                                            &credential_signature,
                                            &credential_values,
                                            &credential_pub_key,
                                            None, None).unwrap();

        let another_master_secret = Prover::new_master_secret().unwrap();
        let proof = proof_builder.finalize(&nonce, &another_master_secret).unwrap();

        // 11. Verifier verifies proof
        let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
        proof_verifier.add_sub_proof_request(key_id,
                                             &sub_proof_request,
                                             &credential_schema,
                                             &credential_pub_key,
                                             None,
                                             None).unwrap();
        assert_eq!(false, proof_verifier.verify(&proof, &nonce).unwrap());
    }

    #[test]
    fn anoncreds_works_for_used_different_nonce() {
        // 1. Issuer creates credential schema
        let credential_schema = helpers::gvt_credential_schema();

        // 2. Issuer creates credential definition
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, false).unwrap();

        // 3. Prover creates master secret
        let master_secret = Prover::new_master_secret().unwrap();

        // 4. Issuer creates nonce used Prover to blind master secret
        let master_secret_blinding_nonce = new_nonce().unwrap();

        // 5. Prover blinds master secret
        let (blinded_master_secret, master_secret_blinding_data, blinded_master_secret_correctness_proof) =
            Prover::blind_master_secret(&credential_pub_key,
                                        &credential_key_correctness_proof,
                                        &master_secret,
                                        &master_secret_blinding_nonce).unwrap();

        // 6. Prover creates nonce used Issuer to credential issue
        let credential_issuance_nonce = new_nonce().unwrap();

        // 7. Issuer creates and signs credential values wrong keys
        let credential_values = helpers::gvt_credential_values();
        let (mut credential_signature, signature_correctness_proof) = Issuer::sign_credential(PROVER_ID,
                                                                                              &blinded_master_secret,
                                                                                              &blinded_master_secret_correctness_proof,
                                                                                              &master_secret_blinding_nonce,
                                                                                              &credential_issuance_nonce,
                                                                                              &credential_values,
                                                                                              &credential_pub_key,
                                                                                              &credential_priv_key).unwrap();

        // 8. Prover processes credential signature
        Prover::process_credential_signature(&mut credential_signature,
                                             &credential_values,
                                             &signature_correctness_proof,
                                             &master_secret_blinding_data,
                                             &master_secret,
                                             &credential_pub_key,
                                             &credential_issuance_nonce,
                                             None, None, None).unwrap();

        // 9. Verifier creates sub proof request
        let sub_proof_request = helpers::gvt_sub_proof_request();

        // 10. Prover creates proof by sub proof request not corresponded to verifier proof request
        let key_id = "key_id";
        let nonce_for_proof_creation = new_nonce().unwrap();

        let mut proof_builder = Prover::new_proof_builder().unwrap();
        proof_builder.add_sub_proof_request(key_id,
                                            &sub_proof_request,
                                            &credential_schema,
                                            &credential_signature,
                                            &credential_values,
                                            &credential_pub_key,
                                            None, None).unwrap();

        let proof = proof_builder.finalize(&nonce_for_proof_creation, &master_secret).unwrap();

        // 11. Verifier verifies proof
        let nonce_for_proof_verification = new_nonce().unwrap();

        let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
        proof_verifier.add_sub_proof_request(key_id,
                                             &sub_proof_request,
                                             &credential_schema,
                                             &credential_pub_key,
                                             None,
                                             None).unwrap();
        assert_eq!(false, proof_verifier.verify(&proof, &nonce_for_proof_verification).unwrap());
    }

    #[test]
    fn anoncreds_works_for_proof_not_correspond_to_verifier_proof_request() {
        // 1. Issuer creates credential schema
        let credential_schema = helpers::gvt_credential_schema();

        // 2. Issuer creates credential definition
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, false).unwrap();

        // 3. Prover creates master secret
        let master_secret = Prover::new_master_secret().unwrap();

        // 4. Issuer creates nonce used Prover to blind master secret
        let master_secret_blinding_nonce = new_nonce().unwrap();

        // 5. Prover blinds master secret
        let (blinded_master_secret, master_secret_blinding_data, blinded_master_secret_correctness_proof) =
            Prover::blind_master_secret(&credential_pub_key,
                                        &credential_key_correctness_proof,
                                        &master_secret,
                                        &master_secret_blinding_nonce).unwrap();

        // 6. Prover creates nonce used Issuer to credential issue
        let credential_issuance_nonce = new_nonce().unwrap();

        // 7. Issuer creates and signs credential values
        let credential_values = helpers::gvt_credential_values();
        let (mut credential_signature, signature_correctness_proof) = Issuer::sign_credential(PROVER_ID,
                                                                                              &blinded_master_secret,
                                                                                              &blinded_master_secret_correctness_proof,
                                                                                              &master_secret_blinding_nonce,
                                                                                              &credential_issuance_nonce,
                                                                                              &credential_values,
                                                                                              &credential_pub_key,
                                                                                              &credential_priv_key).unwrap();

        // 8. Prover processes credential signature
        Prover::process_credential_signature(&mut credential_signature,
                                             &credential_values,
                                             &signature_correctness_proof,
                                             &master_secret_blinding_data,
                                             &master_secret,
                                             &credential_pub_key,
                                             &credential_issuance_nonce,
                                             None, None, None).unwrap();

        // 9. Prover creates proof by sub proof request not corresponded to verifier proof request
        let sub_proof_request = helpers::gvt_sub_proof_request();

        let mut proof_builder = Prover::new_proof_builder().unwrap();
        let nonce = new_nonce().unwrap();

        let key_id = "key_id";
        proof_builder.add_sub_proof_request(key_id,
                                            &sub_proof_request,
                                            &credential_schema,
                                            &credential_signature,
                                            &credential_values,
                                            &credential_pub_key,
                                            None, None).unwrap();
        let proof = proof_builder.finalize(&nonce, &master_secret).unwrap();

        // 10. Verifier verifies proof
        let xyz_credential_schema = helpers::xyz_credential_schema();
        let (xyz_credential_pub_key, _, _) = Issuer::new_credential_def(&xyz_credential_schema, false).unwrap();
        let xyz_sub_proof_request = helpers::xyz_sub_proof_request();

        let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
        proof_verifier.add_sub_proof_request(key_id,
                                             &xyz_sub_proof_request,
                                             &xyz_credential_schema,
                                             &xyz_credential_pub_key,
                                             None, None).unwrap();
        let res = proof_verifier.verify(&proof, &nonce);
        assert_eq!(ErrorCode::AnoncredsProofRejected, res.unwrap_err().to_error_code());
    }

    #[test]
    fn issuer_create_keys_works_for_empty_credential_schema() {
        // 1. Issuer creates credential schema
        let credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
        let credential_schema = credential_schema_builder.finalize().unwrap();

        // 2. Issuer creates credential definition(with revocation keys)
        let res = Issuer::new_credential_def(&credential_schema, false);
        assert_eq!(ErrorCode::CommonInvalidStructure, res.unwrap_err().to_error_code());
    }

    #[test]
    fn issuer_create_revocation_registry_works_for_keys_without_revocation_part() {
        // 1. Issuer creates credential schema
        let credential_schema = helpers::gvt_credential_schema();

        // 2. Issuer creates credential definition(without revocation part)
        let (credential_pub_key, _, _) = Issuer::new_credential_def(&credential_schema, false).unwrap();

        // 3. Issuer creates revocation registry
        let res =
            Issuer::new_revocation_registry_def(&credential_pub_key, 5, false);
        assert_eq!(ErrorCode::CommonInvalidStructure, res.unwrap_err().to_error_code());
    }

    #[test]
    #[ignore]
    fn issuer_revoke_works_for_invalid_revocation_index() {
        // 1. Issuer creates credential schema
        let credential_schema = helpers::gvt_credential_schema();

        // 2. Issuer creates credential definition(with revocation keys)
        let (credential_pub_key, _, _) = Issuer::new_credential_def(&credential_schema, true).unwrap();

        // 3. Issuer creates revocation registry
        let max_cred_num = 5;
        let (_, _, mut rev_reg, mut rev_tails_generator) =
            Issuer::new_revocation_registry_def(&credential_pub_key, max_cred_num, false).unwrap();

        let simple_tail_accessor = SimpleTailsAccessor::new(&mut rev_tails_generator).unwrap();

        // 4. Issuer tries revoke not not added index
        let rev_idx = 1;
        let res = Issuer::revoke_credential(&mut rev_reg, max_cred_num, rev_idx, &simple_tail_accessor);
        assert_eq!(ErrorCode::AnoncredsInvalidRevocationAccumulatorIndex, res.unwrap_err().to_error_code());
    }

    #[test]
    fn issuer_sign_credential_works_for_credential_values_not_correspond_to_issuer_keys() {
        // 1. Issuer creates credential schema
        let credential_schema = helpers::gvt_credential_schema();

        // 2. Issuer creates credential definition
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, false).unwrap();

        // 3. Prover creates master secret
        let master_secret = Prover::new_master_secret().unwrap();

        // 4. Issuer creates nonce used Prover to blind master secret
        let master_secret_blinding_nonce = new_nonce().unwrap();

        // 5. Prover blinds master secret
        let (blinded_master_secret, _, blinded_master_secret_correctness_proof) =
            Prover::blind_master_secret(&credential_pub_key,
                                        &credential_key_correctness_proof,
                                        &master_secret,
                                        &master_secret_blinding_nonce).unwrap();

        // 6. Prover creates nonce used Issuer to credential issue
        let credential_issuance_nonce = new_nonce().unwrap();

        // 7. Issuer creates credential values not correspondent to issuer keys
        let credential_values = helpers::xyz_credential_values();

        // 8. Issuer signs wrong credential values
        let res = Issuer::sign_credential(PROVER_ID,
                                          &blinded_master_secret,
                                          &blinded_master_secret_correctness_proof,
                                          &master_secret_blinding_nonce,
                                          &credential_issuance_nonce,
                                          &credential_values,
                                          &credential_pub_key,
                                          &credential_priv_key);

        assert_eq!(ErrorCode::CommonInvalidStructure, res.unwrap_err().to_error_code());
    }

    #[test]
    fn proof_builder_add_sub_proof_works_for_credential_values_not_correspond_to_credential_schema() {
        // 1. Issuer creates credential schema
        let credential_schema = helpers::gvt_credential_schema();

        // 2. Issuer creates credential definition
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, false).unwrap();

        // 3. Prover creates master secret
        let master_secret = Prover::new_master_secret().unwrap();

        // 4. Issuer creates nonce used Prover to blind master secret
        let master_secret_blinding_nonce = new_nonce().unwrap();

        // 5. Prover blinds master secret
        let (blinded_master_secret, master_secret_blinding_data, blinded_master_secret_correctness_proof) =
            Prover::blind_master_secret(&credential_pub_key,
                                        &credential_key_correctness_proof,
                                        &master_secret,
                                        &master_secret_blinding_nonce).unwrap();

        // 6. Prover creates nonce used Issuer to credential issue
        let credential_issuance_nonce = new_nonce().unwrap();

        // 7. Issuer creates and signs credential values
        let credential_values = helpers::gvt_credential_values();
        let (mut credential_signature, signature_correctness_proof) = Issuer::sign_credential(PROVER_ID,
                                                                                              &blinded_master_secret,
                                                                                              &blinded_master_secret_correctness_proof,
                                                                                              &master_secret_blinding_nonce,
                                                                                              &credential_issuance_nonce,
                                                                                              &credential_values,
                                                                                              &credential_pub_key,
                                                                                              &credential_priv_key).unwrap();

        // 8. Prover processes credential signature
        Prover::process_credential_signature(&mut credential_signature,
                                             &credential_values,
                                             &signature_correctness_proof,
                                             &master_secret_blinding_data,
                                             &master_secret,
                                             &credential_pub_key,
                                             &credential_issuance_nonce,
                                             None, None, None).unwrap();

        // 9. Prover creates proof
        let mut proof_builder = Prover::new_proof_builder().unwrap();

        // Wrong credential values
        let credential_values = helpers::xyz_credential_values();

        let sub_proof_request = helpers::gvt_sub_proof_request();

        let key_id = "key_id";
        let res = proof_builder.add_sub_proof_request(key_id,
                                                      &sub_proof_request,
                                                      &credential_schema,
                                                      &credential_signature,
                                                      &credential_values,
                                                      &credential_pub_key,
                                                      None, None);

        assert_eq!(ErrorCode::CommonInvalidStructure, res.unwrap_err().to_error_code());
    }

    #[test]
    fn proof_builder_add_sub_proof_works_for_credential_not_satisfy_to_sub_proof_request() {
        // 1. Issuer creates credential schema
        let credential_schema = helpers::gvt_credential_schema();

        // 2. Issuer creates credential definition
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, false).unwrap();

        // 3. Prover creates master secret
        let master_secret = Prover::new_master_secret().unwrap();

        // 4. Issuer creates nonce used Prover to blind master secret
        let master_secret_blinding_nonce = new_nonce().unwrap();

        // 5. Prover blinds master secret
        let (blinded_master_secret, master_secret_blinding_data, blinded_master_secret_correctness_proof) =
            Prover::blind_master_secret(&credential_pub_key,
                                        &credential_key_correctness_proof,
                                        &master_secret,
                                        &master_secret_blinding_nonce).unwrap();

        // 6. Prover creates nonce used Issuer to credential issue
        let credential_issuance_nonce = new_nonce().unwrap();

        // 7. Issuer creates and signs credential values
        let credential_values = helpers::gvt_credential_values();
        let (mut credential_signature, signature_correctness_proof) = Issuer::sign_credential(PROVER_ID,
                                                                                              &blinded_master_secret,
                                                                                              &blinded_master_secret_correctness_proof,
                                                                                              &master_secret_blinding_nonce,
                                                                                              &credential_issuance_nonce,
                                                                                              &credential_values,
                                                                                              &credential_pub_key,
                                                                                              &credential_priv_key).unwrap();

        // 8. Prover processes credential signature
        Prover::process_credential_signature(&mut credential_signature,
                                             &credential_values,
                                             &signature_correctness_proof,
                                             &master_secret_blinding_data,
                                             &master_secret,
                                             &credential_pub_key,
                                             &credential_issuance_nonce,
                                             None, None, None).unwrap();

        // 9. Verifier creates sub proof request
        let sub_proof_request = helpers::xyz_sub_proof_request();

        // 10. Prover creates proof by credential not correspondent to proof request
        let mut proof_builder = Prover::new_proof_builder().unwrap();

        let key_id = "key_id";
        let res = proof_builder.add_sub_proof_request(key_id,
                                                      &sub_proof_request,
                                                      &credential_schema,
                                                      &credential_signature,
                                                      &credential_values,
                                                      &credential_pub_key,
                                                      None, None);
        assert_eq!(ErrorCode::CommonInvalidStructure, res.unwrap_err().to_error_code());
    }

    #[test]
    fn proof_builder_add_sub_proof_works_for_credential_not_contained_requested_attribute() {
        // 1. Issuer creates credential schema
        let credential_schema = helpers::gvt_credential_schema();

        // 2. Issuer creates credential definition
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, false).unwrap();

        // 3. Prover creates master secret
        let master_secret = Prover::new_master_secret().unwrap();

        // 4. Issuer creates nonce used Prover to blind master secret
        let master_secret_blinding_nonce = new_nonce().unwrap();

        // 5. Prover blinds master secret
        let (blinded_master_secret, master_secret_blinding_data, blinded_master_secret_correctness_proof) =
            Prover::blind_master_secret(&credential_pub_key,
                                        &credential_key_correctness_proof,
                                        &master_secret,
                                        &master_secret_blinding_nonce).unwrap();

        // 6. Prover creates nonce used Issuer to credential issue
        let credential_issuance_nonce = new_nonce().unwrap();

        // 7. Issuer creates and signs credential values
        let credential_values = helpers::gvt_credential_values();
        let (mut credential_signature, signature_correctness_proof) = Issuer::sign_credential(PROVER_ID,
                                                                                              &blinded_master_secret,
                                                                                              &blinded_master_secret_correctness_proof,
                                                                                              &master_secret_blinding_nonce,
                                                                                              &credential_issuance_nonce,
                                                                                              &credential_values,
                                                                                              &credential_pub_key,
                                                                                              &credential_priv_key).unwrap();

        // 8. Prover processes credential signature
        Prover::process_credential_signature(&mut credential_signature,
                                             &credential_values,
                                             &signature_correctness_proof,
                                             &master_secret_blinding_data,
                                             &master_secret,
                                             &credential_pub_key,
                                             &credential_issuance_nonce,
                                             None, None, None).unwrap();

        // 9. Verifier creates sub proof request
        let mut sub_proof_request_builder = Verifier::new_sub_proof_request_builder().unwrap();
        sub_proof_request_builder.add_revealed_attr("status").unwrap();
        let sub_proof_request = sub_proof_request_builder.finalize().unwrap();

        // 10. Prover creates proof by credential not contained requested attribute
        let mut proof_builder = Prover::new_proof_builder().unwrap();

        let key_id = "key_id";
        let res = proof_builder.add_sub_proof_request(key_id,
                                                      &sub_proof_request,
                                                      &credential_schema,
                                                      &credential_signature,
                                                      &credential_values,
                                                      &credential_pub_key,
                                                      None, None);
        assert_eq!(ErrorCode::CommonInvalidStructure, res.unwrap_err().to_error_code());
    }

    #[test]
    fn proof_builder_add_sub_proof_works_for_credential_not_satisfied_requested_predicate() {
        // 1. Issuer creates credential schema
        let credential_schema = helpers::gvt_credential_schema();

        // 2. Issuer creates credential definition
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, false).unwrap();

        // 3. Prover creates master secret
        let master_secret = Prover::new_master_secret().unwrap();

        // 4. Issuer creates nonce used Prover to blind master secret
        let master_secret_blinding_nonce = new_nonce().unwrap();

        // 5. Prover blinds master secret
        let (blinded_master_secret, master_secret_blinding_data, blinded_master_secret_correctness_proof) =
            Prover::blind_master_secret(&credential_pub_key,
                                        &credential_key_correctness_proof,
                                        &master_secret,
                                        &master_secret_blinding_nonce).unwrap();

        // 6. Prover creates nonce used Issuer to credential issue
        let credential_issuance_nonce = new_nonce().unwrap();

        // 7. Issuer creates and signs credential values
        let credential_values = helpers::gvt_credential_values();
        let (mut credential_signature, signature_correctness_proof) = Issuer::sign_credential(PROVER_ID,
                                                                                              &blinded_master_secret,
                                                                                              &blinded_master_secret_correctness_proof,
                                                                                              &master_secret_blinding_nonce,
                                                                                              &credential_issuance_nonce,
                                                                                              &credential_values,
                                                                                              &credential_pub_key,
                                                                                              &credential_priv_key).unwrap();

        // 8. Prover processes credential signature
        Prover::process_credential_signature(&mut credential_signature,
                                             &credential_values,
                                             &signature_correctness_proof,
                                             &master_secret_blinding_data,
                                             &master_secret,
                                             &credential_pub_key,
                                             &credential_issuance_nonce,
                                             None, None, None).unwrap();

        // 9. Verifier creates sub proof request
        let mut gvt_sub_proof_request_builder = Verifier::new_sub_proof_request_builder().unwrap();
        gvt_sub_proof_request_builder.add_revealed_attr("name").unwrap();
        gvt_sub_proof_request_builder.add_predicate("age", "GE", 50).unwrap();
        let sub_proof_request = gvt_sub_proof_request_builder.finalize().unwrap();

        // 10. Prover creates proof by credential value not satisfied predicate
        let mut proof_builder = Prover::new_proof_builder().unwrap();

        let key_id = "key_id";
        let res = proof_builder.add_sub_proof_request(key_id,
                                                      &sub_proof_request,
                                                      &credential_schema,
                                                      &credential_signature,
                                                      &credential_values,
                                                      &credential_pub_key,
                                                      None, None);
        assert_eq!(ErrorCode::CommonInvalidStructure, res.unwrap_err().to_error_code());
    }

    #[test]
    fn proof_verifier_add_sub_proof_request_works_for_credential_schema_not_satisfied_to_sub_proof_request() {
        // 1. Issuer creates credential schema
        let credential_schema = helpers::gvt_credential_schema();

        // 2. Issuer creates credential definition
        let (credential_pub_key, _, _) = Issuer::new_credential_def(&credential_schema, false).unwrap();

        // 3. Verifier build proof verifier
        let key_id = "key_id";
        let sub_proof_request = helpers::gvt_sub_proof_request();
        let xyz_credential_schema = helpers::xyz_credential_schema();

        let mut proof_verifier = Verifier::new_proof_verifier().unwrap();

        let res = proof_verifier.add_sub_proof_request(key_id,
                                                       &sub_proof_request,
                                                       &xyz_credential_schema,
                                                       &credential_pub_key,
                                                       None, None);
        assert_eq!(ErrorCode::CommonInvalidStructure, res.unwrap_err().to_error_code());
    }

    #[test]
    fn prover_blind_master_secret_works_for_key_correctness_proof_not_correspond_to_public_key() {
        // 1. Prover creates master secret
        let master_secret = Prover::new_master_secret().unwrap();

        // 2. Issuer creates GVT credential definition
        let gvt_credential_schema = helpers::gvt_credential_schema();
        let (gvt_credential_pub_key, _, _) =
            Issuer::new_credential_def(&gvt_credential_schema, false).unwrap();

        // 3. Issuer creates XYZ credential definition
        let xyz_credential_schema = helpers::xyz_credential_schema();
        let (_, _, xyz_credential_key_correctness_proof) =
            Issuer::new_credential_def(&xyz_credential_schema, false).unwrap();

        // 4. Issuer creates nonce used Prover to blind master secret
        let gvt_master_secret_blinding_nonce = new_nonce().unwrap();

        // 5. Prover blind master secret by gvt_public_key and xyz_key_correctness_proof
        let res =
            Prover::blind_master_secret(&gvt_credential_pub_key,
                                        &xyz_credential_key_correctness_proof,
                                        &master_secret,
                                        &gvt_master_secret_blinding_nonce);
        assert_eq!(ErrorCode::CommonInvalidStructure, res.unwrap_err().to_error_code());
    }

    #[test]
    fn issuer_sign_credential_works_for_prover_used_different_nonce_to_blind_master_secret() {
        // 1. Issuer creates credential schema
        let credential_schema = helpers::gvt_credential_schema();

        // 2. Issuer creates credential definition
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, false).unwrap();

        // 3. Prover creates master secret
        let master_secret = Prover::new_master_secret().unwrap();

        // 4. Issuer creates nonce used Prover to blind master secret
        let master_secret_blinding_nonce = new_nonce().unwrap();

        let other_nonce = new_nonce().unwrap();

        // 5. Prover blinds master secret
        let (blinded_ms, _, blinded_master_secret_correctness_proof) =
            Prover::blind_master_secret(&credential_pub_key, &credential_key_correctness_proof, &master_secret, &other_nonce).unwrap();

        // 6. Prover creates nonce used Issuer to credential issue
        let credential_issuance_nonce = new_nonce().unwrap();

        // 7. Issuer creates credential values
        let credential_values = helpers::gvt_credential_values();

        // 8. Issuer signs credential values
        let res = Issuer::sign_credential(PROVER_ID,
                                          &blinded_ms,
                                          &blinded_master_secret_correctness_proof,
                                          &master_secret_blinding_nonce,
                                          &credential_issuance_nonce,
                                          &credential_values,
                                          &credential_pub_key,
                                          &credential_priv_key);
        assert_eq!(ErrorCode::CommonInvalidStructure, res.unwrap_err().to_error_code());
    }

    #[test]
    fn issuer_sign_credential_works_for_keys_not_correspond_to_blinded_master_secret_correctness_proof() {
        // 1. Issuer creates GVT credential definition
        let credential_schema = helpers::gvt_credential_schema();
        let (gvt_credential_pub_key, _, gvt_credential_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, false).unwrap();

        // 2. Issuer creates XYZ credential definition
        let credential_schema = helpers::gvt_credential_schema();
        let (xyz_credential_pub_key, xyz_credential_priv_key, _) = Issuer::new_credential_def(&credential_schema, false).unwrap();

        // 3. Prover creates master secret
        let master_secret = Prover::new_master_secret().unwrap();

        // 4. Issuer creates nonce used Prover to blind master secret
        let master_secret_blinding_nonce = new_nonce().unwrap();

        // 5. Prover blinds master secret by GVT key
        let (blinded_ms, _, blinded_master_secret_correctness_proof) =
            Prover::blind_master_secret(&gvt_credential_pub_key, &gvt_credential_key_correctness_proof, &master_secret, &master_secret_blinding_nonce).unwrap();

        // 6. Prover creates nonce used Issuer to credential issue
        let credential_issuance_nonce = new_nonce().unwrap();

        // 7. Issuer creates credential values
        let xyz_credential_values = helpers::xyz_credential_values();

        // 8. Issuer signs XYZ credential values for Prover
        let res = Issuer::sign_credential(PROVER_ID,
                                          &blinded_ms,
                                          &blinded_master_secret_correctness_proof,
                                          &master_secret_blinding_nonce,
                                          &credential_issuance_nonce,
                                          &xyz_credential_values,
                                          &xyz_credential_pub_key,
                                          &xyz_credential_priv_key);
        assert_eq!(ErrorCode::CommonInvalidStructure, res.unwrap_err().to_error_code());
    }

    #[test]
    fn issuer_sign_credential_works_for_blinded_master_secret_not_correspond_to_blinded_master_secret_correctness_proof() {
        // 1. Issuer creates GVT credential definition
        let credential_schema = helpers::gvt_credential_schema();
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, false).unwrap();

        // 2. Prover creates master secret
        let master_secret = Prover::new_master_secret().unwrap();

        // 3. Issuer creates nonce used Prover to blind master secret
        let master_secret_blinding_nonce = new_nonce().unwrap();

        // 4. Prover blinds master secret
        let (_, _, blinded_master_secret_correctness_proof) =
            Prover::blind_master_secret(&credential_pub_key, &credential_key_correctness_proof, &master_secret, &master_secret_blinding_nonce).unwrap();

        // 5. Prover blinds master secret second time
        let (blinded_ms, _, _) =
            Prover::blind_master_secret(&credential_pub_key, &credential_key_correctness_proof, &master_secret, &master_secret_blinding_nonce).unwrap();

        // 6. Prover creates nonce used Issuer to credential issue
        let credential_issuance_nonce = new_nonce().unwrap();

        // 7. Issuer creates credential values
        let credential_values = helpers::gvt_credential_values();

        // 8. Issuer signs credential values for Prover
        let res = Issuer::sign_credential(PROVER_ID,
                                          &blinded_ms,
                                          &blinded_master_secret_correctness_proof,
                                          &master_secret_blinding_nonce,
                                          &credential_issuance_nonce,
                                          &credential_values,
                                          &credential_pub_key,
                                          &credential_priv_key);
        assert_eq!(ErrorCode::CommonInvalidStructure, res.unwrap_err().to_error_code());
    }

    #[test]
    fn prover_process_credential_signature_works_for_issuer_used_different_nonce() {
        // 1. Issuer creates credential schema
        let credential_schema = helpers::gvt_credential_schema();

        // 2. Issuer creates credential definition
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, false).unwrap();

        // 3. Prover creates master secret
        let master_secret = Prover::new_master_secret().unwrap();

        // 4. Issuer creates nonce used Prover to blind master secret
        let master_secret_blinding_nonce = new_nonce().unwrap();

        // 5. Prover blinds master secret
        let (blinded_ms, master_secret_blinding_data, blinded_master_secret_correctness_proof) =
            Prover::blind_master_secret(&credential_pub_key, &credential_key_correctness_proof, &master_secret, &master_secret_blinding_nonce).unwrap();

        // 6. Prover creates nonce used Issuer to credential issue
        let credential_issuance_nonce = new_nonce().unwrap();

        let different_nonce = new_nonce().unwrap();

        // 7. Issuer creates credential values
        let credential_values = helpers::gvt_credential_values();

        // 8. Issuer signs credential values
        let (mut credential_signature, signature_correctness_proof) = Issuer::sign_credential(PROVER_ID,
                                                                                              &blinded_ms,
                                                                                              &blinded_master_secret_correctness_proof,
                                                                                              &master_secret_blinding_nonce,
                                                                                              &different_nonce,
                                                                                              &credential_values,
                                                                                              &credential_pub_key,
                                                                                              &credential_priv_key).unwrap();

        // 9. Prover processes credential signature
        let res = Prover::process_credential_signature(&mut credential_signature,
                                                       &credential_values,
                                                       &signature_correctness_proof,
                                                       &master_secret_blinding_data,
                                                       &master_secret,
                                                       &credential_pub_key,
                                                       &credential_issuance_nonce,
                                                       None, None, None);
        assert_eq!(ErrorCode::CommonInvalidStructure, res.unwrap_err().to_error_code());
    }

    #[test]
    fn prover_process_credential_signature_works_for_credential_signature_not_correspond_to_signature_correctness_proof() {
        // 1. Issuer creates credential schema
        let credential_schema = helpers::gvt_credential_schema();

        // 2. Issuer creates credential definition
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, false).unwrap();

        // 3. Prover creates master secret
        let master_secret = Prover::new_master_secret().unwrap();

        // 4. Issuer creates nonce used Prover to blind master secret
        let master_secret_blinding_nonce = new_nonce().unwrap();

        // 5. Prover blinds master secret
        let (blinded_ms, master_secret_blinding_data, blinded_master_secret_correctness_proof) =
            Prover::blind_master_secret(&credential_pub_key, &credential_key_correctness_proof, &master_secret, &master_secret_blinding_nonce).unwrap();

        // 6. Prover creates nonce used Issuer to credential issue
        let credential_issuance_nonce = new_nonce().unwrap();

        let different_nonce = new_nonce().unwrap();

        // 7. Issuer creates credential values
        let credential_values = helpers::gvt_credential_values();

        // 8. Issuer signs credential values
        let (mut credential_signature, _) = Issuer::sign_credential(PROVER_ID,
                                                                    &blinded_ms,
                                                                    &blinded_master_secret_correctness_proof,
                                                                    &master_secret_blinding_nonce,
                                                                    &different_nonce,
                                                                    &credential_values,
                                                                    &credential_pub_key,
                                                                    &credential_priv_key).unwrap();

        // 9. Issuer signs credential values second time
        let (_, signature_correctness_proof) = Issuer::sign_credential(PROVER_ID,
                                                                       &blinded_ms,
                                                                       &blinded_master_secret_correctness_proof,
                                                                       &master_secret_blinding_nonce,
                                                                       &different_nonce,
                                                                       &credential_values,
                                                                       &credential_pub_key,
                                                                       &credential_priv_key).unwrap();

        // 10. Prover processes credential signature
        let res = Prover::process_credential_signature(&mut credential_signature,
                                                       &credential_values,
                                                       &signature_correctness_proof,
                                                       &master_secret_blinding_data,
                                                       &master_secret,
                                                       &credential_pub_key,
                                                       &credential_issuance_nonce,
                                                       None, None, None);
        assert_eq!(ErrorCode::CommonInvalidStructure, res.unwrap_err().to_error_code());
    }

    #[test]
    fn prover_process_credential_signature_works_for_master_secret_blinding_data_not_correspond_to_signature() {
        // 1. Issuer creates credential schema
        let credential_schema = helpers::gvt_credential_schema();

        // 2. Issuer creates credential definition
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, false).unwrap();

        // 3. Prover creates master secret
        let master_secret = Prover::new_master_secret().unwrap();

        // 4. Issuer creates nonce used Prover to blind master secret
        let master_secret_blinding_nonce = new_nonce().unwrap();

        // 5. Prover blinds master secret
        let (blinded_ms, _, blinded_master_secret_correctness_proof) =
            Prover::blind_master_secret(&credential_pub_key, &credential_key_correctness_proof, &master_secret, &master_secret_blinding_nonce).unwrap();

        // 6. Prover blinds master secret second time
        let (_, master_secret_blinding_data, _) =
            Prover::blind_master_secret(&credential_pub_key, &credential_key_correctness_proof, &master_secret, &master_secret_blinding_nonce).unwrap();

        // 7. Prover creates nonce used Issuer to credential issue
        let credential_issuance_nonce = new_nonce().unwrap();

        // 8. Issuer creates credential values
        let credential_values = helpers::gvt_credential_values();

        // 9. Issuer signs credential values
        let (mut credential_signature, signature_correctness_proof) = Issuer::sign_credential(PROVER_ID,
                                                                                              &blinded_ms,
                                                                                              &blinded_master_secret_correctness_proof,
                                                                                              &master_secret_blinding_nonce,
                                                                                              &credential_issuance_nonce,
                                                                                              &credential_values,
                                                                                              &credential_pub_key,
                                                                                              &credential_priv_key).unwrap();

        // 10. Prover processes credential signature
        let res = Prover::process_credential_signature(&mut credential_signature,
                                                       &credential_values,
                                                       &signature_correctness_proof,
                                                       &master_secret_blinding_data,
                                                       &master_secret,
                                                       &credential_pub_key,
                                                       &credential_issuance_nonce,
                                                       None, None, None);
        assert_eq!(ErrorCode::CommonInvalidStructure, res.unwrap_err().to_error_code());
    }

    #[test]
    fn prover_process_credential_signature_works_for_use_different_nonce() {
        // 1. Issuer creates credential schema
        let credential_schema = helpers::gvt_credential_schema();

        // 2. Issuer creates credential definition
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, false).unwrap();

        // 3. Prover creates master secret
        let master_secret = Prover::new_master_secret().unwrap();

        // 4. Issuer creates nonce used Prover to blind master secret
        let master_secret_blinding_nonce = new_nonce().unwrap();

        // 5. Prover blinds master secret
        let (blinded_ms, master_secret_blinding_data, blinded_master_secret_correctness_proof) =
            Prover::blind_master_secret(&credential_pub_key, &credential_key_correctness_proof, &master_secret, &master_secret_blinding_nonce).unwrap();

        // 6. Prover creates nonce used Issuer to credential issue
        let credential_issuance_nonce = new_nonce().unwrap();

        // 7. Issuer creates credential values
        let credential_values = helpers::gvt_credential_values();

        // 8. Issuer signs credential values
        let (mut credential_signature, signature_correctness_proof) = Issuer::sign_credential(PROVER_ID,
                                                                                              &blinded_ms,
                                                                                              &blinded_master_secret_correctness_proof,
                                                                                              &master_secret_blinding_nonce,
                                                                                              &credential_issuance_nonce,
                                                                                              &credential_values,
                                                                                              &credential_pub_key,
                                                                                              &credential_priv_key).unwrap();

        let other_nonce = new_nonce().unwrap();

        // 9. Prover processes credential signature
        let res = Prover::process_credential_signature(&mut credential_signature,
                                                       &credential_values,
                                                       &signature_correctness_proof,
                                                       &master_secret_blinding_data,
                                                       &master_secret,
                                                       &credential_pub_key,
                                                       &other_nonce,
                                                       None, None, None);
        assert_eq!(ErrorCode::CommonInvalidStructure, res.unwrap_err().to_error_code());
    }
}

mod helpers {
    use super::*;
    use indy_crypto::cl::*;

    pub fn gvt_credential_schema() -> CredentialSchema {
        let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
        credential_schema_builder.add_attr("name").unwrap();
        credential_schema_builder.add_attr("sex").unwrap();
        credential_schema_builder.add_attr("age").unwrap();
        credential_schema_builder.add_attr("height").unwrap();
        credential_schema_builder.finalize().unwrap()
    }

    pub fn xyz_credential_schema() -> CredentialSchema {
        let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
        credential_schema_builder.add_attr("status").unwrap();
        credential_schema_builder.add_attr("period").unwrap();
        credential_schema_builder.finalize().unwrap()
    }

    pub fn gvt_credential_values() -> CredentialValues {
        let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();
        credential_values_builder.add_value("name", "1139481716457488690172217916278103335").unwrap();
        credential_values_builder.add_value("sex", "5944657099558967239210949258394887428692050081607692519917050011144233115103").unwrap();
        credential_values_builder.add_value("age", "28").unwrap();
        credential_values_builder.add_value("height", "175").unwrap();
        credential_values_builder.finalize().unwrap()
    }

    pub fn xyz_credential_values() -> CredentialValues {
        let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();
        credential_values_builder.add_value("status", "51792877103171595686471452153480627530895").unwrap();
        credential_values_builder.add_value("period", "8").unwrap();
        credential_values_builder.finalize().unwrap()
    }

    pub fn gvt_sub_proof_request() -> SubProofRequest {
        let mut gvt_sub_proof_request_builder = Verifier::new_sub_proof_request_builder().unwrap();
        gvt_sub_proof_request_builder.add_revealed_attr("name").unwrap();
        gvt_sub_proof_request_builder.add_predicate("age", "GE", 18).unwrap();
        gvt_sub_proof_request_builder.finalize().unwrap()
    }

    pub fn xyz_sub_proof_request() -> SubProofRequest {
        let mut xyz_sub_proof_request_builder = Verifier::new_sub_proof_request_builder().unwrap();
        xyz_sub_proof_request_builder.add_revealed_attr("status").unwrap();
        xyz_sub_proof_request_builder.add_predicate("period", "GE", 4).unwrap();
        xyz_sub_proof_request_builder.finalize().unwrap()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct RegistryDelta {
    prev_accum: Option<PointG2>,
    accum: PointG2,
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    #[serde(default)]
    issued: HashSet<u32>,
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    #[serde(default)]
    revoked: HashSet<u32>
}

impl RegistryDelta {
    fn from_rev_reg(rev_reg: &RevocationRegistry, max_cred_num: u32) -> RegistryDelta {
        let mut rev_reg_delta = serde_json::from_str::<RegistryDelta>(&serde_json::to_string(&rev_reg).unwrap()).unwrap();
        let mut issued = HashSet::new();
        for i in 1..max_cred_num + 1 {
            issued.insert(i);
        }
        rev_reg_delta.issued = issued;
        rev_reg_delta
    }

    fn to_delta(&self) -> RevocationRegistryDelta {
        serde_json::from_str::<RevocationRegistryDelta>(&serde_json::to_string(&self).unwrap()).unwrap()
    }
}

