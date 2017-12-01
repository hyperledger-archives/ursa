extern crate indy_crypto;

use indy_crypto::cl::issuer::Issuer;
use indy_crypto::cl::prover::Prover;
use indy_crypto::cl::verifier::Verifier;

pub const PROVER_ID: &'static str = "CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW";

mod test {
    use super::*;
    use indy_crypto::ffi::ErrorCode;
    use indy_crypto::errors::ToErrorCode;

    #[test]
    fn anoncreds_demo() {
        // 1. Prover creates master secret
        let master_secret = Prover::new_master_secret().unwrap();

        // Issuer creates GVT claim
        // 2. Issuer creates GVT claim schema
        let mut claim_schema_builder = Issuer::new_claim_schema_builder().unwrap();
        claim_schema_builder.add_attr("name").unwrap();
        claim_schema_builder.add_attr("sex").unwrap();
        claim_schema_builder.add_attr("age").unwrap();
        claim_schema_builder.add_attr("height").unwrap();
        let gvt_claim_schema = claim_schema_builder.finalize().unwrap();

        // 3. Issuer creates keys
        let (gvt_issuer_pub_key, gvt_issuer_priv_key) = Issuer::new_keys(&gvt_claim_schema, true).unwrap();

        // 4. Issuer creates GVT revocation registry
        let (mut gvt_rev_reg_pub, gvt_rev_reg_priv) =
            Issuer::new_revocation_registry(&gvt_issuer_pub_key, 5).unwrap();

        // 5. Prover blinds master secret
        let (gvt_blinded_ms, gvt_master_secret_blinding_data) =
            Prover::blind_master_secret(&gvt_issuer_pub_key, &master_secret).unwrap();

        // 6. Issuer creates GVT claim values
        let mut claim_values_builder = Issuer::new_claim_values_builder().unwrap();
        claim_values_builder.add_value("name", "1139481716457488690172217916278103335").unwrap();
        claim_values_builder.add_value("sex", "5944657099558967239210949258394887428692050081607692519917050011144233115103").unwrap();
        claim_values_builder.add_value("age", "28").unwrap();
        claim_values_builder.add_value("height", "175").unwrap();
        let gvt_claim_values = claim_values_builder.finalize().unwrap();

        // 7. Issuer signs GVT claim values
        let mut gvt_claim_signature = Issuer::sign_claim(PROVER_ID,
                                                         &gvt_blinded_ms,
                                                         &gvt_claim_values,
                                                         &gvt_issuer_pub_key,
                                                         &gvt_issuer_priv_key,
                                                         Some(1),
                                                         Some(&mut gvt_rev_reg_pub),
                                                         Some(&gvt_rev_reg_priv)).unwrap();

        // 8. Prover processes GVT claim signature
        Prover::process_claim_signature(&mut gvt_claim_signature,
                                        &gvt_master_secret_blinding_data,
                                        &gvt_issuer_pub_key,
                                        Some(&gvt_rev_reg_pub)).unwrap();

        // Issuer creates XYZ claim
        // 9. Issuer creates XYZ claim schema
        let mut claim_schema_builder = Issuer::new_claim_schema_builder().unwrap();
        claim_schema_builder.add_attr("period").unwrap();
        claim_schema_builder.add_attr("status").unwrap();
        let xyz_claim_schema = claim_schema_builder.finalize().unwrap();

        // 10. Issuer creates keys
        let (xyz_issuer_pub_key, xyz_issuer_priv_key) = Issuer::new_keys(&xyz_claim_schema, true).unwrap();

        // 11. Issuer creates XYZ revocation registry
        let (mut xyz_rev_reg_pub, xyz_rev_reg_priv) =
            Issuer::new_revocation_registry(&xyz_issuer_pub_key, 5).unwrap();

        // 12. Prover blinds master secret
        let (xyz_blinded_ms, xyz_master_secret_blinding_data) =
            Prover::blind_master_secret(&xyz_issuer_pub_key, &master_secret).unwrap();

        // 13. Issuer creates XYZ claim values
        let mut claim_values_builder = Issuer::new_claim_values_builder().unwrap();
        claim_values_builder.add_value("status", "51792877103171595686471452153480627530895").unwrap();
        claim_values_builder.add_value("period", "8").unwrap();
        let xyz_claim_values = claim_values_builder.finalize().unwrap();

        // 14. Issuer signs XYZ claim values
        let mut xyz_claim_signature = Issuer::sign_claim(PROVER_ID,
                                                         &xyz_blinded_ms,
                                                         &xyz_claim_values,
                                                         &xyz_issuer_pub_key,
                                                         &xyz_issuer_priv_key,
                                                         Some(1),
                                                         Some(&mut xyz_rev_reg_pub),
                                                         Some(&xyz_rev_reg_priv)).unwrap();

        // 15. Prover processes XYZ claim signature
        Prover::process_claim_signature(&mut xyz_claim_signature,
                                        &xyz_master_secret_blinding_data,
                                        &xyz_issuer_pub_key,
                                        Some(&xyz_rev_reg_pub)).unwrap();

        // 16. Verifier creates sub proof request related to GVT claim
        let mut sub_proof_request_builder = Verifier::new_sub_proof_request_builder().unwrap();
        sub_proof_request_builder.add_revealed_attr("name").unwrap();
        sub_proof_request_builder.add_predicate("age", "GE", 18).unwrap();
        let gvt_sub_proof_request = sub_proof_request_builder.finalize().unwrap();

        // 17. Verifier creates sub proof request related to XYZ claim
        let mut sub_proof_request_builder = Verifier::new_sub_proof_request_builder().unwrap();
        sub_proof_request_builder.add_revealed_attr("status").unwrap();
        sub_proof_request_builder.add_predicate("period", "GE", 4).unwrap();
        let xyz_sub_proof_request = sub_proof_request_builder.finalize().unwrap();

        // 18. Verifier creates nonce
        let nonce = Verifier::new_nonce().unwrap();

        // 19. Prover creates proof for two sub proof requests
        let gvt_key_id = "gvt_key_id";
        let xyz_key_id = "xyz_key_id";
        let mut proof_builder = Prover::new_proof_builder().unwrap();

        proof_builder.add_sub_proof_request(gvt_key_id,
                                            &gvt_sub_proof_request,
                                            &gvt_claim_schema,
                                            &gvt_claim_signature,
                                            &gvt_claim_values,
                                            &gvt_issuer_pub_key,
                                            Some(&gvt_rev_reg_pub)).unwrap();

        proof_builder.add_sub_proof_request(xyz_key_id,
                                            &xyz_sub_proof_request,
                                            &xyz_claim_schema,
                                            &xyz_claim_signature,
                                            &xyz_claim_values,
                                            &xyz_issuer_pub_key,
                                            Some(&xyz_rev_reg_pub)).unwrap();


        let proof = proof_builder.finalize(&nonce, &master_secret).unwrap();

        // 20. Verifier verifies proof
        let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
        proof_verifier.add_sub_proof_request(gvt_key_id,
                                             &gvt_sub_proof_request,
                                             &gvt_claim_schema,
                                             &gvt_issuer_pub_key,
                                             Some(&gvt_rev_reg_pub)).unwrap();

        proof_verifier.add_sub_proof_request(xyz_key_id,
                                             &xyz_sub_proof_request,
                                             &xyz_claim_schema,
                                             &xyz_issuer_pub_key,
                                             Some(&xyz_rev_reg_pub)).unwrap();

        assert!(proof_verifier.verify(&proof, &nonce).unwrap());
    }

    #[test]
    fn anoncreds_works_for_primary_only() {
        // 1. Issuer creates claim schema
        let claim_schema = helpers::gvt_claim_schema();

        // 2. Issuer creates keys
        let (issuer_pub_key, issuer_priv_key) = Issuer::new_keys(&claim_schema, false).unwrap();

        // 3. Prover creates master secret
        let master_secret = Prover::new_master_secret().unwrap();

        // 4. Prover blinds master secret
        let (blinded_ms, master_secret_blinding_data) = Prover::blind_master_secret(&issuer_pub_key, &master_secret).unwrap();

        // 5. Issuer creates claim values
        let claim_values = helpers::gvt_claim_values();

        // 6. Issuer signs claim values
        let mut claim_signature = Issuer::sign_claim(PROVER_ID,
                                                     &blinded_ms,
                                                     &claim_values,
                                                     &issuer_pub_key, &issuer_priv_key,
                                                     None,
                                                     None,
                                                     None).unwrap();

        // 7. Prover processes claim signature
        Prover::process_claim_signature(&mut claim_signature, &master_secret_blinding_data, &issuer_pub_key, None).unwrap();

        // 8. Verifier create sub proof request
        let sub_proof_request = helpers::gvt_sub_proof_request();
        let key_id = "issuer_key_id_1";

        // 9. Verifier creates nonce
        let nonce = Verifier::new_nonce().unwrap();

        // 10. Prover creates proof
        let mut proof_builder = Prover::new_proof_builder().unwrap();
        proof_builder.add_sub_proof_request(key_id, &sub_proof_request, &claim_schema, &claim_signature, &claim_values, &issuer_pub_key, None).unwrap();
        let proof = proof_builder.finalize(&nonce, &master_secret).unwrap();

        // 11. Verifier verifies proof
        let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
        proof_verifier.add_sub_proof_request(key_id, &sub_proof_request, &claim_schema, &issuer_pub_key, None).unwrap();
        assert!(proof_verifier.verify(&proof, &nonce).unwrap());
    }

    #[test]
    fn anoncreds_works_for_multiple_claims_used_for_proof() {
        // 1. Prover creates master secret
        let master_secret = Prover::new_master_secret().unwrap();

        // 2. Issuer creates and signs GVT claim for Prover
        let gvt_claim_schema = helpers::gvt_claim_schema();
        let (gvt_issuer_pub_key, gvt_issuer_priv_key) = Issuer::new_keys(&gvt_claim_schema, false).unwrap();
        let (gvt_blinded_ms, gvt_master_secret_blinding_data) = Prover::blind_master_secret(&gvt_issuer_pub_key, &master_secret).unwrap();
        let gvt_claim_values = helpers::gvt_claim_values();
        let mut gvt_claim_signature = Issuer::sign_claim(PROVER_ID,
                                                         &gvt_blinded_ms,
                                                         &gvt_claim_values,
                                                         &gvt_issuer_pub_key,
                                                         &gvt_issuer_priv_key,
                                                         None,
                                                         None,
                                                         None).unwrap();

        // 3. Prover processes GVT claim
        Prover::process_claim_signature(&mut gvt_claim_signature, &gvt_master_secret_blinding_data, &gvt_issuer_pub_key, None).unwrap();

        // 4. Issuer creates and signs XYZ claim for Prover
        let xyz_claim_schema = helpers::xyz_claim_schema();
        let (xyz_issuer_pub_key, xyz_issuer_priv_key) = Issuer::new_keys(&xyz_claim_schema, false).unwrap();
        let (xyz_blinded_ms, xyz_master_secret_blinding_data) = Prover::blind_master_secret(&xyz_issuer_pub_key, &master_secret).unwrap();
        let xyz_claim_values = helpers::xyz_claim_values();
        let mut xyz_claim_signature = Issuer::sign_claim(PROVER_ID,
                                                         &xyz_blinded_ms,
                                                         &xyz_claim_values,
                                                         &xyz_issuer_pub_key,
                                                         &xyz_issuer_priv_key,
                                                         None,
                                                         None,
                                                         None).unwrap();

        // 5. Prover processes XYZ claim
        Prover::process_claim_signature(&mut xyz_claim_signature, &xyz_master_secret_blinding_data, &xyz_issuer_pub_key, None).unwrap();

        // 6. Verifier creates nonce
        let nonce = Verifier::new_nonce().unwrap();

        // 7. Verifier creates proof request which contains two sub proof requests: GVT and XYZ
        let gvt_sub_proof_request = helpers::gvt_sub_proof_request();
        let xyz_sub_proof_request = helpers::xyz_sub_proof_request();

        // 8. Prover creates proof builder
        let mut proof_builder = Prover::new_proof_builder().unwrap();

        let gvt_key_id = "gvt_key_id";
        // 9. Prover adds GVT sub proof request
        proof_builder.add_sub_proof_request(gvt_key_id,
                                            &gvt_sub_proof_request,
                                            &gvt_claim_schema,
                                            &gvt_claim_signature,
                                            &gvt_claim_values,
                                            &gvt_issuer_pub_key,
                                            None).unwrap();

        // 10. Prover adds XYZ sub proof request
        let xyz_key_id = "xyz_key_id";
        proof_builder.add_sub_proof_request(xyz_key_id,
                                            &xyz_sub_proof_request,
                                            &xyz_claim_schema,
                                            &xyz_claim_signature,
                                            &xyz_claim_values,
                                            &xyz_issuer_pub_key,
                                            None).unwrap();

        // 11. Prover gets proof which contains sub proofs for GVT and XYZ sub proof requests
        let proof = proof_builder.finalize(&nonce, &master_secret).unwrap();

        // 12. Verifier verifies proof for GVT and XYZ sub proof requests
        let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
        proof_verifier.add_sub_proof_request(gvt_key_id, &gvt_sub_proof_request, &gvt_claim_schema, &gvt_issuer_pub_key, None).unwrap();
        proof_verifier.add_sub_proof_request(xyz_key_id, &xyz_sub_proof_request, &xyz_claim_schema, &xyz_issuer_pub_key, None).unwrap();

        assert!(proof_verifier.verify(&proof, &nonce).unwrap());
    }

    #[test]
    fn anoncreds_works_for_revocation_proof() {
        // 1. Issuer creates claim schema
        let claim_schema = helpers::gvt_claim_schema();

        // 2. Issuer creates keys(with revocation keys)
        let (issuer_pub_key, issuer_priv_key) = Issuer::new_keys(&claim_schema, true).unwrap();

        // 3. Issuer creates revocation registry
        let (mut rev_reg_pub, rev_reg_priv) = Issuer::new_revocation_registry(&issuer_pub_key, 5).unwrap();

        // 4. Prover creates master secret
        let master_secret = Prover::new_master_secret().unwrap();

        // 5. Prover blinds master secret
        let (blinded_ms, master_secret_blinding_data) = Prover::blind_master_secret(&issuer_pub_key, &master_secret).unwrap();

        // 6. Issuer creates and sign claim values
        let claim_values = helpers::gvt_claim_values();
        let mut claim_signature = Issuer::sign_claim(PROVER_ID,
                                                     &blinded_ms,
                                                     &claim_values,
                                                     &issuer_pub_key,
                                                     &issuer_priv_key,
                                                     Some(1),
                                                     Some(&mut rev_reg_pub),
                                                     Some(&rev_reg_priv)).unwrap();

        // 7. Prover processes claim signature
        Prover::process_claim_signature(&mut claim_signature, &master_secret_blinding_data, &issuer_pub_key, Some(&rev_reg_pub)).unwrap();

        // 8. Verifier creates nonce
        let nonce = Verifier::new_nonce().unwrap();

        // 9. Verifier create sub proof request
        let sub_proof_request = helpers::gvt_sub_proof_request();

        // 10. Prover creates proof
        let mut proof_builder = Prover::new_proof_builder().unwrap();
        let key_id = "key_id";
        proof_builder.add_sub_proof_request(key_id, &sub_proof_request, &claim_schema, &claim_signature, &claim_values, &issuer_pub_key, Some(&rev_reg_pub)).unwrap();
        let proof = proof_builder.finalize(&nonce, &master_secret).unwrap();

        // 11. Verifier verifies proof
        let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
        proof_verifier.add_sub_proof_request(key_id, &sub_proof_request, &claim_schema, &issuer_pub_key, Some(&rev_reg_pub)).unwrap();
        assert!(proof_verifier.verify(&proof, &nonce).unwrap());
    }

    #[test]
    fn anoncreds_works_for_proof_created_before_claim_revoked() {
        // 1. Issuer creates claim schema
        let claim_schema = helpers::gvt_claim_schema();

        // 2. Issuer creates keys(with revocation keys)
        let (issuer_pub_key, issuer_priv_key) = Issuer::new_keys(&claim_schema, true).unwrap();

        // 3. Issuer creates revocation registry
        let (mut rev_reg_pub, rev_reg_priv) = Issuer::new_revocation_registry(&issuer_pub_key, 5).unwrap();
        let rev_idx = 1;

        // 4. Prover creates master secret
        let master_secret = Prover::new_master_secret().unwrap();

        // 5. Prover blinds master secret
        let (blinded_ms, master_secret_blinding_data) = Prover::blind_master_secret(&issuer_pub_key, &master_secret).unwrap();

        // 6. Issuer creates and signs claim values
        let claim_values = helpers::gvt_claim_values();
        let mut claim_signature = Issuer::sign_claim(PROVER_ID,
                                                     &blinded_ms,
                                                     &claim_values,
                                                     &issuer_pub_key,
                                                     &issuer_priv_key,
                                                     Some(rev_idx),
                                                     Some(&mut rev_reg_pub),
                                                     Some(&rev_reg_priv)).unwrap();

        // 7. Prover processes claim signature
        Prover::process_claim_signature(&mut claim_signature, &master_secret_blinding_data, &issuer_pub_key, Some(&rev_reg_pub)).unwrap();

        // 8. Verifier creates nonce
        let nonce = Verifier::new_nonce().unwrap();

        // 9. Verifier creates sub proof request
        let sub_proof_request = helpers::gvt_sub_proof_request();

        // 10. Prover creates proof
        let mut proof_builder = Prover::new_proof_builder().unwrap();
        let key_id = "key_id";
        proof_builder.add_sub_proof_request(key_id, &sub_proof_request, &claim_schema, &claim_signature, &claim_values, &issuer_pub_key, Some(&rev_reg_pub)).unwrap();
        let proof = proof_builder.finalize(&nonce, &master_secret).unwrap();

        // 11. Issuer revokes claim used for proof building
        Issuer::revoke_claim(&mut rev_reg_pub, rev_idx).unwrap();

        // 12. Verifier verifies proof
        let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
        proof_verifier.add_sub_proof_request(key_id, &sub_proof_request, &claim_schema, &issuer_pub_key, Some(&rev_reg_pub)).unwrap();
        assert_eq!(false, proof_verifier.verify(&proof, &nonce).unwrap());
    }

    #[test]
    fn anoncreds_works_for_create_proof_after_claim_revoked() {
        // 1. Issuer creates claim schema
        let claim_schema = helpers::gvt_claim_schema();

        // 2. Issuer creates keys(with revocation keys)
        let (issuer_pub_key, issuer_priv_key) = Issuer::new_keys(&claim_schema, true).unwrap();

        // 3. Issuer creates revocation registry
        let (mut rev_reg_pub, rev_reg_priv) = Issuer::new_revocation_registry(&issuer_pub_key, 5).unwrap();
        let rev_idx = 1;

        // 4. Prover creates master secret
        let master_secret = Prover::new_master_secret().unwrap();

        // 5. Prover blinds master secret
        let (blinded_ms, master_secret_blinding_data) = Prover::blind_master_secret(&issuer_pub_key, &master_secret).unwrap();

        // 6. Issuer creates and signs claim values
        let claim_values = helpers::gvt_claim_values();
        let mut claim_signature = Issuer::sign_claim(PROVER_ID,
                                                     &blinded_ms,
                                                     &claim_values,
                                                     &issuer_pub_key,
                                                     &issuer_priv_key,
                                                     Some(rev_idx),
                                                     Some(&mut rev_reg_pub),
                                                     Some(&rev_reg_priv)).unwrap();

        // 7. Prover processes claim signature
        Prover::process_claim_signature(&mut claim_signature, &master_secret_blinding_data, &issuer_pub_key, Some(&rev_reg_pub)).unwrap();

        // 8. Issuer revokes claim used for proof building
        Issuer::revoke_claim(&mut rev_reg_pub, rev_idx).unwrap();

        // 9. Verifier creates sub proof request
        let sub_proof_request = helpers::gvt_sub_proof_request();

        // 10. Prover creates proof
        let mut proof_builder = Prover::new_proof_builder().unwrap();

        let key_id = "key_id";
        let res = proof_builder.add_sub_proof_request(key_id,
                                                      &sub_proof_request,
                                                      &claim_schema,
                                                      &claim_signature,
                                                      &claim_values,
                                                      &issuer_pub_key,
                                                      Some(&rev_reg_pub));
        assert_eq!(ErrorCode::AnoncredsClaimRevoked, res.unwrap_err().to_error_code());
    }

    #[test]
    fn anoncreds_works_for_full_accumulator() {
        // 1. Issuer creates claim schema
        let claim_schema = helpers::gvt_claim_schema();

        // 2. Issuer creates keys(with revocation keys)
        let (issuer_pub_key, issuer_priv_key) = Issuer::new_keys(&claim_schema, true).unwrap();

        // 3. Issuer creates revocation registry for only 1 claim
        let (mut rev_reg_pub, rev_reg_priv) = Issuer::new_revocation_registry(&issuer_pub_key, 1).unwrap();

        // 4. Prover creates master secret
        let master_secret = Prover::new_master_secret().unwrap();

        // 5. Prover blinds master secret
        let (blinded_ms, _) = Prover::blind_master_secret(&issuer_pub_key, &master_secret).unwrap();

        // 6. Issuer creates and sign first claim values
        let claim_values = helpers::gvt_claim_values();
        Issuer::sign_claim(PROVER_ID,
                           &blinded_ms,
                           &claim_values,
                           &issuer_pub_key,
                           &issuer_priv_key,
                           Some(1),
                           Some(&mut rev_reg_pub),
                           Some(&rev_reg_priv)).unwrap();

        // 7. Issuer creates and sign second claim values
        let res = Issuer::sign_claim(PROVER_ID,
                                     &blinded_ms,
                                     &claim_values,
                                     &issuer_pub_key,
                                     &issuer_priv_key,
                                     Some(2),
                                     Some(&mut rev_reg_pub),
                                     Some(&rev_reg_priv));
        assert_eq!(ErrorCode::AnoncredsRevocationAccumulatorIsFull, res.unwrap_err().to_error_code());
    }

    #[test]
    #[ignore]
    fn anoncreds_works_for_reissue_claim() {
        // 1. Issuer creates claim schema
        let claim_schema = helpers::gvt_claim_schema();

        // 2. Issuer creates keys(with revocation keys)
        let (issuer_pub_key, issuer_priv_key) = Issuer::new_keys(&claim_schema, true).unwrap();

        // 3. Issuer creates revocation registry
        let (mut rev_reg_pub, rev_reg_priv) = Issuer::new_revocation_registry(&issuer_pub_key, 5).unwrap();
        let rev_idx = 1;

        // FIRST Issue of claim
        // 4. Prover creates master secret
        let master_secret = Prover::new_master_secret().unwrap();

        // 5. Prover blinds master secret
        let (blinded_ms, master_secret_blinding_data) = Prover::blind_master_secret(&issuer_pub_key, &master_secret).unwrap();

        // 6. Issuer creates and signs claim values
        let claim_values = helpers::gvt_claim_values();
        let mut claim_signature = Issuer::sign_claim(PROVER_ID,
                                                     &blinded_ms,
                                                     &claim_values,
                                                     &issuer_pub_key,
                                                     &issuer_priv_key,
                                                     Some(rev_idx),
                                                     Some(&mut rev_reg_pub),
                                                     Some(&rev_reg_priv)).unwrap();

        // 7. Prover processes claim signature
        Prover::process_claim_signature(&mut claim_signature, &master_secret_blinding_data, &issuer_pub_key, Some(&rev_reg_pub)).unwrap();

        // Create proof by issued claim
        // 8. Verifier creates nonce
        let nonce = Verifier::new_nonce().unwrap();

        // 9. Verifier creates sub proof request
        let sub_proof_request = helpers::gvt_sub_proof_request();

        // 10. Prover creates proof
        let mut proof_builder = Prover::new_proof_builder().unwrap();
        let key_id = "key_id";
        proof_builder.add_sub_proof_request(key_id, &sub_proof_request, &claim_schema, &claim_signature, &claim_values, &issuer_pub_key, Some(&rev_reg_pub)).unwrap();
        let proof = proof_builder.finalize(&nonce, &master_secret).unwrap();

        // 11. Verifier verifies proof
        let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
        proof_verifier.add_sub_proof_request(key_id, &sub_proof_request, &claim_schema, &issuer_pub_key, Some(&rev_reg_pub)).unwrap();
        assert_eq!(false, proof_verifier.verify(&proof, &nonce).unwrap());

        // 12. Issuer revokes claim used for proof building
        Issuer::revoke_claim(&mut rev_reg_pub, rev_idx).unwrap();

        // 13. Verifier verifies proof after revocation
        let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
        proof_verifier.add_sub_proof_request(key_id, &sub_proof_request, &claim_schema, &issuer_pub_key, Some(&rev_reg_pub)).unwrap();
        assert_eq!(false, proof_verifier.verify(&proof, &nonce).unwrap());

        // Reissue claim with different values but same rev_index
        // 14. Prover blinds master secret
        let (new_blinded_ms, new_master_secret_blinding_data) = Prover::blind_master_secret(&issuer_pub_key, &master_secret).unwrap();

        // 15. Issuer creates and signs new claim values
        let mut claim_values_builder = Issuer::new_claim_values_builder().unwrap();
        claim_values_builder.add_value("name", "1139481716457488690172217916278103335").unwrap();
        claim_values_builder.add_value("sex", "5944657099558967239210949258394887428692050081607692519917050011144233115103").unwrap();
        claim_values_builder.add_value("age", "44").unwrap();
        claim_values_builder.add_value("height", "165").unwrap();
        let claim_values = claim_values_builder.finalize().unwrap();

        let mut new_claim_signature = Issuer::sign_claim(PROVER_ID,
                                                         &new_blinded_ms,
                                                         &claim_values,
                                                         &issuer_pub_key,
                                                         &issuer_priv_key,
                                                         Some(rev_idx),
                                                         Some(&mut rev_reg_pub),
                                                         Some(&rev_reg_priv)).unwrap();

        // 16. Prover processes new claim signature
        Prover::process_claim_signature(&mut new_claim_signature, &new_master_secret_blinding_data, &issuer_pub_key, Some(&rev_reg_pub)).unwrap();

        // 17. Prover creates proof using new claim
        let mut new_proof_builder = Prover::new_proof_builder().unwrap();

        new_proof_builder.add_sub_proof_request(key_id,
                                                &sub_proof_request,
                                                &claim_schema,
                                                &new_claim_signature,
                                                &claim_values,
                                                &issuer_pub_key,
                                                Some(&rev_reg_pub)).unwrap();

        let new_proof = proof_builder.finalize(&nonce, &master_secret).unwrap();

        // 18. Verifier verifies proof created by new claim
        let mut new_proof_verifier = Verifier::new_proof_verifier().unwrap();
        new_proof_verifier.add_sub_proof_request(key_id, &sub_proof_request, &claim_schema, &issuer_pub_key, Some(&rev_reg_pub)).unwrap();
        assert!(new_proof_verifier.verify(&new_proof, &nonce).unwrap());

        // 19. Verifier verifies proof created before the first claim had been revoked
        let mut old_proof_verifier = Verifier::new_proof_verifier().unwrap();
        old_proof_verifier.add_sub_proof_request(key_id, &sub_proof_request, &claim_schema, &issuer_pub_key, Some(&rev_reg_pub)).unwrap();
        assert_eq!(false, old_proof_verifier.verify(&proof, &nonce).unwrap());
    }

    #[test]
    fn anoncreds_works_for_missed_process_claim_step() {
        // 1. Issuer creates claim schema
        let claim_schema = helpers::gvt_claim_schema();

        // 2. Issuer creates keys
        let (issuer_pub_key, issuer_priv_key) = Issuer::new_keys(&claim_schema, false).unwrap();

        // 3. Prover creates master secret
        let master_secret = Prover::new_master_secret().unwrap();

        // 4. Prover blinds master secret
        let (blinded_ms, _) = Prover::blind_master_secret(&issuer_pub_key, &master_secret).unwrap();

        // 5. Issuer creates and signs claim values
        let claim_values = helpers::gvt_claim_values();
        let claim_signature = Issuer::sign_claim(PROVER_ID,
                                                 &blinded_ms,
                                                 &claim_values,
                                                 &issuer_pub_key,
                                                 &issuer_priv_key,
                                                 None,
                                                 None,
                                                 None).unwrap();

        // 6. Verifier creates nonce and sub proof request
        let nonce = Verifier::new_nonce().unwrap();
        let sub_proof_request = helpers::gvt_sub_proof_request();

        // 7. Prover creates proof by sub proof request not corresponded to verifier proof request
        let key_id = "key_id";

        let mut proof_builder = Prover::new_proof_builder().unwrap();
        proof_builder.add_sub_proof_request(key_id,
                                            &sub_proof_request,
                                            &claim_schema,
                                            &claim_signature,
                                            &claim_values,
                                            &issuer_pub_key,
                                            None).unwrap();
        let proof = proof_builder.finalize(&nonce, &master_secret).unwrap();

        // 8. Verifier verifies proof
        let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
        proof_verifier.add_sub_proof_request(key_id, &sub_proof_request, &claim_schema, &issuer_pub_key, None).unwrap();
        assert_eq!(false, proof_verifier.verify(&proof, &nonce).unwrap());
    }

    #[test]
    fn anoncreds_works_for_proof_created_with_wrong_master_secret() {
        // 1. Issuer creates claim schema
        let claim_schema = helpers::gvt_claim_schema();

        // 2. Issuer creates keys
        let (issuer_pub_key, issuer_priv_key) = Issuer::new_keys(&claim_schema, false).unwrap();

        // 3. Prover creates master secret
        let master_secret = Prover::new_master_secret().unwrap();

        // 4. Prover blinds master secret
        let (blinded_ms, master_secret_blinding_data) = Prover::blind_master_secret(&issuer_pub_key, &master_secret).unwrap();

        // 5. Issuer creates and signs claim values wrong keys
        let claim_values = helpers::gvt_claim_values();

        let mut claim_signature = Issuer::sign_claim(PROVER_ID,
                                                     &blinded_ms,
                                                     &claim_values,
                                                     &issuer_pub_key,
                                                     &issuer_priv_key,
                                                     None,
                                                     None,
                                                     None).unwrap();

        // 6. Prover processes claim signature
        Prover::process_claim_signature(&mut claim_signature, &master_secret_blinding_data, &issuer_pub_key, None).unwrap();

        // 7. Verifier creates nonce and sub proof request
        let nonce = Verifier::new_nonce().unwrap();
        let sub_proof_request = helpers::gvt_sub_proof_request();

        // 8. Prover creates proof by sub proof request not corresponded to verifier proof request
        let key_id = "key_id";

        let mut proof_builder = Prover::new_proof_builder().unwrap();
        proof_builder.add_sub_proof_request(key_id,
                                            &sub_proof_request,
                                            &claim_schema,
                                            &claim_signature,
                                            &claim_values,
                                            &issuer_pub_key,
                                            None).unwrap();

        let another_master_secret = Prover::new_master_secret().unwrap();
        let proof = proof_builder.finalize(&nonce, &another_master_secret).unwrap();

        // 9. Verifier verifies proof
        let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
        proof_verifier.add_sub_proof_request(key_id, &sub_proof_request, &claim_schema, &issuer_pub_key, None).unwrap();
        assert_eq!(false, proof_verifier.verify(&proof, &nonce).unwrap());
    }

    #[test]
    fn anoncreds_works_for_used_different_nonce() {
        // 1. Issuer creates claim schema
        let claim_schema = helpers::gvt_claim_schema();

        // 2. Issuer creates keys
        let (issuer_pub_key, issuer_priv_key) = Issuer::new_keys(&claim_schema, false).unwrap();

        // 3. Prover creates master secret
        let master_secret = Prover::new_master_secret().unwrap();

        // 4. Prover blinds master secret
        let (blinded_ms, master_secret_blinding_data) = Prover::blind_master_secret(&issuer_pub_key, &master_secret).unwrap();

        // 5. Issuer creates and signs claim values wrong keys
        let claim_values = helpers::gvt_claim_values();

        let mut claim_signature = Issuer::sign_claim(PROVER_ID,
                                                     &blinded_ms,
                                                     &claim_values,
                                                     &issuer_pub_key,
                                                     &issuer_priv_key,
                                                     None,
                                                     None,
                                                     None).unwrap();

        // 6. Prover processes claim signature
        Prover::process_claim_signature(&mut claim_signature, &master_secret_blinding_data, &issuer_pub_key, None).unwrap();

        // 7. Verifier creates sub proof request
        let sub_proof_request = helpers::gvt_sub_proof_request();

        // 8. Prover creates proof by sub proof request not corresponded to verifier proof request
        let key_id = "key_id";
        let nonce_for_proof_creation = Verifier::new_nonce().unwrap();

        let mut proof_builder = Prover::new_proof_builder().unwrap();
        proof_builder.add_sub_proof_request(key_id,
                                            &sub_proof_request,
                                            &claim_schema,
                                            &claim_signature,
                                            &claim_values,
                                            &issuer_pub_key,
                                            None).unwrap();

        let proof = proof_builder.finalize(&nonce_for_proof_creation, &master_secret).unwrap();

        // 9. Verifier verifies proof
        let nonce_for_proof_verification = Verifier::new_nonce().unwrap();

        let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
        proof_verifier.add_sub_proof_request(key_id, &sub_proof_request, &claim_schema, &issuer_pub_key, None).unwrap();
        assert_eq!(false, proof_verifier.verify(&proof, &nonce_for_proof_verification).unwrap());
    }

    #[test]
    fn anoncreds_works_for_proof_not_correspond_to_verifier_proof_request() {
        // 1. Issuer creates claim schema
        let claim_schema = helpers::gvt_claim_schema();

        // 2. Issuer creates keys
        let (issuer_pub_key, issuer_priv_key) = Issuer::new_keys(&claim_schema, false).unwrap();

        // 3. Prover creates master secret
        let master_secret = Prover::new_master_secret().unwrap();

        // 4. Prover blinds master secret
        let (blinded_ms, master_secret_blinding_data) = Prover::blind_master_secret(&issuer_pub_key, &master_secret).unwrap();

        // 5. Issuer creates and signs claim values
        let claim_values = helpers::gvt_claim_values();
        let mut claim_signature = Issuer::sign_claim(PROVER_ID,
                                                     &blinded_ms,
                                                     &claim_values,
                                                     &issuer_pub_key,
                                                     &issuer_priv_key,
                                                     None,
                                                     None,
                                                     None).unwrap();

        // 6. Prover processes claim signature
        Prover::process_claim_signature(&mut claim_signature, &master_secret_blinding_data, &issuer_pub_key, None).unwrap();

        // 7. Prover creates proof by sub proof request not corresponded to verifier proof request
        let sub_proof_request = helpers::gvt_sub_proof_request();

        let mut proof_builder = Prover::new_proof_builder().unwrap();
        let nonce = Verifier::new_nonce().unwrap();

        let key_id = "key_id";
        proof_builder.add_sub_proof_request(key_id,
                                            &sub_proof_request,
                                            &claim_schema,
                                            &claim_signature,
                                            &claim_values,
                                            &issuer_pub_key,
                                            None).unwrap();
        let proof = proof_builder.finalize(&nonce, &master_secret).unwrap();

        // 8. Verifier verifies proof
        let xyz_claim_schema = helpers::xyz_claim_schema();
        let (xyz_issuer_pub_key, _) = Issuer::new_keys(&xyz_claim_schema, false).unwrap();
        let xyz_sub_proof_request = helpers::xyz_sub_proof_request();

        let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
        proof_verifier.add_sub_proof_request(key_id, &xyz_sub_proof_request, &xyz_claim_schema, &xyz_issuer_pub_key, None).unwrap();
        let res = proof_verifier.verify(&proof, &nonce);
        assert_eq!(ErrorCode::AnoncredsProofRejected, res.unwrap_err().to_error_code());
    }

    #[test]
    fn issuer_create_keys_works_for_empty_claim_schema() {
        // 1. Issuer creates claim schema
        let claim_schema_builder = Issuer::new_claim_schema_builder().unwrap();
        let claim_schema = claim_schema_builder.finalize().unwrap();

        // 2. Issuer creates keys(with revocation keys)
        let res = Issuer::new_keys(&claim_schema, false);
        assert_eq!(ErrorCode::CommonInvalidStructure, res.unwrap_err().to_error_code());
    }

    #[test]
    fn issuer_create_revocation_registry_works_for_keys_without_revocation_part() {
        // 1. Issuer creates claim schema
        let claim_schema = helpers::gvt_claim_schema();

        // 2. Issuer creates keys(without revocation part)
        let (issuer_pub_key, _) = Issuer::new_keys(&claim_schema, false).unwrap();

        // 3. Issuer creates revocation registry
        let res = Issuer::new_revocation_registry(&issuer_pub_key, 5);
        assert_eq!(ErrorCode::CommonInvalidStructure, res.unwrap_err().to_error_code());
    }

    #[test]
    fn issuer_revoke_works_for_invalid_revocation_index() {
        // 1. Issuer creates claim schema
        let claim_schema = helpers::gvt_claim_schema();

        // 2. Issuer creates keys(with revocation keys)
        let (issuer_pub_key, _) = Issuer::new_keys(&claim_schema, true).unwrap();

        // 3. Issuer creates revocation registry
        let (mut rev_reg_pub, _) = Issuer::new_revocation_registry(&issuer_pub_key, 5).unwrap();

        // 4. Issuer tries revoke not not added index
        let rev_idx = 1;
        let res = Issuer::revoke_claim(&mut rev_reg_pub, rev_idx);
        assert_eq!(ErrorCode::AnoncredsInvalidRevocationAccumulatorIndex, res.unwrap_err().to_error_code());
    }

    #[test]
    fn issuer_sign_claim_works_for_claim_values_not_correspond_to_issuer_keys() {
        // 1. Issuer creates claim schema
        let claim_schema = helpers::gvt_claim_schema();

        // 2. Issuer creates keys
        let (issuer_pub_key, issuer_priv_key) = Issuer::new_keys(&claim_schema, false).unwrap();

        // 3. Prover creates master secret
        let master_secret = Prover::new_master_secret().unwrap();

        // 4. Prover blinds master secret
        let (blinded_ms, _) = Prover::blind_master_secret(&issuer_pub_key, &master_secret).unwrap();

        // 5. Issuer creates claim values not correspondent to issuer keys
        let claim_values = helpers::xyz_claim_values();

        // 6. Issuer signs wrong claim values
        let res = Issuer::sign_claim(PROVER_ID,
                                     &blinded_ms,
                                     &claim_values,
                                     &issuer_pub_key,
                                     &issuer_priv_key,
                                     None,
                                     None,
                                     None);


        assert_eq!(ErrorCode::CommonInvalidStructure, res.unwrap_err().to_error_code());
    }

    #[test]
    fn proof_builder_add_sub_proof_works_for_claim_values_not_correspond_to_claim_schema() {
        // 1. Issuer creates claim schema
        let claim_schema = helpers::gvt_claim_schema();

        // 2. Issuer creates keys
        let (issuer_pub_key, issuer_priv_key) = Issuer::new_keys(&claim_schema, false).unwrap();

        // 3. Prover creates master secret
        let master_secret = Prover::new_master_secret().unwrap();

        // 4. Prover blinds master secret
        let (blinded_ms, master_secret_blinding_data) = Prover::blind_master_secret(&issuer_pub_key, &master_secret).unwrap();

        // 5. Issuer creates and signs claim values
        let claim_values = helpers::gvt_claim_values();
        let mut claim_signature = Issuer::sign_claim(PROVER_ID,
                                                     &blinded_ms,
                                                     &claim_values,
                                                     &issuer_pub_key,
                                                     &issuer_priv_key,
                                                     None,
                                                     None,
                                                     None).unwrap();

        // 6. Prover processes claim signature
        Prover::process_claim_signature(&mut claim_signature, &master_secret_blinding_data, &issuer_pub_key, None).unwrap();

        // 7. Prover creates proof
        let mut proof_builder = Prover::new_proof_builder().unwrap();

        // Wrong claim values
        let claim_values = helpers::xyz_claim_values();

        let sub_proof_request = helpers::gvt_sub_proof_request();

        let key_id = "key_id";
        let res = proof_builder.add_sub_proof_request(key_id,
                                                      &sub_proof_request,
                                                      &claim_schema,
                                                      &claim_signature,
                                                      &claim_values,
                                                      &issuer_pub_key,
                                                      None);

        assert_eq!(ErrorCode::CommonInvalidStructure, res.unwrap_err().to_error_code());
    }

    #[test]
    fn proof_builder_add_sub_proof_works_for_claim_not_satisfy_to_sub_proof_request() {
        // 1. Issuer creates claim schema
        let claim_schema = helpers::gvt_claim_schema();

        // 2. Issuer creates keys
        let (issuer_pub_key, issuer_priv_key) = Issuer::new_keys(&claim_schema, false).unwrap();

        // 3. Prover creates master secret
        let master_secret = Prover::new_master_secret().unwrap();

        // 4. Prover blinds master secret
        let (blinded_ms, master_secret_blinding_data) = Prover::blind_master_secret(&issuer_pub_key, &master_secret).unwrap();

        // 5. Issuer creates and signs claim values
        let claim_values = helpers::gvt_claim_values();
        let mut claim_signature = Issuer::sign_claim(PROVER_ID,
                                                     &blinded_ms,
                                                     &claim_values,
                                                     &issuer_pub_key,
                                                     &issuer_priv_key,
                                                     None,
                                                     None,
                                                     None).unwrap();

        // 6. Prover processes claim signature
        Prover::process_claim_signature(&mut claim_signature, &master_secret_blinding_data, &issuer_pub_key, None).unwrap();

        // 7. Verifier creates sub proof request
        let sub_proof_request = helpers::xyz_sub_proof_request();

        // 8. Prover creates proof by claim not correspondent to proof request
        let mut proof_builder = Prover::new_proof_builder().unwrap();

        let key_id = "key_id";
        let res = proof_builder.add_sub_proof_request(key_id,
                                                      &sub_proof_request,
                                                      &claim_schema,
                                                      &claim_signature,
                                                      &claim_values,
                                                      &issuer_pub_key,
                                                      None);
        assert_eq!(ErrorCode::CommonInvalidStructure, res.unwrap_err().to_error_code());
    }

    #[test]
    fn proof_builder_add_sub_proof_works_for_claim_not_contained_requested_attribute() {
        // 1. Issuer creates claim schema
        let claim_schema = helpers::gvt_claim_schema();

        // 2. Issuer creates keys
        let (issuer_pub_key, issuer_priv_key) = Issuer::new_keys(&claim_schema, false).unwrap();

        // 3. Prover creates master secret
        let master_secret = Prover::new_master_secret().unwrap();

        // 4. Prover blinds master secret
        let (blinded_ms, master_secret_blinding_data) = Prover::blind_master_secret(&issuer_pub_key, &master_secret).unwrap();

        // 5. Issuer creates and signs claim values
        let claim_values = helpers::gvt_claim_values();
        let mut claim_signature = Issuer::sign_claim(PROVER_ID,
                                                     &blinded_ms,
                                                     &claim_values,
                                                     &issuer_pub_key,
                                                     &issuer_priv_key,
                                                     None,
                                                     None,
                                                     None).unwrap();

        // 6. Prover processes claim signature
        Prover::process_claim_signature(&mut claim_signature, &master_secret_blinding_data, &issuer_pub_key, None).unwrap();

        // 7. Verifier creates sub proof request
        let mut sub_proof_request_builder = Verifier::new_sub_proof_request_builder().unwrap();
        sub_proof_request_builder.add_revealed_attr("status").unwrap();
        let sub_proof_request = sub_proof_request_builder.finalize().unwrap();

        // 8. Prover creates proof by claim not contained requested attribute
        let mut proof_builder = Prover::new_proof_builder().unwrap();

        let key_id = "key_id";
        let res = proof_builder.add_sub_proof_request(key_id,
                                                      &sub_proof_request,
                                                      &claim_schema,
                                                      &claim_signature,
                                                      &claim_values,
                                                      &issuer_pub_key,
                                                      None);
        assert_eq!(ErrorCode::CommonInvalidStructure, res.unwrap_err().to_error_code());
    }

    #[test]
    fn proof_builder_add_sub_proof_works_for_claim_not_satisfied_requested_predicate() {
        // 1. Issuer creates claim schema
        let claim_schema = helpers::gvt_claim_schema();

        // 2. Issuer creates keys
        let (issuer_pub_key, issuer_priv_key) = Issuer::new_keys(&claim_schema, false).unwrap();

        // 3. Prover creates master secret
        let master_secret = Prover::new_master_secret().unwrap();

        // 4. Prover blinds master secret
        let (blinded_ms, master_secret_blinding_data) = Prover::blind_master_secret(&issuer_pub_key, &master_secret).unwrap();

        // 5. Issuer creates and signs claim values
        let claim_values = helpers::gvt_claim_values();
        let mut claim_signature = Issuer::sign_claim(PROVER_ID,
                                                     &blinded_ms,
                                                     &claim_values,
                                                     &issuer_pub_key,
                                                     &issuer_priv_key,
                                                     None,
                                                     None,
                                                     None).unwrap();

        // 6. Prover processes claim signature
        Prover::process_claim_signature(&mut claim_signature, &master_secret_blinding_data, &issuer_pub_key, None).unwrap();

        // 7. Verifier creates sub proof request
        let mut gvt_sub_proof_request_builder = Verifier::new_sub_proof_request_builder().unwrap();
        gvt_sub_proof_request_builder.add_revealed_attr("name").unwrap();
        gvt_sub_proof_request_builder.add_predicate("age", "GE", 50).unwrap();
        let sub_proof_request = gvt_sub_proof_request_builder.finalize().unwrap();

        // 8. Prover creates proof by claim value not satisfied predicate
        let mut proof_builder = Prover::new_proof_builder().unwrap();

        let key_id = "key_id";
        let res = proof_builder.add_sub_proof_request(key_id,
                                                      &sub_proof_request,
                                                      &claim_schema,
                                                      &claim_signature,
                                                      &claim_values,
                                                      &issuer_pub_key,
                                                      None);
        assert_eq!(ErrorCode::CommonInvalidStructure, res.unwrap_err().to_error_code());
    }

    #[test]
    fn proof_verifier_add_sub_proof_request_works_for_claim_schema_not_satisfied_to_sub_proof_request() {
        // 1. Issuer creates claim schema
        let claim_schema = helpers::gvt_claim_schema();

        // 2. Issuer creates keys
        let (issuer_pub_key, _) = Issuer::new_keys(&claim_schema, false).unwrap();

        // 3. Verifier build proof verifier
        let key_id = "key_id";
        let sub_proof_request = helpers::gvt_sub_proof_request();
        let xyz_claim_schema = helpers::xyz_claim_schema();

        let mut proof_verifier = Verifier::new_proof_verifier().unwrap();

        let res = proof_verifier.add_sub_proof_request(key_id, &sub_proof_request, &xyz_claim_schema, &issuer_pub_key, None);
        assert_eq!(ErrorCode::CommonInvalidStructure, res.unwrap_err().to_error_code());
    }
}

mod helpers {
    use super::*;
    use indy_crypto::cl::*;

    pub fn gvt_claim_schema() -> ClaimSchema {
        let mut claim_schema_builder = Issuer::new_claim_schema_builder().unwrap();
        claim_schema_builder.add_attr("name").unwrap();
        claim_schema_builder.add_attr("sex").unwrap();
        claim_schema_builder.add_attr("age").unwrap();
        claim_schema_builder.add_attr("height").unwrap();
        claim_schema_builder.finalize().unwrap()
    }

    pub fn xyz_claim_schema() -> ClaimSchema {
        let mut claim_schema_builder = Issuer::new_claim_schema_builder().unwrap();
        claim_schema_builder.add_attr("status").unwrap();
        claim_schema_builder.add_attr("period").unwrap();
        claim_schema_builder.finalize().unwrap()
    }

    pub fn gvt_claim_values() -> ClaimValues {
        let mut claim_values_builder = Issuer::new_claim_values_builder().unwrap();
        claim_values_builder.add_value("name", "1139481716457488690172217916278103335").unwrap();
        claim_values_builder.add_value("sex", "5944657099558967239210949258394887428692050081607692519917050011144233115103").unwrap();
        claim_values_builder.add_value("age", "28").unwrap();
        claim_values_builder.add_value("height", "175").unwrap();
        claim_values_builder.finalize().unwrap()
    }

    pub fn xyz_claim_values() -> ClaimValues {
        let mut claim_values_builder = Issuer::new_claim_values_builder().unwrap();
        claim_values_builder.add_value("status", "51792877103171595686471452153480627530895").unwrap();
        claim_values_builder.add_value("period", "8").unwrap();
        claim_values_builder.finalize().unwrap()
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

