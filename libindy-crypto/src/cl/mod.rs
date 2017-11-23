mod constants;
mod helpers;
pub mod issuer;
pub mod prover;
pub mod types;
pub mod verifier;


#[cfg(test)]
mod test {
    use super::*;
    use self::issuer::Issuer;
    use self::prover::Prover;
    use self::verifier::Verifier;

    #[test]
    #[ignore]
    fn demo() {
        let claim_schema_builder = Issuer::new_claim_schema_builder().unwrap();
        let claim_schema = claim_schema_builder
            .add_attr("name").unwrap()
            .add_attr("sex").unwrap()
            .add_attr("age").unwrap()
            .add_attr("height").unwrap()
            .finalize().unwrap();
        let (issuer_pub, issuer_priv) = Issuer::new_keys(&claim_schema, false).unwrap();

        let master_secret = Prover::new_master_secret().unwrap();
        let (blinded_master_secret, blinded_master_secret_data) = Prover::blinded_master_secret(&issuer_pub, &master_secret).unwrap();
        let claim_schema_values_builder = Issuer::new_claim_values_builder().unwrap();
        let claim_values = claim_schema_values_builder
            .add_value("name", "1139481716457488690172217916278103335").unwrap()
            .add_value("sex", "5944657099558967239210949258394887428692050081607692519917050011144233115103").unwrap()
            .add_value("age", "28").unwrap()
            .add_value("height", "175").unwrap()
            .finalize().unwrap();
        let mut claim = Issuer::sign_claim("CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW", &blinded_master_secret,
                                           &claim_values,
                                           &issuer_pub, &issuer_priv,
                                           Some(1), None, None).unwrap();
        Prover::process_claim_signature(&mut claim, &blinded_master_secret_data, &issuer_pub, None).unwrap();

        let sub_proof_request = types::SubProofRequestBuilder::new().unwrap()
            .add_revealed_attr("name").unwrap()
            .add_predicate(&types::Predicate {
                attr_name: "age".to_string(),
                value: 18,
                p_type: types::PredicateType::GE,
            }).unwrap()
            .finalize().unwrap();
        let mut proof_builder = Prover::new_proof_builder().unwrap();
        proof_builder.add_sub_proof_request("issuer_key_id_1", &claim, claim_values,
                                            &issuer_pub,
                                            None,
                                            sub_proof_request.clone(),
                                            claim_schema.clone()).unwrap();
        let nonce = Verifier::new_nonce().unwrap();
        let proof = proof_builder.finalize(&nonce, &master_secret).unwrap();

        let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
        proof_verifier.add_sub_proof_request("issuer_key_id_1", issuer_pub, None, sub_proof_request, claim_schema).unwrap();
        assert_eq!(true, proof_verifier.verify(&proof, &nonce).unwrap());
    }
}
