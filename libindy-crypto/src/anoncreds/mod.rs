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
    use self::prover::{Prover, ProofBuilder};
    use self::verifier::Verifier;

    #[test]
    fn demo() {
        let claim_attributes_builder = Issuer::new_claim_attrs_builder().unwrap();
        let claim_attributes = claim_attributes_builder
            .add_attr("name").unwrap()
            .add_attr("sex").unwrap()
            .add_attr("age").unwrap()
            .finalize().unwrap();
        let (issuer_pub, issuer_priv) = Issuer::new_keys(&claim_attributes, false).unwrap();

        let master_secret = Prover::generate_master_secret().unwrap();
        let (blinded_master_secret, blinded_master_secret_data) = Prover::generate_blinded_master_secret(&issuer_pub, &master_secret).unwrap();
        let claim_attributes_values_builder = Issuer::new_claim_attrs_values_builder().unwrap();
        let claim_attributes_values = claim_attributes_values_builder
            .add_attr_value("name", "111").unwrap()
            .add_attr_value("sex", "0").unwrap()
            .add_attr_value("age", "22").unwrap()
            .finalize().unwrap();
        let mut claim = Issuer::new_claim("prover1", &blinded_master_secret,
                                          &claim_attributes_values,
                                          &issuer_pub, &issuer_priv,
                                          None, None, None).unwrap();
        Prover::process_claim(&mut claim, &blinded_master_secret_data, None, None).unwrap();

        let proof_attrs = types::ProofAttrsBuilder::new().unwrap()
            .add_revealed_attr("sex").unwrap()
            .add_revealed_attr("name").unwrap()
            .add_revealed_attr("age").unwrap()
            //            .add_predicate(&types::Predicate {
            //                attr_name: "age".to_string(),
            //                value: 21,
            //                p_type: types::PredicateType::GE,
            //            }).unwrap()
            .finalize().unwrap();
        let mut proof_builder = ProofBuilder::new().unwrap();
        proof_builder.add_claim("issuer_key_id_1", &claim, &claim_attributes_values,
                                &issuer_pub,
                                None,
                                &proof_attrs).unwrap();
        let nonce = Verifier::generate_nonce().unwrap();
        let proof = proof_builder.finalize(&nonce, &master_secret).unwrap();

        let mut verifier = Verifier::new();
        verifier.add_claim("issuer_key_id_1", issuer_pub, None, None, proof_attrs).unwrap();
        assert_eq!(true, verifier.verify(&proof, &nonce).unwrap());
    }
}
