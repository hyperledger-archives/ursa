#[cfg(feature = "cl")]
extern crate ursa;

use ursa::cl::issuer::Issuer;
use ursa::cl::prover::Prover;
use ursa::cl::verifier::Verifier;
use ursa::cl::*;

use std::time::{Duration, Instant};

pub fn get_credential_schema() -> CredentialSchema {
    let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
    credential_schema_builder.add_attr("name").unwrap();
    credential_schema_builder.add_attr("sex").unwrap();
    credential_schema_builder.add_attr("age").unwrap();
    credential_schema_builder.add_attr("height").unwrap();
    credential_schema_builder.finalize().unwrap()
}

fn get_non_credential_schema() -> NonCredentialSchema {
    let mut non_credential_schema_builder = Issuer::new_non_credential_schema_builder().unwrap();
    non_credential_schema_builder
        .add_attr("master_secret")
        .unwrap();
    non_credential_schema_builder.finalize().unwrap()
}

fn get_credential_values(master_secret: &MasterSecret) -> CredentialValues {
    let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();
    credential_values_builder
        .add_value_hidden("master_secret", &master_secret.value().unwrap())
        .unwrap();
    credential_values_builder
        .add_dec_known("name", "1139481716457488690172217916278103335")
        .unwrap();
    credential_values_builder
        .add_dec_known(
            "sex",
            "5944657099558967239210949258394887428692050081607692519917050011144233115103",
        )
        .unwrap();
    credential_values_builder
        .add_dec_known("age", "28")
        .unwrap();
    credential_values_builder
        .add_dec_known("height", "175")
        .unwrap();
    credential_values_builder.finalize().unwrap()
}

fn get_sub_proof_request() -> SubProofRequest {
    let mut sub_proof_request_builder = Verifier::new_sub_proof_request_builder().unwrap();
    sub_proof_request_builder.add_revealed_attr("name").unwrap();
    sub_proof_request_builder.finalize().unwrap()
}

type ProverData = (u32, CredentialValues, CredentialSignature, Witness);

fn setup_cred_and_issue(
    max_cred_num: u32,
    issuance_by_default: bool,
) -> (
    CredentialSchema,
    NonCredentialSchema,
    CredentialPublicKey,
    RevocationKeyPublic,
    RevocationRegistry,
    RevocationRegistryDelta,
    SimpleTailsAccessor,
    Vec<ProverData>,
) {
    let credential_schema = get_credential_schema();
    let non_credential_schema = get_non_credential_schema();

    // 2. Issuer creates credential definition(with revocation keys)
    let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
        Issuer::new_credential_def(&credential_schema, &non_credential_schema, true).unwrap();

    // 3. Issuer creates revocation registry
    let (rev_key_pub, rev_key_priv, mut rev_reg, mut rev_tails_generator) =
        Issuer::new_revocation_registry_def(&credential_pub_key, max_cred_num, issuance_by_default)
            .unwrap();

    let simple_tail_accessor = SimpleTailsAccessor::new(&mut rev_tails_generator).unwrap();

    let mut prover_data: Vec<ProverData> = vec![];

    let mut rev_reg_delta: Option<RevocationRegistryDelta> = None;

    let start = Instant::now();
    for i in 0..max_cred_num {
        let credential_values = get_credential_values(&Prover::new_master_secret().unwrap());

        // 5. Issuer creates nonce used by Prover to create correctness proof for blinded secrets
        let blinding_correctness_nonce = new_nonce().unwrap();

        // 6. Prover blinds master secret
        let (
            blinded_credential_secrets,
            credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof,
        ) = Prover::blind_credential_secrets(
            &credential_pub_key,
            &credential_key_correctness_proof,
            &credential_values,
            &blinding_correctness_nonce,
        )
        .unwrap();

        // 7. Prover creates nonce used by Issuer to create correctness proof for signature
        let signature_correctness_nonce = new_nonce().unwrap();

        // 8. Issuer creates and sign credential values
        let rev_idx = i + 1;
        let (mut credential_signature, signature_correctness_proof, rr_delta) =
            Issuer::sign_credential_with_revoc(
                &rev_idx.to_string(),
                &blinded_credential_secrets,
                &blinded_credential_secrets_correctness_proof,
                &blinding_correctness_nonce,
                &signature_correctness_nonce,
                &credential_values,
                &credential_pub_key,
                &credential_priv_key,
                rev_idx,
                max_cred_num,
                issuance_by_default,
                &mut rev_reg,
                &rev_key_priv,
                &simple_tail_accessor,
            )
            .unwrap();

        if i == 0 {
            rev_reg_delta = rr_delta;
        } else {
            let mut new_delta = rev_reg_delta.unwrap();
            new_delta.merge(&rr_delta.unwrap()).unwrap();
            rev_reg_delta = Some(new_delta)
        }

        let unwrapped_delta = rev_reg_delta.unwrap();
        // 9. Prover creates witness
        let witness = Witness::new(
            rev_idx,
            max_cred_num,
            issuance_by_default,
            &unwrapped_delta,
            &simple_tail_accessor,
        )
        .unwrap();
        rev_reg_delta = Some(unwrapped_delta);

        // 10. Prover processes credential signature
        Prover::process_credential_signature(
            &mut credential_signature,
            &credential_values,
            &signature_correctness_proof,
            &credential_secrets_blinding_factors,
            &credential_pub_key,
            &signature_correctness_nonce,
            Some(&rev_key_pub),
            Some(&rev_reg),
            Some(&witness),
        )
        .unwrap();

        prover_data.push((rev_idx, credential_values, credential_signature, witness))
    }

    println!(
        "Issuance time for {} is {:?}",
        max_cred_num,
        start.elapsed()
    );

    (
        credential_schema,
        non_credential_schema,
        credential_pub_key,
        rev_key_pub,
        rev_reg,
        rev_reg_delta.unwrap(),
        simple_tail_accessor,
        prover_data,
    )
}

fn gen_proofs(
    max_cred_num: u32,
    issuance_by_default: bool,
    credential_schema: &CredentialSchema,
    non_credential_schema: &NonCredentialSchema,
    credential_pub_key: &CredentialPublicKey,
    sub_proof_request: &SubProofRequest,
    nonces: &[Nonce],
    rev_reg: &RevocationRegistry,
    rev_reg_delta: &RevocationRegistryDelta,
    simple_tail_accessor: &SimpleTailsAccessor,
    prover_data: &mut [ProverData],
) -> Vec<Proof> {
    let mut proofs = Vec::with_capacity(nonces.len());
    let mut total_witness_gen = Duration::new(0, 0);
    let mut total_proving = Duration::new(0, 0);
    for i in 0..nonces.len() {
        let (rev_idx, ref credential_values, ref credential_signature, ref mut _witness) =
            prover_data[i as usize];

        let mut start = Instant::now();
        let witness = Witness::new(
            rev_idx,
            max_cred_num,
            issuance_by_default,
            rev_reg_delta,
            simple_tail_accessor,
        )
        .unwrap();
        //witness.update(rev_idx, max_cred_num, rev_reg_delta, simple_tail_accessor).unwrap();
        total_witness_gen += start.elapsed();

        let mut proof_builder = Prover::new_proof_builder().unwrap();
        proof_builder.add_common_attribute("master_secret").unwrap();

        start = Instant::now();
        proof_builder
            .add_sub_proof_request(
                sub_proof_request,
                credential_schema,
                non_credential_schema,
                credential_signature,
                credential_values,
                credential_pub_key,
                Some(rev_reg),
                Some(&witness),
            )
            .unwrap();
        proofs.push(proof_builder.finalize(&nonces[i as usize]).unwrap());
        total_proving += start.elapsed();
    }

    println!(
        "Total witness gen time for {} is {:?}",
        nonces.len(),
        total_witness_gen
    );
    println!(
        "Total proving time for {} is {:?}",
        nonces.len(),
        total_proving
    );

    proofs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bench() {
        let max_cred_num = 10;
        let num_proofs_to_do = 1;
        let issuance_by_default = false;

        let sub_proof_request = get_sub_proof_request();
        let (
            credential_schema,
            non_credential_schema,
            credential_pub_key,
            rev_key_pub,
            rev_reg,
            rev_reg_delta,
            simple_tail_accessor,
            mut prover_data,
        ) = setup_cred_and_issue(max_cred_num, issuance_by_default);

        let nonces: Vec<_> = (0..num_proofs_to_do)
            .map(|_| new_nonce().unwrap())
            .collect();

        let mut start = Instant::now();
        let proofs = gen_proofs(
            max_cred_num,
            issuance_by_default,
            &credential_schema,
            &non_credential_schema,
            &credential_pub_key,
            &sub_proof_request,
            &nonces,
            &rev_reg,
            &rev_reg_delta,
            &simple_tail_accessor,
            &mut prover_data,
        );
        println!(
            "Proof gen time for {} is {:?}",
            num_proofs_to_do,
            start.elapsed()
        );

        start = Instant::now();
        for i in 0..num_proofs_to_do {
            let idx = i as usize;
            let mut verifier = Verifier::new_proof_verifier().unwrap();
            verifier
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_pub_key,
                    Some(&rev_key_pub),
                    Some(&rev_reg),
                )
                .unwrap();
            assert!(verifier.verify(&proofs[idx], &nonces[idx]).unwrap());
        }
        println!(
            "Verif time for {} is {:?}",
            num_proofs_to_do,
            start.elapsed()
        );
    }
}
