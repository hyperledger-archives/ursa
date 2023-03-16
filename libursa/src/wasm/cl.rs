use cl;
use js_sys::Function;
use std::collections::HashSet;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use crate::cl::RevocationTailsAccessor;

use super::convert_from_js;

#[wasm_bindgen]
pub struct CredentialSchema(cl::CredentialSchemaBuilder);

#[wasm_bindgen]
impl CredentialSchema {
    #[wasm_bindgen(constructor)]
    pub fn new() -> CredentialSchema {
        CredentialSchema(cl::CredentialSchemaBuilder::new().unwrap())
    }

    #[wasm_bindgen(js_name = addAttr)]
    pub fn add_attr(&mut self, attribute: &str) {
        self.0.add_attr(attribute).unwrap();
    }
}

#[wasm_bindgen]
pub struct NonCredentialSchema(cl::NonCredentialSchemaBuilder);

#[wasm_bindgen]
impl NonCredentialSchema {
    #[wasm_bindgen(constructor)]
    pub fn new() -> NonCredentialSchema {
        NonCredentialSchema(cl::NonCredentialSchemaBuilder::new().unwrap())
    }

    #[wasm_bindgen(js_name = addAttr)]
    pub fn add_attr(&mut self, attribute: &str) {
        self.0.add_attr(attribute).unwrap();
    }
}

#[wasm_bindgen]
pub struct CredentialValues(cl::CredentialValuesBuilder);

#[wasm_bindgen]
impl CredentialValues {
    #[wasm_bindgen(constructor)]
    pub fn new() -> CredentialValues {
        CredentialValues(cl::CredentialValuesBuilder::new().unwrap())
    }

    #[wasm_bindgen(js_name = addMasterSecret)]
    pub fn add_master_secret(&mut self, value: &MasterSecret) -> Result<(), JsValue> {
        let ms = maperr!(value.0.value());
        maperr!(self.0.add_value_hidden("master_secret", &ms));
        Ok(())
    }

    #[wasm_bindgen(js_name = addKnown)]
    pub fn add_known(&mut self, attr: &str, value: &str) -> Result<(), JsValue> {
        maperr!(self.0.add_dec_known(attr, value));
        Ok(())
    }

    #[wasm_bindgen(js_name = addHidden)]
    pub fn add_hidden(&mut self, attr: &str, value: &str) -> Result<(), JsValue> {
        maperr!(self.0.add_dec_hidden(attr, value));
        Ok(())
    }

    #[wasm_bindgen(js_name = addCommitment)]
    pub fn add_commitment(
        &mut self,
        attr: &str,
        value: &str,
        blinding_factor: &str,
    ) -> Result<(), JsValue> {
        maperr!(self.0.add_dec_commitment(attr, value, blinding_factor));
        Ok(())
    }
}

#[wasm_bindgen]
pub struct CredentialPrimaryPublicKey(cl::CredentialPrimaryPublicKey);

#[wasm_bindgen]
pub struct CredentialPublicKey(cl::CredentialPublicKey);

#[wasm_bindgen]
impl CredentialPublicKey {
    #[wasm_bindgen(js_name = getPrimaryKey)]
    pub fn get_primary_key(&self) -> Result<CredentialPrimaryPublicKey, JsValue> {
        Ok(CredentialPrimaryPublicKey(maperr!(self
            .0
            .get_primary_key())))
    }

    #[wasm_bindgen(js_name = getRevocationKey)]
    pub fn get_revocation_key(&self) -> Result<JsValue, JsValue> {
        match maperr!(self.0.get_revocation_key()) {
            Some(k) => Ok(JsValue::from_serde(&CredentialRevocationPublicKey(k)).unwrap()),
            None => Ok(JsValue::NULL),
        }
    }
}

#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct CredentialRevocationPublicKey(cl::CredentialRevocationPublicKey);

#[wasm_bindgen]
pub struct CredentialPrivateKey(cl::CredentialPrivateKey);

#[wasm_bindgen]
pub struct CredentialKeyCorrectnessProof(cl::CredentialKeyCorrectnessProof);

/// Convenience class for javascript. This provides a name-value pair structure
/// instead of a tuple. The compiler complains about unused fields
/// so allow(unused) is in place for now
#[wasm_bindgen]
#[allow(dead_code)]
pub struct CredentialDefinition {
    public_key: CredentialPublicKey,
    private_key: CredentialPrivateKey,
    key_correctness_proof: CredentialKeyCorrectnessProof,
}

#[wasm_bindgen]
pub struct MasterSecret(cl::MasterSecret);

#[wasm_bindgen]
impl MasterSecret {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<MasterSecret, JsValue> {
        Ok(MasterSecret(maperr!(
            cl::prover::Prover::new_master_secret()
        )))
    }
}

#[wasm_bindgen]
pub struct Nonce(cl::Nonce);

#[wasm_bindgen]
impl Nonce {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<Nonce, JsValue> {
        Ok(Nonce(maperr!(cl::new_nonce())))
    }
}

#[wasm_bindgen]
pub struct BlindedCredentialSecrets(cl::BlindedCredentialSecrets);

#[wasm_bindgen]
pub struct CredentialSecretsBlindingFactors(cl::CredentialSecretsBlindingFactors);

#[wasm_bindgen]
pub struct BlindedCredentialSecretsCorrectnessProof(cl::BlindedCredentialSecretsCorrectnessProof);

/// Convenience class for javascript. This provides a name-value pair structure
/// instead of a tuple. The compiler complains about unused fields
/// so allow(unused) is in place for now
#[wasm_bindgen]
#[allow(dead_code)]
pub struct ProverBlindedCredentialSecrets {
    blinded_credential_secrets: BlindedCredentialSecrets,
    credential_secrets_blinding_factors: CredentialSecretsBlindingFactors,
    blinded_credential_secrets_correctness_proof: BlindedCredentialSecretsCorrectnessProof,
}

#[wasm_bindgen]
pub struct CredentialSignature(cl::CredentialSignature);

#[wasm_bindgen]
impl CredentialSignature {
    #[wasm_bindgen(js_name = extractIndex)]
    pub fn extract_index(&self) -> Option<u32> {
        self.0.extract_index()
    }
}

#[wasm_bindgen]
pub struct SignatureCorrectnessProof(cl::SignatureCorrectnessProof);

#[wasm_bindgen]
pub struct IssuedCredential {
    credential_signature: CredentialSignature,
    signature_correctness_proof: SignatureCorrectnessProof,
}

/// Convenience class for javascript. This provides a name-value pair structure
/// instead of a tuple. The compiler complains about unused fields
/// so allow(unused) is in place for now
#[wasm_bindgen]
#[allow(dead_code)]
pub struct IssuedCredentialWithRevocation {
    issued_credential: IssuedCredential,
    delta: Option<RevocationRegistryDelta>,
}

#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct Tail(cl::Tail);

#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct RevocationPublicKey(cl::RevocationKeyPublic);

#[wasm_bindgen]
pub struct RevocationPrivateKey(cl::RevocationKeyPrivate);

#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct RevocationRegistry(cl::RevocationRegistry);

#[wasm_bindgen]
pub struct RevocationRegistryDelta(cl::RevocationRegistryDelta);

#[wasm_bindgen]
impl RevocationRegistryDelta {
    #[wasm_bindgen(js_name = fromParts)]
    pub fn from_parts(
        rev_reg_from: &JsValue,
        rev_reg_to: &RevocationRegistry,
        issued: &JsValue,
        revoked: &JsValue,
    ) -> Result<RevocationRegistryDelta, JsValue> {
        let rev_reg_from = check_opt_reference!(rev_reg_from, RevocationRegistry);
        let issued: HashSet<u32> = convert_from_js(issued)?;
        let revoked: HashSet<u32> = convert_from_js(revoked)?;

        let rrd = cl::RevocationRegistryDelta::from_parts(
            rev_reg_from.as_ref(),
            &rev_reg_to.0,
            &issued,
            &revoked,
        );
        Ok(RevocationRegistryDelta(rrd))
    }

    pub fn merge(&mut self, other_delta: &RevocationRegistryDelta) -> Result<(), JsValue> {
        self.0.merge(&other_delta.0)?;
        Ok(())
    }
}

#[wasm_bindgen]
pub struct RevocationTailsGenerator(cl::RevocationTailsGenerator);

#[wasm_bindgen]
impl RevocationTailsGenerator {
    pub fn count(&self) -> u32 {
        self.0.count()
    }

    #[wasm_bindgen(js_name = next)]
    pub fn try_next(&mut self) -> Result<JsValue, JsValue> {
        let res = maperr!(self.0.try_next());
        match res {
            Some(p) => Ok(JsValue::from_serde(&Tail(p)).unwrap()),
            None => Ok(JsValue::NULL),
        }
    }
}

#[wasm_bindgen]
pub struct SimpleTailsAccessor(cl::SimpleTailsAccessor);

#[wasm_bindgen]
impl SimpleTailsAccessor {
    #[wasm_bindgen(constructor)]
    pub fn new(
        rev_tails_generator: &mut RevocationTailsGenerator,
    ) -> Result<SimpleTailsAccessor, JsValue> {
        let sta = maperr!(cl::SimpleTailsAccessor::new(&mut rev_tails_generator.0));
        Ok(SimpleTailsAccessor(sta))
    }

    #[wasm_bindgen(js_name = accessTail)]
    pub fn access_tail(&self, tail_id: u32, accessor: &Function) {
        let context = JsValue::NULL;
        self.0
            .access_tail(tail_id, &mut |tail| {
                accessor
                    .call1(&context, &JsValue::from_serde(tail).unwrap())
                    .unwrap();
            })
            .unwrap();
    }
}

#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct Witness(cl::Witness);

#[wasm_bindgen]
impl Witness {
    #[wasm_bindgen(constructor)]
    pub fn new(
        rev_idx: u32,
        max_cred_num: u32,
        issuance_by_default: bool,
        rev_reg_delta: &RevocationRegistryDelta,
        rev_tails_accessor: &SimpleTailsAccessor,
    ) -> Result<Witness, JsValue> {
        let w = maperr!(cl::Witness::new(
            rev_idx,
            max_cred_num,
            issuance_by_default,
            &rev_reg_delta.0,
            &rev_tails_accessor.0
        ));
        Ok(Witness(w))
    }

    pub fn update(
        &mut self,
        rev_idx: u32,
        max_cred_num: u32,
        rev_reg_delta: &RevocationRegistryDelta,
        rev_tails_accessor: &SimpleTailsAccessor,
    ) -> Result<(), JsValue> {
        maperr!(self.0.update(
            rev_idx,
            max_cred_num,
            &rev_reg_delta.0,
            &rev_tails_accessor.0
        ));
        Ok(())
    }
}

#[wasm_bindgen]
pub struct Proof(cl::Proof);

#[wasm_bindgen]
pub struct SubProofRequest(cl::SubProofRequestBuilder);

#[wasm_bindgen]
impl SubProofRequest {
    #[wasm_bindgen(constructor)]
    pub fn new() -> SubProofRequest {
        let spr = cl::verifier::Verifier::new_sub_proof_request_builder().unwrap();
        SubProofRequest(spr)
    }

    #[wasm_bindgen(js_name = addRevealedAttribute)]
    pub fn add_revelated_attribute(&mut self, attribute: &str) {
        self.0.add_revealed_attr(attribute).unwrap();
    }

    #[wasm_bindgen(js_name = addPredicate)]
    pub fn add_predicate(&mut self, attribute: &str, p_type: &str, value: i32) {
        self.0.add_predicate(attribute, p_type, value).unwrap();
    }
}

#[wasm_bindgen]
pub struct ProofBuilder(cl::prover::ProofBuilder);

#[wasm_bindgen]
impl ProofBuilder {
    #[wasm_bindgen(constructor)]
    pub fn new() -> ProofBuilder {
        ProofBuilder(cl::prover::Prover::new_proof_builder().unwrap())
    }

    #[wasm_bindgen(js_name = addCommonAttribute)]
    pub fn add_common_attribute(&mut self, attribute: &str) {
        self.0.add_common_attribute(attribute).unwrap();
    }

    #[wasm_bindgen(js_name = addSubProofRequest)]
    pub fn add_sub_proof_request(
        &mut self,
        sub_proof_request: SubProofRequest,
        credential_schema: CredentialSchema,
        non_credential_schema: NonCredentialSchema,
        credential_signature: &CredentialSignature,
        credential_values: CredentialValues,
        credential_pub_key: &CredentialPublicKey,
        rev_reg: &JsValue,
        witness: &JsValue,
    ) -> Result<(), JsValue> {
        let spr = finalize!(sub_proof_request);
        let cs = finalize!(credential_schema);
        let ncs = finalize!(non_credential_schema);
        let cv = finalize!(credential_values);
        let rev_reg = check_opt_reference!(rev_reg, RevocationRegistry);
        let witness = check_opt_reference!(witness, Witness);

        maperr!(self.0.add_sub_proof_request(
            &spr,
            &cs,
            &ncs,
            &credential_signature.0,
            &cv,
            &credential_pub_key.0,
            rev_reg.as_ref(),
            witness.as_ref()
        ));
        Ok(())
    }

    pub fn finalize(&self, nonce: &Nonce) -> Result<Proof, JsValue> {
        let res = maperr!(self.0.finalize(&nonce.0));
        Ok(Proof(res))
    }
}

#[wasm_bindgen]
pub struct ProofVerifier(cl::verifier::ProofVerifier);

#[wasm_bindgen]
impl ProofVerifier {
    #[wasm_bindgen(constructor)]
    pub fn new() -> ProofVerifier {
        ProofVerifier(cl::verifier::Verifier::new_proof_verifier().unwrap())
    }

    #[wasm_bindgen(js_name = addSubProofRequest)]
    pub fn add_sub_proof_request(
        &mut self,
        sub_proof_request: SubProofRequest,
        credential_schema: CredentialSchema,
        non_credential_schema: NonCredentialSchema,
        credential_pub_key: &CredentialPublicKey,
        rev_key_pub: &JsValue,
        rev_reg: &JsValue,
    ) -> Result<(), JsValue> {
        let spr = finalize!(sub_proof_request);
        let cs = finalize!(credential_schema);
        let ncs = finalize!(non_credential_schema);
        let rev_key_pub = check_opt_reference!(rev_key_pub, RevocationPublicKey);
        let rev_reg = check_opt_reference!(rev_reg, RevocationRegistry);

        maperr!(self.0.add_sub_proof_request(
            &spr,
            &cs,
            &ncs,
            &credential_pub_key.0,
            rev_key_pub.as_ref(),
            rev_reg.as_ref()
        ));
        Ok(())
    }

    pub fn verify(&mut self, proof: &Proof, nonce: &Nonce) -> Result<bool, JsValue> {
        let res = maperr!(self.0.verify(&proof.0, &nonce.0));
        Ok(res)
    }
}

#[wasm_bindgen]
pub struct Issuer;

#[wasm_bindgen]
impl Issuer {
    #[wasm_bindgen(js_name = newCredentialDefinition)]
    pub fn new_credential_def(
        credential_schema: CredentialSchema,
        non_credential_schema: NonCredentialSchema,
        support_revocation: bool,
    ) -> Result<CredentialDefinition, JsValue> {
        let cs = finalize!(credential_schema);
        let ncs = finalize!(non_credential_schema);
        let (pk, sk, kp) = maperr!(cl::issuer::Issuer::new_credential_def(
            &cs,
            &ncs,
            support_revocation
        ));
        Ok(CredentialDefinition {
            public_key: CredentialPublicKey(pk),
            private_key: CredentialPrivateKey(sk),
            key_correctness_proof: CredentialKeyCorrectnessProof(kp),
        })
    }

    #[wasm_bindgen(js_name = signCredential)]
    pub fn sign_credential(
        prover_id: &str,
        blinded_credential_secrets: &BlindedCredentialSecrets,
        blinded_credential_secrets_correctness_proof: &BlindedCredentialSecretsCorrectnessProof,
        credential_nonce: &Nonce,
        credential_issuance_nonce: &Nonce,
        credential_values: CredentialValues,
        credential_pub_key: &CredentialPublicKey,
        credential_priv_key: &CredentialPrivateKey,
    ) -> Result<IssuedCredential, JsValue> {
        let cv = finalize!(credential_values);

        let (cs, scp) = maperr!(cl::issuer::Issuer::sign_credential(
            prover_id,
            &blinded_credential_secrets.0,
            &blinded_credential_secrets_correctness_proof.0,
            &credential_nonce.0,
            &credential_issuance_nonce.0,
            &cv,
            &credential_pub_key.0,
            &credential_priv_key.0
        ));
        Ok(IssuedCredential {
            credential_signature: CredentialSignature(cs),
            signature_correctness_proof: SignatureCorrectnessProof(scp),
        })
    }

    #[wasm_bindgen(js_name = signCredentialWithRevocation)]
    pub fn sign_credential_with_revocation(
        prover_id: &str,
        blinded_credential_secrets: &BlindedCredentialSecrets,
        blinded_credential_secrets_correctness_proof: &BlindedCredentialSecretsCorrectnessProof,
        credential_nonce: &Nonce,
        credential_issuance_nonce: &Nonce,
        credential_values: CredentialValues,
        credential_pub_key: &CredentialPublicKey,
        credential_priv_key: &CredentialPrivateKey,
        rev_idx: u32,
        max_cred_num: u32,
        issuance_by_default: bool,
        rev_reg: &mut RevocationRegistry,
        rev_key_priv: &RevocationPrivateKey,
        rev_tails_accessor: &SimpleTailsAccessor,
    ) -> Result<IssuedCredentialWithRevocation, JsValue> {
        let cv = finalize!(credential_values);

        let (cs, scp, delta) = maperr!(cl::issuer::Issuer::sign_credential_with_revoc(
            prover_id,
            &blinded_credential_secrets.0,
            &blinded_credential_secrets_correctness_proof.0,
            &credential_nonce.0,
            &credential_issuance_nonce.0,
            &cv,
            &credential_pub_key.0,
            &credential_priv_key.0,
            rev_idx,
            max_cred_num,
            issuance_by_default,
            &mut rev_reg.0,
            &rev_key_priv.0,
            &rev_tails_accessor.0
        ));
        Ok(IssuedCredentialWithRevocation {
            issued_credential: IssuedCredential {
                credential_signature: CredentialSignature(cs),
                signature_correctness_proof: SignatureCorrectnessProof(scp),
            },
            delta: delta.map(|d| RevocationRegistryDelta(d)),
        })
    }
}

#[wasm_bindgen]
pub struct Prover;

#[wasm_bindgen]
impl Prover {
    #[wasm_bindgen(js_name = blindedCredentialSecrets)]
    pub fn blind_credential_secrets(
        credential_pub_key: &CredentialPublicKey,
        credential_key_correctness_proof: &CredentialKeyCorrectnessProof,
        credential_values: CredentialValues,
        credential_nonce: &Nonce,
    ) -> Result<ProverBlindedCredentialSecrets, JsValue> {
        let cv = finalize!(credential_values);
        let (
            blinded_credential_secrets,
            credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof,
        ) = maperr!(cl::prover::Prover::blind_credential_secrets(
            &credential_pub_key.0,
            &credential_key_correctness_proof.0,
            &cv,
            &credential_nonce.0
        ));
        Ok(ProverBlindedCredentialSecrets {
            blinded_credential_secrets: BlindedCredentialSecrets(blinded_credential_secrets),
            credential_secrets_blinding_factors: CredentialSecretsBlindingFactors(
                credential_secrets_blinding_factors,
            ),
            blinded_credential_secrets_correctness_proof: BlindedCredentialSecretsCorrectnessProof(
                blinded_credential_secrets_correctness_proof,
            ),
        })
    }

    #[wasm_bindgen(js_name = processCredentialSignature)]
    pub fn process_credential_signature(
        issued_credential: &IssuedCredential,
        credential_values: CredentialValues,
        credential_secrets_blinding_factors: &CredentialSecretsBlindingFactors,
        credential_pub_key: &CredentialPublicKey,
        nonce: &Nonce,
        rev_key_pub: &JsValue,
        rev_reg: &JsValue,
        witness: &JsValue,
    ) -> Result<CredentialSignature, JsValue> {
        let rev_key_pub = check_opt_reference!(rev_key_pub, RevocationPublicKey);
        let rev_reg = check_opt_reference!(rev_reg, RevocationRegistry);
        let witness = check_opt_reference!(witness, Witness);

        let mut cs = maperr!(issued_credential.credential_signature.0.try_clone());
        let cv = finalize!(credential_values);

        maperr!(cl::prover::Prover::process_credential_signature(
            &mut cs,
            &cv,
            &issued_credential.signature_correctness_proof.0,
            &credential_secrets_blinding_factors.0,
            &credential_pub_key.0,
            &nonce.0,
            rev_key_pub.as_ref(),
            rev_reg.as_ref(),
            witness.as_ref()
        ));
        Ok(CredentialSignature(cs))
    }
}
