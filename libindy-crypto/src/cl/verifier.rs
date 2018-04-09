use bn::BigNumber;
use cl::*;
use cl::constants::{LARGE_E_START_VALUE, ITERATION};
use cl::helpers::*;
use errors::IndyCryptoError;

use std::collections::BTreeSet;
use std::iter::FromIterator;
use utils::get_hash_as_int;

/// Party that wants to check that prover has some credentials provided by issuer.
pub struct Verifier {}

impl Verifier {
    /// Creates and returns sub proof request entity builder.
    /// Part of proof request related to a particular schema-key.
    ///
    /// The purpose of sub proof request builder is building of sub proof request entity that
    /// represents requested attributes and predicates.
    ///
    /// # Example
    /// ```
    /// use indy_crypto::cl::verifier::Verifier;
    ///
    /// let mut sub_proof_request_builder = Verifier::new_sub_proof_request_builder().unwrap();
    /// sub_proof_request_builder.add_revealed_attr("name").unwrap();
    /// sub_proof_request_builder.add_predicate("age", "GE", 18).unwrap();
    /// let _sub_proof_request = sub_proof_request_builder.finalize().unwrap();
    /// ```
    pub fn new_sub_proof_request_builder() -> Result<SubProofRequestBuilder, IndyCryptoError> {
        let res = SubProofRequestBuilder::new()?;
        Ok(res)
    }

    /// Creates and returns proof verifier.
    ///
    /// The purpose of `proof verifier` is check proof provided by Prover.
    ///
    /// # Example
    /// ```
    /// use indy_crypto::cl::verifier::Verifier;
    ///
    /// let _proof_verifier = Verifier::new_proof_verifier().unwrap();
    /// ```
    pub fn new_proof_verifier() -> Result<ProofVerifier, IndyCryptoError> {
        Ok(ProofVerifier {
            credentials: Vec::new(),
        })
    }
}


#[derive(Debug)]
pub struct ProofVerifier {
    credentials: Vec<VerifiableCredential>,
}

impl ProofVerifier {
    /// Add sub proof request to proof verifier.
    /// The order of sub-proofs is important: both Prover and Verifier should use the same order.
    ///
    /// # Arguments
    /// * `proof_verifier` - Proof verifier.
    /// * `credential_schema` - Credential schema.
    /// * `credential_pub_key` - Credential public key.
    /// * `rev_reg_pub` - Revocation registry public key.
    /// * `sub_proof_request` - Requested attributes and predicates instance pointer.
    ///
    /// #Example
    /// ```
    /// use indy_crypto::cl::issuer::Issuer;
    /// use indy_crypto::cl::verifier::Verifier;
    ///
    /// let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
    /// credential_schema_builder.add_attr("sex").unwrap();
    /// let credential_schema = credential_schema_builder.finalize().unwrap();
    ///
    /// let mut non_credential_schema_builder = Issuer::new_non_credential_schema_builder().unwrap();
    /// non_credential_schema_builder.add_attr("master_secret").unwrap();
    /// let non_credential_schema = non_credential_schema_builder.finalize().unwrap();
    ///
    /// let (credential_pub_key, credential_priv_key, cred_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, &non_credential_schema, false).unwrap();
    ///
    /// let (credential_pub_key, _credential_priv_key, _credential_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, &non_credential_schema, false).unwrap();
    ///
    /// let mut sub_proof_request_builder = Verifier::new_sub_proof_request_builder().unwrap();
    /// sub_proof_request_builder.add_revealed_attr("sex").unwrap();
    /// let sub_proof_request = sub_proof_request_builder.finalize().unwrap();
    ///
    /// let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
    ///
    /// proof_verifier.add_sub_proof_request(&sub_proof_request,
    ///                                      &credential_schema,
    ///                                      &non_credential_schema,
    ///                                      &credential_pub_key,
    ///                                      None,
    ///                                      None).unwrap();
    /// ```
    pub fn add_sub_proof_request(&mut self,
                                 sub_proof_request: &SubProofRequest,
                                 credential_schema: &CredentialSchema,
                                 non_credential_schema: &NonCredentialSchema,
                                 credential_pub_key: &CredentialPublicKey,
                                 rev_key_pub: Option<&RevocationKeyPublic>,
                                 rev_reg: Option<&RevocationRegistry>) -> Result<(), IndyCryptoError> {
        ProofVerifier::_check_add_sub_proof_request_params_consistency(sub_proof_request, credential_schema)?;

        self.credentials.push(VerifiableCredential {
            pub_key: credential_pub_key.clone()?,
            sub_proof_request: sub_proof_request.clone(),
            credential_schema: credential_schema.clone(),
            non_credential_schema: non_credential_schema.clone(),
            rev_key_pub: rev_key_pub.map(Clone::clone),
            rev_reg: rev_reg.map(Clone::clone)
        });
        Ok(())
    }

    /// Verifies proof.
    ///
    /// # Arguments
    /// * `proof_verifier` - Proof verifier.
    /// * `proof` - Proof generated by Prover.
    /// * `nonce` - Nonce.
    ///
    ///
    /// #Example
    /// ```
    /// use indy_crypto::cl::new_nonce;
    /// use indy_crypto::cl::issuer::Issuer;
    /// use indy_crypto::cl::prover::Prover;
    /// use indy_crypto::cl::verifier::Verifier;
    ///
    /// let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
    /// credential_schema_builder.add_attr("sex").unwrap();
    /// let credential_schema = credential_schema_builder.finalize().unwrap();
    ///
    /// let mut non_credential_schema_builder = Issuer::new_non_credential_schema_builder().unwrap();
    /// non_credential_schema_builder.add_attr("master_secret").unwrap();
    /// let non_credential_schema = non_credential_schema_builder.finalize().unwrap();
    ///
    /// let (credential_pub_key, credential_priv_key, cred_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, &non_credential_schema, false).unwrap();
    ///
    /// let master_secret = Prover::new_master_secret().unwrap();
    ///
    /// let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();
    /// credential_values_builder.add_value_hidden("master_secret", &master_secret.value().unwrap()).unwrap();
    /// credential_values_builder.add_dec_known("sex", "5944657099558967239210949258394887428692050081607692519917050011144233115103").unwrap();
    /// let credential_values = credential_values_builder.finalize().unwrap();
    ///
    /// let credential_nonce = new_nonce().unwrap();
    /// let (blinded_credential_secrets, credential_secrets_blinding_factors, blinded_credential_secrets_correctness_proof) =
    ///     Prover::blind_credential_secrets(&credential_pub_key, &cred_key_correctness_proof, &credential_values, &credential_nonce).unwrap();
    ///
    /// let credential_issuance_nonce = new_nonce().unwrap();
    ///
    /// let (mut credential_signature, signature_correctness_proof) =
    ///     Issuer::sign_credential("CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW",
    ///                             &blinded_credential_secrets,
    ///                             &blinded_credential_secrets_correctness_proof,
    ///                             &credential_nonce,
    ///                             &credential_issuance_nonce,
    ///                             &credential_values,
    ///                             &credential_pub_key,
    ///                             &credential_priv_key).unwrap();
    ///
    /// Prover::process_credential_signature(&mut credential_signature,
    ///                                      &credential_values,
    ///                                      &signature_correctness_proof,
    ///                                      &credential_secrets_blinding_factors,
    ///                                      &credential_pub_key,
    ///                                      &credential_issuance_nonce,
    ///                                      None, None, None).unwrap();
    ///
    /// let mut sub_proof_request_builder = Verifier::new_sub_proof_request_builder().unwrap();
    /// sub_proof_request_builder.add_revealed_attr("sex").unwrap();
    /// let sub_proof_request = sub_proof_request_builder.finalize().unwrap();
    ///
    /// let mut proof_builder = Prover::new_proof_builder().unwrap();
    /// proof_builder.add_common_attribute("master_secret").unwrap();
    /// proof_builder.add_sub_proof_request(&sub_proof_request,
    ///                                     &credential_schema,
    ///                                     &non_credential_schema,
    ///                                     &credential_signature,
    ///                                     &credential_values,
    ///                                     &credential_pub_key,
    ///                                     None,
    ///                                     None).unwrap();
    ///
    /// let proof_request_nonce = new_nonce().unwrap();
    /// let proof = proof_builder.finalize(&proof_request_nonce).unwrap();
    ///
    /// let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
    ///
    /// proof_verifier.add_sub_proof_request(&sub_proof_request,
    ///                                      &credential_schema,
    ///                                      &non_credential_schema,
    ///                                      &credential_pub_key,
    ///                                      None,
    ///                                      None).unwrap();
    /// assert!(proof_verifier.verify(&proof, &proof_request_nonce).unwrap());
    /// ```
    pub fn verify(&self,
                  proof: &Proof,
                  nonce: &Nonce) -> Result<bool, IndyCryptoError> {
        trace!("ProofVerifier::verify: >>> proof: {:?}, nonce: {:?}", proof, nonce);

        ProofVerifier::_check_verify_params_consistency(&self.credentials, proof)?;

        let mut tau_list: Vec<Vec<u8>> = Vec::new();

        assert_eq!(proof.proofs.len(), self.credentials.len()); //FIXME return error
        for idx in 0..proof.proofs.len() {
            let proof_item = &proof.proofs[idx];
            let credential = &self.credentials[idx];
            if let (Some(non_revocation_proof), Some(cred_rev_pub_key), Some(rev_reg), Some(rev_key_pub)) = (proof_item.non_revoc_proof.as_ref(),
                                                                                                             credential.pub_key.r_key.as_ref(),
                                                                                                             credential.rev_reg.as_ref(),
                                                                                                             credential.rev_key_pub.as_ref()) {
                tau_list.extend_from_slice(
                    &ProofVerifier::_verify_non_revocation_proof(&cred_rev_pub_key,
                                                                 &rev_reg,
                                                                 &rev_key_pub,
                                                                 &proof.aggregated_proof.c_hash,
                                                                 &non_revocation_proof)?.as_slice()?
                );
            };

            tau_list.append_vec(
                &ProofVerifier::_verify_primary_proof(&credential.pub_key.p_key,
                                                      &proof.aggregated_proof.c_hash,
                                                      &proof_item.primary_proof,
                                                      &credential.credential_schema,
                                                      &credential.non_credential_schema,
                                                      &credential.sub_proof_request)?
            )?;
        }

        let mut values: Vec<Vec<u8>> = Vec::new();
        values.extend_from_slice(&tau_list);
        values.extend_from_slice(&proof.aggregated_proof.c_list);
        values.push(nonce.to_bytes()?);

        let c_hver = get_hash_as_int(&values)?;

        info!(target: "anoncreds_service", "Verifier verify proof -> done");

        let valid = c_hver == proof.aggregated_proof.c_hash;

        trace!("ProofVerifier::verify: <<< valid: {:?}", valid);

        Ok(valid)
    }

    fn _check_add_sub_proof_request_params_consistency(sub_proof_request: &SubProofRequest,
                                                       cred_schema: &CredentialSchema) -> Result<(), IndyCryptoError> {
        trace!("ProofVerifier::_check_add_sub_proof_request_params_consistency: >>> sub_proof_request: {:?}, cred_schema: {:?}", sub_proof_request, cred_schema);

        if sub_proof_request.revealed_attrs.difference(&cred_schema.attrs).count() != 0 {
            return Err(IndyCryptoError::InvalidStructure(format!("Credential doesn't contain requested attribute")));
        }

        let predicates_attrs =
            sub_proof_request.predicates.iter()
                .map(|predicate| predicate.attr_name.clone())
                .collect::<BTreeSet<String>>();

        if predicates_attrs.difference(&cred_schema.attrs).count() != 0 {
            return Err(IndyCryptoError::InvalidStructure(format!("Credential doesn't contain attribute requested in predicate")));
        }

        trace!("ProofVerifier::_check_add_sub_proof_request_params_consistency: <<<");

        Ok(())
    }

    fn _check_verify_params_consistency(credentials: &Vec<VerifiableCredential>,
                                        proof: &Proof) -> Result<(), IndyCryptoError> {
        trace!("ProofVerifier::_check_verify_params_consistency: >>> credentials: {:?}, proof: {:?}", credentials, proof);

        assert_eq!(proof.proofs.len(), credentials.len()); //FIXME return error
        for idx in 0..proof.proofs.len() {
            let proof_for_credential = &proof.proofs[idx];
            let credential = &credentials[idx];

            let proof_revealed_attrs = BTreeSet::from_iter(proof_for_credential.primary_proof.eq_proof.revealed_attrs.keys().cloned());

            if proof_revealed_attrs != credential.sub_proof_request.revealed_attrs {
                return Err(IndyCryptoError::AnoncredsProofRejected(format!("Proof revealed attributes not correspond to requested attributes")));
            }

            let proof_predicates =
                proof_for_credential.primary_proof.ge_proofs.iter()
                    .map(|ge_proof| ge_proof.predicate.clone())
                    .collect::<BTreeSet<Predicate>>();

            if proof_predicates != credential.sub_proof_request.predicates {
                return Err(IndyCryptoError::AnoncredsProofRejected(format!("Proof predicates not correspond to requested predicates")));
            }
        }

        trace!("ProofVerifier::_check_verify_params_consistency: <<<");

        Ok(())
    }

    fn _verify_primary_proof(p_pub_key: &CredentialPrimaryPublicKey,
                             c_hash: &BigNumber,
                             primary_proof: &PrimaryProof,
                             cred_schema: &CredentialSchema,
                             non_cred_schema: &NonCredentialSchema,
                             sub_proof_request: &SubProofRequest) -> Result<Vec<BigNumber>, IndyCryptoError> {
        trace!("ProofVerifier::_verify_primary_proof: >>> p_pub_key: {:?}, c_hash: {:?}, primary_proof: {:?}, cred_schema: {:?}, sub_proof_request: {:?}",
               p_pub_key, c_hash, primary_proof, cred_schema, sub_proof_request);

        let mut t_hat: Vec<BigNumber> = ProofVerifier::_verify_equality(p_pub_key,
                                                                        &primary_proof.eq_proof,
                                                                        c_hash,
                                                                        cred_schema,
                                                                        non_cred_schema,
                                                                        sub_proof_request)?;

        for ge_proof in primary_proof.ge_proofs.iter() {
            t_hat.append(&mut ProofVerifier::_verify_ge_predicate(p_pub_key, ge_proof, c_hash)?)
        }

        trace!("ProofVerifier::_verify_primary_proof: <<< t_hat: {:?}", t_hat);

        Ok(t_hat)
    }

    fn _verify_equality(p_pub_key: &CredentialPrimaryPublicKey,
                        proof: &PrimaryEqualProof,
                        c_hash: &BigNumber,
                        cred_schema: &CredentialSchema,
                        non_cred_schema: &NonCredentialSchema,
                        sub_proof_request: &SubProofRequest) -> Result<Vec<BigNumber>, IndyCryptoError> {
        trace!("ProofVerifier::_verify_equality: >>> p_pub_key: {:?}, proof: {:?}, c_hash: {:?}, cred_schema: {:?}, sub_proof_request: {:?}",
               p_pub_key, proof, c_hash, cred_schema, sub_proof_request);


        let unrevealed_attrs = cred_schema
            .attrs
            .union(&non_cred_schema.attrs)
            .cloned()
            .collect::<BTreeSet<String>>()
            .difference(&sub_proof_request.revealed_attrs)
            .cloned()
            .collect::<BTreeSet<String>>();

        let t1: BigNumber = calc_teq(&p_pub_key, &proof.a_prime, &proof.e, &proof.v, &proof.m, &proof.m2, &unrevealed_attrs)?;

        let mut ctx = BigNumber::new_context()?;

        let mut rar = proof.a_prime.mod_exp(&LARGE_E_START_VALUE, &p_pub_key.n, Some(&mut ctx))?;

        for (attr, encoded_value) in &proof.revealed_attrs {
            let cur_r = p_pub_key.r.get(attr)
                .ok_or(IndyCryptoError::AnoncredsProofRejected(format!("Value by key '{}' not found in pk.r", attr)))?;

            rar = cur_r
                .mod_exp(encoded_value, &p_pub_key.n, Some(&mut ctx))?
                .mod_mul(&rar, &p_pub_key.n, Some(&mut ctx))?;
        }

        let t2: BigNumber = p_pub_key.z
            .mod_div(&rar, &p_pub_key.n, Some(&mut ctx))?
            .inverse(&p_pub_key.n, Some(&mut ctx))?
            .mod_exp(&c_hash, &p_pub_key.n, Some(&mut ctx))?;

        let t: BigNumber = t1.mod_mul(&t2, &p_pub_key.n, Some(&mut ctx))?;

        trace!("ProofVerifier::_verify_equality: <<< t: {:?}", t);

        Ok(vec![t])
    }

    fn _verify_ge_predicate(p_pub_key: &CredentialPrimaryPublicKey,
                            proof: &PrimaryPredicateGEProof,
                            c_hash: &BigNumber) -> Result<Vec<BigNumber>, IndyCryptoError> {
        trace!("ProofVerifier::_verify_ge_predicate: >>> p_pub_key: {:?}, proof: {:?}, c_hash: {:?}", p_pub_key, proof, c_hash);

        let mut ctx = BigNumber::new_context()?;
        let mut tau_list = calc_tge(&p_pub_key, &proof.u, &proof.r, &proof.mj,
                                    &proof.alpha, &proof.t)?;

        for i in 0..ITERATION {
            let cur_t = proof.t.get(&i.to_string())
                .ok_or(IndyCryptoError::AnoncredsProofRejected(format!("Value by key '{}' not found in proof.t", i)))?;

            tau_list[i] = cur_t
                .mod_exp(&c_hash, &p_pub_key.n, Some(&mut ctx))?
                .inverse(&p_pub_key.n, Some(&mut ctx))?
                .mod_mul(&tau_list[i], &p_pub_key.n, Some(&mut ctx))?;
        }

        let delta = proof.t.get("DELTA")
            .ok_or(IndyCryptoError::AnoncredsProofRejected(format!("Value by key '{}' not found in proof.t", "DELTA")))?;

        tau_list[ITERATION] = p_pub_key.z
            .mod_exp(&BigNumber::from_dec(&proof.predicate.value.to_string())?,
                &p_pub_key.n, Some(&mut ctx))?
            .mul(&delta, Some(&mut ctx))?
            .mod_exp(&c_hash, &p_pub_key.n, Some(&mut ctx))?
            .inverse(&p_pub_key.n, Some(&mut ctx))?
            .mod_mul(&tau_list[ITERATION], &p_pub_key.n, Some(&mut ctx))?;

        tau_list[ITERATION + 1] = delta
            .mod_exp(&c_hash, &p_pub_key.n, Some(&mut ctx))?
            .inverse(&p_pub_key.n, Some(&mut ctx))?
            .mod_mul(&tau_list[ITERATION + 1], &p_pub_key.n, Some(&mut ctx))?;

        trace!("ProofVerifier::_verify_ge_predicate: <<< tau_list: {:?},", tau_list);

        Ok(tau_list)
    }

    fn _verify_non_revocation_proof(r_pub_key: &CredentialRevocationPublicKey,
                                    rev_reg: &RevocationRegistry,
                                    rev_key_pub: &RevocationKeyPublic,
                                    c_hash: &BigNumber, proof: &NonRevocProof) -> Result<NonRevocProofTauList, IndyCryptoError> {
        trace!("ProofVerifier::_verify_non_revocation_proof: >>> r_pub_key: {:?}, rev_reg: {:?}, rev_key_pub: {:?}, c_hash: {:?}",
               r_pub_key, rev_reg, rev_key_pub, c_hash);

        let ch_num_z = bignum_to_group_element(&c_hash)?;

        let t_hat_expected_values = create_tau_list_expected_values(r_pub_key, rev_reg, rev_key_pub, &proof.c_list)?;
        let t_hat_calc_values = create_tau_list_values(&r_pub_key, rev_reg, &proof.x_list, &proof.c_list)?;


        let non_revoc_proof_tau_list = Ok(NonRevocProofTauList {
            t1: t_hat_expected_values.t1.mul(&ch_num_z)?.add(&t_hat_calc_values.t1)?,
            t2: t_hat_expected_values.t2.mul(&ch_num_z)?.add(&t_hat_calc_values.t2)?,
            t3: t_hat_expected_values.t3.pow(&ch_num_z)?.mul(&t_hat_calc_values.t3)?,
            t4: t_hat_expected_values.t4.pow(&ch_num_z)?.mul(&t_hat_calc_values.t4)?,
            t5: t_hat_expected_values.t5.mul(&ch_num_z)?.add(&t_hat_calc_values.t5)?,
            t6: t_hat_expected_values.t6.mul(&ch_num_z)?.add(&t_hat_calc_values.t6)?,
            t7: t_hat_expected_values.t7.pow(&ch_num_z)?.mul(&t_hat_calc_values.t7)?,
            t8: t_hat_expected_values.t8.pow(&ch_num_z)?.mul(&t_hat_calc_values.t8)?
        });

        trace!("ProofVerifier::_verify_non_revocation_proof: <<< non_revoc_proof_tau_list: {:?}", non_revoc_proof_tau_list);

        non_revoc_proof_tau_list
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cl::prover;
    use cl::issuer;
    use cl::helpers::MockHelper;
    use cl::prover::mocks::*;

    #[test]
    fn sub_proof_request_builder_works() {
        let mut sub_proof_request_builder = Verifier::new_sub_proof_request_builder().unwrap();
        sub_proof_request_builder.add_revealed_attr("name").unwrap();
        sub_proof_request_builder.add_predicate("age", "GE", 18).unwrap();
        let sub_proof_request = sub_proof_request_builder.finalize().unwrap();

        assert!(sub_proof_request.revealed_attrs.contains("name"));
        assert!(sub_proof_request.predicates.contains(&predicate()));
    }

    #[test]
    fn verify_equality_works() {
        MockHelper::inject();

        let proof = prover::mocks::eq_proof();
        let pk = issuer::mocks::credential_primary_public_key();
        let c_h = prover::mocks::aggregated_proof().c_hash;
        let credential_schema = issuer::mocks::credential_schema();
        let non_credential_schema = issuer::mocks::non_credential_schema();

        let mut sub_proof_request_builder = SubProofRequestBuilder::new().unwrap();
        sub_proof_request_builder.add_revealed_attr("name").unwrap();
        let sub_proof_request = sub_proof_request_builder.finalize().unwrap();

        let res: Vec<BigNumber> = ProofVerifier::_verify_equality(&pk,
                                                                  &proof,
                                                                  &c_h,
                                                                  &credential_schema,
                                                                  &non_credential_schema,
                                                                  &sub_proof_request).unwrap();

        assert_eq!("10033055650650536307076535582106563131022201440643374305953651825727599954819318\
        32776539357457020109333992502903750221996474184246600192046150335243527737793180535397491251\
        36486792690681259916650903863021550308696974134411562524591774050899062767720649066796739436\
        27397581927453211752118291877772829029684359327455206466243000746391720320628738675493563637\
        17662893668647677165235667497714749188075836722966424443613777009272647747723101033371964746\
        21326803520855024350671435451377509133601181643692585768497035223029241717837378002182177772\
        013841825604270144085274570353058542150547852185340515159203077602883003894263", res[0].to_dec().unwrap());
    }

    #[test]
    fn _verify_ge_predicate_works() {
        MockHelper::inject();

        let proof = prover::mocks::ge_proof();
        let c_h = prover::mocks::aggregated_proof().c_hash;
        let pk = issuer::mocks::credential_primary_public_key();

        let res = ProofVerifier::_verify_ge_predicate(&pk, &proof, &c_h);

        assert!(res.is_ok());
        let res_data = res.unwrap();

        assert_eq!("57751218046505338238183461098782003080847816859886891270686297843457149187073649\
        65739960046309281573960723093575143691445129397777229699708529613711858683818596049039395895\
        39797919600616625080942329992481472431273688702788653832923648058758544471562009139715503579\
        65609577313787385466121242592254993651305714763959156321689291354027457176111007193732131841\
        56349557204064052101034800892299754720256826852528224133723052224077506099451460290719285594\
        53434613132035686231462430742314752340558131808055248092500204392980253966449115099031064384\
        4782277058104451329443287733260065635985062237748146923600356379728377136117", res_data[0].to_dec().unwrap());

        assert_eq!("57751218046505338238183461098782003080847816859886891270686297843457149187073649\
        65739960046309281573960723093575143691445129397777229699708529613711858683818596049039395895\
        39797919600616625080942329992481472431273688702788653832923648058758544471562009139715503579\
        65609577313787385466121242592254993651305714763959156321689291354027457176111007193732131841\
        56349557204064052101034800892299754720256826852528224133723052224077506099451460290719285594\
        53434613132035686231462430742314752340558131808055248092500204392980253966449115099031064384\
        4782277058104451329443287733260065635985062237748146923600356379728377136117", res_data[4].to_dec().unwrap());

        assert_eq!("39043573194062843188289697546611918107532805117598645832449214642534318612913845\
        32075367968952105925575138233724002452864405925664204730713059864148595067740603328250882518\
        11954314026835752054692082938808344114109325017520232439627822778481078256743741189055686491\
        40719993402086278461408304318382071709512982618346808542261941396861110469854677713167733150\
        19589667632703174158767949929708057309502598155913756881855400228180120266833516847035270313\
        63797835534388275004037081643711680763785295550040017849212848303155001351017276181699668707\
        61712270273123073354380462035137352013253457506110569108524475928798373175939", res_data[5].to_dec().unwrap());
    }
}
