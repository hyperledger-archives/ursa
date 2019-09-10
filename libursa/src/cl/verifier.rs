use bn::BigNumber;
use cl::constants::{ITERATION, LARGE_E_START_VALUE};
use cl::hash::get_hash_as_int;
use cl::helpers::*;
use cl::*;
use errors::prelude::*;

use std::collections::hash_map::Entry;
use std::collections::{BTreeSet, HashMap};
use std::iter::FromIterator;

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
    /// use ursa::cl::verifier::Verifier;
    ///
    /// let mut sub_proof_request_builder = Verifier::new_sub_proof_request_builder().unwrap();
    /// sub_proof_request_builder.add_revealed_attr("name").unwrap();
    /// sub_proof_request_builder.add_predicate("age", "GE", 18).unwrap();
    /// let _sub_proof_request = sub_proof_request_builder.finalize().unwrap();
    /// ```
    pub fn new_sub_proof_request_builder() -> UrsaCryptoResult<SubProofRequestBuilder> {
        let res = SubProofRequestBuilder::new()?;
        Ok(res)
    }

    /// Creates and returns proof verifier.
    ///
    /// The purpose of `proof verifier` is check proof provided by Prover.
    ///
    /// # Example
    /// ```
    /// use ursa::cl::verifier::Verifier;
    ///
    /// let _proof_verifier = Verifier::new_proof_verifier().unwrap();
    /// ```
    pub fn new_proof_verifier() -> UrsaCryptoResult<ProofVerifier> {
        Ok(ProofVerifier {
            credentials: Vec::new(),
            common_attributes: HashMap::new(),
        })
    }
}

#[derive(Debug)]
pub struct ProofVerifier {
    credentials: Vec<VerifiableCredential>,
    common_attributes: HashMap<String, Option<BigNumber>>,
}

impl ProofVerifier {
    /// Attributes that are supposed to have same value across all subproofs.
    /// The verifier first enters attribute names in the hashmap before proof verification starts.
    /// The hashmap is again updated during verification of sub proofs by the blinded value of attributes (`m_hat`s in paper)
    pub fn add_common_attribute(&mut self, attr_name: &str) -> UrsaCryptoResult<()> {
        self.common_attributes.insert(attr_name.to_owned(), None);
        Ok(())
    }

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
    /// use ursa::cl::issuer::Issuer;
    /// use ursa::cl::verifier::Verifier;
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
    pub fn add_sub_proof_request(
        &mut self,
        sub_proof_request: &SubProofRequest,
        credential_schema: &CredentialSchema,
        non_credential_schema: &NonCredentialSchema,
        credential_pub_key: &CredentialPublicKey,
        rev_key_pub: Option<&RevocationKeyPublic>,
        rev_reg: Option<&RevocationRegistry>,
    ) -> UrsaCryptoResult<()> {
        ProofVerifier::_check_add_sub_proof_request_params_consistency(
            sub_proof_request,
            credential_schema,
        )?;

        self.credentials.push(VerifiableCredential {
            pub_key: credential_pub_key.try_clone()?,
            sub_proof_request: sub_proof_request.clone(),
            credential_schema: credential_schema.clone(),
            non_credential_schema: non_credential_schema.clone(),
            rev_key_pub: rev_key_pub.map(Clone::clone),
            rev_reg: rev_reg.map(Clone::clone),
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
    /// use ursa::cl::new_nonce;
    /// use ursa::cl::issuer::Issuer;
    /// use ursa::cl::prover::Prover;
    /// use ursa::cl::verifier::Verifier;
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
    pub fn verify(&mut self, proof: &Proof, nonce: &Nonce) -> UrsaCryptoResult<bool> {
        trace!(
            "ProofVerifier::verify: >>> proof: {:?}, nonce: {:?}",
            proof,
            nonce
        );

        ProofVerifier::_check_verify_params_consistency(&self.credentials, proof)?;

        let mut tau_list: Vec<Vec<u8>> = Vec::new();

        for idx in 0..proof.proofs.len() {
            let proof_item = &proof.proofs[idx];
            let credential = &self.credentials[idx];
            if let (
                Some(non_revocation_proof),
                Some(cred_rev_pub_key),
                Some(rev_reg),
                Some(rev_key_pub),
            ) = (
                proof_item.non_revoc_proof.as_ref(),
                credential.pub_key.r_key.as_ref(),
                credential.rev_reg.as_ref(),
                credential.rev_key_pub.as_ref(),
            ) {
                tau_list.extend_from_slice(
                    &ProofVerifier::_verify_non_revocation_proof(
                        &cred_rev_pub_key,
                        &rev_reg,
                        &rev_key_pub,
                        &proof.aggregated_proof.c_hash,
                        &non_revocation_proof,
                    )?
                    .as_slice()?,
                );
            };

            // Check that `m_hat`s of all common attributes are same. Also `m_hat` for each common attribute must be present in each sub proof
            let attr_names: Vec<String> = self
                .common_attributes
                .keys()
                .map(|s| s.to_string())
                .collect();
            for attr_name in attr_names {
                if proof_item.primary_proof.eq_proof.m.contains_key(&attr_name) {
                    let m_hat = &proof_item.primary_proof.eq_proof.m[&attr_name];
                    match self.common_attributes.entry(attr_name.clone()) {
                        Entry::Occupied(mut entry) => {
                            let x = entry.get_mut();
                            match x {
                                Some(v) => {
                                    if v != m_hat {
                                        return Err(err_msg(
                                            UrsaCryptoErrorKind::ProofRejected,
                                            format!("Blinded value for common attribute '{}' different across sub proofs", attr_name),
                                        ));
                                    }
                                }
                                // For first subproof
                                None => {
                                    *x = Some(m_hat.try_clone()?);
                                }
                            }
                        }
                        // Vacant is not possible because `attr_names` is constructed from keys of `self.common_attributes`
                        Entry::Vacant(_) => (),
                    }
                } else {
                    // `m_hat` for common attribute not present in sub proof
                    return Err(err_msg(
                        UrsaCryptoErrorKind::ProofRejected,
                        format!(
                            "Blinded value for common attribute '{}' not found in proof.m",
                            attr_name
                        ),
                    ));
                }
            }
            tau_list.append_vec(&ProofVerifier::_verify_primary_proof(
                &credential.pub_key.p_key,
                &proof.aggregated_proof.c_hash,
                &proof_item.primary_proof,
                &credential.credential_schema,
                &credential.non_credential_schema,
                &credential.sub_proof_request,
            )?)?;
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

    fn _check_add_sub_proof_request_params_consistency(
        sub_proof_request: &SubProofRequest,
        cred_schema: &CredentialSchema,
    ) -> UrsaCryptoResult<()> {
        trace!("ProofVerifier::_check_add_sub_proof_request_params_consistency: >>> sub_proof_request: {:?}, cred_schema: {:?}", sub_proof_request, cred_schema);

        if sub_proof_request
            .revealed_attrs
            .difference(&cred_schema.attrs)
            .count()
            != 0
        {
            return Err(err_msg(
                UrsaCryptoErrorKind::InvalidStructure,
                "Credential doesn't contain requested attribute",
            ));
        }

        let predicates_attrs = sub_proof_request
            .predicates
            .iter()
            .map(|predicate| predicate.attr_name.clone())
            .collect::<BTreeSet<String>>();

        if predicates_attrs.difference(&cred_schema.attrs).count() != 0 {
            return Err(err_msg(
                UrsaCryptoErrorKind::InvalidStructure,
                "Credential doesn't contain attribute requested in predicate",
            ));
        }

        trace!("ProofVerifier::_check_add_sub_proof_request_params_consistency: <<<");

        Ok(())
    }

    fn _check_verify_params_consistency(
        credentials: &[VerifiableCredential],
        proof: &Proof,
    ) -> UrsaCryptoResult<()> {
        trace!(
            "ProofVerifier::_check_verify_params_consistency: >>> credentials: {:?}, proof: {:?}",
            credentials,
            proof
        );

        if proof.proofs.len() != credentials.len() {
            return Err(err_msg(
                UrsaCryptoErrorKind::ProofRejected,
                "Invalid proof length".to_string(),
            ));
        }

        for (proof_for_credential, credential) in proof.proofs.iter().zip(credentials) {
            let proof_revealed_attrs = BTreeSet::from_iter(
                proof_for_credential
                    .primary_proof
                    .eq_proof
                    .revealed_attrs
                    .keys()
                    .cloned(),
            );

            if proof_revealed_attrs != credential.sub_proof_request.revealed_attrs {
                return Err(err_msg(
                    UrsaCryptoErrorKind::ProofRejected,
                    "Proof revealed attributes not correspond to requested attributes",
                ));
            }

            let proof_predicates = proof_for_credential
                .primary_proof
                .ne_proofs
                .iter()
                .map(|ne_proof| ne_proof.predicate.clone())
                .collect::<BTreeSet<Predicate>>();

            if proof_predicates != credential.sub_proof_request.predicates {
                return Err(err_msg(
                    UrsaCryptoErrorKind::ProofRejected,
                    "Proof predicates not correspond to requested predicates",
                ));
            }
        }

        trace!("ProofVerifier::_check_verify_params_consistency: <<<");

        Ok(())
    }

    fn _verify_primary_proof(
        p_pub_key: &CredentialPrimaryPublicKey,
        c_hash: &BigNumber,
        primary_proof: &PrimaryProof,
        cred_schema: &CredentialSchema,
        non_cred_schema: &NonCredentialSchema,
        sub_proof_request: &SubProofRequest,
    ) -> UrsaCryptoResult<Vec<BigNumber>> {
        trace!("ProofVerifier::_verify_primary_proof: >>> p_pub_key: {:?}, c_hash: {:?}, primary_proof: {:?}, cred_schema: {:?}, sub_proof_request: {:?}",
               p_pub_key, c_hash, primary_proof, cred_schema, sub_proof_request);

        let mut t_hat: Vec<BigNumber> = ProofVerifier::_verify_equality(
            p_pub_key,
            &primary_proof.eq_proof,
            c_hash,
            cred_schema,
            non_cred_schema,
            sub_proof_request,
        )?;

        for ne_proof in primary_proof.ne_proofs.iter() {
            t_hat.append(&mut ProofVerifier::_verify_ne_predicate(
                p_pub_key, ne_proof, c_hash,
            )?)
        }

        trace!(
            "ProofVerifier::_verify_primary_proof: <<< t_hat: {:?}",
            t_hat
        );

        Ok(t_hat)
    }

    fn _verify_equality(
        p_pub_key: &CredentialPrimaryPublicKey,
        proof: &PrimaryEqualProof,
        c_hash: &BigNumber,
        cred_schema: &CredentialSchema,
        non_cred_schema: &NonCredentialSchema,
        sub_proof_request: &SubProofRequest,
    ) -> UrsaCryptoResult<Vec<BigNumber>> {
        trace!("ProofVerifier::_verify_equality: >>> p_pub_key: {:?}, proof: {:?}, c_hash: {:?}, cred_schema: {:?}, sub_proof_request: {:?}",
               p_pub_key, proof, c_hash, cred_schema, sub_proof_request);

        let unrevealed_attrs = cred_schema
            .attrs
            .union(&non_cred_schema.attrs)
            .cloned()
            .collect::<BTreeSet<String>>()
            .difference(&sub_proof_request.revealed_attrs)
            .cloned()
            .collect::<HashSet<String>>();

        let t1: BigNumber = calc_teq(
            &p_pub_key,
            &proof.a_prime,
            &proof.e,
            &proof.v,
            &proof.m,
            &proof.m2,
            &unrevealed_attrs,
        )?;

        let mut ctx = BigNumber::new_context()?;

        let mut rar = proof
            .a_prime
            .mod_exp(&LARGE_E_START_VALUE, &p_pub_key.n, Some(&mut ctx))?;

        for (attr, encoded_value) in &proof.revealed_attrs {
            let cur_r = p_pub_key.r.get(attr).ok_or_else(|| {
                err_msg(
                    UrsaCryptoErrorKind::ProofRejected,
                    format!("Value by key '{}' not found in pk.r", attr),
                )
            })?;

            rar = cur_r
                .mod_exp(encoded_value, &p_pub_key.n, Some(&mut ctx))?
                .mod_mul(&rar, &p_pub_key.n, Some(&mut ctx))?;
        }

        let t2: BigNumber = p_pub_key
            .z
            .mod_div(&rar, &p_pub_key.n, Some(&mut ctx))?
            .inverse(&p_pub_key.n, Some(&mut ctx))?
            .mod_exp(&c_hash, &p_pub_key.n, Some(&mut ctx))?;

        let t: BigNumber = t1.mod_mul(&t2, &p_pub_key.n, Some(&mut ctx))?;

        trace!("ProofVerifier::_verify_equality: <<< t: {:?}", t);

        Ok(vec![t])
    }

    fn _verify_ne_predicate(
        p_pub_key: &CredentialPrimaryPublicKey,
        proof: &PrimaryPredicateInequalityProof,
        c_hash: &BigNumber,
    ) -> UrsaCryptoResult<Vec<BigNumber>> {
        trace!(
            "ProofVerifier::_verify_ne_predicate: >>> p_pub_key: {:?}, proof: {:?}, c_hash: {:?}",
            p_pub_key,
            proof,
            c_hash
        );

        let mut ctx = BigNumber::new_context()?;
        let mut tau_list = calc_tne(
            &p_pub_key,
            &proof.u,
            &proof.r,
            &proof.mj,
            &proof.alpha,
            &proof.t,
            proof.predicate.is_less(),
        )?;

        for i in 0..ITERATION {
            let cur_t = proof.t.get(&i.to_string()).ok_or_else(|| {
                err_msg(
                    UrsaCryptoErrorKind::ProofRejected,
                    format!("Value by key '{}' not found in proof.t", i),
                )
            })?;

            tau_list[i] = cur_t
                .mod_exp(&c_hash, &p_pub_key.n, Some(&mut ctx))?
                .inverse(&p_pub_key.n, Some(&mut ctx))?
                .mod_mul(&tau_list[i], &p_pub_key.n, Some(&mut ctx))?;
        }

        let delta = proof.t.get("DELTA").ok_or_else(|| {
            err_msg(
                UrsaCryptoErrorKind::ProofRejected,
                format!("Value by key '{}' not found in proof.t", "DELTA"),
            )
        })?;

        let delta_prime = if proof.predicate.is_less() {
            delta.inverse(&p_pub_key.n, Some(&mut ctx))?
        } else {
            delta.try_clone()?
        };

        tau_list[ITERATION] = p_pub_key
            .z
            .mod_exp(
                &proof.predicate.get_delta_prime()?,
                &p_pub_key.n,
                Some(&mut ctx),
            )?
            .mul(&delta_prime, Some(&mut ctx))?
            .mod_exp(&c_hash, &p_pub_key.n, Some(&mut ctx))?
            .inverse(&p_pub_key.n, Some(&mut ctx))?
            .mod_mul(&tau_list[ITERATION], &p_pub_key.n, Some(&mut ctx))?;

        tau_list[ITERATION + 1] = delta
            .mod_exp(&c_hash, &p_pub_key.n, Some(&mut ctx))?
            .inverse(&p_pub_key.n, Some(&mut ctx))?
            .mod_mul(&tau_list[ITERATION + 1], &p_pub_key.n, Some(&mut ctx))?;

        trace!(
            "ProofVerifier::_verify_ne_predicate: <<< tau_list: {:?},",
            tau_list
        );

        Ok(tau_list)
    }

    fn _verify_non_revocation_proof(
        r_pub_key: &CredentialRevocationPublicKey,
        rev_reg: &RevocationRegistry,
        rev_key_pub: &RevocationKeyPublic,
        c_hash: &BigNumber,
        proof: &NonRevocProof,
    ) -> UrsaCryptoResult<NonRevocProofTauList> {
        trace!("ProofVerifier::_verify_non_revocation_proof: >>> r_pub_key: {:?}, rev_reg: {:?}, rev_key_pub: {:?}, c_hash: {:?}",
               r_pub_key, rev_reg, rev_key_pub, c_hash);

        let ch_num_z = bignum_to_group_element(&c_hash)?;

        let t_hat_expected_values =
            create_tau_list_expected_values(r_pub_key, rev_reg, rev_key_pub, &proof.c_list)?;
        let t_hat_calc_values =
            create_tau_list_values(&r_pub_key, rev_reg, &proof.x_list, &proof.c_list)?;

        let non_revoc_proof_tau_list = Ok(NonRevocProofTauList {
            t1: t_hat_expected_values
                .t1
                .mul(&ch_num_z)?
                .add(&t_hat_calc_values.t1)?,
            t2: t_hat_expected_values
                .t2
                .mul(&ch_num_z)?
                .add(&t_hat_calc_values.t2)?,
            t3: t_hat_expected_values
                .t3
                .pow(&ch_num_z)?
                .mul(&t_hat_calc_values.t3)?,
            t4: t_hat_expected_values
                .t4
                .pow(&ch_num_z)?
                .mul(&t_hat_calc_values.t4)?,
            t5: t_hat_expected_values
                .t5
                .mul(&ch_num_z)?
                .add(&t_hat_calc_values.t5)?,
            t6: t_hat_expected_values
                .t6
                .mul(&ch_num_z)?
                .add(&t_hat_calc_values.t6)?,
            t7: t_hat_expected_values
                .t7
                .pow(&ch_num_z)?
                .mul(&t_hat_calc_values.t7)?,
            t8: t_hat_expected_values
                .t8
                .pow(&ch_num_z)?
                .mul(&t_hat_calc_values.t8)?,
        });

        trace!(
            "ProofVerifier::_verify_non_revocation_proof: <<< non_revoc_proof_tau_list: {:?}",
            non_revoc_proof_tau_list
        );

        non_revoc_proof_tau_list
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cl::helpers::MockHelper;
    use cl::issuer;
    use cl::prover;
    use cl::prover::mocks::*;

    #[test]
    fn sub_proof_request_builder_works() {
        let mut sub_proof_request_builder = Verifier::new_sub_proof_request_builder().unwrap();
        sub_proof_request_builder.add_revealed_attr("name").unwrap();
        sub_proof_request_builder
            .add_predicate("age", "GE", 18)
            .unwrap();
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

        let res: Vec<BigNumber> = ProofVerifier::_verify_equality(
            &pk,
            &proof,
            &c_h,
            &credential_schema,
            &non_credential_schema,
            &sub_proof_request,
        )
        .unwrap();

        assert_eq!("10403187904873314760355557832761590691431383521745031865309573910963034393207684\
        41047372720051528347747837647360259125725910627967862485202935551931564829193622679374932738\
        38474536597850351434049013891806846939373481702013509894344027659392557687896251802916259781\
        84555673228742169810564578048461551461925810052930346018787363753466820600660809185539201223\
        71561407375323615559370420617674817058682033406887804922024342182995444044012636448897449995\
        96623718830501291018016504024850859488898905605533676936340030965601041522317339491952524844\
        02507347769428679283112853202405399796966635008669186194259851326316679551259", res[0].to_dec().unwrap());
    }

    #[test]
    fn _verify_ne_predicate_works() {
        MockHelper::inject();

        let proof = prover::mocks::ne_proof();
        let c_h = prover::mocks::aggregated_proof().c_hash;
        let pk = issuer::mocks::credential_primary_public_key();

        let res = ProofVerifier::_verify_ne_predicate(&pk, &proof, &c_h);

        assert!(res.is_ok());
        let res_data = res.unwrap();

        assert_eq!("84541983257221862363846490076513159323178083291858042421207690118109227097470776\
        29156584847233795772635909150135300090254032895037949890518860393886507672431721432085454991\
        53093207263594616249619617338381693555232209880961750666056680810026822527599168269456730020\
        01231825064670095844788135102734720995698848664953286323041296412437988472201525915887801570\
        70103470323302606738147041031249783093273756323937754190996658020897337906239502331775611703\
        28042970307095658890209337238786401127759306357959942690001365403300148843097814151882478353\
        39418932462384016593481929101948092657508460688911105398322543841514412679282", res_data[0].to_dec().unwrap());

        assert_eq!("84541983257221862363846490076513159323178083291858042421207690118109227097470776\
        29156584847233795772635909150135300090254032895037949890518860393886507672431721432085454991\
        53093207263594616249619617338381693555232209880961750666056680810026822527599168269456730020\
        01231825064670095844788135102734720995698848664953286323041296412437988472201525915887801570\
        70103470323302606738147041031249783093273756323937754190996658020897337906239502331775611703\
        28042970307095658890209337238786401127759306357959942690001365403300148843097814151882478353\
        39418932462384016593481929101948092657508460688911105398322543841514412679282", res_data[4].to_dec().unwrap());

        assert_eq!("71576740094469616050175125038612941221466947853166771156257978699698137573095744\
        20081189100581220746619329202518959516574932458476055705176224361367551303754232635252988973\
        23789904575729089031680343784068658206913548928748946934732765157510452464211110112604384315\
        16865750528792129415255282372242857723274819466930397323134722222564785435619193280367926994\
        59191029832881324878202293930994818463297709055310139101500199217390179488337854210925404890\
        00403016403129020563799240705009712476150627783447048219852434435047969447195784507059403459\
        40533745092900800249667587825786217899894277583562804465078452786585349967293", res_data[5].to_dec().unwrap());
    }
}
