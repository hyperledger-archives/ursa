use bn::BigNumber;
use cl::*;
use cl::constants::*;
use errors::IndyCryptoError;
use pair::*;
use super::helpers::*;
use utils::commitment::get_pedersen_commitment;
use utils::get_hash_as_int;

use std::collections::{BTreeMap, BTreeSet};
use std::iter::FromIterator;

/// Credentials owner that can proof and partially disclose the credentials to verifier.
pub struct Prover {}

impl Prover {
    /// Creates a master secret.
    ///
    /// # Example
    /// ```
    /// use indy_crypto::cl::prover::Prover;
    ///
    /// let _master_secret = Prover::new_master_secret().unwrap();
    /// ```
    pub fn new_master_secret() -> Result<MasterSecret, IndyCryptoError> {
        Ok(MasterSecret { ms: bn_rand(LARGE_MASTER_SECRET)? })
    }

    /// Creates blinded master secret for given issuer key and master secret.
    ///
    /// # Arguments
    /// * `credential_pub_key` - Credential public keys.
    /// * `credential_key_correctness_proof` - Credential key correctness proof.
    /// * `credential_values` - Credential values.
    /// * `credential_nonce` - Nonce used for creation of blinded_credential_secrets_correctness_proof.
    ///
    /// # Example
    /// ```
    /// use indy_crypto::cl::new_nonce;
    /// use indy_crypto::cl::issuer::Issuer;
    /// use indy_crypto::cl::prover::Prover;
    ///
    /// let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
    /// credential_schema_builder.add_attr("sex").unwrap();
    /// let credential_schema = credential_schema_builder.finalize().unwrap();
    ///
    /// let mut non_credential_schema_builder = Issuer::new_non_credential_schema_builder().unwrap();
    /// non_credential_schema_builder.add_attr("master_secret").unwrap();
    /// let non_credential_schema_elements = non_credential_schema_builder.finalize().unwrap();
    ///
    /// let (credential_pub_key, _credential_priv_key, cred_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, &non_credential_schema_elements, false).unwrap();
    ///
    /// let master_secret = Prover::new_master_secret().unwrap();
    /// let credential_nonce = new_nonce().unwrap();
    ///
    /// let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();
    /// credential_values_builder.add_value_hidden("master_secret", &master_secret.value().unwrap()).unwrap();
    /// let cred_values = credential_values_builder.finalize().unwrap();
    ///
    /// let (_blinded_credential_secrets, _credential_secrets_blinding_factors, _blinded_credential_secrets_correctness_proof) =
    ///     Prover::blind_credential_secrets(&credential_pub_key,
    ///                                 &cred_key_correctness_proof,
    ///                                 &cred_values,
    ///                                 &credential_nonce).unwrap();
    /// ```
    pub fn blind_credential_secrets(credential_pub_key: &CredentialPublicKey,
                               credential_key_correctness_proof: &CredentialKeyCorrectnessProof,
                               credential_values: &CredentialValues,
                               credential_nonce: &Nonce) -> Result<(BlindedCredentialSecrets,
                                                                    CredentialSecretsBlindingFactors,
                                                                    BlindedCredentialSecretsCorrectnessProof), IndyCryptoError> {
            trace!("Prover::blind_credential_secrets: >>> credential_pub_key: {:?}, \
                                                      credential_key_correctness_proof: {:?}, \
                                                      credential_values: {:?}, \
                                                      credential_nonce: {:?}",
            credential_pub_key,
            credential_key_correctness_proof,
            credential_values,
            credential_nonce
        );
        Prover::_check_credential_key_correctness_proof(&credential_pub_key.p_key, credential_key_correctness_proof)?;

        let blinded_primary_credential_secrets =
            Prover::_generate_blinded_primary_credential_secrets_factors(&credential_pub_key.p_key, &credential_values)?;

        let blinded_revocation_credential_secrets = match credential_pub_key.r_key {
            Some(ref r_pk) => Some(Prover::_generate_blinded_revocation_credential_secrets(r_pk)?),
            _ => None
        };

        let blinded_credential_secrets_correctness_proof =
            Prover::_new_blinded_credential_secrets_correctness_proof(&credential_pub_key.p_key,
                                                                 &blinded_primary_credential_secrets,
                                                                 &credential_nonce,
                                                                 &credential_values)?;

        let blinded_credential_secrets = BlindedCredentialSecrets {
            u: blinded_primary_credential_secrets.u,
            ur: blinded_revocation_credential_secrets.as_ref().map(|d| d.ur),
            hidden_attributes: blinded_primary_credential_secrets.hidden_attributes,
            committed_attributes: blinded_primary_credential_secrets.committed_attributes,
        };

        let credential_secrets_blinding_factors = CredentialSecretsBlindingFactors {
            v_prime: blinded_primary_credential_secrets.v_prime,
            vr_prime: blinded_revocation_credential_secrets.map(|d| d.vr_prime)
        };

        trace!("Prover::blind_credential_secrets: <<< blinded_credential_secrets: {:?}, \
                                                      credential_secrets_blinding_factors: {:?}, \
                                                      blinded_credential_secrets_correctness_proof: {:?},",
            blinded_credential_secrets,
            credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof
        );

        Ok((
            blinded_credential_secrets,
            credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof,
        ))
    }

    /// Updates the credential signature by a master secret blinding data.
    ///
    /// # Arguments
    /// * `credential_signature` - Credential signature generated by Issuer.
    /// * `credential_values` - Credential values.
    /// * `signature_correctness_proof` - Credential signature correctness proof.
    /// * `credential_secrets_blinding_factors` - Master secret blinding data.
    /// * `credential_pub_key` - Credential public key.
    /// * `nonce` -  Nonce was used by Issuer for the creation of signature_correctness_proof.
    /// * `rev_key_pub` - (Optional) Revocation registry public key.
    /// * `rev_reg` - (Optional) Revocation registry.
    /// * `witness` - (Optional) Witness.
    ///
    /// # Example
    /// ```
    /// use indy_crypto::cl::new_nonce;
    /// use indy_crypto::cl::issuer::Issuer;
    /// use indy_crypto::cl::prover::Prover;
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
    /// let credential_nonce = new_nonce().unwrap();
    ///
    /// let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();
    /// credential_values_builder.add_value_hidden("master_secret", &master_secret.value().unwrap()).unwrap();
    /// credential_values_builder.add_dec_known("sex", "5944657099558967239210949258394887428692050081607692519917050011144233115103").unwrap();
    /// let credential_values = credential_values_builder.finalize().unwrap();
    ///
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
    /// ```
    pub fn process_credential_signature(credential_signature: &mut CredentialSignature,
                                        credential_values: &CredentialValues,
                                        signature_correctness_proof: &SignatureCorrectnessProof,
                                        credential_secrets_blinding_factors: &CredentialSecretsBlindingFactors,
                                        credential_pub_key: &CredentialPublicKey,
                                        nonce: &Nonce,
                                        rev_key_pub: Option<&RevocationKeyPublic>,
                                        rev_reg: Option<&RevocationRegistry>,
                                        witness: Option<&Witness>) -> Result<(), IndyCryptoError> {
        trace!("Prover::process_credential_signature: >>> credential_signature: {:?}, \
                                                          credential_values: {:?}, \
                                                          signature_correctness_proof: {:?}, \
                                                          credential_secrets_blinding_factors: {:?}, \
                                                          credential_pub_key: {:?}, \
                                                          nonce: {:?}, \
                                                          rev_key_pub: {:?}, \
                                                          rev_reg: {:?}, \
                                                          witness: {:?}",
            credential_signature,
            credential_values,
            signature_correctness_proof,
            credential_secrets_blinding_factors,
            credential_pub_key,
            nonce,
            rev_key_pub,
            rev_reg,
            witness
        );

        Prover::_process_primary_credential(&mut credential_signature.p_credential, &credential_secrets_blinding_factors.v_prime)?;

        Prover::_check_signature_correctness_proof(&credential_signature.p_credential,
                                                   credential_values,
                                                   signature_correctness_proof,
                                                   &credential_pub_key.p_key,
                                                   nonce)?;

        if let (&mut Some(ref mut non_revocation_cred), Some(ref vr_prime), &Some(ref r_key),
            Some(ref r_key_pub), Some(ref r_reg), Some(ref witness)) = (&mut credential_signature.r_credential,
                                                                        credential_secrets_blinding_factors.vr_prime,
                                                                        &credential_pub_key.r_key,
                                                                        rev_key_pub,
                                                                        rev_reg,
                                                                        witness) {
            Prover::_process_non_revocation_credential(non_revocation_cred,
                                                       vr_prime,
                                                       &r_key,
                                                       r_key_pub,
                                                       r_reg,
                                                       witness)?;
        }

        trace!("Prover::process_credential_signature: <<<");

        Ok(())
    }

    /// Creates and returns proof builder.
    ///
    /// The purpose of proof builder is building of proof entity according to the given request .
    /// # Example
    /// ```
    /// use indy_crypto::cl::prover::Prover;
    ///
    /// let _proof_builder = Prover::new_proof_builder();
    pub fn new_proof_builder() -> Result<ProofBuilder, IndyCryptoError> {
        Ok(ProofBuilder {
            common_attributes: BTreeMap::new(),
            init_proofs: Vec::new(),
            c_list: Vec::new(),
            tau_list: Vec::new()
        })
    }

    #[cfg(test)]
    pub fn check_credential_key_correctness_proof(pr_pub_key: &CredentialPrimaryPublicKey,
                                               key_correctness_proof: &CredentialKeyCorrectnessProof) -> Result<(), IndyCryptoError> {
        Prover::_check_credential_key_correctness_proof(pr_pub_key, key_correctness_proof)
    }

    fn _check_credential_key_correctness_proof(pr_pub_key: &CredentialPrimaryPublicKey,
                                               key_correctness_proof: &CredentialKeyCorrectnessProof) -> Result<(), IndyCryptoError> {
        trace!("Prover::_check_credential_key_correctness_proof: >>> pr_pub_key: {:?}, key_correctness_proof: {:?}",
            pr_pub_key,
            key_correctness_proof
        );

        if pr_pub_key.r.keys().collect::<HashSet<&String>>().ne(
            &key_correctness_proof.xr_cap.iter().map(|&(ref key, ref _val)| key).collect()) {
            return Err(IndyCryptoError::InvalidStructure(
                format!("Key Correctness Proof invalid: attributes {:?} are inconsistent with public key {:?}",
                        key_correctness_proof.xr_cap, pr_pub_key)));
        }

        let mut ctx = BigNumber::new_context()?;

        let z_inverse = pr_pub_key.z.inverse(&pr_pub_key.n, Some(&mut ctx))?;
        let z_cap = get_pedersen_commitment(
            &z_inverse,
            &key_correctness_proof.c,
            &pr_pub_key.s,
            &key_correctness_proof.xz_cap,
            &pr_pub_key.n,
            &mut ctx,
        )?;

        let mut ordered_r_values = Vec::new();
        let mut ordered_r_cap_values = Vec::new();

        for &(ref key, ref xr_cap_value) in &key_correctness_proof.xr_cap {
            let r_value = &pr_pub_key.r[key];
            ordered_r_values.push(r_value.clone()?);

            let r_inverse = r_value.inverse(&pr_pub_key.n, Some(&mut ctx))?;
            let val = get_pedersen_commitment(
                &r_inverse,
                &key_correctness_proof.c,
                &pr_pub_key.s,
                &xr_cap_value,
                &pr_pub_key.n,
                &mut ctx,
            )?;

            r_cap.insert(key.to_owned(), val);
        }

        let mut values: Vec<u8> = Vec::new();
        values.extend_from_slice(&pr_pub_key.z.to_bytes()?);
        for val in ordered_r_values {
            values.extend_from_slice(&val.to_bytes()?);
        }
        values.extend_from_slice(&z_cap.to_bytes()?);
        for val in ordered_r_cap_values {
            values.extend_from_slice(&val.to_bytes()?);
        }

        let c = get_hash_as_int(&mut vec![values])?;

        let valid = key_correctness_proof.c.eq(&c);

        if !valid {
            return Err(IndyCryptoError::InvalidStructure(format!("Invalid Credential key correctness proof")));
        }

        trace!("Prover::_check_credential_key_correctness_proof: <<<");

        Ok(())
    }

    fn _generate_blinded_primary_credential_secrets_factors(p_pub_key: &CredentialPrimaryPublicKey,
                                                            credential_values: &CredentialValues) -> Result<PrimaryBlindedCredentialSecretsFactors, IndyCryptoError> {
        trace!("Prover::_generate_blinded_primary_credential_secrets_factors: >>> p_pub_key: {:?}, credential_values: {:?}",
            p_pub_key,
            credential_values
        );

        let mut ctx = BigNumber::new_context()?;
        let v_prime = bn_rand(LARGE_VPRIME)?;

        //Hidden attributes are combined in this value
        let hidden_attributes = credential_values
                                    .attrs_values
                                    .iter()
                                    .filter(|&(_, v)| v.is_hidden())
                                    .map(|(attr, _)| attr.clone())
                                    .collect::<BTreeSet<String>>();
        let u = hidden_attributes.iter().fold(
                p_pub_key.s.mod_exp(
                    &v_prime,
                    &p_pub_key.n,
                    Some(&mut ctx),
                ),
                |acc, attr| {
                    let pk_r = p_pub_key.r.get(&attr.clone()).ok_or(
                        IndyCryptoError::InvalidStructure(
                            format!("Value by key '{}' not found in pk.r", attr),
                        ),
                    )?;
                    let cred_value = &credential_values.attrs_values[attr];
                    acc?.mod_mul(
                        &pk_r.mod_exp(
                            cred_value.value(),
                            &p_pub_key.n,
                            Some(&mut ctx),
                        )?,
                        &p_pub_key.n,
                        Some(&mut ctx),
                    )
                },
            )?;


        let mut committed_attributes = BTreeMap::new();

        for (attr, cv) in credential_values.attrs_values.iter().filter(|&(_, v)| v.is_commitment()) {
            if let &CredentialValue::Commitment { ref value, ref blinding_factor } = cv {
                committed_attributes.insert(
                    attr.clone(),
                    get_pedersen_commitment(
                        &p_pub_key.s,
                        blinding_factor,
                        &p_pub_key.z,
                        value,
                        &p_pub_key.n,
                        &mut ctx,
                    )?,
                );
            }
        }

        let primary_blinded_cred_secrets = PrimaryBlindedCredentialSecretsFactors {
            u,
            v_prime,
            hidden_attributes,
            committed_attributes,
        };

        trace!("Prover::_generate_blinded_primary_credential_secrets_factors: <<< primary_blinded_cred_secrets: {:?}", primary_blinded_cred_secrets);

        Ok(primary_blinded_cred_secrets)
    }

    fn _generate_blinded_revocation_credential_secrets(r_pub_key: &CredentialRevocationPublicKey) -> Result<RevocationBlindedCredentialSecretsFactors, IndyCryptoError> {
        trace!("Prover::_generate_blinded_revocation_credential_secrets: >>> r_pub_key: {:?}", r_pub_key);

        let vr_prime = GroupOrderElement::new()?;
        let ur = r_pub_key.h2.mul(&vr_prime)?;

        let revocation_blinded_credential_secrets = RevocationBlindedCredentialSecretsFactors { ur, vr_prime };

        trace!("Prover::_generate_blinded_revocation_credential_secrets: <<< revocation_blinded_credential_secrets: {:?}", revocation_blinded_credential_secrets);

        Ok(revocation_blinded_credential_secrets)
    }

    fn _new_blinded_credential_secrets_correctness_proof(p_pub_key: &CredentialPrimaryPublicKey,
                                                         blinded_primary_credential_secrets: &PrimaryBlindedCredentialSecretsFactors,
                                                         nonce: &BigNumber,
                                                         credential_values: &CredentialValues) -> Result<BlindedCredentialSecretsCorrectnessProof, IndyCryptoError> {
        trace!("Prover::_new_blinded_credential_secrets_correctness_proof: >>> p_pub_key: {:?}, \
                                                                               blinded_primary_credential_secrets: {:?}, \
                                                                               nonce: {:?}, \
                                                                               credential_values: {:?}",
                                            blinded_primary_credential_secrets,
                                            nonce,
                                            p_pub_key,
                                            credential_values);

        let mut ctx = BigNumber::new_context()?;

        let v_dash_tilde = bn_rand(LARGE_VPRIME_TILDE)?;

        let mut m_tildes = BTreeMap::new();
        let mut r_tildes = BTreeMap::new();

        let mut values: Vec<u8> = Vec::new();
        let mut u_tilde = p_pub_key.s.mod_exp(
            &v_dash_tilde,
            &p_pub_key.n,
            Some(&mut ctx),
        )?;

        for (attr, cred_value) in credential_values.attrs_values
                                                   .iter()
                                                   .filter(|&(_, v)|  v.is_hidden() || v.is_commitment()) {
            let m_tilde = bn_rand(LARGE_MTILDE)?;
            let pk_r = p_pub_key.r.get(attr).ok_or(
                IndyCryptoError::InvalidStructure(
                    format!(
                        "Value by key '{}' not found in pk.r",
                        attr
                    ),
                ),
            )?;

            match *cred_value {
                CredentialValue::Hidden { .. } => {
                    u_tilde = u_tilde.mod_mul(
                        &pk_r.mod_exp(&m_tilde, &p_pub_key.n, Some(&mut ctx))?,
                        &p_pub_key.n,
                        Some(&mut ctx),
                    )?;
                    ()
                }
                CredentialValue::Commitment { .. } => {
                    let r_tilde = bn_rand(LARGE_MTILDE)?;
                    let commitment_tilde = get_pedersen_commitment(
                        &p_pub_key.z,
                        &m_tilde,
                        &p_pub_key.s,
                        &r_tilde,
                        &p_pub_key.n,
                        &mut ctx,
                    )?;
                    r_tildes.insert(attr.clone(), r_tilde);

                    values.extend_from_slice(&commitment_tilde.to_bytes()?);
                    let ca_value = blinded_primary_credential_secrets.committed_attributes
                                                               .get(attr)
                                                               .ok_or(IndyCryptoError::InvalidStructure(format!("Value by key '{}' not found in primary_blinded_cred_secrets.committed_attributes", attr)))?;
                    values.extend_from_slice(&ca_value.to_bytes()?);
                    ()
                }
                _ => (),
            }
            m_tildes.insert(attr.clone(), m_tilde);
        }

        values.extend_from_slice(&blinded_primary_credential_secrets.u.to_bytes()?);
        values.extend_from_slice(&u_tilde.to_bytes()?);
        values.extend_from_slice(&nonce.to_bytes()?);

        let c = get_hash_as_int(&vec![values])?;

        let v_dash_cap = c.mul(&blinded_primary_credential_secrets.v_prime, Some(&mut ctx))?
            .add(&v_dash_tilde)?;

        let mut m_caps = BTreeMap::new();
        let mut r_caps = BTreeMap::new();

        for (attr, m_tilde) in &m_tildes {
            let ca = credential_values.attrs_values.get(attr).ok_or(
                IndyCryptoError::InvalidStructure(format!(
                    "Value by key '{}' not found in cred_values.committed_attributes",
                    attr
                )),
            )?;

            match ca {
                &CredentialValue::Hidden { ref value } => {
                    let m_cap = m_tilde.add(&c.mul(value, Some(&mut ctx))?)?;
                    m_caps.insert(attr.clone(), m_cap);
                    ()
                }
                &CredentialValue::Commitment {
                    ref value,
                    ref blinding_factor,
                } => {
                    let m_cap = m_tilde.add(&c.mul(value, Some(&mut ctx))?)?;
                    let r_cap = r_tildes[attr].add(&c.mul(blinding_factor, Some(&mut ctx))?)?;

                    m_caps.insert(attr.clone(), m_cap);
                    r_caps.insert(attr.clone(), r_cap);
                    ()
                }
                _ => (),
            }
        }

        let blinded_credential_secrets_correctness_proof =
            BlindedCredentialSecretsCorrectnessProof {
                c,
                v_dash_cap,
                m_caps,
                r_caps,
            };

        trace!("Prover::_new_blinded_credential_secrets_correctness_proof: <<< blinded_primary_master_secret_correctness_proof: {:?}", blinded_credential_secrets_correctness_proof);

        Ok(blinded_credential_secrets_correctness_proof)
    }

    fn _process_primary_credential(p_cred: &mut PrimaryCredentialSignature,
                                   v_prime: &BigNumber) -> Result<(), IndyCryptoError> {
        trace!("Prover::_process_primary_credential: >>> p_cred: {:?}, v_prime: {:?}", p_cred, v_prime);

        p_cred.v = v_prime.add(&p_cred.v)?;

        trace!("Prover::_process_primary_credential: <<<");

        Ok(())
    }

    fn _process_non_revocation_credential(r_cred: &mut NonRevocationCredentialSignature,
                                          vr_prime: &GroupOrderElement,
                                          cred_rev_pub_key: &CredentialRevocationPublicKey,
                                          rev_key_pub: &RevocationKeyPublic,
                                          rev_reg: &RevocationRegistry,
                                          witness: &Witness) -> Result<(), IndyCryptoError> {
        trace!("Prover::_process_non_revocation_credential: >>> r_cred: {:?}, vr_prime: {:?}, cred_rev_pub_key: {:?}, rev_reg: {:?}, rev_key_pub: {:?}",
               r_cred, vr_prime, cred_rev_pub_key, rev_reg, rev_key_pub);

        let r_cnxt_m2 = BigNumber::from_bytes(&r_cred.m2.to_bytes()?)?;
        r_cred.vr_prime_prime = vr_prime.add_mod(&r_cred.vr_prime_prime)?;
        Prover::_test_witness_signature(&r_cred, cred_rev_pub_key, rev_key_pub, rev_reg, witness, &r_cnxt_m2)?;

        trace!("Prover::_process_non_revocation_credential: <<<");

        Ok(())
    }

    fn _check_signature_correctness_proof(p_cred_sig: &PrimaryCredentialSignature,
                                          cred_values: &CredentialValues,
                                          signature_correctness_proof: &SignatureCorrectnessProof,
                                          p_pub_key: &CredentialPrimaryPublicKey,
                                          nonce: &Nonce) -> Result<(), IndyCryptoError> {
        trace!("Prover::_check_signature_correctness_proof: >>> p_cred_sig: {:?}, \
                                                                cred_values: {:?}, \
                                                                signature_correctness_proof: {:?}, \
                                                                p_pub_key: {:?}, \
                                                                nonce: {:?}",
            p_cred_sig,
            cred_values,
            signature_correctness_proof,
            p_pub_key,
            nonce
        );


        let mut ctx = BigNumber::new_context()?;

        if !p_cred_sig.e.is_prime(Some(&mut ctx))? {
            return Err(IndyCryptoError::InvalidStructure(format!("Invalid Signature correctness proof")));
        }

        if let Some((ref attr, _)) = cred_values.attrs_values
                      .iter()
                      .find(|&(ref attr, ref value)|
                (value.is_known() || value.is_hidden()) && !p_pub_key.r.contains_key(attr.clone())) {
                return Err(IndyCryptoError::InvalidStructure(format!("Value by key '{}' not found in public key", attr)));
        }

        let rx = cred_values
            .attrs_values
            .iter()
            .filter(|&(ref attr, ref value)| {
                (value.is_known() || value.is_hidden()) && p_pub_key.r.contains_key(attr.clone())
            })
            .fold(
                get_pedersen_commitment(
                    &p_pub_key.s,
                    &p_cred_sig.v,
                    &p_pub_key.rctxt,
                    &p_cred_sig.m_2,
                    &p_pub_key.n,
                    &mut ctx,
                ),
                |acc, (attr, value)| {
                    acc?.mod_mul(
                        &p_pub_key.r[&attr.clone()].mod_exp(
                            value.value(),
                            &p_pub_key.n,
                            Some(&mut ctx),
                        )?,
                        &p_pub_key.n,
                        Some(&mut ctx),
                    )
                },
            )?;

        let q = p_pub_key.z.mod_div(&rx, &p_pub_key.n, Some(&mut ctx))?;

        let expected_q = p_cred_sig.a.mod_exp(&p_cred_sig.e, &p_pub_key.n, Some(&mut ctx))?;

        if !q.eq(&expected_q) {
            return Err(IndyCryptoError::InvalidStructure(format!("Invalid Signature correctness proof q != q'")));
        }

        let degree = signature_correctness_proof.c.add(
            &signature_correctness_proof.se.mul(&p_cred_sig.e, Some(&mut ctx))?
        )?;

        let a_cap = p_cred_sig.a.mod_exp(&degree, &p_pub_key.n, Some(&mut ctx))?;

        let mut values: Vec<u8> = Vec::new();
        values.extend_from_slice(&q.to_bytes()?);
        values.extend_from_slice(&p_cred_sig.a.to_bytes()?);
        values.extend_from_slice(&a_cap.to_bytes()?);
        values.extend_from_slice(&nonce.to_bytes()?);

        let c = get_hash_as_int(&vec![values])?;

        let valid = signature_correctness_proof.c.eq(&c);

        if !valid {
            return Err(IndyCryptoError::InvalidStructure(format!("Invalid Signature correctness proof c != c'")));
        }

        trace!("Prover::_check_signature_correctness_proof: <<<");

        Ok(())
    }

    fn _test_witness_signature(r_cred: &NonRevocationCredentialSignature,
                               cred_rev_pub_key: &CredentialRevocationPublicKey,
                               rev_key_pub: &RevocationKeyPublic,
                               rev_reg: &RevocationRegistry,
                               witness: &Witness,
                               r_cnxt_m2: &BigNumber) -> Result<(), IndyCryptoError> {
        trace!("Prover::_test_witness_signature: >>> r_cred: {:?}, cred_rev_pub_key: {:?}, rev_key_pub: {:?}, rev_reg: {:?}, r_cnxt_m2: {:?}",
               r_cred, cred_rev_pub_key, rev_key_pub, rev_reg, r_cnxt_m2);

        let z_calc = Pair::pair(&r_cred.witness_signature.g_i, &rev_reg.accum)?
            .mul(&Pair::pair(&cred_rev_pub_key.g, &witness.omega)?.inverse()?)?;

        if z_calc != rev_key_pub.z {
            return Err(IndyCryptoError::InvalidStructure("Issuer is sending incorrect data".to_string()));
        }
        let pair_gg_calc = Pair::pair(&cred_rev_pub_key.pk.add(&r_cred.g_i)?, &r_cred.witness_signature.sigma_i)?;
        let pair_gg = Pair::pair(&cred_rev_pub_key.g, &cred_rev_pub_key.g_dash)?;

        if pair_gg_calc != pair_gg {
            return Err(IndyCryptoError::InvalidStructure("Issuer is sending incorrect data".to_string()));
        }

        let m2 = GroupOrderElement::from_bytes(&r_cnxt_m2.to_bytes()?)?;

        let pair_h1 = Pair::pair(&r_cred.sigma, &cred_rev_pub_key.y.add(&cred_rev_pub_key.h_cap.mul(&r_cred.c)?)?)?;
        let pair_h2 = Pair::pair(
            &cred_rev_pub_key.h0
                .add(&cred_rev_pub_key.h1.mul(&m2)?)?
                .add(&cred_rev_pub_key.h2.mul(&r_cred.vr_prime_prime)?)?
                .add(&r_cred.g_i)?,
            &cred_rev_pub_key.h_cap
        )?;

        if pair_h1 != pair_h2 {
            return Err(IndyCryptoError::InvalidStructure("Issuer is sending incorrect data".to_string()));
        }

        trace!("Prover::_test_witness_signature: <<<");

        Ok(())
    }
}

#[derive(Debug)]
pub struct ProofBuilder {
    common_attributes: BTreeMap<String, BigNumber>,
    init_proofs: Vec<InitProof>,
    c_list: Vec<Vec<u8>>,
    tau_list: Vec<Vec<u8>>,
}

impl ProofBuilder {
    /// Creates m_tildes for attributes that will be the same across all subproofs
    pub fn add_common_attribute(&mut self, attr_name: &str) -> Result<(), IndyCryptoError> {
        self.common_attributes.insert(attr_name.to_owned(), bn_rand(LARGE_MVECT)?);
        Ok(())
    }
    /// Adds sub proof request to proof builder which will be used fo building of proof.
    /// Part of proof request related to a particular schema-key.
    /// The order of sub-proofs is important: both Prover and Verifier should use the same order.
    ///
    /// # Arguments
    /// * `proof_builder` - Proof builder.
    /// * `sub_proof_request` -Requested attributes and predicates.
    /// * `credential_schema` - Credential schema.
    /// * `credential_signature` - Credential signature.
    /// * `credential_values` - Credential values.
    /// * `credential_pub_key` - Credential public key.
    /// * `rev_reg_pub` - (Optional) Revocation registry public.
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
    /// let credential_nonce = new_nonce().unwrap();
    ///
    /// let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();
    /// credential_values_builder.add_value_hidden("master_secret", &master_secret.value().unwrap()).unwrap();
    /// credential_values_builder.add_dec_known("sex", "5944657099558967239210949258394887428692050081607692519917050011144233115103").unwrap();
    /// let credential_values = credential_values_builder.finalize().unwrap();
    ///
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
    /// ```
    pub fn add_sub_proof_request(&mut self,
                                 sub_proof_request: &SubProofRequest,
                                 credential_schema: &CredentialSchema,
                                 non_credential_schema: &NonCredentialSchema,
                                 credential_signature: &CredentialSignature,
                                 credential_values: &CredentialValues,
                                 credential_pub_key: &CredentialPublicKey,
                                 rev_reg: Option<&RevocationRegistry>,
                                 witness: Option<&Witness>) -> Result<(), IndyCryptoError> {
        trace!("ProofBuilder::add_sub_proof_request: >>> sub_proof_request: {:?}, \
                                                         credential_schema: {:?}, \
                                                         non_credential_schema: {:?}, \
                                                         credential_signature: {:?}, \
                                                         credential_values: {:?}, \
                                                         credential_pub_key: {:?}, \
                                                         rev_reg: {:?}, \
                                                         witness: {:?}",
                                                         sub_proof_request,
                                                         credential_schema,
                                                         non_credential_schema,
                                                         credential_signature,
                                                         credential_values,
                                                         credential_pub_key,
                                                         rev_reg,
                                                         witness);
        ProofBuilder::_check_add_sub_proof_request_params_consistency(
            credential_values,
            sub_proof_request,
            credential_schema,
            non_credential_schema,
        )?;

        let mut non_revoc_init_proof = None;
        let mut m2_tilde: Option<BigNumber> = None;

        if let (&Some(ref r_cred), &Some(ref r_reg), &Some(ref r_pub_key), &Some(ref witness)) = (&credential_signature.r_credential,
                                                                                                  &rev_reg,
                                                                                                  &credential_pub_key.r_key,
                                                                                                  &witness) {
            let proof = ProofBuilder::_init_non_revocation_proof(&r_cred,
                                                                 &r_reg,
                                                                 &r_pub_key,
                                                                 &witness)?;

            self.c_list.extend_from_slice(&proof.as_c_list()?);
            self.tau_list.extend_from_slice(&proof.as_tau_list()?);
            m2_tilde = Some(group_element_to_bignum(&proof.tau_list_params.m2)?);
            non_revoc_init_proof = Some(proof);
        }

        let primary_init_proof = ProofBuilder::_init_primary_proof(&self.common_attributes,
                                                                   &credential_pub_key.p_key,
                                                                   &credential_signature.p_credential,
                                                                   credential_values,
                                                                   credential_schema,
                                                                   non_credential_schema,
                                                                   sub_proof_request,
                                                                   m2_tilde)?;

        self.c_list.extend_from_slice(&primary_init_proof.as_c_list()?);
        self.tau_list.extend_from_slice(&primary_init_proof.as_tau_list()?);

        let init_proof = InitProof {
            primary_init_proof,
            non_revoc_init_proof,
            credential_values: credential_values.clone()?,
            sub_proof_request: sub_proof_request.clone(),
            credential_schema: credential_schema.clone(),
            non_credential_schema: non_credential_schema.clone(),
        };
        self.init_proofs.push(init_proof);

        trace!("ProofBuilder::add_sub_proof_request: <<<");

        Ok(())
    }

    /// Finalize proof.
    ///
    /// # Arguments
    /// * `proof_builder` - Proof builder.
    /// * `nonce` - Nonce.
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
    /// credential_values_builder.add_value_hidden("master_secret", &master_secret.value().unwrap());
    /// credential_values_builder.add_dec_known("sex", "5944657099558967239210949258394887428692050081607692519917050011144233115103").unwrap();
    /// let credential_values = credential_values_builder.finalize().unwrap();
    ///
    /// let credential_nonce = new_nonce().unwrap();
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
    /// let _proof = proof_builder.finalize(&proof_request_nonce).unwrap();
    /// ```
    pub fn finalize(&self, nonce: &Nonce) -> Result<Proof, IndyCryptoError> {
        trace!("ProofBuilder::finalize: >>> nonce: {:?}", nonce);

        let mut values: Vec<Vec<u8>> = Vec::new();
        values.extend_from_slice(&self.tau_list);
        values.extend_from_slice(&self.c_list);
        values.push(nonce.to_bytes()?);

        // In the anoncreds whitepaper, `challenge` is denoted by `c_h`
        let challenge = get_hash_as_int(&values)?;

        let mut proofs: Vec<SubProof> = Vec::new();

        for init_proof in self.init_proofs.iter() {
            let mut non_revoc_proof: Option<NonRevocProof> = None;
            if let Some(ref non_revoc_init_proof) = init_proof.non_revoc_init_proof {
                non_revoc_proof = Some(ProofBuilder::_finalize_non_revocation_proof(&non_revoc_init_proof, &challenge)?);
            }

            let primary_proof = ProofBuilder::_finalize_primary_proof(
                &init_proof.primary_init_proof,
                &challenge,
                &init_proof.credential_schema,
                &init_proof.non_credential_schema,
                &init_proof.credential_values,
                &init_proof.sub_proof_request,
            )?;

            let proof = SubProof { primary_proof, non_revoc_proof };
            proofs.push(proof);
        }

        let aggregated_proof = AggregatedProof { c_hash: challenge, c_list: self.c_list.clone() };

        let proof = Proof { proofs, aggregated_proof };

        trace!("ProofBuilder::finalize: <<< proof: {:?}", proof);

        Ok(proof)
    }

    fn _check_add_sub_proof_request_params_consistency(
        cred_values: &CredentialValues,
        sub_proof_request: &SubProofRequest,
        cred_schema: &CredentialSchema,
        non_credential_schema: &NonCredentialSchema,
    ) -> Result<(), IndyCryptoError> {
        trace!(
            "ProofBuilder::_check_add_sub_proof_request_params_consistency: >>> cred_values: {:?}, sub_proof_request: {:?}, cred_schema: {:?}",
            cred_values,
            sub_proof_request,
            cred_schema
        );

        let schema_attrs = non_credential_schema
            .attrs
            .union(&cred_schema.attrs)
            .cloned()
            .collect::<BTreeSet<String>>();

        let cred_attrs = BTreeSet::from_iter(cred_values.attrs_values.keys().cloned());

        if schema_attrs != cred_attrs {
            return Err(IndyCryptoError::InvalidStructure(format!("Credential doesn't correspond to credential schema")));
        }

        if sub_proof_request
            .revealed_attrs
            .difference(&cred_attrs)
            .count() != 0
        {
            return Err(IndyCryptoError::InvalidStructure(
                format!("Credential doesn't contain requested attribute"),
            ));
        }

        let predicates_attrs = sub_proof_request
            .predicates
            .iter()
            .map(|predicate| predicate.attr_name.clone())
            .collect::<BTreeSet<String>>();

        if predicates_attrs.difference(&cred_attrs).count() != 0 {
            return Err(IndyCryptoError::InvalidStructure(format!("Credential doesn't contain attribute requested in predicate")));
        }

        trace!("ProofBuilder::_check_add_sub_proof_request_params_consistency: <<<");

        Ok(())
    }

    fn _init_primary_proof(common_attributes: &BTreeMap<String, BigNumber>,
                           issuer_pub_key: &CredentialPrimaryPublicKey,
                           c1: &PrimaryCredentialSignature,
                           cred_values: &CredentialValues,
                           cred_schema: &CredentialSchema,
                           non_cred_schema_elems: &NonCredentialSchema,
                           sub_proof_request: &SubProofRequest,
                           m2_t: Option<BigNumber>) -> Result<PrimaryInitProof, IndyCryptoError> {
        trace!("ProofBuilder::_init_primary_proof: >>> common_attributes: {:?}, \
                                                       issuer_pub_key: {:?}, \
                                                       c1: {:?}, \
                                                       cred_values: {:?}, \
                                                       cred_schema: {:?}, \
                                                       non_cred_schema_elems: {:?}, \
                                                       sub_proof_request: {:?}, \
                                                       m2_t: {:?}",
               common_attributes, issuer_pub_key, c1, cred_values, cred_schema, non_cred_schema_elems, sub_proof_request, m2_t);


        let eq_proof = ProofBuilder::_init_eq_proof(common_attributes,
            issuer_pub_key,
            c1,
            cred_schema,
            non_cred_schema_elems,
            sub_proof_request,
            m2_t,
        )?;

        let mut ge_proofs: Vec<PrimaryPredicateGEInitProof> = Vec::new();
        for predicate in sub_proof_request.predicates.iter() {
            let ge_proof = ProofBuilder::_init_ge_proof(
                &issuer_pub_key,
                &eq_proof.m_tilde,
                cred_values,
                predicate,
            )?;
            ge_proofs.push(ge_proof);
        }

        let primary_init_proof = PrimaryInitProof { eq_proof, ge_proofs };

        trace!("ProofBuilder::_init_primary_proof: <<< primary_init_proof: {:?}", primary_init_proof);

        Ok(primary_init_proof)
    }

    fn _init_non_revocation_proof(r_cred: &NonRevocationCredentialSignature,
                                  rev_reg: &RevocationRegistry,
                                  cred_rev_pub_key: &CredentialRevocationPublicKey,
                                  witness: &Witness) -> Result<NonRevocInitProof, IndyCryptoError> {
        trace!("ProofBuilder::_init_non_revocation_proof: >>> r_cred: {:?}, rev_reg: {:?}, cred_rev_pub_key: {:?}, witness: {:?}",
               r_cred, rev_reg, cred_rev_pub_key, witness);

        let c_list_params = ProofBuilder::_gen_c_list_params(&r_cred)?;
        let c_list = ProofBuilder::_create_c_list_values(&r_cred, &c_list_params, &cred_rev_pub_key, witness)?;

        let tau_list_params = ProofBuilder::_gen_tau_list_params()?;
        let tau_list = create_tau_list_values(&cred_rev_pub_key,
                                              &rev_reg,
                                              &tau_list_params,
                                              &c_list)?;

        let r_init_proof = NonRevocInitProof {
            c_list_params,
            tau_list_params,
            c_list,
            tau_list
        };

        trace!("ProofBuilder::_init_non_revocation_proof: <<< r_init_proof: {:?}", r_init_proof);

        Ok(r_init_proof)
    }

    fn _init_eq_proof(common_attributes: &BTreeMap<String, BigNumber>,
                      cred_pub_key: &CredentialPrimaryPublicKey,
                      c1: &PrimaryCredentialSignature,
                      cred_schema: &CredentialSchema,
                      non_cred_schema_elems: &NonCredentialSchema,
                      sub_proof_request: &SubProofRequest,
                      m2_t: Option<BigNumber>) -> Result<PrimaryEqualInitProof, IndyCryptoError> {
        trace!("ProofBuilder::_init_eq_proof: >>> cred_pub_key: {:?}, \
                                                  c1: {:?}, \
                                                  cred_schema: {:?}, \
                                                  non_cred_schema_elems: {:?}, \
                                                  sub_proof_request: {:?}, \
                                                  m2_t: {:?}",
               cred_pub_key, c1, cred_schema, non_cred_schema_elems, sub_proof_request, m2_t);

        let mut ctx = BigNumber::new_context()?;

        let m2_tilde = m2_t.unwrap_or(bn_rand(LARGE_MVECT)?);

        let r = bn_rand(LARGE_VPRIME)?;
        let e_tilde = bn_rand(LARGE_ETILDE)?;
        let v_tilde = bn_rand(LARGE_VTILDE)?;

        let unrevealed_attrs = non_cred_schema_elems.attrs.union(&cred_schema.attrs)
                                                              .cloned()
                                                              .collect::<BTreeSet<String>>()
                                                              .difference(&sub_proof_request.revealed_attrs)
                                                              .cloned()
                                                              .collect::<BTreeSet<String>>();

        let mut m_tilde = clone_bignum_map(&common_attributes)?;
        get_mtilde(&unrevealed_attrs, &mut m_tilde)?;

        let a_prime = cred_pub_key.s
            .mod_exp(&r, &cred_pub_key.n, Some(&mut ctx))?
            .mod_mul(&c1.a, &cred_pub_key.n, Some(&mut ctx))?;

        let e_prime = c1.e.sub(&LARGE_E_START_VALUE)?;

        let v_prime = c1.v.sub(&c1.e.mul(&r, Some(&mut ctx))?)?;

        let t = calc_teq(&cred_pub_key, &a_prime, &e_tilde, &v_tilde, &m_tilde, &m2_tilde, &unrevealed_attrs)?;

        let primary_equal_init_proof = PrimaryEqualInitProof {
            a_prime,
            t,
            e_tilde,
            e_prime,
            v_tilde,
            v_prime,
            m_tilde,
            m2_tilde: m2_tilde.clone()?,
            m2: c1.m_2.clone()?
        };

        trace!("ProofBuilder::_init_eq_proof: <<< primary_equal_init_proof: {:?}", primary_equal_init_proof);

        Ok(primary_equal_init_proof)
    }

    fn _init_ge_proof(p_pub_key: &CredentialPrimaryPublicKey,
                      m_tilde: &BTreeMap<String, BigNumber>,
                      cred_values: &CredentialValues,
                      predicate: &Predicate) -> Result<PrimaryPredicateGEInitProof, IndyCryptoError> {
        trace!("ProofBuilder::_init_ge_proof: >>> p_pub_key: {:?}, m_tilde: {:?}, cred_values: {:?}, predicate: {:?}",
               p_pub_key, m_tilde, cred_values, predicate);

        let mut ctx = BigNumber::new_context()?;
        let (k, value) = (&predicate.attr_name, predicate.value);

        let attr_value = cred_values.attrs_values.get(k.as_str())
            .ok_or(IndyCryptoError::InvalidStructure(format!("Value by key '{}' not found in cred_values", k)))?
            .value()
            .to_dec()?
            .parse::<i32>()
            .map_err(|_| IndyCryptoError::InvalidStructure(format!("Value by key '{}' has invalid format", k)))?;

        let delta: i32 = attr_value - value;

        if delta < 0 {
            return Err(IndyCryptoError::InvalidStructure("Predicate is not satisfied".to_string()));
        }

        let u = four_squares(delta)?;

        let mut r = BTreeMap::new();
        let mut t = BTreeMap::new();
        let mut c_list: Vec<BigNumber> = Vec::new();

        for i in 0..ITERATION {
            let cur_u = u.get(&i.to_string())
                .ok_or(IndyCryptoError::InvalidStructure(format!("Value by key '{}' not found in u1", i)))?;

            let cur_r = bn_rand(LARGE_VPRIME)?;
            let cut_t = get_pedersen_commitment(&p_pub_key.z, &cur_u, &p_pub_key.s,
                                                &cur_r, &p_pub_key.n, &mut ctx)?;

            r.insert(i.to_string(), cur_r);
            t.insert(i.to_string(), cut_t.clone()?);
            c_list.push(cut_t)
        }

        let r_delta = bn_rand(LARGE_VPRIME)?;

        let t_delta = get_pedersen_commitment(&p_pub_key.z, &BigNumber::from_dec(&delta.to_string())?,
                                              &p_pub_key.s, &r_delta, &p_pub_key.n, &mut ctx)?;

        r.insert("DELTA".to_string(), r_delta);
        t.insert("DELTA".to_string(), t_delta.clone()?);
        c_list.push(t_delta);

        let mut u_tilde = BTreeMap::new();
        let mut r_tilde = BTreeMap::new();

        for i in 0..ITERATION {
            u_tilde.insert(i.to_string(), bn_rand(LARGE_UTILDE)?);
            r_tilde.insert(i.to_string(), bn_rand(LARGE_RTILDE)?);
        }

        r_tilde.insert("DELTA".to_string(), bn_rand(LARGE_RTILDE)?);
        let alpha_tilde = bn_rand(LARGE_ALPHATILDE)?;

        let mj = m_tilde.get(k.as_str())
            .ok_or(IndyCryptoError::InvalidStructure(format!("Value by key '{}' not found in eq_proof.mtilde", k)))?;

        let tau_list = calc_tge(&p_pub_key, &u_tilde, &r_tilde, &mj, &alpha_tilde, &t)?;

        let primary_predicate_ge_init_proof = PrimaryPredicateGEInitProof {
            c_list,
            tau_list,
            u,
            u_tilde,
            r,
            r_tilde,
            alpha_tilde,
            predicate: predicate.clone(),
            t
        };

        trace!("ProofBuilder::_init_ge_proof: <<< primary_predicate_ge_init_proof: {:?}", primary_predicate_ge_init_proof);

        Ok(primary_predicate_ge_init_proof)
    }

    fn _finalize_eq_proof(init_proof: &PrimaryEqualInitProof,
                          challenge: &BigNumber,
                          cred_schema: &CredentialSchema,
                          non_cred_schema_elems: &NonCredentialSchema,
                          cred_values: &CredentialValues,
                          sub_proof_request: &SubProofRequest) -> Result<PrimaryEqualProof, IndyCryptoError> {
        trace!(
            "ProofBuilder::_finalize_eq_proof: >>> init_proof: {:?}, challenge: {:?}, cred_schema: {:?}, \
        cred_values: {:?}, sub_proof_request: {:?}",
            init_proof,
            challenge,
            cred_schema,
            cred_values,
            sub_proof_request
        );

        let mut ctx = BigNumber::new_context()?;

        let e = challenge
            .mul(&init_proof.e_prime, Some(&mut ctx))?
            .add(&init_proof.e_tilde)?;

        let v = challenge
            .mul(&init_proof.v_prime, Some(&mut ctx))?
            .add(&init_proof.v_tilde)?;

        let mut m = BTreeMap::new();


        let unrevealed_attrs = non_cred_schema_elems
            .attrs
            .union(&cred_schema.attrs)
            .cloned()
            .collect::<BTreeSet<String>>()
            .difference(&sub_proof_request.revealed_attrs)
            .cloned()
            .collect::<BTreeSet<String>>();

        for k in unrevealed_attrs.iter() {
            let cur_mtilde = init_proof.m_tilde.get(k)
                .ok_or(IndyCryptoError::InvalidStructure(format!("Value by key '{}' not found in init_proof.mtilde", k)))?;

            let cur_val = cred_values.attrs_values.get(k)
                .ok_or(IndyCryptoError::InvalidStructure(format!("Value by key '{}' not found in attributes_values", k)))?;

            let val = challenge
                .mul(&cur_val.value(), Some(&mut ctx))?
                .add(&cur_mtilde)?;

            m.insert(k.clone(), val);
        }

        let m2 = challenge
            .mul(&init_proof.m2, Some(&mut ctx))?
            .add(&init_proof.m2_tilde)?;

        let mut revealed_attrs_with_values = BTreeMap::new();

        for attr in sub_proof_request.revealed_attrs.iter() {
            revealed_attrs_with_values.insert(
                attr.clone(),
                cred_values.attrs_values
                    .get(attr)
                    .ok_or(IndyCryptoError::InvalidStructure(format!("Encoded value not found")))?
                    .value()
                    .clone()?,
            );
        }

        let primary_equal_proof = PrimaryEqualProof {
            revealed_attrs: revealed_attrs_with_values,
            a_prime: init_proof.a_prime.clone()?,
            e,
            v,
            m,
            m2
        };

        trace!("ProofBuilder::_finalize_eq_proof: <<< primary_equal_proof: {:?}", primary_equal_proof);

        Ok(primary_equal_proof)
    }

    fn _finalize_ge_proof(c_h: &BigNumber,
                          init_proof: &PrimaryPredicateGEInitProof,
                          eq_proof: &PrimaryEqualProof) -> Result<PrimaryPredicateGEProof, IndyCryptoError> {
        trace!("ProofBuilder::_finalize_ge_proof: >>> c_h: {:?}, init_proof: {:?}, eq_proof: {:?}", c_h, init_proof, eq_proof);

        let mut ctx = BigNumber::new_context()?;
        let mut u = BTreeMap::new();
        let mut r = BTreeMap::new();
        let mut urproduct = BigNumber::new()?;

        for i in 0..ITERATION {
            let cur_utilde = &init_proof.u_tilde[&i.to_string()];
            let cur_u = &init_proof.u[&i.to_string()];
            let cur_rtilde = &init_proof.r_tilde[&i.to_string()];
            let cur_r = &init_proof.r[&i.to_string()];

            let new_u: BigNumber = c_h
                .mul(&cur_u, Some(&mut ctx))?
                .add(&cur_utilde)?;
            let new_r: BigNumber = c_h
                .mul(&cur_r, Some(&mut ctx))?
                .add(&cur_rtilde)?;

            u.insert(i.to_string(), new_u);
            r.insert(i.to_string(), new_r);

            urproduct = cur_u
                .mul(&cur_r, Some(&mut ctx))?
                .add(&urproduct)?;

            let cur_rtilde_delta = &init_proof.r_tilde["DELTA"];

            let new_delta = c_h
                .mul(&init_proof.r["DELTA"], Some(&mut ctx))?
                .add(&cur_rtilde_delta)?;

            r.insert("DELTA".to_string(), new_delta);
        }

        let alpha = init_proof.r["DELTA"]
            .sub(&urproduct)?
            .mul(&c_h, Some(&mut ctx))?
            .add(&init_proof.alpha_tilde)?;

        let primary_predicate_ge_proof = PrimaryPredicateGEProof {
            u,
            r,
            mj: eq_proof.m[&init_proof.predicate.attr_name].clone()?,
            alpha,
            t: clone_bignum_map(&init_proof.t)?,
            predicate: init_proof.predicate.clone()
        };

        trace!("ProofBuilder::_finalize_ge_proof: <<< primary_predicate_ge_proof: {:?}", primary_predicate_ge_proof);

        Ok(primary_predicate_ge_proof)
    }

    fn _finalize_primary_proof(init_proof: &PrimaryInitProof,
                               challenge: &BigNumber,
                               cred_schema: &CredentialSchema,
                               non_cred_schema_elems: &NonCredentialSchema,
                               cred_values: &CredentialValues,
                               sub_proof_request: &SubProofRequest) -> Result<PrimaryProof, IndyCryptoError> {
        trace!(
            "ProofBuilder::_finalize_primary_proof: >>> init_proof: {:?}, challenge: {:?}, cred_schema: {:?}, \
        cred_values: {:?}, sub_proof_request: {:?}",
            init_proof,
            challenge,
            cred_schema,
            cred_values,
            sub_proof_request
        );

        let eq_proof = ProofBuilder::_finalize_eq_proof(
            &init_proof.eq_proof,
            challenge,
            cred_schema,
            non_cred_schema_elems,
            cred_values,
            sub_proof_request,
        )?;
        let mut ge_proofs: Vec<PrimaryPredicateGEProof> = Vec::new();

        for init_ge_proof in init_proof.ge_proofs.iter() {
            let ge_proof = ProofBuilder::_finalize_ge_proof(challenge, init_ge_proof, &eq_proof)?;
            ge_proofs.push(ge_proof);
        }

        let primary_proof = PrimaryProof { eq_proof, ge_proofs };

        trace!("ProofBuilder::_finalize_primary_proof: <<< primary_proof: {:?}", primary_proof);

        Ok(primary_proof)
    }

    fn _gen_c_list_params(r_cred: &NonRevocationCredentialSignature) -> Result<NonRevocProofXList, IndyCryptoError> {
        trace!("ProofBuilder::_gen_c_list_params: >>> r_cred: {:?}", r_cred);

        let rho = GroupOrderElement::new()?;
        let r = GroupOrderElement::new()?;
        let r_prime = GroupOrderElement::new()?;
        let r_prime_prime = GroupOrderElement::new()?;
        let r_prime_prime_prime = GroupOrderElement::new()?;
        let o = GroupOrderElement::new()?;
        let o_prime = GroupOrderElement::new()?;
        let m = rho.mul_mod(&r_cred.c)?;
        let m_prime = r.mul_mod(&r_prime_prime)?;
        let t = o.mul_mod(&r_cred.c)?;
        let t_prime = o_prime.mul_mod(&r_prime_prime)?;
        let m2 = GroupOrderElement::from_bytes(&r_cred.m2.to_bytes()?)?;

        let non_revoc_proof_x_list = NonRevocProofXList {
            rho,
            r,
            r_prime,
            r_prime_prime,
            r_prime_prime_prime,
            o,
            o_prime,
            m,
            m_prime,
            t,
            t_prime,
            m2,
            s: r_cred.vr_prime_prime,
            c: r_cred.c
        };

        trace!("ProofBuilder::_gen_c_list_params: <<< non_revoc_proof_x_list: {:?}", non_revoc_proof_x_list);

        Ok(non_revoc_proof_x_list)
    }

    fn _create_c_list_values(r_cred: &NonRevocationCredentialSignature,
                             params: &NonRevocProofXList,
                             r_pub_key: &CredentialRevocationPublicKey,
                             witness: &Witness) -> Result<NonRevocProofCList, IndyCryptoError> {
        trace!("ProofBuilder::_create_c_list_values: >>> r_cred: {:?}, r_pub_key: {:?}", r_cred, r_pub_key);

        let e = r_pub_key.h
            .mul(&params.rho)?
            .add(
                &r_pub_key.htilde.mul(&params.o)?
            )?;

        let d = r_pub_key.g
            .mul(&params.r)?
            .add(
                &r_pub_key.htilde.mul(&params.o_prime)?
            )?;

        let a = r_cred.sigma
            .add(
                &r_pub_key.htilde.mul(&params.rho)?
            )?;

        let g = r_cred.g_i
            .add(
                &r_pub_key.htilde.mul(&params.r)?
            )?;

        let w = witness.omega
            .add(
                &r_pub_key.h_cap.mul(&params.r_prime)?
            )?;

        let s = r_cred.witness_signature.sigma_i
            .add(
                &r_pub_key.h_cap.mul(&params.r_prime_prime)?
            )?;

        let u = r_cred.witness_signature.u_i
            .add(
                &r_pub_key.h_cap.mul(&params.r_prime_prime_prime)?
            )?;

        let non_revoc_proof_c_list = NonRevocProofCList {
            e,
            d,
            a,
            g,
            w,
            s,
            u
        };

        trace!("ProofBuilder::_create_c_list_values: <<< non_revoc_proof_c_list: {:?}", non_revoc_proof_c_list);

        Ok(non_revoc_proof_c_list)
    }

    fn _gen_tau_list_params() -> Result<NonRevocProofXList, IndyCryptoError> {
        trace!("ProofBuilder::_gen_tau_list_params: >>>");

        let non_revoc_proof_x_list = NonRevocProofXList {
            rho: GroupOrderElement::new()?,
            r: GroupOrderElement::new()?,
            r_prime: GroupOrderElement::new()?,
            r_prime_prime: GroupOrderElement::new()?,
            r_prime_prime_prime: GroupOrderElement::new()?,
            o: GroupOrderElement::new()?,
            o_prime: GroupOrderElement::new()?,
            m: GroupOrderElement::new()?,
            m_prime: GroupOrderElement::new()?,
            t: GroupOrderElement::new()?,
            t_prime: GroupOrderElement::new()?,
            m2: GroupOrderElement::new()?,
            s: GroupOrderElement::new()?,
            c: GroupOrderElement::new()?
        };

        trace!("ProofBuilder::_gen_tau_list_params: <<< Nnon_revoc_proof_x_list: {:?}", non_revoc_proof_x_list);

        Ok(non_revoc_proof_x_list)
    }

    fn _finalize_non_revocation_proof(init_proof: &NonRevocInitProof, c_h: &BigNumber) -> Result<NonRevocProof, IndyCryptoError> {
        trace!("ProofBuilder::_finalize_non_revocation_proof: >>> init_proof: {:?}, c_h: {:?}", init_proof, c_h);

        let ch_num_z = bignum_to_group_element(&c_h)?;
        let mut x_list: Vec<GroupOrderElement> = Vec::new();

        for (x, y) in init_proof.tau_list_params.as_list()?.iter().zip(init_proof.c_list_params.as_list()?.iter()) {
            x_list.push(x.add_mod(
                &ch_num_z.mul_mod(&y)?.mod_neg()?
            )?);
        }

        let non_revoc_proof = NonRevocProof {
            x_list: NonRevocProofXList::from_list(x_list),
            c_list: init_proof.c_list.clone()
        };

        trace!("ProofBuilder::_finalize_non_revocation_proof: <<< non_revoc_proof: {:?}", non_revoc_proof);

        Ok(non_revoc_proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cl::issuer;

    #[test]
    fn generate_master_secret_works() {
        MockHelper::inject();

        let ms = Prover::new_master_secret().unwrap();
        assert_eq!(ms.ms.to_dec().unwrap(), mocks::master_secret().ms.to_dec().unwrap());
    }

    #[test]
    fn generate_blinded_primary_credential_secrets_works() {
        MockHelper::inject();

        let pk = issuer::mocks::credential_primary_public_key();
        let credential_values = issuer::mocks::credential_values();

        let _blinded_primary_credential_secrets = Prover::_generate_blinded_primary_credential_secrets_factors(&pk, &credential_values).unwrap();
        assert_eq!(_blinded_primary_credential_secrets, mocks::primary_blinded_credential_secrets_factors());
    }

    #[test]
    fn generate_blinded_revocation_credential_secrets_works() {
        MockHelper::inject();

        let r_pk = issuer::mocks::credential_revocation_public_key();
        Prover::_generate_blinded_revocation_credential_secrets(&r_pk).unwrap();
    }

    #[test]
    fn generate_blinded_credential_secrets_works() {
        MockHelper::inject();

        let pk = issuer::mocks::credential_public_key();
        let key_correctness_proof = issuer::mocks::credential_key_correctness_proof();
        let credential_values = issuer::mocks::credential_values();
        let nonce = issuer::mocks::credential_nonce();

        let (blinded_credential_secrets, credential_secrets_blinding_factors, blinded_credential_secrets_correctness_proof) =
            Prover::blind_credential_secrets(&pk, &key_correctness_proof, &credential_values, &nonce).unwrap();

        assert_eq!(blinded_credential_secrets.u, mocks::primary_blinded_credential_secrets_factors().u);
        assert_eq!(credential_secrets_blinding_factors.v_prime, mocks::primary_blinded_credential_secrets_factors().v_prime);
        assert!(blinded_credential_secrets.ur.is_some());
        assert!(credential_secrets_blinding_factors.vr_prime.is_some());

        let expected_blinded_credential_secrets_correctness_proof = BlindedCredentialSecretsCorrectnessProof {
            c: BigNumber::from_dec("31112617379873791811826693905481586216258945588891199393233239240031294952876").unwrap(),
            v_dash_cap: BigNumber::from_dec("1363335311228326349885864895573525858889056615834382117755417442654983793170146206406624183979675990021180406188855521760602353471602942706209794637782241189586576050213402198348725433808364943110660099080289430845777605400012927233527508538182470868276011084976748589016520667384365885660838251282787511473092237449084653043918406479948645889765969617372318001032647736972066956541819690538010176540431130230766927748691677371758164678646896444746633090939706100763377311139680427312684857559129036937844898911420596827192245277943255159867055324670511555983948672909890017634609238730859555658435998773243922095276487163827873799805475759059211931618362842247540123673133130292326543595494930542657883610069658117018").unwrap(),
            m_caps: btreemap!["master_secret".to_string() => BigNumber::from_dec("10838856720335086997514320589011221802471647172352648280461570291955695158835273474728967096765018754710508950735933577983784747770727422998069029130488338927266947414824451806235").unwrap()],
            r_caps: BTreeMap::new()
        };

        assert_eq!(blinded_credential_secrets_correctness_proof, expected_blinded_credential_secrets_correctness_proof);
    }

    #[test]
    fn process_primary_credential_works() {
        MockHelper::inject();

        let mut credential = issuer::mocks::primary_credential();
        let v_prime = mocks::primary_blinded_credential_secrets_factors().v_prime;

        Prover::_process_primary_credential(&mut credential, &v_prime).unwrap();

        assert_eq!(mocks::primary_credential(), credential);
    }

    #[ignore]
    #[test]
    fn process_credential_works() {
        MockHelper::inject();

        let mut credential_signature = issuer::mocks::credential();
        let credential_values = issuer::mocks::credential_values();
        let pk = issuer::mocks::credential_public_key();
        let credential_secrets_blinding_factors = mocks::credential_secrets_blinding_factors();
        let signature_correctness_proof = issuer::mocks::signature_correctness_proof();
        let nonce = new_nonce().unwrap();

        Prover::process_credential_signature(&mut credential_signature,
                                             &credential_values,
                                             &signature_correctness_proof,
                                             &credential_secrets_blinding_factors,
                                             &pk,
                                             &nonce,
                                             None,
                                             None,
                                             None).unwrap();

        assert_eq!(mocks::primary_credential(), credential_signature.p_credential);
    }

    #[test]
    fn init_eq_proof_works() {
        MockHelper::inject();

        let common_attributes = btreemap!["master_secret".to_string() => mocks::m1_t()];
        let pk = issuer::mocks::credential_primary_public_key();
        let cred_schema = issuer::mocks::credential_schema();
        let non_cred_schema_elems = issuer::mocks::non_credential_schema();
        let credential = mocks::primary_credential();
        let sub_proof_request = mocks::sub_proof_request();
        let m2_tilde = group_element_to_bignum(&mocks::init_non_revocation_proof().tau_list_params.m2).unwrap();

        let init_eq_proof = ProofBuilder::_init_eq_proof(&common_attributes,
                                                         &pk,
                                                         &credential,
                                                         &cred_schema,
                                                         &non_cred_schema_elems,
                                                         &sub_proof_request,
                                                         Some(m2_tilde)).unwrap();

        assert_eq!(mocks::primary_equal_init_proof(), init_eq_proof);
    }

    #[test]
    fn init_ge_proof_works() {
        MockHelper::inject();

        let pk = issuer::mocks::credential_primary_public_key();
        let init_eq_proof = mocks::primary_equal_init_proof();
        let predicate = mocks::predicate();
        let credential_values = issuer::mocks::credential_values();

        let init_ge_proof = ProofBuilder::_init_ge_proof(&pk,
                                                         &init_eq_proof.m_tilde,
                                                         &credential_values,
                                                         &predicate).unwrap();

        assert_eq!(mocks::primary_ge_init_proof(), init_ge_proof);
    }

    #[test]
    fn init_primary_proof_works() {
        MockHelper::inject();

        let pk = issuer::mocks::credential_primary_public_key();
        let credential_schema = issuer::mocks::credential_schema();
        let non_credential_schema = issuer::mocks::non_credential_schema();
        let credential = mocks::credential();
        let credential_values = issuer::mocks::credential_values();
        let sub_proof_request = mocks::sub_proof_request();
        let common_attributes = mocks::proof_common_attributes();
        let m2_tilde = group_element_to_bignum(&mocks::init_non_revocation_proof().tau_list_params.m2).unwrap();

        let init_proof = ProofBuilder::_init_primary_proof(&common_attributes,
                                                           &pk,
                                                           &credential.p_credential,
                                                           &credential_values,
                                                           &credential_schema,
                                                           &non_credential_schema,
                                                           &sub_proof_request,
                                                            Some(m2_tilde)).unwrap();
        assert_eq!(mocks::primary_init_proof(), init_proof);
    }

    #[test]
    fn finalize_eq_proof_works() {
        MockHelper::inject();

        let c_h = mocks::aggregated_proof().c_hash;
        let init_proof = mocks::primary_equal_init_proof();
        let credential_values = issuer::mocks::credential_values();
        let non_credential_schema = issuer::mocks::non_credential_schema();
        let credential_schema = issuer::mocks::credential_schema();
        let sub_proof_request = mocks::sub_proof_request();

        let eq_proof = ProofBuilder::_finalize_eq_proof(&init_proof,
                                                        &c_h,
                                                        &credential_schema,
                                                        &non_credential_schema,
                                                        &credential_values,
                                                        &sub_proof_request).unwrap();

        assert_eq!(mocks::eq_proof(), eq_proof);
    }

    #[test]
    fn finalize_ge_proof_works() {
        MockHelper::inject();

        let c_h = mocks::aggregated_proof().c_hash;
        let ge_proof = mocks::primary_ge_init_proof();
        let eq_proof = mocks::eq_proof();

        let ge_proof = ProofBuilder::_finalize_ge_proof(&c_h,
                                                        &ge_proof,
                                                        &eq_proof).unwrap();
        assert_eq!(mocks::ge_proof(), ge_proof);
    }

    #[test]
    fn finalize_primary_proof_works() {
        MockHelper::inject();

        let proof = mocks::primary_init_proof();
        let c_h = mocks::aggregated_proof().c_hash;
        let credential_schema = issuer::mocks::credential_schema();
        let non_credential_schema = issuer::mocks::non_credential_schema();
        let credential_values = issuer::mocks::credential_values();
        let sub_proof_request = mocks::sub_proof_request();

        let proof = ProofBuilder::_finalize_primary_proof(&proof,
                                                          &c_h,
                                                          &credential_schema,
                                                          &non_credential_schema,
                                                          &credential_values,
                                                          &sub_proof_request).unwrap();

        assert_eq!(mocks::primary_proof(), proof);
    }

    extern crate time;

    /*
    Results:

    N = 100
    Create RevocationRegistry Time: Duration { secs: 0, nanos: 153759082 }
    Update NonRevocation Credential Time: Duration { secs: 0, nanos: 490382 }
    Total Time for 100 credentials: Duration { secs: 5, nanos: 45915383 }

    N = 1000
    Create RevocationRegistry Time: Duration { secs: 1, nanos: 636113212 }
    Update NonRevocation Credential Time: Duration { secs: 0, nanos: 5386575 }
    Total Time for 1000 credentials: Duration { secs: 6, nanos: 685771457 }

    N = 10000
    Create RevocationRegistry Time: Duration { secs: 16, nanos: 844061103 }
    Update NonRevocation Credential Time: Duration { secs: 0, nanos: 52396763 }
    Total Time for 10000 credentials: Duration { secs: 29, nanos: 628240611 }

    N = 100000
    Create RevocationRegistry Time: Duration { secs: 175, nanos: 666428558 }
    Update NonRevocation Credential Time: Duration { secs: 0, nanos: 667879620 }
    Total Time for 100000 credentials: Duration { secs: 185, nanos: 810126906 }

    N = 1000000
    Create RevocationRegistry Time: Duration { secs: 1776, nanos: 485208599 }
    Update NonRevocation Credential Time: Duration { secs: 6, nanos: 35027554 }
    Total Time for 1000000 credentials: Duration { secs: 1798, nanos: 420564334 }
    */
    #[test]
    fn test_update_proof() {
        println!("Update Proof test -> start");
        let n = 100;

        let total_start_time = time::get_time();

        let cred_schema = issuer::mocks::credential_schema();
        let non_cred_schema = issuer::mocks::non_credential_schema();
        let (cred_pub_key, cred_priv_key, cred_key_correctness_proof) = issuer::Issuer::new_credential_def(&cred_schema, &non_cred_schema, true).unwrap();

        let start_time = time::get_time();

        let (rev_key_pub, rev_key_priv, mut rev_reg, mut rev_tails_generator) = issuer::Issuer::new_revocation_registry_def(&cred_pub_key, n, false).unwrap();

        let simple_tail_accessor = SimpleTailsAccessor::new(&mut rev_tails_generator).unwrap();

        let end_time = time::get_time();

        println!("Create RevocationRegistry Time: {:?}", end_time - start_time);

        let cred_values = issuer::mocks::credential_values();

        // Issue first correct Claim
        let credential_nonce = new_nonce().unwrap();

        let (blinded_credential_secrets, credential_secrets_blinding_factors, blinded_credential_secrets_correctness_proof) =
            Prover::blind_credential_secrets(&cred_pub_key,
                                        &cred_key_correctness_proof,
                                        &cred_values,
                                        &credential_nonce).unwrap();

        let cred_issuance_nonce = new_nonce().unwrap();

        let rev_idx = 1;
        let (mut cred_signature, signature_correctness_proof, rev_reg_delta) =
            issuer::Issuer::sign_credential_with_revoc("CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW",
                                                       &blinded_credential_secrets,
                                                       &blinded_credential_secrets_correctness_proof,
                                                       &credential_nonce,
                                                       &cred_issuance_nonce,
                                                       &cred_values,
                                                       &cred_pub_key,
                                                       &cred_priv_key,
                                                       rev_idx,
                                                       n,
                                                       false,
                                                       &mut rev_reg,
                                                       &rev_key_priv,
                                                       &simple_tail_accessor).unwrap();
        let mut rev_reg_delta = rev_reg_delta.unwrap();

        let mut witness = Witness::new(rev_idx, n, false, &rev_reg_delta, &simple_tail_accessor).unwrap();

        Prover::process_credential_signature(&mut cred_signature,
                                             &cred_values,
                                             &signature_correctness_proof,
                                             &credential_secrets_blinding_factors,
                                             &cred_pub_key,
                                             &cred_issuance_nonce,
                                             Some(&rev_key_pub),
                                             Some(&rev_reg),
                                             Some(&witness)).unwrap();

        // Populate accumulator
        for i in 2..n {
            let index = n + 1 - i;

            simple_tail_accessor.access_tail(index, &mut |tail| {
                rev_reg_delta.accum = rev_reg_delta.accum.sub(tail).unwrap();
            }).unwrap();

            rev_reg_delta.issued.insert(i);
        }

        // Update NonRevoc Credential

        let start_time = time::get_time();

        witness.update(rev_idx, n, &rev_reg_delta, &simple_tail_accessor).unwrap();

        let end_time = time::get_time();

        println!("Update NonRevocation Credential Time: {:?}", end_time - start_time);

        let total_end_time = time::get_time();
        println!("Total Time for {} credentials: {:?}", n, total_end_time - total_start_time);

        println!("Update Proof test -> end");
    }

    #[test]
    #[ignore]
    fn generate_proof_mocks() {
        let credential_schema = issuer::mocks::credential_schema();
        let non_credential_schema = issuer::mocks::non_credential_schema();
        let cred_signature = mocks::credential();
        let cred_values = issuer::mocks::credential_values();
        let cred_pub_key = issuer::mocks::credential_public_key();
        let rev_reg = issuer::mocks::revocation_registry();
        let witness = issuer::mocks::witness();

        let sub_proof_request = mocks::sub_proof_request();

        let mut proof_builder = Prover::new_proof_builder().unwrap();
        proof_builder.add_common_attribute("master_secret").unwrap();
        proof_builder.add_sub_proof_request(&sub_proof_request,
                                            &credential_schema,
                                            &non_credential_schema,
                                            &cred_signature,
                                            &cred_values,
                                            &cred_pub_key,
                                            Some(&rev_reg),
                                            Some(&witness)).unwrap();
        let proof_request_nonce = new_nonce().unwrap();
        let proof = proof_builder.finalize(&proof_request_nonce).unwrap();

        println!("proof_request_nonce = {:#?}", proof_request_nonce);
        println!("proof = {:#?}", proof);

//        let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
//        proof_verifier.add_sub_proof_request(&sub_proof_request,
//                                             &credential_schema,
//                                             &non_credential_schema,
//                                             &cred_pub_key,
//                                             Some(&rev_key_pub),
//                                             Some(&rev_reg)).unwrap();

    }
}

pub mod mocks {
    use super::*;
    use self::issuer::mocks as issuer_mocks;

    pub const PROVER_DID: &'static str = "CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW";

    pub fn master_secret() -> MasterSecret {
        MasterSecret {
            ms: BigNumber::from_dec("21578029250517794450984707538122537192839006240802068037273983354680998203845").unwrap()
        }
    }

    pub fn proof_common_attributes() -> BTreeMap<String, BigNumber> {
        btreemap!["master_secret".to_string() => BigNumber::from_dec("67940925789970108743024738273926421512152745397724199848594503731042154269417576665420030681245389493783225644817826683796657351721363490290016166310023506339911751676800452438014771736117676826911321621579680668201191205819012441197794443970687648330757835198888257781967404396196813475280544039772512800509").unwrap()]
    }

    pub fn blinded_credential_secrets() -> BlindedCredentialSecrets {
        BlindedCredentialSecrets {
            u: primary_blinded_credential_secrets_factors().u,
            ur: Some(revocation_blinded_credential_secrets_factors().ur),
            hidden_attributes: primary_blinded_credential_secrets_factors().hidden_attributes,
            committed_attributes: primary_blinded_credential_secrets_factors().committed_attributes
        }
    }

    pub fn credential_secrets_blinding_factors() -> CredentialSecretsBlindingFactors {
        CredentialSecretsBlindingFactors {
            v_prime: primary_blinded_credential_secrets_factors().v_prime,
            vr_prime: Some(revocation_blinded_credential_secrets_factors().vr_prime)
        }
    }

    pub fn primary_blinded_credential_secrets_factors() -> PrimaryBlindedCredentialSecretsFactors {
        PrimaryBlindedCredentialSecretsFactors {
            u: BigNumber::from_dec("90736407601154268942168157104903234952360065311487243849084269734873299527511182830774611139189290224819345671684251706821639402723220759744837220186762030984612732058625792294981537421278637522985531255498378380724624057491992283809860995022105266457008540385709981731854234549072840444466441403414625910966897254877127628576556263069743869740076498539583664244579542604581944995484024167429668186856342472700295144668637042873726468349675344333841204436306605752709604388796040186193116315781142929220422920542474085998878545282252921509121146671967303033856259567745092005106497947375787538654303796784079961901319").unwrap(),
            v_prime: BigNumber::from_dec("35131625843806290832574870589259287147303302356085937450138681169270844305658441640899780357851554390281352797472151859633451190372182905767740276000477099644043795107449461869975792759973231599572009337886283219344284767785705740629929916685684025616389621432096690068102576167647117576924865030253290356476886389376786906469624913865400296221181743871195998667521041628188272244376790322856843509187067488962831880868979749045372839549034465343690176440012266969614156191820420452812733264350018673445974099278245215963827842041818557926829011513408602244298030173493359464182527821314118075880620818817455331127028576670474022443879858290").unwrap(),
            hidden_attributes: btreeset!["master_secret".to_string()],
            committed_attributes: BTreeMap::new()
        }
    }

    pub fn revocation_blinded_credential_secrets_factors() -> RevocationBlindedCredentialSecretsFactors {
        RevocationBlindedCredentialSecretsFactors {
            ur: PointG1::from_string("false C5EEF1C6090965 F565893239016A FB8981F4EBA4BC 8A6E4055EC94AB 170C93DA 4CAEA6A3B2322D D6CBC56037A657 18283A0CDB3189 C5D4CF51371C11 1158A779 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD").unwrap(),
            vr_prime: GroupOrderElement::from_string("B6452E9ED6329 E895E0A06B4D7F 120938CB56E3BC 2515A38404157 21B2F773").unwrap()
        }
    }

    pub fn blinded_credential_secrets_correctness_proof() -> BlindedCredentialSecretsCorrectnessProof {
        BlindedCredentialSecretsCorrectnessProof {
            c: BigNumber::from_dec("7693879002891325854580633172775542263622308503851226227512383778297475533273").unwrap(),
            v_dash_cap: BigNumber::from_dec("270298478417095479220290594584939047494346369147130625108591856876117642868419712751969590245254334991166889036788530148477803140478672027928370955091370583281459907700064946334767292519162627481902897542449108651799429220474716102517267041190109007705837996084500291972767516961856433422463928489596635755968305697657263602410315315699668569475294284149420689787369293572415520120407813627728294966186505049911304085251972396326360619772719074462112179705644380720999568711278918891648826835780390171047267207545376556256492132741157234203510394954083841819337935748090844979201296564715517060661494523573360443178066251365907452546112932609156697658169869612094693691147056425870741422286622837497671512722430033268").unwrap(),
            m_caps: btreemap!["master_secret".to_string() => BigNumber::from_dec("21509241919376692260980560583706197323914759323290322267026749611973036811183867628868616613573181103989153093382513795561743848398837927167191271207384237816654872781491563762266").unwrap()],
            r_caps: BTreeMap::new()
        }
    }

    pub fn credential() -> CredentialSignature {
        CredentialSignature {
            p_credential: primary_credential(),
            r_credential: Some(issuer::mocks::revocation_credential())
        }
    }

    pub fn m1_t() -> BigNumber {
        BigNumber::from_dec("67940925789970108743024738273926421512152745397724199848594503731042154269417576665420030681245389493783225644817826683796657351721363490290016166310023506339911751676800452438014771736117676826911321621579680668201191205819012441197794443970687648330757835198888257781967404396196813475280544039772512800509").unwrap()
    }

    pub fn primary_credential() -> PrimaryCredentialSignature {
        PrimaryCredentialSignature {
            m_2: issuer_mocks::m2(),
            a: BigNumber::from_dec("60598096300110505279750181320130587026716953168722029465442100858765611388437518362663364506285714393889528526925769421571092083357542485349102861386986057219969921557487809995601556559987762243518822764509094413774190105074641519836018069694204467033725909348537798613387434106828072295539069401257717308548203193143526998793635659215707816324637606186537330000247168547726551874138698100814471988467062706901218694137515927694259483279409479745022260125873317036913720086519524465890008868911411373324450614877678917640617150293767932573524818488647061713391998713343528454289262358169184742033153828930903815476187").unwrap(),
            e: BigNumber::from_dec("259344723055062059907025491480697571938277889515152306249728583105665800713306759149981690559193987143012367913206299323899696942213235956742929944698562575392316272320549893391771").unwrap(),
            v: BigNumber::from_dec("6996057067686934709231174434558258486493808267378248647410976878261435225657894050774133393922654332955534902104832478531341852292938521469275360591816338451092268559834937570490355169308920756816946962817711481861143943871900797954709350869360964024548143652111659355479064432270682257272219357118775375472245934978534333124970525297378636845487858976653372476545844219359675658273713850084463568554100647679840820706321480077702925036475944108056747248139600975294322857353480767758477246332229170851966225303340765286335421570503293912668099677617563841932344536407298305348779134451568607117266938169121644451916162538229608327391163548118947045754746812558379728035533429818779414026856560266740902684135655340533772436148213449317114404997572258299630969948716423481236020481718191456826480948751251384597319439926").unwrap(),
        }
    }

    pub fn revocation_credential() -> NonRevocationCredentialSignature {
        NonRevocationCredentialSignature {
            sigma: PointG1::from_string("false AB4BD3CCD0BBBE 5D0014CD3EFF03 6CD367F9FED33C 252866E5D486E0 1BA866F4 F9E47FE0764B75 DF4764388D9975 69CB86E110DD94 BC921065392D76 13DEC0A0 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD").unwrap(),
            c: GroupOrderElement::from_string("FC3A0DC778C70B 307B5E69297040 7D2C9B5223FAB7 C95B27163873DF 2361F8F5").unwrap(),
            vr_prime_prime: GroupOrderElement::from_string("BB6E294A0367F5 955A45802AF9EB 94D643437E1A35 36C57B8D7041F7 460A61B").unwrap(),
            witness_signature: WitnessSignature {
                sigma_i: PointG2::from_string("false 773262BD1D451C 5A035B573DEE78 2706F804B8DC97 76A30C207CF165 1475F5FC B5B704805F6095 47F8DD533F46BC 88B64BEC891EF6 222A37DA413AD3 D102B5F 36DCDF2369ABC3 C9030D39852E5A 35F52211B216B9 6E66D7E02C3809 1C1F6C59 9B2F851D20F66C 9A3600B4B14BA6 7621E4C21370D9 7D1A6CC1F174A7 47AD6AA FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD 0 0 0 0 0").unwrap(),
                u_i: PointG2::from_string("false E9229D3DBE936 83210F4A805C4A 720FDB4CFF40DC 7CD3D3B5206332 D44D4E6 9E9C6ED9DD2643 486DBC7878498E 4B01C9632610E9 A9689488CFFE77 1263FD6B 2882F34A68691C 29D6DBCC76D4B C59186A66B6944 98955D0D9CD9B5 F95C ABD07A01CAF75D FAD6F38FD2C798 F838BEFD25D2A6 4CC8326B14FA64 23DBE9C1 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD 0 0 0 0 0").unwrap(),
                g_i: PointG1::from_string("false C32B36210779E2 79634A59496335 3A64D66D90849E E233C11F521683 241D27B2 D22279343E9D84 928365752F930B 6B3CEDB3E9CFFE 56CA632705FBC3 19E63F01 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45D").unwrap()
            },
            g_i: PointG1::from_string("false C32B36210779E2 79634A59496335 3A64D66D90849E E233C11F521683 241D27B2 D22279343E9D84 928365752F930B 6B3CEDB3E9CFFE 56CA632705FBC3 19E63F01 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD").unwrap(),
            i: 1,
            m2: GroupOrderElement::from_string("7D412BFCA6D402 79B043B875CBB3 701CAE80805BED 1F6D7DD6247DBE 99A79BA").unwrap()
        }
    }

    pub fn proof_request_nonce() -> Nonce { BigNumber::from_dec("1164046393264787986302355").unwrap() }

    pub fn proof() -> Proof {
        Proof {
            proofs: vec![subproof()],
            aggregated_proof: aggregated_proof()
        }
    }

    pub fn subproof() -> SubProof {
        SubProof {
            primary_proof: primary_proof(),
            non_revoc_proof: Some(non_revoc_proof())
        }
    }

    pub fn primary_init_proof() -> PrimaryInitProof {
        PrimaryInitProof {
            eq_proof: primary_equal_init_proof(),
            ge_proofs: vec![primary_ge_init_proof()]
        }
    }

    pub fn primary_equal_init_proof() -> PrimaryEqualInitProof {
        PrimaryEqualInitProof {
            a_prime: BigNumber::from_dec("98083412087941751319175618866781122590479284581673955575977167750706692410363966539978281286793344011091879972831432290802422526482067470902170920129092990385600986791472965375471697144441461408255676746753921940280511603253961628643658731570881924868888461121912555903093239557335266094500337398191254297446694472435235309272346404878193065709626181016470921324208727713741179607609493197480064525167807106030331264425336412564902683911565270575611090930455665500679365584799031661398267309583319680407195946205787285635776773274200578353276068164851510711301539810826484069163335829923344377854229894833727236225073").unwrap(),
            t: BigNumber::from_dec("100330556506505363070765355821065631310222014406433743059536518257275999548193183277653935745702010933399250290375022199647418424660019204615033524352773779318053539749125136486792690681259916650903863021550308696974134411562524591774050899062767720649066796739436273975819274532117521182918777728290296843593274552064662430007463917203206287386754935636371766289366864767716523566749771474918807583672296642444361377700927264774772310103337196474621326803520855024350671435451377509133601181643692585768497035223029241717837378002182177772013841825604270144085274570353058542150547852185340515159203077602883003894263").unwrap(),
            e_tilde: BigNumber::from_dec("162083298053730499878539835193560156486733663622707027216327685550780519347628838870322946818623352681120371349972731968874009673965057322").unwrap(),
            e_prime: BigNumber::from_dec("267566439844950992409607955548161435").unwrap(),
            v_tilde: BigNumber::from_dec("241132863422049783305938184561371219250127488499746090592218003869595412171810997360214885239402274273939963489505434726467041932541499422544431299362364797699330176612923593931231233163363211565697860685967381420219969754969010598350387336530924879073366177641099382257720898488467175132844984811431059686249020737675861448309521855120928434488546976081485578773933300425198911646071284164884533755653094354378714645351464093907890440922615599556866061098147921890790915215227463991346847803620736586839786386846961213073783437136210912924729098636427160258710930323242639624389905049896225019051952864864612421360643655700799102439682797806477476049234033513929028472955119936073490401848509891547105031112859155855833089675654686301183778056755431562224990888545742379494795601542482680006851305864539769704029428620446639445284011289708313620219638324467338840766574612783533920114892847440641473989502440960354573501").unwrap(),
            v_prime: BigNumber::from_dec("-2115144707249068739243261723062812252870944454534082872053033459286924751426195347607094397555133556941852700969777086746714901158847202047337606751521628651908298086227170782647157154116321372155673886018835263106673495734957604044337903406830615176475364251764857232708143767934487980053426056588832846678638207522898863394540311689198910798790636655160635674692367288683036856376480975647831497676623776738942265893251490503327644673288971268274782434155403433485686205559692390603399491350421466914114874556633558925191525252568412893374064244213307649086774654556193745122292685328155798305575095640228291006049089061607308341869733040582797569411808816321130930277817102511757485189961766032400006682964752706737495479544813972016906949899820338859107760717278238944906441448837514897802153705908955191321612691664").unwrap(),
            m_tilde: btreemap![
                "age".to_string() => BigNumber::from_dec("6461691768834933403326572830814516653957231030793837560544354737855803497655300429843454445497126567767486684087006218691084619904526729989680526652503377438786587511370042964338").unwrap(),
                "height".to_string() => BigNumber::from_dec("6461691768834933403326572830814516653957231030793837560544354737855803497655300429843454445497126567767486684087006218691084619904526729989680526652503377438786587511370042964338").unwrap(),
                "master_secret".to_string() => BigNumber::from_dec("67940925789970108743024738273926421512152745397724199848594503731042154269417576665420030681245389493783225644817826683796657351721363490290016166310023506339911751676800452438014771736117676826911321621579680668201191205819012441197794443970687648330757835198888257781967404396196813475280544039772512800509").unwrap(),
                "sex".to_string() => BigNumber::from_dec("6461691768834933403326572830814516653957231030793837560544354737855803497655300429843454445497126567767486684087006218691084619904526729989680526652503377438786587511370042964338").unwrap()
            ],
            m2_tilde: BigNumber::from_dec("14049198043322723487718055550558829839278677959655715165983472882418452212100").unwrap(),
            m2: issuer::mocks::m2(),
        }
    }

    pub fn primary_ge_init_proof() -> PrimaryPredicateGEInitProof {
        PrimaryPredicateGEInitProof {
            c_list: c_list(),
            tau_list: tau_list(),
            u: btreemap![
                "0".to_string() => BigNumber::from_u32(2).unwrap(),
                "1".to_string() => BigNumber::from_u32(1).unwrap(),
                "2".to_string() => BigNumber::from_u32(1).unwrap(),
                "3".to_string() => BigNumber::from_u32(1).unwrap()
            ],
            u_tilde: btreemap![
                "0".to_string() => BigNumber::from_dec("6461691768834933403326572830814516653957231030793837560544354737855803497655300429843454445497126567767486684087006218691084619904526729989680526652503377438786587511370042964338").unwrap(),
                "1".to_string() => BigNumber::from_dec("6461691768834933403326572830814516653957231030793837560544354737855803497655300429843454445497126567767486684087006218691084619904526729989680526652503377438786587511370042964338").unwrap(),
                "2".to_string() => BigNumber::from_dec("6461691768834933403326572830814516653957231030793837560544354737855803497655300429843454445497126567767486684087006218691084619904526729989680526652503377438786587511370042964338").unwrap(),
                "3".to_string() => BigNumber::from_dec("6461691768834933403326572830814516653957231030793837560544354737855803497655300429843454445497126567767486684087006218691084619904526729989680526652503377438786587511370042964338").unwrap()
            ],
            r: btreemap![
                "0".to_string() => BigNumber::from_dec("35131625843806290832574870589259287147303302356085937450138681169270844305658441640899780357851554390281352797472151859633451190372182905767740276000477099644043795107449461869975792759973231599572009337886283219344284767785705740629929916685684025616389621432096690068102576167647117576924865030253290356476886389376786906469624913865400296221181743871195998667521041628188272244376790322856843509187067488962831880868979749045372839549034465343690176440012266969614156191820420452812733264350018673445974099278245215963827842041818557926829011513408602244298030173493359464182527821314118075880620818817455331127028576670474022443879858290").unwrap(),
                "1".to_string() => BigNumber::from_dec("35131625843806290832574870589259287147303302356085937450138681169270844305658441640899780357851554390281352797472151859633451190372182905767740276000477099644043795107449461869975792759973231599572009337886283219344284767785705740629929916685684025616389621432096690068102576167647117576924865030253290356476886389376786906469624913865400296221181743871195998667521041628188272244376790322856843509187067488962831880868979749045372839549034465343690176440012266969614156191820420452812733264350018673445974099278245215963827842041818557926829011513408602244298030173493359464182527821314118075880620818817455331127028576670474022443879858290").unwrap(),
                "2".to_string() => BigNumber::from_dec("35131625843806290832574870589259287147303302356085937450138681169270844305658441640899780357851554390281352797472151859633451190372182905767740276000477099644043795107449461869975792759973231599572009337886283219344284767785705740629929916685684025616389621432096690068102576167647117576924865030253290356476886389376786906469624913865400296221181743871195998667521041628188272244376790322856843509187067488962831880868979749045372839549034465343690176440012266969614156191820420452812733264350018673445974099278245215963827842041818557926829011513408602244298030173493359464182527821314118075880620818817455331127028576670474022443879858290").unwrap(),
                "3".to_string() => BigNumber::from_dec("35131625843806290832574870589259287147303302356085937450138681169270844305658441640899780357851554390281352797472151859633451190372182905767740276000477099644043795107449461869975792759973231599572009337886283219344284767785705740629929916685684025616389621432096690068102576167647117576924865030253290356476886389376786906469624913865400296221181743871195998667521041628188272244376790322856843509187067488962831880868979749045372839549034465343690176440012266969614156191820420452812733264350018673445974099278245215963827842041818557926829011513408602244298030173493359464182527821314118075880620818817455331127028576670474022443879858290").unwrap(),
                "DELTA".to_string() => BigNumber::from_dec("35131625843806290832574870589259287147303302356085937450138681169270844305658441640899780357851554390281352797472151859633451190372182905767740276000477099644043795107449461869975792759973231599572009337886283219344284767785705740629929916685684025616389621432096690068102576167647117576924865030253290356476886389376786906469624913865400296221181743871195998667521041628188272244376790322856843509187067488962831880868979749045372839549034465343690176440012266969614156191820420452812733264350018673445974099278245215963827842041818557926829011513408602244298030173493359464182527821314118075880620818817455331127028576670474022443879858290").unwrap()
            ],
            r_tilde: btreemap![
                "0".to_string() => BigNumber::from_dec("7575191721496255329790454166600075461811327744716122725414003704363002865687003988444075479817517968742651133011723131465916075452356777073568785406106174349810313776328792235352103470770562831584011847").unwrap(),
                "1".to_string() => BigNumber::from_dec("7575191721496255329790454166600075461811327744716122725414003704363002865687003988444075479817517968742651133011723131465916075452356777073568785406106174349810313776328792235352103470770562831584011847").unwrap(),
                "2".to_string() => BigNumber::from_dec("7575191721496255329790454166600075461811327744716122725414003704363002865687003988444075479817517968742651133011723131465916075452356777073568785406106174349810313776328792235352103470770562831584011847").unwrap(),
                "3".to_string() => BigNumber::from_dec("7575191721496255329790454166600075461811327744716122725414003704363002865687003988444075479817517968742651133011723131465916075452356777073568785406106174349810313776328792235352103470770562831584011847").unwrap(),
                "DELTA".to_string() => BigNumber::from_dec("7575191721496255329790454166600075461811327744716122725414003704363002865687003988444075479817517968742651133011723131465916075452356777073568785406106174349810313776328792235352103470770562831584011847").unwrap()
            ],
            alpha_tilde: BigNumber::from_dec("15019832071918025992746443764672619814038193111378331515587108416842661492145380306078894142589602719572721868876278167686578705125701790763532708415180504799241968357487349133908918935916667492626745934151420791943681376124817051308074507483664691464171654649868050938558535412658082031636255658721308264295197092495486870266555635348911182100181878388728256154149188718706253259396012667950509304959158288841789791483411208523521415447630365867367726300467842829858413745535144815825801952910447948288047749122728907853947789264574578039991615261320141035427325207080621563365816477359968627596441227854436137047681372373555472236147836722255880181214889123172703767379416198854131024048095499109158532300492176958443747616386425935907770015072924926418668194296922541290395990933578000312885508514814484100785527174742772860178035596639").unwrap(),
            predicate: predicate(),
            t: btreemap![
                "0".to_string() => BigNumber::from_dec("45887522242738319279196889299657822541046664216878578336808042945125451139840040825561690968347044536762778150971829234756470526941028113519206229570365686216640687082274467331142763005798816544125258315029333996225576228590116929438471586380138255578593270656460773000013070410658372651131563857262584842602791566975020494202579932224190492541604218647017880022281498245192014620970073319585484343100002046222427390264027904112384802330678838982248984244928242410653065668507897204617392989726228386902372021470449499935996026031217415714201826609961699023358066569895830429212309740095153822634031758861936119220850").unwrap(),
                "1".to_string() => BigNumber::from_dec("62315956102176608163522366142177549463854112549383329033516258805992229683393503292402122036458817248822050639564495292440782572586989128395078476713764454421847936760805178292823293985681917429356971501554019491783994090052283433090567843404419170964322848476200015136166024698309879428880371165176020235842186203823876774428642545038271656317783553193239066260476414908819005866786045526592504595564056645215836902612548387633624382205555668857734880668539555354969249653395408944595536691227001815345554058263728667105204897931501062049048598129679732407281705284032102688379350669393498413591687438302475681130500").unwrap(),
                "2".to_string() => BigNumber::from_dec("62315956102176608163522366142177549463854112549383329033516258805992229683393503292402122036458817248822050639564495292440782572586989128395078476713764454421847936760805178292823293985681917429356971501554019491783994090052283433090567843404419170964322848476200015136166024698309879428880371165176020235842186203823876774428642545038271656317783553193239066260476414908819005866786045526592504595564056645215836902612548387633624382205555668857734880668539555354969249653395408944595536691227001815345554058263728667105204897931501062049048598129679732407281705284032102688379350669393498413591687438302475681130500").unwrap(),
                "3".to_string() => BigNumber::from_dec("62315956102176608163522366142177549463854112549383329033516258805992229683393503292402122036458817248822050639564495292440782572586989128395078476713764454421847936760805178292823293985681917429356971501554019491783994090052283433090567843404419170964322848476200015136166024698309879428880371165176020235842186203823876774428642545038271656317783553193239066260476414908819005866786045526592504595564056645215836902612548387633624382205555668857734880668539555354969249653395408944595536691227001815345554058263728667105204897931501062049048598129679732407281705284032102688379350669393498413591687438302475681130500").unwrap(),
                "DELTA".to_string() => BigNumber::from_dec("291567847375395063913000075071320372897694394455273554485157096725853148039190094768570336774949686386596377954571802384435577840746209087388228393480424885165676139209814280070316596727655404361235860371276359547881589483049819087235321499340059751433022683282973723009482722885112400459979181158380556177027546032272025001331081314455185047469222559849942000245305558585614856956998707245141416269449819698175812989579584958553289822513307102506010363715217187612856543152879318103443656469314082864192644475027424764965784594882785423148329118995164696741995413101066871131784641958921631480771696614061925102279").unwrap()
            ]
        }
    }

    pub fn c_list() -> Vec<BigNumber> {
        vec![
            BigNumber::from_dec("45887522242738319279196889299657822541046664216878578336808042945125451139840040825561690968347044536762778150971829234756470526941028113519206229570365686216640687082274467331142763005798816544125258315029333996225576228590116929438471586380138255578593270656460773000013070410658372651131563857262584842602791566975020494202579932224190492541604218647017880022281498245192014620970073319585484343100002046222427390264027904112384802330678838982248984244928242410653065668507897204617392989726228386902372021470449499935996026031217415714201826609961699023358066569895830429212309740095153822634031758861936119220850").unwrap(),
            BigNumber::from_dec("62315956102176608163522366142177549463854112549383329033516258805992229683393503292402122036458817248822050639564495292440782572586989128395078476713764454421847936760805178292823293985681917429356971501554019491783994090052283433090567843404419170964322848476200015136166024698309879428880371165176020235842186203823876774428642545038271656317783553193239066260476414908819005866786045526592504595564056645215836902612548387633624382205555668857734880668539555354969249653395408944595536691227001815345554058263728667105204897931501062049048598129679732407281705284032102688379350669393498413591687438302475681130500").unwrap(),
            BigNumber::from_dec("62315956102176608163522366142177549463854112549383329033516258805992229683393503292402122036458817248822050639564495292440782572586989128395078476713764454421847936760805178292823293985681917429356971501554019491783994090052283433090567843404419170964322848476200015136166024698309879428880371165176020235842186203823876774428642545038271656317783553193239066260476414908819005866786045526592504595564056645215836902612548387633624382205555668857734880668539555354969249653395408944595536691227001815345554058263728667105204897931501062049048598129679732407281705284032102688379350669393498413591687438302475681130500").unwrap(),
            BigNumber::from_dec("62315956102176608163522366142177549463854112549383329033516258805992229683393503292402122036458817248822050639564495292440782572586989128395078476713764454421847936760805178292823293985681917429356971501554019491783994090052283433090567843404419170964322848476200015136166024698309879428880371165176020235842186203823876774428642545038271656317783553193239066260476414908819005866786045526592504595564056645215836902612548387633624382205555668857734880668539555354969249653395408944595536691227001815345554058263728667105204897931501062049048598129679732407281705284032102688379350669393498413591687438302475681130500").unwrap(),
            BigNumber::from_dec("291567847375395063913000075071320372897694394455273554485157096725853148039190094768570336774949686386596377954571802384435577840746209087388228393480424885165676139209814280070316596727655404361235860371276359547881589483049819087235321499340059751433022683282973723009482722885112400459979181158380556177027546032272025001331081314455185047469222559849942000245305558585614856956998707245141416269449819698175812989579584958553289822513307102506010363715217187612856543152879318103443656469314082864192644475027424764965784594882785423148329118995164696741995413101066871131784641958921631480771696614061925102279").unwrap()
        ]
    }

    pub fn tau_list() -> Vec<BigNumber> {
        vec![
            BigNumber::from_dec("5775121804650533823818346109878200308084781685988689127068629784345714918707364965739960046309281573960723093575143691445129397777229699708529613711858683818596049039395895397979196006166250809423299924814724312736887027886538329236480587585444715620091397155035796560957731378738546612124259225499365130571476395915632168929135402745717611100719373213184156349557204064052101034800892299754720256826852528224133723052224077506099451460290719285594534346131320356862314624307423147523405581318080552480925002043929802539664491150990310643844782277058104451329443287733260065635985062237748146923600356379728377136117").unwrap(),
            BigNumber::from_dec("5775121804650533823818346109878200308084781685988689127068629784345714918707364965739960046309281573960723093575143691445129397777229699708529613711858683818596049039395895397979196006166250809423299924814724312736887027886538329236480587585444715620091397155035796560957731378738546612124259225499365130571476395915632168929135402745717611100719373213184156349557204064052101034800892299754720256826852528224133723052224077506099451460290719285594534346131320356862314624307423147523405581318080552480925002043929802539664491150990310643844782277058104451329443287733260065635985062237748146923600356379728377136117").unwrap(),
            BigNumber::from_dec("5775121804650533823818346109878200308084781685988689127068629784345714918707364965739960046309281573960723093575143691445129397777229699708529613711858683818596049039395895397979196006166250809423299924814724312736887027886538329236480587585444715620091397155035796560957731378738546612124259225499365130571476395915632168929135402745717611100719373213184156349557204064052101034800892299754720256826852528224133723052224077506099451460290719285594534346131320356862314624307423147523405581318080552480925002043929802539664491150990310643844782277058104451329443287733260065635985062237748146923600356379728377136117").unwrap(),
            BigNumber::from_dec("5775121804650533823818346109878200308084781685988689127068629784345714918707364965739960046309281573960723093575143691445129397777229699708529613711858683818596049039395895397979196006166250809423299924814724312736887027886538329236480587585444715620091397155035796560957731378738546612124259225499365130571476395915632168929135402745717611100719373213184156349557204064052101034800892299754720256826852528224133723052224077506099451460290719285594534346131320356862314624307423147523405581318080552480925002043929802539664491150990310643844782277058104451329443287733260065635985062237748146923600356379728377136117").unwrap(),
            BigNumber::from_dec("5775121804650533823818346109878200308084781685988689127068629784345714918707364965739960046309281573960723093575143691445129397777229699708529613711858683818596049039395895397979196006166250809423299924814724312736887027886538329236480587585444715620091397155035796560957731378738546612124259225499365130571476395915632168929135402745717611100719373213184156349557204064052101034800892299754720256826852528224133723052224077506099451460290719285594534346131320356862314624307423147523405581318080552480925002043929802539664491150990310643844782277058104451329443287733260065635985062237748146923600356379728377136117").unwrap(),
            BigNumber::from_dec("39043573194062843188289697546611918107532805117598645832449214642534318612913845320753679689521059255751382337240024528644059256642047307130598641485950677406033282508825181195431402683575205469208293880834411410932501752023243962782277848107825674374118905568649140719993402086278461408304318382071709512982618346808542261941396861110469854677713167733150195896676327031741587679499297080573095025981559137568818554002281801202668335168470352703136379783553438827500403708164371168076378529555004001784921284830315500135101727618169966870761712270273123073354380462035137352013253457506110569108524475928798373175939").unwrap()
        ]
    }

    pub fn m_tilde() -> BTreeMap<String, BigNumber> {
        btreemap![
            "master_secret".to_string() => BigNumber::from_dec("67940925789970108743024738273926421512152745397724199848594503731042154269417576665420030681245389493783225644817826683796657351721363490290016166310023506339911751676800452438014771736117676826911321621579680668201191205819012441197794443970687648330757835198888257781967404396196813475280544039772512800509").unwrap(),
            "height".to_string() => BigNumber::from_dec("6461691768834933403326572830814516653957231030793837560544354737855803497655300429843454445497126567767486684087006218691084619904526729989680526652503377438786587511370042964338").unwrap(),
            "age".to_string() => BigNumber::from_dec("6461691768834933403326572830814516653957231030793837560544354737855803497655300429843454445497126567767486684087006218691084619904526729989680526652503377438786587511370042964338").unwrap(),
            "sex".to_string() => BigNumber::from_dec("6461691768834933403326572830814516653957231030793837560544354737855803497655300429843454445497126567767486684087006218691084619904526729989680526652503377438786587511370042964338").unwrap()
        ]
    }

    pub fn eq_proof() -> PrimaryEqualProof {
        PrimaryEqualProof {
            revealed_attrs: btreemap!["name".to_string() => BigNumber::from_dec("66682250590915135919393234675423675079281389286836524491448775067034910960723").unwrap()],
            a_prime: BigNumber::from_dec("98083412087941751319175618866781122590479284581673955575977167750706692410363966539978281286793344011091879972831432290802422526482067470902170920129092990385600986791472965375471697144441461408255676746753921940280511603253961628643658731570881924868888461121912555903093239557335266094500337398191254297446694472435235309272346404878193065709626181016470921324208727713741179607609493197480064525167807106030331264425336412564902683911565270575611090930455665500679365584799031661398267309583319680407195946205787285635776773274200578353276068164851510711301539810826484069163335829923344377854229894833727236225073").unwrap(),
            e: BigNumber::from_dec("162083298053730499878539845022414093116291829149769650815162760407650123629230156197707443039104041707537615796903962170805909712864412792").unwrap(),
            v: BigNumber::from_dec("241132863422049783305938106863105343928758159712875655208147506851139555325051423517258172055216134383906932651994543306685112210786262889479691309357852570352505675146606419910627247162997802174662039269758277612755992529430063768594211222875946000061228207520004094952997142370947975621859648372639523011419190678994147458173378587546356569421633199397836629352472494037450864091145969859153838694089755748330211990472566913007681989381371473053992667784854957504510828388143814069630583233315743609346154581049275922052638373286336670365322524123871308762464261782049192133342897048661664260069415801661825656292939897526620181579126585010052820354737539654849464757210421731840595591024108171639296748566749576324910789891056979726425069465289491561208276506963437318050058739068411185088353929700107125604776405891141731817869406484823288772596691772956496407364530537457835938003408441351158062642671144532114200733").unwrap(),
            m: btreemap![
                "age".to_string() => BigNumber::from_dec("6461691768834933403326572830814516653957231030793837560544354737855803497655300429843454445497126568685843068983890896122000977852186661939211990733462807944627807336518424313388").unwrap(),
                "height".to_string() => BigNumber::from_dec("6461691768834933403326572830814516653957231030793837560544354737855803497655300429843454445497126574195981378365198960707499125538146253636400775219219390979675126287408712407688").unwrap(),
                "master_secret".to_string() => BigNumber::from_dec("67940925789970108743024738273926421512152745397724199848594503731042154269417576665420030681245389493783225644817826683796657351721363490290016166310023507132564589104990678182299219306228446316250328302891742457726158298612477188160335451477126201081347058945471957804431939288091328124225198960258432684399").unwrap(),
                "sex".to_string() => BigNumber::from_dec("6461691768834933403326575020439114193500962122447442182375470664835531264262887123435773676729731478629261405277091910956944655533226659560277758686479462667297473396368211269136").unwrap()
            ],
            m2: BigNumber::from_dec("2553030889054034879941219523536672152702359185828546810612564355745759663351165380563310203986319611277915826660660011443138240248924364893067083241825560").unwrap()
        }
    }

    pub fn aggregated_proof() -> AggregatedProof {
        AggregatedProof {
            c_hash: BigNumber::from_dec("36734255395875387097236654317906397277981258563238377220233648793005935253962").unwrap(),
            c_list: vec![
                    vec![4, 15, 40, 221, 185, 162, 221, 161, 254, 176, 57, 207, 14, 190, 121, 73, 122, 188, 36, 147, 47, 72, 242, 193, 17, 241, 109, 66, 73, 52, 131, 185, 112, 8, 84, 230, 192, 255, 105, 116, 83, 170, 71, 219, 182, 149, 126, 9, 180, 11, 152, 255, 241, 228, 123, 229, 108, 200, 210, 17, 231, 83, 158, 93, 114, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    vec![4, 28, 250, 35, 217, 251, 183, 160, 58, 131, 37, 66, 222, 201, 38, 193, 138, 177, 229, 88, 130, 59, 53, 75, 226, 216, 166, 7, 23, 245, 57, 128, 209, 19, 86, 133, 7, 82, 39, 63, 42, 66, 66, 228, 69, 93, 156, 108, 147, 249, 138, 148, 56, 223, 216, 102, 204, 90, 134, 78, 135, 164, 254, 181, 71, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    vec![4, 2, 107, 241, 180, 5, 3, 229, 146, 229, 80, 96, 229, 210, 175, 238, 65, 126, 113, 152, 143, 49, 231, 47, 144, 156, 239, 75, 149, 169, 140, 112, 107, 14, 249, 31, 191, 70, 33, 146, 43, 37, 116, 188, 36, 78, 23, 15, 36, 90, 97, 103, 149, 137, 1, 69, 230, 214, 159, 35, 217, 75, 217, 129, 101, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    vec![4, 36, 173, 234, 183, 207, 24, 100, 172, 217, 41, 238, 60, 232, 136, 84, 41, 129, 223, 88, 29, 111, 132, 214, 99, 54, 252, 215, 160, 195, 248, 53, 127, 29, 196, 61, 22, 192, 127, 209, 129, 74, 115, 208, 177, 10, 177, 7, 80, 197, 209, 72, 58, 159, 244, 141, 207, 108, 59, 255, 71, 233, 195, 77, 157, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    vec![21, 39, 33, 136, 4, 35, 81, 232, 221, 50, 46, 137, 180, 37, 68, 198, 205, 92, 210, 203, 242, 91, 190, 222, 21, 10, 99, 147, 17, 10, 254, 238, 25, 87, 208, 140, 223, 63, 52, 47, 159, 24, 121, 222, 233, 36, 55, 227, 15, 72, 28, 2, 160, 137, 120, 159, 50, 140, 82, 152, 35, 213, 100, 213, 21, 84, 190, 96, 165, 232, 146, 117, 252, 253, 26, 247, 179, 48, 76, 241, 74, 64, 22, 232, 177, 232, 212, 64, 161, 198, 27, 223, 164, 122, 206, 11, 27, 52, 163, 239, 155, 71, 87, 221, 17, 160, 128, 70, 123, 232, 177, 38, 18, 80, 72, 147, 150, 193, 146, 127, 155, 135, 110, 222, 23, 227, 56, 131],
                    vec![28, 237, 222, 213, 234, 194, 241, 249, 239, 157, 147, 62, 11, 203, 25, 150, 180, 231, 63, 84, 153, 26, 206, 79, 58, 75, 86, 61, 31, 109, 67, 59, 19, 57, 174, 176, 165, 87, 167, 78, 193, 53, 45, 106, 121, 182, 87, 79, 57, 63, 119, 21, 170, 135, 99, 137, 169, 190, 232, 179, 145, 21, 93, 55, 7, 5, 222, 148, 253, 230, 147, 253, 12, 149, 89, 159, 207, 219, 48, 75, 105, 67, 3, 121, 81, 145, 202, 199, 118, 73, 28, 23, 237, 177, 247, 146, 28, 119, 71, 155, 232, 63, 22, 240, 112, 247, 180, 192, 176, 234, 116, 233, 207, 154, 224, 115, 177, 236, 32, 186, 139, 159, 134, 118, 56, 155, 200, 165],
                    vec![25, 93, 0, 27, 250, 169, 144, 36, 216, 143, 51, 252, 92, 156, 171, 245, 170, 182, 90, 155, 59, 0, 138, 84, 6, 90, 215, 215, 45, 47, 250, 15, 8, 252, 188, 97, 242, 241, 207, 232, 195, 100, 252, 182, 254, 227, 217, 16, 251, 87, 121, 96, 101, 204, 185, 43, 67, 237, 160, 143, 247, 10, 52, 33, 22, 241, 186, 108, 67, 227, 145, 13, 52, 67, 22, 238, 126, 129, 54, 68, 159, 71, 179, 147, 198, 12, 199, 0, 9, 92, 232, 40, 178, 34, 172, 187, 16, 6, 17, 84, 137, 147, 242, 238, 8, 88, 151, 254, 178, 149, 190, 46, 43, 249, 133, 164, 15, 77, 210, 177, 153, 235, 51, 12, 39, 106, 207, 77],
                    vec![1, 39, 90, 159, 247, 134, 155, 5, 88, 27, 171, 241, 196, 35, 255, 144, 167, 205, 110, 43, 253, 22, 127, 201, 227, 133, 192, 22, 170, 22, 87, 93, 158, 89, 203, 59, 80, 13, 46, 104, 216, 77, 111, 122, 96, 111, 17, 125, 104, 208, 139, 2, 58, 245, 217, 152, 50, 239, 205, 102, 250, 37, 214, 12, 118, 204, 99, 233, 215, 53, 226, 50, 120, 208, 61, 98, 49, 48, 182, 109, 235, 86, 184, 164, 189, 9, 239, 252, 27, 143, 213, 131, 62, 193, 197, 184, 236, 1, 114, 86, 61, 69, 229, 65, 236, 6, 164, 208, 105, 20, 4, 125, 63, 43, 66, 207, 112, 61, 131, 130, 251, 242, 175, 253, 233, 43, 226, 205, 239, 89, 235, 104, 225, 96, 209, 69, 65, 134, 56, 180, 120, 53, 125, 191, 111, 29, 250, 153, 158, 169, 250, 139, 37, 229, 207, 126, 38, 150, 65, 39, 219, 58, 180, 114, 204, 0, 188, 164, 188, 53, 186, 230, 181, 48, 23, 122, 106, 107, 31, 221, 142, 237, 129, 35, 23, 11, 67, 85, 177, 166, 190, 19, 148, 238, 223, 206, 211, 40, 183, 123, 203, 75, 88, 159, 0, 52, 8, 138, 192, 144, 97, 177, 180, 212, 45, 91, 237, 86, 36, 161, 180, 47, 61, 239, 155, 44, 187, 162, 124, 178, 38, 252, 167, 166, 147, 27, 156, 115, 105, 218, 24, 163, 214, 183, 10, 216, 25, 222, 187, 243, 123, 232, 197, 29, 30, 133, 47],
                    vec![2, 143, 29, 183, 142, 29, 117, 172, 90, 120, 157, 84, 126, 194, 34, 226, 142, 152, 56, 25, 37, 145, 30, 102, 45, 73, 131, 55, 43, 33, 138, 174, 97, 250, 234, 215, 49, 197, 194, 21, 16, 58, 156, 69, 108, 214, 139, 71, 141, 205, 160, 47, 5, 83, 143, 58, 171, 150, 166, 180, 217, 193, 236, 108, 9, 114, 7, 122, 65, 212, 150, 227, 168, 216, 175, 141, 82, 50, 62, 205, 178, 69, 100, 205, 85, 18, 173, 25, 186, 149, 195, 119, 169, 165, 107, 28, 146, 17, 36, 101, 125, 158, 127, 249, 20, 112, 227, 118, 58, 128, 101, 249, 120, 152, 147, 121, 27, 78, 242, 138, 154, 226, 196, 27, 77, 5, 4, 216, 72, 225, 167, 102, 226, 67, 152, 119, 85, 81, 71, 131, 91, 113, 74, 152, 140, 2, 9, 84, 197, 97, 38, 50, 181, 26, 228, 252, 24, 254, 158, 80, 224, 106, 49, 226, 255, 1, 143, 118, 250, 155, 19, 104, 154, 35, 56, 121, 94, 16, 163, 213, 225, 10, 32, 125, 87, 116, 110, 103, 127, 251, 212, 227, 41, 230, 28, 143, 94, 149, 46, 40, 77, 28, 247, 40, 159, 105, 52, 178, 46, 150, 0, 207, 111, 143, 98, 152, 79, 218, 176, 242, 18, 224, 230, 135, 74, 1, 50, 250, 138, 126, 89, 79, 199, 177, 220, 199, 224, 44, 89, 142, 224, 169, 164, 169, 32, 130, 82, 178, 156, 233, 197, 157, 11, 35, 212, 100, 222],
                    vec![1, 15, 91, 146, 224, 9, 222, 151, 66, 32, 116, 1, 233, 133, 250, 79, 40, 227, 195, 180, 173, 37, 206, 231, 172, 177, 61, 134, 178, 158, 135, 167, 46, 154, 181, 100, 54, 45, 107, 102, 106, 122, 232, 12, 146, 63, 125, 166, 247, 128, 230, 126, 254, 243, 2, 152, 19, 217, 41, 107, 207, 76, 225, 205, 77, 103, 18, 137, 145, 20, 198, 94, 106, 172, 10, 166, 45, 232, 29, 179, 185, 31, 205, 57, 247, 223, 166, 229, 216, 229, 45, 22, 227, 20, 16, 100, 198, 55, 14, 90, 77, 144, 110, 175, 218, 120, 192, 139, 20, 130, 214, 206, 135, 37, 223, 14, 172, 26, 93, 156, 252, 180, 27, 40, 236, 249, 248, 116, 160, 47, 123, 249, 53, 213, 143, 1, 104, 171, 151, 211, 183, 99, 208, 11, 24, 191, 172, 57, 175, 244, 53, 223, 168, 209, 247, 79, 193, 87, 140, 40, 254, 5, 65, 189, 224, 92, 103, 23, 219, 89, 171, 25, 153, 224, 147, 14, 78, 26, 3, 17, 196, 1, 250, 177, 107, 140, 67, 176, 3, 122, 233, 14, 232, 72, 44, 21, 142, 141, 54, 33, 165, 12, 101, 4, 55, 145, 60, 16, 152, 214, 42, 204, 158, 109, 12, 115, 230, 254, 45, 162, 84, 120, 147, 218, 228, 149, 99, 209, 140, 39, 253, 234, 247, 123, 183, 239, 253, 84, 87, 147, 5, 65, 6, 12, 214, 164, 76, 237, 174, 189, 211, 200, 214, 184, 3, 148, 30],
                    vec![112, 136, 12, 69, 162, 232, 90, 39, 235, 18, 179, 156, 164, 229, 85, 100, 26, 106, 16, 229, 75, 96, 231, 27, 156, 137, 219, 80, 17, 195, 30, 191, 190, 138, 125, 73, 177, 90, 163, 12, 180, 146, 47, 156, 132, 26, 89, 24, 220, 151, 226, 24, 28, 129, 73, 218, 11, 220, 178, 114, 190, 130, 222, 96, 72, 176, 8, 117, 64, 241, 48, 247, 228, 125, 207, 40, 106, 93, 164, 236, 52, 112, 12, 135, 179, 4, 96, 117, 48, 203, 123, 59, 231, 150, 44, 90, 79, 75, 55, 150, 253, 239, 148, 119, 50, 177, 246, 104, 156, 205, 13, 17, 71, 238, 149, 88, 77, 68, 112, 130, 22, 55, 141, 34, 170, 133, 238, 134, 40, 180, 212, 195, 132, 28, 175, 208, 235, 145, 228, 79, 112, 75, 235, 96, 140, 111, 102, 236, 203, 3, 239, 236, 189, 193, 33, 253, 226, 1, 124, 37, 36, 173, 125, 187, 109, 44, 31, 30, 4, 139, 125, 243, 73, 108, 109, 105, 138, 128, 140, 106, 54, 52, 103, 104, 152, 27, 185, 6, 150, 105, 151, 124, 67, 25, 221, 161, 13, 97, 20, 111, 129, 255, 95, 56, 137, 141, 149, 168, 245, 105, 31, 81, 11, 90, 166, 141, 188, 69, 85, 126, 201, 38, 128, 158, 9, 123, 132, 118, 22, 107, 212, 173, 122, 106, 237, 109, 26, 57, 89, 218, 173, 97, 101, 51, 224, 36, 201, 160, 57, 55, 226, 68, 191, 183, 151, 187],
                    vec![1, 36, 34, 217, 148, 4, 116, 74, 94, 18, 213, 219, 10, 186, 52, 205, 246, 171, 246, 1, 244, 105, 203, 134, 211, 51, 152, 9, 108, 39, 0, 113, 95, 86, 147, 173, 92, 23, 194, 206, 112, 210, 224, 121, 226, 110, 1, 204, 123, 63, 201, 221, 146, 109, 204, 16, 122, 199, 50, 172, 197, 5, 59, 20, 59, 95, 59, 238, 162, 75, 237, 81, 209, 48, 71, 105, 213, 49, 201, 238, 156, 7, 101, 149, 230, 249, 108, 40, 77, 5, 187, 204, 144, 62, 205, 225, 62, 214, 80, 56, 72, 149, 75, 92, 185, 5, 25, 26, 23, 221, 25, 133, 23, 163, 72, 142, 5, 153, 67, 129, 250, 23, 39, 23, 237, 137, 255, 34, 2, 1, 105, 74, 116, 228, 165, 214, 216, 139, 213, 184, 177, 19, 169, 74, 31, 7, 77, 177, 2, 116, 104, 168, 35, 53, 201, 162, 150, 123, 236, 5, 81, 197, 160, 209, 146, 5, 237, 191, 13, 153, 64, 230, 61, 155, 254, 118, 112, 135, 162, 210, 217, 243, 5, 66, 204, 161, 190, 190, 115, 80, 246, 130, 7, 174, 243, 124, 44, 92, 215, 31, 23, 143, 81, 85, 51, 175, 208, 232, 240, 242, 151, 194, 42, 222, 111, 32, 80, 185, 17, 60, 52, 147, 62, 135, 81, 196, 164, 62, 115, 96, 221, 14, 186, 23, 172, 38, 29, 41, 145, 13, 191, 8, 34, 174, 70, 10, 204, 109, 17, 144, 112, 200, 228, 239, 63, 122, 91],
                    vec![67, 166, 56, 239, 86, 131, 23, 62, 130, 21, 236, 196, 219, 166, 34, 35, 168, 88, 154, 22, 214, 47, 37, 232, 17, 105, 61, 39, 233, 155, 167, 46, 22, 162, 113, 91, 17, 72, 56, 236, 241, 15, 90, 78, 115, 180, 156, 67, 56, 51, 21, 72, 122, 185, 199, 19, 77, 132, 139, 104, 228, 230, 152, 144, 89, 95, 196, 14, 176, 93, 68, 157, 116, 188, 93, 66, 174, 130, 76, 156, 87, 2, 246, 180, 28, 151, 181, 73, 67, 76, 82, 79, 121, 98, 46, 85, 140, 67, 19, 68, 188, 208, 45, 55, 217, 107, 124, 73, 45, 112, 164, 133, 58, 102, 109, 239, 203, 143, 40, 118, 135, 152, 199, 50, 91, 117, 42, 196, 176, 113, 152, 154, 149, 117, 214, 174, 54, 187, 79, 190, 113, 15, 86, 150, 242, 6, 8, 148, 205, 3, 127, 18, 251, 184, 115, 16, 152, 66, 15, 53, 74, 152, 131, 162, 211, 99, 17, 106, 57, 112, 200, 253, 252, 209, 157, 64, 54, 103, 126, 101, 173, 203, 239, 201, 163, 181, 66, 145, 207, 32, 191, 21, 67, 107, 58, 237, 182, 17, 201, 134, 217, 112, 123, 85, 239, 156, 132, 27, 74, 48, 228, 212, 24, 241, 12, 139, 152, 237, 130, 25, 128, 153, 128, 34, 253, 163, 123, 169, 154, 10, 73, 35, 23, 50, 123, 133, 240, 140, 19, 97, 176, 4, 45, 175, 234, 32, 68, 17, 105, 45, 50, 74, 82, 219, 233, 179]
            ]
        }
    }

    pub fn ge_proof() -> PrimaryPredicateGEProof {
        PrimaryPredicateGEProof {
            u: btreemap![
                "0".to_string() => BigNumber::from_dec("6461691768834933403326572830814516653957231030793837560544354737855803497655300429843454445497126567840955194878756992885557928540339524545643043778980131879253885097381913472262").unwrap(),
                "1".to_string() => BigNumber::from_dec("6461691768834933403326572830814516653957231030793837560544354737855803497655300429843454445497126567804220939482881605788321274222433127267661785215741754659020236304375978218300").unwrap(),
                "2".to_string() => BigNumber::from_dec("6461691768834933403326572830814516653957231030793837560544354737855803497655300429843454445497126567804220939482881605788321274222433127267661785215741754659020236304375978218300").unwrap(),
                "3".to_string() => BigNumber::from_dec("6461691768834933403326572830814516653957231030793837560544354737855803497655300429843454445497126567804220939482881605788321274222433127267661785215741754659020236304375978218300").unwrap()
            ],
            r: btreemap![
                "0".to_string() => BigNumber::from_dec("1290534116218716438320066296998198963418131286408035380529548316941923398410560113108756798582290425306108955869685395227366233856654792649735912224097611558139789753950408584482847689838795587330987971669161415485990020598912935103565044825010972005166748548886258351774424917360400285403279510922304340427648959687851483846826461162205002537903920975405118476175947131589471870709350253892921592871530107416727676553006745099259773619545623692882161367026324069754047935205197405410348516798706677778839870157117614346079006190506251578369476561129106768237088298646216941156526296494287589126706469975404040325634910290392295066762902049752200300569175726527074032536078980610848985062237596740068429384399305056827").unwrap(),
                "1".to_string() => BigNumber::from_dec("1290534116218716438320066296998198963418131286408035380529548316941923398410560113108756798582290425306108955869685395227366233856654792649735912224097611558139789753950408584482847689838795587330987971669161415485990020598912935103565044825010972005166748548886258351774424917360400285403279510922304340427648959687851483846826461162205002537903920975405118476175947131589471870709350253892921592871530107416727676553006745099259773619545623692882161367026324069754047935205197405410348516798706677778839870157117614346079006190506251578369476561129106768237088298646216941156526296494287589126706469975404040325634910290392295066762902049752200300569175726527074032536078980610848985062237596740068429384399305056827").unwrap(),
                "2".to_string() => BigNumber::from_dec("1290534116218716438320066296998198963418131286408035380529548316941923398410560113108756798582290425306108955869685395227366233856654792649735912224097611558139789753950408584482847689838795587330987971669161415485990020598912935103565044825010972005166748548886258351774424917360400285403279510922304340427648959687851483846826461162205002537903920975405118476175947131589471870709350253892921592871530107416727676553006745099259773619545623692882161367026324069754047935205197405410348516798706677778839870157117614346079006190506251578369476561129106768237088298646216941156526296494287589126706469975404040325634910290392295066762902049752200300569175726527074032536078980610848985062237596740068429384399305056827").unwrap(),
                "3".to_string() => BigNumber::from_dec("1290534116218716438320066296998198963418131286408035380529548316941923398410560113108756798582290425306108955869685395227366233856654792649735912224097611558139789753950408584482847689838795587330987971669161415485990020598912935103565044825010972005166748548886258351774424917360400285403279510922304340427648959687851483846826461162205002537903920975405118476175947131589471870709350253892921592871530107416727676553006745099259773619545623692882161367026324069754047935205197405410348516798706677778839870157117614346079006190506251578369476561129106768237088298646216941156526296494287589126706469975404040325634910290392295066762902049752200300569175726527074032536078980610848985062237596740068429384399305056827").unwrap(),
                "DELTA".to_string() => BigNumber::from_dec("1290534116218716438320066296998198963418131286408035380529548316941923398410560113108756798582290425306108955869685395227366233856654792649735912224097611558139789753950408584482847689838795587330987971669161415485990020598912935103565044825010972005166748548886258351774424917360400285403279510922304340427648959687851483846826461162205002537903920975405118476175947131589471870709350253892921592871530107416727676553006745099259773619545623692882161367026324069754047935205197405410348516798706677778839870157117614346079006190506251578369476561129106768237088298646216941156526296494287589126706469975404040325634910290392295066762902049752200300569175726527074032536078980610848985062237596740068429384399305056827").unwrap()
            ],
            mj: BigNumber::from_dec("6461691768834933403326572830814516653957231030793837560544354737855803497655300429843454445497126568685843068983890896122000977852186661939211990733462807944627807336518424313388").unwrap(),
            alpha: BigNumber::from_dec("15019832071918025992746443764672619814038193111378331515587108416842661492145380306078894142589602719572721868876278167681416568660826925010252443227187708945569443211855207611790725668148973898984505481716393597614519674900381227829332926574199756037552484050924402042168089180098923015834621320789917504940014743171534983589909973404951099704530137974468076854105300698039259063850979260852809635517557147228671747794193846812925576696224430480061881651647832678242729843914670911122013426552560465450646733551042536367827359597663871827964634864281046557244830435551976095260520198343776886775651606213042069852854661258195991607677409638706741404211201971511463923164836371216756693954129390497870798334804568467571644016689534705243099458035791551892923659589930766121987359966906294865968827326523859020776548628352137573907151416719").unwrap(),
            t: btreemap![
                "0".to_string() => BigNumber::from_dec("45887522242738319279196889299657822541046664216878578336808042945125451139840040825561690968347044536762778150971829234756470526941028113519206229570365686216640687082274467331142763005798816544125258315029333996225576228590116929438471586380138255578593270656460773000013070410658372651131563857262584842602791566975020494202579932224190492541604218647017880022281498245192014620970073319585484343100002046222427390264027904112384802330678838982248984244928242410653065668507897204617392989726228386902372021470449499935996026031217415714201826609961699023358066569895830429212309740095153822634031758861936119220850").unwrap(),
                "1".to_string() => BigNumber::from_dec("62315956102176608163522366142177549463854112549383329033516258805992229683393503292402122036458817248822050639564495292440782572586989128395078476713764454421847936760805178292823293985681917429356971501554019491783994090052283433090567843404419170964322848476200015136166024698309879428880371165176020235842186203823876774428642545038271656317783553193239066260476414908819005866786045526592504595564056645215836902612548387633624382205555668857734880668539555354969249653395408944595536691227001815345554058263728667105204897931501062049048598129679732407281705284032102688379350669393498413591687438302475681130500").unwrap(),
                "2".to_string() => BigNumber::from_dec("62315956102176608163522366142177549463854112549383329033516258805992229683393503292402122036458817248822050639564495292440782572586989128395078476713764454421847936760805178292823293985681917429356971501554019491783994090052283433090567843404419170964322848476200015136166024698309879428880371165176020235842186203823876774428642545038271656317783553193239066260476414908819005866786045526592504595564056645215836902612548387633624382205555668857734880668539555354969249653395408944595536691227001815345554058263728667105204897931501062049048598129679732407281705284032102688379350669393498413591687438302475681130500").unwrap(),
                "3".to_string() => BigNumber::from_dec("62315956102176608163522366142177549463854112549383329033516258805992229683393503292402122036458817248822050639564495292440782572586989128395078476713764454421847936760805178292823293985681917429356971501554019491783994090052283433090567843404419170964322848476200015136166024698309879428880371165176020235842186203823876774428642545038271656317783553193239066260476414908819005866786045526592504595564056645215836902612548387633624382205555668857734880668539555354969249653395408944595536691227001815345554058263728667105204897931501062049048598129679732407281705284032102688379350669393498413591687438302475681130500").unwrap(),
                "DELTA".to_string() => BigNumber::from_dec("291567847375395063913000075071320372897694394455273554485157096725853148039190094768570336774949686386596377954571802384435577840746209087388228393480424885165676139209814280070316596727655404361235860371276359547881589483049819087235321499340059751433022683282973723009482722885112400459979181158380556177027546032272025001331081314455185047469222559849942000245305558585614856956998707245141416269449819698175812989579584958553289822513307102506010363715217187612856543152879318103443656469314082864192644475027424764965784594882785423148329118995164696741995413101066871131784641958921631480771696614061925102279").unwrap()
            ],
            predicate: predicate()
        }
    }

    pub fn primary_proof() -> PrimaryProof {
        PrimaryProof {
            eq_proof: eq_proof(),
            ge_proofs: vec![ge_proof()]
        }
    }

    pub fn init_non_revocation_proof() -> NonRevocInitProof {
        NonRevocInitProof {
            c_list_params: NonRevocProofXList {
                rho: GroupOrderElement::from_string("8A2A9CF5B0ECAC B57AC31CEC0D03 AFB7E29BE4E304 D304045A4F0E92 1D9432AC").unwrap(),
                r: GroupOrderElement::from_string("24B4BBA5DB9933 ADF916991A1C40 8BA4C20EC221EA A8111DB183D0C 2501A88F").unwrap(),
                r_prime: GroupOrderElement::from_string("3B234DB3441D4 996B163E14A602 43726262AB3B57 CA17B50750375E 1091EF19").unwrap(),
                r_prime_prime: GroupOrderElement::from_string("D5055082A70A68 CE92BDFF8F4538 2343CAB09F57CE D2FA395CA8BBE5 1AC83CB0").unwrap(),
                r_prime_prime_prime: GroupOrderElement::from_string("D34948AE816A31 ABC60A7E4643F8 BF3048382937D3 7112FA3BBE8FC2 18593C29").unwrap(),
                o: GroupOrderElement::from_string("27F9DA9768BC96 426652C38F6DA7 BA53401DBB1C77 EB4299D372EA58 198A91AD").unwrap(),
                o_prime: GroupOrderElement::from_string("259B3946C9D4A9 B30A8FF71E1231 4C66E9F14FB2A6 732A14ED70AA89 16AC4873").unwrap(),
                m: GroupOrderElement::from_string("E4982647B10AEA DD01B4ACC63386 E2EE429481583C F25EF18A496A45 1C711A92").unwrap(),
                m_prime: GroupOrderElement::from_string("110DF73182F127 D09865A68A74A5 E7E29C6E7423F2 CC41CF3AD171A5 1C9D01A3").unwrap(),
                t: GroupOrderElement::from_string("ADAD18FDDE30C5 AEE10358FF21C8 D475F22EE97DC0 C8C6E60B0E46C2 EB3CF17").unwrap(),
                t_prime: GroupOrderElement::from_string("A07F08476E5AB9 E159C1517FA490 3F58E661D36607 2FC10CD7678555 314899F").unwrap(),
                m2: GroupOrderElement::from_string("7D412BFCA6D402 79B043B875CBB3 701CAE80805BED 1F6D7DD6247DBE 99A79BA").unwrap(),
                s: GroupOrderElement::from_string("B009D6601604D9 2CC464DFBFBD0D 2CD0A782F3618 74742156EA34EE 7D1132A").unwrap(),
                c: GroupOrderElement::from_string("FC3A0DC778C70B 307B5E69297040 7D2C9B5223FAB7 C95B27163873DF 2361F8F").unwrap()
            },
            tau_list_params: NonRevocProofXList {
                rho: GroupOrderElement::from_string("2F1C9EA7FAAB4C 71826D0041F7A1 58142621690111 4598BDE2886E9F 22674C7D").unwrap(),
                r: GroupOrderElement::from_string("DFBA527CDEB256 E575333F20E87 2E12F8BC58EB82 80B6D7592BECCC 177AD1C0").unwrap(),
                r_prime: GroupOrderElement::from_string("E11E4E48BC4AC3 B6D4DA526AFA95 CE2FF60BD8B50D 136F4DB647040F 1C6D18A").unwrap(),
                r_prime_prime: GroupOrderElement::from_string("40F5A8778FF8E8 9FF1A033631C86 48114E1936A2D3 8BBA7C53D7E872 B222556").unwrap(),
                r_prime_prime_prime: GroupOrderElement::from_string("720123FAFF4C5A D9341B8D3A0BCB BA905852B13E13 376608BD7617BE B6C0D13").unwrap(),
                o: GroupOrderElement::from_string("4A4CC2356D98B3 B9467C70B91BA0 BBB22548D9D4EE 709C781DD07F42 241B8DA0").unwrap(),
                o_prime: GroupOrderElement::from_string("97A002E7AE6612 35DA7321DAAE70 3E7122B4486FF4 110FE1D3DF8A25 6947A2E").unwrap(),
                m: GroupOrderElement::from_string("4FABBC3D15A918 26697C521E738 328EC6AEB764CC 44112C1CF3DAFC 194F785E").unwrap(),
                m_prime: GroupOrderElement::from_string("1BB49B5FC458E7 7D665C7EDB74CD BBD5D5532C248E 84EFD20CCE013A 73C5D93").unwrap(),
                t: GroupOrderElement::from_string("372F58AEDBB4AC 37E8C58FA05942 62B2BD31C1BC79 3FB78814E96FD9 1172571F").unwrap(),
                t_prime: GroupOrderElement::from_string("27AB5074A81972 29496BDA901DCE D8130635467C94 49204DBF040B11 E4FEED4").unwrap(),
                m2: GroupOrderElement::from_string("2156CC1D7B2984 B8557020CC20B 716F30DBCDB801 F1F788A63440BC 1F0F9075").unwrap(),
                s: GroupOrderElement::from_string("2DE752A04C7430 EF831F0E28F05C CCF2DF0AFCCA7D 84D879AFACFE99 EA2C0F5").unwrap(),
                c: GroupOrderElement::from_string("819BCE9EE02FC4 83514DA58858A0 1A84A8BEB96D79 F554147480C711 1594829").unwrap()
            },
            c_list: NonRevocProofCList {
                e: PointG1::from_string("false 87EEAF680B4A36 E72D7F024B2871 A9FAD9451A4168 100BAB7A3C3281 3FCE336A E7EDD567DD92E8 551A3A89648331 DBABD11D194299 4C9400040AE4A8 47A69A51 C117C7422992B4 F239A98C89CA17 C1477E3A95CD33 CEC5BEE692BD1F C69F45C").unwrap(),
                d: PointG1::from_string("false CFA66C3918514F B90B321EFB56D3 2AA291D2AEA24E FFB1C1F315E1DC 2B577B63 5D8C8CDE96778F 325D25EB7E2DD 3257FFDE8183 46A549B8E5F0DF 458E0180 6F0F0289DBF93B F0BACB0792D4B6 615A73CF9DEB7D 91C0DE4FCF6B4F 1382E98C").unwrap(),
                a: PointG1::from_string("false DBC13D7E8A33E0 9AA28769090E48 57D17ECA374FFB E9ADD741D0464E 2510E16F CE9ADCE45A4605 86BB828C980E9D CC1444DE2EF598 EF240490E4DC9B 657297D1 8DD5AC68A80225 32713D99D7DA5C EAD54FC578CFF1 E091EB43A8B85E 17B7ABA2").unwrap(),
                g: PointG1::from_string("false 4692B4F2A26AE5 AE0931060B89ED 3D0BDB3C423D50 B9370ECEA4C42D 2ACF58F0 5B4AACC7B3744C 4DF0EFEFF335CE 3175469DBFCEAA CB9B03A8A4FDF9 5D47FDD2 8FD395B3BE086F 82D060A84BA908 498D5BAF7E74E8 46DFF513041C6E 14618FF3").unwrap(),
                w: PointG2::from_string("false 31429403AFB0D0 24CC7FC9F7BC5D E4D72445A5FE55 CF1654884058B9 1BCA7F68 3C8F98067CF378 FD30291A5458C9 95A052167C2B0A 23820F077B129B 20A9ADD7 7259B9061913F9 7139E0919E6353 4E14A1D637EDF8 B69029B9AAF354 A02522B DD4888AC016D57 5F9F2ECFB7F6DD 3F3ADDB64CBF87 2E297B4851A222 19BC3220 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD 0 0 0 0 0").unwrap(),
                s: PointG2::from_string("false 5C7FC3BE93CDA6 52659F0E393BE3 7865D5D9AAC549 839EBC8E7F8D56 17A574E39 C2FFB861B74025 DD36A67440AEB7 4720101773569F 3B655BFFDC89C1 1AFB9BF4A 93601BFA88028E 3685037460F9CF 886B503D5EA2CC 5390350C9C77DE 11F25D2A7 40D227A8BF8B01 BFB3F8E0C4A899 ABF04838C8AB96 9AAA293B8D2AA 1306E80C7 B18E2CB0226B3 6C5DB0F4876E80 F7140D95FD6DB7 BBE850A8716C97 6867E792 BB7DA64C1C1E94 9FC777B6D91587 9C0078E5F36B4E 452B316239ABCA 427CB9FC").unwrap(),
                u: PointG2::from_string("false 2995D5B792321C 6CFFC4111977B2 29B3B195516E87 97754F709D0572 1A4602690 EA9A5232B7E92A 6AFFD087B62E60 A28787110ED9A8 E59EBD7281AFBE 187B76B62 FF249B4BA0B0AE D00CF4EB802A9C 2C63D43E4CF9F6 C0134A0CFE967B 136C90005 B32EE24320FD74 D6B59A50713BCB 5F756462E1EC00 196427A65CE4F3 ED139245 327877521C2D90 510CEDD397E646 794D44AC6583E2 BC2C75711AC67E 6A0FD899 4AB71272756C5D 7F327DB48DDFC8 F16F69AE45D4B2 30533915443530 2EECF92").unwrap()
            },
            tau_list: NonRevocProofTauList {
                t1: PointG1::from_string("false 3061D958599372 B7DE65CC908BF1 E67B12B2296E7C 24C153C979FD58 36787003 8E1C4E1E9F1E7A 43536B649C287 B7D9E236D8040F D6A1DC1330EF6B 4899713B B023F4477A79A3 F8BC7EC138960A DD66B6CC87D997 15E53AC4AF12D7 1482F91").unwrap(),
                t2: PointG1::from_string("false 7CA87E1D62FA9E D34FF51D2ACD97 3350AD96F5802B E630B0FE95AC37 5702010C EB7233002B21E6 9CAA9A0F7F90A0 FAA9FB7995E221 AEA12987B4B57C 66A362A8 21A9932A2130AA F857C1E98F334E 45E3F984BEF072 41C33799E32E2B 18144B56").unwrap(),
                t3: Pair::from_string("2FE4DFE1A46F49 E43267F2461FAB 803285C73F17A9 D9726CF0CDBFA3 210B51DB C75F938CE0F9C8 2B1BC605543AEC D451FD7A6E8589 E07CD7353B10D5 8C30A04 572D8C7D924D19 17380E6ADF7325 C5E2A1FF0CE7B5 70144A5D071871 1D583888 F752222178D515 A5793DA336E9D 327A4E202957BE DCD5743930A7B4 9E20633 F0D28BFC238578 E2F5F57D91DBF2 DA5C8083BCCDA2 26B08EB6147A80 5C57A7A 78E07D8BC2728 CB92734E9E0722 C26D4577FAEF96 F9255E04EE123C 1F9FC5FA 2F4C8341CDF86B CCDC748141BF23 EDD6E500C6378D B308C907152A1D 1C9265D1 427ACF6366CA59 7C53E68BE3113E 4081717D6C4463 8284812FA0C83D 1761FC0F C6CF1D7F34A02E 9DA756D9CB7B7A 826781748A8EF9 B798DA22EBD513 91E6E55 28F1B7C5D89541 75616631E40860 CE5CC9D391625A 65D9C07CC87540 1FC3B54A 87B423F7E9B883 6DB33677FE50FF 9E0795AC202574 6461442C0200D6 15AC82C6 FBC188DC2E2167 1BC83BD658EB54 80A5236180DEBA FC9FBE71BBD950 1FC6B6EF").unwrap(),
                t4: Pair::from_string("F559B558568F00 2E5703978652E4 84ABB1EFBDE1F5 24F60F8A18B2E9 1089AEFD E0550ED79B610A 60942E9FF0DD2B E8011DAE5780 1C28B2523E6BBB 12FFB2C0 72357BA6624136 9BE8465A8A1C42 B336C83289455F DE3F9F26FEAC0 A8A9EB6 AF377021835DE 6A2D8CE5E73F9C 5C4BABCD6E2408 95D1EF22E5623D 12523BC3 4E9D466474F164 4E46BDCDE3AA66 633386B385D7B5 DE3001C9EA78C4 DE69863 2100B10EB4F866 C75D4B617F38A7 DDDD779FC3FD60 B1768840B262E7 81D419F 46458D320AE1D2 6091232786A4EB 2CC71441BBDE10 655451AD6AA1B7 598A8ED 91DD81867CAE43 2DA9E7382C5570 3E50D4D63D2A5C E7ACF6EAC4D3CB 24F131F1 4FCB9EAC7CDAB2 D31F70DC453C37 2ED71C2B2F0DF4 ECBF8FC8FFFC53 129B4824 ED10302BCB912 C1F12B735A4350 2D3A1FF226480C 9BF59AD8B50BB5 185D2059 22E99F8CBD0CC3 8653D4C3E8893B ACED9F3ADED327 2742931E12B464 6CF1027 C431848A41206E 4BE80A43D46CB5 EE1BE106103718 F0AC7FBB3115FE 243C4C16").unwrap(),
                t5: PointG1::from_string("false 239BE83F71CABC BC84B407A1E510 D8A109D51A552E 7752BBBF303ECA 31F880D4 58623E2A9619FA D507B8BF84D1B9 EE9E297E6D1E01 E0A8C868FC72A0 593B9A26 D35CC32FDBC48D E7F36E878FAD2B EBA44AA576C2EC 88187C505D91CC 4445E01").unwrap(),
                t6: PointG1::from_string("false C078373DD322F4 FEA55734A98E0D E5BBEC1DE9A4E7 9A315DB3BB6F9D 3D55331C 24E814FB1FCD62 CD0FBB2648C004 581C21FDBACE14 FF1A13C4F7B6B9 66427E6F 4A8D875D96104E A946A9EF03E037 F77F419B042594 8DF9D4EBE16971 45E8764").unwrap(),
                t7: Pair::from_string("6BF617224E4CF3 F587E726F82F9F 2A3BBB00C43493 E69BACAD5654F3 229E5A94 B75BBEDD0B7565 31D93CF371F1BA 32F8E0B1702B22 ECE60840C67AD3 23B2FA97 2581921C62F012 A795043D98654A D9C2F0FAE14AE0 4F59CF2B2EC00D 663D0C3 2FA571E3BFF816 CD5AB1B2D661A3 E11775A129AA9B 4B7DAA690616BF 8EE457 2F475F2C7CEB30 595C5003D5BB65 C530979B467E22 AFBD304ADAD36C 54950BD A01ED36128EA5B 22EF123884BF34 716514958414E A0C702628F4F3C 122FED2E 5843188B155AEF 4BD931FD09862A E8B84785098ADF 986A86681B3D54 7342D1B 7D6A963E5DAB86 CA8985E39971C1 8DC57FB4BF4C9E 209F3DE93E9066 41DE3D2 F5A695AFDF6F12 8AE2105C4C4CFB D206C971C7523A 1EE3A385B4AEE2 EA5790E B0E195CEC810C4 16AD2E1D898E7B BA3CCCBF9F535B 4F711DD6697A1A 15C9066E 89F1D711FA08F6 C63A584DE7E0CF AB59A5AA104A78 5146DBA647C4D 1150FD24 A0046E5FF148C9 DDEFBED8178CF7 F0CA0DCFBC974F 803FC84CB514AD 1591FB").unwrap(),
                t8: Pair::from_string("E892C846B7DC2C 4760838C68B088 B1B6DDF183D5EF E3C1FB1D99656 1A0FB1F8 A6F8A65FBDCD05 1DFE1FE8B4101E 2A63E672EBCD93 46F16A30D6481B 1235B7EF 2DFDFCB743ED0F CA1701281076E6 806D4C8D1D2E7 1AD1C591ACC4F9 2CFBC53 F851B9BFD640B 964EAC3AA0F00D 8FA1C2AFE168CE B4C5E83208F7CB 2472470C 939F2540FE6132 34570164DFAE0 3CA350D731E47E D62468BB8D1951 15010B4B 27D23A1C9F80A0 7BB0B73BA02719 9F7700CC2A341A DFB66D9C48655F 145BB54D EF8C35953B1FA9 7DE3EB9952F773 A8041ED9C789D5 A3500BF02E7A95 236FB4C3 7A5DFEDF9DE0C7 74D0DA5B00B30E BE32F6E0DC013 32832510A0DBDE 152902DA 3B3B10E4606449 7A8CAE17A030B0 982AE2808F5D57 C4079A513FA5B1 15A9F25F 3FA304277D2DC7 7161510E56CA4 F0A4A5490DD695 F066E5C4C79106 CCF8D3E B866E0BFE3CA06 A5CD4213974007 B5F8A75B27074C 4995CABA1A07C0 14AB6981 E1011C2B73FC7C 1213DB50454659 11E19BB4D748F3 18EBB8E894FEFB 1512725").unwrap()
            }
        }
    }

    pub fn non_revoc_proof() -> NonRevocProof {
        NonRevocProof {
            x_list: NonRevocProofXList {
                rho: GroupOrderElement::from_string("862EAEC368F8BE 848D2F871E101A 2E91FFA9DE85A7 AC1F5A5C4BDE56 16E43DCF").unwrap(),
                r: GroupOrderElement::from_string("D0642C8FC9CD0C 4102C1474B2EC7 D927670781F436 205DEB89AEB30D 2BAA847").unwrap(),
                r_prime: GroupOrderElement::from_string("50AE77DF5F4FCF 7409D48B6518BC 4072381C958C32 C22B13AC703D7C D63094C").unwrap(),
                r_prime_prime: GroupOrderElement::from_string("E36B82ADBFD7AA 3CCE79B3E4E774 58B4847D148754 A6D1C5D21ADF4 72FA71B").unwrap(),
                r_prime_prime_prime: GroupOrderElement::from_string("CED70672958514 C9690F9F0C3C12 9372FA695565DB E3C3BEDB407029 15A0D18A").unwrap(),
                o: GroupOrderElement::from_string("32FAB652969BE6 517A7FF317757D D34EC9DC7F1186 90E0C9FCEDA9B5 19B2553E").unwrap(),
                o_prime: GroupOrderElement::from_string("ABAF020163F3F3 B271F5EA6143C2 232BDF2F73D382 B9F72199751258 1A45C9D9").unwrap(),
                m: GroupOrderElement::from_string("6BBF3F293B6EE4 8B74DBFC74B5B9 C52AFFBD85F720 97DFD5464AE6BE 11C22EEB").unwrap(),
                m_prime: GroupOrderElement::from_string("60F60877A17AB5 D18C7AFA6DBC2B 259C5531B7A142 E797E2D6C0DDCA B9E2616").unwrap(),
                t: GroupOrderElement::from_string("15FB7F7FC34B3F 4C2F0140A4A584 14CD6B6D5D455B 9C63345F66E892 21B88E3F").unwrap(),
                t_prime: GroupOrderElement::from_string("179B1F02AA6FB4 5E1E2ED844C75A BDF47D8F55BF90 192E37622D8CA0 1634FC27").unwrap(),
                m2: GroupOrderElement::from_string("EB43877A948FC4 52B12394658B53 394E050536B5E6 F44634D076AB0 1D89C97F").unwrap(),
                s: GroupOrderElement::from_string("84BC05710625A1 DED5F03DF74609 5F72CE7609971B 2B43CA5E2A5C03 350174").unwrap(),
                c: GroupOrderElement::from_string("7B5C7449CE3E59 34EADC67AD3E9E D634E35BF03EAC 63AE8185057976 9925E1").unwrap()
            },
            c_list: NonRevocProofCList {
                e: PointG1::from_string("false 87EEAF680B4A36 E72D7F024B2871 A9FAD9451A4168 100BAB7A3C3281 3FCE336A E7EDD567DD92E8 551A3A89648331 DBABD11D194299 4C9400040AE4A8 47A69A51 C117C7422992B4 F239A98C89CA17 C1477E3A95CD33 CEC5BEE692BD1F C69F45C").unwrap(),
                d: PointG1::from_string("false CFA66C3918514F B90B321EFB56D3 2AA291D2AEA24E FFB1C1F315E1DC 2B577B63 5D8C8CDE96778F 325D25EB7E2DD 3257FFDE8183 46A549B8E5F0DF 458E0180 6F0F0289DBF93B F0BACB0792D4B6 615A73CF9DEB7D 91C0DE4FCF6B4F 1382E98C").unwrap(),
                a: PointG1::from_string("false DBC13D7E8A33E0 9AA28769090E48 57D17ECA374FFB E9ADD741D0464E 2510E16F CE9ADCE45A4605 86BB828C980E9D CC1444DE2EF598 EF240490E4DC9B 657297D1 8DD5AC68A80225 32713D99D7DA5C EAD54FC578CFF1 E091EB43A8B85E 17B7ABA2").unwrap(),
                g: PointG1::from_string("false 4692B4F2A26AE5 AE0931060B89ED 3D0BDB3C423D50 B9370ECEA4C42D 2ACF58F0 5B4AACC7B3744C 4DF0EFEFF335CE 3175469DBFCEAA CB9B03A8A4FDF9 5D47FDD2 8FD395B3BE086F 82D060A84BA908 498D5BAF7E74E8 46DFF513041C6E 14618FF3").unwrap(),
                w: PointG2::from_string("false 31429403AFB0D0 24CC7FC9F7BC5D E4D72445A5FE55 CF1654884058B9 1BCA7F68 3C8F98067CF378 FD30291A5458C9 95A052167C2B0A 23820F077B129B 20A9ADD7 7259B9061913F9 7139E0919E6353 4E14A1D637EDF8 B69029B9AAF354 A02522B DD4888AC016D57 5F9F2ECFB7F6DD 3F3ADDB64CBF87 2E297B4851A222 19BC3220 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD 0 0 0 0 0").unwrap(),
                s: PointG2::from_string("false 5C7FC3BE93CDA6 52659F0E393BE3 7865D5D9AAC549 839EBC8E7F8D56 17A574E39 C2FFB861B74025 DD36A67440AEB7 4720101773569F 3B655BFFDC89C1 1AFB9BF4A 93601BFA88028E 3685037460F9CF 886B503D5EA2CC 5390350C9C77DE 11F25D2A7 40D227A8BF8B01 BFB3F8E0C4A899 ABF04838C8AB96 9AAA293B8D2AA 1306E80C7 B18E2CB0226B3 6C5DB0F4876E80 F7140D95FD6DB7 BBE850A8716C97 6867E792 BB7DA64C1C1E94 9FC777B6D91587 9C0078E5F36B4E 452B316239ABCA 427CB9FC").unwrap(),
                u: PointG2::from_string("false 2995D5B792321C 6CFFC4111977B2 29B3B195516E87 97754F709D0572 1A4602690 EA9A5232B7E92A 6AFFD087B62E60 A28787110ED9A8 E59EBD7281AFBE 187B76B62 FF249B4BA0B0AE D00CF4EB802A9C 2C63D43E4CF9F6 C0134A0CFE967B 136C90005 B32EE24320FD74 D6B59A50713BCB 5F756462E1EC00 196427A65CE4F3 ED139245 327877521C2D90 510CEDD397E646 794D44AC6583E2 BC2C75711AC67E 6A0FD899 4AB71272756C5D 7F327DB48DDFC8 F16F69AE45D4B2 30533915443530 2EECF92").unwrap()
            }
        }
    }

    pub fn sub_proof_request() -> SubProofRequest {
        let mut sub_proof_request_builder = SubProofRequestBuilder::new().unwrap();
        sub_proof_request_builder.add_revealed_attr("name").unwrap();
        sub_proof_request_builder.add_predicate("age", "GE", 18).unwrap();
        sub_proof_request_builder.finalize().unwrap()
    }

    pub fn revealed_attrs() -> BTreeSet<String> {
        btreeset!["name".to_owned()]
    }

    pub fn unrevealed_attrs() -> BTreeSet<String> {
        btreeset!["height".to_owned(), "age".to_owned(), "sex".to_owned()]
    }

    pub fn credential_revealed_attributes_values() -> CredentialValues {
        let mut credential_values_builder = CredentialValuesBuilder::new().unwrap();
        credential_values_builder.add_dec_known("name", "1139481716457488690172217916278103335").unwrap();
        credential_values_builder.finalize().unwrap()
    }

    pub fn predicate() -> Predicate {
        Predicate {
            attr_name: "age".to_owned(),
            p_type: PredicateType::GE,
            value: 18
        }
    }
}
