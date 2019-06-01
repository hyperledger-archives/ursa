use super::helpers::*;
use bn::BigNumber;
use cl::constants::*;
use cl::hash::get_hash_as_int;
use cl::*;
use errors::prelude::*;
use pair::*;
use utils::commitment::get_pedersen_commitment;

use std::collections::{BTreeMap, BTreeSet, HashSet};

use std::iter::FromIterator;

/// Credentials owner that can proof and partially disclose the credentials to verifier.
pub struct Prover {}

impl Prover {
    /// Creates a master secret.
    ///
    /// # Example
    /// ```
    /// use ursa::cl::prover::Prover;
    ///
    /// let _master_secret = Prover::new_master_secret().unwrap();
    /// ```
    pub fn new_master_secret() -> UrsaCryptoResult<MasterSecret> {
        Ok(MasterSecret {
            ms: bn_rand(LARGE_MASTER_SECRET)?,
        })
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
    /// use ursa::cl::new_nonce;
    /// use ursa::cl::issuer::Issuer;
    /// use ursa::cl::prover::Prover;
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
    pub fn blind_credential_secrets(
        credential_pub_key: &CredentialPublicKey,
        credential_key_correctness_proof: &CredentialKeyCorrectnessProof,
        credential_values: &CredentialValues,
        credential_nonce: &Nonce,
    ) -> Result<
        (
            BlindedCredentialSecrets,
            CredentialSecretsBlindingFactors,
            BlindedCredentialSecretsCorrectnessProof,
        ),
        UrsaCryptoError,
    > {
        trace!(
            "Prover::blind_credential_secrets: >>> credential_pub_key: {:?}, \
             credential_key_correctness_proof: {:?}, \
             credential_values: {:?}, \
             credential_nonce: {:?}",
            credential_pub_key,
            credential_key_correctness_proof,
            credential_values,
            credential_nonce
        );
        Prover::_check_credential_key_correctness_proof(
            &credential_pub_key.p_key,
            credential_key_correctness_proof,
        )?;

        let blinded_primary_credential_secrets =
            Prover::_generate_blinded_primary_credential_secrets_factors(
                &credential_pub_key.p_key,
                &credential_values,
            )?;

        let blinded_revocation_credential_secrets = match credential_pub_key.r_key {
            Some(ref r_pk) => Some(Prover::_generate_blinded_revocation_credential_secrets(
                r_pk,
            )?),
            _ => None,
        };

        let blinded_credential_secrets_correctness_proof =
            Prover::_new_blinded_credential_secrets_correctness_proof(
                &credential_pub_key.p_key,
                &blinded_primary_credential_secrets,
                &credential_nonce,
                &credential_values,
            )?;

        let blinded_credential_secrets = BlindedCredentialSecrets {
            u: blinded_primary_credential_secrets.u,
            ur: blinded_revocation_credential_secrets.as_ref().map(|d| d.ur),
            hidden_attributes: blinded_primary_credential_secrets.hidden_attributes,
            committed_attributes: blinded_primary_credential_secrets.committed_attributes,
        };

        let credential_secrets_blinding_factors = CredentialSecretsBlindingFactors {
            v_prime: blinded_primary_credential_secrets.v_prime,
            vr_prime: blinded_revocation_credential_secrets.map(|d| d.vr_prime),
        };

        trace!(
            "Prover::blind_credential_secrets: <<< blinded_credential_secrets: {:?}, \
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
    /// use ursa::cl::new_nonce;
    /// use ursa::cl::issuer::Issuer;
    /// use ursa::cl::prover::Prover;
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
    pub fn process_credential_signature(
        credential_signature: &mut CredentialSignature,
        credential_values: &CredentialValues,
        signature_correctness_proof: &SignatureCorrectnessProof,
        credential_secrets_blinding_factors: &CredentialSecretsBlindingFactors,
        credential_pub_key: &CredentialPublicKey,
        nonce: &Nonce,
        rev_key_pub: Option<&RevocationKeyPublic>,
        rev_reg: Option<&RevocationRegistry>,
        witness: Option<&Witness>,
    ) -> UrsaCryptoResult<()> {
        trace!(
            "Prover::process_credential_signature: >>> credential_signature: {:?}, \
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

        Prover::_process_primary_credential(
            &mut credential_signature.p_credential,
            &credential_secrets_blinding_factors.v_prime,
        )?;

        Prover::_check_signature_correctness_proof(
            &credential_signature.p_credential,
            credential_values,
            signature_correctness_proof,
            &credential_pub_key.p_key,
            nonce,
        )?;

        if let (
            &mut Some(ref mut non_revocation_cred),
            Some(ref vr_prime),
            &Some(ref r_key),
            Some(ref r_key_pub),
            Some(ref r_reg),
            Some(ref witness),
        ) = (
            &mut credential_signature.r_credential,
            credential_secrets_blinding_factors.vr_prime,
            &credential_pub_key.r_key,
            rev_key_pub,
            rev_reg,
            witness,
        ) {
            Prover::_process_non_revocation_credential(
                non_revocation_cred,
                vr_prime,
                &r_key,
                r_key_pub,
                r_reg,
                witness,
            )?;
        }

        trace!("Prover::process_credential_signature: <<<");

        Ok(())
    }

    /// Creates and returns proof builder.
    ///
    /// The purpose of proof builder is building of proof entity according to the given request .
    /// # Example
    /// ```
    /// use ursa::cl::prover::Prover;
    ///
    /// let _proof_builder = Prover::new_proof_builder();
    pub fn new_proof_builder() -> UrsaCryptoResult<ProofBuilder> {
        Ok(ProofBuilder {
            common_attributes: HashMap::new(),
            init_proofs: Vec::new(),
            c_list: Vec::new(),
            tau_list: Vec::new(),
        })
    }

    #[cfg(test)]
    pub fn check_credential_key_correctness_proof(
        pr_pub_key: &CredentialPrimaryPublicKey,
        key_correctness_proof: &CredentialKeyCorrectnessProof,
    ) -> UrsaCryptoResult<()> {
        Prover::_check_credential_key_correctness_proof(pr_pub_key, key_correctness_proof)
    }

    fn _check_credential_key_correctness_proof(
        pr_pub_key: &CredentialPrimaryPublicKey,
        key_correctness_proof: &CredentialKeyCorrectnessProof,
    ) -> UrsaCryptoResult<()> {
        trace!("Prover::_check_credential_key_correctness_proof: >>> pr_pub_key: {:?}, key_correctness_proof: {:?}",
               pr_pub_key,
               key_correctness_proof
        );

        let correctness_names: HashSet<&String> = HashSet::from_iter(
            key_correctness_proof
                .xr_cap
                .iter()
                .map(|&(ref key, ref _v)| key),
        );
        for r_key in pr_pub_key.r.keys() {
            if !correctness_names.contains(r_key) {
                //V1 didn't include "master_secret" in the correctness proof
                //so for now if this is the only missing key, its okay
                //In the future this "if" statement should be removed
                if r_key != "master_secret" {
                    return Err(err_msg(
                        UrsaCryptoErrorKind::InvalidStructure,
                        format!(
                            "Value by key '{}' not found in key_correctness_proof.xr_cap",
                            r_key
                        ),
                    ));
                }
            }
        }
        for correctness_name in &correctness_names {
            if !pr_pub_key.r.contains_key(correctness_name.as_str()) {
                return Err(err_msg(UrsaCryptoErrorKind::InvalidStructure, format!("Public key doesn't contains item for {} key in key_correctness_proof.xr_cap", correctness_name)));
            }
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
            ordered_r_values.push(r_value.try_clone()?);

            let r_inverse = r_value.inverse(&pr_pub_key.n, Some(&mut ctx))?;
            let val = get_pedersen_commitment(
                &r_inverse,
                &key_correctness_proof.c,
                &pr_pub_key.s,
                &xr_cap_value,
                &pr_pub_key.n,
                &mut ctx,
            )?;
            ordered_r_cap_values.push(val);
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

        let c = get_hash_as_int(&[values])?;

        let valid = key_correctness_proof.c.eq(&c);

        if !valid {
            return Err(err_msg(
                UrsaCryptoErrorKind::InvalidStructure,
                "Invalid Credential key correctness proof",
            ));
        }

        trace!("Prover::_check_credential_key_correctness_proof: <<<");

        Ok(())
    }

    fn _generate_blinded_primary_credential_secrets_factors(
        p_pub_key: &CredentialPrimaryPublicKey,
        credential_values: &CredentialValues,
    ) -> UrsaCryptoResult<PrimaryBlindedCredentialSecretsFactors> {
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
            p_pub_key.s.mod_exp(&v_prime, &p_pub_key.n, Some(&mut ctx)),
            |acc, attr| {
                let pk_r = p_pub_key.r.get(&attr.clone()).ok_or_else(|| {
                    err_msg(
                        UrsaCryptoErrorKind::InvalidStructure,
                        format!("Value by key '{}' not found in pk.r", attr),
                    )
                })?;
                let cred_value = &credential_values.attrs_values[attr];
                acc?.mod_mul(
                    &pk_r.mod_exp(cred_value.value(), &p_pub_key.n, Some(&mut ctx))?,
                    &p_pub_key.n,
                    Some(&mut ctx),
                )
            },
        )?;

        let mut committed_attributes = BTreeMap::new();

        for (attr, cv) in credential_values
            .attrs_values
            .iter()
            .filter(|(_, v)| v.is_commitment())
        {
            if let CredentialValue::Commitment {
                value,
                blinding_factor,
            } = cv
            {
                committed_attributes.insert(
                    attr.clone(),
                    get_pedersen_commitment(
                        &p_pub_key.s,
                        &blinding_factor,
                        &p_pub_key.z,
                        &value,
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

    fn _generate_blinded_revocation_credential_secrets(
        r_pub_key: &CredentialRevocationPublicKey,
    ) -> UrsaCryptoResult<RevocationBlindedCredentialSecretsFactors> {
        trace!(
            "Prover::_generate_blinded_revocation_credential_secrets: >>> r_pub_key: {:?}",
            r_pub_key
        );

        let vr_prime = GroupOrderElement::new()?;
        let ur = r_pub_key.h2.mul(&vr_prime)?;

        let revocation_blinded_credential_secrets =
            RevocationBlindedCredentialSecretsFactors { ur, vr_prime };

        trace!("Prover::_generate_blinded_revocation_credential_secrets: <<< revocation_blinded_credential_secrets: {:?}", revocation_blinded_credential_secrets);

        Ok(revocation_blinded_credential_secrets)
    }

    fn _new_blinded_credential_secrets_correctness_proof(
        p_pub_key: &CredentialPrimaryPublicKey,
        blinded_primary_credential_secrets: &PrimaryBlindedCredentialSecretsFactors,
        nonce: &BigNumber,
        credential_values: &CredentialValues,
    ) -> UrsaCryptoResult<BlindedCredentialSecretsCorrectnessProof> {
        trace!(
            "Prover::_new_blinded_credential_secrets_correctness_proof: >>> p_pub_key: {:?}, \
             blinded_primary_credential_secrets: {:?}, \
             nonce: {:?}, \
             credential_values: {:?}",
            blinded_primary_credential_secrets,
            nonce,
            p_pub_key,
            credential_values
        );

        let mut ctx = BigNumber::new_context()?;

        let v_dash_tilde = bn_rand(LARGE_VPRIME_TILDE)?;

        let mut m_tildes = BTreeMap::new();
        let mut r_tildes = BTreeMap::new();

        let mut values: Vec<u8> = Vec::new();
        let mut u_tilde = p_pub_key
            .s
            .mod_exp(&v_dash_tilde, &p_pub_key.n, Some(&mut ctx))?;

        for (attr, cred_value) in credential_values
            .attrs_values
            .iter()
            .filter(|&(_, v)| v.is_hidden() || v.is_commitment())
        {
            let m_tilde = bn_rand(LARGE_MTILDE)?;
            let pk_r = p_pub_key.r.get(attr).ok_or_else(|| {
                err_msg(
                    UrsaCryptoErrorKind::InvalidStructure,
                    format!("Value by key '{}' not found in pk.r", attr),
                )
            })?;

            match *cred_value {
                CredentialValue::Hidden { .. } => {
                    u_tilde = u_tilde.mod_mul(
                        &pk_r.mod_exp(&m_tilde, &p_pub_key.n, Some(&mut ctx))?,
                        &p_pub_key.n,
                        Some(&mut ctx),
                    )?;
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
                        .ok_or_else(||
                            err_msg(UrsaCryptoErrorKind::InvalidStructure, format!("Value by key '{}' not found in primary_blinded_cred_secrets.committed_attributes", attr)))?;
                    values.extend_from_slice(&ca_value.to_bytes()?);
                }
                _ => (),
            }
            m_tildes.insert(attr.clone(), m_tilde);
        }

        values.extend_from_slice(&blinded_primary_credential_secrets.u.to_bytes()?);
        values.extend_from_slice(&u_tilde.to_bytes()?);
        values.extend_from_slice(&nonce.to_bytes()?);

        let c = get_hash_as_int(&[values])?;

        let v_dash_cap = c
            .mul(&blinded_primary_credential_secrets.v_prime, Some(&mut ctx))?
            .add(&v_dash_tilde)?;

        let mut m_caps = BTreeMap::new();
        let mut r_caps = BTreeMap::new();

        for (attr, m_tilde) in &m_tildes {
            let ca = credential_values.attrs_values.get(attr).ok_or_else(|| {
                err_msg(
                    UrsaCryptoErrorKind::InvalidStructure,
                    format!(
                        "Value by key '{}' not found in cred_values.committed_attributes",
                        attr
                    ),
                )
            })?;

            match ca {
                CredentialValue::Hidden { value } => {
                    let m_cap = m_tilde.add(&c.mul(value, Some(&mut ctx))?)?;
                    m_caps.insert(attr.clone(), m_cap);
                }
                CredentialValue::Commitment {
                    value,
                    blinding_factor,
                } => {
                    let m_cap = m_tilde.add(&c.mul(value, Some(&mut ctx))?)?;
                    let r_cap = r_tildes[attr].add(&c.mul(blinding_factor, Some(&mut ctx))?)?;

                    m_caps.insert(attr.clone(), m_cap);
                    r_caps.insert(attr.clone(), r_cap);
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

    fn _process_primary_credential(
        p_cred: &mut PrimaryCredentialSignature,
        v_prime: &BigNumber,
    ) -> UrsaCryptoResult<()> {
        trace!(
            "Prover::_process_primary_credential: >>> p_cred: {:?}, v_prime: {:?}",
            p_cred,
            v_prime
        );

        p_cred.v = v_prime.add(&p_cred.v)?;

        trace!("Prover::_process_primary_credential: <<<");

        Ok(())
    }

    fn _process_non_revocation_credential(
        r_cred: &mut NonRevocationCredentialSignature,
        vr_prime: &GroupOrderElement,
        cred_rev_pub_key: &CredentialRevocationPublicKey,
        rev_key_pub: &RevocationKeyPublic,
        rev_reg: &RevocationRegistry,
        witness: &Witness,
    ) -> UrsaCryptoResult<()> {
        trace!("Prover::_process_non_revocation_credential: >>> r_cred: {:?}, vr_prime: {:?}, cred_rev_pub_key: {:?}, rev_reg: {:?}, rev_key_pub: {:?}",
               r_cred, vr_prime, cred_rev_pub_key, rev_reg, rev_key_pub);

        let r_cnxt_m2 = BigNumber::from_bytes(&r_cred.m2.to_bytes()?)?;
        r_cred.vr_prime_prime = vr_prime.add_mod(&r_cred.vr_prime_prime)?;
        Prover::_test_witness_signature(
            &r_cred,
            cred_rev_pub_key,
            rev_key_pub,
            rev_reg,
            witness,
            &r_cnxt_m2,
        )?;

        trace!("Prover::_process_non_revocation_credential: <<<");

        Ok(())
    }

    fn _check_signature_correctness_proof(
        p_cred_sig: &PrimaryCredentialSignature,
        cred_values: &CredentialValues,
        signature_correctness_proof: &SignatureCorrectnessProof,
        p_pub_key: &CredentialPrimaryPublicKey,
        nonce: &Nonce,
    ) -> UrsaCryptoResult<()> {
        trace!(
            "Prover::_check_signature_correctness_proof: >>> p_cred_sig: {:?}, \
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
            return Err(err_msg(
                UrsaCryptoErrorKind::InvalidStructure,
                "Invalid Signature correctness proof",
            ));
        }

        if let Some((ref attr, _)) = cred_values.attrs_values.iter().find(|(attr, value)| {
            (value.is_known() || value.is_hidden()) && !p_pub_key.r.contains_key(attr.as_str())
        }) {
            return Err(err_msg(
                UrsaCryptoErrorKind::InvalidStructure,
                format!("Value by key '{}' not found in public key", attr),
            ));
        }

        let rx = cred_values
            .attrs_values
            .iter()
            .filter(|(attr, value)| {
                (value.is_known() || value.is_hidden()) && p_pub_key.r.contains_key(attr.as_str())
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

        let expected_q = p_cred_sig
            .a
            .mod_exp(&p_cred_sig.e, &p_pub_key.n, Some(&mut ctx))?;

        if !q.eq(&expected_q) {
            return Err(err_msg(
                UrsaCryptoErrorKind::InvalidStructure,
                "Invalid Signature correctness proof q != q'",
            ));
        }

        let degree = signature_correctness_proof.c.add(
            &signature_correctness_proof
                .se
                .mul(&p_cred_sig.e, Some(&mut ctx))?,
        )?;

        let a_cap = p_cred_sig
            .a
            .mod_exp(&degree, &p_pub_key.n, Some(&mut ctx))?;

        let mut values: Vec<u8> = Vec::new();
        values.extend_from_slice(&q.to_bytes()?);
        values.extend_from_slice(&p_cred_sig.a.to_bytes()?);
        values.extend_from_slice(&a_cap.to_bytes()?);
        values.extend_from_slice(&nonce.to_bytes()?);

        let c = get_hash_as_int(&[values])?;

        let valid = signature_correctness_proof.c.eq(&c);

        if !valid {
            return Err(err_msg(
                UrsaCryptoErrorKind::InvalidStructure,
                "Invalid Signature correctness proof c != c'",
            ));
        }

        trace!("Prover::_check_signature_correctness_proof: <<<");

        Ok(())
    }

    fn _test_witness_signature(
        r_cred: &NonRevocationCredentialSignature,
        cred_rev_pub_key: &CredentialRevocationPublicKey,
        rev_key_pub: &RevocationKeyPublic,
        rev_reg: &RevocationRegistry,
        witness: &Witness,
        r_cnxt_m2: &BigNumber,
    ) -> UrsaCryptoResult<()> {
        trace!("Prover::_test_witness_signature: >>> r_cred: {:?}, cred_rev_pub_key: {:?}, rev_key_pub: {:?}, rev_reg: {:?}, r_cnxt_m2: {:?}",
               r_cred, cred_rev_pub_key, rev_key_pub, rev_reg, r_cnxt_m2);

        let z_calc = Pair::pair(&r_cred.witness_signature.g_i, &rev_reg.accum)?
            .mul(&Pair::pair(&cred_rev_pub_key.g, &witness.omega)?.inverse()?)?;

        if z_calc != rev_key_pub.z {
            return Err(err_msg(
                UrsaCryptoErrorKind::InvalidStructure,
                "Issuer is sending incorrect data",
            ));
        }
        let pair_gg_calc = Pair::pair(
            &cred_rev_pub_key.pk.add(&r_cred.g_i)?,
            &r_cred.witness_signature.sigma_i,
        )?;
        let pair_gg = Pair::pair(&cred_rev_pub_key.g, &cred_rev_pub_key.g_dash)?;

        if pair_gg_calc != pair_gg {
            return Err(err_msg(
                UrsaCryptoErrorKind::InvalidStructure,
                "Issuer is sending incorrect data",
            ));
        }

        let m2 = GroupOrderElement::from_bytes(&r_cnxt_m2.to_bytes()?)?;

        let pair_h1 = Pair::pair(
            &r_cred.sigma,
            &cred_rev_pub_key
                .y
                .add(&cred_rev_pub_key.h_cap.mul(&r_cred.c)?)?,
        )?;
        let pair_h2 = Pair::pair(
            &cred_rev_pub_key
                .h0
                .add(&cred_rev_pub_key.h1.mul(&m2)?)?
                .add(&cred_rev_pub_key.h2.mul(&r_cred.vr_prime_prime)?)?
                .add(&r_cred.g_i)?,
            &cred_rev_pub_key.h_cap,
        )?;

        if pair_h1 != pair_h2 {
            return Err(err_msg(
                UrsaCryptoErrorKind::InvalidStructure,
                "Issuer is sending incorrect data",
            ));
        }

        trace!("Prover::_test_witness_signature: <<<");

        Ok(())
    }
}

#[derive(Debug)]
pub struct ProofBuilder {
    common_attributes: HashMap<String, BigNumber>,
    init_proofs: Vec<InitProof>,
    c_list: Vec<Vec<u8>>,
    tau_list: Vec<Vec<u8>>,
}

impl ProofBuilder {
    /// Creates m_tildes for attributes that will be the same across all subproofs
    pub fn add_common_attribute(&mut self, attr_name: &str) -> UrsaCryptoResult<()> {
        self.common_attributes
            .insert(attr_name.to_owned(), bn_rand(LARGE_MVECT)?);
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
    pub fn add_sub_proof_request(
        &mut self,
        sub_proof_request: &SubProofRequest,
        credential_schema: &CredentialSchema,
        non_credential_schema: &NonCredentialSchema,
        credential_signature: &CredentialSignature,
        credential_values: &CredentialValues,
        credential_pub_key: &CredentialPublicKey,
        rev_reg: Option<&RevocationRegistry>,
        witness: Option<&Witness>,
    ) -> UrsaCryptoResult<()> {
        trace!(
            "ProofBuilder::add_sub_proof_request: >>> sub_proof_request: {:?}, \
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
            witness
        );
        ProofBuilder::_check_add_sub_proof_request_params_consistency(
            credential_values,
            sub_proof_request,
            credential_schema,
            non_credential_schema,
        )?;

        let mut non_revoc_init_proof = None;
        let mut m2_tilde: Option<BigNumber> = None;

        if let (&Some(ref r_cred), &Some(ref r_reg), &Some(ref r_pub_key), &Some(ref witness)) = (
            &credential_signature.r_credential,
            &rev_reg,
            &credential_pub_key.r_key,
            &witness,
        ) {
            let proof =
                ProofBuilder::_init_non_revocation_proof(&r_cred, &r_reg, &r_pub_key, &witness)?;

            self.c_list.extend_from_slice(&proof.as_c_list()?);
            self.tau_list.extend_from_slice(&proof.as_tau_list()?);
            m2_tilde = Some(group_element_to_bignum(&proof.tau_list_params.m2)?);
            non_revoc_init_proof = Some(proof);
        }

        let primary_init_proof = ProofBuilder::_init_primary_proof(
            &self.common_attributes,
            &credential_pub_key.p_key,
            &credential_signature.p_credential,
            credential_values,
            credential_schema,
            non_credential_schema,
            sub_proof_request,
            m2_tilde,
        )?;

        self.c_list
            .extend_from_slice(&primary_init_proof.as_c_list()?);
        self.tau_list
            .extend_from_slice(&primary_init_proof.as_tau_list()?);

        let init_proof = InitProof {
            primary_init_proof,
            non_revoc_init_proof,
            credential_values: credential_values.try_clone()?,
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
    pub fn finalize(&self, nonce: &Nonce) -> UrsaCryptoResult<Proof> {
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
                non_revoc_proof = Some(ProofBuilder::_finalize_non_revocation_proof(
                    &non_revoc_init_proof,
                    &challenge,
                )?);
            }

            let primary_proof = ProofBuilder::_finalize_primary_proof(
                &init_proof.primary_init_proof,
                &challenge,
                &init_proof.credential_schema,
                &init_proof.non_credential_schema,
                &init_proof.credential_values,
                &init_proof.sub_proof_request,
            )?;

            let proof = SubProof {
                primary_proof,
                non_revoc_proof,
            };
            proofs.push(proof);
        }

        let aggregated_proof = AggregatedProof {
            c_hash: challenge,
            c_list: self.c_list.clone(),
        };

        let proof = Proof {
            proofs,
            aggregated_proof,
        };

        trace!("ProofBuilder::finalize: <<< proof: {:?}", proof);

        Ok(proof)
    }

    fn _check_add_sub_proof_request_params_consistency(
        cred_values: &CredentialValues,
        sub_proof_request: &SubProofRequest,
        cred_schema: &CredentialSchema,
        non_credential_schema: &NonCredentialSchema,
    ) -> UrsaCryptoResult<()> {
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
            return Err(err_msg(
                UrsaCryptoErrorKind::InvalidStructure,
                "Credential doesn't correspond to credential schema",
            ));
        }

        if sub_proof_request
            .revealed_attrs
            .difference(&cred_attrs)
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

        if predicates_attrs.difference(&cred_attrs).count() != 0 {
            return Err(err_msg(
                UrsaCryptoErrorKind::InvalidStructure,
                "Credential doesn't contain attribute requested in predicate",
            ));
        }

        trace!("ProofBuilder::_check_add_sub_proof_request_params_consistency: <<<");

        Ok(())
    }

    fn _init_primary_proof(
        common_attributes: &HashMap<String, BigNumber>,
        issuer_pub_key: &CredentialPrimaryPublicKey,
        c1: &PrimaryCredentialSignature,
        cred_values: &CredentialValues,
        cred_schema: &CredentialSchema,
        non_cred_schema_elems: &NonCredentialSchema,
        sub_proof_request: &SubProofRequest,
        m2_t: Option<BigNumber>,
    ) -> UrsaCryptoResult<PrimaryInitProof> {
        trace!(
            "ProofBuilder::_init_primary_proof: >>> common_attributes: {:?}, \
             issuer_pub_key: {:?}, \
             c1: {:?}, \
             cred_values: {:?}, \
             cred_schema: {:?}, \
             non_cred_schema_elems: {:?}, \
             sub_proof_request: {:?}, \
             m2_t: {:?}",
            common_attributes,
            issuer_pub_key,
            c1,
            cred_values,
            cred_schema,
            non_cred_schema_elems,
            sub_proof_request,
            m2_t
        );

        let eq_proof = ProofBuilder::_init_eq_proof(
            common_attributes,
            issuer_pub_key,
            c1,
            cred_schema,
            non_cred_schema_elems,
            sub_proof_request,
            m2_t,
        )?;

        let mut ne_proofs: Vec<PrimaryPredicateInequalityInitProof> = Vec::new();
        for predicate in sub_proof_request.predicates.iter() {
            let ne_proof = ProofBuilder::_init_ne_proof(
                &issuer_pub_key,
                &eq_proof.m_tilde,
                cred_values,
                predicate,
            )?;
            ne_proofs.push(ne_proof);
        }

        let primary_init_proof = PrimaryInitProof {
            eq_proof,
            ne_proofs,
        };

        trace!(
            "ProofBuilder::_init_primary_proof: <<< primary_init_proof: {:?}",
            primary_init_proof
        );

        Ok(primary_init_proof)
    }

    fn _init_non_revocation_proof(
        r_cred: &NonRevocationCredentialSignature,
        rev_reg: &RevocationRegistry,
        cred_rev_pub_key: &CredentialRevocationPublicKey,
        witness: &Witness,
    ) -> UrsaCryptoResult<NonRevocInitProof> {
        trace!("ProofBuilder::_init_non_revocation_proof: >>> r_cred: {:?}, rev_reg: {:?}, cred_rev_pub_key: {:?}, witness: {:?}",
               r_cred, rev_reg, cred_rev_pub_key, witness);

        let c_list_params = ProofBuilder::_gen_c_list_params(&r_cred)?;
        let c_list = ProofBuilder::_create_c_list_values(
            &r_cred,
            &c_list_params,
            &cred_rev_pub_key,
            witness,
        )?;

        let tau_list_params = ProofBuilder::_gen_tau_list_params()?;
        let tau_list =
            create_tau_list_values(&cred_rev_pub_key, &rev_reg, &tau_list_params, &c_list)?;

        let r_init_proof = NonRevocInitProof {
            c_list_params,
            tau_list_params,
            c_list,
            tau_list,
        };

        trace!(
            "ProofBuilder::_init_non_revocation_proof: <<< r_init_proof: {:?}",
            r_init_proof
        );

        Ok(r_init_proof)
    }

    fn _init_eq_proof(
        common_attributes: &HashMap<String, BigNumber>,
        cred_pub_key: &CredentialPrimaryPublicKey,
        c1: &PrimaryCredentialSignature,
        cred_schema: &CredentialSchema,
        non_cred_schema_elems: &NonCredentialSchema,
        sub_proof_request: &SubProofRequest,
        m2_t: Option<BigNumber>,
    ) -> UrsaCryptoResult<PrimaryEqualInitProof> {
        trace!(
            "ProofBuilder::_init_eq_proof: >>> cred_pub_key: {:?}, \
             c1: {:?}, \
             cred_schema: {:?}, \
             non_cred_schema_elems: {:?}, \
             sub_proof_request: {:?}, \
             m2_t: {:?}",
            cred_pub_key,
            c1,
            cred_schema,
            non_cred_schema_elems,
            sub_proof_request,
            m2_t
        );

        let mut ctx = BigNumber::new_context()?;

        let m2_tilde = m2_t.unwrap_or(bn_rand(LARGE_MVECT)?);

        let r = bn_rand(LARGE_VPRIME)?;
        let e_tilde = bn_rand(LARGE_ETILDE)?;
        let v_tilde = bn_rand(LARGE_VTILDE)?;

        let unrevealed_attrs = non_cred_schema_elems
            .attrs
            .union(&cred_schema.attrs)
            .cloned()
            .collect::<BTreeSet<String>>()
            .difference(&sub_proof_request.revealed_attrs)
            .cloned()
            .collect::<HashSet<String>>();

        let mut m_tilde = clone_bignum_map(&common_attributes)?;
        get_mtilde(&unrevealed_attrs, &mut m_tilde)?;

        let a_prime = cred_pub_key
            .s
            .mod_exp(&r, &cred_pub_key.n, Some(&mut ctx))?
            .mod_mul(&c1.a, &cred_pub_key.n, Some(&mut ctx))?;

        let e_prime = c1.e.sub(&LARGE_E_START_VALUE)?;

        let v_prime = c1.v.sub(&c1.e.mul(&r, Some(&mut ctx))?)?;

        let t = calc_teq(
            &cred_pub_key,
            &a_prime,
            &e_tilde,
            &v_tilde,
            &m_tilde,
            &m2_tilde,
            &unrevealed_attrs,
        )?;

        let primary_equal_init_proof = PrimaryEqualInitProof {
            a_prime,
            t,
            e_tilde,
            e_prime,
            v_tilde,
            v_prime,
            m_tilde,
            m2_tilde: m2_tilde.try_clone()?,
            m2: c1.m_2.try_clone()?,
        };

        trace!(
            "ProofBuilder::_init_eq_proof: <<< primary_equal_init_proof: {:?}",
            primary_equal_init_proof
        );

        Ok(primary_equal_init_proof)
    }

    fn _init_ne_proof(
        p_pub_key: &CredentialPrimaryPublicKey,
        m_tilde: &HashMap<String, BigNumber>,
        cred_values: &CredentialValues,
        predicate: &Predicate,
    ) -> UrsaCryptoResult<PrimaryPredicateInequalityInitProof> {
        trace!("ProofBuilder::_init_ne_proof: >>> p_pub_key: {:?}, m_tilde: {:?}, cred_values: {:?}, predicate: {:?}",
               p_pub_key, m_tilde, cred_values, predicate);

        let mut ctx = BigNumber::new_context()?;

        let attr_value = cred_values
            .attrs_values
            .get(&predicate.attr_name)
            .ok_or_else(|| {
                err_msg(
                    UrsaCryptoErrorKind::InvalidStructure,
                    format!(
                        "Value by key '{}' not found in cred_values",
                        predicate.attr_name
                    ),
                )
            })?
            .value()
            .to_dec()?
            .parse::<i32>()
            .map_err(|_| {
                err_msg(
                    UrsaCryptoErrorKind::InvalidStructure,
                    format!("Value by key '{}' has invalid format", predicate.attr_name),
                )
            })?;

        let delta = predicate.get_delta(attr_value);

        if delta < 0 {
            return Err(err_msg(
                UrsaCryptoErrorKind::InvalidStructure,
                "Predicate is not satisfied",
            ));
        }

        let u = four_squares(delta)?;

        let mut r = HashMap::new();
        let mut t = HashMap::new();
        let mut c_list: Vec<BigNumber> = Vec::new();

        for i in 0..ITERATION {
            let cur_u = u.get(&i.to_string()).ok_or_else(|| {
                err_msg(
                    UrsaCryptoErrorKind::InvalidStructure,
                    format!("Value by key '{}' not found in u1", i),
                )
            })?;

            let cur_r = bn_rand(LARGE_VPRIME)?;
            let cut_t = get_pedersen_commitment(
                &p_pub_key.z,
                &cur_u,
                &p_pub_key.s,
                &cur_r,
                &p_pub_key.n,
                &mut ctx,
            )?;

            r.insert(i.to_string(), cur_r);
            t.insert(i.to_string(), cut_t.try_clone()?);
            c_list.push(cut_t)
        }

        let r_delta = bn_rand(LARGE_VPRIME)?;

        let t_delta = get_pedersen_commitment(
            &p_pub_key.z,
            &BigNumber::from_dec(&delta.to_string())?,
            &p_pub_key.s,
            &r_delta,
            &p_pub_key.n,
            &mut ctx,
        )?;

        r.insert("DELTA".to_string(), r_delta);
        t.insert("DELTA".to_string(), t_delta.try_clone()?);
        c_list.push(t_delta);

        let mut u_tilde = HashMap::new();
        let mut r_tilde = HashMap::new();

        for i in 0..ITERATION {
            u_tilde.insert(i.to_string(), bn_rand(LARGE_UTILDE)?);
            r_tilde.insert(i.to_string(), bn_rand(LARGE_RTILDE)?);
        }

        r_tilde.insert("DELTA".to_string(), bn_rand(LARGE_RTILDE)?);
        let alpha_tilde = bn_rand(LARGE_ALPHATILDE)?;

        let mj = m_tilde.get(&predicate.attr_name).ok_or_else(|| {
            err_msg(
                UrsaCryptoErrorKind::InvalidStructure,
                format!(
                    "Value by key '{}' not found in eq_proof.mtilde",
                    predicate.attr_name
                ),
            )
        })?;

        let tau_list = calc_tne(
            &p_pub_key,
            &u_tilde,
            &r_tilde,
            &mj,
            &alpha_tilde,
            &t,
            predicate.is_less(),
        )?;

        let primary_predicate_ne_init_proof = PrimaryPredicateInequalityInitProof {
            c_list,
            tau_list,
            u,
            u_tilde,
            r,
            r_tilde,
            alpha_tilde,
            predicate: predicate.clone(),
            t,
        };

        trace!(
            "ProofBuilder::_init_ne_proof: <<< primary_predicate_ne_init_proof: {:?}",
            primary_predicate_ne_init_proof
        );

        Ok(primary_predicate_ne_init_proof)
    }

    fn _finalize_eq_proof(
        init_proof: &PrimaryEqualInitProof,
        challenge: &BigNumber,
        cred_schema: &CredentialSchema,
        non_cred_schema_elems: &NonCredentialSchema,
        cred_values: &CredentialValues,
        sub_proof_request: &SubProofRequest,
    ) -> UrsaCryptoResult<PrimaryEqualProof> {
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

        let mut m_hat = HashMap::new();

        let unrevealed_attrs = non_cred_schema_elems
            .attrs
            .union(&cred_schema.attrs)
            .cloned()
            .collect::<BTreeSet<String>>()
            .difference(&sub_proof_request.revealed_attrs)
            .cloned()
            .collect::<BTreeSet<String>>();

        for k in unrevealed_attrs.iter() {
            let cur_mtilde = init_proof.m_tilde.get(k).ok_or_else(|| {
                err_msg(
                    UrsaCryptoErrorKind::InvalidStructure,
                    format!("Value by key '{}' not found in init_proof.mtilde", k),
                )
            })?;

            let cur_val = cred_values.attrs_values.get(k).ok_or_else(|| {
                err_msg(
                    UrsaCryptoErrorKind::InvalidStructure,
                    format!("Value by key '{}' not found in attributes_values", k),
                )
            })?;

            // val = cur_mtilde + (cur_val * challenge)
            let val = challenge
                .mul(&cur_val.value(), Some(&mut ctx))?
                .add(&cur_mtilde)?;

            m_hat.insert(k.clone(), val);
        }

        let m2 = challenge
            .mul(&init_proof.m2, Some(&mut ctx))?
            .add(&init_proof.m2_tilde)?;

        let mut revealed_attrs_with_values = BTreeMap::new();

        for attr in sub_proof_request.revealed_attrs.iter() {
            revealed_attrs_with_values.insert(
                attr.clone(),
                cred_values
                    .attrs_values
                    .get(attr)
                    .ok_or_else(|| {
                        err_msg(
                            UrsaCryptoErrorKind::InvalidStructure,
                            "Encoded value not found",
                        )
                    })?
                    .value()
                    .try_clone()?,
            );
        }

        let primary_equal_proof = PrimaryEqualProof {
            revealed_attrs: revealed_attrs_with_values,
            a_prime: init_proof.a_prime.try_clone()?,
            e,
            v,
            m: m_hat,
            m2,
        };

        trace!(
            "ProofBuilder::_finalize_eq_proof: <<< primary_equal_proof: {:?}",
            primary_equal_proof
        );

        Ok(primary_equal_proof)
    }

    fn _finalize_ne_proof(
        c_h: &BigNumber,
        init_proof: &PrimaryPredicateInequalityInitProof,
        eq_proof: &PrimaryEqualProof,
    ) -> UrsaCryptoResult<PrimaryPredicateInequalityProof> {
        trace!(
            "ProofBuilder::_finalize_ne_proof: >>> c_h: {:?}, init_proof: {:?}, eq_proof: {:?}",
            c_h,
            init_proof,
            eq_proof
        );

        let mut ctx = BigNumber::new_context()?;
        let mut u = HashMap::new();
        let mut r = HashMap::new();
        let mut urproduct = BigNumber::new()?;

        for i in 0..ITERATION {
            let cur_utilde = &init_proof.u_tilde[&i.to_string()];
            let cur_u = &init_proof.u[&i.to_string()];
            let cur_rtilde = &init_proof.r_tilde[&i.to_string()];
            let cur_r = &init_proof.r[&i.to_string()];

            let new_u: BigNumber = c_h.mul(&cur_u, Some(&mut ctx))?.add(&cur_utilde)?;
            let new_r: BigNumber = c_h.mul(&cur_r, Some(&mut ctx))?.add(&cur_rtilde)?;

            u.insert(i.to_string(), new_u);
            r.insert(i.to_string(), new_r);

            urproduct = cur_u.mul(&cur_r, Some(&mut ctx))?.add(&urproduct)?;

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

        let primary_predicate_ne_proof = PrimaryPredicateInequalityProof {
            u,
            r,
            mj: eq_proof.m[&init_proof.predicate.attr_name].try_clone()?,
            alpha,
            t: clone_bignum_map(&init_proof.t)?,
            predicate: init_proof.predicate.clone(),
        };

        trace!(
            "ProofBuilder::_finalize_ne_proof: <<< primary_predicate_ne_proof: {:?}",
            primary_predicate_ne_proof
        );

        Ok(primary_predicate_ne_proof)
    }

    fn _finalize_primary_proof(
        init_proof: &PrimaryInitProof,
        challenge: &BigNumber,
        cred_schema: &CredentialSchema,
        non_cred_schema_elems: &NonCredentialSchema,
        cred_values: &CredentialValues,
        sub_proof_request: &SubProofRequest,
    ) -> UrsaCryptoResult<PrimaryProof> {
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
        let mut ne_proofs: Vec<PrimaryPredicateInequalityProof> = Vec::new();

        for init_ne_proof in init_proof.ne_proofs.iter() {
            let ne_proof = ProofBuilder::_finalize_ne_proof(challenge, init_ne_proof, &eq_proof)?;
            ne_proofs.push(ne_proof);
        }

        let primary_proof = PrimaryProof {
            eq_proof,
            ne_proofs,
        };

        trace!(
            "ProofBuilder::_finalize_primary_proof: <<< primary_proof: {:?}",
            primary_proof
        );

        Ok(primary_proof)
    }

    fn _gen_c_list_params(
        r_cred: &NonRevocationCredentialSignature,
    ) -> UrsaCryptoResult<NonRevocProofXList> {
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
            c: r_cred.c,
        };

        trace!(
            "ProofBuilder::_gen_c_list_params: <<< non_revoc_proof_x_list: {:?}",
            non_revoc_proof_x_list
        );

        Ok(non_revoc_proof_x_list)
    }

    fn _create_c_list_values(
        r_cred: &NonRevocationCredentialSignature,
        params: &NonRevocProofXList,
        r_pub_key: &CredentialRevocationPublicKey,
        witness: &Witness,
    ) -> UrsaCryptoResult<NonRevocProofCList> {
        trace!(
            "ProofBuilder::_create_c_list_values: >>> r_cred: {:?}, r_pub_key: {:?}",
            r_cred,
            r_pub_key
        );

        let e = r_pub_key
            .h
            .mul(&params.rho)?
            .add(&r_pub_key.htilde.mul(&params.o)?)?;

        let d = r_pub_key
            .g
            .mul(&params.r)?
            .add(&r_pub_key.htilde.mul(&params.o_prime)?)?;

        let a = r_cred.sigma.add(&r_pub_key.htilde.mul(&params.rho)?)?;

        let g = r_cred.g_i.add(&r_pub_key.htilde.mul(&params.r)?)?;

        let w = witness.omega.add(&r_pub_key.h_cap.mul(&params.r_prime)?)?;

        let s = r_cred
            .witness_signature
            .sigma_i
            .add(&r_pub_key.h_cap.mul(&params.r_prime_prime)?)?;

        let u = r_cred
            .witness_signature
            .u_i
            .add(&r_pub_key.h_cap.mul(&params.r_prime_prime_prime)?)?;

        let non_revoc_proof_c_list = NonRevocProofCList {
            e,
            d,
            a,
            g,
            w,
            s,
            u,
        };

        trace!(
            "ProofBuilder::_create_c_list_values: <<< non_revoc_proof_c_list: {:?}",
            non_revoc_proof_c_list
        );

        Ok(non_revoc_proof_c_list)
    }

    fn _gen_tau_list_params() -> UrsaCryptoResult<NonRevocProofXList> {
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
            c: GroupOrderElement::new()?,
        };

        trace!(
            "ProofBuilder::_gen_tau_list_params: <<< Nnon_revoc_proof_x_list: {:?}",
            non_revoc_proof_x_list
        );

        Ok(non_revoc_proof_x_list)
    }

    fn _finalize_non_revocation_proof(
        init_proof: &NonRevocInitProof,
        c_h: &BigNumber,
    ) -> UrsaCryptoResult<NonRevocProof> {
        trace!(
            "ProofBuilder::_finalize_non_revocation_proof: >>> init_proof: {:?}, c_h: {:?}",
            init_proof,
            c_h
        );

        let ch_num_z = bignum_to_group_element(&c_h)?;
        let mut x_list: Vec<GroupOrderElement> = Vec::new();

        for (x, y) in init_proof
            .tau_list_params
            .as_list()?
            .iter()
            .zip(init_proof.c_list_params.as_list()?.iter())
        {
            x_list.push(x.add_mod(&ch_num_z.mul_mod(&y)?.mod_neg()?)?);
        }

        let non_revoc_proof = NonRevocProof {
            x_list: NonRevocProofXList::from_list(x_list.as_slice()),
            c_list: init_proof.c_list.clone(),
        };

        trace!(
            "ProofBuilder::_finalize_non_revocation_proof: <<< non_revoc_proof: {:?}",
            non_revoc_proof
        );

        Ok(non_revoc_proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cl::issuer;
    use serde_json;

    #[test]
    fn key_correctness_proof_validation_works_for_deserialized_output_v0_4_1_crypto() {
        let kcp = r#"{"c":"37611675737093606611354469283892411880852495117565168932358663398963131397507","xz_cap":"81579130320284221659747319740108875652446580605626929564515869699158446225972801134098632494713496313081314380866687966418290227597750899002882970519534702423347828404017509366494708523530025686292969865053261834885716665417122559158656847219251019258307743208838075692695164262680850087806525721184647037789559371016575764323904037635266872661253754958239070844593676990703001641163014837607074604574439994741936613409912802229927895424755757352646030336597690950842465911939873272966620342405909930599727835739699655473154455657878429132861698360924836632047016333549106122684361100949241413364697739541658923119788014990949301155631757300624437448380216292364426202602100074188682993006187","xr_cap":[["sex","800280099800023684394221657855578281425593426428797438278634535803826854973287741112297002561462044581730457464290768546940348121889048006353304776646794823653560200707175243576534399257694825778643847023451169693956070462522652667711052051119060371846591706152099200381794609252833996514839617453462295422079364560725012355479350713908774407072059863925714626035129287654437915380442859411132043551952897474887960834654566958110046975477442837252851593858380406893298039998278146813948374557719947480415431505168848477644721410506100843223565186964968463081686726318431810101100839476456665117568759117498622946466335362502138675885007428245786030655866656241152568981953362753866546347245506"],["age","588088631461299425903748636894451597454180996508770107860820879608066278697726969676142820725979998876687628461524297952569445512912113947952863000770341397107329530774939533674792868680827566279577518607195225037390604727483704420911912238224219864823492245908348105557153285313698657725038609899106209002384198903035975551652419617009072704552236735717389754124395458798446740853188430442908535423980999434501037185906780341482928855355637070027953698599569975766436241558834373873737728336703980967063844033141464829186289408341005936078717542471679931243178369744750036706021440802187762189222523038598747576436835546143611288733061739572462869076736405341538116562816483588163276630145588"],["height","553220455491285418654889779078476533199565266037716057819253262456706086296310865820014979289644399892322745082334493480377902246036427120996737141182672228618720768916010742192428961333242647461723166430891725984061962166185290028781330840468287369467210902803713581463138002887245708126181113498506095878475477562185158200076760989353034954621747102865883089591566895303014875251551529870810800964290188402770835695975293408858132429212162793578010820152709965777440582153499339685425754384078776656170709303540365276228433474426237479107459583876421876578975913079855215398240111839997147164550277110095530104844265258104360762567118292063538492192083952712713837994596074547775217382719579"],["name","383325619072931698489524170594499308335325217367787209202882000237923187775119979058633557703022426956865524033530017842216102964924733310029537256438963746099184641563671420576298749176202668215626084998168583932862834827081323228031589641597768136343232183260789201414439414019145929237988915293970815065021922162304853953719973584719975042952713084160885042865916208477614187377876264496125987756268019899327470534991407455234648438185065303663808513544394761315253646500213994569448735987674657147571753166712102581100080484612181607406695322516789021386859985149430517261727189786324895636842320235453633433344220062995558348664785301570376489352431483740437508437906549673849465012384545"]]}"#;
        let kcp: CredentialKeyCorrectnessProof = serde_json::from_str(kcp).unwrap();
        let pubk = r#"{"n":"86665665305306769743640998224032428193374900036388291715266092147536610386173810739519984157965270336632097478597133094406827128255264173203719192251941076854234380657937875659812339068403255817830210066933353759285050420231434817447848623428018855901024003008780452712192795913736482764111358491981149466167261944317488834539736598521002312500014254876871827822649202649309519738154335154609870140475670078398227343824784472798186609231215203087817789245463171907749900122171003521003136568142555330919506366608015786657222086233584954494509284547220890985090423192050178382287421103895144841008791277424496846590741","s":"83084163632683971683103510860027729005278842005821378555008971393342897392394093342482468616999826338514906468919119092064240935309882157132018738683925997494322683283644873286332530900221372911048040341879770635765398264433097793470382168370175851530892980676372148031453280943554540985196123749287845370983365759591955970122115501383179848658624899567590986296264637696901386460135503547126706669607760428113275656838469622794704409212798232179158959884444053511985108292873108039408961013644385675435128342006156787386874406242855120817575247911530681953409173281506124827795181567509455566645223216553134031503032","rms":"69540359214451479987976389839616773230804891002271862455489788750024323222733394500266873735434564107738717337220827491008967759706709372565552228384904852634720433291813577752768701243935217183477184067373049521880834253860649384979614391662024054097693432121508214770293387973206706683957445191440404479633757825124711432420521767784744980561784436151749299730486237837674646141707602951431297500069238129179016565225863870295416031631661258637234775727294775109328255742562659112211808214601970739232270739508093496331998175767125907647677454591673824341876899967173912159053625668577289747835336310228049011105497","r":{"name":"73614884251601813600582203388045085651956041752738830638546275116795417039802182721736430810092702654004453073102067560584416096337783004370774252635058785795031308603877713457768114466947487437017872377059777880761556878710962187533340923809034359538128804737439701806806409957308961705155864645834371173637804141648101201929881187996764636843224817433854456934878290876974385617040959220896441840245127670933144736719991059740420252177851321193552027855601520183643194174630916715502382695700600714805746627413031100287526592940885568497779252694786291104140611371241632211916514383838919499760824668336365583324932","height":"32265171152828173132713789140570643111700266065729911854113144982743849278867404735396847699193525729571735553493306628940808000956416968915321660049178547864196558803186466239359868516043720069552027345930404635373118304914324622526461555852237275305473914047266280025696890899994598011931375804216247338150888041648539670793394645189736727715324829416653875431830621713717186359552041360452761091952990177937845471119498327535198904810568194993285480067818837018253517166215847295813814736920370175582896616957506470379883979553529641429454344298317799362993471811350299848771690117490999682821655004195370468488699","age":"69210210547019257818547850772050709707382309688606699530323725893459773560538103626922071761954050425702250113423976753292214882085897799387395111502105907983214335565997703927644961496300299895632463495897058156522724703286230283448141168541391892836942725363192216987834154982014295076489073625863422550142489184202964353148888883562845140305191596053910119813840558882592688507644486162029886601540499588388441038704851571799439290300947981481715544121770832266036219326576649318754679877198644972011143938420331953697435689747620330999597118287049144404253273801163402037908352075827948221723974973202563583169029","sex":"5971519037640940094397505444316292356065914418354413662186912639811787832463405986659531131133706084880528333584675434816923909544959483919437902975463053732118075030168192272872018865925821857454603799079400957171974895910013062322661909444545643725830160192061905089825121620661836173733315345693314865009989915005759000502383446436810221464568780337079802915890342086506095042145762385725396136006754632851260394335317652166852945930163401043307161826219524803994416323829329312236456379236861294978014561075584507177255338308981019128047314646739471838679506863910116659292783031180706216778151764077702443723295"},"rctxt":"24228185624916991961962522722033145014536714971267927881595876306708625090087873943587238042338121243221012924646178581114559800123476592488566533926756525736648656965761268303310909919204479477384704998557980706682021675823615661983902466146791403727510024640824366557949526383885081089370176066855024067559778863113567573051646482832906197882129941655230936969584340013096005087458997081502931677191413621909541057087395999516425826306677322668329779030018674094652403510183462402288474015372669796858832632923858712304178225982621192335397879717352273004351853493492335932505042039408264279970283524861807398499029","z":"37872997963859527792682078354805696750491698208574994141016267688009297894818042895750265909571960338543790691705028130537151406387984323533817281854853188040586780335230980277951542091044326573188687021343455212924263783843075314376017285018682581592125063885274634931746002023241752606715276609073865600094747779631416689289134066495197013137975380131067470474525255115016486667571541756942937282801093910899243018623825563669293619561358219654815146153557959081662796370699327299000703491066556205494543858597953793350653557670249482561691228852566047112200298646525727087592715767034204051762640986863872476786675"}"#;
        let pubk: CredentialPrimaryPublicKey = serde_json::from_str(pubk).unwrap();

        Prover::check_credential_key_correctness_proof(&pubk, &kcp).unwrap();
    }

    #[test]
    fn key_correctness_proof_validation_works_for_key_correctness_proof_has_extra_keys() {
        let kcp = json!({
            "c":"37611675737093606611354469283892411880852495117565168932358663398963131397507",
            "xz_cap":"81579130320284221659747319740108875652446580605626929564515869699158446225972801134098632494713496313081314380866687966418290227597750899002882970519534702423347828404017509366494708523530025686292969865053261834885716665417122559158656847219251019258307743208838075692695164262680850087806525721184647037789559371016575764323904037635266872661253754958239070844593676990703001641163014837607074604574439994741936613409912802229927895424755757352646030336597690950842465911939873272966620342405909930599727835739699655473154455657878429132861698360924836632047016333549106122684361100949241413364697739541658923119788014990949301155631757300624437448380216292364426202602100074188682993006187",
            "xr_cap":[
                ["sex","800280099800023684394221657855578281425593426428797438278634535803826854973287741112297002561462044581730457464290768546940348121889048006353304776646794823653560200707175243576534399257694825778643847023451169693956070462522652667711052051119060371846591706152099200381794609252833996514839617453462295422079364560725012355479350713908774407072059863925714626035129287654437915380442859411132043551952897474887960834654566958110046975477442837252851593858380406893298039998278146813948374557719947480415431505168848477644721410506100843223565186964968463081686726318431810101100839476456665117568759117498622946466335362502138675885007428245786030655866656241152568981953362753866546347245506"],
                ["age","588088631461299425903748636894451597454180996508770107860820879608066278697726969676142820725979998876687628461524297952569445512912113947952863000770341397107329530774939533674792868680827566279577518607195225037390604727483704420911912238224219864823492245908348105557153285313698657725038609899106209002384198903035975551652419617009072704552236735717389754124395458798446740853188430442908535423980999434501037185906780341482928855355637070027953698599569975766436241558834373873737728336703980967063844033141464829186289408341005936078717542471679931243178369744750036706021440802187762189222523038598747576436835546143611288733061739572462869076736405341538116562816483588163276630145588"],
                ["height","553220455491285418654889779078476533199565266037716057819253262456706086296310865820014979289644399892322745082334493480377902246036427120996737141182672228618720768916010742192428961333242647461723166430891725984061962166185290028781330840468287369467210902803713581463138002887245708126181113498506095878475477562185158200076760989353034954621747102865883089591566895303014875251551529870810800964290188402770835695975293408858132429212162793578010820152709965777440582153499339685425754384078776656170709303540365276228433474426237479107459583876421876578975913079855215398240111839997147164550277110095530104844265258104360762567118292063538492192083952712713837994596074547775217382719579"],
                ["name","383325619072931698489524170594499308335325217367787209202882000237923187775119979058633557703022426956865524033530017842216102964924733310029537256438963746099184641563671420576298749176202668215626084998168583932862834827081323228031589641597768136343232183260789201414439414019145929237988915293970815065021922162304853953719973584719975042952713084160885042865916208477614187377876264496125987756268019899327470534991407455234648438185065303663808513544394761315253646500213994569448735987674657147571753166712102581100080484612181607406695322516789021386859985149430517261727189786324895636842320235453633433344220062995558348664785301570376489352431483740437508437906549673849465012384545"]
            ]
        }).to_string();

        let kcp: CredentialKeyCorrectnessProof = serde_json::from_str(&kcp).unwrap();

        let pubk = json!({
            "n":"86665665305306769743640998224032428193374900036388291715266092147536610386173810739519984157965270336632097478597133094406827128255264173203719192251941076854234380657937875659812339068403255817830210066933353759285050420231434817447848623428018855901024003008780452712192795913736482764111358491981149466167261944317488834539736598521002312500014254876871827822649202649309519738154335154609870140475670078398227343824784472798186609231215203087817789245463171907749900122171003521003136568142555330919506366608015786657222086233584954494509284547220890985090423192050178382287421103895144841008791277424496846590741",
            "s":"83084163632683971683103510860027729005278842005821378555008971393342897392394093342482468616999826338514906468919119092064240935309882157132018738683925997494322683283644873286332530900221372911048040341879770635765398264433097793470382168370175851530892980676372148031453280943554540985196123749287845370983365759591955970122115501383179848658624899567590986296264637696901386460135503547126706669607760428113275656838469622794704409212798232179158959884444053511985108292873108039408961013644385675435128342006156787386874406242855120817575247911530681953409173281506124827795181567509455566645223216553134031503032",
            "rms":"69540359214451479987976389839616773230804891002271862455489788750024323222733394500266873735434564107738717337220827491008967759706709372565552228384904852634720433291813577752768701243935217183477184067373049521880834253860649384979614391662024054097693432121508214770293387973206706683957445191440404479633757825124711432420521767784744980561784436151749299730486237837674646141707602951431297500069238129179016565225863870295416031631661258637234775727294775109328255742562659112211808214601970739232270739508093496331998175767125907647677454591673824341876899967173912159053625668577289747835336310228049011105497",
            "r":{
                "name":"73614884251601813600582203388045085651956041752738830638546275116795417039802182721736430810092702654004453073102067560584416096337783004370774252635058785795031308603877713457768114466947487437017872377059777880761556878710962187533340923809034359538128804737439701806806409957308961705155864645834371173637804141648101201929881187996764636843224817433854456934878290876974385617040959220896441840245127670933144736719991059740420252177851321193552027855601520183643194174630916715502382695700600714805746627413031100287526592940885568497779252694786291104140611371241632211916514383838919499760824668336365583324932",
                "height":"32265171152828173132713789140570643111700266065729911854113144982743849278867404735396847699193525729571735553493306628940808000956416968915321660049178547864196558803186466239359868516043720069552027345930404635373118304914324622526461555852237275305473914047266280025696890899994598011931375804216247338150888041648539670793394645189736727715324829416653875431830621713717186359552041360452761091952990177937845471119498327535198904810568194993285480067818837018253517166215847295813814736920370175582896616957506470379883979553529641429454344298317799362993471811350299848771690117490999682821655004195370468488699",
                "age":"69210210547019257818547850772050709707382309688606699530323725893459773560538103626922071761954050425702250113423976753292214882085897799387395111502105907983214335565997703927644961496300299895632463495897058156522724703286230283448141168541391892836942725363192216987834154982014295076489073625863422550142489184202964353148888883562845140305191596053910119813840558882592688507644486162029886601540499588388441038704851571799439290300947981481715544121770832266036219326576649318754679877198644972011143938420331953697435689747620330999597118287049144404253273801163402037908352075827948221723974973202563583169029",
             },
             "rctxt":"24228185624916991961962522722033145014536714971267927881595876306708625090087873943587238042338121243221012924646178581114559800123476592488566533926756525736648656965761268303310909919204479477384704998557980706682021675823615661983902466146791403727510024640824366557949526383885081089370176066855024067559778863113567573051646482832906197882129941655230936969584340013096005087458997081502931677191413621909541057087395999516425826306677322668329779030018674094652403510183462402288474015372669796858832632923858712304178225982621192335397879717352273004351853493492335932505042039408264279970283524861807398499029",
             "z":"37872997963859527792682078354805696750491698208574994141016267688009297894818042895750265909571960338543790691705028130537151406387984323533817281854853188040586780335230980277951542091044326573188687021343455212924263783843075314376017285018682581592125063885274634931746002023241752606715276609073865600094747779631416689289134066495197013137975380131067470474525255115016486667571541756942937282801093910899243018623825563669293619561358219654815146153557959081662796370699327299000703491066556205494543858597953793350653557670249482561691228852566047112200298646525727087592715767034204051762640986863872476786675"
        }).to_string();
        let pubk: CredentialPrimaryPublicKey = serde_json::from_str(&pubk).unwrap();

        Prover::check_credential_key_correctness_proof(&pubk, &kcp).unwrap_err();
    }

    #[test]
    fn generate_master_secret_works() {
        MockHelper::inject();

        let ms = Prover::new_master_secret().unwrap();
        assert_eq!(
            ms.ms.to_dec().unwrap(),
            mocks::master_secret().ms.to_dec().unwrap()
        );
    }

    #[test]
    fn generate_blinded_primary_credential_secrets_works() {
        MockHelper::inject();

        let pk = issuer::mocks::credential_primary_public_key();
        let credential_values = issuer::mocks::credential_values();

        let _blinded_primary_credential_secrets =
            Prover::_generate_blinded_primary_credential_secrets_factors(&pk, &credential_values)
                .unwrap();
        let expected_u = BigNumber::from_dec("90379212883377051942444457214004439563879517047934957924109506327827266424864106127396714346970738216284320507530527754324729206801422601992700522417322083581628939167117187181423638437856384315973558857250692265909530560844452355964326255821057551846167569170509524949792604814958417070636632379251447321861706466435758587453671398786938921675857732974923901803378547250372362630279485056161267415391507414010183531088200803261695568846058335634754886427522606528221525388671780017596236038760448329929785833010252968356814800693372830944570065390232033948827218950397755480445898892886723022422888608162061797883541").unwrap();
        let expected_v_prime = BigNumber::from_dec("35131625843806290832574870589259287147303302356085937450138681169270844305658441640899780357851554390281352797472151859633451190372182905767740276000477099644043795107449461869975792759973231599572009337886283219344284767785705740629929916685684025616389621432096690068102576167647117576924865030253290356476886389376786906469624913865400296221181743871195998667521041628188272244376790322856843509187067488962831880868979749045372839549034465343690176440012266969614156191820420452812733264350018673445974099278245215963827842041818557926829011513408602244298030173493359464182527821314118075880620818817455331127028576670474022443879858290").unwrap();

        assert_eq!(_blinded_primary_credential_secrets.u, expected_u);
        assert_eq!(
            _blinded_primary_credential_secrets.v_prime,
            expected_v_prime
        );
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

        let (
            blinded_credential_secrets,
            credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof,
        ) = Prover::blind_credential_secrets(
            &pk,
            &key_correctness_proof,
            &credential_values,
            &nonce,
        )
        .unwrap();

        assert_eq!(blinded_credential_secrets.u, BigNumber::from_dec("90379212883377051942444457214004439563879517047934957924109506327827266424864106127396714346970738216284320507530527754324729206801422601992700522417322083581628939167117187181423638437856384315973558857250692265909530560844452355964326255821057551846167569170509524949792604814958417070636632379251447321861706466435758587453671398786938921675857732974923901803378547250372362630279485056161267415391507414010183531088200803261695568846058335634754886427522606528221525388671780017596236038760448329929785833010252968356814800693372830944570065390232033948827218950397755480445898892886723022422888608162061797883541").unwrap());
        assert_eq!(credential_secrets_blinding_factors.v_prime, BigNumber::from_dec("35131625843806290832574870589259287147303302356085937450138681169270844305658441640899780357851554390281352797472151859633451190372182905767740276000477099644043795107449461869975792759973231599572009337886283219344284767785705740629929916685684025616389621432096690068102576167647117576924865030253290356476886389376786906469624913865400296221181743871195998667521041628188272244376790322856843509187067488962831880868979749045372839549034465343690176440012266969614156191820420452812733264350018673445974099278245215963827842041818557926829011513408602244298030173493359464182527821314118075880620818817455331127028576670474022443879858290").unwrap());
        assert!(blinded_credential_secrets.ur.is_some());
        assert!(credential_secrets_blinding_factors.vr_prime.is_some());

        let expected_blinded_credential_secrets_correctness_proof = BlindedCredentialSecretsCorrectnessProof {
            c: BigNumber::from_dec("62987495574713125276927020393421215004000405197826691815490873602430880071520").unwrap(),
            v_dash_cap: BigNumber::from_dec("2483151605786321488759217858501299625266963483281448836084574210022576435206971822449121240893054977812189270973953627508037664673471639762741607301607126279750737315145287752582361238341982527770578389690599482404077240465548717461486060588059213780492836836099219386099202724363461616817064821942869122776850201866032510147820895329800625363912874314625087444433725870407798073299656701830491704373376211865053561350143025726764395631372922114017947241869273369417350214158750221246048552576266052085095574621924764537536843949047976577393704529093690922681660593080666896873908897832916208130004347705000071204141451034807634347513854683282384195146310448772446387795954589966062700678176289767810096596561215075778").unwrap(),
            m_caps: btreemap![
                "master_secret".to_string() => BigNumber::from_dec("10838856720335086997514321276808275847406618787892605766896852714686897722667846274831751967934281244850533820384194801107183060846242551328524580159640640402707269360579673792415").unwrap()
            ],
            r_caps: BTreeMap::new()
        };

        assert_eq!(
            blinded_credential_secrets_correctness_proof,
            expected_blinded_credential_secrets_correctness_proof
        );
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

        Prover::process_credential_signature(
            &mut credential_signature,
            &credential_values,
            &signature_correctness_proof,
            &credential_secrets_blinding_factors,
            &pk,
            &nonce,
            None,
            None,
            None,
        )
        .unwrap();

        assert_eq!(
            mocks::primary_credential(),
            credential_signature.p_credential
        );
    }

    #[test]
    fn init_eq_proof_works() {
        MockHelper::inject();

        let common_attributes = hashmap!["master_secret".to_string() => mocks::m1_t()];
        let pk = issuer::mocks::credential_primary_public_key();
        let cred_schema = issuer::mocks::credential_schema();
        let non_cred_schema_elems = issuer::mocks::non_credential_schema();
        let credential = mocks::primary_credential();
        let sub_proof_request = mocks::sub_proof_request();
        let m2_tilde =
            group_element_to_bignum(&mocks::init_non_revocation_proof().tau_list_params.m2)
                .unwrap();

        let init_eq_proof = ProofBuilder::_init_eq_proof(
            &common_attributes,
            &pk,
            &credential,
            &cred_schema,
            &non_cred_schema_elems,
            &sub_proof_request,
            Some(m2_tilde),
        )
        .unwrap();

        assert_eq!(mocks::primary_equal_init_proof(), init_eq_proof);
    }

    #[test]
    fn init_ne_proof_works() {
        MockHelper::inject();

        let pk = issuer::mocks::credential_primary_public_key();
        let init_eq_proof = mocks::primary_equal_init_proof();
        let predicate = mocks::predicate();
        let credential_values = issuer::mocks::credential_values();

        let init_ne_proof = ProofBuilder::_init_ne_proof(
            &pk,
            &init_eq_proof.m_tilde,
            &credential_values,
            &predicate,
        )
        .unwrap();

        assert_eq!(mocks::primary_ne_init_proof(), init_ne_proof);
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
        let m2_tilde =
            group_element_to_bignum(&mocks::init_non_revocation_proof().tau_list_params.m2)
                .unwrap();

        let init_proof = ProofBuilder::_init_primary_proof(
            &common_attributes,
            &pk,
            &credential.p_credential,
            &credential_values,
            &credential_schema,
            &non_credential_schema,
            &sub_proof_request,
            Some(m2_tilde),
        )
        .unwrap();
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

        let eq_proof = ProofBuilder::_finalize_eq_proof(
            &init_proof,
            &c_h,
            &credential_schema,
            &non_credential_schema,
            &credential_values,
            &sub_proof_request,
        )
        .unwrap();

        assert_eq!(mocks::eq_proof(), eq_proof);
    }

    #[test]
    fn finalize_ne_proof_works() {
        MockHelper::inject();

        let c_h = mocks::aggregated_proof().c_hash;
        let ne_proof = mocks::primary_ne_init_proof();
        let eq_proof = mocks::eq_proof();

        let ne_proof = ProofBuilder::_finalize_ne_proof(&c_h, &ne_proof, &eq_proof).unwrap();
        assert_eq!(mocks::ne_proof(), ne_proof);
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

        let proof = ProofBuilder::_finalize_primary_proof(
            &proof,
            &c_h,
            &credential_schema,
            &non_credential_schema,
            &credential_values,
            &sub_proof_request,
        )
        .unwrap();

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
        let (cred_pub_key, cred_priv_key, cred_key_correctness_proof) =
            issuer::Issuer::new_credential_def(&cred_schema, &non_cred_schema, true).unwrap();

        let start_time = time::get_time();

        let (rev_key_pub, rev_key_priv, mut rev_reg, mut rev_tails_generator) =
            issuer::Issuer::new_revocation_registry_def(&cred_pub_key, n, false).unwrap();

        let simple_tail_accessor = SimpleTailsAccessor::new(&mut rev_tails_generator).unwrap();

        let end_time = time::get_time();

        println!(
            "Create RevocationRegistry Time: {:?}",
            end_time - start_time
        );

        let cred_values = issuer::mocks::credential_values();

        // Issue first correct Claim
        let credential_nonce = new_nonce().unwrap();

        let (
            blinded_credential_secrets,
            credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof,
        ) = Prover::blind_credential_secrets(
            &cred_pub_key,
            &cred_key_correctness_proof,
            &cred_values,
            &credential_nonce,
        )
        .unwrap();

        let cred_issuance_nonce = new_nonce().unwrap();

        let rev_idx = 1;
        let (mut cred_signature, signature_correctness_proof, rev_reg_delta) =
            issuer::Issuer::sign_credential_with_revoc(
                "CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW",
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
                &simple_tail_accessor,
            )
            .unwrap();
        let mut rev_reg_delta = rev_reg_delta.unwrap();

        let mut witness =
            Witness::new(rev_idx, n, false, &rev_reg_delta, &simple_tail_accessor).unwrap();

        Prover::process_credential_signature(
            &mut cred_signature,
            &cred_values,
            &signature_correctness_proof,
            &credential_secrets_blinding_factors,
            &cred_pub_key,
            &cred_issuance_nonce,
            Some(&rev_key_pub),
            Some(&rev_reg),
            Some(&witness),
        )
        .unwrap();

        // Populate accumulator
        for i in 2..n {
            let index = n + 1 - i;

            simple_tail_accessor
                .access_tail(index, &mut |tail| {
                    rev_reg_delta.accum = rev_reg_delta.accum.sub(tail).unwrap();
                })
                .unwrap();

            rev_reg_delta.issued.insert(i);
        }

        // Update NonRevoc Credential

        let start_time = time::get_time();

        witness
            .update(rev_idx, n, &rev_reg_delta, &simple_tail_accessor)
            .unwrap();

        let end_time = time::get_time();

        println!(
            "Update NonRevocation Credential Time: {:?}",
            end_time - start_time
        );

        let total_end_time = time::get_time();
        println!(
            "Total Time for {} credentials: {:?}",
            n,
            total_end_time - total_start_time
        );

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
        proof_builder
            .add_sub_proof_request(
                &sub_proof_request,
                &credential_schema,
                &non_credential_schema,
                &cred_signature,
                &cred_values,
                &cred_pub_key,
                Some(&rev_reg),
                Some(&witness),
            )
            .unwrap();
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
    use self::issuer::mocks as issuer_mocks;
    use super::*;

    pub const PROVER_DID: &str = "CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW";

    pub fn master_secret() -> MasterSecret {
        MasterSecret {
            ms: BigNumber::from_dec(
                "21578029250517794450984707538122537192839006240802068037273983354680998203845",
            )
            .unwrap(),
        }
    }

    pub fn proof_common_attributes() -> HashMap<String, BigNumber> {
        hashmap!["master_secret".to_string() => BigNumber::from_dec("67940925789970108743024738273926421512152745397724199848594503731042154269417576665420030681245389493783225644817826683796657351721363490290016166310023506339911751676800452438014771736117676826911321621579680668201191205819012441197794443970687648330757835198888257781967404396196813475280544039772512800509").unwrap()]
    }

    pub fn blinded_credential_secrets() -> BlindedCredentialSecrets {
        BlindedCredentialSecrets {
            u: primary_blinded_credential_secrets_factors().u,
            ur: Some(revocation_blinded_credential_secrets_factors().ur),
            hidden_attributes: primary_blinded_credential_secrets_factors().hidden_attributes,
            committed_attributes: primary_blinded_credential_secrets_factors().committed_attributes,
        }
    }

    pub fn credential_secrets_blinding_factors() -> CredentialSecretsBlindingFactors {
        CredentialSecretsBlindingFactors {
            v_prime: primary_blinded_credential_secrets_factors().v_prime,
            vr_prime: Some(revocation_blinded_credential_secrets_factors().vr_prime),
        }
    }

    pub fn primary_blinded_credential_secrets_factors() -> PrimaryBlindedCredentialSecretsFactors {
        PrimaryBlindedCredentialSecretsFactors {
            u: BigNumber::from_dec("29886088795834867514843257516725390120695400501030529097284039390368790815575021635250530614213018681181988509245497291697096400642083556011533709419559093272463941467048229075669169982486794002215066973530359559887625494349697053094374207511972238240585263726687400873579565728309925932428828259994865164163424616316010921876375695134796431452213160307642602047068850613980365292879225268541496792937217643512177002909976194809774522070435958593564453397872456084507586441979982272217101445730758916117271411775198252053733912610377801532235777389533016011592526547689804183396422168278692293648762898952646304212013").unwrap(),
            v_prime: BigNumber::from_dec("6234844602485198065715756912521084242993832843051505355881690088421550551850125549467092918472695354667100784726622500908091984895363871286940784380653569775818713255809878796986154551268879573825031821103450254794930344156466843783745517992101460563664971267756222007515829473274370597181721580148128191921140248433916209946579773949932257689092058069152841665645156998538141017773327123384878437182202653889178001096252517024209221623151798643305483807921036895305555116721867996362173429413895058464367314162481624252843139719897874833510487628409201743567035205919178492111631830988434158830013048075011555896064621456955153949773969786").unwrap(),
            hidden_attributes: btreeset!["master_secret".to_string()],
            committed_attributes: BTreeMap::new()
        }
    }

    pub fn revocation_blinded_credential_secrets_factors(
    ) -> RevocationBlindedCredentialSecretsFactors {
        RevocationBlindedCredentialSecretsFactors {
            ur: PointG1::from_string("1 19C7E3A5BC00073DFDF072C87818E94E5036FABABCECED727CA52B35CD13623E 1 14338266060779CA8E7881A8C6F01D76493C6E2E0799699B48B9B0C37EFB7F10 1 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8").unwrap(),
            vr_prime: GroupOrderElement::from_string("208420C983A52DB6FEEAC0B4401E1C644DE02CEDB54A5B9727E67C15D42D3F47").unwrap(),
        }
    }

    pub fn blinded_credential_secrets_correctness_proof() -> BlindedCredentialSecretsCorrectnessProof
    {
        BlindedCredentialSecretsCorrectnessProof {
            c: BigNumber::from_dec("22221897091810097116104550881114461643082148268292262107370452543809392119980").unwrap(),
            v_dash_cap: BigNumber::from_dec("138550075139853703898921089249742109370933383442122536758241462797136898723372217745073733484760321944313196224005959283313214691823866099200206619511094340510410379756132564018900336272408451952758744911909745270186687469351805926400048940751546663384456932526357210721105286298911954309847673030848924669039030892926351271528361352647229815570200886413331044936523522169734991711074388744670236246090794460955452530165454411261777397994727107643177636412180478391610457843032096905372535244501319937136828286952881920600234066686774078964666681460452086101831609169073744423947479573031477418206287304633516634999897586640587369694314600219843979420979423192697295668825747083934480262776849450155189470507444304681").unwrap(),
            m_caps: btreemap![
                "master_secret".to_string() => BigNumber::from_dec("4013850682121471572108494732681923882818824463486221403305684759463606521257843454944595738801258160965585302031329898063691848370284494122908692611653736561002522186660023387006").unwrap()
            ],
            r_caps: BTreeMap::new()
        }
    }

    pub fn credential() -> CredentialSignature {
        CredentialSignature {
            p_credential: primary_credential(),
            r_credential: Some(issuer::mocks::revocation_credential()),
        }
    }

    pub fn m1_t() -> BigNumber {
        BigNumber::from_dec("67940925789970108743024738273926421512152745397724199848594503731042154269417576665420030681245389493783225644817826683796657351721363490290016166310023506339911751676800452438014771736117676826911321621579680668201191205819012441197794443970687648330757835198888257781967404396196813475280544039772512800509").unwrap()
    }

    pub fn primary_credential() -> PrimaryCredentialSignature {
        PrimaryCredentialSignature {
            m_2: issuer_mocks::m2(),
            a: BigNumber::from_dec("95840110198672318069386609447820151443303148951672148942302688159852522121826159131255863808996897783707552162739643131614378528599266064592118168070949684856089397179020395909339742237237109001659944052044286789806424622568162248593348615174430412805702304864926111235957265861502223089731337030295342624021263130121667019811704170784741732056631313942416364801356888740473027595965734903554651671716594105480808073860478030458113568270415524334664803892787850828500787726840657357062470014690758530620898492638223285406749451191024373781693292064727907810317973909071993122608011728847903567696437202869261275989357").unwrap(),
            e: BigNumber::from_dec("259344723055062059907025491480697571938277889515152306249728583105665800713306759149981690559193987143012367913206299323899696942213235956742929737627098149467059334482909224329289").unwrap(),
            v: BigNumber::from_dec("5177522642739961905246451779745106415833631678527419493097979847130674994322175317813358680588112397645817545181196877920447218934221099725680400456473461773006574524248907665384069518157432557230427794792544714775524902716631869307992674890701616332103616420135180307240542722829685362316354032918997175853064288731457227803175575337112574432904127165206560820902041401274516490327091476187030657201035927133430393941435525975335190749278773148315112822506617623675477992756350007489528613526034511833547894815621871575785462157607204578035548822396308273354001083587343882755447719022481211554294628383454636017668696472984966918067804683145814957304587119358302001854977263434073677172744911862627274079939469529048710473175607519218460813606549569599500786512608765354400191406122436231062562384489882363964080152503").unwrap(),
        }
    }

    pub fn revocation_credential() -> NonRevocationCredentialSignature {
        NonRevocationCredentialSignature {
            sigma: PointG1::from_string("61FEBE2CFEAA04 5440090222C6AC E933B40264261C A5AA97421F4AEB 1D18E69F 23DDFBC92248BC F4CD0C7051CBEC 7057318CAFB551 B88E41A2CB508A 1461756F FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD").unwrap(),
            c: GroupOrderElement::from_string("250DCBD902AA4C DACB681C7E461 38E136EE1709BA 73C0CC0780C602 1AF7987A").unwrap(),
            vr_prime_prime: GroupOrderElement::from_string("82AD6D5A28057D 249C7DE575B04 C8DCE90C7B2A5E 131D9D72956B4 1DF0DB17").unwrap(),
            witness_signature: WitnessSignature {
                sigma_i: PointG2::from_string("7F776B0F39CC6F 94D2756312D6D9 DA89E7F1530B93 364915CE54A5E1 2680D6A 53C7407A3AF9AC 59BF2A8957F1C8 CB93EC5E8EE75D 864E2703884B81 15DE23D8 9A70E82C370335 FFC1864755EBB7 9B7F220E00A944 18E9FF42298D7B 6B72EAC EAF36C13DFD06F BEE2F1B3FE954 BE121EE8DF2C7F CC4368D001D9F0 116BF610 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD 0 0 0 0 0").unwrap(),
                u_i: PointG2::from_string("D540513002E157 95568C8E8157E5 64E2F4BFEEC606 8CFA0A0F9F6C0D 76EF2B8 3AF7BD1F488386 260E33A289B893 3849E25048B145 B8658101B73033 3D08363 4A7D1682403EB 89449BA919077B EAE01A470A6B16 F4A319CD5C8066 19C0C5E9 9881CB0EA6BCE9 16E3494EE75A08 7CA6B06B0F55C6 8C9E9B456163E8 1A521BBD FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD 0 0 0 0 0").unwrap(),
                g_i: PointG1::from_string("B8A039A309E618 CB462817D7FA39 D76E63681DE743 D992E2E8E63447 15A85746 698A99317E892F 35D22342F7CEC6 468968DDB4D3CD A4DF81C629EE8E 8271151 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45D").unwrap()
            },
            g_i: PointG1::from_string("B8A039A309E618 CB462817D7FA39 D76E63681DE743 D992E2E8E63447 15A85746 698A99317E892F 35D22342F7CEC6 468968DDB4D3CD A4DF81C629EE8E 8271151 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD").unwrap(),
            i: 1,
            m2: GroupOrderElement::from_string("7D412BFCA6D402 79B043B875CBB3 701CAE80805BED 1F6D7DD6247DBE 99A79BA").unwrap()
        }
    }

    pub fn proof_request_nonce() -> Nonce {
        BigNumber::from_dec("1164046393264787986302355").unwrap()
    }

    pub fn proof() -> Proof {
        Proof {
            proofs: vec![subproof()],
            aggregated_proof: aggregated_proof(),
        }
    }

    pub fn subproof() -> SubProof {
        SubProof {
            primary_proof: primary_proof(),
            non_revoc_proof: Some(non_revoc_proof()),
        }
    }

    pub fn primary_init_proof() -> PrimaryInitProof {
        PrimaryInitProof {
            eq_proof: primary_equal_init_proof(),
            ne_proofs: vec![primary_ne_init_proof()],
        }
    }

    pub fn primary_equal_init_proof() -> PrimaryEqualInitProof {
        PrimaryEqualInitProof {
            a_prime: BigNumber::from_dec("93850854506025106167175657367900738564840399460457583396522672546367771557204596986051012396385435450263898123125896474854176367786952154894815573554451004746144139656996044265545613968836176711502602815031392209790095794160045376494471161541029201092195175557986308757797292716881081775201092320235240062158880723682328272460090331253190919323449053508332270184449026105339413097644934519533429034485982687030017670766107427442501537423985935074367321676374406375566791092427955935956566771002472855738585522175250186544831364686282512410608147641314561395934098066750903464501612432084069923446054698174905994358631").unwrap(),
            t: BigNumber::from_dec("10403187904873314760355557832761590691431383521745031865309573910963034393207684410473727200515283477478376473602591257259106279678624852029355519315648291936226793749327383847453659785035143404901389180684693937348170201350989434402765939255768789625180291625978184555673228742169810564578048461551461925810052930346018787363753466820600660809185539201223715614073753236155593704206176748170586820334068878049220243421829954440440126364488974499959662371883050129101801650402485085948889890560553367693634003096560104152231733949195252484402507347769428679283112853202405399796966635008669186194259851326316679551259").unwrap(),
            e_tilde: BigNumber::from_dec("162083298053730499878539835193560156486733663622707027216327685550780519347628838870322946818623352681120371349972731968874009673965057322").unwrap(),
            e_prime: BigNumber::from_dec("60494975419025735471770314879098953").unwrap(),
            v_tilde: BigNumber::from_dec("241132863422049783305938184561371219250127488499746090592218003869595412171810997360214885239402274273939963489505434726467041932541499422544431299362364797699330176612923593931231233163363211565697860685967381420219969754969010598350387336530924879073366177641099382257720898488467175132844984811431059686249020737675861448309521855120928434488546976081485578773933300425198911646071284164884533755653094354378714645351464093907890440922615599556866061098147921890790915215227463991346847803620736586839786386846961213073783437136210912924729098636427160258710930323242639624389905049896225019051952864864612421360643655700799102439682797806477476049234033513929028472955119936073490401848509891547105031112859155855833089675654686301183778056755431562224990888545742379494795601542482680006851305864539769704029428620446639445284011289708313620219638324467338840766574612783533920114892847440641473989502440960354573501").unwrap(),
            v_prime: BigNumber::from_dec("-3933679132196041543227984377875964323531121043384912026366030490417684982761914080567869110889675492251570057893412687357609534517564623790932559612107294189343252843584326660832087391623581676980476192211576666219440539086001581350842394156432471405814701503655049905260108993545134389868429138075642439278230638803697729577397642505741046550417722938537604111655112388852219733523721842548435877574860968257932976172723204960375200633362775576318242266138197660143904836830250308199946646572659762288834118885456533190103996489544961182163702913298477094102725424062670990581903973887402216626878419981310392255956539915352659754508144632499805200970202656174873085820067193997637731842246948009728135617055639316524831123601879078077549775935978211127245412604921678956014690199361110001048510333615270212657536303307").unwrap(),
            m_tilde: hashmap![
                "age".to_string() => BigNumber::from_dec("6461691768834933403326572830814516653957231030793837560544354737855803497655300429843454445497126567767486684087006218691084619904526729989680526652503377438786587511370042964338").unwrap(),
                "height".to_string() => BigNumber::from_dec("6461691768834933403326572830814516653957231030793837560544354737855803497655300429843454445497126567767486684087006218691084619904526729989680526652503377438786587511370042964338").unwrap(),
                "master_secret".to_string() => BigNumber::from_dec("67940925789970108743024738273926421512152745397724199848594503731042154269417576665420030681245389493783225644817826683796657351721363490290016166310023506339911751676800452438014771736117676826911321621579680668201191205819012441197794443970687648330757835198888257781967404396196813475280544039772512800509").unwrap(),
                "sex".to_string() => BigNumber::from_dec("6461691768834933403326572830814516653957231030793837560544354737855803497655300429843454445497126567767486684087006218691084619904526729989680526652503377438786587511370042964338").unwrap()
            ],
            m2_tilde: BigNumber::from_dec("14049198043322723487718055550558829839278677959655715165983472882418452212100").unwrap(),
            m2: BigNumber::from_dec("69500003785041890145270364348670634122591474903142468939711692725859480163330").unwrap(),
        }
    }

    pub fn primary_ne_init_proof() -> PrimaryPredicateInequalityInitProof {
        PrimaryPredicateInequalityInitProof {
            c_list: vec![BigNumber::from_dec("43417630723399995147405704831160043226699738088974193922655952212791839159754229694686612556171069291164098371675806713394528764380709961777960841038615195545807927068699240698185936054936058987270723246617225807473853778766553004798072895122353570790092748990750480624057398606328445597615405248766964525613248873555789413697599780484025628512744521163202295727342982847311596077107082893351168466054656892320738566499198863605986805507318252961936985165071695751733674272963680749928972044675415743646575121033161921861708756912378060863266945905724585703789710405474198524740599479287511121708188363170466265186645").unwrap(),
                         BigNumber::from_dec("36722226848982314680567811997771062638383828354047012538919806599939999127160456447237226368950393496439962666992459033698311124733744083963711166393470803955290971381911274507193981709387505523191368117187074091384646924346700638973173807722733727281592410397831676026466279786567075569837905995849670457506509424137093869661050737596446262008457839619766874798049461600065862281592856187622939978475437479264484697284570903713919546205855317475701520320262681749419906746018812343025594374083863097715974951329849978864273409720176255874977432080252739943546406857149724432737271924184396597489413743665435203185036").unwrap(),
                         BigNumber::from_dec("36722226848982314680567811997771062638383828354047012538919806599939999127160456447237226368950393496439962666992459033698311124733744083963711166393470803955290971381911274507193981709387505523191368117187074091384646924346700638973173807722733727281592410397831676026466279786567075569837905995849670457506509424137093869661050737596446262008457839619766874798049461600065862281592856187622939978475437479264484697284570903713919546205855317475701520320262681749419906746018812343025594374083863097715974951329849978864273409720176255874977432080252739943546406857149724432737271924184396597489413743665435203185036").unwrap(),
                         BigNumber::from_dec("36722226848982314680567811997771062638383828354047012538919806599939999127160456447237226368950393496439962666992459033698311124733744083963711166393470803955290971381911274507193981709387505523191368117187074091384646924346700638973173807722733727281592410397831676026466279786567075569837905995849670457506509424137093869661050737596446262008457839619766874798049461600065862281592856187622939978475437479264484697284570903713919546205855317475701520320262681749419906746018812343025594374083863097715974951329849978864273409720176255874977432080252739943546406857149724432737271924184396597489413743665435203185036").unwrap(),
                         BigNumber::from_dec("15200925076882677157789591684702017059623383056989770565868903056027181948730543992958006723308726004921912800892308236693106779956052024828189927624378588628187084092193792048585904847438401997035239363347036370831220022455446480767807526930979439902956066177870277956875422590851200730884317152112566873283886794804628965955076151434506744414935581441315505752347360465283012954289570640444309747412339681120486660356348167053880912640976118012919486038730936152926928255294036631715239230898556511907889484813751124436548299317858768444665139178324370349441645851840646275463995503285251979214896561204281531077329").unwrap()
            ],
            tau_list: vec![BigNumber::from_dec("84541983257221862363846490076513159323178083291858042421207690118109227097470776291565848472337957726359091501353000902540328950379498905188603938865076724317214320854549915309320726359461624961961733838169355523220988096175066605668081002682252759916826945673002001231825064670095844788135102734720995698848664953286323041296412437988472201525915887801570701034703233026067381470410312497830932737563239377541909966580208973379062395023317756117032804297030709565889020933723878640112775930635795994269000136540330014884309781415188247835339418932462384016593481929101948092657508460688911105398322543841514412679282").unwrap(),
                           BigNumber::from_dec("84541983257221862363846490076513159323178083291858042421207690118109227097470776291565848472337957726359091501353000902540328950379498905188603938865076724317214320854549915309320726359461624961961733838169355523220988096175066605668081002682252759916826945673002001231825064670095844788135102734720995698848664953286323041296412437988472201525915887801570701034703233026067381470410312497830932737563239377541909966580208973379062395023317756117032804297030709565889020933723878640112775930635795994269000136540330014884309781415188247835339418932462384016593481929101948092657508460688911105398322543841514412679282").unwrap(),
                           BigNumber::from_dec("84541983257221862363846490076513159323178083291858042421207690118109227097470776291565848472337957726359091501353000902540328950379498905188603938865076724317214320854549915309320726359461624961961733838169355523220988096175066605668081002682252759916826945673002001231825064670095844788135102734720995698848664953286323041296412437988472201525915887801570701034703233026067381470410312497830932737563239377541909966580208973379062395023317756117032804297030709565889020933723878640112775930635795994269000136540330014884309781415188247835339418932462384016593481929101948092657508460688911105398322543841514412679282").unwrap(),
                           BigNumber::from_dec("84541983257221862363846490076513159323178083291858042421207690118109227097470776291565848472337957726359091501353000902540328950379498905188603938865076724317214320854549915309320726359461624961961733838169355523220988096175066605668081002682252759916826945673002001231825064670095844788135102734720995698848664953286323041296412437988472201525915887801570701034703233026067381470410312497830932737563239377541909966580208973379062395023317756117032804297030709565889020933723878640112775930635795994269000136540330014884309781415188247835339418932462384016593481929101948092657508460688911105398322543841514412679282").unwrap(),
                           BigNumber::from_dec("84541983257221862363846490076513159323178083291858042421207690118109227097470776291565848472337957726359091501353000902540328950379498905188603938865076724317214320854549915309320726359461624961961733838169355523220988096175066605668081002682252759916826945673002001231825064670095844788135102734720995698848664953286323041296412437988472201525915887801570701034703233026067381470410312497830932737563239377541909966580208973379062395023317756117032804297030709565889020933723878640112775930635795994269000136540330014884309781415188247835339418932462384016593481929101948092657508460688911105398322543841514412679282").unwrap(),
                           BigNumber::from_dec("71576740094469616050175125038612941221466947853166771156257978699698137573095744200811891005812207466193292025189595165749324584760557051762243613675513037542326352529889732378990457572908903168034378406865820691354892874894693473276515751045246421111011260438431516865750528792129415255282372242857723274819466930397323134722222564785435619193280367926994591910298328813248782022939309948184632977090553101391015001992173901794883378542109254048900040301640312902056379924070500971247615062778344704821985243443504796944719578450705940345940533745092900800249667587825786217899894277583562804465078452786585349967293").unwrap()
            ],
            u: hashmap![
                "0".to_string() => BigNumber::from_u32(2).unwrap(),
                "1".to_string() => BigNumber::from_u32(1).unwrap(),
                "2".to_string() => BigNumber::from_u32(1).unwrap(),
                "3".to_string() => BigNumber::from_u32(1).unwrap()
            ],
            u_tilde: hashmap![
                "0".to_string() => BigNumber::from_dec("6461691768834933403326572830814516653957231030793837560544354737855803497655300429843454445497126567767486684087006218691084619904526729989680526652503377438786587511370042964338").unwrap(),
                "1".to_string() => BigNumber::from_dec("6461691768834933403326572830814516653957231030793837560544354737855803497655300429843454445497126567767486684087006218691084619904526729989680526652503377438786587511370042964338").unwrap(),
                "2".to_string() => BigNumber::from_dec("6461691768834933403326572830814516653957231030793837560544354737855803497655300429843454445497126567767486684087006218691084619904526729989680526652503377438786587511370042964338").unwrap(),
                "3".to_string() => BigNumber::from_dec("6461691768834933403326572830814516653957231030793837560544354737855803497655300429843454445497126567767486684087006218691084619904526729989680526652503377438786587511370042964338").unwrap()
            ],
            r: hashmap![
                "0".to_string() => BigNumber::from_dec("35131625843806290832574870589259287147303302356085937450138681169270844305658441640899780357851554390281352797472151859633451190372182905767740276000477099644043795107449461869975792759973231599572009337886283219344284767785705740629929916685684025616389621432096690068102576167647117576924865030253290356476886389376786906469624913865400296221181743871195998667521041628188272244376790322856843509187067488962831880868979749045372839549034465343690176440012266969614156191820420452812733264350018673445974099278245215963827842041818557926829011513408602244298030173493359464182527821314118075880620818817455331127028576670474022443879858290").unwrap(),
                "2".to_string() => BigNumber::from_dec("35131625843806290832574870589259287147303302356085937450138681169270844305658441640899780357851554390281352797472151859633451190372182905767740276000477099644043795107449461869975792759973231599572009337886283219344284767785705740629929916685684025616389621432096690068102576167647117576924865030253290356476886389376786906469624913865400296221181743871195998667521041628188272244376790322856843509187067488962831880868979749045372839549034465343690176440012266969614156191820420452812733264350018673445974099278245215963827842041818557926829011513408602244298030173493359464182527821314118075880620818817455331127028576670474022443879858290").unwrap(),
                "1".to_string() => BigNumber::from_dec("35131625843806290832574870589259287147303302356085937450138681169270844305658441640899780357851554390281352797472151859633451190372182905767740276000477099644043795107449461869975792759973231599572009337886283219344284767785705740629929916685684025616389621432096690068102576167647117576924865030253290356476886389376786906469624913865400296221181743871195998667521041628188272244376790322856843509187067488962831880868979749045372839549034465343690176440012266969614156191820420452812733264350018673445974099278245215963827842041818557926829011513408602244298030173493359464182527821314118075880620818817455331127028576670474022443879858290").unwrap(),
                "3".to_string() => BigNumber::from_dec("35131625843806290832574870589259287147303302356085937450138681169270844305658441640899780357851554390281352797472151859633451190372182905767740276000477099644043795107449461869975792759973231599572009337886283219344284767785705740629929916685684025616389621432096690068102576167647117576924865030253290356476886389376786906469624913865400296221181743871195998667521041628188272244376790322856843509187067488962831880868979749045372839549034465343690176440012266969614156191820420452812733264350018673445974099278245215963827842041818557926829011513408602244298030173493359464182527821314118075880620818817455331127028576670474022443879858290").unwrap(),
                "DELTA".to_string() => BigNumber::from_dec("35131625843806290832574870589259287147303302356085937450138681169270844305658441640899780357851554390281352797472151859633451190372182905767740276000477099644043795107449461869975792759973231599572009337886283219344284767785705740629929916685684025616389621432096690068102576167647117576924865030253290356476886389376786906469624913865400296221181743871195998667521041628188272244376790322856843509187067488962831880868979749045372839549034465343690176440012266969614156191820420452812733264350018673445974099278245215963827842041818557926829011513408602244298030173493359464182527821314118075880620818817455331127028576670474022443879858290").unwrap()
            ],
            r_tilde: hashmap![
                "0".to_string() => BigNumber::from_dec("7575191721496255329790454166600075461811327744716122725414003704363002865687003988444075479817517968742651133011723131465916075452356777073568785406106174349810313776328792235352103470770562831584011847").unwrap(),
                "1".to_string() => BigNumber::from_dec("7575191721496255329790454166600075461811327744716122725414003704363002865687003988444075479817517968742651133011723131465916075452356777073568785406106174349810313776328792235352103470770562831584011847").unwrap(),
                "2".to_string() => BigNumber::from_dec("7575191721496255329790454166600075461811327744716122725414003704363002865687003988444075479817517968742651133011723131465916075452356777073568785406106174349810313776328792235352103470770562831584011847").unwrap(),
                "3".to_string() => BigNumber::from_dec("7575191721496255329790454166600075461811327744716122725414003704363002865687003988444075479817517968742651133011723131465916075452356777073568785406106174349810313776328792235352103470770562831584011847").unwrap(),
                "DELTA".to_string() => BigNumber::from_dec("7575191721496255329790454166600075461811327744716122725414003704363002865687003988444075479817517968742651133011723131465916075452356777073568785406106174349810313776328792235352103470770562831584011847").unwrap()
            ],
            alpha_tilde: BigNumber::from_dec("15019832071918025992746443764672619814038193111378331515587108416842661492145380306078894142589602719572721868876278167686578705125701790763532708415180504799241968357487349133908918935916667492626745934151420791943681376124817051308074507483664691464171654649868050938558535412658082031636255658721308264295197092495486870266555635348911182100181878388728256154149188718706253259396012667950509304959158288841789791483411208523521415447630365867367726300467842829858413745535144815825801952910447948288047749122728907853947789264574578039991615261320141035427325207080621563365816477359968627596441227854436137047681372373555472236147836722255880181214889123172703767379416198854131024048095499109158532300492176958443747616386425935907770015072924926418668194296922541290395990933578000312885508514814484100785527174742772860178035596639").unwrap(),
            predicate: predicate(),
            t: hashmap![
                "0".to_string() => BigNumber::from_dec("43417630723399995147405704831160043226699738088974193922655952212791839159754229694686612556171069291164098371675806713394528764380709961777960841038615195545807927068699240698185936054936058987270723246617225807473853778766553004798072895122353570790092748990750480624057398606328445597615405248766964525613248873555789413697599780484025628512744521163202295727342982847311596077107082893351168466054656892320738566499198863605986805507318252961936985165071695751733674272963680749928972044675415743646575121033161921861708756912378060863266945905724585703789710405474198524740599479287511121708188363170466265186645").unwrap(),
                "1".to_string() => BigNumber::from_dec("36722226848982314680567811997771062638383828354047012538919806599939999127160456447237226368950393496439962666992459033698311124733744083963711166393470803955290971381911274507193981709387505523191368117187074091384646924346700638973173807722733727281592410397831676026466279786567075569837905995849670457506509424137093869661050737596446262008457839619766874798049461600065862281592856187622939978475437479264484697284570903713919546205855317475701520320262681749419906746018812343025594374083863097715974951329849978864273409720176255874977432080252739943546406857149724432737271924184396597489413743665435203185036").unwrap(),
                "2".to_string() => BigNumber::from_dec("36722226848982314680567811997771062638383828354047012538919806599939999127160456447237226368950393496439962666992459033698311124733744083963711166393470803955290971381911274507193981709387505523191368117187074091384646924346700638973173807722733727281592410397831676026466279786567075569837905995849670457506509424137093869661050737596446262008457839619766874798049461600065862281592856187622939978475437479264484697284570903713919546205855317475701520320262681749419906746018812343025594374083863097715974951329849978864273409720176255874977432080252739943546406857149724432737271924184396597489413743665435203185036").unwrap(),
                "3".to_string() => BigNumber::from_dec("36722226848982314680567811997771062638383828354047012538919806599939999127160456447237226368950393496439962666992459033698311124733744083963711166393470803955290971381911274507193981709387505523191368117187074091384646924346700638973173807722733727281592410397831676026466279786567075569837905995849670457506509424137093869661050737596446262008457839619766874798049461600065862281592856187622939978475437479264484697284570903713919546205855317475701520320262681749419906746018812343025594374083863097715974951329849978864273409720176255874977432080252739943546406857149724432737271924184396597489413743665435203185036").unwrap(),
                "DELTA".to_string() => BigNumber::from_dec("15200925076882677157789591684702017059623383056989770565868903056027181948730543992958006723308726004921912800892308236693106779956052024828189927624378588628187084092193792048585904847438401997035239363347036370831220022455446480767807526930979439902956066177870277956875422590851200730884317152112566873283886794804628965955076151434506744414935581441315505752347360465283012954289570640444309747412339681120486660356348167053880912640976118012919486038730936152926928255294036631715239230898556511907889484813751124436548299317858768444665139178324370349441645851840646275463995503285251979214896561204281531077329").unwrap()
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
            revealed_attrs: btreemap![
                "name".to_string() => BigNumber::from_dec("66682250590915135919393234675423675079281389286836524491448775067034910960723").unwrap()
            ],
            a_prime: BigNumber::from_dec("93850854506025106167175657367900738564840399460457583396522672546367771557204596986051012396385435450263898123125896474854176367786952154894815573554451004746144139656996044265545613968836176711502602815031392209790095794160045376494471161541029201092195175557986308757797292716881081775201092320235240062158880723682328272460090331253190919323449053508332270184449026105339413097644934519533429034485982687030017670766107427442501537423985935074367321676374406375566791092427955935956566771002472855738585522175250186544831364686282512410608147641314561395934098066750903464501612432084069923446054698174905994358631").unwrap(),
            e: BigNumber::from_dec("162083298053730499878539837415798033696428693449892281052193919207514842725975444071338657195491572547562439622393591965427898285748359108").unwrap(),
            v: BigNumber::from_dec("241132863422049783305938040060597331735278274539541049316128678268379301866997158072011728743321723078574060931449243960464715113938435991871547190135480379265493203441002211218757120311064385792274455797457074741542288420192538286547871288116110058144080647854995527978708188991483561739974917309498779192480418427060775726652318167442183177955447797995160859302520108340826199956754805286213211181508112097818654928169122460464135690611512133363376553662825967455495276836834812520601471833287810311342575033448652033691127511180098524259451386027266077398672694996373787324223860522678035901333613641370426224798680813171225438770578377781015860719028452471648107174226406996348525110692233661632116547069810544117288754524961349911209241835217711929316799411645465546281445291569655422683908113895340361971530636987203042713656548617543163562701947578529101436799250628979720035967402306966520999250819096598649121167").unwrap(),
            m: hashmap![
                "master_secret".to_string() => BigNumber::from_dec("67940925789970108743024738273926421512152745397724199848594503731042154269417576665420030681245389493783225644817826683796657351721363490290016166310023507132564589104990678182299219306228446316250328302891742457726158298612477188160335451477126201081347058945471957804431939288091328124225198960258432684399").unwrap(),
                "sex".to_string() => BigNumber::from_dec("6461691768834933403326575020439114193500962122447442182375470664835531264262887123435773676729731478629261405277091910956944655533226659560277758686479462667297473396368211269136").unwrap(),
                "height".to_string() => BigNumber::from_dec("6461691768834933403326572830814516653957231030793837560544354737855803497655300429843454445497126574195981378365198960707499125538146253636400775219219390979675126287408712407688").unwrap(),
                "age".to_string() => BigNumber::from_dec("6461691768834933403326572830814516653957231030793837560544354737855803497655300429843454445497126568685843068983890896122000977852186661939211990733462807944627807336518424313388").unwrap()
            ],
            m2: BigNumber::from_dec("2553030889054034879941219523536672152702359185828546810612564355745759663351165380563310203986319611277915826660660011443138240248924364893067083241825560").unwrap(),
        }
    }

    pub fn aggregated_proof() -> AggregatedProof {
        AggregatedProof {
            c_hash: BigNumber::from_dec(
                "36734255395875387097236654317906397277981258563238377220233648793005935253962",
            )
            .unwrap(),
            c_list: vec![
                vec![
                    4, 15, 40, 221, 185, 162, 221, 161, 254, 176, 57, 207, 14, 190, 121, 73, 122,
                    188, 36, 147, 47, 72, 242, 193, 17, 241, 109, 66, 73, 52, 131, 185, 112, 8, 84,
                    230, 192, 255, 105, 116, 83, 170, 71, 219, 182, 149, 126, 9, 180, 11, 152, 255,
                    241, 228, 123, 229, 108, 200, 210, 17, 231, 83, 158, 93, 114, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0,
                ],
                vec![
                    4, 28, 250, 35, 217, 251, 183, 160, 58, 131, 37, 66, 222, 201, 38, 193, 138,
                    177, 229, 88, 130, 59, 53, 75, 226, 216, 166, 7, 23, 245, 57, 128, 209, 19, 86,
                    133, 7, 82, 39, 63, 42, 66, 66, 228, 69, 93, 156, 108, 147, 249, 138, 148, 56,
                    223, 216, 102, 204, 90, 134, 78, 135, 164, 254, 181, 71, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0,
                ],
                vec![
                    4, 2, 107, 241, 180, 5, 3, 229, 146, 229, 80, 96, 229, 210, 175, 238, 65, 126,
                    113, 152, 143, 49, 231, 47, 144, 156, 239, 75, 149, 169, 140, 112, 107, 14,
                    249, 31, 191, 70, 33, 146, 43, 37, 116, 188, 36, 78, 23, 15, 36, 90, 97, 103,
                    149, 137, 1, 69, 230, 214, 159, 35, 217, 75, 217, 129, 101, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0,
                ],
                vec![
                    4, 36, 173, 234, 183, 207, 24, 100, 172, 217, 41, 238, 60, 232, 136, 84, 41,
                    129, 223, 88, 29, 111, 132, 214, 99, 54, 252, 215, 160, 195, 248, 53, 127, 29,
                    196, 61, 22, 192, 127, 209, 129, 74, 115, 208, 177, 10, 177, 7, 80, 197, 209,
                    72, 58, 159, 244, 141, 207, 108, 59, 255, 71, 233, 195, 77, 157, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
                vec![
                    21, 39, 33, 136, 4, 35, 81, 232, 221, 50, 46, 137, 180, 37, 68, 198, 205, 92,
                    210, 203, 242, 91, 190, 222, 21, 10, 99, 147, 17, 10, 254, 238, 25, 87, 208,
                    140, 223, 63, 52, 47, 159, 24, 121, 222, 233, 36, 55, 227, 15, 72, 28, 2, 160,
                    137, 120, 159, 50, 140, 82, 152, 35, 213, 100, 213, 21, 84, 190, 96, 165, 232,
                    146, 117, 252, 253, 26, 247, 179, 48, 76, 241, 74, 64, 22, 232, 177, 232, 212,
                    64, 161, 198, 27, 223, 164, 122, 206, 11, 27, 52, 163, 239, 155, 71, 87, 221,
                    17, 160, 128, 70, 123, 232, 177, 38, 18, 80, 72, 147, 150, 193, 146, 127, 155,
                    135, 110, 222, 23, 227, 56, 131,
                ],
                vec![
                    28, 237, 222, 213, 234, 194, 241, 249, 239, 157, 147, 62, 11, 203, 25, 150,
                    180, 231, 63, 84, 153, 26, 206, 79, 58, 75, 86, 61, 31, 109, 67, 59, 19, 57,
                    174, 176, 165, 87, 167, 78, 193, 53, 45, 106, 121, 182, 87, 79, 57, 63, 119,
                    21, 170, 135, 99, 137, 169, 190, 232, 179, 145, 21, 93, 55, 7, 5, 222, 148,
                    253, 230, 147, 253, 12, 149, 89, 159, 207, 219, 48, 75, 105, 67, 3, 121, 81,
                    145, 202, 199, 118, 73, 28, 23, 237, 177, 247, 146, 28, 119, 71, 155, 232, 63,
                    22, 240, 112, 247, 180, 192, 176, 234, 116, 233, 207, 154, 224, 115, 177, 236,
                    32, 186, 139, 159, 134, 118, 56, 155, 200, 165,
                ],
                vec![
                    25, 93, 0, 27, 250, 169, 144, 36, 216, 143, 51, 252, 92, 156, 171, 245, 170,
                    182, 90, 155, 59, 0, 138, 84, 6, 90, 215, 215, 45, 47, 250, 15, 8, 252, 188,
                    97, 242, 241, 207, 232, 195, 100, 252, 182, 254, 227, 217, 16, 251, 87, 121,
                    96, 101, 204, 185, 43, 67, 237, 160, 143, 247, 10, 52, 33, 22, 241, 186, 108,
                    67, 227, 145, 13, 52, 67, 22, 238, 126, 129, 54, 68, 159, 71, 179, 147, 198,
                    12, 199, 0, 9, 92, 232, 40, 178, 34, 172, 187, 16, 6, 17, 84, 137, 147, 242,
                    238, 8, 88, 151, 254, 178, 149, 190, 46, 43, 249, 133, 164, 15, 77, 210, 177,
                    153, 235, 51, 12, 39, 106, 207, 77,
                ],
                vec![
                    1, 39, 90, 159, 247, 134, 155, 5, 88, 27, 171, 241, 196, 35, 255, 144, 167,
                    205, 110, 43, 253, 22, 127, 201, 227, 133, 192, 22, 170, 22, 87, 93, 158, 89,
                    203, 59, 80, 13, 46, 104, 216, 77, 111, 122, 96, 111, 17, 125, 104, 208, 139,
                    2, 58, 245, 217, 152, 50, 239, 205, 102, 250, 37, 214, 12, 118, 204, 99, 233,
                    215, 53, 226, 50, 120, 208, 61, 98, 49, 48, 182, 109, 235, 86, 184, 164, 189,
                    9, 239, 252, 27, 143, 213, 131, 62, 193, 197, 184, 236, 1, 114, 86, 61, 69,
                    229, 65, 236, 6, 164, 208, 105, 20, 4, 125, 63, 43, 66, 207, 112, 61, 131, 130,
                    251, 242, 175, 253, 233, 43, 226, 205, 239, 89, 235, 104, 225, 96, 209, 69, 65,
                    134, 56, 180, 120, 53, 125, 191, 111, 29, 250, 153, 158, 169, 250, 139, 37,
                    229, 207, 126, 38, 150, 65, 39, 219, 58, 180, 114, 204, 0, 188, 164, 188, 53,
                    186, 230, 181, 48, 23, 122, 106, 107, 31, 221, 142, 237, 129, 35, 23, 11, 67,
                    85, 177, 166, 190, 19, 148, 238, 223, 206, 211, 40, 183, 123, 203, 75, 88, 159,
                    0, 52, 8, 138, 192, 144, 97, 177, 180, 212, 45, 91, 237, 86, 36, 161, 180, 47,
                    61, 239, 155, 44, 187, 162, 124, 178, 38, 252, 167, 166, 147, 27, 156, 115,
                    105, 218, 24, 163, 214, 183, 10, 216, 25, 222, 187, 243, 123, 232, 197, 29, 30,
                    133, 47,
                ],
                vec![
                    2, 143, 29, 183, 142, 29, 117, 172, 90, 120, 157, 84, 126, 194, 34, 226, 142,
                    152, 56, 25, 37, 145, 30, 102, 45, 73, 131, 55, 43, 33, 138, 174, 97, 250, 234,
                    215, 49, 197, 194, 21, 16, 58, 156, 69, 108, 214, 139, 71, 141, 205, 160, 47,
                    5, 83, 143, 58, 171, 150, 166, 180, 217, 193, 236, 108, 9, 114, 7, 122, 65,
                    212, 150, 227, 168, 216, 175, 141, 82, 50, 62, 205, 178, 69, 100, 205, 85, 18,
                    173, 25, 186, 149, 195, 119, 169, 165, 107, 28, 146, 17, 36, 101, 125, 158,
                    127, 249, 20, 112, 227, 118, 58, 128, 101, 249, 120, 152, 147, 121, 27, 78,
                    242, 138, 154, 226, 196, 27, 77, 5, 4, 216, 72, 225, 167, 102, 226, 67, 152,
                    119, 85, 81, 71, 131, 91, 113, 74, 152, 140, 2, 9, 84, 197, 97, 38, 50, 181,
                    26, 228, 252, 24, 254, 158, 80, 224, 106, 49, 226, 255, 1, 143, 118, 250, 155,
                    19, 104, 154, 35, 56, 121, 94, 16, 163, 213, 225, 10, 32, 125, 87, 116, 110,
                    103, 127, 251, 212, 227, 41, 230, 28, 143, 94, 149, 46, 40, 77, 28, 247, 40,
                    159, 105, 52, 178, 46, 150, 0, 207, 111, 143, 98, 152, 79, 218, 176, 242, 18,
                    224, 230, 135, 74, 1, 50, 250, 138, 126, 89, 79, 199, 177, 220, 199, 224, 44,
                    89, 142, 224, 169, 164, 169, 32, 130, 82, 178, 156, 233, 197, 157, 11, 35, 212,
                    100, 222,
                ],
                vec![
                    1, 15, 91, 146, 224, 9, 222, 151, 66, 32, 116, 1, 233, 133, 250, 79, 40, 227,
                    195, 180, 173, 37, 206, 231, 172, 177, 61, 134, 178, 158, 135, 167, 46, 154,
                    181, 100, 54, 45, 107, 102, 106, 122, 232, 12, 146, 63, 125, 166, 247, 128,
                    230, 126, 254, 243, 2, 152, 19, 217, 41, 107, 207, 76, 225, 205, 77, 103, 18,
                    137, 145, 20, 198, 94, 106, 172, 10, 166, 45, 232, 29, 179, 185, 31, 205, 57,
                    247, 223, 166, 229, 216, 229, 45, 22, 227, 20, 16, 100, 198, 55, 14, 90, 77,
                    144, 110, 175, 218, 120, 192, 139, 20, 130, 214, 206, 135, 37, 223, 14, 172,
                    26, 93, 156, 252, 180, 27, 40, 236, 249, 248, 116, 160, 47, 123, 249, 53, 213,
                    143, 1, 104, 171, 151, 211, 183, 99, 208, 11, 24, 191, 172, 57, 175, 244, 53,
                    223, 168, 209, 247, 79, 193, 87, 140, 40, 254, 5, 65, 189, 224, 92, 103, 23,
                    219, 89, 171, 25, 153, 224, 147, 14, 78, 26, 3, 17, 196, 1, 250, 177, 107, 140,
                    67, 176, 3, 122, 233, 14, 232, 72, 44, 21, 142, 141, 54, 33, 165, 12, 101, 4,
                    55, 145, 60, 16, 152, 214, 42, 204, 158, 109, 12, 115, 230, 254, 45, 162, 84,
                    120, 147, 218, 228, 149, 99, 209, 140, 39, 253, 234, 247, 123, 183, 239, 253,
                    84, 87, 147, 5, 65, 6, 12, 214, 164, 76, 237, 174, 189, 211, 200, 214, 184, 3,
                    148, 30,
                ],
                vec![
                    112, 136, 12, 69, 162, 232, 90, 39, 235, 18, 179, 156, 164, 229, 85, 100, 26,
                    106, 16, 229, 75, 96, 231, 27, 156, 137, 219, 80, 17, 195, 30, 191, 190, 138,
                    125, 73, 177, 90, 163, 12, 180, 146, 47, 156, 132, 26, 89, 24, 220, 151, 226,
                    24, 28, 129, 73, 218, 11, 220, 178, 114, 190, 130, 222, 96, 72, 176, 8, 117,
                    64, 241, 48, 247, 228, 125, 207, 40, 106, 93, 164, 236, 52, 112, 12, 135, 179,
                    4, 96, 117, 48, 203, 123, 59, 231, 150, 44, 90, 79, 75, 55, 150, 253, 239, 148,
                    119, 50, 177, 246, 104, 156, 205, 13, 17, 71, 238, 149, 88, 77, 68, 112, 130,
                    22, 55, 141, 34, 170, 133, 238, 134, 40, 180, 212, 195, 132, 28, 175, 208, 235,
                    145, 228, 79, 112, 75, 235, 96, 140, 111, 102, 236, 203, 3, 239, 236, 189, 193,
                    33, 253, 226, 1, 124, 37, 36, 173, 125, 187, 109, 44, 31, 30, 4, 139, 125, 243,
                    73, 108, 109, 105, 138, 128, 140, 106, 54, 52, 103, 104, 152, 27, 185, 6, 150,
                    105, 151, 124, 67, 25, 221, 161, 13, 97, 20, 111, 129, 255, 95, 56, 137, 141,
                    149, 168, 245, 105, 31, 81, 11, 90, 166, 141, 188, 69, 85, 126, 201, 38, 128,
                    158, 9, 123, 132, 118, 22, 107, 212, 173, 122, 106, 237, 109, 26, 57, 89, 218,
                    173, 97, 101, 51, 224, 36, 201, 160, 57, 55, 226, 68, 191, 183, 151, 187,
                ],
                vec![
                    1, 36, 34, 217, 148, 4, 116, 74, 94, 18, 213, 219, 10, 186, 52, 205, 246, 171,
                    246, 1, 244, 105, 203, 134, 211, 51, 152, 9, 108, 39, 0, 113, 95, 86, 147, 173,
                    92, 23, 194, 206, 112, 210, 224, 121, 226, 110, 1, 204, 123, 63, 201, 221, 146,
                    109, 204, 16, 122, 199, 50, 172, 197, 5, 59, 20, 59, 95, 59, 238, 162, 75, 237,
                    81, 209, 48, 71, 105, 213, 49, 201, 238, 156, 7, 101, 149, 230, 249, 108, 40,
                    77, 5, 187, 204, 144, 62, 205, 225, 62, 214, 80, 56, 72, 149, 75, 92, 185, 5,
                    25, 26, 23, 221, 25, 133, 23, 163, 72, 142, 5, 153, 67, 129, 250, 23, 39, 23,
                    237, 137, 255, 34, 2, 1, 105, 74, 116, 228, 165, 214, 216, 139, 213, 184, 177,
                    19, 169, 74, 31, 7, 77, 177, 2, 116, 104, 168, 35, 53, 201, 162, 150, 123, 236,
                    5, 81, 197, 160, 209, 146, 5, 237, 191, 13, 153, 64, 230, 61, 155, 254, 118,
                    112, 135, 162, 210, 217, 243, 5, 66, 204, 161, 190, 190, 115, 80, 246, 130, 7,
                    174, 243, 124, 44, 92, 215, 31, 23, 143, 81, 85, 51, 175, 208, 232, 240, 242,
                    151, 194, 42, 222, 111, 32, 80, 185, 17, 60, 52, 147, 62, 135, 81, 196, 164,
                    62, 115, 96, 221, 14, 186, 23, 172, 38, 29, 41, 145, 13, 191, 8, 34, 174, 70,
                    10, 204, 109, 17, 144, 112, 200, 228, 239, 63, 122, 91,
                ],
                vec![
                    67, 166, 56, 239, 86, 131, 23, 62, 130, 21, 236, 196, 219, 166, 34, 35, 168,
                    88, 154, 22, 214, 47, 37, 232, 17, 105, 61, 39, 233, 155, 167, 46, 22, 162,
                    113, 91, 17, 72, 56, 236, 241, 15, 90, 78, 115, 180, 156, 67, 56, 51, 21, 72,
                    122, 185, 199, 19, 77, 132, 139, 104, 228, 230, 152, 144, 89, 95, 196, 14, 176,
                    93, 68, 157, 116, 188, 93, 66, 174, 130, 76, 156, 87, 2, 246, 180, 28, 151,
                    181, 73, 67, 76, 82, 79, 121, 98, 46, 85, 140, 67, 19, 68, 188, 208, 45, 55,
                    217, 107, 124, 73, 45, 112, 164, 133, 58, 102, 109, 239, 203, 143, 40, 118,
                    135, 152, 199, 50, 91, 117, 42, 196, 176, 113, 152, 154, 149, 117, 214, 174,
                    54, 187, 79, 190, 113, 15, 86, 150, 242, 6, 8, 148, 205, 3, 127, 18, 251, 184,
                    115, 16, 152, 66, 15, 53, 74, 152, 131, 162, 211, 99, 17, 106, 57, 112, 200,
                    253, 252, 209, 157, 64, 54, 103, 126, 101, 173, 203, 239, 201, 163, 181, 66,
                    145, 207, 32, 191, 21, 67, 107, 58, 237, 182, 17, 201, 134, 217, 112, 123, 85,
                    239, 156, 132, 27, 74, 48, 228, 212, 24, 241, 12, 139, 152, 237, 130, 25, 128,
                    153, 128, 34, 253, 163, 123, 169, 154, 10, 73, 35, 23, 50, 123, 133, 240, 140,
                    19, 97, 176, 4, 45, 175, 234, 32, 68, 17, 105, 45, 50, 74, 82, 219, 233, 179,
                ],
            ],
        }
    }

    pub fn ne_proof() -> PrimaryPredicateInequalityProof {
        PrimaryPredicateInequalityProof {
            u: hashmap![
                "0".to_string() => BigNumber::from_dec("6461691768834933403326572830814516653957231030793837560544354737855803497655300429843454445497126567840955194878756992885557928540339524545643043778980131879253885097381913472262").unwrap(),
                "1".to_string() => BigNumber::from_dec("6461691768834933403326572830814516653957231030793837560544354737855803497655300429843454445497126567804220939482881605788321274222433127267661785215741754659020236304375978218300").unwrap(),
                "2".to_string() => BigNumber::from_dec("6461691768834933403326572830814516653957231030793837560544354737855803497655300429843454445497126567804220939482881605788321274222433127267661785215741754659020236304375978218300").unwrap(),
                "3".to_string() => BigNumber::from_dec("6461691768834933403326572830814516653957231030793837560544354737855803497655300429843454445497126567804220939482881605788321274222433127267661785215741754659020236304375978218300").unwrap()
            ],
            r: hashmap![
                "0".to_string() => BigNumber::from_dec("1290534116218716438320066296998198963418131286408035380529548316941923398410560113108756798582290425306108955869685395227366233856654792649735912224097611558139789753950408584482847689838795587330987971669161415485990020598912935103565044825010972005166748548886258351774424917360400285403279510922304340427648959687851483846826461162205002537903920975405118476175947131589471870709350253892921592871530107416727676553006745099259773619545623692882161367026324069754047935205197405410348516798706677778839870157117614346079006190506251578369476561129106768237088298646216941156526296494287589126706469975404040325634910290392295066762902049752200300569175726527074032536078980610848985062237596740068429384399305056827").unwrap(),
                "1".to_string() => BigNumber::from_dec("1290534116218716438320066296998198963418131286408035380529548316941923398410560113108756798582290425306108955869685395227366233856654792649735912224097611558139789753950408584482847689838795587330987971669161415485990020598912935103565044825010972005166748548886258351774424917360400285403279510922304340427648959687851483846826461162205002537903920975405118476175947131589471870709350253892921592871530107416727676553006745099259773619545623692882161367026324069754047935205197405410348516798706677778839870157117614346079006190506251578369476561129106768237088298646216941156526296494287589126706469975404040325634910290392295066762902049752200300569175726527074032536078980610848985062237596740068429384399305056827").unwrap(),
                "2".to_string() => BigNumber::from_dec("1290534116218716438320066296998198963418131286408035380529548316941923398410560113108756798582290425306108955869685395227366233856654792649735912224097611558139789753950408584482847689838795587330987971669161415485990020598912935103565044825010972005166748548886258351774424917360400285403279510922304340427648959687851483846826461162205002537903920975405118476175947131589471870709350253892921592871530107416727676553006745099259773619545623692882161367026324069754047935205197405410348516798706677778839870157117614346079006190506251578369476561129106768237088298646216941156526296494287589126706469975404040325634910290392295066762902049752200300569175726527074032536078980610848985062237596740068429384399305056827").unwrap(),
                "3".to_string() => BigNumber::from_dec("1290534116218716438320066296998198963418131286408035380529548316941923398410560113108756798582290425306108955869685395227366233856654792649735912224097611558139789753950408584482847689838795587330987971669161415485990020598912935103565044825010972005166748548886258351774424917360400285403279510922304340427648959687851483846826461162205002537903920975405118476175947131589471870709350253892921592871530107416727676553006745099259773619545623692882161367026324069754047935205197405410348516798706677778839870157117614346079006190506251578369476561129106768237088298646216941156526296494287589126706469975404040325634910290392295066762902049752200300569175726527074032536078980610848985062237596740068429384399305056827").unwrap(),
                "DELTA".to_string() => BigNumber::from_dec("1290534116218716438320066296998198963418131286408035380529548316941923398410560113108756798582290425306108955869685395227366233856654792649735912224097611558139789753950408584482847689838795587330987971669161415485990020598912935103565044825010972005166748548886258351774424917360400285403279510922304340427648959687851483846826461162205002537903920975405118476175947131589471870709350253892921592871530107416727676553006745099259773619545623692882161367026324069754047935205197405410348516798706677778839870157117614346079006190506251578369476561129106768237088298646216941156526296494287589126706469975404040325634910290392295066762902049752200300569175726527074032536078980610848985062237596740068429384399305056827").unwrap()
            ],
            mj: BigNumber::from_dec("6461691768834933403326572830814516653957231030793837560544354737855803497655300429843454445497126568685843068983890896122000977852186661939211990733462807944627807336518424313388").unwrap(),
            alpha: BigNumber::from_dec("15019832071918025992746443764672619814038193111378331515587108416842661492145380306078894142589602719572721868876278167681416568660826925010252443227187708945569443211855207611790725668148973898984505481716393597614519674900381227829332926574199756037552484050924402042168089180098923015834621320789917504940014743171534983589909973404951099704530137974468076854105300698039259063850979260852809635517557147228671747794193846812925576696224430480061881651647832678242729843914670911122013426552560465450646733551042536367827359597663871827964634864281046557244830435551976095260520198343776886775651606213042069852854661258195991607677409638706741404211201971511463923164836371216756693954129390497870798334804568467571644016689534705243099458035791551892923659589930766121987359966906294865968827326523859020776548628352137573907151416719").unwrap(),
            t: hashmap![
                "0".to_string() => BigNumber::from_dec("43417630723399995147405704831160043226699738088974193922655952212791839159754229694686612556171069291164098371675806713394528764380709961777960841038615195545807927068699240698185936054936058987270723246617225807473853778766553004798072895122353570790092748990750480624057398606328445597615405248766964525613248873555789413697599780484025628512744521163202295727342982847311596077107082893351168466054656892320738566499198863605986805507318252961936985165071695751733674272963680749928972044675415743646575121033161921861708756912378060863266945905724585703789710405474198524740599479287511121708188363170466265186645").unwrap(),
                "1".to_string() => BigNumber::from_dec("36722226848982314680567811997771062638383828354047012538919806599939999127160456447237226368950393496439962666992459033698311124733744083963711166393470803955290971381911274507193981709387505523191368117187074091384646924346700638973173807722733727281592410397831676026466279786567075569837905995849670457506509424137093869661050737596446262008457839619766874798049461600065862281592856187622939978475437479264484697284570903713919546205855317475701520320262681749419906746018812343025594374083863097715974951329849978864273409720176255874977432080252739943546406857149724432737271924184396597489413743665435203185036").unwrap(),
                "2".to_string() => BigNumber::from_dec("36722226848982314680567811997771062638383828354047012538919806599939999127160456447237226368950393496439962666992459033698311124733744083963711166393470803955290971381911274507193981709387505523191368117187074091384646924346700638973173807722733727281592410397831676026466279786567075569837905995849670457506509424137093869661050737596446262008457839619766874798049461600065862281592856187622939978475437479264484697284570903713919546205855317475701520320262681749419906746018812343025594374083863097715974951329849978864273409720176255874977432080252739943546406857149724432737271924184396597489413743665435203185036").unwrap(),
                "3".to_string() => BigNumber::from_dec("36722226848982314680567811997771062638383828354047012538919806599939999127160456447237226368950393496439962666992459033698311124733744083963711166393470803955290971381911274507193981709387505523191368117187074091384646924346700638973173807722733727281592410397831676026466279786567075569837905995849670457506509424137093869661050737596446262008457839619766874798049461600065862281592856187622939978475437479264484697284570903713919546205855317475701520320262681749419906746018812343025594374083863097715974951329849978864273409720176255874977432080252739943546406857149724432737271924184396597489413743665435203185036").unwrap(),
                "DELTA".to_string() => BigNumber::from_dec("15200925076882677157789591684702017059623383056989770565868903056027181948730543992958006723308726004921912800892308236693106779956052024828189927624378588628187084092193792048585904847438401997035239363347036370831220022455446480767807526930979439902956066177870277956875422590851200730884317152112566873283886794804628965955076151434506744414935581441315505752347360465283012954289570640444309747412339681120486660356348167053880912640976118012919486038730936152926928255294036631715239230898556511907889484813751124436548299317858768444665139178324370349441645851840646275463995503285251979214896561204281531077329").unwrap()
            ],
            predicate: predicate()
        }
    }

    pub fn primary_proof() -> PrimaryProof {
        PrimaryProof {
            eq_proof: eq_proof(),
            ne_proofs: vec![ne_proof()],
        }
    }

    pub fn init_non_revocation_proof() -> NonRevocInitProof {
        NonRevocInitProof {
            c_list_params: NonRevocProofXList {
                rho: GroupOrderElement::from_string("1D9432ACD304045A4F0E92AFB7E29BE4E304B57AC31CEC0D038A2A9CF5B0ECAC").unwrap(),
                r: GroupOrderElement::from_string("2501A88F0A8111DB183D0C8BA4C20EC221EAADF916991A1C4024B4BBA5DB9933").unwrap(),
                r_prime: GroupOrderElement::from_string("1091EF19CA17B50750375E43726262AB3B57996B163E14A60203B234DB3441D4").unwrap(),
                r_prime_prime: GroupOrderElement::from_string("1AC83CB0D2FA395CA8BBE52343CAB09F57CECE92BDFF8F4538D5055082A70A68").unwrap(),
                r_prime_prime_prime: GroupOrderElement::from_string("18593C297112FA3BBE8FC2BF3048382937D3ABC60A7E4643F8D34948AE816A31").unwrap(),
                o: GroupOrderElement::from_string("198A91ADEB4299D372EA58BA53401DBB1C77426652C38F6DA727F9DA9768BC96").unwrap(),
                o_prime: GroupOrderElement::from_string("16AC4873732A14ED70AA894C66E9F14FB2A6B30A8FF71E1231259B3946C9D4A9").unwrap(),
                m: GroupOrderElement::from_string("1C711A92F25EF18A496A45E2EE429481583CDD01B4ACC63386E4982647B10AEA").unwrap(),
                m_prime: GroupOrderElement::from_string("1C9D01A3CC41CF3AD171A5E7E29C6E7423F2D09865A68A74A5110DF73182F127").unwrap(),
                t: GroupOrderElement::from_string("0EB3CF17C8C6E60B0E46C2D475F22EE97DC0AEE10358FF21C8ADAD18FDDE30C5").unwrap(),
                t_prime: GroupOrderElement::from_string("0314899F2FC10CD76785553F58E661D36607E159C1517FA490A07F08476E5AB9").unwrap(),
                m2: GroupOrderElement::from_string("099A79BA1F6D7DD6247DBE701CAE80805BED79B043B875CBB37D412BFCA6D402").unwrap(),
                s: GroupOrderElement::from_string("07D1132A74742156EA34EE02CD0A782F36182CC464DFBFBD0DB009D6601604D9").unwrap(),
                c: GroupOrderElement::from_string("02361F8FC95B27163873DF7D2C9B5223FAB7307B5E69297040FC3A0DC778C70B").unwrap(),
            },
            tau_list_params: NonRevocProofXList {
                rho: GroupOrderElement::from_string("22674C7D4598BDE2886E9F5814262169011171826D0041F7A12F1C9EA7FAAB4C").unwrap(),
                r: GroupOrderElement::from_string("177AD1C080B6D7592BECCC2E12F8BC58EB820E575333F20E87DFBA527CDEB256").unwrap(),
                r_prime: GroupOrderElement::from_string("01C6D18A136F4DB647040FCE2FF60BD8B50DB6D4DA526AFA95E11E4E48BC4AC3").unwrap(),
                r_prime_prime: GroupOrderElement::from_string("0B2225568BBA7C53D7E87248114E1936A2D39FF1A033631C8640F5A8778FF8E8").unwrap(),
                r_prime_prime_prime: GroupOrderElement::from_string("0B6C0D13376608BD7617BEBA905852B13E13D9341B8D3A0BCB720123FAFF4C5A").unwrap(),
                o: GroupOrderElement::from_string("241B8DA0709C781DD07F42BBB22548D9D4EEB9467C70B91BA04A4CC2356D98B3").unwrap(),
                o_prime: GroupOrderElement::from_string("06947A2E110FE1D3DF8A253E7122B4486FF435DA7321DAAE7097A002E7AE6612").unwrap(),
                m: GroupOrderElement::from_string("194F785E44112C1CF3DAFC328EC6AEB764CC026697C521E7384FABBC3D15A918").unwrap(),
                m_prime: GroupOrderElement::from_string("073C5D9384EFD20CCE013ABBD5D5532C248E7D665C7EDB74CD1BB49B5FC458E7").unwrap(),
                t: GroupOrderElement::from_string("1172571F3FB78814E96FD962B2BD31C1BC7937E8C58FA05942372F58AEDBB4AC").unwrap(),
                t_prime: GroupOrderElement::from_string("0E4FEED449204DBF040B11D8130635467C9429496BDA901DCE27AB5074A81972").unwrap(),
                m2: GroupOrderElement::from_string("1F0F9075F1F788A63440BC716F30DBCDB8010B8557020CC20B2156CC1D7B2984").unwrap(),
                s: GroupOrderElement::from_string("0EA2C0F584D879AFACFE99CCF2DF0AFCCA7DEF831F0E28F05C2DE752A04C7430").unwrap(),
                c: GroupOrderElement::from_string("01594829F554147480C7111A84A8BEB96D7983514DA58858A0819BCE9EE02FC4").unwrap(),
            },
            c_list: NonRevocProofCList {
                e: PointG1::from_string("1 3FCE336A100BAB7A3C3281A9FAD9451A4168E72D7F024B287187EEAF680B4A36 1 47A69A514C9400040AE4A8DBABD11D194299551A3A89648331E7EDD567DD92E8 1 0C69F45CCEC5BEE692BD1FC1477E3A95CD33F239A98C89CA17C117C7422992B4").unwrap(),
                d: PointG1::from_string("1 2B577B63FFB1C1F315E1DC2AA291D2AEA24EB90B321EFB56D3CFA66C3918514F 1 458E018046A549B8E5F0DF003257FFDE81830325D25EB7E2DD5D8C8CDE96778F 1 1382E98C91C0DE4FCF6B4F615A73CF9DEB7DF0BACB0792D4B66F0F0289DBF93B").unwrap(),
                a: PointG1::from_string("1 2510E16FE9ADD741D0464E57D17ECA374FFB9AA28769090E48DBC13D7E8A33E0 1 657297D1EF240490E4DC9BCC1444DE2EF59886BB828C980E9DCE9ADCE45A4605 1 17B7ABA2E091EB43A8B85EEAD54FC578CFF132713D99D7DA5C8DD5AC68A80225").unwrap(),
                g: PointG1::from_string("1 2ACF58F0B9370ECEA4C42D3D0BDB3C423D50AE0931060B89ED4692B4F2A26AE5 1 5D47FDD2CB9B03A8A4FDF93175469DBFCEAA4DF0EFEFF335CE5B4AACC7B3744C 1 14618FF346DFF513041C6E498D5BAF7E74E882D060A84BA9088FD395B3BE086F").unwrap(),
                w: PointG2::from_string("1 1BCA7F68CF1654884058B9E4D72445A5FE5524CC7FC9F7BC5D31429403AFB0D0 1 20A9ADD723820F077B129B95A052167C2B0AFD30291A5458C93C8F98067CF378 1 0A02522BB69029B9AAF3544E14A1D637EDF87139E0919E63537259B9061913F9 1 19BC32202E297B4851A2223F3ADDB64CBF875F9F2ECFB7F6DDDD4888AC016D57 1 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8 1 0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
                s: PointG2::from_string("1 7A574E39839EBC8E7F8D567865D5D9AAC54952659F0E393BE35C7FC3BE93CDA6 1 AFB9BF4A3B655BFFDC89C14720101773569FDD36A67440AEB7C2FFB861B74025 1 1F25D2A75390350C9C77DE886B503D5EA2CC3685037460F9CF93601BFA88028E 1 306E80C709AAA293B8D2AAABF04838C8AB96BFB3F8E0C4A89940D227A8BF8B01 1 6867E792BBE850A8716C97F7140D95FD6DB76C5DB0F4876E800B18E2CB0226B3 1 427CB9FC452B316239ABCA9C0078E5F36B4E9FC777B6D91587BB7DA64C1C1E94").unwrap(),
                u: PointG2::from_string("1 A460269097754F709D057229B3B195516E876CFFC4111977B22995D5B792321C 1 87B76B62E59EBD7281AFBEA28787110ED9A86AFFD087B62E60EA9A5232B7E92A 1 36C90005C0134A0CFE967B2C63D43E4CF9F6D00CF4EB802A9CFF249B4BA0B0AE 1 ED139245196427A65CE4F35F756462E1EC00D6B59A50713BCBB32EE24320FD74 1 6A0FD899BC2C75711AC67E794D44AC6583E2510CEDD397E646327877521C2D90 1 02EECF9230533915443530F16F69AE45D4B27F327DB48DDFC84AB71272756C5D").unwrap(),
            },
            tau_list: NonRevocProofTauList {
                t1: PointG1::from_string("1 3678700324C153C979FD58E67B12B2296E7CB7DE65CC908BF13061D958599372 1 4899713BD6A1DC1330EF6BB7D9E236D8040F043536B649C2878E1C4E1E9F1E7A 1 01482F9115E53AC4AF12D7DD66B6CC87D997F8BC7EC138960AB023F4477A79A3").unwrap(),
                t2: PointG1::from_string("1 5702010CE630B0FE95AC373350AD96F5802BD34FF51D2ACD977CA87E1D62FA9E 1 66A362A8AEA12987B4B57CFAA9FB7995E2219CAA9A0F7F90A0EB7233002B21E6 1 18144B5641C33799E32E2B45E3F984BEF072F857C1E98F334E21A9932A2130AA").unwrap(),
                t3: Pair::from_string("1 210B51DBD9726CF0CDBFA3803285C73F17A9E43267F2461FAB2FE4DFE1A46F49 1 08C30A04E07CD7353B10D5D451FD7A6E85892B1BC605543AECC75F938CE0F9C8 1 1D58388870144A5D071871C5E2A1FF0CE7B517380E6ADF7325572D8C7D924D19 1 09E20633DCD5743930A7B4327A4E202957BE0A5793DA336E9DF752222178D515 1 05C57A7A26B08EB6147A80DA5C8083BCCDA2E2F5F57D91DBF2F0D28BFC238578 1 1F9FC5FAF9255E04EE123CC26D4577FAEF96CB92734E9E0722078E07D8BC2728 1 1C9265D1B308C907152A1DEDD6E500C6378DCCDC748141BF232F4C8341CDF86B 1 1761FC0F8284812FA0C83D4081717D6C44637C53E68BE3113E427ACF6366CA59 1 091E6E55B798DA22EBD513826781748A8EF99DA756D9CB7B7AC6CF1D7F34A02E 1 1FC3B54A65D9C07CC87540CE5CC9D391625A75616631E4086028F1B7C5D89541 1 15AC82C66461442C0200D69E0795AC2025746DB33677FE50FF87B423F7E9B883 1 1FC6B6EFFC9FBE71BBD95080A5236180DEBA1BC83BD658EB54FBC188DC2E2167").unwrap(),
                t4: Pair::from_string("1 1089AEFD24F60F8A18B2E984ABB1EFBDE1F52E5703978652E4F559B558568F00 1 12FFB2C01C28B2523E6BBB00E8011DAE578060942E9FF0DD2BE0550ED79B610A 1 0A8A9EB60DE3F9F26FEAC0B336C83289455F9BE8465A8A1C4272357BA6624136 1 12523BC395D1EF22E5623D5C4BABCD6E24086A2D8CE5E73F9C0AF377021835DE 1 0DE69863DE3001C9EA78C4633386B385D7B54E46BDCDE3AA664E9D466474F164 1 081D419FB1768840B262E7DDDD779FC3FD60C75D4B617F38A72100B10EB4F866 1 0598A8ED655451AD6AA1B72CC71441BBDE106091232786A4EB46458D320AE1D2 1 24F131F1E7ACF6EAC4D3CB3E50D4D63D2A5C2DA9E7382C557091DD81867CAE43 1 129B4824ECBF8FC8FFFC532ED71C2B2F0DF4D31F70DC453C374FCB9EAC7CDAB2 1 185D20599BF59AD8B50BB52D3A1FF226480CC1F12B735A43500ED10302BCB912 1 06CF10272742931E12B464ACED9F3ADED3278653D4C3E8893B22E99F8CBD0CC3 1 243C4C16F0AC7FBB3115FEEE1BE1061037184BE80A43D46CB5C431848A41206E").unwrap(),
                t5: PointG1::from_string("1 31F880D47752BBBF303ECAD8A109D51A552EBC84B407A1E510239BE83F71CABC 1 593B9A26E0A8C868FC72A0EE9E297E6D1E01D507B8BF84D1B958623E2A9619FA 1 04445E0188187C505D91CCEBA44AA576C2ECE7F36E878FAD2BD35CC32FDBC48D").unwrap(),
                t6: PointG1::from_string("1 3D55331C9A315DB3BB6F9DE5BBEC1DE9A4E7FEA55734A98E0DC078373DD322F4 1 66427E6FFF1A13C4F7B6B9581C21FDBACE14CD0FBB2648C00424E814FB1FCD62 1 045E87648DF9D4EBE16971F77F419B042594A946A9EF03E0374A8D875D96104E").unwrap(),
                t7: Pair::from_string("1 229E5A94E69BACAD5654F32A3BBB00C43493F587E726F82F9F6BF617224E4CF3 1 23B2FA97ECE60840C67AD332F8E0B1702B2231D93CF371F1BAB75BBEDD0B7565 1 0663D0C34F59CF2B2EC00DD9C2F0FAE14AE0A795043D98654A2581921C62F012 1 008EE4574B7DAA690616BFE11775A129AA9BCD5AB1B2D661A32FA571E3BFF816 1 054950BDAFBD304ADAD36CC530979B467E22595C5003D5BB652F475F2C7CEB30 1 122FED2EA0C702628F4F3C0716514958414E22EF123884BF34A01ED36128EA5B 1 07342D1B986A86681B3D54E8B84785098ADF4BD931FD09862A5843188B155AEF 1 041DE3D2209F3DE93E90668DC57FB4BF4C9ECA8985E39971C17D6A963E5DAB86 1 0EA5790E1EE3A385B4AEE2D206C971C7523A8AE2105C4C4CFBF5A695AFDF6F12 1 15C9066E4F711DD6697A1ABA3CCCBF9F535B16AD2E1D898E7BB0E195CEC810C4 1 1150FD2405146DBA647C4DAB59A5AA104A78C63A584DE7E0CF89F1D711FA08F6 1 001591FB803FC84CB514ADF0CA0DCFBC974FDDEFBED8178CF7A0046E5FF148C9").unwrap(),
                t8: Pair::from_string("1 1A0FB1F80E3C1FB1D99656B1B6DDF183D5EF4760838C68B088E892C846B7DC2C 1 1235B7EF46F16A30D6481B2A63E672EBCD931DFE1FE8B4101EA6F8A65FBDCD05 1 02CFBC531AD1C591ACC4F90806D4C8D1D2E7CA1701281076E62DFDFCB743ED0F 1 2472470CB4C5E83208F7CB8FA1C2AFE168CE964EAC3AA0F00D0F851B9BFD640B 1 15010B4BD62468BB8D19513CA350D731E47E034570164DFAE0939F2540FE6132 1 145BB54DDFB66D9C48655F9F7700CC2A341A7BB0B73BA0271927D23A1C9F80A0 1 236FB4C3A3500BF02E7A95A8041ED9C789D57DE3EB9952F773EF8C35953B1FA9 1 152902DA32832510A0DBDE0BE32F6E0DC01374D0DA5B00B30E7A5DFEDF9DE0C7 1 15A9F25FC4079A513FA5B1982AE2808F5D577A8CAE17A030B03B3B10E4606449 1 0CCF8D3EF066E5C4C79106F0A4A5490DD69507161510E56CA43FA304277D2DC7 1 14AB69814995CABA1A07C0B5F8A75B27074CA5CD4213974007B866E0BFE3CA06 1 0151272518EBB8E894FEFB11E19BB4D748F31213DB50454659E1011C2B73FC7C").unwrap(),
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
                e: PointG1::from_string("1 87EEAF680B4A36 1 E72D7F024B2871 1 A9FAD9451A4168 1 100BAB7A3C3281 1 3FCE336A 1 E7EDD567DD92E8 1 551A3A89648331 1 DBABD11D194299 1 4C9400040AE4A8 1 47A69A51 1 C117C7422992B4 1 F239A98C89CA17 1 C1477E3A95CD33 1 CEC5BEE692BD1F 1 C69F45C").unwrap(),
                d: PointG1::from_string("1 CFA66C3918514F 1 B90B321EFB56D3 1 2AA291D2AEA24E 1 FFB1C1F315E1DC 1 2B577B63 1 5D8C8CDE96778F 1 325D25EB7E2DD 1 3257FFDE8183 1 46A549B8E5F0DF 1 458E0180 1 6F0F0289DBF93B 1 F0BACB0792D4B6 1 615A73CF9DEB7D 1 91C0DE4FCF6B4F 1 1382E98C").unwrap(),
                a: PointG1::from_string("1 DBC13D7E8A33E0 1 9AA28769090E48 1 57D17ECA374FFB 1 E9ADD741D0464E 1 2510E16F 1 CE9ADCE45A4605 1 86BB828C980E9D 1 CC1444DE2EF598 1 EF240490E4DC9B 1 657297D1 1 8DD5AC68A80225 1 32713D99D7DA5C 1 EAD54FC578CFF1 1 E091EB43A8B85E 1 17B7ABA2").unwrap(),
                g: PointG1::from_string("1 4692B4F2A26AE5 1 AE0931060B89ED 1 3D0BDB3C423D50 1 B9370ECEA4C42D 1 2ACF58F0 1 5B4AACC7B3744C 1 4DF0EFEFF335CE 1 3175469DBFCEAA 1 CB9B03A8A4FDF9 1 5D47FDD2 1 8FD395B3BE086F 1 82D060A84BA908 1 498D5BAF7E74E8 1 46DFF513041C6E 1 14618FF3").unwrap(),
                w: PointG2::from_string("1 31429403AFB0D0 1 24CC7FC9F7BC5D 1 E4D72445A5FE55 1 CF1654884058B9 1 1BCA7F68 1 3C8F98067CF378 1 FD30291A5458C9 1 95A052167C2B0A 1 23820F077B129B 1 20A9ADD7 1 7259B9061913F9 1 7139E0919E6353 1 4E14A1D637EDF8 1 B69029B9AAF354 1 A02522B 1 DD4888AC016D57 1 5F9F2ECFB7F6DD 1 3F3ADDB64CBF87 1 2E297B4851A222 1 19BC3220 1 FFFFFF7D07A8A8 1 FFFF7888802F07 1 FFC63D474548B7 1 F417D05FB10933 1 95E45DD 1 0 0 0 0 0").unwrap(),
                s: PointG2::from_string("1 5C7FC3BE93CDA6 1 52659F0E393BE3 1 7865D5D9AAC549 1 839EBC8E7F8D56 1 17A574E39 1 C2FFB861B74025 1 DD36A67440AEB7 1 4720101773569F 1 3B655BFFDC89C1 1 1AFB9BF4A 1 93601BFA88028E 1 3685037460F9CF 1 886B503D5EA2CC 1 5390350C9C77DE 1 11F25D2A7 1 40D227A8BF8B01 1 BFB3F8E0C4A899 1 ABF04838C8AB96 1 9AAA293B8D2AA 1 1306E80C7 1 B18E2CB0226B3 1 6C5DB0F4876E80 1 F7140D95FD6DB7 1 BBE850A8716C97 1 6867E792 1 BB7DA64C1C1E94 1 9FC777B6D91587 1 9C0078E5F36B4E 1 452B316239ABCA 1 427CB9FC").unwrap(),
                u: PointG2::from_string("1 2995D5B792321C 1 6CFFC4111977B2 1 29B3B195516E87 1 97754F709D0572 1 1A4602690 1 EA9A5232B7E92A 1 6AFFD087B62E60 1 A28787110ED9A8 1 E59EBD7281AFBE 1 187B76B62 1 FF249B4BA0B0AE 1 D00CF4EB802A9C 1 2C63D43E4CF9F6 1 C0134A0CFE967B 1 136C90005 1 B32EE24320FD74 1 D6B59A50713BCB 1 5F756462E1EC00 1 196427A65CE4F3 1 ED139245 1 327877521C2D90 1 510CEDD397E646 1 794D44AC6583E2 1 BC2C75711AC67E 1 6A0FD899 1 4AB71272756C5D 1 7F327DB48DDFC8 1 F16F69AE45D4B2 1 30533915443530 1 2EECF92").unwrap()
            }
        }
    }

    pub fn sub_proof_request() -> SubProofRequest {
        let mut sub_proof_request_builder = SubProofRequestBuilder::new().unwrap();
        sub_proof_request_builder.add_revealed_attr("name").unwrap();
        sub_proof_request_builder
            .add_predicate("age", "GE", 18)
            .unwrap();
        sub_proof_request_builder.finalize().unwrap()
    }

    pub fn revealed_attrs() -> BTreeSet<String> {
        btreeset!["name".to_owned()]
    }

    pub fn unrevealed_attrs() -> HashSet<String> {
        hashset!["height".to_owned(), "age".to_owned(), "sex".to_owned()]
    }

    pub fn credential_revealed_attributes_values() -> CredentialValues {
        let mut credential_values_builder = CredentialValuesBuilder::new().unwrap();
        credential_values_builder
            .add_dec_known("name", "1139481716457488690172217916278103335")
            .unwrap();
        credential_values_builder.finalize().unwrap()
    }

    pub fn predicate() -> Predicate {
        Predicate {
            attr_name: "age".to_owned(),
            p_type: PredicateType::GE,
            value: 18,
        }
    }
}
