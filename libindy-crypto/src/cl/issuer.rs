use bn::BigNumber;
use cl::*;
use errors::IndyCryptoError;
use pair::*;
use cl::constants::*;
use cl::helpers::*;

use std::collections::{BTreeMap, HashSet};

/// Trust source that provides credentials to prover.
pub struct Issuer {}

impl Issuer {
    /// Creates and returns credential schema entity builder.
    ///
    /// The purpose of credential schema builder is building of credential schema entity that
    /// represents credential schema attributes set.
    ///
    /// # Example
    /// ```
    /// use indy_crypto::cl::issuer::Issuer;
    /// let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
    /// credential_schema_builder.add_attr("sex").unwrap();
    /// credential_schema_builder.add_attr("name").unwrap();
    /// let _credential_schema = credential_schema_builder.finalize().unwrap();
    /// ```
    pub fn new_credential_schema_builder() -> Result<CredentialSchemaBuilder, IndyCryptoError> {
        let res = CredentialSchemaBuilder::new()?;
        Ok(res)
    }

    /// Creates and returns credential definition (public and private keys, correctness proof) entities.
    ///
    /// # Arguments
    /// * `credential_schema` - credential schema entity.
    /// * `support_revocation` - If true non revocation part of keys will be generated.
    ///
    /// # Example
    /// ```
    /// use indy_crypto::cl::issuer::Issuer;
    /// let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
    /// credential_schema_builder.add_attr("name").unwrap();
    /// credential_schema_builder.add_attr("sex").unwrap();
    /// let credential_schema = credential_schema_builder.finalize().unwrap();
    ///
    /// let (_cred_pub_key, _cred_priv_key, _cred_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, true).unwrap();
    /// ```
    pub fn new_credential_def(credential_schema: &CredentialSchema,
                              support_revocation: bool) -> Result<(CredentialPublicKey,
                                                                   CredentialPrivateKey,
                                                                   CredentialKeyCorrectnessProof), IndyCryptoError> {
        trace!("Issuer::new_credential_def: >>> credential_schema: {:?}, support_revocation: {:?}", credential_schema, support_revocation);

        let (p_pub_key, p_priv_key, p_key_meta) =
            Issuer::_new_credential_primary_keys(credential_schema)?;

        let (r_pub_key, r_priv_key) = if support_revocation {
            Issuer::_new_credential_revocation_keys()
                .map(|(r_pub_key, r_priv_key)| (Some(r_pub_key), Some(r_priv_key)))?
        } else {
            (None, None)
        };

        let cred_pub_key = CredentialPublicKey { p_key: p_pub_key, r_key: r_pub_key };
        let cred_priv_key = CredentialPrivateKey { p_key: p_priv_key, r_key: r_priv_key };
        let cred_key_correctness_proof =
            Issuer::_new_credential_key_correctness_proof(&cred_pub_key.p_key,
                                                          &cred_priv_key.p_key,
                                                          &p_key_meta)?;

        trace!("Issuer::new_credential_def: <<< cred_pub_key: {:?}, cred_priv_key: {:?}, cred_key_correctness_proof: {:?}",
               cred_pub_key, cred_priv_key, cred_key_correctness_proof);

        Ok((cred_pub_key, cred_priv_key, cred_key_correctness_proof))
    }

    /// Creates and returns revocation registry definition (public and private keys, accumulator and tails generator) entities.
    ///
    /// # Arguments
    /// * `credential_pub_key` - Credential public key instance pointer.
    /// * `max_cred_num` - Max credential number in generated registry.
    /// * `issuance_by_default` - Type of issuance.
    ///  If true all indices are assumed to be issued and initial accumulator is calculated over all indices
    ///  If false nothing is issued initially accumulator is 1
    ///
    /// # Example
    /// ```
    /// use indy_crypto::cl::issuer::Issuer;
    /// let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
    /// credential_schema_builder.add_attr("name").unwrap();
    /// credential_schema_builder.add_attr("sex").unwrap();
    /// let credential_schema = credential_schema_builder.finalize().unwrap();
    ///
    /// let (cred_pub_key, _cred_priv_key, _cred_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, true).unwrap();
    ///
    /// let max_cred_num = 5;
    /// let (_rev_key_pub, _rev_key_priv, _rev_reg, _rev_tails_generator) = Issuer::new_revocation_registry_def(&cred_pub_key, max_cred_num, false).unwrap();

    /// ```
    pub fn new_revocation_registry_def(credential_pub_key: &CredentialPublicKey,
                                       max_cred_num: u32,
                                       issuance_by_default: bool) -> Result<(RevocationKeyPublic,
                                                                             RevocationKeyPrivate,
                                                                             RevocationRegistry,
                                                                             RevocationTailsGenerator), IndyCryptoError> {
        trace!("Issuer::new_revocation_registry_def: >>> credential_pub_key: {:?}, max_cred_num: {:?}, issuance_by_default: {:?}",
               credential_pub_key, max_cred_num, issuance_by_default);

        let cred_rev_pub_key: &CredentialRevocationPublicKey = credential_pub_key.r_key
            .as_ref()
            .ok_or(IndyCryptoError::InvalidStructure(format!("No revocation part present in credential public key.")))?;

        let (rev_key_pub, rev_key_priv) = Issuer::_new_revocation_registry_keys(cred_rev_pub_key, max_cred_num)?;

        let rev_reg = Issuer::_new_revocation_registry(cred_rev_pub_key,
                                                       &rev_key_priv,
                                                       max_cred_num,
                                                       issuance_by_default)?;

        let rev_tails_generator = RevocationTailsGenerator {
            size: 2 * max_cred_num,
            current_index: 0,
            gamma: rev_key_priv.gamma.clone(),
            g_dash: cred_rev_pub_key.g_dash.clone()
        };

        trace!("Issuer::new_revocation_registry_def: <<< rev_key_pub: {:?}, rev_key_priv: {:?}, rev_reg: {:?}, rev_tails_generator: {:?}",
               rev_key_pub, rev_key_priv, rev_reg, rev_tails_generator);

        Ok((rev_key_pub, rev_key_priv, rev_reg, rev_tails_generator))
    }

    /// Creates and returns credential values entity builder.
    ///
    /// The purpose of credential values builder is building of credential values entity that
    /// represents credential attributes values map.
    ///
    /// # Example
    /// ```
    /// use indy_crypto::cl::issuer::Issuer;
    /// let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();
    /// credential_values_builder.add_value("sex", "5944657099558967239210949258394887428692050081607692519917050011144233115103").unwrap();
    /// credential_values_builder.add_value("name", "1139481716457488690172217916278103335").unwrap();
    /// let _credential_values = credential_values_builder.finalize().unwrap();
    /// ```
    pub fn new_credential_values_builder() -> Result<CredentialValuesBuilder, IndyCryptoError> {
        let res = CredentialValuesBuilder::new()?;
        Ok(res)
    }

    /// Sign given credential values with primary only part.
    ///
    /// # Arguments
    /// * `prover_id` - Prover identifier.
    /// * `blinded_master_secret` - Blinded master secret.
    /// * `blinded_master_secret_correctness_proof` - Blinded master secret correctness proof.
    /// * `master_secret_blinding_nonce` - Nonce used for blinded_master_secret_correctness_proof verification.
    /// * `credential_issuance_nonce` - Nonce used for creating of signature correctness proof.
    /// * `credential_values` - Claim values to be signed.
    /// * `credential_pub_key` - credential public key.
    /// * `credential_priv_key` - credential private key.
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
    /// let (credential_pub_key, credential_priv_key, cred_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, false).unwrap();
    ///
    /// let master_secret = Prover::new_master_secret().unwrap();
    /// let master_secret_blinding_nonce = new_nonce().unwrap();
    /// let (blinded_master_secret, _, blinded_master_secret_correctness_proof) =
    ///      Prover::blind_master_secret(&credential_pub_key, &cred_key_correctness_proof, &master_secret, &master_secret_blinding_nonce).unwrap();
    ///
    /// let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();
    /// credential_values_builder.add_value("sex", "5944657099558967239210949258394887428692050081607692519917050011144233115103").unwrap();
    /// let credential_values = credential_values_builder.finalize().unwrap();
    ///
    /// let credential_issuance_nonce = new_nonce().unwrap();
    ///
    /// let (_credential_signature, _signature_correctness_proof) =
    ///     Issuer::sign_credential("CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW",
    ///                             &blinded_master_secret,
    ///                             &blinded_master_secret_correctness_proof,
    ///                             &master_secret_blinding_nonce,
    ///                             &credential_issuance_nonce,
    ///                             &credential_values,
    ///                             &credential_pub_key,
    ///                             &credential_priv_key).unwrap();
    /// ```
    pub fn sign_credential(prover_id: &str,
                           blinded_master_secret: &BlindedMasterSecret,
                           blinded_master_secret_correctness_proof: &BlindedMasterSecretCorrectnessProof,
                           master_secret_blinding_nonce: &Nonce,
                           credential_issuance_nonce: &Nonce,
                           credential_values: &CredentialValues,
                           credential_pub_key: &CredentialPublicKey,
                           credential_priv_key: &CredentialPrivateKey) -> Result<(CredentialSignature, SignatureCorrectnessProof), IndyCryptoError> {
        trace!("Issuer::sign_credential: >>> prover_id: {:?}, blinded_master_secret: {:?}, blinded_master_secret_correctness_proof: {:?},\
        master_secret_blinding_nonce: {:?}, credential_issuance_nonce: {:?}, credential_values: {:?}, credential_pub_key: {:?}, credential_priv_key: {:?}",
               prover_id, blinded_master_secret, blinded_master_secret_correctness_proof, master_secret_blinding_nonce, credential_values, credential_issuance_nonce,
               credential_pub_key, credential_priv_key);

        Issuer::_check_blinded_master_secret_correctness_proof(blinded_master_secret,
                                                               blinded_master_secret_correctness_proof,
                                                               master_secret_blinding_nonce,
                                                               &credential_pub_key.p_key)?;

        // In the anoncreds whitepaper, `credential context` is denoted by `m2`
        let cred_context = Issuer::_gen_credential_context(prover_id, None)?;

        let (p_cred, q) = Issuer::_new_primary_credential(&cred_context,
                                                          credential_pub_key,
                                                          credential_priv_key,
                                                          blinded_master_secret,
                                                          credential_values)?;

        let cred_signature = CredentialSignature { p_credential: p_cred, r_credential: None };

        let signature_correctness_proof = Issuer::_new_signature_correctness_proof(&credential_pub_key.p_key,
                                                                                   &credential_priv_key.p_key,
                                                                                   &cred_signature.p_credential,
                                                                                   &q,
                                                                                   credential_issuance_nonce)?;


        trace!("Issuer::sign_credential: <<< cred_signature: {:?}, signature_correctness_proof: {:?}",
               cred_signature, signature_correctness_proof);

        Ok((cred_signature, signature_correctness_proof))
    }

    /// Sign given credential values with both primary and revocation parts.
    ///
    /// # Arguments
    /// * `prover_id` - Prover identifier.
    /// * `blinded_master_secret` - Blinded master secret.
    /// * `blinded_master_secret_correctness_proof` - Blinded master secret correctness proof.
    /// * `master_secret_blinding_nonce` - Nonce used for blinded_master_secret_correctness_proof verification.
    /// * `credential_issuance_nonce` - Nonce used for creating of signature correctness proof.
    /// * `credential_values` - Claim values to be signed.
    /// * `credential_pub_key` - credential public key.
    /// * `credential_priv_key` - credential private key.
    /// * `rev_idx` - User index in revocation accumulator. Required for non-revocation credential_signature part generation.
    /// * `max_cred_num` - Max credential number in generated registry.
    /// * `rev_reg` - Revocation registry.
    /// * `rev_key_priv` - Revocation registry private key.
    /// * `rev_tails_accessor` - Revocation registry tails accessor.
    ///
    /// # Example
    /// ```
    /// use indy_crypto::cl::{new_nonce, SimpleTailsAccessor};
    /// use indy_crypto::cl::issuer::Issuer;
    /// use indy_crypto::cl::prover::Prover;
    ///
    /// let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
    /// credential_schema_builder.add_attr("name").unwrap();
    /// credential_schema_builder.add_attr("sex").unwrap();
    /// let credential_schema = credential_schema_builder.finalize().unwrap();
    ///
    /// let (cred_pub_key, cred_priv_key, cred_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, true).unwrap();
    ///
    /// let max_cred_num = 5;
    /// let (_rev_key_pub, rev_key_priv, mut rev_reg, mut rev_tails_generator) = Issuer::new_revocation_registry_def(&cred_pub_key, max_cred_num, false).unwrap();
    ///
    /// let simple_tail_accessor = SimpleTailsAccessor::new(&mut rev_tails_generator).unwrap();
    ///
    /// let master_secret = Prover::new_master_secret().unwrap();
    ///
    /// let master_secret_blinding_nonce = new_nonce().unwrap();
    ///
    /// let (blinded_master_secret, _master_secret_blinding_data, blinded_master_secret_correctness_proof) =
    ///     Prover::blind_master_secret(&cred_pub_key,
    ///                                 &cred_key_correctness_proof,
    ///                                 &master_secret,
    ///                                 &master_secret_blinding_nonce).unwrap();
    ///
    /// let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();
    /// credential_values_builder.add_value("name", "1139481716457488690172217916278103335").unwrap();
    /// credential_values_builder.add_value("sex", "5944657099558967239210949258394887428692050081607692519917050011144233115103").unwrap();
    /// let cred_values = credential_values_builder.finalize().unwrap();
    ///
    /// let credential_issuance_nonce = new_nonce().unwrap();
    ///
    /// let rev_idx = 1;
    /// let (_cred_signature, _signature_correctness_proof, _rev_reg_delta) =
    ///     Issuer::sign_credential_with_revoc("CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW",
    ///                                        &blinded_master_secret,
    ///                                        &blinded_master_secret_correctness_proof,
    ///                                        &master_secret_blinding_nonce,
    ///                                        &credential_issuance_nonce,
    ///                                        &cred_values,
    ///                                        &cred_pub_key,
    ///                                        &cred_priv_key,
    ///                                        rev_idx,
    ///                                        max_cred_num,
    ///                                        false,
    ///                                        &mut rev_reg,
    ///                                        &rev_key_priv,
    ///                                         &simple_tail_accessor).unwrap();
    /// ```
    pub fn sign_credential_with_revoc<RTA>(prover_id: &str,
                                           blinded_master_secret: &BlindedMasterSecret,
                                           blinded_master_secret_correctness_proof: &BlindedMasterSecretCorrectnessProof,
                                           master_secret_blinding_nonce: &Nonce,
                                           credential_issuance_nonce: &Nonce,
                                           credential_values: &CredentialValues,
                                           credential_pub_key: &CredentialPublicKey,
                                           credential_priv_key: &CredentialPrivateKey,
                                           rev_idx: u32,
                                           max_cred_num: u32,
                                           issuance_by_default: bool,
                                           rev_reg: &mut RevocationRegistry,
                                           rev_key_priv: &RevocationKeyPrivate,
                                           rev_tails_accessor: &RTA)
                                           -> Result<(CredentialSignature, SignatureCorrectnessProof, Option<RevocationRegistryDelta>),
                                               IndyCryptoError> where RTA: RevocationTailsAccessor {
        trace!("Issuer::sign_credential: >>> prover_id: {:?}, blinded_master_secret: {:?}, blinded_master_secret_correctness_proof: {:?},\
        master_secret_blinding_nonce: {:?}, credential_issuance_nonce: {:?}, credential_values: {:?}, credential_pub_key: {:?}, credential_priv_key: {:?}, \
        rev_idx: {:?}, max_cred_num: {:?}, rev_reg: {:?}, rev_key_priv: {:?}",
               prover_id, blinded_master_secret, blinded_master_secret_correctness_proof, master_secret_blinding_nonce, credential_values, credential_issuance_nonce,
               credential_pub_key, credential_priv_key, rev_idx, max_cred_num, rev_reg, rev_key_priv);

        Issuer::_check_blinded_master_secret_correctness_proof(blinded_master_secret,
                                                               blinded_master_secret_correctness_proof,
                                                               master_secret_blinding_nonce,
                                                               &credential_pub_key.p_key)?;

        // In the anoncreds whitepaper, `credential context` is denoted by `m2`
        let cred_context = Issuer::_gen_credential_context(prover_id, Some(rev_idx))?;

        let (p_cred, q) = Issuer::_new_primary_credential(&cred_context,
                                                          credential_pub_key,
                                                          credential_priv_key,
                                                          blinded_master_secret,
                                                          credential_values)?;

        let (r_cred, rev_reg_delta) = Issuer::_new_non_revocation_credential(rev_idx,
                                                                             &cred_context,
                                                                             blinded_master_secret,
                                                                             credential_pub_key,
                                                                             credential_priv_key,
                                                                             max_cred_num,
                                                                             issuance_by_default,
                                                                             rev_reg,
                                                                             rev_key_priv,
                                                                             rev_tails_accessor)?;

        let cred_signature = CredentialSignature { p_credential: p_cred, r_credential: Some(r_cred) };

        let signature_correctness_proof = Issuer::_new_signature_correctness_proof(&credential_pub_key.p_key,
                                                                                   &credential_priv_key.p_key,
                                                                                   &cred_signature.p_credential,
                                                                                   &q,
                                                                                   credential_issuance_nonce)?;


        trace!("Issuer::sign_credential: <<< cred_signature: {:?}, signature_correctness_proof: {:?}, rev_reg_delta: {:?}",
               cred_signature, signature_correctness_proof, rev_reg_delta);

        Ok((cred_signature, signature_correctness_proof, rev_reg_delta))
    }

    /// Revokes a credential by a rev_idx in a given revocation registry
    ///
    /// # Arguments
    /// * `rev_reg` - Revocation registry.
    /// * `max_cred_num` - (Optional) Max credential number in generated registry.
    ///  * rev_idx` - index of the user in the accumulator
    /// * `rev_tails_accessor` - (Optional) Revocation registry tails accessor.
    ///
    /// # Example
    /// ```
    /// use indy_crypto::cl::{new_nonce, SimpleTailsAccessor};
    /// use indy_crypto::cl::issuer::Issuer;
    /// use indy_crypto::cl::prover::Prover;
    ///
    /// let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
    /// credential_schema_builder.add_attr("name").unwrap();
    /// credential_schema_builder.add_attr("sex").unwrap();
    /// let credential_schema = credential_schema_builder.finalize().unwrap();
    ///
    /// let (cred_pub_key, cred_priv_key, cred_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, true).unwrap();
    ///
    /// let max_cred_num = 5;
    /// let (_rev_key_pub, rev_key_priv, mut rev_reg, mut rev_tails_generator) = Issuer::new_revocation_registry_def(&cred_pub_key, max_cred_num, false).unwrap();
    ///
    /// let simple_tail_accessor = SimpleTailsAccessor::new(&mut rev_tails_generator).unwrap();
    ///
    /// let master_secret = Prover::new_master_secret().unwrap();
    ///
    /// let master_secret_blinding_nonce = new_nonce().unwrap();
    ///
    /// let (blinded_master_secret, _master_secret_blinding_data, blinded_master_secret_correctness_proof) =
    ///     Prover::blind_master_secret(&cred_pub_key,
    ///                                 &cred_key_correctness_proof,
    ///                                 &master_secret,
    ///                                 &master_secret_blinding_nonce).unwrap();
    ///
    /// let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();
    /// credential_values_builder.add_value("name", "1139481716457488690172217916278103335").unwrap();
    /// credential_values_builder.add_value("sex", "5944657099558967239210949258394887428692050081607692519917050011144233115103").unwrap();
    /// let cred_values = credential_values_builder.finalize().unwrap();
    ///
    /// let credential_issuance_nonce = new_nonce().unwrap();
    ///
    /// let rev_idx = 1;
    /// let (_cred_signature, _signature_correctness_proof, _rev_reg_delta) =
    ///     Issuer::sign_credential_with_revoc("CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW",
    ///                                        &blinded_master_secret,
    ///                                        &blinded_master_secret_correctness_proof,
    ///                                        &master_secret_blinding_nonce,
    ///                                        &credential_issuance_nonce,
    ///                                        &cred_values,
    ///                                        &cred_pub_key,
    ///                                        &cred_priv_key,
    ///                                        rev_idx,
    ///                                        max_cred_num,
    ///                                        false,
    ///                                        &mut rev_reg,
    ///                                        &rev_key_priv,
    ///                                         &simple_tail_accessor).unwrap();
    /// Issuer::revoke_credential(&mut rev_reg, max_cred_num, rev_idx, &simple_tail_accessor).unwrap();
    /// ```
    pub fn revoke_credential<RTA>(rev_reg: &mut RevocationRegistry,
                                  max_cred_num: u32,
                                  rev_idx: u32,
                                  rev_tails_accessor: &RTA) -> Result<RevocationRegistryDelta, IndyCryptoError> where RTA: RevocationTailsAccessor {
        trace!("Issuer::revoke_credential: >>> rev_reg: {:?}, rev_idx: {:?}", rev_reg, rev_idx);

        let prev_accum = rev_reg.accum.clone();

        let index = max_cred_num + 1 - rev_idx;

        rev_tails_accessor.access_tail(index, &mut |tail| {
            rev_reg.accum = rev_reg.accum.sub(tail).unwrap();
        })?;

        let mut revoked = HashSet::new();
        revoked.insert(rev_idx);

        let rev_reg_delta = RevocationRegistryDelta {
            prev_accum: Some(prev_accum),
            accum: rev_reg.accum.clone(),
            issued: HashSet::new(),
            revoked
        };

        trace!("Issuer::revoke_credential: <<< rev_reg_delta: {:?}", rev_reg_delta);

        Ok(rev_reg_delta)
    }

    fn _new_credential_primary_keys(credential_schema: &CredentialSchema) -> Result<(CredentialPrimaryPublicKey,
                                                                                     CredentialPrimaryPrivateKey,
                                                                                     CredentialPrimaryPublicKeyMetadata), IndyCryptoError> {
        trace!("Issuer::_new_credential_primary_keys: >>> credential_schema: {:?}", credential_schema);

        let mut ctx = BigNumber::new_context()?;

        if credential_schema.attrs.len() == 0 {
            return Err(IndyCryptoError::InvalidStructure(format!("List of attributes is empty")));
        }

        let p_safe = generate_safe_prime(LARGE_PRIME)?;
        let q_safe = generate_safe_prime(LARGE_PRIME)?;

        let mut p = p_safe.sub(&BigNumber::from_u32(1)?)?;
        p.div_word(2)?;

        let mut q = q_safe.sub(&BigNumber::from_u32(1)?)?;
        q.div_word(2)?;

        let n = p_safe.mul(&q_safe, Some(&mut ctx))?;
        let s = random_qr(&n)?;
        let xz = gen_x(&p, &q)?;

        let mut xr = BTreeMap::new();
        for attribute in &credential_schema.attrs {
            xr.insert(attribute.to_string(), gen_x(&p, &q)?);
        }

        let mut r = BTreeMap::new();
        for (key, xr_value) in xr.iter() {
            r.insert(key.to_string(), s.mod_exp(&xr_value, &n, Some(&mut ctx))?);
        }

        let z = s.mod_exp(&xz, &n, Some(&mut ctx))?;

        let rms = s.mod_exp(&gen_x(&p, &q)?, &n, Some(&mut ctx))?;
        let rctxt = s.mod_exp(&gen_x(&p, &q)?, &n, Some(&mut ctx))?;

        let cred_pr_pub_key = CredentialPrimaryPublicKey { n, s, rms, rctxt, r, z };
        let cred_pr_priv_key = CredentialPrimaryPrivateKey { p, q };
        let cred_pr_pub_key_metadata = CredentialPrimaryPublicKeyMetadata { xz, xr };

        trace!("Issuer::_new_credential_primary_keys: <<< cred_pr_pub_key: {:?}, cred_pr_priv_key: {:?}, cred_pr_pub_key_metadata: {:?}",
               cred_pr_pub_key, cred_pr_priv_key, cred_pr_pub_key_metadata);

        Ok((cred_pr_pub_key, cred_pr_priv_key, cred_pr_pub_key_metadata))
    }

    fn _new_credential_revocation_keys() -> Result<(CredentialRevocationPublicKey,
                                                    CredentialRevocationPrivateKey), IndyCryptoError> {
        trace!("Issuer::_new_credential_revocation_keys: >>>");

        let h = PointG1::new()?;
        let h0 = PointG1::new()?;
        let h1 = PointG1::new()?;
        let h2 = PointG1::new()?;
        let htilde = PointG1::new()?;
        let g = PointG1::new()?;

        let u = PointG2::new()?;
        let h_cap = PointG2::new()?;

        let x = GroupOrderElement::new()?;
        let sk = GroupOrderElement::new()?;
        let g_dash = PointG2::new()?;

        let pk = g.mul(&sk)?;
        let y = h_cap.mul(&x)?;

        let cred_rev_pub_key = CredentialRevocationPublicKey { g, g_dash, h, h0, h1, h2, htilde, h_cap, u, pk, y };
        let cred_rev_priv_key = CredentialRevocationPrivateKey { x, sk };

        trace!("Issuer::_new_credential_revocation_keys: <<< cred_rev_pub_key: {:?}, cred_rev_priv_key: {:?}", cred_rev_pub_key, cred_rev_priv_key);

        Ok((cred_rev_pub_key, cred_rev_priv_key))
    }

    fn _new_credential_key_correctness_proof(cred_pr_pub_key: &CredentialPrimaryPublicKey,
                                             cred_pr_priv_key: &CredentialPrimaryPrivateKey,
                                             cred_pr_pub_key_meta: &CredentialPrimaryPublicKeyMetadata)
                                             -> Result<CredentialKeyCorrectnessProof, IndyCryptoError> {
        trace!("Issuer::_new_credential_key_correctness_proof: >>> cred_pr_pub_key: {:?}, cred_pr_priv_key: {:?}, cred_pr_pub_key_meta: {:?}", cred_pr_pub_key, cred_pr_priv_key, cred_pr_pub_key_meta);

        let mut ctx = BigNumber::new_context()?;

        let func = gen_x;

        let xz_tilda = func(&cred_pr_priv_key.p, &cred_pr_priv_key.q)?;

        let mut xr_tilda = BTreeMap::new();
        for key in cred_pr_pub_key.r.keys() {
            xr_tilda.insert(key.to_string(), func(&cred_pr_priv_key.p, &cred_pr_priv_key.q)?);
        }

        let z_tilda = cred_pr_pub_key.s.mod_exp(&xz_tilda, &cred_pr_pub_key.n, Some(&mut ctx))?;

        let mut r_tilda = BTreeMap::new();
        for (key, xr_tilda_value) in xr_tilda.iter() {
            r_tilda.insert(key.to_string(), cred_pr_pub_key.s.mod_exp(&xr_tilda_value, &cred_pr_pub_key.n, Some(&mut ctx))?);
        }

        let mut values: Vec<u8> = Vec::new();
        values.extend_from_slice(&cred_pr_pub_key.z.to_bytes()?);
        for val in cred_pr_pub_key.r.values() {
            values.extend_from_slice(&val.to_bytes()?);
        }
        values.extend_from_slice(&z_tilda.to_bytes()?);
        for val in r_tilda.values() {
            values.extend_from_slice(&val.to_bytes()?);
        }

        let c = get_hash_as_int(&mut vec![values])?;

        let xz_cap =
            c.mul(&cred_pr_pub_key_meta.xz, Some(&mut ctx))?
                .add(&xz_tilda)?;

        let mut xr_cap: BTreeMap<String, BigNumber> = BTreeMap::new();
        for (key, xr_tilda_value) in xr_tilda {
            let val =
                c.mul(&cred_pr_pub_key_meta.xr[&key], Some(&mut ctx))?
                    .add(&xr_tilda_value)?;
            xr_cap.insert(key.to_string(), val);
        }

        let key_correctness_proof = CredentialKeyCorrectnessProof { c, xz_cap, xr_cap };

        trace!("Issuer::_new_credential_key_correctness_proof: <<< key_correctness_proof: {:?}", key_correctness_proof);

        Ok(key_correctness_proof)
    }

    fn _new_revocation_registry(cred_rev_pub_key: &CredentialRevocationPublicKey,
                                rev_key_priv: &RevocationKeyPrivate,
                                max_cred_num: u32,
                                issuance_by_default: bool) -> Result<RevocationRegistry, IndyCryptoError> {
        trace!("Issuer::_new_revocation_registry: >>> cred_rev_pub_key: {:?}, rev_key_priv: {:?}, max_cred_num: {:?}, issuance_by_default: {:?}",
               cred_rev_pub_key, rev_key_priv, max_cred_num, issuance_by_default);

        let mut accum = Accumulator::new_inf()?;

        if issuance_by_default {
            for i in 1..max_cred_num + 1 {
                let index = max_cred_num + 1 - i;
                accum = accum.add(&Tail::new_tail(index, &cred_rev_pub_key.g_dash, &rev_key_priv.gamma)?)?;
            }
        };

        let rev_reg = RevocationRegistry {
            accum
        };

        trace!("Issuer::_new_revocation_registry: <<< rev_reg: {:?}", rev_reg);

        Ok(rev_reg)
    }

    fn _new_revocation_registry_keys(cred_rev_pub_key: &CredentialRevocationPublicKey,
                                     max_cred_num: u32) -> Result<(RevocationKeyPublic, RevocationKeyPrivate), IndyCryptoError> {
        trace!("Issuer::_new_revocation_registry_keys: >>> cred_rev_pub_key: {:?}, max_cred_num: {:?}",
               cred_rev_pub_key, max_cred_num);

        let gamma = GroupOrderElement::new()?;

        let mut z = Pair::pair(&cred_rev_pub_key.g, &cred_rev_pub_key.g_dash)?;
        let mut pow = GroupOrderElement::from_bytes(&transform_u32_to_array_of_u8(max_cred_num + 1))?;
        pow = gamma.pow_mod(&pow)?;
        z = z.pow(&pow)?;

        let rev_key_pub = RevocationKeyPublic { z };
        let rev_key_priv = RevocationKeyPrivate { gamma };

        trace!("Issuer::_new_revocation_registry_keys: <<< rev_key_pub: {:?}, rev_key_priv: {:?}",
               rev_key_pub, rev_key_priv);

        Ok((rev_key_pub, rev_key_priv))
    }

    fn _check_blinded_master_secret_correctness_proof(blinded_ms: &BlindedMasterSecret,
                                                      blinded_ms_correctness_proof: &BlindedMasterSecretCorrectnessProof,
                                                      nonce: &Nonce,
                                                      cred_pr_pub_key: &CredentialPrimaryPublicKey) -> Result<(), IndyCryptoError> {
        trace!("Issuer::_check_blinded_master_secret_correctness_proof: >>> blinded_ms: {:?}, blinded_ms_correctness_proof: {:?},\
         nonce: {:?}, cred_pr_pub_key: {:?}", blinded_ms, blinded_ms_correctness_proof, nonce, cred_pr_pub_key);

        let mut ctx = BigNumber::new_context()?;

        let u_cap =
            blinded_ms.u
                .inverse(&cred_pr_pub_key.n, Some(&mut ctx))?
                .mod_exp(&blinded_ms_correctness_proof.c, &cred_pr_pub_key.n, Some(&mut ctx))?
                .mod_mul(
                    &cred_pr_pub_key.s.mod_exp(&blinded_ms_correctness_proof.v_dash_cap, &cred_pr_pub_key.n, Some(&mut ctx))?,
                    &cred_pr_pub_key.n,
                    Some(&mut ctx)
                )?
                .mod_mul(
                    &cred_pr_pub_key.rms.mod_exp(&blinded_ms_correctness_proof.ms_cap, &cred_pr_pub_key.n, Some(&mut ctx))?,
                    &cred_pr_pub_key.n,
                    Some(&mut ctx)
                )?;

        let mut values: Vec<u8> = Vec::new();
        values.extend_from_slice(&blinded_ms.u.to_bytes()?);
        values.extend_from_slice(&u_cap.to_bytes()?);
        values.extend_from_slice(&nonce.to_bytes()?);

        let c = get_hash_as_int(&mut vec![values])?;

        let valid = blinded_ms_correctness_proof.c.eq(&c);

        if !valid {
            return Err(IndyCryptoError::InvalidStructure(format!("Invalid BlindedMasterSecret correctness proof")));
        }

        trace!("Issuer::_check_blinded_master_secret_correctness_proof: <<<");

        Ok(())
    }

    // In the anoncreds whitepaper, `credential context` is denoted by `m2`
    fn _gen_credential_context(prover_id: &str, rev_idx: Option<u32>) -> Result<BigNumber, IndyCryptoError> {
        trace!("Issuer::_calc_m2: >>> prover_id: {:?}, rev_idx: {:?}", prover_id, rev_idx);

        let rev_idx = rev_idx.map(|i| i as i32).unwrap_or(-1);

        let prover_id_bn = encode_attribute(prover_id, ByteOrder::Little)?;
        let rev_idx_bn = encode_attribute(&rev_idx.to_string(), ByteOrder::Little)?;

        let mut s = vec![
            bitwise_or_big_int(&rev_idx_bn, &prover_id_bn)?.to_bytes()?
        ];

        /* TODO: FIXME: use const!!! */
        let pow_2 = BigNumber::from_u32(2)?.exp(&BigNumber::from_u32(LARGE_MASTER_SECRET)?, None)?;
        let credential_context = get_hash_as_int(&mut s)?.modulus(&pow_2, None)?;

        trace!("Issuer::_gen_credential_context: <<< credential_context: {:?}", credential_context);

        Ok(credential_context)
    }

    fn _new_primary_credential(credential_context: &BigNumber,
                               cred_pub_key: &CredentialPublicKey,
                               cred_priv_key: &CredentialPrivateKey,
                               blinded_ms: &BlindedMasterSecret,
                               cred_values: &CredentialValues) -> Result<(PrimaryCredentialSignature, BigNumber), IndyCryptoError> {
        trace!("Issuer::_new_primary_credential: >>> credential_context: {:?}, cred_pub_key: {:?}, cred_priv_key: {:?}, blinded_ms: {:?},\
         cred_values: {:?}", credential_context, cred_pub_key, cred_priv_key, blinded_ms, cred_values);

        let v = generate_v_prime_prime()?;

        let e_start = BigNumber::from_u32(2)?.exp(&BigNumber::from_u32(LARGE_E_START)?, None)?;
        let e_end = BigNumber::from_u32(2)?
            .exp(&BigNumber::from_u32(LARGE_E_END_RANGE)?, None)?
            .add(&e_start)?;

        let e = generate_prime_in_range(&e_start, &e_end)?;
        let (a, q) = Issuer::_sign_primary_credential(cred_pub_key, cred_priv_key, &credential_context, &cred_values, &v, blinded_ms, &e)?;

        let pr_cred_sig = PrimaryCredentialSignature { m_2: credential_context.clone()?, a, e, v };

        trace!("Issuer::_new_primary_credential: <<< pr_cred_sig: {:?}, q: {:?}", pr_cred_sig, q);

        Ok((pr_cred_sig, q))
    }

    fn _sign_primary_credential(cred_pub_key: &CredentialPublicKey,
                                cred_priv_key: &CredentialPrivateKey,
                                cred_context: &BigNumber,
                                cred_values: &CredentialValues,
                                v: &BigNumber,
                                blnd_ms: &BlindedMasterSecret,
                                e: &BigNumber) -> Result<(BigNumber, BigNumber), IndyCryptoError> {
        trace!("Issuer::_sign_primary_credential: >>> cred_pub_key: {:?}, cred_priv_key: {:?}, cred_context: {:?}, cred_values: {:?}, v: {:?},\
         blnd_ms: {:?}, e: {:?}", cred_pub_key, cred_priv_key, cred_context, cred_values, v, blnd_ms, e);

        let p_pub_key = &cred_pub_key.p_key;
        let p_priv_key = &cred_priv_key.p_key;

        let mut context = BigNumber::new_context()?;

        let mut rx = p_pub_key.s
            .mod_exp(&v, &p_pub_key.n, Some(&mut context))?;

        if blnd_ms.u != BigNumber::from_u32(0)? {
            rx = blnd_ms.u.modulus(&p_pub_key.n, Some(&mut context))?
                .mul(&rx, Some(&mut context))?;
        }

        rx = p_pub_key.rctxt.mod_exp(&cred_context, &p_pub_key.n, Some(&mut context))?
            .mul(&rx, Some(&mut context))?;

        for (key, value) in &cred_values.attrs_values {
            let pk_r = p_pub_key.r
                .get(key)
                .ok_or(IndyCryptoError::InvalidStructure(format!("Value by key '{}' not found in pk.r", key)))?;

            rx = pk_r.mod_exp(&value, &p_pub_key.n, Some(&mut context))?
                .mod_mul(&rx, &p_pub_key.n, Some(&mut context))?;
        }

        let q = p_pub_key.z.mod_div(&rx, &p_pub_key.n)?;

        let n = p_priv_key.p.mul(&p_priv_key.q, Some(&mut context))?;
        let e_inverse = e.inverse(&n, Some(&mut context))?;

        let a = q.mod_exp(&e_inverse, &p_pub_key.n, Some(&mut context))?;

        trace!("Issuer::_sign_primary_credential: <<< a: {:?}, q: {:?}", a, q);

        Ok((a, q))
    }

    fn _new_signature_correctness_proof(p_pub_key: &CredentialPrimaryPublicKey,
                                        p_priv_key: &CredentialPrimaryPrivateKey,
                                        p_cred_signature: &PrimaryCredentialSignature,
                                        q: &BigNumber,
                                        nonce: &BigNumber) -> Result<SignatureCorrectnessProof, IndyCryptoError> {
        trace!("Issuer::_new_signature_correctness_proof: >>> p_pub_key: {:?}, p_priv_key: {:?}, p_cred_signature: {:?}, q: {:?}, nonce: {:?}",
               p_pub_key, p_priv_key, p_cred_signature, q, nonce);

        let mut ctx = BigNumber::new_context()?;

        let n = p_priv_key.p.mul(&p_priv_key.q, Some(&mut ctx))?;
        let r = bn_rand_range(&n)?;

        let a_cap = q.mod_exp(&r, &p_pub_key.n, Some(&mut ctx))?;

        let mut values: Vec<u8> = Vec::new();
        values.extend_from_slice(&q.to_bytes()?);
        values.extend_from_slice(&p_cred_signature.a.to_bytes()?);
        values.extend_from_slice(&a_cap.to_bytes()?);
        values.extend_from_slice(&nonce.to_bytes()?);

        let c = get_hash_as_int(&mut vec![values])?;

        let se = r.mod_sub(
            &c.mod_mul(&p_cred_signature.e.inverse(&n, Some(&mut ctx))?, &n, Some(&mut ctx))?,
            &n,
            Some(&mut ctx)
        )?;

        let signature_correctness_proof = SignatureCorrectnessProof { c, se };

        trace!("Issuer::_new_signature_correctness_proof: <<< signature_correctness_proof: {:?}", signature_correctness_proof);

        Ok(signature_correctness_proof)
    }

    fn _new_non_revocation_credential(rev_idx: u32,
                                      cred_context: &BigNumber,
                                      blinded_ms: &BlindedMasterSecret,
                                      cred_pub_key: &CredentialPublicKey,
                                      cred_priv_key: &CredentialPrivateKey,
                                      max_cred_num: u32,
                                      issuance_by_default: bool,
                                      rev_reg: &mut RevocationRegistry,
                                      rev_key_priv: &RevocationKeyPrivate,
                                      rev_tails_accessor: &RevocationTailsAccessor)
                                      -> Result<(NonRevocationCredentialSignature, Option<RevocationRegistryDelta>), IndyCryptoError> {
        trace!("Issuer::_new_non_revocation_credential: >>> rev_idx: {:?}, cred_context: {:?}, blinded_ms: {:?}, cred_pub_key: {:?}, cred_priv_key: {:?}, \
        max_cred_num: {:?}, issuance_by_default: {:?}, rev_reg: {:?}, rev_key_priv: {:?}",
               rev_idx, cred_context, blinded_ms, cred_pub_key, cred_priv_key, max_cred_num, issuance_by_default, rev_reg, rev_key_priv);

        let ur = blinded_ms.ur
            .ok_or(IndyCryptoError::InvalidStructure(format!("No revocation part present in blinded master secret.")))?;

        let r_pub_key: &CredentialRevocationPublicKey = cred_pub_key.r_key
            .as_ref()
            .ok_or(IndyCryptoError::InvalidStructure(format!("No revocation part present in credential revocation public key.")))?;

        let r_priv_key: &CredentialRevocationPrivateKey = cred_priv_key.r_key
            .as_ref()
            .ok_or(IndyCryptoError::InvalidStructure(format!("No revocation part present in credential revocation private key.")))?;

        let vr_prime_prime = GroupOrderElement::new()?;
        let c = GroupOrderElement::new()?;
        let m2 = GroupOrderElement::from_bytes(&cred_context.to_bytes()?)?;

        let g_i = {
            let i_bytes = transform_u32_to_array_of_u8(rev_idx);
            let mut pow = GroupOrderElement::from_bytes(&i_bytes)?;
            pow = rev_key_priv.gamma.pow_mod(&pow)?;
            r_pub_key.g.mul(&pow)?
        };

        let sigma =
            r_pub_key.h0.add(&r_pub_key.h1.mul(&m2)?)?
                .add(&ur)?
                .add(&g_i)?
                .add(&r_pub_key.h2.mul(&vr_prime_prime)?)?
                .mul(&r_priv_key.x.add_mod(&c)?.inverse()?)?;


        let sigma_i = r_pub_key.g_dash
            .mul(&r_priv_key.sk
                .add_mod(&rev_key_priv.gamma
                    .pow_mod(&GroupOrderElement::from_bytes(&transform_u32_to_array_of_u8(rev_idx))?)?)?
                .inverse()?)?;
        let u_i = r_pub_key.u
            .mul(&rev_key_priv.gamma
                .pow_mod(&GroupOrderElement::from_bytes(&transform_u32_to_array_of_u8(rev_idx))?)?)?;

        let index = max_cred_num + 1 - rev_idx;

        let rev_reg_delta = if issuance_by_default {
            None
        } else {
            let prev_acc = rev_reg.accum.clone();

            rev_tails_accessor.access_tail(index, &mut |tail| {
                rev_reg.accum = rev_reg.accum.add(tail).unwrap();
            })?;

            let mut issued = HashSet::new();
            issued.insert(rev_idx);

            Some(RevocationRegistryDelta {
                prev_accum: Some(prev_acc),
                accum: rev_reg.accum.clone(),
                issued,
                revoked: HashSet::new()
            })
        };

        let witness_signature = WitnessSignature {
            sigma_i,
            u_i,
            g_i: g_i.clone(),
        };

        let non_revocation_cred_sig = NonRevocationCredentialSignature {
            sigma,
            c,
            vr_prime_prime,
            witness_signature,
            g_i: g_i.clone(),
            i: rev_idx,
            m2
        };

        trace!("Issuer::_new_non_revocation_credential: <<< non_revocation_cred_sig: {:?}, rev_reg_delta: {:?}",
               non_revocation_cred_sig, rev_reg_delta);

        Ok((non_revocation_cred_sig, rev_reg_delta))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cl::issuer::{Issuer, mocks};
    use cl::helpers::MockHelper;

    #[test]
    fn generate_context_attribute_works() {
        let rev_idx = 110;
        let user_id = "111";
        let answer = BigNumber::from_dec("59059690488564137142247698318091397258460906844819605876079330034815387295451").unwrap();
        let result = Issuer::_gen_credential_context(user_id, Some(rev_idx)).unwrap();
        assert_eq!(result, answer);
    }

    #[test]
    fn credential_schema_builder_works() {
        let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
        credential_schema_builder.add_attr("sex").unwrap();
        credential_schema_builder.add_attr("name").unwrap();
        credential_schema_builder.add_attr("age").unwrap();
        let credential_schema = credential_schema_builder.finalize().unwrap();

        assert!(credential_schema.attrs.contains("sex"));
        assert!(credential_schema.attrs.contains("name"));
        assert!(credential_schema.attrs.contains("age"));
        assert!(!credential_schema.attrs.contains("height"));
    }

    #[test]
    fn credential_values_builder_works() {
        let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();
        credential_values_builder.add_value("sex", "89057765651800459030103911598694169835931320404459570102253965466045532669865684092518362135930940112502263498496335250135601124519172068317163741086983519494043168252186111551835366571584950296764626458785776311514968350600732183408950813066589742888246925358509482561838243805468775416479523402043160919428168650069477488093758569936116799246881809224343325540306266957664475026390533069487455816053169001876208052109360113102565642529699056163373190930839656498261278601357214695582219007449398650197048218304260447909283768896882743373383452996855450316360259637079070460616248922547314789644935074980711243164129").unwrap();
        credential_values_builder.add_value("name", "58606710922154038918005745652863947546479611221487923871520854046018234465128105585608812090213473225037875788462225679336791123783441657062831589984290779844020407065450830035885267846722229953206567087435754612694085258455822926492275621650532276267042885213400704012011608869094703483233081911010530256094461587809601298503874283124334225428746479707531278882536314925285434699376158578239556590141035593717362562548075653598376080466948478266094753818404986494459240364648986755479857098110402626477624280802323635285059064580583239726433768663879431610261724430965980430886959304486699145098822052003020688956471").unwrap();
        let credential_values = credential_values_builder.finalize().unwrap();

        assert!(credential_values.attrs_values.get("sex").unwrap().eq(&BigNumber::from_dec("89057765651800459030103911598694169835931320404459570102253965466045532669865684092518362135930940112502263498496335250135601124519172068317163741086983519494043168252186111551835366571584950296764626458785776311514968350600732183408950813066589742888246925358509482561838243805468775416479523402043160919428168650069477488093758569936116799246881809224343325540306266957664475026390533069487455816053169001876208052109360113102565642529699056163373190930839656498261278601357214695582219007449398650197048218304260447909283768896882743373383452996855450316360259637079070460616248922547314789644935074980711243164129").unwrap()));
        assert!(credential_values.attrs_values.get("name").unwrap().eq(&BigNumber::from_dec("58606710922154038918005745652863947546479611221487923871520854046018234465128105585608812090213473225037875788462225679336791123783441657062831589984290779844020407065450830035885267846722229953206567087435754612694085258455822926492275621650532276267042885213400704012011608869094703483233081911010530256094461587809601298503874283124334225428746479707531278882536314925285434699376158578239556590141035593717362562548075653598376080466948478266094753818404986494459240364648986755479857098110402626477624280802323635285059064580583239726433768663879431610261724430965980430886959304486699145098822052003020688956471").unwrap()));
        assert!(credential_values.attrs_values.get("age").is_none());
    }

    #[test]
    fn issuer_new_credential_def_works() {
        MockHelper::inject();

        let (pub_key, priv_key, key_correctness_proof) = Issuer::new_credential_def(&mocks::credential_schema(), true).unwrap();
        assert_eq!(pub_key.p_key, mocks::credential_primary_public_key());
        assert_eq!(priv_key.p_key, mocks::credential_primary_private_key());
        assert_eq!(key_correctness_proof, mocks::credential_key_correctness_proof());
        assert!(pub_key.r_key.is_some());
        assert!(priv_key.r_key.is_some());
    }

    #[test]
    fn issuer_new_credential_def_works_without_revocation_part() {
        MockHelper::inject();

        let (pub_key, priv_key, key_correctness_proof) = Issuer::new_credential_def(&mocks::credential_schema(), false).unwrap();
        assert_eq!(pub_key.p_key, mocks::credential_primary_public_key());
        assert_eq!(priv_key.p_key, mocks::credential_primary_private_key());
        assert_eq!(key_correctness_proof, mocks::credential_key_correctness_proof());
        assert!(pub_key.r_key.is_none());
        assert!(priv_key.r_key.is_none());
    }

    #[test]
    fn issuer_new_credential_works_for_empty_attributes() {
        let cred_attrs = CredentialSchema { attrs: HashSet::new() };
        let res = Issuer::new_credential_def(&cred_attrs, false);
        assert!(res.is_err())
    }

    #[test]
    fn issuer_new_revocation_registry_def_works() {
        MockHelper::inject();

        let (pub_key, _, _) = Issuer::new_credential_def(&mocks::credential_schema(), true).unwrap();
        Issuer::new_revocation_registry_def(&pub_key, 100, false).unwrap();
    }

    #[test]
    fn sign_primary_credential_works() {
        MockHelper::inject();

        let (pub_key, secret_key) = (mocks::credential_public_key(), mocks::credential_private_key());
        let context_attribute = BigNumber::from_dec("59059690488564137142247698318091397258460906844819605876079330034815387295451").unwrap();

        let credential_values = mocks::credential_values();

        let v = BigNumber::from_dec("5237513942984418438429595379849430501110274945835879531523435677101657022026899212054747703201026332785243221088006425007944260107143086435227014329174143861116260506019310628220538205630726081406862023584806749693647480787838708606386447727482772997839699379017499630402117304253212246286800412454159444495341428975660445641214047184934669036997173182682771745932646179140449435510447104436243207291913322964918630514148730337977117021619857409406144166574010735577540583316493841348453073326447018376163876048624924380855323953529434806898415857681702157369526801730845990252958130662749564283838280707026676243727830151176995470125042111348846500489265328810592848939081739036589553697928683006514398844827534478669492201064874941684905413964973517155382540340695991536826170371552446768460042588981089470261358687308").unwrap();

        let u = BigNumber::from_dec("72637991796589957272144423539998982864769854130438387485781642285237707120228376409769221961371420625002149758076600738245408098270501483395353213773728601101770725294535792756351646443825391806535296461087756781710547778467803194521965309091287301376623972321639262276779134586366620773325502044026364814032821517244814909708610356590687571152567177116075706850536899272749781370266769562695357044719529245223811232258752001942940813585440938291877640445002571323841625932424781535818087233087621479695522263178206089952437764196471098717335358765920438275944490561172307673744212256272352897964947435086824617146019").unwrap();
        let e = BigNumber::from_dec("259344723055062059907025491480697571938277889515152306249728583105665800713306759149981690559193987143012367913206299323899696942213235956742930214202955935602153431795703076242907").unwrap();

        let expected_signature = BigNumber::from_dec("28748151213526235356806559302394713234708919908503693283861771311017778909029307989059154007823711057388221409308121224597301914007508580498985253922086489241065285193059997346332076248684330624957067344016446755572964815456056930278425883796750731908534333384959509746585564275501093362841366335955561237226624645170675067095743367895186059835073250297480315430811087601896371266213408739927940580173817412189118678276094925364341985978659550229327835510932814819830163166484857629278032552734675432915303389204079219287453130354714417551011163735621955266079226631695289893390164242695387374962452897413162593627569").unwrap();
        let expected_q = BigNumber::from_dec("62363291072105309734429421111781667277622338652614541474016228570557906784227711277508032382480694834439351345015578229222850418542973745058822742491558379363835885374702190788016205722518754261589148352959080144887818045985349619774317322203773276528345285327751288976595236600315518298828390132112243875494849058906743589411550479599132880095939710337582014885376559000168175623243474494316451725482257681430068204444716308910642965319732117037454207020297910067729648337741704358082947378729621100937295340132926246628185800807161500324382279607244112382284981206740340575810018294756514449073650757734843766249759").unwrap();

        let (credential_signature, q) = Issuer::_sign_primary_credential(&pub_key, &secret_key, &context_attribute, &credential_values, &v, &BlindedMasterSecret { u: u, ur: None }, &e).unwrap();
        assert_eq!(expected_signature, credential_signature);
        assert_eq!(expected_q, q);
    }

    #[test]
    fn sign_credential_signature_works() {
        MockHelper::inject();

        let (pub_key, priv_key) = (mocks::credential_public_key(), mocks::credential_private_key());
        let blinded_master_secret_nonce = new_nonce().unwrap();
        let (blinded_master_secret, blinded_master_secret_correctness_proof) =
            (prover::mocks::blinded_master_secret(), prover::mocks::blinded_master_secret_correctness_proof());

        let credential_issuance_nonce = new_nonce().unwrap();
        let (credential_signature_signature, signature_correctness_proof) = Issuer::sign_credential("CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW",
                                                                                                    &blinded_master_secret,
                                                                                                    &blinded_master_secret_correctness_proof,
                                                                                                    &blinded_master_secret_nonce,
                                                                                                    &credential_issuance_nonce,
                                                                                                    &mocks::credential_values(),
                                                                                                    &pub_key,
                                                                                                    &priv_key).unwrap();

        assert_eq!(mocks::primary_credential(), credential_signature_signature.p_credential);
        assert_eq!(mocks::signature_correctness_proof(), signature_correctness_proof);
    }
}

pub mod mocks {
    use super::*;

    pub fn credential_public_key() -> CredentialPublicKey {
        CredentialPublicKey {
            p_key: credential_primary_public_key(),
            r_key: Some(credential_revocation_public_key())
        }
    }

    pub fn credential_private_key() -> CredentialPrivateKey {
        CredentialPrivateKey {
            p_key: credential_primary_private_key(),
            r_key: Some(credential_revocation_private_key())
        }
    }

    pub fn credential_key_correctness_proof() -> CredentialKeyCorrectnessProof {
        let mut xr_cap = BTreeMap::new();
        xr_cap.insert("age".to_string(), BigNumber::from_dec("1892231043724130909171141289812960615426192763023418622932834943058282432968198987153126474388668979622947264509624644685841143428132616237743193881655603543892398769262916442024063101723277760823416453262665595605413303749293649394575427429231094228050006371082139202645115071447248921364818624346023096421568826743647498028863458488776307399553475370443302355461781568944402350106239705726036665437182231254430750846071779577750530648388732768012623381961314442543645998258153643016348344220528405876072425692989455706003666388719067824778596213331852938073597370702167042039617821822401076715832575652516496480221563316441949008136915415492164815053192131153384072074830072935640451598321664").unwrap());
        xr_cap.insert("height".to_string(), BigNumber::from_dec("1892231043724130909171141289812960615426192763023418622932834943058282432968198987153126474388668979622947264509624644685841143428132616237743193881655603543892398769262916442024063101723277760823416453262665595605413303749293649394575427429231094228050006371082139202645115071447248921364818624346023096421568826743647498028863458488776307399553475370443302355461781568944402350106239705726036665437182231254430750846071779577750530648388732768012623381961314442543645998258153643016348344220528405876072425692989455706003666388719067824778596213331852938073597370702167042039617821822401076715832575652516496480221563316441949008136915415492164815053192131153384072074830072935640451598321664").unwrap());
        xr_cap.insert("name".to_string(), BigNumber::from_dec("1892231043724130909171141289812960615426192763023418622932834943058282432968198987153126474388668979622947264509624644685841143428132616237743193881655603543892398769262916442024063101723277760823416453262665595605413303749293649394575427429231094228050006371082139202645115071447248921364818624346023096421568826743647498028863458488776307399553475370443302355461781568944402350106239705726036665437182231254430750846071779577750530648388732768012623381961314442543645998258153643016348344220528405876072425692989455706003666388719067824778596213331852938073597370702167042039617821822401076715832575652516496480221563316441949008136915415492164815053192131153384072074830072935640451598321664").unwrap());
        xr_cap.insert("sex".to_string(), BigNumber::from_dec("1892231043724130909171141289812960615426192763023418622932834943058282432968198987153126474388668979622947264509624644685841143428132616237743193881655603543892398769262916442024063101723277760823416453262665595605413303749293649394575427429231094228050006371082139202645115071447248921364818624346023096421568826743647498028863458488776307399553475370443302355461781568944402350106239705726036665437182231254430750846071779577750530648388732768012623381961314442543645998258153643016348344220528405876072425692989455706003666388719067824778596213331852938073597370702167042039617821822401076715832575652516496480221563316441949008136915415492164815053192131153384072074830072935640451598321664").unwrap());
        CredentialKeyCorrectnessProof {
            c: BigNumber::from_dec("86973363028626279158199826465770246126907236299495499221033315518220576867327").unwrap(),
            xz_cap: BigNumber::from_dec("1892231043724130909171141289812960615426192763023418622932834943058282432968198987153126474388668979622947264509624644685841143428132616237743193881655603543892398769262916442024063101723277760823416453262665595605413303749293649394575427429231094228050006371082139202645115071447248921364818624346023096421568826743647498028863458488776307399553475370443302355461781568944402350106239705726036665437182231254430750846071779577750530648388732768012623381961314442543645998258153643016348344220528405876072425692989455706003666388719067824778596213331852938073597370702167042039617821822401076715832575652516496480221563316441949008136915415492164815053192131153384072074830072935640451598321664").unwrap(),
            xr_cap
        }
    }

    pub fn credential_primary_public_key() -> CredentialPrimaryPublicKey {
        let n = BigNumber::from_dec("89057765651800459030103911598694169835931320404459570102253965466045532669865684092518362135930940112502263498496335250135601124519172068317163741086983519494043168252186111551835366571584950296764626458785776311514968350600732183408950813066589742888246925358509482561838243805468775416479523402043160919428168650069477488093758569936116799246881809224343325540306266957664475026390533069487455816053169001876208052109360113102565642529699056163373190930839656498261278601357214695582219007449398650197048218304260447909283768896882743373383452996855450316360259637079070460616248922547314789644935074980711243164129").unwrap();
        let s = BigNumber::from_dec("64684820421150545443421261645532741305438158267230326415141505826951816460650437611148133267480407958360035501128469885271549378871140475869904030424615175830170939416512594291641188403335834762737251794282186335118831803135149622404791467775422384378569231649224208728902565541796896860352464500717052768431523703881746487372385032277847026560711719065512366600220045978358915680277126661923892187090579302197390903902744925313826817940566429968987709582805451008234648959429651259809188953915675063700676546393568304468609062443048457324721450190021552656280473128156273976008799243162970386898307404395608179975243").unwrap();
        let rms = BigNumber::from_dec("58606710922154038918005745652863947546479611221487923871520854046018234465128105585608812090213473225037875788462225679336791123783441657062831589984290779844020407065450830035885267846722229953206567087435754612694085258455822926492275621650532276267042885213400704012011608869094703483233081911010530256094461587809601298503874283124334225428746479707531278882536314925285434699376158578239556590141035593717362562548075653598376080466948478266094753818404986494459240364648986755479857098110402626477624280802323635285059064580583239726433768663879431610261724430965980430886959304486699145098822052003020688956471").unwrap();

        let mut r: BTreeMap<String, BigNumber> = BTreeMap::new();
        r.insert("sex".to_string(), BigNumber::from_dec("58606710922154038918005745652863947546479611221487923871520854046018234465128105585608812090213473225037875788462225679336791123783441657062831589984290779844020407065450830035885267846722229953206567087435754612694085258455822926492275621650532276267042885213400704012011608869094703483233081911010530256094461587809601298503874283124334225428746479707531278882536314925285434699376158578239556590141035593717362562548075653598376080466948478266094753818404986494459240364648986755479857098110402626477624280802323635285059064580583239726433768663879431610261724430965980430886959304486699145098822052003020688956471").unwrap());
        r.insert("name".to_string(), BigNumber::from_dec("58606710922154038918005745652863947546479611221487923871520854046018234465128105585608812090213473225037875788462225679336791123783441657062831589984290779844020407065450830035885267846722229953206567087435754612694085258455822926492275621650532276267042885213400704012011608869094703483233081911010530256094461587809601298503874283124334225428746479707531278882536314925285434699376158578239556590141035593717362562548075653598376080466948478266094753818404986494459240364648986755479857098110402626477624280802323635285059064580583239726433768663879431610261724430965980430886959304486699145098822052003020688956471").unwrap());
        r.insert("age".to_string(), BigNumber::from_dec("58606710922154038918005745652863947546479611221487923871520854046018234465128105585608812090213473225037875788462225679336791123783441657062831589984290779844020407065450830035885267846722229953206567087435754612694085258455822926492275621650532276267042885213400704012011608869094703483233081911010530256094461587809601298503874283124334225428746479707531278882536314925285434699376158578239556590141035593717362562548075653598376080466948478266094753818404986494459240364648986755479857098110402626477624280802323635285059064580583239726433768663879431610261724430965980430886959304486699145098822052003020688956471").unwrap());
        r.insert("height".to_string(), BigNumber::from_dec("58606710922154038918005745652863947546479611221487923871520854046018234465128105585608812090213473225037875788462225679336791123783441657062831589984290779844020407065450830035885267846722229953206567087435754612694085258455822926492275621650532276267042885213400704012011608869094703483233081911010530256094461587809601298503874283124334225428746479707531278882536314925285434699376158578239556590141035593717362562548075653598376080466948478266094753818404986494459240364648986755479857098110402626477624280802323635285059064580583239726433768663879431610261724430965980430886959304486699145098822052003020688956471").unwrap());

        let rctxt = BigNumber::from_dec("58606710922154038918005745652863947546479611221487923871520854046018234465128105585608812090213473225037875788462225679336791123783441657062831589984290779844020407065450830035885267846722229953206567087435754612694085258455822926492275621650532276267042885213400704012011608869094703483233081911010530256094461587809601298503874283124334225428746479707531278882536314925285434699376158578239556590141035593717362562548075653598376080466948478266094753818404986494459240364648986755479857098110402626477624280802323635285059064580583239726433768663879431610261724430965980430886959304486699145098822052003020688956471").unwrap();
        let z = BigNumber::from_dec("58606710922154038918005745652863947546479611221487923871520854046018234465128105585608812090213473225037875788462225679336791123783441657062831589984290779844020407065450830035885267846722229953206567087435754612694085258455822926492275621650532276267042885213400704012011608869094703483233081911010530256094461587809601298503874283124334225428746479707531278882536314925285434699376158578239556590141035593717362562548075653598376080466948478266094753818404986494459240364648986755479857098110402626477624280802323635285059064580583239726433768663879431610261724430965980430886959304486699145098822052003020688956471").unwrap();

        CredentialPrimaryPublicKey { n, s, rms, r, rctxt, z }
    }

    pub fn credential_primary_private_key() -> CredentialPrimaryPrivateKey {
        let p = BigNumber::from_dec("149212738775716179659508649034140914067267873385650452563221860367878267143635191771233591587868730221903476199105022913859057555905442876114559838735355652672950963033972314646471235775711934244481758977047119803475879470383993713606231800156950590334088086141997103196482505556481059579729337361392854778311").unwrap();
        let q = BigNumber::from_dec("149212738775716179659508649034140914067267873385650452563221860367878267143635191771233591587868730221903476199105022913859057555905442876114559838735355652672950963033972314646471235775711934244481758977047119803475879470383993713606231800156950590334088086141997103196482505556481059579729337361392854778311").unwrap();

        CredentialPrimaryPrivateKey { p, q }
    }

    pub fn credential_schema() -> CredentialSchema {
        let mut credential_schema_builder = CredentialSchemaBuilder::new().unwrap();
        credential_schema_builder.add_attr("name").unwrap();
        credential_schema_builder.add_attr("age").unwrap();
        credential_schema_builder.add_attr("height").unwrap();
        credential_schema_builder.add_attr("sex").unwrap();
        credential_schema_builder.finalize().unwrap()
    }

    pub fn credential_values() -> CredentialValues {
        let mut credential_values_builder = CredentialValuesBuilder::new().unwrap();
        credential_values_builder.add_value("name", "1139481716457488690172217916278103335").unwrap();
        credential_values_builder.add_value("age", "28").unwrap();
        credential_values_builder.add_value("sex", "5944657099558967239210949258394887428692050081607692519917050011144233115103").unwrap();
        credential_values_builder.add_value("height", "175").unwrap();
        credential_values_builder.finalize().unwrap()
    }

    pub fn credential() -> CredentialSignature {
        CredentialSignature {
            p_credential: primary_credential(),
            r_credential: Some(revocation_credential())
        }
    }

    pub fn primary_credential() -> PrimaryCredentialSignature {
        PrimaryCredentialSignature {
            m_2: BigNumber::from_dec("79198861930494722247098854124679815411215565468368019592091735771996515839812").unwrap(),
            a: BigNumber::from_dec("2015509093129106237691981433225679632774255267161330031955213488684080337772589661796272396005429999572765056564502896756584978722526495279899984542746563590582561692675025757898334695221229933231304404189890550211532764993559283672307725561940191641851157625662904809711682211053992968131340525941580045401951996762335579069985811415532641838234302256559149674721325965693307667573037324373216732925398827597304601333904583644212982848121263412244201228166100334275374295995076714802844245430263875269888443704086843131227874627682947957080489690366818166145882129549310321236789991170607896175695451648282033539854").unwrap(),
            e: BigNumber::from_dec("259344723055062059907025491480697571938277889515152306249728583105665800713306759149981690559193987143012367913206299323899696942213235956742930201588264091397308910346117473868881").unwrap(),
            v: BigNumber::from_dec("6620937836014079781509458870800001917950459774302786434315639456568768602266735503527631640833663968617512880802104566048179854406925811731340920442625764155409951969854303612644125623549271204625894424804352003689903192473464433927658013251120302922648839652919662117216521257876025436906282750361355336367533874548955283776610021309110505377492806210342214471251451681722267655419075635703240258044336607001296052867746675049720589092355650996711033859489737240617860392914314205277920274997312351322125481593636904917159990500837822414761512231315313922792934655437808723096823124948039695324591344458785345326611693414625458359651738188933757751726392220092781991665483583988703321457480411992304516676385323318285847376271589157730040526123521479652961899368891914982347831632139045838008837541334927738208491424027").unwrap()
        }
    }

    pub fn signature_correctness_proof() -> SignatureCorrectnessProof {
        SignatureCorrectnessProof {
            se: BigNumber::from_dec("2867182988873870181255627349227831046791694164118209127116572638244509572025021916261962130207547328863447729702686926496508433257557339124176299613296377411163151406688199246232396418861179359172020811052147235396534737968322518954078287279318544461509931619642909378833468508005205055106687589375873270523669653723490309768542021891720464501437671542685518550495957409788172739863568679796589846789698040159530816920085324699754124124222177973692274292167815374272822640605758257682733226162790101966911029062233704666526794753275670414075670096002626035474717637906458773215726535442042214417461860636241718792853").unwrap(),
            c: BigNumber::from_dec("38689741549120078408010091653015945512217729474158229796203853185078442030991").unwrap(),
        }
    }

    pub fn revocation_credential() -> NonRevocationCredentialSignature {
        NonRevocationCredentialSignature {
            sigma: PointG1::from_string("false C8C7213101C60F F625A22E65736C 695A1F398B4787 D087ABB966C5BC 1EA63E37 7895832C96B02C 60C7E086DFA7AF 1518CD71A957F3 C1BED176429FB9 11DD23B3 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD").unwrap(),
            c: GroupOrderElement::from_string("4CF57E7A173E6 27720818863F49 D72801BCE5CBE9 7C8C588E2A8B3B 3642B08").unwrap(),
            vr_prime_prime: GroupOrderElement::from_string("2BC52B6D8B5F4B 26E57208D0DB35 D0411E4BE49639 18A8BC10BF946E 1F8689A5").unwrap(),
            witness_signature: witness_signature(),
            g_i: PointG1::from_string("false 1A5D92950F9D1C 82DB5D4BF49AB8 FBFF5E631AD221 9B89F534C2AC04 165F1606 2E5EE0ECDBB554 F4C238315ACC2 57CAA2D6085FA6 CCE1970A4628E9 119D86E1 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD").unwrap(),
            i: 1,
            m2: GroupOrderElement::from_string("7219C82BC1A5C5 2E958256CDE0D B6FBB94E62AC37 4DAA41B3F577 74DDF3F3").unwrap()
        }
    }

    fn witness_signature() -> WitnessSignature {
        WitnessSignature {
            sigma_i: PointG2::from_string("false D75D129A90AC7C E980CE49738692 E81F6656B7EC8B 5CB508713E5514 1C8D263D 277F296ED2870 DD07D7557B996C 3E3A4CBE72B433 CE6A5B3F49DCF0 12760A8D 794C7329844D36 5F061EF8268D0B 6931F242E445A2 941EE07805B105 112CCA EA8F2154379FFC E347F4C23152D6 81B0FD797DECC 99649EAE531C52 306F627 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD 0 0 0 0 0").unwrap(),
            u_i: PointG2::from_string("false 5BDC53BAF81A3F 161769B604A474 B7D29413291CFF 339D755F2188BC 33CD0CE D67B914F2755B3 9753565047A4C7 A431380FD96DC BDC9CF432D6969 167143C2 E8C107037A2973 9D6DC89136F5CD 24A92213C2C956 5B52182802ADB 23673530 237EC2A2AE67B4 B2680968AA2A 52E5202656A6A6 CB2696283382AE 251DD0E6 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD 0 0 0 0 0").unwrap(),
            g_i: PointG1::from_string("false 1A5D92950F9D1C 82DB5D4BF49AB8 FBFF5E631AD221 9B89F534C2AC04 165F1606 2E5EE0ECDBB554 F4C238315ACC2 57CAA2D6085FA6 CCE1970A4628E9 119D86E1 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD").unwrap(),
        }
    }

    pub fn witness() -> Witness {
        Witness {
            omega: PointG2::from_string("true 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0").unwrap()
        }
    }

    pub fn credential_revocation_public_key() -> CredentialRevocationPublicKey {
        CredentialRevocationPublicKey {
            g: PointG1::from_string("false F7061FFC5D86BD FEA559D709EBB4 184F0E83E83C7F 77518EACC28D21 1B2D4E76 86D88DDE8770D0 5034DD68624C0 CA409B38BD8B6A EC15B842470D5B 2188CB11 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD").unwrap(),
            g_dash: PointG2::from_string("false B689CDF1EEE6B9 7879E722A8927E 7A5F92EB847EF4 CB7D2B559A4B7A 94DFCE9 F353AFC74815B1 DF1DB4459153A0 FEBB4F1B0DC6CB 375723BC12026E 3A02BC0 CA432D2B712EBE 28310825C67A82 FCD05276543D75 4A06A4C1A05435 1DA19E B02395BAE668B8 10BD3BCD5F1CC9 92FC516611102D CC2E8568C3C687 1A06AE72 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD 0 0 0 0 0").unwrap(),
            h: PointG1::from_string("false E6C4969BF7F6E4 D2FF8C24B9EAA4 88F6451A20353E E46C8775910036 1F23D6AB E7E72372E2006B 20894EC16703C2 E97C22B6CFA42A A7EAD87F1E74BE 242E67D3 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD").unwrap(),
            h0: PointG1::from_string("false BEBA02E97255CC CB4AA09F541688 7AF29F26C85B42 6F3597F4EF2844 205788E5 8A078274BC3198 ADAC33647064BA 7E67D45EF39249 58FD2A0AFE6250 18010994 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD").unwrap(),
            h1: PointG1::from_string("false 9661FB704E366 51836F20094702 27521DB454AEB9 801E3DA189E912 A37E50F 367705F353C794 515F17102321FC 9A7D613710C121 84DCCCAA671F2D 10CF357E FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD").unwrap(),
            h2: PointG1::from_string("false C242FAE6B2465C 952C5CFEB62F09 CAA6A61B8238EA 67C2CE0F7EFB6A 190433AA FFA4D1B5551EEA A35F5F43E84616 B92A757ABD51D6 8110F04280410A 664C174 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD").unwrap(),
            htilde: PointG1::from_string("false 1AE71B910A158E 330457779B6C85 F1C907A134D795 19A9DB2FD49411 D3B769E 6015F30C57A0E7 310B6007D23DBD C1B8D416480847 85C92B35A32A25 18E8F8A2 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD").unwrap(),
            h_cap: PointG2::from_string("false 1A1C59765D49BE BCE6181A3B736A BAB72551F8F462 5F99B2715F2A25 1FEFD0C7 8A6472CB371D3E C4F6C33AA80CB 86EAAE909EA09 197B4EC78A3B09 1333E51F 2DC7441E28B2D4 C388A79FA4961A 79058DBBCF4C8A 8B2F97E23D4342 FBC67FF 52B82226D2995D 34D053907E3850 D965050D54F027 A4E7CF8D2A5220 8C29822 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD 0 0 0 0 0").unwrap(),
            u: PointG2::from_string("false 9B1FCFE75F79F8 73D1BC00D107C7 577D8010343FC0 35533CFE595E1F 13CEE3F8 8F38C7640C9982 F42092066D94BB D309384A81D943 340E1CCB6D1788 22A6CB75 43CC781E5A6C8F 4BD67F27D8C58D 884C09DE7F5DD6 5687B2A7047663 1441F423 313BC475C70F5B 36957040BCE3BA D9E78497E2F745 48902ADC4EC27B 853A4A3 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD 0 0 0 0 0").unwrap(),
            pk: PointG1::from_string("false 14A982E1F1C801 30A3F71F937305 E9780E68F9B8A3 11A7A4ECED7FF2 1D873FD7 24632538A440FA E77FAD44B8C9A 78854503568CAC 1A0BC5C8E7F1B9 8EAF176 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD").unwrap(),
            y: PointG2::from_string("false 8B7A8A72F510A 72414040912D7 760941DAB9E957 4D95E546557B75 6025130 7A9DB180AD2CA9 4FB0C15F96EB6E D753A5F9284015 D75962552FE3E5 1682A17B 30DA4BF8C17A8A 5DA41C9E4F7BED 4F01B812A1E5E1 7F5151E1A47E99 1358AD80 4E75A24CC7339 AC18180F5D570A BE9C1DA918469B 578E1909A8B1F C7EDD39 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD 0 0 0 0 0").unwrap(),

        }
    }

    pub fn credential_revocation_private_key() -> CredentialRevocationPrivateKey {
        CredentialRevocationPrivateKey {
            x: GroupOrderElement::new().unwrap(),
            sk: GroupOrderElement::new().unwrap()
        }
    }

    pub fn revocation_key_public() -> RevocationKeyPublic {
        RevocationKeyPublic {
            z: Pair::from_string("B0C52EBB799E8 6FC6F7D6883390 BC4244EDBC1787 FDEA974C84C1F1 234FA3A6 F411BCC525581F B238C8B10BBACB 8536CC797D203D DEFEAA1B1DBC5B 736EAC 529F008C0398B9 CD0B30B71A1F14 2D332E37CEBF1B A3D9B3319DCDAD CA1AAD2 E5B506C98D6F95 575329E5789B3B CA3A9AB8CED863 BB16612D7EDFC9 241D0C39 810C5FA05825E3 C8A863BA7721CD DCCCB939E4BC22 1817F872AA9906 E423204 C38DCA6D9C80D6 5DE52EA7CFE23E FB41FA284C112E E438D18C192C1D 88A018F EF8569C86B3916 119FE81D359A09 6D5A0088955ED3 6904F412A28BD4 11F6C539 29AD474B03EE99 D0353A66812CA7 C9763FC9EEB4A3 217160B2B8982E 10983B69 7F67C0FCFD4244 45C9665E75EC5B 4A23D9F0D1182F 3A8C685A922F6 20A176A9 883FF71EB14569 5030243F2B2B79 95A67EF0922D07 A6D74310BFE00A F8BBB21 476E55B2836798 16B49B2120D6EB 68EABD968A44DE E8DF358500A99A 15A3F96B 28749CC7A07F60 F82B17A0CA933F EE4166241C77F2 9BE2BB4B802250 19F0D85E").unwrap(),
        }
    }

    fn accumulator() -> Accumulator {
        PointG2::from_string("false 1348A2A978E0DB 34007FF6AF40CE 6D0587A6FB0664 5C7BE100A9A5F0 195FD169 A8C3298C4E3638 F93A75199C097D F3659F1FB6AE4A A03EC27AEB629 2435D86 4DA6C9C1917365 866CCF7C293373 216DF40B2F9E81 19F44DEEC2C748 170C3B8A DDEA4569FCEEC7 1685AB7B80F94F 5BB29412B2822D 3FE85A96139673 109B08B8 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD 0 0 0 0 0").unwrap()
    }

    pub fn revocation_registry() -> RevocationRegistry {
        RevocationRegistry {
            accum: accumulator()
        }
    }

    pub fn max_cred_num() -> u32 {
        5
    }

    pub fn revocation_registry_delta() -> RevocationRegistryDelta {
        let mut issued: HashSet<u32> = HashSet::new();
        issued.insert(1);

        RevocationRegistryDelta {
            prev_accum: None,
            accum: accumulator(),
            issued,
            revoked: HashSet::new()
        }
    }

    pub fn r_cnxt_m2() -> BigNumber {
        BigNumber::from_dec("52860447312636183767369476481903349046618423276302392993759146262753859184069").unwrap()
    }
}