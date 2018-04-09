use bn::BigNumber;
use cl::*;
use errors::IndyCryptoError;
use pair::*;
use cl::constants::*;
use cl::helpers::*;
use utils::commitment::*;
use utils::get_hash_as_int;

use std::collections::{HashMap, HashSet};

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
    ///
    /// let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
    /// credential_schema_builder.add_attr("sex").unwrap();
    /// credential_schema_builder.add_attr("name").unwrap();
    /// let _credential_schema = credential_schema_builder.finalize().unwrap();
    /// ```
    pub fn new_credential_schema_builder() -> Result<CredentialSchemaBuilder, IndyCryptoError> {
        let res = CredentialSchemaBuilder::new()?;
        Ok(res)
    }

    pub fn new_non_credential_schema_builder() -> Result<NonCredentialSchemaBuilder, IndyCryptoError> {
        NonCredentialSchemaBuilder::new()
    }

    /// Creates and returns credential definition (public and private keys, correctness proof) entities.
    ///
    /// # Arguments
    /// * `credential_schema` - Credential schema entity.
    /// * `support_revocation` - If true non revocation part of keys will be generated.
    ///
    /// # Example
    /// ```
    /// use indy_crypto::cl::issuer::Issuer;
    ///
    /// let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
    /// credential_schema_builder.add_attr("name").unwrap();
    /// credential_schema_builder.add_attr("sex").unwrap();
    /// let credential_schema = credential_schema_builder.finalize().unwrap();
    ///
    /// let mut non_credential_schema_builder = Issuer::new_non_credential_schema_builder().unwrap();
    /// non_credential_schema_builder.add_attr("master_secret").unwrap();
    /// let non_credential_schema = non_credential_schema_builder.finalize().unwrap();
    ///
    /// let (_cred_pub_key, _cred_priv_key, _cred_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, &non_credential_schema, true).unwrap();
    /// ```
    pub fn new_credential_def(credential_schema: &CredentialSchema,
                              non_credential_schema: &NonCredentialSchema,
                              support_revocation: bool) -> Result<(CredentialPublicKey,
                                                                   CredentialPrivateKey,
                                                                   CredentialKeyCorrectnessProof), IndyCryptoError> {
        trace!("Issuer::new_credential_def: >>> credential_schema: {:?}, support_revocation: {:?}", credential_schema, support_revocation);

        let (p_pub_key, p_priv_key, p_key_meta) =
            Issuer::_new_credential_primary_keys(credential_schema, non_credential_schema)?;

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
    /// * `credential_pub_key` - Credential public key entity.
    /// * `max_cred_num` - Max credential number in generated registry.
    /// * `issuance_by_default` - Type of issuance.
    ///   If true all indices are assumed to be issued and initial accumulator is calculated over all indices
    ///   If false nothing is issued initially accumulator is 1
    ///
    /// # Example
    /// ```
    /// use indy_crypto::cl::issuer::Issuer;
    ///
    /// let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
    /// credential_schema_builder.add_attr("name").unwrap();
    /// credential_schema_builder.add_attr("sex").unwrap();
    /// let credential_schema = credential_schema_builder.finalize().unwrap();
    ///
    /// let mut non_credential_schema_builder = Issuer::new_non_credential_schema_builder().unwrap();
    /// non_credential_schema_builder.add_attr("master_secret").unwrap();
    /// let non_credential_schema = non_credential_schema_builder.finalize().unwrap();
    ///
    /// let (_cred_pub_key, _cred_priv_key, _cred_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, &non_credential_schema, true).unwrap();
    ///
    /// let (_rev_key_pub, _rev_key_priv, _rev_reg, _rev_tails_generator) = Issuer::new_revocation_registry_def(&_cred_pub_key, 5, false).unwrap();
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
            .ok_or(IndyCryptoError::InvalidStructure(format!("There are not revocation keys in the credential public key.")))?;

        let (rev_key_pub, rev_key_priv) = Issuer::_new_revocation_registry_keys(cred_rev_pub_key, max_cred_num)?;

        let rev_reg = Issuer::_new_revocation_registry(cred_rev_pub_key,
                                                       &rev_key_priv,
                                                       max_cred_num,
                                                       issuance_by_default)?;

        let rev_tails_generator = RevocationTailsGenerator::new(
            max_cred_num,
            rev_key_priv.gamma.clone(),
            cred_rev_pub_key.g_dash.clone());

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
    ///
    /// let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();
    /// credential_values_builder.add_dec_known("sex", "5944657099558967239210949258394887428692050081607692519917050011144233115103").unwrap();
    /// credential_values_builder.add_dec_known("name", "1139481716457488690172217916278103335").unwrap();
    /// let _credential_values = credential_values_builder.finalize().unwrap();
    /// ```
    pub fn new_credential_values_builder() -> Result<CredentialValuesBuilder, IndyCryptoError> {
        let res = CredentialValuesBuilder::new()?;
        Ok(res)
    }

    /// Signs credential values with primary keys only.
    ///
    /// # Arguments
    /// * `prover_id` - Prover identifier.
    /// * `blinded_credential_secrets` - Blinded credential secrets generated by Prover.
    /// * `blinded_credential_secrets_correctness_proof` - Blinded credential secrets correctness proof.
    /// * `credential_nonce` - Nonce used for verification of blinded_credential_secrets_correctness_proof.
    /// * `credential_issuance_nonce` - Nonce used for creation of signature_correctness_proof.
    /// * `credential_values` - Credential values to be signed.
    /// * `credential_pub_key` - Credential public key.
    /// * `credential_priv_key` - Credential private key.
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
    ///
    /// let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();
    /// credential_values_builder.add_value_hidden("master_secret", &master_secret.value().unwrap());
    /// credential_values_builder.add_dec_known("sex", "5944657099558967239210949258394887428692050081607692519917050011144233115103").unwrap();
    /// let credential_values = credential_values_builder.finalize().unwrap();
    ///
    /// let credential_nonce = new_nonce().unwrap();
    /// let (blinded_credential_secrets, _, blinded_credential_secrets_correctness_proof) =
    ///      Prover::blind_credential_secrets(&credential_pub_key, &cred_key_correctness_proof, &credential_values, &credential_nonce).unwrap();
    ///
    /// let credential_issuance_nonce = new_nonce().unwrap();
    ///
    /// let (_credential_signature, _signature_correctness_proof) =
    ///     Issuer::sign_credential("CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW",
    ///                             &blinded_credential_secrets,
    ///                             &blinded_credential_secrets_correctness_proof,
    ///                             &credential_nonce,
    ///                             &credential_issuance_nonce,
    ///                             &credential_values,
    ///                             &credential_pub_key,
    ///                             &credential_priv_key).unwrap();
    /// ```
    pub fn sign_credential(prover_id: &str,
                           blinded_credential_secrets: &BlindedCredentialSecrets,
                           blinded_credential_secrets_correctness_proof: &BlindedCredentialSecretsCorrectnessProof,
                           credential_nonce: &Nonce,
                           credential_issuance_nonce: &Nonce,
                           credential_values: &CredentialValues,
                           credential_pub_key: &CredentialPublicKey,
                           credential_priv_key: &CredentialPrivateKey) -> Result<(CredentialSignature, SignatureCorrectnessProof), IndyCryptoError> {
        trace!("Issuer::sign_credential: >>> prover_id: {:?}\n \
                                             blinded_credential_secrets: {:?}\n \
                                             blinded_credential_secrets_correctness_proof: {:?}\n \
                                             credential_nonce: {:?}\n \
                                             credential_issuance_nonce: {:?}\n \
                                             credential_values: {:?}\n \
                                             credential_pub_key: {:?}\n \
                                             credential_priv_key: {:?}",
                                            prover_id,
                                            blinded_credential_secrets,
                                            blinded_credential_secrets_correctness_proof,
                                            credential_nonce,
                                            credential_issuance_nonce,
                                            credential_values,
                                            credential_pub_key,
                                            credential_priv_key);

        Issuer::_check_blinded_credential_secrets_correctness_proof(blinded_credential_secrets,
                                                               blinded_credential_secrets_correctness_proof,
                                                               credential_nonce,
                                                               &credential_pub_key.p_key)?;

        // In the anoncreds whitepaper, `credential context` is denoted by `m2`
        let cred_context = Issuer::_gen_credential_context(prover_id, None)?;

        let (p_cred, q) = Issuer::_new_primary_credential(&cred_context,
                                                          credential_pub_key,
                                                          credential_priv_key,
                                                          blinded_credential_secrets,
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

    /// Signs credential values with both primary and revocation keys.
    ///
    /// # Arguments
    /// * `prover_id` - Prover identifier.
    /// * `blinded_credential_secrets` - Blinded credential secrets generated by Prover.
    /// * `blinded_credential_secrets_correctness_proof` - Blinded credential secrets correctness proof.
    /// * `credential_nonce` - Nonce used for verification of blinded_credential_secrets_correctness_proof.
    /// * `credential_issuance_nonce` - Nonce used for creation of signature_correctness_proof.
    /// * `credential_values` - Credential values to be signed.
    /// * `credential_pub_key` - Credential public key.
    /// * `credential_priv_key` - Credential private key.
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
    /// let credential_schema = credential_schema_builder.finalize().unwrap();
    ///
    /// let mut non_credential_schema_builder = Issuer::new_non_credential_schema_builder().unwrap();
    /// non_credential_schema_builder.add_attr("master_secret").unwrap();
    /// let non_credential_schema = non_credential_schema_builder.finalize().unwrap();
    ///
    /// let (cred_pub_key, cred_priv_key, cred_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, &non_credential_schema, true).unwrap();
    ///
    /// let max_cred_num = 5;
    /// let (_rev_key_pub, rev_key_priv, mut rev_reg, mut rev_tails_generator) = Issuer::new_revocation_registry_def(&cred_pub_key, max_cred_num, false).unwrap();
    ///
    /// let simple_tail_accessor = SimpleTailsAccessor::new(&mut rev_tails_generator).unwrap();
    ///
    /// let master_secret = Prover::new_master_secret().unwrap();
    ///
    /// let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();
    /// credential_values_builder.add_value_hidden("master_secret", &master_secret.value().unwrap());
    /// credential_values_builder.add_dec_known("name", "1139481716457488690172217916278103335").unwrap();
    /// let cred_values = credential_values_builder.finalize().unwrap();
    ///
    /// let credential_nonce = new_nonce().unwrap();
    ///
    /// let (blinded_credential_secrets, _credential_secrets_blinding_factors, blinded_credential_secrets_correctness_proof) =
    ///     Prover::blind_credential_secrets(&cred_pub_key, &cred_key_correctness_proof, &cred_values, &credential_nonce).unwrap();
    ///
    /// let credential_issuance_nonce = new_nonce().unwrap();
    ///
    /// let (_cred_signature, _signature_correctness_proof, _rev_reg_delta) =
    ///     Issuer::sign_credential_with_revoc("CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW",
    ///                                        &blinded_credential_secrets,
    ///                                        &blinded_credential_secrets_correctness_proof,
    ///                                        &credential_nonce,
    ///                                        &credential_issuance_nonce,
    ///                                        &cred_values,
    ///                                        &cred_pub_key,
    ///                                        &cred_priv_key,
    ///                                        1,
    ///                                        max_cred_num,
    ///                                        false,
    ///                                        &mut rev_reg,
    ///                                        &rev_key_priv,
    ///                                        &simple_tail_accessor).unwrap();
    /// ```
    pub fn sign_credential_with_revoc<RTA>(prover_id: &str,
                                           blinded_credential_secrets: &BlindedCredentialSecrets,
                                           blinded_credential_secrets_correctness_proof: &BlindedCredentialSecretsCorrectnessProof,
                                           credential_nonce: &Nonce,
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
        trace!("Issuer::sign_credential: >>> prover_id: {:?}, blinded_credential_secrets: {:?}, blinded_credential_secrets_correctness_proof: {:?},\
        credential_nonce: {:?}, credential_issuance_nonce: {:?}, credential_values: {:?}, credential_pub_key: {:?}, credential_priv_key: {:?}, \
        rev_idx: {:?}, max_cred_num: {:?}, rev_reg: {:?}, rev_key_priv: {:?}",
               prover_id, blinded_credential_secrets, blinded_credential_secrets_correctness_proof, credential_nonce, credential_values, credential_issuance_nonce,
               credential_pub_key, credential_priv_key, rev_idx, max_cred_num, rev_reg, rev_key_priv);

        Issuer::_check_blinded_credential_secrets_correctness_proof(blinded_credential_secrets,
                                                                    blinded_credential_secrets_correctness_proof,
                                                                    credential_nonce,
                                                                    &credential_pub_key.p_key)?;

        // In the anoncreds whitepaper, `credential context` is denoted by `m2`
        let cred_context = Issuer::_gen_credential_context(prover_id, Some(rev_idx))?;

        let (p_cred, q) = Issuer::_new_primary_credential(&cred_context,
                                                          credential_pub_key,
                                                          credential_priv_key,
                                                          blinded_credential_secrets,
                                                          credential_values)?;

        let (r_cred, rev_reg_delta) = Issuer::_new_non_revocation_credential(rev_idx,
                                                                             &cred_context,
                                                                             blinded_credential_secrets,
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

    /// Revokes a credential by a rev_idx in a given revocation registry.
    ///
    /// # Arguments
    /// * `rev_reg` - Revocation registry.
    /// * `max_cred_num` - Max credential number in revocation registry.
    ///  * rev_idx` - Index of the user in the revocation registry.
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
    /// let credential_schema = credential_schema_builder.finalize().unwrap();
    ///
    /// let mut non_credential_schema_builder = Issuer::new_non_credential_schema_builder().unwrap();
    /// non_credential_schema_builder.add_attr("master_secret").unwrap();
    /// let non_credential_schema = non_credential_schema_builder.finalize().unwrap();
    ///
    /// let (cred_pub_key, cred_priv_key, cred_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, &non_credential_schema, true).unwrap();
    ///
    /// let max_cred_num = 5;
    /// let (_rev_key_pub, rev_key_priv, mut rev_reg, mut rev_tails_generator) = Issuer::new_revocation_registry_def(&cred_pub_key, max_cred_num, false).unwrap();
    ///
    /// let simple_tail_accessor = SimpleTailsAccessor::new(&mut rev_tails_generator).unwrap();
    ///
    /// let master_secret = Prover::new_master_secret().unwrap();
    ///
    /// let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();
    /// credential_values_builder.add_value_hidden("master_secret", &master_secret.value().unwrap());
    /// credential_values_builder.add_dec_known("name", "1139481716457488690172217916278103335").unwrap();
    /// let cred_values = credential_values_builder.finalize().unwrap();
    ///
    /// let credential_nonce = new_nonce().unwrap();
    ///
    /// let (blinded_credential_secrets, _credential_secrets_blinding_factors, blinded_credential_secrets_correctness_proof) =
    ///     Prover::blind_credential_secrets(&cred_pub_key, &cred_key_correctness_proof, &cred_values, &credential_nonce).unwrap();
    /// let credential_issuance_nonce = new_nonce().unwrap();
    ///
    /// let rev_idx = 1;
    /// let (_cred_signature, _signature_correctness_proof, _rev_reg_delta) =
    ///     Issuer::sign_credential_with_revoc("CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW",
    ///                                        &blinded_credential_secrets,
    ///                                        &blinded_credential_secrets_correctness_proof,
    ///                                        &credential_nonce,
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
        trace!("Issuer::revoke_credential: >>> rev_reg: {:?}, max_cred_num: {:?}, rev_idx: {:?}", rev_reg, max_cred_num, rev_idx);

        let prev_accum = rev_reg.accum.clone();

        let index = Issuer::_get_index(max_cred_num, rev_idx);

        rev_tails_accessor.access_tail(index, &mut |tail| {
            rev_reg.accum = rev_reg.accum.sub(tail).unwrap();
        })?;

        let rev_reg_delta = RevocationRegistryDelta {
            prev_accum: Some(prev_accum),
            accum: rev_reg.accum.clone(),
            issued: HashSet::new(),
            revoked: hashset![rev_idx]
        };

        trace!("Issuer::revoke_credential: <<< rev_reg_delta: {:?}", rev_reg_delta);

        Ok(rev_reg_delta)
    }

    /// Recovery a credential by a rev_idx in a given revocation registry
    ///
    /// # Arguments
    /// * `rev_reg` - Revocation registry.
    /// * `max_cred_num` - Max credential number in revocation registry.
    ///  * rev_idx` - Index of the user in the revocation registry.
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
    /// let credential_schema = credential_schema_builder.finalize().unwrap();
    ///
    /// let mut non_credential_schema_builder = Issuer::new_non_credential_schema_builder().unwrap();
    /// non_credential_schema_builder.add_attr("master_secret").unwrap();
    /// let non_credential_schema = non_credential_schema_builder.finalize().unwrap();
    ///
    /// let (cred_pub_key, cred_priv_key, cred_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, &non_credential_schema, true).unwrap();
    ///
    /// let max_cred_num = 5;
    /// let (_rev_key_pub, rev_key_priv, mut rev_reg, mut rev_tails_generator) = Issuer::new_revocation_registry_def(&cred_pub_key, max_cred_num, false).unwrap();
    ///
    /// let simple_tail_accessor = SimpleTailsAccessor::new(&mut rev_tails_generator).unwrap();
    ///
    /// let master_secret = Prover::new_master_secret().unwrap();
    ///
    /// let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();
    /// credential_values_builder.add_value_hidden("master_secret", &master_secret.value().unwrap());
    /// credential_values_builder.add_dec_known("name", "1139481716457488690172217916278103335").unwrap();
    /// let cred_values = credential_values_builder.finalize().unwrap();
    ///
    /// let credential_nonce = new_nonce().unwrap();
    ///
    /// let (blinded_credential_secrets, _credential_secrets_blinding_factors, blinded_credential_secrets_correctness_proof) =
    ///     Prover::blind_credential_secrets(&cred_pub_key, &cred_key_correctness_proof, &cred_values, &credential_nonce).unwrap();
    ///
    /// let credential_issuance_nonce = new_nonce().unwrap();
    ///
    /// let rev_idx = 1;
    /// let (_cred_signature, _signature_correctness_proof, _rev_reg_delta) =
    ///     Issuer::sign_credential_with_revoc("CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW",
    ///                                        &blinded_credential_secrets,
    ///                                        &blinded_credential_secrets_correctness_proof,
    ///                                        &credential_nonce,
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
    /// Issuer::recovery_credential(&mut rev_reg, max_cred_num, rev_idx, &simple_tail_accessor).unwrap();
    /// ```
    pub fn recovery_credential<RTA>(rev_reg: &mut RevocationRegistry,
                                    max_cred_num: u32,
                                    rev_idx: u32,
                                    rev_tails_accessor: &RTA) -> Result<RevocationRegistryDelta, IndyCryptoError> where RTA: RevocationTailsAccessor {
        trace!("Issuer::recovery_credential: >>> rev_reg: {:?}, max_cred_num: {:?}, rev_idx: {:?}", rev_reg, max_cred_num, rev_idx);

        let prev_accum = rev_reg.accum.clone();

        let index = Issuer::_get_index(max_cred_num, rev_idx);

        rev_tails_accessor.access_tail(index, &mut |tail| {
            rev_reg.accum = rev_reg.accum.add(tail).unwrap();
        })?;

        let rev_reg_delta = RevocationRegistryDelta {
            prev_accum: Some(prev_accum),
            accum: rev_reg.accum.clone(),
            issued: hashset![rev_idx],
            revoked: HashSet::new()
        };

        trace!("Issuer::recovery_credential: <<< rev_reg_delta: {:?}", rev_reg_delta);

        Ok(rev_reg_delta)
    }

    fn _new_credential_primary_keys(credential_schema: &CredentialSchema,
                                    non_credential_schema: &NonCredentialSchema) ->
                                                                          Result<(CredentialPrimaryPublicKey,
                                                                                  CredentialPrimaryPrivateKey,
                                                                                  CredentialPrimaryPublicKeyMetadata), IndyCryptoError> {
        trace!("Issuer::_new_credential_primary_keys: >>> credential_schema: {:?}", credential_schema);

        let mut ctx = BigNumber::new_context()?;

        if credential_schema.attrs.len() == 0 {
            return Err(IndyCryptoError::InvalidStructure(format!("List of attributes is empty")));
        }

        let p_safe = generate_safe_prime(LARGE_PRIME)?;
        let q_safe = generate_safe_prime(LARGE_PRIME)?;

        let p = p_safe.rshift1()?;
        let q = q_safe.rshift1()?;

        let n = p_safe.mul(&q_safe, Some(&mut ctx))?;
        let s = random_qr(&n)?;
        let xz = gen_x(&p, &q)?;

        let mut xr = BTreeMap::new();
        for non_schema_element in &non_credential_schema.attrs {
            xr.insert(non_schema_element.to_string(), gen_x(&p, &q)?);
        }

        for attribute in &credential_schema.attrs {
            xr.insert(attribute.to_string(), gen_x(&p, &q)?);
        }

        let mut r = HashMap::new();
        for (key, xr_value) in xr.iter() {
            r.insert(key.to_string(), s.mod_exp(&xr_value, &n, Some(&mut ctx))?);
        }

        let z = s.mod_exp(&xz, &n, Some(&mut ctx))?;

        let rctxt = s.mod_exp(&gen_x(&p, &q)?, &n, Some(&mut ctx))?;

        let cred_pr_pub_key = CredentialPrimaryPublicKey { n, s, rctxt, r, z };
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
                                             cred_pr_pub_key_meta: &CredentialPrimaryPublicKeyMetadata) -> Result<CredentialKeyCorrectnessProof, IndyCryptoError> {
        trace!("Issuer::_new_credential_key_correctness_proof: >>> cred_pr_pub_key: {:?}, cred_pr_priv_key: {:?}, cred_pr_pub_key_meta: {:?}",
               cred_pr_pub_key, cred_pr_priv_key, cred_pr_pub_key_meta);

        let mut ctx = BigNumber::new_context()?;

        let xz_tilda = gen_x(&cred_pr_priv_key.p, &cred_pr_priv_key.q)?;

        let mut xr_tilda = HashMap::new();
        for key in cred_pr_pub_key.r.keys() {
            xr_tilda.insert(key.to_string(), gen_x(&cred_pr_priv_key.p, &cred_pr_priv_key.q)?);
        }

        let z_tilda = cred_pr_pub_key.s.mod_exp(&xz_tilda, &cred_pr_pub_key.n, Some(&mut ctx))?;

        let mut r_tilda = HashMap::new();
        for (key, xr_tilda_value) in xr_tilda.iter() {
            r_tilda.insert(key.to_string(), cred_pr_pub_key.s.mod_exp(&xr_tilda_value, &cred_pr_pub_key.n, Some(&mut ctx))?);
        }

        let mut values: Vec<u8> = Vec::new();
        let mut ordered_attrs: Vec<String> = Vec::new();
        values.extend_from_slice(&cred_pr_pub_key.z.to_bytes()?);
        for (key, val) in cred_pr_pub_key.r.iter() {
            values.extend_from_slice(&val.to_bytes()?);
            ordered_attrs.push(key.to_owned());
        }
        values.extend_from_slice(&z_tilda.to_bytes()?);
        for attr in &ordered_attrs {
            let val = &r_tilda[attr];
            values.extend_from_slice(&val.to_bytes()?);
        }

        let c = get_hash_as_int(&mut vec![values])?;

        let xz_cap =
            c.mul(&cred_pr_pub_key_meta.xz, Some(&mut ctx))?
                .add(&xz_tilda)?;

        let mut xr_cap: Vec<(String, BigNumber)> = Vec::new();
        for key in ordered_attrs {
            let xr_tilda_value = &xr_tilda[&key];
            let val =
                c.mul(&cred_pr_pub_key_meta.xr[&key], Some(&mut ctx))?
                    .add(&xr_tilda_value)?;
            xr_cap.push((key, val));
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
                let index = Issuer::_get_index(max_cred_num, i);
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

        trace!("Issuer::_new_revocation_registry_keys: <<< rev_key_pub: {:?}, rev_key_priv: {:?}", rev_key_pub, rev_key_priv);

        Ok((rev_key_pub, rev_key_priv))
    }

    fn _check_blinded_credential_secrets_correctness_proof(blinded_cred_secrets: &BlindedCredentialSecrets,
                                                           blinded_cred_secrets_correctness_proof: &BlindedCredentialSecretsCorrectnessProof,
                                                           nonce: &Nonce,
                                                           cred_pr_pub_key: &CredentialPrimaryPublicKey) -> Result<(), IndyCryptoError> {
        trace!("Issuer::_check_blinded_credential_secrets_correctness_proof: >>> blinded_cred_secrets: {:?}, blinded_cred_secrets_correctness_proof: {:?},\
         nonce: {:?}, cred_pr_pub_key: {:?}", blinded_cred_secrets, blinded_cred_secrets_correctness_proof, nonce, cred_pr_pub_key);

        let mut values: Vec<u8> = Vec::new();
        let mut ctx = BigNumber::new_context()?;

        let u_cap = blinded_cred_secrets.hidden_attributes
                                        .iter()
                                        .fold(blinded_cred_secrets.u
                                                    .inverse(&cred_pr_pub_key.n, Some(&mut ctx))?
                                                    .mod_exp(&blinded_cred_secrets_correctness_proof.c, &cred_pr_pub_key.n, Some(&mut ctx))?
                                                    .mod_mul(
                                                        &cred_pr_pub_key.s.mod_exp(&blinded_cred_secrets_correctness_proof.v_dash_cap, &cred_pr_pub_key.n, Some(&mut ctx))?,
                                                        &cred_pr_pub_key.n,
                                                        Some(&mut ctx)
                                                    ),
                                              |acc, attr| {
                                                  let pk_r = cred_pr_pub_key.r
                                                                    .get(&attr.clone())
                                                                    .ok_or(IndyCryptoError::InvalidStructure(format!("Value by key '{}' not found in cred_pr_pub_key.r", attr)))?;
                                                  let m_cap = &blinded_cred_secrets_correctness_proof.m_caps[attr];
                                                  acc?.mod_mul(&pk_r.mod_exp(&m_cap, &cred_pr_pub_key.n, Some(&mut ctx))?,
                                                               &cred_pr_pub_key.n, Some(&mut ctx))
                                              })?;

        for (key, value) in &blinded_cred_secrets.committed_attributes {
            let m_cap = &blinded_cred_secrets_correctness_proof.m_caps[key];
            let comm_att_cap = value.inverse(&cred_pr_pub_key.n, Some(&mut ctx))?
                                    .mod_exp(&blinded_cred_secrets_correctness_proof.c, &cred_pr_pub_key.n, Some(&mut ctx))?
                                    .mod_mul(&get_pedersen_commitment(&cred_pr_pub_key.z, &m_cap,
                                                                      &cred_pr_pub_key.s, &blinded_cred_secrets_correctness_proof.r_caps[key],
                                                                      &cred_pr_pub_key.n, &mut ctx)?,
                                             &cred_pr_pub_key.n, Some(&mut ctx))?;

            values.extend_from_slice(&comm_att_cap.to_bytes()?);
            values.extend_from_slice(&value.to_bytes()?);
        }


        values.extend_from_slice(&blinded_cred_secrets.u.to_bytes()?);
        values.extend_from_slice(&u_cap.to_bytes()?);
        values.extend_from_slice(&nonce.to_bytes()?);

        let c = get_hash_as_int(&vec![values])?;

        let valid = blinded_cred_secrets_correctness_proof.c.eq(&c);

        if !valid {
            return Err(IndyCryptoError::InvalidStructure(format!("Invalid BlindedCredentialSecrets correctness proof")));
        }

        trace!("Issuer::_check_blinded_credential_secrets_correctness_proof: <<<");

        Ok(())
    }

    // In the anoncreds whitepaper, `credential context` is denoted by `m2`
    fn _gen_credential_context(prover_id: &str, rev_idx: Option<u32>) -> Result<BigNumber, IndyCryptoError> {
        trace!("Issuer::_calc_m2: >>> prover_id: {:?}, rev_idx: {:?}", prover_id, rev_idx);

        let rev_idx = rev_idx.map(|i| i as i32).unwrap_or(-1);

        let prover_id_bn = encode_attribute(prover_id, ByteOrder::Little)?;
        let rev_idx_bn = encode_attribute(&rev_idx.to_string(), ByteOrder::Little)?;

        let mut values: Vec<u8> = Vec::new();
        values.extend_from_slice(&prover_id_bn.to_bytes()?);
        values.extend_from_slice(&rev_idx_bn.to_bytes()?);

        let credential_context = get_hash_as_int(&vec![values])?;

        trace!("Issuer::_gen_credential_context: <<< credential_context: {:?}", credential_context);

        Ok(credential_context)
    }

    fn _new_primary_credential(credential_context: &BigNumber,
                               cred_pub_key: &CredentialPublicKey,
                               cred_priv_key: &CredentialPrivateKey,
                               blinded_credential_secrets: &BlindedCredentialSecrets,
                               cred_values: &CredentialValues) -> Result<(PrimaryCredentialSignature, BigNumber), IndyCryptoError> {
        trace!("Issuer::_new_primary_credential: >>> credential_context: {:?}, cred_pub_key: {:?}, cred_priv_key: {:?}, blinded_ms: {:?},\
         cred_values: {:?}", credential_context, cred_pub_key, cred_priv_key, blinded_credential_secrets, cred_values);

        let v = generate_v_prime_prime()?;

        let e = generate_prime_in_range(&LARGE_E_START_VALUE, &LARGE_E_END_RANGE_VALUE)?;
        let (a, q) = Issuer::_sign_primary_credential(cred_pub_key, cred_priv_key, &credential_context, &cred_values, &v, blinded_credential_secrets, &e)?;

        let pr_cred_sig = PrimaryCredentialSignature { m_2: credential_context.clone()?, a, e, v };

        trace!("Issuer::_new_primary_credential: <<< pr_cred_sig: {:?}, q: {:?}", pr_cred_sig, q);

        Ok((pr_cred_sig, q))
    }

    fn _sign_primary_credential(cred_pub_key: &CredentialPublicKey,
                                cred_priv_key: &CredentialPrivateKey,
                                cred_context: &BigNumber,
                                cred_values: &CredentialValues,
                                v: &BigNumber,
                                blinded_cred_secrets: &BlindedCredentialSecrets,
                                e: &BigNumber) -> Result<(BigNumber, BigNumber), IndyCryptoError> {
        trace!("Issuer::_sign_primary_credential: >>> cred_pub_key: {:?}, \
                                                      cred_priv_key: {:?}, \
                                                      cred_context: {:?}, \
                                                      cred_values: {:?}, \
                                                      v: {:?},\
                                                      blinded_cred_secrets: {:?}, \
                                                      e: {:?}", cred_pub_key, cred_priv_key, cred_context, cred_values, v, blinded_cred_secrets, e);

        let p_pub_key = &cred_pub_key.p_key;
        let p_priv_key = &cred_priv_key.p_key;

        let mut context = BigNumber::new_context()?;

        let mut rx = p_pub_key.s.mod_exp(&v, &p_pub_key.n, Some(&mut context))?;

        if blinded_cred_secrets.u != BigNumber::from_u32(0)? {
            rx = rx.mod_mul(&blinded_cred_secrets.u, &p_pub_key.n, Some(&mut context))?;
        }

        rx = rx.mod_mul(&p_pub_key.rctxt.mod_exp(&cred_context, &p_pub_key.n, Some(&mut context))?, &p_pub_key.n, Some(&mut context))?;

        for (key, attr) in cred_values.attrs_values.iter().filter(|&(_, v)| v.is_known()) {
            let pk_r = p_pub_key.r
                .get(key)
                .ok_or(IndyCryptoError::InvalidStructure(format!("Value by key '{}' not found in pk.r", key)))?;

            rx = pk_r.mod_exp(attr.value(), &p_pub_key.n, Some(&mut context))?
                     .mod_mul(&rx, &p_pub_key.n, Some(&mut context))?;
        }

        let q = p_pub_key.z.mod_div(&rx, &p_pub_key.n, Some(&mut context))?;

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

    fn _get_index(max_cred_num: u32, rev_idx: u32) -> u32 {
        max_cred_num + 1 - rev_idx
    }

    fn _new_non_revocation_credential(rev_idx: u32,
                                      cred_context: &BigNumber,
                                      blinded_credential_secrets: &BlindedCredentialSecrets,
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
               rev_idx, cred_context, blinded_credential_secrets, cred_pub_key, cred_priv_key, max_cred_num, issuance_by_default, rev_reg, rev_key_priv);

        let ur = blinded_credential_secrets.ur
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

        let index = Issuer::_get_index(max_cred_num, rev_idx);

        let rev_reg_delta = if issuance_by_default {
            None
        } else {
            let prev_acc = rev_reg.accum.clone();

            rev_tails_accessor.access_tail(index, &mut |tail| {
                rev_reg.accum = rev_reg.accum.add(tail).unwrap();
            })?;

            Some(RevocationRegistryDelta {
                prev_accum: Some(prev_acc),
                accum: rev_reg.accum.clone(),
                issued: hashset![rev_idx],
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
    use self::prover::mocks as prover_mocks;
    use self::prover::Prover;

    #[test]
    fn generate_context_attribute_works() {
        let rev_idx = 110;
        let user_id = "111";
        let answer = BigNumber::from_dec("31894574610223295263712513093148707509913459424901632064286025736442349335521").unwrap();
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
        credential_values_builder.add_dec_known("sex", "89057765651800459030103911598694169835931320404459570102253965466045532669865684092518362135930940112502263498496335250135601124519172068317163741086983519494043168252186111551835366571584950296764626458785776311514968350600732183408950813066589742888246925358509482561838243805468775416479523402043160919428168650069477488093758569936116799246881809224343325540306266957664475026390533069487455816053169001876208052109360113102565642529699056163373190930839656498261278601357214695582219007449398650197048218304260447909283768896882743373383452996855450316360259637079070460616248922547314789644935074980711243164129").unwrap();
        credential_values_builder.add_dec_known("name", "58606710922154038918005745652863947546479611221487923871520854046018234465128105585608812090213473225037875788462225679336791123783441657062831589984290779844020407065450830035885267846722229953206567087435754612694085258455822926492275621650532276267042885213400704012011608869094703483233081911010530256094461587809601298503874283124334225428746479707531278882536314925285434699376158578239556590141035593717362562548075653598376080466948478266094753818404986494459240364648986755479857098110402626477624280802323635285059064580583239726433768663879431610261724430965980430886959304486699145098822052003020688956471").unwrap();
        let credential_values = credential_values_builder.finalize().unwrap();

        assert!(credential_values.attrs_values["sex"].value().eq(&BigNumber::from_dec("89057765651800459030103911598694169835931320404459570102253965466045532669865684092518362135930940112502263498496335250135601124519172068317163741086983519494043168252186111551835366571584950296764626458785776311514968350600732183408950813066589742888246925358509482561838243805468775416479523402043160919428168650069477488093758569936116799246881809224343325540306266957664475026390533069487455816053169001876208052109360113102565642529699056163373190930839656498261278601357214695582219007449398650197048218304260447909283768896882743373383452996855450316360259637079070460616248922547314789644935074980711243164129").unwrap()));
        assert!(credential_values.attrs_values["name"].value().eq(&BigNumber::from_dec("58606710922154038918005745652863947546479611221487923871520854046018234465128105585608812090213473225037875788462225679336791123783441657062831589984290779844020407065450830035885267846722229953206567087435754612694085258455822926492275621650532276267042885213400704012011608869094703483233081911010530256094461587809601298503874283124334225428746479707531278882536314925285434699376158578239556590141035593717362562548075653598376080466948478266094753818404986494459240364648986755479857098110402626477624280802323635285059064580583239726433768663879431610261724430965980430886959304486699145098822052003020688956471").unwrap()));
        assert!(credential_values.attrs_values.get("age").is_none());
    }

    #[test]
    fn issuer_new_credential_def_works() {
        MockHelper::inject();

        let (pub_key, priv_key, key_correctness_proof) = Issuer::new_credential_def(&mocks::credential_schema(), &mocks::non_credential_schema(), true).unwrap();
        assert!(pub_key.r_key.is_some());
        assert!(priv_key.r_key.is_some());
        Prover::check_credential_key_correctness_proof(&mocks::credential_primary_public_key(), &mocks::credential_key_correctness_proof()).unwrap();
        Prover::check_credential_key_correctness_proof(&pub_key.p_key, &key_correctness_proof).unwrap();
    }

    #[test]
    fn issuer_new_credential_def_works_without_revocation_part() {
        MockHelper::inject();

        let (pub_key, priv_key, key_correctness_proof) = Issuer::new_credential_def(&mocks::credential_schema(), &mocks::non_credential_schema(), false).unwrap();
        assert!(pub_key.r_key.is_none());
        assert!(priv_key.r_key.is_none());
        Prover::check_credential_key_correctness_proof(&mocks::credential_primary_public_key(), &mocks::credential_key_correctness_proof()).unwrap();
        Prover::check_credential_key_correctness_proof(&pub_key.p_key, &key_correctness_proof).unwrap();
    }

    #[test]
    fn issuer_new_credential_works_for_empty_attributes() {
        let cred_attrs = CredentialSchema { attrs: BTreeSet::new() };
        let non_cred_attrs = NonCredentialSchema { attrs: BTreeSet::new() };
        let res = Issuer::new_credential_def(&cred_attrs, &non_cred_attrs, false);
        assert!(res.is_err())
    }

    #[test]
    fn issuer_new_revocation_registry_def_works() {
        MockHelper::inject();

        let (pub_key, _, _) = Issuer::new_credential_def(&mocks::credential_schema(), &mocks::non_credential_schema(), true).unwrap();
        Issuer::new_revocation_registry_def(&pub_key, 100, false).unwrap();
    }

    #[test]
    fn sign_primary_credential_works() {
        MockHelper::inject();

        let (pub_key, secret_key) = (mocks::credential_public_key(), mocks::credential_private_key());
        let context_attribute = mocks::m2();

        let credential_values = mocks::credential_values();
        let primary_credential = mocks::primary_credential();

        let expected_q = primary_credential.a.mod_exp(&primary_credential.e, &pub_key.p_key.n, None).unwrap();

        let (credential_signature, q) = Issuer::_sign_primary_credential(&pub_key, &secret_key, &context_attribute, &credential_values, &primary_credential.v, &prover_mocks::blinded_credential_secrets(), &primary_credential.e).unwrap();
        assert_eq!(primary_credential.a, credential_signature);
        assert_eq!(expected_q, q);
    }

    #[test]
    fn sign_credential_signature_works() {
        MockHelper::inject();

        let (pub_key, priv_key) = (mocks::credential_public_key(), mocks::credential_private_key());
        let blinded_credential_secrets_nonce = mocks::credential_nonce();
        let (blinded_credential_secrets, blinded_credential_secrets_correctness_proof) =
            (prover::mocks::blinded_credential_secrets(), prover::mocks::blinded_credential_secrets_correctness_proof());

        let credential_issuance_nonce = mocks::credential_issuance_nonce();
        let (credential_signature, signature_correctness_proof) = Issuer::sign_credential(prover_mocks::PROVER_DID,
                                                                                        &blinded_credential_secrets,
                                                                                        &blinded_credential_secrets_correctness_proof,
                                                                                        &blinded_credential_secrets_nonce,
                                                                                        &credential_issuance_nonce,
                                                                                        &mocks::credential_values(),
                                                                                        &pub_key,
                                                                                        &priv_key).unwrap();
        let expected_credential_signature = PrimaryCredentialSignature {
                m_2: BigNumber::from_dec("69277050336954731912953999596899794023422356864020449587821228635678593076726").unwrap(),
                a: BigNumber::from_dec("70440498515924074536240292859277583630451742240279439935717350639617448969549093696955613248043908099762959902912065607566009153884685161056994685047480889247369965624632337451574666427678833401079050003523296902547782414282924153126345647025090751385864458706469197210153335432026933889545655877519930013716100086825933567701731961803401241169404981745171175490083339254392436261445795445090112940671342922753889853868689690074359970574257804742997843041865109539632915531943077535271714329883392236431724435117196654449899564087400876128793981039610769251451873428827201495403241611326753426745345121665029198025756").unwrap(),
                e: BigNumber::from_dec("259344723055062059907025491480697571938277889515152306249728583105665800713306759149981690559193987143012367913206299323899696942213235956742930201588264091397308910346117473868881").unwrap(),
                v: BigNumber::from_dec("6620937836014079781509458870800001917950459774302786434315639456568768602266735503527631640833663968617512880802104566048179854406925811731340920442625764155409951969854303612644125623549271204625894424804352003689903192473464433927658013251120302922648839652919662117216521257876025436906282750361355336367533874548955283776610021309110505377492806210342214471251451681722267655419075635703240258044336607001296052867746675049720589092355650996711033859489737240617860392914314205277920274997312351322125481593636904917159990500837822414761512231315313922792934655437808723096823124948039695324591344458785345326611693414625458359651738188933757751726392220092781991665483583988703321457480411992304516676385323318285847376271589157730040526123521479652961899368891914982347831632139045838008837541334927738208491424027").unwrap(),
            };

        let expected_signature_correctness_proof = SignatureCorrectnessProof {
            se: BigNumber::from_dec("8481997129487502407156564609201073256372636432553392298940699191485310706048807714896199609491481703518303525486750701021541614004024331969157939768039225102458169060626155222451725002935183478381146066923476052328200996603219035952243075204378434631926065801919357652141080948952848986400835136940202513223915936077406202053307147246797765620593626304281347103023966471285999010946401148439528095105346393702668815349779147145475493588638037730363867454549012575433007195781433266661023423194282114743999098904505091901986566104755535722321486180325462438973115236934272968987307367081029923419158990477745474384362").unwrap(),
            c: BigNumber::from_dec("81706072459632571037913748513602601899239086191003323683246846573036230181290").unwrap(),
        };

        assert_eq!(expected_credential_signature, credential_signature.p_credential);
        assert_eq!(expected_signature_correctness_proof, signature_correctness_proof);
    }

    #[test]
    #[ignore]
    fn generate_mocks() {
//        MockHelper::inject();

        let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
        credential_schema_builder.add_attr("name").unwrap();
        credential_schema_builder.add_attr("sex").unwrap();
        credential_schema_builder.add_attr("age").unwrap();
        credential_schema_builder.add_attr("height").unwrap();
        let credential_schema = credential_schema_builder.finalize().unwrap();

        let mut non_credential_builder = NonCredentialSchemaBuilder::new().unwrap();
        non_credential_builder.add_attr("master_secret").unwrap();
        let non_credential_schema = non_credential_builder.finalize().unwrap();

        let (cred_pub_key, cred_priv_key, cred_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, &non_credential_schema, true).unwrap();

        println!("cred_pub_key={:#?}", cred_pub_key);
        println!("cred_priv_key={:#?}", cred_priv_key);
        println!("cred_key_correctness_proof={:#?}", cred_key_correctness_proof);

        let mut credential_values_builder = CredentialValuesBuilder::new().unwrap();
        credential_values_builder.add_value_hidden("master_secret", &prover_mocks::master_secret().value().unwrap()).unwrap();
        credential_values_builder.add_value_known("name", &string_to_bignumber("indy-crypto")).unwrap();
        credential_values_builder.add_dec_known("age", "25").unwrap();
        credential_values_builder.add_value_known("sex", &string_to_bignumber("refused")).unwrap();
        credential_values_builder.add_dec_known("height", "175").unwrap();

        let cred_values = credential_values_builder.finalize().unwrap();

        println!("credential_values={:#?}", cred_values);

        let credential_nonce = new_nonce().unwrap();

        println!("credential_nonce={:#?}", credential_nonce);

        let (blinded_credential_secrets, credential_secrets_blinding_factors, blinded_credential_secrets_correctness_proof) =
                    Prover::blind_credential_secrets(&cred_pub_key,
                                                     &cred_key_correctness_proof,
                                                     &cred_values,
                                                     &credential_nonce).unwrap();

        println!("blinded_credential_secrets={:#?}", blinded_credential_secrets);
        println!("credential_secrets_blinding_factors={:#?}", credential_secrets_blinding_factors);
        println!("blinded_credential_secrets_correctness_proof={:#?}", blinded_credential_secrets_correctness_proof);

        let max_cred_num = 5;
        let issuance_by_default = false;
        let (rev_key_pub, rev_key_priv, mut rev_reg, mut rev_tails_generator) = Issuer::new_revocation_registry_def(&cred_pub_key, max_cred_num, issuance_by_default).unwrap();
        let simple_tail_accessor = SimpleTailsAccessor::new(&mut rev_tails_generator).unwrap();

        println!("rev_key_pub={:#?}", rev_key_pub);
        println!("rev_key_priv={:#?}", rev_key_priv);
        println!("rev_reg={:#?}", rev_reg);

        let credential_issuance_nonce = new_nonce().unwrap();

        println!("credential_issuance_nonce={:#?}", credential_issuance_nonce);

        let rev_idx = 1;
        let (mut cred_signature, signature_correctness_proof, rev_reg_delta) =
                Issuer::sign_credential_with_revoc(prover_mocks::PROVER_DID,
                                                   &blinded_credential_secrets,
                                                   &blinded_credential_secrets_correctness_proof,
                                                   &credential_nonce,
                                                   &credential_issuance_nonce,
                                                   &cred_values,
                                                   &cred_pub_key,
                                                   &cred_priv_key,
                                                   rev_idx,
                                                   max_cred_num,
                                                   issuance_by_default,
                                                   &mut rev_reg,
                                                   &rev_key_priv,
                                                   &simple_tail_accessor).unwrap();

        println!("before prover cred_signature={:#?}", cred_signature);
        println!("signature_correctness_proof={:#?}", signature_correctness_proof);
        println!("rev_reg_delta={:#?}", rev_reg_delta);

        let witness = Witness::new(rev_idx, max_cred_num, issuance_by_default, &rev_reg_delta.unwrap(), &simple_tail_accessor).unwrap();

        println!("witness={:#?}", witness);

        Prover::process_credential_signature(&mut cred_signature,
                                             &cred_values,
                                             &signature_correctness_proof,
                                             &credential_secrets_blinding_factors,
                                             &cred_pub_key,
                                             &credential_issuance_nonce,
                                             Some(&rev_key_pub),
                                             Some(&rev_reg),
                                             Some(&witness)).unwrap();
        println!("after prover cred_signature={:#?}", cred_signature);
    }

    fn string_to_bignumber(s: &str) -> BigNumber {
        let hash = BigNumber::hash(s.as_bytes()).unwrap();
        BigNumber::from_bytes(&hash[..]).unwrap()
    }
}

pub mod mocks {
    use super::*;
    use self::prover::mocks as prover_mocks;

    pub fn m2() -> BigNumber {
        BigNumber::from_dec("69500003785041890145270364348670634122591474903142468939711692725859480163330").unwrap()
    }

    pub fn credential_public_key() -> CredentialPublicKey {
        CredentialPublicKey {
            p_key: credential_primary_public_key(),
            r_key: Some(credential_revocation_public_key())
        }
    }

    pub fn credential_nonce() -> Nonce {
        BigNumber::from_dec("922886149418546788306777").unwrap()
    }

    pub fn credential_issuance_nonce() -> Nonce { BigNumber::from_dec("961495420773990165680682").unwrap() }

    pub fn credential_private_key() -> CredentialPrivateKey {
        CredentialPrivateKey {
            p_key: credential_primary_private_key(),
            r_key: Some(credential_revocation_private_key())
        }
    }

    pub fn credential_key_correctness_proof() -> CredentialKeyCorrectnessProof {
        CredentialKeyCorrectnessProof {
            c: BigNumber::from_dec("71113322178490952412002544133909409236408656166008035642305568009169588992321").unwrap(),
            xz_cap: BigNumber::from_dec("1311424321268910097324752278244955410461664510097161695606029565646218533381707480460755894045461303168315878840262987865704814722406674480058901543223385868994175956318660581197673704499907966327230464367687804032705476374091796273991357095271547742599325817404598951788320866888105425166192759048457784705502710775822984481591646122546803902928372697457567291699752685825915480837331061491219315979178819329318974198844074488631040384781446154284544752565584433877916304967382688352570791829815025831232481028304557907113146186454507082616067672651873466799186592865708844744375853868938958601438006533043679556054414262611866590552724601514738349305357349427098350007523385537209277835668391").unwrap(),
            xr_cap: btreemap![
                "age".to_string() => BigNumber::from_dec("1774406280716312037720693578116090030757261208434496639385979343596859974172978604200811579894944901311197388452683262446612373669605050946031499603252257167637618437412488152825102207228978307332449329254061761671152689880087912846447839737857262874989191753472709803909202705913008006188404551376768528220383685127606619543016764250181977324720633921402217965095137975878703691234127491314711941366485540915155822928454777319213065918931770737123335301191733535152926439734510935177876205847980143427199760068519608675318435225400053651214666079293480299147554115044547064628849281140201186173073729870850102150860138538452123396323972995465310629628353217868079348080031604270553289593993492").unwrap(),
                "height".to_string() => BigNumber::from_dec("1632278948651591888168656398970363610255109995957256589398208803663909194990748711440741127217288256356317972839070978594347184199691160054984573766706197315227182444002643695231358977955984561867966814259949226552961214820127601830225364099458457176500887143556770392153444455663451488180564436144701911270550510268901166634946016134380305110749467496009732794003221180081094056299146120527617656751706050129540612951319830736904707487212031450679701078815123380315017346732107015335412641604596034779760236276214134877786503258034621075664145613139511800830138251166199227395580880003489717864986830861950755464183073329556599680160399227135211443619218012101549881404453667687580320791080844").unwrap(),
                "master_secret".to_string() => BigNumber::from_dec("264213972976693728901144815189952241314470418871121928245726646186691340926764866326394704595340191619395438976463547352994117494015816298817543622741428269792918545736312628336814218913183707486864168590671707196240744832596088960326500426475844464044162662052256730239404349429516318260930829669630110267782608032421499585711460764943240741019971154436705277237520377189400038768614201441188289319067017891336079134284373577436938594187343097258526549801031628898874638212271955190036720988202393902974865102471960086914106823693741840364696187023456402622850995685909392509849054875939218976784146875989581473426250129367059869275028279250638068255576732052438639476969943105236007311013658").unwrap(),
                "name".to_string() => BigNumber::from_dec("751986541854263022330404757594361836318058265442549108783555229504396921821109016409036760273831707428175900149149823410826427997091955618417905562933186942107278810007382790377167147567064298779612256751724477134569886185143180380026302388477543091519789521851619389515588235298290396907565155725185231072219597544580969433522577350288927621335428016256705005850308080783049546375541452320136669909940855416818834152992256821794126286986773983748179775829342708737512260073782161035749894205343996190701455706367722873140750007227365055435892770512623049557935981999019304595670489372940303708114226515629335249518887625905642413181468803927398644435635416124900423402221899083672866160463480").unwrap(),
                "sex".to_string() => BigNumber::from_dec("53612280240931190720786650729699636939926735628976922530726167526886778352774923016913798774938544228245216103151830348835769898915385742609087254132404972722737603937256939051814235568824651324018867683691191737999694207817939679236272347656677626447027865803465709850977480223927564343804506365636728921201762169661435181378717213456156938392350717138036829920246587933728952805066512493942178695990394387228065010766060671600405207872311743490473228341593012255167897761050073156152212677645797099486877079162002465340988754753121314295152117514571693060616905065916540845218304602858582074820244331145751818023465074208274454072919166809156090576043357114142253496214571334962938567726272").unwrap()
            ]
        }
    }

    pub fn credential_primary_public_key() -> CredentialPrimaryPublicKey {
        CredentialPrimaryPublicKey {
            n: BigNumber::from_dec("120363395533886611192572989804978065861942913468286323558506705415254554817222759246054753213798000815141758443287270568250887753784391304324065729830934411996733139173148371341900064941403020628132930952686851631767407759947661662934310086167076411479342246665071263164774643931096225309193388784974523884870332969182117183021118638837405986522895245669611653999771231715895826627660108615358374447206007565935074330049045254112047783731111245508464767262478303838339623568923085165401361857614841978748707573323116347737013232555176263293381670928918673087120722996350803998448117776307736678985566010200761790935969").unwrap(),
            s: BigNumber::from_dec("93114334831513298077697376433427654227052106069569088827622652378594681061414518588231274683249601788183367008387466980478915819324787709147516306269271779382650114812109955724450294330206394219366534777980211676414922970149191450084394465369175814992070820499149072722157801258202864562698020627400201566051843058639853815135860551432851291646850605895445262559800486491575851950170691304275600174565735584005729852321284413932575867487999498077101942632606931950765912988051287690668973855853739061038491137363186695307199845123380462047089023190566542901598107621274118309606119695706599087464592529701805116347843").unwrap(),
            r: btreemap![
                "age".to_string() => BigNumber::from_dec("32594669333564873468830150453597422989025779864618204745146587476526466652767057363614420550305428840478871425942273748768572637117561113347727529826085915193245451810340568195942868578935058275152498935855011402087123156615746516181583164903844214522858102058198474601487432545971197618020290672543775794736528705651698185022545544512292807581444580696944895278925332432315304813490005594876644087951424601396611431240023409828672420636883221946988875955684044441026038027791224617633360174599756439802980718813635203025055377945035025619404601689913075363199239346821789035404195260090923078792098504706977721263519").unwrap(),
                "height".to_string() => BigNumber::from_dec("113615319831101593829291212438476499578400295358531619484693702862967742453281240254845751687986328969980044799185245853531410447318111310427231713305713526013395683376033708608571562685058376027990140529290519140979804632211761828516091183883084896751626984923601558915104859266402172736858478404257410383802404491628126231928114858618448791587192302554100760623508768481402206273547478977196211939870536415381083321490658524768071091986089307149789099901232850197945791367685788132054705225223821296971046429511673599608054578235518673142278420074296922808515847400573982580408240854731366154932914154129754126259969").unwrap(),
                "master_secret".to_string() => BigNumber::from_dec("108258010280298590435468265849536593226448748165633043552417553770478449592679051195364369358463646370534823543169605754950302132077042476630229340744919299244021135058779885373695679177561485798369757901412282545653784038157827562260562952805558130202006155912331399317322494958676965777687488544655798298039070002529226635684398181341445629955954630380393069710541460118224832322982267347355878989003354064929618167204590217600301675679614322936970047121234040364510585732383239479765041649608667080732604552275674263685655319154947929443255636480149057471413257960315936160097054618042389811849794749346772235612450").unwrap(),
                "name".to_string() => BigNumber::from_dec("107584545280835516097346973274567052149006002855095447276931131613698234826471573095399976573786297838670321479975648831817075003456670971089851419753737576985241328149643708954677644167655623266133490190635512261159910388176974642315445487649653625201920107714307536568261805823303322023824758698895407502730481248513732047052317007361842928784595648885926073211038720900669743413912857105829697741522066604265306865948839444951324871091436534683310966870729774864597469154821653661898151453630444999481651686481415106999409175016685191718509911784341853575049150478997637760429336005594142963777260403226857230786754").unwrap(),
                "sex".to_string() => BigNumber::from_dec("97219804208488772397494152287887060275243097465292537357152051252553998279777659340998591497595304443987698083952269166986225618792893125508314232305456802890882786978104610184172587939365418725636219280320576038693450233158689370659307598327173327301812634759784143926568475361939884586309433958110887379961281552492667068143019455806019066757479537352570741520094311333204523421699996272141023512605811343057433023800008984167330632086749472372768782582745615544837223508139678209194214282230864828551645375480593811327712239831104241920938832174117435471424432616888867564569879384834078857564763730314477614782471").unwrap()
            ],
            rctxt: BigNumber::from_dec("68075052140650597086719814856683167277918382559530620070362388677846518196886157631395920994028244904741093755103377517354631586045896054102297937684326170231779833905804016789616484215558366634936889440735929964053326772039049682020146378173845331399248832900321752607923373460356084370965037146735634070345156839393967188825689869313941330049511690310207899816625429650311731941231336044379144111163471320714828121785901430468820080916122857994331773771953914411303804627874108320815122006869165509905911754543909081750694899266769101991679285031136936258159539903258499632687086775551924935685039213866052026074229").unwrap(),
            z: BigNumber::from_dec("117446886962812789681879559806097239446190890549631370857707059455202326374396418447517110698078414129814730124955604255273935910192570099873177181348447632753411015921054949051310272411317034981084796764541371410836736689911745764627616854712055611173553142669511844257596511896658651186712864975852577649451656825004006588560659125515598201619891310170465591778971065986288095052417560866092460936560532311136330024640852531821840788047643738931275086500230131712410948439523630728867792492452701835323971118389975924428192321616744807156534473933645728711405404827723047144734896894573927501593374710606963367614013").unwrap()
        }
    }

    pub fn credential_primary_private_key() -> CredentialPrimaryPrivateKey {
        CredentialPrimaryPrivateKey {
            p: BigNumber::from_dec("167763327223779848079150051849754646628628171296887905313969575308169478003884069329000630150543021351670293324319396780176663483114409366356264692620025605532200370823057670400221259449806575499511384972909786244020491441498150221925265674135631956379119101326655239403328610900571921234398003090158000790043").unwrap(),
            q: BigNumber::from_dec("179364878972228581464665396145542688182130061050348810405596542593392738782681171830581800157532123274093064918712574165185754401816146428391046302525410709735526822836714373394975505823346236111100948619381844845728522581771722931634631831558773402686386324706983766129069577249822205076470419464674597686643").unwrap()
        }
    }

    pub fn credential_schema() -> CredentialSchema {
        CredentialSchema {
            attrs: btreeset!["name".to_string(), "age".to_string(), "height".to_string(), "sex".to_string()]
        }
    }

    pub fn non_credential_schema() -> NonCredentialSchema {
        NonCredentialSchema {
            attrs: btreeset!["master_secret".to_string()]
        }
    }

    pub fn credential_values() -> CredentialValues {
        CredentialValues {
            attrs_values: btreemap![
                "age".to_string() => CredentialValue::Known { value: BigNumber::from_u32(25).unwrap() },
                "height".to_string() => CredentialValue::Known { value: BigNumber::from_u32(175).unwrap() },
                "master_secret".to_string() => CredentialValue::Hidden { value: prover_mocks::master_secret().value().unwrap() },
                "name".to_string() => CredentialValue::Known { value: BigNumber::from_dec("66682250590915135919393234675423675079281389286836524491448775067034910960723").unwrap() },
                "sex".to_string() => CredentialValue::Known { value: BigNumber::from_dec("59607158875075502079861259255950808097316057515161310607657216396491477298979").unwrap() }
            ]
        }
    }

    pub fn credential() -> CredentialSignature {
        CredentialSignature {
            p_credential: primary_credential(),
            r_credential: Some(revocation_credential())
        }
    }

    pub fn primary_credential() -> PrimaryCredentialSignature {
        PrimaryCredentialSignature {
            m_2: m2(),
            a: BigNumber::from_dec("60598096300110505279750181320130587026716953168722029465442100858765611388437518362663364506285714393889528526925769421571092083357542485349102861386986057219969921557487809995601556559987762243518822764509094413774190105074641519836018069694204467033725909348537798613387434106828072295539069401257717308548203193143526998793635659215707816324637606186537330000247168547726551874138698100814471988467062706901218694137515927694259483279409479745022260125873317036913720086519524465890008868911411373324450614877678917640617150293767932573524818488647061713391998713343528454289262358169184742033153828930903815476187").unwrap(),
            e: BigNumber::from_dec("259344723055062059907025491480697571938277889515152306249728583105665800713306759149981690559193987143012367913206299323899696942213235956742929944698562575392316272320549893391771").unwrap(),
            v: BigNumber::from_dec("6996057067686934709231174434558258486493808267378248647410976878261435225657894050774133393922654332955534902104832478531341852292938521469275360591816338451092268559834937570490320037683076950526114387947122222573996640569544712017259212188191693180242485210470759575121212877880400904474747205259141924281873752072766592848970048197734593050380409514783396683785870987760103648935827566865119283786314941939210890789635796052086535415043847417988644671971953857717397992323227477402000359942852383945496600389475364990114239826632097914000578635989375569687967746084441461839592066962605775236397958420076271612367128072885918150951151281149332889562926392105566994771183411145333439927578315050777074842093836782606943424634804847072816374824078898835448442127402305405355399662900736125699452372080777362153439581636").unwrap()
        }
    }

    pub fn signature_correctness_proof() -> SignatureCorrectnessProof {
       SignatureCorrectnessProof {
            se: BigNumber::from_dec("29926400801820235269383823779389066519854586289331589676177113803123456022556837347422334446271735096593173851487054554667140594314578634914359623278367826997350870700968815587203555820827183087969792898580178258914335305156240693606059189720794481492880270933143932251639946585957325013096516682619034323789009548294680961433018027804495256233231346202478668787239133287130203598662333709958691835834863585634112163409214884862456213164229620666691927338400829972894719160802310678296904078018328445538267047813456150969592051766058478770857897619084590392939371253385121322616816090730953834618211120185674550910747").unwrap(),
            c: BigNumber::from_dec("12772596794034715724303716192120031401085748512652564977734885573240777242238").unwrap()
        }
    }

    pub fn revocation_credential() -> NonRevocationCredentialSignature {
        NonRevocationCredentialSignature {
            sigma: PointG1::from_string("false AB4BD3CCD0BBBE 5D0014CD3EFF03 6CD367F9FED33C 252866E5D486E0 1BA866F4 F9E47FE0764B75 DF4764388D9975 69CB86E110DD94 BC921065392D76 13DEC0A0 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD").unwrap(),
            c: GroupOrderElement::from_string("FC3A0DC778C70B 307B5E69297040 7D2C9B5223FAB7 C95B27163873DF 2361F8F5").unwrap(),
            vr_prime_prime: GroupOrderElement::from_string("B009D6601604D9 2CC464DFBFBD0D 2CD0A782F3618 74742156EA34EE 7D1132A").unwrap(),
            witness_signature: witness_signature(),
            g_i: PointG1::from_string("false C32B36210779E2 79634A59496335 3A64D66D90849E E233C11F521683 241D27B2 D22279343E9D84 928365752F930B 6B3CEDB3E9CFFE 56CA632705FBC3 19E63F01 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD").unwrap(),
            i: 1,
            m2: GroupOrderElement::from_string("7D412BFCA6D402 79B043B875CBB3 701CAE80805BED 1F6D7DD6247DBE 99A79BA").unwrap()
        }
    }

    fn witness_signature() -> WitnessSignature {
        WitnessSignature {
            sigma_i: PointG2::from_string("false 773262BD1D451C 5A035B573DEE78 2706F804B8DC97 76A30C207CF165 1475F5FC B5B704805F6095 47F8DD533F46BC 88B64BEC891EF6 222A37DA413AD3 D102B5F 36DCDF2369ABC3 C9030D39852E5A 35F52211B216B9 6E66D7E02C3809 1C1F6C59 9B2F851D20F66C 9A3600B4B14BA6 7621E4C21370D9 7D1A6CC1F174A7 47AD6AA FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD 0 0 0 0 0").unwrap(),
            u_i: PointG2::from_string("false E9229D3DBE936 83210F4A805C4A 720FDB4CFF40DC 7CD3D3B5206332 D44D4E6 9E9C6ED9DD2643 486DBC7878498E 4B01C9632610E9 A9689488CFFE77 1263FD6B 2882F34A68691C 29D6DBCC76D4B C59186A66B6944 98955D0D9CD9B5 F95C ABD07A01CAF75D FAD6F38FD2C798 F838BEFD25D2A6 4CC8326B14FA64 23DBE9C1 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD 0 0 0 0 0").unwrap(),
            g_i: PointG1::from_string("false C32B36210779E2 79634A59496335 3A64D66D90849E E233C11F521683 241D27B2 D22279343E9D84 928365752F930B 6B3CEDB3E9CFFE 56CA632705FBC3 19E63F01 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45D").unwrap()
        }
    }

    pub fn witness() -> Witness {
        Witness {
            omega: PointG2::from_string("true 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0").unwrap()
        }
    }

    pub fn credential_revocation_public_key() -> CredentialRevocationPublicKey {
        CredentialRevocationPublicKey {
            g: PointG1::from_string("false 5ED330060DE62A B5635EA50A2AF2 86DBE3B2EDEF5 956A4D7F2DE503 EF0B349 3FDC81D4282639 1468DBAB568FD9 1FD2A1391ED3E6 1749FA913BFB8C 1D537326 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD").unwrap(),
            g_dash: PointG2::from_string("false 38F3AFB0F17335 EEF057D12268B3 659A296EA4A1D4 4F016B0D2C3030 187AC179 4CA7EECE9EB146 670EFD03C3D22F D34354F0BB54B9 89885DF546CD79 4016600 F11DF388B0B2DE 5EBC1F07BF3E37 53080E595B5BAB F16B77550089A3 17E7316F 3914F300DB8E84 5AB85D4BBFC7D2 151DBBF08BFA86 8C68A8C61E261F E716051 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD 0 0 0 0 0").unwrap(),
            h: PointG1::from_string("false BB89041E306914 8A2FEDBFA2CD0E C84C3EDACF9B80 2062C3B1EA745E 1C36126C E721A2ECFEF1A7 DEE6B93F765498 192DE1E88257F8 6BC8D9000B782F 187FFAB9 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD").unwrap(),
            h0: PointG1::from_string("false 2D6F0EBB7D1441 5E2187F2630FAA 8C135C939EE5AD 419B4C5B5EDBCF 64F9695 11DA3814D77E6 5F05365F81A159 95D99FA80A8190 4A0D6537F9229D 6E366E9 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD").unwrap(),
            h1: PointG1::from_string("false D1DD79EFBBAC5D C70E04BEE38597 16F472F78019DF 6837F829095AF7 EB9F33D 15103EF7C16DC 747D2C18545ACA 32FD78E0DC11B8 A745F6AAE19403 1237749 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD").unwrap(),
            h2: PointG1::from_string("false 277E0BBF4D587C 7ED8B177D384FB B58D80DAE74389 26CE1A006B28B9 15381B9A 71DDAC65E12597 29655676AA28A3 F4449D530EBF6E 4A9A264D7EA05F A69899 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD").unwrap(),
            htilde: PointG1::from_string("false 66CE9868A0929E 6098BBBF8CB757 65C4456D36CAF7 689AE54E6D8BA DB8F4DF 16BC36B449A76D 72FAACD8C172FC AB16A1CBDF108F 44D282407EB054 3D14B57 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD").unwrap(),
            h_cap: PointG2::from_string("false F6D6CCBA2FD449 C68807D6F070E7 E8474D326544F0 A59A8405786BA7 16061CCE EEEF23106B5A29 30E8583E66323B F9CADD7070886C B6469A5947538D 14A24A03 3956C3CF508864 299992E53315F0 4502380CCF4A1C 4F21BD4F4406A0 13561ADF 7CA2D971C35170 5EE97277C58C91 B2061AE5016E09 25B6C2FDEF39DD 516CB5 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD 0 0 0 0 0").unwrap(),
            u: PointG2::from_string("false F9216743F1C3B4 E346528F6E4897 3B2D4DAA67C4EE 901ED004C80912 236D9C20 932BBF9502697A 345AC20C6FD2E6 4E91C8947B0E35 8AC1995BA9D1F6 86C4061 50203A4B896AB4 DF9B8EDC5340E7 96D9D0D6E6D3DC DB350B1A3AFB2 238D524C 42F746BCDA9E22 E5E0FFE6D3691 23BDD9CCF42EC1 B228437BEC9CCD 529BD90 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD 0 0 0 0 0").unwrap(),
            pk: PointG1::from_string("false 7B1DFC93981AE2 4DFC66DD617330 212C832205F97F 8E29D62EE82E3E FDF46AC D22A8C023874A0 7897254F8FD253 C75AAE309A5E55 1061B44903E0DF 11DFFDD0 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD").unwrap(),
            y: PointG2::from_string("false F9C21E8F56F8AA F79C655141E885 64AB0A99284CE3 BEC93CE6477AD6 15777255 33F6CBB27B3F33 4182697F09D943 95072D1059E75 66334B94DD2D7 15002655 3B5310F5AE182E B781EB38CBF0A A2586A848A25F8 C26DDD06974A04 46A2610 2C7A6ADB45F8E3 6A8AF3A9C49FF1 BA7FDAEFEE8ECE 35527C32E1C04D 1E9F8C37 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD 0 0 0 0 ").unwrap()
        }
    }

    pub fn credential_revocation_private_key() -> CredentialRevocationPrivateKey {
        CredentialRevocationPrivateKey {
            x: GroupOrderElement::from_string("504B7B39C105BC 4B06CC402527EC C891DF2C2B1059 333780DAD6664D 6DB859D").unwrap(),
            sk: GroupOrderElement::from_string("95FA43CD5333FE BABC063E357207 CEA2883FDADF05 DC97DBEA63AD2B 1A18E5F").unwrap()
        }
    }

    pub fn revocation_key_public() -> RevocationKeyPublic {
        RevocationKeyPublic {
            z: Pair::from_string("49E6CDCE046D7F 60D6848FD1AFAD 2076B5D36ADD11 C38F12420AF725 12DDCE76 370DB10DD47CF1 8A1528453C66F7 458FA46B7FE118 8C41E9B102B68B C3287CA E74709E2E9E198 D750AA8430F9E3 A1D408166E8458 6CBC28DFC32F91 1664ED7A 92846CBC5F771D ADE9E6D2BF57A2 EC3E08394E542D 1C1AD590A9A629 C3AD26 7F86D194ACD43D 9266FEDE371495 DF90EC1D7525DB BCBF7D86421E7B F5E925 B52BD95B7AD3E1 17D06358C224FA C4486716F436FC 80DE8D76A1DF74 8C2626B 2936926FAAB290 A18E7D95BA2F6A F9244EB3B64CA7 68A90268081438 44A346B 2B88A83204C3FD 7BEC2D4652BEF8 7DF73626BDDE6C 8F8771F8A997F5 1DC36143 2F0DBE343AAD2A BD45D8FD11C852 B1488320F59BED B220B4B8853DF2 B48B3E7 295A3F40B7AC93 8C96EC1D04B613 EC41057656FCB7 276CB1788B4FB8 13314F47 DF7402767EFC5E B34564A40D8A4A C9D70040EF42A5 8D45661A68F562 154B4539 7A3EB27A635860 8E9D4225ADD19C DC162DED382985 D4FF4952908BCB D91D62").unwrap()
        }
    }

    pub fn revocation_key_private() -> RevocationKeyPrivate {
        RevocationKeyPrivate {
            gamma: GroupOrderElement::from_string("D4D1BE89FF86F1 C4FB0BB89C2020 54E635BFB957C1 B8F26C05CE9187 A9908").unwrap()
        }
    }

    fn accumulator() -> Accumulator {
        PointG2::from_string("false 96C651281E64C9 1F8D8A3ECE7383 652EDAFF365353 1D660D978AA97B 3BC3E1C BEE73306BFE21E C1462E5931B25F FF75C61B42F09A CBD6F61BDD2361 15A4D2C7 A0EB09A676662E A831C20AC60BD CE517BBEA3ED26 BD2C3DD4D6DA79 35D4B12 DA60940FA153EA 635458DF30A481 24052C1390DDFC 8DCC62B658F1C9 1CD52E8 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD 0 0 0 0 0").unwrap()
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
        RevocationRegistryDelta {
            prev_accum: Some(PointG2::from_string("true 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0").unwrap()),
            accum: accumulator(),
            issued: hashset![1],
            revoked: HashSet::new()
        }
    }

    pub fn r_cnxt_m2() -> BigNumber {
        BigNumber::from_dec("69500003785041890145270364348670634122591474903142468939711692725859480163330").unwrap()
    }
}
