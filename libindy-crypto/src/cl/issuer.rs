use bn::BigNumber;
use cl::*;
use errors::IndyCryptoError;
use pair::*;
use cl::constants::*;
use cl::helpers::*;

use std::collections::{HashMap, HashSet};

/// Trust source that provides credentials to prover.
pub struct Issuer {}

impl Issuer {
    /// Creates and returns claim schema entity builder.
    ///
    /// The purpose of claim schema builder is building of claim schema entity that
    /// represents claim schema attributes set.
    ///
    /// # Example
    /// ```
    /// use indy_crypto::cl::issuer::Issuer;
    /// let mut claim_schema_builder = Issuer::new_claim_schema_builder().unwrap();
    /// claim_schema_builder.add_attr("sex").unwrap();
    /// claim_schema_builder.add_attr("name").unwrap();
    /// let _claim_schema = claim_schema_builder.finalize().unwrap();
    /// ```
    pub fn new_claim_schema_builder() -> Result<ClaimSchemaBuilder, IndyCryptoError> {
        let res = ClaimSchemaBuilder::new()?;
        Ok(res)
    }

    /// Creates and returns issuer keys (public and private) entities.
    ///
    /// # Arguments
    /// * `claim_schema` - claim schema entity.
    /// * `non_revocation_part` - If true non revocation part of keys will be generated.
    ///
    /// # Example
    /// ```
    /// use indy_crypto::cl::issuer::Issuer;
    /// let mut claim_schema_builder = Issuer::new_claim_schema_builder().unwrap();
    /// claim_schema_builder.add_attr("sex").unwrap();
    /// claim_schema_builder.add_attr("name").unwrap();
    /// let claim_schema = claim_schema_builder.finalize().unwrap();
    /// let (_pub_key, _priv_key) = Issuer::new_keys(&claim_schema, true).unwrap();
    /// ```
    pub fn new_keys(claim_schema: &ClaimSchema, non_revocation_part: bool) -> Result<(IssuerPublicKey, IssuerPrivateKey), IndyCryptoError> {
        trace!("Issuer::new_keys: >>> claim_schema: {:?}, non_revocation_part: {:?}", claim_schema, non_revocation_part);

        let (p_pub_key, p_priv_key) = Issuer::_new_primary_keys(claim_schema)?;

        let (r_pub_key, r_priv_key) = if non_revocation_part {
            let (r_pub_key, r_priv_key) = Issuer::_new_revocation_keys()?;
            (Some(r_pub_key), Some(r_priv_key))
        } else {
            (None, None)
        };

        let issuer_pub_key = IssuerPublicKey { p_key: p_pub_key, r_key: r_pub_key };
        let issuer_priv_key = IssuerPrivateKey { p_key: p_priv_key, r_key: r_priv_key };
        trace!("Issuer::new_keys: <<< issuer_pub_key: {:?}, issuer_priv_key: {:?}", issuer_pub_key, issuer_priv_key);

        Ok((issuer_pub_key, issuer_priv_key))
    }

    /// Creates and returns revocation registries (public and private) entities.
    ///
    /// # Arguments
    /// * `issuer_pub_key` - Issuer pub key instance pointer.
    /// * `max_claim_num` - Max claim number in generated registry.
    ///
    /// # Example
    /// ```
    /// use indy_crypto::cl::issuer::Issuer;
    /// let mut claim_schema_builder = Issuer::new_claim_schema_builder().unwrap();
    /// claim_schema_builder.add_attr("sex").unwrap();
    /// claim_schema_builder.add_attr("name").unwrap();
    /// let claim_schema = claim_schema_builder.finalize().unwrap();
    /// let (pub_key, _priv_key) = Issuer::new_keys(&claim_schema, true).unwrap();
    /// let (_rev_reg_pub, _rev_reg_priv) = Issuer::new_revocation_registry(&pub_key, 100).unwrap();
    /// ```
    pub fn new_revocation_registry(issuer_pub_key: &IssuerPublicKey,
                                   max_claim_num: u32) -> Result<(RevocationRegistryPublic,
                                                                  RevocationRegistryPrivate), IndyCryptoError> {
        trace!("Issuer::new_revocation_registry: >>> issuer_pub_key: {:?}, max_claim_num: {:?}", issuer_pub_key, max_claim_num);

        let r_pub_key = issuer_pub_key.r_key
            .as_ref()
            .ok_or(IndyCryptoError::InvalidStructure(format!("No revocation part present in issuer key.")))?;

        let mut g: HashMap<u32, PointG1> = HashMap::new();
        let gamma = GroupOrderElement::new()?;
        let mut g_dash: HashMap<u32, PointG2> = HashMap::new();

        for i in 0..(2 * max_claim_num) {
            if i != max_claim_num + 1 {
                let i_bytes = transform_u32_to_array_of_u8(i);
                let mut pow = GroupOrderElement::from_bytes(&i_bytes)?;
                pow = gamma.pow_mod(&pow)?;
                g.insert(i, r_pub_key.g.mul(&pow)?);
                g_dash.insert(i, r_pub_key.g_dash.mul(&pow)?);
            }
        }

        let mut z = Pair::pair(&r_pub_key.g, &r_pub_key.g_dash)?;
        let mut pow = GroupOrderElement::from_bytes(&transform_u32_to_array_of_u8(max_claim_num + 1))?;
        pow = gamma.pow_mod(&pow)?;
        z = z.pow(&pow)?;
        let acc = PointG2::new_inf()?;
        let v: HashSet<u32> = HashSet::new();

        let rev_reg_pub = RevocationRegistryPublic {
            acc: RevocationAccumulator { acc, v, max_claim_num },
            key: RevocationAccumulatorPublicKey { z },
            tails: RevocationAccumulatorTails { tails: g, tails_dash: g_dash },

        };

        let rev_reg_priv = RevocationRegistryPrivate {
            key: RevocationAccumulatorPrivateKey { gamma },
        };

        trace!("Issuer::new_revocation_registry: <<< rev_reg_pub: {:?}, rev_reg_priv: {:?}", rev_reg_pub, rev_reg_priv);

        Ok((rev_reg_pub, rev_reg_priv))
    }

    /// Creates and returns claims values entity builder.
    ///
    /// The purpose of claim values builder is building of claim values entity that
    /// represents claim attributes values map.
    ///
    /// # Example
    /// ```
    /// use indy_crypto::cl::issuer::Issuer;
    /// let mut claim_values_builder = Issuer::new_claim_values_builder().unwrap();
    /// claim_values_builder.add_value("sex", "5944657099558967239210949258394887428692050081607692519917050011144233115103").unwrap();
    /// claim_values_builder.add_value("name", "1139481716457488690172217916278103335").unwrap();
    /// let _claim_values = claim_values_builder.finalize().unwrap();
    /// ```
    pub fn new_claim_values_builder() -> Result<ClaimValuesBuilder, IndyCryptoError> {
        let res = ClaimValuesBuilder::new()?;
        Ok(res)
    }

    /// Sign given claim values instance.
    ///
    /// # Arguments
    /// * `prover_id` - Prover identifier.
    /// * `blinded_ms` - Blinded master secret.
    /// * `claim_values` - Claim values to be signed.
    /// * `issuer_pub_key` - Issuer public key.
    /// * `issuer_priv_key` - Issuer private key.
    /// * `rev_idx` - (Optional) User index in revocation accumulator. Required for non-revocation claim_signature part generation.
    /// * `rev_reg_pub` - (Optional) Revocation registry public.
    /// * `rev_reg_priv` - (Optional) Revocation registry private.
    ///
    /// # Example
    /// ```
    /// use indy_crypto::cl::issuer::Issuer;
    /// use indy_crypto::cl::prover::Prover;
    /// let mut claim_schema_builder = Issuer::new_claim_schema_builder().unwrap();
    /// claim_schema_builder.add_attr("sex").unwrap();
    /// let claim_schema = claim_schema_builder.finalize().unwrap();
    ///
    /// let (pub_key, priv_key) = Issuer::new_keys(&claim_schema, false).unwrap();
    /// let master_secret = Prover::new_master_secret().unwrap();
    /// let (blinded_master_secret, _) = Prover::blind_master_secret(&pub_key, &master_secret).unwrap();
    ///
    /// let mut claim_values_builder = Issuer::new_claim_values_builder().unwrap();
    /// claim_values_builder.add_value("sex", "5944657099558967239210949258394887428692050081607692519917050011144233115103").unwrap();
    /// let claim_values = claim_values_builder.finalize().unwrap();
    ///
    /// let _claim_signature = Issuer::sign_claim("CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW",
    ///                                           &blinded_master_secret,
    ///                                           &claim_values,
    ///                                           &pub_key,
    ///                                           &priv_key,
    ///                                           None, None, None).unwrap();
    /// ```
    pub fn sign_claim(prover_id: &str,
                      blinded_ms: &BlindedMasterSecret,
                      claim_values: &ClaimValues,
                      issuer_pub_key: &IssuerPublicKey,
                      issuer_priv_key: &IssuerPrivateKey,
                      rev_idx: Option<u32>,
                      rev_reg_pub: Option<&mut RevocationRegistryPublic>,
                      rev_reg_priv: Option<&RevocationRegistryPrivate>) -> Result<ClaimSignature, IndyCryptoError> {
        trace!("Issuer::sign_claim: >>> prover_id: {:?}, blinded_ms: {:?}, claim_values: {:?}, issuer_pub_key: {:?}, issuer_priv_key: {:?}, rev_idx: {:?}, \
        rev_reg_pub: {:?}, rev_reg_priv: {:?}", prover_id, blinded_ms, claim_values, issuer_pub_key, issuer_priv_key, rev_idx, rev_reg_pub, rev_reg_priv);

        let claim_context = Issuer::_gen_claim_context(prover_id, rev_idx)?;

        let p_claim = Issuer::_new_primary_claim(&claim_context,
                                                 issuer_pub_key,
                                                 issuer_priv_key,
                                                 blinded_ms,
                                                 claim_values)?;

        let r_claim = if let (Some(rev_idx_2), Some(r_reg_pub), Some(r_reg_priv)) = (rev_idx, rev_reg_pub, rev_reg_priv) {
            Some(Issuer::_new_non_revocation_claim(rev_idx_2,
                                                   &claim_context,
                                                   blinded_ms,
                                                   issuer_pub_key,
                                                   issuer_priv_key,
                                                   r_reg_pub,
                                                   r_reg_priv)?)
        } else {
            None
        };

        let claim_signature = ClaimSignature { p_claim, r_claim };

        trace!("Issuer::sign_claim: <<< claim_signature: {:?}", claim_signature);

        Ok(claim_signature)
    }

    /// Revokes a claim by a revoc_id in a given revoc-registry
    ///
    /// # Arguments
    /// * `rev_reg_pub` - Reference that contain revocation registry instance pointer.
    ///  * rev_idx` - index of the user in the accumulator
    ///
    /// # Example
    /// ```
    /// use indy_crypto::cl::issuer::Issuer;
    /// use indy_crypto::cl::prover::Prover;
    /// let mut claim_schema_builder = Issuer::new_claim_schema_builder().unwrap();
    /// claim_schema_builder.add_attr("sex").unwrap();
    /// let claim_schema = claim_schema_builder.finalize().unwrap();
    ///
    /// let (pub_key, priv_key) = Issuer::new_keys(&claim_schema, true).unwrap();
    /// let (mut rev_reg_pub, rev_reg_priv) = Issuer::new_revocation_registry(&pub_key, 1).unwrap();
    /// let master_secret = Prover::new_master_secret().unwrap();
    /// let (blinded_master_secret, _) = Prover::blind_master_secret(&pub_key, &master_secret).unwrap();
    ///
    /// let mut claim_values_builder = Issuer::new_claim_values_builder().unwrap();
    /// claim_values_builder.add_value("sex", "5944657099558967239210949258394887428692050081607692519917050011144233115103").unwrap();
    /// let claim_values = claim_values_builder.finalize().unwrap();
    ///
    /// let _claim_signature = Issuer::sign_claim("CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW",
    ///                                           &blinded_master_secret,
    ///                                           &claim_values,
    ///                                           &pub_key,
    ///                                           &priv_key,
    ///                                           Some(1), Some(&mut rev_reg_pub), Some(&rev_reg_priv)).unwrap();
    /// Issuer::revoke_claim(&mut rev_reg_pub, 1).unwrap();
    /// ```
    pub fn revoke_claim(rev_reg_pub: &mut RevocationRegistryPublic,
                        rev_idx: u32) -> Result<(), IndyCryptoError> {
        trace!("Issuer::revoke_claim: >>> rev_reg_pub: {:?}, rev_idx: {:?}", rev_reg_pub, rev_idx);

        if !rev_reg_pub.acc.v.remove(&rev_idx) {
            return Err(IndyCryptoError::AnoncredsInvalidRevocationAccumulatorIndex(
                format!("User index:{} not found in Accumulator", rev_idx))
            );
        }

        let index: u32 = rev_reg_pub.acc.max_claim_num + 1 - rev_idx;

        let element = rev_reg_pub.tails.tails_dash
            .get(&index)
            .ok_or(IndyCryptoError::InvalidStructure(format!("Value by key '{}' not found in g", index)))?;

        rev_reg_pub.acc.acc = rev_reg_pub.acc.acc.sub(element)?;

        trace!("Issuer::revoke_claim: <<<");

        Ok(())
    }

    fn _new_primary_keys(claim_schema: &ClaimSchema) -> Result<(IssuerPrimaryPublicKey,
                                                                IssuerPrimaryPrivateKey), IndyCryptoError> {
        trace!("Issuer::_new_primary_keys: >>> claim_schema: {:?}", claim_schema);

        let mut ctx = BigNumber::new_context()?;

        if claim_schema.attrs.len() == 0 {
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
        let mut r: HashMap<String, BigNumber> = HashMap::new();

        for attribute in &claim_schema.attrs {
            r.insert(attribute.to_owned(), s.mod_exp(&gen_x(&p, &q)?, &n, Some(&mut ctx))?);
        }

        let z = s.mod_exp(&xz, &n, Some(&mut ctx))?;

        let rms = s.mod_exp(&gen_x(&p, &q)?, &n, Some(&mut ctx))?;
        let rctxt = s.mod_exp(&gen_x(&p, &q)?, &n, Some(&mut ctx))?;

        let issuer_pr_pub_key = IssuerPrimaryPublicKey { n, s, rms, r, rctxt, z };
        let issuer_pr_priv_key = IssuerPrimaryPrivateKey { p, q };

        trace!("Issuer::_new_primary_keys: <<< issuer_pr_pub_key: {:?}, issuer_pr_priv_key: {:?}", issuer_pr_pub_key, issuer_pr_priv_key);

        Ok((issuer_pr_pub_key, issuer_pr_priv_key))
    }

    fn _new_revocation_keys() -> Result<(IssuerRevocationPublicKey,
                                         IssuerRevocationPrivateKey), IndyCryptoError> {
        trace!("Issuer::_new_revocation_keys: >>>");

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

        let issuer_rev_pub_key = IssuerRevocationPublicKey { g, g_dash, h, h0, h1, h2, htilde, h_cap, u, pk, y };
        let issuer_rev_priv_key = IssuerRevocationPrivateKey { x, sk };

        trace!("Issuer::_new_revocation_keys: <<< issuer_rev_pub_key: {:?}, issuer_rev_priv_key: {:?}", issuer_rev_pub_key, issuer_rev_priv_key);

        Ok((issuer_rev_pub_key, issuer_rev_priv_key))
    }

    fn _gen_claim_context(prover_id: &str, rev_idx: Option<u32>) -> Result<BigNumber, IndyCryptoError> {
        trace!("Issuer::_calc_m2: >>> prover_id: {:?}, rev_idx: {:?}", prover_id, rev_idx);

        let rev_idx = rev_idx.map(|i| i as i32).unwrap_or(-1);

        let prover_id_bn = encode_attribute(prover_id, ByteOrder::Little)?;
        let rev_idx_bn = encode_attribute(&rev_idx.to_string(), ByteOrder::Little)?;

        let mut s = vec![
            bitwise_or_big_int(&rev_idx_bn, &prover_id_bn)?.to_bytes()?
        ];

        /* TODO: FIXME: use const!!! */
        let pow_2 = BigNumber::from_u32(2)?.exp(&BigNumber::from_u32(LARGE_MASTER_SECRET)?, None)?;
        let claim_context = get_hash_as_int(&mut s)?.modulus(&pow_2, None)?;

        trace!("Issuer::_gen_claim_context: <<< claim_context: {:?}", claim_context);

        Ok(claim_context)
    }

    fn _new_primary_claim(claim_context: &BigNumber,
                          issuer_pub_key: &IssuerPublicKey,
                          issuer_priv_key: &IssuerPrivateKey,
                          blnd_ms: &BlindedMasterSecret,
                          claim_values: &ClaimValues) -> Result<PrimaryClaimSignature, IndyCryptoError> {
        trace!("Issuer::_new_primary_claim: >>> claim_context: {:?}, issuer_pub_key: {:?}, issuer_priv_key: {:?}, blnd_ms: {:?}, claim_values: {:?}",
               claim_context, issuer_pub_key, issuer_priv_key, blnd_ms, claim_values);

        let v = generate_v_prime_prime()?;

        let e_start = BigNumber::from_u32(2)?.exp(&BigNumber::from_u32(LARGE_E_START)?, None)?;
        let e_end = BigNumber::from_u32(2)?
            .exp(&BigNumber::from_u32(LARGE_E_END_RANGE)?, None)?
            .add(&e_start)?;

        let e = generate_prime_in_range(&e_start, &e_end)?;
        let a = Issuer::_sign_primary_claim(issuer_pub_key, issuer_priv_key, &claim_context, &claim_values, &v, blnd_ms, &e)?;

        let pr_claim_signature = PrimaryClaimSignature { m_2: claim_context.clone()?, a, e, v };

        trace!("Issuer::_new_primary_claim: <<< pr_claim_signature: {:?}", pr_claim_signature);

        Ok(pr_claim_signature)
    }

    fn _sign_primary_claim(p_pub_key: &IssuerPublicKey,
                           p_priv_key: &IssuerPrivateKey,
                           claim_context: &BigNumber,
                           claim_values: &ClaimValues,
                           v: &BigNumber,
                           blnd_ms: &BlindedMasterSecret,
                           e: &BigNumber) -> Result<BigNumber, IndyCryptoError> {
        trace!("Issuer::_sign_primary_claim: >>> p_pub_key: {:?}, p_priv_key: {:?}, claim_context: {:?}, claim_values: {:?}, v: {:?}, blnd_ms: {:?}, e: {:?}",
               p_pub_key, p_priv_key, claim_context, claim_values, v, blnd_ms, e);

        let p_pub_key = &p_pub_key.p_key;
        let p_priv_key = &p_priv_key.p_key;

        let mut context = BigNumber::new_context()?;
        let mut rx = BigNumber::from_u32(1)?;

        for (key, value) in &claim_values.attrs_values {
            let pk_r = p_pub_key.r
                .get(key)
                .ok_or(IndyCryptoError::InvalidStructure(format!("Value by key '{}' not found in pk.r", key)))?;

            rx = rx.mul(
                &pk_r.mod_exp(&value, &p_pub_key.n, Some(&mut context))?,
                Some(&mut context)
            )?;
        }

        rx = p_pub_key.rctxt.mod_exp(&claim_context, &p_pub_key.n, Some(&mut context))?
            .mul(&rx, Some(&mut context))?;

        if blnd_ms.u != BigNumber::from_u32(0)? {
            rx = blnd_ms.u.modulus(&p_pub_key.n, Some(&mut context))?
                .mul(&rx, Some(&mut context))?;
        }

        let n = p_priv_key.p.mul(&p_priv_key.q, Some(&mut context))?;
        let mut e_inverse = e.modulus(&n, Some(&mut context))?;

        let mut a = p_pub_key.s
            .mod_exp(&v, &p_pub_key.n, Some(&mut context))?
            .mul(&rx, Some(&mut context))?;
        a = p_pub_key.z.mod_div(&a, &p_pub_key.n)?;

        e_inverse = e_inverse.inverse(&n, Some(&mut context))?;
        a = a.mod_exp(&e_inverse, &p_pub_key.n, Some(&mut context))?;

        trace!("Issuer::_sign_primary_claim: <<< a: {:?}", a);

        Ok(a)
    }

    fn _new_non_revocation_claim(rev_idx: u32,
                                 claim_context: &BigNumber,
                                 blnd_ms: &BlindedMasterSecret,
                                 issuer_pub_key: &IssuerPublicKey,
                                 issuer_priv_key: &IssuerPrivateKey,
                                 rev_reg_pub: &mut RevocationRegistryPublic,
                                 rev_reg_priv: &RevocationRegistryPrivate) -> Result<NonRevocationClaimSignature, IndyCryptoError> {
        trace!("Issuer::_new_non_revocation_claim: >>> rev_idx: {:?}, claim_context: {:?}, blnd_ms: {:?}, issuer_pub_key: {:?}, issuer_priv_key: {:?}, rev_reg_pub: {:?}, rev_reg_priv: {:?}",
               rev_idx, claim_context, blnd_ms, issuer_pub_key, issuer_priv_key, rev_reg_pub, rev_reg_priv);

        let ur = blnd_ms.ur
            .ok_or(IndyCryptoError::InvalidStructure(format!("No revocation part present in blinded master secred.")))?;

        let r_pub_key = issuer_pub_key.r_key
            .as_ref()
            .ok_or(IndyCryptoError::InvalidStructure(format!("No revocation part present in issuer public key.")))?;

        let r_priv_key = issuer_priv_key.r_key
            .as_ref()
            .ok_or(IndyCryptoError::InvalidStructure(format!("No revocation part present in issuer private key.")))?;

        let r_acc: &mut RevocationAccumulator = &mut rev_reg_pub.acc;
        let r_acc_tails: &mut RevocationAccumulatorTails = &mut rev_reg_pub.tails;
        let r_acc_priv_key: &RevocationAccumulatorPrivateKey = &rev_reg_priv.key;

        if r_acc.is_full() {
            return Err(IndyCryptoError::AnoncredsRevocationAccumulatorIsFull(format!("Revocation accumulator is full.")));
        }

        if r_acc.is_idx_used(rev_idx) {
            return Err(IndyCryptoError::AnoncredsRevocationAccumulatorIsFull(format!("Revocation index is already used."))); //TODO Is it correct error?
        }

        let i = rev_idx;

        let vr_prime_prime = GroupOrderElement::new()?;
        let c = GroupOrderElement::new()?;
        let m2 = GroupOrderElement::from_bytes(&claim_context.to_bytes()?)?;

        let g_i = r_acc_tails.tails
            .get(&i)
            .ok_or(IndyCryptoError::InvalidStructure(format!("Value by key '{}' not found in tails.g", i)))?;

        let sigma =
            r_pub_key.h0.add(&r_pub_key.h1.mul(&m2)?)?
                .add(&ur)?
                .add(g_i)?
                .add(&r_pub_key.h2.mul(&vr_prime_prime)?)?
                .mul(&r_priv_key.x.add_mod(&c)?.inverse()?)?;

        let mut omega = PointG2::new_inf()?;

        for j in &r_acc.v {
            let index = r_acc.max_claim_num + 1 - j + i;
            omega = omega.add(r_acc_tails.tails_dash
                .get(&index)
                .ok_or(IndyCryptoError::InvalidStructure(format!("Value by key '{}' not found in g", index)))?)?;
        }

        let sigma_i = r_pub_key.g_dash
            .mul(&r_priv_key.sk
                .add_mod(&r_acc_priv_key.gamma
                    .pow_mod(&GroupOrderElement::from_bytes(&transform_u32_to_array_of_u8(i as u32))?)?)?
                .inverse()?)?;
        let u_i = r_pub_key.u
            .mul(&r_acc_priv_key.gamma
                .pow_mod(&GroupOrderElement::from_bytes(&transform_u32_to_array_of_u8(i as u32))?)?)?;

        let index = r_acc.max_claim_num + 1 - i;

        r_acc.acc = r_acc.acc
            .add(r_acc_tails.tails_dash
                .get(&index)
                .ok_or(IndyCryptoError::InvalidStructure(format!("Value by key '{}' not found in g", index)))?)?;

        r_acc.v.insert(i);

        let witness = Witness {
            sigma_i,
            u_i,
            g_i: g_i.clone(),
            omega,
            v: r_acc.v.clone()
        };

        let non_revocation_claim_sig = NonRevocationClaimSignature { sigma, c, vr_prime_prime, witness, g_i: g_i.clone(), i, m2 };

        trace!("Issuer::_new_non_revocation_claim: <<< non_revocation_claim_sig: {:?}", non_revocation_claim_sig);

        Ok(non_revocation_claim_sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cl::issuer::{Issuer, mocks};
    use cl::prover::Prover;
    use cl::helpers::MockHelper;

    #[test]
    fn generate_context_attribute_works() {
        let rev_idx = 110;
        let user_id = "111";
        let answer = BigNumber::from_dec("59059690488564137142247698318091397258460906844819605876079330034815387295451").unwrap();
        let result = Issuer::_gen_claim_context(user_id, Some(rev_idx)).unwrap();
        assert_eq!(result, answer);
    }

    #[test]
    fn claim_schema_builder_works() {
        let mut claim_schema_builder = Issuer::new_claim_schema_builder().unwrap();
        claim_schema_builder.add_attr("sex").unwrap();
        claim_schema_builder.add_attr("name").unwrap();
        claim_schema_builder.add_attr("age").unwrap();
        let claim_schema = claim_schema_builder.finalize().unwrap();

        assert!(claim_schema.attrs.contains("sex"));
        assert!(claim_schema.attrs.contains("name"));
        assert!(claim_schema.attrs.contains("age"));
        assert!(!claim_schema.attrs.contains("height"));
    }

    #[test]
    fn claim_values_builder_works() {
        let mut claim_values_builder = Issuer::new_claim_values_builder().unwrap();
        claim_values_builder.add_value("sex", "89057765651800459030103911598694169835931320404459570102253965466045532669865684092518362135930940112502263498496335250135601124519172068317163741086983519494043168252186111551835366571584950296764626458785776311514968350600732183408950813066589742888246925358509482561838243805468775416479523402043160919428168650069477488093758569936116799246881809224343325540306266957664475026390533069487455816053169001876208052109360113102565642529699056163373190930839656498261278601357214695582219007449398650197048218304260447909283768896882743373383452996855450316360259637079070460616248922547314789644935074980711243164129").unwrap();
        claim_values_builder.add_value("name", "58606710922154038918005745652863947546479611221487923871520854046018234465128105585608812090213473225037875788462225679336791123783441657062831589984290779844020407065450830035885267846722229953206567087435754612694085258455822926492275621650532276267042885213400704012011608869094703483233081911010530256094461587809601298503874283124334225428746479707531278882536314925285434699376158578239556590141035593717362562548075653598376080466948478266094753818404986494459240364648986755479857098110402626477624280802323635285059064580583239726433768663879431610261724430965980430886959304486699145098822052003020688956471").unwrap();
        let claim_values = claim_values_builder.finalize().unwrap();

        assert!(claim_values.attrs_values.get("sex").unwrap().eq(&BigNumber::from_dec("89057765651800459030103911598694169835931320404459570102253965466045532669865684092518362135930940112502263498496335250135601124519172068317163741086983519494043168252186111551835366571584950296764626458785776311514968350600732183408950813066589742888246925358509482561838243805468775416479523402043160919428168650069477488093758569936116799246881809224343325540306266957664475026390533069487455816053169001876208052109360113102565642529699056163373190930839656498261278601357214695582219007449398650197048218304260447909283768896882743373383452996855450316360259637079070460616248922547314789644935074980711243164129").unwrap()));
        assert!(claim_values.attrs_values.get("name").unwrap().eq(&BigNumber::from_dec("58606710922154038918005745652863947546479611221487923871520854046018234465128105585608812090213473225037875788462225679336791123783441657062831589984290779844020407065450830035885267846722229953206567087435754612694085258455822926492275621650532276267042885213400704012011608869094703483233081911010530256094461587809601298503874283124334225428746479707531278882536314925285434699376158578239556590141035593717362562548075653598376080466948478266094753818404986494459240364648986755479857098110402626477624280802323635285059064580583239726433768663879431610261724430965980430886959304486699145098822052003020688956471").unwrap()));
        assert!(claim_values.attrs_values.get("age").is_none());
    }

    #[test]
    fn issuer_new_keys_works() {
        MockHelper::inject();

        let (pub_key, priv_key) = Issuer::new_keys(&mocks::claim_schema(), true).unwrap();
        assert_eq!(pub_key.p_key, mocks::issuer_primary_public_key());
        assert_eq!(priv_key.p_key, mocks::issuer_primary_private_key());
        assert!(pub_key.r_key.is_some());
        assert!(priv_key.r_key.is_some());
    }

    #[test]
    fn issuer_new_keys_works_without_revocation_part() {
        MockHelper::inject();

        let (pub_key, priv_key) = Issuer::new_keys(&mocks::claim_schema(), false).unwrap();
        assert_eq!(pub_key.p_key, mocks::issuer_primary_public_key());
        assert_eq!(priv_key.p_key, mocks::issuer_primary_private_key());
        assert!(pub_key.r_key.is_none());
        assert!(priv_key.r_key.is_none());
    }

    #[test]
    fn issuer_new_keys_works_for_empty_attributes() {
        let claim_attrs = ClaimSchema { attrs: HashSet::new() };
        let res = Issuer::new_keys(&claim_attrs, false);
        assert!(res.is_err())
    }

    #[test]
    fn issuer_new_revocation_registry_works() {
        MockHelper::inject();

        let (pub_key, _) = Issuer::new_keys(&mocks::claim_schema(), true).unwrap();
        let (_, _) = Issuer::new_revocation_registry(&pub_key, 100).unwrap();
    }

    #[test]
    fn sign_primary_claim_works() {
        MockHelper::inject();

        let (pub_key, secret_key) = (mocks::issuer_public_key(), mocks::issuer_private_key());
        let context_attribute = BigNumber::from_dec("59059690488564137142247698318091397258460906844819605876079330034815387295451").unwrap();

        let mut claim_values_builder = Issuer::new_claim_values_builder().unwrap();
        claim_values_builder.add_value("name", "1139481716457488690172217916278103335").unwrap();
        claim_values_builder.add_value("age", "28").unwrap();
        claim_values_builder.add_value("sex", "5944657099558967239210949258394887428692050081607692519917050011144233115103").unwrap();
        claim_values_builder.add_value("height", "175").unwrap();
        let claim_values = claim_values_builder.finalize().unwrap();

        let v = BigNumber::from_dec("5237513942984418438429595379849430501110274945835879531523435677101657022026899212054747703201026332785243221088006425007944260107143086435227014329174143861116260506019310628220538205630726081406862023584806749693647480787838708606386447727482772997839699379017499630402117304253212246286800412454159444495341428975660445641214047184934669036997173182682771745932646179140449435510447104436243207291913322964918630514148730337977117021619857409406144166574010735577540583316493841348453073326447018376163876048624924380855323953529434806898415857681702157369526801730845990252958130662749564283838280707026676243727830151176995470125042111348846500489265328810592848939081739036589553697928683006514398844827534478669492201064874941684905413964973517155382540340695991536826170371552446768460042588981089470261358687308").unwrap();

        let u = BigNumber::from_dec("72637991796589957272144423539998982864769854130438387485781642285237707120228376409769221961371420625002149758076600738245408098270501483395353213773728601101770725294535792756351646443825391806535296461087756781710547778467803194521965309091287301376623972321639262276779134586366620773325502044026364814032821517244814909708610356590687571152567177116075706850536899272749781370266769562695357044719529245223811232258752001942940813585440938291877640445002571323841625932424781535818087233087621479695522263178206089952437764196471098717335358765920438275944490561172307673744212256272352897964947435086824617146019").unwrap();
        let e = BigNumber::from_dec("259344723055062059907025491480697571938277889515152306249728583105665800713306759149981690559193987143012367913206299323899696942213235956742930214202955935602153431795703076242907").unwrap();
        let result = BigNumber::from_dec("28748151213526235356806559302394713234708919908503693283861771311017778909029307989059154007823711057388221409308121224597301914007508580498985253922086489241065285193059997346332076248684330624957067344016446755572964815456056930278425883796750731908534333384959509746585564275501093362841366335955561237226624645170675067095743367895186059835073250297480315430811087601896371266213408739927940580173817412189118678276094925364341985978659550229327835510932814819830163166484857629278032552734675432915303389204079219287453130354714417551011163735621955266079226631695289893390164242695387374962452897413162593627569").unwrap();

        assert_eq!(result, Issuer::_sign_primary_claim(&pub_key, &secret_key, &context_attribute, &claim_values, &v, &BlindedMasterSecret { u: u, ur: None }, &e).unwrap());
    }

    #[test]
    fn sign_claim_works() {
        MockHelper::inject();

        let (pub_key, priv_key) = Issuer::new_keys(&mocks::claim_schema(), false).unwrap();
        let master_secret = Prover::new_master_secret().unwrap();
        let (blinded_master_secret, _) =
            Prover::blind_master_secret(&pub_key, &master_secret).unwrap();

        let claim_signature = Issuer::sign_claim("CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW",
                                                 &blinded_master_secret,
                                                 &mocks::claim_values(),
                                                 &pub_key,
                                                 &priv_key,
                                                 Some(1), None, None).unwrap();

        assert_eq!(mocks::primary_claim(), claim_signature.p_claim);
    }
}

pub mod mocks {
    use cl::*;

    pub fn issuer_public_key() -> IssuerPublicKey {
        IssuerPublicKey {
            p_key: issuer_primary_public_key(),
            r_key: Some(revocation_pub_key())
        }
    }

    pub fn issuer_private_key() -> IssuerPrivateKey {
        IssuerPrivateKey {
            p_key: issuer_primary_private_key(),
            r_key: Some(revocation_private_key())
        }
    }

    pub fn issuer_primary_public_key() -> IssuerPrimaryPublicKey {
        let n = BigNumber::from_dec("89057765651800459030103911598694169835931320404459570102253965466045532669865684092518362135930940112502263498496335250135601124519172068317163741086983519494043168252186111551835366571584950296764626458785776311514968350600732183408950813066589742888246925358509482561838243805468775416479523402043160919428168650069477488093758569936116799246881809224343325540306266957664475026390533069487455816053169001876208052109360113102565642529699056163373190930839656498261278601357214695582219007449398650197048218304260447909283768896882743373383452996855450316360259637079070460616248922547314789644935074980711243164129").unwrap();
        let s = BigNumber::from_dec("64684820421150545443421261645532741305438158267230326415141505826951816460650437611148133267480407958360035501128469885271549378871140475869904030424615175830170939416512594291641188403335834762737251794282186335118831803135149622404791467775422384378569231649224208728902565541796896860352464500717052768431523703881746487372385032277847026560711719065512366600220045978358915680277126661923892187090579302197390903902744925313826817940566429968987709582805451008234648959429651259809188953915675063700676546393568304468609062443048457324721450190021552656280473128156273976008799243162970386898307404395608179975243").unwrap();
        let rms = BigNumber::from_dec("58606710922154038918005745652863947546479611221487923871520854046018234465128105585608812090213473225037875788462225679336791123783441657062831589984290779844020407065450830035885267846722229953206567087435754612694085258455822926492275621650532276267042885213400704012011608869094703483233081911010530256094461587809601298503874283124334225428746479707531278882536314925285434699376158578239556590141035593717362562548075653598376080466948478266094753818404986494459240364648986755479857098110402626477624280802323635285059064580583239726433768663879431610261724430965980430886959304486699145098822052003020688956471").unwrap();

        let mut r: HashMap<String, BigNumber> = HashMap::new();
        r.insert("sex".to_string(), BigNumber::from_dec("58606710922154038918005745652863947546479611221487923871520854046018234465128105585608812090213473225037875788462225679336791123783441657062831589984290779844020407065450830035885267846722229953206567087435754612694085258455822926492275621650532276267042885213400704012011608869094703483233081911010530256094461587809601298503874283124334225428746479707531278882536314925285434699376158578239556590141035593717362562548075653598376080466948478266094753818404986494459240364648986755479857098110402626477624280802323635285059064580583239726433768663879431610261724430965980430886959304486699145098822052003020688956471").unwrap());
        r.insert("name".to_string(), BigNumber::from_dec("58606710922154038918005745652863947546479611221487923871520854046018234465128105585608812090213473225037875788462225679336791123783441657062831589984290779844020407065450830035885267846722229953206567087435754612694085258455822926492275621650532276267042885213400704012011608869094703483233081911010530256094461587809601298503874283124334225428746479707531278882536314925285434699376158578239556590141035593717362562548075653598376080466948478266094753818404986494459240364648986755479857098110402626477624280802323635285059064580583239726433768663879431610261724430965980430886959304486699145098822052003020688956471").unwrap());
        r.insert("age".to_string(), BigNumber::from_dec("58606710922154038918005745652863947546479611221487923871520854046018234465128105585608812090213473225037875788462225679336791123783441657062831589984290779844020407065450830035885267846722229953206567087435754612694085258455822926492275621650532276267042885213400704012011608869094703483233081911010530256094461587809601298503874283124334225428746479707531278882536314925285434699376158578239556590141035593717362562548075653598376080466948478266094753818404986494459240364648986755479857098110402626477624280802323635285059064580583239726433768663879431610261724430965980430886959304486699145098822052003020688956471").unwrap());
        r.insert("height".to_string(), BigNumber::from_dec("58606710922154038918005745652863947546479611221487923871520854046018234465128105585608812090213473225037875788462225679336791123783441657062831589984290779844020407065450830035885267846722229953206567087435754612694085258455822926492275621650532276267042885213400704012011608869094703483233081911010530256094461587809601298503874283124334225428746479707531278882536314925285434699376158578239556590141035593717362562548075653598376080466948478266094753818404986494459240364648986755479857098110402626477624280802323635285059064580583239726433768663879431610261724430965980430886959304486699145098822052003020688956471").unwrap());

        let rctxt = BigNumber::from_dec("58606710922154038918005745652863947546479611221487923871520854046018234465128105585608812090213473225037875788462225679336791123783441657062831589984290779844020407065450830035885267846722229953206567087435754612694085258455822926492275621650532276267042885213400704012011608869094703483233081911010530256094461587809601298503874283124334225428746479707531278882536314925285434699376158578239556590141035593717362562548075653598376080466948478266094753818404986494459240364648986755479857098110402626477624280802323635285059064580583239726433768663879431610261724430965980430886959304486699145098822052003020688956471").unwrap();
        let z = BigNumber::from_dec("58606710922154038918005745652863947546479611221487923871520854046018234465128105585608812090213473225037875788462225679336791123783441657062831589984290779844020407065450830035885267846722229953206567087435754612694085258455822926492275621650532276267042885213400704012011608869094703483233081911010530256094461587809601298503874283124334225428746479707531278882536314925285434699376158578239556590141035593717362562548075653598376080466948478266094753818404986494459240364648986755479857098110402626477624280802323635285059064580583239726433768663879431610261724430965980430886959304486699145098822052003020688956471").unwrap();

        IssuerPrimaryPublicKey { n, s, rms, r, rctxt, z }
    }

    pub fn issuer_primary_private_key() -> IssuerPrimaryPrivateKey {
        let p = BigNumber::from_dec("149212738775716179659508649034140914067267873385650452563221860367878267143635191771233591587868730221903476199105022913859057555905442876114559838735355652672950963033972314646471235775711934244481758977047119803475879470383993713606231800156950590334088086141997103196482505556481059579729337361392854778311").unwrap();
        let q = BigNumber::from_dec("149212738775716179659508649034140914067267873385650452563221860367878267143635191771233591587868730221903476199105022913859057555905442876114559838735355652672950963033972314646471235775711934244481758977047119803475879470383993713606231800156950590334088086141997103196482505556481059579729337361392854778311").unwrap();

        IssuerPrimaryPrivateKey { p, q }
    }

    pub fn claim_schema() -> ClaimSchema {
        let mut claim_schema_builder = ClaimSchemaBuilder::new().unwrap();
        claim_schema_builder.add_attr("name").unwrap();
        claim_schema_builder.add_attr("age").unwrap();
        claim_schema_builder.add_attr("height").unwrap();
        claim_schema_builder.add_attr("sex").unwrap();
        claim_schema_builder.finalize().unwrap()
    }

    pub fn claim_values() -> ClaimValues {
        let mut claim_values_builder = ClaimValuesBuilder::new().unwrap();
        claim_values_builder.add_value("name", "1139481716457488690172217916278103335").unwrap();
        claim_values_builder.add_value("age", "28").unwrap();
        claim_values_builder.add_value("sex", "5944657099558967239210949258394887428692050081607692519917050011144233115103").unwrap();
        claim_values_builder.add_value("height", "175").unwrap();
        claim_values_builder.finalize().unwrap()
    }

    pub fn claim() -> ClaimSignature {
        ClaimSignature {
            p_claim: primary_claim(),
            r_claim: Some(revocation_claim())
        }
    }

    pub fn primary_claim() -> PrimaryClaimSignature {
        PrimaryClaimSignature {
            m_2: BigNumber::from_dec("94880167908247457149699082277807545911629132893821703817366687134445318249228").unwrap(),
            a: BigNumber::from_dec("49132363239670159787093110938226673449134304271682974269447432344742116194321299671237726890946751467604148940160960878389315018748968369324920041829812940290495892617484508167397279335797727252561964527234608788562556758908905751101202717778202353145195614091112566435036522962919148975492906117295892318112254557428194748194500923814804029097083178321689709119206691962548916694618289798605008896501236499585406286135857829085917853488040591522806635137841948126557076578432458560145981983607545219636425132731496278118460851115172092828609386003425340146394948070616734134255308348098680856366416432858457119085389").unwrap(),
            e: BigNumber::from_dec("259344723055062059907025491480697571938277889515152306249728583105665800713306759149981690559193987143012367913206299323899696942213235956742930201588264091397308910346117473868881").unwrap(),
            v: BigNumber::from_dec("6620937836014079781509458870800001917950459774302786434315639456568768602266735503527631640833663968617512880802104566048179854406925811731340920442625764155409951969854303612644125623549271204625894424804352003689903192473464433927658013251120302922648839652919662117216521257876025436906282750361355336367533874548955283776610021309110505377492806210342214471251451681722267655419075635703240258044336607001296052867746675049720589092355650996711033859489737240617860392914314205277920274997312351322125481593636904917159990500837822414761512231315313922792934655437808723096823124948039695324591344458785345326611693414625458359651738188933757751726392220092781991665483583988703321457480411992304516676385323318285847376271589157730040526123521479652961899368891914982347831632139045838008837541334927738208491424027").unwrap()
        }
    }

    pub fn revocation_claim() -> NonRevocationClaimSignature {
        NonRevocationClaimSignature {
            sigma: PointG1::from_string("false C8C7213101C60F F625A22E65736C 695A1F398B4787 D087ABB966C5BC 1EA63E37 7895832C96B02C 60C7E086DFA7AF 1518CD71A957F3 C1BED176429FB9 11DD23B3 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD").unwrap(),
            c: GroupOrderElement::from_string("4CF57E7A173E6 27720818863F49 D72801BCE5CBE9 7C8C588E2A8B3B 3642B08").unwrap(),
            vr_prime_prime: GroupOrderElement::from_string("2BC52B6D8B5F4B 26E57208D0DB35 D0411E4BE49639 18A8BC10BF946E 1F8689A5").unwrap(),
            witness: witness(),
            g_i: PointG1::from_string("false 1A5D92950F9D1C 82DB5D4BF49AB8 FBFF5E631AD221 9B89F534C2AC04 165F1606 2E5EE0ECDBB554 F4C238315ACC2 57CAA2D6085FA6 CCE1970A4628E9 119D86E1 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD").unwrap(),
            i: 1,
            m2: GroupOrderElement::from_string("7219C82BC1A5C5 2E958256CDE0D B6FBB94E62AC37 4DAA41B3F577 74DDF3F3").unwrap()
        }
    }

    fn witness() -> Witness {
        let mut v: HashSet<u32> = HashSet::new();
        v.insert(1);

        Witness {
            sigma_i: PointG2::from_string("false D75D129A90AC7C E980CE49738692 E81F6656B7EC8B 5CB508713E5514 1C8D263D 277F296ED2870 DD07D7557B996C 3E3A4CBE72B433 CE6A5B3F49DCF0 12760A8D 794C7329844D36 5F061EF8268D0B 6931F242E445A2 941EE07805B105 112CCA EA8F2154379FFC E347F4C23152D6 81B0FD797DECC 99649EAE531C52 306F627 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD 0 0 0 0 0").unwrap(),
            u_i: PointG2::from_string("false 5BDC53BAF81A3F 161769B604A474 B7D29413291CFF 339D755F2188BC 33CD0CE D67B914F2755B3 9753565047A4C7 A431380FD96DC BDC9CF432D6969 167143C2 E8C107037A2973 9D6DC89136F5CD 24A92213C2C956 5B52182802ADB 23673530 237EC2A2AE67B4 B2680968AA2A 52E5202656A6A6 CB2696283382AE 251DD0E6 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD 0 0 0 0 0").unwrap(),
            g_i: PointG1::from_string("false 1A5D92950F9D1C 82DB5D4BF49AB8 FBFF5E631AD221 9B89F534C2AC04 165F1606 2E5EE0ECDBB554 F4C238315ACC2 57CAA2D6085FA6 CCE1970A4628E9 119D86E1 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD").unwrap(),
            omega: PointG2::from_string("true 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0").unwrap(),
            v
        }
    }

    pub fn revocation_pub_key() -> IssuerRevocationPublicKey {
        IssuerRevocationPublicKey {
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

    pub fn revocation_private_key() -> IssuerRevocationPrivateKey {
        IssuerRevocationPrivateKey {
            x: GroupOrderElement::new().unwrap(),
            sk: GroupOrderElement::new().unwrap()
        }
    }

    pub fn accumulator_pub_key() -> RevocationAccumulatorPublicKey {
        RevocationAccumulatorPublicKey {
            z: Pair::from_string("B0C52EBB799E8 6FC6F7D6883390 BC4244EDBC1787 FDEA974C84C1F1 234FA3A6 F411BCC525581F B238C8B10BBACB 8536CC797D203D DEFEAA1B1DBC5B 736EAC 529F008C0398B9 CD0B30B71A1F14 2D332E37CEBF1B A3D9B3319DCDAD CA1AAD2 E5B506C98D6F95 575329E5789B3B CA3A9AB8CED863 BB16612D7EDFC9 241D0C39 810C5FA05825E3 C8A863BA7721CD DCCCB939E4BC22 1817F872AA9906 E423204 C38DCA6D9C80D6 5DE52EA7CFE23E FB41FA284C112E E438D18C192C1D 88A018F EF8569C86B3916 119FE81D359A09 6D5A0088955ED3 6904F412A28BD4 11F6C539 29AD474B03EE99 D0353A66812CA7 C9763FC9EEB4A3 217160B2B8982E 10983B69 7F67C0FCFD4244 45C9665E75EC5B 4A23D9F0D1182F 3A8C685A922F6 20A176A9 883FF71EB14569 5030243F2B2B79 95A67EF0922D07 A6D74310BFE00A F8BBB21 476E55B2836798 16B49B2120D6EB 68EABD968A44DE E8DF358500A99A 15A3F96B 28749CC7A07F60 F82B17A0CA933F EE4166241C77F2 9BE2BB4B802250 19F0D85E").unwrap(),
        }
    }

    pub fn accumulator() -> RevocationAccumulator {
        let mut v: HashSet<u32> = HashSet::new();
        v.insert(1);

        RevocationAccumulator {
            acc: PointG2::from_string("false 1348A2A978E0DB 34007FF6AF40CE 6D0587A6FB0664 5C7BE100A9A5F0 195FD169 A8C3298C4E3638 F93A75199C097D F3659F1FB6AE4A A03EC27AEB629 2435D86 4DA6C9C1917365 866CCF7C293373 216DF40B2F9E81 19F44DEEC2C748 170C3B8A DDEA4569FCEEC7 1685AB7B80F94F 5BB29412B2822D 3FE85A96139673 109B08B8 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD 0 0 0 0 0").unwrap(),
            v,
            max_claim_num: 5
        }
    }

    pub fn tails() -> RevocationAccumulatorTails {
        let mut tails: HashMap<u32, PointG1> = HashMap::new();
        tails.insert(7, PointG1::from_string("false 6497C5436F096B 47B5497245ECBD FAFB1DB54701E4 20D8BA8C0BF17 70C77C4 88287D43F7A4B4 8BB4E20D6F44B7 E2AA930F85AC1D E2EFAE9BD7510F 8E58412 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD").unwrap());
        tails.insert(0, PointG1::from_string("false F7061FFC5D86BD FEA559D709EBB4 184F0E83E83C7F 77518EACC28D21 1B2D4E76 86D88DDE8770D0 5034DD68624C0 CA409B38BD8B6A EC15B842470D5B 2188CB11 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD").unwrap());
        tails.insert(2, PointG1::from_string("false 7F09E0BD7D3690 6479A9EC6FA073 64573936BF650B BE36F8593539B1 B171A77 904E5FF1902F37 CFB9E9C4DF1C84 3D02EE7915746B 68D700E062F81D 1DD4A216 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD").unwrap());
        tails.insert(8, PointG1::from_string("false D279E0F66FC8DA E287C065D3AAAB 4CE6A253645D30 433B6C8EF0CDA8 11CCBF5D 37B2100A28726B 4D9F49CF3A19B9 CC2CB102DC087D 7796535BC28B35 F520BB6 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD").unwrap());
        tails.insert(9, PointG1::from_string("false 2D436D106648F2 14A694AE410D8 E1F0468B1CC344 A11933E6D0C2F3 22590BB3 9DF2B5CE005F33 E39339635A02FA A890D5AFE6D251 1743F88BE1D067 D39B2C9 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD").unwrap());
        tails.insert(4, PointG1::from_string("false D2B947E76DC768 9544E27827014B A849C431714D5F D89704800BD2FD 5ABD852 AF2F1718B1CEE6 49242AF192601A CC13E78DA62DC7 6CC9B9161777FE 59A1C57 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD").unwrap());
        tails.insert(5, PointG1::from_string("false 41E6423FDE4D3 ED26FCE2D16487 2D297CA2796CEE 759B69CD067458 204F1642 AB82F9318A595F B574DF93832227 E792C9B54537BB 993558762A4619 967B9E7 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD").unwrap());
        tails.insert(3, PointG1::from_string("false 15720DF0F49B7F 34C04EC737127C BB4CA2E80916C7 A49E082782FC2C 51F62B5 E578481BE30FED 2885D24B4D01C4 A47BE2CEA0074F 849210EFC63320 6B01000 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD").unwrap());
        tails.insert(1, PointG1::from_string("false 1A5D92950F9D1C 82DB5D4BF49AB8 FBFF5E631AD221 9B89F534C2AC04 165F1606 2E5EE0ECDBB554 F4C238315ACC2 57CAA2D6085FA6 CCE1970A4628E9 119D86E1 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD").unwrap());

        let mut tails_dash: HashMap<u32, PointG2> = HashMap::new();
        tails_dash.insert(8, PointG2::from_string("false 390D1709376721 98245AABF4362B AC1FACB6BBD05E E4C3386AE5503A 128CD835 A982F82EC38AA9 C4D509C50A5739 147B931F0BAAB 9D2E2891090067 1E093A4 77F9E4C8101F59 BB5F319909D7D4 564B8C47AA666C CC8C97E732D170 220116B8 3A10DE9707FCB6 52542617716EA EB57185B59742D D01BF217533C5C 193BC78B FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD 0 0 0 0 0").unwrap());
        tails_dash.insert(1, PointG2::from_string("false CD975AFB9C5067 8FA21CC4E37FC3 CCAFBC2CB2CED2 AF24B72B23046E 1085AD0B 29B067BCCC5E0D D1A5FFD58150B E4DBB40838690C 84910B94ED77BE 135D66D F45FCF475FBB9C 63A1CF9D8DBDD2 F55CB07F8233A2 279087BA842772 B93978E 18C43310CDAA0 421A062395787F 96D1D9787FC4FD E2ABEB6A00F0A1 1140BA54 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD 0 0 0 0 0").unwrap());
        tails_dash.insert(4, PointG2::from_string("false 78E66848A7F5F9 132AB1C7553E01 4F277AB53DEFD0 EAAFD109BA7934 2E796AA A9CF83C15175AD 53D69FF43FC5D2 54883C1D7E9981 9C4D4BD276C31E D8DB152 F9457FB683C672 73873FEB68A789 DD761945B7C230 55BB9B119F2376 1D5BD4A1 419BCA31048242 607694D34D4010 203516C8CBF5E5 A1D5CC2ABBA257 6937824 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD 0 0 0 0 0").unwrap());
        tails_dash.insert(0, PointG2::from_string("false B689CDF1EEE6B9 7879E722A8927E 7A5F92EB847EF4 CB7D2B559A4B7A 94DFCE9 F353AFC74815B1 DF1DB4459153A0 FEBB4F1B0DC6CB 375723BC12026E 3A02BC0 CA432D2B712EBE 28310825C67A82 FCD05276543D75 4A06A4C1A05435 1DA19E B02395BAE668B8 10BD3BCD5F1CC9 92FC516611102D CC2E8568C3C687 1A06AE72 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD 0 0 0 0 0").unwrap());
        tails_dash.insert(7, PointG2::from_string("false 16AF65D69D2077 43BFBF1F03B4DB 1F875B833E17A2 70C749CF644BE2 9776105 D8F3E86EDF958C 213C8D6A15CB6 8032FB837CC91D 3D1F0AEAD45AB2 1D9225F9 824C05CC2BC42B E3CC4DF213DF1A 847C5444BB681 F9023211E70E70 1283B8EA E34FE320EFB7E1 9578E301C12C66 F498C7A87F0B99 E77B86E8244F00 10FDA472 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD 0 0 0 0 0").unwrap());
        tails_dash.insert(9, PointG2::from_string("false 77BA09D7BA300E 40B8FD86701B8E 2F74A578990E71 B28868F9A10567 1D23EFFC 6192F7E92893E2 8ECD622E98521 4E911BCF1ED8FB B77137674C6EFB 9CB358A 636339738BC01D 6AB860F1085F6D B53E0479005A69 7D3D559B98792E 239C96A E4468AC977895F 946CC6D42E40A7 EFACABFF178BF E74E1D503F3454 486C83C FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD 0 0 0 0 0").unwrap());
        tails_dash.insert(5, PointG2::from_string("false 1348A2A978E0DB 34007FF6AF40CE 6D0587A6FB0664 5C7BE100A9A5F0 195FD169 A8C3298C4E3638 F93A75199C097D F3659F1FB6AE4A A03EC27AEB629 2435D86 4DA6C9C1917365 866CCF7C293373 216DF40B2F9E81 19F44DEEC2C748 170C3B8A DDEA4569FCEEC7 1685AB7B80F94F 5BB29412B2822D 3FE85A96139673 109B08B8 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD 0 0 0 0 0").unwrap());
        tails_dash.insert(2, PointG2::from_string("false A833A7FEE1899C DDB240BB9D5C70 B12225E6BC6BC8 7214770046E216 11C7AF4B C673E87B0E3CA7 D402059952151C C78BAC6AE271F4 B767948A4CC721 16EDBCA9 9A898AF8DDF47C 2AA64013B834B4 643EFBCBFA5FCA F7FA0B6D3ADC92 1BA2FD5D 7C664B888E3A8F FC90E07B7CF85 A57C697325853C A7383E71F41985 227D1F8B FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD 0 0 0 0 0").unwrap());
        tails_dash.insert(3, PointG2::from_string("false 5E2B71E59F20F1 CDDC6CB91B3D78 9B3130684357E5 A9160132CEDE21 59E3FD8 CBE453D80A803A A96D59D7F885ED 1FAF1E7D84D77D 6703AB31EDF74E 1197DD1B EEEC3499BFBBDC 6B17FABA999A2D 9BE155AB7EFC66 BC4CBFC73D258E 15027EDA 31FDA448757FB7 E4B6213FD3BD56 BCC89B065F8BFF 3775B8DA93E846 107B0CE9 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD 0 0 0 0 0").unwrap());


        RevocationAccumulatorTails {
            tails,
            tails_dash
        }
    }

    pub fn revocation_reg_public() -> RevocationRegistryPublic {
        RevocationRegistryPublic {
            key: accumulator_pub_key(),
            acc: accumulator(),
            tails: tails()
        }
    }

    pub fn r_cnxt_m2() -> BigNumber {
        BigNumber::from_dec("52860447312636183767369476481903349046618423276302392993759146262753859184069").unwrap()
    }
}