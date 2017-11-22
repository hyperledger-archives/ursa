use bn::BigNumber;
use errors::IndyCryptoError;

use pair::{
    GroupOrderElement,
    Pair,
    PointG1,
    PointG2,
};

use super::constants::*;
use super::types::*;
use super::helpers::*;

use std::collections::{HashMap, HashSet};


pub struct Prover {}

impl Prover {
    pub fn generate_master_secret() -> Result<MasterSecret, IndyCryptoError> {
        Ok(MasterSecret {
            ms: rand(LARGE_MASTER_SECRET)?
        })
    }

    pub fn generate_blinded_master_secret(pub_key: &IssuerPublicKey,
                                          ms: &MasterSecret) -> Result<(BlindedMasterSecret,
                                                                        BlindedMasterSecretData), IndyCryptoError> {
        let blinded_primary_master_secret = Prover::_generate_blinded_primary_master_secret(&pub_key.p_key, &ms)?;

        let blinded_revocation_master_secret = match pub_key.r_key {
            Some(ref r_pk) => Some(Prover::_generate_blinded_revocation_master_secret(r_pk)?),
            _ => None
        };

        Ok((
            BlindedMasterSecret {
                u: blinded_primary_master_secret.u,
                ur: blinded_revocation_master_secret.as_ref().map(|d| d.ur)
            },
            BlindedMasterSecretData {
                v_prime: blinded_primary_master_secret.v_prime,
                vr_prime: blinded_revocation_master_secret.map(|d| d.vr_prime)
            }
        ))
    }

    fn _generate_blinded_primary_master_secret(p_pub_key: &IssuerPrimaryPublicKey,
                                               ms: &MasterSecret) -> Result<PrimaryBlindedMasterSecretData, IndyCryptoError> {
        let mut ctx = BigNumber::new_context()?;
        let v_prime = rand(LARGE_VPRIME)?;

        let u = p_pub_key.s
            .mod_exp(&v_prime, &p_pub_key.n, Some(&mut ctx))?
            .mul(
                &p_pub_key.rms.mod_exp(&ms.ms, &p_pub_key.n, Some(&mut ctx))?,
                None
            )?
            .modulus(&p_pub_key.n, Some(&mut ctx))?;

        Ok(PrimaryBlindedMasterSecretData { u, v_prime })
    }

    fn _generate_blinded_revocation_master_secret(r_pub_key: &IssuerRevocationPublicKey) -> Result<RevocationBlindedMasterSecretData, IndyCryptoError> {
        let vr_prime = GroupOrderElement::new()?;
        let ur = r_pub_key.h2.mul(&vr_prime)?;

        Ok(RevocationBlindedMasterSecretData { ur, vr_prime })
    }

    pub fn process_claim(claim: &mut Claim,
                         blinded_master_secret_data: &BlindedMasterSecretData,
                         pub_key: &IssuerPublicKey,
                         r_reg: Option<&RevocationRegistryPublic>) -> Result<(), IndyCryptoError> {
        Prover::_process_primary_claim(&mut claim.p_claim, &blinded_master_secret_data.v_prime)?;

        if let (&mut Some(ref mut non_revocation_claim), Some(ref vr_prime), &Some(ref r_key), Some(ref r_reg)) = (&mut claim.r_claim,
                                                                                                                   blinded_master_secret_data.vr_prime,
                                                                                                                   &pub_key.r_key,
                                                                                                                   r_reg) {
            Prover::_process_non_revocation_claim(non_revocation_claim,
                                                  vr_prime,
                                                  &r_key,
                                                  r_reg)?;
        }
        Ok(())
    }

    fn _process_primary_claim(p_claim: &mut PrimaryClaim,
                              v_prime: &BigNumber) -> Result<(), IndyCryptoError> {
        p_claim.v = v_prime.add(&p_claim.v)?;
        Ok(())
    }

    fn _process_non_revocation_claim(r_claim: &mut NonRevocationClaim,
                                     vr_prime: &GroupOrderElement,
                                     r_pub_key: &IssuerRevocationPublicKey,
                                     r_reg: &RevocationRegistryPublic) -> Result<(), IndyCryptoError> {
        let r_cnxt_m2 = BigNumber::from_bytes(&r_claim.m2.to_bytes()?)?;
        r_claim.vr_prime_prime = vr_prime.add_mod(&r_claim.vr_prime_prime)?;
        Prover::_test_witness_credential(&r_claim, r_pub_key, r_reg, &r_cnxt_m2)?;
        Ok(())
    }

    fn _test_witness_credential(r_claim: &NonRevocationClaim,
                                r_pub_key: &IssuerRevocationPublicKey,
                                r_reg: &RevocationRegistryPublic,
                                r_cnxt_m2: &BigNumber) -> Result<(), IndyCryptoError> {
        let z_calc = Pair::pair(&r_claim.witness.g_i, &r_reg.acc.acc)?
            .mul(&Pair::pair(&r_pub_key.g, &r_claim.witness.omega)?.inverse()?)?;
        if z_calc != r_reg.key.z {
            return Err(IndyCryptoError::InvalidStructure("Issuer is sending incorrect data".to_string()));
        }
        let pair_gg_calc = Pair::pair(&r_pub_key.pk.add(&r_claim.g_i)?, &r_claim.witness.sigma_i)?;
        let pair_gg = Pair::pair(&r_pub_key.g, &r_pub_key.g_dash)?;
        if pair_gg_calc != pair_gg {
            return Err(IndyCryptoError::InvalidStructure("Issuer is sending incorrect data".to_string()));
        }

        let m2 = GroupOrderElement::from_bytes(&r_cnxt_m2.to_bytes()?)?;

        let pair_h1 = Pair::pair(&r_claim.sigma, &r_pub_key.y.add(&r_pub_key.h_cap.mul(&r_claim.c)?)?)?;
        let pair_h2 = Pair::pair(
            &r_pub_key.h0
                .add(&r_pub_key.h1.mul(&m2)?)?
                .add(&r_pub_key.h2.mul(&r_claim.vr_prime_prime)?)?
                .add(&r_claim.g_i)?,
            &r_pub_key.h_cap
        )?;
        if pair_h1 != pair_h2 {
            return Err(IndyCryptoError::InvalidStructure("Issuer is sending incorrect data".to_string()));
        }

        Ok(())
    }
}

#[derive(Debug)]
pub struct ProofBuilder {
    pub m1_tilde: BigNumber,
    pub init_proofs: HashMap<String, InitProof>,
    pub c_list: Vec<Vec<u8>>,
    pub tau_list: Vec<Vec<u8>>,
    pub proof_claims: HashMap<String /* issuer pub key id */, ProofClaims>,
}

impl ProofBuilder {
    pub fn new() -> Result<ProofBuilder, IndyCryptoError> {
        Ok(ProofBuilder {
            m1_tilde: rand(LARGE_M2_TILDE)?,
            init_proofs: HashMap::new(),
            c_list: Vec::new(),
            tau_list: Vec::new()
        })
    }

    pub fn add_claim(&mut self, uuid: &str, claim: Claim, claim_attributes_values: ClaimAttributesValues, p_pub_key: IssuerPublicKey,
                     r_pub_key: Option<IssuerRevocationPublicKey>, r_reg: Option<RevocationRegistryPublic>,
                     attrs_with_predicates: ProofAttrs) -> Result<(), IndyCryptoError> {
        self.proof_claims.insert(uuid.to_owned(),
                                 ProofClaims {
                                     claim,
                                     claim_attributes_values,
                                     p_pub_key,
                                     r_pub_key,
                                     r_reg,
                                     attrs_with_predicates
                                 });
        Ok(())
    }

        if let (&Some(ref r_claim), &Some(ref r_reg), &Some(ref r_pub_key)) = (&claim.r_claim,
                                                                               &r_reg,
                                                                               &pub_key.r_key) {
            let proof = ProofBuilder::_init_non_revocation_proof(&mut r_claim.clone(), &r_reg, &r_pub_key)?;//TODO:FIXME

            self.c_list.extend_from_slice(&proof.as_c_list()?);
            self.tau_list.extend_from_slice(&proof.as_tau_list()?);
            m2_tilde = Some(group_element_to_bignum(&proof.tau_list_params.m2)?);
            non_revoc_init_proof = Some(proof);
        }

        let primary_init_proof = ProofBuilder::_init_primary_proof(&pub_key.p_key,
                                                                   &claim.p_claim,
                                                                   &claim_attributes_values.attrs_values,
                                                                   &attrs_with_predicates,
                                                                   &self.m1_tilde,
                                                                   m2_tilde)?;

        self.c_list.extend_from_slice(&primary_init_proof.as_c_list()?);
        self.tau_list.extend_from_slice(&primary_init_proof.as_tau_list()?);

        let init_proof = InitProof {
            primary_init_proof,
            non_revoc_init_proof,
            attributes_values: claim_attributes_values.clone()?,
            attrs_with_predicates: attrs_with_predicates.clone()
        };
        self.init_proofs.insert(uuid.to_owned(), init_proof);

        Ok(())
    }

    pub fn finalize(&mut self, nonce: &BigNumber, ms: &MasterSecret) -> Result<FullProof, IndyCryptoError> {
        let mut values: Vec<Vec<u8>> = Vec::new();
        values.extend_from_slice(&self.tau_list);
        values.extend_from_slice(&self.c_list);
        values.push(nonce.to_bytes()?);

        let c_h = get_hash_as_int(&mut values)?;

        let mut proofs: HashMap<String, Proof> = HashMap::new();

        for (proof_claim_uuid, init_proof) in self.init_proofs.iter() {
            let mut non_revoc_proof: Option<NonRevocProof> = None;
            if let Some(ref non_revoc_init_proof) = init_proof.non_revoc_init_proof {
                non_revoc_proof = Some(ProofBuilder::_finalize_non_revocation_proof(&non_revoc_init_proof, &c_h)?);
            }

            let primary_proof = ProofBuilder::_finalize_proof(&ms.ms,
                                                              &init_proof.primary_init_proof,
                                                              &c_h,
                                                              &init_proof.attributes_values.attrs_values,
                                                              &init_proof.attrs_with_predicates)?;

            let proof = Proof { primary_proof, non_revoc_proof };
            proofs.insert(proof_claim_uuid.to_owned(), proof);
        }

        let aggregated_proof = AggregatedProof { c_hash: c_h, c_list: self.c_list.clone() };

        Ok(FullProof { proofs, aggregated_proof })
    }

    fn _init_primary_proof(pk: &IssuerPrimaryPublicKey, c1: &PrimaryClaim, attributes: &HashMap<String, BigNumber>,
                           attr_with_predicates: &ProofAttrs, m1_t: &BigNumber,
                           m2_t: Option<BigNumber>) -> Result<PrimaryInitProof, IndyCryptoError> {
        let eq_proof = ProofBuilder::_init_eq_proof(&pk, c1, &attr_with_predicates,
                                                    m1_t, m2_t)?;

        let mut ge_proofs: Vec<PrimaryPredicateGEInitProof> = Vec::new();
        for predicate in attr_with_predicates.predicates.iter() {
            let ge_proof = ProofBuilder::_init_ge_proof(&pk, &eq_proof.m_tilde, attributes, predicate)?;
            ge_proofs.push(ge_proof);
        }

        Ok(PrimaryInitProof { eq_proof, ge_proofs })
    }

    fn _init_non_revocation_proof(claim: &mut NonRevocationClaim, rev_reg: &RevocationRegistryPublic, pkr: &IssuerRevocationPublicKey)
                                  -> Result<NonRevocInitProof, IndyCryptoError> {
        ProofBuilder::_update_non_revocation_claim(claim, &rev_reg.acc, &rev_reg.tails.tails_dash)?;

        let c_list_params = ProofBuilder::_gen_c_list_params(&claim)?;
        let proof_c_list = ProofBuilder::_create_c_list_values(&claim, &c_list_params, &pkr)?;

        let tau_list_params = ProofBuilder::_gen_tau_list_params()?;
        let proof_tau_list = ProofBuilder::create_tau_list_values(&pkr, &rev_reg.acc, &tau_list_params, &proof_c_list)?;

        Ok(NonRevocInitProof {
            c_list_params,
            tau_list_params,
            c_list: proof_c_list,
            tau_list: proof_tau_list
        })
    }

    fn _update_non_revocation_claim(claim: &mut NonRevocationClaim,
                                    accum: &RevocationAccumulator, tails: &HashMap<u32, PointG2>)
                                    -> Result<(), IndyCryptoError> {
        if !accum.v.contains(&claim.i) {
            return Err(IndyCryptoError::InvalidState("Can not update Witness. Claim revoked.".to_string()));
        }

        if claim.witness.v != accum.v {
            let v_old_minus_new: HashSet<u32> =
                claim.witness.v.difference(&accum.v).cloned().collect();
            let mut omega_denom = PointG2::new_inf()?;
            for j in v_old_minus_new.iter() {
                omega_denom = omega_denom.add(
                    tails.get(&(accum.max_claim_num + 1 - j + claim.i))
                        .ok_or(IndyCryptoError::InvalidStructure(format!("Key not found {} in tails", accum.max_claim_num + 1 - j + claim.i)))?)?;
            }
            let mut omega_num = PointG2::new_inf()?;
            let mut new_omega: PointG2 = claim.witness.omega.clone();
            for j in v_old_minus_new.iter() {
                omega_num = omega_num.add(
                    tails.get(&(accum.max_claim_num + 1 - j + claim.i))
                        .ok_or(IndyCryptoError::InvalidStructure(format!("Key not found {} in tails", accum.max_claim_num + 1 - j + claim.i)))?)?;
                new_omega = new_omega.add(
                    &omega_num.sub(&omega_denom)?
                )?;
            }

            claim.witness.v = accum.v.clone();
            claim.witness.omega = new_omega;
        }

        Ok(())
    }

    fn _init_eq_proof(pk: &IssuerPrimaryPublicKey, c1: &PrimaryClaim, attr_with_predicates: &ProofAttrs,
                      m1_tilde: &BigNumber, m2_t: Option<BigNumber>) -> Result<PrimaryEqualInitProof, IndyCryptoError> {
        let mut ctx = BigNumber::new_context()?;

        let m2_tilde = m2_t.unwrap_or(rand(LARGE_MVECT)?);

        let r = rand(LARGE_VPRIME)?;
        let e_tilde = rand(LARGE_ETILDE)?;
        let v_tilde = rand(LARGE_VTILDE)?;

        let m_tilde = get_mtilde(&attr_with_predicates.unrevealed_attrs)?;

        let a_prime = pk.s
            .mod_exp(&r, &pk.n, Some(&mut ctx))?
            .mul(&c1.a, Some(&mut ctx))?
            .modulus(&pk.n, Some(&mut ctx))?;

        let large_e_start = BigNumber::from_dec(&LARGE_E_START.to_string())?;

        let v_prime = c1.v.sub(
            &c1.e.mul(&r, Some(&mut ctx))?
        )?;

        let e_prime = c1.e.sub(
            &BigNumber::from_dec("2")?.exp(&large_e_start, Some(&mut ctx))?
        )?;

        let t = calc_teq(&pk, &a_prime, &e_tilde, &v_tilde, &m_tilde, &m1_tilde,
                         &m2_tilde, &attr_with_predicates.unrevealed_attrs)?;

        Ok(PrimaryEqualInitProof {
            a_prime,
            t,
            e_tilde,
            e_prime,
            v_tilde,
            v_prime,
            m_tilde,
            m1_tilde: m1_tilde.clone()?,
            m2_tilde: m2_tilde.clone()?,
            m2: c1.m_2.clone()?
        })
    }

    fn _init_ge_proof(pk: &IssuerPrimaryPublicKey, mtilde: &HashMap<String, BigNumber>,
                      attributes: &HashMap<String, BigNumber>, predicate: &Predicate)
                      -> Result<PrimaryPredicateGEInitProof, IndyCryptoError> {
        let mut ctx = BigNumber::new_context()?;
        let (k, value) = (&predicate.attr_name, predicate.value);

        let attr_value = attributes.get(&k[..])
            .ok_or(IndyCryptoError::InvalidStructure(format!("Value by key '{}' not found in c1.encoded_attributes", k)))?
            .to_dec()?
            .parse::<i32>()
            .map_err(|_| IndyCryptoError::InvalidStructure(format!("Value by key '{}' has invalid format", k)))?;

        let delta: i32 = attr_value - value;

        if delta < 0 {
            return Err(IndyCryptoError::InvalidStructure("Predicate is not satisfied".to_string()));
        }

        let u = four_squares(delta)?;

        let mut r: HashMap<String, BigNumber> = HashMap::new();
        let mut t: HashMap<String, BigNumber> = HashMap::new();
        let mut c_list: Vec<BigNumber> = Vec::new();

        for i in 0..ITERATION {
            let cur_u = u.get(&i.to_string())
                .ok_or(IndyCryptoError::InvalidStructure(format!("Value by key '{}' not found in u1", i)))?;

            let cur_r = rand(LARGE_VPRIME)?;

            let cut_t = pk.z
                .mod_exp(&cur_u, &pk.n, Some(&mut ctx))?
                .mul(
                    &pk.s.mod_exp(&cur_r, &pk.n, Some(&mut ctx))?,
                    Some(&mut ctx)
                )?
                .modulus(&pk.n, Some(&mut ctx))?;

            r.insert(i.to_string(), cur_r);
            t.insert(i.to_string(), cut_t.clone()?);
            c_list.push(cut_t)
        }

        let r_delta = rand(LARGE_VPRIME)?;

        let t_delta = pk.z
            .mod_exp(&BigNumber::from_dec(&delta.to_string())?, &pk.n, Some(&mut ctx))?
            .mul(
                &pk.s.mod_exp(&r_delta, &pk.n, Some(&mut ctx))?,
                Some(&mut ctx)
            )?
            .modulus(&pk.n, Some(&mut ctx))?;

        r.insert("DELTA".to_string(), r_delta);
        t.insert("DELTA".to_string(), t_delta.clone()?);
        c_list.push(t_delta);

        let mut u_tilde: HashMap<String, BigNumber> = HashMap::new();
        let mut r_tilde: HashMap<String, BigNumber> = HashMap::new();

        for i in 0..ITERATION {
            u_tilde.insert(i.to_string(), rand(LARGE_UTILDE)?);
            r_tilde.insert(i.to_string(), rand(LARGE_RTILDE)?);
        }

        r_tilde.insert("DELTA".to_string(), rand(LARGE_RTILDE)?);
        let alpha_tilde = rand(LARGE_ALPHATILDE)?;

        let mj = mtilde.get(&k[..])
            .ok_or(IndyCryptoError::InvalidStructure(format!("Value by key '{}' not found in eq_proof.mtilde", k)))?;

        let tau_list = calc_tge(&pk, &u_tilde, &r_tilde, &mj, &alpha_tilde, &t)?;

        Ok(PrimaryPredicateGEInitProof {
            c_list,
            tau_list,
            u,
            u_tilde,
            r,
            r_tilde,
            alpha_tilde,
            predicate: predicate.clone(),
            t
        })
    }

    fn _finalize_eq_proof(ms: &BigNumber, init_proof: &PrimaryEqualInitProof, c_h: &BigNumber,
                          attributes_values: &HashMap<String, BigNumber>, attrs_with_predicates: &ProofAttrs)
                          -> Result<PrimaryEqualProof, IndyCryptoError> {
        let mut ctx = BigNumber::new_context()?;

        let e = c_h
            .mul(&init_proof.e_prime, Some(&mut ctx))?
            .add(&init_proof.e_tilde)?;

        let v = c_h
            .mul(&init_proof.v_prime, Some(&mut ctx))?
            .add(&init_proof.v_tilde)?;

        let mut m: HashMap<String, BigNumber> = HashMap::new();

        for k in attrs_with_predicates.unrevealed_attrs.iter() {
            let cur_mtilde = init_proof.m_tilde.get(k)
                .ok_or(IndyCryptoError::InvalidStructure(format!("Value by key '{}' not found in init_proof.mtilde", k)))?;

            let cur_val = attributes_values.get(k)
                .ok_or(IndyCryptoError::InvalidStructure(format!("Value by key '{}' not found in attributes_values", k)))?;

            let val = c_h
                .mul(&cur_val, Some(&mut ctx))?
                .add(&cur_mtilde)?;

            m.insert(k.clone(), val);
        }

        let m1 = c_h
            .mul(&ms, Some(&mut ctx))?
            .add(&init_proof.m1_tilde)?;

        let m2 = c_h
            .mul(&init_proof.m2, Some(&mut ctx))?
            .add(&init_proof.m2_tilde)?;


        let mut revealed_attrs_with_values: HashMap<String, BigNumber> = HashMap::new();

        for attr in attrs_with_predicates.revealed_attrs.iter() {
            revealed_attrs_with_values.insert(
                attr.clone(),
                attributes_values
                    .get(attr)
                    .ok_or(IndyCryptoError::InvalidStructure(format!("Encoded value not found")))?
                    .clone()?,
            );
        }

        Ok(PrimaryEqualProof {
            revealed_attrs: revealed_attrs_with_values,
            a_prime: init_proof.a_prime.clone()?,
            e,
            v,
            m,
            m1,
            m2
        })
    }

    fn _finalize_ge_proof(c_h: &BigNumber, init_proof: &PrimaryPredicateGEInitProof,
                          eq_proof: &PrimaryEqualProof) -> Result<PrimaryPredicateGEProof, IndyCryptoError> {
        let mut ctx = BigNumber::new_context()?;
        let mut u: HashMap<String, BigNumber> = HashMap::new();
        let mut r: HashMap<String, BigNumber> = HashMap::new();
        let mut urproduct = BigNumber::new()?;

        for i in 0..ITERATION {
            let cur_utilde = init_proof.u_tilde.get(&i.to_string())
                .ok_or(IndyCryptoError::InvalidStructure(format!("Value by key '{}' not found in init_proof.u_tilde", i)))?;
            let cur_u = init_proof.u.get(&i.to_string())
                .ok_or(IndyCryptoError::InvalidStructure(format!("Value by key '{}' not found in init_proof.u", i)))?;
            let cur_rtilde = init_proof.r_tilde.get(&i.to_string())
                .ok_or(IndyCryptoError::InvalidStructure(format!("Value by key '{}' not found in init_proof.r_tilde", i)))?;
            let cur_r = init_proof.r.get(&i.to_string())
                .ok_or(IndyCryptoError::InvalidStructure(format!("Value by key '{}' not found in init_proof.r", i)))?;

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

            let cur_rtilde_delta = init_proof.r_tilde.get("DELTA")
                .ok_or(IndyCryptoError::InvalidStructure(format!("Value by key '{}' not found in init_proof.r_tilde", "DELTA")))?;
            let cur_r_delta = init_proof.r.get("DELTA")
                .ok_or(IndyCryptoError::InvalidStructure(format!("Value by key '{}' not found in init_proof.r", "DELTA")))?;

            let new_delta = c_h
                .mul(&cur_r_delta, Some(&mut ctx))?
                .add(&cur_rtilde_delta)?;

            r.insert("DELTA".to_string(), new_delta);
        }

        let r_delta = init_proof.r.get("DELTA")
            .ok_or(IndyCryptoError::InvalidStructure(format!("Value by key '{}' not found in init_proof.r", "DELTA")))?;

        let alpha = r_delta
            .sub(&urproduct)?
            .mul(&c_h, Some(&mut ctx))?
            .add(&init_proof.alpha_tilde)?;

        let mj = eq_proof.m.get(&init_proof.predicate.attr_name)
            .ok_or(IndyCryptoError::InvalidStructure(format!("Value by key '{}' not found in eq_proof.m", init_proof.predicate.attr_name)))?;

        Ok(PrimaryPredicateGEProof {
            u,
            r,
            mj: mj.clone()?,
            alpha,
            t: clone_bignum_map(&init_proof.t)?,
            predicate: init_proof.predicate.clone()
        })
    }

    fn _finalize_proof(ms: &BigNumber, init_proof: &PrimaryInitProof, c_h: &BigNumber,
                       attributes: &HashMap<String, BigNumber>, attrs_with_predicates: &ProofAttrs)
                       -> Result<PrimaryProof, IndyCryptoError> {
        info!(target: "anoncreds_service", "Prover finalize proof -> start");

        let eq_proof = ProofBuilder::_finalize_eq_proof(ms, &init_proof.eq_proof, c_h, attributes, attrs_with_predicates)?;
        let mut ge_proofs: Vec<PrimaryPredicateGEProof> = Vec::new();

        for init_ge_proof in init_proof.ge_proofs.iter() {
            let ge_proof = ProofBuilder::_finalize_ge_proof(c_h, init_ge_proof, &eq_proof)?;
            ge_proofs.push(ge_proof);
        }

        info!(target: "anoncreds_service", "Prover finalize proof -> done");

        Ok(PrimaryProof { eq_proof, ge_proofs })
    }

    fn _gen_c_list_params(claim: &NonRevocationClaim) -> Result<NonRevocProofXList, IndyCryptoError> {
        let rho = GroupOrderElement::new()?;
        let r = GroupOrderElement::new()?;
        let r_prime = GroupOrderElement::new()?;
        let r_prime_prime = GroupOrderElement::new()?;
        let r_prime_prime_prime = GroupOrderElement::new()?;
        let o = GroupOrderElement::new()?;
        let o_prime = GroupOrderElement::new()?;
        let m = rho.mul_mod(&claim.c)?;
        let m_prime = r.mul_mod(&r_prime_prime)?;
        let t = o.mul_mod(&claim.c)?;
        let t_prime = o_prime.mul_mod(&r_prime_prime)?;
        let m2 = GroupOrderElement::from_bytes(&claim.m2.to_bytes()?)?;

        Ok(NonRevocProofXList {
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
            s: claim.vr_prime_prime,
            c: claim.c
        })
    }

    fn _create_c_list_values(claim: &NonRevocationClaim, params: &NonRevocProofXList,
                             pkr: &IssuerRevocationPublicKey) -> Result<NonRevocProofCList, IndyCryptoError> {
        let e = pkr.h
            .mul(&params.rho)?
            .add(
                &pkr.htilde.mul(&params.o)?
            )?;

        let d = pkr.g
            .mul(&params.r)?
            .add(
                &pkr.htilde.mul(&params.o_prime)?
            )?;

        let a = claim.sigma
            .add(
                &pkr.htilde.mul(&params.rho)?
            )?;

        let g = claim.g_i
            .add(
                &pkr.htilde.mul(&params.r)?
            )?;

        let w = claim.witness.omega
            .add(
                &pkr.h_cap.mul(&params.r_prime)?
            )?;

        let s = claim.witness.sigma_i
            .add(
                &pkr.h_cap.mul(&params.r_prime_prime)?
            )?;

        let u = claim.witness.u_i
            .add(
                &pkr.h_cap.mul(&params.r_prime_prime_prime)?
            )?;

        Ok(NonRevocProofCList {
            e,
            d,
            a,
            g,
            w,
            s,
            u
        })
    }

    fn _gen_tau_list_params() -> Result<NonRevocProofXList, IndyCryptoError> {
        Ok(NonRevocProofXList {
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
        })
    }

    fn _finalize_non_revocation_proof(init_proof: &NonRevocInitProof, c_h: &BigNumber) -> Result<NonRevocProof, IndyCryptoError> {
        info!(target: "anoncreds_service", "Prover finalize non-revocation proof -> start");

        let ch_num_z = bignum_to_group_element(&c_h)?;
        let mut x_list: Vec<GroupOrderElement> = Vec::new();

        for (x, y) in init_proof.tau_list_params.as_list()?.iter().zip(init_proof.c_list_params.as_list()?.iter()) {
            x_list.push(x.add_mod(
                &ch_num_z.mul_mod(&y)?.mod_neg()?
            )?);
        }

        info!(target: "anoncreds_service", "Prover finalize non-revocation proof -> done");

        Ok(NonRevocProof {
            x_list: NonRevocProofXList::from_list(x_list),
            c_list: init_proof.c_list.clone()
        })
    }

    pub fn create_tau_list_values(pk_r: &IssuerRevocationPublicKey, accumulator: &RevocationAccumulator,
                                  params: &NonRevocProofXList, proof_c: &NonRevocProofCList) -> Result<NonRevocProofTauList, IndyCryptoError> {
        let t1 = pk_r.h.mul(&params.rho)?.add(&pk_r.htilde.mul(&params.o)?)?;
        let mut t2 = proof_c.e.mul(&params.c)?
            .add(&pk_r.h.mul(&params.m.mod_neg()?)?)?
            .add(&pk_r.htilde.mul(&params.t.mod_neg()?)?)?;
        if t2.is_inf()? {
            t2 = PointG1::new_inf()?;
        }
        let t3 = Pair::pair(&proof_c.a, &pk_r.h_cap)?.pow(&params.c)?
            .mul(&Pair::pair(&pk_r.htilde, &pk_r.h_cap)?.pow(&params.r)?)?
            .mul(&Pair::pair(&pk_r.htilde, &pk_r.y)?.pow(&params.rho)?
                .mul(&Pair::pair(&pk_r.htilde, &pk_r.h_cap)?.pow(&params.m)?)?
                .mul(&Pair::pair(&pk_r.h1, &pk_r.h_cap)?.pow(&params.m2)?)?
                .mul(&Pair::pair(&pk_r.h2, &pk_r.h_cap)?.pow(&params.s)?)?.inverse()?)?;
        let t4 = Pair::pair(&pk_r.htilde, &accumulator.acc)?
            .pow(&params.r)?
            .mul(&Pair::pair(&pk_r.g.neg()?, &pk_r.h_cap)?.pow(&params.r_prime)?)?;
        let t5 = pk_r.g.mul(&params.r)?.add(&pk_r.htilde.mul(&params.o_prime)?)?;
        let mut t6 = proof_c.d.mul(&params.r_prime_prime)?
            .add(&pk_r.g.mul(&params.m_prime.mod_neg()?)?)?
            .add(&pk_r.htilde.mul(&params.t_prime.mod_neg()?)?)?;
        if t6.is_inf()? {
            t6 = PointG1::new_inf()?;
        }
        let t7 = Pair::pair(&pk_r.pk.add(&proof_c.g)?, &pk_r.h_cap)?.pow(&params.r_prime_prime)?
            .mul(&Pair::pair(&pk_r.htilde, &pk_r.h_cap)?.pow(&params.m_prime.mod_neg()?)?)?
            .mul(&Pair::pair(&pk_r.htilde, &proof_c.s)?.pow(&params.r)?)?;
        let t8 = Pair::pair(&pk_r.htilde, &pk_r.u)?.pow(&params.r)?
            .mul(&Pair::pair(&pk_r.g.neg()?, &pk_r.h_cap)?.pow(&params.r_prime_prime_prime)?)?;

        Ok(NonRevocProofTauList {
            t1,
            t2,
            t3,
            t4,
            t5,
            t6,
            t7,
            t8
        })
    }

    pub fn create_tau_list_expected_values(pk_r: &IssuerRevocationPublicKey, accumulator: &RevocationAccumulator,
                                           accum_pk: &RevocationAccumulatorPublicKey, proof_c: &NonRevocProofCList) -> Result<NonRevocProofTauList, IndyCryptoError> {
        let t1 = proof_c.e;
        let t2 = PointG1::new_inf()?;
        let t3 = Pair::pair(&pk_r.h0.add(&proof_c.g)?, &pk_r.h_cap)?
            .mul(&Pair::pair(&proof_c.a, &pk_r.y)?.inverse()?)?;
        let t4 = Pair::pair(&proof_c.g, &accumulator.acc)?
            .mul(&Pair::pair(&pk_r.g, &proof_c.w)?.mul(&accum_pk.z)?.inverse()?)?;
        let t5 = proof_c.d;
        let t6 = PointG1::new_inf()?;
        let t7 = Pair::pair(&pk_r.pk.add(&proof_c.g)?, &proof_c.s)?
            .mul(&Pair::pair(&pk_r.g, &pk_r.g_dash)?.inverse()?)?;
        let t8 = Pair::pair(&proof_c.g, &pk_r.u)?
            .mul(&Pair::pair(&pk_r.g, &proof_c.u)?.inverse()?)?;

        Ok(NonRevocProofTauList {
            t1,
            t2,
            t3,
            t4,
            t5,
            t6,
            t7,
            t8
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::issuer;

    #[test]
    fn generate_master_secret_works() {
        let ms = Prover::generate_master_secret().unwrap();
        assert_eq!(ms.ms.to_dec().unwrap(), mocks::master_secret().ms.to_dec().unwrap());
    }

    #[test]
    fn generate_blinded_primary_master_secret_works() {
        let pk = issuer::mocks::issuer_primary_public_key();
        let ms = mocks::master_secret();

        let blinded_primary_master_secret = Prover::_generate_blinded_primary_master_secret(&pk, &ms).unwrap();
        assert_eq!(blinded_primary_master_secret, mocks::primary_blinded_master_secret_data());
    }

    #[test]
    fn generate_blinded_revocation_master_secret_works() {
        let r_pk = issuer::mocks::issuer_revocation_public_key();
        Prover::_generate_blinded_revocation_master_secret(&r_pk).unwrap();
    }

    #[test]
    fn generate_blinded_master_secret_works() {
        let pk = issuer::mocks::issuer_public_key();
        let ms = super::mocks::master_secret();

        let (blinded_master_secret, blinded_master_secret_data) = Prover::generate_blinded_master_secret(&pk, &ms).unwrap();

        assert_eq!(blinded_master_secret.u, mocks::primary_blinded_master_secret_data().u);
        assert_eq!(blinded_master_secret_data.v_prime, mocks::primary_blinded_master_secret_data().v_prime);
        assert!(blinded_master_secret.ur.is_some());
        assert!(blinded_master_secret_data.vr_prime.is_some());
    }

    #[test]
    fn _process_primary_claim_works() {
        let mut claim = super::mocks::primary_claim();
        let v_prime = mocks::primary_blinded_master_secret_data().v_prime;

        let old_v = claim.v.clone().unwrap();

        Prover::_process_primary_claim(&mut claim, &v_prime).unwrap();
        let new_v = claim.v;

        assert_ne!(old_v, new_v);
        assert_eq!(new_v, BigNumber::from_dec("6477858587997811893327035319417510316563341854132851390093281262022504586945336581881563055213337677056181844572991952555932751996898440671581814053127951224635658321050035511444954503085657513346849179237794480434375911442013322987051674887132592945890233635605453284558403076620029455818399007111894266660086410526668408855182225343461996944205701323678477386589439096120617239626883641624143871881601120776418596868065347775529349636357270798678980103498962335458062398390874983717770755470680118630150637099010442433570005771926940985392435424847341722158778783743566064471957069643875229555806124258126320547499902827001601615456597645806529030989244918748594934977736595257639382322682996067172388323783009953948509092588302546246573218033358898948457650961085860266597035771527395335213114949463090340318016121863").unwrap());
    }

    #[test]
    fn process_claim_works_for_primary_only() {
        let mut claim = super::mocks::claim();
        let pk = issuer::mocks::issuer_public_key();
        let blinded_master_secret_data = super::mocks::blinded_master_secret_data();

        let old_v = claim.p_claim.v.clone().unwrap();

        Prover::process_claim(&mut claim, &blinded_master_secret_data, &pk, None).unwrap();
        let new_v = claim.p_claim.v;

        assert_ne!(old_v, new_v);
        assert_eq!(new_v, BigNumber::from_dec("6477858587997811893327035319417510316563341854132851390093281262022504586945336581881563055213337677056181844572991952555932751996898440671581814053127951224635658321050035511444954503085657513346849179237794480434375911442013322987051674887132592945890233635605453284558403076620029455818399007111894266660086410526668408855182225343461996944205701323678477386589439096120617239626883641624143871881601120776418596868065347775529349636357270798678980103498962335458062398390874983717770755470680118630150637099010442433570005771926940985392435424847341722158778783743566064471957069643875229555806124258126320547499902827001601615456597645806529030989244918748594934977736595257639382322682996067172388323783009953948509092588302546246573218033358898948457650961085860266597035771527395335213114949463090340318016121863").unwrap());
    }

    #[test]
    fn init_proof_works() {
        let pk = issuer::mocks::issuer_primary_public_key();
        let claim = super::mocks::claim();
        let m1_t = BigNumber::from_dec("21544287380986891419162473617242441136231665555467324140952028776483657408525689082249184862870856267009773225408151321864247533184196094757877079561221602250888815228824796823045594410522810417051146366939126434027952941761214129885206419097498982142646746254256892181011609282364766769899756219988071473111").unwrap();
        let m2_t = BigNumber::from_dec("20019436401620609773538287054563349105448394091395718060076065683409192012223520437097245209626164187921545268202389347437258706857508181049451308664304690853807529189730523256422813648391821847776735976798445049082387614903898637627680273723153113532585372668244465374990535833762731556501213399533698173874").unwrap();
        let claim_attributes = issuer::mocks::claim_attributes_values();
        let attrs_with_predicates = mocks::attrs_with_predicates();

        ProofBuilder::_init_primary_proof(&pk, &claim.p_claim, &claim_attributes.attrs_values, &attrs_with_predicates, &m1_t, Some(m2_t)).unwrap();
    }

    #[test]
    fn finalize_proof_works() {
        let proof = mocks::primary_init_proof();
        let ms = mocks::master_secret();
        let c_h = BigNumber::from_dec("107686359310664445046126368677755391247164319345083587464043204013905993527834").unwrap();
        let claim_attributes = issuer::mocks::claim_attributes_values();
        let attrs_with_predicates = mocks::attrs_with_predicates();

        let res = ProofBuilder::_finalize_proof(&ms.ms, &proof, &c_h, &claim_attributes.attrs_values, &attrs_with_predicates);

        assert!(res.is_ok());
    }

    #[test]
    fn init_eq_proof_works() {
        let pk = issuer::mocks::issuer_primary_public_key();
        let claim = super::mocks::primary_claim();
        let attrs_with_predicates = mocks::attrs_with_predicates();
        let m1_tilde = BigNumber::from_dec("101699538176051593371744225919046760532786718077106502466570844730111441686747507159918166345843978280307167319698104055171476367527139548387778863611093261001762539719090094485796865232109859717006503205961984033284239500178635203251080574429593379622288524622977721677439771060806446693275003002447037756467").unwrap();
        let m2_tilde = BigNumber::from_dec("31230114293795576487127595372834830220228562310818079039836555160797619323909214967951444512173906589379330228717887451770324874651295781099491258571562527679146158488391908045190667642630077485518774594787164364584431134524117765512651773418307564918922308711232172267389727003411383955005915276810988726136").unwrap();

        let init_eq_proof = ProofBuilder::_init_eq_proof(&pk, &claim, &attrs_with_predicates, &m1_tilde, Some(m2_tilde)).unwrap();

        assert_eq!(init_eq_proof.a_prime.to_dec().unwrap(), "87057631969731126162889320560906357360267008247046682344994037071540708847648211770817155467322576564416024131016702461829141826154593193141015555408707962107434889154274101480021851047519249826871065068045489054940673687307364802393856912954529821530366129214823349578250933984191619715737300481000921545131737892947565265902387824838694421659738826630417546849137080518569690367670216680263229483688777919442405436226899082217495953507207561863892643215763362913098682050328209689762892828408774897957041802696642645714627207453405565027136962897066680484021579390417804092995897134437003639398170927787299154075285");
        assert_eq!(init_eq_proof.v_prime.to_dec().unwrap(), "5979547362044420689643605161847007473090081436212966743842241286592937826625276385813360906453355392545643230503360670090004097274446022944279570878276259729306779668575697214067216866429507821180867566895648038856148919510059621853730813107074415548724255552174426281218098200918679203779943916397256259606901368304143824867249078714432422027782927278071444841086260224951432527743093933778851959693368146789991602066025734455616272412130589236198988320593653003193963066617573884531391745988882862687993383824150400809323307293852247592582410221809104069581125010219396759971113914000795860997210346078905489329838723780453966406654041083307266391458113165288688592430952227431062675696350809783088665646193119746626057641646852972527804891696692352131972390096122206815139645180412672265386643453131031235225649159719");
        assert_eq!(init_eq_proof.e_prime.to_dec().unwrap(), "421208355533376344033560360084200567");
    }

    #[test]
    fn finalize_eq_proof_works() {
        let ms = BigNumber::from_dec("12017662702207397635206788416861773342711375658894915181302218291088885004642").unwrap();
        let c_h = BigNumber::from_dec("65052515950080385170056404271846666093263620691254624189854445495335700076548").unwrap();
        let init_proof = mocks::primary_equal_init_proof();
        let claim_attributes = issuer::mocks::claim_attributes_values();
        let attrs_with_predicates = mocks::attrs_with_predicates();

        let proof = ProofBuilder::_finalize_eq_proof(&ms, &init_proof, &c_h, &claim_attributes.attrs_values, &attrs_with_predicates).unwrap();

        assert_eq!("46977509037563772921188771357228696971286986611479769037400887043024357260824466323972528739266623662424083138906804114233154076462225260", proof.e.to_dec().unwrap());
        assert_eq!("555894869457553465718054497220703310113847971154321206264039643437256150021765032391630230094549373082683761872900289443108844758698210311744008775755841424663713495335913737925610645231143512448736634848872651673398623671421680147672048516992617074237823416006998805743252732623168072887558380980816786967972208697482105496476584623670241498051382948079749991653743122008317688039944886441991890739570646377897115078595023503848923611116244104325820581549132685254973230215813377280331818752749674933449141701081762918502111898869410069368198046357103361141404701610657859033620340201121860748524404546417655599945090144921881183922296151990310095095955070183524924902826674801457725425394553828477598974723668103655265677518938090134981829839176785641671819341783587890027487090232485080219343288188381028474008022615299819430842220715432262971141278304167669686965655751310509796666256987764202199558192225907485643584", proof.v.to_dec().unwrap());
        assert_eq!("17884736668674953594474879343533841182802514514784532835710262264561805009458126297222977824304362311586622997817594769134550513911169868072027461607531075593532027490623438201429184516874637111394210856531406371117724109267267829196540990374669452129657796333114585130056514558678918989249474063851032294543", proof.m1.to_dec().unwrap());
        assert_eq!("33970939655505026872690051065527896936826240486176548712174703648151652129591217103741946892383483806205993341432925544541557374346350172352729633028700080895510117255197249531019938518779850139061087723518395934746900289855498383299025412840993553136695018502936439397825288787933388062548604655707739594437", proof.m2.to_dec().unwrap());
        assert_eq!("2976250595835739181594320238227653601426197318110939190760657852629456864395726135468275792741622452401456587655635268677703907105682407452071286027329441960908939293198715566259", proof.m.get("age").unwrap().to_dec().unwrap());
    }

    #[test]
    fn init_ge_proof_works() {
        let pk = issuer::mocks::issuer_primary_public_key();
        let eq_proof = mocks::primary_equal_init_proof();
        let predicate = mocks::predicate();
        let claim_attributes = issuer::mocks::claim_attributes_values();

        let init_ge_proof = ProofBuilder::_init_ge_proof(&pk, &eq_proof.m_tilde, &claim_attributes.attrs_values, &predicate).unwrap();

        assert_eq!(init_ge_proof.c_list.get(0).unwrap().to_dec().unwrap(), "66452646864713459129322124524496160239214129628844448912512675754382373114045232638792544050983258044571320479724542222159607548371946608278224646356448366445559828934782665270370014756906222313296871353700305312489013107502898521331193640487262241439496025903490697084701289251331970932030723857963667757918065298468726954493148633682914144253830507074421917845317843041768030700610129944001550144134234321487234247282527013708361275163765747931441214224397693734342806818103569845752619756970663088347173537279465064357347197203519585032404779938843725754592220777310937230037486845412937230858545348334751626327225");
        assert_eq!(init_ge_proof.c_list.get(4).unwrap().to_dec().unwrap(), "12744073002342538466174266178920319716851536025528365678772164359094855375069597510967107907963978165383581958746728451817220119885059854369802587463275692110468863903085692788520163123046996971844187140303651001700638819763809506725152408953126623513326965559836659294476633000658736763344051801272123315367972537058814718428582311569246639308898362985600736985313610287370218545585443328912998714066030788971356972398823446394808259083145491780287377954911517455205043191986659486803525453280026699756592970920620102979774178487359570489964938005831483280782091403551604164735055022297589542910009750584030261291932");

        assert_eq!(init_ge_proof.t.get("0").unwrap().to_dec().unwrap(), "66452646864713459129322124524496160239214129628844448912512675754382373114045232638792544050983258044571320479724542222159607548371946608278224646356448366445559828934782665270370014756906222313296871353700305312489013107502898521331193640487262241439496025903490697084701289251331970932030723857963667757918065298468726954493148633682914144253830507074421917845317843041768030700610129944001550144134234321487234247282527013708361275163765747931441214224397693734342806818103569845752619756970663088347173537279465064357347197203519585032404779938843725754592220777310937230037486845412937230858545348334751626327225");
        assert_eq!(init_ge_proof.t.get("DELTA").unwrap().to_dec().unwrap(), "12744073002342538466174266178920319716851536025528365678772164359094855375069597510967107907963978165383581958746728451817220119885059854369802587463275692110468863903085692788520163123046996971844187140303651001700638819763809506725152408953126623513326965559836659294476633000658736763344051801272123315367972537058814718428582311569246639308898362985600736985313610287370218545585443328912998714066030788971356972398823446394808259083145491780287377954911517455205043191986659486803525453280026699756592970920620102979774178487359570489964938005831483280782091403551604164735055022297589542910009750584030261291932");

        assert_eq!(init_ge_proof.u.get("0").unwrap().to_dec().unwrap(), "3");
        assert_eq!(init_ge_proof.u.get("1").unwrap().to_dec().unwrap(), "1");
    }

    #[test]
    fn finalize_ge_proof_works() {
        let c_h = BigNumber::from_dec("107686359310664445046126368677755391247164319345083587464043204013905993527834").unwrap();
        let ge_proof = mocks::primary_ge_init_proof();
        let eq_proof = mocks::primary_eq_proof();

        let ge_proof = ProofBuilder::_finalize_ge_proof(&c_h, &ge_proof, &eq_proof).unwrap();

        assert_eq!("14530430712270780620115716831630456792731829285960002962064509786954277815652219734860240775632969505615425989813150680974232279981033881929825516835639704838509146807403579176456", ge_proof.u.get("0").unwrap().to_dec().unwrap());
        assert_eq!("1415830066404575063558956955699897939417161777078791039926340455929989312103567388586750415279750275627689289774355989928259903201283164671369980334635402090593700202419576962251006803664979387881077329091553387025639738608978470326865096461988349436323051092921673039448207467310143157161249548690648317604663697956127142299857431279531067869166789113125108487447241380451860460435536386169606660126687136336515643267258245597749963499390882335368772524506108537160732974827392286571681871686360634706404457817326674394813236360450345475325164815205390904412548072443050097422540706146216417531228071209074620592598469883684966671309568705760392191743050877301212854432940753955279643358353605952631236345030655922045", ge_proof.r.get("0").unwrap().to_dec().unwrap());
        assert_eq!("2909377521678119520977157959638852346549039931868195250658890196374980817755318676413066648981533034386605143040798380729872705956567376032225961933326117009011908374020093877002895162468521578763395678346621437225972600951965633549602979234732083149655058280123465723210167346545435946648092301500495871307611941306714133444462666462818882418100633983906555894992078138873969482714430788917034883079579778040749973092160959984323579215740942468398437958324399647532773947797685551797171537348210954088256282790659454179075257593928991997283548069103317735700818358235857780570873678690413979416837309542554490385517111819905278234351454124245103700468051202549165577210724696681231918320110736784038063606140146272860", ge_proof.r.get("DELTA").unwrap().to_dec().unwrap());
        assert_eq!("44263308381149662900948673540609137605123483577985225626015193605421446490850432944403510911593807877995566074607735765400382861784877744789798777017960357051684400364048124004882741408393303775593487691064638002920853960645913535484864749193831701910596138125770720981871270085109534802728387292108961395671973015447681340852592012638839948998301809908713998541365956149792695654874324699264455657573099688614830144400409479952124271239106111005380360397720399778640177093636911827538708829123941248898780310301607124559838851222069991204870155414077086348071171421803569856093007812236846764361931252088960485440158830117131468627609450498244887243402854104282374544935516477360120294987311548247220633388905908551822949252630925854555366381978721601629564425954576926076828495554017163967076851067453147787769115012365426065129174495136", ge_proof.alpha.to_dec().unwrap());
    }

    #[test]
    fn test_witness_credential_works() {
        let mut r_claim = mocks::revocation_claim();
        let r_key = mocks::revocation_pub_key();
        let pub_rev_reg = mocks::revocation_reg_public();
        let r_cnxt_m2 = mocks::r_cnxt_m2();

        Prover::_test_witness_credential(&mut r_claim, &r_key, &pub_rev_reg, &r_cnxt_m2).unwrap();
    }

    #[test]
    fn process_claim_works() {
        let (pub_key, priv_key) = issuer::Issuer::new_keys(&issuer::mocks::claim_attributes(), true).unwrap();

        let (mut pub_rev_reg, priv_rev_reg) = issuer::Issuer::new_revocation_registry(&pub_key, 5).unwrap();

        let master_secret = Prover::generate_master_secret().unwrap();

        let (blinded_master_secret, blinded_master_secret_data) =
            Prover::generate_blinded_master_secret(&pub_key, &master_secret).unwrap();

        let claim_attributes = issuer::mocks::claim_attributes_values();

        let mut claim = issuer::Issuer::new_claim(mocks::PROVER_DID, &blinded_master_secret,
                                                  &claim_attributes, &pub_key,
                                                  &priv_key, Some(1), Some(&mut pub_rev_reg), Some(&priv_rev_reg)).unwrap();

        Prover::process_claim(&mut claim, &blinded_master_secret_data, &pub_key, Some(&pub_rev_reg)).unwrap();
    }

    #[test]
    fn test_c_and_tau_list() {
        let r_claim = mocks::revocation_claim();
        let r_key = mocks::revocation_pub_key();
        let pub_rev_reg = mocks::revocation_reg_public();

        let c_list_params = ProofBuilder::_gen_c_list_params(&r_claim).unwrap();

        let proof_c_list = ProofBuilder::_create_c_list_values(&r_claim, &c_list_params, &r_key).unwrap();

        let proof_tau_list = ProofBuilder::create_tau_list_values(&r_key, &pub_rev_reg.acc,
                                                                  &c_list_params, &proof_c_list).unwrap();

        let proof_tau_list_calc = ProofBuilder::create_tau_list_expected_values(&r_key,
                                                                                &pub_rev_reg.acc,
                                                                                &pub_rev_reg.key,
                                                                                &proof_c_list).unwrap();

        assert_eq!(proof_tau_list.as_slice().unwrap(), proof_tau_list_calc.as_slice().unwrap());
    }
}

pub mod mocks {
    use super::*;

    pub const PROVER_DID: &'static str = "CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW";

    pub fn attrs_with_predicates() -> ProofAttrs {
        ProofAttrsBuilder::new().unwrap()
            .add_revealed_attr("name").unwrap()
            .add_unrevealed_attr("height").unwrap()
            .add_unrevealed_attr("age").unwrap()
            .add_unrevealed_attr("sex").unwrap()
            .add_predicate(&predicate()).unwrap()
            .finalize().unwrap()
    }

    pub fn revealed_attrs() -> Vec<String> {
        vec!["name".to_owned()]
    }

    pub fn unrevealed_attrs() -> Vec<String> {
        vec!["height".to_owned(), "age".to_owned(), "sex".to_owned()]
    }

    pub fn claim_revealed_attributes_values() -> ClaimAttributesValues {
        ClaimAttributesValuesBuilder::new().unwrap()
            .add_attr_value("name", "1139481716457488690172217916278103335").unwrap()
            .finalize().unwrap()
    }

    pub fn predicate() -> Predicate {
        Predicate {
            attr_name: "age".to_owned(),
            p_type: PredicateType::GE,
            value: 18
        }
    }

    pub fn master_secret() -> MasterSecret {
        MasterSecret {
            ms: BigNumber::from_dec("21578029250517794450984707538122537192839006240802068037273983354680998203845").unwrap()
        }
    }

    pub fn blinded_master_secret_data() -> BlindedMasterSecretData {
        BlindedMasterSecretData {
            v_prime: primary_blinded_master_secret_data().v_prime,
            vr_prime: Some(GroupOrderElement::new().unwrap())
        }
    }

    pub fn primary_blinded_master_secret_data() -> PrimaryBlindedMasterSecretData {
        PrimaryBlindedMasterSecretData {
            u: BigNumber::from_dec("52982693319842421008184990201947015268353732868477059196316101344419727939823283031817305181875925453167744359037023255221834633832965054467225074176519291575621651089196030498146198911336408448554071520487253844835037529970282500278561005622165228601060377905593734613854740961916904227979842180251700355435141313388128705396165707079202193263966276643558859959605088729108462112879919371292759188833225424588764579052940729574366267393614666789902113871190403578912931962887951912756109724748708515497165946928129756103469424694603593617740295030523761222505663841840164501826022788477454808027338874418124385885064").unwrap(),
            v_prime: BigNumber::from_dec("1921424195886158938744777125021406748763985122590553448255822306242766229793715475428833504725487921105078008192433858897449555181018215580757557939320974389877538474522876366787859030586130885280724299566241892352485632499791646228580480458657305087762181033556428779333220803819945703716249441372790689501824842594015722727389764537806761583087605402039968357991056253519683582539703803574767702877615632257021995763302779502949501243649740921598491994352181379637769188829653918416991301420900374928589100515793950374255826572066003334385555085983157359122061582085202490537551988700484875690854200826784921400257387622318582276996322436").unwrap()
        }
    }

    pub fn claim() -> Claim {
        Claim {
            p_claim: primary_claim(),
            r_claim: Some(revocation_claim())
        }
    }

    pub fn primary_claim() -> PrimaryClaim {
        PrimaryClaim {
            m_2: BigNumber::from_dec("59059690488564137142247698318091397258460906844819605876079330034815387295451").unwrap(),
            a: BigNumber::from_dec("9718041686050466417394454846401911338135485472714675418729730425836367006101286571902254065185334609278478268966285580036221254487921329959035516004179696181846182303481304972520273119065229082628152074260549403953056671718537655331440869269274745137172330211653292094784431599793709932507153005886317395811504324510211401461248180054115028194976434036098410711049411182121148080258018668634613727512389415141820208171799071602314334918435751431063443005717167277426824339725300642890836588704754116628420091486522215319582218755888011754179925774397148116144684399342679279867598851549078956970579995906560499116598").unwrap(),
            e: BigNumber::from_dec("259344723055062059907025491480697571938277889515152306249728583105665800713306759149981690559193987143012367913206299323899696942213235956742930098340478263817667896272954429430903").unwrap(),
            v: BigNumber::from_dec("6477858587997811893327035319417510316563341854132851390093281262022504586945336581881563055213337677056181844572991952555932751996898440671581814053127951224635658321050035511444952581661461627187910434460669459027627147456890732433603419064826350179660439920130024451053677588698924377810206573252996817104905392311087651297242904369072119405731178447311689527558852965235336515327317399731791386249101329130190016387606690470441587455323714369899646882695142389754346148949502193028268930628086102907423247334472635671986918166524901017034444368593822038576239079939991296769079454011618207560042821478623371046256253086080003123462245464426891261800415264830177943676315694882710793222167202116798132497210943950614123537502319388887451156451273696457920098972385375390906181570700610413812857561840771758041019799427").unwrap()
        }
    }

    pub fn revocation_claim() -> NonRevocationClaim {
        NonRevocationClaim {
            sigma: PointG1::from_string("false C8C7213101C60F F625A22E65736C 695A1F398B4787 D087ABB966C5BC 1EA63E37 7895832C96B02C 60C7E086DFA7AF 1518CD71A957F3 C1BED176429FB9 11DD23B3 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD").unwrap(),
            c: GroupOrderElement::from_string("4CF57E7A173E6 27720818863F49 D72801BCE5CBE9 7C8C588E2A8B3B 3642B08").unwrap(),
            vr_prime_prime: GroupOrderElement::from_string("2BC52B6D8B5F4B 26E57208D0DB35 D0411E4BE49639 18A8BC10BF946E 1F8689A5").unwrap(),
            witness: witness(),
            g_i: PointG1::from_string("false 1A5D92950F9D1C 82DB5D4BF49AB8 FBFF5E631AD221 9B89F534C2AC04 165F1606 2E5EE0ECDBB554 F4C238315ACC2 57CAA2D6085FA6 CCE1970A4628E9 119D86E1 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD").unwrap(),
            i: 1,
            m2: GroupOrderElement::from_string("7219C82BC1A5C5 2E958256CDE0D B6FBB94E62AC37 4DAA41B3F577 74DDF3F3").unwrap()
        }
    }

    pub fn primary_init_proof() -> PrimaryInitProof {
        PrimaryInitProof {
            eq_proof: primary_equal_init_proof(),
            ge_proofs: vec![primary_ge_init_proof()]
        }
    }

    pub fn primary_equal_init_proof() -> PrimaryEqualInitProof {
        let a_prime = BigNumber::from_dec("73257086769794587064099943967436413456606137933106600328493517494750494246990095654268081436982110418236942052043392353047210521286732387459211325220702233796797988644175700180272575648844736779152872382353777034795665067764357414889894540956741789789825768184852497440167487735512484852870071737572382353032530574683059753247452767913883743959993537969276743507336201600689240177338100796416706021606300904878397845520702439468069188914120053211111411367694831308267216395648656387187450864371933001748318901589141996368935626664855141812654806676458999719330682612787660793512632367212943940189704480718972567395396").unwrap();
        let t = BigNumber::from_dec("44674566012490574873221338726897300898913972309497258940219569980165585727901128041268469063382008728753943624549705899352321456091543114868302412585283526922484825880307252509503073791126004302810210154078010540383153531873388989179579827245098862102426681204339454264314340301557268884832227229252811218295369187558339702047951827768806306420746905540597187171789203160885305546843423145986246941522359210926851598959302132486285824149905366986262860649723244924769182483122471613582108897710332837686070090582706144278719293684893116662729424191599602937927245245078018737281020133694291784582308345229012480867237").unwrap();
        let e_tilde = BigNumber::from_dec("46977509037563772921188733388482759183920721890892331081711466073993908595985901848331080423617265862263799921846536660789175730995922544").unwrap();
        let e_prime = BigNumber::from_dec("583662989559444524697883298067925567").unwrap();
        let v_tilde = BigNumber::from_dec("555894869457553465718054081820422849162991995390494517944838822333270882977281784453553971006695084899118389412528359884323318041943325476169840344330169758975824153331145070636467566443788129175385227046128007984813738241967046976902336929862121881184186366859109984322069665187530843637401779413855818609802312254476734798474431968023612266562224855762384405063415925635256507132513009629860708092064413558502942291653812837032047514674344515747059720035918093216163460638260675950398390880830578559681142235013420891911126992440292399590994566860624336493535424361894744432273285682724123770355673224752107007429152867080154899799528690990463990548404671629807627523244386129350481398153531931938679507753616503159308561903414993607849227745071552258935672048341133052145284351204037153852982932148831702417091773975188604439616639047752092784493713122927003649804603056886698534968937477985617245235844137536420875188").unwrap();
        let v_prime = BigNumber::from_dec("6385614367009544498316319864543758599368125535237154281129593935195304840005981562825197155593411953165678474906281926931734345545746305450155060321085033621943087275107403410421778410927175029299691621870014311758603481338163542127748609425153803125698411340444632405699004049116623822070114354834294417100495058580661465651621088982873513323615197209830002327017414747343279393904208898726365331869009344688921360397873074029215826510233949892379862093346250740392060647414939231278435894873270850369894735486668772618984555075698111243885998180015446535353880393300721921216798608648100651591884384998694753149400256499979477096295284464637015155612555162482909528968752278735282245702719302108328105954407143650479954196184276137753771191346680837180603858473130837072734570076818412628985088803641214956190551904227").unwrap();
        let m_tilde = mocks::mtilde();

        let m1_tilde = BigNumber::from_dec("17884736668674953594474879343533841182802514514784532835710262264561805009458126297222977824304362311586622997817594769134550513911169868072027461607531074811752832872590561469149850932518336232675337827949722723740491540895259903956542158590123078908328645673377676179125379936830018221094043943562296958727").unwrap();
        let m2_tilde = BigNumber::from_dec("33970939655505026872690051065527896936826240486176548712174703648151652129591217103741946892383483806205993341432925544541557374346350172352729633028700077053528659741067902223562294772771229606274461374185549251388524318740149589263256424345429891975622057372801133454251096604596597737126641279540347411289").unwrap();
        let m2 = BigNumber::from_dec("59059690488564137142247698318091397258460906844819605876079330034815387295451").unwrap();

        PrimaryEqualInitProof {
            a_prime,
            t,
            e_tilde,
            e_prime,
            v_tilde,
            v_prime,
            m_tilde,
            m1_tilde,
            m2_tilde,
            m2
        }
    }

    pub fn primary_ge_init_proof() -> PrimaryPredicateGEInitProof {
        let c_list: Vec<BigNumber> = c_list();
        let tau_list: Vec<BigNumber> = tau_list();

        let mut u: HashMap<String, BigNumber> = HashMap::new();
        u.insert("0".to_string(), BigNumber::from_dec("3").unwrap());
        u.insert("1".to_string(), BigNumber::from_dec("1").unwrap());
        u.insert("2".to_string(), BigNumber::from_dec("0").unwrap());
        u.insert("3".to_string(), BigNumber::from_dec("0").unwrap());

        let mut u_tilde = HashMap::new();
        u_tilde.insert("3".to_string(), BigNumber::from_dec("16150358755672241012460695129321325864817061205875004033795225851087833314854821728249641937105666018799012422371351449632923847984317420011432438475930370578146646594276080296620").unwrap());
        u_tilde.insert("1".to_string(), BigNumber::from_dec("919407332653360714123789350916436306282818598634846737462180851932618353714800404545973780338648396108988603165611273851585136854059054058096491382931469477309021233049221498113").unwrap());
        u_tilde.insert("2".to_string(), BigNumber::from_dec("12947014011443544528806555912324837244278059715103522101625396652490441127598860132430239390604274414152958526164107676952222456505578632937449151556057867144023854768899064453215").unwrap());
        u_tilde.insert("0".to_string(), BigNumber::from_dec("14530430712270780620115716831630456792731829285960002962064509786954277815652219734860240775632969505292366911881157345835853173947767708188332558800388942446379534765685598592954").unwrap());

        let mut r = HashMap::new();
        r.insert("3".to_string(), BigNumber::from_dec("24132544754399620065431039572698185029324955788479147508951988368652141824169968012401631405197526596910936236200501256582143713616923547154109572725575025831049700191992467054494004142728014553921553626557686986621281917316088996263926122140046634865717430166998367117286676599143409419427119266152736056710053609203711125989405212726237071472139024673721365397939677743276201109255641130117429575054170206689862492630448098516389565571101329687068784027116494371890703259752175194377877183611963716122547113191413743333828140272547100543539245187448059851898592306246455570727209949211247659088241502448651714103679374008105070016373294139").unwrap());
        r.insert("1".to_string(), BigNumber::from_dec("35594085114524945986639006224801730200805040269697932198069819550362676659001079845522469651677729918531683925947020457364678961154507874999789223287407843566694331672092132006386937192959717680231086106031364492343223860848813656183321276259834157693100328152560173336039125986710038567259388561327714033873384412441701350106617571828450963146214502461758094005490582378541947089847874178371413274096027707156703414573239039996352851800251963501114749923080129276591522903634133702734684169390809940285496300503809706037270335260091643596848671473612632965738250455900304403753944679890823052654248119197790585118329079277482895324313751745").unwrap());
        r.insert("2".to_string(), BigNumber::from_dec("12416745370495785706540664461803499515274608347250522372751993828760489306351885826979329832840050558190176950831767527159950310255159121407314662120565985630054402779252658020076760721381778346175310011216646031116221826523234356681794951060518746570363532356465500405602755795374789457390143843942758354075220594989212432418989437209512300563151542879411125346015814671481005582531474362744461151940296407107019178307871514140216555328464170666072131235143570187183316375551189197788487022794256230528166132115181407432283810165812226326503815433275045997075793535640301266413926518752768461289738628490190972639107320352430895111692883956").unwrap());
        r.insert("0".to_string(), BigNumber::from_dec("13147719687690861784642987903564117321119171978071399340721977775125245434410955945160797651733662914525457223263144997853255627605012387807755261713043301599172048697597969623088108659945671056128663376565520770635189017427518191119838455865079521045511096967890062994509991531319435529014076721106316221553877061138037619390089975320215668573127020159567603520558367466598464066051208531845265756516199237280615346212300039960390316563876371279899260670556125326105845359198862856997934813787872135942081650066851138525063820953011103923516149849171718879990909755711311066630273647571139362231496658023435123993551625990965120905367877028").unwrap());
        r.insert("DELTA".to_string(), BigNumber::from_dec("27017140706603837321930128683239640314000768158256873249678565317492691240380026575901913931941056190702376634224147699776972092380298850972547700066333918991951816592945434946683483826563040675037562054977204619980251439268131171446694007072677802224789195666130332806561436046366163420230684036395638111654271698281134816476714689333767613969261806762069371304995020522349204504739989730038026877050861981423166431273260095284622132391212425440148029904651623110816052419900003918839190100781461896988942446779821380489281562762932476888984542881369286357081355126723729214222892496254014829234244943392135453620530526273515539280130914262").unwrap());

        let mut r_tilde = HashMap::new();
        r_tilde.insert("3".to_string(), BigNumber::from_dec("1581310419623066984941512700585957369097463841185001482669660807480368207297113764053705737662920865913917179154960493364991851661497939487215481046202935838727534817426357413752818118478480001061422592").unwrap());
        r_tilde.insert("1".to_string(), BigNumber::from_dec("12698175784092390914196064326251972665080818640176357824753635500206769181493592026455460352953871545194375704442227937145765550620924766094755145832764559452913248804386143791786806665433772526875435831").unwrap());
        r_tilde.insert("2".to_string(), BigNumber::from_dec("17862530894611881146644634463381143206639453937332223200502790860790433041682100237129826201980749547269161308100519670647739748120710266271206949459654024958050006488529187007087901262025343947304658469").unwrap());
        r_tilde.insert("0".to_string(), BigNumber::from_dec("2998707557005793821174408437474970579753005270493800573947732417828426843052636578438933523490696647169032669416867456683467729604860634400510897331774306232996333435200605615727332230536004853848724693").unwrap());
        r_tilde.insert("DELTA".to_string(), BigNumber::from_dec("19088233876358835207419091970632588113690065223461360271820393633022806844306658668558786053764082234008649301641061865256819721316329021619475938398765638382289927962244874956969520735922406546981704352").unwrap());

        let alpha_tilde = BigNumber::from_dec("44263308381149662900948673540609137605123483577985225626015193605421446490850432944403510911593807877995566074607735765405553971901390456606499786829482599516431010417531712251971394967321246775153919925111546818075969608334965840293178801177046634728971628794958354733739862829268202974391880631744795540398548558220556991011193251909350421018299683294728391990188211711336282937525988363919530945046525731631119770997772548393939963391123532107813552269482929793072647468150911792469305880140318793207179607757703958258825655827605820657411086482548357455342445528631707138831116535366105159771271994970748831148128639376843296223110470512276276476446567585975474806154081654470617634795717498851405124307682847795651436514926925739847629355175444715922870618554631909406889698383588133721911769288573078161344190971202698069599055089014").unwrap();
        let predicate = predicate();

        let mut t = HashMap::new();
        t.insert("3".to_string(), BigNumber::from_dec("78070105827196661040600041337907173457854153272544487321115604386049561730740327194221314976259005306609156189248394958383576900423218823055146785779218825861357426069962919084354758074120740816717011931695486881373830741590805899909505141118332615581712873355033382526097135102214961582694467049685680521168599662570089045106588071095868679795860083477878392645086886419842393734377034091691861772354369870695105905981921915221671803577058964332747681671537519176296905411380141019477128072347200017918410813327520323098847715450370454307294123150568469231654825506721027060142669757561165103933103053528023034511606").unwrap());
        t.insert("1".to_string(), BigNumber::from_dec("47324660473671124619766812292419966979218618321195442620378932643647808062884161914306007419982240044457291065692968166148732382413212489017818981907451810722427822947434701298426390923083851509190004176754308805544221591456757905034099563880547910682773230595375415855727922588298088826548392572988130537249508717978384646013947582546019729481146325021203427278860772516903057439582612008766763139310189576482839673644190743850755863703998143105224320265752122772813607076484126428361088197863213824404833756768819688779202461859342789097743829182212846809717194485567647846915198890325457736010590303357798473896700").unwrap());
        t.insert("2".to_string(), BigNumber::from_dec("66450517869982062342267997954977032094273479808003128223349391866956221490486227999714708210796649990670474598595144373853545114810461129311488376523373030855652459048816291000188287472254577785187966494209478499264992271438571724964296278469527432908172064052750006541558566871906132838361892473377520708599782848821918665128705358243638618866198451401258608314504494676177177947997456537352832881339718141901132664969277082920274734598386059889447857289735878564021235996969965313779742103257439235693097049742098377325618673992118875810433536654414222034985875962188702260416140781008765351079345681492041353915517").unwrap());
        t.insert("0".to_string(), BigNumber::from_dec("40419298688137869960380469261905532334637639358156591584198474730159922131845236332832025717302613443181736582484815352622543977612852994735900017491040605701377167257840237093127235154905233147231624795995550192527737607707481813233736307936765338317096333960487846640715651848248086837945953304627391859983207411514951469156988685936443758957189790705690990639460733132695525553505807698837031674923144499907591301228015553240722485660599743846214527228665753677346129919027033129697444096042970703607475089467398949054480185324997053077334850238886591657619835566943199882335077289734306701560214493298329372650208").unwrap());
        t.insert("DELTA".to_string(), BigNumber::from_dec("83200684536414956340494235687534491849084621311799273540992839950256544160417513543839780900524522144337818273323604172338904806642960330906344496013294511314421085013454657603118717753084155308020373268668810396333088299295804908264158817923391623116540755548965302906724851186886232431450985279429884730164260492598022651383336322153593491103199117187195782444754665111992163534318072330538584638714508386890137616826706777205862989966213285981526090164444190640439286605077153051456582398200856066916720632647408699812551248250054268483664698756596786352565981324521663234607300070180614929105425712839420242514321").unwrap());

        PrimaryPredicateGEInitProof {
            c_list,
            tau_list,
            u,
            u_tilde,
            r,
            r_tilde,
            alpha_tilde,
            predicate,
            t
        }
    }

    pub fn primary_eq_proof() -> PrimaryEqualProof {
        let m = mocks::mtilde();
        let a_prime = BigNumber::from_dec("78844788312843933904888269033662162831422304046107077675905006898972188325961502973244613809697759885634089891809903260596596204050337720745582204425029325009022804719252242584040122299621227721199828176761231376551096458193462372191787196647068079526052265156928268144134736182005375490381484557881773286686542404542426808122757946974594449826818670853550143124991683881881113838215414675622341721941313438212584005249213398724981821052915678073798488388669906236343688340695052465960401053524210111298793496466799018612997781887930492163394165793209802065308672404407680589643793898593773957386855704715017263075623").unwrap();
        let e = BigNumber::from_dec("157211048330804559357890763556004205033325190265048652432262377822213198765450524518019378474079954420822601420627089523829180910221666161").unwrap();
        let v = BigNumber::from_dec("1284941348270882857396668346831283261477214348763690683497348697824290862398878189368957036860440621466109067749261102013043934190657143812489958705080669016032522931660500036446733706678652522515950127754450934645211652056136276859874236807975473521456606914069014082991239036433172213010731627604460900655694372427254286535318919513622655843830315487127605220061147693872530746405109346050119002875962452785135042012369674224406878631029359470440107271769428236320166308531422754837805075091788368691034173422556029573001095280381990063052098520390497628832466059617626095893334305279839243726801057118958286768204379145955518934076042328930415723280186456582783477760604150368095698975266693968743996433862121883506028239575396951810130540073342769017977933561136433479399747016313456753154246044046173236103107056336293744927119766084120338151498135676089834463415910355744516788140991012773923718618015121004759889110").unwrap();
        let m1 = BigNumber::from_dec("113866224097885880522899498541789692895180427088521824413896638850295809029417413411152277496349590174605786763072969787168775556353363043323193169646869348691540567047982131578875798814721573306665422753535462043941706296398687162611874398835403372887990167434056141368901284989978738291863881602850122461103").unwrap();
        let m2 = BigNumber::from_dec("1323766290428560718316650362032141006992517904653586088737644821361547649912995176966509589375485991923219004461467056332846596210374933277433111217288600965656096366761598274718188430661014172306546555075331860671882382331826185116501265994994392187563331774320231157973439421596164605280733821402123058645").unwrap();
        let revealed_attrs = claim_revealed_attributes_values().attrs_values;

        PrimaryEqualProof {
            revealed_attrs,
            a_prime,
            e,
            v,
            m,
            m1,
            m2
        }
    }

    pub fn primary_ge_proof() -> PrimaryPredicateGEProof {
        let mut u = HashMap::new();
        u.insert("3".to_string(), BigNumber::from_dec("8991055448884746937183597583722774762484126625050383332471998457846949141029373442125727754282056746716432451682903479769768810979073516373079900011730658561904955804441830070201").unwrap());
        u.insert("0".to_string(), BigNumber::from_dec("3119202262454581234238204378430624579411334710168862570697460713017731159978676020931526979958444245337314728482384630008014840583008894200291024490955989484910144381416270825034").unwrap());
        u.insert("1".to_string(), BigNumber::from_dec("15518000836072591312584487513042312668531396837108384118443738039943502537464561749838550874453205824891384223838670020857450197084265206790593562375607300810229831781795248272746").unwrap());
        u.insert("2".to_string(), BigNumber::from_dec("14825520448375036868008852928056676407055827587737481734442472562914657791730493564843449537953640698472823089255666508559183853195339338542320239187247714921656011972820165680495").unwrap());

        let mut r = HashMap::new();
        r.insert("3".to_string(), BigNumber::from_dec("1167550272049401879986208522893402310804598464734091634200466392129423083223947805081084530528884868358954909996620252475186022489983411045778042594227739715134711989282499524985320110488413880945529981664361709639820806122583682452503036404728763373201248045691893015110010852379757063328461525233426468857514764722036069158904178265410282906843586731152479716245390735227750422991960772359397820443448680191460821952125514509645145886564188922269624264085160475580804514964397619916759653999513671049924196777087113468144988512960417719152393266552894992285322714901696251664710315454136548433461200202231002410586808552657105706728516271798034029334358544147228606049936435037524531381025620665456890088546982587481").unwrap());
        r.insert("0".to_string(), BigNumber::from_dec("2171447327600461898681893459994311075091382696626274737692544709852701253236804421376958076382402020619134253300345593917220742679092835017076022500855973864844382438540332185636399240848767743775256306580762848493986046436797334807658055576925997185840670777012790272251814692816605648587784323426613630301003579746571336649678357714763941128273025862159957664671610945626170382202342056873023285304345808387951726158704872306035900016749011783867480420800998854987117527975876541158475438393405152741773026550341616888761476445877989444379785612563226680131486775899233053750237483379057705217586225573410360257816090005804925119313735493995305192861301036330809025262997449946935113898554709938543261959225374477075").unwrap());
        r.insert("1".to_string(), BigNumber::from_dec("3407533923994509079922445260572851360802767657194628749769491907793892136495870984243826839220225896118619529161581266999433926347085222629115870923342232719053144390143744050810102224808038416215236832553566711013172199073782742820257909889682618205836240882137941793761945944591631439539425000764465713533076522478368670386820666288924406010336355943518262201405259934614234952964126592210374867434305756945477124161456667354597660261751805125868686764527511228958421917556551368867158045859243933424656693853034751832910802366824624573129457523599814696599411287253040266911475142776766859495751666393668865554821250239426074473894708324406330875647014186109228413419914784738994090638263427510209053496949212198772").unwrap());
        r.insert("2".to_string(), BigNumber::from_dec("376615807259433852994889736265571130722120467111857816971887754558663859714462971707188421230515343999387984197735177426886431376277830270779207802969001925574986158648382233404297833366166880771649557924045749558608142093651421705548864007094298410821850827506796116657011958581079961108367131644360333951829519859638856960948927313849945546613528932570789799649277584112030378539271377025534526299113938027086859429617232980159899286261874751664992426761978572712284693482352940080544009977987614687886895144698432208930945866456583811087222056104304977238806342842107136621744373848258397836622192179796587657390442772422614921141854089119770642649923852479045626615424086862226766993260016650650800970901479317353").unwrap());
        r.insert("DELTA".to_string(), BigNumber::from_dec("1204576405206979680375064721017725873269565442920750053860275824473279578144966505696401529388362488618656880602103746663719014543804181028271885056878992356241850630746057861156554344680578591346709669594164380854748723108090171168846365315480163847141547319673663867587891086140001578226570294284600635554860177021112021218221677503541742648400417051405848715777401449235718828129001371122909809318916605795606301174787694751963509104301818268975054567300992103690013595997066100692742805505022623908866248955309724353017333598591476683281090839126513676860390307767387899158218974766900357521082392372102989396002839389060003178573720443299965136555923047732519831454019881161819607825392645740545819410001935871296").unwrap());

        let mut t = HashMap::new();
        t.insert("3".to_string(), BigNumber::from_dec("83832511302317350174644720338005868487742959910398469815023175597193018639890917887543705415062101786582256768017066777905945250455529792569435063542128440269870355757494523489777576305013971151020301795930610571616963448640783534486881066519012584090452409312729129595716959074161404190572673909049999235573789134838668875246480910001667440875590464739356588846924490130540148723881221509872798683154070397912008198847917146244304739030407870533464478489905826281941434008283229667189082264792381734035454956041612257154896426092221951083981809288053249503709950518771668342922637895684467584044654762057518028814700").unwrap());
        t.insert("0".to_string(), BigNumber::from_dec("17363331019061087402844209719893765371888392521507799534029693411314419650156431062459421604096282340039952269582687900721960971874670054761709293109949110830813780630203308029471950250261299362249372820231198558841826592697963838759408960504585788309222390217432925946851327016608993387530098618165007004227557481762160406061606398711655197702267307202795893150693539328844268725519498759780370661097817433632221804533430784357877040495807116168272952720860492630103774088576448694803769740862452948066783609506217979920299119838909533940158375124964345812560749245376080673497973923586841616454700487914362471202008").unwrap());
        t.insert("1".to_string(), BigNumber::from_dec("89455656994262898696010620361749819360237582245028725962970005737051728267174145415488622733389621460891337449519650169354661297765474368093442921019918627430103490796403713184394321040862188347280121162030527387297914106124615295029438860483643206878385030782115461217026682705339179345799048771007488017061121097664849533202200732993683759185652675229998618989002320091590048075901070991065565826421958646807185596723738384036684650647137579559949478266162844209656689415344016818360348356312264086908726131174312873340317036154962789954493075076421104496622960243079994511377273760209424275802376704240224057017113").unwrap());
        t.insert("2".to_string(), BigNumber::from_dec("89410264446544582460783108256046283919076319065430050325756614584399852372030797406836188839188658589044450904082852710142004660134924756488845128162391217899779712577616690285325130344040888345830793786702389605089886670947913310987447937415013394798653152944186602375622211523989869906842514688368412364643177924764258301720702233619449643601070324239497432310281518069485140179427484578654078080286588210649780194784918635633853990818152978680101738950391705291308278990621417475783919318775532419526399483870315453680012214346133208277396870767376190499172447005639213621681954563685885258611100453847030057210573").unwrap());
        t.insert("DELTA".to_string(), BigNumber::from_dec("17531299058220149467416854489421567897910338960471902975273408583568522392255499968302116890306524687486663687730044248160210339238863476091064742601815037120574733471494286906058476822621292173298642666511349405172455078979126802123773531891625097004911163338483230811323704803366602873408421785889893292223666425119841459293545405397943817131052036368166012943639154162916778629230509814424319368937759879498990977728770262630904002681927411874415760739538041907804807946503694675967291621468790462606280423096949972217261933741626487585406950575711867888842552544895574858154723208928052348208022999454364836959913").unwrap());

        let predicate = predicate();

        let mj = BigNumber::from_dec("1603425011106247404410993992231356816212687443774810147917707956054468639246061842660922922638282972213339086692783888162583747872610530439675358599658842676000681975294259033921").unwrap();
        let alpha = BigNumber::from_dec("10356391427643160498096100322044181597098497015522243313140952718701540840206124784483254227685815326973121415131868716208997744531667356503588945389793642286002145762891552961662804737699174847630739288154243345749050494830443436382280881466833601915627397601315033369264534756381669075511238130934450573103942299767277725603498732898775126784825329479233488928873905649944203334284969529288341712039042121593832892633719941366126598676503928077684908261211960615121039788257179455497199714100480379742080080363623749544442225600170310016965613238530651846654311018291673656192911252359090044631268913200633654215640107245506757349629342277896334140999154991920063754025485899126293818842601918101509689122011832619551509675197082794490012616416413823359927604558553776550532965415598441778103806673039612795460783658848060332784778084904").unwrap();

        PrimaryPredicateGEProof {
            u,
            r,
            mj,
            alpha,
            t,
            predicate
        }
    }

    pub fn c_list() -> Vec<BigNumber> {
        let mut c_list: Vec<BigNumber> = Vec::new();
        c_list.push(BigNumber::from_dec("40419298688137869960380469261905532334637639358156591584198474730159922131845236332832025717302613443181736582484815352622543977612852994735900017491040605701377167257840237093127235154905233147231624795995550192527737607707481813233736307936765338317096333960487846640715651848248086837945953304627391859983207411514951469156988685936443758957189790705690990639460733132695525553505807698837031674923144499907591301228015553240722485660599743846214527228665753677346129919027033129697444096042970703607475089467398949054480185324997053077334850238886591657619835566943199882335077289734306701560214493298329372650208").unwrap());
        c_list.push(BigNumber::from_dec("47324660473671124619766812292419966979218618321195442620378932643647808062884161914306007419982240044457291065692968166148732382413212489017818981907451810722427822947434701298426390923083851509190004176754308805544221591456757905034099563880547910682773230595375415855727922588298088826548392572988130537249508717978384646013947582546019729481146325021203427278860772516903057439582612008766763139310189576482839673644190743850755863703998143105224320265752122772813607076484126428361088197863213824404833756768819688779202461859342789097743829182212846809717194485567647846915198890325457736010590303357798473896700").unwrap());
        c_list.push(BigNumber::from_dec("66450517869982062342267997954977032094273479808003128223349391866956221490486227999714708210796649990670474598595144373853545114810461129311488376523373030855652459048816291000188287472254577785187966494209478499264992271438571724964296278469527432908172064052750006541558566871906132838361892473377520708599782848821918665128705358243638618866198451401258608314504494676177177947997456537352832881339718141901132664969277082920274734598386059889447857289735878564021235996969965313779742103257439235693097049742098377325618673992118875810433536654414222034985875962188702260416140781008765351079345681492041353915517").unwrap());
        c_list.push(BigNumber::from_dec("78070105827196661040600041337907173457854153272544487321115604386049561730740327194221314976259005306609156189248394958383576900423218823055146785779218825861357426069962919084354758074120740816717011931695486881373830741590805899909505141118332615581712873355033382526097135102214961582694467049685680521168599662570089045106588071095868679795860083477878392645086886419842393734377034091691861772354369870695105905981921915221671803577058964332747681671537519176296905411380141019477128072347200017918410813327520323098847715450370454307294123150568469231654825506721027060142669757561165103933103053528023034511606").unwrap());
        c_list.push(BigNumber::from_dec("83200684536414956340494235687534491849084621311799273540992839950256544160417513543839780900524522144337818273323604172338904806642960330906344496013294511314421085013454657603118717753084155308020373268668810396333088299295804908264158817923391623116540755548965302906724851186886232431450985279429884730164260492598022651383336322153593491103199117187195782444754665111992163534318072330538584638714508386890137616826706777205862989966213285981526090164444190640439286605077153051456582398200856066916720632647408699812551248250054268483664698756596786352565981324521663234607300070180614929105425712839420242514321").unwrap());
        c_list
    }

    pub fn tau_list() -> Vec<BigNumber> {
        let mut tau_list: Vec<BigNumber> = Vec::new();
        tau_list.push(BigNumber::from_dec("15140192132563983584011198891415484817238186596993071283607396936354194583335316868900705320271111009411714831320691337831872126628439138871262533224307544703281477371807698525452223425670200750605763418449125326560417154215882193420051788620324946208921285413124444012185102142014009066082073507405990774347752529726721364286432450040059237148949753473594808640751722631907871436041823113427561411327410265647850452755588149194739107401612541934957588751200713263042014153310254117194222238408605703075357183065968515077548856751608663405886764709143763920973999261289863795465373404979606051217224017793032766958811").unwrap());
        tau_list.push(BigNumber::from_dec("22009325014877947630026527174200929317631472626208750791313439728894802205941501133457483305053287492055711395025700211096925855401324104745196675112371703883854338747182592204009840178348481147164357644090276358774264356146958774854024112737375489364695008508208970224155188285475467990251456534404860303212995739991780462885489625391318647267043983051823985749109827583921702054401295234951443763803867227290052184122075487663670525999631601499287795787258527407755075616126319202755499894030817914291589449384977544252255991849316879972035322419088010097341651222610917507166699253633464412656939604939686927779235").unwrap());
        tau_list.push(BigNumber::from_dec("15627964533527004998432038389165000103816136005375029988964505427070988976134211606408535227344041158417145070028255238801455392103113521695579086689578896155932875705490340075005561484163012535940306402641682521571945553659305990483808164193225425501204573377669678891599593106986761315653866565476157194483433336149271900598697489496190572244872015009221591483425535935884303531919258635347941316161540221899064295767010090897562893601204666639265613355995553950307149582738593763092807462903005018385092974255197604160149549388615872030971412913398039602109611976167048531483220445501083739737215277412870810099396").unwrap());
        tau_list.push(BigNumber::from_dec("69750460164463503832019239074179380223142417821933331668103242458939803887386159332871378045711353326082354712806990538579597154273250741009953395178245637905378411876747452614509288221818672025545306689963691675579404059572899417172145497523547047512889912370926674344888289753106210072610765364142940872887546059041780799075090797522396305865608421376284813869031711915938763531973096410258282809600437536302255350228578137679993463517124512267300176775839875875909783384538534171446077525775056641425609563775679897591880695823828105351526687827332736948255168213703139146311683168485769607106041873644234793657396").unwrap());
        tau_list.push(BigNumber::from_dec("34132763173107445610560830841313898488394524485228364539925353006770404496634510086661879191043246497239583692381010279276417009418352322742486751048568992101518984018378013150772900354967187656947771069077786822194631197139777633372530138823901112650920148029338833974489530448873513107614207475925912746846289211981300599307572467810317763139839748754562514339971268176553099225860038153231205184249842168570757272245458275526022597007402749355980752036595066753740086758919247309876789184990621533422299096077633094437542715030347647138342894730223750339935127139185670656368946989949841411629192230558551287266526").unwrap());
        tau_list.push(BigNumber::from_dec("76565683231858220413634970348355655533884193896594121193316140338326831295635725256889489793041881623418796770530744437643757750818290670869856629404442102804539779790470943920985982547126806372689451469829385561786853754658793672376584770590680698494872039421566522136994135799785364832139155336348898806149875050003083388070895449937350438703463774379388035785060136940608144835006837349223795491316522482304986804930841801932706957303647124712691616546214050336437883359026928636182057382080150720957312738870036121843132512663050961368923639527157611326078923388898194496216008348568701317636330495889266691635504").unwrap());
        tau_list
    }

    pub fn mtilde() -> HashMap<String, BigNumber> {
        let mut mtilde = HashMap::new();
        mtilde.insert("height".to_string(), BigNumber::from_dec("3373978431761662936864523680216977257584610980616339878140476966372383023266465253136551434714889555651032143048543421334122669369824546771790431199967902091704924294162747998714").unwrap());
        mtilde.insert("age".to_string(), BigNumber::from_dec("2976250595835739181594320238227653601426197318110939190760657852629456864395726135468275792741622450579986141053384483916124587493975756840689906672199964644984465423799113422915").unwrap());
        mtilde.insert("sex".to_string(), BigNumber::from_dec("1038496187132038951426769629254464579084684144036750642303206209710591608223417014007881207499688569061414518819199568509614376078846399946097722727271077857527181666924731796053").unwrap());
        mtilde
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