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

    pub fn generate_blinded_master_secret(p_pub_key: &IssuerPrimaryPublicKey,
                                          r_pub_key: &Option<IssuerRevocationPublicKey>,
                                          ms: &MasterSecret) -> Result<(BlindedMasterSecret,
                                                                        BlindedMasterSecretData), IndyCryptoError> {
        let blinded_primary_master_secret = Prover::_generate_blinded_primary_master_secret(&p_pub_key, &ms)?;

        let blinded_revocation_master_secret = match r_pub_key {
            &Some(ref r_pk) => Some(Prover::_generate_blinded_revocation_master_secret(r_pk)?),
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

    pub fn _generate_blinded_primary_master_secret(p_pub_key: &IssuerPrimaryPublicKey,
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

    pub fn _generate_blinded_revocation_master_secret(r_pub_key: &IssuerRevocationPublicKey) -> Result<RevocationBlindedMasterSecretData, IndyCryptoError> {
        let vr_prime = GroupOrderElement::new()?;
        let ur = r_pub_key.h2.mul(&vr_prime)?;

        Ok(RevocationBlindedMasterSecretData { ur, vr_prime })
    }

    pub fn process_claim(claim: &mut Claim,
                         blinded_master_secret_data: &BlindedMasterSecretData,
                         r_pub_key: &Option<IssuerRevocationPublicKey>,
                         r_reg: &Option<RevocationRegistryPublic>) -> Result<(), IndyCryptoError> {
        Prover::process_primary_claim(&mut claim.p_claim, &blinded_master_secret_data.v_prime)?;

        if let (&mut Some(ref mut non_revocation_claim), Some(ref vr_prime), &Some(ref r_key), &Some(ref r_reg)) = (&mut claim.r_claim,
                                                                                                                    blinded_master_secret_data.vr_prime,
                                                                                                                    r_pub_key,
                                                                                                                    r_reg) {
            Prover::process_non_revocation_claim(non_revocation_claim,
                                                 vr_prime,
                                                 &r_key,
                                                 r_reg)?;
        }
        Ok(())
    }

    pub fn process_primary_claim(p_claim: &mut PrimaryClaim,
                                 v_prime: &BigNumber) -> Result<(), IndyCryptoError> {
        p_claim.v = v_prime.add(&p_claim.v)?;
        Ok(())
    }

    pub fn process_non_revocation_claim(r_claim: &mut NonRevocationClaim,
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

pub struct ProofBuilder {
    pub m1_tilde: BigNumber,
    pub init_proofs: HashMap<String, InitProof>,
    pub c_list: Vec<Vec<u8>>,
    pub tau_list: Vec<Vec<u8>>,
    pub proof_claims: HashMap<String, ProofClaims>,
}

impl ProofBuilder {
    pub fn new() -> Result<ProofBuilder, IndyCryptoError> {
        Ok(ProofBuilder {
            m1_tilde: rand(LARGE_M2_TILDE)?,
            init_proofs: HashMap::new(),
            c_list: Vec::new(),
            tau_list: Vec::new(),
            proof_claims: HashMap::new()
        })
    }

    pub fn add_claim(&mut self, uuid: &str, claim: ClaimInfo, p_pub_key: IssuerPublicKey,
                     r_pub_key: Option<IssuerRevocationPublicKey>, r_reg: Option<RevocationRegistryPublic>,
                     attrs_with_predicates: AttrsWithPredicates) -> Result<(), IndyCryptoError> {
        self.proof_claims.insert(uuid.to_owned(),
                                 ProofClaims {
                                     claim,
                                     p_pub_key,
                                     r_pub_key,
                                     r_reg,
                                     attrs_with_predicates
                                 });
        Ok(())
    }

    pub fn finalize(&mut self, proof_req: &ProofRequest, ms: MasterSecret) -> Result<FullProof, IndyCryptoError> {
        for (proof_claim_uuid, ref mut proof_claim) in &self.proof_claims {
            let mut non_revoc_init_proof = None;
            let mut m2_tilde: Option<BigNumber> = None;

            if let (&Some(ref r_claim), &Some(ref r_reg), &Some(ref r_pub_key)) = (&proof_claim.claim.signature.r_claim,
                                                                                   &proof_claim.r_reg,
                                                                                   &proof_claim.r_pub_key) {
                let proof = ProofBuilder::_init_non_revocation_proof(&mut r_claim.clone(), r_reg, &r_pub_key)?;//TODO

                self.c_list.extend_from_slice(&proof.as_c_list()?);
                self.tau_list.extend_from_slice(&proof.as_tau_list()?);
                m2_tilde = Some(group_element_to_bignum(&proof.tau_list_params.m2)?);
                non_revoc_init_proof = Some(proof);
            }

            let primary_init_proof = ProofBuilder::_init_proof(&proof_claim.p_pub_key,
                                                               &proof_claim.claim.signature.p_claim,
                                                               &proof_claim.claim.claim,
                                                               &proof_claim.attrs_with_predicates,
                                                               &self.m1_tilde,
                                                               m2_tilde)?;

            self.c_list.extend_from_slice(&primary_init_proof.as_c_list()?);
            self.tau_list.extend_from_slice(&primary_init_proof.as_tau_list()?);

            let init_proof = InitProof { primary_init_proof, non_revoc_init_proof };

            self.init_proofs.insert(proof_claim_uuid.to_owned(), init_proof);
        }

        let mut values: Vec<Vec<u8>> = Vec::new();
        values.extend_from_slice(&self.tau_list);
        values.extend_from_slice(&self.c_list);
        values.push(proof_req.nonce.to_bytes()?);

        let c_h = get_hash_as_int(&mut values)?;

        let mut proofs: HashMap<String, ClaimProof> = HashMap::new();
        let mut attributes: HashMap<String, HashMap<String, Vec<String>>> = HashMap::new();

        for (proof_claim_uuid, init_proof) in self.init_proofs.iter() {
            let proof_claim = self.proof_claims.get(proof_claim_uuid)
                .ok_or(IndyCryptoError::InvalidState(format!("Claim not found")))?;

            let mut non_revoc_proof: Option<NonRevocProof> = None;
            if let Some(ref non_revoc_init_proof) = init_proof.non_revoc_init_proof {
                non_revoc_proof = Some(ProofBuilder::_finalize_non_revocation_proof(&non_revoc_init_proof,
                                                                                    &c_h)?);
            }

            let primary_proof = ProofBuilder::_finalize_proof(&ms.ms,
                                                              &init_proof.primary_init_proof,
                                                              &c_h,
                                                              &proof_claim.claim.claim,
                                                              &proof_claim.attrs_with_predicates)?;

            let proof = Proof { primary_proof, non_revoc_proof };

            let claim_proof = ClaimProof {
                proof,
                schema_seq_no: proof_claim.claim.schema_seq_no,
                issuer_did: proof_claim.claim.issuer_did.to_owned()
            };

            proofs.insert(proof_claim_uuid.to_owned(), claim_proof);
        }

        let aggregated_proof = AggregatedProof { c_hash: c_h, c_list: self.c_list.clone() };

        Ok(FullProof { proofs, aggregated_proof })
    }

    fn _init_proof(pk: &IssuerPublicKey, c1: &PrimaryClaim, attributes: &HashMap<String, Vec<String>>,
                   attr_with_predicates: &AttrsWithPredicates, m1_t: &BigNumber,
                   m2_t: Option<BigNumber>) -> Result<PrimaryInitProof, IndyCryptoError> {
        let eq_proof = ProofBuilder::_init_eq_proof(&pk.p_key, c1, &attr_with_predicates,
                                                    m1_t, m2_t)?;

        let mut ge_proofs: Vec<PrimaryPredicateGEInitProof> = Vec::new();
        for predicate in attr_with_predicates.predicates.iter() {
            let ge_proof = ProofBuilder::_init_ge_proof(&pk.p_key, &eq_proof.mtilde, attributes, predicate)?;
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
        let proof_tau_list = ProofBuilder::_create_tau_list_values(&pkr, &rev_reg.acc, &tau_list_params, &proof_c_list)?;

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
            let v_new_minus_old: HashSet<u32> =
                accum.v.difference(&claim.witness.v).cloned().collect();
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

    fn _init_eq_proof(pk: &IssuerPrimaryPublicKey, c1: &PrimaryClaim, attr_with_predicates: &AttrsWithPredicates,
                      m1_tilde: &BigNumber, m2_t: Option<BigNumber>) -> Result<PrimaryEqualInitProof, IndyCryptoError> {
        let mut ctx = BigNumber::new_context()?;

        let m2_tilde = m2_t.unwrap_or(rand(LARGE_MVECT)?);

        let r = rand(LARGE_VPRIME)?;
        let etilde = rand(LARGE_ETILDE)?;
        let vtilde = rand(LARGE_VTILDE)?;

        let mtilde = get_mtilde(&attr_with_predicates.unrevealed_attrs)?;

        let a_prime = pk.s
            .mod_exp(&r, &pk.n, Some(&mut ctx))?
            .mul(&c1.a, Some(&mut ctx))?
            .modulus(&pk.n, Some(&mut ctx))?;

        let large_e_start = BigNumber::from_dec(&LARGE_E_START.to_string())?;

        let vprime = c1.v.sub(
            &c1.e.mul(&r, Some(&mut ctx))?
        )?;

        let eprime = c1.e.sub(
            &BigNumber::from_dec("2")?.exp(&large_e_start, Some(&mut ctx))?
        )?;

        let t = ProofBuilder::calc_teq(&pk, &a_prime, &etilde, &vtilde, &mtilde, &m1_tilde,
                                       &m2_tilde, &attr_with_predicates.unrevealed_attrs)?;

        Ok(PrimaryEqualInitProof {
            a_prime,
            t,
            etilde,
            eprime,
            vtilde,
            vprime,
            mtilde,
            m1_tilde: m1_tilde.clone()?,
            m2_tilde: m2_tilde.clone()?,
            m2: c1.m_2.clone()?
        })
    }

    fn _init_ge_proof(pk: &IssuerPrimaryPublicKey, mtilde: &HashMap<String, BigNumber>,
                      encoded_attributes: &HashMap<String, Vec<String>>, predicate: &Predicate)
                      -> Result<PrimaryPredicateGEInitProof, IndyCryptoError> {
        let mut ctx = BigNumber::new_context()?;
        let (k, value) = (&predicate.attr_name, predicate.value);

        let attr_value = encoded_attributes.get(&k[..])
            .ok_or(IndyCryptoError::InvalidStructure(format!("Value by key '{}' not found in c1.encoded_attributes", k)))?
            .get(0)
            .ok_or(IndyCryptoError::InvalidStructure(format!("Value not found in c1.encoded_attributes")))?
            .parse::<i32>()
            .map_err(|err|
                IndyCryptoError::InvalidStructure(format!("Value by key '{}' has invalid format", k)))?;

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

        let tau_list = ProofBuilder::calc_tge(&pk, &u_tilde, &r_tilde, &mj, &alpha_tilde, &t)?;

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
                          encoded_attributes: &HashMap<String, Vec<String>>, attrs_with_predicates: &AttrsWithPredicates)
                          -> Result<PrimaryEqualProof, IndyCryptoError> {
        let mut ctx = BigNumber::new_context()?;

        let e = c_h
            .mul(&init_proof.eprime, Some(&mut ctx))?
            .add(&init_proof.etilde)?;

        let v = c_h
            .mul(&init_proof.vprime, Some(&mut ctx))?
            .add(&init_proof.vtilde)?;

        let mut m: HashMap<String, BigNumber> = HashMap::new();

        for k in attrs_with_predicates.unrevealed_attrs.iter() {
            let cur_mtilde = init_proof.mtilde.get(k)
                .ok_or(IndyCryptoError::InvalidStructure(format!("Value by key '{}' not found in init_proof.mtilde", k)))?;
            let cur_val = encoded_attributes.get(k)
                .ok_or(IndyCryptoError::InvalidStructure(format!("Value by key '{}' not found in encoded_attributes", k)))?
                .get(1)
                .ok_or(IndyCryptoError::InvalidStructure(format!("Encoded Value not found in encoded_attributes")))?;

            let val = c_h
                .mul(&BigNumber::from_dec(cur_val)?,
                     Some(&mut ctx))?
                .add(&cur_mtilde)?;

            m.insert(k.clone(), val);
        }

        let m1 = c_h
            .mul(&ms, Some(&mut ctx))?
            .add(&init_proof.m1_tilde)?;

        let m2 = c_h
            .mul(&init_proof.m2, Some(&mut ctx))?
            .add(&init_proof.m2_tilde)?;


        let mut revealed_attrs_with_values: HashMap<String, String> = HashMap::new();

        for attr in attrs_with_predicates.revealed_attrs.iter() {
            revealed_attrs_with_values.insert(
                attr.clone(),
                encoded_attributes
                    .get(attr)
                    .ok_or(IndyCryptoError::InvalidStructure(format!("Encoded value not found")))?
                    .get(1)
                    .ok_or(IndyCryptoError::InvalidStructure(format!("Encoded value not found")))?
                    .clone(),
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
                       encoded_attributes: &HashMap<String, Vec<String>>, attrs_with_predicates: &AttrsWithPredicates)
                       -> Result<PrimaryProof, IndyCryptoError> {
        info!(target: "anoncreds_service", "Prover finalize proof -> start");

        let eq_proof = ProofBuilder::_finalize_eq_proof(ms, &init_proof.eq_proof, c_h, encoded_attributes, attrs_with_predicates)?;
        let mut ge_proofs: Vec<PrimaryPredicateGEProof> = Vec::new();

        for init_ge_proof in init_proof.ge_proofs.iter() {
            let ge_proof = ProofBuilder::_finalize_ge_proof(c_h, init_ge_proof, &eq_proof)?;
            ge_proofs.push(ge_proof);
        }

        info!(target: "anoncreds_service", "Prover finalize proof -> done");

        Ok(PrimaryProof { eq_proof, ge_proofs })
    }

    pub fn calc_tge(pk: &IssuerPrimaryPublicKey, u: &HashMap<String, BigNumber>, r: &HashMap<String, BigNumber>,
                    mj: &BigNumber, alpha: &BigNumber, t: &HashMap<String, BigNumber>)
                    -> Result<Vec<BigNumber>, IndyCryptoError> {
        let mut tau_list: Vec<BigNumber> = Vec::new();
        let mut ctx = BigNumber::new_context()?;

        for i in 0..ITERATION {
            let cur_u = u.get(&i.to_string())
                .ok_or(IndyCryptoError::InvalidStructure(format!("Value by key '{}' not found in u", i)))?;
            let cur_r = r.get(&i.to_string())
                .ok_or(IndyCryptoError::InvalidStructure(format!("Value by key '{}' not found in r", i)))?;

            let t_tau = pk.z
                .mod_exp(&cur_u, &pk.n, Some(&mut ctx))?
                .mul(
                    &pk.s.mod_exp(&cur_r, &pk.n, Some(&mut ctx))?,
                    Some(&mut ctx)
                )?
                .modulus(&pk.n, Some(&mut ctx))?;

            tau_list.push(t_tau);
        }

        let delta = r.get("DELTA")
            .ok_or(IndyCryptoError::InvalidStructure(format!("Value by key '{}' not found in r", "DELTA")))?;


        let t_tau = pk.z
            .mod_exp(&mj, &pk.n, Some(&mut ctx))?
            .mul(
                &pk.s.mod_exp(&delta, &pk.n, Some(&mut ctx))?,
                Some(&mut ctx)
            )?
            .modulus(&pk.n, Some(&mut ctx))?;

        tau_list.push(t_tau);

        let mut q: BigNumber = BigNumber::from_dec("1")?;

        for i in 0..ITERATION {
            let cur_t = t.get(&i.to_string())
                .ok_or(IndyCryptoError::InvalidStructure(format!("Value by key '{}' not found in t", i)))?;
            let cur_u = u.get(&i.to_string())
                .ok_or(IndyCryptoError::InvalidStructure(format!("Value by key '{}' not found in u", i)))?;

            q = cur_t
                .mod_exp(&cur_u, &pk.n, Some(&mut ctx))?
                .mul(&q, Some(&mut ctx))?;
        }

        q = pk.s
            .mod_exp(&alpha, &pk.n, Some(&mut ctx))?
            .mul(&q, Some(&mut ctx))?
            .modulus(&pk.n, Some(&mut ctx))?;

        tau_list.push(q);

        Ok(tau_list)
    }

    pub fn calc_teq(pk: &IssuerPrimaryPublicKey, a_prime: &BigNumber, e: &BigNumber, v: &BigNumber,
                    mtilde: &HashMap<String, BigNumber>, m1tilde: &BigNumber, m2tilde: &BigNumber,
                    unrevealed_attrs: &Vec<String>) -> Result<BigNumber, IndyCryptoError> {
        let mut ctx = BigNumber::new_context()?;
        let mut result: BigNumber = BigNumber::from_dec("1")?;

        for k in unrevealed_attrs.iter() {
            let cur_r = pk.r.get(k)
                .ok_or(IndyCryptoError::InvalidStructure(format!("Value by key '{}' not found in pk.r", k)))?;
            let cur_m = mtilde.get(k)
                .ok_or(IndyCryptoError::InvalidStructure(format!("Value by key '{}' not found in mtilde", k)))?;

            result = cur_r
                .mod_exp(&cur_m, &pk.n, Some(&mut ctx))?
                .mul(&result, Some(&mut ctx))?;
        }

        result = pk.rms
            .mod_exp(&m1tilde, &pk.n, Some(&mut ctx))?
            .mul(&result, Some(&mut ctx))?;

        result = pk.rctxt
            .mod_exp(&m2tilde, &pk.n, Some(&mut ctx))?
            .mul(&result, Some(&mut ctx))?;

        result = a_prime
            .mod_exp(&e, &pk.n, Some(&mut ctx))?
            .mul(&result, Some(&mut ctx))?;

        result = pk.s
            .mod_exp(&v, &pk.n, Some(&mut ctx))?
            .mul(&result, Some(&mut ctx))?
            .modulus(&pk.n, Some(&mut ctx))?;

        Ok(result)
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

    pub fn _create_tau_list_values(pk_r: &IssuerRevocationPublicKey, accumulator: &RevocationAccumulator,
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

    pub fn _create_tau_list_expected_values(pk_r: &IssuerRevocationPublicKey, accumulator: &RevocationAccumulator,
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
        assert_eq!(ms.ms.to_dec().unwrap(), "21578029250517794450984707538122537192839006240802068037273983354680998203845");
    }

    #[test]
    fn generate_blinded_primary_master_secret_works() {
        let pk = issuer::mocks::issuer_primary_public_key();
        let ms = super::mocks::master_secret();

        let blinded_primary_master_secret = Prover::_generate_blinded_primary_master_secret(&pk, &ms).unwrap();

        assert_eq!(blinded_primary_master_secret.v_prime.to_dec().unwrap(), "1921424195886158938744777125021406748763985122590553448255822306242766229793715475428833504725487921105078008192433858897449555181018215580757557939320974389877538474522876366787859030586130885280724299566241892352485632499791646228580480458657305087762181033556428779333220803819945703716249441372790689501824842594015722727389764537806761583087605402039968357991056253519683582539703803574767702877615632257021995763302779502949501243649740921598491994352181379637769188829653918416991301420900374928589100515793950374255826572066003334385555085983157359122061582085202490537551988700484875690854200826784921400257387622318582276996322436");
        assert_eq!(blinded_primary_master_secret.u.to_dec().unwrap(), "76242448573590064405016258439737389305308751658939430245286640100438960019281437749200830095828154995656490316795623959413004501644803662299479412591058642431687903660665344655065168625525452586969727169375623723517902861969847048691526377607004762208719937819914640316377295513994692345889814194525691804485221810462520684486465466644645762808386096321825027491677390741996765477089812850102636281290306349225021109750689221122813209585062598487297616077690207210647793480450738894724087937015208576263139374972514675875069264408157796307069688316536519870595147545540606129541475897775356097530317320274539032783922");
    }

    #[test]
    fn generate_blinded_revocation_master_secret_works() {
        let r_pk = issuer::mocks::issuer_revocation_public_key();
        Prover::_generate_blinded_revocation_master_secret(&r_pk).unwrap();
    }

    #[test]
    fn generate_blinded_master_secret_works() {
        let pk = issuer::mocks::issuer_primary_public_key();
        let r_pk = issuer::mocks::issuer_revocation_public_key();
        let ms = super::mocks::master_secret();

        let (blinded_master_secret, blinded_master_secret_data) = Prover::generate_blinded_master_secret(&pk, &Some(r_pk), &ms).unwrap();

        assert_eq!(blinded_master_secret_data.v_prime.to_dec().unwrap(), "1921424195886158938744777125021406748763985122590553448255822306242766229793715475428833504725487921105078008192433858897449555181018215580757557939320974389877538474522876366787859030586130885280724299566241892352485632499791646228580480458657305087762181033556428779333220803819945703716249441372790689501824842594015722727389764537806761583087605402039968357991056253519683582539703803574767702877615632257021995763302779502949501243649740921598491994352181379637769188829653918416991301420900374928589100515793950374255826572066003334385555085983157359122061582085202490537551988700484875690854200826784921400257387622318582276996322436");
        assert_eq!(blinded_master_secret.u.to_dec().unwrap(), "76242448573590064405016258439737389305308751658939430245286640100438960019281437749200830095828154995656490316795623959413004501644803662299479412591058642431687903660665344655065168625525452586969727169375623723517902861969847048691526377607004762208719937819914640316377295513994692345889814194525691804485221810462520684486465466644645762808386096321825027491677390741996765477089812850102636281290306349225021109750689221122813209585062598487297616077690207210647793480450738894724087937015208576263139374972514675875069264408157796307069688316536519870595147545540606129541475897775356097530317320274539032783922");
    }

    #[test]
    fn process_primary_claim_works() {
        let mut claim = super::mocks::gvt_primary_claim();
        let v_prime = BigNumber::from_dec("21337277489659209697972694275961549241988800625063594810959897509238282352238626810206496164796042921922944861660722790127270481494898810301213699637204250648485409496039792926329367175253071514098050800946366413356551955763141949136004248502185266508852158851178744042138131595587172830689293368213380666221485155781604582222397593802865783047420570234359112294991344669207835283314629238445531337778860979843672592610159700225195191155581629856994556889434019851156913688584355226534153997989337803825600096764199505457938355614863559831818213663754528231270325956208966779676675180767488950507044412716354924086945804065215387295334083509").unwrap();

        let old_v = claim.v.clone().unwrap();

        Prover::process_primary_claim(&mut claim, &v_prime).unwrap();
        let new_v = claim.v;

        assert_ne!(old_v, new_v);
        assert_eq!(new_v, BigNumber::from_dec("6477858587997811893327035319417510316563341854132851390093281262022504586945336581881563055213337677056181844572991952555932751996898440671581814053127951224635658321050035511444973918938951286397608407154945420576869136257515796028414378962335588462012678546940230947218473631620847322671867296043124087586400291121388864996880108619720604815227218240238018894734106036749434566128263766145147938204864471079326020636108875736950439614174893113941785014290729562585035442317715573694490415783867707489645644928275501455034338736759260129329435713263029873859553709178436828106858314991461880152652981178848566237411834715936997680351679484278048175488999620056712097674305032686536393318931401622256070852825807510445941751166073917118721482407482663237596774153152864341413225983416965337899803365905987145336353882936").unwrap());
    }

    #[test]
    fn process_claim_works_for_primary_only() {
        let mut claim = super::mocks::gvt_claim();
        let blinded_master_secret_data = super::mocks::blinded_master_secret_data();

        let old_v = claim.p_claim.v.clone().unwrap();

        Prover::process_claim(&mut claim, &blinded_master_secret_data, &None, &None).unwrap();
        let new_v = claim.p_claim.v;

        assert_ne!(old_v, new_v);
        assert_eq!(new_v, BigNumber::from_dec("6477858587997811893327035319417510316563341854132851390093281262022504586945336581881563055213337677056181844572991952555932751996898440671581814053127951224635658321050035511444973918938951286397608407154945420576869136257515796028414378962335588462012678546940230947218473631620847322671867296043124087586400291121388864996880108619720604815227218240238018894734106036749434566128263766145147938204864471079326020636108875736950439614174893113941785014290729562585035442317715573694490415783867707489645644928275501455034338736759260129329435713263029873859553709178436828106858314991461880152652981178848566237411834715936997680351679484278048175488999620056712097674305032686536393318931401622256070852825807510445941751166073917118721482407482663237596774153152864341413225983416965337899803365905987145336353882936").unwrap());
    }
}

pub mod mocks {
    use super::*;

    pub fn master_secret() -> MasterSecret {
        MasterSecret {
            ms: BigNumber::from_dec("48366230316716542900569044107436065507876331091941474824005719405764413438920").unwrap()
        }
    }

    pub fn gvt_claim() -> Claim {
        Claim {
            p_claim: gvt_primary_claim(),
            r_claim: None
        }
    }

    pub fn gvt_primary_claim() -> PrimaryClaim {
        PrimaryClaim {
            m_2: BigNumber::from_dec("59059690488564137142247698318091397258460906844819605876079330034815387295451").unwrap(),
            a: BigNumber::from_dec("9718041686050466417394454846401911338135485472714675418729730425836367006101286571902254065185334609278478268966285580036221254487921329959035516004179696181846182303481304972520273119065229082628152074260549403953056671718537655331440869269274745137172330211653292094784431599793709932507153005886317395811504324510211401461248180054115028194976434036098410711049411182121148080258018668634613727512389415141820208171799071602314334918435751431063443005717167277426824339725300642890836588704754116628420091486522215319582218755888011754179925774397148116144684399342679279867598851549078956970579995906560499116598").unwrap(),
            e: BigNumber::from_dec("259344723055062059907025491480697571938277889515152306249728583105665800713306759149981690559193987143012367913206299323899696942213235956742930098340478263817667896272954429430903").unwrap(),
            v: BigNumber::from_dec("6477858587997811893327035319417510316563341854132851390093281262022504586945336581881563055213337677056181844572991952555932751996898440671581814053127951224635658321050035511444952581661461627187910434460669459027627147456890732433603419064826350179660439920130024451053677588698924377810206573252996817104905392311087651297242904369072119405731178447311689527558852965235336515327317399731791386249101329130190016387606690470441587455323714369899646882695142389754346148949502193028268930628086102907423247334472635671986918166524901017034444368593822038576239079939991296769079454011618207560042821478623371046256253086080003123462245464426891261800415264830177943676315694882710793222167202116798132497210943950614123537502319388887451156451273696457920098972385375390906181570700610413812857561840771758041019799427").unwrap()
        }
    }

    pub fn xyz_primary_claim() -> PrimaryClaim {
        PrimaryClaim {
            m_2: BigNumber::from_dec("15286000759172100591377181600470463901016563303508229099256868461439682297960").unwrap(),
            a: BigNumber::from_dec("43408781019273294664105361779296865998719682917162544589998989929119545158736110398354782373487097567916720068393146407442522759465524978086454753905759545793463313344124355771811443434314961068264817560048863706416774950086764986003208711210634999865569049808488287390632316256564719056299637763267375333211821087200077890030359272146222631266721181554111124044208681571037538573069584354422205830667741943035073249429293717545002649455447823576929844586944437312395399980004204881381972730440043243134325220149938181771288726598116075075695030469920172383286087838334125452986626866574002045592988278504479246651359").unwrap(),
            e: BigNumber::from_dec("259344723055062059907025491480697571938277889515152306249728583105665800713306759149981690559193987143012367913206299323899696942213235956742930308170826250847785686506076097675457").unwrap(),
            v: BigNumber::from_dec("7317425522031871122929735014725915974219077916357946619324882999809902490147269232962296028836689309258771018375595524160662659624613729571392305833691669152259335217665129469797257019760976768390480752706278700726198757382847155041914663476330765482302082453258348762833072019199096655569755579732675778194731082929384728999646144810214262081001001610168832422312672453860834052510627627346824551328447573097827830742130142542088428980177134613143352951210154765966683768380267930430247816156756639251619256437708986533397482230542350135712118866336262892461386520892248250679440828723728022246922847534535121527862173935365408767109564029775935631584235878269228461929312723471684006178472632005435878448583443911005865851065020755776312530886070184936068216896674345747596811821466782799561319045722635649122612452222").unwrap()
        }
    }

    pub fn blinded_master_secret_data() -> BlindedMasterSecretData {
        BlindedMasterSecretData {
            v_prime: BigNumber::from_dec("21337277489659209697972694275961549241988800625063594810959897509238282352238626810206496164796042921922944861660722790127270481494898810301213699637204250648485409496039792926329367175253071514098050800946366413356551955763141949136004248502185266508852158851178744042138131595587172830689293368213380666221485155781604582222397593802865783047420570234359112294991344669207835283314629238445531337778860979843672592610159700225195191155581629856994556889434019851156913688584355226534153997989337803825600096764199505457938355614863559831818213663754528231270325956208966779676675180767488950507044412716354924086945804065215387295334083509").unwrap(),
            vr_prime: Some(GroupOrderElement::new().unwrap())
        }
    }
}