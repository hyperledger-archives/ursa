//use bn::BigNumber;
//use errors::IndyCryptoError;
//
//use pair::{
//    GroupOrderElement,
//    Pair,
//    PointG1,
//    PointG2,
//};
//
//use super::constants::{
//    LARGE_MASTER_SECRET,
//    LARGE_VPRIME,
//};
//
//use super::issuer::{
//    RevocationAccumulator,
//    RevocationAccumulatorPublicKey,
//    PrimaryPublicKey,
//    RevocationPublicKey,
//    PrimaryClaim,
//    NonRevocationClaim,
//};
//
//use std::collections::HashMap;
//
//pub struct MasterSecret {
//    pub ms: BigNumber,
//}
//
//pub struct BlindedPrimaryMasterSecret {
//    pub u: BigNumber,
//}
//
//pub struct PrimaryMasterSecretBlindingData {
//    pub u: BigNumber,
//    pub v_prime: BigNumber,
//}
//
//pub struct BlindedRevocationMasterSecret {
//    pub ur: PointG1,
//}
//
//pub struct RevocationMasterSecretBlindingData {
//    pub ur: PointG1,
//    pub vr_prime: GroupOrderElement,
//}
//
//#[derive(Clone, Debug, PartialEq, Eq, Hash, Deserialize, Serialize)]
//pub enum PredicateType {
//    GE
//}
//
//pub struct Predicate {
//    pub attr_name: String,
//    pub p_type: PredicateType,
//    pub value: i32,
//}
//
//pub struct PrimaryEqualInitProof {
//    pub a_prime: BigNumber,
//    pub t: BigNumber,
//    pub etilde: BigNumber,
//    pub eprime: BigNumber,
//    pub vtilde: BigNumber,
//    pub vprime: BigNumber,
//    pub mtilde: HashMap<String, BigNumber>,
//    pub m1_tilde: BigNumber,
//    pub m2_tilde: BigNumber,
//    pub m2: BigNumber
//}
//
//impl PrimaryEqualInitProof {
//    pub fn as_list(&self) -> Result<Vec<Vec<u8>>, IndyCryptoError> {
//        Ok(vec![self.a_prime.to_bytes()?])
//    }
//
//    pub fn as_tau_list(&self) -> Result<Vec<Vec<u8>>, IndyCryptoError> {
//        Ok(vec![self.t.to_bytes()?])
//    }
//}
//
//pub struct PrimaryPredicateGEInitProof {
//    pub c_list: Vec<BigNumber>,
//    pub tau_list: Vec<BigNumber>,
//    pub u: HashMap<String, BigNumber>,
//    pub u_tilde: HashMap<String, BigNumber>,
//    pub r: HashMap<String, BigNumber>,
//    pub r_tilde: HashMap<String, BigNumber>,
//    pub alpha_tilde: BigNumber,
//    pub predicate: Predicate,
//    pub t: HashMap<String, BigNumber>
//}
//
//impl PrimaryPredicateGEInitProof {
//    pub fn new(c_list: Vec<BigNumber>, tau_list: Vec<BigNumber>, u: HashMap<String, BigNumber>,
//               u_tilde: HashMap<String, BigNumber>, r: HashMap<String, BigNumber>,
//               r_tilde: HashMap<String, BigNumber>, alpha_tilde: BigNumber, predicate: Predicate,
//               t: HashMap<String, BigNumber>) -> PrimaryPredicateGEInitProof {
//        PrimaryPredicateGEInitProof {
//            c_list: c_list,
//            tau_list: tau_list,
//            u: u,
//            u_tilde: u_tilde,
//            r: r,
//            r_tilde: r_tilde,
//            alpha_tilde: alpha_tilde,
//            predicate: predicate,
//            t: t
//        }
//    }
//
//    pub fn as_list(&self) -> Result<&Vec<BigNumber>, IndyCryptoError> {
//        Ok(&self.c_list)
//    }
//
//    pub fn as_tau_list(&self) -> Result<&Vec<BigNumber>, IndyCryptoError> {
//        Ok(&self.tau_list)
//    }
//}
//
//pub struct PrimaryInitProof {
//    pub eq_proof: PrimaryEqualInitProof,
//    pub ge_proofs: Vec<PrimaryPredicateGEInitProof>
//}
//
//#[derive(Clone, Debug, Deserialize, Serialize)]
//pub struct NonRevocProofXList {
//    pub rho: GroupOrderElement,
//    pub r: GroupOrderElement,
//    pub r_prime: GroupOrderElement,
//    pub r_prime_prime: GroupOrderElement,
//    pub r_prime_prime_prime: GroupOrderElement,
//    pub o: GroupOrderElement,
//    pub o_prime: GroupOrderElement,
//    pub m: GroupOrderElement,
//    pub m_prime: GroupOrderElement,
//    pub t: GroupOrderElement,
//    pub t_prime: GroupOrderElement,
//    pub m2: GroupOrderElement,
//    pub s: GroupOrderElement,
//    pub c: GroupOrderElement
//}
//
//impl NonRevocProofXList {
//    pub fn new(rho: GroupOrderElement, r: GroupOrderElement, r_prime: GroupOrderElement,
//               r_prime_prime: GroupOrderElement, r_prime_prime_prime: GroupOrderElement,
//               o: GroupOrderElement, o_prime: GroupOrderElement, m: GroupOrderElement,
//               m_prime: GroupOrderElement, t: GroupOrderElement, t_prime: GroupOrderElement,
//               m2: GroupOrderElement, s: GroupOrderElement,
//               c: GroupOrderElement) -> NonRevocProofXList {
//        NonRevocProofXList {
//            rho: rho,
//            r: r,
//            r_prime: r_prime,
//            r_prime_prime: r_prime_prime,
//            r_prime_prime_prime: r_prime_prime_prime,
//            o: o,
//            o_prime: o_prime,
//            m: m,
//            m_prime: m_prime,
//            t: t,
//            t_prime: t_prime,
//            m2: m2,
//            s: s,
//            c: c
//        }
//    }
//
//    pub fn as_list(&self) -> Result<Vec<GroupOrderElement>, IndyCryptoError> {
//        Ok(vec![self.rho, self.o, self.c, self.o_prime, self.m, self.m_prime, self.t, self.t_prime,
//                self.m2, self.s, self.r, self.r_prime, self.r_prime_prime, self.r_prime_prime_prime])
//    }
//
//    pub fn from_list(seq: Vec<GroupOrderElement>) -> NonRevocProofXList {
//        NonRevocProofXList::new(seq[0], seq[10], seq[11], seq[12], seq[13], seq[1], seq[3], seq[4],
//                                seq[5], seq[6], seq[7], seq[8], seq[9], seq[2])
//    }
//}
//
//#[derive(Clone, Debug, Deserialize, Serialize)]
//pub struct NonRevocProofCList {
//    pub e: PointG1,
//    pub d: PointG1,
//    pub a: PointG1,
//    pub g: PointG1,
//    pub w: PointG2,
//    pub s: PointG2,
//    pub u: PointG2
//}
//
//impl NonRevocProofCList {
//    pub fn new(e: PointG1, d: PointG1, a: PointG1, g: PointG1, w: PointG2, s: PointG2,
//               u: PointG2) -> NonRevocProofCList {
//        NonRevocProofCList {
//            e: e,
//            d: d,
//            a: a,
//            g: g,
//            w: w,
//            s: s,
//            u: u
//        }
//    }
//
//    pub fn as_list(&self) -> Result<Vec<Vec<u8>>, IndyCryptoError> {
//        Ok(vec![self.e.to_bytes()?, self.d.to_bytes()?, self.a.to_bytes()?, self.g.to_bytes()?,
//                self.w.to_bytes()?, self.s.to_bytes()?, self.u.to_bytes()?])
//    }
//}
//
//#[derive(Clone, Debug, Deserialize, Serialize)]
//pub struct NonRevocProofTauList {
//    pub t1: PointG1,
//    pub t2: PointG1,
//    pub t3: Pair,
//    pub t4: Pair,
//    pub t5: PointG1,
//    pub t6: PointG1,
//    pub t7: Pair,
//    pub t8: Pair
//}
//
//impl NonRevocProofTauList {
//    pub fn new(t1: PointG1, t2: PointG1, t3: Pair, t4: Pair, t5: PointG1, t6: PointG1, t7: Pair,
//               t8: Pair) -> NonRevocProofTauList {
//        NonRevocProofTauList {
//            t1: t1,
//            t2: t2,
//            t3: t3,
//            t4: t4,
//            t5: t5,
//            t6: t6,
//            t7: t7,
//            t8: t8
//        }
//    }
//
//    pub fn as_slice(&self) -> Result<Vec<Vec<u8>>, IndyCryptoError> {
//        Ok(vec![self.t1.to_bytes()?, self.t2.to_bytes()?, self.t3.to_bytes()?, self.t4.to_bytes()?,
//                self.t5.to_bytes()?, self.t6.to_bytes()?, self.t7.to_bytes()?, self.t8.to_bytes()?])
//    }
//}
//
//pub struct NonRevocInitProof {
//    pub c_list_params: NonRevocProofXList,
//    pub tau_list_params: NonRevocProofXList,
//    pub c_list: NonRevocProofCList,
//    pub tau_list: NonRevocProofTauList
//}
//
//impl NonRevocInitProof {
//    pub fn new(c_list_params: NonRevocProofXList, tau_list_params: NonRevocProofXList,
//               c_list: NonRevocProofCList, tau_list: NonRevocProofTauList) -> NonRevocInitProof {
//        NonRevocInitProof {
//            c_list_params: c_list_params,
//            tau_list_params: tau_list_params,
//            c_list: c_list,
//            tau_list: tau_list
//        }
//    }
//
//    pub fn as_c_list(&self) -> Result<Vec<Vec<u8>>, IndyCryptoError> {
//        let vec = self.c_list.as_list()?;
//        Ok(vec)
//    }
//
//    pub fn as_tau_list(&self) -> Result<Vec<Vec<u8>>, IndyCryptoError> {
//        let vec = self.tau_list.as_slice()?;
//        Ok(vec)
//    }
//}
//
//pub struct InitProof {
//    pub primary_init_proof: PrimaryInitProof,
//    pub non_revoc_init_proof: Option<NonRevocInitProof>
//}
//
//pub struct ProofBuildingContext {
//    m1_tilde: BigNumber,
//    pub init_proofs: HashMap<String, InitProof>,
//    pub c_list: Vec<Vec<u8>>,
//    pub tau_list: Vec<Vec<u8>>,
//}
//
//pub struct Prover {}
//
//impl Prover {
//    pub fn generate_master_secret() -> Result<BigNumber, IndyCryptoError> {
//        BigNumber::rand(LARGE_MASTER_SECRET)
//    }
//
//    pub fn generate_blinded_primary_master_secret(p_pub_key: &PrimaryPublicKey,
//                                                  p_ms: &MasterSecret) -> Result<(BlindedPrimaryMasterSecret,
//                                                                                  PrimaryMasterSecretBlindingData), IndyCryptoError> {
//        let mut ctx = BigNumber::new_context()?;
//        let v_prime = BigNumber::rand(LARGE_VPRIME)?;
//
//        let u = p_pub_key.s
//            .mod_exp(&v_prime, &p_pub_key.n, Some(&mut ctx))?
//            .mul(
//                &p_pub_key.rms.mod_exp(&p_ms.ms, &p_pub_key.n, Some(&mut ctx))?,
//                None
//            )?
//            .modulus(&p_pub_key.n, Some(&mut ctx))?;
//
//        Ok((
//            BlindedPrimaryMasterSecret { u: u.clone()? },
//            PrimaryMasterSecretBlindingData { u, v_prime }
//        ))
//    }
//
//    pub fn generate_blinded_revocation_master_secret(r_pub_key: &RevocationPublicKey) -> Result<(BlindedRevocationMasterSecret,
//                                                                                                 RevocationMasterSecretBlindingData), IndyCryptoError> {
//        let vr_prime = GroupOrderElement::new()?;
//        let ur = r_pub_key.h2.mul(&vr_prime)?;
//
//        Ok((
//            BlindedRevocationMasterSecret { ur },
//            RevocationMasterSecretBlindingData { ur, vr_prime }
//        ))
//    }
//
//    pub fn process_primary_claim(p_claim: &mut PrimaryClaim,
//                                 p_ms_blnd_data: &PrimaryMasterSecretBlindingData) -> Result<(), IndyCryptoError> {
//        p_claim.v = p_ms_blnd_data.v_prime.add(&p_claim.v)?;
//        Ok(())
//    }
//
//    pub fn process_non_revocation_claim(r_claim: &mut NonRevocationClaim,
//                                        r_ms_blnd_data: &RevocationMasterSecretBlindingData,
//                                        r_pub_key: &RevocationPublicKey,
//                                        r_acc: &RevocationAccumulator,
//                                        r_acc_pub_key: &RevocationAccumulatorPublicKey) -> Result<(), IndyCryptoError> {
//        let r_cnxt_m2 = BigNumber::from_bytes(&r_claim.m2.to_bytes()?)?;
//        r_claim.vr_prime_prime = r_ms_blnd_data.vr_prime.add_mod(&r_claim.vr_prime_prime)?;
//        Prover::_test_witness_credential(&r_claim, r_pub_key, r_acc, r_acc_pub_key, &r_cnxt_m2)?;
//        Ok(())
//    }
//
//    pub fn init_proof_builder() -> Result<ProofBuildingContext, IndyCryptoError> {
//        let m1_tilde = BigNumber::rand(LARGE_M2_TILDE)?;
//        let init_proofs: HashMap<String, InitProof> = HashMap::new();
//        let c_list: Vec<Vec<u8>> = Vec::new();
//        let tau_list: Vec<Vec<u8>> = Vec::new();
//
//        return ProofBuildingContext { init_proofs, c_list, tau_list, m1_tilde };
//    }
//
//    pub fn add_proof(p_claim: &PrimaryClaim, r_claim: Option<&NonRevocationClaim>) -> Result<(), IndyCryptoError> {
//
//    }
//
//    fn _test_witness_credential(r_claim: &NonRevocationClaim,
//                                r_pub_key: &RevocationPublicKey,
//                                r_acc: &RevocationAccumulator,
//                                r_acc_pub_key: &RevocationAccumulatorPublicKey,
//                                r_cnxt_m2: &BigNumber) -> Result<(), IndyCryptoError> {
//        let z_calc = Pair::pair(&r_claim.witness.g_i, &r_acc.acc)?
//            .mul(&Pair::pair(&r_pub_key.g, &r_claim.witness.omega)?.inverse()?)?;
//        if z_calc != r_acc_pub_key.z {
//            return Err(IndyCryptoError::InvalidStructure("Issuer is sending incorrect data".to_string()));
//        }
//        let pair_gg_calc = Pair::pair(&r_pub_key.pk.add(&r_claim.g_i)?, &r_claim.witness.sigma_i)?;
//        let pair_gg = Pair::pair(&r_pub_key.g, &r_pub_key.g_dash)?;
//        if pair_gg_calc != pair_gg {
//            return Err(IndyCryptoError::InvalidStructure("Issuer is sending incorrect data".to_string()));
//        }
//
//        let m2 = GroupOrderElement::from_bytes(&r_cnxt_m2.to_bytes()?)?;
//
//        let pair_h1 = Pair::pair(&r_claim.sigma, &r_pub_key.y.add(&r_pub_key.h_cap.mul(&r_claim.c)?)?)?;
//        let pair_h2 = Pair::pair(
//            &r_pub_key.h0
//                .add(&r_pub_key.h1.mul(&m2)?)?
//                .add(&r_pub_key.h2.mul(&r_claim.vr_prime_prime)?)?
//                .add(&r_claim.g_i)?,
//            &r_pub_key.h_cap
//        )?;
//        if pair_h1 != pair_h2 {
//            return Err(IndyCryptoError::InvalidStructure("Issuer is sending incorrect data".to_string()));
//        }
//
//        Ok(())
//    }
//}