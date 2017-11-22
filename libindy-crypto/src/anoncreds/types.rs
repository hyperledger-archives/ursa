use bn::BigNumber;
use errors::IndyCryptoError;
use anoncreds::helpers::AppendByteArray;

use pair::{
    GroupOrderElement,
    PointG1,
    PointG2,
    Pair
};

use std::collections::{HashMap, HashSet};
use super::helpers::clone_bignum_map;

#[derive(Debug)]
pub struct ClaimAttributes {
    pub attrs: HashSet<String> /* attr names */
}

#[derive(Debug)]
pub struct ClaimAttributesBuilder {
    attrs: HashSet<String> /* attr names */
}

impl ClaimAttributesBuilder {
    pub fn new() -> Result<ClaimAttributesBuilder, IndyCryptoError> {
        Ok(ClaimAttributesBuilder {
            attrs: HashSet::new()
        })
    }

    pub fn add_attr(mut self, attr: &str) -> Result<ClaimAttributesBuilder, IndyCryptoError> {
        self.attrs.insert(attr.to_owned());
        Ok(self)
    }

    pub fn finalize(self) -> Result<ClaimAttributes, IndyCryptoError> {
        Ok(ClaimAttributes {
            attrs: self.attrs
        })
    }
}

#[derive(Debug)]
pub struct ClaimAttributesValues {
    pub attrs_values: HashMap<String, BigNumber>
}

impl ClaimAttributesValues {
    pub fn clone(&self) -> Result<ClaimAttributesValues, IndyCryptoError> {
        Ok(ClaimAttributesValues {
            attrs_values: clone_bignum_map(&self.attrs_values)?
        })
    }
}

#[derive(Debug)]
pub struct ClaimAttributesValuesBuilder {
    attrs_values: HashMap<String, BigNumber> /* attr_name -> int representation of value */
}

impl ClaimAttributesValuesBuilder {
    pub fn new() -> Result<ClaimAttributesValuesBuilder, IndyCryptoError> {
        Ok(ClaimAttributesValuesBuilder {
            attrs_values: HashMap::new()
        })
    }

    pub fn add_attr_value(mut self, attr: &str, dec_value: &str) -> Result<ClaimAttributesValuesBuilder, IndyCryptoError> {
        self.attrs_values.insert(attr.to_owned(), BigNumber::from_dec(dec_value)?);
        Ok(self)
    }

    pub fn finalize(self) -> Result<ClaimAttributesValues, IndyCryptoError> {
        Ok(ClaimAttributesValues {
            attrs_values: self.attrs_values
        })
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct IssuerPrimaryPrivateKey {
    pub p: BigNumber,
    pub q: BigNumber
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct IssuerPrimaryPublicKey {
    pub n: BigNumber,
    pub s: BigNumber,
    pub rms: BigNumber,
    pub r: HashMap<String /* attr_name */, BigNumber>,
    pub rctxt: BigNumber,
    pub z: BigNumber
}

#[derive(Debug)]
pub struct IssuerRevocationPrivateKey {
    pub x: GroupOrderElement,
    pub sk: GroupOrderElement
}

#[derive(Clone, Debug)]
pub struct IssuerRevocationPublicKey {
    pub g: PointG1,
    pub g_dash: PointG2,
    pub h: PointG1,
    pub h0: PointG1,
    pub h1: PointG1,
    pub h2: PointG1,
    pub htilde: PointG1,
    pub h_cap: PointG2,
    pub u: PointG2,
    pub pk: PointG1,
    pub y: PointG2,
}

#[derive(Debug)]
pub struct IssuerPublicKey {
    pub p_key: IssuerPrimaryPublicKey,
    pub r_key: Option<IssuerRevocationPublicKey>,
}

#[derive(Debug)]
pub struct IssuerPrivateKey {
    pub p_key: IssuerPrimaryPrivateKey,
    pub r_key: Option<IssuerRevocationPrivateKey>,
}

#[derive(Debug)]
pub struct RevocationAccumulator {
    pub acc: PointG2,
    pub v: HashSet<u32> /* used indexes */,
    pub max_claim_num: u32,
}

impl RevocationAccumulator {
    pub fn is_full(&self) -> bool {
        self.v.len() > self.max_claim_num as usize
    }
    pub fn is_idx_used(&self, idx: u32) -> bool {
        self.v.contains(&idx)
    }
}

#[derive(Debug)]
pub struct RevocationAccumulatorPrivateKey {
    pub gamma: GroupOrderElement
}

#[derive(Debug)]
pub struct RevocationAccumulatorPublicKey {
    pub z: Pair
}

#[derive(Debug)]
pub struct RevocationAccumulatorTails {
    pub tails: HashMap<u32 /* index in acc */, PointG1>,
    pub tails_dash: HashMap<u32 /* index in acc */, PointG2>,
}

#[derive(Debug)]
pub struct RevocationRegistryPublic {
    pub key: RevocationAccumulatorPublicKey,
    pub acc: RevocationAccumulator,
    pub tails: RevocationAccumulatorTails,
}

#[derive(Debug)]
pub struct RevocationRegistryPrivate {
    pub key: RevocationAccumulatorPrivateKey,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PrimaryClaim {
    pub m_2: BigNumber,
    pub a: BigNumber,
    pub e: BigNumber,
    pub v: BigNumber
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Witness {
    pub sigma_i: PointG2,
    pub u_i: PointG2,
    pub g_i: PointG1,
    pub omega: PointG2,
    pub v: HashSet<u32>
}

#[derive(Clone, Debug)]
pub struct NonRevocationClaim {
    pub sigma: PointG1,
    pub c: GroupOrderElement,
    pub vr_prime_prime: GroupOrderElement,
    pub witness: Witness,
    pub g_i: PointG1,
    pub i: u32,
    pub m2: GroupOrderElement
}

#[derive(Debug)]
pub struct Claim {
    pub p_claim: PrimaryClaim,
    pub r_claim: Option<NonRevocationClaim> /* will be used to proof is claim revoked preparation */,
}

#[derive(Debug)]
pub struct MasterSecret {
    pub ms: BigNumber,
}

#[derive(Debug)]
pub struct BlindedMasterSecret {
    pub u: BigNumber,
    pub ur: Option<PointG1>
}

#[derive(Debug)]
pub struct BlindedMasterSecretData {
    pub v_prime: BigNumber,
    pub vr_prime: Option<GroupOrderElement>
}

#[derive(Eq, PartialEq, Debug)]
pub struct PrimaryBlindedMasterSecretData {
    pub u: BigNumber,
    pub v_prime: BigNumber,
}

pub struct RevocationBlindedMasterSecretData {
    pub ur: PointG1,
    pub vr_prime: GroupOrderElement,
}

pub struct ClaimInfo {
    pub claim: HashMap<String, Vec<String>>,
    pub schema_seq_no: i32,
    pub signature: Claim,
    pub issuer_did: String
}

#[derive(Debug)]
pub struct PrimaryEqualInitProof {
    pub a_prime: BigNumber,
    pub t: BigNumber,
    pub e_tilde: BigNumber,
    pub e_prime: BigNumber,
    pub v_tilde: BigNumber,
    pub v_prime: BigNumber,
    pub m_tilde: HashMap<String, BigNumber>,
    pub m1_tilde: BigNumber,
    pub m2_tilde: BigNumber,
    pub m2: BigNumber
}

impl PrimaryEqualInitProof {
    pub fn as_list(&self) -> Result<Vec<Vec<u8>>, IndyCryptoError> {
        Ok(vec![self.a_prime.to_bytes()?])
    }

    pub fn as_tau_list(&self) -> Result<Vec<Vec<u8>>, IndyCryptoError> {
        Ok(vec![self.t.to_bytes()?])
    }
}

#[derive(Debug)]
pub struct PrimaryPredicateGEInitProof {
    pub c_list: Vec<BigNumber>,
    pub tau_list: Vec<BigNumber>,
    pub u: HashMap<String, BigNumber>,
    pub u_tilde: HashMap<String, BigNumber>,
    pub r: HashMap<String, BigNumber>,
    pub r_tilde: HashMap<String, BigNumber>,
    pub alpha_tilde: BigNumber,
    pub predicate: Predicate,
    pub t: HashMap<String, BigNumber>
}

impl PrimaryPredicateGEInitProof {
    pub fn as_list(&self) -> Result<&Vec<BigNumber>, IndyCryptoError> {
        Ok(&self.c_list)
    }

    pub fn as_tau_list(&self) -> Result<&Vec<BigNumber>, IndyCryptoError> {
        Ok(&self.tau_list)
    }
}

#[derive(Debug)]
pub struct PrimaryInitProof {
    pub eq_proof: PrimaryEqualInitProof,
    pub ge_proofs: Vec<PrimaryPredicateGEInitProof>
}

impl PrimaryInitProof {
    pub fn as_c_list(&self) -> Result<Vec<Vec<u8>>, IndyCryptoError> {
        let mut c_list: Vec<Vec<u8>> = self.eq_proof.as_list()?;
        for ge_proof in self.ge_proofs.iter() {
            c_list.append_vec(ge_proof.as_list()?)?;
        }
        Ok(c_list)
    }

    pub fn as_tau_list(&self) -> Result<Vec<Vec<u8>>, IndyCryptoError> {
        let mut tau_list: Vec<Vec<u8>> = self.eq_proof.as_tau_list()?;
        for ge_proof in self.ge_proofs.iter() {
            tau_list.append_vec(ge_proof.as_tau_list()?)?;
        }
        Ok(tau_list)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NonRevocProofXList {
    pub rho: GroupOrderElement,
    pub r: GroupOrderElement,
    pub r_prime: GroupOrderElement,
    pub r_prime_prime: GroupOrderElement,
    pub r_prime_prime_prime: GroupOrderElement,
    pub o: GroupOrderElement,
    pub o_prime: GroupOrderElement,
    pub m: GroupOrderElement,
    pub m_prime: GroupOrderElement,
    pub t: GroupOrderElement,
    pub t_prime: GroupOrderElement,
    pub m2: GroupOrderElement,
    pub s: GroupOrderElement,
    pub c: GroupOrderElement
}

impl NonRevocProofXList {
    pub fn as_list(&self) -> Result<Vec<GroupOrderElement>, IndyCryptoError> {
        Ok(vec![self.rho, self.o, self.c, self.o_prime, self.m, self.m_prime, self.t, self.t_prime,
                self.m2, self.s, self.r, self.r_prime, self.r_prime_prime, self.r_prime_prime_prime])
    }

    pub fn from_list(seq: Vec<GroupOrderElement>) -> NonRevocProofXList {
        NonRevocProofXList {
            rho: seq[0],
            r: seq[10],
            r_prime: seq[11],
            r_prime_prime: seq[12],
            r_prime_prime_prime: seq[13],
            o: seq[1],
            o_prime: seq[3],
            m: seq[4],
            m_prime: seq[5],
            t: seq[6],
            t_prime: seq[7],
            m2: seq[8],
            s: seq[9],
            c: seq[2]
        }
    }
}

#[derive(Clone, Debug)]
pub struct NonRevocProofCList {
    pub e: PointG1,
    pub d: PointG1,
    pub a: PointG1,
    pub g: PointG1,
    pub w: PointG2,
    pub s: PointG2,
    pub u: PointG2
}

impl NonRevocProofCList {
    pub fn as_list(&self) -> Result<Vec<Vec<u8>>, IndyCryptoError> {
        Ok(vec![self.e.to_bytes()?, self.d.to_bytes()?, self.a.to_bytes()?, self.g.to_bytes()?,
                self.w.to_bytes()?, self.s.to_bytes()?, self.u.to_bytes()?])
    }
}

#[derive(Clone, Debug)]
pub struct NonRevocProofTauList {
    pub t1: PointG1,
    pub t2: PointG1,
    pub t3: Pair,
    pub t4: Pair,
    pub t5: PointG1,
    pub t6: PointG1,
    pub t7: Pair,
    pub t8: Pair
}

impl NonRevocProofTauList {
    pub fn as_slice(&self) -> Result<Vec<Vec<u8>>, IndyCryptoError> {
        Ok(vec![self.t1.to_bytes()?, self.t2.to_bytes()?, self.t3.to_bytes()?, self.t4.to_bytes()?,
                self.t5.to_bytes()?, self.t6.to_bytes()?, self.t7.to_bytes()?, self.t8.to_bytes()?])
    }
}

#[derive(Debug)]
pub struct NonRevocInitProof {
    pub c_list_params: NonRevocProofXList,
    pub tau_list_params: NonRevocProofXList,
    pub c_list: NonRevocProofCList,
    pub tau_list: NonRevocProofTauList
}

impl NonRevocInitProof {
    pub fn as_c_list(&self) -> Result<Vec<Vec<u8>>, IndyCryptoError> {
        let vec = self.c_list.as_list()?;
        Ok(vec)
    }

    pub fn as_tau_list(&self) -> Result<Vec<Vec<u8>>, IndyCryptoError> {
        let vec = self.tau_list.as_slice()?;
        Ok(vec)
    }
}

#[derive(Debug)]
pub struct InitProof {
    pub primary_init_proof: PrimaryInitProof,
    pub non_revoc_init_proof: Option<NonRevocInitProof>,
    pub attributes_values: ClaimAttributesValues,
    pub attrs_with_predicates: AttrsWithPredicates
}

pub struct ProofRequest {
    pub nonce: BigNumber,
    pub name: String,
    pub version: String,
    pub requested_attrs: HashMap<String, AttributeInfo>,
    pub requested_predicates: HashMap<String, Predicate>
}

#[derive(Debug)]
pub struct ProofClaims {
    pub claim: Claim,
    pub claim_attributes_values: ClaimAttributesValues,
    pub pub_key: IssuerPublicKey,
    pub r_reg: Option<RevocationRegistryPublic>,
    pub attrs_with_predicates: ProofAttrs
}

pub struct VerifyClaim {
    pub p_pub_key: IssuerPublicKey,
    pub r_pub_key: Option<IssuerRevocationPublicKey>,
    pub r_reg: Option<RevocationRegistryPublic>,
    pub proof_attrs: ProofAttrs
}

pub struct PrimaryEqualProof {
    pub revealed_attrs: HashMap<String /* attr_name of revealed */, BigNumber>,
    pub a_prime: BigNumber,
    pub e: BigNumber,
    pub v: BigNumber,
    pub m: HashMap<String /* attr_name of all except revealed */, BigNumber>,
    pub m1: BigNumber,
    pub m2: BigNumber
}

#[derive(Debug)]
pub struct PrimaryPredicateGEProof {
    pub u: HashMap<String, BigNumber>,
    pub r: HashMap<String, BigNumber>,
    pub mj: BigNumber,
    pub alpha: BigNumber,
    pub t: HashMap<String, BigNumber>,
    pub predicate: Predicate
}

#[derive(Debug)]
pub struct PrimaryProof {
    pub eq_proof: PrimaryEqualProof,
    pub ge_proofs: Vec<PrimaryPredicateGEProof>
}

#[derive(Debug)]
pub struct NonRevocProof {
    pub x_list: NonRevocProofXList,
    pub c_list: NonRevocProofCList
}

#[derive(Debug)]
pub struct Proof {
    pub primary_proof: PrimaryProof,
    pub non_revoc_proof: Option<NonRevocProof>
}

#[derive(Debug)]
pub struct AggregatedProof {
    pub c_hash: BigNumber,
    pub c_list: Vec<Vec<u8>>
}

#[derive(Debug)]
pub struct FullProof {
    pub proofs: HashMap<String /* issuer pub key id */, Proof>,
    pub aggregated_proof: AggregatedProof,
}

#[derive(Debug, Clone)]
pub struct ProofAttrs {
    pub revealed_attrs: HashSet<String>,
    pub unrevealed_attrs: HashSet<String>,
    pub predicates: HashSet<Predicate>,
}

pub struct ProofAttrsBuilder {
    value: ProofAttrs
}

impl ProofAttrsBuilder {
    pub fn new() -> Result<ProofAttrsBuilder, IndyCryptoError> {
        Ok(ProofAttrsBuilder {
            value: ProofAttrs {
                revealed_attrs: HashSet::new(),
                unrevealed_attrs: HashSet::new(),
                predicates: HashSet::new()
            }
        })
    }

    pub fn add_revealed_attr(mut self, attr: &str) -> Result<ProofAttrsBuilder, IndyCryptoError> {
        self.value.revealed_attrs.insert(attr.to_owned());
        Ok(self)
    }

    pub fn add_unrevealed_attr(mut self, attr: &str) -> Result<ProofAttrsBuilder, IndyCryptoError> {
        self.value.unrevealed_attrs.insert(attr.to_owned());
        Ok(self)
    }

    pub fn add_predicate(mut self, predicate: Predicate) -> Result<ProofAttrsBuilder, IndyCryptoError> {
        self.value.predicates.insert(predicate);
        Ok(self)
    }

    pub fn finalize(self) -> Result<ProofAttrs, IndyCryptoError> {
        Ok(self.value)
    }
}

pub struct AttributeInfo {
    pub name: String,
    pub schema_seq_no: Option<i32>,
    pub issuer_did: Option<String>
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum PredicateType {
    GE
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Predicate {
    pub attr_name: String,
    pub p_type: PredicateType,
    pub value: i32,
}
