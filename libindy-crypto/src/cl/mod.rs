mod constants;
mod helpers;
pub mod issuer;
pub mod prover;
pub mod verifier;

use bn::BigNumber;
use errors::IndyCryptoError;
use pair::{
    GroupOrderElement,
    PointG1,
    PointG2,
    Pair
};

use std::collections::{HashMap, HashSet};
use std::hash::Hash;

#[derive(Debug, Clone)]
pub struct ClaimSchema {
    attrs: HashSet<String> /* attr names */
}

#[derive(Debug)]
pub struct ClaimSchemaBuilder {
    attrs: HashSet<String> /* attr names */
}

impl ClaimSchemaBuilder {
    pub fn new() -> Result<ClaimSchemaBuilder, IndyCryptoError> {
        Ok(ClaimSchemaBuilder {
            attrs: HashSet::new()
        })
    }

    pub fn add_attr(mut self, attr: &str) -> Result<ClaimSchemaBuilder, IndyCryptoError> {
        self.attrs.insert(attr.to_owned());
        Ok(self)
    }

    pub fn finalize(self) -> Result<ClaimSchema, IndyCryptoError> {
        Ok(ClaimSchema {
            attrs: self.attrs
        })
    }
}

#[derive(Debug)]
pub struct ClaimValues {
    attrs_values: HashMap<String, BigNumber>
}

impl ClaimValues {
    pub fn clone(&self) -> Result<ClaimValues, IndyCryptoError> {
        Ok(ClaimValues {
            attrs_values: clone_bignum_map(&self.attrs_values)?
        })
    }
}

#[derive(Debug)]
pub struct ClaimValuesBuilder {
    attrs_values: HashMap<String, BigNumber> /* attr_name -> int representation of value */
}

impl ClaimValuesBuilder {
    pub fn new() -> Result<ClaimValuesBuilder, IndyCryptoError> {
        Ok(ClaimValuesBuilder {
            attrs_values: HashMap::new()
        })
    }

    pub fn add_value(mut self, attr: &str, dec_value: &str) -> Result<ClaimValuesBuilder, IndyCryptoError> {
        self.attrs_values.insert(attr.to_owned(), BigNumber::from_dec(dec_value)?);
        Ok(self)
    }

    pub fn finalize(self) -> Result<ClaimValues, IndyCryptoError> {
        Ok(ClaimValues {
            attrs_values: self.attrs_values
        })
    }
}

#[derive(Debug, PartialEq)]
pub struct IssuerPrimaryPrivateKey {
    p: BigNumber,
    q: BigNumber
}

#[derive(Debug, PartialEq)]
pub struct IssuerPrimaryPublicKey {
    n: BigNumber,
    s: BigNumber,
    rms: BigNumber,
    r: HashMap<String /* attr_name */, BigNumber>,
    rctxt: BigNumber,
    z: BigNumber
}

#[derive(Debug)]
pub struct IssuerRevocationPrivateKey {
    x: GroupOrderElement,
    sk: GroupOrderElement
}

#[derive(Clone, Debug)]
pub struct IssuerRevocationPublicKey {
    g: PointG1,
    g_dash: PointG2,
    h: PointG1,
    h0: PointG1,
    h1: PointG1,
    h2: PointG1,
    htilde: PointG1,
    h_cap: PointG2,
    u: PointG2,
    pk: PointG1,
    y: PointG2,
}

#[derive(Debug)]
pub struct IssuerPublicKey {
    p_key: IssuerPrimaryPublicKey,
    r_key: Option<IssuerRevocationPublicKey>,
}

#[derive(Debug)]
pub struct IssuerPrivateKey {
    p_key: IssuerPrimaryPrivateKey,
    r_key: Option<IssuerRevocationPrivateKey>,
}

#[derive(Debug)]
pub struct RevocationAccumulator {
    acc: PointG2,
    v: HashSet<u32> /* used indexes */,
    max_claim_num: u32,
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
    gamma: GroupOrderElement
}

#[derive(Debug)]
pub struct RevocationAccumulatorPublicKey {
    z: Pair
}

#[derive(Debug)]
pub struct RevocationAccumulatorTails {
    tails: HashMap<u32 /* index in acc */, PointG1>,
    tails_dash: HashMap<u32 /* index in acc */, PointG2>,
}

#[derive(Debug)]
pub struct RevocationRegistryPublic {
    key: RevocationAccumulatorPublicKey,
    acc: RevocationAccumulator,
    tails: RevocationAccumulatorTails,
}

#[derive(Debug)]
pub struct RevocationRegistryPrivate {
    key: RevocationAccumulatorPrivateKey,
}

#[derive(Debug, PartialEq, Eq)]
pub struct PrimaryClaimSignature {
    m_2: BigNumber,
    a: BigNumber,
    e: BigNumber,
    v: BigNumber
}

#[derive(Clone, Debug)]
pub struct Witness {
    sigma_i: PointG2,
    u_i: PointG2,
    g_i: PointG1,
    omega: PointG2,
    v: HashSet<u32>
}

#[derive(Clone, Debug)]
pub struct NonRevocationClaimSignature {
    sigma: PointG1,
    c: GroupOrderElement,
    vr_prime_prime: GroupOrderElement,
    witness: Witness,
    g_i: PointG1,
    i: u32,
    m2: GroupOrderElement
}

#[derive(Debug)]
pub struct ClaimSignature {
    p_claim: PrimaryClaimSignature,
    r_claim: Option<NonRevocationClaimSignature> /* will be used to proof is claim revoked preparation */,
}

#[derive(Debug)]
pub struct MasterSecret {
    ms: BigNumber,
}

#[derive(Debug)]
pub struct BlindedMasterSecret {
    u: BigNumber,
    ur: Option<PointG1>
}

#[derive(Debug)]
pub struct BlindedMasterSecretData {
    v_prime: BigNumber,
    vr_prime: Option<GroupOrderElement>
}

#[derive(Eq, PartialEq, Debug)]
pub struct PrimaryBlindedMasterSecretData {
    u: BigNumber,
    v_prime: BigNumber,
}

pub struct RevocationBlindedMasterSecretData {
    ur: PointG1,
    vr_prime: GroupOrderElement,
}

#[derive(Debug, Eq, PartialEq)]
pub struct PrimaryEqualInitProof {
    a_prime: BigNumber,
    t: BigNumber,
    e_tilde: BigNumber,
    e_prime: BigNumber,
    v_tilde: BigNumber,
    v_prime: BigNumber,
    m_tilde: HashMap<String, BigNumber>,
    m1_tilde: BigNumber,
    m2_tilde: BigNumber,
    m2: BigNumber
}

impl PrimaryEqualInitProof {
    pub fn as_list(&self) -> Result<Vec<Vec<u8>>, IndyCryptoError> {
        Ok(vec![self.a_prime.to_bytes()?])
    }

    pub fn as_tau_list(&self) -> Result<Vec<Vec<u8>>, IndyCryptoError> {
        Ok(vec![self.t.to_bytes()?])
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct PrimaryPredicateGEInitProof {
    c_list: Vec<BigNumber>,
    tau_list: Vec<BigNumber>,
    u: HashMap<String, BigNumber>,
    u_tilde: HashMap<String, BigNumber>,
    r: HashMap<String, BigNumber>,
    r_tilde: HashMap<String, BigNumber>,
    alpha_tilde: BigNumber,
    predicate: Predicate,
    t: HashMap<String, BigNumber>
}

impl PrimaryPredicateGEInitProof {
    pub fn as_list(&self) -> Result<&Vec<BigNumber>, IndyCryptoError> {
        Ok(&self.c_list)
    }

    pub fn as_tau_list(&self) -> Result<&Vec<BigNumber>, IndyCryptoError> {
        Ok(&self.tau_list)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct PrimaryInitProof {
    eq_proof: PrimaryEqualInitProof,
    ge_proofs: Vec<PrimaryPredicateGEInitProof>
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

#[derive(Clone, Debug)]
pub struct NonRevocProofXList {
    rho: GroupOrderElement,
    r: GroupOrderElement,
    r_prime: GroupOrderElement,
    r_prime_prime: GroupOrderElement,
    r_prime_prime_prime: GroupOrderElement,
    o: GroupOrderElement,
    o_prime: GroupOrderElement,
    m: GroupOrderElement,
    m_prime: GroupOrderElement,
    t: GroupOrderElement,
    t_prime: GroupOrderElement,
    m2: GroupOrderElement,
    s: GroupOrderElement,
    c: GroupOrderElement
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
    e: PointG1,
    d: PointG1,
    a: PointG1,
    g: PointG1,
    w: PointG2,
    s: PointG2,
    u: PointG2
}

impl NonRevocProofCList {
    pub fn as_list(&self) -> Result<Vec<Vec<u8>>, IndyCryptoError> {
        Ok(vec![self.e.to_bytes()?, self.d.to_bytes()?, self.a.to_bytes()?, self.g.to_bytes()?,
                self.w.to_bytes()?, self.s.to_bytes()?, self.u.to_bytes()?])
    }
}

#[derive(Clone, Debug)]
pub struct NonRevocProofTauList {
    t1: PointG1,
    t2: PointG1,
    t3: Pair,
    t4: Pair,
    t5: PointG1,
    t6: PointG1,
    t7: Pair,
    t8: Pair
}

impl NonRevocProofTauList {
    pub fn as_slice(&self) -> Result<Vec<Vec<u8>>, IndyCryptoError> {
        Ok(vec![self.t1.to_bytes()?, self.t2.to_bytes()?, self.t3.to_bytes()?, self.t4.to_bytes()?,
                self.t5.to_bytes()?, self.t6.to_bytes()?, self.t7.to_bytes()?, self.t8.to_bytes()?])
    }
}

#[derive(Debug)]
pub struct NonRevocInitProof {
    c_list_params: NonRevocProofXList,
    tau_list_params: NonRevocProofXList,
    c_list: NonRevocProofCList,
    tau_list: NonRevocProofTauList
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
    primary_init_proof: PrimaryInitProof,
    non_revoc_init_proof: Option<NonRevocInitProof>,
    claim_values: ClaimValues,
    sub_proof_request: SubProofRequest,
    claim_schema: ClaimSchema
}

#[derive(Debug)]
pub struct ProofClaims {
    claim: ClaimSignature,
    claim_attributes_values: ClaimValues,
    pub_key: IssuerPublicKey,
    r_reg: Option<RevocationRegistryPublic>,
    attrs_with_predicates: SubProofRequest
}

#[derive(Debug)]
pub struct VerifyClaim {
    pub_key: IssuerPublicKey,
    r_reg: Option<RevocationRegistryPublic>,
    sub_proof_request: SubProofRequest,
    claim_schema: ClaimSchema
}

#[derive(Debug, PartialEq, Eq)]
pub struct PrimaryEqualProof {
    revealed_attrs: HashMap<String /* attr_name of revealed */, BigNumber>,
    a_prime: BigNumber,
    e: BigNumber,
    v: BigNumber,
    m: HashMap<String /* attr_name of all except revealed */, BigNumber>,
    m1: BigNumber,
    m2: BigNumber
}

#[derive(Debug, PartialEq, Eq)]
pub struct PrimaryPredicateGEProof {
    u: HashMap<String, BigNumber>,
    r: HashMap<String, BigNumber>,
    mj: BigNumber,
    alpha: BigNumber,
    t: HashMap<String, BigNumber>,
    predicate: Predicate
}

#[derive(Debug, PartialEq, Eq)]
pub struct PrimaryProof {
    eq_proof: PrimaryEqualProof,
    ge_proofs: Vec<PrimaryPredicateGEProof>
}

#[derive(Debug)]
pub struct NonRevocProof {
    x_list: NonRevocProofXList,
    c_list: NonRevocProofCList
}

#[derive(Debug)]
pub struct SubProof {
    primary_proof: PrimaryProof,
    non_revoc_proof: Option<NonRevocProof>
}

#[derive(Debug, Eq, PartialEq)]
pub struct AggregatedProof {
    c_hash: BigNumber,
    c_list: Vec<Vec<u8>>
}

#[derive(Debug)]
pub struct Proof {
    proofs: HashMap<String /* issuer pub key id */, SubProof>,
    aggregated_proof: AggregatedProof,
}

#[derive(Debug, Clone)]
pub struct SubProofRequest {
    revealed_attrs: HashSet<String>,
    predicates: HashSet<Predicate>,
}

#[derive(Debug)]
pub struct SubProofRequestBuilder {
    value: SubProofRequest
}

impl SubProofRequestBuilder {
    pub fn new() -> Result<SubProofRequestBuilder, IndyCryptoError> {
        Ok(SubProofRequestBuilder {
            value: SubProofRequest {
                revealed_attrs: HashSet::new(),
                predicates: HashSet::new()
            }
        })
    }

    pub fn add_revealed_attr(mut self, attr: &str) -> Result<SubProofRequestBuilder, IndyCryptoError> {
        self.value.revealed_attrs.insert(attr.to_owned());
        Ok(self)
    }

    pub fn add_predicate(mut self, predicate: &Predicate) -> Result<SubProofRequestBuilder, IndyCryptoError> {
        self.value.predicates.insert(predicate.clone());
        Ok(self)
    }

    pub fn finalize(self) -> Result<SubProofRequest, IndyCryptoError> {
        Ok(self.value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum PredicateType {
    GE
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Predicate {
    attr_name: String,
    p_type: PredicateType,
    value: i32,
}

impl Predicate {
    pub fn new(attr_name: &str, p_type: &str, value: i32) -> Result<Predicate, IndyCryptoError> {
        let p_type = match p_type {
            "GE" => PredicateType::GE,
            p_type => return Err(IndyCryptoError::InvalidStructure(format!("Invalid predicate type: {:?}", p_type)))
        };

        Ok(Predicate {
            attr_name: attr_name.to_owned(),
            p_type,
            value
        })
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct Nonce {
    value: BigNumber
}

pub trait BytesView {
    fn to_bytes(&self) -> Result<Vec<u8>, IndyCryptoError>;
}

impl BytesView for BigNumber {
    fn to_bytes(&self) -> Result<Vec<u8>, IndyCryptoError> {
        Ok(self.to_bytes()?)
    }
}

impl BytesView for PointG1 {
    fn to_bytes(&self) -> Result<Vec<u8>, IndyCryptoError> {
        Ok(self.to_bytes()?)
    }
}

impl BytesView for GroupOrderElement {
    fn to_bytes(&self) -> Result<Vec<u8>, IndyCryptoError> {
        Ok(self.to_bytes()?)
    }
}

impl BytesView for Pair {
    fn to_bytes(&self) -> Result<Vec<u8>, IndyCryptoError> {
        Ok(self.to_bytes()?)
    }
}

pub trait AppendByteArray {
    fn append_vec<T: BytesView>(&mut self, other: &Vec<T>) -> Result<(), IndyCryptoError>;
}

impl AppendByteArray for Vec<Vec<u8>> {
    fn append_vec<T: BytesView>(&mut self, other: &Vec<T>) -> Result<(), IndyCryptoError> {
        for el in other.iter() {
            self.push(el.to_bytes()?);
        }
        Ok(())
    }
}

pub fn clone_bignum_map<K: Clone + Eq + Hash>(other: &HashMap<K, BigNumber>)
                                              -> Result<HashMap<K, BigNumber>, IndyCryptoError> {
    let mut res: HashMap<K, BigNumber> = HashMap::new();
    for (k, v) in other {
        res.insert(k.clone(), v.clone()?);
    }
    Ok(res)
}

#[cfg(test)]
mod test {
    use super::*;
    use self::issuer::Issuer;
    use self::prover::Prover;
    use self::verifier::Verifier;

    #[test]
    #[ignore]
    fn demo() {
        let claim_schema_builder = Issuer::new_claim_schema_builder().unwrap();
        let claim_schema = claim_schema_builder
            .add_attr("name").unwrap()
            .add_attr("sex").unwrap()
            .add_attr("age").unwrap()
            .add_attr("height").unwrap()
            .finalize().unwrap();
        let (issuer_pub, issuer_priv) = Issuer::new_keys(&claim_schema, false).unwrap();

        let master_secret = Prover::new_master_secret().unwrap();
        let (blinded_master_secret, blinded_master_secret_data) = Prover::blinded_master_secret(&issuer_pub, &master_secret).unwrap();
        let claim_schema_values_builder = Issuer::new_claim_values_builder().unwrap();
        let claim_values = claim_schema_values_builder
            .add_value("name", "1139481716457488690172217916278103335").unwrap()
            .add_value("sex", "5944657099558967239210949258394887428692050081607692519917050011144233115103").unwrap()
            .add_value("age", "28").unwrap()
            .add_value("height", "175").unwrap()
            .finalize().unwrap();
        let mut claim = Issuer::sign_claim("CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW", &blinded_master_secret,
                                           &claim_values,
                                           &issuer_pub, &issuer_priv,
                                           Some(1), None, None).unwrap();
        Prover::process_claim_signature(&mut claim, &blinded_master_secret_data, &issuer_pub, None).unwrap();

        let sub_proof_request = SubProofRequestBuilder::new().unwrap()
            .add_revealed_attr("name").unwrap()
            .add_predicate(&Predicate {
                attr_name: "age".to_string(),
                value: 18,
                p_type: PredicateType::GE,
            }).unwrap()
            .finalize().unwrap();
        let mut proof_builder = Prover::new_proof_builder().unwrap();
        proof_builder.add_sub_proof_request("issuer_key_id_1", &claim, claim_values,
                                            &issuer_pub,
                                            None,
                                            sub_proof_request.clone(),
                                            claim_schema.clone()).unwrap();
        let nonce = Verifier::new_nonce().unwrap();
        let proof = proof_builder.finalize(&nonce, &master_secret).unwrap();

        let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
        proof_verifier.add_sub_proof_request("issuer_key_id_1", issuer_pub, None, sub_proof_request, claim_schema).unwrap();
        assert_eq!(true, proof_verifier.verify(&proof, &nonce).unwrap());
    }
}
