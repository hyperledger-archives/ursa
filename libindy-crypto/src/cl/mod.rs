extern crate serde_json;

mod constants;
mod helpers;
pub mod issuer;
pub mod prover;
pub mod verifier;

use bn::BigNumber;
use errors::IndyCryptoError;
use pair::*;
use utils::json::{JsonEncodable, JsonDecodable};

use std::collections::{HashMap, HashSet};
use std::hash::Hash;

/// A list of attributes a Claim is based on.
#[derive(Debug, Clone)]
pub struct ClaimSchema {
    attrs: HashSet<String> /* attr names */
}

/// A Builder of `Claim Schema`.
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

    pub fn add_attr(&mut self, attr: &str) -> Result<(), IndyCryptoError> {
        self.attrs.insert(attr.to_owned());
        Ok(())
    }

    pub fn finalize(self) -> Result<ClaimSchema, IndyCryptoError> {
        Ok(ClaimSchema {
            attrs: self.attrs
        })
    }
}

/// Values of attributes from `Claim Schema` (must be integers).
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

/// A Builder of `Claim Values`.
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

    pub fn add_value(&mut self, attr: &str, dec_value: &str) -> Result<(), IndyCryptoError> {
        self.attrs_values.insert(attr.to_owned(), BigNumber::from_dec(dec_value)?);
        Ok(())
    }

    pub fn finalize(self) -> Result<ClaimValues, IndyCryptoError> {
        Ok(ClaimValues {
            attrs_values: self.attrs_values
        })
    }
}

/// `Issuer Public Key` contains 2 internal parts.
/// One for signing primary claims and second for signing non-revocation claims.
/// These keys are used to proof that claim was issued and doesn’t revoked by this issuer.
/// Issuer keys have global identifier that must be known to all parties.
#[derive(Debug, Deserialize, Serialize)]
pub struct IssuerPublicKey {
    p_key: IssuerPrimaryPublicKey,
    r_key: Option<IssuerRevocationPublicKey>,
}

impl IssuerPublicKey {
    pub fn clone(&self) -> Result<IssuerPublicKey, IndyCryptoError> {
        Ok(IssuerPublicKey {
            p_key: self.p_key.clone()?,
            r_key: self.r_key.clone()
        })
    }
}

impl JsonEncodable for IssuerPublicKey {}

impl<'a> JsonDecodable<'a> for IssuerPublicKey {}

/// `Issuer Private Key`: contains 2 internal parts.
/// One for signing primary claims and second for signing non-revocation claims.
#[derive(Debug, Deserialize, Serialize)]
pub struct IssuerPrivateKey {
    p_key: IssuerPrimaryPrivateKey,
    r_key: Option<IssuerRevocationPrivateKey>,
}

impl JsonEncodable for IssuerPrivateKey {}

impl<'a> JsonDecodable<'a> for IssuerPrivateKey {}

/// `Primary Public Key` is used to prove that claim was issued and satisfy the proof request.
#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub struct IssuerPrimaryPublicKey {
    n: BigNumber,
    s: BigNumber,
    rms: BigNumber,
    r: HashMap<String /* attr_name */, BigNumber>,
    rctxt: BigNumber,
    z: BigNumber
}

impl IssuerPrimaryPublicKey {
    pub fn clone(&self) -> Result<IssuerPrimaryPublicKey, IndyCryptoError> {
        Ok(IssuerPrimaryPublicKey {
            n: self.n.clone()?,
            s: self.s.clone()?,
            rms: self.rms.clone()?,
            r: clone_bignum_map(&self.r)?,
            rctxt: self.rctxt.clone()?,
            z: self.z.clone()?
        })
    }
}

/// `Primary Private Key` is used for signing Claim
#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub struct IssuerPrimaryPrivateKey {
    p: BigNumber,
    q: BigNumber
}

/// `Revocation Public Key` is used to prove that claim wasn’t revoked by Issuer.
#[derive(Clone, Debug, Deserialize, Serialize)]
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

/// `Revocation Private Key` is used for signing Claim.
#[derive(Debug, Deserialize, Serialize)]
pub struct IssuerRevocationPrivateKey {
    x: GroupOrderElement,
    sk: GroupOrderElement
}

/// `Revocation Registry Public` contain revocation keys, accumulator and accumulator tails.
/// Must be shared by Issuer in trusted place
/// Can be used to proof that concrete claim wasn’t revoked.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RevocationRegistryPublic {
    key: RevocationAccumulatorPublicKey,
    acc: RevocationAccumulator,
    tails: RevocationAccumulatorTails,
}

impl JsonEncodable for RevocationRegistryPublic {}

impl<'a> JsonDecodable<'a> for RevocationRegistryPublic {}

/// `Revocation Registry Private` used for adding claims in the accumulator.
#[derive(Debug, Deserialize, Serialize)]
pub struct RevocationRegistryPrivate {
    key: RevocationAccumulatorPrivateKey,
}

impl JsonEncodable for RevocationRegistryPrivate {}

impl<'a> JsonDecodable<'a> for RevocationRegistryPrivate {}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RevocationAccumulator {
    acc: PointG2,
    v: HashSet<u32> /* used indexes */,
    max_claim_num: u32,
}

impl RevocationAccumulator {
    pub fn is_full(&self) -> bool {
        self.v.len() >= self.max_claim_num as usize
    }
    pub fn is_idx_used(&self, idx: u32) -> bool {
        self.v.contains(&idx)
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RevocationAccumulatorPrivateKey {
    gamma: GroupOrderElement
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RevocationAccumulatorPublicKey {
    z: Pair
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RevocationAccumulatorTails {
    tails: HashMap<u32 /* index in acc */, PointG1>,
    tails_dash: HashMap<u32 /* index in acc */, PointG2>,
}

/// Signed by the Issuer part of the Claim.
#[derive(Debug, Deserialize, Serialize)]
pub struct ClaimSignature {
    p_claim: PrimaryClaimSignature,
    r_claim: Option<NonRevocationClaimSignature> /* will be used to proof is claim revoked preparation */,
}

impl JsonEncodable for ClaimSignature {}

impl<'a> JsonDecodable<'a> for ClaimSignature {}

#[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct PrimaryClaimSignature {
    m_2: BigNumber,
    a: BigNumber,
    e: BigNumber,
    v: BigNumber
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NonRevocationClaimSignature {
    sigma: PointG1,
    c: GroupOrderElement,
    vr_prime_prime: GroupOrderElement,
    witness: Witness,
    g_i: PointG1,
    i: u32,
    m2: GroupOrderElement
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Witness {
    sigma_i: PointG2,
    u_i: PointG2,
    g_i: PointG1,
    omega: PointG2,
    v: HashSet<u32>
}

/// Secret prover data that is used to proof that prover owns the claim.
/// Prover blinds master secret by generating “Blinded Master Secret” and “Master Secret Blinding Data”
/// and sends “Blinded Master Secret” to Isseur that uses “Blinded Master Secret” in claim creation.
/// “Master Secret Blinding Dat” uses by Prover for post processing of claims received from Issuer
/// It allows to use this claim by prover only.
#[derive(Debug, Deserialize, Serialize)]
pub struct MasterSecret {
    ms: BigNumber,
}

impl JsonEncodable for MasterSecret {}

impl<'a> JsonDecodable<'a> for MasterSecret {}

/// `Blinded Master Secret` uses by Issuer in claim creation.
#[derive(Debug, Deserialize, Serialize)]
pub struct BlindedMasterSecret {
    u: BigNumber,
    ur: Option<PointG1>
}

impl JsonEncodable for BlindedMasterSecret {}

impl<'a> JsonDecodable<'a> for BlindedMasterSecret {}

/// `Master Secret Blinding Data` uses by Prover for post processing of claims received from Issuer.
#[derive(Debug, Deserialize, Serialize)]
pub struct MasterSecretBlindingData {
    v_prime: BigNumber,
    vr_prime: Option<GroupOrderElement>
}

impl JsonEncodable for MasterSecretBlindingData {}

impl<'a> JsonDecodable<'a> for MasterSecretBlindingData {}

#[derive(Eq, PartialEq, Debug)]
pub struct PrimaryBlindedMasterSecretData {
    u: BigNumber,
    v_prime: BigNumber,
}

#[derive(Debug)]
pub struct RevocationBlindedMasterSecretData {
    ur: PointG1,
    vr_prime: GroupOrderElement,
}

/// “Sub Proof Request” - input to create a Proof for a claim;
/// Contains attributes to be revealed and predicates.
#[derive(Debug, Clone)]
pub struct SubProofRequest {
    revealed_attrs: HashSet<String>,
    predicates: HashSet<Predicate>,
}

/// Builder of “Sub Proof Request”.
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

    pub fn add_revealed_attr(&mut self, attr: &str) -> Result<(), IndyCryptoError> {
        self.value.revealed_attrs.insert(attr.to_owned());
        Ok(())
    }

    pub fn add_predicate(&mut self, predicate: &Predicate) -> Result<(), IndyCryptoError> {
        self.value.predicates.insert(predicate.clone());
        Ok(())
    }

    pub fn finalize(self) -> Result<SubProofRequest, IndyCryptoError> {
        Ok(self.value)
    }
}

/// Some condition that must be proven.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
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

impl JsonEncodable for Predicate {}

impl<'a> JsonDecodable<'a> for Predicate {}

/// Condition type (Currently GE only).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub enum PredicateType {
    GE
}

/// Proof is complex crypto structure created by proved over multiple claims that allows to proof that prover:
/// 1) Owns claims issued with specific issuer keys (identified by key id)
/// 2) Claim contains attributes with specific values that prover wants to disclose
/// 3) Claim contains attributes with valid predicates that prover wants to disclose
#[derive(Debug, Deserialize, Serialize)]
pub struct Proof {
    proofs: HashMap<String /* issuer pub key id */, SubProof>,
    aggregated_proof: AggregatedProof,
}

impl JsonEncodable for Proof {}

impl<'a> JsonDecodable<'a> for Proof {}

#[derive(Debug, Deserialize, Serialize)]
pub struct SubProof {
    primary_proof: PrimaryProof,
    non_revoc_proof: Option<NonRevocProof>
}

#[derive(Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct AggregatedProof {
    c_hash: BigNumber,
    c_list: Vec<Vec<u8>>
}

#[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct PrimaryProof {
    eq_proof: PrimaryEqualProof,
    ge_proofs: Vec<PrimaryPredicateGEProof>
}

#[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct PrimaryEqualProof {
    revealed_attrs: HashMap<String /* attr_name of revealed */, BigNumber>,
    a_prime: BigNumber,
    e: BigNumber,
    v: BigNumber,
    m: HashMap<String /* attr_name of all except revealed */, BigNumber>,
    m1: BigNumber,
    m2: BigNumber
}

#[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct PrimaryPredicateGEProof {
    u: HashMap<String, BigNumber>,
    r: HashMap<String, BigNumber>,
    mj: BigNumber,
    alpha: BigNumber,
    t: HashMap<String, BigNumber>,
    predicate: Predicate
}

#[derive(Debug, Deserialize, Serialize)]
pub struct NonRevocProof {
    x_list: NonRevocProofXList,
    c_list: NonRevocProofCList
}

#[derive(Debug)]
pub struct InitProof {
    primary_init_proof: PrimaryInitProof,
    non_revoc_init_proof: Option<NonRevocInitProof>,
    claim_values: ClaimValues,
    sub_proof_request: SubProofRequest,
    claim_schema: ClaimSchema
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

#[derive(Clone, Debug, Deserialize, Serialize)]
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

#[derive(Clone, Debug, Deserialize, Serialize)]
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

/// Random BigNumber that uses `Prover` for proof generation and `Verifier` for proof verification.
#[derive(Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct Nonce {
    value: BigNumber
}

impl JsonEncodable for Nonce {}

impl<'a> JsonDecodable<'a> for Nonce {}

#[derive(Debug)]
pub struct VerifyClaim {
    pub_key: IssuerPublicKey,
    r_reg: Option<RevocationRegistryPublic>,
    sub_proof_request: SubProofRequest,
    claim_schema: ClaimSchema
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

fn clone_bignum_map<K: Clone + Eq + Hash>(other: &HashMap<K, BigNumber>)
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
    fn demo() {
        let mut claim_schema_builder = Issuer::new_claim_schema_builder().unwrap();
        claim_schema_builder.add_attr("name").unwrap();
        claim_schema_builder.add_attr("sex").unwrap();
        claim_schema_builder.add_attr("age").unwrap();
        claim_schema_builder.add_attr("height").unwrap();
        let claim_schema = claim_schema_builder.finalize().unwrap();
        let (issuer_pub_key, issuer_priv_key) = Issuer::new_keys(&claim_schema, false).unwrap();

        let master_secret = Prover::new_master_secret().unwrap();
        let (blinded_master_secret, master_secret_blinding_data) = Prover::blind_master_secret(&issuer_pub_key, &master_secret).unwrap();
        let mut claim_values_builder = Issuer::new_claim_values_builder().unwrap();
        claim_values_builder.add_value("name", "1139481716457488690172217916278103335").unwrap();
        claim_values_builder.add_value("sex", "5944657099558967239210949258394887428692050081607692519917050011144233115103").unwrap();
        claim_values_builder.add_value("age", "28").unwrap();
        claim_values_builder.add_value("height", "175").unwrap();
        let claim_values = claim_values_builder.finalize().unwrap();
        let mut claim_signature = Issuer::sign_claim("CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW", &blinded_master_secret,
                                                     &claim_values,
                                                     &issuer_pub_key,
                                                     &issuer_priv_key,
                                                     Some(1), None, None).unwrap();
        Prover::process_claim_signature(&mut claim_signature, &master_secret_blinding_data, &issuer_pub_key, None).unwrap();

        let mut sub_proof_request_builder = Verifier::new_sub_proof_request().unwrap();
        sub_proof_request_builder.add_revealed_attr("name").unwrap();
        sub_proof_request_builder.add_predicate(&Predicate {
            attr_name: "age".to_string(),
            value: 18,
            p_type: PredicateType::GE,
        }).unwrap();
        let sub_proof_request = sub_proof_request_builder.finalize().unwrap();
        let mut proof_builder = Prover::new_proof_builder().unwrap();
        proof_builder.add_sub_proof_request("issuer_key_id_1", &claim_signature, &claim_values,
                                            &issuer_pub_key,
                                            None,
                                            &sub_proof_request,
                                            &claim_schema).unwrap();
        let nonce = Verifier::new_nonce().unwrap();
        let proof = proof_builder.finalize(&nonce, &master_secret).unwrap();

        let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
        proof_verifier.add_sub_proof_request("issuer_key_id_1", &issuer_pub_key, None, &sub_proof_request, &claim_schema).unwrap();
        assert_eq!(true, proof_verifier.verify(&proof, &nonce).unwrap());
    }
}
