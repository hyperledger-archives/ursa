extern crate serde_json;

mod constants;
#[macro_use]
mod helpers;
pub mod issuer;
pub mod prover;
pub mod verifier;

use bn::BigNumber;
use errors::IndyCryptoError;
use pair::*;
use utils::json::{JsonEncodable, JsonDecodable};

use std::collections::{BTreeMap, HashMap, HashSet};
use std::hash::Hash;

/// Creates random nonce
///
/// # Example
/// ```
/// use indy_crypto::cl::new_nonce;
///
/// let _nonce = new_nonce().unwrap();
/// ```
pub fn new_nonce() -> Result<Nonce, IndyCryptoError> {
    Ok(helpers::bn_rand(constants::LARGE_NONCE)?)
}

/// A list of attributes a Claim is based on.
#[derive(Debug, Clone)]
pub struct CredentialSchema {
    attrs: HashSet<String> /* attr names */
}

/// A Builder of `Claim Schema`.
#[derive(Debug)]
pub struct CredentialSchemaBuilder {
    attrs: HashSet<String> /* attr names */
}

impl CredentialSchemaBuilder {
    pub fn new() -> Result<CredentialSchemaBuilder, IndyCryptoError> {
        Ok(CredentialSchemaBuilder {
            attrs: HashSet::new()
        })
    }

    pub fn add_attr(&mut self, attr: &str) -> Result<(), IndyCryptoError> {
        self.attrs.insert(attr.to_owned());
        Ok(())
    }

    pub fn finalize(self) -> Result<CredentialSchema, IndyCryptoError> {
        Ok(CredentialSchema {
            attrs: self.attrs
        })
    }
}

/// Values of attributes from `Claim Schema` (must be integers).
#[derive(Debug)]
pub struct CredentialValues {
    attrs_values: HashMap<String, BigNumber>
}

impl CredentialValues {
    pub fn clone(&self) -> Result<CredentialValues, IndyCryptoError> {
        Ok(CredentialValues {
            attrs_values: clone_bignum_map(&self.attrs_values)?
        })
    }
}

/// A Builder of `Claim Values`.
#[derive(Debug)]
pub struct CredentialValuesBuilder {
    attrs_values: HashMap<String, BigNumber> /* attr_name -> int representation of value */
}

impl CredentialValuesBuilder {
    pub fn new() -> Result<CredentialValuesBuilder, IndyCryptoError> {
        Ok(CredentialValuesBuilder {
            attrs_values: HashMap::new()
        })
    }

    pub fn add_value(&mut self, attr: &str, dec_value: &str) -> Result<(), IndyCryptoError> {
        self.attrs_values.insert(attr.to_owned(), BigNumber::from_dec(dec_value)?);
        Ok(())
    }

    pub fn finalize(self) -> Result<CredentialValues, IndyCryptoError> {
        Ok(CredentialValues {
            attrs_values: self.attrs_values
        })
    }
}

/// `Issuer Public Key` contains 2 internal parts.
/// One for signing primary credentials and second for signing non-revocation credentials.
/// These keys are used to proof that credential was issued and doesn’t revoked by this issuer.
/// Issuer keys have global identifier that must be known to all parties.
#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct CredentialPublicKey {
    p_key: CredentialPrimaryPublicKey,
    r_key: Option<CredentialRevocationPublicKey>,
}

impl CredentialPublicKey {
    pub fn clone(&self) -> Result<CredentialPublicKey, IndyCryptoError> {
        Ok(CredentialPublicKey {
            p_key: self.p_key.clone()?,
            r_key: self.r_key.clone()
        })
    }

    pub fn get_primary_key(&self) -> Result<CredentialPrimaryPublicKey, IndyCryptoError> {
        Ok(self.p_key.clone()?)
    }

    pub fn get_revocation_key(&self) -> Result<Option<CredentialRevocationPublicKey>, IndyCryptoError> {
        Ok(self.r_key.clone())
    }

    pub fn build_from_parts(p_key: &CredentialPrimaryPublicKey, r_key: Option<&CredentialRevocationPublicKey>) -> Result<CredentialPublicKey, IndyCryptoError> {
        Ok(CredentialPublicKey {
            p_key: p_key.clone()?,
            r_key: r_key.map(|key| key.clone())
        })
    }
}

impl JsonEncodable for CredentialPublicKey {}

impl<'a> JsonDecodable<'a> for CredentialPublicKey {}

/// `Issuer Private Key`: contains 2 internal parts.
/// One for signing primary credentials and second for signing non-revocation credentials.
#[derive(Debug, Deserialize, Serialize)]
pub struct CredentialPrivateKey {
    p_key: CredentialPrimaryPrivateKey,
    r_key: Option<CredentialRevocationPrivateKey>,
}

impl JsonEncodable for CredentialPrivateKey {}

impl<'a> JsonDecodable<'a> for CredentialPrivateKey {}

/// Issuer's "Public Key" is used to verify the Issuer's signature over the Claim's attributes' values (primary credential).
#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub struct CredentialPrimaryPublicKey {
    n: BigNumber,
    s: BigNumber,
    rms: BigNumber,
    r: BTreeMap<String /* attr_name */, BigNumber>,
    rctxt: BigNumber,
    z: BigNumber
}

impl CredentialPrimaryPublicKey {
    pub fn clone(&self) -> Result<CredentialPrimaryPublicKey, IndyCryptoError> {
        Ok(CredentialPrimaryPublicKey {
            n: self.n.clone()?,
            s: self.s.clone()?,
            rms: self.rms.clone()?,
            r: clone_btree_bignum_map(&self.r)?,
            rctxt: self.rctxt.clone()?,
            z: self.z.clone()?
        })
    }
}

/// Issuer's "Private Key" used for signing Claim's attributes' values (primary credential)
#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub struct CredentialPrimaryPrivateKey {
    p: BigNumber,
    q: BigNumber
}

/// `Primary Public Key Metadata` required for building of Proof Correctness of `Issuer Public Key`
#[derive(Debug)]
pub struct CredentialPrimaryPublicKeyMetadata {
    xz: BigNumber,
    xr: BTreeMap<String, BigNumber>
}

/// Proof of `Issuer Public Key` correctness
#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub struct CredentialKeyCorrectnessProof {
    c: BigNumber,
    xz_cap: BigNumber,
    xr_cap: BTreeMap<String, BigNumber>
}

impl JsonEncodable for CredentialKeyCorrectnessProof {}

impl<'a> JsonDecodable<'a> for CredentialKeyCorrectnessProof {}

/// `Revocation Public Key` is used to verify that credential was'nt revoked by Issuer.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct CredentialRevocationPublicKey {
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
pub struct CredentialRevocationPrivateKey {
    x: GroupOrderElement,
    sk: GroupOrderElement
}

pub type Accumulator = PointG2;

/// `Revocation Registry` contains accumulator.
/// Must be published by Issuer on a tamper-evident and highly available storage
/// Used by prover to prove that a claim hasn't revoked by the issuer
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RevocationRegistry {
    accum: Accumulator
}

impl JsonEncodable for RevocationRegistry {}

impl<'a> JsonDecodable<'a> for RevocationRegistry {}

/// `Revocation Registry Delta` contains Accumulator changes.
/// Must be applied to `Revocation Registry`
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RevocationRegistryDelta {
    prev_accum: Option<Accumulator>,
    accum: Accumulator,
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    #[serde(default)]
    issued: HashSet<u32>,
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    #[serde(default)]
    revoked: HashSet<u32>
}

impl JsonEncodable for RevocationRegistryDelta {}

impl<'a> JsonDecodable<'a> for RevocationRegistryDelta {}

impl RevocationRegistryDelta {
    pub fn merge(&mut self, other_delta: &RevocationRegistryDelta) -> Result<(), IndyCryptoError> {
        if other_delta.prev_accum.is_none() || self.accum != other_delta.prev_accum.unwrap() {
            return Err(IndyCryptoError::InvalidStructure(format!("Deltas can not be merged.")));
        }

        self.prev_accum = Some(self.accum);
        self.accum = other_delta.accum;

        self.issued.extend(
            other_delta.issued.difference(&self.revoked));

        self.revoked.extend(
            other_delta.revoked.difference(&self.issued));

        for index in other_delta.revoked.iter() {
            self.issued.remove(index);
        }

        for index in other_delta.issued.iter() {
            self.revoked.remove(index);
        }

        Ok(())
    }
}

/// `Revocation Key Public` Accumulator public key.
/// Must be published together with Accumulator
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RevocationKeyPublic {
    z: Pair
}

impl JsonEncodable for RevocationKeyPublic {}

impl<'a> JsonDecodable<'a> for RevocationKeyPublic {}

/// `Revocation Key Private` Accumulator primate key.
#[derive(Debug, Deserialize, Serialize)]
pub struct RevocationKeyPrivate {
    gamma: GroupOrderElement
}

impl JsonEncodable for RevocationKeyPrivate {}

impl<'a> JsonDecodable<'a> for RevocationKeyPrivate {}

/// `Tail` point of curve used to update accumulator.
pub type Tail = PointG2;

impl Tail {
    fn new_tail(index: u32, g_dash: &PointG2, gamma: &GroupOrderElement) -> Result<Tail, IndyCryptoError> {
        let i_bytes = helpers::transform_u32_to_array_of_u8(index);
        let mut pow = GroupOrderElement::from_bytes(&i_bytes)?;
        pow = gamma.pow_mod(&pow)?;
        Ok(g_dash.mul(&pow)?)
    }
}

/// Generator of `Tail's`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RevocationTailsGenerator {
    size: u32,
    current_index: u32,
    g_dash: PointG2,
    gamma: GroupOrderElement
}

impl RevocationTailsGenerator {
    fn new(max_cred_num: u32, gamma: GroupOrderElement, g_dash: PointG2) -> Self {
        RevocationTailsGenerator {
            size: 2 * max_cred_num + 1, /* Unused 0th + valuable 1..L + unused (L+1)th + valuable (L+2)..(2L) */
            current_index: 0,
            gamma,
            g_dash,
        }
    }

    pub fn count(&self) -> u32 {
        self.size - self.current_index
    }

    pub fn next(&mut self) -> Result<Option<Tail>, IndyCryptoError> {
        if self.current_index >= self.size {
            return Ok(None);
        }

        let tail = Tail::new_tail(self.current_index, &self.g_dash, &self.gamma)?;

        self.current_index += 1;

        Ok(Some(tail))
    }
}

impl JsonEncodable for RevocationTailsGenerator {}

impl<'a> JsonDecodable<'a> for RevocationTailsGenerator {}

pub trait RevocationTailsAccessor {
    fn access_tail(&self, tail_id: u32, accessor: &mut FnMut(&Tail)) -> Result<(), IndyCryptoError>;
}

/// Simple implementation of `RevocationTailsAccessor` that stores all tails as HashMap.
#[derive(Debug, Clone)]
pub struct SimpleTailsAccessor {
    tails: Vec<Tail>
}

impl RevocationTailsAccessor for SimpleTailsAccessor {
    fn access_tail(&self, tail_id: u32, accessor: &mut FnMut(&Tail)) -> Result<(), IndyCryptoError> {
        Ok(accessor(&self.tails[tail_id as usize]))
    }
}

impl SimpleTailsAccessor {
    pub fn new(rev_tails_generator: &mut RevocationTailsGenerator) -> Result<SimpleTailsAccessor, IndyCryptoError> {
        let mut tails: Vec<Tail> = Vec::new();
        while let Some(tail) = rev_tails_generator.next()? {
            tails.push(tail);
        }
        Ok(SimpleTailsAccessor {
            tails
        })
    }
}


/// Issuer's signature over Claim attribute values.
#[derive(Debug, Deserialize, Serialize)]
pub struct CredentialSignature {
    p_credential: PrimaryCredentialSignature,
    r_credential: Option<NonRevocationCredentialSignature> /* will be used to proof is credential revoked preparation */,
}

impl CredentialSignature {
    pub fn extract_index(&self) -> Option<u32> {
        self.r_credential
            .as_ref()
            .map(|r_credential| r_credential.i)
    }
}

impl JsonEncodable for CredentialSignature {}

impl<'a> JsonDecodable<'a> for CredentialSignature {}

#[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct PrimaryCredentialSignature {
    m_2: BigNumber,
    a: BigNumber,
    e: BigNumber,
    v: BigNumber
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NonRevocationCredentialSignature {
    sigma: PointG1,
    c: GroupOrderElement,
    vr_prime_prime: GroupOrderElement,
    witness_signature: WitnessSignature,
    g_i: PointG1,
    i: u32,
    m2: GroupOrderElement
}

#[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct SignatureCorrectnessProof {
    se: BigNumber,
    c: BigNumber
}

impl JsonEncodable for SignatureCorrectnessProof {}

impl<'a> JsonDecodable<'a> for SignatureCorrectnessProof {}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Witness {
    omega: PointG2
}

impl JsonEncodable for Witness {}

impl<'a> JsonDecodable<'a> for Witness {}

impl Witness {
    pub fn new<RTA>(rev_idx: u32,
                    max_cred_num: u32,
                    rev_reg_delta: &RevocationRegistryDelta,
                    rev_tails_accessor: &RTA) -> Result<Witness, IndyCryptoError> where RTA: RevocationTailsAccessor {
        trace!("Witness::new: >>> rev_idx: {:?}, max_cred_num: {:?}, rev_reg_delta: {:?}",
               rev_idx, max_cred_num, rev_reg_delta);

        let mut omega = PointG2::new_inf()?;

        let mut issued = rev_reg_delta.issued.clone();
        issued.remove(&rev_idx);

        for j in issued.iter() {
            let index = max_cred_num + 1 - j + rev_idx;
            rev_tails_accessor.access_tail(index, &mut |tail| {
                omega = omega.add(tail).unwrap();
            })?;
        }

        let witness = Witness {
            omega
        };

        trace!("Witness::new: <<< witness: {:?}", witness);

        Ok(witness)
    }

    pub fn update<RTA>(&mut self,
                       rev_idx: u32,
                       max_cred_num: u32,
                       rev_reg_delta: &RevocationRegistryDelta,
                       rev_tails_accessor: &RTA) -> Result<(), IndyCryptoError> where RTA: RevocationTailsAccessor {
        trace!("Witness::update: >>> rev_idx: {:?}, max_cred_num: {:?}, rev_reg_delta: {:?}",
               rev_idx, max_cred_num, rev_reg_delta);

        let mut omega_denom = PointG2::new_inf()?;
        for j in rev_reg_delta.revoked.iter() {
            if rev_idx.eq(j) { continue; }

            let index = max_cred_num + 1 - j + rev_idx;
            rev_tails_accessor.access_tail(index, &mut |tail| {
                omega_denom = omega_denom.add(tail).unwrap();
            })?;
        }

        let mut omega_num = PointG2::new_inf()?;
        for j in rev_reg_delta.issued.iter() {
            if rev_idx.eq(j) { continue; }

            let index = max_cred_num + 1 - j + rev_idx;
            rev_tails_accessor.access_tail(index, &mut |tail| {
                omega_num = omega_num.add(tail).unwrap();
            })?;
        }

        let new_omega: PointG2 = self.omega.add(
            &omega_num.sub(&omega_denom)?)?;

        self.omega = new_omega;

        trace!("Witness::update: <<<");

        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WitnessSignature {
    sigma_i: PointG2,
    u_i: PointG2,
    g_i: PointG1
}

/// Secret key encoded in a credential that is used to prove that prover owns the credential; can be used to
/// prove linkage across credentials.
/// Prover blinds master secret, generating `BlindedMasterSecret` and `MasterSecretBlindingData` (blinding factors)
/// and sends the `BlindedMasterSecret` to Issuer who then encodes it credential creation.
/// The blinding factors are used by Prover for post processing of issued credentials.
#[derive(Debug, Deserialize, Serialize)]
pub struct MasterSecret {
    ms: BigNumber,
}

impl MasterSecret {
    pub fn clone(&self) -> Result<MasterSecret, IndyCryptoError> {
        Ok(MasterSecret { ms: self.ms.clone()? })
    }
}

impl JsonEncodable for MasterSecret {}

impl<'a> JsonDecodable<'a> for MasterSecret {}

/// Blinded Master Secret uses by Issuer in credential creation.
#[derive(Debug, Deserialize, Serialize)]
pub struct BlindedMasterSecret {
    u: BigNumber,
    ur: Option<PointG1>
}

impl JsonEncodable for BlindedMasterSecret {}

impl<'a> JsonDecodable<'a> for BlindedMasterSecret {}

/// `Master Secret Blinding Data` used by Prover for post processing of credentials received from Issuer.
/// TODO: Should be renamed `MasterSecretBlindingFactors`
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

#[derive(Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct BlindedMasterSecretCorrectnessProof {
    c: BigNumber,
    v_dash_cap: BigNumber,
    ms_cap: BigNumber
}

impl JsonEncodable for BlindedMasterSecretCorrectnessProof {}

impl<'a> JsonDecodable<'a> for BlindedMasterSecretCorrectnessProof {}

/// “Sub Proof Request” - input to create a Proof for a credential;
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

    pub fn add_predicate(&mut self, attr_name: &str, p_type: &str, value: i32) -> Result<(), IndyCryptoError> {
        let p_type = match p_type {
            "GE" => PredicateType::GE,
            p_type => return Err(IndyCryptoError::InvalidStructure(format!("Invalid predicate type: {:?}", p_type)))
        };

        let predicate = Predicate {
            attr_name: attr_name.to_owned(),
            p_type,
            value
        };

        self.value.predicates.insert(predicate);
        Ok(())
    }

    pub fn finalize(self) -> Result<SubProofRequest, IndyCryptoError> {
        Ok(self.value)
    }
}

/// Some condition that must be satisfied.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct Predicate {
    attr_name: String,
    p_type: PredicateType,
    value: i32,
}

/// Condition type (Currently GE only).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub enum PredicateType {
    GE
}

/// Proof is complex crypto structure created by prover over multiple credentials that allows to prove that prover:
/// 1) Knows signature over credentials issued with specific issuer keys (identified by key id)
/// 2) Claim contains attributes with specific values that prover wants to disclose
/// 3) Claim contains attributes with valid predicates that verifier wants the prover to satisfy.
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
    credential_values: CredentialValues,
    sub_proof_request: SubProofRequest,
    credential_schema: CredentialSchema
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
pub type Nonce = BigNumber;

impl JsonEncodable for Nonce {}

impl<'a> JsonDecodable<'a> for Nonce {}

#[derive(Debug)]
pub struct VerifiableCredential {
    pub_key: CredentialPublicKey,
    sub_proof_request: SubProofRequest,
    credential_schema: CredentialSchema,
    rev_key_pub: Option<RevocationKeyPublic>,
    rev_reg: Option<RevocationRegistry>
}

trait BytesView {
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

trait AppendByteArray {
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

fn clone_btree_bignum_map<K: Clone + Eq + Hash + Ord>(other: &BTreeMap<K, BigNumber>)
                                                      -> Result<BTreeMap<K, BigNumber>, IndyCryptoError> {
    let mut res: BTreeMap<K, BigNumber> = BTreeMap::new();
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
        let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
        credential_schema_builder.add_attr("name").unwrap();
        credential_schema_builder.add_attr("sex").unwrap();
        credential_schema_builder.add_attr("age").unwrap();
        credential_schema_builder.add_attr("height").unwrap();
        let credential_schema = credential_schema_builder.finalize().unwrap();

        let (cred_pub_key, cred_priv_key, cred_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, true).unwrap();

        let master_secret = Prover::new_master_secret().unwrap();

        let master_secret_blinding_nonce = new_nonce().unwrap();

        let (blinded_master_secret, master_secret_blinding_data, blinded_master_secret_correctness_proof) =
            Prover::blind_master_secret(&cred_pub_key,
                                        &cred_key_correctness_proof,
                                        &master_secret,
                                        &master_secret_blinding_nonce).unwrap();

        let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();
        credential_values_builder.add_value("name", "1139481716457488690172217916278103335").unwrap();
        credential_values_builder.add_value("sex", "5944657099558967239210949258394887428692050081607692519917050011144233115103").unwrap();
        credential_values_builder.add_value("age", "28").unwrap();
        credential_values_builder.add_value("height", "175").unwrap();
        let cred_values = credential_values_builder.finalize().unwrap();

        let cred_issuance_nonce = new_nonce().unwrap();

        let (mut cred_signature, signature_correctness_proof) = Issuer::sign_credential("CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW",
                                                                                        &blinded_master_secret,
                                                                                        &blinded_master_secret_correctness_proof,
                                                                                        &master_secret_blinding_nonce,
                                                                                        &cred_issuance_nonce,
                                                                                        &cred_values,
                                                                                        &cred_pub_key,
                                                                                        &cred_priv_key).unwrap();

        Prover::process_credential_signature(&mut cred_signature,
                                             &cred_values,
                                             &signature_correctness_proof,
                                             &master_secret_blinding_data,
                                             &master_secret,
                                             &cred_pub_key,
                                             &cred_issuance_nonce,
                                             None,
                                             None,
                                             None).unwrap();

        let mut sub_proof_request_builder = Verifier::new_sub_proof_request_builder().unwrap();
        sub_proof_request_builder.add_revealed_attr("name").unwrap();
        sub_proof_request_builder.add_predicate("age", "GE", 18).unwrap();
        let sub_proof_request = sub_proof_request_builder.finalize().unwrap();
        let mut proof_builder = Prover::new_proof_builder().unwrap();
        proof_builder.add_sub_proof_request("issuer_key_id_1",
                                            &sub_proof_request,
                                            &credential_schema,
                                            &cred_signature,
                                            &cred_values,
                                            &cred_pub_key,
                                            None,
                                            None).unwrap();

        let proof_request_nonce = new_nonce().unwrap();
        let proof = proof_builder.finalize(&proof_request_nonce, &master_secret).unwrap();

        let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
        proof_verifier.add_sub_proof_request("issuer_key_id_1",
                                             &sub_proof_request,
                                             &credential_schema,
                                             &cred_pub_key,
                                             None,
                                             None).unwrap();
        assert!(proof_verifier.verify(&proof, &proof_request_nonce).unwrap());
    }

    #[test]
    fn demo_revocation() {
        let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
        credential_schema_builder.add_attr("name").unwrap();
        credential_schema_builder.add_attr("sex").unwrap();
        credential_schema_builder.add_attr("age").unwrap();
        credential_schema_builder.add_attr("height").unwrap();
        let credential_schema = credential_schema_builder.finalize().unwrap();

        let (cred_pub_key, cred_priv_key, cred_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, true).unwrap();

        let max_cred_num = 5;
        let issuance_by_default = false;
        let (rev_key_pub, rev_key_priv, mut rev_reg, mut rev_tails_generator) =
            Issuer::new_revocation_registry_def(&cred_pub_key, max_cred_num, issuance_by_default).unwrap();

        let simple_tail_accessor = SimpleTailsAccessor::new(&mut rev_tails_generator).unwrap();

        let master_secret = Prover::new_master_secret().unwrap();

        let master_secret_blinding_nonce = new_nonce().unwrap();

        let (blinded_master_secret, master_secret_blinding_data, blinded_master_secret_correctness_proof) =
            Prover::blind_master_secret(&cred_pub_key,
                                        &cred_key_correctness_proof,
                                        &master_secret,
                                        &master_secret_blinding_nonce).unwrap();

        let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();
        credential_values_builder.add_value("name", "1139481716457488690172217916278103335").unwrap();
        credential_values_builder.add_value("sex", "5944657099558967239210949258394887428692050081607692519917050011144233115103").unwrap();
        credential_values_builder.add_value("age", "28").unwrap();
        credential_values_builder.add_value("height", "175").unwrap();
        let cred_values = credential_values_builder.finalize().unwrap();

        let credential_issuance_nonce = new_nonce().unwrap();

        let rev_idx = 1;
        let (mut cred_signature, signature_correctness_proof, rev_reg_delta) =
            Issuer::sign_credential_with_revoc("CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW",
                                               &blinded_master_secret,
                                               &blinded_master_secret_correctness_proof,
                                               &master_secret_blinding_nonce,
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

        let witness = Witness::new(rev_idx, max_cred_num, &rev_reg_delta.unwrap(), &simple_tail_accessor).unwrap();

        Prover::process_credential_signature(&mut cred_signature,
                                             &cred_values,
                                             &signature_correctness_proof,
                                             &master_secret_blinding_data,
                                             &master_secret,
                                             &cred_pub_key,
                                             &credential_issuance_nonce,
                                             Some(&rev_key_pub),
                                             Some(&rev_reg),
                                             Some(&witness)).unwrap();

        let mut sub_proof_request_builder = Verifier::new_sub_proof_request_builder().unwrap();
        sub_proof_request_builder.add_revealed_attr("name").unwrap();
        sub_proof_request_builder.add_predicate("age", "GE", 18).unwrap();
        let sub_proof_request = sub_proof_request_builder.finalize().unwrap();
        let mut proof_builder = Prover::new_proof_builder().unwrap();
        proof_builder.add_sub_proof_request("issuer_key_id_1",
                                            &sub_proof_request,
                                            &credential_schema,
                                            &cred_signature,
                                            &cred_values,
                                            &cred_pub_key,
                                            Some(&rev_reg),
                                            Some(&witness)).unwrap();
        let proof_request_nonce = new_nonce().unwrap();
        let proof = proof_builder.finalize(&proof_request_nonce, &master_secret).unwrap();

        let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
        proof_verifier.add_sub_proof_request("issuer_key_id_1",
                                             &sub_proof_request,
                                             &credential_schema,
                                             &cred_pub_key,
                                             Some(&rev_key_pub),
                                             Some(&rev_reg)).unwrap();
        assert_eq!(true, proof_verifier.verify(&proof, &proof_request_nonce).unwrap());
    }
}
