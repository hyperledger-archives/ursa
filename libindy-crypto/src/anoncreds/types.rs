use bn::BigNumber;
use errors::IndyCryptoError;

use pair::{
    GroupOrderElement,
    PointG1,
    PointG2,
    Pair
};

use std::collections::{HashMap, HashSet};

pub struct ClaimAttributes {
    pub attrs: HashSet<String>
}

pub struct ClaimAttributesBuilder {
    attrs: HashSet<String>
}

impl ClaimAttributesBuilder {
    pub fn new() -> Result<ClaimAttributesBuilder, IndyCryptoError> {
        Ok(ClaimAttributesBuilder {
            attrs: HashSet::new()
        })
    }

    pub fn add_attr(&mut self, attr: &str) -> Result<(), IndyCryptoError> {
        self.attrs.insert(attr.to_owned());
        Ok(())
    }

    pub fn finalize(self, attribute: String) -> Result<ClaimAttributes, IndyCryptoError> {
        Ok(ClaimAttributes {
            attrs: self.attrs
        })
    }
}

pub struct ClaimAttributesValues {
    pub attrs_values: HashMap<String, BigNumber>
}

pub struct ClaimAttributesValuesBuilder {
    attrs_values: HashMap<String, BigNumber>
}

impl ClaimAttributesValuesBuilder {
    pub fn new() -> Result<ClaimAttributesValuesBuilder, IndyCryptoError> {
        Ok(ClaimAttributesValuesBuilder {
            attrs_values: HashMap::new()
        })
    }

    pub fn add_attr_value(&mut self, attr: &str, dec_value: &str) -> Result<(), IndyCryptoError> {
        self.attrs_values.insert(attr.to_owned(), BigNumber::from_dec(dec_value)?);
        Ok(())
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
    pub r: HashMap<String, BigNumber>,
    pub rctxt: BigNumber,
    pub z: BigNumber
}

pub struct IssuerRevocationPrivateKey {
    pub x: GroupOrderElement,
    pub sk: GroupOrderElement
}

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

pub struct IssuerPublicKey {
    pub p_key: IssuerPrimaryPublicKey,
    pub r_key: Option<IssuerRevocationPublicKey>,
}

pub struct IssuerPrivateKey {
    pub p_key: IssuerPrimaryPrivateKey,
    pub r_key: Option<IssuerRevocationPrivateKey>,
}

pub struct RevocationAccumulator {
    pub acc: PointG2,
    pub v: HashSet<u32>,
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

pub struct RevocationAccumulatorPrivateKey {
    pub gamma: GroupOrderElement
}

pub struct RevocationAccumulatorPublicKey {
    pub z: Pair
}

pub struct RevocationAccumulatorTails {
    pub tails: HashMap<u32, PointG1>,
    pub tails_dash: HashMap<u32, PointG2>,
}

pub struct RevocationRegistryPublic {
    pub key: RevocationAccumulatorPublicKey,
    pub acc: RevocationAccumulator,
    pub tails: RevocationAccumulatorTails,
}

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

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NonRevocationClaim {
    pub sigma: PointG1,
    pub c: GroupOrderElement,
    pub vr_prime_prime: GroupOrderElement,
    pub witness: Witness,
    pub g_i: PointG1,
    pub i: u32,
    pub m2: GroupOrderElement
}

pub struct Claim {
    pub p_claim: PrimaryClaim,
    pub r_claim: Option<NonRevocationClaim>,
}

pub struct MasterSecret {
    pub ms: BigNumber,
}

pub struct BlindedMasterSecret {
    pub u: BigNumber,
    pub ur: Option<PointG1>,
}

pub struct MasterSecretBlindingData {
    pub u: BigNumber,
    pub ur: PointG1,
    pub v_prime: BigNumber,
    pub vr_prime: GroupOrderElement,
}