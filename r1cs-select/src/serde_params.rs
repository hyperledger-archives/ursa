use bellman::groth16::{Parameters, VerifyingKey};
use bls12_381::{Bls12, G1Affine, G2Affine};
use serde::{
    de::{Error as DError, SeqAccess, Unexpected, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::{convert::TryFrom, sync::Arc};

macro_rules! gb {
    ($v:expr, $size:expr) => {
        <[u8; $size]>::try_from($v).unwrap()
    };
}

/// The proof parameters
/// Each field is an uncompressed affine point
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct SerdeParameters {
    pub vk: SerdeVerifyingKey,
    #[serde(with = "SerdeAffine")]
    pub h: Vec<Vec<u8>>,
    #[serde(with = "SerdeAffine")]
    pub l: Vec<Vec<u8>>,
    #[serde(with = "SerdeAffine")]
    pub a: Vec<Vec<u8>>,
    #[serde(with = "SerdeAffine")]
    pub b_g1: Vec<Vec<u8>>,
    #[serde(with = "SerdeAffine")]
    pub b_g2: Vec<Vec<u8>>,
}

impl Default for SerdeParameters {
    fn default() -> Self {
        Self {
            vk: Default::default(),
            h: vec![],
            l: vec![],
            a: vec![],
            b_g1: vec![],
            b_g2: vec![],
        }
    }
}

impl From<Parameters<Bls12>> for SerdeParameters {
    fn from(p: Parameters<Bls12>) -> Self {
        Self {
            vk: p.vk.into(),
            h: p.h.iter().map(|h| h.to_compressed().to_vec()).collect(),
            l: p.l.iter().map(|l| l.to_compressed().to_vec()).collect(),
            a: p.a.iter().map(|a| a.to_compressed().to_vec()).collect(),
            b_g1: p.b_g1.iter().map(|a| a.to_compressed().to_vec()).collect(),
            b_g2: p.b_g2.iter().map(|a| a.to_compressed().to_vec()).collect(),
        }
    }
}

impl From<SerdeParameters> for Parameters<Bls12> {
    fn from(p: SerdeParameters) -> Self {
        bellman::groth16::Parameters::<Bls12> {
            vk: p.vk.into(),
            h: Arc::new(
                p.h.iter()
                    .map(|h| G1Affine::from_compressed(&gb!(h.as_slice(), 48)).unwrap())
                    .collect(),
            ),
            l: Arc::new(
                p.l.iter()
                    .map(|l| G1Affine::from_compressed(&gb!(l.as_slice(), 48)).unwrap())
                    .collect(),
            ),
            a: Arc::new(
                p.a.iter()
                    .map(|a| G1Affine::from_compressed(&gb!(a.as_slice(), 48)).unwrap())
                    .collect(),
            ),
            b_g1: Arc::new(
                p.b_g1
                    .iter()
                    .map(|a| G1Affine::from_compressed(&gb!(a.as_slice(), 48)).unwrap())
                    .collect(),
            ),
            b_g2: Arc::new(
                p.b_g2
                    .iter()
                    .map(|a| G2Affine::from_compressed(&gb!(a.as_slice(), 96)).unwrap())
                    .collect(),
            ),
        }
    }
}

/// The Groth16 verification key
/// Each field is an uncompressed affine point
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct SerdeVerifyingKey {
    #[serde(with = "SerdeAffine")]
    pub alpha_g1: Vec<u8>,
    #[serde(with = "SerdeAffine")]
    pub beta_g1: Vec<u8>,
    #[serde(with = "SerdeAffine")]
    pub beta_g2: Vec<u8>,
    #[serde(with = "SerdeAffine")]
    pub gamma_g2: Vec<u8>,
    #[serde(with = "SerdeAffine")]
    pub delta_g1: Vec<u8>,
    #[serde(with = "SerdeAffine")]
    pub delta_g2: Vec<u8>,
    #[serde(with = "SerdeAffine")]
    pub ic: Vec<Vec<u8>>,
}

impl Default for SerdeVerifyingKey {
    fn default() -> Self {
        Self {
            alpha_g1: vec![],
            beta_g1: vec![],
            beta_g2: vec![],
            gamma_g2: vec![],
            delta_g1: vec![],
            delta_g2: vec![],
            ic: vec![],
        }
    }
}

impl From<VerifyingKey<Bls12>> for SerdeVerifyingKey {
    fn from(k: VerifyingKey<Bls12>) -> Self {
        Self {
            alpha_g1: k.alpha_g1.to_compressed().to_vec(),
            beta_g1: k.beta_g1.to_compressed().to_vec(),
            beta_g2: k.beta_g2.to_compressed().to_vec(),
            gamma_g2: k.gamma_g2.to_compressed().to_vec(),
            delta_g1: k.delta_g1.to_compressed().to_vec(),
            delta_g2: k.delta_g2.to_compressed().to_vec(),
            ic: k.ic.iter().map(|p| p.to_compressed().to_vec()).collect(),
        }
    }
}

impl From<SerdeVerifyingKey> for VerifyingKey<Bls12> {
    fn from(k: SerdeVerifyingKey) -> VerifyingKey<Bls12> {
        VerifyingKey::<Bls12> {
            alpha_g1: G1Affine::from_compressed(&gb!(k.alpha_g1.as_slice(), 48)).unwrap(),
            beta_g1: G1Affine::from_compressed(&gb!(k.beta_g1.as_slice(), 48)).unwrap(),
            beta_g2: G2Affine::from_compressed(&gb!(k.beta_g2.as_slice(), 96)).unwrap(),
            gamma_g2: G2Affine::from_compressed(&gb!(k.gamma_g2.as_slice(), 96)).unwrap(),
            delta_g1: G1Affine::from_compressed(&gb!(k.beta_g1.as_slice(), 48)).unwrap(),
            delta_g2: G2Affine::from_compressed(&gb!(k.beta_g2.as_slice(), 96)).unwrap(),
            ic: k
                .ic
                .iter()
                .map(|p| G1Affine::from_compressed(&gb!(p.as_slice(), 48)).unwrap())
                .collect(),
        }
    }
}

trait SerdeAffine<'de>: Sized {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer;
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>;
}

impl<'de> SerdeAffine<'de> for Vec<Vec<u8>> {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut out = Vec::with_capacity(self.len());
        for b in self {
            out.push(hex::encode(b));
        }
        out.serialize(s)
    }

    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct AffineVisitor;

        impl<'de> Visitor<'de> for AffineVisitor {
            type Value = Vec<Vec<u8>>;

            fn expecting(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
                fmt.write_str("expected array")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Vec<Vec<u8>>, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut out = Vec::new();
                while let Some(a) = seq.next_element()? {
                    out.push(
                        hex::decode(a)
                            .map_err(|_| DError::invalid_type(Unexpected::Str(a), &self))?,
                    );
                }
                Ok(out)
            }
        }

        deserializer.deserialize_seq(AffineVisitor)
    }
}

impl<'de> SerdeAffine<'de> for Vec<u8> {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let d = hex::encode(self);
        s.serialize_str(&d)
    }

    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct AffineVisitor;

        impl<'de> Visitor<'de> for AffineVisitor {
            type Value = Vec<u8>;

            fn expecting(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
                fmt.write_str("expected string")
            }

            fn visit_str<E>(self, s: &str) -> Result<Vec<u8>, E>
            where
                E: DError,
            {
                hex::decode(s).map_err(|_| DError::invalid_type(Unexpected::Str(s), &self))
            }
        }

        deserializer.deserialize_str(AffineVisitor)
    }
}
