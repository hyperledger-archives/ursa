use errors::IndyCryptoError;

use amcl::big::BIG;

use amcl::rom::{
    CURVE_GX,
    CURVE_GY,
    CURVE_ORDER,
    CURVE_PXA,
    CURVE_PYA,
    CURVE_PXB,
    CURVE_PYB,
    MODBYTES
};

use amcl::ecp::ECP;
use amcl::ecp2::ECP2;
use amcl::fp12::FP12;
use amcl::fp2::FP2;
use amcl::pair::{ate, g1mul, g2mul, gtpow, fexp};
use amcl::rand::RAND;

use rand::os::OsRng;
use rand::Rng;
use std::fmt::{Debug, Formatter, Error};

#[cfg(feature = "serialization")]
use serde::ser::{Serialize, Serializer, Error as SError};
#[cfg(feature = "serialization")]
use serde::de::{Deserialize, Deserializer, Visitor, Error as DError};
#[cfg(feature = "serialization")]
use std::fmt;

#[cfg(test)]
use std::cell::RefCell;

#[cfg(test)]
thread_local! {
  pub static PAIR_USE_MOCKS: RefCell<bool> = RefCell::new(false);
}

#[cfg(test)]
pub struct PairMocksHelper {}

#[cfg(test)]
impl PairMocksHelper {
    pub fn inject() {
        PAIR_USE_MOCKS.with(|use_mocks| {
            *use_mocks.borrow_mut() = true;
        });
    }

    pub fn is_injected() -> bool {
        PAIR_USE_MOCKS.with(|use_mocks| {
            return *use_mocks.borrow();
        })
    }
}

#[cfg(not(test))]
fn random_mod_order() -> Result<BIG, IndyCryptoError> {
    _random_mod_order()
}

#[cfg(test)]
fn random_mod_order() -> Result<BIG, IndyCryptoError> {
    if PairMocksHelper::is_injected() {
        Ok(BIG::from_hex("B7D7DC1499EA50 6F16C9B5FE2C00 466542B923D8C9 FB01F2122DE924 22EB5716".to_string()))
    }
    else {
        _random_mod_order()
    }
}

fn _random_mod_order() -> Result<BIG, IndyCryptoError> {
    let entropy_bytes = 128;
    let mut seed = vec![0; entropy_bytes];
    let mut os_rng = OsRng::new().unwrap();
    os_rng.fill_bytes(&mut seed.as_mut_slice());
    let mut rng = RAND::new();
    rng.clean();
    // AMCL recommends to initialise from at least 128 bytes, check doc for `RAND.seed`
    rng.seed(entropy_bytes, &seed);
    Ok(BIG::randomnum(&BIG::new_ints(&CURVE_ORDER), &mut rng))
}

#[derive(Copy, Clone, PartialEq)]
pub struct PointG1 {
    point: ECP
}

impl PointG1 {
    pub const BYTES_REPR_SIZE: usize = MODBYTES * 4;

    /// Creates new random PointG1
    pub fn new() -> Result<PointG1, IndyCryptoError> {
        // generate random point from the group G1
        let point_x = BIG::new_ints(&CURVE_GX);
        let point_y = BIG::new_ints(&CURVE_GY);
        let mut gen_g1 = ECP::new_bigs(&point_x, &point_y);

        let point = g1mul(&mut gen_g1, &mut random_mod_order()?);

        Ok(PointG1 {
            point: point
        })
    }

    /// Creates new infinity PointG1
    pub fn new_inf() -> Result<PointG1, IndyCryptoError> {
        let mut r = ECP::new();
        r.inf();
        Ok(PointG1 {
            point: r
        })
    }

    /// Checks infinity
    pub fn is_inf(&self) -> Result<bool, IndyCryptoError> {
        let mut r = self.point;
        Ok(r.is_infinity())
    }

    /// PointG1 ^ GroupOrderElement
    pub fn mul(&self, e: &GroupOrderElement) -> Result<PointG1, IndyCryptoError> {
        let mut r = self.point;
        let mut bn = e.bn;
        Ok(PointG1 {
            point: g1mul(&mut r, &mut bn)
        })
    }

    /// PointG1 * PointG1
    pub fn add(&self, q: &PointG1) -> Result<PointG1, IndyCryptoError> {
        let mut r = self.point;
        let mut point = q.point;
        r.add(&mut point);
        Ok(PointG1 {
            point: r
        })
    }

    /// PointG1 / PointG1
    pub fn sub(&self, q: &PointG1) -> Result<PointG1, IndyCryptoError> {
        let mut r = self.point;
        let mut point = q.point;
        r.sub(&mut point);
        Ok(PointG1 {
            point: r
        })
    }

    /// 1 / PointG1
    pub fn neg(&self) -> Result<PointG1, IndyCryptoError> {
        let mut r = self.point;
        r.neg();
        Ok(PointG1 {
            point: r
        })
    }

    pub fn to_string(&self) -> Result<String, IndyCryptoError> {
        Ok(self.point.to_hex())
    }

    pub fn from_string(str: &str) -> Result<PointG1, IndyCryptoError> {
        Ok(PointG1 {
            point: ECP::from_hex(str.to_string())
        })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, IndyCryptoError> {
        let mut r = self.point;
        let mut vec = vec![0u8; Self::BYTES_REPR_SIZE];
        r.tobytes(&mut vec);
        Ok(vec)
    }

    pub fn from_bytes(b: &[u8]) -> Result<PointG1, IndyCryptoError> {
        if b.len() != Self::BYTES_REPR_SIZE {
            return Err(IndyCryptoError::InvalidStructure(
                "Invalid len of bytes representation".to_string()));
        }
        Ok(
            PointG1 {
                point: ECP::frombytes(b)
            }
        )
    }

    pub fn from_hash(hash: &[u8]) -> Result<PointG1, IndyCryptoError> {
        let mut el = GroupOrderElement::from_bytes(hash)?;
        let mut point = ECP::new_big(&el.bn);

        while point.is_infinity() {
            el.bn.inc(1);
            point = ECP::new_big(&el.bn);
        }

        Ok(PointG1 {
            point: point
        })
    }
}

impl Debug for PointG1 {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        write!(f, "PointG1 {{ point: {} }}", self.point.to_hex())
    }
}

#[cfg(feature = "serialization")]
impl Serialize for PointG1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
        serializer.serialize_newtype_struct("PointG1", &self.to_string().map_err(SError::custom)?)
    }
}

#[cfg(feature = "serialization")]
impl<'a> Deserialize<'a> for PointG1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: Deserializer<'a> {
        struct PointG1Visitor;

        impl<'a> Visitor<'a> for PointG1Visitor {
            type Value = PointG1;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("expected PointG1")
            }

            fn visit_str<E>(self, value: &str) -> Result<PointG1, E>
                where E: DError
            {
                Ok(PointG1::from_string(value).map_err(DError::custom)?)
            }
        }

        deserializer.deserialize_str(PointG1Visitor)
    }
}

#[derive(Copy, Clone, PartialEq)]
pub struct PointG2 {
    point: ECP2
}

impl PointG2 {
    pub const BYTES_REPR_SIZE: usize = MODBYTES * 4;

    /// Creates new random PointG2
    pub fn new() -> Result<PointG2, IndyCryptoError> {
        let point_xa = BIG::new_ints(&CURVE_PXA);
        let point_xb = BIG::new_ints(&CURVE_PXB);
        let point_ya = BIG::new_ints(&CURVE_PYA);
        let point_yb = BIG::new_ints(&CURVE_PYB);

        let point_x = FP2::new_bigs(&point_xa, &point_xb);
        let point_y = FP2::new_bigs(&point_ya, &point_yb);

        let mut gen_g2 = ECP2::new_fp2s(&point_x, &point_y);

        let point = g2mul(&mut gen_g2, &mut random_mod_order()?);

        Ok(PointG2 {
            point: point
        })
    }

    /// Creates new infinity PointG2
    pub fn new_inf() -> Result<PointG2, IndyCryptoError> {
        let mut point = ECP2::new();
        point.inf();

        Ok(PointG2 {
            point: point
        })
    }

    /// PointG2 * PointG2
    pub fn add(&self, q: &PointG2) -> Result<PointG2, IndyCryptoError> {
        let mut r = self.point;
        let mut point = q.point;
        r.add(&mut point);

        Ok(PointG2 {
            point: r
        })
    }

    /// PointG2 / PointG2
    pub fn sub(&self, q: &PointG2) -> Result<PointG2, IndyCryptoError> {
        let mut r = self.point;
        let mut point = q.point;
        r.sub(&mut point);

        Ok(PointG2 {
            point: r
        })
    }

    /// PointG2 ^ GroupOrderElement
    pub fn mul(&self, e: &GroupOrderElement) -> Result<PointG2, IndyCryptoError> {
        let mut r = self.point;
        let mut bn = e.bn;
        Ok(PointG2 {
            point: g2mul(&mut r, &mut bn)
        })
    }

    pub fn to_string(&self) -> Result<String, IndyCryptoError> {
        Ok(self.point.to_hex())
    }

    pub fn from_string(str: &str) -> Result<PointG2, IndyCryptoError> {
        Ok(PointG2 {
            point: ECP2::from_hex(str.to_string())
        })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, IndyCryptoError> {
        let mut point = self.point;
        let mut vec = vec![0u8; Self::BYTES_REPR_SIZE];
        point.tobytes(&mut vec);
        Ok(vec)
    }

    pub fn from_bytes(b: &[u8]) -> Result<PointG2, IndyCryptoError> {
        if b.len() != Self::BYTES_REPR_SIZE {
            return Err(IndyCryptoError::InvalidStructure(
                "Invalid len of bytes representation".to_string()));
        }
        Ok(
            PointG2 {
                point: ECP2::frombytes(b)
            }
        )
    }
}

impl Debug for PointG2 {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        write!(f, "PointG2 {{ point: {} }}", self.point.to_hex())
    }
}

#[cfg(feature = "serialization")]
impl Serialize for PointG2 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
        serializer.serialize_newtype_struct("PointG2", &self.to_string().map_err(SError::custom)?)
    }
}

#[cfg(feature = "serialization")]
impl<'a> Deserialize<'a> for PointG2 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: Deserializer<'a> {
        struct PointG2Visitor;

        impl<'a> Visitor<'a> for PointG2Visitor {
            type Value = PointG2;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("expected PointG2")
            }

            fn visit_str<E>(self, value: &str) -> Result<PointG2, E>
                where E: DError
            {
                Ok(PointG2::from_string(value).map_err(DError::custom)?)
            }
        }

        deserializer.deserialize_str(PointG2Visitor)
    }
}

#[derive(Copy, Clone, PartialEq)]
pub struct GroupOrderElement {
    bn: BIG
}

impl GroupOrderElement {
    pub const BYTES_REPR_SIZE: usize = MODBYTES;

    pub fn new() -> Result<GroupOrderElement, IndyCryptoError> {
        // returns random element in 0, ..., GroupOrder-1
        Ok(GroupOrderElement {
            bn: random_mod_order()?
        })
    }

    pub fn new_from_seed(seed: &[u8]) -> Result<GroupOrderElement, IndyCryptoError> {
        // returns random element in 0, ..., GroupOrder-1
        if seed.len() != MODBYTES {
            return Err(IndyCryptoError::InvalidStructure(
                format!("Invalid len of seed: expected {}, actual {}", MODBYTES, seed.len())));
        }
        let mut rng = RAND::new();
        rng.clean();
        rng.seed(seed.len(), seed);

        Ok(GroupOrderElement {
            bn: BIG::randomnum(&BIG::new_ints(&CURVE_ORDER), &mut rng)
        })
    }

    /// (GroupOrderElement ^ GroupOrderElement) mod GroupOrder
    pub fn pow_mod(&self, e: &GroupOrderElement) -> Result<GroupOrderElement, IndyCryptoError> {
        let mut base = self.bn;
        let mut pow = e.bn;
        Ok(GroupOrderElement {
            bn: base.powmod(&mut pow, &BIG::new_ints(&CURVE_ORDER))
        })
    }

    /// (GroupOrderElement + GroupOrderElement) mod GroupOrder
    pub fn add_mod(&self, r: &GroupOrderElement) -> Result<GroupOrderElement, IndyCryptoError> {
        let mut sum = self.bn;
        sum.add(&r.bn);
        sum.rmod(&BIG::new_ints(&CURVE_ORDER));
        Ok(GroupOrderElement {
            bn: sum
        })
    }

    /// (GroupOrderElement - GroupOrderElement) mod GroupOrder
    pub fn sub_mod(&self, r: &GroupOrderElement) -> Result<GroupOrderElement, IndyCryptoError> {
        //need to use modneg if sub is negative
        let mut diff = self.bn;
        diff.sub(&r.bn);
        let mut zero = BIG::new();
        zero.zero();

        if diff < zero {
            return Ok(GroupOrderElement {
                bn: BIG::modneg(&mut diff, &BIG::new_ints(&CURVE_ORDER))
            });
        }

        Ok(GroupOrderElement {
            bn: diff
        })
    }

    /// (GroupOrderElement * GroupOrderElement) mod GroupOrder
    pub fn mul_mod(&self, r: &GroupOrderElement) -> Result<GroupOrderElement, IndyCryptoError> {
        let mut base = self.bn;
        let mut r = r.bn;
        Ok(GroupOrderElement {
            bn: BIG::modmul(&mut base, &mut r, &BIG::new_ints(&CURVE_ORDER))
        })
    }

    /// 1 / GroupOrderElement
    pub fn inverse(&self) -> Result<GroupOrderElement, IndyCryptoError> {
        let mut bn = self.bn;
        bn.invmodp(&BIG::new_ints(&CURVE_ORDER));

        Ok(GroupOrderElement {
            bn: bn
        })
    }

    /// - GroupOrderElement mod GroupOrder
    pub fn mod_neg(&self) -> Result<GroupOrderElement, IndyCryptoError> {
        let mut r = self.bn;
        r = BIG::modneg(&mut r, &BIG::new_ints(&CURVE_ORDER));
        Ok(GroupOrderElement {
            bn: r
        })
    }

    pub fn to_string(&self) -> Result<String, IndyCryptoError> {
        Ok(self.bn.to_hex())
    }

    pub fn from_string(str: &str) -> Result<GroupOrderElement, IndyCryptoError> {
        Ok(GroupOrderElement {
            bn: BIG::from_hex(str.to_string())
        })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, IndyCryptoError> {
        let mut bn = self.bn;
        let mut vec = vec![0u8; Self::BYTES_REPR_SIZE];
        bn.tobytes(&mut vec);
        Ok(vec)
    }

    pub fn from_bytes(b: &[u8]) -> Result<GroupOrderElement, IndyCryptoError> {
        if b.len() > Self::BYTES_REPR_SIZE {
            return Err(IndyCryptoError::InvalidStructure(
                "Invalid len of bytes representation".to_string()));
        }
        let mut vec = b.to_vec();
        let len = vec.len();
        if len < MODBYTES {
            let diff = MODBYTES - len;
            let mut result = vec![0; diff];
            result.append(&mut vec);
            return Ok(
                GroupOrderElement {
                    bn: BIG::frombytes(&result)
                }
            );
        }
        Ok(
            GroupOrderElement {
                bn: BIG::frombytes(b)
            }
        )
    }
}

impl Debug for GroupOrderElement {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        write!(f, "GroupOrderElement {{ bn: {} }}", self.bn.to_hex())
    }
}

#[cfg(feature = "serialization")]
impl Serialize for GroupOrderElement {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
        serializer.serialize_newtype_struct("GroupOrderElement", &self.to_string().map_err(SError::custom)?)
    }
}

#[cfg(feature = "serialization")]
impl<'a> Deserialize<'a> for GroupOrderElement {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: Deserializer<'a> {
        struct GroupOrderElementVisitor;

        impl<'a> Visitor<'a> for GroupOrderElementVisitor {
            type Value = GroupOrderElement;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("expected GroupOrderElement")
            }

            fn visit_str<E>(self, value: &str) -> Result<GroupOrderElement, E>
                where E: DError
            {
                Ok(GroupOrderElement::from_string(value).map_err(DError::custom)?)
            }
        }

        deserializer.deserialize_str(GroupOrderElementVisitor)
    }
}

#[derive(Copy, Clone, PartialEq)]
pub struct Pair {
    pair: FP12
}

impl Pair {
    pub const BYTES_REPR_SIZE: usize = MODBYTES * 16;
    /// e(PointG1, PointG2)
    pub fn pair(p: &PointG1, q: &PointG2) -> Result<Pair, IndyCryptoError> {
        let mut p_new = *p;
        let mut q_new = *q;
        let mut result = fexp(&ate(&mut q_new.point, &mut p_new.point));
        result.reduce();

        Ok(Pair {
            pair: result
        })
    }

    /// e() * e()
    pub fn mul(&self, b: &Pair) -> Result<Pair, IndyCryptoError> {
        let mut base = self.pair;
        let mut b = b.pair;
        base.mul(&mut b);
        base.reduce();
        Ok(Pair {
            pair: base
        })
    }

    /// e() ^ GroupOrderElement
    pub fn pow(&self, b: &GroupOrderElement) -> Result<Pair, IndyCryptoError> {
        let mut base = self.pair;
        let mut b = b.bn;

        Ok(Pair {
            pair: gtpow(&mut base, &mut b)
        })
    }

    /// 1 / e()
    pub fn inverse(&self) -> Result<Pair, IndyCryptoError> {
        let mut r = self.pair;
        r.conj();
        Ok(Pair {
            pair: r
        })
    }

    pub fn to_string(&self) -> Result<String, IndyCryptoError> {
        Ok(self.pair.to_hex())
    }

    pub fn from_string(str: &str) -> Result<Pair, IndyCryptoError> {
        Ok(Pair {
            pair: FP12::from_hex(str.to_string())
        })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, IndyCryptoError> {
        let mut r = self.pair;
        let mut vec = vec![0u8; Self::BYTES_REPR_SIZE];
        r.tobytes(&mut vec);
        Ok(vec)
    }
}

impl Debug for Pair {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        write!(f, "Pair {{ pair: {} }}", self.pair.to_hex())
    }
}

#[cfg(feature = "serialization")]
impl Serialize for Pair {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
        serializer.serialize_newtype_struct("Pair", &self.to_string().map_err(SError::custom)?)
    }
}

#[cfg(feature = "serialization")]
impl<'a> Deserialize<'a> for Pair {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: Deserializer<'a> {
        struct PairVisitor;

        impl<'a> Visitor<'a> for PairVisitor {
            type Value = Pair;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("expected Pair")
            }

            fn visit_str<E>(self, value: &str) -> Result<Pair, E>
                where E: DError
            {
                Ok(Pair::from_string(value).map_err(DError::custom)?)
            }
        }

        deserializer.deserialize_str(PairVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use errors::ToErrorCode;
    use ffi::ErrorCode;

    #[test]
    fn group_order_element_new_from_seed_works_for_invalid_seed_len() {
        let err = GroupOrderElement::new_from_seed(&[0, 1, 2]).unwrap_err();
        assert_eq!(err.to_error_code(), ErrorCode::CommonInvalidStructure);
    }

    #[test]
    fn pairing_definition_bilinearity() {
        let a = GroupOrderElement::new().unwrap();
        let b = GroupOrderElement::new().unwrap();
        let p = PointG1::new().unwrap();
        let q = PointG2::new().unwrap();
        let left = Pair::pair(&p.mul(&a).unwrap(), &q.mul(&b).unwrap()).unwrap();
        let right = Pair::pair(&p, &q).unwrap().pow(&a.mul_mod(&b).unwrap()).unwrap();
        assert_eq!(left, right);
    }

    #[test]
    fn point_g1_infinity_test() {
        let p = PointG1::new_inf().unwrap();
        let q = PointG1::new().unwrap();
        let result = p.add(&q).unwrap();
        assert_eq!(q, result);
    }

    #[test]
    fn point_g1_infinity_test2() {
        let p = PointG1::new().unwrap();
        let inf = p.sub(&p).unwrap();
        let q = PointG1::new().unwrap();
        let result = inf.add(&q).unwrap();
        assert_eq!(q, result);
    }

    #[test]
    fn point_g2_infinity_test() {
        let p = PointG2::new_inf().unwrap();
        let q = PointG2::new().unwrap();
        let result = p.add(&q).unwrap();
        assert_eq!(q, result);
    }

    #[test]
    fn inverse_for_pairing() {
        let p1 = PointG1::new().unwrap();
        let q1 = PointG2::new().unwrap();
        let p2 = PointG1::new().unwrap();
        let q2 = PointG2::new().unwrap();
        let pair1 = Pair::pair(&p1, &q1).unwrap();
        let pair2 = Pair::pair(&p2, &q2).unwrap();
        let pair_result = pair1.mul(&pair2).unwrap();
        let pair3 = pair_result.mul(&pair1.inverse().unwrap()).unwrap();
        assert_eq!(pair2, pair3);
    }
}

#[cfg(feature = "serialization")]
#[cfg(test)]
mod serialization_tests {
    use super::*;

    extern crate serde_json;

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct TestGroupOrderElementStructure {
        field: GroupOrderElement
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct TestPointG1Structure {
        field: PointG1
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct TestPointG2Structure {
        field: PointG2
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct TestPairStructure {
        field: Pair
    }

    #[test]
    fn from_bytes_to_bytes_works_for_group_order_element() {
        let vec = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 116, 221, 243, 243, 0, 77, 170, 65, 179, 245, 119, 182, 251, 185, 78, 98];
        let bytes = GroupOrderElement::from_bytes(&vec).unwrap();
        let result = bytes.to_bytes().unwrap();
        assert_eq!(vec, result);
    }

    #[test]
    fn serialize_deserialize_works_for_group_order_element() {
        let structure = TestGroupOrderElementStructure {
            field: GroupOrderElement::from_string("A6F18598A10FAE 736E4DAFC3F174 FA57A6D2B80083 D533FEDE2C88B8 129AA6F2").unwrap()
        };
        let deserialized: TestGroupOrderElementStructure = serde_json::from_str(&serde_json::to_string(&structure).unwrap()).unwrap();

        assert_eq!(structure, deserialized);
    }

    #[test]
    fn serialize_deserialize_works_for_point_g1() {
        let structure = TestPointG1Structure {
            field: PointG1::from_string("false 6556E08075C674 EE6E05C6A17E67 20E189DE31926E DD41F2F92026FC 9181F00 BEC671398C0F1 25D98934EA6B2D 9600760C4F9729 51F977993486B1 9BC9712 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD").unwrap()
        };

        let deserialized: TestPointG1Structure = serde_json::from_str(&serde_json::to_string(&structure).unwrap()).unwrap();

        assert_eq!(structure, deserialized);
    }

    #[test]
    fn deserialize_works_for_point_g2() {
        let structure = TestPointG2Structure {
            field: PointG2::from_string("false 4EAC2B37C43A02 9AB45BED53CE00 56EDA01AC795F7 6CAC874CAE0696 6CA435C 4FB2CB47DCFF1A 23E4966C196375 196238CE0B83FE 41788980E5F233 514F85B F72F76C4F52B69 BADA0D1D556306 413BD4FF30211 3A64D182D7BF25 1A40A6E4 44AD0B40DC32E8 96259C38242511 87743EFF5CDBBE 4F7649B5A5A3B3 10601954 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD 0 0 0 0 0").unwrap()
        };
        let deserialized: TestPointG2Structure = serde_json::from_str(&serde_json::to_string(&structure).unwrap()).unwrap();

        assert_eq!(structure, deserialized);
    }

    #[test]
    fn serialize_deserialize_works_for_pair() {
        let point_g1 = PointG1 {
            point: PointG1::from_string("false 6944F7AC340BD5 BFE2AC0F2996F4 21E205643FDCC1 C5B03061739A46 1FC3950 26812069BB116C 6C255738808107 4B7BE8A38AAFE6 EE2EA7F7E34076 1056E3F5 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD").unwrap().point
        };
        let point_g2 = PointG2 {
            point: PointG2::from_string("false DEE03DE7C57BCC 7B98876D8889A5 948F216B5CFBE0 C15E16E00BFCAD 16027A65 170C1764D6155B 2B3C337E522DDC 25C5BE0F88E27C 286A9485A0DA85 EC9DBC2 849696E99FF31D 3E886C73B3A8B9 E8CDC74F3D64E6 FE70DCC7F81DD8 1A021C8E A32D7B5A0500DC 18155886E7FFF9 B5A9F7E7A82509 FAAE75ACCAF60C 2505CB0C FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD 0 0 0 0 0").unwrap().point
        };
        let pair = TestPairStructure {
            field: Pair::pair(&point_g1, &point_g2).unwrap()
        };
        let deserialized: TestPairStructure = serde_json::from_str(&serde_json::to_string(&pair).unwrap()).unwrap();

        assert_eq!(pair, deserialized);
    }
}
