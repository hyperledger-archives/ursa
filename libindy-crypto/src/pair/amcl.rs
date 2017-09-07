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

fn random_mod_order() -> Result<BIG, IndyCryptoError> {
    let mut seed = vec![0; MODBYTES];
    let mut os_rng = OsRng::new().unwrap();
    os_rng.fill_bytes(&mut seed.as_mut_slice());
    let mut rng = RAND::new();
    rng.clean();
    rng.seed(MODBYTES, &seed);
    Ok(BIG::randomnum(&BIG::new_ints(&CURVE_ORDER), &mut rng))
}

#[derive(Copy, Clone, PartialEq, Debug)]
pub struct PointG1 {
    point: ECP
}

impl PointG1 {
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
        let mut vec = vec![0; MODBYTES * 4];
        r.tobytes(&mut vec);
        Ok(vec)
    }

    pub fn from_bytes(b: &[u8]) -> Result<PointG1, IndyCryptoError> {
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

#[derive(Copy, Clone, PartialEq, Debug)]
pub struct PointG2 {
    point: ECP2
}

impl PointG2 {
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
        let mut vec = vec![0; MODBYTES * 4];
        point.tobytes(&mut vec);
        Ok(vec)
    }

    pub fn from_bytes(b: &[u8]) -> Result<PointG2, IndyCryptoError> {
        Ok(
            PointG2 {
                point: ECP2::frombytes(b)
            }
        )
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct GroupOrderElement {
    bn: BIG
}

impl GroupOrderElement {
    pub fn new() -> Result<GroupOrderElement, IndyCryptoError> {
        // returns random element in 0, ..., GroupOrder-1
        Ok(GroupOrderElement {
            bn: random_mod_order()?
        })
    }

    pub fn new_from_seed(seed: &[u8]) -> Result<GroupOrderElement, IndyCryptoError> {
        // returns random element in 0, ..., GroupOrder-1
        let mut rng = RAND::new();
        rng.clean();
        rng.seed(MODBYTES, seed);

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
        let mut vec: [u8; MODBYTES] = [0; MODBYTES];
        bn.tobytes(&mut vec);
        Ok(vec.to_vec())
    }

    pub fn from_bytes(b: &[u8]) -> Result<GroupOrderElement, IndyCryptoError> {
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

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct Pair {
    pair: FP12
}

impl Pair {
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
        let mut vec = vec![0; MODBYTES * 16];
        r.tobytes(&mut vec);
        Ok(vec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_bytes_to_bytes_works_for_group_order_element() {
        let vec = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 116, 221, 243, 243, 0, 77, 170, 65, 179, 245, 119, 182, 251, 185, 78, 98, 172, 55, 2, 233, 88, 37, 108, 222, 13, 114, 25, 200, 43, 193, 165, 197];
        let bytes = GroupOrderElement::from_bytes(&vec).unwrap();
        let result = bytes.to_bytes().unwrap();
        assert_eq!(vec, result);
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