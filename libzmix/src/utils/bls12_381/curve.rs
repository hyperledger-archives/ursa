use super::{hash_mod_order, random_mod_order, G1, G2, GROUP_ORDER};

use amcl_miracl::arch::Chunk;
use amcl_miracl::bls381::big::BIG;
use amcl_miracl::bls381::ecp::ECP;
use amcl_miracl::bls381::ecp2::ECP2;
use amcl_miracl::bls381::fp12::FP12;
use amcl_miracl::bls381::pair::{ate, ate2, fexp};
use amcl_miracl::bls381::rom;
use rand::prelude::*;
use zeroize::Zeroize;

use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use std::str::FromStr;

/// Used for handling field order elements in the BLS12-381 curve
#[derive(Eq, PartialEq, Ord, PartialOrd)]
pub struct FieldOrderElement(BIG);

impl FieldOrderElement {
    pub const BYTES_REPR_SIZE: usize = rom::MODBYTES;

    pub fn new() -> Self {
        FieldOrderElement(random_mod_order::<ThreadRng>(None))
    }

    pub fn zero() -> Self {
        FieldOrderElement(BIG::new())
    }

    pub fn one() -> Self {
        let mut v = BIG::new();
        v.one();
        FieldOrderElement(v)
    }

    pub fn from_rng<R: Rng>(rng: &mut R) -> Self {
        FieldOrderElement(random_mod_order(Some(rng)))
    }

    pub fn from_hash(data: &[u8], salt: &[u8], domain_sep_context: &[u8]) -> Self {
        FieldOrderElement(hash_mod_order(data, salt, domain_sep_context))
    }

    to_bytes!();

    pub fn inverse(&mut self) {
        self.0.invmodp(&GROUP_ORDER);
    }

    pub fn order() -> FieldOrderElement {
        FieldOrderElement(BIG::new_ints(&rom::CURVE_ORDER))
    }

    fn repr_bytes(&self, res: &mut Vec<u8>) {
        let mut t = self.0;
        t.tobytes(&mut res.as_mut_slice())
    }

    fn to_hex(&self) -> String {
        let mut t = self.0;
        t.to_hex()
    }
}

impl Clone for FieldOrderElement {
    fn clone(&self) -> FieldOrderElement {
        FieldOrderElement(BIG::new_copy(&self.0))
    }
}

impl Zeroize for FieldOrderElement {
    fn zeroize(&mut self) {
        self.0.w.zeroize();
    }
}

impl Drop for FieldOrderElement {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl From<usize> for FieldOrderElement {
    fn from(data: usize) -> FieldOrderElement {
        let mut v = BIG::new();
        v.w[0] = data as Chunk;
        FieldOrderElement(v)
    }
}

default_impl!(FieldOrderElement);
format_impl!(FieldOrderElement);
serialize_impl!(FieldOrderElement, BIG, FieldOrderElementVisitor);
add_impl!(FieldOrderElement, self rhs {
    let mut value = BIG::new_big(&self.0);
    value.add(&rhs.0);
    value.rmod(&GROUP_ORDER);
    FieldOrderElement(value)
}, self rhs {
    self.0.add(&rhs.0);
    self.0.rmod(&GROUP_ORDER);
});
sub_impl!(FieldOrderElement, self rhs {
    let mut value = BIG::new_big(&self.0);
    value.add(&BIG::modneg(&rhs.0, &GROUP_ORDER));
    value.rmod(&GROUP_ORDER);
    FieldOrderElement(value)
}, self rhs {
    let value = BIG::modneg(&rhs.0, &GROUP_ORDER);
    self.0.add(&value);
    self.0.rmod(&GROUP_ORDER);
});

mul_impl!(FieldOrderElement, FieldOrderElement, self rhs {
    FieldOrderElement(BIG::modmul(&self.0, &rhs.0, &GROUP_ORDER))
}, self rhs {
    self.0 = BIG::modmul(&self.0, &rhs.0, &GROUP_ORDER);
});
neg_impl!(FieldOrderElement, self {
    FieldOrderElement(BIG::modneg(&self.0, &GROUP_ORDER))
});

///////////////////////// Point G1 /////////////////////////

#[derive(PartialEq)]
pub struct PointG1(ECP);

impl PointG1 {
    pub const BYTES_REPR_SIZE: usize = rom::MODBYTES * 4;

    pub fn new() -> Self {
        PointG1(G1.mul(&random_mod_order::<ThreadRng>(None)))
    }

    pub fn infinity() -> Self {
        let mut value = ECP::new();
        value.inf();
        PointG1(value)
    }

    pub fn from_rng<R: Rng>(rng: &mut R) -> Self {
        PointG1(G1.mul(&random_mod_order(Some(rng))))
    }

    pub fn from_hash(data: &[u8], salt: &[u8], domain_sep: &[u8]) -> Self {
        let n = FieldOrderElement::from_hash(data, salt, domain_sep);

        //FUTURE: Replace with https://eprint.iacr.org/2019/403.pdf
        //It might be okay to leave as is if `data` is not secret
        //Ideally everything is constant time so no one has to worry
        PointG1(ECP::mapit(n.to_bytes().as_slice()))
    }

    pub fn base() -> Self {
        PointG1(ECP::generator())
    }

    pub fn mul2(
        p1: &PointG1,
        v1: &FieldOrderElement,
        p2: &PointG1,
        v2: &FieldOrderElement,
    ) -> Self {
        PointG1(p1.0.mul2(&v1.0, &p2.0, &v2.0))
    }

    pub fn is_infinity(&self) -> bool {
        self.0.is_infinity()
    }

    to_bytes!();

    fn repr_bytes(&self, res: &mut Vec<u8>) {
        self.0.tobytes(&mut res.as_mut_slice(), false);
    }

    fn to_hex(&self) -> String {
        self.0.to_hex()
    }
}

impl Clone for PointG1 {
    fn clone(&self) -> Self {
        let mut cp = ECP::new();
        cp.copy(&self.0);
        PointG1(cp)
    }
}

default_impl!(PointG1);
format_impl!(PointG1);
serialize_impl!(PointG1, ECP, PointG1Visitor);
add_impl!(PointG1, self rhs {
    let mut value = self.clone();
    value.0.add(&rhs.0);
    value
}, self rhs {
    self.0.add(&rhs.0);
});
sub_impl!(PointG1, self rhs {
    let mut value = self.clone();
    value.0.sub(&rhs.0);
    value
}, self rhs {
    self.0.sub(&rhs.0);
});
mul_impl!(PointG1, FieldOrderElement, self rhs {
    PointG1(self.0.mul(&rhs.0))
}, self rhs {
    self.0 = self.0.mul(&rhs.0)
});
impl Mul<usize> for PointG1 {
    type Output = PointG1;

    fn mul(self, rhs: usize) -> Self::Output {
        let mut v = BIG::new();
        v.w[0] = rhs as Chunk;
        PointG1(self.0.mul(&v))
    }
}
neg_impl!(PointG1, self {
    let mut p = self.clone();
    p.0.neg();
    p
});
///////////////////////// Point G2 /////////////////////////

#[derive(PartialEq)]
pub struct PointG2(ECP2);

impl PointG2 {
    pub const BYTES_REPR_SIZE: usize = rom::MODBYTES * 4;

    pub fn new() -> Self {
        PointG2(G2.mul(&random_mod_order::<ThreadRng>(None)))
    }

    pub fn infinity() -> Self {
        let mut value = ECP2::new();
        value.inf();
        PointG2(value)
    }

    pub fn from_rng<R: Rng>(rng: &mut R) -> Self {
        PointG2(G2.mul(&random_mod_order(Some(rng))))
    }

    pub fn base() -> Self {
        PointG2(ECP2::generator())
    }

    pub fn is_infinity(&self) -> bool {
        self.0.is_infinity()
    }

    to_bytes!();

    fn repr_bytes(&self, res: &mut Vec<u8>) {
        self.0.tobytes(&mut res.as_mut_slice());
    }

    fn to_hex(&self) -> String {
        self.0.to_hex()
    }
}

impl Clone for PointG2 {
    fn clone(&self) -> Self {
        let mut cp = ECP2::new();
        cp.copy(&self.0);
        PointG2(cp)
    }
}

default_impl!(PointG2);
format_impl!(PointG2);
serialize_impl!(PointG2, ECP2, PointG2Visitor);
add_impl!(PointG2, self rhs {
    let mut value = self.clone();
    value.0.add(&rhs.0);
    value
}, self rhs {
    self.0.add(&rhs.0);
});
sub_impl!(PointG2, self rhs {
    let mut value = self.clone();
    value.0.sub(&rhs.0);
    value
}, self rhs {
    self.0.sub(&rhs.0);
});
mul_impl!(PointG2, FieldOrderElement, self rhs {
    PointG2(self.0.mul(&rhs.0))
}, self rhs {
    self.0 = self.0.mul(&rhs.0)
});
impl Mul<usize> for PointG2 {
    type Output = PointG2;

    fn mul(self, rhs: usize) -> Self::Output {
        let mut v = BIG::new();
        v.w[0] = rhs as Chunk;
        PointG2(self.0.mul(&v))
    }
}
neg_impl!(PointG2, self {
    let mut p = self.clone();
    p.0.neg();
    p
});

///////////////////////// Pair /////////////////////////

#[derive(PartialEq)]
pub struct Pair(FP12);

impl Pair {
    pub const BYTES_REPR_SIZE: usize = rom::MODBYTES * 16;

    pub fn pair(p: &PointG1, q: &PointG2) -> Self {
        let mut value = fexp(&ate(&q.0, &p.0));
        value.reduce();
        Pair(value)
    }

    pub fn pair_cmp(p1: &PointG1, q1: &PointG2, p2: &PointG1, q2: &PointG2) -> bool {
        let mut p = p1.0;
        p.neg();
        let value = fexp(&ate2(&q1.0, &p, &q2.0, &p2.0));
        value.isunity()
    }

    pub fn inverse(&mut self) {
        self.0.conj();
    }

    pub fn pow(&self, rhs: &FieldOrderElement) -> Self {
        Pair(self.0.pow(&rhs.0))
    }

    pub fn is_unity(&self) -> bool {
        self.0.isunity()
    }

    to_bytes!();

    fn repr_bytes(&self, res: &mut Vec<u8>) {
        let mut tmp = self.0;
        tmp.tobytes(&mut res.as_mut_slice());
    }

    fn to_hex(&self) -> String {
        self.0.to_hex()
    }
}

impl Clone for Pair {
    fn clone(&self) -> Self {
        Pair(FP12::new_copy(&self.0))
    }
}

format_impl!(Pair);
serialize_impl!(Pair, FP12, PairVisitor);
mul_impl!(Pair, Pair, self rhs {
    let mut value = self.clone();
    value.0.mul(&rhs.0);
    value.0.reduce();
    value
}, self rhs {
    self.0.mul(&rhs.0);
    self.0.reduce();
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_fr() {
        assert_eq!(FieldOrderElement::from(1), FieldOrderElement::one());
        assert_eq!(FieldOrderElement::from(0), FieldOrderElement::zero());
        assert_eq!(FieldOrderElement::from("01"), FieldOrderElement::one());
        let fr = FieldOrderElement::new();
        assert_eq!(fr, fr.clone());
    }

    #[test]
    fn from_hash() {
        let fr = FieldOrderElement::new();
        let salt = b"oiuhgruhqewriuh13k451938475oergnqeiruytkj1b34t098h978123jhk625gv";
        let domain_sep = b"1234rtgfcdewdfghjnbgt56rtyu3io09iurgiokdjfuighujwkemnj5uyiwhjekr";
        let foe = FieldOrderElement::from_hash(fr.to_bytes().as_slice(), salt, domain_sep);
        assert_ne!(foe, fr);
        let salt = b"0";
        let domain_sep = b"0";
        let foe = FieldOrderElement::from_hash(fr.to_bytes().as_slice(), salt, domain_sep);
        assert_ne!(fr, foe);
    }

    #[test]
    fn fr_serialization() {
        let fr = FieldOrderElement::new();
        assert_eq!(fr.to_bytes().len(), FieldOrderElement::BYTES_REPR_SIZE);
        let fr1 = FieldOrderElement::from(fr.to_bytes().as_slice());
        assert_eq!(fr, fr1);
        let res = serde_json::to_string(&fr1);
        assert!(res.is_ok());
        let s_fr1 = res.unwrap();
        let res = serde_json::from_str(&s_fr1);
        assert!(res.is_ok());
        assert_eq!(fr1, res.unwrap());
    }

    #[test]
    fn fr_arithmetic() {
        let fr1 = FieldOrderElement::one();
        let fr2 = FieldOrderElement::one();
        let fr3 = &fr1 + &fr2;
        assert_eq!(fr3, FieldOrderElement::from(2));
        let fr4 = &fr1 + &fr2 - fr3;
        assert_eq!(fr4, FieldOrderElement::zero());
        let fr5 = FieldOrderElement::from(10) * FieldOrderElement::from(10);
        assert_eq!(fr5, FieldOrderElement::from(100));
        let fr6 = FieldOrderElement::new() - FieldOrderElement::new();
        assert!(fr6 < FieldOrderElement::order());
        assert_eq!(FieldOrderElement::from("0000000000000000000000000000000073EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFEFFFFFFFA"), -FieldOrderElement::from(7));
    }

    #[test]
    fn new_g1() {
        assert!(PointG1::infinity().is_infinity());
        assert!(!PointG1::new().is_infinity());
    }

    #[test]
    fn g1_serialization() {
        let h1 = PointG1::new();
        assert_eq!(h1.to_bytes().len(), PointG1::BYTES_REPR_SIZE);
        let h1_1 = PointG1::from(h1.to_bytes().as_slice());
        assert_eq!(h1_1, h1);
        let res = serde_json::to_string(&h1);
        assert!(res.is_ok());
        let s_h1 = res.unwrap();
        let res = serde_json::from_str(&s_h1);
        assert!(res.is_ok());
        assert_eq!(h1_1, res.unwrap());
    }

    #[test]
    fn g1_arithmetic() {
        let g1 = PointG1::infinity();
        let g2 = PointG1::new();
        let g3 = &g1 + &g2;
        assert_eq!(g3, g2);
        assert_eq!(g3 * 2, &g2 + &g2);
        assert_eq!(g1, &g2 - &g2);
    }

    #[test]
    fn new_g2() {
        assert!(PointG2::infinity().is_infinity());
        assert!(!PointG2::new().is_infinity());
    }

    #[test]
    fn g2_serialization() {
        let h1 = PointG2::new();
        assert_eq!(h1.to_bytes().len(), PointG2::BYTES_REPR_SIZE);
        let h1_1 = PointG2::from(h1.to_bytes().as_slice());
        assert_eq!(h1_1, h1);
        let res = serde_json::to_string(&h1);
        assert!(res.is_ok());
        let s_h1 = res.unwrap();
        let res = serde_json::from_str(&s_h1);
        assert!(res.is_ok());
        assert_eq!(h1_1, res.unwrap());
    }

    #[test]
    fn g2_arithmetic() {
        let g1 = PointG2::infinity();
        let g2 = PointG2::new();
        let g3 = &g1 + &g2;
        assert_eq!(g3, g2);
        assert_eq!(g3 * 2, &g2 + &g2);
        assert_eq!(g1, &g2 - &g2);
    }

    #[test]
    fn pair_bilinearity() {
        let a = FieldOrderElement::new();
        let b = FieldOrderElement::new();
        let p = PointG1::new();
        let q = PointG2::new();

        let left = Pair::pair(&(&p * &a), &(&q * &b));
        let right = Pair::pair(&p, &q).pow(&(&a * &b));
        assert_eq!(left, right);

        assert!(Pair::pair_cmp(&p, &q, &p, &q));
        assert!(!Pair::pair_cmp(&p, &q, &(&p * &a), &q));
    }

    #[test]
    fn pair_inverse() {
        let p1 = PointG1::new();
        let q1 = PointG2::new();
        let p2 = PointG1::new();
        let q2 = PointG2::new();

        let mut pair1 = Pair::pair(&p1, &q1);
        let pair2 = Pair::pair(&p2, &q2);

        let pair = &pair1 * &pair2;
        pair1.inverse();
        let pair3 = pair * pair1;
        assert_eq!(pair2, pair3);
    }
}
