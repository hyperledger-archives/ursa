use super::{hash_mod_order, random_mod_order, GROUP_ORDER};

use amcl::arch::Chunk;
use amcl::bls381::big::BIG;
use amcl::bls381::rom;
use rand::rngs::ThreadRng;
use rand::Rng;
use zeroize::Zeroize;

use std::ops::{Add, AddAssign, Mul, Neg, Sub, SubAssign};
use std::str::FromStr;

/// Used for handling field order elements in the BLS12-381 curve
#[derive(Eq, PartialEq, Ord, PartialOrd)]
pub struct FieldOrderElement(BIG);

impl FieldOrderElement {
    pub const BYTES_REPR_SIZE: usize = rom::MODBYTES;

    constructor!(FieldOrderElement);

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

impl Default for FieldOrderElement {
    fn default() -> FieldOrderElement {
        FieldOrderElement::new()
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

format_impl!(FieldOrderElement);
serialize_impl!(FieldOrderElement, BIG, FieldOrderElementVisitor);

impl Neg for FieldOrderElement {
    type Output = FieldOrderElement;

    fn neg(self) -> FieldOrderElement {
        FieldOrderElement(BIG::modneg(&self.0, &GROUP_ORDER))
    }
}

impl<'a> Neg for &'a FieldOrderElement {
    type Output = FieldOrderElement;

    fn neg(self) -> FieldOrderElement {
        FieldOrderElement(BIG::modneg(&self.0, &GROUP_ORDER))
    }
}

impl Add for FieldOrderElement {
    type Output = FieldOrderElement;

    fn add(self, rhs: Self::Output) -> Self::Output {
        &self + &rhs
    }
}

impl<'a, 'b> Add<&'b FieldOrderElement> for &'a FieldOrderElement {
    type Output = FieldOrderElement;

    fn add(self, rhs: &'b Self::Output) -> Self::Output {
        let mut value = BIG::new_big(&self.0);
        value.add(&rhs.0);
        value.rmod(&GROUP_ORDER);
        FieldOrderElement(value)
    }
}

impl AddAssign<&FieldOrderElement> for FieldOrderElement {
    fn add_assign(&mut self, rhs: &Self) {
        self.0.add(&rhs.0);
        self.0.rmod(&GROUP_ORDER);
    }
}

impl Sub for FieldOrderElement {
    type Output = FieldOrderElement;

    fn sub(self, rhs: Self::Output) -> Self::Output {
        &self - &rhs
    }
}

impl<'a, 'b> Sub<&'b FieldOrderElement> for &'a FieldOrderElement {
    type Output = FieldOrderElement;

    fn sub(self, rhs: &'b Self::Output) -> Self::Output {
        let mut value = BIG::new_big(&self.0);
        value.add(&BIG::modneg(&rhs.0, &GROUP_ORDER));
        value.rmod(&GROUP_ORDER);
        FieldOrderElement(value)
    }
}

impl SubAssign<&FieldOrderElement> for FieldOrderElement {
    fn sub_assign(&mut self, rhs: &Self) {
        let value = BIG::modneg(&rhs.0, &GROUP_ORDER);
        self.0.add(&value);
        self.0.rmod(&GROUP_ORDER);
    }
}

impl Mul for FieldOrderElement {
    type Output = FieldOrderElement;

    fn mul(self, rhs: Self::Output) -> Self::Output {
        &self * &rhs
    }
}

impl<'a, 'b> Mul<&'b FieldOrderElement> for &'a FieldOrderElement {
    type Output = FieldOrderElement;

    fn mul(self, rhs: &'b Self::Output) -> Self::Output {
        FieldOrderElement(BIG::modmul(&self.0, &rhs.0, &GROUP_ORDER))
    }
}

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
    }

    #[test]
    fn serialization() {
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
    fn arithmetic() {
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
}
