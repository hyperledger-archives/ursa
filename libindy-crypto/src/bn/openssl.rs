use errors::IndyCryptoError;

use int_traits::IntTraits;

use openssl::bn::{BigNum, BigNumRef, BigNumContext, MSB_MAYBE_ZERO};
use openssl::hash::{hash2, MessageDigest, Hasher};
use openssl::error::ErrorStack;

#[cfg(feature = "serialization")]
use serde::ser::{Serialize, Serializer, Error as SError};

#[cfg(feature = "serialization")]
use serde::de::{Deserialize, Deserializer, Visitor, Error as DError};

use std::error::Error;
use std::fmt;
use std::cmp::Ord;
use std::cmp::Ordering;

pub struct BigNumberContext {
    openssl_bn_context: BigNumContext
}

#[derive(Debug)]
pub struct BigNumber {
    openssl_bn: BigNum
}

impl BigNumber {
    pub fn new_context() -> Result<BigNumberContext, IndyCryptoError> {
        let ctx = BigNumContext::new()?;
        Ok(BigNumberContext {
            openssl_bn_context: ctx
        })
    }

    pub fn new() -> Result<BigNumber, IndyCryptoError> {
        let bn = BigNum::new()?;
        Ok(BigNumber {
            openssl_bn: bn
        })
    }

    pub fn generate_prime(size: usize) -> Result<BigNumber, IndyCryptoError> {
        let mut bn = BigNumber::new()?;
        BigNumRef::generate_prime(&mut bn.openssl_bn, size as i32, false, None, None)?;
        Ok(bn)
    }

    pub fn generate_safe_prime(size: usize) -> Result<BigNumber, IndyCryptoError> {
        let mut bn = BigNumber::new()?;
        BigNumRef::generate_prime(&mut bn.openssl_bn, (size + 1) as i32, true, None, None)?;
        Ok(bn)
    }

    pub fn generate_prime_in_range(start: &BigNumber, end: &BigNumber) -> Result<BigNumber, IndyCryptoError> {
        let mut prime;
        let mut iteration = 0;
        let mut bn_ctx = BigNumber::new_context()?;
        let sub = end.sub(start)?;

        loop {
            prime = sub.rand_range()?;
            prime = prime.add(start)?;

            if prime.is_prime(Some(&mut bn_ctx))? {
                debug!("Found prime in {} iteration", iteration);
                break;
            }
            iteration += 1;
        }

        Ok(prime)
    }

    pub fn is_prime(&self, ctx: Option<&mut BigNumberContext>) -> Result<bool, IndyCryptoError> {
        let prime_len = self.to_dec()?.len();
        let checks = prime_len.log2() as i32;
        match ctx {
            Some(context) => Ok(self.openssl_bn.is_prime(checks, &mut context.openssl_bn_context)?),
            None => {
                let mut ctx = BigNumber::new_context()?;
                Ok(self.openssl_bn.is_prime(checks, &mut ctx.openssl_bn_context)?)
            }
        }
    }

    pub fn rand(size: usize) -> Result<BigNumber, IndyCryptoError> {
        let mut bn = BigNumber::new()?;
        BigNumRef::rand(&mut bn.openssl_bn, size as i32, MSB_MAYBE_ZERO, false)?;
        Ok(bn)
    }

    pub fn rand_range(&self) -> Result<BigNumber, IndyCryptoError> {
        let mut bn = BigNumber::new()?;
        BigNumRef::rand_range(&self.openssl_bn, &mut bn.openssl_bn)?;
        Ok(bn)
    }

    pub fn num_bits(&self) -> Result<i32, IndyCryptoError> {
        Ok(self.openssl_bn.num_bits())
    }

    pub fn is_bit_set(&self, n: i32) -> Result<bool, IndyCryptoError> {
        Ok(self.openssl_bn.is_bit_set(n))
    }

    pub fn set_bit(&mut self, n: i32) -> Result<&mut BigNumber, IndyCryptoError> {
        BigNumRef::set_bit(&mut self.openssl_bn, n)?;
        Ok(self)
    }

    pub fn from_u32(n: usize) -> Result<BigNumber, IndyCryptoError> {
        let bn = BigNum::from_u32(n as u32)?;
        Ok(BigNumber {
            openssl_bn: bn
        })
    }

    pub fn from_dec(dec: &str) -> Result<BigNumber, IndyCryptoError> {
        let bn = BigNum::from_dec_str(dec)?;
        Ok(BigNumber {
            openssl_bn: bn
        })
    }

    pub fn from_hex(hex: &str) -> Result<BigNumber, IndyCryptoError> {
        let bn = BigNum::from_hex_str(hex)?;
        Ok(BigNumber {
            openssl_bn: bn
        })
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<BigNumber, IndyCryptoError> {
        let bn = BigNum::from_slice(bytes)?;
        Ok(BigNumber {
            openssl_bn: bn
        })
    }

    pub fn to_dec(&self) -> Result<String, IndyCryptoError> {
        let result = self.openssl_bn.to_dec_str()?;
        Ok(result.to_string())
    }

    pub fn to_hex(&self) -> Result<String, IndyCryptoError> {
        let result = self.openssl_bn.to_hex_str()?;
        Ok(result.to_string())
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, IndyCryptoError> {
        Ok(self.openssl_bn.to_vec())
    }

    pub fn hash(data: &[u8]) -> Result<Vec<u8>, IndyCryptoError> {
        Ok(hash2(MessageDigest::sha256(), data)?.to_vec())
    }

    pub fn add(&self, a: &BigNumber) -> Result<BigNumber, IndyCryptoError> {
        let mut bn = BigNumber::new()?;
        BigNumRef::checked_add(&mut bn.openssl_bn, &self.openssl_bn, &a.openssl_bn)?;
        Ok(bn)
    }

    pub fn sub(&self, a: &BigNumber) -> Result<BigNumber, IndyCryptoError> {
        let mut bn = BigNumber::new()?;
        BigNumRef::checked_sub(&mut bn.openssl_bn, &self.openssl_bn, &a.openssl_bn)?;
        Ok(bn)
    }

    pub fn sqr(&self, ctx: Option<&mut BigNumberContext>) -> Result<BigNumber, IndyCryptoError> {
        let mut bn = BigNumber::new()?;
        match ctx {
            Some(context) => BigNumRef::sqr(&mut bn.openssl_bn, &self.openssl_bn, &mut context.openssl_bn_context)?,
            None => {
                let mut ctx = BigNumber::new_context()?;
                BigNumRef::sqr(&mut bn.openssl_bn, &self.openssl_bn, &mut ctx.openssl_bn_context)?;
            }
        }
        Ok(bn)
    }

    pub fn mul(&self, a: &BigNumber, ctx: Option<&mut BigNumberContext>) -> Result<BigNumber, IndyCryptoError> {
        let mut bn = BigNumber::new()?;
        match ctx {
            Some(context) => BigNumRef::checked_mul(&mut bn.openssl_bn, &self.openssl_bn, &a.openssl_bn, &mut context.openssl_bn_context)?,
            None => {
                let mut ctx = BigNumber::new_context()?;
                BigNumRef::checked_mul(&mut bn.openssl_bn, &self.openssl_bn, &a.openssl_bn, &mut ctx.openssl_bn_context)?;
            }
        }
        Ok(bn)
    }

    pub fn mod_mul(&self, a: &BigNumber, n: &BigNumber, ctx: Option<&mut BigNumberContext>) -> Result<BigNumber, IndyCryptoError> {
        let mut bn = BigNumber::new()?;
        match ctx {
            Some(context) => BigNumRef::mod_mul(&mut bn.openssl_bn, &self.openssl_bn, &a.openssl_bn, &n.openssl_bn, &mut context.openssl_bn_context)?,
            None => {
                let mut ctx = BigNumber::new_context()?;
                BigNumRef::mod_mul(&mut bn.openssl_bn, &self.openssl_bn, &a.openssl_bn, &n.openssl_bn, &mut ctx.openssl_bn_context)?;
            }
        }
        Ok(bn)
    }

    pub fn mod_sub(&self, a: &BigNumber, n: &BigNumber, ctx: Option<&mut BigNumberContext>) -> Result<BigNumber, IndyCryptoError> {
        let mut bn = BigNumber::new()?;
        match ctx {
            Some(context) => BigNumRef::mod_sub(&mut bn.openssl_bn, &self.openssl_bn, &a.openssl_bn, &n.openssl_bn, &mut context.openssl_bn_context)?,
            None => {
                let mut ctx = BigNumber::new_context()?;
                BigNumRef::mod_sub(&mut bn.openssl_bn, &self.openssl_bn, &a.openssl_bn, &n.openssl_bn, &mut ctx.openssl_bn_context)?;
            }
        }
        Ok(bn)
    }

    pub fn div(&self, a: &BigNumber, ctx: Option<&mut BigNumberContext>) -> Result<BigNumber, IndyCryptoError> {
        let mut bn = BigNumber::new()?;
        match ctx {
            Some(context) => BigNumRef::checked_div(&mut bn.openssl_bn, &self.openssl_bn, &a.openssl_bn, &mut context.openssl_bn_context)?,
            None => {
                let mut ctx = BigNumber::new_context()?;
                BigNumRef::checked_div(&mut bn.openssl_bn, &self.openssl_bn, &a.openssl_bn, &mut ctx.openssl_bn_context)?;
            }
        }
        Ok(bn)
    }

    pub fn add_word(&mut self, w: u32) -> Result<&mut BigNumber, IndyCryptoError> {
        BigNumRef::add_word(&mut self.openssl_bn, w)?;
        Ok(self)
    }

    pub fn sub_word(&mut self, w: u32) -> Result<&mut BigNumber, IndyCryptoError> {
        BigNumRef::sub_word(&mut self.openssl_bn, w)?;
        Ok(self)
    }

    pub fn mul_word(&mut self, w: u32) -> Result<&mut BigNumber, IndyCryptoError> {
        BigNumRef::mul_word(&mut self.openssl_bn, w)?;
        Ok(self)
    }

    pub fn div_word(&mut self, w: u32) -> Result<&mut BigNumber, IndyCryptoError> {
        BigNumRef::div_word(&mut self.openssl_bn, w)?;
        Ok(self)
    }

    pub fn mod_exp(&self, a: &BigNumber, b: &BigNumber, ctx: Option<&mut BigNumberContext>) -> Result<BigNumber, IndyCryptoError> {
        let mut bn = BigNumber::new()?;
        match ctx {
            Some(context) => BigNumRef::mod_exp(&mut bn.openssl_bn, &self.openssl_bn, &a.openssl_bn, &b.openssl_bn, &mut context.openssl_bn_context)?,
            None => {
                let mut ctx = BigNumber::new_context()?;
                BigNumRef::mod_exp(&mut bn.openssl_bn, &self.openssl_bn, &a.openssl_bn, &b.openssl_bn, &mut ctx.openssl_bn_context)?;
            }
        }
        Ok(bn)
    }

    pub fn modulus(&self, a: &BigNumber, ctx: Option<&mut BigNumberContext>) -> Result<BigNumber, IndyCryptoError> {
        let mut bn = BigNumber::new()?;
        match ctx {
            Some(context) => BigNumRef::nnmod(&mut bn.openssl_bn, &self.openssl_bn, &a.openssl_bn, &mut context.openssl_bn_context)?,
            None => {
                let mut ctx = BigNumber::new_context()?;
                BigNumRef::nnmod(&mut bn.openssl_bn, &self.openssl_bn, &a.openssl_bn, &mut ctx.openssl_bn_context)?;
            }
        }
        Ok(bn)
    }

    pub fn exp(&self, a: &BigNumber, ctx: Option<&mut BigNumberContext>) -> Result<BigNumber, IndyCryptoError> {
        let mut bn = BigNumber::new()?;
        match ctx {
            Some(context) => BigNumRef::exp(&mut bn.openssl_bn, &self.openssl_bn, &a.openssl_bn, &mut context.openssl_bn_context)?,
            None => {
                let mut ctx = BigNumber::new_context()?;
                BigNumRef::exp(&mut bn.openssl_bn, &self.openssl_bn, &a.openssl_bn, &mut ctx.openssl_bn_context)?;
            }
        }
        Ok(bn)
    }

    pub fn inverse(&self, n: &BigNumber, ctx: Option<&mut BigNumberContext>) -> Result<BigNumber, IndyCryptoError> {
        let mut bn = BigNumber::new()?;
        match ctx {
            Some(context) => BigNumRef::mod_inverse(&mut bn.openssl_bn, &self.openssl_bn, &n.openssl_bn, &mut context.openssl_bn_context)?,
            None => {
                let mut ctx = BigNumber::new_context()?;
                BigNumRef::mod_inverse(&mut bn.openssl_bn, &self.openssl_bn, &n.openssl_bn, &mut ctx.openssl_bn_context)?;
            }
        }
        Ok(bn)
    }

    pub fn mod_div(&self, b: &BigNumber, p: &BigNumber) -> Result<BigNumber, IndyCryptoError> {
        //(a*  (1/b mod p) mod p)

        let mut context = BigNumber::new_context()?;

        let res = b
            .inverse(p, Some(&mut context))?
            .mul(&self, Some(&mut context))?
            .modulus(&p, Some(&mut context))?;
        Ok(res)
    }

    pub fn clone(&self) -> Result<BigNumber, IndyCryptoError> {
        Ok(BigNumber {
            openssl_bn: BigNum::from_slice(&self.openssl_bn.to_vec()[..])?
        })
    }

    pub fn hash_array(nums: &Vec<Vec<u8>>) -> Result<Vec<u8>, IndyCryptoError> {
        let mut sha256 = Hasher::new(MessageDigest::sha256())?;

        for num in nums.iter() {
            sha256.update(&num)?;
        }

        Ok(sha256.finish2()?.to_vec())
    }
}

impl Ord for BigNumber {
    fn cmp(&self, other: &BigNumber) -> Ordering {
        self.openssl_bn.ucmp(&other.openssl_bn)
    }
}

impl Eq for BigNumber {}

impl PartialOrd for BigNumber {
    fn partial_cmp(&self, other: &BigNumber) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for BigNumber {
    fn eq(&self, other: &BigNumber) -> bool {
        self.openssl_bn == other.openssl_bn
    }
}

#[cfg(feature = "serialization")]
impl Serialize for BigNumber {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
        serializer.serialize_newtype_struct("BigNumber", &self.to_dec().map_err(SError::custom)?)
    }
}

#[cfg(feature = "serialization")]
impl<'a> Deserialize<'a> for BigNumber {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: Deserializer<'a> {
        struct BigNumberVisitor;

        impl<'a> Visitor<'a> for BigNumberVisitor {
            type Value = BigNumber;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("expected BigNumber")
            }

            fn visit_str<E>(self, value: &str) -> Result<BigNumber, E>
                where E: DError
            {
                Ok(BigNumber::from_dec(value).map_err(DError::custom)?)
            }
        }

        deserializer.deserialize_str(BigNumberVisitor)
    }
}

impl From<ErrorStack> for IndyCryptoError {
    fn from(err: ErrorStack) -> IndyCryptoError {
        // TODO: FIXME: Analyze ErrorStack and split invalid structure errors from other errors
        IndyCryptoError::InvalidStructure(err.description().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use serde_json;

    const RANGE_LEFT: usize = 592;
    const RANGE_RIGHT: usize = 592;

    #[test]
    #[ignore] //TODO check
    fn generate_prime_in_range_works() {
        let start = BigNumber::rand(RANGE_LEFT).unwrap();
        let end = BigNumber::rand(RANGE_RIGHT).unwrap();
        let random_prime = BigNumber::generate_prime_in_range(&start, &end).unwrap();
        assert!(start < random_prime);
        assert!(end > random_prime);
    }

    #[cfg(feature = "serialization")]
    #[derive(Serialize, Deserialize)]
    struct Test {
        field: BigNumber
    }

    #[cfg(feature = "serialization")]
    #[test]
    fn serialize_works() {
        let s = Test { field: BigNumber::from_dec("1").unwrap() };
        let serialized = serde_json::to_string(&s);

        assert!(serialized.is_ok());
        assert_eq!("{\"field\":\"1\"}", serialized.unwrap());
    }

    #[cfg(feature = "serialization")]
    #[test]
    fn deserialize_works() {
        let s = "{\"field\":\"1\"}";
        let bn: Result<Test, _> = serde_json::from_str(&s);

        assert!(bn.is_ok());
        assert_eq!("1", bn.unwrap().field.to_dec().unwrap());
    }
}
