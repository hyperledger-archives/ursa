use errors::prelude::*;

use int_traits::IntTraits;

use openssl::bn::{BigNum, BigNumContext, BigNumRef, MsbOption};
use openssl::error::ErrorStack;
use openssl::hash::{hash, Hasher, MessageDigest};

#[cfg(feature = "serialization")]
use serde::ser::{Error as SError, Serialize, Serializer};

#[cfg(feature = "serialization")]
use serde::de::{Deserialize, Deserializer, Error as DError, Visitor};

use std::cmp::Ord;
use std::cmp::Ordering;
use std::fmt;

pub struct BigNumberContext {
    openssl_bn_context: BigNumContext,
}

#[derive(Debug)]
pub struct BigNumber {
    openssl_bn: BigNum,
}

impl BigNumber {
    pub fn new_context() -> UrsaCryptoResult<BigNumberContext> {
        let ctx = BigNumContext::new()?;
        Ok(BigNumberContext {
            openssl_bn_context: ctx,
        })
    }

    pub fn new() -> UrsaCryptoResult<BigNumber> {
        let bn = BigNum::new()?;
        Ok(BigNumber { openssl_bn: bn })
    }

    pub fn generate_prime(size: usize) -> UrsaCryptoResult<BigNumber> {
        let mut bn = BigNumber::new()?;
        BigNumRef::generate_prime(&mut bn.openssl_bn, size as i32, false, None, None)?;
        Ok(bn)
    }

    pub fn generate_safe_prime(size: usize) -> UrsaCryptoResult<BigNumber> {
        let mut bn = BigNumber::new()?;
        BigNumRef::generate_prime(&mut bn.openssl_bn, (size + 1) as i32, true, None, None)?;
        Ok(bn)
    }

    pub fn generate_prime_in_range(
        start: &BigNumber,
        end: &BigNumber,
    ) -> UrsaCryptoResult<BigNumber> {
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

    pub fn is_prime(&self, ctx: Option<&mut BigNumberContext>) -> UrsaCryptoResult<bool> {
        let prime_len = self.to_dec()?.len();
        let checks = prime_len.log2() as i32;
        match ctx {
            Some(context) => Ok(self
                .openssl_bn
                .is_prime(checks, &mut context.openssl_bn_context)?),
            None => {
                let mut ctx = BigNumber::new_context()?;
                Ok(self
                    .openssl_bn
                    .is_prime(checks, &mut ctx.openssl_bn_context)?)
            }
        }
    }

    pub fn is_safe_prime(&self, ctx: Option<&mut BigNumberContext>) -> UrsaCryptoResult<bool> {
        match ctx {
            Some(c) => {
                // according to https://eprint.iacr.org/2003/186.pdf
                // a safe prime is congruent to 2 mod 3

                // a safe prime satisfies (p-1)/2 is prime. Since a
                // prime is odd, We just need to divide by 2
                Ok(
                    self.modulus(&BigNumber::from_u32(3)?, Some(c))? == BigNumber::from_u32(2)?
                        && self.is_prime(Some(c))?
                        && self.rshift1()?.is_prime(Some(c))?,
                )
            }
            None => {
                let mut context = BigNumber::new_context()?;
                self.is_safe_prime(Some(&mut context))
            }
        }
    }

    pub fn rand(size: usize) -> UrsaCryptoResult<BigNumber> {
        let mut bn = BigNumber::new()?;
        BigNumRef::rand(
            &mut bn.openssl_bn,
            size as i32,
            MsbOption::MAYBE_ZERO,
            false,
        )?;
        Ok(bn)
    }

    pub fn rand_range(&self) -> UrsaCryptoResult<BigNumber> {
        let mut bn = BigNumber::new()?;
        BigNumRef::rand_range(&self.openssl_bn, &mut bn.openssl_bn)?;
        Ok(bn)
    }

    pub fn num_bits(&self) -> UrsaCryptoResult<i32> {
        Ok(self.openssl_bn.num_bits())
    }

    pub fn is_bit_set(&self, n: i32) -> UrsaCryptoResult<bool> {
        Ok(self.openssl_bn.is_bit_set(n))
    }

    pub fn set_bit(&mut self, n: i32) -> UrsaCryptoResult<&mut BigNumber> {
        BigNumRef::set_bit(&mut self.openssl_bn, n)?;
        Ok(self)
    }

    pub fn from_u32(n: usize) -> UrsaCryptoResult<BigNumber> {
        let bn = BigNum::from_u32(n as u32)?;
        Ok(BigNumber { openssl_bn: bn })
    }

    pub fn from_dec(dec: &str) -> UrsaCryptoResult<BigNumber> {
        let bn = BigNum::from_dec_str(dec)?;
        Ok(BigNumber { openssl_bn: bn })
    }

    pub fn from_hex(hex: &str) -> UrsaCryptoResult<BigNumber> {
        let bn = BigNum::from_hex_str(hex)?;
        Ok(BigNumber { openssl_bn: bn })
    }

    pub fn from_bytes(bytes: &[u8]) -> UrsaCryptoResult<BigNumber> {
        let bn = BigNum::from_slice(bytes)?;
        Ok(BigNumber { openssl_bn: bn })
    }

    pub fn to_dec(&self) -> UrsaCryptoResult<String> {
        let result = self.openssl_bn.to_dec_str()?;
        Ok(result.to_string())
    }

    pub fn to_hex(&self) -> UrsaCryptoResult<String> {
        let result = self.openssl_bn.to_hex_str()?;
        Ok(result.to_string())
    }

    pub fn to_bytes(&self) -> UrsaCryptoResult<Vec<u8>> {
        Ok(self.openssl_bn.to_vec())
    }

    pub fn hash(data: &[u8]) -> UrsaCryptoResult<Vec<u8>> {
        Ok(hash(MessageDigest::sha256(), data)?.to_vec())
    }

    pub fn add(&self, a: &BigNumber) -> UrsaCryptoResult<BigNumber> {
        let mut bn = BigNumber::new()?;
        BigNumRef::checked_add(&mut bn.openssl_bn, &self.openssl_bn, &a.openssl_bn)?;
        Ok(bn)
    }

    pub fn sub(&self, a: &BigNumber) -> UrsaCryptoResult<BigNumber> {
        let mut bn = BigNumber::new()?;
        BigNumRef::checked_sub(&mut bn.openssl_bn, &self.openssl_bn, &a.openssl_bn)?;
        Ok(bn)
    }

    // TODO: There should be a mod_sqr using underlying math library's square modulo since squaring is faster.
    pub fn sqr(&self, ctx: Option<&mut BigNumberContext>) -> UrsaCryptoResult<BigNumber> {
        let mut bn = BigNumber::new()?;
        match ctx {
            Some(context) => BigNumRef::sqr(
                &mut bn.openssl_bn,
                &self.openssl_bn,
                &mut context.openssl_bn_context,
            )?,
            None => {
                let mut ctx = BigNumber::new_context()?;
                BigNumRef::sqr(
                    &mut bn.openssl_bn,
                    &self.openssl_bn,
                    &mut ctx.openssl_bn_context,
                )?;
            }
        }
        Ok(bn)
    }

    pub fn mul(
        &self,
        a: &BigNumber,
        ctx: Option<&mut BigNumberContext>,
    ) -> UrsaCryptoResult<BigNumber> {
        let mut bn = BigNumber::new()?;
        match ctx {
            Some(context) => BigNumRef::checked_mul(
                &mut bn.openssl_bn,
                &self.openssl_bn,
                &a.openssl_bn,
                &mut context.openssl_bn_context,
            )?,
            None => {
                let mut ctx = BigNumber::new_context()?;
                BigNumRef::checked_mul(
                    &mut bn.openssl_bn,
                    &self.openssl_bn,
                    &a.openssl_bn,
                    &mut ctx.openssl_bn_context,
                )?;
            }
        }
        Ok(bn)
    }

    pub fn mod_mul(
        &self,
        a: &BigNumber,
        n: &BigNumber,
        ctx: Option<&mut BigNumberContext>,
    ) -> UrsaCryptoResult<BigNumber> {
        let mut bn = BigNumber::new()?;
        match ctx {
            Some(context) => BigNumRef::mod_mul(
                &mut bn.openssl_bn,
                &self.openssl_bn,
                &a.openssl_bn,
                &n.openssl_bn,
                &mut context.openssl_bn_context,
            )?,
            None => {
                let mut ctx = BigNumber::new_context()?;
                BigNumRef::mod_mul(
                    &mut bn.openssl_bn,
                    &self.openssl_bn,
                    &a.openssl_bn,
                    &n.openssl_bn,
                    &mut ctx.openssl_bn_context,
                )?;
            }
        }
        Ok(bn)
    }

    pub fn mod_sub(
        &self,
        a: &BigNumber,
        n: &BigNumber,
        ctx: Option<&mut BigNumberContext>,
    ) -> UrsaCryptoResult<BigNumber> {
        let mut bn = BigNumber::new()?;
        match ctx {
            Some(context) => BigNumRef::mod_sub(
                &mut bn.openssl_bn,
                &self.openssl_bn,
                &a.openssl_bn,
                &n.openssl_bn,
                &mut context.openssl_bn_context,
            )?,
            None => {
                let mut ctx = BigNumber::new_context()?;
                BigNumRef::mod_sub(
                    &mut bn.openssl_bn,
                    &self.openssl_bn,
                    &a.openssl_bn,
                    &n.openssl_bn,
                    &mut ctx.openssl_bn_context,
                )?;
            }
        }
        Ok(bn)
    }

    pub fn div(
        &self,
        a: &BigNumber,
        ctx: Option<&mut BigNumberContext>,
    ) -> UrsaCryptoResult<BigNumber> {
        let mut bn = BigNumber::new()?;
        match ctx {
            Some(context) => BigNumRef::checked_div(
                &mut bn.openssl_bn,
                &self.openssl_bn,
                &a.openssl_bn,
                &mut context.openssl_bn_context,
            )?,
            None => {
                let mut ctx = BigNumber::new_context()?;
                BigNumRef::checked_div(
                    &mut bn.openssl_bn,
                    &self.openssl_bn,
                    &a.openssl_bn,
                    &mut ctx.openssl_bn_context,
                )?;
            }
        }
        Ok(bn)
    }

    pub fn gcd(
        a: &BigNumber,
        b: &BigNumber,
        ctx: Option<&mut BigNumberContext>,
    ) -> UrsaCryptoResult<BigNumber> {
        let mut gcd = BigNumber::new()?;
        match ctx {
            Some(context) => BigNumRef::gcd(
                &mut gcd.openssl_bn,
                &a.openssl_bn,
                &b.openssl_bn,
                &mut context.openssl_bn_context,
            )?,
            None => {
                let mut ctx = BigNumber::new_context()?;
                BigNumRef::gcd(
                    &mut gcd.openssl_bn,
                    &a.openssl_bn,
                    &b.openssl_bn,
                    &mut ctx.openssl_bn_context,
                )?;
            }
        }
        Ok(gcd)
    }

    // Question: The *_word APIs seem odd. When the method is already mutating, why return the reference?

    pub fn add_word(&mut self, w: u32) -> UrsaCryptoResult<&mut BigNumber> {
        BigNumRef::add_word(&mut self.openssl_bn, w)?;
        Ok(self)
    }

    pub fn sub_word(&mut self, w: u32) -> UrsaCryptoResult<&mut BigNumber> {
        BigNumRef::sub_word(&mut self.openssl_bn, w)?;
        Ok(self)
    }

    pub fn mul_word(&mut self, w: u32) -> UrsaCryptoResult<&mut BigNumber> {
        BigNumRef::mul_word(&mut self.openssl_bn, w)?;
        Ok(self)
    }

    pub fn div_word(&mut self, w: u32) -> UrsaCryptoResult<&mut BigNumber> {
        BigNumRef::div_word(&mut self.openssl_bn, w)?;
        Ok(self)
    }

    pub fn mod_exp(
        &self,
        a: &BigNumber,
        b: &BigNumber,
        ctx: Option<&mut BigNumberContext>,
    ) -> UrsaCryptoResult<BigNumber> {
        match ctx {
            Some(context) => self._mod_exp(a, b, context),
            None => {
                let mut ctx = BigNumber::new_context()?;
                self._mod_exp(a, b, &mut ctx)
            }
        }
    }

    fn _mod_exp(
        &self,
        a: &BigNumber,
        b: &BigNumber,
        ctx: &mut BigNumberContext,
    ) -> UrsaCryptoResult<BigNumber> {
        let mut bn = BigNumber::new()?;

        if a.openssl_bn.is_negative() {
            BigNumRef::mod_exp(
                &mut bn.openssl_bn,
                &self.inverse(b, Some(ctx))?.openssl_bn,
                &a.set_negative(false)?.openssl_bn,
                &b.openssl_bn,
                &mut ctx.openssl_bn_context,
            )?;
        } else {
            BigNumRef::mod_exp(
                &mut bn.openssl_bn,
                &self.openssl_bn,
                &a.openssl_bn,
                &b.openssl_bn,
                &mut ctx.openssl_bn_context,
            )?;
        };
        Ok(bn)
    }

    pub fn modulus(
        &self,
        a: &BigNumber,
        ctx: Option<&mut BigNumberContext>,
    ) -> UrsaCryptoResult<BigNumber> {
        let mut bn = BigNumber::new()?;
        match ctx {
            Some(context) => BigNumRef::nnmod(
                &mut bn.openssl_bn,
                &self.openssl_bn,
                &a.openssl_bn,
                &mut context.openssl_bn_context,
            )?,
            None => {
                let mut ctx = BigNumber::new_context()?;
                BigNumRef::nnmod(
                    &mut bn.openssl_bn,
                    &self.openssl_bn,
                    &a.openssl_bn,
                    &mut ctx.openssl_bn_context,
                )?;
            }
        }
        Ok(bn)
    }

    pub fn exp(
        &self,
        a: &BigNumber,
        ctx: Option<&mut BigNumberContext>,
    ) -> UrsaCryptoResult<BigNumber> {
        let mut bn = BigNumber::new()?;
        match ctx {
            Some(context) => BigNumRef::exp(
                &mut bn.openssl_bn,
                &self.openssl_bn,
                &a.openssl_bn,
                &mut context.openssl_bn_context,
            )?,
            None => {
                let mut ctx = BigNumber::new_context()?;
                BigNumRef::exp(
                    &mut bn.openssl_bn,
                    &self.openssl_bn,
                    &a.openssl_bn,
                    &mut ctx.openssl_bn_context,
                )?;
            }
        }
        Ok(bn)
    }

    pub fn inverse(
        &self,
        n: &BigNumber,
        ctx: Option<&mut BigNumberContext>,
    ) -> UrsaCryptoResult<BigNumber> {
        let mut bn = BigNumber::new()?;
        match ctx {
            Some(context) => BigNumRef::mod_inverse(
                &mut bn.openssl_bn,
                &self.openssl_bn,
                &n.openssl_bn,
                &mut context.openssl_bn_context,
            )?,
            None => {
                let mut ctx = BigNumber::new_context()?;
                BigNumRef::mod_inverse(
                    &mut bn.openssl_bn,
                    &self.openssl_bn,
                    &n.openssl_bn,
                    &mut ctx.openssl_bn_context,
                )?;
            }
        }
        Ok(bn)
    }

    pub fn set_negative(&self, negative: bool) -> UrsaCryptoResult<BigNumber> {
        let mut bn = BigNum::from_slice(&self.openssl_bn.to_vec())?;
        bn.set_negative(negative);
        Ok(BigNumber { openssl_bn: bn })
    }

    pub fn is_negative(&self) -> bool {
        self.openssl_bn.is_negative()
    }

    pub fn increment(&self) -> UrsaCryptoResult<BigNumber> {
        let mut bn = BigNum::from_slice(&self.openssl_bn.to_vec())?;
        bn.add_word(1)?;
        Ok(BigNumber { openssl_bn: bn })
    }

    pub fn decrement(&self) -> UrsaCryptoResult<BigNumber> {
        let mut bn = BigNum::from_slice(&self.openssl_bn.to_vec())?;
        bn.sub_word(1)?;
        Ok(BigNumber { openssl_bn: bn })
    }

    pub fn lshift1(&self) -> UrsaCryptoResult<BigNumber> {
        let mut bn = BigNumber::new()?;
        BigNumRef::lshift1(&mut bn.openssl_bn, &self.openssl_bn)?;
        Ok(bn)
    }

    pub fn rshift1(&self) -> UrsaCryptoResult<BigNumber> {
        let mut bn = BigNumber::new()?;
        BigNumRef::rshift1(&mut bn.openssl_bn, &self.openssl_bn)?;
        Ok(bn)
    }

    pub fn rshift(&self, n: u32) -> UrsaCryptoResult<BigNumber> {
        let mut bn = BigNumber::new()?;
        BigNumRef::rshift(&mut bn.openssl_bn, &self.openssl_bn, n as i32)?;
        Ok(bn)
    }

    pub fn mod_div(
        &self,
        b: &BigNumber,
        p: &BigNumber,
        ctx: Option<&mut BigNumberContext>,
    ) -> UrsaCryptoResult<BigNumber> {
        //(a * (1/b mod p) mod p)
        match ctx {
            Some(mut context) => self._mod_div(b, p, &mut context),
            None => {
                let mut context = BigNumber::new_context()?;
                self._mod_div(b, p, &mut context)
            }
        }
    }

    ///(a * (1/b mod p) mod p)
    fn _mod_div(
        &self,
        b: &BigNumber,
        p: &BigNumber,
        ctx: &mut BigNumberContext,
    ) -> UrsaCryptoResult<BigNumber> {
        let mut bn = BigNumber::new()?;
        BigNumRef::mod_mul(
            &mut bn.openssl_bn,
            &self.openssl_bn,
            &b.inverse(p, Some(ctx))?.openssl_bn,
            &p.openssl_bn,
            &mut ctx.openssl_bn_context,
        )?;
        Ok(bn)
    }

    pub fn random_qr(n: &BigNumber) -> UrsaCryptoResult<BigNumber> {
        let qr = n.rand_range()?.sqr(None)?.modulus(&n, None)?;
        Ok(qr)
    }

    // Question: Why does this need to be a Result? When is creating a BigNumber same as another
    // BigNumber not possible given sufficient memory?
    pub fn try_clone(&self) -> UrsaCryptoResult<BigNumber> {
        let mut openssl_bn = BigNum::from_slice(&self.openssl_bn.to_vec()[..])?;
        openssl_bn.set_negative(self.is_negative());
        Ok(BigNumber { openssl_bn })
    }

    pub fn hash_array(nums: &[Vec<u8>]) -> UrsaCryptoResult<Vec<u8>> {
        let mut sha256 = Hasher::new(MessageDigest::sha256())?;

        for num in nums.iter() {
            sha256.update(&num)?;
        }

        Ok(sha256.finish()?.to_vec())
    }
}

impl Ord for BigNumber {
    fn cmp(&self, other: &BigNumber) -> Ordering {
        self.openssl_bn.cmp(&other.openssl_bn)
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
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_newtype_struct("BigNumber", &self.to_dec().map_err(SError::custom)?)
    }
}

#[cfg(feature = "serialization")]
impl<'a> Deserialize<'a> for BigNumber {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'a>,
    {
        struct BigNumberVisitor;

        impl<'a> Visitor<'a> for BigNumberVisitor {
            type Value = BigNumber;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("expected BigNumber")
            }

            fn visit_str<E>(self, value: &str) -> Result<BigNumber, E>
            where
                E: DError,
            {
                Ok(BigNumber::from_dec(value).map_err(DError::custom)?)
            }
        }

        deserializer.deserialize_str(BigNumberVisitor)
    }
}

impl From<ErrorStack> for UrsaCryptoError {
    fn from(err: ErrorStack) -> Self {
        // TODO: FIXME: Analyze ErrorStack and split invalid structure errors from other errors
        err.to_ursa(UrsaCryptoErrorKind::InvalidState, "Internal OpenSSL error")
    }
}

impl Default for BigNumber {
    fn default() -> BigNumber {
        BigNumber::from_u32(0).unwrap()
    }
}

// Constants that are used throughout the code, so avoiding recomputation.
lazy_static! {
    pub static ref BIGNUMBER_1: BigNumber = BigNumber::from_u32(1).unwrap();
    pub static ref BIGNUMBER_2: BigNumber = BigNumber::from_u32(2).unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    use serde_json;

    const RANGE_LEFT: usize = 592;
    const RANGE_RIGHT: usize = 592;

    #[test]
    fn test_exp_works() {
        let answer = BigNumber::from_dec("259344723055062059907025491480697571938277889515152306249728583105665800713306759149981690559193987143012367913206299323899696942213235956742929677132122730441323862712594345230336").unwrap();
        let test = BigNumber::from_u32(2)
            .unwrap()
            .exp(&BigNumber::from_u32(596).unwrap(), None)
            .unwrap();
        assert_eq!(answer, test);
    }

    #[ignore]
    #[test]
    fn generate_prime_in_range_works() {
        let start = BigNumber::rand(RANGE_LEFT).unwrap();
        let end = BigNumber::rand(RANGE_RIGHT).unwrap();
        let random_prime = BigNumber::generate_prime_in_range(&start, &end).unwrap();
        assert!(start < random_prime);
        assert!(end > random_prime);
    }

    #[test]
    fn is_prime_works() {
        let primes: Vec<u64> = vec![2, 23, 31, 42885908609, 24473809133, 47055833459];
        for pr in primes {
            let num = BigNumber::from_dec(&pr.to_string()).unwrap();
            assert!(num.is_prime(None).unwrap());
        }
        let num = BigNumber::from_dec("36").unwrap();
        assert!(!num.is_prime(None).unwrap());

        let mut n128 = BigNumber::new().unwrap();
        BigNumRef::generate_prime(&mut n128.openssl_bn, 128, false, None, None).unwrap();
        assert!(n128.is_prime(None).unwrap());
        let mut n256 = BigNumber::new().unwrap();
        BigNumRef::generate_prime(&mut n256.openssl_bn, 256, false, None, None).unwrap();
        assert!(n256.is_prime(None).unwrap());

        let vec1 = vec![9, 252, 51, 8, 129]; // big endian representation of 42885908609
        let v1 = BigNumber::from_bytes(&vec1).unwrap();
        assert!(v1.is_prime(None).unwrap());
        let vec2 = vec![129, 8, 51, 252, 9]; // little endian representation of 42885908609
        let v2 = BigNumber::from_bytes(&vec2).unwrap();
        assert!(!v2.is_prime(None).unwrap());
        let vec3 = vec![1, 153, 25]; // big endian representation of 104729
        let v3 = BigNumber::from_bytes(&vec3).unwrap();
        assert!(v3.is_prime(None).unwrap());
    }

    #[test]
    fn modulus_works() {
        let base = BigNumber::from_u32(6).unwrap();
        assert!(base.modulus(&BigNumber::new().unwrap(), None).is_err());

        for (modulus, expected) in [
            (BigNumber::from_u32(1).unwrap(), BigNumber::new().unwrap()),
            (
                BigNumber::from_u32(1).unwrap().set_negative(true).unwrap(),
                BigNumber::new().unwrap(),
            ),
            (BigNumber::from_u32(2).unwrap(), BigNumber::new().unwrap()),
            (
                BigNumber::from_u32(2).unwrap().set_negative(true).unwrap(),
                BigNumber::new().unwrap(),
            ),
            (
                BigNumber::from_u32(5).unwrap(),
                BigNumber::from_u32(1).unwrap(),
            ),
            (
                BigNumber::from_u32(5).unwrap().set_negative(true).unwrap(),
                BigNumber::from_u32(1).unwrap(),
            ),
        ]
        .iter()
        {
            assert_eq!(*expected, base.modulus(&modulus, None).unwrap());
        }
    }

    #[test]
    fn test_modular_exponentiation() {
        let base = BigNumber::from_dec("12714671911903680502393098440562958150461307840092575886187217264492970515611166458444182780904860535776274190597528985988632488194981204988199325501696648896748368401254829974173258613724800116424602180755019588176641580062215499750550535543002990347313784260314641340394494547935943176226649412526659864646068220114536172189443925908781755710141006387091748541976715633668919725277837668568166444731358541327097786024076841158424402136565558677098853060675674958695935207345864359540948421232816012865873346545455513695413921957708811080877422273777355768568166638843699798663264533662595755767287970642902713301649").unwrap();
        let exp = BigNumber::from_dec("13991423645225256679625502829143442357836305738777175327623021076136862973228390317258480888217725740262243618881809894688804251512223982403225288178492105393953431042196371492402144120299046493467608097411259757604892535967240041988260332063962457178993277482991886508015739613530825229685281072180891075265116698114782553748364913010741387964956740720544998915158970813171997488129859542399633104746793770216517872705889857552727967921847493285577238").unwrap();
        let modulus = BigNumber::from_dec("991272771610724400277702356109350334773782112020672787325464582894874455338156617087078683660308327009158085342465983713825070967004447592080649030930737560915527173820649490032274245863850782844569456999473516497618489127293328524608584652323593452247534656999363158875176879817952982494174728640545484193154314433925648566686738628413929222467005197087738850212963801663981588243042912430590088435419451359859770426041670326127890520192033283832465411962274045956439947646966560440910244870464709982605844468449227905039953511431640780483761563845223213570597106855699997837768334871601402132694515676785338799407204529154456178837013845488372635042715003769626150545960460800980936426723680755798495767188398126674428244764038147226578038085253616108968402209263400729503458144370189359160926796812468410806201905992347006546335038212090539118675048292666041345556742530041533878341459110515497642054583635133581316796089099043782055893003258788369004899742992039315008110063759802733045648131896557338576682560236591353394201381103042167106112201578883917022695113857967398885475101031596068885337186646296664517159150904935112836318654117577507707562065113238913343761942585545093919444150946120523831367132144754209388110483749").unwrap();
        let n = base.mod_exp(&exp, &modulus, None).unwrap();
        assert_eq!(n, BigNumber::from_dec("156669382818249607878298589043381544147555658222157929549484054385620519150887267126359684884641035264854247223281407349108771361611707714806192334779156374961296686821846487267487447347213829476609283133961216115764596907219173912888367998704856300105745961091899745329082513615681466199188236178266479183520370119131067362815102553237342546358580424556049196548520326206809677290296313839918774603549816182657993044271509706055893922152644469350618465711055733369291523796837304622919600074130968607301641438272377350795631212741686475924538423333008944556761300787668873766797549942827958501053262330421256183088509761636226277739400954175538503984519144969688787730088704522060486181427528150632576628856946041322195818246199503927686629821338146828603690778689292695518745939007886131151503766930229761608131819298276772877945842806872426029069949874062579870088710097070526608376602732627661781899595747063793310401032556802468649888104062151213860356554306295111191704764944574687548637446778783560586599000631975868701382113259027374431129732911012887214749014288413818636520182416636289308770657630129067046301651835893708731812616847614495049523221056260334965662875649480493232265453415256612460815802528012166114764216881").unwrap());

        let base = BigNumber::from_u32(6).unwrap();
        let exp = BigNumber::from_u32(5).unwrap().set_negative(true).unwrap();
        let modulus = BigNumber::from_u32(13).unwrap();
        assert_eq!(
            BigNumber::from_u32(7).unwrap(),
            base.mod_exp(&exp, &modulus, None).unwrap()
        );

        let modulus = BigNumber::from_u32(5).unwrap().set_negative(true).unwrap();
        assert_eq!(
            BigNumber::from_u32(1).unwrap(),
            base.mod_exp(&exp, &modulus, None).unwrap()
        );
    }

    #[test]
    fn is_safe_prime_works() {
        let tests =
            [("18088387217903330459", 6),
             ("33376463607021642560387296949", 6),
             ("170141183460469231731687303717167733089", 6),
             ("113910913923300788319699387848674650656041243163866388656000063249848353322899", 5),
             ("1675975991242824637446753124775730765934920727574049172215445180465220503759193372100234287270862928461253982273310756356719235351493321243304213304923049", 5),
             ("153739637779647327330155094463476939112913405723627932550795546376536722298275674187199768137486929460478138431076223176750734095693166283451594721829574797878338183845296809008576378039501400850628591798770214582527154641716248943964626446190042367043984306973709604255015629102866732543697075866901827761489", 4),
             ("66295144163396665403376179086308918015255210762161712943347745256800426733181435998953954369657699924569095498869393378860769817738689910466139513014839505675023358799693196331874626976637176000078613744447569887988972970496824235261568439949705345174465781244618912962800788579976795988724553365066910412859", 4),
             ("820487282547358769999412885360222660576380474310550379805815205126382064582513754977028835433175916179747652683836060304824653681337501863788890799590780972441917586297563543467703579662178567005653571376063099400019232223632330329795684409261771589617763237736441493626109590280374575246142877096898790823019919184975618595550451798334727636308466158736200343427240101972133364701056380402654685095871114841124384154429149515486150114363963276777169261541633795383304623350867534398592252716751849685025134858878838140569141018718631392957748884293332928915134136215143014948055229407749052752101848315855158944468016884298587263993258236848884932980148243876982276799403077114631798358541555605636220846630743269407933148520394657959774584499003246457264189421332913812855364345248054990102801114399784993674416044569272611209733832017619177693894139979496122025481552572188051013282143916147122297298055829333928425354847295988683286038218946776211988871738419664461787066106418386242958463113678229760398832001107060788455379133616893701874144525350368407189299943856497368730891887657349819575057553523442357336804219224754445704270452590146111445528895773014533306318524971435831504890959063653868338360441906137639730716820611", 2)];

        for (p, chain) in tests.iter() {
            let mut prime = BigNumber::from_dec(*p).unwrap();
            for _ in 1..*chain {
                prime = prime.lshift1().unwrap().increment().unwrap();
                assert!(prime.is_safe_prime(None).unwrap());
            }
        }
    }

    #[test]
    fn decrement_works() {
        let num = BigNumber::from_u32(1000).unwrap();
        assert_eq!(num.decrement().unwrap(), num.sub(&BIGNUMBER_1).unwrap());
    }

    #[test]
    fn increment_works() {
        let num = BigNumber::from_u32(1000).unwrap();
        assert_eq!(num.increment().unwrap(), num.add(&BIGNUMBER_1).unwrap());
    }

    #[test]
    fn rshift1_works() {
        let num = BigNumber::from_u32(1000).unwrap();
        assert_eq!(num.rshift1().unwrap(), BigNumber::from_u32(500).unwrap());
    }

    #[test]
    fn rshift_works() {
        let num = BigNumber::from_u32(1024).unwrap();
        assert_eq!(num.rshift(1).unwrap(), BigNumber::from_u32(512).unwrap());
        assert_eq!(num.rshift(2).unwrap(), BigNumber::from_u32(256).unwrap());
        assert_eq!(num.rshift(3).unwrap(), BigNumber::from_u32(128).unwrap());
        assert_eq!(num.rshift(4).unwrap(), BigNumber::from_u32(64).unwrap());
    }

    #[test]
    fn lshift1_works() {
        let num = BigNumber::from_u32(1000).unwrap();
        assert_eq!(num.lshift1().unwrap(), BigNumber::from_u32(2000).unwrap());
    }

    #[test]
    fn clone_negative_works() {
        let num = BigNumber::from_dec("-1").unwrap();
        let num_cloned = num.try_clone().unwrap();
        assert_eq!(num, num_cloned);
    }

    #[cfg(feature = "serialization")]
    #[derive(Serialize, Deserialize)]
    struct Test {
        field: BigNumber,
    }

    #[cfg(feature = "serialization")]
    #[test]
    fn serialize_works() {
        let s = Test {
            field: BigNumber::from_dec("1").unwrap(),
        };
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
