use errors::HLCryptoError;

use int_traits::IntTraits;

use openssl::bn::{BigNum, BigNumRef, BigNumContext, MsbOption};
use openssl::hash::{hash, MessageDigest, Hasher};
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
    pub fn new_context() -> Result<BigNumberContext, HLCryptoError> {
        let ctx = BigNumContext::new()?;
        Ok(BigNumberContext {
            openssl_bn_context: ctx
        })
    }

    pub fn new() -> Result<BigNumber, HLCryptoError> {
        let bn = BigNum::new()?;
        Ok(BigNumber {
            openssl_bn: bn
        })
    }

    pub fn generate_prime(size: usize) -> Result<BigNumber, HLCryptoError> {
        let mut bn = BigNumber::new()?;
        BigNumRef::generate_prime(&mut bn.openssl_bn, size as i32, false, None, None)?;
        Ok(bn)
    }

    pub fn generate_safe_prime(size: usize) -> Result<BigNumber, HLCryptoError> {
        let mut bn = BigNumber::new()?;
        BigNumRef::generate_prime(&mut bn.openssl_bn, (size + 1) as i32, true, None, None)?;
        Ok(bn)
    }

    pub fn generate_prime_in_range(start: &BigNumber, end: &BigNumber) -> Result<BigNumber, HLCryptoError> {
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

    pub fn is_prime(&self, ctx: Option<&mut BigNumberContext>) -> Result<bool, HLCryptoError> {
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

    pub fn is_safe_prime(&self, ctx: Option<&mut BigNumberContext>) -> Result<bool, HLCryptoError> {

        match ctx {
            Some(c) => {
                // according to https://eprint.iacr.org/2003/186.pdf
                // a safe prime is congruent to 2 mod 3

                // a safe prime satisfies (p-1)/2 is prime. Since a
                // prime is odd, We just need to divide by 2
                Ok(
                    self.modulus(&BigNumber::from_u32(3)?, Some(c))? == BigNumber::from_u32(2)? &&
                    self.is_prime(Some(c))? &&
                    self.rshift1()?.is_prime(Some(c))?
                )
            },
            None => {
                let mut context = BigNumber::new_context()?;
                self.is_safe_prime(Some(&mut context))
            }
        }
    }

    pub fn rand(size: usize) -> Result<BigNumber, HLCryptoError> {
        let mut bn = BigNumber::new()?;
        BigNumRef::rand(&mut bn.openssl_bn, size as i32, MsbOption::MAYBE_ZERO, false)?;
        Ok(bn)
    }

    pub fn rand_range(&self) -> Result<BigNumber, HLCryptoError> {
        let mut bn = BigNumber::new()?;
        BigNumRef::rand_range(&self.openssl_bn, &mut bn.openssl_bn)?;
        Ok(bn)
    }

    pub fn num_bits(&self) -> Result<i32, HLCryptoError> {
        Ok(self.openssl_bn.num_bits())
    }

    pub fn is_bit_set(&self, n: i32) -> Result<bool, HLCryptoError> {
        Ok(self.openssl_bn.is_bit_set(n))
    }

    pub fn set_bit(&mut self, n: i32) -> Result<&mut BigNumber, HLCryptoError> {
        BigNumRef::set_bit(&mut self.openssl_bn, n)?;
        Ok(self)
    }

    pub fn from_u32(n: usize) -> Result<BigNumber, HLCryptoError> {
        let bn = BigNum::from_u32(n as u32)?;
        Ok(BigNumber {
            openssl_bn: bn
        })
    }

    pub fn from_dec(dec: &str) -> Result<BigNumber, HLCryptoError> {
        let bn = BigNum::from_dec_str(dec)?;
        Ok(BigNumber {
            openssl_bn: bn
        })
    }

    pub fn from_hex(hex: &str) -> Result<BigNumber, HLCryptoError> {
        let bn = BigNum::from_hex_str(hex)?;
        Ok(BigNumber {
            openssl_bn: bn
        })
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<BigNumber, HLCryptoError> {
        let bn = BigNum::from_slice(bytes)?;
        Ok(BigNumber {
            openssl_bn: bn
        })
    }

    pub fn to_dec(&self) -> Result<String, HLCryptoError> {
        let result = self.openssl_bn.to_dec_str()?;
        Ok(result.to_string())
    }

    pub fn to_hex(&self) -> Result<String, HLCryptoError> {
        let result = self.openssl_bn.to_hex_str()?;
        Ok(result.to_string())
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, HLCryptoError> {
        Ok(self.openssl_bn.to_vec())
    }

    pub fn hash(data: &[u8]) -> Result<Vec<u8>, HLCryptoError> {
        Ok(hash(MessageDigest::sha256(), data)?.to_vec())
    }

    pub fn add(&self, a: &BigNumber) -> Result<BigNumber, HLCryptoError> {
        let mut bn = BigNumber::new()?;
        BigNumRef::checked_add(&mut bn.openssl_bn, &self.openssl_bn, &a.openssl_bn)?;
        Ok(bn)
    }

    pub fn sub(&self, a: &BigNumber) -> Result<BigNumber, HLCryptoError> {
        let mut bn = BigNumber::new()?;
        BigNumRef::checked_sub(&mut bn.openssl_bn, &self.openssl_bn, &a.openssl_bn)?;
        Ok(bn)
    }

    pub fn sqr(&self, ctx: Option<&mut BigNumberContext>) -> Result<BigNumber, HLCryptoError> {
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

    pub fn mul(&self, a: &BigNumber, ctx: Option<&mut BigNumberContext>) -> Result<BigNumber, HLCryptoError> {
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

    pub fn mod_mul(&self, a: &BigNumber, n: &BigNumber, ctx: Option<&mut BigNumberContext>) -> Result<BigNumber, HLCryptoError> {
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

    pub fn mod_sub(&self, a: &BigNumber, n: &BigNumber, ctx: Option<&mut BigNumberContext>) -> Result<BigNumber, HLCryptoError> {
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

    pub fn div(&self, a: &BigNumber, ctx: Option<&mut BigNumberContext>) -> Result<BigNumber, HLCryptoError> {
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

    pub fn add_word(&mut self, w: u32) -> Result<&mut BigNumber, HLCryptoError> {
        BigNumRef::add_word(&mut self.openssl_bn, w)?;
        Ok(self)
    }

    pub fn sub_word(&mut self, w: u32) -> Result<&mut BigNumber, HLCryptoError> {
        BigNumRef::sub_word(&mut self.openssl_bn, w)?;
        Ok(self)
    }

    pub fn mul_word(&mut self, w: u32) -> Result<&mut BigNumber, HLCryptoError> {
        BigNumRef::mul_word(&mut self.openssl_bn, w)?;
        Ok(self)
    }

    pub fn div_word(&mut self, w: u32) -> Result<&mut BigNumber, HLCryptoError> {
        BigNumRef::div_word(&mut self.openssl_bn, w)?;
        Ok(self)
    }

    pub fn mod_exp(&self, a: &BigNumber, b: &BigNumber, ctx: Option<&mut BigNumberContext>) -> Result<BigNumber, HLCryptoError> {
        match ctx {
            Some(context) => self._mod_exp(a, b, context),
            None => {
                let mut ctx = BigNumber::new_context()?;
                self._mod_exp(a, b, &mut ctx)
            }
        }
    }

    fn _mod_exp(&self, a: &BigNumber, b: &BigNumber, ctx: &mut BigNumberContext) -> Result<BigNumber, HLCryptoError> {
        let mut bn = BigNumber::new()?;

        if a.openssl_bn.is_negative() {
            BigNumRef::mod_exp(&mut bn.openssl_bn, &self.inverse(b, Some(ctx))?.openssl_bn, &a.set_negative(false)?.openssl_bn, &b.openssl_bn, &mut ctx.openssl_bn_context)?;
        } else {
            BigNumRef::mod_exp(&mut bn.openssl_bn, &self.openssl_bn, &a.openssl_bn, &b.openssl_bn, &mut ctx.openssl_bn_context)?;
        };
        Ok(bn)
    }

    pub fn modulus(&self, a: &BigNumber, ctx: Option<&mut BigNumberContext>) -> Result<BigNumber, HLCryptoError> {
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

    pub fn exp(&self, a: &BigNumber, ctx: Option<&mut BigNumberContext>) -> Result<BigNumber, HLCryptoError> {
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

    pub fn inverse(&self, n: &BigNumber, ctx: Option<&mut BigNumberContext>) -> Result<BigNumber, HLCryptoError> {
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

    pub fn set_negative(&self, negative: bool) -> Result<BigNumber, HLCryptoError> {
        let mut bn = BigNum::from_slice(&self.openssl_bn.to_vec())?;
        bn.set_negative(negative);
        Ok(BigNumber {
            openssl_bn: bn
        })
    }

    pub fn is_negative(&self) -> bool {
        self.openssl_bn.is_negative()
    }

    pub fn increment(&self) -> Result<BigNumber, HLCryptoError> {
        let mut bn = BigNum::from_slice(&self.openssl_bn.to_vec())?;
        bn.add_word(1)?;
        Ok(BigNumber {
            openssl_bn: bn
        })
    }

    pub fn decrement(&self) -> Result<BigNumber, HLCryptoError> {
        let mut bn = BigNum::from_slice(&self.openssl_bn.to_vec())?;
        bn.sub_word(1)?;
        Ok(BigNumber {
            openssl_bn: bn
        })
    }

    pub fn lshift1(&self) -> Result<BigNumber, HLCryptoError> {
        let mut bn = BigNumber::new()?;
        BigNumRef::lshift1(&mut bn.openssl_bn, &self.openssl_bn)?;
        Ok(bn)
    }

    pub fn rshift1(&self) -> Result<BigNumber, HLCryptoError> {
        let mut bn = BigNumber::new()?;
        BigNumRef::rshift1(&mut bn.openssl_bn, &self.openssl_bn)?;
        Ok(bn)
    }

    pub fn rshift(&self, n: i32) -> Result<BigNumber, HLCryptoError> {
        let mut bn = BigNumber::new()?;
        BigNumRef::rshift(&mut bn.openssl_bn, &self.openssl_bn, n)?;
        Ok(bn)
    }

    pub fn mod_div(&self, b: &BigNumber, p: &BigNumber, ctx: Option<&mut BigNumberContext>) -> Result<BigNumber, HLCryptoError> {
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
    fn _mod_div(&self, b: &BigNumber, p: &BigNumber, ctx: &mut BigNumberContext)-> Result<BigNumber, HLCryptoError> {
        let mut bn = BigNumber::new()?;
        BigNumRef::mod_mul(&mut bn.openssl_bn, &self.openssl_bn,
                           &b.inverse(p, Some(ctx))?.openssl_bn,
                           &p.openssl_bn, &mut ctx.openssl_bn_context)?;
        Ok(bn)
    }

    pub fn random_qr(n: &BigNumber) -> Result<BigNumber, HLCryptoError> {
        let qr = n
            .rand_range()?
            .sqr(None)?
            .modulus(&n, None)?;
        Ok(qr)
    }

    pub fn clone(&self) -> Result<BigNumber, HLCryptoError> {
        Ok(BigNumber {
            openssl_bn: BigNum::from_slice(&self.openssl_bn.to_vec()[..])?
        })
    }

    pub fn hash_array(nums: &Vec<Vec<u8>>) -> Result<Vec<u8>, HLCryptoError> {
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

impl From<ErrorStack> for HLCryptoError {
    fn from(err: ErrorStack) -> HLCryptoError {
        // TODO: FIXME: Analyze ErrorStack and split invalid structure errors from other errors
        HLCryptoError::InvalidStructure(err.description().to_string())
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
    #[ignore] //TODO check
    fn generate_prime_in_range_works() {
        let start = BigNumber::rand(RANGE_LEFT).unwrap();
        let end = BigNumber::rand(RANGE_RIGHT).unwrap();
        let random_prime = BigNumber::generate_prime_in_range(&start, &end).unwrap();
        assert!(start < random_prime);
        assert!(end > random_prime);
    }

    #[test]
    fn is_prime_works() {
        let primes:Vec<u64> = vec![2, 23, 31, 42885908609, 24473809133, 47055833459];
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
    fn test_modular_exponentiation() {
        let base = BigNumber::from_dec("12714671911903680502393098440562958150461307840092575886187217264492970515611166458444182780904860535776274190597528985988632488194981204988199325501696648896748368401254829974173258613724800116424602180755019588176641580062215499750550535543002990347313784260314641340394494547935943176226649412526659864646068220114536172189443925908781755710141006387091748541976715633668919725277837668568166444731358541327097786024076841158424402136565558677098853060675674958695935207345864359540948421232816012865873346545455513695413921957708811080877422273777355768568166638843699798663264533662595755767287970642902713301649").unwrap();
        let exp = BigNumber::from_dec("13991423645225256679625502829143442357836305738777175327623021076136862973228390317258480888217725740262243618881809894688804251512223982403225288178492105393953431042196371492402144120299046493467608097411259757604892535967240041988260332063962457178993277482991886508015739613530825229685281072180891075265116698114782553748364913010741387964956740720544998915158970813171997488129859542399633104746793770216517872705889857552727967921847493285577238").unwrap();
        let modulus = BigNumber::from_dec("991272771610724400277702356109350334773782112020672787325464582894874455338156617087078683660308327009158085342465983713825070967004447592080649030930737560915527173820649490032274245863850782844569456999473516497618489127293328524608584652323593452247534656999363158875176879817952982494174728640545484193154314433925648566686738628413929222467005197087738850212963801663981588243042912430590088435419451359859770426041670326127890520192033283832465411962274045956439947646966560440910244870464709982605844468449227905039953511431640780483761563845223213570597106855699997837768334871601402132694515676785338799407204529154456178837013845488372635042715003769626150545960460800980936426723680755798495767188398126674428244764038147226578038085253616108968402209263400729503458144370189359160926796812468410806201905992347006546335038212090539118675048292666041345556742530041533878341459110515497642054583635133581316796089099043782055893003258788369004899742992039315008110063759802733045648131896557338576682560236591353394201381103042167106112201578883917022695113857967398885475101031596068885337186646296664517159150904935112836318654117577507707562065113238913343761942585545093919444150946120523831367132144754209388110483749").unwrap();
        let n = base.mod_exp(&exp, &modulus, None).unwrap();
        assert_eq!(n, BigNumber::from_dec("156669382818249607878298589043381544147555658222157929549484054385620519150887267126359684884641035264854247223281407349108771361611707714806192334779156374961296686821846487267487447347213829476609283133961216115764596907219173912888367998704856300105745961091899745329082513615681466199188236178266479183520370119131067362815102553237342546358580424556049196548520326206809677290296313839918774603549816182657993044271509706055893922152644469350618465711055733369291523796837304622919600074130968607301641438272377350795631212741686475924538423333008944556761300787668873766797549942827958501053262330421256183088509761636226277739400954175538503984519144969688787730088704522060486181427528150632576628856946041322195818246199503927686629821338146828603690778689292695518745939007886131151503766930229761608131819298276772877945842806872426029069949874062579870088710097070526608376602732627661781899595747063793310401032556802468649888104062151213860356554306295111191704764944574687548637446778783560586599000631975868701382113259027374431129732911012887214749014288413818636520182416636289308770657630129067046301651835893708731812616847614495049523221056260334965662875649480493232265453415256612460815802528012166114764216881").unwrap());

        let base = BigNumber::from_u32(6).unwrap();
        let exp = BigNumber::from_u32(5).unwrap().set_negative(true).unwrap();
        let modulus = BigNumber::from_u32(13).unwrap();
        assert_eq!(BigNumber::from_u32(7).unwrap(), base.mod_exp(&exp, &modulus, None).unwrap());
    }

    #[test]
    #[ignore]
    fn is_safe_prime_works() {
        let prime1 = BigNumber::generate_safe_prime(256).unwrap();
        let prime2 = BigNumber::generate_safe_prime(1024).unwrap();
        assert!(prime1.is_safe_prime(None).unwrap());
        assert!(prime2.is_safe_prime(None).unwrap());
    }

    #[test]
    #[ignore] //TODO Expensive test, only run to generate public params
    fn is_safe_prime_works_for_large_prime() {
        let prime = BigNumber::generate_safe_prime(4096).unwrap();
        assert!(prime.is_safe_prime(None).unwrap());
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
