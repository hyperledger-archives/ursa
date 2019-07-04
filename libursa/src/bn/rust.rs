use errors::prelude::*;

use glass_pumpkin::{prime, safe_prime};
use hash::{sha2, Digest};
use num_bigint::{BigInt, BigUint, RandBigInt, Sign, ToBigInt};
use num_integer::Integer;
use num_traits::identities::{One, Zero};
use num_traits::{Num, Pow, Signed, ToPrimitive};
use rand::rngs::OsRng;

#[cfg(feature = "serialization")]
use serde::ser::{Error as SError, Serialize, Serializer};

#[cfg(feature = "serialization")]
use serde::de::{Deserialize, Deserializer, Error as DError, Visitor};

use std::cmp::Ord;
use std::cmp::Ordering;
#[cfg(feature = "ffi")]
use std::error::Error;
use std::fmt;

pub struct BigNumberContext;

pub struct BigNumber {
    bn: BigInt,
}

macro_rules! prime_generation {
    ($f:ident, $size:ident, $msg:expr) => {
        match $f::new($size)?.to_bigint() {
            Some(bn) => Ok(BigNumber { bn }),
            None => Err(UrsaCryptoError::from_msg(
                UrsaCryptoErrorKind::InvalidState,
                $msg.to_string(),
            )),
        }
    };
}

macro_rules! prime_check {
    ($f:ident, $value:expr, $msg:expr) => {
        if $value.is_negative() {
            Ok(false)
        } else {
            match $value.bn.to_biguint() {
                Some(bn) => Ok($f::check(&bn)),
                None => Err(UrsaCryptoError::from_msg(
                    UrsaCryptoErrorKind::InvalidState,
                    $msg.to_string(),
                )),
            }
        }
    };
}

impl BigNumber {
    pub fn new_context() -> UrsaCryptoResult<BigNumberContext> {
        Ok(BigNumberContext {})
    }

    pub fn new() -> UrsaCryptoResult<BigNumber> {
        Ok(BigNumber { bn: BigInt::zero() })
    }

    pub fn generate_prime(size: usize) -> UrsaCryptoResult<BigNumber> {
        prime_generation!(prime, size, "Unable to generate prime")
    }

    pub fn generate_safe_prime(size: usize) -> UrsaCryptoResult<BigNumber> {
        prime_generation!(safe_prime, size, "Unable to generate safe prime")
    }

    pub fn generate_prime_in_range(
        start: &BigNumber,
        end: &BigNumber,
    ) -> UrsaCryptoResult<BigNumber> {
        let mut res;
        let mut iteration = 0;
        let mut rng = OsRng::new()?;
        let mut start = match start.bn.to_biguint() {
            Some(bn) => bn,
            None => {
                return Err(UrsaCryptoError::from_msg(
                    UrsaCryptoErrorKind::InvalidState,
                    format!("Invalid number for 'start': {:?}", start),
                ));
            }
        };
        let mut end = match end.bn.to_biguint() {
            Some(bn) => bn,
            None => {
                return Err(UrsaCryptoError::from_msg(
                    UrsaCryptoErrorKind::InvalidState,
                    format!("Invalid number for 'end': {:?}", end),
                ));
            }
        };

        if start > end {
            let temp = start;
            start = end.clone();
            end = temp;
        }

        loop {
            res = rng.gen_biguint_range(&start, &end);
            res |= BigUint::one();

            if prime::check(&res) {
                debug!("Found prime in {} iteration", iteration);
                break;
            }
            iteration += 1;
        }

        match res.to_bigint() {
            Some(bn) => Ok(BigNumber { bn }),
            None => Err(UrsaCryptoError::from_msg(
                UrsaCryptoErrorKind::InvalidState,
                "Unable to generate prime in range".to_string(),
            )),
        }
    }

    pub fn is_prime(&self, _ctx: Option<&mut BigNumberContext>) -> UrsaCryptoResult<bool> {
        prime_check!(prime, self, "An error in is_prime")
    }

    pub fn is_safe_prime(&self, _ctx: Option<&mut BigNumberContext>) -> UrsaCryptoResult<bool> {
        prime_check!(safe_prime, self, "An error in is_safe_prime")
    }

    pub fn rand(size: usize) -> UrsaCryptoResult<BigNumber> {
        let mut rng = OsRng::new()?;
        let res = rng.gen_biguint(size).to_bigint();
        Ok(BigNumber { bn: res.unwrap() })
    }

    pub fn rand_range(&self) -> UrsaCryptoResult<BigNumber> {
        let mut rng = OsRng::new()?;
        let res = rng.gen_bigint_range(&BigInt::zero(), &self.bn);
        match res.to_bigint() {
            Some(bn) => Ok(BigNumber { bn }),
            None => Err(UrsaCryptoError::from_msg(
                UrsaCryptoErrorKind::InvalidState,
                "An error in rand_range".to_string(),
            )),
        }
    }

    pub fn num_bits(&self) -> UrsaCryptoResult<i32> {
        Ok(self.bn.bits() as i32)
    }

    pub fn is_bit_set(&self, n: i32) -> UrsaCryptoResult<bool> {
        let bits = n as usize;
        let res = &self.bn >> bits;
        Ok(res.is_odd())
    }

    pub fn set_bit(&mut self, n: i32) -> Result<&mut BigNumber, UrsaCryptoError> {
        let bits = n as usize;
        let mask = BigInt::one() << bits;
        self.bn |= mask;
        Ok(self)
    }

    pub fn from_u32(n: usize) -> UrsaCryptoResult<BigNumber> {
        Ok(BigNumber {
            bn: BigInt::from(n),
        })
    }

    pub fn from_dec(dec: &str) -> UrsaCryptoResult<BigNumber> {
        Ok(BigNumber {
            bn: BigInt::from_str_radix(dec, 10)?,
        })
    }

    pub fn from_hex(hex: &str) -> UrsaCryptoResult<BigNumber> {
        Ok(BigNumber {
            bn: BigInt::from_str_radix(hex, 16)?,
        })
    }

    pub fn from_bytes(bytes: &[u8]) -> UrsaCryptoResult<BigNumber> {
        Ok(BigNumber {
            bn: BigInt::from_bytes_be(Sign::Plus, bytes),
        })
    }

    pub fn to_dec(&self) -> UrsaCryptoResult<String> {
        Ok(self.bn.to_str_radix(10))
    }

    pub fn to_hex(&self) -> UrsaCryptoResult<String> {
        Ok(self.bn.to_str_radix(16).to_uppercase())
    }

    pub fn to_bytes(&self) -> UrsaCryptoResult<Vec<u8>> {
        let (_, res) = self.bn.to_bytes_be();
        Ok(res)
    }

    pub fn hash(data: &[u8]) -> UrsaCryptoResult<Vec<u8>> {
        Ok(sha2::Sha256::digest(data).as_slice().to_vec())
    }

    pub fn add(&self, a: &BigNumber) -> UrsaCryptoResult<BigNumber> {
        let res = &self.bn + &a.bn;
        Ok(BigNumber { bn: res })
    }

    pub fn sub(&self, a: &BigNumber) -> UrsaCryptoResult<BigNumber> {
        let res = &self.bn - &a.bn;
        Ok(BigNumber { bn: res })
    }

    pub fn sqr(&self, _ctx: Option<&mut BigNumberContext>) -> UrsaCryptoResult<BigNumber> {
        let res = &self.bn * &self.bn;
        Ok(BigNumber { bn: res })
    }

    pub fn mul(
        &self,
        a: &BigNumber,
        _ctx: Option<&mut BigNumberContext>,
    ) -> UrsaCryptoResult<BigNumber> {
        let res = &self.bn * &a.bn;
        Ok(BigNumber { bn: res })
    }

    pub fn mod_mul(
        &self,
        a: &BigNumber,
        n: &BigNumber,
        _ctx: Option<&mut BigNumberContext>,
    ) -> UrsaCryptoResult<BigNumber> {
        //TODO: Use montgomery reduction
        self.mul(&a, None)?.modulus(&n, None)
    }

    pub fn mod_sub(
        &self,
        a: &BigNumber,
        n: &BigNumber,
        _ctx: Option<&mut BigNumberContext>,
    ) -> UrsaCryptoResult<BigNumber> {
        self.sub(&a)?.modulus(&n, None)
    }

    pub fn div(
        &self,
        a: &BigNumber,
        _ctx: Option<&mut BigNumberContext>,
    ) -> UrsaCryptoResult<BigNumber> {
        if a.bn.is_zero() {
            Err(UrsaCryptoError::from_msg(
                UrsaCryptoErrorKind::InvalidState,
                "a cannot be zero".to_string(),
            ))
        } else {
            let res = &self.bn / &a.bn;
            Ok(BigNumber { bn: res })
        }
    }

    pub fn gcd(
        a: &BigNumber,
        b: &BigNumber,
        _ctx: Option<&mut BigNumberContext>,
    ) -> UrsaCryptoResult<BigNumber> {
        Ok(BigNumber {
            bn: a.bn.gcd(&b.bn),
        })
    }

    pub fn add_word(&mut self, w: u32) -> Result<&mut BigNumber, UrsaCryptoError> {
        self.bn += w;
        Ok(self)
    }

    pub fn sub_word(&mut self, w: u32) -> Result<&mut BigNumber, UrsaCryptoError> {
        self.bn -= w;
        Ok(self)
    }

    pub fn mul_word(&mut self, w: u32) -> Result<&mut BigNumber, UrsaCryptoError> {
        self.bn *= w;
        Ok(self)
    }

    pub fn div_word(&mut self, w: u32) -> Result<&mut BigNumber, UrsaCryptoError> {
        if w == 0 {
            Err(UrsaCryptoError::from_msg(
                UrsaCryptoErrorKind::InvalidState,
                "a cannot be zero".to_string(),
            ))
        } else {
            self.bn /= w;
            Ok(self)
        }
    }

    pub fn mod_exp(
        &self,
        a: &BigNumber,
        b: &BigNumber,
        _ctx: Option<&mut BigNumberContext>,
    ) -> UrsaCryptoResult<BigNumber> {
        if b.bn.is_one() {
            return BigNumber::new();
        }

        if a.is_negative() {
            let res = self.inverse(&b, _ctx)?;
            let a = a.set_negative(false)?;
            Ok(BigNumber {
                bn: res.bn.modpow(&a.bn, &BigNumber::_get_modulus(&b.bn)),
            })
        } else {
            let res = self.bn.modpow(&a.bn, &BigNumber::_get_modulus(&b.bn));
            Ok(BigNumber { bn: res })
        }
    }

    pub fn modulus(
        &self,
        a: &BigNumber,
        _ctx: Option<&mut BigNumberContext>,
    ) -> UrsaCryptoResult<BigNumber> {
        if a.bn == BigInt::zero() {
            return Err(UrsaCryptoError::from_msg(
                UrsaCryptoErrorKind::InvalidState,
                "Cannot have modulus==0".to_string(),
            ));
        }
        let res = &self.bn % &BigNumber::_get_modulus(&a.bn);
        Ok(BigNumber { bn: res })
    }

    fn _get_modulus(bn: &BigInt) -> BigInt {
        if bn.is_positive() {
            bn.clone()
        } else {
            -bn.clone()
        }
    }

    pub fn exp(
        &self,
        a: &BigNumber,
        _ctx: Option<&mut BigNumberContext>,
    ) -> UrsaCryptoResult<BigNumber> {
        if self.bn.bits() == 0 {
            return Ok(BigNumber::default());
        } else if a.bn.is_one() {
            return Ok(self.try_clone()?);
        }

        match a.bn.to_u64() {
            Some(num) => Ok(BigNumber {
                bn: self.bn.pow(num),
            }),
            None => Err(UrsaCryptoError::from_msg(
                UrsaCryptoErrorKind::InvalidState,
                "'a' cannot be u64".to_string(),
            )),
        }
    }

    pub fn inverse(
        &self,
        n: &BigNumber,
        _ctx: Option<&mut BigNumberContext>,
    ) -> UrsaCryptoResult<BigNumber> {
        if n.bn.is_one() || n.bn.is_zero() {
            return Err(UrsaCryptoError::from_msg(
                UrsaCryptoErrorKind::InvalidState,
                "Invalid modulus".to_string(),
            ));
        }
        let n = BigNumber::_get_modulus(&n.bn);

        // Euclid's extended algorithm, Bèzout coefficient of `n` is not needed
        //n is either prime or coprime
        //
        //function inverse(a, n)
        //    t := 0;     newt := 1;
        //    r := n;     newr := a;
        //    while newr ≠ 0
        //        quotient := r div newr
        //        (t, newt) := (newt, t - quotient * newt)
        //        (r, newr) := (newr, r - quotient * newr)
        //    if r > 1 then return "a is not invertible"
        //    if t < 0 then t := t + n
        //    return t
        //
        let (mut t, mut new_t) = (BigInt::zero(), BigInt::one());
        let (mut r, mut new_r) = (n.clone(), self.bn.clone());

        while !new_r.is_zero() {
            let quotient = &r / &new_r;
            let temp_t = t.clone();
            let temp_new_t = new_t.clone();

            t = temp_new_t.clone();
            new_t = temp_t - &quotient * temp_new_t;

            let temp_r = r.clone();
            let temp_new_r = new_r.clone();

            r = temp_new_r.clone();
            new_r = temp_r - quotient * temp_new_r;
        }
        if r > BigInt::one() {
            return Err(UrsaCryptoError::from_msg(
                UrsaCryptoErrorKind::InvalidState,
                "Not invertible".to_string(),
            ));
        } else if t < BigInt::zero() {
            t += n.clone()
        }

        Ok(BigNumber { bn: t })
    }

    pub fn set_negative(&self, negative: bool) -> UrsaCryptoResult<BigNumber> {
        match (self.bn < BigInt::zero(), negative) {
            (true, true) => Ok(BigNumber {
                bn: self.bn.clone(),
            }),
            (false, false) => Ok(BigNumber {
                bn: self.bn.clone(),
            }),
            (true, false) => Ok(BigNumber {
                bn: -self.bn.clone(),
            }),
            (false, true) => Ok(BigNumber {
                bn: -self.bn.clone(),
            }),
        }
    }

    pub fn is_negative(&self) -> bool {
        self.bn.is_negative()
    }

    pub fn increment(&self) -> UrsaCryptoResult<BigNumber> {
        Ok(BigNumber { bn: &self.bn + 1 })
    }

    pub fn decrement(&self) -> UrsaCryptoResult<BigNumber> {
        Ok(BigNumber { bn: &self.bn - 1 })
    }

    pub fn lshift1(&self) -> UrsaCryptoResult<BigNumber> {
        Ok(BigNumber { bn: &self.bn << 1 })
    }

    pub fn rshift1(&self) -> UrsaCryptoResult<BigNumber> {
        Ok(BigNumber { bn: &self.bn >> 1 })
    }

    pub fn rshift(&self, n: u32) -> UrsaCryptoResult<BigNumber> {
        let n = n as usize;
        Ok(BigNumber { bn: &self.bn >> n })
    }

    pub fn mod_div(
        &self,
        b: &BigNumber,
        p: &BigNumber,
        _ctx: Option<&mut BigNumberContext>,
    ) -> UrsaCryptoResult<BigNumber> {
        //(a * (1/b mod p) mod p)
        self.mul(&b.inverse(&p, None)?, None)?.modulus(&p, None)
    }

    pub fn random_qr(n: &BigNumber) -> UrsaCryptoResult<BigNumber> {
        let qr = n.rand_range()?.sqr(None)?.modulus(&n, None)?;
        Ok(qr)
    }

    pub fn try_clone(&self) -> UrsaCryptoResult<BigNumber> {
        Ok(BigNumber {
            bn: self.bn.clone(),
        })
    }

    pub fn hash_array(nums: &[Vec<u8>]) -> UrsaCryptoResult<Vec<u8>> {
        let mut hasher = sha2::Sha256::new();

        for num in nums.iter() {
            hasher.input(&num);
        }

        Ok(hasher.result().as_slice().to_vec())
    }
}

impl fmt::Debug for BigNumber {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "BigNumber {{ bn: {} }}", self.bn.to_str_radix(10))
    }
}

impl fmt::Display for BigNumber {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "BigNumber {{ bn: {} }}", self.bn.to_str_radix(10))
    }
}

impl Ord for BigNumber {
    fn cmp(&self, other: &BigNumber) -> Ordering {
        self.bn.cmp(&other.bn)
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
        self.bn == other.bn
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

impl From<glass_pumpkin::error::Error> for UrsaCryptoError {
    fn from(err: glass_pumpkin::error::Error) -> UrsaCryptoError {
        UrsaCryptoError::from_msg(
            UrsaCryptoErrorKind::InvalidState,
            format!("Internal Prime Generation error: {}", err.to_string()),
        )
    }
}

impl From<rand::Error> for UrsaCryptoError {
    fn from(err: rand::Error) -> UrsaCryptoError {
        UrsaCryptoError::from_msg(
            UrsaCryptoErrorKind::InvalidState,
            format!("Internal Random Number error: {}", err.to_string()),
        )
    }
}

impl From<num_bigint::ParseBigIntError> for UrsaCryptoError {
    fn from(err: num_bigint::ParseBigIntError) -> UrsaCryptoError {
        UrsaCryptoError::from_msg(
            UrsaCryptoErrorKind::InvalidState,
            format!("Internal Parse BigInt error: {}", err.to_string()),
        )
    }
}

impl Default for BigNumber {
    fn default() -> BigNumber {
        BigNumber { bn: BigInt::zero() }
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
    fn exp_works() {
        let test = BigNumber::from_u32(3)
            .unwrap()
            .exp(&BigNumber::from_u32(2).unwrap(), None)
            .unwrap();
        assert_eq!(BigNumber::from_u32(9).unwrap(), test);

        let test = BigNumber::from_u32(3)
            .unwrap()
            .exp(&BigNumber::from_u32(3).unwrap(), None)
            .unwrap();
        assert_eq!(BigNumber::from_u32(27).unwrap(), test);

        let test = BigNumber::from_u32(2)
            .unwrap()
            .exp(&BigNumber::from_u32(16).unwrap(), None)
            .unwrap();
        assert_eq!(BigNumber::from_u32(65536).unwrap(), test);

        let answer = BigNumber::from_dec("259344723055062059907025491480697571938277889515152306249728583105665800713306759149981690559193987143012367913206299323899696942213235956742929677132122730441323862712594345230336").unwrap();
        let test = BigNumber::from_u32(2)
            .unwrap()
            .exp(&BigNumber::from_u32(596).unwrap(), None)
            .unwrap();
        assert_eq!(answer, test);
    }

    #[test]
    fn inverse_works() {
        let mut ctx = BigNumber::new_context().unwrap();
        let mut bn = BigNumber::from_u32(3).unwrap();
        assert_eq!(
            BigNumber::from_u32(16).unwrap(),
            bn.inverse(&BigNumber::from_u32(47).unwrap(), Some(&mut ctx))
                .unwrap()
        );
        bn = BigNumber::from_u32(9).unwrap();
        assert_eq!(
            BigNumber::from_u32(3).unwrap(),
            bn.inverse(&BigNumber::from_u32(13).unwrap(), Some(&mut ctx))
                .unwrap()
        );

        let modulus = BigNumber::generate_prime(128).unwrap();
        let one = BigNumber::from_u32(1).unwrap();
        for _ in 0..25 {
            let r = BigNumber::rand(128).unwrap();
            let s = r.inverse(&modulus, Some(&mut ctx)).unwrap();

            let res = r.mod_mul(&s, &modulus, Some(&mut ctx)).unwrap();
            assert_eq!(res, one);
        }
        let modulus = BigNumber::generate_prime(128)
            .unwrap()
            .mul(&modulus, Some(&mut ctx))
            .unwrap();
        for _ in 0..25 {
            let r = BigNumber::rand(256).unwrap();
            let s = r.inverse(&modulus, Some(&mut ctx)).unwrap();

            let res = r.mod_mul(&s, &modulus, Some(&mut ctx)).unwrap();
            assert_eq!(res, one);
        }
    }

    #[test]
    fn generate_prime_in_range_works() {
        let mut start = BigNumber::rand(RANGE_LEFT).unwrap();
        let mut end = BigNumber::rand(RANGE_RIGHT).unwrap();
        if start > end {
            let temp = start;
            start = end.try_clone().unwrap();
            end = temp;
        }
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
        assert_eq!(
            BigNumber::from_u32(7).unwrap(),
            base.mod_exp(&exp, &modulus, None).unwrap()
        );

        let modulus = BigNumber::from_u32(1).unwrap();
        assert_eq!(
            BigNumber::new().unwrap(),
            base.mod_exp(&exp, &modulus, None).unwrap()
        );

        let modulus = BigNumber::from_u32(0).unwrap();
        assert!(base.mod_exp(&exp, &modulus, None).is_err());

        let modulus = BigNumber::from_u32(1).unwrap().set_negative(true).unwrap();
        assert_eq!(
            BigNumber::new().unwrap(),
            base.mod_exp(&exp, &modulus, None).unwrap()
        );

        let modulus = BigNumber::from_u32(5).unwrap().set_negative(true).unwrap();
        assert_eq!(
            BigNumber::from_u32(1).unwrap(),
            base.mod_exp(&exp, &modulus, None).unwrap()
        );
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
