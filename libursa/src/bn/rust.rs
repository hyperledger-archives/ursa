use errors::UrsaCryptoError;

use hash::{digest, DigestAlgorithm, Digest, sha2};
use num_bigint::{BigInt, BigUint, RandBigInt, ToBigInt, Sign};
use num_integer::Integer;
use num_traits::identities::{One, Zero};
use num_traits::{Num, Signed, ToPrimitive, Pow};
use glass_pumpkin::{prime, safe_prime};
use rand::rngs::OsRng;

#[cfg(feature = "serialization")]
use serde::ser::{Serialize, Serializer, Error as SError};

#[cfg(feature = "serialization")]
use serde::de::{Deserialize, Deserializer, Visitor, Error as DError};

use std::error::Error;
use std::fmt;
use std::cmp::Ord;
use std::cmp::Ordering;

pub struct BigNumberContext;

pub struct BigNumber {
    bn: BigInt
}

macro_rules! prime_generation {
    ($f:ident, $size:ident, $msg:expr) => {
        match $f::new($size)?.to_bigint() {
            Some(bn) => Ok(BigNumber { bn }),
            None => Err(UrsaCryptoError::InvalidStructure($msg.to_string()))
        }
    };
}

impl BigNumber {
    pub fn new_context() -> Result<BigNumberContext, UrsaCryptoError> {
        Ok(BigNumberContext{})
    }

    pub fn new() -> Result<BigNumber, UrsaCryptoError> {
        Ok(BigNumber {
            bn: BigInt::zero()
        })
    }

    pub fn generate_prime(size: usize) -> Result<BigNumber, UrsaCryptoError> {
        prime_generation!(prime, size, "Unable to generate prime")
    }

    pub fn generate_safe_prime(size: usize) -> Result<BigNumber, UrsaCryptoError> {
        prime_generation!(safe_prime, size, "Unable to generate safe prime")
    }

    pub fn generate_prime_in_range(start: &BigNumber, end: &BigNumber) -> Result<BigNumber, UrsaCryptoError> {
        let mut res;
        let mut iteration = 0;
        let mut rng = OsRng::new()?;
        let start = match start.bn.to_biguint() {
            Some(bn) => bn,
            None => return Err(UrsaCryptoError::InvalidStructure(format!("Invalid number for 'start': {:?}", start)))
        };
        let end = match end.bn.to_biguint() {
            Some(bn) => bn,
            None => return Err(UrsaCryptoError::InvalidStructure(format!("Invalid number for 'end': {:?}", end)))
        };

        let bits = (&end -  &start).bits();
        let mask = (BigUint::from(3u8) << (bits - 2)) | BigUint::one();

        loop {
            res = rng.gen_biguint_range(&start, &end);
            res |= &mask;

            if prime::check(&res) {
                debug!("Found prime in {} iteration", iteration);
                break;
            }
            iteration += 1;
        }

        match res.to_bigint() {
            Some(bn) => Ok(BigNumber{bn}),
            None => Err(UrsaCryptoError::InvalidStructure("Unable to generate prime in range".to_string()))
        }
    }

    pub fn is_prime(&self, _ctx: Option<&mut BigNumberContext>) -> Result<bool, UrsaCryptoError> {
        if self.is_negative() {
            Ok(false)
        } else {
            match self.bn.to_biguint() {
                Some(bn) => Ok(prime::check(&bn)),
                None => Err(UrsaCryptoError::InvalidStructure("An error in is_prime".to_string()))
            }
        }
    }

    pub fn is_safe_prime(&self, _ctx: Option<&mut BigNumberContext>) -> Result<bool, UrsaCryptoError> {
        if self.is_negative() {
            Ok(false)
        } else {
            match self.bn.to_biguint() {
                Some(bn) => Ok(safe_prime::check(&bn)),
                None => Err(UrsaCryptoError::InvalidStructure("An error in is_safe_prime".to_string()))
            }
        }
    }

    pub fn rand(size: usize) -> Result<BigNumber, UrsaCryptoError> {
        let mut rng = OsRng::new()?;
        let res = rng.gen_biguint(size).to_bigint();
        Ok(BigNumber { bn: res.unwrap() })
    }

    pub fn rand_range(&self) -> Result<BigNumber, UrsaCryptoError> {
        let mut rng = OsRng::new()?;
        let res = rng.gen_bigint_range(&BigInt::zero(), &self.bn);
        match res.to_bigint() {
            Some(bn) => Ok(BigNumber{bn}),
            None => Err(UrsaCryptoError::InvalidStructure("An error in rand_range".to_string()))
        }
    }

    pub fn num_bits(&self) -> Result<i32, UrsaCryptoError> {
        Ok(self.bn.bits() as i32)
    }

    pub fn is_bit_set(&self, n: i32) -> Result<bool, UrsaCryptoError> {
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

    pub fn from_u32(n: usize) -> Result<BigNumber, UrsaCryptoError> {
        Ok(BigNumber { bn: BigInt::from(n) })
    }

    pub fn from_dec(dec: &str) -> Result<BigNumber, UrsaCryptoError> {
        Ok(BigNumber{ bn: BigInt::from_str_radix(dec, 10)? })
    }

    pub fn from_hex(hex: &str) -> Result<BigNumber, UrsaCryptoError> {
        Ok(BigNumber{ bn: BigInt::from_str_radix(hex, 16)? })
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<BigNumber, UrsaCryptoError> {
        Ok(BigNumber { bn: BigInt::from_bytes_be(Sign::Plus, bytes) })
    }

    pub fn to_dec(&self) -> Result<String, UrsaCryptoError> {
        Ok(self.bn.to_str_radix(10))
    }

    pub fn to_hex(&self) -> Result<String, UrsaCryptoError> {
        Ok(self.bn.to_str_radix(16).to_uppercase())
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, UrsaCryptoError> {
        let (_, res) = self.bn.to_bytes_be();
        Ok(res)
    }

    pub fn hash(data: &[u8]) -> Result<Vec<u8>, UrsaCryptoError> {
        digest(DigestAlgorithm::Sha2_256, data).map_err(|e| UrsaCryptoError::InvalidStructure(e.to_string()))
    }

    pub fn add(&self, a: &BigNumber) -> Result<BigNumber, UrsaCryptoError> {
        let res = &self.bn + &a.bn;
        Ok(BigNumber { bn: res })
    }

    pub fn sub(&self, a: &BigNumber) -> Result<BigNumber, UrsaCryptoError> {
        let res = &self.bn - &a.bn;
        Ok(BigNumber { bn: res })
    }

    pub fn sqr(&self, _ctx: Option<&mut BigNumberContext>) -> Result<BigNumber, UrsaCryptoError> {
        let res = &self.bn * &self.bn;
        Ok(BigNumber { bn: res })
    }

    pub fn mul(&self, a: &BigNumber, _ctx: Option<&mut BigNumberContext>) -> Result<BigNumber, UrsaCryptoError> {
        let res = &self.bn * &a.bn;
        Ok(BigNumber { bn: res })
    }

    pub fn mod_mul(&self, a: &BigNumber, n: &BigNumber, _ctx: Option<&mut BigNumberContext>) -> Result<BigNumber, UrsaCryptoError> {
        //TODO: Use montgomery reduction
        let res = (&self.bn * &a.bn) % &n.bn;
        Ok(BigNumber { bn: res })
    }

    pub fn mod_sub(&self, a: &BigNumber, n: &BigNumber, _ctx: Option<&mut BigNumberContext>) -> Result<BigNumber, UrsaCryptoError> {
        let res = (&self.bn - &a.bn) % &n.bn;
        Ok(BigNumber { bn: res })
    }

    pub fn div(&self, a: &BigNumber, _ctx: Option<&mut BigNumberContext>) -> Result<BigNumber, UrsaCryptoError> {
        let res = &self.bn / &a.bn;
        Ok(BigNumber { bn: res })
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
        self.bn /= w;
        Ok(self)
    }

    pub fn mod_exp(&self, a: &BigNumber, b: &BigNumber, _ctx: Option<&mut BigNumberContext>) -> Result<BigNumber, UrsaCryptoError> {
        if a.is_negative() {
            let res = self.inverse(&b, _ctx)?;
            let a = a.set_negative(false)?;
            Ok(BigNumber{ bn: res.bn.modpow(&a.bn, &b.bn) })
        } else {
            let res = self.bn.modpow(&a.bn, &b.bn);
            Ok(BigNumber { bn: res })
        }
    }

    pub fn modulus(&self, a: &BigNumber, _ctx: Option<&mut BigNumberContext>) -> Result<BigNumber, UrsaCryptoError> {
        let res = &self.bn % &a.bn;
        Ok(BigNumber { bn: res })
    }

    pub fn exp(&self, a: &BigNumber, _ctx: Option<&mut BigNumberContext>) -> Result<BigNumber, UrsaCryptoError> {
        if self.bn.bits() == 0 {
            return Ok(BigNumber::default())
        } else if a.bn.is_one() {
            return Ok(self.try_clone()?)
        }

        match a.bn.to_u64() {
            Some(num) => Ok(BigNumber { bn: self.bn.pow(num) }),
            None => Err(UrsaCryptoError::InvalidStructure("'a' cannot be help in u64".to_string()))
        }
    }

    pub fn inverse(&self, n: &BigNumber, _ctx: Option<&mut BigNumberContext>) -> Result<BigNumber, UrsaCryptoError> {
        if n.bn.is_one() ||
           n.bn.is_zero() {
            return Err(UrsaCryptoError::InvalidStructure("Invalid modulus".to_string()))
        }

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
        let (mut r, mut new_r) = (n.bn.clone(), self.bn.clone());

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
            return Err(UrsaCryptoError::InvalidStructure("Not invertible".to_string()));
        } else if t < BigInt::zero() {
            t += n.bn.clone()
        }

        Ok(BigNumber { bn: t })
    }

    pub fn set_negative(&self, negative: bool) -> Result<BigNumber, UrsaCryptoError> {
        match (self.bn < BigInt::zero(), negative) {
            (true, true) => Ok(BigNumber { bn: self.bn.clone() }),
            (false, false) => Ok(BigNumber { bn: self.bn.clone() }),
            (true, false) => Ok(BigNumber { bn: -self.bn.clone() }),
            (false, true) => Ok(BigNumber { bn: -self.bn.clone() }),
        }
    }

    pub fn is_negative(&self) -> bool {
        self.bn.is_negative()
    }

    pub fn increment(&self) -> Result<BigNumber, UrsaCryptoError> {
        Ok(BigNumber { bn: &self.bn + 1 })
    }

    pub fn decrement(&self) -> Result<BigNumber, UrsaCryptoError> {
        Ok(BigNumber { bn: &self.bn - 1 })
    }

    pub fn lshift1(&self) -> Result<BigNumber, UrsaCryptoError> {
        Ok(BigNumber { bn: &self.bn << 1 })
    }

    pub fn rshift1(&self) -> Result<BigNumber, UrsaCryptoError> {
        Ok(BigNumber { bn: &self.bn >> 1 })
    }

    pub fn rshift(&self, n: i32) -> Result<BigNumber, UrsaCryptoError> {
        let n = n as usize;
        Ok(BigNumber { bn: &self.bn >> n })
    }

    pub fn mod_div(&self, b: &BigNumber, p: &BigNumber, _ctx: Option<&mut BigNumberContext>) -> Result<BigNumber, UrsaCryptoError> {
        //(a * (1/b mod p) mod p)
        let res = (&self.bn * b.inverse(p, _ctx)?.bn) % &p.bn;
        Ok(BigNumber { bn: res })
    }

    pub fn random_qr(n: &BigNumber) -> Result<BigNumber, UrsaCryptoError> {
        let qr = n
            .rand_range()?
            .sqr(None)?
            .modulus(&n, None)?;
        Ok(qr)
    }

    pub fn try_clone(&self) -> Result<BigNumber, UrsaCryptoError> {
        Ok(BigNumber {
            bn: self.bn.clone()
        })
    }

    pub fn hash_array(nums: &[Vec<u8>]) -> Result<Vec<u8>, UrsaCryptoError> {
        let mut hasher = sha2::Sha256::new();

        for num in nums.iter() {
            hasher.update(&num);
        }

        hasher.finalize().map_err(|e| UrsaCryptoError::InvalidStructure(e.to_string()))
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

impl From<glass_pumpkin::error::Error> for UrsaCryptoError {
    fn from(err: glass_pumpkin::error::Error) -> UrsaCryptoError {
        UrsaCryptoError::InvalidStructure(err.description().to_string())
    }
}

impl From<rand::Error> for UrsaCryptoError {
    fn from(err: rand::Error) -> UrsaCryptoError {
        UrsaCryptoError::InvalidStructure(err.description().to_string())
    }
}

impl From<num_bigint::ParseBigIntError> for UrsaCryptoError {
    fn from(err: num_bigint::ParseBigIntError) -> UrsaCryptoError {
        UrsaCryptoError::InvalidStructure(err.description().to_string())
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
        let test = BigNumber::from_u32(3).unwrap().exp(&BigNumber::from_u32(2).unwrap(), None).unwrap();
        assert_eq!(BigNumber::from_u32(9).unwrap(), test);

        let test = BigNumber::from_u32(3).unwrap().exp(&BigNumber::from_u32(3).unwrap(), None).unwrap();
        assert_eq!(BigNumber::from_u32(27).unwrap(), test);

        let test = BigNumber::from_u32(2).unwrap().exp(&BigNumber::from_u32(16).unwrap(), None).unwrap();
        assert_eq!(BigNumber::from_u32(65536).unwrap(), test);

        let answer = BigNumber::from_dec("259344723055062059907025491480697571938277889515152306249728583105665800713306759149981690559193987143012367913206299323899696942213235956742929677132122730441323862712594345230336").unwrap();
        let test = BigNumber::from_u32(2).unwrap().exp(&BigNumber::from_u32(596).unwrap(), None).unwrap();
        assert_eq!(answer, test);
    }

    #[test]
    fn inverse_works() {
        let mut ctx = BigNumber::new_context().unwrap();
        let mut bn = BigNumber::from_u32(3).unwrap();
        assert_eq!(BigNumber::from_u32(16).unwrap(), bn.inverse(&BigNumber::from_u32(47).unwrap(), Some(&mut ctx)).unwrap());
        bn = BigNumber::from_u32(9).unwrap();
        assert_eq!(BigNumber::from_u32(3).unwrap(), bn.inverse(&BigNumber::from_u32(13).unwrap(), Some(&mut ctx)).unwrap());

        let modulus = BigNumber::generate_prime(128).unwrap();
        let one = BigNumber::from_u32(1).unwrap();
        for _ in 0..25 {
            let r = BigNumber::rand(128).unwrap();
            let s = r.inverse(&modulus, Some(&mut ctx)).unwrap();

            let res = r.mod_mul(&s, &modulus, Some(&mut ctx)).unwrap();
            assert_eq!(res, one);
        }
        let modulus = BigNumber::generate_prime(128).unwrap().mul(&modulus, Some(&mut ctx)).unwrap();
        for _ in 0..25 {
            let r = BigNumber::rand(256).unwrap();
            let s = r.inverse(&modulus, Some(&mut ctx)).unwrap();

            let res = r.mod_mul(&s, &modulus, Some(&mut ctx)).unwrap();
            assert_eq!(res, one);
        }
    }

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
