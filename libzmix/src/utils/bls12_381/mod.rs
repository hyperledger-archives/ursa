use amcl_miracl::bls381::big::BIG;
use amcl_miracl::bls381::dbig::DBIG;
use amcl_miracl::bls381::ecp::ECP;
use amcl_miracl::bls381::ecp2::ECP2;
use amcl_miracl::bls381::rom;

use sha2::Sha256;

use rand::thread_rng;
use rand_core::RngCore;

use hkdf::Hkdf;

lazy_static! {
    static ref G1: ECP = ECP::generator();
    static ref G2: ECP2 = ECP2::generator();
    static ref GROUP_ORDER: BIG = BIG::new_ints(&rom::CURVE_ORDER);
}

macro_rules! serialize_impl {
    ($name:ident, $internal:ident, $visitor:ident) => {
        impl std::str::FromStr for $name {
            type Err = std::num::ParseIntError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Ok($name($internal::from_hex(s.to_string())))
            }
        }

        impl From<&str> for $name {
            fn from(data: &str) -> $name {
                $name($internal::from_hex(data.to_string()))
            }
        }

        impl From<&[u8]> for $name {
            fn from(data: &[u8]) -> $name {
                let mut vec = data.to_vec();
                if data.len() > Self::BYTES_REPR_SIZE {
                    vec = data[0..Self::BYTES_REPR_SIZE].to_vec();
                } else if data.len() < Self::BYTES_REPR_SIZE {
                    let diff = Self::BYTES_REPR_SIZE - data.len();
                    let mut res = vec![0u8; diff];
                    res.append(&mut vec);
                    vec = res;
                }
                $name($internal::frombytes(vec.as_slice()))
            }
        }

        impl serde::ser::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::ser::Serializer,
            {
                serializer.serialize_newtype_struct(stringify!($name), &self.to_string())
            }
        }

        impl<'a> serde::de::Deserialize<'a> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::de::Deserializer<'a>,
            {
                struct $visitor;

                impl<'a> serde::de::Visitor<'a> for $visitor {
                    type Value = $name;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                        formatter.write_str(stringify!($name))
                    }

                    fn visit_str<E>(self, value: &str) -> Result<$name, E>
                    where
                        E: serde::de::Error,
                    {
                        let name_str = stringify!($name);
                        if value.starts_with(name_str) {
                            Ok(
                                $name::from_str(&value[(name_str.len() + 2)..(value.len() - 2)])
                                    .map_err(serde::de::Error::custom)?,
                            )
                        } else {
                            Err(E::custom(format!("Invalid string: {}", value)))
                        }
                    }
                }

                deserializer.deserialize_str($visitor)
            }
        }
    };
}

macro_rules! format_impl {
    ($name:ident) => {
        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "{}( {} )", stringify!($name), self.to_hex())
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "{}( {} )", stringify!($name), self.to_hex())
            }
        }
    };
}

macro_rules! add_impl {
    ($name: ident, $sel1:ident $rhs1:ident $add:block, $sel2:ident $rhs2:ident $assign:block) => {
        impl Add for $name {
            type Output = $name;

            fn add(self, rhs: $name) -> $name {
                &self + &rhs
            }
        }

        impl<'a, 'b> Add<&'b $name> for &'a $name {
            type Output = $name;

            fn add($sel1, $rhs1: &'b $name) -> $name $add
        }

        impl AddAssign for $name {
            fn add_assign(&mut $sel2, $rhs2: $name) $assign
        }

        impl AddAssign<&$name> for $name {
            fn add_assign(&mut $sel2, $rhs2: &$name) $assign
        }
    };
}

macro_rules! sub_impl {
    ($name: ident, $sel1:ident $rhs1:ident $sub:block, $sel2:ident $rhs2:ident $assign:block) => {
        impl Sub for $name {
            type Output = $name;

            fn sub(self, rhs: $name) -> $name {
                &self - &rhs
            }
        }

        impl<'a, 'b> Sub<&'b $name> for &'a $name {
            type Output = $name;

            fn sub($sel1, $rhs1: &'b $name) -> $name $sub
        }

        impl SubAssign for $name {
            fn sub_assign(&mut $sel2, $rhs2: $name) $assign
        }

        impl SubAssign<&$name> for $name {
            fn sub_assign(&mut $sel2, $rhs2: &$name) $assign
        }
    };
}

macro_rules! mul_impl {
    ($name:ident, $rhs:ident, $sel1:ident $rhs1:ident $mul:block, $sel2:ident $rhs2:ident $assign: block) => {
        impl Mul<$rhs> for $name {
            type Output = $name;

            fn mul(self, rhs: $rhs) -> $name {
                &self * &rhs
            }
        }

        impl<'a, 'b> Mul<&'b $rhs>for &'a $name {
            type Output = $name;

            fn mul($sel1, $rhs1: &'b $rhs) -> $name $mul
        }

        impl MulAssign<$rhs> for $name {
            fn mul_assign(&mut $sel2, $rhs2: $rhs) $assign
        }

        impl MulAssign<&$rhs> for $name {
            fn mul_assign(&mut $sel2, $rhs2: &$rhs) $assign
        }
    };
}

macro_rules! neg_impl {
    ($name:ident, $sel:ident $code:block) => {
        impl Neg for $name {
            type Output = $name;

            fn neg($sel) -> $name $code
        }

        impl<'a> Neg for &'a $name {
            type Output = $name;

            fn neg($sel) -> $name $code
        }
    };
}

macro_rules! default_impl {
    ($name:ident) => {
        impl Default for $name {
            fn default() -> $name {
                $name::new()
            }
        }
    };
}

macro_rules! to_bytes {
    () => {
        pub fn to_bytes(&self) -> Vec<u8> {
            let mut res = vec![0u8; Self::BYTES_REPR_SIZE];
            self.repr_bytes(&mut res);
            res
        }
    };
}

/// Generate a random number twice the number of bytes as the curve reduced by mod CURVE_ORDER
/// Here 96 bytes are randomly generated mod CURVE_ORDER. The result is 48 bytes.
fn random_mod_order<R: RngCore>(r: Option<&mut R>) -> BIG {
    let mut seed1 = vec![0u8; rom::MODBYTES];
    let mut seed2 = vec![0u8; rom::MODBYTES];

    match r {
        Some(rr) => {
            rr.fill_bytes(&mut seed1.as_mut_slice());
            rr.fill_bytes(&mut seed2.as_mut_slice());
        }
        None => {
            thread_rng().fill_bytes(&mut seed1.as_mut_slice());
            thread_rng().fill_bytes(&mut seed2.as_mut_slice());
        }
    }

    compute_big(seed1.as_slice(), seed2.as_slice())
}

/// Hash the data to a field order element
/// Based on standardization efforts for BLS12-381, it is recommended to use HKDF
/// instead of SHA2 due to its properties of better hiding low entropy inputs.
///
/// Here, 96 bytes is used. This allows a bigger range than SHA2-256 and eliminates some biases
/// for outputs that are close to the CURVE_ORDER like SHA2-384.
///
/// Salt should be of sufficient length to add the security of the keying material (See https://tools.ietf.org/html/rfc5869)
/// The output of 96 bytes should require the salt to not be less than 32 bytes
///
/// The result is 48 bytes.
fn hash_mod_order(data: &[u8], salt: &[u8], domain_sep_context: &[u8]) -> BIG {
    //Domain salt and key
    let hk = Hkdf::<Sha256>::extract(Some(salt), data);
    let mut output = vec![0u8; rom::MODBYTES * 2];
    hk.expand(domain_sep_context, output.as_mut_slice())
        .unwrap();

    compute_big(
        &output.as_slice()[0..rom::MODBYTES],
        &output.as_slice()[rom::MODBYTES..],
    )
}

fn compute_big(seed1: &[u8], seed2: &[u8]) -> BIG {
    let num1 = BIG::frombytes(seed1);
    let num2 = BIG::frombytes(seed2);
    let num1 = DBIG::new_scopy(&num1);
    let mut res = DBIG::new();
    res.ucopy(&num2);
    res.add(&num1);
    res.dmod(&GROUP_ORDER)
}

pub mod curve;

#[cfg(test)]
mod tests {
    use super::{hash_mod_order, random_mod_order};
    use amcl_miracl::bls381::big::BIG;
    use amcl_miracl::bls381::rom;
    use rand::prelude::*;
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;

    #[test]
    fn random_tests() {
        let seed = b"11111111111111111111111111111111";
        let order = BIG::new_ints(&rom::CURVE_ORDER);
        let mut rng = ChaChaRng::from_seed(*seed);

        let r = random_mod_order(Some(&mut rng));
        assert_eq!(r, BIG::from_hex("000000000000000000000000000000005C9F002063FDC7EDD33E8787C8322E794198C2F397DEF85F382FE9075A2A0E5F".to_string()));
        assert!(r < order);
        let r = random_mod_order(Some(&mut rng));
        assert_eq!(r, BIG::from_hex("0000000000000000000000000000000002EB5988AC48026ABEAF0206276C9D1158B5A2BE12EAFF2097A9AD8D8CFFD64D".to_string()));

        for _ in 0..30 {
            let r1 = random_mod_order::<ThreadRng>(None);
            let r2 = random_mod_order::<ThreadRng>(None);
            assert_ne!(r1, r2);
        }
    }

    #[test]
    fn hash_tests() {
        let seed = b"11111111111111111111111111111111";
        let order = BIG::new_ints(&rom::CURVE_ORDER);
        let mut rng = ChaChaRng::from_seed(*seed);

        let mut r = [0u8; 48];
        let mut salt = [0u8; 64];
        let mut domain_sep = [0u8; 64];
        rng.fill_bytes(&mut salt);
        rng.fill_bytes(&mut domain_sep);
        rng.fill_bytes(&mut r);

        let h = hash_mod_order(&r, &salt, &domain_sep);
        assert_eq!(h, BIG::from_hex("000000000000000000000000000000006B3BEB2C3B7533E0779C7CBAD706CD5C4D1A509CB745407C261A255E50994659".to_string()));
        assert!(h < order);
        let h1 = hash_mod_order(&r, &salt, &domain_sep);
        assert_eq!(h, h1);
        rng.fill_bytes(&mut r);
        let h = hash_mod_order(&r, &salt, &domain_sep);
        assert_eq!(h, BIG::from_hex("0000000000000000000000000000000031166009F73832723867A5DF39C2D5AEFCF49B4EDCB4192019E101CED9F9A264".to_string()));
        assert!(h < order);
    }
}
