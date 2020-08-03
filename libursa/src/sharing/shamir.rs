//! Implements Shamir's simple secret sharing scheme.
//! Not an implementation of verifiable secret sharing as described by Feldman
//! (see <https://www.cs.umd.edu/~gasarch/TOPICS/secretsharing/feldmanVSS.pdf>
//! or Pedersen
//! (see <https://www.cs.cornell.edu/courses/cs754/2001fa/129.PDF>)
//! or adept secret sharing as described by Phillip Rogaway
//! (see <https://eprint.iacr.org/2020/800>
//!
//! Future work would be to use pedersen commitments or reed-solomon
//! codes to check for corrupted shares.

use bn::BigNumber;
use std::{cmp::Ordering, collections::BTreeSet};

use {CryptoError, CryptoResult};

/// Represents an element in a finite field as [0, n)
#[derive(Debug)]
struct Element {
    /// A prime number
    modulus: BigNumber,
    /// The current element value
    value: BigNumber,
}

impl Element {
    /// Create a new finite field element
    pub fn new(modulus: BigNumber, value: BigNumber) -> Self {
        let value = value.modulus(&modulus, None).unwrap();
        Self { modulus, value }
    }

    /// true if `value` lies within [0, modulus)
    pub fn is_valid(&self) -> bool {
        !self.value.is_negative() && self.value < self.modulus
    }

    /// Returns the current value in bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        self.value.to_bytes().unwrap()
    }

    /// Read bytes from `value` and reduce by the modulus
    pub fn from_bytes<B: AsRef<[u8]>>(modulus: BigNumber, value: B) -> CryptoResult<Self> {
        let value = BigNumber::from_bytes(value.as_ref())?;
        Ok(Self::new(modulus, value))
    }

    /// Compute `self.value` + `b.value` mod n
    pub fn add(&self, b: &Self) -> CryptoResult<Self> {
        self.validate(b)?;
        let value = self.value.add(&b.value)?.modulus(&self.modulus, None)?;
        Ok(Self {
            modulus: self.modulus.try_clone()?,
            value,
        })
    }

    /// Compute `self.value` - `b.value` mod n
    pub fn sub(&self, b: &Self) -> CryptoResult<Self> {
        self.validate(b)?;
        let value = self.value.mod_sub(&b.value, &self.modulus, None)?;
        Ok(Self {
            modulus: self.modulus.try_clone()?,
            value,
        })
    }

    /// Compute `self.value` * `b.value` mod n
    pub fn mul(&self, b: &Self) -> CryptoResult<Self> {
        self.validate(b)?;
        let value = self.value.mod_mul(&b.value, &b.modulus, None)?;
        Ok(Self {
            modulus: self.modulus.try_clone()?,
            value,
        })
    }

    /// Compute `self.value` * `b.value^-1` mod n
    pub fn div(&self, b: &Self) -> CryptoResult<Self> {
        self.validate(b)?;
        let value = self.value.mod_div(&b.value, &b.modulus, None)?;
        Ok(Self {
            modulus: self.modulus.try_clone()?,
            value,
        })
    }

    /// Computes 0 - `self.value`
    pub fn neg(&self) -> CryptoResult<Self> {
        let zero = BigNumber::new()?;
        let value = zero.mod_sub(&self.value, &self.modulus, None)?;
        Ok(Self {
            modulus: self.modulus.try_clone()?,
            value,
        })
    }

    fn validate(&self, b: &Self) -> CryptoResult<()> {
        if self.modulus != b.modulus {
            Err(CryptoError::GeneralError(
                "Different modulus not allowed".to_string(),
            ))
        } else {
            Ok(())
        }
    }

    /// Clone this element
    pub fn try_clone(&self) -> CryptoResult<Self> {
        Ok(Self {
            modulus: self.modulus.try_clone()?,
            value: self.value.try_clone()?,
        })
    }
}

impl PartialEq for Element {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl Eq for Element {}

impl PartialOrd for Element {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Element {
    fn cmp(&self, other: &Self) -> Ordering {
        self.value.cmp(&other.value)
    }
}

#[derive(Debug)]
struct Polynomial {
    coefficients: Vec<Element>,
}

impl Polynomial {
    /// Construct a random polynomial of the specified degree using a specified intercept
    pub fn new(intercept: &Element, degree: usize) -> CryptoResult<Polynomial> {
        let mut coefficients = Vec::with_capacity(degree + 1);

        // Ensure intercept is set
        coefficients.push(intercept.try_clone()?);

        // Assign random coefficients to polynomial
        // Start at 1 since 0 is the intercept and not chosen at random
        for _ in 1..(degree + 1) {
            let value = intercept.modulus.rand_range()?;
            coefficients.push(Element {
                modulus: intercept.modulus.try_clone()?,
                value,
            });
        }
        Ok(Polynomial { coefficients })
    }

    /// Compute the value of the polynomial for the given `x`
    pub fn evaluate(&self, x: &Element) -> CryptoResult<Element> {
        // Compute the polynomial value using Horner's Method
        let degree = self.coefficients.len() - 1;
        // b_n = a_n
        let mut out = self.coefficients[degree].try_clone()?;

        for i in (0..degree).rev() {
            // b_{n-1} = a_{n-1} + b_n*x
            out = out.mul(x)?.add(&self.coefficients[i])?;
        }
        Ok(out)
    }

    /// Takes N sample points and returns the value at a given x using
    /// Lagrange Interpolation
    pub fn interpolate(
        x_coordinates: &[Element],
        y_coordinates: &[Element],
    ) -> CryptoResult<Element> {
        debug_assert_eq!(x_coordinates.len(), y_coordinates.len());

        let limit = x_coordinates.len();
        // Initialize to zero
        let mut result = Element {
            modulus: x_coordinates[0].modulus.try_clone()?,
            value: BigNumber::new()?,
        };

        for i in 0..limit {
            let mut basis = Element {
                modulus: x_coordinates[0].modulus.try_clone()?,
                value: BigNumber::from_u32(1)?,
            };
            for j in 0..limit {
                if i == j {
                    continue;
                }

                // -x_m
                let num = x_coordinates[j].neg()?;
                // x_j - x_m
                let denom = x_coordinates[i].sub(&x_coordinates[j])?;
                // -x_m / (x_j - x_m) * ...
                basis = basis.mul(&num.div(&denom)?)?;
            }
            let group = y_coordinates[i].mul(&basis)?;
            result = result.add(&group)?;
        }
        Ok(result)
    }
}

/// Represents a share created from a split
#[derive(Debug)]
pub struct Share {
    /// x-coordinate
    pub identifier: u8,
    /// y-coordinate
    pub value: BigNumber,
}

impl Share {
    /// Return byte representation of this share: value || identifier
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut output = self.value.to_bytes().unwrap();
        output.push(self.identifier);
        output
    }

    /// Convert a share from bytes, assumes the last byte is the identifier
    pub fn from_bytes<B: AsRef<[u8]>>(data: B, modulus: &BigNumber) -> CryptoResult<Self> {
        let data = data.as_ref();
        let value = BigNumber::from_bytes(&data[..(data.len() - 1)])?.modulus(modulus, None)?;
        let identifier = data[data.len() - 1];
        Ok(Self { identifier, value })
    }
}

impl Clone for Share {
    fn clone(&self) -> Self {
        Self {
            identifier: self.identifier,
            value: self.value.try_clone().unwrap(),
        }
    }
}

/// Take a `secret` and generate `total` shares, which `threshold` is required to
/// reconstruct the `secret` in the specified finite `field`.
/// The `threshold` and `total` must be at least 2. Doesn't support more than 255
/// (not sure why so many would be needed). The returned shares attach
/// attach a one byte tag used to reconstruct the secret.
///
/// Make sure `field` is either prime or prime power, i.e. is actually a field
/// otherwise this method is insecure
pub fn split_secret<B: AsRef<[u8]>>(
    secret: B,
    threshold: u8,
    total: u8,
    field: &BigNumber,
) -> CryptoResult<Vec<Share>> {
    if total < threshold {
        return Err(CryptoError::GeneralError(
            "total cannot be less than the threshold".to_string(),
        ));
    }
    if threshold < 2 {
        return Err(CryptoError::GeneralError(
            "threshold must be at least 2".to_string(),
        ));
    }
    let secret = secret.as_ref();
    if secret.len() == 0 {
        return Err(CryptoError::GeneralError(
            "secret cannot be empty".to_string(),
        ));
    }
    if field < &BigNumber::from_u32(2)? {
        return Err(CryptoError::GeneralError(
            "field must be greater than 1".to_string(),
        ));
    }
    let element = Element {
        modulus: field.try_clone()?,
        value: BigNumber::from_bytes(secret)?,
    };
    if !element.is_valid() {
        return Err(CryptoError::GeneralError("secret is too large".to_string()));
    }
    let polynomial = Polynomial::new(&element, (threshold - 1) as usize)?;

    // Generate the shares of (x, y) coordinates
    // x coordinates are incremental from [1, total+1). 0 is reserved for the secret.
    let mut shares = Vec::with_capacity(total as usize);
    for i in 0..total {
        let identifier = i + 1;
        let x = Element::from_bytes(field.try_clone()?, &[identifier])?;
        let y = polynomial.evaluate(&x)?;
        shares.push(Share {
            identifier,
            value: y.value,
        });
    }
    Ok(shares)
}

/// Reconstruct a secret from at least a threshold set of `shares` in the specified finite `field`.
pub fn combine_shares<B: AsRef<[Share]>>(shares: B, field: &BigNumber) -> CryptoResult<Vec<u8>> {
    let shares = shares.as_ref();
    // Verify minimum shares
    if shares.len() < 2 {
        return Err(CryptoError::GeneralError(
            "Less than two shares cannot be used to reconstruct the secret".to_string(),
        ));
    }
    if field < &BigNumber::from_u32(2)? {
        return Err(CryptoError::GeneralError(
            "field must be greater than 1".to_string(),
        ));
    }

    // Verify the secrets are non-empty and identifiers are valid
    let mut dups = BTreeSet::new();
    let zero = BigNumber::new()?;
    let mut x_coordinates = Vec::with_capacity(shares.len());
    let mut y_coordinates = Vec::with_capacity(shares.len());

    for share in shares {
        if &share.value == &zero {
            return Err(CryptoError::GeneralError(
                "Share must have a non-zero value".to_string(),
            ));
        }
        if share.identifier == 0 {
            return Err(CryptoError::GeneralError(
                "Share must have a non-zero identifier".to_string(),
            ));
        }
        if dups.contains(&share.identifier) {
            return Err(CryptoError::GeneralError(
                "Duplicate shares cannot be used to reconstruct the secret".to_string(),
            ));
        }
        dups.insert(share.identifier);
        x_coordinates.push(Element::from_bytes(
            field.try_clone()?,
            &[share.identifier],
        )?);
        y_coordinates.push(Element {
            modulus: field.try_clone()?,
            value: share.value.try_clone()?,
        });
    }
    let secret = Polynomial::interpolate(&x_coordinates, &y_coordinates)?;
    Ok(secret.to_bytes())
}

#[cfg(test)]
mod tests {

    const ED25519_SUBGROUP_ORDER: &str =
        "1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED";
    const BLS12_381_SUBGROUP_ORDER: &str =
        "73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001";

    macro_rules! tests {
        ($name:ident, $mod:expr) => {
            mod $name {
                use super::super::*;
                use super::*;
                #[test]
                fn split_invalid_args() {
                    let modulus = BigNumber::from_hex($mod).unwrap();

                    let secret = b"test";

                    assert!(split_secret(secret.as_ref(), 0, 0, &modulus).is_err());
                    assert!(split_secret(secret.as_ref(), 3, 2, &modulus).is_err());
                    assert!(split_secret(secret.as_ref(), 1, 10, &modulus).is_err());
                    assert!(split_secret(&[], 2, 3, &modulus).is_err());
                    let mut too_big_secret = Vec::new();
                    while too_big_secret.len() < (($mod.len() / 2) + 1) {
                        too_big_secret.push(65u8);
                    }
                    assert!(split_secret(too_big_secret.as_slice(), 2, 3, &modulus).is_err());
                }

                #[test]
                fn combine_invalid() {
                    let modulus = BigNumber::from_hex($mod).unwrap();

                    // No shares
                    let shares = Vec::new();
                    assert!(combine_shares(shares, &modulus).is_err());

                    // No secret
                    let shares = vec![
                        Share {
                            value: BigNumber::new().unwrap(),
                            identifier: 1,
                        },
                        Share {
                            value: BigNumber::new().unwrap(),
                            identifier: 2,
                        },
                    ];
                    assert!(combine_shares(shares, &modulus).is_err());

                    // Zero identifier
                    let shares = vec![
                        Share {
                            value: BigNumber::from_bytes(b"abc").unwrap(),
                            identifier: 0,
                        },
                        Share {
                            value: BigNumber::from_bytes(b"abc").unwrap(),
                            identifier: 2,
                        },
                    ];
                    assert!(combine_shares(shares, &modulus).is_err());

                    // Duplicate shares
                    let shares = vec![
                        Share {
                            value: BigNumber::from_bytes(b"abc").unwrap(),
                            identifier: 1,
                        },
                        Share {
                            value: BigNumber::from_bytes(b"abc").unwrap(),
                            identifier: 1,
                        },
                    ];
                    assert!(combine_shares(shares, &modulus).is_err());
                }

                #[test]
                fn combine_single() {
                    let modulus = BigNumber::from_hex($mod).unwrap();

                    let secret = b"hello";

                    let res = split_secret(secret, 2, 3, &modulus);
                    assert!(res.is_ok());
                    let shares = res.unwrap();

                    let res = combine_shares(shares, &modulus);
                    assert!(res.is_ok());
                    let secret_1 = res.unwrap();

                    assert!(secret.to_vec() == secret_1);
                }

                #[test]
                fn combine_all_combinations() {
                    let modulus = BigNumber::from_hex($mod).unwrap();

                    let secret = b"hello";

                    let res = split_secret(secret, 3, 5, &modulus);
                    assert!(res.is_ok());
                    let shares = res.unwrap();

                    // There is 5*4*3 possible choices
                    // try them all. May take a while
                    for i in 0..5 {
                        for j in 0..5 {
                            if i == j {
                                continue;
                            }

                            for k in 0..5 {
                                if k == i || k == j {
                                    continue;
                                }
                                let parts =
                                    &[shares[i].clone(), shares[j].clone(), shares[k].clone()];

                                let res = combine_shares(parts, &modulus);
                                assert!(res.is_ok());
                                let secret_1 = res.unwrap();
                                assert!(secret.to_vec() == secret_1);
                            }
                        }
                    }
                }

                #[test]
                fn polynomial_set_intercept() {
                    let modulus = BigNumber::from_hex($mod).unwrap();

                    let intercept = Element {
                        value: BigNumber::from_u32(42).unwrap(),
                        modulus: modulus.try_clone().unwrap(),
                    };
                    let zero = Element {
                        value: BigNumber::from_u32(0).unwrap(),
                        modulus: modulus.try_clone().unwrap(),
                    };

                    let p = Polynomial::new(&intercept, 1).unwrap();

                    let out = p.evaluate(&zero).unwrap();
                    assert_eq!(out, intercept);

                    let one = Element {
                        value: BigNumber::from_u32(1).unwrap(),
                        modulus: modulus.try_clone().unwrap(),
                    };

                    let out = p.evaluate(&one).unwrap();
                    let exp = intercept.add(&p.coefficients[1]).unwrap();
                    assert_eq!(out, exp);
                }
            }
        };
    }

    tests!(ed25519, ED25519_SUBGROUP_ORDER);
    tests!(bls12381, BLS12_381_SUBGROUP_ORDER);
}
