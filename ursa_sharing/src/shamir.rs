// Copyright 2020 Hyperledger Ursa Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
use super::{
    error::{SharingError, SharingResult},
    Field, Group, Polynomial,
};
use rand::{CryptoRng, RngCore};
use std::{collections::BTreeSet, convert::TryFrom};
use zeroize::Zeroize;

/// A Shamir simple secret share
/// provides no integrity checking
#[derive(Debug, Zeroize)]
#[zeroize(drop)]
pub struct Share {
    /// X-coordinate
    pub(crate) identifier: u32,
    /// Y-coordinate
    pub(crate) value: Vec<u8>,
}

impl Share {
    /// Create a new share
    pub fn new<B: AsRef<[u8]>>(identifier: usize, value: B) -> Self {
        Self {
            identifier: identifier as u32,
            value: value.as_ref().to_vec(),
        }
    }

    /// Output the share value and the identifier.
    /// The identifier is the first 4 bytes
    pub fn to_bytes(&mut self) -> Vec<u8> {
        let mut o = self.identifier.to_be_bytes().to_vec();
        o.append(&mut self.value);
        o
    }

    /// Get the identifier
    pub fn identifier(&self) -> u32 {
        self.identifier
    }

    /// Get the current value of the share
    pub fn value(&self) -> &[u8] {
        self.value.as_slice()
    }
}

impl TryFrom<&[u8]> for Share {
    type Error = SharingError;

    fn try_from(value: &[u8]) -> SharingResult<Self> {
        if value.len() < 4 {
            return Err(SharingError::ShareSecretMinSize);
        }
        let mut identifier = [0u8; 4];
        identifier.copy_from_slice(&value[..4]);
        Ok(Self {
            identifier: u32::from_be_bytes(identifier),
            value: value[4..].to_vec(),
        })
    }
}

impl Clone for Share {
    fn clone(&self) -> Self {
        Self {
            identifier: self.identifier,
            value: self.value.clone(),
        }
    }
}

/// Shamir's simple secret sharing scheme.
#[derive(Copy, Clone, Debug)]
pub struct Scheme {
    threshold: usize,
    limit: usize,
}

impl Scheme {
    /// Create a new Shamir scheme
    pub fn new(threshold: usize, limit: usize) -> SharingResult<Self> {
        if limit < threshold {
            return Err(SharingError::ShareLimitLessThanThreshold);
        }
        if threshold < 2 {
            return Err(SharingError::ShareMinThreshold);
        }
        Ok(Self { threshold, limit })
    }

    /// Create Shares from a secret
    pub fn split_secret<S: Field>(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        secret: &S,
    ) -> SharingResult<Vec<Share>> {
        let (shares, _) = self.get_shares_and_polynomial(rng, secret)?;
        Ok(shares)
    }

    pub(crate) fn get_shares_and_polynomial<S: Field>(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        secret: &S,
    ) -> SharingResult<(Vec<Share>, Polynomial<S>)> {
        if !secret.is_valid() {
            return Err(SharingError::ShareInvalidSecret);
        }

        let polynomial = Polynomial::new(rng, secret, self.threshold);

        // Generate the shares of (x, y) coordinates
        // x coordinates are incremental from [1, total+1). 0 is reserved for the secret.
        let mut shares = Vec::with_capacity(self.limit);
        for i in 0..self.limit {
            let identifier = i + 1;
            let x = S::from_usize(identifier);
            let y = polynomial.evaluate(&x);
            shares.push(Share {
                identifier: identifier as u32,
                value: y.to_bytes().to_vec(),
            });
        }
        Ok((shares, polynomial))
    }

    /// Reconstruct a secret from shares created from `split_secret`
    pub fn combine_shares<S: Field, R: Group<S>>(&self, shares: &[Share]) -> SharingResult<R> {
        // Verify minimum shares
        if shares.len() < self.threshold {
            return Err(SharingError::ShareMinThreshold);
        }

        // Verify the secrets are non-empty and identifiers are valid
        let mut dups = BTreeSet::new();
        let mut x_coordinates = Vec::with_capacity(shares.len());
        let mut y_coordinates = Vec::with_capacity(shares.len());

        for share in shares {
            if share.identifier == 0 {
                return Err(SharingError::ShareInvalidIdentifier);
            }
            if dups.contains(&share.identifier) {
                return Err(SharingError::ShareDuplicateIdentifier);
            }

            let y = R::from_bytes(&share.value)?;
            if !y.is_valid() {
                return Err(SharingError::ShareInvalidValue);
            }
            let x = S::from_usize(share.identifier as usize);
            dups.insert(share.identifier);
            x_coordinates.push(x);
            y_coordinates.push(y);
        }
        let secret = Self::interpolate(x_coordinates.as_slice(), y_coordinates.as_slice());
        Ok(secret)
    }

    /// Calculate lagrange interpolation
    fn interpolate<S: Field, R: Group<S>>(x_coordinates: &[S], y_coordinates: &[R]) -> R {
        debug_assert_eq!(x_coordinates.len(), y_coordinates.len());

        let limit = x_coordinates.len();
        // Initialize to zero
        let mut result = R::zero();

        for i in 0..limit {
            let mut basis = S::one();
            for j in 0..limit {
                if i == j {
                    continue;
                }

                // x_m
                let mut x_m = S::zero();
                x_m.add_assign(&x_coordinates[j]);
                // x_m - x_j
                let mut denom = S::zero();
                denom.add_assign(&x_coordinates[j]);
                denom.sub_assign(&x_coordinates[i]);
                // x_m / (x_m - x_j) * ...
                x_m.scalar_div_assign(&denom);
                basis.scalar_mul_assign(&x_m);
            }
            let mut group = R::zero();
            group.add_assign(&y_coordinates[i]);
            group.scalar_mul_assign(&basis);
            result.add_assign(&group);
        }
        result
    }
}
