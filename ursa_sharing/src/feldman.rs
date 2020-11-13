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
    shamir::{Scheme as ShamirScheme, Share as ShamirShare},
    Field, ShareVerifier,
};
use rand::prelude::*;
use std::marker::PhantomData;

/// Feldman's Verifiable secret sharing scheme.
/// (see <https://www.cs.umd.edu/~gasarch/TOPICS/secretsharing/feldmanVSS.pdf>
#[derive(Copy, Clone, Debug)]
pub struct Scheme {
    threshold: usize,
    limit: usize,
}

impl Scheme {
    /// Create a new Feldman verifiable secret sharing scheme
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
    /// Caller can optionally supply a random generator for use
    /// when computing share verifiers.
    /// If [`None`] is passed as the parameter then the `R::random()` is used.
    pub fn split_secret<S: Field<S>, R: Field<S>>(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        secret: &S,
        g: Option<R>,
    ) -> SharingResult<(FeldmanVerifier<S, R>, Vec<ShamirShare>)> {
        let (shares, polynomial) = ShamirScheme::new(self.threshold, self.limit)?
            .get_shares_and_polynomial(rng, secret)?;

        let g = g.unwrap_or_else(|| R::random(rng));

        // Generate the verifiable commitments to the polynomial for the shares
        // Each share is multiple of the polynomial and the specified generator point.
        // {g^p0, g^p1, g^p2, ..., g^pn}
        let mut vs = Vec::with_capacity(self.limit);
        for c in &polynomial.coefficients {
            let mut v = R::zero();
            v.add_assign(&g);
            v.mul_assign(c);
            vs.push(ShareVerifier {
                value: v,
                phantom: PhantomData,
            });
        }

        Ok((FeldmanVerifier { g, commitments: vs }, shares))
    }

    /// Checks if the share is valid according to verifier set
    pub fn verify_share<S: Field<S>, R: Field<S>>(
        &self,
        share: &ShamirShare,
        verifier: &FeldmanVerifier<S, R>,
    ) -> SharingResult<()> {
        if verifier.commitments.len() < self.threshold {
            return Err(SharingError::ShareMinThreshold);
        }
        let s = S::from_bytes(&share.value)?;
        if !s.is_valid() {
            return Err(SharingError::ShareInvalidValue);
        }

        let x = S::from_usize(share.identifier);
        let mut i = S::one();

        // FUTURE: execute this sum of products
        // c_0 * c_1^i * c_2^{i^2} ... c_t^{i^t}
        // as a constant time operation using <https://cr.yp.to/papers/pippenger.pdf>
        // or Guide to Elliptic Curve Cryptography book,
        // "Algorithm 3.48 Simultaneous multiple point multiplication"
        // without precomputing the addition but still reduces doublings

        // c_0
        let mut rhs = R::zero();
        rhs.add_assign(&verifier.commitments[0].value);
        for v in &verifier.commitments[1..] {
            // i *= x
            i.mul_assign(&x);

            // c_0 * c_1^i * c_2^{i^2} ... c_t^{i^t}
            let mut c = R::zero();
            c.add_assign(&v.value);
            c.mul_assign(&i);
            rhs.add_assign(&c);
        }
        let mut lhs = R::zero();
        lhs.add_assign(&verifier.g);
        lhs.negate();
        lhs.mul_assign(&s);
        rhs.add_assign(&lhs);

        if rhs.is_zero() {
            Ok(())
        } else {
            Err(SharingError::ShareInvalidValue)
        }
    }

    /// Reconstruct a secret from shares created from `split_secret`.
    /// The shares should be verified first by calling `verify_share`.
    /// This method assumes all the shares have been verified.
    /// Usually `verify_share` is called when the share is received.
    pub fn combine_shares<S: Field<S>, R: Field<S>>(
        &self,
        shares: &[ShamirShare],
    ) -> SharingResult<R> {
        ShamirScheme::new(self.threshold, self.limit)?.combine_shares::<S, R>(shares)
    }
}

/// A Feldman verifier is used to provide integrity checking of shamir shares
#[derive(Debug, Clone)]
pub struct FeldmanVerifier<S: Field<S>, R: Field<S>> {
    /// The generator for the share scalar
    pub g: R,
    /// The blinded commitments the polynomials
    pub commitments: Vec<ShareVerifier<S, R>>,
}
