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
    Field, Group, ShareVerifier,
};
use generic_array::typenum::Unsigned;
use rand::{CryptoRng, RngCore};
use std::{convert::TryFrom, marker::PhantomData};

/// Implements Pedersen's Verifiable secret sharing scheme.
/// (see <https://www.cs.cornell.edu/courses/cs754/2001fa/129.PDF>)
#[derive(Copy, Clone, Debug)]
pub struct Scheme {
    threshold: usize,
    limit: usize,
}

impl Scheme {
    /// Create a new Pedersen verifiable secret sharing scheme
    pub fn new(threshold: usize, limit: usize) -> SharingResult<Self> {
        if limit < threshold {
            return Err(SharingError::ShareLimitLessThanThreshold);
        }
        if threshold < 2 {
            return Err(SharingError::ShareMinThreshold);
        }
        Ok(Self { threshold, limit })
    }

    /// Create shares from a secret
    /// Caller can optionally supply random generators for use
    /// when computing share verifiers.
    /// If [`None`] is passed as the parameter then `R::random()` is used for `g` and `R::random()` for `h`.
    /// A random blinding factor is generated and split as well
    pub fn split_secret<S: Field, R: Group<S>>(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        secret: &S,
        g: Option<R>,
        h: Option<R>,
    ) -> SharingResult<PedersenVssResult<S, R>> {
        let g = g.unwrap_or_else(|| R::random(rng));
        let h = h.unwrap_or_else(|| R::random(rng));
        let blinding = S::random(rng);

        let shamir = ShamirScheme::new(self.threshold, self.limit)?;
        let (secret_shares, secret_polynomial) = shamir.get_shares_and_polynomial(rng, secret)?;
        let (blinding_shares, blinding_polynomial) =
            shamir.get_shares_and_polynomial(rng, &blinding)?;

        let mut commitments = Vec::with_capacity(self.limit);
        // {(g^p0 h^r0), (g^p1, h^r1), ..., (g^pn, h^rn)}
        for i in 0..self.threshold {
            let mut g_i = R::zero();
            g_i.add_assign(&g);
            g_i.scalar_mul_assign(&secret_polynomial.coefficients[i]);

            let mut h_i = R::zero();
            h_i.add_assign(&h);
            h_i.scalar_mul_assign(&blinding_polynomial.coefficients[i]);

            g_i.add_assign(&h_i);

            commitments.push(ShareVerifier {
                value: g_i,
                phantom: PhantomData,
            });
        }

        Ok(PedersenVssResult {
            blinding,
            blinding_shares,
            secret_shares,
            verifier: PedersenVerifier { g, h, commitments },
        })
    }

    /// Checks if the share is valid according to verifier
    pub fn verify_share<S: Field, R: Group<S>>(
        &self,
        share: &ShamirShare,
        blind_share: &ShamirShare,
        verifier: &PedersenVerifier<S, R>,
    ) -> SharingResult<()> {
        let s = S::from_bytes(&share.value)?;
        if !s.is_valid() {
            return Err(SharingError::ShareInvalidValue);
        }
        let t = S::from_bytes(&blind_share.value)?;
        if !t.is_valid() {
            return Err(SharingError::PedersenBlindShareInvalid);
        }

        let x = S::from_usize(share.identifier as usize);
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
            i.scalar_mul_assign(&x);
            // c_0 * c_1^i * c_2^{i^2} ... c_t^{i^t}
            let mut c = R::zero();
            c.add_assign(&v.value);
            c.scalar_mul_assign(&i);
            rhs.add_assign(&c);
        }

        let mut g = R::zero();
        g.add_assign(&verifier.g);
        g.negate();
        g.scalar_mul_assign(&s);
        rhs.add_assign(&g);

        let mut h = R::zero();
        h.add_assign(&verifier.h);
        h.negate();
        h.scalar_mul_assign(&t);
        rhs.add_assign(&h);

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
    pub fn combine_shares<S: Field, R: Group<S>>(
        &self,
        shares: &[ShamirShare],
    ) -> SharingResult<R> {
        ShamirScheme::new(self.threshold, self.limit)?.combine_shares::<S, R>(shares)
    }
}

/// A Pedersen verifier is used to provide integrity checking of shamir shares
#[derive(Debug, Clone)]
pub struct PedersenVerifier<S: Field, R: Group<S>> {
    /// The generator for the share scalar
    pub g: R,
    /// The generator for the blinding factor
    pub h: R,
    /// The blinded commitments the polynomials
    pub commitments: Vec<ShareVerifier<S, R>>,
}

impl<S: Field, R: Group<S>> PedersenVerifier<S, R> {
    /// Convert this verifier to a byte array
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut o = self.g.to_bytes().to_vec();
        o.append(&mut self.h.to_bytes().to_vec());
        o.extend_from_slice((self.commitments.len() as u32).to_be_bytes().as_ref());
        for c in &self.commitments {
            o.append(&mut c.to_bytes().to_vec());
        }
        o
    }
}

impl<S: Field, R: Group<S>> TryFrom<&[u8]> for PedersenVerifier<S, R> {
    type Error = SharingError;

    fn try_from(value: &[u8]) -> SharingResult<Self> {
        if value.len() < R::Size::to_usize() * 2 + 4 {
            return Err(SharingError::PedersenVerifierMinSize(
                R::Size::to_usize() * 2 + 4,
                value.len(),
            ));
        }
        let mut offset = 0;
        let mut end = R::Size::to_usize();
        let g = R::from_bytes(&value[offset..end])?;

        offset = end;
        end += R::Size::to_usize();

        let h = R::from_bytes(&value[offset..end])?;

        offset = end;
        end += 4;

        let mut c_size = [0u8; 4];
        c_size.copy_from_slice(&value[offset..end]);
        let cs = u32::from_be_bytes(c_size) as usize;
        let mut commitments = Vec::with_capacity(cs);
        offset = end;
        end += R::Size::to_usize();
        for _ in 0..cs {
            let c = R::from_bytes(&value[offset..end])?;
            commitments.push(ShareVerifier {
                value: c,
                phantom: PhantomData,
            });
        }
        Ok(Self { g, h, commitments })
    }
}

/// A Pedersen result returned when calling `split_secret`
#[derive(Debug, Clone)]
pub struct PedersenVssResult<S: Field, R: Group<S>> {
    /// The blinding factor randomly generated
    pub blinding: S,
    /// The blinding factor shares
    pub blinding_shares: Vec<ShamirShare>,
    /// The secret shares
    pub secret_shares: Vec<ShamirShare>,
    /// The verifier used to check shares
    pub verifier: PedersenVerifier<S, R>,
}
