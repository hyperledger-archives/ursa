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
#![deny(
    missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unconditional_recursion,
    unused_import_braces,
    unused_lifetimes,
    unused_qualifications,
    unused_extern_crates,
    unused_parens,
    while_true
)]
//! Implements Shamir's simple secret sharing scheme.
//! Also provides an implementation of verifiable secret sharing as described by:
//!  Feldman (see <https://www.cs.umd.edu/~gasarch/TOPICS/secretsharing/feldmanVSS.pdf>
//! and Pedersen
//! (see <https://www.cs.cornell.edu/courses/cs754/2001fa/129.PDF>)
//!
//! Feldman and Pedersen are similar in many ways. It's hard to describe when to use
//! one over the other. Indeed both are used in
//! <http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.134.6445&rep=rep1&type=pdf>.
//!
//! Feldman reveals the public value of the verifier whereas Pedersen's hides it.
//!
//! FUTURE: Adept secret sharing as described by Phillip Rogaway
//! (see <https://eprint.iacr.org/2020/800>
//!
//! Future work would be to use reed-solomon
//! codes to check for corrupted shares.

#![cfg_attr(feature = "nightly", feature(doc_cfg))]

pub use generic_array::{self, typenum};

use error::{SharingError, SharingResult};
use generic_array::{ArrayLength, GenericArray};
use rand::prelude::*;
use std::{convert::TryFrom, marker::PhantomData};

/// Represents the finite field methods used by Sharing Schemes
pub trait Field<Exp, Ops = Self> {
    /// The field size in bytes
    type FieldSize: ArrayLength<u8>;
    /// Return the zero element of the field, the additive identity
    fn zero() -> Self;
    /// Return the one element of the field, the multiplicative identity
    fn one() -> Self;
    /// Return the element from the given number
    fn from_usize(value: usize) -> Self;
    /// Return the element from the specified bytes, length's less than `SIZE` should be
    /// supported
    fn from_bytes<B: AsRef<[u8]>>(value: B) -> SharingResult<Self>
    where
        Self: Sized;
    /// Return the element chosen uniformly at random using the user-provided RNG
    fn random(rng: &mut (impl RngCore + CryptoRng)) -> Self;
    /// True iff this element is zero
    fn is_zero(&self) -> bool;
    /// True iff this element is not zero and less than the modulus
    fn is_valid(&self) -> bool;
    /// Field negation
    fn negate(&mut self);
    /// Add another element to this element
    fn add_assign(&mut self, rhs: &Ops);
    /// Subtract another element from this element
    fn sub_assign(&mut self, rhs: &Ops);
    /// Multiply another element with this element
    fn mul_assign(&mut self, rhs: &Exp);
    /// Multiply the inverse of another element with this element
    fn div_assign(&mut self, rhs: &Exp);
    /// Serialize this element to bytes
    fn to_bytes(&self) -> GenericArray<u8, Self::FieldSize>;
}

/// The polynomial used for generating the shares
#[derive(Debug)]
pub(crate) struct Polynomial<S: Field<S>> {
    pub(crate) coefficients: Vec<S>,
}

impl<S: Field<S>> Polynomial<S> {
    /// Construct a random polynomial of the specified degree using a specified intercept
    pub fn new(rng: &mut (impl RngCore + CryptoRng), intercept: &S, degree: usize) -> Self {
        let mut coefficients = Vec::with_capacity(degree);

        // Ensure intercept is set
        let mut i = S::zero();
        i.add_assign(intercept);
        coefficients.push(i);

        // Assign random coefficients to polynomial
        // Start at 1 since 0 is the intercept and not chosen at random
        for _ in 1..degree {
            coefficients.push(S::random(rng));
        }
        Self { coefficients }
    }

    /// Compute the value of the polynomial for the given `x`
    pub fn evaluate(&self, x: &S) -> S {
        // Compute the polynomial value using Horner's Method
        let degree = self.coefficients.len() - 1;
        // b_n = a_n
        let mut out = S::zero();
        out.add_assign(&self.coefficients[degree]);

        for i in (0..degree).rev() {
            // b_{n-1} = a_{n-1} + b_n*x
            out.mul_assign(x);
            out.add_assign(&self.coefficients[i]);
        }
        out
    }
}

/// A share verifier is used to provide integrity checking of shamir shares
#[derive(Debug)]
pub struct ShareVerifier<S: Field<S>, R: Field<S>> {
    pub(crate) value: R,
    pub(crate) phantom: PhantomData<S>,
}

impl<S: Field<S>, R: Field<S>> ShareVerifier<S, R> {
    /// Output the share value and the identifier.
    /// The identifier is the first 4 bytes
    pub fn to_bytes(&self) -> GenericArray<u8, R::FieldSize> {
        self.value.to_bytes()
    }
}

impl<S: Field<S>, R: Field<S>> TryFrom<&[u8]> for ShareVerifier<S, R> {
    type Error = SharingError;

    fn try_from(value: &[u8]) -> SharingResult<Self> {
        Ok(Self {
            value: R::from_bytes(value)?,
            phantom: PhantomData,
        })
    }
}

impl<S: Field<S>, R: Field<S>> Clone for ShareVerifier<S, R> {
    fn clone(&self) -> Self {
        Self {
            value: R::from_bytes(&self.value.to_bytes()).unwrap(),
            phantom: PhantomData,
        }
    }
}

/// Sharing Errors and Results
pub mod error;
/// Feldman's verifiable secret sharing scheme
pub mod feldman;
/// Pedersen's verifiable secret sharing scheme
pub mod pedersen;
/// Shamir secret sharing scheme
pub mod shamir;

/// Provide a suite of tests for implementers to run for their implementations
#[cfg(feature = "impl_tests")]
pub mod tests;
