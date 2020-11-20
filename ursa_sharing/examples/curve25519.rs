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
use rand::{CryptoRng, RngCore};
use ursa_sharing::{error::*, tests::*, Field, Group};

use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT,
    edwards::CompressedEdwardsY,
    scalar::Scalar,
    traits::{Identity, IsIdentity},
};
use generic_array::{typenum::U32, GenericArray};
use std::ops::Neg;
use subtle::ConstantTimeEq;

struct C25519Scalar(Scalar);

impl Field for C25519Scalar {
    fn one() -> Self {
        Self(Scalar::one())
    }

    fn from_usize(value: usize) -> Self {
        Self(Scalar::from(value as u64))
    }

    fn scalar_div_assign(&mut self, rhs: &Self) {
        self.0 *= rhs.0.invert()
    }
}

impl Group for C25519Scalar {
    type Size = U32;

    fn zero() -> Self {
        Self(Scalar::zero())
    }

    fn from_bytes<B: AsRef<[u8]>>(value: B) -> SharingResult<Self> {
        let value = value.as_ref();
        match value.len() {
            32 => {
                let mut s = [0u8; 32];
                s.copy_from_slice(value);
                Ok(Self(Scalar::from_bits(s)))
            }
            64 => {
                let mut s = [0u8; 64];
                s.copy_from_slice(value);
                Ok(Self(Scalar::from_bytes_mod_order_wide(&s)))
            }
            _ => {
                if value.len() < 32 {
                    let mut s = [0u8; 32];
                    s[..value.len()].copy_from_slice(value);
                    Ok(Self(Scalar::from_bits(s)))
                } else {
                    Err(SharingError::ShareInvalidSecret)
                }
            }
        }
    }

    fn random(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        Self(Scalar::random(rng))
    }

    fn is_zero(&self) -> bool {
        self.0.ct_eq(&Self::zero().0).unwrap_u8() == 1
    }

    fn is_valid(&self) -> bool {
        !self.is_zero()
    }

    fn negate(&mut self) {
        self.0 = self.0.neg();
    }

    fn add_assign(&mut self, rhs: &Self) {
        self.0 += rhs.0;
    }

    fn sub_assign(&mut self, rhs: &Self) {
        self.0 -= rhs.0;
    }

    fn scalar_mul_assign(&mut self, rhs: &C25519Scalar) {
        self.0 *= rhs.0
    }

    fn to_bytes(&self) -> GenericArray<u8, Self::Size> {
        self.0.to_bytes().into()
    }
}

struct C25519Point(CompressedEdwardsY);

impl Group<C25519Scalar> for C25519Point {
    type Size = U32;

    fn zero() -> Self {
        Self(CompressedEdwardsY::identity())
    }

    fn from_bytes<B: AsRef<[u8]>>(value: B) -> SharingResult<Self> {
        let value = value.as_ref();
        Ok(Self(CompressedEdwardsY::from_slice(value)))
    }

    fn random(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        Self((ED25519_BASEPOINT_POINT * Scalar::random(rng)).compress())
    }

    fn is_zero(&self) -> bool {
        self.0.is_identity()
    }

    fn is_valid(&self) -> bool {
        !self.0.is_identity()
    }

    fn negate(&mut self) {
        self.0 = self.0.decompress().unwrap().neg().compress()
    }

    fn add_assign(&mut self, rhs: &C25519Point) {
        self.0 = (self.0.decompress().unwrap() + rhs.0.decompress().unwrap()).compress()
    }

    fn sub_assign(&mut self, rhs: &C25519Point) {
        self.0 = (self.0.decompress().unwrap() - rhs.0.decompress().unwrap()).compress()
    }

    fn scalar_mul_assign(&mut self, rhs: &C25519Scalar) {
        self.0 = (self.0.decompress().unwrap() * rhs.0).compress()
    }

    fn to_bytes(&self) -> GenericArray<u8, Self::Size> {
        self.0.to_bytes().into()
    }
}

fn main() {
    println!("Splitting");
    split_invalid_args::<C25519Scalar>();
    println!("Combine invalid fail");
    combine_invalid::<C25519Scalar>();
    println!("Combine single success");
    combine_single::<C25519Scalar, C25519Point>();
    println!("Combine combinations success");
    combine_all_combinations::<C25519Scalar, C25519Point>();
}
