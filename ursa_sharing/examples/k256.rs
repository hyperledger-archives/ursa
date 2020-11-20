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
use ff::Field as FFField;
use generic_array::{typenum::U32, GenericArray};
use k256::{
    elliptic_curve::{
        sec1::{FromEncodedPoint, ToEncodedPoint},
        Group as ECCGroup,
    },
    EncodedPoint, FieldBytes, ProjectivePoint, Scalar,
};
use rand::{CryptoRng, RngCore};
use ursa_sharing::{error::*, tests::*, Field, Group};

struct K256Scalar(Scalar);

impl Field for K256Scalar {
    fn one() -> Self {
        Self(Scalar::one())
    }

    fn from_usize(value: usize) -> Self {
        Self(Scalar::from(value as u64))
    }

    fn scalar_div_assign(&mut self, rhs: &Self) {
        self.0 *= rhs.0.invert().unwrap()
    }
}

impl Group for K256Scalar {
    type Size = U32;

    fn zero() -> Self {
        Self(Scalar::zero())
    }

    fn from_bytes<B: AsRef<[u8]>>(value: B) -> SharingResult<Self> {
        let value = value.as_ref();
        if value.len() <= 32 {
            let mut s = [0u8; 32];
            s[..value.len()].copy_from_slice(value);
            Ok(Self(Scalar::from_bytes_reduced(FieldBytes::from_slice(&s))))
        } else {
            Err(SharingError::ShareInvalidSecret)
        }
    }

    fn random(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        Self(Scalar::random(rng))
    }

    fn is_zero(&self) -> bool {
        self.0.is_zero().unwrap_u8() == 1
    }

    fn is_valid(&self) -> bool {
        self.0.is_zero().unwrap_u8() == 0
    }

    fn negate(&mut self) {
        self.0 = self.0.negate()
    }

    fn add_assign(&mut self, rhs: &Self) {
        self.0 += rhs.0
    }

    fn sub_assign(&mut self, rhs: &Self) {
        self.0 -= rhs.0
    }

    fn scalar_mul_assign(&mut self, rhs: &Self) {
        self.0 *= rhs.0
    }

    fn to_bytes(&self) -> GenericArray<u8, Self::Size> {
        let mut c = [0u8; 32];
        c.copy_from_slice(self.0.to_bytes().as_slice());
        c.into()
    }
}

struct K256Point(ProjectivePoint);

impl Group<K256Scalar> for K256Point {
    type Size = U32;

    fn zero() -> Self {
        Self(ProjectivePoint::identity())
    }

    fn from_bytes<B: AsRef<[u8]>>(value: B) -> SharingResult<Self> {
        match EncodedPoint::from_bytes(value.as_ref()) {
            Ok(ept) => {
                let ppt = ProjectivePoint::from_encoded_point(&ept);
                if ppt.is_some().unwrap_u8() == 1 {
                    Ok(Self(ppt.unwrap()))
                } else {
                    Err(SharingError::InvalidPoint)
                }
            }
            Err(_) => Err(SharingError::InvalidPoint),
        }
    }

    fn random(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        Self(ProjectivePoint::random(rng))
    }

    fn is_zero(&self) -> bool {
        self.0.is_identity().unwrap_u8() == 1
    }

    fn is_valid(&self) -> bool {
        self.0.is_identity().unwrap_u8() == 0
    }

    fn negate(&mut self) {
        self.0 = -self.0
    }

    fn add_assign(&mut self, rhs: &Self) {
        self.0 += rhs.0;
    }

    fn sub_assign(&mut self, rhs: &Self) {
        self.0 -= rhs.0;
    }

    fn scalar_mul_assign(&mut self, rhs: &K256Scalar) {
        self.0 *= rhs.0;
    }

    fn to_bytes(&self) -> GenericArray<u8, Self::Size> {
        let mut c = [0u8; 32];
        c.copy_from_slice(
            self.0
                .to_affine()
                .to_encoded_point(true)
                .to_bytes()
                .as_ref(),
        );
        c.into()
    }
}

fn main() {
    println!("Splitting");
    split_invalid_args::<K256Scalar>();
    println!("Combine invalid fail");
    combine_invalid::<K256Scalar>();
    println!("Combine single success");
    combine_single::<K256Scalar, K256Point>();
    println!("Combine combinations success");
    combine_all_combinations::<K256Scalar, K256Point>();
}
