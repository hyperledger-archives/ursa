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
use ff_zeroize::{Field as FFField, PrimeField};
use generic_array::{
    typenum::{Unsigned, U32, U48, U96},
    GenericArray,
};
use pairing_plus::{
    bls12_381::{Fr, FrRepr, G1, G2},
    hash_to_curve::HashToCurve,
    hash_to_field::{BaseFromRO, ExpandMsgXmd},
    serdes::SerDes,
    CurveProjective,
};
use rand::{CryptoRng, RngCore};
use ursa_sharing::{error::*, tests::*, Field, Group};

struct FrField(Fr);

impl Field for FrField {
    fn one() -> Self {
        Self(Fr::from_repr(FrRepr::from(1u64)).unwrap())
    }

    fn from_usize(value: usize) -> Self {
        Self(Fr::from_repr(FrRepr::from(value as u64)).unwrap())
    }

    fn scalar_div_assign(&mut self, rhs: &Self) {
        self.0.mul_assign(&rhs.0.inverse().unwrap());
    }
}

impl Group for FrField {
    type Size = U32;

    fn zero() -> Self {
        Self(Fr::default())
    }

    fn from_bytes<B: AsRef<[u8]>>(value: B) -> SharingResult<Self> {
        let value = value.as_ref();
        if value.len() < Self::Size::to_usize() {
            let mut s = [0u8; 48];
            s[..value.len()].copy_from_slice(value);
            return Ok(Self(Fr::from_okm(GenericArray::from_slice(&s))));
        } else if value.len() == Self::Size::to_usize() {
            let mut r = std::io::Cursor::new(value.as_ref());
            match Fr::deserialize(&mut r, true) {
                Ok(f) => Ok(Self(f)),
                Err(_) => Err(SharingError::ShareInvalidSecret),
            }
        } else {
            Err(SharingError::ShareInvalidSecret)
        }
    }

    fn random(rng: &mut impl RngCore) -> Self {
        let mut b = [0u8; 48];
        rng.fill_bytes(&mut b);
        Self(Fr::from_okm(GenericArray::from_slice(&b)))
    }

    fn is_zero(&self) -> bool {
        self.0 == Fr::default()
    }

    fn is_valid(&self) -> bool {
        self.0 != Fr::default()
    }

    fn negate(&mut self) {
        self.0.negate()
    }

    fn add_assign(&mut self, rhs: &Self) {
        self.0.add_assign(&rhs.0);
    }

    fn sub_assign(&mut self, rhs: &Self) {
        self.0.sub_assign(&rhs.0);
    }

    fn scalar_mul_assign(&mut self, rhs: &Self) {
        self.0.mul_assign(&rhs.0);
    }

    fn to_bytes(&self) -> GenericArray<u8, Self::Size> {
        let mut r = [0u8; 32];
        self.0.serialize(&mut r.as_mut(), true).unwrap();
        r.into()
    }
}

struct G1Field(G1);

impl Group<FrField> for G1Field {
    type Size = U48;

    fn zero() -> Self {
        Self(G1::zero())
    }

    fn from_bytes<B: AsRef<[u8]>>(value: B) -> SharingResult<Self> {
        let value = value.as_ref();
        if value.len() != Self::Size::to_usize() {
            return Ok(Self(
                <G1 as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::hash_to_curve(
                    value,
                    "BLS12381G1_XMD:SHA256_SSWU_RO_BLS:1_0_0",
                ),
            ));
        }
        let mut c = std::io::Cursor::new(value);
        match G1::deserialize(&mut c, true) {
            Ok(p) => Ok(Self(p)),
            Err(_) => Err(SharingError::InvalidPoint),
        }
    }

    fn random(rng: &mut impl RngCore) -> Self {
        Self(G1::random(rng))
    }

    fn is_zero(&self) -> bool {
        self.0.is_zero()
    }

    fn is_valid(&self) -> bool {
        !self.0.is_zero()
    }

    fn negate(&mut self) {
        self.0.negate();
    }

    fn add_assign(&mut self, rhs: &Self) {
        self.0.add_assign(&rhs.0);
    }

    fn sub_assign(&mut self, rhs: &Self) {
        self.0.sub_assign(&rhs.0);
    }

    fn scalar_mul_assign(&mut self, rhs: &FrField) {
        self.0.mul_assign(rhs.0);
    }

    fn to_bytes(&self) -> GenericArray<u8, Self::Size> {
        let mut r = [0u8; 48];
        self.0.serialize(&mut r.as_mut(), true).unwrap();
        GenericArray::clone_from_slice(&r)
    }
}

struct G2Field(G2);

impl Group<FrField> for G2Field {
    type Size = U96;

    fn zero() -> Self {
        Self(G2::zero())
    }

    fn from_bytes<B: AsRef<[u8]>>(value: B) -> SharingResult<Self> {
        let value = value.as_ref();
        if value.len() != Self::Size::to_usize() {
            return Ok(Self(
                <G2 as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::hash_to_curve(
                    value,
                    "BLS12381G2_XMD:SHA256_SSWU_RO_BLS:1_0_0",
                ),
            ));
        }
        let mut c = std::io::Cursor::new(value);
        match G2::deserialize(&mut c, true) {
            Ok(p) => Ok(Self(p)),
            Err(_) => Err(SharingError::InvalidPoint),
        }
    }

    fn random(rng: &mut impl RngCore) -> Self {
        Self(G2::random(rng))
    }

    fn is_zero(&self) -> bool {
        self.0.is_zero()
    }

    fn is_valid(&self) -> bool {
        !self.0.is_zero()
    }

    fn negate(&mut self) {
        self.0.negate();
    }

    fn add_assign(&mut self, rhs: &G2Field) {
        self.0.add_assign(&rhs.0);
    }

    fn sub_assign(&mut self, rhs: &G2Field) {
        self.0.sub_assign(&rhs.0);
    }

    fn scalar_mul_assign(&mut self, rhs: &FrField) {
        self.0.mul_assign(rhs.0);
    }

    fn to_bytes(&self) -> GenericArray<u8, Self::Size> {
        let mut r = [0u8; 96];
        self.0.serialize(&mut r.as_mut(), true).unwrap();
        GenericArray::clone_from_slice(&r)
    }
}

fn main() {
    println!("Splitting");
    split_invalid_args::<FrField>();
    println!("Combine invalid fail");
    combine_invalid::<FrField>();
    println!("Combine single G1 success");
    combine_single::<FrField, G1Field>();
    println!("Combine combinations G1 success");
    combine_all_combinations::<FrField, G1Field>();
    println!("Combine single G2 success");
    combine_single::<FrField, G2Field>();
    println!("Combine combinations G2 success");
    combine_all_combinations::<FrField, G2Field>();
}
