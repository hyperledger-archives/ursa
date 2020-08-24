use keys::{PrivateKey, PublicKey};
use pair::{Pair, PointG1, PointG2};

pub struct ID(pub Vec<u8>);
impl_bytearray!(ID);

pub struct VerificationKey(pub Vec<u8>);
impl_bytearray!(VerificationKey);

pub struct ShareKey(pub Vec<u8>);
impl_bytearray!(ShareKey);

pub struct PrivateKeyShare(pub Vec<u8>);
impl_bytearray!(PrivateKeyShare);




pub fn setup(n: i32, k: i32, a: i32) -> (PublicKey, VerificationKey, Vec::<ShareKey>) {
    g1 = PointG1::new().unwrap();
    g2 = PointG2::new().unwrap();
    h = PointG2::new().unwrap();
}


pub fn shareKeyGen(pk: PublicKey, i: i32, ski: ShareKey, id: ID) -> PrivateKeyShare {}

pub fn shareVerify(pk: PublicKey, vk: VerificationKey, id: ID, ti: PrivateKeyShare) -> bool {}

pub fn combine(pk: PublicKey, vk: String, id: ID, si: &[i32]) -> PrivateKey {}

pub fn encrypt(pk: PublicKey, id: ID, m: String) -> String {}

pub fn decrypt(pk: PublicKey, id: ID, d: String, c: String) -> String {}

pub fn validateCt(pk: PublicKey, id: i32, c: String) -> bool {}



