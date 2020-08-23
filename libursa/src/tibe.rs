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



// Run the group generator GG(Λ) to obtain a bilinear group G of
// prime order p > n. Select random generators g, g2, h1 in G, and a random
// degree k − 1 polynomial f ∈ Zp[X]. Set α = f(0) ∈ Zp and g1 = g^α.
// The system parameters PK consist of PK = (G, g, g1, g2, h1). For i = 1, . . . , n
// the master key share (i, SKi) of server i is defined as SKi = g2^f(i)
// The public verification key VK consists of the n-tuple (gf(1), . . . , gf(n)).
pub fn setup(n: i32, k: i32, a: i32) -> (PublicKey, VerificationKey, Vec::<ShareKey>) {
    p1 = PointG1::new().unwrap();
    p2 = PointG2::new().unwrap();
    pair = Pair::pair(&p1, &q1).unwrap();
}


pub fn shareKeyGen(pk: PublicKey, i: i32, ski: ShareKey, id: ID) -> PrivateKeyShare {}

pub fn shareVerify(pk: PublicKey, vk: VerificationKey, id: ID, ti: PrivateKeyShare) -> bool {}

pub fn combine(pk: PublicKey, vk: String, id: ID, si: &[i32]) -> PrivateKey {}

pub fn encrypt(pk: PublicKey, id: ID, m: String) -> String {}

pub fn decrypt(pk: PublicKey, id: ID, d: String, c: String) -> String {}

pub fn validateCt(pk: PublicKey, id: i32, c: String) -> bool {}



