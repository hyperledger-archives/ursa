
#[macro_use]
extern crate criterion;
use criterion::Criterion;

extern crate ursa;
use ursa::encoding::hex::{bin2hex, hex2bin};
use ursa::signatures::{Signer, SignatureScheme};
use ursa::keys::{PrivateKey, PublicKey, KeyGenOption};
use ursa::signatures::ed25519::{Ed25519Sha512};

const MESSAGE_1: &[u8] = b"This is a dummy message for use with tests";
const SIGNATURE_1: &str = "451b5b8e8725321541954997781de51f4142e4a56bab68d24f6a6b92615de5eefb74134138315859a32c7cf5fe5a488bc545e2e08e5eedfd1fb10188d532d808";
const PRIVATE_KEY: &str = "1c1179a560d092b90458fe6ab8291215a427fcd6b3927cb240701778ef55201927c96646f2d4632d4fc241f84cbc427fbc3ecaa95becba55088d6c7b81fc5bbf";
const PUBLIC_KEY: &str = "27c96646f2d4632d4fc241f84cbc427fbc3ecaa95becba55088d6c7b81fc5bbf";

fn create_new_keys() {
    let scheme = Ed25519Sha512::new();
    let (p, s) = scheme.keypair(None).unwrap();
}

fn create_new_keys_benchmark(c: &mut Criterion) {
    c.bench_function("ed25519 key creation", |b| b.iter(|| create_new_keys()));
}

fn ed25519_load_keys() {
    let scheme = Ed25519Sha512::new();
    let secret = PrivateKey(hex2bin(PRIVATE_KEY).unwrap());
    let sres = scheme.keypair(Some(KeyGenOption::FromSecretKey(secret)));
    let (p1, s1) = sres.unwrap();
}

fn ed25519_load_keys_benchmark(c: &mut Criterion) {
    c.bench_function("ed25519 key loading", |b| b.iter(|| ed25519_load_keys()));
}

fn ed25519_verify() {
    let scheme = Ed25519Sha512::new();
    let secret = PrivateKey(hex2bin(PRIVATE_KEY).unwrap());
    let (p, _) = scheme.keypair(Some(KeyGenOption::FromSecretKey(secret))).unwrap();

    let result = scheme.verify(&MESSAGE_1, hex2bin(SIGNATURE_1).unwrap().as_slice(), &p);
}

fn ed25519_verify_benchmark(c: &mut Criterion) {
    c.bench_function("ed25519 verification", |b| b.iter(|| ed25519_verify()));
}

fn ed25519_sign() {
    let scheme = Ed25519Sha512::new();
    let secret = PrivateKey(hex2bin(PRIVATE_KEY).unwrap());
    let (p, s) = scheme.keypair(Some(KeyGenOption::FromSecretKey(secret))).unwrap();

    let signer = Signer::new(&scheme, &s);
    match signer.sign(&MESSAGE_1) {
        Ok(signed) => {
            let result = scheme.verify(&MESSAGE_1, &signed, &p);
        },
        Err(er) => panic!("Encountered error during signing.")
    }
}

fn ed25519_sign_benchmark(c: &mut Criterion) {
    c.bench_function("ed25519 signing", |b| b.iter(|| ed25519_sign()));
}

criterion_group!{
    name = benches;
    config = Criterion::default();
    targets = create_new_keys_benchmark, ed25519_load_keys_benchmark,
        ed25519_verify_benchmark, ed25519_sign_benchmark
}
criterion_main!(benches);