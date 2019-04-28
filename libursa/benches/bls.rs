
use criterion::Criterion;

use ursa::bls::*;
use ursa::encoding::hex::hex2bin;

// values with the same number were derived from each other
const GEN_1: &str = "2242fba831f2c048e74d317c39317b1538eacba98f53910faecdbed2bbf2f463049b94926c3f1cd846b61fcb5f5b1c80fbb0556d7c3e7bea99169f1ea63e8eb320bfdd298f44e6981739333fc2660400b9fbf7d9c5f9998700d3f58edba6fa18119ef00908ca091b0a02eb54504c8d4fdc272fb05654a934625fb7557cb4868d";
const SIGN_KEY_1: &str = "04ff96831fec2e6a912b48c59f17fd633598d76a632e36c31dea282d837b833a";
const VER_KEY_1: &str = "10d1a1c35aaf11a574b4abf8061399a0423485ba59e1f928bb1a4d01d378b6e623a411fa32c59123b64e33043bd1768b4cce5c1ed27854d2febcd3deb88a7ce90846f38188c964a76520625c70a74a644faeec225a4fb0ee7549cf733cb8afd2174ccf6aaddf9d09dc88dbd1568b601faee475d6b680bffe4f4be2cf0e10c461";
const SIG_1: &str = "0421046189f5d4d9791d08a229dd1082915266a8deb96f2bffd822649a16dbf663231385de753a410998764bc5d755cd1cbee7e108fce525da882809acae2c6a75000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
const POP_1: &str = "04029c0cab11d033f68455e938be2a7841ec7e52b4526f88c8eee6a1fb2a16f00e1d4ddfdc12c0c84003f5075bb3c17b177bffb144a8b8f5568839bfd440e18b22000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

const SIGN_KEY_2: &str = "0cfd3dea7b8461164161dd80072980a944a7cc336d954a64a507fd71fba561ce";
const SIG_2: &str = "041c31a36f9be130f19ee861850ef0977f539977e6a15b0b32741b1de8cad1158a1831fcdf96271d71ce3cd4f11785be919dc509e79d9c6efab2553eaf8f39c932000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

const MSG: &str = "6361726e69766f7269736d2063617573657320636f6c6f6e2063616e636572";
const SEED: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 2, 3, 4, 5, 6, 7, 8, 9, 10, 21, 2, 3, 4, 5, 6, 7, 8, 9, 10, 31, 32];
    
fn create_generator() {
    Generator::new().unwrap();
}

pub fn create_generator_benchmark(c: &mut Criterion) {
    c.bench_function("bls generator creation", |b| b.iter(|| create_generator()));
}

fn create_sign_key_none() {
    SignKey::new(None).unwrap();
}

pub fn create_sign_key_none_benchmark(c: &mut Criterion) {
    c.bench_function("bls SignKey creation from None", |b| b.iter(|| create_sign_key_none()));
}

fn create_sign_key_seed() {
    SignKey::new(Some(SEED)).unwrap();
}

pub fn create_sign_key_seed_benchmark(c: &mut Criterion) {
    c.bench_function("bls SignKey creation from seed", |b| b.iter(|| create_sign_key_seed()));
}

fn create_ver_key() {
    let gen = Generator::from_bytes(&hex2bin(GEN_1).unwrap()).unwrap();
    let sign_key = SignKey::from_bytes(&hex2bin(SIGN_KEY_1).unwrap()).unwrap();
    VerKey::new(&gen, &sign_key).unwrap();
}

pub fn create_ver_key_benchmark(c: &mut Criterion) {
    c.bench_function("bls VerKey creation", |b| b.iter(|| create_ver_key()));
}

fn create_pop() {
    let sign_key = SignKey::from_bytes(&hex2bin(SIGN_KEY_1).unwrap()).unwrap();
    let ver_key = VerKey::from_bytes(&hex2bin(VER_KEY_1).unwrap()).unwrap();
    ProofOfPossession::new(&ver_key, &sign_key).unwrap();
}

pub fn create_pop_benchmark(c: &mut Criterion) {
    c.bench_function("bls ProofOfPossession creation", |b| b.iter(|| create_pop()));
}

fn sign() {
    let sign_key = SignKey::from_bytes(&hex2bin(SIGN_KEY_2).unwrap()).unwrap();
    Bls::sign(&hex2bin(MSG).unwrap(), &sign_key).unwrap();
}

pub fn sign_benchmark(c: &mut Criterion) {
    c.bench_function("bls sign", |b| b.iter(|| sign()));
}

fn create_multi_sig() {

    let signature1 = Signature::from_bytes(&hex2bin(SIG_1).unwrap()).unwrap();
    let signature2 = Signature::from_bytes(&hex2bin(SIG_2).unwrap()).unwrap();

    let signatures = vec![
        &signature1,
        &signature2
    ];

    MultiSignature::new(&signatures).unwrap();
}

pub fn create_multi_sig_benchmark(c: &mut Criterion) {
    c.bench_function("bls multi sign", |b| b.iter(|| create_multi_sig()));
}

fn verify() {
    let valid = Bls::verify(
        &Signature::from_bytes(&hex2bin(SIG_1).unwrap()).unwrap(),
        &hex2bin(MSG).unwrap(),
        &VerKey::from_bytes(&hex2bin(VER_KEY_1).unwrap()).unwrap(),
        &Generator::from_bytes(&hex2bin(GEN_1).unwrap()).unwrap()
    ).unwrap();
    assert!(valid)
}

pub fn verify_benchmark(c: &mut Criterion) {
    c.bench_function("bls verify signature", |b| b.iter(|| verify()));
}

fn verify_pop() {
    let valid = Bls::verify_proof_of_posession(
        &ProofOfPossession::from_bytes(&hex2bin(POP_1).unwrap()).unwrap(),
        &VerKey::from_bytes(&hex2bin(VER_KEY_1).unwrap()).unwrap(),
        &Generator::from_bytes(&hex2bin(GEN_1).unwrap()).unwrap()
    ).unwrap();
    assert!(valid)
}

pub fn verify_pop_benchmark(c: &mut Criterion) {
    c.bench_function("bls verify ProofOfPossession", |b| b.iter(|| verify_pop()));
}
