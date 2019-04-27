
pub mod ed25519 {

    use criterion::Criterion;

    use ursa::encoding::hex::{hex2bin};
    use ursa::signatures::{SignatureScheme};
    use ursa::keys::{PublicKey, PrivateKey, KeyGenOption};
    use ursa::signatures::ed25519::Ed25519Sha512;

    const MESSAGE_1: &[u8] = b"This is a dummy message for use with tests";
    const SIGNATURE_1: &str = "451b5b8e8725321541954997781de51f4142e4a56bab68d24f6a6b92615de5eefb74134138315859a32c7cf5fe5a488bc545e2e08e5eedfd1fb10188d532d808";
    const PRIVATE_KEY: &str = "1c1179a560d092b90458fe6ab8291215a427fcd6b3927cb240701778ef55201927c96646f2d4632d4fc241f84cbc427fbc3ecaa95becba55088d6c7b81fc5bbf";
    const PUBLIC_KEY: &str = "27c96646f2d4632d4fc241f84cbc427fbc3ecaa95becba55088d6c7b81fc5bbf";

    fn create_keys() {
        let scheme = Ed25519Sha512::new();
        let result = scheme.keypair(None);
        assert!(result.is_ok());
    } 

    pub fn create_keys_benchmark(c: &mut Criterion) {
        c.bench_function("ed25519 key creation", |b| b.iter(|| create_keys()));
    }

    fn load_keys() {
        let scheme = Ed25519Sha512::new();
        let secret = PrivateKey(hex2bin(PRIVATE_KEY).unwrap());
        let result = scheme.keypair(Some(KeyGenOption::FromSecretKey(secret)));
        assert!(result.is_ok());
    }

    pub fn load_keys_benchmark(c: &mut Criterion) {
        c.bench_function("ed25519 key loading", |b| b.iter(|| load_keys()));
    }

    fn sign() {
        let scheme = Ed25519Sha512::new();
        let s = PrivateKey(hex2bin(PRIVATE_KEY).unwrap());
        let result = scheme.sign(MESSAGE_1, &s);
        assert!(result.is_ok());
    }

    pub fn sign_benchmark(c: &mut Criterion) {
        c.bench_function("ed25519 signing", |b| b.iter(|| sign()));
    }

    fn verify() {
        let scheme = Ed25519Sha512::new();
        let p = PublicKey(hex2bin(PUBLIC_KEY).unwrap());
        let result = scheme.verify(&MESSAGE_1, hex2bin(SIGNATURE_1).unwrap().as_slice(), &p);
        assert!(result.is_ok());
    }

    pub fn verify_benchmark(c: &mut Criterion) {
        c.bench_function("ed25519 verification", |b| b.iter(|| verify()));
    }
}

pub mod secp256k1 {

    use criterion::Criterion;

    use ursa::encoding::hex;
    use ursa::keys::{PrivateKey, PublicKey, KeyGenOption};
    use ursa::signatures::*;
    use ursa::signatures::secp256k1::EcdsaSecp256k1Sha256;
    use libsecp256k1;
    use ursa::sha2::Digest;
    use openssl::ecdsa::EcdsaSig;
    use openssl::ec::{EcGroup, EcPoint, EcKey};
    use openssl::nid::Nid;
    use openssl::bn::{BigNum, BigNumContext};

    const MESSAGE_1: &[u8] = b"This is a dummy message for use with tests";
    const SIGNATURE_1: &str = "ae46d3fec8e2eb95ebeaf95f7f096ec4bf517f5ef898e4379651f8af8e209ed75f3c47156445d6687a5f817fb3e188e2a76df653b330df859ec47579c8c409be";
    const PRIVATE_KEY: &str = "e4f21b38e005d4f895a29e84948d7cc83eac79041aeb644ee4fab8d9da42f713";
    const PUBLIC_KEY: &str = "0242c1e1f775237a26da4fd51b8d75ee2709711f6e90303e511169a324ef0789c0";

    fn create_keys() {
        let scheme = EcdsaSecp256k1Sha256::new();
        let result = scheme.keypair(None);
        assert!(result.is_ok());
    }

    pub fn create_keys_benchmark(c: &mut Criterion) {
        c.bench_function("secp256k1 key creation", |b| b.iter(|| create_keys()));
    }

    fn load_keys() {
        let scheme = EcdsaSecp256k1Sha256::new();
        let secret = PrivateKey(hex::hex2bin(PRIVATE_KEY).unwrap());
        let result = scheme.keypair(Some(KeyGenOption::FromSecretKey(secret)));
        assert!(result.is_ok());
    }

    pub fn load_keys_benchmark(c: &mut Criterion) {
        c.bench_function("secp256k1 key loading", |b| b.iter(|| load_keys()));
    }

    fn sign() {
        let scheme = EcdsaSecp256k1Sha256::new();
        let s = PrivateKey(hex::hex2bin(PRIVATE_KEY).unwrap());
        let result = scheme.sign(MESSAGE_1, &s);
        assert!(result.is_ok());
    }

    pub fn sign_benchmark(c: &mut Criterion) {
        c.bench_function("secp256k1 signing", |b| b.iter(|| sign()));
    }

    fn sign_libsecp256k1() {
        let context = libsecp256k1::Secp256k1::new();
        let sk = libsecp256k1::key::SecretKey::from_slice(
            hex::hex2bin(PRIVATE_KEY).unwrap().as_slice()
        ).unwrap();

        let h = sha2::Sha256::digest(&MESSAGE_1);

        let msg = libsecp256k1::Message::from_slice(h.as_slice()).unwrap();
        let _sig_1 = context.sign(&msg, &sk).serialize_compact();
    }

    pub fn sign_libsecp256k1_benchmark(c: &mut Criterion) {
        c.bench_function("(external) libsecp256k1 signing", |b| b.iter(|| sign_libsecp256k1()));
    }

    fn sign_openssl() {

        let pk = hex::hex2bin(PUBLIC_KEY).unwrap();
        let h = sha2::Sha256::digest(&MESSAGE_1);

        let openssl_group = EcGroup::from_curve_name(Nid::SECP256K1).unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        let openssl_point = EcPoint::from_bytes(
            &openssl_group, pk.as_slice(), &mut ctx
        ).unwrap();
        let openssl_skey = EcKey::from_private_components(
            &openssl_group, &BigNum::from_hex_str(PRIVATE_KEY).unwrap(), &openssl_point
        ).unwrap();

        let openssl_sig = EcdsaSig::sign(h.as_slice(), &openssl_skey);
        assert!(openssl_sig.is_ok());
    }

    pub fn sign_openssl_benchmark(c: &mut Criterion) {
        c.bench_function("(external) openssl signing", |b| b.iter(|| sign_openssl()));
    }

    fn verify() {
        let scheme = EcdsaSecp256k1Sha256::new();
        let p = PublicKey(hex::hex2bin(PUBLIC_KEY).unwrap());
        let result = scheme.verify(&MESSAGE_1, hex::hex2bin(SIGNATURE_1).unwrap().as_slice(), &p);
        assert!(result.is_ok());
    }

    pub fn verify_benchmark(c: &mut Criterion) {
        c.bench_function("secp256k1 verification", |b| b.iter(|| verify()));
    }

    fn verify_libsecp256k1() {

        let context = libsecp256k1::Secp256k1::new();
        let pk = libsecp256k1::key::PublicKey::from_slice(
            hex::hex2bin(PUBLIC_KEY).unwrap().as_slice()
        ).unwrap();

        let h = sha2::Sha256::digest(&MESSAGE_1);
        let msg = libsecp256k1::Message::from_slice(h.as_slice()).unwrap();

        let mut signature = libsecp256k1::Signature::from_compact(&hex::hex2bin(SIGNATURE_1)
            .unwrap()[..]).unwrap();
        signature.normalize_s();
        let result = context.verify(&msg, &signature, &pk);
        assert!(result.is_ok());
    }

    pub fn verify_libsecp256k1_benchmark(c: &mut Criterion) {
        c.bench_function("(external) libsecp256k1 verification", |b| b.iter(|| verify_libsecp256k1()));
    }

    fn verify_openssl() {

        let h = sha2::Sha256::digest(&MESSAGE_1);
        let pk = hex::hex2bin(PUBLIC_KEY).unwrap();

        let openssl_group = EcGroup::from_curve_name(Nid::SECP256K1).unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        let openssl_point = EcPoint::from_bytes(
            &openssl_group, pk.as_slice(), &mut ctx
        ).unwrap();
        let openssl_pkey = EcKey::from_public_key(&openssl_group, &openssl_point).unwrap();

        let (r, s) = SIGNATURE_1.split_at(SIGNATURE_1.len() / 2);
        let openssl_r = BigNum::from_hex_str(r).unwrap();
        let openssl_s = BigNum::from_hex_str(s).unwrap();
        let openssl_sig = EcdsaSig::from_private_components(openssl_r, openssl_s).unwrap();
        let openssl_result = openssl_sig.verify(h.as_slice(), &openssl_pkey);
        assert!(openssl_result.is_ok());
    }

    pub fn verify_openssl_benchmark(c: &mut Criterion) {
        c.bench_function("(external) openssl verification", |b| b.iter(|| verify_openssl()));
    }
}
