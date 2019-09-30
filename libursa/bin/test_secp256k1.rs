extern crate openssl;
extern crate secp256k1;
extern crate ursa;

use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::ecdsa::EcdsaSig;
use openssl::nid::Nid;
use ursa::hash::sha2::{Digest, Sha256};
use ursa::signatures::secp256k1::EcdsaSecp256k1Sha256;
use ursa::signatures::{EcdsaPublicKeyHandler, SignatureScheme};

use std::io;
use std::io::Write;
use std::time::Instant;

fn main() {
    let letters = b"abcdefghijklmnopqrstuvwxyz";
    let trials = 200;
    println!(
        "Running 3 tests for secp256k1 signing of {} messages",
        trials
    );
    print!("This library - ");
    io::stdout().flush().unwrap();
    let scheme = EcdsaSecp256k1Sha256::new();
    let (p, s) = scheme.keypair(None).unwrap();
    let mut now = Instant::now();

    for _ in 0..trials {
        let signature = scheme.sign(&letters[..], &s).unwrap();
        scheme.verify(&letters[..], &signature, &p).unwrap();
    }
    let elapsed = now.elapsed();
    println!("{}.{:03}", elapsed.as_secs(), elapsed.subsec_millis());

    print!("C based secp256k1 - ");
    io::stdout().flush().unwrap();
    let context = secp256k1::Secp256k1::new();
    let sk = secp256k1::key::SecretKey::from_slice(&s[..]).unwrap();
    let pk = secp256k1::key::PublicKey::from_slice(&p[..]).unwrap();

    now = Instant::now();
    for _ in 0..trials {
        let hash = Sha256::digest(&letters[..]);
        let msg = secp256k1::Message::from_slice(&hash[..]).unwrap();
        let sig_1 = context.sign(&msg, &sk);
        context.verify(&msg, &sig_1, &pk).unwrap();
    }

    let elapsed = now.elapsed();
    println!("{}.{:03}", elapsed.as_secs(), elapsed.subsec_millis());

    print!("Openssl based secp256k1 - ");
    io::stdout().flush().unwrap();
    let openssl_group = EcGroup::from_curve_name(Nid::SECP256K1).unwrap();
    let mut ctx = BigNumContext::new().unwrap();
    let openssl_point = EcPoint::from_bytes(
        &openssl_group,
        &scheme.public_key_uncompressed(&p)[..],
        &mut ctx,
    )
    .unwrap();
    let openssl_pkey = EcKey::from_public_key(&openssl_group, &openssl_point).unwrap();
    let openssl_skey = EcKey::from_private_components(
        &openssl_group,
        &BigNum::from_slice(&s[..]).unwrap(),
        &openssl_point,
    )
    .unwrap();

    now = Instant::now();
    for _ in 0..trials {
        let hash = Sha256::digest(&letters[..]);
        let openssl_sig = EcdsaSig::sign(&hash, &openssl_skey).unwrap();
        openssl_sig.verify(&hash, &openssl_pkey).unwrap();
    }

    let elapsed = now.elapsed();
    println!("{}.{:03}", elapsed.as_secs(), elapsed.subsec_millis());
}
