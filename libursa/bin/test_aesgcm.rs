extern crate openssl;
extern crate ursa;

use openssl::symm::{
    decrypt_aead as openssl_decrypt, encrypt_aead as openssl_encrypt, Cipher as OpenSslCipher,
};

use ursa::encryption::random_vec;
use ursa::encryption::symm::prelude::*;

use std::io;
use std::io::Write;
use std::time::Instant;

fn main() {
    let aad = b"test_aesgcm";
    let msg = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/-_";
    let trials = 2000;
    println!(
        "Running 2 tests for AesCbcHmac encryption of {} messages",
        trials
    );
    print!("This library Aes128Gcm - ");
    io::stdout().flush().unwrap();
    let encryptor = SymmetricEncryptor::<Aes128Gcm>::default();

    let mut now = Instant::now();

    for _ in 0..trials {
        let ciphertext = encryptor.encrypt_easy(&aad[..], &msg[..]).unwrap();
        encryptor.decrypt_easy(&aad[..], &ciphertext).unwrap();
    }
    let elapsed = now.elapsed();
    println!("{}.{:03}", elapsed.as_secs(), elapsed.subsec_millis());

    print!("openssl based aes-128-gcm - ");
    io::stdout().flush().unwrap();

    let key = random_vec(16).unwrap();
    now = Instant::now();
    for _ in 0..trials {
        let ciphertext = aes_128_gcm_encrypt(key.as_slice(), &aad[..], &msg[..]);
        aes_128_gcm_decrypt(key.as_slice(), &aad[..], ciphertext.as_slice()).unwrap();
    }

    let elapsed = now.elapsed();
    println!("{}.{:03}", elapsed.as_secs(), elapsed.subsec_millis());

    print!("This library Aes256Gcm - ");
    io::stdout().flush().unwrap();
    let encryptor = SymmetricEncryptor::<Aes256CbcHmac512>::default();

    let mut now = Instant::now();

    for _ in 0..trials {
        let ciphertext = encryptor.encrypt_easy(&aad[..], &msg[..]).unwrap();
        encryptor.decrypt_easy(&aad[..], &ciphertext).unwrap();
    }
    let elapsed = now.elapsed();
    println!("{}.{:03}", elapsed.as_secs(), elapsed.subsec_millis());

    print!("openssl based aes-256-gcm - ");
    io::stdout().flush().unwrap();

    let key = random_vec(32).unwrap();
    now = Instant::now();
    for _ in 0..trials {
        let ciphertext = aes_256_gcm_encrypt(key.as_slice(), &aad[..], &msg[..]);
        aes_256_gcm_decrypt(key.as_slice(), &aad[..], ciphertext.as_slice()).unwrap();
    }

    let elapsed = now.elapsed();
    println!("{}.{:03}", elapsed.as_secs(), elapsed.subsec_millis());
}

macro_rules! aes_gcm_impl {
    ($encrypt:ident, $decrypt:ident, $cipherid:ident) => {
        fn $encrypt(key: &[u8], aad: &[u8], msg: &[u8]) -> Vec<u8> {
            let mut nonce = random_vec(12).unwrap();
            let mut tag = vec![0u8; 16];

            let ciphertext = openssl_encrypt(
                OpenSslCipher::$cipherid(),
                key,
                Some(nonce.as_slice()),
                aad,
                msg,
                tag.as_mut_slice(),
            )
            .unwrap();
            nonce.extend_from_slice(ciphertext.as_slice());
            nonce.extend_from_slice(tag.as_slice());
            nonce
        }

        fn $decrypt(key: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, &'static str> {
            if ciphertext.len() < 28 {
                return Err("Invalid ciphertext length");
            }

            let nonce = Vec::from(&ciphertext[..12]);
            let ciphertext = Vec::from(&ciphertext[12..]);

            let tag_start = ciphertext.len() - 16;
            let plaintext = openssl_decrypt(
                OpenSslCipher::$cipherid(),
                key,
                Some(nonce.as_slice()),
                aad,
                &ciphertext[..tag_start],
                &ciphertext[tag_start..],
            )
            .map_err(|_| "Decryption Error")?;
            Ok(plaintext)
        }
    };
}

aes_gcm_impl!(aes_128_gcm_encrypt, aes_128_gcm_decrypt, aes_128_gcm);
aes_gcm_impl!(aes_256_gcm_encrypt, aes_256_gcm_decrypt, aes_256_gcm);
