extern crate openssl;
extern crate ursa;

use openssl::{
    hash::MessageDigest,
    memcmp,
    pkey::PKey,
    sign::Signer,
    symm::{decrypt as openssl_decrypt, encrypt as openssl_encrypt, Cipher as OpenSslCipher},
};

use ursa::encryption::random_vec;
use ursa::encryption::symm::prelude::*;

use std::io;
use std::io::Write;
use std::time::Instant;

fn main() {
    let aad = b"test_aescbc";
    let msg = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/-_";
    let trials = 2000;
    println!(
        "Running 2 tests for AesCbcHmac encryption of {} messages",
        trials
    );
    print!("This library Aes128CbcHmac256 - ");
    io::stdout().flush().unwrap();
    let encryptor = SymmetricEncryptor::<Aes128CbcHmac256>::default();

    let mut now = Instant::now();

    for _ in 0..trials {
        let ciphertext = encryptor.encrypt_easy(&aad[..], &msg[..]).unwrap();
        encryptor.decrypt_easy(&aad[..], &ciphertext).unwrap();
    }
    let elapsed = now.elapsed();
    println!("{}.{:03}", elapsed.as_secs(), elapsed.subsec_millis());

    print!("openssl based aes-128-cbc-hmac-256 - ");
    io::stdout().flush().unwrap();

    let key = random_vec(32).unwrap();
    now = Instant::now();
    for _ in 0..trials {
        let ciphertext = aes_128_cbc_hmac_256_encrypt(key.as_slice(), &aad[..], &msg[..]);
        aes_128_cbc_hmac_256_decrypt(key.as_slice(), &aad[..], ciphertext.as_slice()).unwrap();
    }

    let elapsed = now.elapsed();
    println!("{}.{:03}", elapsed.as_secs(), elapsed.subsec_millis());

    print!("This library Aes256CbcHmac512 - ");
    io::stdout().flush().unwrap();
    let encryptor = SymmetricEncryptor::<Aes256CbcHmac512>::default();

    let mut now = Instant::now();

    for _ in 0..trials {
        let ciphertext = encryptor.encrypt_easy(&aad[..], &msg[..]).unwrap();
        encryptor.decrypt_easy(&aad[..], &ciphertext).unwrap();
    }
    let elapsed = now.elapsed();
    println!("{}.{:03}", elapsed.as_secs(), elapsed.subsec_millis());

    print!("openssl based aes-256-cbc-hmac-512 - ");
    io::stdout().flush().unwrap();

    let key = random_vec(64).unwrap();
    now = Instant::now();
    for _ in 0..trials {
        let ciphertext = aes_256_cbc_hmac_512_encrypt(key.as_slice(), &aad[..], &msg[..]);
        aes_256_cbc_hmac_512_decrypt(key.as_slice(), &aad[..], ciphertext.as_slice()).unwrap();
    }

    let elapsed = now.elapsed();
    println!("{}.{:03}", elapsed.as_secs(), elapsed.subsec_millis());
}

macro_rules! aes_cbc_hmac_impl {
    ($encrypt:ident, $decrypt:ident, $cipher:ident, $mac:ident, $tagsize:expr) => {
        fn $encrypt(key: &[u8], aad: &[u8], msg: &[u8]) -> Vec<u8> {
            let cipher = OpenSslCipher::$cipher();
            let mut nonce = random_vec(16).unwrap();
            let ciphertext = openssl_encrypt(
                cipher,
                &key[..cipher.key_len()],
                Some(nonce.as_slice()),
                msg,
            )
            .unwrap();
            let sslkey = PKey::hmac(&key[cipher.key_len()..]).unwrap();
            let mut hmac = Signer::new(MessageDigest::$mac(), &sslkey).unwrap();
            hmac.update(aad).unwrap();
            hmac.update(nonce.as_slice()).unwrap();
            hmac.update(ciphertext.as_slice()).unwrap();
            let mac = hmac.sign_to_vec().unwrap();
            nonce.extend_from_slice(ciphertext.as_slice());
            nonce.extend_from_slice(mac.as_slice());
            nonce
        }

        fn $decrypt(key: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, &'static str> {
            let cipher = OpenSslCipher::$cipher();

            if ciphertext.len() < 48 {
                return Err("Invalid ciphertext length");
            }

            let nonce = Vec::from(&ciphertext[..16]);
            let ciphertext = Vec::from(&ciphertext[16..]);

            let tag_start = ciphertext.len() - $tagsize;
            let buffer = Vec::from(&ciphertext[..tag_start]);
            let tag = Vec::from(&ciphertext[tag_start..]);
            let sslkey = PKey::hmac(&key[cipher.key_len()..]).map_err(|_| "Invalid hmac key")?;
            let mut hmac =
                Signer::new(MessageDigest::$mac(), &sslkey).map_err(|_| "Invalid signer")?;

            hmac.update(aad).map_err(|_| "Invalid update with aad")?;
            hmac.update(nonce.as_slice())
                .map_err(|_| "Invalid update with nonce")?;
            hmac.update(buffer.as_slice())
                .map_err(|_| "Invalid update with buffer")?;
            let mac = hmac.sign_to_vec().map_err(|_| "Invalid sign to vec")?;
            if memcmp::eq(&mac, &tag) {
                let plaintext = openssl_decrypt(
                    cipher,
                    &key[..cipher.key_len()],
                    Some(nonce.as_slice()),
                    buffer.as_slice(),
                )
                .map_err(|_| "Decryption failure")?;
                Ok(plaintext)
            } else {
                Err("mac != tag")
            }
        }
    };
}

aes_cbc_hmac_impl!(
    aes_128_cbc_hmac_256_encrypt,
    aes_128_cbc_hmac_256_decrypt,
    aes_128_cbc,
    sha256,
    32
);
aes_cbc_hmac_impl!(
    aes_256_cbc_hmac_512_encrypt,
    aes_256_cbc_hmac_512_decrypt,
    aes_256_cbc,
    sha512,
    64
);
