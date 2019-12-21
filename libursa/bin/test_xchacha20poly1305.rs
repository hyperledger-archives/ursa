extern crate libsodium_ffi as ffi;
use std::{os::raw, ptr};
extern crate ursa;

use ursa::encryption::random_vec;
use ursa::encryption::symm::prelude::*;

use std::io;
use std::io::Write;
use std::time::Instant;

fn main() {
    unsafe { ffi::sodium_init() };
    let aad = b"test_xchacha20poly1305";
    let msg = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/-_";
    let trials = 2000;
    println!(
        "Running 2 tests for XChaCha20Poly1305 encryption of {} messages",
        trials
    );
    print!("This library - ");
    io::stdout().flush().unwrap();
    let encryptor = SymmetricEncryptor::<XChaCha20Poly1305>::default();

    let mut now = Instant::now();

    for _ in 0..trials {
        let ciphertext = encryptor.encrypt_easy(&aad[..], &msg[..]).unwrap();
        encryptor.decrypt_easy(&aad[..], &ciphertext).unwrap();
    }
    let elapsed = now.elapsed();
    println!("{}.{:03}", elapsed.as_secs(), elapsed.subsec_millis());

    print!("libsodium - ");
    io::stdout().flush().unwrap();

    let key = random_vec(32).unwrap();
    now = Instant::now();
    for _ in 0..trials {
        let ciphertext = xchacha20_poly1305_encrypt(key.as_slice(), &aad[..], &msg[..]);
        xchacha20_poly1305_decrypt(key.as_slice(), &aad[..], ciphertext.as_slice()).unwrap();
    }

    let elapsed = now.elapsed();
    println!("{}.{:03}", elapsed.as_secs(), elapsed.subsec_millis());
}

fn xchacha20_poly1305_encrypt(key: &[u8], aad: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut nonce = random_vec(24).unwrap();
    let mut ciphertext = Vec::with_capacity(msg.len() + 16);
    let mut clen = ciphertext.len() as raw::c_ulonglong;

    unsafe {
        ffi::crypto_aead_xchacha20poly1305_ietf_encrypt(
            ciphertext.as_mut_ptr(),
            &mut clen,
            msg.as_ptr(),
            msg.len() as raw::c_ulonglong,
            aad.as_ptr(),
            aad.len() as raw::c_ulonglong,
            ptr::null_mut(),
            nonce.as_slice().as_ptr(),
            key.as_ptr(),
        );
        ciphertext.set_len(clen as usize);
    }
    nonce.extend_from_slice(ciphertext.as_slice());
    nonce
}

fn xchacha20_poly1305_decrypt(key: &[u8], aad: &[u8], msg: &[u8]) -> Result<Vec<u8>, &'static str> {
    if msg.len() < 16 {
        return Err("Invalid tag length");
    }

    let nonce = Vec::from(&msg[..24]);
    let ciphertext = Vec::from(&msg[24..]);
    let mut plaintext = Vec::with_capacity(ciphertext.len() - 16);
    let mut plen = plaintext.len() as raw::c_ulonglong;

    unsafe {
        let res = ffi::crypto_aead_xchacha20poly1305_ietf_decrypt(
            plaintext.as_mut_ptr(),
            &mut plen,
            ptr::null_mut(),
            ciphertext.as_ptr(),
            ciphertext.len() as raw::c_ulonglong,
            aad.as_ptr(),
            aad.len() as raw::c_ulonglong,
            nonce.as_slice().as_ptr(),
            key.as_ptr(),
        );
        if res != 0 {
            return Err("Decryption Error");
        }
        plaintext.set_len(plen as usize);
    }
    Ok(plaintext)
}
