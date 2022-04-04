extern crate ursa;

use ursa::encryption::symm::prelude::*;

use std::io;
use std::io::Write;
use std::time::Instant;

fn main() {
    let aad = b"test_xchacha20poly1305";
    let msg = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/-_";
    let trials = 2000;
    println!(
        "Running test for XChaCha20Poly1305 encryption of {} messages",
        trials
    );
    io::stdout().flush().unwrap();
    let encryptor = SymmetricEncryptor::<XChaCha20Poly1305>::default();

    let now = Instant::now();

    for _ in 0..trials {
        let ciphertext = encryptor.encrypt_easy(&aad[..], &msg[..]).unwrap();
        encryptor.decrypt_easy(&aad[..], &ciphertext).unwrap();
    }
    let elapsed = now.elapsed();
    println!("{}.{:03}", elapsed.as_secs(), elapsed.subsec_millis());
}
