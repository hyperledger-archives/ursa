extern crate libsodium_ffi as ffi;
extern crate ursa;

use ursa::signatures::ed25519::Ed25519Sha512;
use ursa::signatures::SignatureScheme;

use std::io;
use std::io::Write;
use std::time::Instant;

fn main() {
    let letters = b"abcdefghijklmnopqrstuvwxyz";
    let trials = 200;
    println!("Running 3 tests for ed25519 signing of {} messages", trials);
    print!("This library - ");
    io::stdout().flush().unwrap();
    let scheme = Ed25519Sha512::new();
    let (p, s) = scheme.keypair(None).unwrap();
    let mut now = Instant::now();

    for _ in 0..trials {
        let signature = scheme.sign(&letters[..], &s).unwrap();
        scheme.verify(&letters[..], &signature, &p).unwrap();
    }
    let elapsed = now.elapsed();
    println!("{}.{:03}", elapsed.as_secs(), elapsed.subsec_millis());

    let mut signature = [0u8; 64];
    print!("libsodium based ed25519 - ");
    io::stdout().flush().unwrap();

    now = Instant::now();
    for _ in 0..trials {
        unsafe {
            ffi::crypto_sign_ed25519_detached(
                signature.as_mut_ptr() as *mut u8,
                0u64 as *mut u64,
                letters.as_ptr() as *const u8,
                letters.len() as u64,
                s.as_ptr() as *const u8,
            );

            ffi::crypto_sign_ed25519_verify_detached(
                signature.as_ptr() as *const u8,
                letters.as_ptr() as *const u8,
                letters.len() as u64,
                p.as_ptr() as *const u8,
            )
        };
    }

    let elapsed = now.elapsed();
    println!("{}.{:03}", elapsed.as_secs(), elapsed.subsec_millis());
}
