extern crate ursa;

use ursa::signatures::prelude::*;

use std::io;
use std::io::Write;
use std::time::Instant;

fn main() {
    let letters = b"abcdefghijklmnopqrstuvwxyz";
    let trials = 200;
    println!("Running test for ed25519 signing of {} messages", trials);
    io::stdout().flush().unwrap();
    let scheme = Ed25519Sha512::new();
    let (p, s) = scheme.keypair(None).unwrap();
    let now = Instant::now();

    for _ in 0..trials {
        let signature = scheme.sign(&letters[..], &s).unwrap();
        scheme.verify(&letters[..], &signature, &p).unwrap();
    }
    let elapsed = now.elapsed();
    println!("{}.{:03}", elapsed.as_secs(), elapsed.subsec_millis());
}
