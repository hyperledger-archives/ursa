
#[macro_use]
extern crate criterion;
use criterion::Criterion;

extern crate secp256k1 as libsecp256k1;
extern crate openssl;
extern crate ursa;

// benchmark functions defined in benches/bench_wrappers
mod bench_wrappers;

// Signatures
use bench_wrappers::signatures::{ed25519, secp256k1};

// ed25519
criterion_group!{
    name = bench_ed25519;
    config = Criterion::default();
    targets = ed25519::create_keys_benchmark, ed25519::load_keys_benchmark,
        ed25519::sign_benchmark, ed25519::verify_benchmark
}

// secp256k1
criterion_group!{
    name = bench_secp256k1;
    config = Criterion::default();
    targets = secp256k1::create_keys_benchmark, secp256k1::load_keys_benchmark,
        secp256k1::sign_benchmark, secp256k1::sign_libsecp256k1_benchmark,
        secp256k1::sign_openssl_benchmark,
        secp256k1::verify_benchmark, secp256k1::verify_libsecp256k1_benchmark,
        secp256k1::verify_openssl_benchmark
}

// BLS
use bench_wrappers::bls;

criterion_group!{
    name = bench_bls;
    config = Criterion::default();
    targets = bls::create_generator_benchmark, bls::create_sign_key_none_benchmark,
        bls::create_sign_key_seed_benchmark, bls::create_ver_key_benchmark,
        bls::create_pop_benchmark, bls::sign_benchmark, bls::create_multi_sig_benchmark,
        bls::verify_benchmark, bls::verify_pop_benchmark
}

// run benchmarks
criterion_main!(bench_ed25519, bench_secp256k1, bench_bls);
