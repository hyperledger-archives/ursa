
#[macro_use]
extern crate criterion;
use criterion::Criterion;

extern crate secp256k1 as libsecp256k1;
extern crate openssl;
extern crate ursa;

mod signatures;
use signatures::{ed25519, secp256k1};

// ed25519
fn ed25519_create_keys_benchmark(c: &mut Criterion) {
    c.bench_function("ed25519 key creation", |b| b.iter(|| ed25519::create_keys()));
}

fn ed25519_load_keys_benchmark(c: &mut Criterion) {
    c.bench_function("ed25519 key loading", |b| b.iter(|| ed25519::load_keys()));
}

fn ed25519_verify_benchmark(c: &mut Criterion) {
    c.bench_function("ed25519 verification", |b| b.iter(|| ed25519::verify()));
}

fn ed25519_sign_benchmark(c: &mut Criterion) {
    c.bench_function("ed25519 signing", |b| b.iter(|| ed25519::sign()));
}

criterion_group!{
    name = bench_ed25519;
    config = Criterion::default();
    targets = ed25519_create_keys_benchmark, ed25519_load_keys_benchmark,
        ed25519_verify_benchmark, ed25519_sign_benchmark
}

// secp256k1
fn secp256k1_create_keys_benchmark(c: &mut Criterion) {
    c.bench_function("secp256k1 key creation", |b| b.iter(|| secp256k1::create_keys()));
}

fn secp256k1_load_keys_benchmark(c: &mut Criterion) {
    c.bench_function("secp256k1 key loading", |b| b.iter(|| secp256k1::load_keys()));
}

fn secp256k1_verify_benchmark(c: &mut Criterion) {
    c.bench_function("secp256k1 verification", |b| b.iter(|| secp256k1::verify()));
}

fn secp256k1_sign_benchmark(c: &mut Criterion) {
    c.bench_function("secp256k1 signing", |b| b.iter(|| secp256k1::sign()));
}

criterion_group!{
    name = bench_secp256k1;
    config = Criterion::default();
    targets = secp256k1_create_keys_benchmark, secp256k1_load_keys_benchmark,
        secp256k1_verify_benchmark, secp256k1_sign_benchmark
}

// run benchmarks
criterion_main!(bench_ed25519, bench_secp256k1);
