#[macro_use]
extern crate criterion;
extern crate zmix;

use criterion::Criterion;

use zmix::signatures::bbs::keys::generate as bbs_keys_generate;
use zmix::signatures::bbs::signature::Signature;
use zmix::signatures::bbs::BBSMessageVector;
use zmix::signatures::ps::keys::keygen as ps_keys_generate;

fn keypair_benchmark(c: &mut Criterion) {
    for i in vec![1, 2, 5, 10, 20, 50, 100] {
        let atts = i;
        c.bench_function(format!("create bbs+ key for {}", i).as_str(), move |b| {
            b.iter(|| bbs_keys_generate(atts))
        });
        c.bench_function(format!("create ps key for {}", i).as_str(), move |b| {
            b.iter(|| ps_keys_generate(atts, format!("create ps key for {}", i).as_bytes()))
        });
    }
}

fn bbs_sign_messages_benchmark(c: &mut Criterion) {
    for i in vec![1, 2, 5, 10, 20, 50, 100] {
        let atts = i;
        let (pk, sk) = bbs_keys_generate(atts).unwrap();
        let attributes = BBSMessageVector::random(atts);
        c.bench_function(format!("sign {} atts", i).as_str(), move |b| {
            b.iter(|| Signature::new(attributes.as_slice(), &sk, &pk))
        });
    }
}

fn bbs_sign_committed_messages_benchmark(c: &mut Criterion) {}

fn bbs_prove_benchmark(c: &mut Criterion) {}

criterion_group!(
    name = bench_bbs;
    config = Criterion::default();
    targets = keypair_benchmark, bbs_sign_messages_benchmark, bbs_sign_committed_messages_benchmark, bbs_prove_benchmark
);

criterion_main!(bench_bbs);
